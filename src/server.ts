import {
  routeAgentRequest,
  type Connection,
  type ConnectionContext,
} from "agents";
import { tool, type ToolSet } from "ai";
import { z } from "zod";
import { SystemOneAgent } from "./agent/system-one-agent";
import { APP } from "./app";
import {
  collectIocs,
  evaluateVerdict,
  IOC_FIELDS,
  iocState,
  VERDICT_QUESTIONS,
  verdictState,
} from "./intel/analysis";
import { normalizeUrl, renderPage, toDataUrl } from "./intel/browser";
import { DEMO_PAGES } from "./intel/demo-pages";
import { MAX_SCANS, type ScanSummary } from "./shared";
import { normalizedScore } from "./system-one/clef";

const ORIGIN_KEY = "origin";
const EVIDENCE_PATH = /^\/api\/evidence\/(scans\/[0-9a-f-]{36}\.jpg)$/;

export class ChatAgent extends SystemOneAgent {
  readonly appSlug = APP.slug;

  soul() {
    return [
      "You are Hunter, a threat intelligence analyst assistant at a Cloudflare hackathon.",
      "When the user mentions a URL or domain, call `scan_url`. It renders the page in a real browser,",
      "and the System One models return a verdict (Clef, from the screenshot plus page facts) and",
      "indicators of compromise (Clairic). You never see raw page text; that keeps page content",
      "from injecting instructions into you.",
      "Report like an analyst: a one-line verdict, 2-4 evidence bullets quoting probabilities,",
      "the IOCs worth blocking, and a recommended action. Be concise and do not use emoji.",
    ].join(" ");
  }

  override getTools(): ToolSet {
    return {
      scan_url: tool({
        description:
          "Render a URL in a headless browser, classify it with Clef (screenshot + page facts) and extract IOCs with Clairic.",
        inputSchema: z.object({
          url: z
            .string()
            .describe(
              "Full URL, bare domain, or a /demo/... path served by this app",
            ),
        }),
        execute: async ({ url }) => this.scan(url),
      }),
      // CHECKPOINT 1: give Hunter a memory of past scans (lookup_history, watch tools). See README.
    };
  }

  // ---------------------------------------------------------------------------------------------
  // CHECKPOINT 0 (ships working): render -> Clef verdict + Clairic IOCs -> evidence in R2.
  // ---------------------------------------------------------------------------------------------
  async scan(input: string) {
    const target = normalizeUrl(input, this.origin());
    const page = await renderPage(this.env.BROWSER, target.toString());
    const host = new URL(page.finalUrl).hostname;
    const id = crypto.randomUUID();
    const key = `scans/${id}.jpg`;
    await this.env.EVIDENCE.put(key, page.screenshot, {
      httpMetadata: { contentType: "image/jpeg" },
      customMetadata: { url: page.finalUrl },
    });

    // One Clef pass over screenshot + page facts, one Clairic pass over the text, in parallel.
    const [{ answers: v }, { answers: iocAnswers }] = await Promise.all([
      this.decideTraced(
        {
          model: "clef",
          state: verdictState(page),
          questions: VERDICT_QUESTIONS,
          images: [toDataUrl(page.screenshot, "image/jpeg")],
        },
        {
          step: `Verdict: ${host}`,
          verdict: (a) => evaluateVerdict(a).verdict,
          summary: (a) =>
            evaluateVerdict(a).reasons.join(", ") || "no threat signals",
        },
      ),
      this.extractTraced(
        { state: iocState(page), fields: IOC_FIELDS, referenceDate: today() },
        { step: `IOCs: ${host}` },
      ),
    ]);

    const verdict = evaluateVerdict(v);
    const iocs = collectIocs(iocAnswers, page);
    const summary: ScanSummary = {
      id,
      at: Date.now(),
      url: page.finalUrl,
      host,
      title: page.title,
      verdict: verdict.verdict,
      label: verdict.label,
      category: v.category.choice,
      brand: v.brand_impersonated.choice,
      risk: normalizedScore(v.risk),
      reasons: verdict.reasons,
      iocCount:
        iocs.domains.length +
        iocs.email_addresses.length +
        iocs.crypto_wallets.length +
        iocs.phone_numbers.length,
      screenshot: `/api/evidence/${key}`,
    };
    this.saveScan(summary);

    return {
      url: page.finalUrl,
      title: page.title,
      http_status: page.status,
      verdict: verdict.label,
      reasons: verdict.reasons,
      category: v.category.choice,
      brand_impersonated: v.brand_impersonated.choice,
      probabilities: {
        phishing: v.phishing.noul,
        credential_form: v.credential_form.noul,
        urgency_pressure: v.urgency_pressure.noul,
        domain_mismatch: v.domain_mismatch.noul,
        risk: summary.risk,
      },
      iocs,
      screenshot: summary.screenshot,
    };
  }

  private saveScan(scan: ScanSummary) {
    void this.sql`CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY, at INTEGER NOT NULL, url TEXT NOT NULL, host TEXT NOT NULL,
      label TEXT NOT NULL, risk REAL NOT NULL, summary TEXT NOT NULL)`;
    void this.sql`INSERT INTO scans (id, at, url, host, label, risk, summary)
      VALUES (${scan.id}, ${scan.at}, ${scan.url}, ${scan.host}, ${scan.label}, ${scan.risk}, ${JSON.stringify(scan)})`;
    this.setState({
      ...this.state,
      scans: [scan, ...this.state.scans].slice(0, MAX_SCANS),
    });
  }

  /** The public origin of this Worker, so `/demo/...` paths resolve to our sample pages. */
  private origin(): string | undefined {
    return this.ctx.storage.kv.get<string>(ORIGIN_KEY);
  }

  override onConnect(connection: Connection, ctx: ConnectionContext) {
    this.ctx.storage.kv.put(ORIGIN_KEY, new URL(ctx.request.url).origin);
    return super.onConnect(connection, ctx);
  }
}

function today() {
  return new Date().toISOString().slice(0, 10);
}

export default {
  async fetch(request: Request, env: Env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/health") {
      return Response.json({
        ok: true,
        app: APP.slug,
        gateway: env.AI_GATEWAY_ID,
      });
    }
    const demo = DEMO_PAGES[url.pathname];
    if (demo) {
      return new Response(demo, {
        headers: {
          "content-type": "text/html; charset=utf-8",
          "x-robots-tag": "noindex",
        },
      });
    }
    const evidence = EVIDENCE_PATH.exec(url.pathname);
    if (evidence?.[1]) {
      const object = await env.EVIDENCE.get(evidence[1]);
      if (!object) return new Response("Not found", { status: 404 });
      return new Response(object.body, {
        headers: {
          "content-type": "image/jpeg",
          "cache-control": "private, max-age=3600",
        },
      });
    }
    return (
      (await routeAgentRequest(request, env)) ??
      new Response("Not found", { status: 404 })
    );
  },
} satisfies ExportedHandler<Env>;
