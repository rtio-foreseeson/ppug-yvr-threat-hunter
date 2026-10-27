import { describe, expect, it } from "vitest";
import {
  collectIocs,
  evaluateVerdict,
  expandToToken,
  verdictState,
  type IocAnswers,
  type VerdictAnswers,
} from "../src/intel/analysis";
import {
  normalizeUrl,
  toDataUrl,
  type RenderedPage,
} from "../src/intel/browser";

const page: RenderedPage = {
  requestedUrl: "http://localhost:5173/demo/cloudflare-verify",
  finalUrl: "http://localhost:5173/demo/cloudflare-verify",
  status: 200,
  title: "Cloudflare | Account Security Verification",
  text: "Verify within 24 hours.\nHelp: security@cloudfIare-support.example\nSend the fee to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\nPPUG training sample",
  forms: [
    {
      action: "https://cf-account-verify.example/collect",
      method: "post",
      passwordFields: 1,
      inputs: ["email", "password"],
    },
  ],
  links: [
    "https://cloudfiare-support.example/terms",
    "http://localhost:5173/demo/shop",
  ],
  screenshot: new Uint8Array([1, 2, 3]),
};

const noul = (p: number) => ({ type: "noul" as const, noul: p });
const choice = <O extends string>(c: O) => ({
  type: "choice" as const,
  choice: c,
  // Only the chosen option matters to evaluateVerdict; the full option map is irrelevant here.
  probabilities: { [c]: 0.9 } as never,
  confidence: 0.9,
});
const score = (n: number) => ({
  type: "score" as const,
  score: n * 4,
  legend: {},
  probabilities: {},
  confidence: 0.9,
});

function verdict(
  p: Partial<
    Record<
      | "phishing"
      | "credential_form"
      | "urgency_pressure"
      | "domain_mismatch"
      | "risk",
      number
    >
  >,
  brand = "none",
): VerdictAnswers {
  return {
    category: choice("login_portal"),
    phishing: noul(p.phishing ?? 0.02),
    brand_impersonated: choice(brand as "none"),
    credential_form: noul(p.credential_form ?? 0.02),
    urgency_pressure: noul(p.urgency_pressure ?? 0.02),
    domain_mismatch: noul(p.domain_mismatch ?? 0.02),
    risk: score(p.risk ?? 0),
  };
}

describe("evaluateVerdict", () => {
  it("calls clear phishing malicious and names the brand", () => {
    const out = evaluateVerdict(
      verdict(
        { phishing: 0.98, credential_form: 0.99, risk: 0.94 },
        "cloudflare",
      ),
    );
    expect(out.label).toBe("malicious");
    expect(out.reasons[0]).toBe("impersonates cloudflare");
  });

  it("flags pages with several weak signals as suspicious", () => {
    expect(
      evaluateVerdict(verdict({ urgency_pressure: 0.6, domain_mismatch: 0.6 }))
        .label,
    ).toBe("suspicious");
  });

  it("passes clean pages, even when they show a real brand", () => {
    expect(evaluateVerdict(verdict({}, "cloudflare"))).toEqual({
      verdict: "allow",
      label: "clean",
      reasons: [],
    });
  });
});

describe("IOC clean-up", () => {
  it("expands truncated spans to the full token", () => {
    expect(expandToToken(page.text, "bc1qxy2kgdygjrs")).toBe(
      "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
    );
    expect(expandToToken(page.text, "not in text")).toBe("not in text");
  });

  it("validates each IOC type and adds outbound link hosts", () => {
    const answers = {
      domains: {
        type: "list",
        value: ["PPUG training", "v", "cloudfIare-support.example"],
      },
      email_addresses: {
        type: "list",
        value: ["security@cloudfIare-support.example"],
      },
      crypto_wallets: { type: "list", value: ["bc1qxy2kgdygjrs"] },
      phone_numbers: { type: "list", value: ["+1 (415) 555-0199", "24"] },
      brand_claimed: { type: "text", value: "Cloudflare" },
      deadline_hours: { type: "duration", value: 24 },
      payment_amount: { type: "number", value: 49.99 },
    } as unknown as IocAnswers;
    const iocs = collectIocs(answers, page);
    expect(iocs.domains).toEqual([
      "cloudfiare-support.example",
      "cf-account-verify.example",
    ]);
    expect(iocs.crypto_wallets).toEqual([
      "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
    ]);
    expect(iocs.phone_numbers).toEqual(["+1 (415) 555-0199"]);
    expect(iocs.deadline_hours).toBe(24);
  });
});

describe("page helpers", () => {
  it("builds structured Clef state without same-host links", () => {
    const state = verdictState(page);
    expect(state.host).toBe("localhost");
    expect(state.external_link_hosts).toEqual(["cloudfiare-support.example"]);
  });

  it("normalizes URLs and refuses non-http schemes", () => {
    expect(normalizeUrl("example.com").toString()).toBe("https://example.com/");
    expect(normalizeUrl("/demo/shop", "https://app.example").toString()).toBe(
      "https://app.example/demo/shop",
    );
    expect(() => normalizeUrl("javascript:alert(1)")).toThrow(/Only http/);
    expect(() => normalizeUrl("file:///etc/passwd")).toThrow(/Only http/);
  });

  it("encodes screenshots as data URLs for Clef", () => {
    expect(toDataUrl(new Uint8Array([104, 105]), "image/jpeg")).toBe(
      "data:image/jpeg;base64,aGk=",
    );
  });
});
