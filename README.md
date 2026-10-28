# Threat Hunter

**Cloudflare Peer Point User Group: System One hackathon starter**

Give **Hunter** a URL. It opens the page in a real browser with **Browser Run**, and then two System
One models analyse it in parallel: **Clef** judges the screenshot plus the page facts, and **Clairic**
pulls out indicators of compromise. An LLM writes the analyst report. This is the same pattern
Cloudflare's own threat intelligence team uses Clef for.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/vnikhilbuddhavarapu/ppug-yvr-threat-hunter)

```
 "is this safe?"   ┌──────────── Durable Object (one per chat session) ─────────────┐
 browser ───ws────▶│ Think agent ── scan_url tool                                     │
                   │   1. Browser Run   → screenshot, visible text, forms, links      │
                   │   2. R2            ← screenshot evidence                         │
                   │   3. in parallel:                                                │
                   │        clef     (image + facts) → phishing? brand? risk score    │
                   │        clairic  (text)          → domains, emails, wallets, $    │
                   │   4. LLM gets the verdict + IOCs, never the raw page text        │
                   │   SQLite: scans history, memory, chat                            │
                   └──────────────────────────┬──────────────────────────────────────┘
                                              ▼  every model call
                                  AI Gateway (logs, metadata, analytics)
```

> **Why the LLM never sees the page.** Web pages are attacker-controlled text. If you paste them
> into an LLM, you invite prompt injection. Here the System One models read the page and return
> typed values, and the LLM only sees those. Fast, cheap and safer.

## What you get out of the box

- **A working, stateful chat agent** on the [Think harness](https://developers.cloudflare.com/agents/harnesses/think/):
  streaming, persistent memory and history in a Durable Object.
- **`scan_url` (CHECKPOINT 0), already working**: Browser Run, then a Clef verdict (7 questions in one pass,
  with the screenshot) and Clairic IOC extraction (7 typed fields), with screenshot evidence in R2.
- **IOC hygiene in code.** Clairic finds candidates; deterministic checks validate them and repair
  truncated spans. Extraction models are well formed but not always right, so verify.
- **Recent scans gallery** with screenshot thumbnails and verdict badges, plus the **Decision Trace**
  panel showing every Clef/Clairic call with probabilities, latency and cost.
- **Built-in, harmless sample pages** at `/demo/cloudflare-verify` (a fake phishing kit) and
  `/demo/shop` (a benign store), so the demo never depends on live malicious sites.
- **Two LLMs on Workers AI** behind a switcher, routed through **AI Gateway**.

## Quickstart (10 minutes)

Prerequisites: Node.js 24+, and a Cloudflare account (provided at the event).

```bash
git clone https://github.com/vnikhilbuddhavarapu/ppug-yvr-threat-hunter
cd ppug-yvr-threat-hunter
npm install
npx wrangler login        # Workers AI has no local simulator, so dev talks to your account
npm run dev               # http://localhost:5173
```

The first scan in `npm run dev` downloads a local Chrome for the browser binding, which takes
about a minute. After that, scans take a few seconds. If your login can see several accounts, run
`CLOUDFLARE_ACCOUNT_ID=<id> npm run dev`.

Ship it (Wrangler creates the R2 evidence bucket automatically on first deploy):

```bash
npm run deploy
```

### Try the scenarios

| Scenario          | What should happen                                                              |
| ----------------- | ------------------------------------------------------------------------------- |
| Phishing sample   | **malicious**: impersonates Cloudflare, credential form, 24h deadline, wallet IOC |
| Legit shop sample | **clean**, ecommerce                                                            |
| example.com       | **clean**, parked/other                                                         |
| Cloudflare blog   | **clean**, news_media, brand is genuine                                         |

Then try your own URLs. Click a thumbnail in **Recent scans** to see the full screenshot.

## Checkpoints

You have about **2 hours** of build time. Checkpoint 0 already works. Checkpoints 1 and 2 take most
people 30-40 minutes each. Checkpoint 3 is the boss level: big enough to fill the rest of the time and
make a great demo.

### CHECKPOINT 0: explore the pipeline (15 min)

- [`src/intel/analysis.ts`](src/intel/analysis.ts): `VERDICT_QUESTIONS` (Clef) and `IOC_FIELDS` (Clairic) are the
  whole classifier. Add a category, a brand, or a question like *"Is this a fake crypto giveaway?"*.
- `evaluateVerdict()` turns probabilities into **malicious / suspicious / clean**.
- [`src/server.ts`](src/server.ts) → `scan()` runs the pipeline. Note the `Promise.all`: Clef and Clairic run in parallel.

### CHECKPOINT 1: give Hunter a memory (30-40 min)

Every scan is already written to a `scans` table in the agent's SQLite (`saveScan()`). Add tools so
Hunter can use it:

1. `lookup_history({ host })`: `SELECT … FROM scans WHERE host = ?`, returning past verdicts.
2. Ask: *"Have we seen this domain before?"*. Hunter should now answer from memory.

```ts
const rows = this.sql<{ at: number; url: string; label: string; risk: number }>`
  SELECT at, url, label, risk FROM scans WHERE host = ${host} ORDER BY at DESC LIMIT 10`;
```

### CHECKPOINT 2: watchlist with scheduled re-scans (30-40 min)

Phishing kits often go live *after* a domain has been scanned clean. Add:

1. A `watch_url({ url })` tool that stores the URL in a `watchlist` table.
2. A recurring job: `await this.scheduleEvery(300, "rescanWatchlist")`. Check `this.getSchedules()`
   first so you only create it once.
3. `async rescanWatchlist()`: re-run `this.scan(url)` for each entry. If the verdict changed, post an
   alert into the chat with `await this.deliverNotice({ markdown: "…" })`.

### CHECKPOINT 3, the boss level: phishing email triage (rest of the build time)

Most phishing doesn't arrive as a URL; it arrives as an email. Teach Hunter to triage the whole thing.

1. **Add a `triage_email({ email })` tool** in `src/server.ts`.
2. **Extract with Clairic.** Pull typed values out of the email: `sender` (text), `reply_to`
   (text), `links` (a list of text), `brand_claimed` (text), `deadline_hours` (duration, hours) and
   `amount_requested` (number, USD). Clean the links up in code, like `collectIocs()` does.
3. **Decide with Clef** on the email itself: does it impersonate a brand, pressure the reader with
   urgency, ask for credentials or payment, or have a sender that doesn't match the brand? Add an
   overall `risk` score too.
4. **Scan the links** with the existing `this.scan(url)`, at most 3 links and one at a time, so you
   stay inside Browser Run's concurrency limits. You get screenshots and verdicts for free.
5. **One verdict for the email.** Combine them: the email is as bad as its worst signal, whether
   that's the email itself or any link. Return a short report, and let the LLM write the analyst summary.

Test email (fake, safe; `/demo/...` resolves to this app's sample pages):

```text
From: Cloudflare Security <security@cloudfIare-support.example>
Reply-To: billing-desk@protonmail.example
Subject: Action required: your account will be suspended

We detected unusual sign-in activity on your Cloudflare account. Verify your identity
within 24 hours or all zones and Workers will be permanently deleted.

Verify now: /demo/cloudflare-verify
A $49.99 reactivation fee applies. Questions? Call +1 (415) 555-0199.
```

**Done when:** pasting that email returns one **malicious** verdict, with the sender mismatch,
the deadline, the amount and a screenshot of the scanned link.

### Or: bring your own use case

Have a better idea? Use this starter as a base and build anything with Clef or Clairic. The agent,
UI, Decision Trace and AI Gateway wiring are all reusable. See the
[hackathon guide](https://github.com/vnikhilbuddhavarapu/ppug-yvr-system-one-hackathon#bring-your-own-use-case)
for ideas and the two ground rules.

### More stretch ideas

- **Block it for real**: push malicious domains to a Cloudflare Zero Trust Gateway list or a WAF
  custom list via the Cloudflare API, so detection turns into enforcement.
- **Bulk triage**: paste 20 domains and scan them concurrently. Rank by `risk`.
- **Agentic browsing**: give Hunter a full browser with `browserTool` from `agents/browser/ai-sdk`
  so it can click through redirect chains (needs a `worker_loaders` binding).
- **Video or ad review**: send short screen recordings to `clef-omni` (`videos: [dataUrl]`).
- **Fine-tuning story**: tag scans with AI Gateway `metadata`. Those logs are your Clef fine-tuning
  dataset.

Stuck on a checkpoint? Ask a Cloudflare facilitator: we have reference implementations and can point you in the right direction.

## How it works

| Piece                             | Where                                                 |
| --------------------------------- | ----------------------------------------------------- |
| Agent and `scan_url` tool         | `src/server.ts`                                       |
| Browser Run rendering             | `src/intel/browser.ts` (`@cloudflare/puppeteer`)       |
| Clef questions, Clairic fields    | `src/intel/analysis.ts`                               |
| Sample pages                      | `src/intel/demo-pages.ts`                             |
| Base agent: model, memory, traces | `src/agent/system-one-agent.ts`                       |
| Typed Clef / Clairic clients      | `src/system-one/*.ts`                                 |
| Shared types (server + UI)        | `src/shared.ts`                                       |
| UI (gallery in `extensions.tsx`)  | `src/ui/*`                                            |

Bindings (`wrangler.jsonc`): `AI` (Workers AI), `BROWSER` (Browser Run), `EVIDENCE` (R2), and
`ChatAgent` (Durable Object). Screenshots are served at `/api/evidence/scans/<uuid>.jpg`. The ids are
random but unauthenticated; add auth before using this beyond a demo.

### System One models

| Model        | Used here for                         | Price (input only) |
| ------------ | ------------------------------------- | ------------------ |
| `clef`       | verdict from screenshot + page facts  | $0.24 / M tokens   |
| `clairic`    | IOC and value extraction              | $0.10 / M tokens   |
| `clef-flash` | try it for cheaper bulk triage        | $0.038 / M tokens  |
| `clef-omni`  | video/audio (stretch)                 | $0.15 / M tokens   |

Docs: [Clef](https://developers.cloudflare.com/workers-ai/models/clef/) ·
[Clairic](https://developers.cloudflare.com/workers-ai/models/clairic/) ·
[Browser Run](https://developers.cloudflare.com/browser-run/) ·
[Think](https://developers.cloudflare.com/agents/harnesses/think/) ·
[AI Gateway](https://developers.cloudflare.com/ai-gateway/)

## Scripts

| Command          | What it does                                          |
| ---------------- | ----------------------------------------------------- |
| `npm run dev`    | local dev (AI calls go to your account, local Chrome) |
| `npm run deploy` | build and deploy to Workers                           |
| `npm test`       | unit tests (no Cloudflare account needed)             |
| `npm run check`  | format check, lint, typecheck                         |
| `npm run types`  | regenerate `env.d.ts` after editing `wrangler.jsonc`  |

## Troubleshooting

- **First scan hangs in dev**: the local Chrome is downloading. Watch the terminal.
- **`Not logged in` / AI errors**: run `npx wrangler login`. Set `CLOUDFLARE_ACCOUNT_ID` if you have
  several accounts.
- **Browser Run limits**: concurrent browsers are capped per account. If scans fail with a rate
  limit, wait a few seconds; don't fire off dozens at once.
- **`requires compatibility date …`**: keep the pinned versions (`npm ci`).
- **Logs**: Dashboard → AI → AI Gateway → `default` (every Clef/Clairic/LLM call, tagged with
  `app` and `step`), and Workers & Pages → your Worker → Observability.
