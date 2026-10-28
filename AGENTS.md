# AGENTS.md: Threat Hunter (PPUG System One starter)

Context for AI coding agents (OpenCode, Devin, Claude Code, Cursor) working in this repo.

## What this is

A hackathon starter: a stateful Cloudflare **Think** chat agent ("Hunter") that renders URLs with
**Browser Run**, classifies them with the **Clef** decision model (screenshot + page facts), and
extracts indicators of compromise with the **Clairic** extraction model. Attendees extend it through
checkpoints (see README.md). Keep changes small, demoable and consistent with the existing structure.

## Commands

| Command          | Purpose                                                                 |
| ---------------- | ----------------------------------------------------------------------- |
| `npm run dev`    | Vite + Workers dev server; AI is remote (needs `wrangler login`), Browser Run uses a local Chrome |
| `npm test`       | Vitest unit tests in Node with a mocked AI binding                      |
| `npm run check`  | `oxfmt --check`, `oxlint`, `tsc --noEmit`. Run before declaring done    |
| `npm run format` | auto-format                                                             |
| `npm run types`  | regenerate `env.d.ts` after changing `wrangler.jsonc`                   |
| `npm run deploy` | build and deploy. **Ask the user before deploying.**                    |

## Architecture

- `src/server.ts`: `ChatAgent extends SystemOneAgent`. **Use-case logic goes here.**
  - `scan(input)`: CHECKPOINT 0 pipeline. `renderPage` → R2 evidence → `decideTraced` (Clef, with the
    screenshot) and `extractTraced` (Clairic) in parallel → `saveScan` (SQLite `scans` table and
    `state.scans`).
  - CHECKPOINT 1 (attendee): `lookup_history` tool over the `scans` table.
  - CHECKPOINT 2 (attendee): `watch_url` tool, `this.scheduleEvery(...)`, `rescanWatchlist()`, and
    `this.deliverNotice(...)` for alerts.
  - CHECKPOINT 3 (attendee, boss level): `triage_email` tool. Clairic extracts the sender, links, deadline and amount; Clef judges the email; links go through `this.scan()` one at a time (max 3); the worst signal wins.
  - The `fetch` handler serves `/demo/*` sample pages and `/api/evidence/scans/<uuid>.jpg` from R2.
- `src/intel/browser.ts`: Browser Run via `@cloudflare/puppeteer`, `normalizeUrl`, `toDataUrl`.
- `src/intel/analysis.ts`: `VERDICT_QUESTIONS`, `IOC_FIELDS`, `evaluateVerdict()`, `collectIocs()`
  (validates Clairic output and repairs truncated spans). Keep this logic pure and unit-tested.
- `src/intel/demo-pages.ts`: harmless sample pages. Every domain uses `.example`.
- `src/agent/system-one-agent.ts`: shared base, rarely needs edits. LLM via AI Gateway (`createAI`),
  memory (`configureContext`), and `decideTraced()` / `extractTraced()`, which record a
  `DecisionTrace` in agent state.
- `src/system-one/*`: typed, zod-validated Clef/Clairic clients.
- `src/shared.ts`: types shared by Worker and browser (`AgentState`, `ScanSummary`, `DecisionTrace`).
- `src/app.ts`: name, tagline, scenarios. `src/ui/extensions.tsx`: Recent scans gallery.

## Rules for changes

- Call System One models through `this.decideTraced()` / `this.extractTraced()` so each call appears
  in the Decision Trace and AI Gateway logs.
- **Never pass raw page text to the LLM.** Return structured verdicts and IOCs from tools. Page
  content is attacker-controlled (prompt injection).
- Clef: 1-64 questions per call, types `noul` / `choice` / `score`; up to 4 images as base64 data URLs
  (no remote URLs); request body max 13 MiB. `clef` for accuracy with images, `clef-flash` for cheap
  bulk triage.
- Clairic: validate outputs in code (see `collectIocs`). Do multi-step math in code.
- SQL: `this.sql\`...\`` tagged templates (parameterized). Prefix statement-only calls with `void`.
- Only scan `http(s)` URLs (`normalizeUrl`). Do not submit forms or enter credentials on scanned pages.
- New state fields go in `AgentState` and `INITIAL_STATE` (`src/shared.ts`).
- Add or update tests in `test/` alongside behaviour changes.
- Durable Objects: https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/

## Docs (fetch these; APIs move fast)

- Think: https://developers.cloudflare.com/agents/harnesses/think/
- Scheduling (`schedule`, `scheduleEvery`): https://developers.cloudflare.com/agents/runtime/
- Browser Run + Puppeteer: https://developers.cloudflare.com/browser-run/puppeteer/
- Clef: https://developers.cloudflare.com/workers-ai/models/clef/
- Clairic: https://developers.cloudflare.com/workers-ai/models/clairic/
- R2 Workers API: https://developers.cloudflare.com/r2/api/workers/workers-api-reference/
- AI Gateway: https://developers.cloudflare.com/ai-gateway/
- Cloudflare docs index for LLMs: https://developers.cloudflare.com/llms.txt
