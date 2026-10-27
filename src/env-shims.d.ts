// `wrangler types` names the browser binding `BrowserRun`, which newer @cloudflare/workers-types
// releases declare as a class. This interface merges with that declaration once you upgrade.
interface BrowserRun extends Fetcher {}
