import puppeteer, { type BrowserWorker } from "@cloudflare/puppeteer";

export type RenderedPage = {
  requestedUrl: string;
  finalUrl: string;
  status: number | null;
  title: string;
  text: string;
  forms: Array<{
    action: string;
    method: string;
    passwordFields: number;
    inputs: string[];
  }>;
  links: string[];
  screenshot: Uint8Array;
};

const MAX_TEXT = 8000;
const MAX_LINKS = 60;

/**
 * Render a URL in Browser Run (headless Chrome on Cloudflare's network) and collect what an analyst
 * would look at: a screenshot, the visible text, forms and outbound links.
 */
export async function renderPage(
  binding: BrowserRun,
  url: string,
): Promise<RenderedPage> {
  const browser = await puppeteer.launch(binding as unknown as BrowserWorker);
  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });
    const response = await page.goto(url, {
      waitUntil: "networkidle2",
      timeout: 20_000,
    });
    // page.evaluate returns serialized values; a JSON string keeps the shape explicit.
    const raw = await page.evaluate(() =>
      JSON.stringify({
        text: document.body?.innerText ?? "",
        forms: [...document.forms].map((f) => ({
          action: f.action,
          method: f.method,
          passwordFields: f.querySelectorAll("input[type=password]").length,
          inputs: [...f.querySelectorAll("input")].map((i) => i.name || i.type),
        })),
        links: [...document.links].map((a) => a.href),
      }),
    );
    const data = JSON.parse(raw) as Pick<
      RenderedPage,
      "text" | "forms" | "links"
    >;
    const screenshot = await page.screenshot({ type: "jpeg", quality: 60 });
    return {
      requestedUrl: url,
      finalUrl: page.url(),
      status: response?.status() ?? null,
      title: await page.title(),
      text: data.text.replace(/\n{3,}/g, "\n\n").slice(0, MAX_TEXT),
      forms: data.forms,
      links: [...new Set(data.links)].slice(0, MAX_LINKS),
      screenshot: new Uint8Array(screenshot),
    };
  } finally {
    await browser.close();
  }
}

/** Accepts bare domains, rejects anything that is not http(s). */
export function normalizeUrl(input: string, origin?: string): URL {
  const trimmed = input.trim();
  const candidate =
    trimmed.startsWith("/") && origin
      ? new URL(trimmed, origin).toString()
      : /^[a-z][a-z0-9+.-]*:/i.test(trimmed)
        ? trimmed
        : `https://${trimmed}`;
  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    throw new Error(`"${input}" is not a valid URL`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`Only http(s) URLs can be scanned, got ${url.protocol}`);
  }
  return url;
}

export function toDataUrl(bytes: Uint8Array, mediaType: string): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return `data:${mediaType};base64,${btoa(binary)}`;
}
