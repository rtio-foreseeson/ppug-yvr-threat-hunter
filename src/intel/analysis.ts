import type { Verdict } from "../shared";
import { normalizedScore, type ClefAnswers } from "../system-one/clef";
import type { ClairicAnswers } from "../system-one/clairic";
import type { RenderedPage } from "./browser";

/**
 * CHECKPOINT 0 (ships working): what Clef is asked about every page.
 *
 * Clef reads the screenshot *and* the page facts in one forward pass, the same way Cloudflare's
 * threat intelligence team classifies domains. Edit the wording, add categories, add brands.
 */
export const VERDICT_QUESTIONS = {
  category: {
    type: "choice",
    instructions: "What kind of website is this?",
    criteria: {
      ecommerce: "Online store",
      banking_finance: "Bank, payments, insurance or investing",
      saas_software: "Software product, developer tool or cloud service",
      news_media: "News, blog or media",
      social: "Social network or forum",
      government: "Government or public service",
      crypto: "Cryptocurrency or web3",
      login_portal: "A page that mainly exists to sign in",
      parked_domain: "Parked or for-sale domain, little content",
      other: "Anything else",
    },
  },
  phishing: {
    type: "noul",
    instructions:
      "Is this page impersonating a brand or service to trick visitors into giving credentials, codes or payment details?",
  },
  brand_impersonated: {
    type: "choice",
    instructions:
      "Which brand does the page look like it belongs to, judging by logos, colours and wording?",
    criteria: {
      none: "No well-known brand, or the page is genuinely the brand's own",
      cloudflare: "Cloudflare",
      microsoft: "Microsoft / Office 365",
      google: "Google",
      apple: "Apple",
      paypal: "PayPal",
      amazon: "Amazon",
      bank: "A bank",
      other_brand: "Another well-known brand",
    },
  },
  credential_form: {
    type: "noul",
    instructions:
      "Does the page ask for a password, one-time code, recovery phrase or payment card?",
  },
  urgency_pressure: {
    type: "noul",
    instructions:
      "Does the page use urgency or threats (account suspended, verify within 24 hours, legal action) to pressure the visitor?",
  },
  domain_mismatch: {
    type: "noul",
    instructions:
      "Does the domain in the URL look unrelated to, or a lookalike of, the brand shown on the page?",
  },
  risk: {
    type: "score",
    instructions:
      "Overall, how dangerous is it for an ordinary person to interact with this page?",
    criteria: ["Safe", "Low", "Suspicious", "Likely malicious", "Malicious"],
  },
} as const;

/** What Clairic pulls out of the page text: indicators of compromise and typed facts. */
export const IOC_FIELDS = {
  domains: {
    type: "list",
    items: "text",
    instructions: "Every domain or hostname mentioned or linked",
  },
  email_addresses: {
    type: "list",
    items: "text",
    instructions: "Every email address",
  },
  crypto_wallets: {
    type: "list",
    items: "text",
    instructions:
      "Cryptocurrency wallet addresses (Bitcoin, Ethereum, Solana, etc.)",
  },
  phone_numbers: { type: "list", items: "text", instructions: "Phone numbers" },
  brand_claimed: {
    type: "text",
    instructions: "The company or brand the page claims to be",
  },
  deadline_hours: {
    type: "duration",
    unit: "hours",
    integer: true,
    instructions:
      "How long the visitor is given to act, if the page sets a deadline",
  },
  payment_amount: {
    type: "number",
    decimals: 2,
    unit: "USD",
    instructions: "Amount of money the page asks the visitor to pay, if any",
  },
} as const;

export type VerdictAnswers = ClefAnswers<typeof VERDICT_QUESTIONS>;
export type IocAnswers = ClairicAnswers<typeof IOC_FIELDS>;

export type ThreatVerdict = {
  verdict: Verdict;
  label: "malicious" | "suspicious" | "clean";
  reasons: string[];
};

const pct = (p: number) => `${Math.round(p * 100)}%`;

export function evaluateVerdict(a: VerdictAnswers): ThreatVerdict {
  const risk = normalizedScore(a.risk);
  const signals: Array<[string, number]> = [
    ["phishing", a.phishing.noul],
    ["credential_form", a.credential_form.noul],
    ["urgency_pressure", a.urgency_pressure.noul],
    ["domain_mismatch", a.domain_mismatch.noul],
  ];
  const reasons = signals
    .filter(([, p]) => p >= 0.5)
    .map(([k, p]) => `${k} ${pct(p)}`);
  if (a.brand_impersonated.choice !== "none" && a.phishing.noul >= 0.5) {
    reasons.unshift(`impersonates ${a.brand_impersonated.choice}`);
  }
  if (a.phishing.noul >= 0.7 || risk >= 0.75) {
    return {
      verdict: "block",
      label: "malicious",
      reasons: [...reasons, `risk ${pct(risk)}`],
    };
  }
  if (a.phishing.noul >= 0.4 || risk >= 0.5 || reasons.length >= 2) {
    return {
      verdict: "review",
      label: "suspicious",
      reasons: [...reasons, `risk ${pct(risk)}`],
    };
  }
  return { verdict: "allow", label: "clean", reasons };
}

/** The page facts Clef reads next to the screenshot. Structured state, not a prompt. */
export function verdictState(page: RenderedPage) {
  const host = new URL(page.finalUrl).hostname;
  return {
    url: page.requestedUrl,
    final_url: page.finalUrl,
    host,
    http_status: page.status,
    title: page.title,
    forms: page.forms,
    external_link_hosts: [
      ...new Set(
        page.links
          .map((l) => safeHost(l))
          .filter((h): h is string => !!h && h !== host),
      ),
    ].slice(0, 20),
    visible_text: page.text.slice(0, 4000),
  };
}

export function iocState(page: RenderedPage): string {
  return [
    `URL: ${page.finalUrl}`,
    `Title: ${page.title}`,
    "",
    page.text,
    "",
    "Links:",
    ...page.links.slice(0, 40),
  ].join("\n");
}

const DOMAIN =
  /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const EMAIL = /^[^\s@]+@[^\s@]+\.[a-z]{2,63}$/i;
const WALLET =
  /^(bc1[a-z0-9]{20,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|[1-9A-HJ-NP-Za-km-z]{32,44})$/;
const PHONE = /\d[\d\s().-]{6,}\d/;

/**
 * Clairic returns spans of the input. A span can stop mid-token, so grow it to the surrounding
 * non-whitespace run in the source text ("bc1qxy2k" -> the full wallet address).
 */
export function expandToToken(source: string, value: string): string {
  const at = source.indexOf(value);
  if (at < 0) return value;
  let start = at;
  let end = at + value.length;
  while (start > 0 && !/[\s<>"'(),]/.test(source.charAt(start - 1))) start--;
  while (end < source.length && !/[\s<>"'(),]/.test(source.charAt(end))) end++;
  return source.slice(start, end).replace(/[.;:!?]+$/, "");
}

const unique = (values: string[]) => [...new Set(values)].slice(0, 15);

/**
 * Clean up IOC lists. Clairic finds candidates fast; code then validates them, because extraction
 * models are well-formed but not always correct (see the Clairic launch post).
 */
export function collectIocs(a: IocAnswers, page: RenderedPage) {
  const source = iocState(page);
  const clean = (
    values: Array<string | number>,
    valid: RegExp,
    phone = false,
  ) =>
    unique(
      values
        .map((v) => String(v).trim())
        .map((v) => (phone ? v : expandToToken(source, v)))
        .map((v) => v.replace(/^https?:\/\//i, "").replace(/\/.*$/, ""))
        // A domain inside an email address expands to the whole address; keep the domain part.
        .map((v) =>
          valid === DOMAIN && v.includes("@") ? (v.split("@").pop() ?? v) : v,
        )
        .filter((v) => valid.test(v)),
    );
  const host = new URL(page.finalUrl).hostname;
  const linkHosts = [...page.forms.map((f) => f.action), ...page.links]
    .map(safeHost)
    .filter((h): h is string => !!h && h !== host && DOMAIN.test(h));
  return {
    domains: unique(
      [...clean(a.domains.value, DOMAIN), ...linkHosts].map((d) =>
        d.toLowerCase(),
      ),
    ),
    email_addresses: clean(a.email_addresses.value, EMAIL),
    crypto_wallets: clean(a.crypto_wallets.value, WALLET),
    phone_numbers: clean(a.phone_numbers.value, PHONE, true),
    brand_claimed: a.brand_claimed.value,
    deadline_hours: a.deadline_hours.value,
    payment_amount_usd: a.payment_amount.value,
  };
}

function safeHost(href: string): string | null {
  try {
    return new URL(href).hostname || null;
  } catch {
    return null;
  }
}
