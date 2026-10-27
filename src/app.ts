/**
 * Use-case branding and one-click demo scenarios, shared by the agent and the UI.
 */
export type Scenario = {
  label: string;
  prompt: string;
  /** Optional sample file in /public attached to the message. */
  attachment?: string;
};

export const APP = {
  slug: "ppug-yvr-threat-hunter",
  name: "Threat Hunter",
  tagline: "Browser Run renders it. Clef judges it. Clairic pulls the IOCs.",
  scenarios: [
    {
      label: "Phishing sample",
      prompt: "Is this page safe? /demo/cloudflare-verify",
    },
    {
      label: "Legit shop sample",
      prompt: "Scan /demo/shop and tell me what it is.",
    },
    { label: "example.com", prompt: "Scan example.com" },
    {
      label: "Cloudflare blog",
      prompt: "Classify https://blog.cloudflare.com",
    },
  ] satisfies Scenario[],
};
