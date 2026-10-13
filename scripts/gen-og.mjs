// SPDX-License-Identifier: AGPL-3.0-only
// Render server/src/og.png, the 1200 × 630 picture link previews show for https://brod.sh (og:image, twitter:image).
// It is the landing page's own hero: the headline beside the transcript of an agent putting an app online.
// Usage: npm run gen:og
import { chromium } from 'playwright';

const html = `<!doctype html><html><head><meta charset="utf-8">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,500..800&family=Instrument+Sans:wght@400..700&family=JetBrains+Mono:wght@400;600&display=swap">
<style>
* { box-sizing: border-box; margin: 0; }
body { width: 1200px; height: 630px; background: #F1F5F2; color: #13201A; font: 22px/1.5 'Instrument Sans', sans-serif; padding: 64px 72px;
  display: grid; grid-template-columns: 1.05fr 0.95fr; gap: 56px; align-items: center; overflow: hidden; }
.brand { display: flex; align-items: center; gap: 14px; font: 750 40px 'Bricolage Grotesque', sans-serif; letter-spacing: -0.03em; }
.mark { width: 38px; height: 23px; border-radius: 13px; background: #F4B62E; box-shadow: 11px -9px 0 -3px #F4B62E; margin-top: 8px; }
h1 { font: 750 64px/1.02 'Bricolage Grotesque', sans-serif; letter-spacing: -0.035em; margin-top: 40px; }
.sub { color: #55655C; font-size: 24px; margin-top: 24px; }
.url { font: 600 21px 'JetBrains Mono', monospace; color: #1E5B4A; margin-top: 28px; }
.talk { background: #FBFCFB; border: 1px solid #D3DDD6; border-radius: 24px; padding: 24px; display: flex; flex-direction: column; gap: 14px;
  box-shadow: 0 30px 70px -40px rgba(30,91,74,.6); font-size: 18px; }
.said { align-self: flex-end; max-width: 90%; background: #13201A; color: #F1F5F2; padding: 12px 16px; border-radius: 18px 18px 5px 18px; }
.call { padding: 8px 14px; border-left: 2px solid #D3DDD6; color: #55655C; }
.call code { font: 600 16px 'JetBrains Mono', monospace; color: #1E5B4A; margin-right: 8px; }
.live { border: 1px solid #D3DDD6; border-radius: 16px; overflow: hidden; background: #F1F5F2; }
.bar { display: flex; align-items: center; gap: 9px; padding: 10px 14px; background: #E4EBE6; font: 15px 'JetBrains Mono', monospace; }
.bar i { width: 9px; height: 9px; border-radius: 50%; background: #2B7A4B; }
.who { display: flex; justify-content: space-between; align-items: center; gap: 10px; padding: 14px; }
.chip { font-weight: 600; font-size: 15px; padding: 3px 12px; border-radius: 99px; border: 1px solid #2B7A4B; color: #2B7A4B; }
</style></head><body>
<div>
  <div class="brand"><span class="mark"></span>Brod</div>
  <h1>Your agent built it. Brod puts it online for your team.</h1>
  <p class="sub">Sign-in, roles and storage already there.</p>
  <p class="url">brod.sh</p>
</div>
<div class="talk">
  <p class="said">Put the shift swap tool online for the warehouse team.</p>
  <div class="call"><code>get_workspace</code>Reads your groups and roles.</div>
  <div class="call"><code>deploy_app</code>Shift swap, version 1. Live in seconds.</div>
  <div class="live">
    <div class="bar"><i></i>shift-swap.harborops.brod.sh</div>
    <div class="who"><span>Everyone in Harbor Ops</span><span class="chip">Shared</span></div>
  </div>
</div>
</body></html>`;

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1200, height: 630 } });
await page.setContent(html, { waitUntil: 'networkidle' });
await page.evaluate(() => document.fonts.ready);
await page.screenshot({ path: 'server/src/og.png', type: 'png' });
await browser.close();
console.log('Wrote server/src/og.png');
