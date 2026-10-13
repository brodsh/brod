// src/home.ts is generated from server/src/home.html (npm run gen:home); the Rust server embeds the HTML file itself.
// Both servers must send the same page with the same ETag.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { HOME_ETAG, HOME_HTML, OG_PNG_BASE64, OG_PNG_ETAG } from '../src/home';
import { page } from '../src/lib';

describe('the landing page', () => {
  it('matches server/src/home.html; run npm run gen:home after editing it', () => {
    const html = readFileSync(new URL('../server/src/home.html', import.meta.url), 'utf8');
    expect(HOME_HTML).toBe(html);
    expect(HOME_ETAG).toBe(`"${createHash('sha256').update(html).digest('hex').slice(0, 16)}"`);
  });

  it('carries server/src/og.png, a 1200 × 630 picture for link previews', () => {
    const png = readFileSync(new URL('../server/src/og.png', import.meta.url));
    expect(OG_PNG_BASE64).toBe(png.toString('base64'));
    expect(OG_PNG_ETAG).toBe(`"${createHash('sha256').update(png).digest('hex').slice(0, 16)}"`);
    expect([png.readUInt32BE(16), png.readUInt32BE(20)]).toEqual([1200, 630]);
    expect(HOME_HTML).toContain('<meta name="twitter:card" content="summary_large_image">');
    expect(HOME_HTML).toContain('<link rel="canonical" href="https://brod.sh/">');
  });

  it('carries the Google tag, with every kind of storage denied until a visitor accepts', () => {
    expect(HOME_HTML).toContain('googletagmanager.com/gtag/js?id=G-CCYYNHQKR7');
    const consent = HOME_HTML.indexOf("gtag('consent', 'default'"), config = HOME_HTML.indexOf("gtag('config', 'G-CCYYNHQKR7')");
    expect(consent).toBeGreaterThan(0);
    expect(config).toBeGreaterThan(consent);
    for (const kind of ['analytics_storage', 'ad_storage', 'ad_user_data', 'ad_personalization']) expect(HOME_HTML).toContain(`${kind}: 'denied'`);
  });

  it('is the only page with it: sign-in and the other platform pages are built on page() and have none', async () => {
    const html = await page(200, 'Sign in', '<h1>Sign in</h1>').text();
    expect(html).toContain('<title>Sign in</title>');
    expect(html).not.toContain('G-CCYYNHQKR7');
    expect(html).not.toContain('googletagmanager');
  });
});
