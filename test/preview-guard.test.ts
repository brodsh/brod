// SPDX-License-Identifier: AGPL-3.0-only
// The preview service's network guard (deploy/preview/guard.mjs): a previewed page reaches its sandbox and the public
// internet, never the private network the service runs in.
import { describe, expect, it } from 'vitest';
import { allowed, allowedResolved } from '../deploy/preview/guard.mjs';

const SANDBOX = '0123456789abcdef0123456789abcdef.brod-preview.internal';

describe('preview network guard', () => {
  it('lets the page load its own sandbox, data and the public internet', () => {
    for (const url of [`http://${SANDBOX}:8080/app.js`, 'https://fonts.googleapis.com/css2?family=Inter', 'https://93.184.215.14/x',
      'data:image/png;base64,AAAA', 'blob:https://x.test/1', 'wss://realtime.example.com/socket', 'https://[2606:4700::1111]/']) {
      expect(allowed(url, SANDBOX), url).toBe(true);
    }
  });
  it('refuses the private network, other sandboxes and other schemes', () => {
    for (const url of ['http://brod:8080/_runtime/code', 'http://runtime:8081/', 'http://postgres:5432/', 'http://localhost:8080/',
      'http://127.0.0.1/', 'http://10.0.0.5/', 'http://172.20.0.3/', 'http://192.168.1.1/', 'http://169.254.169.254/latest/meta-data/',
      'http://100.64.0.1/', 'http://0.0.0.0/', 'http://[::1]/', 'http://[fd00::1]/', 'http://[::ffff:127.0.0.1]/', 'http://[::ffff:7f00:1]/',
      'http://db.internal/', 'http://printer.local/', 'http://ffffffffffffffffffffffffffffffff.brod-preview.internal/',
      'file:///etc/passwd', 'ftp://example.com/', 'not a url']) {
      expect(allowed(url, SANDBOX), url).toBe(false);
    }
  });
});

describe('allowedResolved', () => {
  const resolver = (map: Record<string, string[]>) => async (host: string) => {
    if (!(host in map)) throw new Error('ENOTFOUND');
    return map[host].map(address => ({ address, family: address.includes(':') ? 6 : 4 }));
  };
  const dns = resolver({ 'cdn.example.com': ['93.184.215.14'], 'evil.example.com': ['10.0.0.5'], 'mixed.example.com': ['93.184.215.14', '127.0.0.1'], 'v6.example.com': ['fd00::1'] });

  it('lets public names that resolve to public addresses through', async () => {
    expect(await allowedResolved('https://cdn.example.com/app.js', 'x' + '.brod-preview.internal', dns)).toBe(true);
  });

  it('refuses public names that resolve to private or loopback addresses', async () => {
    for (const host of ['evil.example.com', 'mixed.example.com', 'v6.example.com'])
      expect(await allowedResolved(`https://${host}/`, 'x.brod-preview.internal', dns), host).toBe(false);
  });

  it('refuses names that do not resolve, and still refuses what allowed() refuses', async () => {
    expect(await allowedResolved('https://nowhere.example.com/', 'x.brod-preview.internal', dns)).toBe(false);
    expect(await allowedResolved('http://127.0.0.1/', 'x.brod-preview.internal', dns)).toBe(false);
  });
});
