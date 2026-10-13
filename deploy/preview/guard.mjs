// SPDX-License-Identifier: AGPL-3.0-only
// Which URLs a previewed page may load (deploy/preview/server.mjs): its own sandbox, data and blob URLs, and the
// public internet. Never Brod's private network: private and loopback addresses, single-label names (brod, runtime,
// postgres) and names under .internal, .local, .localhost and the like.
import { isIP } from 'node:net';

export const SUFFIX = '.brod-preview.internal';

function privateV4(ip) {
  const [a, b] = ip.split('.').map(Number);
  return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
}

function privateV6(ip) {
  const h = ip.toLowerCase();
  if (h === '::' || h === '::1') return true;
  // IPv4-mapped and -translated addresses stand for an IPv4 address: judge that one.
  const v4 = h.match(/^::(?:ffff:)?(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) return privateV4(v4[1]);
  if (h.startsWith('::ffff:')) return true;
  return /^(fc|fd|fe[89ab])/.test(h);
}

/** Whether the page in the sandbox at `sandbox` (a host name) may load `url`. */
export function allowed(url, sandbox) {
  let u;
  try { u = new URL(url); } catch { return false; }
  if (u.protocol === 'data:' || u.protocol === 'blob:') return true;
  if (!['http:', 'https:', 'ws:', 'wss:'].includes(u.protocol)) return false;
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (host === sandbox) return true;
  if (host.endsWith(SUFFIX)) return false;
  const kind = isIP(host);
  if (kind === 4) return !privateV4(host);
  if (kind === 6) return !privateV6(host);
  if (!host.includes('.') || /(^|\.)(localhost|internal|local|lan|home|corp|intranet)$/.test(host)) return false;
  return true;
}
