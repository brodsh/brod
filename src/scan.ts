// The deploy-time phishing check: a cheap heuristic scan of a version's HTML and JavaScript, with no outside service.
// server/src/scan.rs is the same algorithm. Both are tested on small abstract snippets with a made-up brand list
// (test/scan.test.ts and the tests in scan.rs), never on imitation pages.
//
// A version is flagged when it asks for a password or a card number AND carries enough impersonation signals (a brand
// name in the title, a heading or a logo, "sign in to your <brand> account", "verify your account", a form that posts to
// another site, code that sends data to a Telegram bot). A seed-phrase prompt, a "connect your wallet to claim" prompt,
// or a page that writes itself from an encoded string is flagged on its own. A login form for the app's own data, with
// none of those signals, is not.

export interface ScanFile { path: string; bytes: Uint8Array }
export interface Scan { flagged: boolean; score: number; reasons: string[] }

const FILE_BYTES = 1024 * 1024;          // read at most this much of each file
const TOTAL_BYTES = 8 * 1024 * 1024;     // and of the whole bundle
const TEXT = ['html', 'htm', 'js', 'mjs', 'cjs', 'svg'];
const THRESHOLD = 3;

/** Names phishing pages imitate. Multi-word names match with single spaces. */
export const BRANDS = [
  'microsoft', 'office 365', 'office365', 'outlook', 'onedrive', 'sharepoint', 'google', 'gmail', 'apple', 'icloud', 'paypal',
  'amazon', 'netflix', 'facebook', 'instagram', 'whatsapp', 'linkedin', 'dropbox', 'docusign', 'adobe', 'chase bank', 'wells fargo',
  'bank of america', 'citibank', 'hsbc', 'barclays', 'santander', 'lloyds', 'natwest', 'coinbase', 'binance', 'metamask',
  'trust wallet', 'ledger live', 'trezor', 'kraken', 'blockchain.com', 'dhl', 'fedex', 'usps', 'hmrc', 'yahoo', 'venmo', 'revolut',
];
/** Brands that are also everyday words or common integrations: they count in a title or next to sign-in words, never as a bare mention. */
const AMBIGUOUS = new Set(['apple', 'amazon', 'google', 'outlook', 'office 365', 'office365']);
const STRONG_BEFORE = ['sign in to your ', 'sign in to ', 'log in to your ', 'log in to ', 'login to your ', 'login to ', 'verify your ', 'confirm your ', 'unlock your ', 'restore your '];
const WEAK_AFTER = [' account', ' id', ' login', ' sign in', ' sign-in', ' password', ' wallet', ' verification', ' security'];
const PHRASES = [
  'verify your account', 'verify your identity', 'confirm your identity', 'confirm your account', 'validate your account',
  'sign in to continue', 'log in to continue', 'login to continue', 'unusual activity', 'unusual sign-in activity',
  'account has been suspended', 'account has been locked', 'account has been limited', 'account is suspended', 'account is locked',
  'update your payment', 'update your billing', 're-enter your password', 'reenter your password', 'your session has expired',
  'unlock your account', 'security alert',
];
const SEED = [
  'seed phrase', 'recovery phrase', 'mnemonic phrase', 'secret phrase', '12 word phrase', '12-word phrase', '24 word phrase',
  '24-word phrase', '12 word seed', '12-word seed', '24 word seed', '24-word seed',
];
const WALLET = ['walletconnect', 'wallet connect', 'connect wallet', 'connect your wallet'];
const WALLET_ACTION = [
  'validate wallet', 'validate your wallet', 'rectify', 'sync wallet', 'sync your wallet', 'synchronize wallet', 'restore wallet',
  'restore your wallet', 'recover wallet', 'import wallet', 'import your wallet', 'claim airdrop', 'claim your airdrop', 'claim reward',
  'claim your reward', 'claim your tokens', 'migrate wallet', 'unlock wallet',
];
const CARD_VALUES = ['cardnumber', 'card-number', 'card_number', 'ccnumber', 'cc-number', 'cc_number', 'cvv', 'cvv2', 'cvc', 'csc'];
const CARD = [
  'autocomplete=cc-number', 'autocomplete:cc-number', 'autocomplete=cc-csc', 'autocomplete:cc-csc',
  ...['name', 'id'].flatMap(k => ['=', ':'].flatMap(s => CARD_VALUES.map(v => `${k}${s}${v}`))),
];
const PASSWORD = ['type=password', 'type:password', 'autocomplete=current-password', 'autocomplete:current-password'];
const OBFUSCATED = ['document.write(unescape(', 'document.write(atob(', 'document.write(window.atob(', 'document.write(decodeuricomponent('];
const EXFIL: [string, string][] = [
  ['api.telegram.org/bot', 'code that sends data to a Telegram bot'],
  ['discord.com/api/webhooks', 'code that sends data to a Discord webhook'],
  ['discordapp.com/api/webhooks', 'code that sends data to a Discord webhook'],
];
const IP_LOOKUP = ['api.ipify.org', 'ipapi.co', 'ip-api.com', 'ipinfo.io', 'geoplugin.net'];
const HEADINGS = ['title', 'h1', 'h2', 'h3'];
const ATTRS = ['alt=', 'aria-label=', 'placeholder=', 'title='];

const alnum = (c: string | undefined) => c !== undefined && /^[a-z0-9]$/.test(c);
const isSpace = (c: string) => c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f' || c === '\v';

/** Lower case, with every run of whitespace made one space. */
export function collapse(s: string): string {
  let out = '', space = false;
  for (const ch of s.toLowerCase()) {
    if (isSpace(ch)) { space = true; continue; }
    if (space && out) out += ' ';
    space = false;
    out += ch;
  }
  return out;
}
const PUNCT = '=:(),;{}[]<>';
/**
 * Lower case, without quotes and backslashes, with whitespace collapsed and dropped next to punctuation:
 * `type = "password" name` and `{type:\"password\"}` read type=password name and {type:password}.
 */
export function compact(s: string): string {
  let out = '';
  for (const ch of collapse(s)) {
    if (ch === '"' || ch === "'" || ch === '`' || ch === '\\') continue;
    if (ch === ' ' && (out.endsWith(' ') || PUNCT.includes(out[out.length - 1]))) continue;
    if (PUNCT.includes(ch) && out.endsWith(' ')) out = out.slice(0, -1);
    out += ch;
  }
  return out;
}
/** Every index where `word` occurs in `hay` with no letter or digit on either side. */
function wordAt(hay: string, word: string): number[] {
  const out: number[] = [];
  for (let i = hay.indexOf(word); i >= 0; i = hay.indexOf(word, i + 1)) {
    if (!alnum(hay[i - 1]) && !alnum(hay[i + word.length])) out.push(i);
  }
  return out;
}
const hasWord = (hay: string, word: string) => wordAt(hay, word).length > 0;
/** `needle` occurs with no letter or digit right after it. */
function endsClean(hay: string, needle: string): boolean {
  for (let i = hay.indexOf(needle); i >= 0; i = hay.indexOf(needle, i + 1)) if (!alnum(hay[i + needle.length])) return true;
  return false;
}

/** The text between <tag ...> and </tag>, for each such element. `s` is lower case. */
function elements(s: string, tag: string): string[] {
  const out: string[] = [];
  for (let i = s.indexOf(`<${tag}`); i >= 0; i = s.indexOf(`<${tag}`, i + 1)) {
    if (alnum(s[i + tag.length + 1])) continue;
    const open = s.indexOf('>', i);
    if (open < 0) break;
    const close = s.indexOf(`</${tag}`, open);
    out.push(s.slice(open + 1, close < 0 ? Math.min(s.length, open + 1 + 400) : close));
  }
  return out;
}
/** The value after `name` (which ends in "="), quoted or not. `s` is collapsed. */
function attrValues(s: string, name: string): string[] {
  const out: string[] = [];
  for (let i = s.indexOf(name); i >= 0; i = s.indexOf(name, i + 1)) {
    if (alnum(s[i - 1]) || s[i - 1] === '-') continue;
    let j = i + name.length;
    const q = s[j];
    if (q === '"' || q === "'") {
      const end = s.indexOf(q, j + 1);
      out.push(s.slice(j + 1, end < 0 ? s.length : end));
    } else {
      let end = j;
      while (end < s.length && !isSpace(s[end]) && s[end] !== '>') end++;
      out.push(s.slice(j, end));
    }
  }
  return out;
}
/** Drop <script>, <style> and comments, then every tag, then words that are addresses or emails: roughly what a visitor reads. */
function visibleText(s: string): string {
  let t = s;
  for (const [a, b] of [['<script', '</script'], ['<style', '</style'], ['<!--', '-->']]) {
    let out = '', i = 0;
    for (;;) {
      const start = t.indexOf(a, i);
      if (start < 0) { out += t.slice(i); break; }
      out += t.slice(i, start) + ' ';
      const end = t.indexOf(b, start);
      if (end < 0) break;
      i = end + b.length;
    }
    t = out;
  }
  let out = '', inTag = false;
  for (const ch of t) {
    if (ch === '<') { inTag = true; out += ' '; } else if (ch === '>') { inTag = false; out += ' '; } else if (!inTag) out += ch;
  }
  return collapse(out.split(' ').filter(w => !w.includes('://') && !w.includes('www.') && !w.includes('@')).join(' '));
}

/** Look at a bundle's pages and scripts. Pure and synchronous. `brands` is replaceable for tests. */
export function scanBundle(files: ScanFile[], brands: string[] = BRANDS): Scan {
  const dec = new TextDecoder();
  let budget = TOTAL_BYTES;
  let password = false, card = false, seed = false, walletAsk = false, walletAct = false, obfuscated = false, input = false;
  let prominent = '', strong = '', weak = '', mention = '', exfil = '', ipLookup = '';
  const phrases: string[] = [], forms: string[] = [];

  for (const f of files) {
    const base = f.path.toLowerCase().split('/').pop() ?? '';
    // A logo file named after a brand, such as microsoft-logo.svg.
    if (!prominent && base.includes('logo')) prominent = brands.find(b => hasWord(base.replace(/[-_.]/g, ' '), b)) ?? '';
    const ext = base.includes('.') ? base.split('.').pop()! : '';
    if (!TEXT.includes(ext) || budget <= 0) continue;
    const take = Math.min(f.bytes.byteLength, FILE_BYTES, budget);
    budget -= take;
    const raw = dec.decode(f.bytes.subarray(0, take));
    const text = collapse(raw), tight = compact(raw);
    const html = ext === 'html' || ext === 'htm' || ext === 'svg';

    if (PASSWORD.some(n => endsClean(tight, n))) password = true;
    if (CARD.some(n => endsClean(tight, n))) card = true;
    if (OBFUSCATED.some(n => tight.includes(n))) obfuscated = true;
    if (['<input', '<textarea', '"textarea"', "'textarea'", '"input"', "'input'"].some(n => text.includes(n))) input = true;
    if (SEED.some(n => text.includes(n))) seed = true;
    if (WALLET.some(n => text.includes(n))) walletAsk = true;
    if (WALLET_ACTION.some(n => text.includes(n))) walletAct = true;
    for (const p of PHRASES) if (!phrases.includes(p) && text.includes(p)) phrases.push(p);
    for (const [n, why] of EXFIL) if (!exfil && text.includes(n)) exfil = why;
    if (!ipLookup) ipLookup = IP_LOOKUP.find(n => text.includes(n)) ?? '';

    for (const b of brands) {
      for (const at of wordAt(text, b)) {
        const before = text.slice(Math.max(0, at - 24), at), after = text.slice(at + b.length, at + b.length + 16);
        if (!strong && STRONG_BEFORE.some(p => before.endsWith(p))) strong = `"${(STRONG_BEFORE.find(p => before.endsWith(p)) ?? '') + b}"`;
        if (!weak && WEAK_AFTER.some(s => after.startsWith(s) && !alnum(after[s.length]))) weak = `"${b}${WEAK_AFTER.find(s => after.startsWith(s))}"`;
      }
    }
    if (!html) continue;
    const shown = [...HEADINGS.flatMap(t => elements(text, t)), ...ATTRS.flatMap(a => attrValues(text, a))].join(' ');
    if (!prominent) prominent = brands.find(b => hasWord(shown, b)) ?? '';
    if (!prominent) prominent = brands.find(b => attrValues(text, 'src=').some(v => v.includes('logo') && hasWord(v.replace(/[-_./]/g, ' '), b))) ?? '';
    if (!mention) {
      const visible = visibleText(text);
      // "Sign in with Google" is a button for another provider, not an imitation of it.
      mention = brands.find(b => !AMBIGUOUS.has(b) && wordAt(visible, b).some(at => !visible.slice(Math.max(0, at - 5), at).endsWith('with '))) ?? '';
    }
    for (let i = text.indexOf('<form'); i >= 0; i = text.indexOf('<form', i + 1)) {
      const end = text.indexOf('>', i);
      const tag = text.slice(i, end < 0 ? text.length : end + 1).replace(/ ?= ?/g, '=');
      for (const v of attrValues(tag, 'action=')) {
        const host = v.startsWith('mailto:') ? 'email' : /^(https?:)?\/\//.test(v) ? v.replace(/^(https?:)?\/\//, '').split(/[/?#]/)[0] : '';
        if (host && !forms.includes(host)) forms.push(host);
      }
    }
  }

  const reasons: string[] = [];
  let score = 0;
  if (password) reasons.push('a password field');
  if (card) reasons.push('card number or security code fields');
  if (prominent) { score += 2; reasons.push(`the brand "${prominent}" in the page title, a heading, a label or a logo`); }
  if (strong) { score += 3; reasons.push(`sign-in words next to a brand (${strong})`); } else if (weak) { score += 2; reasons.push(`a brand account name (${weak})`); }
  // A brand already counted for the title or a heading is not counted again for being in the text.
  if (mention && mention !== prominent) { score += 1; reasons.push(`the brand "${mention}" in the page text`); }
  if (phrases.length) { score += Math.min(2, phrases.length); reasons.push(`the words ${phrases.slice(0, 3).map(p => `"${p}"`).join(', ')}`); }
  if (forms.length) { score += 2; reasons.push(`a form that sends what is typed to another site (${forms.slice(0, 3).join(', ')})`); }
  if (exfil) { score += 3; reasons.push(exfil); }
  if (ipLookup) { score += 1; reasons.push(`a lookup of the visitor's IP address (${ipLookup})`); }
  const seedAsk = seed && input, wallet = walletAsk && walletAct;
  if (seedAsk) reasons.push('a prompt for a wallet seed or recovery phrase');
  if (wallet) reasons.push('a prompt to connect a crypto wallet to claim, sync or restore it');
  if (obfuscated) reasons.push('a page that writes itself from an encoded string, as phishing kits do to hide from scanners');
  const flagged = obfuscated || seedAsk || wallet || ((password || card) && score >= THRESHOLD);
  return { flagged, score, reasons: flagged ? reasons : [] };
}
