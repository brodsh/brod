// The deploy-time phishing check, scored on tiny abstract snippets with a made-up brand list. server/src/scan.rs has
// the same cases. No test here imitates a real sign-in page.
import { describe, expect, it } from 'vitest';
import { ipKey } from '../src/abuse';
import { scanBundle } from '../src/scan';

const enc = new TextEncoder();
const BRANDS = ['examplebank', 'example mail'];
const scan = (files: Record<string, string>, brands = BRANDS) =>
  scanBundle(Object.entries(files).map(([path, s]) => ({ path, bytes: enc.encode(s) })), brands);
const PASSWORD = '<input type="password" name="p">';

describe('phishing check', () => {
  it('flags a password field with a brand in the title and a verification phrase', () => {
    const r = scan({ 'index.html': `<title>ExampleBank</title><p>Verify your account</p>${PASSWORD}` });
    expect(r.flagged).toBe(true);
    expect(r.score).toBe(3);
    expect(r.reasons).toEqual(['a password field', 'the brand "examplebank" in the page title, a heading, a label or a logo', 'the words "verify your account"']);
  });
  it('flags sign-in words next to a brand', () => {
    const r = scan({ 'index.html': `<p>Sign in to your  examplebank account</p>${PASSWORD}` });
    expect(r.flagged).toBe(true);
    expect(r.reasons).toContain('sign-in words next to a brand ("sign in to your examplebank")');
  });
  it('flags a password form that posts to another site', () => {
    const r = scan({ 'index.html': `<form action="https://collector.example.net/x">${PASSWORD}</form><p>Verify your account</p>` });
    expect(r.flagged).toBe(true);
    expect(r.reasons).toContain('a form that sends what is typed to another site (collector.example.net)');
  });
  it('flags card fields with code that posts to a chat bot', () => {
    const r = scan({ 'index.html': '<input name="cvv">', 'app.js': "fetch('https://api.telegram.org/bot1/sendMessage')" });
    expect(r.flagged).toBe(true);
    expect(r.reasons).toEqual(['card number or security code fields', 'code that sends data to a Telegram bot']);
  });
  it('flags a seed phrase prompt and a page written from an encoded string on their own', () => {
    expect(scan({ 'index.html': '<p>Enter your recovery phrase</p><textarea></textarea>' }).flagged).toBe(true);
    expect(scan({ 'index.html': '<script>document.write(atob("PHA+"))</script>' }).flagged).toBe(true);
  });
  it('reads a brand from a logo file name', () => {
    const r = scan({ 'index.html': `${PASSWORD}<p>Verify your account</p>`, 'img/examplebank-logo.svg': '<svg/>' });
    expect(r.flagged).toBe(true);
  });

  it('leaves an internal tool\'s own login form alone', () => {
    const r = scan({ 'index.html': `<title>Stock room</title><h1>Sign in</h1><form action="/login"><input name="user">${PASSWORD}<button>Sign in</button></form>` });
    expect(r).toEqual({ flagged: false, score: 0, reasons: [] });
  });
  it('leaves a "Sign in with Google" button next to a login form alone, with the real brand list', () => {
    const r = scanBundle([{ path: 'index.html', bytes: enc.encode(`<title>Team notes</title><button>Sign in with Google</button>${PASSWORD}`) }]);
    expect(r.flagged).toBe(false);
    expect(r.score).toBe(0);
  });
  it('leaves a newsletter form that posts elsewhere alone: it asks for no password', () => {
    const r = scan({ 'index.html': '<title>ExampleBank news</title><form action="https://letters.example.org/join"><input type="email" placeholder="Your email"></form>' });
    expect(r.flagged).toBe(false);
  });
  it('needs more than a brand name next to a password field', () => {
    const r = scan({ 'index.html': `<title>ExampleBank</title>${PASSWORD}` });
    expect(r.flagged).toBe(false);
    expect(r.score).toBe(2);
  });
});

describe('client addresses for rate limits', () => {
  it('keeps IPv4, unwraps mapped IPv4, and counts IPv6 per /64', () => {
    expect(ipKey('203.0.113.9')).toBe('203.0.113.9');
    expect(ipKey('::ffff:203.0.113.9')).toBe('203.0.113.9');
    expect(ipKey('2001:db8:1:2:3:4:5:6')).toBe('2001:db8:1:2::/64');
    expect(ipKey('2001:db8::1')).toBe('2001:db8:0:0::/64');
    expect(ipKey('::1')).toBe('0:0:0:0::/64');
  });
});
