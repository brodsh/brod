// HTMLRewriter exists only on Cloudflare. Elsewhere, put a snippet at the end of <body> by finding the last </body>.
// Pages are at most LIMITS.fileBytes (10 MB), so buffering one is fine. Works on bytes, so any ASCII-compatible
// encoding survives. Like HTMLRewriter's body selector, a page without a <body> tag is left alone.

const lower = (b: number) => (b >= 65 && b <= 90 ? b + 32 : b);
function lastIndexOf(hay: Uint8Array, needle: string): number {
  const n = [...needle].map(ch => ch.charCodeAt(0));
  outer: for (let i = hay.length - n.length; i >= 0; i--) {
    for (let j = 0; j < n.length; j++) if (lower(hay[i + j]) !== n[j]) continue outer;
    return i;
  }
  return -1;
}

export function appendToBody(page: Uint8Array, snippet: string): Uint8Array {
  let at = lastIndexOf(page, '</body');
  if (at < 0) {
    if (lastIndexOf(page, '<body') < 0) return page;
    at = page.length;   // <body> never closed: the end of the document is the end of the body
  }
  const add = new TextEncoder().encode(snippet), out = new Uint8Array(page.length + add.length);
  out.set(page.subarray(0, at)); out.set(add, at); out.set(page.subarray(at), at + add.length);
  return out;
}

/** The same transform as `new HTMLRewriter().on('body', { element: e => e.append(snippet, { html: true }) })`. */
export async function appendToBodyResponse(res: Response, snippet: string): Promise<Response> {
  const page = new Uint8Array(await res.arrayBuffer());
  return new Response(appendToBody(page, snippet), { status: res.status, headers: res.headers });
}
