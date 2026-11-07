// @brodsh/auth/client: sign-in for an app's own login page, in the browser. Brod sends the code, checks it and sets the
// session on the app's address, so this code never handles a password or a session token. No dependencies.

export interface SignInMethods {
  email: boolean;
  google: boolean;
  app?: { name: string };
  return?: string;
}

export interface VerifyResult {
  ok: true;
  /** False when the app is not shared with this person: tell them on the page. */
  allowed: boolean;
  /** Where to send them: always a path on this app. */
  return: string;
}

/** A refused sign-in step. `message` is written for the person; `code` is stable (bad_code, rate_limited, ...). */
export class BrodSignInError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, message: string, status: number) {
    super(message);
    this.name = 'BrodSignInError';
    this.code = code;
    this.status = status;
  }
}

async function post<T>(path: string, body: object = {}): Promise<T> {
  const r = await fetch(`/_brod/auth/${path}`, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = (await r.json().catch(() => ({}))) as { error?: { code?: string; message?: string } };
  if (!r.ok) throw new BrodSignInError(data.error?.code ?? 'failed', data.error?.message ?? 'Sign-in failed. Try again.', r.status);
  return data as T;
}

/** The path a signed-out visitor was going to, from ?return=. Never an address on another site. */
export function returnTo(search: string = location.search): string {
  const r = new URLSearchParams(search).get('return');
  return r && r[0] === '/' && r[1] !== '/' && r[1] !== '\\' ? r : '/';
}

/** How people can sign in here. Both false when the app has no approved sign-in page yet. */
export async function methods(): Promise<SignInMethods> {
  const r = await fetch('/_brod/auth/methods', { credentials: 'same-origin' });
  return r.ok ? ((await r.json()) as SignInMethods) : { email: false, google: false };
}

/** Email a six-digit sign-in code. */
export function sendCode(email: string): Promise<{ sent: true; email: string }> {
  return post('start', { email });
}

/** Swap the code for this app's session cookie. Throws BrodSignInError when the code is wrong or expired. */
export function verifyCode(email: string, code: string, to: string = returnTo()): Promise<VerifyResult> {
  return post('verify', { email, code, return: to });
}

/** Leave for Google, and come back signed in. Check methods().google first. */
export function google(to: string = returnTo()): void {
  location.href = `/_brod/auth/google?return=${encodeURIComponent(to)}`;
}

/** End the session and stay on the app's pages. */
export function signOut(): Promise<{ ok: true }> {
  return post('signout');
}
