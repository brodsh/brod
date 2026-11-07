// @brodsh/auth/next: the signed-in person in Next.js server components, route handlers and server actions.
//
// Middleware gets the request itself: use currentUser(request) from '@brodsh/auth' there.
import { headers } from 'next/headers';
import { currentUser, requireUser, type BrodAuthOptions, type BrodUser } from '@brodsh/auth';

/**
 * The person signed in to this app, from the current request's headers, or null when the request is anonymous.
 * Works in server components, route handlers and server actions (Next.js 14 and later). Throws BrodAuthError when a
 * token is present but does not verify.
 */
export async function currentUserFromHeaders(opts?: BrodAuthOptions): Promise<BrodUser | null> {
  // headers() returns a promise from Next.js 15 on and the headers themselves before; await covers both.
  return currentUser(await headers(), opts);
}

/** Like currentUserFromHeaders, but throws BrodAuthError (status 401) when nobody is signed in. */
export async function requireUserFromHeaders(opts?: BrodAuthOptions): Promise<BrodUser> {
  return requireUser(await headers(), opts);
}

export { BrodAuthError, currentUser, filterValues, requireUser, verifyIdentityToken } from '@brodsh/auth';
export type { BrodAuthErrorCode, BrodAuthOptions, BrodClaims, BrodUser } from '@brodsh/auth';
