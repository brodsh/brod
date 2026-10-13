// Outgoing email: sign-in links and invitations. Sent through Resend when RESEND_API_KEY is set.
// Locally (DEV_MODE=1) messages are logged instead, and the API returns the link so tests can follow it.
import { Env, Problem } from './lib';

export const devMode = (env: Env) => env.DEV_MODE === '1';

export async function sendEmail(env: Env, to: string, subject: string, text: string): Promise<void> {
  if (env.RESEND_API_KEY) {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { authorization: `Bearer ${env.RESEND_API_KEY}`, 'content-type': 'application/json' },
      body: JSON.stringify({ from: env.EMAIL_FROM || 'Brod <no-reply@brod.sh>', to: [to], subject, text }),
    });
    if (!r.ok) { console.error('email failed', r.status, await r.text()); throw new Problem(502, 'email_failed', 'We could not send the email. Try again in a minute.'); }
    return;
  }
  if (devMode(env)) { console.log(`[email to ${to}] ${subject}\n${text}`); return; }
  throw new Problem(503, 'email_unavailable', 'Email is not configured on this server, so sign-in links cannot be sent.');
}
