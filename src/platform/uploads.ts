// Uploads on hosts whose request-body limit is below the 25 MB bundle limit (Vercel Functions take about 4.5 MB).
// The agent PUTs the archive to a presigned file-store URL, then POSTs /v1/uploads/<id>/finish, which deploys it.
// On Cloudflare env.HOST is unset, so createUpload keeps its single PUT to /v1/uploads/<id>.
import { Env, LIMITS, Problem, readCapped } from '../lib';

export const stagedKey = (id: string) => `_uploads/${id}.tar.gz`;   // app files live under app_…/, so this never collides

export async function directUpload(env: Env, id: string) {
  if (!env.HOST?.presignPut) return null;
  const upload_url = await env.HOST.presignPut(stagedKey(id), LIMITS.uploadTtlMs / 1000);
  const finish_url = `${env.API_ORIGIN}/v1/uploads/${id}/finish`;
  return {
    upload_url, finish_url, expires_in_seconds: LIMITS.uploadTtlMs / 1000,
    next_step: 'Upload the built output folder as a tar.gz, then deploy it. Run this one line; the second response is the deploy result.\n' +
      `  tar -czf - -C <build folder> . | curl -sS --fail -X PUT --data-binary @- "${upload_url}" && curl -sS -X POST "${finish_url}"`,
  };
}

/** Read the staged archive and remove it, so a used or refused upload leaves nothing behind. */
export async function takeStaged(env: Env, id: string): Promise<Uint8Array> {
  if (!/^up_[0-9a-f]+$/.test(id)) throw new Problem(410, 'upload_gone', 'This upload address has expired or was already used. Call deploy_app again for a new one.');
  const obj = await env.BUNDLES.get(stagedKey(id));
  if (!obj) throw new Problem(400, 'no_archive', 'Nothing has been uploaded for this address yet. PUT the tar.gz to its upload_url first, then call finish again.');
  try {
    if (obj.size > LIMITS.bundleBytes) { await obj.body.cancel(); throw new Problem(413, 'too_large', 'The bundle is larger than 25 MB.'); }
    return await readCapped(obj.body, LIMITS.bundleBytes, 'The bundle');
  } finally {
    await env.BUNDLES.delete(stagedKey(id));
  }
}
