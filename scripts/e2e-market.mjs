// The marketplace on the Rust server: one workspace lists an app, another installs a copy, and updates are offered to
// the copy but only deployed when its workspace asks. Run by scripts/e2e-rust.mjs after scripts/e2e-billing.mjs.
// Usage: node scripts/e2e-market.mjs <api origin>
import http from 'node:http';

const API = process.argv[2] ?? 'http://localhost:8787';
const api = new URL(API);
let passed = 0, failed = 0;
const check = (name, ok, detail = '') => { ok ? passed++ : failed++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n      ${detail}`}`); };
const run = Date.now();

/** Send a request to Brod with any Host header, so app hosts need not resolve on this machine. */
function send(url, { method = 'GET', headers = {}, body } = {}) {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const req = http.request({ host: api.hostname, port: api.port, path: u.pathname + u.search, method, headers: { host: u.host, ...headers } }, res => {
      let data = ''; res.on('data', c => (data += c)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject); if (body) req.write(body); req.end();
  });
}

class Browser {
  constructor(email) { this.email = email; this.jars = {}; }
  async go(url, o = {}) {
    const u = new URL(url, API);
    const headers = { ...(o.headers ?? {}) };
    const jar = Object.entries(this.jars[u.host] ?? {}).map(([k, v]) => `${k}=${v}`).join('; ');
    if (jar) headers.cookie = jar;
    let body;
    if (o.body) body = o.body;
    if (o.json) { body = JSON.stringify(o.json); headers['content-type'] = 'application/json'; }
    if (o.form) { body = new URLSearchParams(o.form).toString(); headers['content-type'] = 'application/x-www-form-urlencoded'; }
    if (body || (o.method && o.method !== 'GET')) headers.origin ??= API;
    const r = await send(u.href, { method: o.method ?? (body ? 'POST' : 'GET'), headers, body });
    for (const sc of [].concat(r.headers['set-cookie'] ?? [])) {
      const [kv] = sc.split(';'); const [k, v] = kv.split('=');
      (this.jars[u.host] ??= {})[k.trim()] = v;
    }
    return r;
  }
  async signIn() {
    const start = await this.go('/auth/start', { json: { email: this.email, return: '/' } });
    const token = new URL(JSON.parse(start.body).dev_link).searchParams.get('token');
    return this.go('/auth/verify', { form: { token } });
  }
  async api(path, o = {}) {
    const r = await this.go(path, { ...o, headers: { ...(o.headers ?? {}), 'x-brod-workspace': this.workspace ?? '' } });
    return { status: r.status, body: r.body ? JSON.parse(r.body) : null };
  }
}
async function workspace(who, name) {
  const b = new Browser(`${who}-${run}@market.test`);
  await b.signIn();
  b.workspace = (await b.api('/v1/workspaces', { json: { name: `${name} ${run}`, accept_terms: true } })).body.workspace;
  // A new free workspace keeps its apps inside it for a day unless the operator trusts it (src/abuse.ts).
  await send(`${API}/v1/admin/workspaces/${b.workspace}/trust`, { method: 'POST', headers: { authorization: `Bearer ${process.env.ADMIN_SECRET ?? 'dev-admin-secret'}` } });
  return b;
}
const page = (text) => [{ path: 'index.html', content: `<h1>${text}</h1>` }, { path: 'app.js', content: `console.log(${JSON.stringify(text)})` }];
/** The page an app serves, after making it public. */
async function served(b, slug, url) {
  await b.api(`/v1/apps/${slug}/access`, { json: { access: 'public' } });
  return (await send(url + '/')).body;
}

// ---------- publishing ----------

const ada = await workspace('ada', 'Maker');
const cy = await workspace('cy', 'Shop');
const made = await ada.api('/v1/deploys', { json: { name: `Notes ${run}`, files: page('notes one') } });
const SRC = made.body.app;

check('a paid listing cannot be made yet', (await ada.api('/v1/listings', { json: { app: SRC, price: 500 } })).body?.error?.code === 'paid_not_yet');
const tok = await ada.api('/v1/tokens', { json: { name: 'agent' } });
const asAgent = await send(`${API}/v1/listings`, { method: 'POST', headers: { authorization: `Bearer ${tok.body.token}`, 'content-type': 'application/json' }, body: JSON.stringify({ app: SRC }) });
check('an agent cannot put an app in the marketplace', asAgent.status === 403 && JSON.parse(asAgent.body).error.code === 'people_only', asAgent.body);

const listed = await ada.api('/v1/listings', { json: { app: SRC, name: 'Team notes', summary: 'Shared notes for a small team', description: 'Longer text' } });
const L = listed.body?.listing;
check('a builder lists an app; its live version is release 1', listed.status === 201 && listed.body.latest_release === 1 && listed.body.free && listed.body.releases[0].from_version === 1 && listed.body.app === SRC, JSON.stringify(listed.body));
check('an app is listed once', (await ada.api('/v1/listings', { json: { app: SRC } })).body?.error?.code === 'already_listed');

// ---------- previews Brod takes itself ----------

const PREVIEWS = process.env.E2E_PREVIEWS === '1';
const SERVER_APPS = process.env.E2E_SKIP_SERVER_APPS !== '1';
/** Wait until a listing's automatic previews show its latest release (they are taken in the background). */
async function settled(who, listing) {
  if (!PREVIEWS) return null;
  for (let i = 0; i < 240; i++) {
    const l = (await who.api(`/v1/marketplace/${listing}`)).body;
    if (l.previews_release === l.latest_release) return l;
    await new Promise(r => setTimeout(r, 250));
  }
  return (await who.api(`/v1/marketplace/${listing}`)).body;
}
const autoBytes = async (listing) => PREVIEWS ? (await ada.api(`/v1/marketplace/${listing}`)).body.media.filter(m => m.source === 'auto').reduce((t, m) => t + m.bytes, 0) : 0;
const pngWidth = (b) => b.length > 24 && b.readUInt32BE(16);
const fetchBytes = (who, url) => new Promise((resolve, reject) => {
  const u = new URL(`${url}?workspace=${who.workspace}`, API);
  const jar = Object.entries(who.jars[u.host] ?? {}).map(([k, v]) => `${k}=${v}`).join('; ');
  http.get({ host: api.hostname, port: api.port, path: u.pathname + u.search, headers: { host: u.host, cookie: jar } }, res => {
    const parts = []; res.on('data', c => parts.push(c)); res.on('end', () => resolve({ status: res.statusCode, type: res.headers['content-type'], body: Buffer.concat(parts) }));
  }).on('error', reject);
});

if (PREVIEWS) {
  const l = await settled(cy, L);
  const auto = l.media.filter(m => m.source === 'auto');
  check('listing an app makes previews of it by itself: a screenshot, a screencast and a phone screenshot',
    l.previews_release === 1 && auto.map(m => m.kind).join() === 'image,video,image' && l.media[0].source === 'auto', JSON.stringify(l.media));
  const desk = await fetchBytes(cy, auto[0].url), cast = await fetchBytes(cy, auto[1].url), phone = await fetchBytes(cy, auto[2].url);
  check('the screenshot is a real desktop-sized PNG of the app', desk.status === 200 && desk.type === 'image/png' && pngWidth(desk.body) === 1280 && desk.body.length > 2000, `${desk.status} ${desk.type} ${pngWidth(desk.body)}`);
  check('the screencast is a real video', cast.status === 200 && cast.type === 'video/webm' && cast.body.length > 5000, `${cast.status} ${cast.type} ${cast.body.length}`);
  check('the phone screenshot is phone-sized', phone.type === 'image/png' && pngWidth(phone.body) === 780, String(pngWidth(phone.body)));
  const before = auto.map(m => m.id).join();
  const again = await ada.api(`/v1/listings/${L}/previews`, { method: 'POST' });
  const now = again.body.media?.filter(m => m.source === 'auto') ?? [];
  check('the publisher can take them again, which replaces the old ones', again.status === 200 && now.length === 3 && now.map(m => m.id).join() !== before, JSON.stringify(again.body).slice(0, 300));
  check('only the publisher can', (await cy.api(`/v1/listings/${L}/previews`, { method: 'POST' })).status === 403);
  const stray = await send(`http://${'f'.repeat(32)}.brod-preview.internal:${api.port}/`);
  check('a sandbox address without a live token serves nothing', stray.status === 404 && !stray.body.includes('notes'), `${stray.status}`);

  if (SERVER_APPS) {
    // The preview runs the release in an empty sandbox: none of the publisher's data, none of its secrets.
    const worker = `export default { async fetch(req, env) {
      await env.DB.run('CREATE TABLE IF NOT EXISTS notes (t TEXT)');
      if (req.method === 'POST') { await env.DB.run('INSERT INTO notes VALUES (?)', [await req.text()]); return new Response('ok'); }
      const n = (await env.DB.query('SELECT COUNT(*) AS n FROM notes'))[0].n;
      const who = req.headers.get('x-brod-user-email') || 'nobody';
      return new Response('<!doctype html><title>' + n + ' notes, secret ' + (env.TOKEN ? 'set' : 'unset') + ', ' + who + '</title><h1>' + n + ' notes</h1>', { headers: { 'content-type': 'text/html' } });
    } };`;
    const sa = await ada.api('/v1/deploys', { json: { name: `Counter ${run}`, files: [{ path: '_worker.js', content: worker }] } });
    await ada.api(`/v1/apps/${sa.body.app}/secrets/TOKEN`, { method: 'PUT', json: { value: 'publisher-only' } });
    await ada.api(`/v1/apps/${sa.body.app}/access`, { json: { access: 'public' } });
    for (const t of ['private note', 'another']) await send(sa.body.url + '/', { method: 'POST', body: t });
    const live = (await send(sa.body.url + '/')).body;
    const LS = (await ada.api('/v1/listings', { json: { app: sa.body.app } })).body.listing;
    const ls = await settled(ada, LS);
    const caption = ls.media.find(m => m.source === 'auto' && m.kind === 'image')?.caption;
    check('a server app is previewed in an empty sandbox, not with the publisher\'s data or secrets',
      live.includes('2 notes, secret set') && caption === '0 notes, secret unset, preview@brod.invalid', `live: ${live.slice(0, 80)} | preview: ${caption}`);
    check('and the sandbox is emptied afterwards', (await send(sa.body.url + '/')).body.includes('2 notes'));
    await ada.api(`/v1/listings/${LS}`, { method: 'DELETE' });
    await ada.api(`/v1/apps/${sa.body.app}`, { method: 'DELETE' });
  }
}

// ---------- browsing and installing ----------

const browse = await cy.api('/v1/marketplace');
const seen = browse.body.listings.find(l => l.listing === L);
check('another workspace sees it in the marketplace, free, with nothing installed', seen && seen.publisher === `Maker ${run}` && seen.free && seen.installs === 0 && seen.installed.length === 0 && !seen.yours && !('app' in seen), JSON.stringify(seen));
check('the marketplace can be searched', (await cy.api('/v1/marketplace?search=shared%20notes')).body.listings.some(l => l.listing === L)
  && !(await cy.api('/v1/marketplace?search=zzznothing')).body.listings.length);

const inst = await cy.api(`/v1/marketplace/${L}/install`, { json: {} });
const APP = inst.body?.app;
check('installing makes a private app in the installing workspace from the release', inst.status === 201 && inst.body.created && inst.body.access === 'private' && inst.body.version === 1 && inst.body.files === 2 && inst.body.marketplace.release === 1, JSON.stringify(inst.body));
check('the install is in the installer\'s activity log', (await cy.api('/v1/events?action=install')).body.events.some(e => e.app === APP));
check('the copy serves the release', (await served(cy, APP, inst.body.url)).includes('notes one'));
check('the publisher sees an install count, not who', (await ada.api(`/v1/marketplace/${L}`)).body.installs === 1);
check('the installer sees which of its apps came from the listing', (await cy.api(`/v1/marketplace/${L}`)).body.installed[0] === APP);

// ---------- updates are offered, not deployed ----------

await ada.api('/v1/deploys', { json: { app: SRC, files: page('notes two') } });
let st = (await cy.api(`/v1/apps/${APP}`)).body;
check('a new version of the source app alone changes nothing for installers', st.marketplace.update_available === false && st.marketplace.release === 1, JSON.stringify(st.marketplace));

const rel = await ada.api(`/v1/listings/${L}/releases`, { json: { note: 'Bigger headings' } });
check('the publisher publishes the new version as release 2', rel.status === 201 && rel.body.published === 2 && rel.body.releases[0].from_version === 2, JSON.stringify(rel.body));
check('publishing the same version again is refused', (await ada.api(`/v1/listings/${L}/releases`, { json: {} })).body?.error?.code === 'nothing_new');

st = (await cy.api(`/v1/apps/${APP}`)).body;
check('the installed app is offered the update', st.marketplace.update_available && st.marketplace.latest_release === 2 && st.marketplace.newer[0]?.note === 'Bigger headings', JSON.stringify(st.marketplace));
check('but it is not deployed: the copy still serves release 1', st.live_version === 1 && (await send(inst.body.url + '/')).body.includes('notes one'));
check('the app list shows the update too', (await cy.api('/v1/apps')).body.apps.find(a => a.app === APP)?.marketplace?.update_available === true);

const up = await cy.api(`/v1/apps/${APP}/marketplace/update`, { json: {} });
check('deploying the update makes it the next version', up.status === 200 && up.body.version === 2 && up.body.marketplace.release === 2 && !up.body.marketplace.update_available, JSON.stringify(up.body));
check('the copy now serves release 2', (await send(inst.body.url + '/')).body.includes('notes two'));
check('a second update finds nothing new', (await cy.api(`/v1/apps/${APP}/marketplace/update`, { json: {} })).body?.error?.code === 'up_to_date');
const back = await cy.api(`/v1/apps/${APP}/rollback`, { json: { version: 1 } });
check('the update rolls back like any deploy', back.status === 200 && (await send(inst.body.url + '/')).body.includes('notes one'));
check('the publisher cannot change someone else\'s copy', (await ada.api(`/v1/apps/${APP}/marketplace/update`, { json: {} })).status === 404);
check('the installer cannot publish to the listing', (await cy.api(`/v1/listings/${L}/releases`, { json: {} })).body?.error?.code === 'not_yours');

// ---------- storage, unlisting and deleting ----------

await settled(ada, L);
const usage = (await ada.api('/v1/usage')).body.storage.total;
const auto = await autoBytes(L);
const versions = (await ada.api(`/v1/apps/${SRC}`)).body.versions.reduce((t, v) => t + v.bytes, 0);
const releases = (await ada.api('/v1/listings')).body.listings[0].releases.reduce((t, r) => t + r.bytes, 0);
check('releases (and previews) count toward the publisher\'s storage', usage === versions + releases + auto && releases > 0, `${usage} vs ${versions} + ${releases} + ${auto}`);

// ---------- screenshots and screencasts ----------

const png = Buffer.from('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d49444154789c6360000002000154a24f5d0000000049454e44ae426082', 'hex');
const mp4 = Buffer.concat([Buffer.from('00000018667479706d703432', 'hex'), Buffer.alloc(64)]);
const upload = (body, type, q = '') => ada.go(`/v1/listings/${L}/media${q}`, { method: 'POST', headers: { 'x-brod-workspace': ada.workspace, 'content-type': type }, body })
  .then(r => ({ status: r.status, body: JSON.parse(r.body) }));
const shotUp = await upload(png, 'image/png', '?caption=Main%20screen');
const castUp = await upload(mp4, 'video/mp4');
check('a publisher adds a screenshot and a screencast', shotUp.status === 201 && shotUp.body.kind === 'image' && shotUp.body.caption === 'Main screen' && castUp.status === 201 && castUp.body.kind === 'video', JSON.stringify([shotUp.body, castUp.body]));
const html = await upload('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', 'image/png');
check('markup is refused whatever type it claims', html.status === 415 && html.body.error.code === 'bad_media', JSON.stringify(html.body));
const media = (await cy.api(`/v1/marketplace/${L}`)).body.media.filter(m => m.source === 'upload');
check('other workspaces see the previews in order', media?.length === 2 && media[0].kind === 'image' && media[1].kind === 'video', JSON.stringify(media));
const file = await cy.go(`${media[0].url}?workspace=${cy.workspace}`);
check('a preview is served as the image it is, never sniffed or run', file.status === 200 && file.headers['content-type'] === 'image/png' && file.headers['x-content-type-options'] === 'nosniff' && /sandbox/.test(file.headers['content-security-policy']), JSON.stringify(file.headers));
check('previews count toward the publisher\'s storage', (await ada.api('/v1/usage')).body.storage.total === versions + releases + auto + png.length + mp4.length);
check('only the publisher can add previews', (await cy.go(`/v1/listings/${L}/media`, { method: 'POST', headers: { 'x-brod-workspace': cy.workspace, 'content-type': 'image/png' }, body: png })).status === 403);
const rm = await ada.api(`/v1/listings/${L}/media/${castUp.body.id}`, { method: 'DELETE' });
check('a preview can be removed', rm.status === 200 && (await ada.api(`/v1/marketplace/${L}`)).body.media.filter(m => m.source === 'upload').length === 1);
check('previews are not part of what installs copy', (await cy.api(`/v1/apps/${APP}`)).body.versions.every(v => v.files === 2));

const un = await ada.api(`/v1/listings/${L}`, { method: 'PATCH', json: { status: 'unlisted' } });
check('unlisting hides it from the marketplace', un.body.status === 'unlisted' && !(await cy.api('/v1/marketplace')).body.listings.some(l => l.listing === L));
check('and stops new installs', (await cy.api(`/v1/marketplace/${L}/install`, { json: {} })).status === 404);
check('installed copies stay linked', (await cy.api(`/v1/apps/${APP}`)).body.marketplace?.listing === L);
check('the publisher still sees it in their listings', (await ada.api('/v1/listings')).body.listings.some(l => l.listing === L && l.status === 'unlisted'));

const del = await ada.api(`/v1/listings/${L}`, { method: 'DELETE' });
st = (await cy.api(`/v1/apps/${APP}`)).body;
check('deleting the listing unlinks installed copies, which keep running', del.status === 200 && !st.marketplace && st.live_version === 1 && (await send(inst.body.url + '/')).body.includes('notes one'), JSON.stringify(st.marketplace));
check('and frees the publisher\'s storage', (await ada.api('/v1/usage')).body.storage.total === versions);

// Unlinking by hand: install again from a fresh listing, then stop following it.
const L2 = (await ada.api('/v1/listings', { json: { app: SRC } })).body.listing;
const again = (await cy.api(`/v1/marketplace/${L2}/install`, { json: { name: 'My notes' } })).body;
check('an install can be given its own name', again.name === 'My notes' && again.marketplace.listing === L2, JSON.stringify(again));
const unl = await cy.api(`/v1/apps/${again.app}/marketplace`, { method: 'DELETE' });
check('an installed app can stop following its listing', unl.status === 200 && !(await cy.api(`/v1/apps/${again.app}`)).body.marketplace);
await ada.api(`/v1/apps/${SRC}`, { method: 'DELETE' });
const orphan = (await ada.api('/v1/listings')).body.listings.find(l => l.listing === L2);
check('deleting the source app keeps its published releases', orphan && orphan.app === null && orphan.latest_release === 1, JSON.stringify(orphan));
check('so it can still be installed', (await cy.api(`/v1/marketplace/${L2}/install`, { json: {} })).status === 201);

// ---------- settings: the maker declares them, each installer fills them in ----------

const manifest = { settings: [
  { key: 'name', label: 'Cafe name', type: 'text', default: 'The Corner Cafe' },
  { key: 'logo', label: 'Logo', type: 'image', default: 'logo.png' },
  { key: 'accent', label: 'Accent colour', type: 'color', default: '#1F6F4A' },
  { key: 'tables', label: 'Tables', type: 'number', min: 1, max: 40, default: 8 },
] };
const cafe = (m) => [{ path: 'index.html', content: '<h1>Cafe</h1>' }, { path: 'logo.png', content: 'not really a png' }, { path: 'brod.json', content: JSON.stringify(m) }];
const badManifest = await ada.api('/v1/deploys', { json: { name: `Cafe bad ${run}`, files: cafe({ settings: [{ key: 'Name!' }] }) } });
check('a brod.json Brod cannot use is refused at deploy', badManifest.status === 400 && badManifest.body.error.code === 'bad_settings', JSON.stringify(badManifest.body));
const cafeApp = (await ada.api('/v1/deploys', { json: { name: `Cafe ${run}`, files: cafe(manifest) } })).body;
const own = (await ada.api(`/v1/apps/${cafeApp.app}`)).body.settings;
check('an app\'s settings are what its brod.json declares, with their defaults', own?.length === 4 && own[0].value === 'The Corner Cafe' && own[2].value === '#1f6f4a' && own.every(x => !x.customised), JSON.stringify(own));
const LC = (await ada.api('/v1/listings', { json: { app: cafeApp.app, summary: 'A menu for your cafe' } })).body.listing;
const shown = (await cy.api(`/v1/marketplace/${LC}`)).body.settings;
check('the marketplace shows what an installer can customise', shown?.map(x => x.key).join() === 'name,logo,accent,tables', JSON.stringify(shown));

// Make room in the installer's free plan: the copies from the sections above are done with.
for (const a of (await cy.api('/v1/apps')).body.apps) await cy.api(`/v1/apps/${a.app}`, { method: 'DELETE' });
const appsBefore = (await cy.api('/v1/apps')).body.apps.length;
const wrong = await cy.api(`/v1/marketplace/${LC}/install`, { json: { settings: { accent: 'green' } } });
const unknown = await cy.api(`/v1/marketplace/${LC}/install`, { json: { settings: { colour: '#fff' } } });
check('an install with a value that does not fit is refused before anything is deployed',
  wrong.body?.error?.code === 'bad_setting' && unknown.body?.error?.code === 'unknown_setting' && (await cy.api('/v1/apps')).body.apps.length === appsBefore, JSON.stringify([wrong.body, unknown.body]));
const mine = await cy.api(`/v1/marketplace/${LC}/install`, { json: { name: 'Cy cafe', settings: { name: 'Cy\'s Coffee', accent: '#C0FFEE', tables: '12' } } });
const CAFE = mine.body?.app;
check('the installer names and colours their copy as they install it', mine.status === 201 && mine.body.settings.find(x => x.key === 'name').value === 'Cy\'s Coffee' && mine.body.settings.find(x => x.key === 'accent').customised, JSON.stringify(mine.body));
await served(cy, CAFE, mine.body.url);
let values = JSON.parse((await send(mine.body.url + '/_brod/settings')).body);
check('the app reads its settings at /_brod/settings, defaults filled in', values.name === 'Cy\'s Coffee' && values.accent === '#c0ffee' && values.tables === 12 && values.logo === '/logo.png', JSON.stringify(values));
check('the maker\'s own copy keeps its own values', JSON.parse((await served(ada, cafeApp.app, cafeApp.url).then(() => send(cafeApp.url + '/_brod/settings'))).body).name === 'The Corner Cafe');
check('client.js offers Brod.settings()', (await send(mine.body.url + '/_brod/client.js')).body.includes('settings()'));

const patched = await cy.api(`/v1/apps/${CAFE}/settings`, { method: 'PATCH', json: { tables: 41 } });
check('a value out of range is refused', patched.body?.error?.code === 'bad_setting', JSON.stringify(patched.body));
await cy.api(`/v1/apps/${CAFE}/settings`, { method: 'PATCH', json: { name: null, tables: 20 } });
values = JSON.parse((await send(mine.body.url + '/_brod/settings')).body);
check('settings change without a deploy, and null puts one back to its default', values.name === 'The Corner Cafe' && values.tables === 20 && (await cy.api(`/v1/apps/${CAFE}`)).body.versions.length === 1, JSON.stringify(values));

const usedBefore = (await cy.api('/v1/usage')).body.storage.total;
const logoUp = await cy.go(`/v1/apps/${CAFE}/settings/logo`, { method: 'PUT', headers: { 'x-brod-workspace': cy.workspace, 'content-type': 'image/png' }, body: png });
const svgUp = await cy.go(`/v1/apps/${CAFE}/settings/logo`, { method: 'PUT', headers: { 'x-brod-workspace': cy.workspace, 'content-type': 'image/png' }, body: '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>' });
check('an installer uploads their own logo; markup is refused', logoUp.status === 200 && svgUp.status === 415, `${logoUp.status} ${svgUp.status}`);
values = JSON.parse((await send(mine.body.url + '/_brod/settings')).body);
const logo = await send(mine.body.url + values.logo);
check('the logo is served from the app\'s own address, as the image it is', values.logo.startsWith('/_brod/settings/logo?v=') && logo.status === 200 && logo.headers['content-type'] === 'image/png' && logo.headers['x-content-type-options'] === 'nosniff', `${values.logo} ${logo.status}`);
check('an uploaded logo counts toward the installer\'s storage', (await cy.api('/v1/usage')).body.storage.total === usedBefore + png.length);
await cy.api(`/v1/apps/${CAFE}/settings/logo`, { method: 'DELETE' });
values = JSON.parse((await send(mine.body.url + '/_brod/settings')).body);
check('removing it goes back to the logo the app ships with, and frees the storage', values.logo === '/logo.png' && (await cy.api('/v1/usage')).body.storage.total === usedBefore && (await send(mine.body.url + '/_brod/settings/logo')).status === 404);
check('settings changes are in the activity log', (await cy.api('/v1/events?action=settings_changed')).body.events.some(e => e.app === CAFE));
await cy.api(`/v1/apps/${CAFE}/access`, { json: { access: 'private' } });
check('a private app\'s settings are for the people who can open it', (await send(mine.body.url + '/_brod/settings')).status !== 200);

if (SERVER_APPS) {
  const shop = `export default { fetch(req, env) { return Response.json(env.SETTINGS); } };`;
  const sv = (await cy.api('/v1/deploys', { json: { name: `Shop ${run}`, files: [{ path: '_worker.js', content: shop }, { path: 'brod.json', content: JSON.stringify({ settings: [{ key: 'greeting', default: 'Hello' }] }) }] } })).body;
  await cy.api(`/v1/apps/${sv.app}/access`, { json: { access: 'public' } });
  const first = JSON.parse((await send(sv.url + '/')).body);
  await cy.api(`/v1/apps/${sv.app}/settings`, { method: 'PATCH', json: { greeting: 'Namaste' } });
  const second = JSON.parse((await send(sv.url + '/')).body);
  check('server code reads its settings as env.SETTINGS, and sees a change on its next request', first.greeting === 'Hello' && second.greeting === 'Namaste', JSON.stringify([first, second]));
  await cy.api(`/v1/apps/${sv.app}`, { method: 'DELETE' });
}

// ---------- network: an app may only send data where it declares, and installers approve that ----------

// Run with BROD_NETWORK=enforce to check that undeclared requests are refused rather than only recorded.
const ENFORCE = process.env.BROD_NETWORK === 'enforce';
const CSP = ENFORCE ? 'content-security-policy' : 'content-security-policy-report-only';
const net = (hosts, text = 'shop') => [{ path: 'index.html', content: `<h1>${text}</h1>` }, { path: 'brod.json', content: JSON.stringify({ network: hosts }) }];
const badNet = await ada.api('/v1/deploys', { json: { name: `Net bad ${run}`, files: net(['https://api.example.com/v1']) } });
check('a network list Brod cannot use is refused at deploy', badNet.status === 400 && badNet.body.error.code === 'bad_network', JSON.stringify(badNet.body));
const shopApp = (await ada.api('/v1/deploys', { json: { name: `Pay ${run}`, files: net(['api.pay.test']) } })).body;
await ada.api(`/v1/apps/${shopApp.app}/access`, { json: { access: 'public' } });
const shopPage = await send(shopApp.url + '/');
const policy = shopPage.headers[CSP] ?? '';
check(`an app's pages carry a policy naming only its own address and its declared hosts (${ENFORCE ? 'enforced' : 'report-only while logging'})`,
  /connect-src 'self' https:\/\/api\.pay\.test wss:\/\/api\.pay\.test;/.test(policy) && /report-uri \/_brod\/csp/.test(policy) && !shopPage.headers[ENFORCE ? 'content-security-policy-report-only' : 'content-security-policy'], policy);
const plainPolicy = (await send(cafeApp.url + '/')).headers[CSP] ?? '';
check('an app that declares nothing may only reach its own address', /connect-src 'self';/.test(plainPolicy), plainPolicy);
const report = JSON.stringify({ 'csp-report': { 'blocked-uri': 'https://collector.evil.test/x?d=secret', disposition: ENFORCE ? 'enforce' : 'report' } });
await send(shopApp.url + '/_brod/csp', { method: 'POST', headers: { 'content-type': 'application/csp-report' }, body: report });
let netStatus = (await ada.api(`/v1/apps/${shopApp.app}`)).body.network;
const rec = netStatus.undeclared.find(r => r.host === 'collector.evil.test');
check('the browser\'s reports of undeclared hosts are shown to the app\'s owners', netStatus.policy === (ENFORCE ? 'enforce' : 'log') && netStatus.declared.join() === 'api.pay.test' && rec?.source === 'browser' && rec.blocked === ENFORCE, JSON.stringify(netStatus));

const LN = (await ada.api('/v1/listings', { json: { app: shopApp.app } })).body.listing;
const netListing = (await cy.api(`/v1/marketplace/${LN}`)).body;
check('the marketplace tells installers where an app sends data, and whether Brod enforces it', netListing.network?.join() === 'api.pay.test' && netListing.network_policy === (ENFORCE ? 'enforce' : 'log'), JSON.stringify(netListing));
const noAccept = await cy.api(`/v1/marketplace/${LN}/install`, { json: {} });
check('installing it needs a person to approve those hosts first', noAccept.status === 409 && noAccept.body.error.code === 'accept_network' && noAccept.body.error.network?.[0] === 'api.pay.test', JSON.stringify(noAccept.body));
const cyTok = (await cy.api('/v1/tokens', { json: { name: 'agent' } })).body.token;
const agentAccept = await send(`${API}/v1/marketplace/${LN}/install`, { method: 'POST', headers: { authorization: `Bearer ${cyTok}`, 'content-type': 'application/json' }, body: JSON.stringify({ accept_network: true }) });
check('an agent cannot approve them for the workspace', agentAccept.status === 403 && JSON.parse(agentAccept.body).error.code === 'network_needs_a_person', agentAccept.body);
const okInstall = await cy.api(`/v1/marketplace/${LN}/install`, { json: { accept_network: true } });
check('once approved it installs, and says where it sends data', okInstall.status === 201 && okInstall.body.network?.join() === 'api.pay.test', JSON.stringify(okInstall.body));

await ada.api('/v1/deploys', { json: { app: shopApp.app, environment: 'production', files: net(['api.pay.test', '*.track.test'], 'shop two') } });
await ada.api(`/v1/listings/${LN}/releases`, { json: { note: 'Adds tracking' } });
const offered = (await cy.api(`/v1/apps/${okInstall.body.app}`)).body.marketplace;
check('an update that sends data somewhere new says so', offered.update_available && offered.network_added?.join() === '*.track.test', JSON.stringify(offered));
const upNo = await cy.api(`/v1/apps/${okInstall.body.app}/marketplace/update`, { json: {} });
const upYes = await cy.api(`/v1/apps/${okInstall.body.app}/marketplace/update`, { json: { accept_network: true } });
check('and is deployed only once a person approves the new host', upNo.body?.error?.code === 'accept_network' && upYes.status === 200 && upYes.body.marketplace.release === 2, JSON.stringify([upNo.body, upYes.body?.marketplace]));

if (SERVER_APPS) {
  const leaky = `export default { async fetch(req, env) {
    const r = await fetch('http://127.0.0.1:9/collect?d=1').then(r => r.status, e => 'failed');
    return new Response('tried: ' + r);
  } };`;
  const lk = (await cy.api('/v1/deploys', { json: { name: `Leaky ${run}`, files: [{ path: '_worker.js', content: leaky }] } })).body;
  await cy.api(`/v1/apps/${lk.app}/access`, { json: { access: 'public' } });
  const tried = (await send(lk.url + '/')).body;
  let seenLeak;
  for (let i = 0; i < 40 && !seenLeak; i++) {
    seenLeak = (await cy.api(`/v1/apps/${lk.app}`)).body.network.undeclared.find(r => r.host === '127.0.0.1' && r.source === 'server');
    if (!seenLeak) await new Promise(r => setTimeout(r, 250));
  }
  check(`server code reaching a host it does not declare is ${ENFORCE ? 'refused' : 'recorded'}`, seenLeak && seenLeak.blocked === ENFORCE && (!ENFORCE || tried === 'tried: 403'), `${tried} ${JSON.stringify(seenLeak)}`);
  await cy.api(`/v1/apps/${lk.app}`, { method: 'DELETE' });
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
