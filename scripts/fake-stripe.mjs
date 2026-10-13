// A small in-memory stand-in for the parts of the Stripe API Brod uses: customers, prices, Checkout sessions,
// subscriptions, invoices and customer portal sessions. Opening a Checkout session's url "pays" it: the fake makes an
// active subscription and an invoice, sends checkout.session.completed and customer.subscription.created to the
// webhook signed the way Stripe signs them, then redirects to the session's success_url. Subscription changes send
// customer.subscription.updated. POST /_test/subscriptions/<id> (form fields) and DELETE /_test/subscriptions/<id>
// change or cancel one as a failed payment or the customer portal would, and tell the webhook.
// Usage: node scripts/fake-stripe.mjs [port] [webhook url]   (key: sk_test_fake, webhook secret: whsec_fake)
import { createHmac, randomBytes } from 'node:crypto';
import http from 'node:http';
import { fileURLToPath } from 'node:url';

export const SECRET_KEY = 'sk_test_fake', WEBHOOK_SECRET = 'whsec_fake';
export const PRICES = { price_solo: { unit_amount: 900, currency: 'eur' }, price_team: { unit_amount: 2900, currency: 'eur' } };

const id = (prefix) => `${prefix}_${randomBytes(8).toString('hex')}`;
const sec = () => Math.floor(Date.now() / 1000);
const json = (status, v) => ({ status, body: JSON.stringify(v), type: 'application/json' });

export function sign(payload, secret = WEBHOOK_SECRET, t = sec()) {
  return `t=${t},v1=${createHmac('sha256', secret).update(`${t}.${payload}`).digest('hex')}`;
}

export function fakeStripe(webhookUrl) {
  const customers = new Map(), sessions = new Map(), subs = new Map(), invoices = [];
  const delivered = [];
  let origin = '';

  async function emit(type, object) {
    const payload = JSON.stringify({ id: id('evt'), object: 'event', type, data: { object } });
    const r = await fetch(webhookUrl, { method: 'POST', headers: { 'content-type': 'application/json', 'stripe-signature': sign(payload) }, body: payload });
    delivered.push({ type, status: r.status });
    return r;
  }
  const subscription = (customer, price, metadata) => {
    const s = {
      id: id('sub'), object: 'subscription', customer, status: 'active', metadata, cancel_at_period_end: false, cancel_at: null,
      items: { data: [{ id: id('si'), price: { id: price }, current_period_end: sec() + 30 * 86400 }] },
    };
    subs.set(s.id, s);
    return s;
  };
  const invoice = (customer, price) => {
    const n = invoices.length + 1;
    invoices.unshift({ id: id('in'), number: `FAKE-${String(n).padStart(4, '0')}`, customer, status: 'paid', created: sec(),
      amount_paid: PRICES[price].unit_amount, amount_due: 0, currency: PRICES[price].currency,
      hosted_invoice_url: `${origin}/invoice/${n}`, invoice_pdf: `${origin}/invoice/${n}.pdf` });
  };

  async function handle(method, path, query, form, auth) {
    if (path.startsWith('/pay/')) {
      const s = sessions.get(path.slice(5));
      if (!s || s.status === 'complete') return json(404, { error: { message: 'No such session' } });
      s.status = 'complete';
      const sub = subscription(s.customer, s.price, s.metadata);
      s.subscription = sub.id;
      invoice(s.customer, s.price);
      await emit('checkout.session.completed', { id: s.id, object: 'checkout.session', customer: s.customer, subscription: sub.id, client_reference_id: s.client_reference_id });
      await emit('customer.subscription.created', sub);
      return { status: 303, location: s.success_url };
    }
    // Test controls, for scripts that run in another process: change or delete a subscription as Stripe would.
    const t = path.match(/^\/_test\/subscriptions\/([A-Za-z0-9_]+)$/);
    if (t && subs.has(t[1])) {
      const s = subs.get(t[1]);
      if (method === 'DELETE') { s.status = 'canceled'; subs.delete(t[1]); await emit('customer.subscription.deleted', s); return json(200, s); }
      Object.assign(s, Object.fromEntries(form)); await emit('customer.subscription.updated', s); return json(200, s);
    }
    if (path === '/_test/delivered') return json(200, delivered);
    if (path === '/_test/subscriptions') return json(200, [...subs.values()]);
    if (auth !== `Bearer ${SECRET_KEY}`) return json(401, { error: { message: 'Invalid API Key provided' } });
    const kind = ['checkout/sessions', 'billing_portal/sessions', 'customers', 'prices', 'subscriptions', 'invoices']
      .find(k => path === `/v1/${k}` || path.startsWith(`/v1/${k}/`));
    if (!kind) return json(404, { error: { message: `Unrecognized request URL (${method}: ${path})` } });
    const key = path.slice(`/v1/${kind}/`.length) || undefined;
    if (kind === 'customers' && method === 'POST') {
      const c = { id: id('cus'), object: 'customer', email: form.get('email'), name: form.get('name'), metadata: { workspace_id: form.get('metadata[workspace_id]') } };
      customers.set(c.id, c);
      return json(200, c);
    }
    if (kind === 'prices' && method === 'GET') {
      const p = PRICES[key];
      return p ? json(200, { id: key, object: 'price', ...p, recurring: { interval: 'month', interval_count: 1 } }) : json(404, { error: { message: `No such price: '${key}'` } });
    }
    if (kind === 'checkout/sessions' && method === 'POST') {
      const price = form.get('line_items[0][price]');
      if (!PRICES[price]) return json(400, { error: { message: `No such price: '${price}'` } });
      if (!customers.has(form.get('customer'))) return json(400, { error: { message: 'No such customer' } });
      const s = { id: id('cs'), object: 'checkout.session', mode: form.get('mode'), customer: form.get('customer'), price, status: 'open',
        client_reference_id: form.get('client_reference_id'), success_url: form.get('success_url'), cancel_url: form.get('cancel_url'),
        metadata: { workspace_id: form.get('subscription_data[metadata][workspace_id]') } };
      sessions.set(s.id, s);
      return json(200, { ...s, url: `${origin}/pay/${s.id}` });
    }
    if (kind === 'subscriptions' && key) {
      const s = subs.get(key);
      if (!s) return json(404, { error: { message: `No such subscription: '${key}'` } });
      if (method === 'GET') return json(200, s);
      if (method === 'POST') {
        if (form.has('items[0][price]')) {
          const price = form.get('items[0][price]');
          if (!PRICES[price]) return json(400, { error: { message: `No such price: '${price}'` } });
          s.items.data[0].price = { id: price };
          invoice(s.customer, price);
        }
        if (form.has('cancel_at_period_end')) {
          s.cancel_at_period_end = form.get('cancel_at_period_end') === 'true';
          s.cancel_at = s.cancel_at_period_end ? s.items.data[0].current_period_end : null;
        }
        await emit('customer.subscription.updated', s);
        return json(200, s);
      }
    }
    if (kind === 'invoices' && method === 'GET') {
      return json(200, { object: 'list', data: invoices.filter(i => i.customer === query.get('customer')).slice(0, Number(query.get('limit') ?? 10)) });
    }
    if (kind === 'billing_portal/sessions' && method === 'POST') {
      if (!customers.has(form.get('customer'))) return json(400, { error: { message: 'No such customer' } });
      return json(200, { id: id('bps'), object: 'billing_portal.session', url: `${origin}/portal?return=${encodeURIComponent(form.get('return_url'))}` });
    }
    return json(404, { error: { message: `Unrecognized request URL (${method}: ${path})` } });
  }

  return {
    customers, sessions, subs, invoices, delivered, emit,
    setOrigin(o) { origin = o; },
    handle,
  };
}

export function serveFakeStripe(webhookUrl, port = 0) {
  const stripe = fakeStripe(webhookUrl);
  const server = http.createServer(async (req, res) => {
    const chunks = []; for await (const c of req) chunks.push(c);
    const u = new URL(req.url, 'http://x');
    const r = await stripe.handle(req.method, u.pathname, u.searchParams, new URLSearchParams(Buffer.concat(chunks).toString()), req.headers.authorization);
    if (r.location) { res.writeHead(r.status, { location: r.location }); res.end(); return; }
    res.writeHead(r.status, { 'content-type': r.type }); res.end(r.body);
  });
  return new Promise(resolve => server.listen(port, '127.0.0.1', () => {
    const p = server.address().port;
    stripe.setOrigin(`http://127.0.0.1:${p}`);
    resolve({ server, port: p, stripe });
  }));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const { port } = await serveFakeStripe(process.argv[3] ?? 'http://localhost:8787/stripe/webhook', Number(process.argv[2] ?? 12111));
  console.log(`fake Stripe on http://127.0.0.1:${port} (${SECRET_KEY}, webhook secret ${WEBHOOK_SECRET})`);
}
