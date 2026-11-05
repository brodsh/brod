// SPDX-License-Identifier: AGPL-3.0-only
// The shield: bot and flood protection in front of every app (shield.enabled, BROD_SHIELD, on by default).
//
// Each request to an app gets a `Guard` before anything else is done for it. The guard classifies the request
// (traffic.rs) and, with the shield on:
//   * tarpits and refuses (403) an address blocked as a scanner: one refused `shield.scanner_probes` probe paths
//     (/wp-login.php, /.env, ...) within ten minutes, blocked for `shield.block_minutes`;
//   * answers 429 once an address made more than `shield.requests_per_minute` requests to apps this minute (the
//     same in-memory windows abuse.rs keeps for API calls);
//   * makes a page load pass a proof-of-work check when it is suspicious (`shield.challenge_suspicious`) or its
//     address made more than `shield.challenge_per_minute` requests this minute. The check is a small page whose
//     script finds a number that gives a SHA-256 hash with `shield.challenge_bits` leading zero bits, then posts it
//     to /_brod/challenge; a right answer sets a signed cookie, bound to the address, that lets the client through
//     for `shield.pass_hours`. No third-party service is involved.
//
// Never checked: people signed in to the app, open paths (webhooks and other machine callers), anything other than
// a page load (scripts, images, fetch() calls from the app's own pages), Brod's own /_brod/ endpoints (the insights
// script, its beacon, health and sign-in), bots that say what they are, and loopback and private-network addresses.
// The REST API and MCP never pass through here: they have their own limits per connection (abuse.rs).
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::http::Method;
use axum::response::Response;
use sha2::{Digest, Sha256};

use crate::http::{Req, header_pairs, notice, page, redirect, response};
use crate::problem::Result;
use crate::state::State;
use crate::traffic::{Class, Facts, Limits, Seen, Verdict};
use crate::util::{b64url, esc, hmac_b64url, now, random_bytes, safe_equal, set_cookie};

pub const REQUESTS_PER_MINUTE: i64 = 1200;
pub const CHALLENGE_PER_MINUTE: i64 = 300;
pub const CHALLENGE_BITS: i64 = 16;
/// The cookie a client gets for passing the check (with __Host- on https).
pub const PASS_COOKIE: &str = "brod_pass";
/// How long a client has to solve a check.
pub const CHALLENGE_TTL: i64 = 10 * 60_000;
/// How long a blocked scanner waits for its 403, and how many may wait at once (more get it at once).
const TARPIT: Duration = Duration::from_secs(3);
const MAX_TARPITS: usize = 64;
static TARPITS: AtomicUsize = AtomicUsize::new(0);

/// The shield's settings, read once per request.
#[derive(Clone, Copy, Debug)]
pub struct Opts {
    pub enabled: bool,
    pub requests_per_minute: u32,
    pub challenge_per_minute: u32,
    pub challenge_suspicious: bool,
    pub bits: u32,
    pub pass_ms: i64,
    pub block_ms: i64,
    pub limits: Limits,
}

impl Opts {
    pub fn from_settings(s: &crate::instance::Settings) -> Opts {
        let n = |k: &str| u32::try_from(s.int(k).max(0)).unwrap_or(u32::MAX);
        Opts {
            enabled: s.flag("shield.enabled"),
            requests_per_minute: n("shield.requests_per_minute"),
            challenge_per_minute: n("shield.challenge_per_minute"),
            challenge_suspicious: s.flag("shield.challenge_suspicious"),
            bits: n("shield.challenge_bits").clamp(8, 24),
            pass_ms: s.int("shield.pass_hours").max(1) * 3_600_000,
            block_ms: s.int("shield.block_minutes").max(1) * 60_000,
            limits: Limits::from_settings(s),
        }
    }
}

/// Loopback, private, link-local and unique-local addresses: a LAN, or a proxy in front of Brod that it was not
/// told to trust (BROD_TRUST_PROXY), so one address may be everyone. They are classified but never refused.
pub fn is_internal(ip_key: &str) -> bool {
    let ip = ip_key.strip_suffix("/64").unwrap_or(ip_key).parse::<IpAddr>();
    match ip {
        Ok(IpAddr::V4(a)) => a.is_loopback() || a.is_private() || a.is_link_local() || a.is_unspecified(),
        Ok(IpAddr::V6(a)) => a.is_loopback() || a.is_unique_local() || a.is_unicast_link_local() || a.is_unspecified(),
        Err(_) => true,
    }
}

/// One request to an app, as the shield sees it.
pub struct Guard {
    /// The client's address as a rate-limit key (abuse::ip_key), when known.
    pub ip: Option<String>,
    pub opts: Opts,
    /// The shield is on and the address is one it may refuse.
    enforce: bool,
    pub facts: Facts,
    pub seen: Seen,
    /// Requests from the address to apps this minute, this one included.
    pub per_minute: u32,
    /// The client carries a valid pass from an earlier check.
    pub passed: bool,
    /// The request's class; `settle` refines it once the app and visitor are known.
    pub verdict: Verdict,
    at: i64,
}

impl Guard {
    pub async fn new(st: &State, req: &Req) -> Guard {
        let opts = Opts::from_settings(&*crate::instance::current(st).await);
        let at = now();
        let ip = crate::abuse::client_ip(&st.cfg, req);
        let facts = Facts::of(req);
        let view = crate::usage::is_page_view(req) || facts.probe;
        let (mut seen, mut per_minute, mut passed) = (Seen::default(), 0, false);
        // Everyone behind a LAN or an untrusted proxy shares its address, so what that address did says nothing about
        // one visitor: internal addresses are neither tracked nor judged by their history.
        let tracked = ip.as_deref().is_some_and(|i| !is_internal(i));
        if let Some(ip) = &ip {
            if tracked {
                seen = st.traffic.seen(ip, at, view);
            }
            // The insights beacon reports what a page already did; it is not counted against the address.
            if req.path != "/_brod/insights" {
                per_minute = st.app_requests.count(&format!("ip:{ip}"), at);
            }
            let pass = crate::util::cookie(req.header("cookie"), &req.origin(), PASS_COOKIE);
            passed = !pass.is_empty() && pass_valid(&st.cfg.identity_secret, ip, &pass, at);
        }
        let enforce = opts.enabled && tracked;
        let verdict = crate::traffic::classify(&facts, &seen, passed.then_some("js"), &opts.limits);
        Guard { ip, opts, enforce, facts, seen, per_minute, passed, verdict, at }
    }

    /// Classify again now that it is known whether the visitor is signed in or proved it runs JavaScript.
    pub fn settle(&mut self, verified: Option<&'static str>) {
        if verified.is_some() && !self.passed {
            self.verdict = crate::traffic::classify(&self.facts, &self.seen, verified, &self.opts.limits);
        }
    }

    /// A blocked scanner's or a flooding address's answer, before any work is done for the request.
    pub async fn refuse(&self) -> Option<Response> {
        if !self.enforce {
            return None;
        }
        if self.seen.blocked_until > self.at {
            if TARPITS.fetch_add(1, Ordering::SeqCst) < MAX_TARPITS {
                tokio::time::sleep(TARPIT).await;
            }
            TARPITS.fetch_sub(1, Ordering::SeqCst);
            let retry = ((self.seen.blocked_until - self.at) / 1000).max(1);
            return Some(response(
                403,
                "Blocked: this address asked for too many paths that only vulnerability scanners ask for.\n",
                &[
                    ("content-type", "text/plain; charset=utf-8".into()),
                    ("cache-control", "no-store".into()),
                    ("retry-after", retry.to_string()),
                ],
            ));
        }
        if self.per_minute > self.opts.requests_per_minute {
            let retry = (60 - (self.at / 1000) % 60).max(1);
            let mut res = notice(
                429,
                "Too many requests",
                "This address sent too many requests in the last minute. Wait a moment and try again.",
                "",
            );
            header_pairs(&mut res, &[("retry-after", retry.to_string())]);
            return Some(res);
        }
        None
    }

    /// The proof-of-work page, when this page load must pass the check first.
    pub fn challenge(&self, st: &State, req: &Req, signed_in: bool) -> Option<Response> {
        if !self.enforce || signed_in || self.passed || req.method != Method::GET || !crate::usage::is_page_view(req) {
            return None;
        }
        let reasons: Vec<&str> = self.verdict.reason.split(',').collect();
        // A bot that says what it is (a search engine, an uptime check) cannot run the check; the request limit
        // still applies to it. Probes and scanners are left to the app's 404s and the block.
        let hard = ["ua", "no_ua", "probe", "scanner"].iter().any(|r| reasons.contains(r));
        let odd = match self.verdict.class {
            Class::Human => false,
            Class::Suspicious | Class::Bot => !hard && self.opts.challenge_suspicious,
        };
        let busy = self.opts.challenge_per_minute > 0 && self.per_minute > self.opts.challenge_per_minute && !reasons.contains(&"ua");
        if !odd && !busy {
            return None;
        }
        let ip = self.ip.as_deref()?;
        let ret = if req.query.is_empty() { req.path.clone() } else { format!("{}?{}", req.path, req.query) };
        Some(challenge_page(&make_token(&st.cfg.identity_secret, ip, self.opts.bits, self.at), &ret))
    }

    /// Count the finished request for its address; block the address when it turned out to be scanning.
    pub fn done(&self, st: &State, status: u16) {
        let Some(ip) = self.ip.as_ref().filter(|i| !is_internal(i)) else { return };
        let probes = if self.enforce { self.opts.limits.scanner_probes } else { 0 };
        if st.traffic.done(ip, now(), status, self.facts.probe, probes, self.opts.block_ms) {
            tracing::warn!(ip = %ip, minutes = self.opts.block_ms / 60_000, "blocked an address that scans apps for vulnerable paths");
        }
    }
}

// ---------- the check ----------

/// POST /_brod/challenge on an app: token, nonce and return from the check's form. A right answer gets the pass
/// cookie and goes back to the page it was asked for; anything else gets a new check.
pub async fn answer(st: &State, req: &mut Req, visitor: &str) -> Result<Response> {
    if req.method != Method::POST {
        return Ok(redirect("/", &[]));
    }
    let body = req.bytes(4096, "The answer").await?;
    let form: Vec<(String, String)> = form_urlencoded::parse(&body).map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
    let get = |k: &str| form.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let ret = crate::gateway::app_return(get("return"));
    let Some(ip) = crate::abuse::client_ip(&st.cfg, req) else { return Ok(redirect(&ret, &[])) };
    let opts = Opts::from_settings(&*crate::instance::current(st).await);
    let (secret, at) = (&st.cfg.identity_secret, now());
    if !verify_solution(secret, &ip, &get("token").unwrap_or_default(), &get("nonce").unwrap_or_default(), at) {
        return Ok(challenge_page(&make_token(secret, &ip, opts.bits, at), &ret));
    }
    st.traffic.verify(visitor, at);
    let cookie = set_cookie(&req.origin(), PASS_COOKIE, &pass_value(secret, &ip, at, opts.pass_ms), opts.pass_ms / 1000);
    Ok(redirect(&ret, &[("set-cookie", cookie)]))
}

fn signed(secret: &str, what: &str, ip: &str, data: &str) -> String {
    hmac_b64url(secret, &format!("brod-shield:{what}:{ip}:{data}"))
}

/// A check for `ip`: "`<expires>`.`<random>`.`<bits>`.`<signature>`". The client must find a number n for which
/// SHA-256("`<token>`:`<n>`") starts with `bits` zero bits.
pub fn make_token(secret: &str, ip: &str, bits: u32, at: i64) -> String {
    let data = format!("{}.{}.{bits}", at + CHALLENGE_TTL, b64url(&random_bytes(12)));
    format!("{data}.{}", signed(secret, "challenge", ip, &data))
}

pub fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut n = 0;
    for b in hash {
        if *b == 0 {
            n += 8;
        } else {
            return n + b.leading_zeros();
        }
    }
    n
}

/// Whether `nonce` solves `token` for `ip` at `at`: signed by this server for this address, not expired, and hard
/// enough (at least 8 bits, whatever the token says).
pub fn verify_solution(secret: &str, ip: &str, token: &str, nonce: &str, at: i64) -> bool {
    let Some((data, sig)) = token.rsplit_once('.') else { return false };
    let mut parts = data.split('.');
    let (Some(exp), Some(_), Some(bits), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else { return false };
    let (Ok(exp), Ok(bits)) = (exp.parse::<i64>(), bits.parse::<u32>()) else { return false };
    if exp <= at || exp > at + CHALLENGE_TTL || !(8..=32).contains(&bits) || nonce.is_empty() || nonce.len() > 20 {
        return false;
    }
    if !safe_equal(sig, &signed(secret, "challenge", ip, data)) {
        return false;
    }
    leading_zero_bits(&Sha256::digest(format!("{token}:{nonce}").as_bytes())) >= bits
}

/// The cookie value for a client at `ip` that passed: "`<expires>`.`<signature>`".
pub fn pass_value(secret: &str, ip: &str, at: i64, ttl_ms: i64) -> String {
    let exp = (at + ttl_ms).to_string();
    format!("{exp}.{}", signed(secret, "pass", ip, &exp))
}

pub fn pass_valid(secret: &str, ip: &str, value: &str, at: i64) -> bool {
    let Some((exp, sig)) = value.split_once('.') else { return false };
    exp.parse::<i64>().is_ok_and(|e| e > at) && safe_equal(sig, &signed(secret, "pass", ip, exp))
}

/// The check's page. Its script is plain JavaScript with its own SHA-256, so it also works where WebCrypto does
/// not (plain http on a LAN address); it hashes in slices so the page stays responsive.
fn challenge_page(token: &str, ret: &str) -> Response {
    let body = format!(
        r#"<h1>Checking your browser</h1>
<p class="muted" id="brod-check">This takes a moment, and only happens once in a while.</p>
<noscript><p>Turn on JavaScript to open this page.</p></noscript>
<form id="brod-pass" method="post" action="/_brod/challenge">
<input type="hidden" name="token" value="{token}"><input type="hidden" name="nonce" value="">
<input type="hidden" name="return" value="{ret}"><noscript><button type="submit" disabled>Continue</button></noscript>
</form>
<script>{CHALLENGE_JS}</script>"#,
        token = esc(token),
        ret = esc(ret),
    );
    page(403, "Checking your browser", &body, None, &[("x-brod-challenge", "1".into())])
}

const CHALLENGE_JS: &str = r#"(function () {
  var f = document.getElementById('brod-pass'), token = f.token.value, bits = +token.split('.')[2];
  var K = [], H = [], n = 2, c = 0;
  while (c < 64) {
    var p = true;
    for (var d = 2; d * d <= n; d++) if (n % d === 0) { p = false; break; }
    if (p) { if (c < 8) H[c] = (Math.pow(n, 1 / 2) * 4294967296) | 0; K[c] = (Math.pow(n, 1 / 3) * 4294967296) | 0; c++; }
    n++;
  }
  function rot(x, k) { return (x >>> k) | (x << (32 - k)); }
  function first(s) {
    var l = s.length * 8, w = [], i, j;
    s += '\x80';
    while (s.length % 64 !== 56) s += '\x00';
    for (i = 0; i < s.length; i++) w[i >> 2] |= s.charCodeAt(i) << ((3 - (i % 4)) * 8);
    w.push((l / 4294967296) | 0, l | 0);
    var h = H.slice(0, 8);
    for (j = 0; j < w.length; j += 16) {
      var m = w.slice(j, j + 16), a = h[0], b = h[1], cc = h[2], dd = h[3], e = h[4], ff = h[5], g = h[6], hh = h[7];
      for (i = 0; i < 64; i++) {
        if (i >= 16) {
          var x = m[i - 15], y = m[i - 2];
          m[i] = (m[i - 16] + (rot(x, 7) ^ rot(x, 18) ^ (x >>> 3)) + m[i - 7] + (rot(y, 17) ^ rot(y, 19) ^ (y >>> 10))) | 0;
        }
        var t1 = (hh + (rot(e, 6) ^ rot(e, 11) ^ rot(e, 25)) + ((e & ff) ^ (~e & g)) + K[i] + (m[i] | 0)) | 0;
        var t2 = ((rot(a, 2) ^ rot(a, 13) ^ rot(a, 22)) + ((a & b) ^ (a & cc) ^ (b & cc))) | 0;
        hh = g; g = ff; ff = e; e = (dd + t1) | 0; dd = cc; cc = b; b = a; a = (t1 + t2) | 0;
      }
      h = [(h[0] + a) | 0, (h[1] + b) | 0, (h[2] + cc) | 0, (h[3] + dd) | 0, (h[4] + e) | 0, (h[5] + ff) | 0, (h[6] + g) | 0, (h[7] + hh) | 0];
    }
    return h[0] >>> 0;
  }
  var nonce = 0, limit = Math.pow(2, 32 - bits);
  (function step() {
    for (var k = 0; k < 4000; k++, nonce++) {
      if (first(token + ':' + nonce) < limit) { f.nonce.value = String(nonce); f.submit(); return; }
    }
    setTimeout(step, 0);
  })();
})();"#;

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_KEY: &str = "test-secret";

    fn solve(token: &str, bits: u32) -> String {
        (0u64..).map(|n| n.to_string()).find(|n| leading_zero_bits(&Sha256::digest(format!("{token}:{n}").as_bytes())) >= bits).unwrap()
    }

    #[test]
    fn counts_leading_zero_bits() {
        assert_eq!(leading_zero_bits(&[0xff]), 0);
        assert_eq!(leading_zero_bits(&[0x00, 0x01]), 15);
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x80]), 16);
        assert_eq!(leading_zero_bits(&[0x00, 0x00]), 16);
    }

    #[test]
    fn a_solved_check_verifies_only_for_its_address_until_it_expires() {
        let at = 1_000_000;
        let token = make_token(SECRET_KEY, "1.2.3.4", 10, at);
        let nonce = solve(&token, 10);
        assert!(verify_solution(SECRET_KEY, "1.2.3.4", &token, &nonce, at + 1000));
        // Another address, another server's secret, a wrong answer, or too late: no.
        assert!(!verify_solution(SECRET_KEY, "5.6.7.8", &token, &nonce, at + 1000));
        assert!(!verify_solution("other", "1.2.3.4", &token, &nonce, at + 1000));
        assert!(!verify_solution(SECRET_KEY, "1.2.3.4", &token, "", at + 1000));
        assert!(!verify_solution(SECRET_KEY, "1.2.3.4", &token, &nonce, at + CHALLENGE_TTL));
        // A token whose difficulty was lowered no longer matches its signature.
        let easier = token.replacen(".10.", ".8.", 1);
        assert!(!verify_solution(SECRET_KEY, "1.2.3.4", &easier, &solve(&easier, 8), at + 1000));
        // A forged token with too little work is refused even if signed.
        let data = format!("{}.x.4", at + 1000);
        let weak = format!("{data}.{}", signed(SECRET_KEY, "challenge", "1.2.3.4", &data));
        assert!(!verify_solution(SECRET_KEY, "1.2.3.4", &weak, &solve(&weak, 4), at));
        assert!(!verify_solution(SECRET_KEY, "1.2.3.4", "garbage", "1", at));
    }

    #[test]
    fn a_pass_is_signed_bound_to_the_address_and_expires() {
        let v = pass_value(SECRET_KEY, "1.2.3.4", 0, 3_600_000);
        assert!(pass_valid(SECRET_KEY, "1.2.3.4", &v, 3_599_999));
        assert!(!pass_valid(SECRET_KEY, "1.2.3.4", &v, 3_600_000));
        assert!(!pass_valid(SECRET_KEY, "1.2.3.5", &v, 0));
        assert!(!pass_valid("other", "1.2.3.4", &v, 0));
        let (_, sig) = v.split_once('.').unwrap();
        assert!(!pass_valid(SECRET_KEY, "1.2.3.4", &format!("99999999999999.{sig}"), 0));
        assert!(!pass_valid(SECRET_KEY, "1.2.3.4", "", 0));
    }

    #[test]
    fn internal_addresses_are_never_refused() {
        for ip in ["127.0.0.1", "10.1.2.3", "192.168.0.4", "172.16.9.9", "fd00:1:2:3::/64", "fe80:0:0:0::/64", "::1"] {
            assert!(is_internal(ip), "{ip}");
        }
        for ip in ["8.8.8.8", "2a01:4f8:1:2::/64", "145.220.1.1"] {
            assert!(!is_internal(ip), "{ip}");
        }
    }
}
