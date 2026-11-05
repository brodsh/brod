// SPDX-License-Identifier: AGPL-3.0-only
// Smart traffic: whether a request comes from a person, a bot, or something in between.
//
// Every request to an app gets a class, `human`, `suspicious` or `bot`, and the short reasons that decided it
// (stored with each page view, migrations/0028_traffic.sql). A user agent that says it is a bot is only one signal:
// most scanners send a browser's user agent, so the class also looks at
//   * the request itself: no User-Agent, no Accept-Language, no Accept, HTTP/1.0, and probe paths (/wp-login.php,
//     /.env, /.git/, /phpmyadmin, ...) that only scanners ask an app for;
//   * the address it comes from, over the last ten minutes (`Tracker`, in memory): its page views per minute, its
//     share of 4xx answers, and how many probe paths it was refused;
//   * whether the visitor ever proved it runs JavaScript: the insights script reported for it, it passed the
//     proof-of-work check (shield.rs), or it is signed in.
//
// The rules, in order:
//   1. bot: the user agent says so ("ua"), there is none ("no_ua"), the path is a probe ("probe"), or the address has
//      been refused `scanner_probes` probe paths ("scanner"). These hold even for a visitor that runs JavaScript.
//   2. human: the visitor proved it runs JavaScript or is signed in ("js", "signed_in").
//   3. suspicious, for any one of "no_lang", "no_accept", "http1.0", "burst" (more than `burst_views_per_minute`
//      page views a minute from the address) and "4xx" (at least half of 20 or more requests answered 4xx); bot
//      when three or more of these add up.
//   4. human otherwise.
// Reports read a stored `suspicious` view as human when its visitor's browser reported to the insights script later
// (analytics.rs), so a person whose first page looked odd still counts once their browser has proven itself.
use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use crate::http::Req;

const MINUTE: i64 = 60_000;
/// How long the tracker remembers an address's requests, 4xx answers and probes.
pub const WINDOW: i64 = 10 * MINUTE;
/// An address needs this many requests in the window before its share of 4xx answers says anything.
pub const RATIO_MIN_REQUESTS: u32 = 20;
/// Suspicious signals that, together, make a request a bot's.
pub const BOT_SIGNALS: usize = 3;
/// Addresses and visitors the tracker keeps at most; past that it forgets the quiet ones first.
const MAX_ENTRIES: usize = 50_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Class {
    #[default]
    Human,
    Suspicious,
    Bot,
}

impl Class {
    pub const ALL: [Class; 3] = [Class::Human, Class::Suspicious, Class::Bot];

    pub fn as_str(self) -> &'static str {
        match self {
            Class::Human => "human",
            Class::Suspicious => "suspicious",
            Class::Bot => "bot",
        }
    }

    pub fn parse(s: &str) -> Option<Class> {
        Class::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

/// A class and the signals that decided it, comma-separated ("" for an ordinary human).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Verdict {
    pub class: Class,
    pub reason: String,
}

/// Thresholds (instance settings, docs/configuration.md).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub burst_views_per_minute: u32,
    /// Probe paths refused before an address counts as a scanner; 0 never does.
    pub scanner_probes: u32,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { burst_views_per_minute: 30, scanner_probes: 8 }
    }
}

impl Limits {
    pub fn from_settings(s: &crate::instance::Settings) -> Limits {
        let n = |k: &str| u32::try_from(s.int(k).max(0)).unwrap_or(u32::MAX);
        Limits { burst_views_per_minute: n("traffic.burst_views_per_minute"), scanner_probes: n("shield.scanner_probes") }
    }
}

/// What a request says about itself.
#[derive(Clone, Debug, Default)]
pub struct Facts {
    pub ua: String,
    pub has_accept: bool,
    pub has_lang: bool,
    pub http10: bool,
    pub probe: bool,
}

impl Facts {
    pub fn of(req: &Req) -> Facts {
        let present = |h: &str| req.header(h).is_some_and(|v| !v.trim().is_empty());
        Facts {
            ua: req.header("user-agent").unwrap_or("").trim().to_string(),
            has_accept: present("accept"),
            has_lang: present("accept-language"),
            http10: req.version <= axum::http::Version::HTTP_10,
            probe: is_probe(&req.path),
        }
    }
}

/// What the tracker has seen from the request's address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Seen {
    /// Page views this minute, this one included.
    pub views_minute: u32,
    /// Requests, 4xx answers and refused probe paths in the window, not counting this request.
    pub requests: u32,
    pub s4xx: u32,
    pub probes: u32,
    /// Until when the address is blocked as a scanner (ms), 0 if it is not.
    pub blocked_until: i64,
}

pub fn classify(f: &Facts, seen: &Seen, verified: Option<&'static str>, lim: &Limits) -> Verdict {
    let mut bot: Vec<&str> = Vec::new();
    if f.ua.is_empty() {
        bot.push("no_ua");
    } else if crate::analytics::is_bot(&f.ua) {
        bot.push("ua");
    }
    if f.probe {
        bot.push("probe");
    }
    if seen.blocked_until > 0 || (lim.scanner_probes > 0 && seen.probes >= lim.scanner_probes) {
        bot.push("scanner");
    }
    if !bot.is_empty() {
        return Verdict { class: Class::Bot, reason: bot.join(",") };
    }
    if let Some(how) = verified {
        return Verdict { class: Class::Human, reason: how.into() };
    }
    let mut odd: Vec<&str> = Vec::new();
    if !f.has_lang {
        odd.push("no_lang");
    }
    if !f.has_accept {
        odd.push("no_accept");
    }
    if f.http10 {
        odd.push("http1.0");
    }
    if lim.burst_views_per_minute > 0 && seen.views_minute > lim.burst_views_per_minute {
        odd.push("burst");
    }
    if seen.requests >= RATIO_MIN_REQUESTS && seen.s4xx * 2 >= seen.requests {
        odd.push("4xx");
    }
    let class = match odd.len() {
        0 => Class::Human,
        n if n >= BOT_SIGNALS => Class::Bot,
        _ => Class::Suspicious,
    };
    Verdict { class, reason: odd.join(",") }
}

/// Paths that only vulnerability scanners ask a Brod app for: WordPress and PHP admin pages, dotfiles holding
/// secrets or a repository, CGI and well-known router and server exploits. Matched on the lowercased path.
pub fn is_probe(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    const ANYWHERE: [&str; 27] = [
        "/wp-admin",
        "/wp-login",
        "/wp-content/",
        "/wp-includes/",
        "/wp-json/",
        "/wp-config",
        "/xmlrpc.php",
        "/.env",
        "/.git/",
        "/.svn/",
        "/.hg/",
        "/.aws/",
        "/.ssh/",
        "/.ds_store",
        "/.htaccess",
        "/.htpasswd",
        "/phpmyadmin",
        "/phpinfo",
        "/pma/",
        "/myadmin/",
        "/mysqladmin",
        "/adminer",
        "/cgi-bin/",
        "/vendor/phpunit",
        "/boaform",
        "/hnap1",
        "/server-status",
    ];
    ANYWHERE.iter().any(|m| p.contains(m)) || p.ends_with("/.git") || p.starts_with("/actuator/") || p.starts_with("/owa/")
}

// ---------- what each address and visitor has done lately ----------

#[derive(Clone, Copy, Default)]
struct Address {
    window: i64,
    requests: u32,
    s4xx: u32,
    probes: u32,
    minute: i64,
    views: u32,
    blocked_until: i64,
}

impl Address {
    fn roll(&mut self, at: i64) {
        if at - self.window >= WINDOW {
            (self.window, self.requests, self.s4xx, self.probes) = (at, 0, 0, 0);
        }
        if at / MINUTE != self.minute {
            (self.minute, self.views) = (at / MINUTE, 0);
        }
        if self.blocked_until <= at {
            self.blocked_until = 0;
        }
    }
}

/// Recent requests per address and the visitors that proved they run JavaScript, kept in memory: a restart forgets
/// them, which only means a scanner is blocked again a little later.
#[derive(Default)]
pub struct Tracker {
    addresses: Mutex<HashMap<String, Address>>,
    /// Visitor hash (usage::visitor_hash, which changes every day) to when it stops counting as verified.
    verified: Mutex<HashMap<String, i64>>,
}

impl Tracker {
    /// What the address did before this request; counts this request as a page view when it is one.
    pub fn seen(&self, ip: &str, at: i64, view: bool) -> Seen {
        let mut all = self.addresses.lock().unwrap_or_else(PoisonError::into_inner);
        if all.len() >= MAX_ENTRIES && !all.contains_key(ip) {
            all.retain(|_, a| at - a.window < WINDOW || a.blocked_until > at);
            if all.len() >= MAX_ENTRIES {
                return Seen::default();
            }
        }
        let a = all.entry(ip.to_string()).or_insert(Address { window: at, minute: at / MINUTE, ..Default::default() });
        a.roll(at);
        a.views += u32::from(view);
        Seen { views_minute: a.views, requests: a.requests, s4xx: a.s4xx, probes: a.probes, blocked_until: a.blocked_until }
    }

    /// Count a finished request. A probe path answered 4xx counts towards `scanner_probes`; reaching it blocks the
    /// address for `block_ms`. True when this request blocked it.
    pub fn done(&self, ip: &str, at: i64, status: u16, probe: bool, scanner_probes: u32, block_ms: i64) -> bool {
        let mut all = self.addresses.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(a) = all.get_mut(ip) else { return false };
        a.roll(at);
        a.requests = a.requests.saturating_add(1);
        let refused = (400..500).contains(&status);
        a.s4xx += u32::from(refused);
        if probe && refused {
            a.probes += 1;
            if scanner_probes > 0 && a.probes >= scanner_probes && a.blocked_until == 0 {
                a.blocked_until = at + block_ms;
                return true;
            }
        }
        false
    }

    /// Until when `ip` is blocked, if it is.
    pub fn blocked_until(&self, ip: &str, at: i64) -> Option<i64> {
        let all = self.addresses.lock().unwrap_or_else(PoisonError::into_inner);
        all.get(ip).map(|a| a.blocked_until).filter(|u| *u > at)
    }

    /// Remember that `visitor` runs JavaScript, for the rest of the day its hash is good for (and a little more).
    pub fn verify(&self, visitor: &str, at: i64) {
        let mut v = self.verified.lock().unwrap_or_else(PoisonError::into_inner);
        if v.len() >= MAX_ENTRIES && !v.contains_key(visitor) {
            v.retain(|_, until| *until > at);
            if v.len() >= MAX_ENTRIES {
                return;
            }
        }
        v.insert(visitor.to_string(), at + 26 * 60 * MINUTE);
    }

    pub fn is_verified(&self, visitor: &str, at: i64) -> bool {
        let v = self.verified.lock().unwrap_or_else(PoisonError::into_inner);
        v.get(visitor).is_some_and(|until| *until > at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROME: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36";

    fn browser() -> Facts {
        Facts { ua: CHROME.into(), has_accept: true, has_lang: true, http10: false, probe: false }
    }
    fn class(f: &Facts, seen: &Seen, verified: Option<&'static str>) -> (Class, String) {
        let v = classify(f, seen, verified, &Limits::default());
        (v.class, v.reason)
    }

    #[test]
    fn an_ordinary_browser_is_human() {
        assert_eq!(class(&browser(), &Seen::default(), None), (Class::Human, String::new()));
    }

    #[test]
    fn self_declared_and_nameless_clients_are_bots() {
        let f = Facts { ua: "Googlebot/2.1 (+http://www.google.com/bot.html)".into(), ..browser() };
        assert_eq!(class(&f, &Seen::default(), None), (Class::Bot, "ua".into()));
        let f = Facts { ua: String::new(), ..browser() };
        assert_eq!(class(&f, &Seen::default(), None), (Class::Bot, "no_ua".into()));
        // Running JavaScript does not make a declared bot a person.
        let f = Facts { ua: "Mozilla/5.0 HeadlessChrome/126.0".into(), ..browser() };
        assert_eq!(class(&f, &Seen::default(), Some("js")).0, Class::Bot);
    }

    #[test]
    fn a_scanner_with_a_browser_user_agent_is_caught() {
        // What brod.sh saw: a Chrome user agent, no Accept-Language, asking for /wp-login.php.
        let f = Facts { has_lang: false, probe: is_probe("/wp-login.php"), ..browser() };
        assert_eq!(class(&f, &Seen::default(), None), (Class::Bot, "probe".into()));
        // Its next request, for the home page, is a scanner's too once the address was refused enough probes.
        let f = Facts { has_lang: false, ..browser() };
        let seen = Seen { probes: 8, requests: 9, s4xx: 8, ..Default::default() };
        assert_eq!(class(&f, &seen, None), (Class::Bot, "scanner".into()));
        let blocked = Seen { blocked_until: 1, ..Default::default() };
        assert_eq!(class(&browser(), &blocked, None).0, Class::Bot);
        // Below the threshold the same request is only suspicious.
        let seen = Seen { probes: 2, ..Default::default() };
        assert_eq!(class(&f, &seen, None), (Class::Suspicious, "no_lang".into()));
    }

    #[test]
    fn odd_headers_rates_and_errors_are_suspicious_and_add_up_to_a_bot() {
        let f = Facts { has_accept: false, ..browser() };
        assert_eq!(class(&f, &Seen::default(), None), (Class::Suspicious, "no_accept".into()));
        let burst = Seen { views_minute: 31, ..Default::default() };
        assert_eq!(class(&browser(), &burst, None), (Class::Suspicious, "burst".into()));
        assert_eq!(class(&browser(), &Seen { views_minute: 30, ..Default::default() }, None).0, Class::Human);
        let errors = Seen { requests: 20, s4xx: 10, ..Default::default() };
        assert_eq!(class(&browser(), &errors, None), (Class::Suspicious, "4xx".into()));
        // Too few requests to judge a ratio.
        assert_eq!(class(&browser(), &Seen { requests: 4, s4xx: 4, ..Default::default() }, None).0, Class::Human);
        let f = Facts { has_lang: false, http10: true, ..browser() };
        assert_eq!(class(&f, &burst, None), (Class::Bot, "no_lang,http1.0,burst".into()));
    }

    #[test]
    fn javascript_or_signing_in_clears_the_odd_signals() {
        let f = Facts { has_lang: false, has_accept: false, ..browser() };
        assert_eq!(class(&f, &Seen::default(), Some("js")), (Class::Human, "js".into()));
        assert_eq!(class(&f, &Seen::default(), Some("signed_in")), (Class::Human, "signed_in".into()));
    }

    #[test]
    fn thresholds_can_be_turned_off() {
        let lim = Limits { burst_views_per_minute: 0, scanner_probes: 0 };
        let seen = Seen { views_minute: 1000, probes: 1000, ..Default::default() };
        assert_eq!(classify(&browser(), &seen, None, &lim).class, Class::Human);
    }

    #[test]
    fn probe_paths() {
        for p in [
            "/wp-admin/",
            "/blog/wp-login.php",
            "/xmlrpc.php",
            "/.env",
            "/.env.production",
            "/.git/config",
            "/a/.git",
            "/PHPMYADMIN/",
            "/cgi-bin/luci",
            "/actuator/health",
            "/vendor/phpunit/x.php",
        ] {
            assert!(is_probe(p), "{p}");
        }
        for p in ["/", "/about", "/.well-known/security.txt", "/.github/x", "/wp", "/api/env", "/blog/wordpress-tips", "/index.php"] {
            assert!(!is_probe(p), "{p}");
        }
    }

    #[test]
    fn the_tracker_counts_per_address_and_blocks_scanners() {
        let t = Tracker::default();
        let at = 1_000_000_000_000;
        assert_eq!(t.seen("1.2.3.4", at, true).views_minute, 1);
        assert_eq!(t.seen("1.2.3.4", at + 1, true).views_minute, 2);
        // A new minute starts the count again; other addresses have their own.
        assert_eq!(t.seen("1.2.3.4", at + MINUTE, true).views_minute, 1);
        assert_eq!(t.seen("5.6.7.8", at, true).views_minute, 1);
        for i in 0..3 {
            t.seen("9.9.9.9", at + i, false);
            assert!(!t.done("9.9.9.9", at + i, 404, true, 3, 60 * MINUTE) || i == 2);
        }
        assert_eq!(t.blocked_until("9.9.9.9", at + 10), Some(at + 2 + 60 * MINUTE));
        let s = t.seen("9.9.9.9", at + 10, false);
        assert_eq!((s.requests, s.s4xx, s.probes), (3, 3, 3));
        // A probe the app answered is not counted, and the block ends on time.
        t.done("9.9.9.9", at + 11, 200, true, 3, 60 * MINUTE);
        assert_eq!(t.seen("9.9.9.9", at + 12, false).probes, 3);
        assert_eq!(t.blocked_until("9.9.9.9", at + 2 + 60 * MINUTE), None);
        // The window forgets.
        assert_eq!(t.seen("9.9.9.9", at + WINDOW + 5, false).probes, 0);
    }

    #[test]
    fn verified_visitors_expire() {
        let t = Tracker::default();
        t.verify("v1", 0);
        assert!(t.is_verified("v1", 60 * MINUTE));
        assert!(!t.is_verified("v2", 0));
        assert!(!t.is_verified("v1", 27 * 60 * MINUTE));
    }
}
