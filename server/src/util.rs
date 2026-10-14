// Small helpers shared by every module: ids, hashing, signing, slugs, emails, content types, escaping, cookies,
// URI encoding and dates.
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use unicode_normalization::UnicodeNormalization;

use crate::config::Config;

/// Milliseconds since the Unix epoch, like Date.now().
pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    // The OS random source does not fail on supported platforms; a zeroed id would still be unique per prefix.
    if getrandom::fill(&mut b).is_err() {
        panic!("the operating system's random source is unavailable");
    }
    b
}

/// A prefix plus `bytes` random bytes in hex, like randomId().
pub fn random_id(prefix: &str, bytes: usize) -> String {
    format!("{prefix}{}", hex::encode(random_bytes(bytes)))
}

pub fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

pub fn safe_equal(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |r, (x, y)| r | (x ^ y)) == 0
}

pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// HMAC-SHA256 of `data` keyed with the UTF-8 bytes of `secret`, as base64url without padding.
pub fn hmac_b64url(secret: &str, data: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC takes a key of any length");
    mac.update(data.as_bytes());
    b64url(&mac.finalize().into_bytes())
}

/// The most PBKDF2 iterations a password hash may use (100,000, the most WebCrypto on Cloudflare Workers allows, so
/// hashes made by Brod's first version still verify).
const PASSWORD_ITERATIONS: u32 = 100_000;

/// PBKDF2-HMAC-SHA256 with one 32-byte block, as WebCrypto's deriveBits(256).
fn pbkdf2(password: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    let key = Hmac::<Sha256>::new_from_slice(password.as_bytes()).expect("HMAC takes a key of any length");
    let mut mac = key.clone();
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut u: [u8; 32] = mac.finalize().into_bytes().into();
    let mut out = u;
    for _ in 1..iterations {
        let mut mac = key.clone();
        mac.update(&u);
        u = mac.finalize().into_bytes().into();
        out.iter_mut().zip(u).for_each(|(o, x)| *o ^= x);
    }
    out
}

/// Store a password as "pbkdf2$<iterations>$<salt>$<hash>" (base64url), never the password itself, like hashPassword().
pub fn hash_password(password: &str) -> String {
    let salt = random_bytes(16);
    format!("pbkdf2${PASSWORD_ITERATIONS}${}${}", b64url(&salt), b64url(&pbkdf2(password, &salt, PASSWORD_ITERATIONS)))
}

pub fn verify_password(password: &str, stored: &str) -> bool {
    let parts: Vec<&str> = stored.split('$').collect();
    let [kind, n, salt, hash] = parts.as_slice() else { return false };
    let (Ok(n), Ok(salt)) = (n.parse::<u32>(), URL_SAFE_NO_PAD.decode(salt)) else { return false };
    *kind == "pbkdf2" && !hash.is_empty() && n > 0 && n <= PASSWORD_ITERATIONS && safe_equal(&b64url(&pbkdf2(password, &salt, n)), hash)
}

/// A compact signed token: base64url(JSON payload) + "." + HMAC-SHA256 signature.
pub fn sign_token(secret: &str, payload: &Value) -> String {
    let body = b64url(payload.to_string().as_bytes());
    let sig = hmac_b64url(secret, &body);
    format!("{body}.{sig}")
}

pub fn is_local(apps_domain: &str) -> bool {
    let rest = apps_domain.strip_prefix("localhost").or_else(|| apps_domain.strip_prefix("127.0.0.1"));
    matches!(rest, Some(r) if r.is_empty() || r.starts_with(':'))
}
/// Apps live at <app>.<workspace>.<APPS_DOMAIN>, so app names only need to be unique inside a workspace.
pub fn app_url(cfg: &Config, workspace: &str, slug: &str) -> String {
    let scheme = if is_local(&cfg.apps_domain) { "http" } else { "https" };
    format!("{scheme}://{slug}.{workspace}.{}", cfg.apps_domain)
}
/// What ends the first label of an app's staging address: <slug>--staging.<workspace>.<APPS_DOMAIN>. Slugs never hold
/// "--" (slugify folds runs of separators into one hyphen), so the staging address can never be another app's.
pub const STAGING_SUFFIX: &str = "--staging";
/// The address an app's staging version is served at.
pub fn staging_url(cfg: &Config, workspace: &str, slug: &str) -> String {
    app_url(cfg, workspace, &format!("{slug}{STAGING_SUFFIX}"))
}
/// The origin of any address Brod serves apps at, a custom domain included: https, except in local development.
pub fn host_origin(cfg: &Config, host: &str) -> String {
    let scheme = if is_local(&cfg.apps_domain) { "http" } else { "https" };
    format!("{scheme}://{host}")
}

const RESERVED: &[&str] = &["api", "www", "app", "apps", "admin", "mcp", "dashboard", "mail", "status", "docs", "help", "login", "auth"];
/// Workspace names are the first label under APPS_DOMAIN, so they must not take a name the platform or a visitor
/// would expect to be ours.
const RESERVED_WORKSPACES: &[&str] = &[
    "about",
    "abuse",
    "account",
    "accounts",
    "assets",
    "autoconfig",
    "autodiscover",
    "billing",
    "blog",
    "brod",
    "cdn",
    "console",
    "dev",
    "developer",
    "developers",
    "download",
    "email",
    "ftp",
    "git",
    "hostmaster",
    "id",
    "identity",
    "imap",
    "info",
    "internal",
    "legal",
    "localhost",
    "m",
    "manage",
    "media",
    "mta-sts",
    "mx",
    "my",
    "new",
    "news",
    "noc",
    "ns",
    "ns1",
    "ns2",
    "oauth",
    "pop",
    "pop3",
    "portal",
    "postmaster",
    "pricing",
    "privacy",
    "registry",
    "root",
    "security",
    "settings",
    "signin",
    "signup",
    "smtp",
    "sso",
    "staff",
    "stage",
    "staging",
    "static",
    "store",
    "support",
    "system",
    "team",
    "terms",
    "test",
    "u",
    "user",
    "users",
    "w",
    "webmail",
    "webmaster",
    "ws",
    "wss",
];

/// A workspace's address label: like `slugify`, but a reserved name becomes `team-<name>`.
pub fn workspace_slugify(name: &str) -> String {
    let s = slugify(name);
    match s.strip_prefix("app-") {
        Some(r) if RESERVED.contains(&r) || r == "x" => format!("team-{r}"),
        _ if RESERVED_WORKSPACES.contains(&s.as_str()) => format!("team-{s}"),
        _ => s,
    }
}

pub fn slugify(name: &str) -> String {
    let lower: String = name.to_lowercase().nfkd().collect();
    let mut s = String::new();
    let mut dash = false;
    for c in lower.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            s.push(c);
            dash = false;
        } else if !dash {
            s.push('-');
            dash = true;
        }
    }
    let s: String = s.trim_matches('-').chars().take(40).collect();
    let s = s.trim_end_matches('-').to_string();
    if s.is_empty() || RESERVED.contains(&s.as_str()) { format!("app-{}", if s.is_empty() { "x" } else { &s }) } else { s }
}

pub fn norm_email(e: &str) -> String {
    e.trim().to_lowercase()
}

/// `/^[^@\s]+@[^@\s]+\.[^@\s]+$/` and at most 254 UTF-16 code units.
pub fn is_email(e: &str) -> bool {
    if e.encode_utf16().count() > 254 {
        return false;
    }
    let Some((local, domain)) = e.split_once('@') else {
        return false;
    };
    let ok = |s: &str| !s.is_empty() && !s.chars().any(|c| c == '@' || is_js_space(c));
    if !ok(local) || !ok(domain) {
        return false;
    }
    let chars: Vec<char> = domain.chars().collect();
    chars.iter().enumerate().any(|(i, c)| *c == '.' && i > 0 && i < chars.len() - 1)
}

/// What `\s` matches in a JavaScript regular expression.
pub fn is_js_space(c: char) -> bool {
    c.is_whitespace() || c == '\u{feff}'
}

pub fn content_type(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "map" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "md" => "text/markdown; charset=utf-8",
        "xml" => "application/xml",
        "csv" => "text/csv; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "webmanifest" => "application/manifest+json",
        _ => "application/octet-stream",
    }
}

/// HTML-escape &, <, >, " and '.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

pub fn is_hex_color(c: &str) -> bool {
    c.len() == 7 && c.starts_with('#') && c[1..].chars().all(|x| x.is_ascii_hexdigit())
}

// ---------- cookies ----------

/// Cookie names for the site at `origin`. On HTTPS they carry the __Host- prefix, so browsers refuse to let any other
/// host set or overwrite them: an app on a sibling subdomain (for example x.apps.brod.sh next to brod.sh) cannot
/// plant a sign-in cookie. Local HTTP development keeps plain names. Decided from the configured origin, never the
/// request URL: behind Caddy the request reaching Brod is plain HTTP.
pub fn cookie_name(origin: &str, name: &str) -> String {
    if origin.starts_with("https:") { format!("__Host-{name}") } else { name.to_string() }
}

/// The value of cookie `name` (with the prefix `origin` calls for) in a Cookie header, or "".
pub fn cookie(header: Option<&str>, origin: &str, name: &str) -> String {
    let name = cookie_name(origin, name);
    for part in header.unwrap_or("").split(';') {
        if let Some((k, v)) = part.trim_start().split_once('=')
            && k == name
        {
            return v.to_string();
        }
    }
    String::new()
}

pub fn set_cookie(origin: &str, name: &str, value: &str, max_age_sec: i64) -> String {
    let secure = if origin.starts_with("https:") { "; Secure" } else { "" };
    format!("{}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_sec}{secure}", cookie_name(origin, name))
}

// ---------- URI encoding, as JavaScript does it ----------

const URI_COMPONENT: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');

pub fn encode_uri_component(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, URI_COMPONENT).to_string()
}

/// decodeURIComponent: None where JavaScript would throw a URIError.
pub fn decode_uri_component(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() || !(b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit()) {
                return None;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    percent_encoding::percent_decode_str(s).decode_utf8().ok().map(|c| c.into_owned())
}

/// The value of a query parameter, decoded as URLSearchParams does.
pub fn query_param(query: &str, name: &str) -> Option<String> {
    form_urlencoded::parse(query.as_bytes()).find(|(k, _)| k == name).map(|(_, v)| v.into_owned())
}

// ---------- dates ----------

/// new Date(ms).toISOString()
pub fn iso(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if mo <= 2 { 1 } else { 0 };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z")
}

/// Upper-case the first character, like `s.replace(/^./, c => c.toUpperCase())`.
pub fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// `s.slice(0, n)` on UTF-16 code units, without splitting a character.
pub fn js_slice(s: &str, n: usize) -> String {
    let mut units = 0;
    let mut out = String::new();
    for c in s.chars() {
        units += c.len_utf16();
        if units > n {
            break;
        }
        out.push(c);
    }
    out
}

/// String.prototype.trim: JavaScript's whitespace set.
pub fn js_trim(s: &str) -> &str {
    s.trim_matches(|c: char| is_js_space(c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn passwords_hash_with_pbkdf2_as_webcrypto_does() {
        // RFC 7914, section 11: PBKDF2-HMAC-SHA256("password", "salt", 4096), first 32 bytes.
        assert_eq!(hex::encode(pbkdf2("password", b"salt", 4096)), "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
        // Made by WebCrypto's PBKDF2 with 1000 iterations, as Brod's first version stored them.
        let by_ts = "pbkdf2$1000$AwoRGB8mLTQ7QklQV15lbA$D_UaNY6a5eoLek8TFeCpHvj9vIr2jO4gd0ds86M1Edw";
        assert!(verify_password("open sesame ✓", by_ts));
        assert!(!verify_password("open sesame", by_ts));
        let mine = hash_password("hunter22");
        assert!(mine.starts_with("pbkdf2$100000$") && verify_password("hunter22", &mine) && !verify_password("hunter23", &mine));
        assert_ne!(mine, hash_password("hunter22"), "every hash has its own salt");
        for bad in ["", "pbkdf2$0$AA$AA", "pbkdf2$999999999$AA$AA", "md5$1$AA$AA", "pbkdf2$1$!!$AA"] {
            assert!(!verify_password("x", bad), "{bad}");
        }
    }

    #[test]
    fn slugify_makes_readable_addresses() {
        assert_eq!(slugify("Reading List!"), "reading-list");
        assert_eq!(slugify("  Café   Menu  "), "cafe-menu");
        assert_eq!(slugify("API"), "app-api");
        assert_eq!(slugify("!!!"), "app-x");
        assert_eq!(workspace_slugify("www"), "team-www");
        assert_eq!(workspace_slugify("API"), "team-api");
        assert_eq!(workspace_slugify("Support"), "team-support");
        assert_eq!(workspace_slugify("Acme"), "acme");
        let s = slugify(&("a".repeat(39) + " b c"));
        assert!(s.len() <= 40 && !s.ends_with('-'));
    }

    #[test]
    fn small_helpers() {
        assert!(safe_equal("abc", "abc"));
        assert!(!safe_equal("abc", "abd"));
        assert!(!safe_equal("abc", "abcd"));
        assert_eq!(esc("<a href=\"x\">'&"), "&lt;a href=&quot;x&quot;&gt;&#39;&amp;");
        assert!(content_type("a/b/app.JS").starts_with("text/javascript"));
        assert_eq!(content_type("x.unknown"), "application/octet-stream");
        assert!(is_email("a@b.co") && !is_email("a@b") && !is_email("a b@c.d") && !is_email("a@.c") && !is_email("a@b."));
        assert_eq!(encode_uri_component("/a b?c=d&e'(x)"), "%2Fa%20b%3Fc%3Dd%26e'(x)");
        assert_eq!(decode_uri_component("a%20b").as_deref(), Some("a b"));
        assert_eq!(decode_uri_component("%E0%A4%A"), None);
        assert_eq!(decode_uri_component("%"), None);
        assert_eq!(iso(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso(1_791_627_771_457), "2026-10-10T10:22:51.457Z");
        assert_eq!(cookie(Some("a=1; brod_session=xyz"), "http://localhost:8787", "brod_session"), "xyz");
        assert_eq!(cookie(Some("xbrod_session=1"), "http://localhost:8787", "brod_session"), "");
    }

    #[test]
    fn cookies_use_the_host_prefix_on_https() {
        assert_eq!(cookie_name("https://brod.sh", "brod_platform"), "__Host-brod_platform");
        assert_eq!(cookie_name("http://localhost:8787", "brod_platform"), "brod_platform");
        let set = set_cookie("https://notes.apps.brod.sh", "brod_session", "abc", 60);
        assert_eq!(set, "__Host-brod_session=abc; Path=/; HttpOnly; SameSite=Lax; Max-Age=60; Secure");
        assert!(!set.to_lowercase().contains("domain="));
        // An unprefixed cookie that an app planted on HTTPS is ignored.
        assert_eq!(cookie(Some("brod_platform=planted"), "https://brod.sh", "brod_platform"), "");
        assert_eq!(cookie(Some("brod_platform=planted; __Host-brod_platform=real"), "https://brod.sh", "brod_platform"), "real");
    }

    #[test]
    fn signs_identity_tokens_like_lib_ts() {
        // Expected values computed independently with WebCrypto HMAC-SHA256 (signToken('k', { sub: 'usr_1', role: 'editor' })).
        let token = sign_token("k", &json!({ "sub": "usr_1", "role": "editor" }));
        let (body, sig) = token.split_once('.').unwrap();
        assert_eq!(body, "eyJzdWIiOiJ1c3JfMSIsInJvbGUiOiJlZGl0b3IifQ");
        assert_eq!(sig, hmac_b64url("k", body));
        assert_ne!(sig, hmac_b64url("other", body));
    }
}
