// The request as the handlers see it, and the response shapes every module uses: JSON, platform pages, redirects.
use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::Response;
use bytes::Bytes;
use futures_util::StreamExt;
use serde_json::Value;

use crate::problem::{Problem, Result};
use crate::util::{esc, is_hex_color, query_param};

/// One incoming request: the parts of `new URL(request.url)` and the headers and body the handlers read.
/// The address of the connection a request came in on (set by main.rs).
#[derive(Clone, Copy, Debug)]
pub struct Peer(pub std::net::IpAddr);

/// Which listener a request came in on. Only the internal one (BROD_LISTEN, behind a proxy or on the private network)
/// answers /_caddy/ask and /_runtime/*; Brod's own HTTPS listener (tls.rs) is public and always https.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    Internal,
    Https,
}

pub struct Req {
    pub method: Method,
    /// "http" or "https".
    pub scheme: String,
    /// The Host, lowercased, with its port.
    pub host: String,
    /// The path with dot segments resolved, still percent-encoded, like URL.pathname.
    pub path: String,
    /// The query string without "?".
    pub query: String,
    pub headers: HeaderMap,
    /// The connection's address, when the server knows it.
    pub peer: Option<std::net::IpAddr>,
    pub via: Via,
    /// In a Mutex only so that a &Req can be held across an await: the body itself is used once.
    pub body: std::sync::Mutex<Body>,
}

impl Req {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
    pub fn param(&self, name: &str) -> Option<String> {
        query_param(&self.query, name)
    }
    /// A request for unit tests: `method path?query` on host x.test, with these headers.
    #[cfg(test)]
    pub fn for_tests(method: &str, target: &str, headers: &[(&str, &str)]) -> Req {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let mut map = HeaderMap::new();
        for (k, v) in headers {
            map.insert(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
        }
        Req {
            method: method.parse().unwrap(),
            scheme: "https".into(),
            host: "x.test".into(),
            path: path.into(),
            query: query.into(),
            headers: map,
            peer: None,
            via: Via::Internal,
            body: std::sync::Mutex::new(Body::empty()),
        }
    }
    pub fn origin(&self) -> String {
        format!("{}://{}", self.scheme, self.host)
    }
    pub fn href(&self) -> String {
        if self.query.is_empty() {
            format!("{}{}", self.origin(), self.path)
        } else {
            format!("{}{}?{}", self.origin(), self.path, self.query)
        }
    }
    pub fn is_json(&self) -> bool {
        self.header("content-type").unwrap_or("").contains("application/json")
    }
    pub fn take_body(&mut self) -> Body {
        match self.body.get_mut() {
            Ok(b) => std::mem::take(b),
            Err(p) => std::mem::take(p.into_inner()),
        }
    }

    /// Read the body, refusing more than `cap` bytes, like readCapped().
    pub async fn bytes(&mut self, cap: usize, what: &str) -> Result<Vec<u8>> {
        read_capped(self.take_body(), cap, what).await
    }

    /// The body as a JSON object; anything that is not an object reads as {}.
    pub async fn json_object(&mut self) -> Result<serde_json::Map<String, Value>> {
        let raw = self.bytes(8 * 1024 * 1024, "The request body").await?;
        match serde_json::from_slice::<Value>(&raw) {
            Ok(Value::Object(m)) => Ok(m),
            Ok(_) => Ok(Default::default()),
            Err(_) => Err(Problem::new(400, "bad_json", "The request body must be JSON.")),
        }
    }

    /// The body of a form post (application/x-www-form-urlencoded), as name to value.
    pub async fn form(&mut self) -> Result<Vec<(String, String)>> {
        let raw = self.bytes(1024 * 1024, "The form").await?;
        Ok(form_urlencoded::parse(&raw).map(|(k, v)| (k.into_owned(), v.into_owned())).collect())
    }
}

pub async fn read_capped(body: Body, cap: usize, what: &str) -> Result<Vec<u8>> {
    let mut stream = body.into_data_stream();
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| Problem::new(400, "bad_body", format!("The request body could not be read: {e}")))?;
        if out.len() + chunk.len() > cap {
            return Err(too_large(what, cap));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

pub fn too_large(what: &str, cap: usize) -> Problem {
    Problem::new(413, "too_large", format!("{what} is larger than {} MB.", (cap as f64 / 1_048_576.0).round() as u64))
}

/// Resolve "." and ".." segments the way the URL parser does for http(s) URLs.
pub fn normalize_path(raw: &str) -> String {
    let raw = raw.replace('\\', "/");
    let mut out: Vec<&str> = Vec::new();
    let segments: Vec<&str> = raw.split('/').skip(1).collect();
    let n = segments.len();
    for (i, s) in segments.iter().enumerate() {
        let lower = s.to_ascii_lowercase();
        let last = i == n - 1;
        if lower == "." || lower == "%2e" {
            if last {
                out.push("");
            }
        } else if matches!(lower.as_str(), ".." | ".%2e" | "%2e." | "%2e%2e") {
            out.pop();
            if last {
                out.push("");
            }
        } else {
            out.push(s);
        }
    }
    format!("/{}", out.join("/"))
}

// ---------- responses ----------

pub fn header_pairs(res: &mut Response, headers: &[(&str, String)]) {
    for (k, v) in headers {
        if let (Ok(name), Ok(value)) = (HeaderName::try_from(*k), HeaderValue::try_from(v.as_str())) {
            if name == axum::http::header::SET_COOKIE {
                res.headers_mut().append(name, value);
            } else {
                res.headers_mut().insert(name, value);
            }
        }
    }
}

pub fn response(status: u16, body: impl Into<Body>, headers: &[(&str, String)]) -> Response {
    let mut res = Response::new(body.into());
    *res.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    header_pairs(&mut res, headers);
    res
}

/// JSON with two-space indentation, like JSON.stringify(data, null, 2).
pub fn json_response(data: &Value, status: u16, headers: &[(&str, String)]) -> Response {
    let body = serde_json::to_string_pretty(data).unwrap_or_else(|_| "null".into());
    let mut all: Vec<(&str, String)> = vec![("content-type", "application/json; charset=utf-8".into())];
    all.extend(headers.iter().cloned());
    response(status, Body::from(body), &all)
}

pub fn json(data: Value) -> Response {
    json_response(&data, 200, &[])
}

/// The look shared by every platform page. Keep it in step with PAGE_CSS in src/lib.ts.
const PAGE_CSS: &str = r##":root{--bg:#F1F5F2;--surface:#FBFCFB;--sunk:#E7EDE8;--ink:#15201B;--muted:#5A6860;--line:#D7E0D9;--deploy:#F4B62E;--green:#1E5B4A;--ok:#2B7A4B;--bad:#B2372E;--bad-bg:#FBECEA;--display:'Bricolage Grotesque','Segoe UI',system-ui,sans-serif;--body:'Instrument Sans','Segoe UI',system-ui,sans-serif;--mono:'JetBrains Mono',ui-monospace,'SF Mono',Menlo,monospace;color-scheme:light}
@media(prefers-color-scheme:dark){:root{--bg:#111815;--surface:#182019;--sunk:#0C120F;--ink:#E6EDE8;--muted:#93A199;--line:#2A3630;--green:#7FD0B0;--ok:#6CC48D;--bad:#F0857A;--bad-bg:#2E1A18;color-scheme:dark}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;flex-direction:column;align-items:center;background:var(--bg);color:var(--ink);font:15px/1.5 var(--body);-webkit-font-smoothing:antialiased}
.top{padding:40px 16px 20px}
.brand{display:flex;align-items:center;gap:9px;font:650 1.15rem var(--display)}
.logo{width:22px;height:14px;border-radius:8px;background:var(--deploy);box-shadow:7px -5px 0 -2px var(--deploy)}
main{width:min(28rem,calc(100% - 32px));background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:28px;margin:0 0 20px;overflow:hidden;display:flex;flex-direction:column;gap:14px}
main::before{content:"";display:block;height:6px;background:var(--accent);margin:-28px -28px 6px}
main>*{margin:0}
h1,h2{font-family:var(--display);letter-spacing:-.01em;text-wrap:balance}
h1{font-size:1.6rem;font-weight:650;line-height:1.15}
h2{font-size:1.1rem;font-weight:600;margin-top:10px;padding-top:20px;border-top:1px solid var(--line)}
p{margin:0}
b{font-weight:600}
a{color:var(--green);text-decoration-color:color-mix(in srgb,var(--green) 35%,transparent);text-underline-offset:3px}
a:hover{text-decoration-color:currentColor}
small,.muted{color:var(--muted);font-size:.85rem}
:focus-visible{outline:2px solid var(--green);outline-offset:2px;border-radius:4px}
form{display:flex;flex-direction:column;gap:10px;margin:0}
form>button:not(.block){align-self:flex-start}
form p{margin:0}
input,button,select{font:inherit;color:inherit}
input:not([type=checkbox]):not([type=hidden]),select{width:100%;border:1px solid var(--line);background:var(--surface);border-radius:8px;padding:9px 11px}
input:focus-visible,select:focus-visible{outline:2px solid var(--green);outline-offset:0;border-radius:8px}
input[readonly]{font:.82rem/1.5 var(--mono);background:var(--sunk);cursor:copy}
input[type=checkbox]{accent-color:var(--green);margin:0 6px 0 0;vertical-align:-2px}
label{display:block}
button,.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;border:1px solid var(--accent);background:var(--accent);color:#fff;padding:8px 16px;border-radius:9px;font-weight:600;cursor:pointer;text-decoration:none;white-space:nowrap}
button:hover,.btn:hover{filter:brightness(1.08)}
button.secondary,.btn.secondary{background:var(--surface);border-color:var(--line);color:var(--ink);font-weight:550}
button.secondary:hover,.btn.secondary:hover{filter:none;border-color:var(--muted)}
button.small{padding:4px 12px;font-size:.85rem}
.block{width:100%}
.actions{display:flex;flex-wrap:wrap;gap:8px}
form .actions{margin-top:4px}
.or{display:flex;align-items:center;gap:12px;color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.09em;font-weight:600}
.or::before,.or::after{content:"";flex:1;height:1px;background:var(--line)}
.icon{font-size:2rem;line-height:1}
ul{list-style:none;margin:0;padding:0;border-top:1px solid var(--line)}
li{display:flex;flex-wrap:wrap;align-items:center;gap:8px 16px;padding:12px 0;border-bottom:1px solid var(--line);position:relative}
li>span{flex:1 1 12rem;min-width:0;overflow-wrap:anywhere}
li form{display:block}
#apps li>a{color:var(--ink);font:650 1.02rem var(--display);text-decoration:none}
#apps li>a::before{content:"";position:absolute;inset:0}
#apps li:hover>a{text-decoration:underline}
#apps li::after{content:"→";margin-left:auto;color:var(--muted)}
#apps li small{flex-basis:100%;margin-top:-8px;order:3}
#apps li br{display:none}
[role=alert]{background:var(--bad-bg);color:var(--bad);border:1px solid color-mix(in srgb,var(--bad) 35%,transparent);border-radius:10px;padding:12px 14px}
[role=status]{border-left:3px solid var(--green);background:var(--sunk);padding:12px 14px;border-radius:0 10px 10px 0;display:flex;flex-direction:column;gap:8px}
footer{color:var(--muted);font-size:.8rem;padding:0 16px 32px}
[hidden]{display:none!important}"##;
const LOGO: &str = r#"<span class="logo" aria-hidden="true"></span>"#;
const FONTS: &str = r#"<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,500..700&family=Instrument+Sans:wght@400..700&family=JetBrains+Mono:wght@400;600&display=swap">"#;

/// A plain page in the platform's style. `body` is trusted HTML: callers escape what they put in it.
pub fn page(status: u16, title: &str, body: &str, color: Option<&str>, headers: &[(&str, String)]) -> Response {
    let accent = match color {
        Some(c) if is_hex_color(c) => c,
        _ => "#1f6f4a",
    };
    let html = format!(
        r#"<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title>
{FONTS}
<style>:root{{--accent:{accent}}}
{PAGE_CSS}</style>
<header class="top"><span class="brand">{LOGO}Brod</span></header>
<main>{body}</main>
<footer>Powered by Brod</footer></html>"#,
        title = esc(title),
    );
    let mut all: Vec<(&str, String)> = vec![
        ("content-type", "text/html; charset=utf-8".into()),
        ("cache-control", "no-store".into()),
        ("x-robots-tag", "noindex".into()),
        ("x-frame-options", "DENY".into()),
    ];
    all.extend(headers.iter().cloned());
    response(status, Body::from(html), &all)
}

pub fn notice(status: u16, title: &str, text: &str, extra: &str) -> Response {
    page(status, title, &format!("<h1>{}</h1><p>{}</p>{extra}", esc(title), esc(text)), None, &[])
}

/// Keep in step with NOT_FOUND_CSS in src/lib.ts.
const NOT_FOUND_CSS: &str = r##"<style>
.nf{display:flex;flex-direction:column;align-items:center;text-align:center;gap:12px;padding:6px 0 2px}
.nf-art{position:relative;width:176px;height:116px;margin:6px 0 8px}
.nf-win{position:absolute;inset:0;border:2px dashed var(--line);border-radius:16px;background:repeating-linear-gradient(135deg,transparent 0 11px,color-mix(in srgb,var(--line) 45%,transparent) 11px 12px)}
.nf-win::before{content:"";position:absolute;left:12px;top:11px;width:7px;height:7px;border-radius:50%;background:var(--line);box-shadow:11px 0 var(--line),22px 0 var(--line)}
.nf-code{position:absolute;inset:0;display:grid;place-items:center;font:700 2.7rem/1 var(--display);letter-spacing:-.04em;color:var(--muted);opacity:.5}
.nf-pill{position:absolute;right:-18px;top:-20px;width:46px;height:28px;border-radius:16px;background:var(--deploy);box-shadow:15px -10px 0 -4px var(--deploy);animation:nf-drift 5s ease-in-out infinite}
@keyframes nf-drift{50%{transform:translate(-8px,9px) rotate(-7deg)}}
@media(prefers-reduced-motion:reduce){.nf-pill{animation:none}}
.nf .actions{justify-content:center;margin-top:6px}
</style>"##;

/// The page for an app that is not there. A visitor who may not open an app sees exactly this too, so an address
/// says nothing about whether an app lives at it. Keep in step with notFound() in src/lib.ts.
pub fn not_found(api_origin: &str) -> Response {
    let body = format!(
        r#"{NOT_FOUND_CSS}<div class="nf">
<div class="nf-art" aria-hidden="true"><div class="nf-win"></div><div class="nf-code">404</div><div class="nf-pill"></div></div>
<h1>App not found</h1>
<p class="muted">There is no app at this address, or it has not been shared with you.</p>
<p class="muted">Check the link, or ask whoever sent it to share the app with you.</p>
<div class="actions"><a class="btn secondary" href="{}">Go to Brod</a></div>
</div>"#,
        esc(api_origin)
    );
    page(404, "App not found", &body, None, &[])
}

pub fn redirect(location: &str, headers: &[(&str, String)]) -> Response {
    let mut all: Vec<(&str, String)> = vec![("location", location.to_string()), ("cache-control", "no-store".into())];
    all.extend(headers.iter().cloned());
    response(302, Body::empty(), &all)
}

pub fn empty(status: u16) -> Response {
    response(status, Body::empty(), &[])
}

pub fn bytes_body(b: Vec<u8>) -> Body {
    Body::from(Bytes::from(b))
}

#[cfg(test)]
mod tests {
    use super::normalize_path;

    #[test]
    fn resolves_dot_segments_like_the_url_parser() {
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("/a/../b"), "/b");
        assert_eq!(normalize_path("/a/./b/"), "/a/b/");
        assert_eq!(normalize_path("/a/%2E%2e/b"), "/b");
        assert_eq!(normalize_path("/../../x"), "/x");
        assert_eq!(normalize_path("/a/.."), "/");
        assert_eq!(normalize_path("/about"), "/about");
    }
}
