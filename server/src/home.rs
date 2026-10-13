// The public landing page at / for people who are not signed in. Signed-in people are sent on to their workspace
// (auth.rs), so the same URL answers differently by cookie: the page may be cached, but only with revalidation and
// "Vary: Cookie", so that someone who has just signed in is never shown a stored copy of it.
//
// home.html is a template. {{ORIGIN}} and {{APPS_DOMAIN}} name this server, so a self-hosted Brod's landing page
// tells visitors to connect to it, and {{#analytics}}...{{/analytics}} (the Google tag and its consent banner)
// is kept only when BROD_GA_ID is set.
use std::sync::{LazyLock, OnceLock};

use axum::response::Response;
use sha2::Digest;

use crate::config::Config;
use crate::http::{Req, response};
use crate::util::{esc, sha256_hex};

const TEMPLATE: &str = include_str!("home.html");

/// The page for this server, with its ETag: the first 16 hex digits of the page's SHA-256.
struct Home {
    body: String,
    etag: String,
}

static HOME: OnceLock<Home> = OnceLock::new();

/// Fill in the template. `ga_id` is checked by config.rs, so it is safe to put in a script.
fn render(origin: &str, apps_domain: &str, ga_id: Option<&str>) -> String {
    let mut out = String::with_capacity(TEMPLATE.len());
    let mut rest = TEMPLATE;
    while let Some(start) = rest.find("{{#analytics}}") {
        out.push_str(&rest[..start]);
        let after = &rest[start + "{{#analytics}}".len()..];
        let end = after.find("{{/analytics}}").expect("home.html: every {{#analytics}} has a {{/analytics}}");
        if ga_id.is_some() {
            out.push_str(&after[..end]);
        }
        rest = &after[end + "{{/analytics}}".len()..];
    }
    out.push_str(rest);
    out.replace("{{ORIGIN}}", &esc(origin)).replace("{{APPS_DOMAIN}}", &esc(apps_domain)).replace("{{GA_ID}}", ga_id.unwrap_or(""))
}

pub fn page(cfg: &Config, req: &Req) -> Response {
    let home = HOME.get_or_init(|| {
        let body = render(&cfg.api_origin, &cfg.apps_domain, cfg.ga_id.as_deref());
        let etag = format!("\"{}\"", &sha256_hex(&body)[..16]);
        Home { body, etag }
    });
    let headers = [
        ("content-type", "text/html; charset=utf-8".to_string()),
        ("cache-control", "public, no-cache".to_string()),
        ("vary", "Cookie".to_string()),
        ("etag", home.etag.clone()),
        ("x-frame-options", "DENY".to_string()),
    ];
    if req.header("if-none-match").is_some_and(|v| v.split(',').any(|t| t.trim() == home.etag)) {
        return response(304, "", &headers[1..]);
    }
    response(200, home.body.clone(), &headers)
}

/// The link preview picture (og:image), rendered by scripts/gen-og.mjs.
pub const OG_PNG: &[u8] = include_bytes!("og.png");
static OG_ETAG: LazyLock<String> = LazyLock::new(|| format!("\"{}\"", &hex::encode(sha2::Sha256::digest(OG_PNG))[..16]));

pub fn og_image(req: &Req) -> Response {
    let headers =
        [("content-type", "image/png".to_string()), ("cache-control", "public, max-age=86400".to_string()), ("etag", OG_ETAG.clone())];
    if req.header("if-none-match").is_some_and(|v| v.split(',').any(|t| t.trim() == OG_ETAG.as_str())) {
        return response(304, "", &headers[1..]);
    }
    response(200, OG_PNG, &headers)
}

/// What search engines read first. Both name the request's own origin, so a self-hosted Brod points at itself.
pub fn robots(req: &Req) -> Response {
    let body = format!(
        "User-agent: *\nDisallow: /auth/\nDisallow: /w/\nDisallow: /v1/\nDisallow: /oauth/\nDisallow: /mcp\nDisallow: /new\n\nSitemap: {}/sitemap.xml\n",
        req.origin()
    );
    response(200, body, &[("content-type", "text/plain; charset=utf-8".to_string()), ("cache-control", "public, max-age=3600".to_string())])
}

pub fn sitemap(req: &Req) -> Response {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n  <url><loc>{}/</loc></url>\n</urlset>\n",
        req.origin()
    );
    response(
        200,
        body,
        &[("content-type", "application/xml; charset=utf-8".to_string()), ("cache-control", "public, max-age=3600".to_string())],
    )
}

#[cfg(test)]
mod tests {
    use super::render;

    const ORIGIN: &str = "https://brod.example.test";

    #[test]
    fn links_point_at_real_pages() {
        let page = render(ORIGIN, "apps.example.test", None);
        assert!(page.contains("<title>Brod: a cloud for the small software your team builds with AI</title>"));
        assert!(!page.contains("href=\"/signin\""));
        for anchor in ["how", "apps", "teams", "pricing", "connect"] {
            assert!(page.contains(&format!("id=\"{anchor}\"")), "#{anchor} has no target");
        }
    }

    #[test]
    fn names_this_server_and_never_brod_sh() {
        let page = render(ORIGIN, "apps.example.test", None);
        assert!(!page.contains("{{"), "a placeholder was left in the page");
        assert!(!page.contains("brod.sh"));
        assert!(page.contains("claude mcp add --transport http brod https://brod.example.test/mcp"));
        assert!(page.contains("https://shift-swap.harborops.apps.example.test"));
    }

    #[test]
    fn link_previews_have_a_large_picture() {
        let page = render(ORIGIN, "apps.example.test", None);
        assert!(page.contains("<meta property=\"og:image\" content=\"https://brod.example.test/og.png\">"));
        assert!(page.contains("<meta name=\"twitter:card\" content=\"summary_large_image\">"));
        assert!(page.contains("<link rel=\"canonical\" href=\"https://brod.example.test/\">"));
        // A PNG of 1200 × 630: the width and height sit in the IHDR chunk, after the 8-byte signature.
        let og = super::OG_PNG;
        assert_eq!(&og[..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(u32::from_be_bytes(og[16..20].try_into().unwrap()), 1200);
        assert_eq!(u32::from_be_bytes(og[20..24].try_into().unwrap()), 630);
    }

    #[test]
    fn start_free_leads_to_sign_up_and_status_is_gone() {
        let page = render(ORIGIN, "apps.example.test", None);
        assert_eq!(page.matches("href=\"/auth/signup\"").count(), 4);
        assert!(!page.contains("href=\"/healthz\""));
    }

    #[test]
    fn no_google_tag_unless_configured() {
        let page = render(ORIGIN, "apps.example.test", None);
        assert!(!page.contains("googletagmanager") && !page.contains("gtag(") && !page.contains("id=\"consent"));
    }

    #[test]
    fn google_analytics_waits_for_consent() {
        let page = render(ORIGIN, "apps.example.test", Some("G-TEST1234"));
        assert!(page.contains("googletagmanager.com/gtag/js?id=G-TEST1234"));
        let default = page.find("gtag('consent', 'default'").expect("consent defaults are set");
        let config = page.find("gtag('config', 'G-TEST1234')").expect("the tag is configured");
        assert!(default < config, "consent must be denied before the config call");
        for kind in ["analytics_storage", "ad_storage", "ad_user_data", "ad_personalization"] {
            assert!(page.contains(&format!("{kind}: 'denied'")), "{kind} is not denied by default");
        }
        assert!(page.contains("data-consent=\"granted\"") && page.contains("data-consent=\"denied\""));
        assert!(page.contains("id=\"consent-open\""));
    }

    /// The sign-in, workspace, admin and connection pages are all built on http::page, and never carry the tag.
    #[tokio::test]
    async fn platform_pages_have_no_google_tag() {
        let res = crate::http::page(200, "Sign in", "<h1>Sign in</h1>", None, &[]);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.expect("a body");
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("<title>Sign in</title>"));
        assert!(!html.contains("googletagmanager"));
    }
}
