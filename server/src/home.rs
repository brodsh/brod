// The public landing page at / for people who are not signed in. Signed-in people are sent on to their workspace
// (auth.rs), so the same URL answers differently by cookie: the page may be cached, but only with revalidation and
// "Vary: Cookie", so that someone who has just signed in is never shown a stored copy of it.
use std::sync::LazyLock;

use axum::response::Response;
use sha2::Digest;

use crate::http::{Req, response};
use crate::util::sha256_hex;

pub const PAGE: &str = include_str!("home.html");

/// The ETag: the first 16 hex digits of the page's SHA-256.
static ETAG: LazyLock<String> = LazyLock::new(|| format!("\"{}\"", &sha256_hex(PAGE)[..16]));

pub fn page(req: &Req) -> Response {
    let headers = [
        ("content-type", "text/html; charset=utf-8".to_string()),
        ("cache-control", "public, no-cache".to_string()),
        ("vary", "Cookie".to_string()),
        ("etag", ETAG.clone()),
        ("x-frame-options", "DENY".to_string()),
    ];
    if req.header("if-none-match").is_some_and(|v| v.split(',').any(|t| t.trim() == ETAG.as_str())) {
        return response(304, "", &headers[1..]);
    }
    response(200, PAGE, &headers)
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
    #[test]
    fn links_point_at_real_pages() {
        assert!(super::PAGE.contains("<title>Brod: a cloud for the small software your team builds with AI</title>"));
        assert!(!super::PAGE.contains("href=\"/signin\""));
        for anchor in ["how", "apps", "teams", "pricing", "connect"] {
            assert!(super::PAGE.contains(&format!("id=\"{anchor}\"")), "#{anchor} has no target");
        }
    }

    #[test]
    fn link_previews_have_a_large_picture() {
        let page = super::PAGE;
        assert!(page.contains("<meta property=\"og:image\" content=\"https://brod.sh/og.png\">"));
        assert!(page.contains("<meta name=\"twitter:card\" content=\"summary_large_image\">"));
        assert!(page.contains("<link rel=\"canonical\" href=\"https://brod.sh/\">"));
        // A PNG of 1200 × 630: the width and height sit in the IHDR chunk, after the 8-byte signature.
        let og = super::OG_PNG;
        assert_eq!(&og[..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(u32::from_be_bytes(og[16..20].try_into().unwrap()), 1200);
        assert_eq!(u32::from_be_bytes(og[20..24].try_into().unwrap()), 630);
    }

    #[test]
    fn start_free_leads_to_sign_up_and_status_is_gone() {
        assert_eq!(super::PAGE.matches("href=\"/auth/signup\"").count(), 4);
        assert!(!super::PAGE.contains("href=\"/healthz\""));
    }

    #[test]
    fn google_analytics_waits_for_consent() {
        let page = super::PAGE;
        assert!(page.contains("googletagmanager.com/gtag/js?id=G-CCYYNHQKR7"));
        let default = page.find("gtag('consent', 'default'").expect("consent defaults are set");
        let config = page.find("gtag('config', 'G-CCYYNHQKR7')").expect("the tag is configured");
        assert!(default < config, "consent must be denied before the config call");
        for kind in ["analytics_storage", "ad_storage", "ad_user_data", "ad_personalization"] {
            assert!(page.contains(&format!("{kind}: 'denied'")), "{kind} is not denied by default");
        }
        assert!(page.contains("data-consent=\"granted\"") && page.contains("data-consent=\"denied\""));
    }

    /// The sign-in, workspace, admin and connection pages are all built on http::page, and never carry the tag.
    #[tokio::test]
    async fn platform_pages_have_no_google_tag() {
        let res = crate::http::page(200, "Sign in", "<h1>Sign in</h1>", None, &[]);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.expect("a body");
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("<title>Sign in</title>"));
        assert!(!html.contains("G-CCYYNHQKR7") && !html.contains("googletagmanager"));
    }
}
