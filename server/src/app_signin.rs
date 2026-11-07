// SPDX-License-Identifier: AGPL-3.0-only
// Sign-in for an app's own login page. The app designs the page and Brod does the work: these routes, on the app's own
// address, send a code by email, check it and set the app's session cookie. The app's code sees the address and the code
// a person types, and never a session token.
//
// They answer only when the served version names a sign-in page that a person approved as an open path (open_paths.rs),
// so no app can send email through Brod until its owner has agreed. A session made here belongs to this one app: it has
// no platform session behind it, so a code entered on an app's page can never reach the account or another app.
use axum::http::Method;
use axum::response::Response;
use serde_json::{Map, Value, json};

use crate::db::{Sql, params};
use crate::gateway::{APP_COOKIE, admit_staging, app_return};
use crate::http::{Req, json_response};
use crate::model::{AppRow, limits};
use crate::people::{self, SessionUser};
use crate::problem::{Problem, Result};
use crate::state::State;
use crate::util::{is_email, norm_email, now, random_bytes, random_id, safe_equal, set_cookie, sha256_hex};

const BODY_BYTES: usize = 4 * 1024;

fn answer(body: &Value, cookie: Option<String>) -> Response {
    let mut headers = vec![("cache-control", "no-store".to_string())];
    if let Some(c) = cookie {
        headers.push(("set-cookie", c));
    }
    json_response(body, 200, &headers)
}

/// A POST with a JSON body from the app's own pages. A missing or foreign Origin is refused.
fn check_post(req: &Req, origin: &str) -> Result<()> {
    if req.method != Method::POST {
        return Err(Problem::new(405, "method_not_allowed", "Use POST."));
    }
    if !req.is_json() {
        return Err(Problem::new(415, "json_required", "Send a JSON body."));
    }
    if !req.header("origin").is_some_and(|o| o.eq_ignore_ascii_case(origin)) {
        return Err(Problem::new(403, "bad_origin", "Sign-in requests must come from the app's own pages."));
    }
    Ok(())
}

async fn body(req: &mut Req) -> Result<Map<String, Value>> {
    let raw = req.bytes(BODY_BYTES, "The request").await?;
    match serde_json::from_slice(&raw) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err(Problem::new(400, "bad_json", "The request body is not a JSON object.")),
    }
}

fn field<'a>(b: &'a Map<String, Value>, key: &str) -> &'a str {
    b.get(key).and_then(Value::as_str).unwrap_or("")
}

fn new_code() -> String {
    let mut b = [0u8; 8];
    b.copy_from_slice(&random_bytes(8));
    format!("{:06}", u64::from_le_bytes(b) % 1_000_000)
}

fn code_hash(app_id: &str, email: &str, code: &str) -> String {
    sha256_hex(&format!("sign-in:{app_id}:{email}:{code}"))
}

/// The app's name for an email: one line, and short. The address under it says where the code belongs.
fn name_for_email(name: &str) -> String {
    let one_line: String = name.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let short: String = one_line.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(60).collect();
    if short.is_empty() { "this app".to_string() } else { short }
}

fn email_text(name: &str, code: &str, origin: &str) -> String {
    format!(
        "Your sign-in code for {name} is:\n\n{code}\n\nIt works once and expires in {} minutes. Only enter it at {origin}.\n\nIf you did not ask for it, ignore this email.\n\nSent by Brod for {origin}",
        limits::APP_SIGN_IN_CODE_TTL_MS / 60_000
    )
}

/// POST /_brod/auth/start { email }: email a sign-in code.
pub async fn start(st: &State, req: &mut Req, app: &AppRow, origin: &str) -> Result<Response> {
    check_post(req, origin)?;
    let b = body(req).await?;
    let email = norm_email(field(&b, "email"));
    if !is_email(&email) {
        return Err(Problem::new(400, "bad_email", "That does not look like an email address."));
    }
    let code = new_code();
    let t = now();
    let row = (random_id("", 12), app.id.clone(), email.clone(), code_hash(&app.id, &email, &code));
    let (cfg, ip) = (st.cfg.clone(), crate::abuse::client_ip(&st.cfg, req));
    st.db
        .call(move |c| {
            let (id, app_id, email, hash) = row;
            crate::allowances::check_new_signin(c, &cfg, &email)?;
            if let Some(ip) = &ip {
                crate::abuse::rate_limit(
                    c,
                    // Not the platform's bucket: an office logging in to one app must not lock its people out of Brod.
                    "app_signin_ip",
                    ip,
                    limits::APP_SIGN_IN_CODES_PER_IP_HOUR,
                    crate::abuse::HOUR,
                    "Too many sign-in codes were asked for from your network in the last hour.",
                )?;
            }
            // Counted across apps, so that many apps together cannot flood one inbox.
            crate::abuse::rate_limit(
                c,
                "signin_email",
                &email,
                limits::LOGIN_LINKS_PER_HOUR,
                crate::abuse::HOUR,
                "Too many sign-in codes for this address.",
            )?;
            crate::abuse::rate_limit(
                c,
                "signin_app",
                &app_id,
                limits::APP_SIGN_IN_CODES_PER_HOUR,
                crate::abuse::HOUR,
                "This app has sent too many sign-in codes in the last hour.",
            )?;
            c.run("DELETE FROM app_sign_in_codes WHERE expires_at < ?", [t])?;
            c.run(
                "UPDATE app_sign_in_codes SET used_at = ? WHERE app_id = ? AND email = ? AND used_at IS NULL",
                params![t, app_id, email],
            )?;
            c.run(
                "INSERT INTO app_sign_in_codes (id, app_id, email, hash, created_at, expires_at) VALUES (?,?,?,?,?,?)",
                params![id, app_id, email, hash, t, t + limits::APP_SIGN_IN_CODE_TTL_MS],
            )?;
            Ok(())
        })
        .await?;
    let name = name_for_email(&app.name);
    crate::email::send(st, &email, &format!("Your sign-in code for {name}"), &email_text(&name, &code, origin)).await?;
    let mut out = json!({ "sent": true, "email": email });
    if st.cfg.dev_mode {
        out["dev_code"] = json!(code);
    }
    Ok(answer(&out, None))
}

/// POST /_brod/auth/verify { email, code, return }: swap a code for this app's session. `allowed` says whether the app is
/// shared with the person, so the page can tell them instead of sending them to an address that shows nothing.
pub async fn verify(st: &State, req: &mut Req, app: &AppRow, origin: &str, staging: bool) -> Result<Response> {
    check_post(req, origin)?;
    let b = body(req).await?;
    let email = norm_email(field(&b, "email"));
    let code: String = field(&b, "code").chars().filter(char::is_ascii_digit).collect();
    let back = app_return(b.get("return").and_then(Value::as_str).map(String::from));
    let want = code_hash(&app.id, &email, &code);
    let (cfg, ip, app2) = (st.cfg.clone(), crate::abuse::client_ip(&st.cfg, req), app.clone());
    let signed = st
        .db
        .call(move |c| {
            if let Some(ip) = &ip {
                crate::abuse::rate_limit(
                    c,
                    "signin_verify_ip",
                    ip,
                    limits::APP_SIGN_IN_CHECKS_PER_IP_HOUR,
                    crate::abuse::HOUR,
                    "Too many sign-in attempts from your network in the last hour.",
                )?;
            }
            let t = now();
            let row = c.first(
                "SELECT id, hash FROM app_sign_in_codes WHERE app_id = ? AND email = ? AND used_at IS NULL AND expires_at > ? ORDER BY created_at DESC LIMIT 1",
                params![app2.id, email, t],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )?;
            let Some((id, hash)) = row else { return Ok(None) };
            // Counted before the comparison, and kept when the comparison fails.
            let tries = c.first(
                "UPDATE app_sign_in_codes SET attempts = attempts + 1 WHERE id = ? AND used_at IS NULL AND attempts < ? RETURNING attempts",
                params![id, limits::APP_SIGN_IN_CODE_TRIES],
                |r| r.get::<_, i64>(0),
            )?;
            let Some(tries) = tries else { return Ok(None) };
            if !safe_equal(&hash, &want) {
                if tries >= limits::APP_SIGN_IN_CODE_TRIES {
                    c.run("UPDATE app_sign_in_codes SET used_at = ? WHERE id = ?", params![t, id])?;
                }
                return Ok(None);
            }
            if c.run("UPDATE app_sign_in_codes SET used_at = ? WHERE id = ? AND used_at IS NULL", params![t, id])? == 0 {
                return Ok(None);
            }
            crate::allowances::check_new_signin(c, &cfg, &email)?;
            let user = people::verified_user(c, &email, "")?;
            let token = people::create_session(c, &user.id, Some(&app2.id), None)?;
            let visitor = people::session_user(c, &token, Some(&app2.id))?;
            let mut decision = people::decide(c, &app2, Some(&user))?;
            if staging {
                admit_staging(&app2, &mut decision, visitor.as_ref().map(|v| &v.user));
            }
            Ok(Some((token, decision.allowed)))
        })
        .await?;
    let Some((token, allowed)) = signed else {
        return Err(Problem::new(400, "bad_code", "That code is wrong or has expired. Check it, or ask for a new one."));
    };
    let cookie = set_cookie(origin, APP_COOKIE, &token, limits::SESSION_TTL_MS / 1000);
    Ok(answer(&json!({ "ok": true, "allowed": allowed, "return": back }), Some(cookie)))
}

/// GET /_brod/auth/methods: how a person can sign in here, for the page to offer.
pub fn methods(st: &State, req: &Req, app: &AppRow) -> Response {
    answer(
        &json!({
            "email": true,
            "google": st.cfg.google_client_id.is_some(),
            "app": { "name": app.name },
            "return": app_return(req.param("return")),
        }),
        None,
    )
}

/// POST /_brod/auth/signout: end this person's session and stay on the app's own pages.
pub async fn sign_out(st: &State, req: &Req, origin: &str, visitor: Option<SessionUser>) -> Result<Response> {
    check_post(req, origin)?;
    if let Some(hash) = visitor.map(|v| v.parent.unwrap_or(v.hash)) {
        st.db.call(move |c| people::revoke_session(c, &hash)).await?;
    }
    Ok(answer(&json!({ "ok": true }), Some(set_cookie(origin, APP_COOKIE, "", 0))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_is_six_digits() {
        for _ in 0..200 {
            let c = new_code();
            assert_eq!(c.len(), 6);
            assert!(c.chars().all(|d| d.is_ascii_digit()));
        }
    }

    #[test]
    fn a_code_belongs_to_one_app_and_one_address() {
        let h = code_hash("app_a", "a@x.test", "123456");
        assert_ne!(h, code_hash("app_b", "a@x.test", "123456"));
        assert_ne!(h, code_hash("app_a", "b@x.test", "123456"));
    }

    #[test]
    fn an_app_name_stays_one_short_line_in_an_email() {
        assert_eq!(name_for_email("Acme\r\nBcc: x@evil.test"), "Acme Bcc: x@evil.test");
        assert_eq!(name_for_email("  \n "), "this app");
        assert_eq!(name_for_email(&"n".repeat(200)).chars().count(), 60);
    }

    #[test]
    fn the_email_says_where_the_code_belongs() {
        let t = email_text("Sanga", "123456", "https://sanga.example.com");
        assert!(t.contains("123456") && t.contains("Only enter it at https://sanga.example.com"));
    }
}
