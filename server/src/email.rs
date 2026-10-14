// Outgoing email: sign-in links and invitations. Sent through Resend when RESEND_API_KEY is set, from EMAIL_FROM
// (config.rs requires both together).
// With DEV_MODE=1 messages are logged instead, and the API returns the link so tests can follow it.
use serde_json::json;

use crate::problem::{Problem, Result};
use crate::state::State;

pub async fn send(st: &State, to: &str, subject: &str, text: &str) -> Result<()> {
    if let (Some(key), Some(from)) = (&st.cfg.resend_api_key, &st.cfg.email_from) {
        let res = st
            .http
            .post("https://api.resend.com/emails")
            .bearer_auth(key)
            .json(&json!({ "from": from, "to": [to], "subject": subject, "text": text }))
            .send()
            .await;
        return match res {
            Ok(r) if r.status().is_success() => Ok(()),
            Ok(r) => {
                let status = r.status();
                eprintln!("email failed {status} {}", r.text().await.unwrap_or_default());
                Err(Problem::new(502, "email_failed", "We could not send the email. Try again in a minute."))
            }
            Err(e) => {
                eprintln!("email failed {e}");
                Err(Problem::new(502, "email_failed", "We could not send the email. Try again in a minute."))
            }
        };
    }
    if st.cfg.dev_mode {
        println!("[email to {to}] {subject}\n{text}");
        return Ok(());
    }
    Err(Problem::new(503, "email_unavailable", "Email is not configured on this server, so sign-in links cannot be sent."))
}
