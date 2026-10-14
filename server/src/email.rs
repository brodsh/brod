// SPDX-License-Identifier: AGPL-3.0-only
// Outgoing email: sign-in links and invitations. One of four ways, picked from the configuration:
//   Resend    RESEND_API_KEY and EMAIL_FROM
//   SMTP      SMTP_URL (smtp:// with STARTTLS, or smtps://) and EMAIL_FROM
//   the log   self-hosted with neither: each message is printed to Brod's log, where only the operator can read it
//   DEV_MODE  messages are logged and the API also returns sign-in links, so tests can follow them
// A hosted server with none of these refuses to send, so nobody is told a link is on its way when it is not.
use lettre::message::Mailbox;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde_json::json;

use crate::config::{Config, Mode};
use crate::problem::{Problem, Result};
use crate::state::State;

enum Transport<'a> {
    Resend { key: &'a str, from: &'a str },
    Smtp { url: &'a str, from: &'a str },
    Log,
    Off,
}

fn transport(cfg: &Config) -> Transport<'_> {
    match (&cfg.resend_api_key, &cfg.smtp_url, &cfg.email_from) {
        (Some(key), _, Some(from)) => Transport::Resend { key, from },
        (None, Some(url), Some(from)) => Transport::Smtp { url, from },
        _ if cfg.dev_mode || cfg.mode == Mode::SelfHosted => Transport::Log,
        _ => Transport::Off,
    }
}

/// One line for the start-up log.
pub fn describe(cfg: &Config) -> String {
    match transport(cfg) {
        Transport::Resend { .. } => "sent through Resend".into(),
        Transport::Smtp { url, .. } => format!("sent through SMTP at {}", smtp_host(url)),
        Transport::Log => "printed to this log (set SMTP_URL or RESEND_API_KEY to send it)".into(),
        Transport::Off => "off: set SMTP_URL or RESEND_API_KEY, or nobody can sign in".into(),
    }
}

/// The host and port of an SMTP URL, without the credentials.
fn smtp_host(url: &str) -> &str {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let rest = rest.rsplit_once('@').map(|(_, h)| h).unwrap_or(rest);
    rest.split(['/', '?']).next().unwrap_or(rest)
}

pub async fn send(st: &State, to: &str, subject: &str, text: &str) -> Result<()> {
    let failed = || Problem::new(502, "email_failed", "We could not send the email. Try again in a minute.");
    match transport(&st.cfg) {
        Transport::Resend { key, from } => {
            let res = st
                .http
                .post("https://api.resend.com/emails")
                .bearer_auth(key)
                .json(&json!({ "from": from, "to": [to], "subject": subject, "text": text }))
                .send()
                .await;
            match res {
                Ok(r) if r.status().is_success() => Ok(()),
                Ok(r) => {
                    let status = r.status();
                    eprintln!("email failed {status} {}", r.text().await.unwrap_or_default());
                    Err(failed())
                }
                Err(e) => {
                    eprintln!("email failed {e}");
                    Err(failed())
                }
            }
        }
        Transport::Smtp { url, from } => {
            let message = (|| -> std::result::Result<Message, String> {
                let from: Mailbox = from.parse().map_err(|e| format!("EMAIL_FROM: {e}"))?;
                let to: Mailbox = to.parse().map_err(|e| format!("recipient: {e}"))?;
                Message::builder().from(from).to(to).subject(subject).body(text.to_string()).map_err(|e| e.to_string())
            })();
            let message = message.map_err(|e| {
                eprintln!("email failed: {e}");
                failed()
            })?;
            let mailer = AsyncSmtpTransport::<Tokio1Executor>::from_url(url).map_err(|e| {
                eprintln!("email failed: SMTP_URL: {e}");
                failed()
            })?;
            mailer.build().send(message).await.map(|_| ()).map_err(|e| {
                eprintln!("email failed: {e}");
                failed()
            })
        }
        Transport::Log => {
            println!("email to {to}: {subject}\n{text}\n");
            Ok(())
        }
        Transport::Off => {
            Err(Problem::new(503, "email_unavailable", "Email is not configured on this server, so sign-in links cannot be sent."))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_the_transport_from_the_configuration() {
        let mut c = Config::for_tests();
        c.dev_mode = false;
        c.mode = Mode::SelfHosted;
        assert!(describe(&c).starts_with("printed to this log"));
        c.mode = Mode::Hosted;
        assert!(describe(&c).starts_with("off"));
        c.smtp_url = Some("smtps://brod:hunter2@smtp.example.test:465".into());
        c.email_from = Some("Brod <brod@example.test>".into());
        assert_eq!(describe(&c), "sent through SMTP at smtp.example.test:465");
        c.resend_api_key = Some("re_test".into());
        assert_eq!(describe(&c), "sent through Resend");
    }
}
