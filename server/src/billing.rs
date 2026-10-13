// SPDX-License-Identifier: AGPL-3.0-only
// Billing through Stripe. A workspace's plan (free, solo, team) is a Stripe subscription to one of two prices.
//
// Upgrading starts a Stripe Checkout session; changing between paid plans updates the subscription in place; moving
// back to free cancels it at the end of the paid period. The card, receipts and cancellation live in Stripe's customer
// portal. Stripe's signed webhooks (POST /stripe/webhook) are what move workspaces.plan, so allowances follow payment:
// a canceled or unpaid subscription drops the workspace to free, and apps over the free allowance keep running but no
// more can start until it is upgraded again or some are paused.
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::db::{Connection, params};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;

use crate::config::{Config, StripeConfig};
use crate::db::{Sql, event, tx};
use crate::model::{Caller, PLANS, plan_named};
use crate::people::require_role;
use crate::problem::{Problem, Result};
use crate::state::State;
use crate::util::{now, safe_equal};

/// How old a webhook signature may be, as Stripe's own libraries allow.
const TOLERANCE_SEC: i64 = 300;

fn stripe_cfg(cfg: &Config) -> Result<&StripeConfig> {
    cfg.stripe.as_ref().ok_or_else(|| {
        Problem::new(503, "billing_off", "Billing is not set up on this server. Its operator sets STRIPE_SECRET_KEY and the plan prices.")
    })
}

fn price_for(s: &StripeConfig, plan: &str) -> Option<String> {
    match plan {
        "solo" => s.price_solo.clone(),
        "team" => s.price_team.clone(),
        _ => None,
    }
}

fn plan_for_price(s: &StripeConfig, price: &str) -> Option<&'static str> {
    if s.price_solo.as_deref() == Some(price) {
        Some("solo")
    } else if s.price_team.as_deref() == Some(price) {
        Some("team")
    } else {
        None
    }
}

/// One call to the Stripe API, form-encoded the way Stripe expects.
async fn stripe(st: &State, method: reqwest::Method, path: &str, form: &[(&str, String)]) -> Result<Value> {
    let s = stripe_cfg(&st.cfg)?;
    let url = format!("{}/v1/{path}", s.api_base);
    let mut rq = st.http.request(method.clone(), &url).bearer_auth(&s.secret_key);
    if !form.is_empty() {
        let body = form_urlencoded::Serializer::new(String::new()).extend_pairs(form.iter().map(|(k, v)| (*k, v.as_str()))).finish();
        rq = if method == reqwest::Method::GET {
            rq.query(&form.iter().map(|(k, v)| (*k, v.as_str())).collect::<Vec<_>>())
        } else {
            rq.header("content-type", "application/x-www-form-urlencoded").body(body)
        };
    }
    let res = rq.send().await.map_err(|e| Problem::new(502, "stripe_unreachable", format!("Stripe did not answer: {e}")))?;
    let status = res.status();
    let v: Value = res.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let msg = v["error"]["message"].as_str().unwrap_or("Stripe refused the request.");
        return Err(Problem::new(502, "stripe_error", format!("Stripe: {msg}")));
    }
    Ok(v)
}

/// What a price costs, read from Stripe and kept for an hour.
async fn price_info(st: &State, price: &str) -> Option<Value> {
    static CACHE: OnceLock<Mutex<HashMap<String, (Value, Instant)>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some((v, at)) = cache.lock().ok()?.get(price).cloned()
        && at.elapsed() < Duration::from_secs(3600)
    {
        return Some(v);
    }
    let p = stripe(st, reqwest::Method::GET, &format!("prices/{price}"), &[]).await.ok()?;
    let v = json!({
        "amount": p["unit_amount"], "currency": p["currency"],
        "interval": p["recurring"]["interval"], "interval_count": p["recurring"]["interval_count"],
    });
    cache.lock().ok()?.insert(price.to_string(), (v.clone(), Instant::now()));
    Some(v)
}

struct Account {
    customer: Option<String>,
    subscription: Option<String>,
    status: String,
    renews_at: Option<i64>,
    cancel_at: Option<i64>,
}

fn account(conn: &Connection, workspace_id: &str) -> Result<Account> {
    conn.first(
        "SELECT stripe_customer, stripe_subscription, plan_status, plan_renews_at, plan_cancel_at FROM workspaces WHERE id = ?",
        [workspace_id],
        |r| Ok(Account { customer: r.get(0)?, subscription: r.get(1)?, status: r.get(2)?, renews_at: r.get(3)?, cancel_at: r.get(4)? }),
    )?
    .ok_or_else(|| Problem::new(404, "not_found", "No such workspace."))
}

fn live(status: &str) -> bool {
    matches!(status, "active" | "trialing" | "past_due")
}

/// GET /v1/billing: the plan, what it allows and costs, what is used, and the recent invoices.
pub async fn summary(st: &State, c: &Caller) -> Result<Value> {
    require_role(c, "admin", "see billing")?;
    let c2 = c.clone();
    let (acct, running, members, storage, workspace_plan) = st
        .db
        .call(move |conn| {
            let a = account(conn, &c2.workspace.id)?;
            let running = conn.count("SELECT COUNT(*) FROM apps WHERE workspace_id = ? AND status = 'live'", [&c2.workspace.id])?;
            let members = crate::people::member_count(conn, &c2.workspace)?;
            let storage = crate::usage::workspace_storage(conn, &c2.workspace.id)?.total();
            // The plan as stored now, which a webhook may have moved since this request was authenticated.
            let p: String = conn.first("SELECT plan FROM workspaces WHERE id = ?", [&c2.workspace.id], |r| r.get(0))?.unwrap_or_default();
            Ok((a, running, members, storage, p))
        })
        .await?;
    let enabled = st.cfg.stripe.is_some();
    let mut plans = Vec::new();
    for name in PLANS {
        let p = plan_named(name);
        let price = match st.cfg.stripe.as_ref().and_then(|s| price_for(s, name)) {
            Some(id) => price_info(st, &id).await,
            None => None,
        };
        let available = name == "free" || (enabled && st.cfg.stripe.as_ref().and_then(|s| price_for(s, name)).is_some());
        plans.push(json!({
            "id": name, "apps": p.apps, "members": p.members, "storage": p.storage, "analytics_days": p.analytics_days, "price": price,
            "current": name == workspace_plan, "available": available,
        }));
    }
    let invoices = match (&acct.customer, enabled) {
        (Some(cus), true) => stripe(st, reqwest::Method::GET, "invoices", &[("customer", cus.clone()), ("limit", "12".into())])
            .await
            .map(|v| {
                v["data"]
                    .as_array()
                    .map(|list| {
                        list.iter()
                            .map(|i| {
                                json!({
                                    "id": i["id"], "number": i["number"], "status": i["status"], "created": i["created"],
                                    "amount": if i["status"] == "paid" { i["amount_paid"].clone() } else { i["amount_due"].clone() },
                                    "currency": i["currency"], "url": i["hosted_invoice_url"], "pdf": i["invoice_pdf"],
                                })
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            })
            .unwrap_or_default(),
        _ => vec![],
    };
    let limits = plan_named(&workspace_plan);
    Ok(json!({
        "enabled": enabled, "plan": workspace_plan, "status": acct.status,
        "renews_at": acct.renews_at, "cancel_at": acct.cancel_at, "has_customer": acct.customer.is_some(),
        "usage": {
            "running_apps": running, "app_limit": limits.apps, "members": members, "member_limit": limits.members,
            "storage": storage, "storage_limit": limits.storage, "analytics_days": limits.analytics_days,
        },
        "plans": plans, "invoices": invoices,
    }))
}

/// POST /v1/billing/checkout {plan}: start paying for a plan, switch between paid plans, or go back to free.
/// Answers {url} when the person must finish in Stripe, or the new state when the change was made here.
pub async fn change_plan(st: &State, c: &Caller, want: &str) -> Result<Value> {
    require_role(c, "admin", "change the plan")?;
    let s = stripe_cfg(&st.cfg)?.clone();
    if !PLANS.contains(&want) {
        return Err(Problem::new(400, "bad_plan", "Pick a plan: free, solo or team."));
    }
    let wid = c.workspace.id.clone();
    let acct = st.db.call(move |conn| account(conn, &wid)).await?;
    let sub = acct.subscription.clone().filter(|_| live(&acct.status));

    if want == "free" {
        let Some(sub) = sub else { return Ok(json!({ "plan": "free", "changed": false })) };
        let updated =
            stripe(st, reqwest::Method::POST, &format!("subscriptions/{sub}"), &[("cancel_at_period_end", "true".into())]).await?;
        apply(st, &c.workspace.id, &updated, false, &c.actor).await?;
        return Ok(json!({ "plan": c.workspace.plan, "cancel_at_period_end": true }));
    }
    let price = price_for(&s, want).ok_or_else(|| Problem::new(400, "bad_plan", format!("The {want} plan is not on sale here.")))?;

    // Already paying: move the subscription to the other price, prorated, and undo a scheduled cancellation.
    if let Some(sub) = sub {
        let current = stripe(st, reqwest::Method::GET, &format!("subscriptions/{sub}"), &[]).await?;
        let item = current["items"]["data"][0]["id"].as_str().unwrap_or_default().to_string();
        let updated = stripe(
            st,
            reqwest::Method::POST,
            &format!("subscriptions/{sub}"),
            &[
                ("items[0][id]", item),
                ("items[0][price]", price),
                ("proration_behavior", "create_prorations".into()),
                ("cancel_at_period_end", "false".into()),
            ],
        )
        .await?;
        apply(st, &c.workspace.id, &updated, false, &c.actor).await?;
        return Ok(json!({ "plan": want, "changed": true }));
    }

    // New subscription: a Stripe customer for the workspace, then Checkout.
    let customer = match acct.customer {
        Some(cus) => cus,
        None => {
            let cus = stripe(
                st,
                reqwest::Method::POST,
                "customers",
                &[
                    ("email", c.user.email.clone()),
                    ("name", c.workspace.name.clone()),
                    ("metadata[workspace_id]", c.workspace.id.clone()),
                    ("metadata[workspace]", c.workspace.slug.clone()),
                ],
            )
            .await?;
            let id = cus["id"].as_str().unwrap_or_default().to_string();
            let (wid, id2) = (c.workspace.id.clone(), id.clone());
            st.db
                .call(move |conn| conn.run("UPDATE workspaces SET stripe_customer = ? WHERE id = ?", params![id2, wid]).map(|_| ()))
                .await?;
            id
        }
    };
    let back = format!("{}/w/{}/admin#billing", st.cfg.api_origin, c.workspace.slug);
    let session = stripe(
        st,
        reqwest::Method::POST,
        "checkout/sessions",
        &[
            ("mode", "subscription".into()),
            ("customer", customer),
            ("client_reference_id", c.workspace.id.clone()),
            ("line_items[0][price]", price),
            ("line_items[0][quantity]", "1".into()),
            ("subscription_data[metadata][workspace_id]", c.workspace.id.clone()),
            ("allow_promotion_codes", "true".into()),
            ("success_url", format!("{back}/done")),
            ("cancel_url", back),
        ],
    )
    .await?;
    Ok(json!({ "url": session["url"] }))
}

/// POST /v1/billing/portal: a Stripe customer portal session for the card, receipts and cancelling.
pub async fn portal(st: &State, c: &Caller) -> Result<Value> {
    require_role(c, "admin", "manage billing")?;
    stripe_cfg(&st.cfg)?;
    let wid = c.workspace.id.clone();
    let acct = st.db.call(move |conn| account(conn, &wid)).await?;
    let Some(customer) = acct.customer else {
        return Err(Problem::new(409, "no_customer", "This workspace has not paid for a plan yet. Pick a plan first."));
    };
    let back = format!("{}/w/{}/admin#billing", st.cfg.api_origin, c.workspace.slug);
    let session = stripe(st, reqwest::Method::POST, "billing_portal/sessions", &[("customer", customer), ("return_url", back)]).await?;
    Ok(json!({ "url": session["url"] }))
}

// ---------- webhooks ----------

/// Check a Stripe-Signature header ("t=...,v1=...") against the raw body.
pub fn verify_signature(secret: &str, header: &str, body: &[u8], now_sec: i64) -> bool {
    let mut t = None;
    let mut sigs = Vec::new();
    for part in header.split(',') {
        match part.trim().split_once('=') {
            Some(("t", v)) => t = v.parse::<i64>().ok(),
            Some(("v1", v)) => sigs.push(v.to_string()),
            _ => {}
        }
    }
    let Some(t) = t else { return false };
    if (now_sec - t).abs() > TOLERANCE_SEC {
        return false;
    }
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else { return false };
    mac.update(format!("{t}.").as_bytes());
    mac.update(body);
    let want = hex::encode(mac.finalize().into_bytes());
    sigs.iter().any(|s| safe_equal(s, &want))
}

/// The plan, status and dates a subscription implies for a workspace.
pub fn plan_change(s: &StripeConfig, sub: &Value, deleted: bool) -> (Option<&'static str>, String, Option<i64>, Option<i64>) {
    let status = if deleted { "canceled".to_string() } else { sub["status"].as_str().unwrap_or("").to_string() };
    let item = &sub["items"]["data"][0];
    let price = item["price"]["id"].as_str().unwrap_or("");
    let plan = match status.as_str() {
        "active" | "trialing" | "past_due" => plan_for_price(s, price),
        "canceled" | "unpaid" | "incomplete_expired" => Some("free"),
        // incomplete: the first payment has not gone through yet, so nothing changes.
        _ => None,
    };
    // Newer API versions keep the period on the item.
    let renews = sub["current_period_end"].as_i64().or_else(|| item["current_period_end"].as_i64()).map(|s| s * 1000);
    let cancel = if sub["cancel_at_period_end"].as_bool() == Some(true) {
        sub["cancel_at"].as_i64().map(|s| s * 1000).or(renews)
    } else {
        sub["cancel_at"].as_i64().map(|s| s * 1000)
    };
    (plan, status, renews, cancel)
}

fn apply_now(conn: &Connection, s: &StripeConfig, workspace_id: &str, sub: &Value, deleted: bool, actor: &str) -> Result<()> {
    let (plan, status, renews, cancel) = plan_change(s, sub, deleted);
    let old: Option<String> = conn.first("SELECT plan FROM workspaces WHERE id = ?", [workspace_id], |r| r.get(0))?;
    let Some(old) = old else { return Ok(()) };
    let new = plan.map(String::from).unwrap_or_else(|| old.clone());
    let sub_id = if new == "free" { None } else { sub["id"].as_str().map(String::from) };
    conn.run(
        "UPDATE workspaces SET plan = ?, plan_status = ?, plan_renews_at = ?, plan_cancel_at = ?, stripe_subscription = ?,
           stripe_customer = COALESCE(stripe_customer, ?) WHERE id = ?",
        params![new, status, renews, cancel, sub_id, sub["customer"].as_str(), workspace_id],
    )?;
    if new != old {
        event(conn, workspace_id, actor, None, "plan", &format!("{old} to {new} ({status})"))?;
    }
    Ok(())
}

async fn apply(st: &State, workspace_id: &str, sub: &Value, deleted: bool, actor: &str) -> Result<()> {
    let s = stripe_cfg(&st.cfg)?.clone();
    let (w, sub, a) = (workspace_id.to_string(), sub.clone(), actor.to_string());
    st.db.call(move |conn| tx(conn, |x| apply_now(x, &s, &w, &sub, deleted, &a))).await
}

/// The workspace a subscription belongs to: its metadata, or the customer we made for the workspace.
fn workspace_of(conn: &Connection, sub: &Value) -> Result<Option<String>> {
    if let Some(w) = sub["metadata"]["workspace_id"].as_str()
        && conn.exists("SELECT 1 FROM workspaces WHERE id = ?", [w])?
    {
        return Ok(Some(w.to_string()));
    }
    match sub["customer"].as_str() {
        Some(cus) => conn.first("SELECT id FROM workspaces WHERE stripe_customer = ?", [cus], |r| r.get(0)),
        None => Ok(None),
    }
}

/// POST /stripe/webhook. Stripe retries anything but a 2xx, so only a bad signature or our own failure answers otherwise.
pub async fn webhook(st: &State, header: Option<&str>, body: &[u8]) -> Result<Value> {
    let s = stripe_cfg(&st.cfg)?.clone();
    if !verify_signature(&s.webhook_secret, header.unwrap_or(""), body, now() / 1000) {
        return Err(Problem::new(400, "bad_signature", "The Stripe-Signature header does not match this endpoint's secret."));
    }
    let ev: Value = serde_json::from_slice(body)?;
    let (id, kind) = (ev["id"].as_str().unwrap_or("").to_string(), ev["type"].as_str().unwrap_or("").to_string());
    let id2 = id.clone();
    if st.db.call(move |c| c.exists("SELECT 1 FROM stripe_events WHERE id = ?", [id2])).await? {
        return Ok(json!({ "received": true, "duplicate": true }));
    }
    let obj = &ev["data"]["object"];
    // The subscription this event is about, fetched fresh for a finished Checkout.
    let sub = match kind.as_str() {
        "checkout.session.completed" => match obj["subscription"].as_str() {
            Some(sid) => {
                let mut sub = stripe(st, reqwest::Method::GET, &format!("subscriptions/{sid}"), &[]).await?;
                if sub["metadata"]["workspace_id"].is_null()
                    && let Some(w) = obj["client_reference_id"].as_str()
                {
                    sub["metadata"]["workspace_id"] = json!(w);
                }
                Some(sub)
            }
            None => None,
        },
        "customer.subscription.created" | "customer.subscription.updated" | "customer.subscription.deleted" => Some(obj.clone()),
        _ => None,
    };
    let deleted = kind == "customer.subscription.deleted";
    st.db
        .call(move |conn| {
            tx(conn, |x| {
                x.run("INSERT OR IGNORE INTO stripe_events (id, type, received_at) VALUES (?,?,?)", params![id, kind, now()])?;
                if let Some(sub) = &sub
                    && let Some(w) = workspace_of(x, sub)?
                {
                    // A deleted subscription that is not the workspace's current one (an old, replaced one) changes nothing.
                    let current: Option<String> =
                        x.first("SELECT stripe_subscription FROM workspaces WHERE id = ?", [&w], |r| r.get(0))?.flatten();
                    let stale = deleted && current.is_some() && current.as_deref() != sub["id"].as_str();
                    if !stale {
                        apply_now(x, &s, &w, sub, deleted, "stripe")?;
                    }
                }
                Ok(json!({ "received": true }))
            })
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_db;

    fn cfg() -> StripeConfig {
        StripeConfig {
            secret_key: "sk_test".into(),
            webhook_secret: "whsec_test".into(),
            price_solo: Some("price_solo".into()),
            price_team: Some("price_team".into()),
            api_base: "http://stripe.test".into(),
        }
    }

    fn sign(secret: &str, t: i64, body: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(format!("{t}.{body}").as_bytes());
        format!("t={t},v1=deadbeef,v1={}", hex::encode(mac.finalize().into_bytes()))
    }

    #[test]
    fn checks_webhook_signatures() {
        let body = r#"{"id":"evt_1"}"#;
        let h = sign("whsec_test", 1_000_000, body);
        assert!(verify_signature("whsec_test", &h, body.as_bytes(), 1_000_100));
        assert!(!verify_signature("whsec_other", &h, body.as_bytes(), 1_000_100));
        assert!(!verify_signature("whsec_test", &h, b"{\"id\":\"evt_2\"}", 1_000_100));
        // Too old: a replayed event is refused.
        assert!(!verify_signature("whsec_test", &h, body.as_bytes(), 1_000_000 + TOLERANCE_SEC + 1));
        assert!(!verify_signature("whsec_test", "v1=abc", body.as_bytes(), 1_000_000));
    }

    #[test]
    fn maps_subscriptions_to_plans() {
        let s = cfg();
        let sub = |status: &str, price: &str| {
            json!({ "id": "sub_1", "status": status, "customer": "cus_1", "current_period_end": 1_700_000_000,
                     "items": { "data": [{ "price": { "id": price } }] } })
        };
        assert_eq!(plan_change(&s, &sub("active", "price_team"), false).0, Some("team"));
        assert_eq!(plan_change(&s, &sub("past_due", "price_solo"), false).0, Some("solo"));
        assert_eq!(plan_change(&s, &sub("incomplete", "price_team"), false).0, None);
        assert_eq!(plan_change(&s, &sub("unpaid", "price_team"), false).0, Some("free"));
        assert_eq!(plan_change(&s, &sub("active", "price_team"), true).0, Some("free"));
        assert_eq!(plan_change(&s, &sub("active", "price_other"), false).0, None);
        let mut ending = sub("active", "price_solo");
        ending["cancel_at_period_end"] = json!(true);
        let (_, _, renews, cancel) = plan_change(&s, &ending, false);
        assert_eq!((renews, cancel), (Some(1_700_000_000_000), Some(1_700_000_000_000)));
    }

    #[tokio::test]
    async fn applies_a_subscription_to_its_workspace() {
        let db = test_db();
        let r = db
            .call(|c| {
                c.run("INSERT INTO workspaces (id, slug, name, created_at, stripe_customer) VALUES ('ws_b','b','B',1,'cus_1')", ())?;
                let s = cfg();
                let sub = json!({ "id": "sub_1", "status": "active", "customer": "cus_1",
                                  "items": { "data": [{ "price": { "id": "price_team" }, "current_period_end": 1_700_000_000 }] } });
                let w = workspace_of(c, &sub)?.unwrap();
                apply_now(c, &s, &w, &sub, false, "stripe")?;
                let up: (String, String, Option<i64>, Option<String>) = c
                    .first("SELECT plan, plan_status, plan_renews_at, stripe_subscription FROM workspaces WHERE id = 'ws_b'", (), |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                    })?
                    .unwrap();
                apply_now(c, &s, &w, &sub, true, "stripe")?;
                let down: (String, Option<String>) = c
                    .first("SELECT plan, stripe_subscription FROM workspaces WHERE id = 'ws_b'", (), |r| Ok((r.get(0)?, r.get(1)?)))?
                    .unwrap();
                let events = c.count("SELECT COUNT(*) FROM events WHERE workspace_id = 'ws_b' AND action = 'plan'", ())?;
                Ok((up, down, events))
            })
            .await
            .unwrap();
        assert_eq!(r.0, ("team".into(), "active".into(), Some(1_700_000_000_000), Some("sub_1".into())));
        assert_eq!(r.1, ("free".into(), None));
        assert_eq!(r.2, 2);
    }
}
