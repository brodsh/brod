// An error the caller can act on. `code` is stable; `message` is written for a person or an agent.
// Renders as {"error": {code, message, ...extra}}.
use axum::response::Response;
use serde_json::{Map, Value, json};

use crate::http::json_response;

#[derive(Debug, Clone)]
pub struct Problem {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub extra: Box<Map<String, Value>>,
    /// Set for failures that are ours rather than the caller's; they answer as `internal`.
    pub internal: Option<Box<str>>,
}

pub type Result<T, E = Problem> = std::result::Result<T, E>;

impl Problem {
    pub fn new(status: u16, code: &str, message: impl Into<String>) -> Self {
        Problem { status, code: code.to_string(), message: message.into(), extra: Box::default(), internal: None }
    }
    pub fn with(mut self, key: &str, value: Value) -> Self {
        self.extra.insert(key.to_string(), value);
        self
    }
    /// Something went wrong on our side. The detail is logged, never shown.
    pub fn internal(detail: impl std::fmt::Display) -> Self {
        Problem {
            status: 500,
            code: "internal".into(),
            message: "Something went wrong on our side. Try again.".into(),
            extra: Box::default(),
            internal: Some(detail.to_string().into()),
        }
    }
    pub fn is_internal(&self) -> bool {
        self.internal.is_some()
    }

    /// The JSON body the API answers with.
    pub fn body(&self) -> Value {
        let mut e = Map::new();
        e.insert("code".into(), json!(self.code));
        e.insert("message".into(), json!(self.message));
        for (k, v) in self.extra.iter() {
            e.insert(k.clone(), v.clone());
        }
        json!({ "error": e })
    }

    pub fn response(&self) -> Response {
        if let Some(detail) = &self.internal {
            eprintln!("error: {detail}");
        }
        json_response(&self.body(), self.status, &[])
    }
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.internal.as_deref().unwrap_or(&self.message))
    }
}

impl From<rusqlite::Error> for Problem {
    fn from(e: rusqlite::Error) -> Self {
        Problem::internal(format!("database: {e}"))
    }
}
impl From<postgres::Error> for Problem {
    fn from(e: postgres::Error) -> Self {
        Problem::internal(format!("database: {e}"))
    }
}
impl From<serde_json::Error> for Problem {
    fn from(e: serde_json::Error) -> Self {
        Problem::internal(format!("json: {e}"))
    }
}
impl From<std::io::Error> for Problem {
    fn from(e: std::io::Error) -> Self {
        Problem::internal(format!("io: {e}"))
    }
}
