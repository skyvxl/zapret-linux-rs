use serde_json::{Value, json};

#[derive(Debug)]
pub struct AppError {
    pub kind: &'static str,
    pub message: String,
}

pub type Result<T> = std::result::Result<T, AppError>;

impl AppError {
    pub fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn json(&self) -> Value {
        json!({"error": {"kind": self.kind, "message": self.message}})
    }
}
