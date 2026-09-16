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
pub fn combine<T>(result: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (result, cleanup) {
        (Err(first), Err(second)) => Err(AppError::new(
            first.kind,
            format!("{}; {}", first.message, second.message),
        )),
        (Err(error), _) | (_, Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}
