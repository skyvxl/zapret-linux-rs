use crate::config::Config;
use serde_json::{Value, json};
pub struct PreparedInputs {
    pub config: std::path::PathBuf,
    pub bundle: std::path::PathBuf,
    pub config_sha256: String,
    pub bundle_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeState {
    Absent,
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
    Unavailable,
    Unknown,
    RecoveryRequired,
}
impl RuntimeState {
    pub fn name(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Stopped => "stopped",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Failed => "failed",
            Self::Unavailable => "unavailable",
            Self::Unknown => "unknown",
            Self::RecoveryRequired => "recovery_required",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Absent => "Фоновый режим не настроен",
            Self::Stopped => "Остановлен",
            Self::Starting => "Запускается",
            Self::Running => "Работает в фоне",
            Self::Stopping => "Останавливается",
            Self::Failed => "Ошибка запуска",
            Self::Unavailable => "Фоновый режим недоступен",
            Self::Unknown => "Не удалось определить",
            Self::RecoveryRequired => "Требуется восстановление",
        }
    }
}
#[derive(Clone, Debug)]
pub struct InstalledConfig {
    pub installation_id: String,
    pub strategy: String,
    pub config: Config,
    pub inventory: Value,
}
#[derive(Clone, Debug)]
pub struct ServiceView {
    pub state: RuntimeState,
    pub enabled: Option<bool>,
    pub installed: Option<InstalledConfig>,
    pub running_strategy: Option<String>,
    pub detail: Option<String>,
}
impl ServiceView {
    pub fn json(&self) -> Value {
        json!({"state":self.state.name(),"enabled":self.enabled,
            "installed":self.installed.as_ref().map(|i|json!({"installation_id":i.installation_id,"strategy":i.strategy,"config":i.config.json()})),
            "running_strategy":self.running_strategy,"detail":self.detail})
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionStatus {
    Completed,
    Cancelled,
    Failed,
    NeedsRecovery,
}
impl ActionStatus {
    pub fn name(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::NeedsRecovery => "needs_recovery",
        }
    }
    pub fn code(self) -> i32 {
        match self {
            Self::Completed => 0,
            Self::Cancelled => 130,
            _ => 1,
        }
    }
}
#[derive(Debug, Clone)]
pub struct ActionOutcome {
    pub status: ActionStatus,
    pub data: Value,
    pub cleanup: String,
    pub restoration: String,
    pub error: Option<Value>,
}
impl ActionOutcome {
    pub fn json(&self) -> Value {
        json!({"status":self.status.name(),"data":self.data,"cleanup":self.cleanup,"restoration":self.restoration,"error":self.error})
    }
    pub fn parse(v: &Value) -> crate::error::Result<Self> {
        let bad = || crate::error::AppError::new("protocol", "Некорректный итог действия");
        let status = match v["status"].as_str() {
            Some("completed") => ActionStatus::Completed,
            Some("cancelled") => ActionStatus::Cancelled,
            Some("failed") => ActionStatus::Failed,
            Some("needs_recovery") => ActionStatus::NeedsRecovery,
            _ => return Err(bad()),
        };
        let cleanup = v["cleanup"]
            .as_str()
            .filter(|s| ["confirmed", "not_needed", "unknown"].contains(s))
            .ok_or_else(bad)?;
        let restoration = v["restoration"]
            .as_str()
            .filter(|s| ["restored", "not_needed", "failed", "unknown"].contains(s))
            .ok_or_else(bad)?;
        if status == ActionStatus::Completed
            && (cleanup == "unknown"
                || ["failed", "unknown"].contains(&restoration)
                || !v["error"].is_null())
        {
            return Err(bad());
        }
        if v.as_object()
            .is_none_or(|o| o.len() != 5 || !o.contains_key("data") || !o.contains_key("error"))
        {
            return Err(bad());
        }
        Ok(Self {
            status,
            data: v["data"].clone(),
            cleanup: cleanup.into(),
            restoration: restoration.into(),
            error: (!v["error"].is_null()).then(|| v["error"].clone()),
        })
    }
}
