use super::*;
pub fn command(name: &str) -> Result<Command> {
    let mut c = Command::new(std::env::current_exe().map_err(terminal::error)?);
    c.args(["ui", "job", name])
        .stdin(std::process::Stdio::null());
    Ok(c)
}
pub fn run(name: &str) -> Result<()> {
    let _protocol = crate::output::Protocol::enter();
    let signals = Signals::install()?;
    let result = match name {
        "status" => {
            let s = crate::service_status::observe();
            let mut value = s.json();
            value["label"] = json!(s.state.label());
            if let Some(i) = s.installed {
                value["installed"]["inventory"] = i.inventory;
            }
            Ok(value)
        }
        "update" => AppPaths::discover().and_then(|p| {
            crate::app_setup::update_catalog(&p, None).map(|b| json!({"bundle":b.json()}))
        }),
        "setup" | "doctor" => crate::app_setup::ui(&[name]),
        _ => Err(AppError::new("usage", "Неизвестная внутренняя операция")),
    };
    let status = if result.is_ok() {
        ActionStatus::Completed
    } else if signals.requested().is_some() {
        ActionStatus::Cancelled
    } else {
        ActionStatus::Failed
    };
    let outcome = ActionOutcome {
        status,
        data: result.as_ref().ok().cloned().unwrap_or(Value::Null),
        error: result.as_ref().err().map(|e| e.json()["error"].clone()),
        cleanup: "not_needed".into(),
        restoration: "not_needed".into(),
    };
    crate::ui_events::emit_finished(&outcome, &signals)?;
    match status {
        ActionStatus::Completed => Ok(()),
        ActionStatus::Cancelled => Err(AppError::new("cancelled", "Отменено")),
        _ => Err(AppError::new("action", "Операция не завершена")),
    }
}
