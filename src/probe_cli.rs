use crate::{
    diagnostic_http::Probe,
    diagnostic_targets,
    error::{AppError, Result},
    signals::Signals,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path, time::Duration};

pub fn run(options: &[&str]) -> Result<Value> {
    let mut values = BTreeMap::new();
    let mut quic = false;
    let mut index = 0;
    while index < options.len() {
        let key = options[index];
        if key == "--quic" && !quic {
            quic = true;
            index += 1;
            continue;
        }
        if !["--curl", "--targets", "--timeout-ms", "--ca-file"].contains(&key) {
            return Err(AppError::new(
                "usage",
                format!("Неизвестный или повторный параметр: {key}"),
            ));
        }
        let value = options
            .get(index + 1)
            .filter(|v| !v.starts_with("--"))
            .ok_or_else(|| AppError::new("usage", format!("Нет значения для {key}")))?;
        if values.insert(key, *value).is_some() {
            return Err(AppError::new("usage", format!("Повторный параметр: {key}")));
        }
        index += 2;
    }
    let binary = values
        .get("--curl")
        .ok_or_else(|| AppError::new("usage", "Требуется --curl FILE"))?;
    let timeout = values
        .get("--timeout-ms")
        .unwrap_or(&"5000")
        .parse::<u64>()
        .ok()
        .filter(|n| (1..=60000).contains(n))
        .ok_or_else(|| AppError::new("usage", "--timeout-ms: ожидается 1..60000"))?;
    let targets = diagnostic_targets::load(values.get("--targets").map(Path::new))?;
    let signals = Signals::install()?;
    let mut tick = || signals.check();
    let probe = Probe::new(
        Path::new(binary),
        Duration::from_millis(timeout),
        values.get("--ca-file").map(Path::new),
        &mut tick,
    )?;
    let mut results = Vec::new();
    for target in &targets {
        results.push(probe.check(target, false, &mut tick)?);
        if quic {
            results.push(probe.check(target, true, &mut tick)?);
        }
    }
    Ok(
        json!({"targets":targets.iter().map(|t|t.json()).collect::<Vec<_>>(),"results":results,"coverage":"HTTP response checks only; does not establish video playback or Discord voice quality"}),
    )
}
