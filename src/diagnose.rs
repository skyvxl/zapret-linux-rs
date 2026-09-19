use crate::{
    config::Config,
    diagnostic_http::Probe,
    diagnostic_targets,
    error::{AppError, Result},
    lifecycle, output, queue_owner, queue_probe,
    signals::Signals,
    validation::resolve_strategy,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::Path, time::Duration};

fn usage(message: impl Into<String>) -> AppError {
    AppError::new("usage", message)
}

fn candidates(directory: &Path, selected: Option<&str>) -> Result<Vec<String>> {
    if let Some(name) = selected {
        let file = resolve_strategy(directory, name)?;
        return Ok(vec![
            file.file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| usage("Имя стратегии должно быть UTF-8"))?
                .to_owned(),
        ]);
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(directory).map_err(|e| AppError::new("strategy", e.to_string()))? {
        let entry = entry.map_err(|e| AppError::new("strategy", e.to_string()))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| usage("Имена стратегий должны быть UTF-8"))?;
        // Flowseal ships its Windows service manager alongside the strategies.
        if name.eq_ignore_ascii_case("service.bat") || !name.to_ascii_lowercase().ends_with(".bat")
        {
            continue;
        }
        let kind = entry
            .file_type()
            .map_err(|e| AppError::new("strategy", e.to_string()))?;
        if !kind.is_file() && !kind.is_symlink() {
            continue;
        }
        if name.len() > 255 || name.chars().any(char::is_control) {
            return Err(usage("Некорректное имя стратегии"));
        }
        names.push(name);
        if names.len() > 128 {
            return Err(usage("Не более 128 стратегий за один прогон"));
        }
    }
    names.sort();
    if names.is_empty() {
        return Err(AppError::new("strategy", "В каталоге нет стратегий .bat"));
    }
    Ok(names)
}

fn all_passed(row: &Value, transport: &str) -> bool {
    if row["status"] != "tested" || row["cleanup_confirmed"] != true {
        return false;
    }
    let Some(checks) = row["checks"].as_array() else {
        return false;
    };
    let required: Vec<_> = checks
        .iter()
        .filter(|c| c["transport"] == transport && c["required"] == true)
        .collect();
    !required.is_empty() && required.iter().all(|c| c["status"] == "passed")
}

fn report(rows: &[Value], targets: &[Value], aborted: bool, reason: Option<&str>) -> Value {
    let passed = |transport| {
        rows.iter()
            .filter(|r| all_passed(r, transport))
            .map(|r| r["strategy"].clone())
            .collect::<Vec<_>>()
    };
    let both = rows
        .iter()
        .filter(|r| all_passed(r, "tcp") && all_passed(r, "quic"))
        .map(|r| r["strategy"].clone())
        .collect::<Vec<_>>();
    json!({"version":1,"status":if aborted {"aborted"} else {"completed"},"abort_reason":reason,
        "strategies":rows,"targets":targets,"tcp_passed":passed("tcp"),"quic_passed":passed("quic"),"both_passed":both,
        "route":"direct","coverage":"HTTP availability only; video playback and voice were not tested",
        "configuration_changed":false})
}

fn table(report: &Value) -> String {
    let mut text = String::from("Стратегия\tTCP\tQUIC\tПроверки сайтов\n");
    for row in report["strategies"].as_array().into_iter().flatten() {
        let checks = row["checks"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|c| {
                format!(
                    "{}:{}={}",
                    c["target"].as_str().unwrap_or("?"),
                    c["transport"].as_str().unwrap_or("?"),
                    c["status"].as_str().unwrap_or("?")
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        text.push_str(&format!(
            "{}\t{}\t{}\t{}{}\n",
            row["strategy"].as_str().unwrap_or("?"),
            if all_passed(row, "tcp") {
                "passed"
            } else {
                "—"
            },
            if all_passed(row, "quic") {
                "passed"
            } else {
                "—"
            },
            row["status"].as_str().unwrap_or("?"),
            if checks.is_empty() {
                String::new()
            } else {
                format!(": {checks}")
            }
        ));
    }
    text.push_str("HTTP-проверки не подтверждают воспроизведение видео или голосовую связь.\n");
    text
}

pub fn run(args: &[&str]) -> Result<()> {
    let mut options = BTreeMap::new();
    let mut quic = false;
    let mut index = 0;
    while index < args.len() {
        let key = args[index];
        if key == "--quic" && !quic {
            quic = true;
            index += 1;
            continue;
        }
        if ![
            "--config",
            "--strategies",
            "--assets",
            "--nfqws",
            "--nft",
            "--iptables-save",
            "--ip6tables-save",
            "--state-dir",
            "--timeout-ms",
            "--curl",
            "--targets",
            "--probe-timeout-ms",
            "--ca-file",
            "--strategy",
        ]
        .contains(&key)
        {
            return Err(usage(format!("Неизвестный или повторный параметр: {key}")));
        }
        let value = *args
            .get(index + 1)
            .ok_or_else(|| usage(format!("Нет значения для {key}")))?;
        if value.starts_with("--") || options.insert(key, value).is_some() {
            return Err(usage(format!("Нет значения или повторный параметр: {key}")));
        }
        index += 2;
    }
    let required = |key| {
        options
            .get(key)
            .copied()
            .ok_or_else(|| usage(format!("Требуется {key}")))
    };
    for key in [
        "--config",
        "--strategies",
        "--assets",
        "--nfqws",
        "--nft",
        "--iptables-save",
        "--ip6tables-save",
        "--state-dir",
        "--curl",
    ] {
        required(key)?;
    }
    let millis = |key: &str, default| {
        options
            .get(key)
            .copied()
            .unwrap_or(default)
            .parse::<u64>()
            .ok()
            .filter(|n| (1..=60000).contains(n))
            .map(Duration::from_millis)
            .ok_or_else(|| usage(format!("{key}: ожидается 1..60000")))
    };
    let timeout = millis("--timeout-ms", "5000")?;
    let probe_timeout = millis("--probe-timeout-ms", "5000")?;
    Config::load(Path::new(required("--config")?))?;
    let names = candidates(
        Path::new(required("--strategies")?),
        options.get("--strategy").copied(),
    )?;
    let targets = diagnostic_targets::load(options.get("--targets").map(Path::new))?;
    if !targets.iter().any(|t| t.required) {
        return Err(usage("Нужна хотя бы одна обязательная цель"));
    }
    let target_json: Vec<_> = targets.iter().map(|t| t.json()).collect();
    let mut rows: Vec<_> = names
        .iter()
        .map(
            |name| json!({"strategy":name,"status":"not_run","checks":[],"cleanup_confirmed":true}),
        )
        .collect();
    let signals = Signals::install()?;
    output::emit(
        json!({"event":"diagnosis_started","strategy_order":names,"targets":target_json,"quic":quic}),
        &signals,
        timeout,
        false,
    )?;
    let probe = Probe::new(
        Path::new(required("--curl")?),
        probe_timeout,
        options.get("--ca-file").map(Path::new),
        &mut || signals.check(),
    );
    let mut abort = None;
    if let Err(error) = &probe {
        abort = Some(error.message.clone());
    }
    let mut runtime = vec!["--host"];
    for (key, value) in &options {
        if [
            "--config",
            "--strategies",
            "--assets",
            "--nfqws",
            "--nft",
            "--iptables-save",
            "--ip6tables-save",
            "--state-dir",
            "--timeout-ms",
        ]
        .contains(key)
        {
            runtime.extend([*key, *value]);
        }
    }
    if let Ok(probe) = probe {
        for (index, name) in names.iter().enumerate() {
            if let Err(error) = signals.check() {
                abort = Some(error.message);
                break;
            }
            if output::is_human() {
                output::emit(
                    json!({"event":"strategy_started","strategy":name}),
                    &signals,
                    timeout,
                    false,
                )?;
            }
            let mut checks = Vec::new();
            let mut evidence = Value::Null;
            let mut ready_reached = false;
            let mut sink_failed = false;
            let outcome = lifecycle::supervise(
                &runtime,
                Some(name),
                &signals,
                |child, ready, _, _| {
                    evidence = ready.clone();
                    ready_reached = true;
                    output::emit(
                        json!({"event":"strategy_ready","strategy":name,"engine_pid":child.id()}),
                        &signals,
                        timeout,
                        true,
                    )
                    .inspect_err(|e| {
                        sink_failed = e.kind != "interrupted";
                    })?;
                    for target in &targets {
                        for transport in [false, true].into_iter().filter(|q| !q || quic) {
                            let mut tick = || {
                                signals.check()?;
                                queue_probe::alive(child)?;
                                queue_owner::require(child.id())
                            };
                            if output::is_human() {
                                output::emit(json!({"event":"probe_started","strategy":name,"target":target.id,"transport":if transport {"quic"} else {"tcp"}}), &signals, timeout, true)
                                    .inspect_err(|e| { sink_failed = e.kind != "interrupted"; })?;
                            }
                            let result = probe.check(target, transport, &mut tick)?;
                            tick()?;
                            checks.push(result.clone());
                            output::emit(
                                json!({"event":"probe_result","strategy":name,"result":result}),
                                &signals,
                                timeout,
                                true,
                            )
                            .inspect_err(|e| {
                                sink_failed = e.kind != "interrupted";
                            })?;
                        }
                    }
                    Ok(())
                },
            );
            if sink_failed {
                return outcome.result;
            }
            let failed = outcome.result.as_ref().err();
            let fatal = !outcome.cleanup_confirmed
                || failed.is_some_and(|e| {
                    [
                        "interrupted",
                        "permissions",
                        "locked",
                        "state",
                        "preflight",
                        "signal",
                        "output",
                        "curl",
                    ]
                    .contains(&e.kind)
                        || (ready_reached
                            && ["engine", "readiness", "timeout", "process"].contains(&e.kind))
                });
            rows[index] = json!({"strategy":name,"status":if failed.is_some() {"failed"} else {"tested"},
                "checks":checks,"cleanup_confirmed":outcome.cleanup_confirmed,"error":failed.map(|e| e.json()["error"].clone()),
                "execution":evidence,"shutdown":outcome.stopped});
            output::emit(
                json!({"event":"strategy_complete","result":rows[index]}),
                &signals,
                timeout,
                false,
            )?;
            if fatal {
                abort = Some(
                    failed.map_or("Не подтверждена очистка".to_owned(), |e| e.message.clone()),
                );
                break;
            }
        }
    }
    let final_report = report(&rows, &target_json, abort.is_some(), abort.as_deref());
    output::emit(
        json!({"event":"diagnosis_complete","report":final_report}),
        &signals,
        timeout,
        false,
    )?;
    if !output::is_human() {
        output::stderr(&table(&final_report), &signals, timeout)?;
    }
    if let Some(reason) = abort {
        return Err(AppError::new("diagnosis_aborted", reason));
    }
    Ok(())
}
