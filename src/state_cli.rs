use crate::{
    error::{AppError, Result, combine},
    nft::Nft,
    state_dir::StateDir,
    state_record::Record,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path, time::Duration};

pub fn run(args: &[&str]) -> Result<Value> {
    let Some((&mode, args)) = args.split_first() else {
        return Err(AppError::new(
            "usage",
            "Требуется state inspect или state recover",
        ));
    };
    if !["inspect", "recover"].contains(&mode) {
        return Err(AppError::new("usage", "Неизвестная команда state"));
    }
    let previous_count = args
        .iter()
        .filter(|a| **a == "--allow-previous-boot")
        .count();
    if previous_count > 1 || (previous_count != 0 && mode != "recover") {
        return Err(AppError::new(
            "usage",
            "--allow-previous-boot допустим один раз для state recover",
        ));
    }
    let allow_previous_boot = previous_count == 1;
    let args: Vec<_> = args
        .iter()
        .copied()
        .filter(|a| *a != "--allow-previous-boot")
        .collect();
    let mut options = BTreeMap::new();
    for pair in args.chunks(2) {
        if pair.len() != 2
            || !["--state-dir", "--nft", "--timeout-ms"].contains(&pair[0])
            || pair[1].starts_with("--")
            || (mode == "inspect" && pair[0] != "--state-dir")
            || options.insert(pair[0], pair[1]).is_some()
        {
            return Err(AppError::new(
                "usage",
                "Некорректные или повторные параметры state",
            ));
        }
    }
    let directory = options
        .get("--state-dir")
        .ok_or_else(|| AppError::new("usage", "Требуется --state-dir"))?;
    let timeout = options
        .get("--timeout-ms")
        .unwrap_or(&"5000")
        .parse::<u64>()
        .ok()
        .filter(|n| (1..=60000).contains(n))
        .ok_or_else(|| AppError::new("usage", "--timeout-ms: ожидается 1..60000"))?;
    let nft = if mode == "recover" {
        let path = options
            .get("--nft")
            .ok_or_else(|| AppError::new("usage", "Требуется --nft"))?;
        let path = Path::new(path)
            .canonicalize()
            .map_err(|e| AppError::new("firewall", e.to_string()))?;
        if !path.is_file() {
            return Err(AppError::new("firewall", "nft должен быть обычным файлом"));
        }
        Some(path)
    } else {
        None
    };
    let directory = StateDir::open(Path::new(directory))?;
    if mode == "inspect" {
        return match directory.read()? {
            None => Ok(json!({"state":{"status":"empty"}})),
            Some(value) => {
                let record = Record::parse(value)?;
                Ok(
                    json!({"state":{"status":if record.previous_boot()? {"previous_boot"} else if record.owner_alive()? {"running"} else {"recovery_required"}, "record":record.json()}}),
                )
            }
        };
    }
    let lease = directory.lock()?;
    let Some(value) = lease.read()? else {
        return Ok(json!({"state":{"status":"empty","cleanup":"not_needed"}}));
    };
    let record = Record::parse(value)?;
    if record.previous_boot()? && allow_previous_boot {
        if record.scope() != "current_network_namespace" {
            return Err(AppError::new(
                "state",
                "Истечение после перезагрузки разрешено только для журнала текущей сети",
            ));
        }
        crate::host_run::context()?;
        let _network_guard = crate::host_run::lock_network()?;
        let nft = Nft {
            binary: nft
                .as_ref()
                .ok_or_else(|| AppError::new("usage", "Требуется --nft"))?,
            timeout: Duration::from_millis(timeout),
        };
        require_absent(&nft)?;
        lease.clear()?;
        return Ok(
            json!({"state":{"status":"expired_previous_boot","scope":record.scope(),"cleanup":"not_needed"}}),
        );
    }
    record.validate_recovery()?;
    let _network_guard = if record.scope() == "current_network_namespace" {
        crate::host_run::context()?;
        Some(crate::host_run::lock_network()?)
    } else {
        None
    };
    let binary = nft
        .as_ref()
        .ok_or_else(|| AppError::new("usage", "Требуется --nft"))?;
    let nft = Nft {
        binary,
        timeout: Duration::from_millis(timeout),
    };
    let mut result = Ok(());
    for table in record.tables() {
        result = combine(result, table.remove(&nft));
    }
    result?;
    lease.clear()?;
    Ok(json!({"state":{"status":"recovered","scope":record.scope(),"cleanup":"removed"}}))
}

fn require_absent(nft: &Nft<'_>) -> Result<()> {
    let entries = nft.list("previous-boot", &["--json", "list", "tables"])?;
    for entry in entries {
        let object = entry
            .as_object()
            .filter(|o| o.len() == 1)
            .ok_or_else(|| AppError::new("state", "Неизвестный формат списка таблиц"))?;
        if let Some(meta) = object.get("metainfo") {
            if meta.get("json_schema_version") != Some(&json!(1)) {
                return Err(AppError::new("state", "Неизвестная схема списка таблиц"));
            }
            continue;
        }
        let table = object
            .get("table")
            .and_then(Value::as_object)
            .ok_or_else(|| AppError::new("state", "Неполный список таблиц"))?;
        let family = table
            .get("family")
            .and_then(Value::as_str)
            .filter(|s| ["inet", "ip", "ip6", "arp", "bridge", "netdev"].contains(s))
            .ok_or_else(|| AppError::new("state", "Неизвестное семейство таблицы"))?;
        let name = table
            .get("name")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| AppError::new("state", "Нет имени таблицы"))?;
        if family == "inet" && ["zapret_rs", "zapret_rs_probe"].contains(&name) {
            return Err(AppError::new(
                "state",
                "После перезагрузки существует таблица zapret_rs; журнал сохранён, удаление запрещено",
            ));
        }
    }
    Ok(())
}
