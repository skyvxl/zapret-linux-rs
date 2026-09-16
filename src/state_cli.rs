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
                    json!({"state":{"status":if record.owner_alive()? {"running"} else {"recovery_required"}, "record":record.json()}}),
                )
            }
        };
    }
    let lease = directory.lock()?;
    let Some(value) = lease.read()? else {
        return Ok(json!({"state":{"status":"empty","cleanup":"not_needed"}}));
    };
    let record = Record::parse(value)?;
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
