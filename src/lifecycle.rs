use crate::{
    config::Config,
    error::{AppError, Result, combine},
    firewall::FirewallPlan,
    host_run, namespace,
    nft::Nft,
    output::emit,
    owned_table::OwnedTable,
    process::Managed,
    queue_owner, queue_probe,
    runtime::{FWMARK, QUEUE_NUM},
    signals::Signals,
    state_dir::StateDir,
    state_record::Record,
    strategy::Plan,
    validation::{resolve_strategy, validate_command},
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

fn executable(path: &str, kind: &'static str) -> Result<PathBuf> {
    let binary = Path::new(path)
        .canonicalize()
        .map_err(|e| AppError::new(kind, format!("{path}: {e}")))?;
    if !binary.is_file() {
        return Err(AppError::new(
            kind,
            format!("{path}: требуется обычный исполняемый файл"),
        ));
    }
    Ok(binary)
}

fn engine(binary: &Path, plan: &Plan) -> Command {
    let mut command = Command::new(binary);
    command
        .args([
            format!("--qnum={QUEUE_NUM}"),
            format!("--dpi-desync-fwmark={FWMARK:#x}"),
        ])
        .args(&plan.args)
        .current_dir(&plan.assets)
        .env_clear()
        .env("LANG", "C");
    // SAFETY: stack-only syscalls before exec. Prevent nfqws's UID/GID switch
    // (including inherited capabilities) so it retains the parent-death signal
    // installed by Managed after this hook. nfqws drops other capabilities.
    unsafe {
        command.pre_exec(host_run::restrict_child_ids);
    }
    command
}

pub fn run(options: &[&str]) -> Result<()> {
    let mut values = BTreeMap::new();
    let mut mode = None;
    let mut index = 0;
    while index < options.len() {
        let key = options[index];
        if ["--isolated", "--host"].contains(&key) && mode.is_none() {
            mode = Some(key);
            index += 1;
            continue;
        }
        if ![
            "--config",
            "--strategies",
            "--assets",
            "--nfqws",
            "--nft",
            "--timeout-ms",
            "--run-for-ms",
            "--state-dir",
            "--iptables-save",
            "--ip6tables-save",
        ]
        .contains(&key)
        {
            return Err(AppError::new(
                "usage",
                format!("Неизвестный или повторный параметр: {key}"),
            ));
        }
        let value = options
            .get(index + 1)
            .ok_or_else(|| AppError::new("usage", format!("Нет значения для {key}")))?;
        if value.starts_with("--") || values.insert(key, *value).is_some() {
            return Err(AppError::new(
                "usage",
                format!("Нет значения или повторный параметр: {key}"),
            ));
        }
        index += 2;
    }
    if mode.is_none() {
        return Err(AppError::new("usage", "Требуется --isolated или --host"));
    }
    let host = mode == Some("--host");
    let required = |key: &str| {
        values
            .get(key)
            .copied()
            .ok_or_else(|| AppError::new("usage", format!("Требуется {key}")))
    };
    if host {
        for key in [
            "--state-dir",
            "--run-for-ms",
            "--iptables-save",
            "--ip6tables-save",
        ] {
            required(key)?;
        }
    } else if ["--iptables-save", "--ip6tables-save"]
        .iter()
        .any(|key| values.contains_key(key))
    {
        return Err(AppError::new(
            "usage",
            "Параметры legacy-save допустимы только для --host",
        ));
    }
    let duration = |key: &str, value: &str| {
        value
            .parse::<u64>()
            .ok()
            .filter(|n| (1..=60000).contains(n))
            .map(Duration::from_millis)
            .ok_or_else(|| AppError::new("usage", format!("{key}: ожидается 1..60000")))
    };
    let timeout = duration(
        "--timeout-ms",
        values.get("--timeout-ms").unwrap_or(&"5000"),
    )?;
    let run_for = values
        .get("--run-for-ms")
        .map(|value| duration("--run-for-ms", value))
        .transpose()?;
    let config = Config::load(Path::new(required("--config")?))?;
    let file = resolve_strategy(Path::new(required("--strategies")?), &config.strategy)?;
    let plan = Plan::load(
        &file,
        Path::new(required("--assets")?),
        config.gamefiltertcp,
        config.gamefilterudp,
    )?;
    let firewall = FirewallPlan::new(&config, &plan)?;
    let binary = executable(required("--nfqws")?, "engine")?;
    let nft_binary = executable(required("--nft")?, "firewall")?;
    let legacy = if host {
        Some((
            executable(required("--iptables-save")?, "preflight")?,
            executable(required("--ip6tables-save")?, "preflight")?,
        ))
    } else {
        None
    };
    let current = if host {
        host_run::check_interface(&config.interface)?;
        Some(host_run::context()?)
    } else {
        None
    };
    let _network_guard = if host {
        Some(host_run::lock_network()?)
    } else {
        None
    };
    let lease = values
        .get("--state-dir")
        .map(|path| StateDir::open(Path::new(path))?.lock())
        .transpose()?;
    if let Some(lease) = &lease
        && lease.read()?.is_some()
    {
        return Err(AppError::new(
            "state",
            "Есть незавершённый журнал; сначала выполните state inspect и восстановление",
        ));
    }
    let signals = Signals::install()?;
    let isolation = match current {
        Some(context) => context,
        None => namespace::enter()?,
    };
    let scope = if host {
        "current_network_namespace"
    } else {
        "isolated_network_namespace"
    };
    signals.check()?;
    if !host {
        namespace::loopback_up()?;
    }
    if let Some((ipv4, ipv6)) = &legacy {
        host_run::preflight(&nft_binary, ipv4, ipv6, timeout)?;
        signals.check()?;
    }
    let mut dry = engine(&binary, &plan);
    dry.arg("--dry-run");
    validate_command(dry, timeout)?;
    signals.check()?;
    let nft = Nft {
        binary: &nft_binary,
        timeout,
    };
    nft.run("check", &["--check", "--file", "-"], &firewall.batch())?;
    signals.check()?;
    let table = OwnedTable::new(crate::firewall::TABLE)?;
    let probe = OwnedTable::new("zapret_rs_probe")?;
    let mut record = if let Some(lease) = &lease {
        let record = if host {
            Record::new_current(isolation.clone(), &[&table, &probe])?
        } else {
            Record::new(isolation.clone(), &[&table, &probe])?
        };
        lease.write(&record.json())?;
        Some(record)
    } else {
        None
    };
    let mut child = match Managed::spawn(engine(&binary, &plan)) {
        Ok(child) => child,
        Err(error) => {
            return combine(
                Err(error),
                lease.as_ref().map_or(Ok(()), |lease| lease.clear()),
            );
        }
    };
    let mut applied = false;
    let result = (|| {
        if let (Some(lease), Some(record)) = (&lease, &mut record) {
            record.set_engine(child.id())?;
            lease.write(&record.json())?;
        }
        if host {
            queue_owner::wait(&mut child, &signals, timeout)?;
        }
        queue_probe::verify(&nft, &mut child, &signals, timeout, &probe, host)?;
        signals.check()?;
        queue_probe::alive(&mut child)?;
        if host {
            queue_owner::require(child.id())?;
        }
        table.apply(&nft, "apply", &firewall.batch())?;
        applied = true;
        nft.inspect(&firewall)?;
        signals.check()?;
        queue_probe::alive(&mut child)?;
        if host {
            queue_owner::require(child.id())?;
        }
        emit(
            json!({"event":"ready", "scope":scope, "isolation":isolation,
            "run_for_ms":run_for.map(|duration|duration.as_millis()),"duration_starts_after_ready":true,
            "queue_ownership":if host {"exclusive_child_netfilter_sockets"} else {"not_inspected"},
            "readiness":"queue_packet_roundtrip", "engine_pid":child.id(), "strategy_file":file,
            "queue_num":QUEUE_NUM, "fwmark":FWMARK, "network_validation":"not_run"}),
            &signals,
            timeout,
            true,
        )?;
        let start = Instant::now();
        loop {
            queue_probe::alive(&mut child)?;
            if let Some(signal) = signals.requested() {
                return Ok(signal);
            }
            if run_for.is_some_and(|limit| start.elapsed() >= limit) {
                return Ok("duration");
            }
            thread::sleep(Duration::from_millis(10));
        }
    })();
    // Keep nfqws alive while removing rules; aggregate cleanup errors instead of
    // losing the original failure. Retain the journal if cleanup cannot be
    // confirmed; current-network mode cannot rely on namespace destruction.
    let cleanup = if lease.is_some() {
        combine(table.remove(&nft), probe.remove(&nft))
    } else if applied {
        table.remove(&nft)
    } else {
        Ok(())
    };
    let cleanup_ok = cleanup.is_ok();
    let stopped = child.stop(timeout.min(Duration::from_millis(1000)));
    let mut result = combine(result, cleanup);
    if cleanup_ok
        && stopped.is_ok()
        && let Some(lease) = &lease
    {
        result = combine(result, lease.clear());
    }
    match stopped {
        Ok((output, forced)) => {
            let reason = result?;
            emit(
                json!({"event":"stopped", "scope":scope, "reason":reason,
                "cleanup":"removed", "engine_forced_kill":forced, "engine_exit_code":output.status.code(),
                "stdout":output.stdout, "stderr":output.stderr, "output_truncated":output.truncated}),
                &signals,
                timeout,
                false,
            )
        }
        Err(error) => combine(result, Err(error)).map(|_| ()),
    }
}
