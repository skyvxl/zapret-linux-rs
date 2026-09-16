use crate::{
    config::Config,
    error::{AppError, Result, combine},
    firewall::FirewallPlan,
    namespace,
    nft::Nft,
    output::emit,
    owned_table::OwnedTable,
    process::Managed,
    queue_probe,
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
    io,
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
    // SAFETY: scalar prctl calls only, before exec. In our single-UID user
    // namespace setgroups is denied. Removing these bounding capabilities makes
    // nfqws skip its automatic UID/GID switch; it still drops other capabilities.
    unsafe {
        command.pre_exec(|| {
            for capability in [6, 7] {
                // CAP_SETGID, CAP_SETUID
                if libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    command
}

pub fn run(options: &[&str]) -> Result<()> {
    let mut values = BTreeMap::new();
    let mut isolated = false;
    let mut index = 0;
    while index < options.len() {
        let key = options[index];
        if key == "--isolated" && !isolated {
            isolated = true;
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
    if !isolated {
        return Err(AppError::new("usage", "Требуется --isolated"));
    }
    let required = |key: &str| {
        values
            .get(key)
            .copied()
            .ok_or_else(|| AppError::new("usage", format!("Требуется {key}")))
    };
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
    let isolation = namespace::enter()?;
    signals.check()?;
    namespace::loopback_up()?;
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
        let record = Record::new(isolation.clone(), &[&table, &probe])?;
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
        queue_probe::verify(&nft, &mut child, &signals, timeout, &probe)?;
        signals.check()?;
        queue_probe::alive(&mut child)?;
        table.apply(&nft, "apply", &firewall.batch())?;
        applied = true;
        nft.inspect(&firewall)?;
        signals.check()?;
        queue_probe::alive(&mut child)?;
        emit(
            json!({"event":"ready", "scope":"isolated_network_namespace", "isolation":isolation,
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
    // losing the original failure. The new namespace contains uncertain results.
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
                json!({"event":"stopped", "scope":"isolated_network_namespace", "reason":reason,
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
