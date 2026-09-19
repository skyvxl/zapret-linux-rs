use crate::{
    config::Config,
    error::{AppError, Result, combine},
    firewall::FirewallPlan,
    host_run, namespace,
    nft::Nft,
    notify::Notifier,
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
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
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

pub struct Outcome<T> {
    pub result: Result<T>,
    pub cleanup_confirmed: bool,
    pub stopped: Option<Value>,
}

pub fn run(options: &[&str]) -> Result<()> {
    let signals = Signals::install()?;
    let mut timeout = Duration::from_millis(5000);
    let outcome = supervise(
        options,
        None,
        &signals,
        |child, ready, run_for, operation_timeout| {
            timeout = operation_timeout;
            emit(ready.clone(), &signals, timeout, true)?;
            let start = Instant::now();
            loop {
                queue_probe::alive(child)?;
                if let Some(signal) = signals.requested() {
                    return Ok(signal);
                }
                if run_for.is_some_and(|limit| start.elapsed() >= limit) {
                    return Ok("duration");
                }
                thread::sleep(Duration::from_millis(10));
            }
        },
    );
    debug_assert!(outcome.result.is_err() || outcome.cleanup_confirmed);
    let reason = outcome.result?;
    if let Some(mut stopped) = outcome.stopped {
        stopped["reason"] = json!(reason);
        emit(stopped, &signals, timeout, false)?;
    }
    Ok(())
}

pub fn supervise<T>(
    options: &[&str],
    strategy_override: Option<&str>,
    signals: &Signals,
    on_ready: impl FnOnce(&mut Managed, &Value, Option<Duration>, Duration) -> Result<T>,
) -> Outcome<T> {
    let mut cleanup_confirmed = true;
    let mut stopped_event = None;
    let result = execute(
        options,
        strategy_override,
        signals,
        on_ready,
        &mut cleanup_confirmed,
        &mut stopped_event,
    );
    Outcome {
        result,
        cleanup_confirmed,
        stopped: stopped_event,
    }
}

fn execute<T>(
    options: &[&str],
    strategy_override: Option<&str>,
    signals: &Signals,
    on_ready: impl FnOnce(&mut Managed, &Value, Option<Duration>, Duration) -> Result<T>,
    cleanup_confirmed: &mut bool,
    stopped_event: &mut Option<Value>,
) -> Result<T> {
    let mut values = BTreeMap::new();
    let mut mode = None;
    let mut systemd_notify = false;
    let mut index = 0;
    while index < options.len() {
        let key = options[index];
        if key == "--systemd-notify" && !systemd_notify {
            systemd_notify = true;
            index += 1;
            continue;
        }
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
    if systemd_notify && !host {
        return Err(AppError::new(
            "usage",
            "--systemd-notify допустим только для --host",
        ));
    }
    let notifier = Notifier::from_env(systemd_notify)?;
    let required = |key: &str| {
        values
            .get(key)
            .copied()
            .ok_or_else(|| AppError::new("usage", format!("Требуется {key}")))
    };
    if host {
        for key in ["--state-dir", "--iptables-save", "--ip6tables-save"] {
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
    let mut config = Config::load(Path::new(required("--config")?))?;
    if let Some(name) = strategy_override {
        config.strategy = name.to_string();
    }
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
    let validation = validate_command(dry, timeout)?;
    signals.check()?;
    let nft = Nft {
        binary: &nft_binary,
        timeout,
    };
    nft.run("check", &["--check", "--file", "-"], &firewall.batch())?;
    signals.check()?;
    let table = OwnedTable::new(crate::firewall::TABLE)?;
    let probe = OwnedTable::new("zapret_rs_probe")?;
    *cleanup_confirmed = false;
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
            let cleanup = lease.as_ref().map_or(Ok(()), |lease| lease.clear());
            *cleanup_confirmed = cleanup.is_ok();
            return combine(Err(error), cleanup);
        }
    };
    let result = (|| {
        if let (Some(lease), Some(record)) = (&lease, &mut record) {
            record.set_engine(child.id())?;
            lease.write(&record.json())?;
        }
        if host {
            queue_owner::wait(&mut child, signals, timeout)?;
        }
        queue_probe::verify(&nft, &mut child, signals, timeout, &probe, host)?;
        signals.check()?;
        queue_probe::alive(&mut child)?;
        if host {
            queue_owner::require(child.id())?;
        }
        table.apply(&nft, "apply", &firewall.batch())?;
        nft.inspect(&firewall)?;
        signals.check()?;
        queue_probe::alive(&mut child)?;
        if host {
            queue_owner::require(child.id())?;
        }
        let engine_version = validation["stdout"].as_str().and_then(|out| {
            out.lines().find(|line| {
                [
                    "github version ",
                    "github android version ",
                    "self-built version ",
                    "self-built android version ",
                ]
                .iter()
                .any(|prefix| line.starts_with(prefix))
            })
        });
        let engine_argv: Vec<_> = engine(&binary, &plan)
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let identity = json!({"version":1,"config":config.json(),"plan":plan.json(true),"strategy_file":file,
            "engine_binary":binary,"engine_version":engine_version,"engine_argv":engine_argv});
        let fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(identity.to_string().as_bytes())
        );
        let ready = json!({"event":"ready", "scope":scope, "isolation":isolation,
            "run_for_ms":run_for.map(|duration|duration.as_millis()),"duration_starts_after_ready":true,
            "queue_ownership":if host {"verified_child_nfqueue_socket"} else {"not_inspected"},
            "readiness":"queue_packet_roundtrip", "engine_pid":child.id(), "strategy_file":file,
            "queue_num":QUEUE_NUM, "fwmark":FWMARK, "network_validation":"not_run",
            "config":config.json(),"plan":plan.json(true),"engine_binary":binary,"validation":validation,
            "plan_fingerprint":fingerprint,"fingerprint_schema":1,"engine_version":engine_version,"engine_argv":engine_argv});
        if let Some(notifier) = &notifier {
            notifier.ready(timeout, &mut || {
                signals.check()?;
                queue_probe::alive(&mut child)?;
                queue_owner::require(child.id())
            })?;
        }
        on_ready(&mut child, &ready, run_for, timeout)
    })();
    if let Some(notifier) = &notifier {
        notifier.stopping();
    }
    // Keep nfqws alive while removing rules; aggregate cleanup errors instead of
    // losing the original failure. Retain the journal if cleanup cannot be
    // confirmed; current-network mode cannot rely on namespace destruction.
    let cleanup = combine(table.remove(&nft), probe.remove(&nft));
    let stopped = child.stop(timeout.min(Duration::from_millis(1000)));
    let mut cleanup = cleanup;
    if cleanup.is_ok()
        && stopped.is_ok()
        && let Some(lease) = &lease
    {
        cleanup = lease.clear();
    }
    *cleanup_confirmed = cleanup.is_ok() && stopped.is_ok();
    let result = combine(result, cleanup);
    match stopped {
        Ok((output, forced)) => {
            *stopped_event = Some(json!({"event":"stopped", "scope":scope,
                "cleanup":if *cleanup_confirmed {"removed"} else {"failed"},
                "engine_forced_kill":forced, "engine_exit_code":output.status.code(),
                "stdout":output.stdout, "stderr":output.stderr, "output_truncated":output.truncated}));
            result
        }
        Err(error) => combine(result, Err(error)),
    }
}
