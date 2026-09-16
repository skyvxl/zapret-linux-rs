use crate::{
    error::{AppError, Result},
    process,
    service_fs::{self, Dir},
    service_unit,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

pub struct Manager {
    binary: PathBuf,
}
#[derive(Clone)]
pub struct Status {
    pub fields: BTreeMap<String, String>,
}
impl Status {
    pub fn get(&self, key: &str) -> &str {
        self.fields.get(key).map(String::as_str).unwrap_or("")
    }
    pub fn idle(&self) -> bool {
        ["inactive", "failed"].contains(&self.get("ActiveState"))
            && self.get("MainPID") == "0"
            && self.no_job()
    }
    pub fn no_job(&self) -> bool {
        matches!(self.get("Job"), "" | "0")
    }
    pub fn owned(&self) -> Result<()> {
        if self.get("LoadState") != "loaded"
            || self.get("FragmentPath") != service_unit::UNIT
            || !self.get("DropInPaths").is_empty()
        {
            return Err(service_fs::fail(
                "Loaded unit is foreign, masked, or has drop-ins",
            ));
        }
        if !self.no_job() {
            return Err(service_fs::fail("Unit has an outstanding job"));
        }
        Ok(())
    }
    pub fn absent(&self) -> Result<()> {
        if self.get("LoadState") != "not-found"
            || !self.get("FragmentPath").is_empty()
            || !self.get("DropInPaths").is_empty()
            || !self.no_job()
            || !self.idle()
        {
            return Err(service_fs::fail(
                "A same-name loaded/active/foreign unit exists",
            ));
        }
        Ok(())
    }
    pub fn json(&self) -> Value {
        json!(self.fields)
    }
}
impl Manager {
    pub fn new() -> Result<Self> {
        for p in ["/usr/bin/systemctl", "/bin/systemctl"] {
            if let Ok(path) = Path::new(p).canonicalize() {
                let parent = Dir::absolute(path.parent().unwrap(), true, false)?;
                let name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| service_fs::fail("Invalid systemctl path"))?;
                let file = parent.open(name, libc::O_RDONLY, 0)?;
                use std::os::unix::fs::MetadataExt;
                let m = file.metadata().map_err(service_fs::fail)?;
                if m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0 && m.mode() & 0o111 != 0 {
                    return Ok(Self { binary: path });
                }
            }
        }
        Err(service_fs::fail("Trusted systemctl executable unavailable"))
    }
    fn invoke(&self, args: &[&str], timeout: Duration) -> Result<String> {
        let mut command = Command::new(&self.binary);
        command
            .args(["--no-pager", "--no-ask-password"])
            .args(args)
            .current_dir("/")
            .env_clear()
            .env("LC_ALL", "C")
            .env("SYSTEMD_COLORS", "0");
        let signals = crate::signals::Signals::install()?;
        let mut running = process::Managed::spawn(command).map_err(|e| {
            AppError::new(
                "outcome_unknown",
                format!("systemctl launch outcome unknown: {}", e.message),
            )
        })?;
        let started = Instant::now();
        let output = loop {
            if running.poll()?.is_some() {
                break running.stop(Duration::ZERO)?.0;
            }
            if signals.requested().is_some() || started.elapsed() >= timeout {
                let reason = if signals.requested().is_some() {
                    "interrupted"
                } else {
                    "timed out"
                };
                running.stop(Duration::ZERO)?;
                return Err(AppError::new(
                    "outcome_unknown",
                    format!("systemctl {reason}; manager job may continue; package retained"),
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        if output.truncated || !output.stdout_valid_utf8 {
            return Err(AppError::new(
                "outcome_unknown",
                "Invalid or truncated systemctl output; package retained",
            ));
        }
        if !output.status.success() {
            return Err(service_fs::fail(format!(
                "systemctl failed: {} {}",
                output.status, output.stderr
            )));
        }
        Ok(output.stdout)
    }
    pub fn show(&self) -> Result<Status> {
        const PROPS: [&str; 9] = [
            "LoadState",
            "FragmentPath",
            "DropInPaths",
            "ActiveState",
            "SubState",
            "Result",
            "UnitFileState",
            "MainPID",
            "Job",
        ];
        let text=self.invoke(&["show",service_unit::NAME,"--property=LoadState,FragmentPath,DropInPaths,ActiveState,SubState,Result,UnitFileState,MainPID,Job"],Duration::from_secs(10))?;
        let mut fields: BTreeMap<String, String> = BTreeMap::new();
        for line in text.lines() {
            let (k, v) = line
                .split_once('=')
                .ok_or_else(|| service_fs::fail("Malformed systemctl show"))?;
            if !PROPS.contains(&k) || fields.insert(k.into(), v.into()).is_some() {
                return Err(service_fs::fail(
                    "Unexpected or duplicate systemctl property",
                ));
            }
        }
        if fields.len() != PROPS.len() || fields["MainPID"].parse::<u32>().is_err() {
            return Err(service_fs::fail("Incomplete systemctl show"));
        }
        Ok(Status { fields })
    }
    pub fn reload(&self) -> Result<()> {
        self.invoke(&["daemon-reload"], Duration::from_secs(30))
            .map(|_| ())
    }
    pub fn control(&self, action: &str) -> Result<Status> {
        self.show()?.owned()?;
        if let Err(e) = self.invoke(&[action, service_unit::NAME], Duration::from_secs(300)) {
            let observed = self
                .show()
                .map(|s| s.json())
                .unwrap_or(json!({"runtime":"unknown"}));
            return Err(AppError::new(
                e.kind,
                format!(
                    "{}; phase={action}; observed={observed}; installation retained",
                    e.message
                ),
            ));
        }
        let after = self.show()?;
        after.owned()?;
        let success = match action {
            "start" | "restart" => {
                after.get("ActiveState") == "active"
                    && after.get("SubState") == "running"
                    && after.get("MainPID") != "0"
            }
            "stop" => after.idle(),
            "enable" => after.get("UnitFileState") == "enabled",
            "disable" => after.get("UnitFileState") == "disabled",
            _ => false,
        };
        if !success {
            return Err(AppError::new(
                "outcome_unknown",
                format!(
                    "systemctl {action} returned without confirming expected state: {}; installation retained",
                    after.json()
                ),
            ));
        }
        Ok(after)
    }
}
