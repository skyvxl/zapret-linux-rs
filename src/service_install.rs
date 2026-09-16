use crate::{
    config::Config,
    error::{AppError, Result},
    service_control::{Manager, Status},
    service_fs::{self, Dir, digest, fail},
    service_unit,
};
use serde_json::{Map, Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    time::Duration,
};
const PAYLOAD: &str = "zapret-linux-rs";
const UNIT: &str = "zapret-linux-rs.service";
const BINS: [&str; 5] = [
    "zapret-linux-rs",
    "nfqws",
    "nft",
    "iptables-legacy-save",
    "ip6tables-legacy-save",
];
const MB: u64 = 1024 * 1024;
pub struct Options<'a> {
    pub root: &'a str,
    pub values: BTreeMap<&'a str, &'a str>,
    pub start: bool,
    pub enable: bool,
    pub stop: bool,
}
// StateDir::write reserves this exact namespace before writing/renaming its
// journal. Zero-length and partial files are legitimate crash leftovers: their
// bytes are never recovery authority, and cleanup requires the stable lock.
fn state_temp_name(name: &str) -> bool {
    let Some(stem) = name
        .strip_prefix(".state-")
        .and_then(|s| s.strip_suffix(".tmp"))
    else {
        return false;
    };
    let Some((pid, stamp)) = stem.split_once('-') else {
        return false;
    };
    pid.parse::<u32>()
        .is_ok_and(|n| n > 0 && n <= i32::MAX as u32 && n.to_string() == pid)
        && stamp.parse::<u128>().is_ok_and(|n| n.to_string() == stamp)
}
fn state_temp_file(directory: &Dir, name: &str) -> Result<File> {
    let file = directory.open(name, libc::O_RDONLY, 0)?;
    service_fs::trusted_file(&file, 0o600)?;
    if file.metadata().map_err(fail)?.len() > 65536 {
        return Err(fail("Oversized state write temporary file; retained"));
    }
    Ok(file)
}
struct Layout {
    root: PathBuf,
    _root: Dir,
    opt: Dir,
    system: Dir,
    state_parent: Dir,
    _installer_lock: File,
    offline: bool,
}
impl Layout {
    fn open(root: &str, offline: bool) -> Result<Self> {
        let r = Dir::absolute(Path::new(root), true, offline)?;
        let m = r.0.metadata().map_err(fail)?;
        if m.uid() != service_fs::uid() || m.mode() & 0o022 != 0 {
            return Err(fail(
                "Deployment root must be caller-owned and not group/world writable",
            ));
        }
        let root = Path::new(root).canonicalize().map_err(fail)?;
        let run = r.ensure("run")?;
        let lock = if run.exists("zapret-linux-rs-install.lock")? {
            run.open("zapret-linux-rs-install.lock", libc::O_RDWR, 0)?
        } else {
            let f = run.open(
                "zapret-linux-rs-install.lock",
                libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
                0o600,
            )?;
            service_fs::own(&f)?;
            f
        };
        service_fs::trusted_file(&lock, 0o600)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(fail("Installer is locked"));
        }
        let opt = r.ensure("opt")?;
        let system = r.ensure("etc")?.ensure("systemd")?.ensure("system")?;
        let state_parent = r.ensure("var")?.ensure("lib")?;
        Ok(Self {
            root,
            _root: r,
            opt,
            system,
            state_parent,
            _installer_lock: lock,
            offline,
        })
    }
    fn manager(&self) -> Result<Option<Manager>> {
        if self.offline {
            Ok(None)
        } else {
            Manager::new().map(Some)
        }
    }
    fn deployment(&self) -> &str {
        if self.offline { "offline" } else { "local" }
    }
    fn verify_state(&self, id: &str, empty: bool) -> Result<Option<Dir>> {
        if !self.state_parent.exists(PAYLOAD)? {
            return Ok(None);
        }
        let d = self.state_parent.child(PAYLOAD)?;
        let m = d.0.metadata().map_err(fail)?;
        if m.uid() != service_fs::uid()
            || m.gid() != service_fs::gid()
            || m.mode() & 0o7777 != 0o700
        {
            return Err(fail("Foreign state directory"));
        }
        let names = d.names()?;
        if names
            .iter()
            .any(|s| s != "lock" && s != "state.json" && !state_temp_name(s))
            || !names.iter().any(|s| s == "lock")
        {
            return Err(fail("Unexpected state contents"));
        }
        if d.read("lock", 0o600, 128)? != id.as_bytes() {
            return Err(fail("State directory installation identity mismatch"));
        }
        for name in names.iter().filter(|s| state_temp_name(s)) {
            state_temp_file(&d, name)?;
        }
        if d.exists("state.json")? {
            d.read("state.json", 0o600, 65536)?;
            if empty {
                return Err(fail(
                    "State journal is not empty; recovery required; package retained",
                ));
            }
        }
        Ok(Some(d))
    }
    fn verify_unit(&self) -> Result<bool> {
        if !self.system.exists(UNIT)? {
            return Ok(false);
        }
        if self.system.read(UNIT, 0o644, 65536)? != service_unit::text().as_bytes() {
            return Err(fail("Foreign or modified unit"));
        }
        Ok(true)
    }
    fn definitions(&self, allow_enable: bool) -> Result<bool> {
        // Refuse definitions that our fixed unit would shadow, masks, and drop-ins.
        for rel in [
            "etc/systemd/system",
            "etc/systemd/system.control",
            "etc/systemd/system.attached",
            "run/systemd/system",
            "run/systemd/system.control",
            "run/systemd/system.attached",
            "usr/local/lib/systemd/system",
            "usr/lib/systemd/system",
            "lib/systemd/system",
            "run/systemd/transient",
            "run/systemd/generator.early",
            "run/systemd/generator",
            "run/systemd/generator.late",
        ] {
            let p = self.root.join(rel);
            if !p.exists() {
                continue;
            }
            // /lib commonly aliases /usr/lib. Resolve only this read-only search root,
            // then validate the canonical directory ownership and each entry.
            let p = p.canonicalize().map_err(fail)?;
            if !p.starts_with(&self.root) {
                return Err(fail("Unit search path escapes offline root"));
            }
            let d = Dir::absolute(&p, true, self.offline)?;
            if rel != "etc/systemd/system" && d.exists(UNIT)? {
                return Err(fail("Alternate same-name service definition exists"));
            }
            if d.exists("zapret-linux-rs.service.d")? {
                return Err(fail("Service drop-in directory exists"));
            }
        }
        let mut enabled = false;
        for base in [
            self.root.join("etc/systemd/system"),
            self.root.join("run/systemd/system"),
        ] {
            if !base.exists() {
                continue;
            }
            let d = Dir::absolute(&base, true, self.offline)?;
            for n in d.names()? {
                let p = d.path().join(&n);
                let m = fs::symlink_metadata(&p).map_err(fail)?;
                if m.file_type().is_symlink() {
                    let target = fs::read_link(&p).map_err(fail)?;
                    if n != UNIT && target.file_name().is_some_and(|s| s == UNIT) {
                        return Err(fail("Unexpected alias for owned unit"));
                    }
                }
                if n.ends_with(".wants") || n.ends_with(".requires") {
                    let links = d.child(&n)?;
                    links.ancestor(self.offline)?;
                    for child in links.names()? {
                        let lp = links.path().join(&child);
                        let lm = fs::symlink_metadata(&lp).map_err(fail)?;
                        let target = if lm.file_type().is_symlink() {
                            Some(fs::read_link(&lp).map_err(fail)?)
                        } else {
                            None
                        };
                        if child == UNIT
                            || target
                                .as_ref()
                                .is_some_and(|t| t.file_name().is_some_and(|s| s == UNIT))
                        {
                            let owned = allow_enable
                                && base == self.root.join("etc/systemd/system")
                                && n == "multi-user.target.wants"
                                && child == UNIT
                                && lm.uid() == service_fs::uid()
                                && lm.gid() == service_fs::gid()
                                && target.as_ref().is_some_and(|p| {
                                    p == Path::new(service_unit::UNIT)
                                        || p == Path::new("../zapret-linux-rs.service")
                                });
                            if !owned {
                                return Err(fail("Foreign enable link or alias exists"));
                            }
                            enabled = true;
                        }
                    }
                }
            }
        }
        Ok(enabled)
    }
}
fn strict_keys(value: &Value, keys: &[&str]) -> Result<()> {
    let o = value
        .as_object()
        .ok_or_else(|| fail("Expected manifest object"))?;
    if o.len() != keys.len() || o.keys().any(|k| !keys.contains(&k.as_str())) {
        return Err(fail("Malformed manifest fields"));
    }
    Ok(())
}
fn inventory(
    dir: &Dir,
    relative: &str,
    out: &mut Map<String, Value>,
    asset_bytes: &mut u64,
) -> Result<()> {
    let directory_metadata = dir.0.metadata().map_err(fail)?;
    if directory_metadata.uid() != service_fs::uid()
        || directory_metadata.gid() != service_fs::gid()
        || (!relative.is_empty() && directory_metadata.mode() & 0o7777 != 0o755)
    {
        return Err(fail("Payload directory ownership or mode changed"));
    }
    if relative.split('/').count() > 66 {
        return Err(fail("Payload directory depth exceeded"));
    }
    for name in dir.names()? {
        if relative.is_empty() && name == "manifest.json" {
            continue;
        }
        if out.len() >= 20016 {
            return Err(fail("Payload inventory limit exceeded"));
        }
        let rel = if relative.is_empty() {
            name.clone()
        } else {
            format!("{relative}/{name}")
        };
        let m = fs::symlink_metadata(dir.path().join(&name)).map_err(fail)?;
        let allowed_dir =
            rel == "bin" || rel == "strategies" || rel == "assets" || rel.starts_with("assets/");
        let allowed_file = ["unit.service", "config.env", "strategies/selected.bat"]
            .contains(&rel.as_str())
            || BINS.iter().any(|b| rel == format!("bin/{b}"))
            || rel.starts_with("assets/");
        if m.uid() != service_fs::uid() || m.gid() != service_fs::gid() {
            return Err(fail("Payload owner changed"));
        }
        if m.is_dir() && allowed_dir {
            if m.mode() & 0o7777 != 0o755 {
                return Err(fail("Payload directory mode changed"));
            }
            let child = dir.child(&name)?;
            out.insert(rel.clone(), json!({"type":"directory","mode":493}));
            inventory(&child, &rel, out, asset_bytes)?;
        } else if m.is_file() && allowed_file {
            let mode = if rel.starts_with("bin/") {
                0o755
            } else {
                0o644
            };
            let limit = if rel.starts_with("bin/") {
                256 * MB
            } else {
                64 * MB
            };
            let bytes = dir.read(&name, mode, limit)?;
            if rel.starts_with("assets/") {
                *asset_bytes += bytes.len() as u64;
                if *asset_bytes > 512 * MB {
                    return Err(fail("Asset byte limit exceeded"));
                }
            }
            out.insert(
                rel,
                json!({"type":"file","mode":mode,"length":bytes.len(),"sha256":digest(&bytes)}),
            );
        } else {
            return Err(fail(format!("Unexpected payload object: {rel}")));
        }
    }
    Ok(())
}
fn scan(dir: &Dir) -> Result<Value> {
    let mut out = Map::new();
    inventory(dir, "", &mut out, &mut 0)?;
    let files = out
        .iter()
        .filter(|(p, v)| p.starts_with("assets/") && v["type"] == "file")
        .count();
    if files > 10000 {
        return Err(fail("Asset file limit exceeded"));
    }
    Ok(Value::Object(out))
}
fn verify_payload(parent: &Dir, name: &str) -> Result<(Dir, Value)> {
    let dir = parent.child(name)?;
    let meta = dir.0.metadata().map_err(fail)?;
    if meta.uid() != service_fs::uid()
        || meta.gid() != service_fs::gid()
        || meta.mode() & 0o7777 != 0o755
    {
        return Err(fail("Foreign payload directory"));
    }
    let bytes = dir.read("manifest.json", 0o644, 8 * MB)?;
    let manifest: Value = serde_json::from_slice(&bytes).map_err(fail)?;
    // Require canonical serialization as well as exact schema; duplicate JSON keys
    // or ambiguous encodings cannot become deletion authority.
    if serde_json::to_vec(&manifest).map_err(fail)? != bytes {
        return Err(fail("Manifest is not canonical JSON"));
    }
    strict_keys(
        &manifest,
        &[
            "schema",
            "product",
            "installation_id",
            "sources",
            "config",
            "unit_sha256",
            "inventory",
        ],
    )?;
    if manifest["schema"] != 1
        || manifest["product"] != "zapret-linux-rs"
        || manifest["installation_id"].as_str().is_none_or(|s| {
            s.len() != 32
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
        || manifest["unit_sha256"] != digest(service_unit::text().as_bytes())
    {
        return Err(fail("Malformed or foreign manifest"));
    }
    strict_keys(
        &manifest["sources"],
        &[
            "config",
            "config_sha256",
            "strategies",
            "assets",
            "nfqws",
            "nft",
            "iptables-save",
            "ip6tables-save",
            "executable",
            "strategy_name",
        ],
    )?;
    if manifest["sources"]
        .as_object()
        .unwrap()
        .values()
        .any(|v| v.as_str().is_none_or(|s| s.chars().any(char::is_control)))
    {
        return Err(fail("Malformed source labels"));
    }
    let actual = scan(&dir)?;
    if actual != manifest["inventory"] {
        return Err(fail("Payload inventory or SHA-256 digest mismatch"));
    }
    for fixed in [
        "bin",
        "strategies",
        "assets",
        "unit.service",
        "config.env",
        "strategies/selected.bat",
    ] {
        if actual.get(fixed).is_none() {
            return Err(fail("Incomplete payload inventory"));
        }
    }
    for bin in BINS {
        if actual.get(format!("bin/{bin}")).is_none() {
            return Err(fail("Incomplete binary snapshot"));
        }
    }
    if dir.read("unit.service", 0o644, 65536)? != service_unit::text().as_bytes() {
        return Err(fail("Unit snapshot mismatch"));
    }
    let config =
        Config::parse(std::str::from_utf8(&dir.read("config.env", 0o644, 65536)?).map_err(fail)?)?;
    if config.strategy != "selected.bat" || config.json() != manifest["config"] {
        return Err(fail("Normalized configuration mismatch"));
    }
    Ok((dir, manifest))
}
fn copy_assets(
    src: &Dir,
    dst: &Dir,
    count: &mut usize,
    total: &mut u64,
    depth: usize,
) -> Result<()> {
    if depth > 64 {
        return Err(fail("Asset directory depth exceeded"));
    }
    let before = src.0.metadata().map_err(fail)?;
    for n in src.names()? {
        *count += 1;
        if *count > 20000 {
            return Err(fail("Asset entry limit exceeded"));
        }
        let m = fs::symlink_metadata(src.path().join(&n)).map_err(fail)?;
        if m.is_dir() {
            let child = src.child(&n)?;
            let target = dst.mkdir(&n, 0o755)?;
            copy_assets(&child, &target, count, total, depth + 1)?;
        } else if m.is_file() && m.nlink() == 1 {
            let f = src.open(&n, libc::O_RDONLY, 0)?;
            let b = service_fs::read_stable(f, 64 * MB)?;
            *total += b.len() as u64;
            if *total > 512 * MB {
                return Err(fail("Asset byte limit exceeded"));
            }
            dst.write(&n, &b, 0o644)?;
            let after = fs::symlink_metadata(src.path().join(&n)).map_err(fail)?;
            if !service_fs::same(&m, &after) {
                return Err(fail("Asset changed during copy"));
            }
        } else {
            return Err(fail(
                "Assets must be directories and regular nonlinked files",
            ));
        }
    }
    if !service_fs::same(&before, &src.0.metadata().map_err(fail)?) {
        return Err(fail("Asset directory changed during copy"));
    }
    dst.sync()
}
fn snapshot(layout: &Layout, o: &Options) -> Result<(String, Value)> {
    let id = service_fs::random_id()?;
    let name = format!(".zapret-linux-rs.stage-{id}");
    let stage = layout.opt.mkdir(&name, 0o700)?;
    let result = (|| {
        let config_bytes = service_fs::source(Path::new(o.values["--config"]), 65536, false)?;
        let mut config = Config::parse(std::str::from_utf8(&config_bytes).map_err(fail)?)?;
        let original = config.strategy.clone();
        let strategies = Dir::absolute(Path::new(o.values["--strategies"]), false, false)?;
        let selected = crate::validation::resolve_strategy(&strategies.path(), &config.strategy)?;
        // resolve_strategy normalizes convenient names; reject symlinks even if
        // their targets happen to remain inside the strategy directory.
        for n in strategies.names()? {
            if strategies.path().join(&n).canonicalize().ok().as_ref() == Some(&selected)
                && fs::symlink_metadata(strategies.path().join(&n))
                    .map_err(fail)?
                    .file_type()
                    .is_symlink()
            {
                return Err(fail("Selected strategy symlink is not supported"));
            }
        }
        let strategy_bytes = service_fs::source(&selected, 64 * MB, false)?;
        config.strategy = "selected.bat".into();
        let normalized = format!(
            "interface={}\ngamefiltertcp={}\ngamefilterudp={}\nstrategy=selected.bat\nfirewall_backend={}\n",
            config.interface,
            config.gamefiltertcp,
            config.gamefilterudp,
            config.backend.name()
        );
        stage.write("config.env", normalized.as_bytes(), 0o644)?;
        stage.write("unit.service", service_unit::text().as_bytes(), 0o644)?;
        stage
            .mkdir("strategies", 0o755)?
            .write("selected.bat", &strategy_bytes, 0o644)?;
        let src = Dir::absolute(Path::new(o.values["--assets"]), false, false)?;
        copy_assets(&src, &stage.mkdir("assets", 0o755)?, &mut 0, &mut 0, 0)?;
        let bin = stage.mkdir("bin", 0o755)?;
        let exe = std::env::current_exe().map_err(fail)?;
        bin.write(
            "zapret-linux-rs",
            &service_fs::source(&exe, 256 * MB, true)?,
            0o755,
        )?;
        for (key, dest) in [
            ("--nfqws", "nfqws"),
            ("--nft", "nft"),
            ("--iptables-save", "iptables-legacy-save"),
            ("--ip6tables-save", "ip6tables-legacy-save"),
        ] {
            bin.write(
                dest,
                &service_fs::source(Path::new(o.values[key]), 256 * MB, true)?,
                0o755,
            )?;
        }
        let root = stage.path().canonicalize().map_err(fail)?;
        let plan = crate::strategy::Plan::load(
            &root.join("strategies/selected.bat"),
            &root.join("assets"),
            config.gamefiltertcp,
            config.gamefilterudp,
        )?;
        let _firewall = crate::firewall::FirewallPlan::new(&config, &plan)?;
        let before_validation = scan(&stage)?;
        let validation = crate::validation::validate_engine(
            &root.join("bin/nfqws"),
            &plan,
            Duration::from_secs(5),
        )?;
        if validation["output_truncated"] != false {
            return Err(fail("nfqws dry-run output truncated"));
        }
        if scan(&stage)? != before_validation {
            return Err(fail("Staged payload changed during engine validation"));
        }
        let mut sources = Map::new();
        for (key, path) in &o.values {
            if *key != "--root" {
                service_fs::path_ok(Path::new(path))?;
                sources.insert(key.trim_start_matches("--").into(), json!(path));
            }
        }
        sources.insert("executable".into(), json!(exe));
        sources.insert("strategy_name".into(), json!(original));
        sources.insert("config_sha256".into(), json!(digest(&config_bytes)));
        let manifest = json!({"schema":1,"product":"zapret-linux-rs","installation_id":id,"sources":sources,"config":config.json(),"unit_sha256":digest(service_unit::text().as_bytes()),"inventory":scan(&stage)?});
        stage.write(
            "manifest.json",
            &serde_json::to_vec(&manifest).map_err(fail)?,
            0o644,
        )?;
        stage.mode(0o755)?;
        stage.sync()?;
        verify_payload(&layout.opt, &name)?;
        Ok(manifest)
    })();
    result.map(|m| (name.clone(), m)).map_err(|e| {
        AppError::new(
            e.kind,
            format!(
                "{}; unpublished stage retained for inspection: {}",
                e.message,
                layout.root.join("opt").join(&name).display()
            ),
        )
    })
}
// Delete only a verified inventory, derived from actual directory enumeration.
// Manifest data never supplies a path to unlinkat. Unexpected new objects stop
// removal, retaining the manifest and remaining evidence.
fn empty_payload(dir: &Dir, relative: &str, expected: &Value) -> Result<()> {
    for name in dir.names()? {
        if relative.is_empty() && name == "manifest.json" {
            continue;
        }
        let rel = if relative.is_empty() {
            name.clone()
        } else {
            format!("{relative}/{name}")
        };
        let item = expected
            .get(&rel)
            .ok_or_else(|| fail("New payload object appeared during removal; evidence retained"))?;
        let before = fs::symlink_metadata(dir.path().join(&name)).map_err(fail)?;
        if before.uid() != service_fs::uid()
            || before.gid() != service_fs::gid()
            || Some((before.mode() & 0o7777) as u64) != item["mode"].as_u64()
            || (item["type"] == "file" && (!before.is_file() || before.nlink() != 1))
            || (item["type"] == "directory" && !before.is_dir())
        {
            return Err(fail("Object changed before removal; retained"));
        }
        let moved = format!(".removing-{}", service_fs::random_id()?);
        dir.rename(&name, dir, &moved)?;
        let after = fs::symlink_metadata(dir.path().join(&moved)).map_err(fail)?;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(fail(format!("Concurrent replacement retained as {moved}")));
        }
        if item["type"] == "directory" {
            let child = dir.child(&moved)?;
            empty_payload(&child, &rel, expected)?;
            dir.unlink(&moved, true)?;
        } else {
            let mode = item["mode"].as_u64().ok_or_else(|| fail("Invalid mode"))? as u32;
            let bytes = dir.read(&moved, mode, 256 * MB)?;
            if json!(digest(&bytes)) != item["sha256"] {
                return Err(fail(format!("Changed file retained as {moved}")));
            }
            dir.unlink(&moved, false)?;
        }
    }
    Ok(())
}
fn remove_payload(parent: &Dir, name: &str, manifest: &Value) -> Result<()> {
    let (original, actual) = verify_payload(parent, name)?;
    if actual != *manifest {
        return Err(fail("Payload identity changed; retained"));
    }
    let quarantine = format!(".zapret-linux-rs.removing-{}", service_fs::random_id()?);
    parent.rename(name, parent, &quarantine)?;
    let (dir, actual) = verify_payload(parent, &quarantine)?;
    let before = original.0.metadata().map_err(fail)?;
    let after = dir.0.metadata().map_err(fail)?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(fail(format!(
            "Concurrent payload replacement retained as {quarantine}"
        )));
    }
    if actual != *manifest {
        return Err(fail(format!(
            "Concurrent replacement retained as {quarantine}"
        )));
    }
    empty_payload(&dir, "", &manifest["inventory"])?;
    if dir.names()? != ["manifest.json"] {
        return Err(fail("Unexpected object during final removal"));
    }
    let evidence = format!(
        ".zapret-linux-rs.manifest-removing-{}",
        service_fs::random_id()?
    );
    dir.rename("manifest.json", parent, &evidence)?;
    if parent.read(&evidence, 0o644, 8 * MB)? != serde_json::to_vec(manifest).map_err(fail)? {
        return Err(fail(format!("Changed manifest retained as {evidence}")));
    }
    parent.unlink(&quarantine, true).map_err(|e| {
        fail(format!(
            "{}; manifest evidence retained as {evidence}",
            e.message
        ))
    })?;
    parent.unlink(&evidence, false)
}
fn remove_unit(layout: &Layout) -> Result<()> {
    layout.verify_unit()?;
    let original = layout.system.open(UNIT, libc::O_RDONLY, 0)?;
    let before = original.metadata().map_err(fail)?;
    let n = format!(
        ".zapret-linux-rs.unit-removing-{}",
        service_fs::random_id()?
    );
    layout.system.rename(UNIT, &layout.system, &n)?;
    let current = layout.system.open(&n, libc::O_RDONLY, 0)?;
    let after = current.metadata().map_err(fail)?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(fail(format!("Concurrent unit replacement retained as {n}")));
    }
    if layout.system.read(&n, 0o644, 65536)? != service_unit::text().as_bytes() {
        return Err(fail(format!("Concurrent unit replacement retained as {n}")));
    }
    layout.system.unlink(&n, false)
}
fn remove_state(layout: &Layout, id: &str) -> Result<()> {
    let Some(d) = layout.verify_state(id, true)? else {
        return Ok(());
    };
    let f = d.open("lock", libc::O_RDWR, 0)?;
    service_fs::trusted_file(&f, 0o600)?;
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(fail("Runtime state is locked; retained"));
    }
    if d.names()?
        .iter()
        .any(|name| name != "lock" && !state_temp_name(name))
    {
        return Err(fail("New state appeared; retained"));
    }
    let quarantine = format!(
        ".zapret-linux-rs.state-removing-{}",
        service_fs::random_id()?
    );
    layout
        .state_parent
        .rename(PAYLOAD, &layout.state_parent, &quarantine)?;
    let moved = layout.state_parent.child(&quarantine)?;
    let a = d.0.metadata().map_err(fail)?;
    let b = moved.0.metadata().map_err(fail)?;
    if a.dev() != b.dev() || a.ino() != b.ino() {
        return Err(fail(format!(
            "Concurrent state replacement retained as {quarantine}"
        )));
    }
    let expected = f.metadata().map_err(fail)?;
    let observed = moved
        .open("lock", libc::O_RDONLY, 0)?
        .metadata()
        .map_err(fail)?;
    if expected.dev() != observed.dev()
        || expected.ino() != observed.ino()
        || moved.read("lock", 0o600, 128)? != id.as_bytes()
    {
        return Err(fail(format!(
            "Concurrent state lock replacement retained as {quarantine}"
        )));
    }
    let names = moved.names()?;
    if names
        .iter()
        .any(|name| name != "lock" && !state_temp_name(name))
    {
        return Err(fail("New state appeared; retained"));
    }
    for name in names.iter().filter(|name| state_temp_name(name)) {
        let original = state_temp_file(&moved, name)?;
        let before = original.metadata().map_err(fail)?;
        let temporary = format!(".orphan-removing-{}", service_fs::random_id()?);
        moved.rename(name, &moved, &temporary)?;
        let current = state_temp_file(&moved, &temporary)?;
        let after = current.metadata().map_err(fail)?;
        if before.dev() != after.dev() || before.ino() != after.ino() || before.len() != after.len()
        {
            return Err(fail(format!(
                "Concurrent state temporary replacement retained as {quarantine}/{temporary}"
            )));
        }
        moved.unlink(&temporary, false)?;
    }
    if moved.names()? != ["lock"] {
        return Err(fail(
            "New state appeared during temporary cleanup; retained",
        ));
    }
    moved.unlink("lock", false)?;
    layout.state_parent.unlink(&quarantine, true)
}
fn report(
    layout: &Layout,
    status: &str,
    manifest: Option<&Value>,
    runtime: Option<&Status>,
    enabled: bool,
) -> Value {
    json!({"service":{"status":status,"deployment":layout.deployment(),"owned":manifest.is_some(),"installation_id":manifest.map(|m|&m["installation_id"]),"strategy":manifest.map(|m|&m["sources"]["strategy_name"]),"enabled":enabled,"runtime":runtime.map(|r|json!(r.get("ActiveState"))).unwrap_or(json!("not_queried")),"manager":runtime.map(Status::json)}})
}
fn activate(o: &Options, manager: Option<&Manager>) -> Result<Option<Status>> {
    let Some(m) = manager else {
        return Ok(None);
    };
    let mut current = m.show()?;
    current.owned()?;
    if o.enable && current.get("UnitFileState") != "enabled" {
        current = m.control("enable")?;
    }
    if o.start {
        if current.idle() {
            start_preflight().map_err(|e| {
                AppError::new(
                    e.kind,
                    format!(
                        "phase=start_preflight; {}; observed={}; installation retained",
                        e.message,
                        current.json()
                    ),
                )
            })?;
        }
        current = m.control("start")?;
    }
    Ok(Some(current))
}
fn recover_service_state() -> Result<()> {
    crate::state_cli::run(&[
        "recover",
        "--state-dir",
        "/var/lib/zapret-linux-rs",
        "--nft",
        "/opt/zapret-linux-rs/bin/nft",
        "--timeout-ms",
        "5000",
        "--allow-previous-boot",
    ])
    .map(|_| ())
}
fn start_preflight() -> Result<()> {
    // Callers have verified the installed objects and an idle owned manager
    // unit. Match ExecStartPre: retire only strictly owned stale state before
    // deciding whether the remaining host rules represent a foreign conflict.
    recover_service_state()?;
    crate::host_run::context()?;
    crate::host_run::preflight(
        Path::new("/opt/zapret-linux-rs/bin/nft"),
        Path::new("/opt/zapret-linux-rs/bin/iptables-legacy-save"),
        Path::new("/opt/zapret-linux-rs/bin/ip6tables-legacy-save"),
        Duration::from_secs(5),
    )
}
pub fn run(action: &str, o: &Options) -> Result<Value> {
    service_fs::path_ok(Path::new(o.root))?;
    // A noncanonical spelling of / is still real: never allow --root /. to
    // bypass privilege checks or send a rooted operation to the host manager.
    let root = Path::new(o.root).canonicalize().map_err(fail)?;
    let offline = root != Path::new("/");
    if offline
        && (o.enable || o.start || !["install", "uninstall", "remove", "status"].contains(&action))
    {
        return Err(AppError::new(
            "usage",
            "Offline roots cannot activate or control host services",
        ));
    }
    if !offline && (unsafe { libc::getuid() } != 0 || service_fs::uid() != 0) {
        return Err(AppError::new(
            "permissions",
            "Service deployment/control requires UID=EUID=0",
        ));
    }
    let layout = Layout::open(o.root, offline)?;
    let manager = layout.manager()?;
    let exists = layout.opt.exists(PAYLOAD)?;
    if action == "install" {
        return install(&layout, o, manager.as_ref(), exists);
    }
    if !exists {
        if layout.system.exists(UNIT)? || layout.state_parent.exists(PAYLOAD)? {
            return Err(fail(
                "incomplete_install: payload absent; unit/state retained",
            ));
        }
        layout.definitions(false)?;
        let state = manager.as_ref().map(Manager::show).transpose()?;
        if let Some(s) = &state {
            s.absent()?;
        }
        return if action == "status" {
            Ok(report(
                &layout,
                "not_installed",
                None,
                state.as_ref(),
                false,
            ))
        } else {
            Err(fail("Service is not installed"))
        };
    }
    let (_, manifest) = verify_payload(&layout.opt, PAYLOAD)?;
    let id = manifest["installation_id"].as_str().unwrap();
    let unit = layout.verify_unit()?;
    let state_exists = layout.verify_state(id, false)?.is_some();
    let enabled = layout.definitions(true)?;
    let current = manager.as_ref().map(Manager::show).transpose()?;
    if action == "status" {
        let manager_loaded = current
            .as_ref()
            .map(manager_owns_unit)
            .transpose()?
            .unwrap_or(true);
        return Ok(report(
            &layout,
            if unit && state_exists && manager_loaded {
                "installed"
            } else {
                "incomplete_install"
            },
            Some(&manifest),
            current.as_ref(),
            enabled,
        ));
    }
    if ["uninstall", "remove"].contains(&action) {
        return uninstall(
            &layout,
            o,
            manager.as_ref(),
            current.as_ref(),
            &manifest,
            unit,
            enabled,
        );
    }
    if !unit || !state_exists {
        return Err(fail("incomplete_install: controls are refused"));
    }
    let manager = manager
        .as_ref()
        .ok_or_else(|| fail("Offline controls are unavailable"))?;
    let before = current.as_ref().unwrap();
    before.owned()?;
    if action == "start" && before.idle() {
        start_preflight()?;
    }
    let after = manager.control(action)?;
    layout.definitions(true)?;
    Ok(report(
        &layout,
        action,
        Some(&manifest),
        Some(&after),
        after.get("UnitFileState") == "enabled",
    ))
}
// A verified disk snapshot can precede daemon-reload after a process crash.
// Treat only a strictly absent, idle manager state as an unreconciled snapshot;
// all other states still require the exact owned loaded fragment and no jobs.
fn manager_owns_unit(status: &Status) -> Result<bool> {
    if status.get("LoadState") == "not-found" {
        status.absent()?;
        Ok(false)
    } else {
        status.owned()?;
        Ok(true)
    }
}
fn install(layout: &Layout, o: &Options, manager: Option<&Manager>, exists: bool) -> Result<Value> {
    let mut prior = None;
    if exists {
        let (_, m) = verify_payload(&layout.opt, PAYLOAD)?;
        if !layout.verify_unit()?
            || layout
                .verify_state(m["installation_id"].as_str().unwrap(), false)?
                .is_none()
        {
            return Err(fail(
                "incomplete_install: inspect service status and uninstall",
            ));
        }
        layout.definitions(true)?;
        if let Some(manager) = manager {
            manager_owns_unit(&manager.show()?)?;
        }
        prior = Some(m);
    } else {
        if layout.system.exists(UNIT)? || layout.state_parent.exists(PAYLOAD)? {
            return Err(fail("Foreign or partial unit/state already exists"));
        }
        layout.definitions(false)?;
        if let Some(manager) = manager {
            manager.show()?.absent()?;
        }
    }
    let (stage, manifest) = snapshot(layout, o)?;
    if let Some(old) = prior {
        let mut a = old.clone();
        let mut b = manifest.clone();
        a.as_object_mut().unwrap().remove("installation_id");
        b.as_object_mut().unwrap().remove("installation_id");
        remove_payload(&layout.opt, &stage, &manifest)?;
        if a != b {
            return Err(AppError::new(
                "already_installed_different",
                "Installed snapshot differs; uninstall before installing another snapshot",
            ));
        }
        if let Some(manager) = manager
            && !manager_owns_unit(&manager.show()?)?
        {
            // Validation ran a copied source executable. Recheck the installed
            // objects and override conflicts before changing the manager cache.
            let (_, current) = verify_payload(&layout.opt, PAYLOAD)?;
            if current != old
                || !layout.verify_unit()?
                || layout
                    .verify_state(old["installation_id"].as_str().unwrap(), false)?
                    .is_none()
            {
                return Err(fail(
                    "Installation changed before manager reconciliation; retained",
                ));
            }
            layout.definitions(true)?;
            manager.reload()?;
            manager.show()?.owned()?;
        }
        let enabled = layout.definitions(true)?;
        let runtime = activate(o, manager)?;
        return Ok(report(
            layout,
            "already_installed",
            Some(&old),
            runtime.as_ref(),
            if let Some(s) = &runtime {
                s.get("UnitFileState") == "enabled"
            } else {
                enabled
            },
        ));
    }
    let id = manifest["installation_id"].as_str().unwrap();
    let state_stage = format!(".zapret-linux-rs.state-{id}");
    let state = layout.state_parent.mkdir(&state_stage, 0o700)?;
    state.write("lock", id.as_bytes(), 0o600)?;
    let unit_stage = format!(".zapret-linux-rs.unit-{id}");
    layout
        .system
        .write(&unit_stage, service_unit::text().as_bytes(), 0o644)?;
    let mut payload_published = false;
    let mut state_published = false;
    let mut unit_published = false;
    let transaction = (|| {
        layout.opt.rename(&stage, &layout.opt, PAYLOAD)?;
        payload_published = true;
        layout
            .state_parent
            .rename(&state_stage, &layout.state_parent, PAYLOAD)?;
        state_published = true;
        layout.system.rename(&unit_stage, &layout.system, UNIT)?;
        unit_published = true;
        if let Some(m) = manager {
            m.reload()?;
            m.show()?.owned()?;
        }
        Ok(())
    })();
    if let Err(error) = transaction {
        let error: AppError = error;
        // A manager timeout can leave a job in flight: retain the complete
        // installation, never remove binaries on an uncertain manager result.
        if error.kind == "outcome_unknown" {
            return Err(AppError::new(
                error.kind,
                format!("{}; incomplete_install retained", error.message),
            ));
        }
        let rollback = (|| {
            if unit_published {
                if let Some(m) = manager {
                    let s = m.show()?;
                    if s.get("LoadState") == "not-found" {
                        s.absent()?;
                    } else {
                        s.owned()?;
                    }
                    if !s.idle() {
                        return Err(fail(
                            "Runtime may be active; rollback preserves installation",
                        ));
                    }
                }
                remove_unit(layout)?;
                if let Some(m) = manager {
                    m.reload()?;
                    m.show()?.absent()?;
                }
            }
            if state_published {
                remove_state(layout, id)?;
            }
            if payload_published {
                remove_payload(&layout.opt, PAYLOAD, &manifest)?;
            }
            Ok(())
        })();
        return Err(match rollback {
            Ok(()) => AppError::new(
                error.kind,
                format!(
                    "{}; published objects rolled back; unpublished stage evidence may remain",
                    error.message
                ),
            ),
            Err(e) => {
                let e: AppError = e;
                AppError::new(
                    error.kind,
                    format!(
                        "{}; rollback stopped: {}; incomplete_install retained",
                        error.message, e.message
                    ),
                )
            }
        });
    }
    let runtime = activate(o, manager)?;
    let enabled = layout.definitions(true)?;
    Ok(report(
        layout,
        "installed",
        Some(&manifest),
        runtime.as_ref(),
        enabled,
    ))
}
fn uninstall(
    layout: &Layout,
    o: &Options,
    manager: Option<&Manager>,
    current: Option<&Status>,
    manifest: &Value,
    unit: bool,
    enabled: bool,
) -> Result<Value> {
    if let Some(m) = manager {
        let s = current.unwrap();
        manager_owns_unit(s)?;
        if !s.idle() {
            if !o.stop {
                return Err(fail("Service is active; use service uninstall --stop"));
            }
            m.control("stop")?;
        }
        let s = m.show()?;
        manager_owns_unit(&s)?;
        if !s.idle() {
            return Err(AppError::new(
                "outcome_unknown",
                "Service is not confirmed stopped; package retained",
            ));
        }
    }
    let id = manifest["installation_id"].as_str().unwrap();
    if layout.verify_state(id, false)?.is_some() {
        if !layout.offline {
            recover_service_state()?;
        }
        layout.verify_state(id, true)?;
    }
    // Recheck the whole inventory after recovery and before the first deletion.
    let (_, actual) = verify_payload(&layout.opt, PAYLOAD)?;
    if actual != *manifest {
        return Err(fail("Installation changed during recovery"));
    }
    layout.definitions(true)?;
    if enabled {
        let m = manager.ok_or_else(|| {
            fail("Offline enabled symlink must be removed explicitly before uninstall")
        })?;
        if !manager_owns_unit(&m.show()?)? {
            if !unit || !layout.verify_unit()? {
                return Err(fail(
                    "Cannot reconcile an enabled installation without its owned disk unit",
                ));
            }
            layout.definitions(true)?;
            m.reload()?;
            m.show()?.owned()?;
        }
        m.control("disable")?;
        if layout.definitions(true)? {
            return Err(fail("Enable link remains; package retained"));
        }
    }
    if let Some(m) = manager {
        let current = m.show()?;
        manager_owns_unit(&current)?;
        if !current.idle() {
            return Err(fail("Runtime changed before uninstall; package retained"));
        }
    }
    if unit {
        remove_unit(layout)?;
    }
    if let Some(m) = manager
        && let Err(e) = m.reload().and_then(|_| m.show()?.absent())
    {
        return Err(AppError::new(
            e.kind,
            format!(
                "partially_uninstalled: {}; payload and state retained",
                e.message
            ),
        ));
    }
    remove_state(layout, id)?;
    remove_payload(&layout.opt, PAYLOAD, manifest)?;
    Ok(report(layout, "uninstalled", None, None, false))
}
