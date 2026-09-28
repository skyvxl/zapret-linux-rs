//! Durable service replacement. The journal is intent, observed identities are authority.
use super::*;
use std::ffi::CString;
const OPERATIONS: &str = "zapret-linux-rs-operations";
const JOURNAL: &str = "operation.json";
const PENDING: &str = "zapret-linux-rs-operation.pending";
const PENDING_BYTES: &[u8] = b"zapret-linux-rs operation pending v1\n";
fn begin(l: &Layout) -> Result<()> {
    let temporary = format!(
        ".zapret-linux-rs-operation-{}.tmp",
        service_fs::random_id()?
    );
    l.state_parent.write(&temporary, PENDING_BYTES, 0o644)?;
    l.state_parent.rename(&temporary, &l.state_parent, PENDING)
}
fn clear_pending(l: &Layout) -> Result<()> {
    if l.state_parent.exists(PENDING)? {
        if l.state_parent.read(PENDING, 0o644, 128)? != PENDING_BYTES {
            return Err(recovery("Изменён маркер операции"));
        }
        l.state_parent.unlink(PENDING, false)?;
    }
    Ok(())
}
fn recovery(e: impl std::fmt::Display) -> AppError {
    AppError::new(
        "recovery_required",
        format!("Операция не завершена: {e}. Выполните service recover; файлы сохранены"),
    )
}
fn private(d: &Dir, mode: u32) -> Result<()> {
    let m = d.0.metadata().map_err(fail)?;
    if m.uid() != service_fs::uid() || m.gid() != service_fs::gid() || m.mode() & 0o7777 != mode {
        return Err(recovery("Чужой каталог операции"));
    }
    Ok(())
}
fn directory(l: &Layout) -> Result<Dir> {
    let d = if l.state_parent.exists(OPERATIONS)? {
        l.state_parent.child(OPERATIONS)?
    } else {
        l.state_parent.mkdir(OPERATIONS, 0o700)?
    };
    private(&d, 0o700)?;
    Ok(d)
}
pub(super) fn require_idle(l: &Layout) -> Result<()> {
    if l.state_parent.exists(PENDING)? {
        return Err(recovery("Есть незавершённая операция"));
    }
    if l.state_parent.exists(OPERATIONS)? {
        let d = l.state_parent.child(OPERATIONS)?;
        private(&d, 0o700)?;
        if d.exists(JOURNAL)? {
            return Err(recovery("Есть журнал предыдущей операции"));
        }
    }
    Ok(())
}
fn write(d: &Dir, j: &Value) -> Result<()> {
    let temp = format!(".operation-{}.tmp", service_fs::random_id()?);
    d.write(&temp, &serde_json::to_vec(j).map_err(fail)?, 0o600)?;
    let a = CString::new(temp.as_str()).map_err(fail)?;
    let b = CString::new(JOURNAL).map_err(fail)?;
    if unsafe { libc::renameat(d.0.as_raw_fd(), a.as_ptr(), d.0.as_raw_fd(), b.as_ptr()) } != 0 {
        return Err(recovery(std::io::Error::last_os_error()));
    }
    d.sync().map_err(|e| recovery(e.message))
}
fn phase(d: &Dir, j: &mut Value, p: &str) -> Result<()> {
    j["phase"] = json!(p);
    write(d, j)
}
fn boot() -> Result<String> {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().into())
        .map_err(fail)
}
fn hash(m: &Value) -> Result<String> {
    Ok(digest(&serde_json::to_vec(m).map_err(fail)?))
}
fn id<'a>(j: &'a Value, key: &str) -> Result<&'a str> {
    j[key]
        .as_str()
        .filter(|s| {
            s.len() == 32
                && s.bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        })
        .ok_or_else(|| recovery("Некорректный идентификатор"))
}
fn load(d: &Dir) -> Result<Value> {
    let bytes = d.read(JOURNAL, 0o600, 24 * MB)?;
    let j: Value = serde_json::from_slice(&bytes).map_err(fail)?;
    if serde_json::to_vec(&j).map_err(fail)? != bytes
        || j["schema"] != 1
        || !["apply", "pause"].contains(&j["kind"].as_str().unwrap_or(""))
        || !j["was_running"].is_boolean()
        || !j["enabled"].is_boolean()
        || j["boot_id"].as_str().is_none()
    {
        return Err(recovery("Некорректный журнал"));
    }
    id(&j, "operation_id")?;
    for key in ["old", "new"] {
        if key == "new" && j["kind"] == "pause" {
            continue;
        }
        let manifest = &j[key];
        id(manifest, "installation_id")?;
        if manifest["product"] != "zapret-linux-rs"
            || manifest["schema"] != 1
            || j[format!("{key}_sha256")] != hash(manifest)?
        {
            return Err(recovery("Изменён manifest операции"));
        }
    }
    if ![
        "prepared",
        "stopping",
        "paused",
        "moving_old_payload",
        "moving_old_state",
        "publishing_payload",
        "publishing_state",
        "starting",
        "restoring",
        "rolled_back",
        "committed",
    ]
    .contains(&j["phase"].as_str().unwrap_or(""))
    {
        return Err(recovery("Неизвестная фаза"));
    }
    Ok(j)
}
fn verified(l: &Layout) -> Result<Value> {
    let (_, m) = verify_payload(&l.opt, PAYLOAD)?;
    if !l.verify_unit()?
        || l.verify_state(m["installation_id"].as_str().unwrap(), false)?
            .is_none()
    {
        return Err(recovery("Неполная установка"));
    }
    l.definitions(true)?;
    Ok(m)
}
fn current(m: Option<&Manager>) -> Result<Option<Status>> {
    let s = m.map(Manager::show).transpose()?;
    if let Some(s) = &s {
        s.owned()?;
        if !s.idle()
            && !(s.get("ActiveState") == "active"
                && s.get("SubState") == "running"
                && s.get("MainPID") != "0")
        {
            return Err(recovery("Состояние службы меняется"));
        }
    }
    Ok(s)
}
fn state_lease(parent: &Dir, name: &str, expected: &str) -> Result<File> {
    let d = parent.child(name)?;
    private(&d, 0o700)?;
    if d.read("lock", 0o600, 128)? != expected.as_bytes()
        || d.names()?
            .iter()
            .any(|n| n != "lock" && !state_temp_name(n))
    {
        return Err(recovery(
            "Состояние не очищено или принадлежит другой установке",
        ));
    }
    for name in d.names()?.iter().filter(|n| state_temp_name(n)) {
        state_temp_file(&d, name)?;
    }
    let f = d.open("lock", libc::O_RDWR, 0)?;
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(recovery("Состояние используется другим процессом"));
    }
    if d.read("lock", 0o600, 128)? != expected.as_bytes()
        || d.names()?
            .iter()
            .any(|n| n != "lock" && !state_temp_name(n))
    {
        return Err(recovery("Состояние изменилось до получения блокировки"));
    }
    Ok(f)
}
fn payload_matches(parent: &Dir, name: &str, expected: &Value) -> Result<()> {
    if verify_payload(parent, name)?.1 != *expected {
        return Err(recovery("Изменилась установка"));
    }
    Ok(())
}
// A fixed, journal-owned name makes deletion restartable after each unlink.
fn prune(d: &Dir, relative: &str, inventory: &Value) -> Result<()> {
    for name in d.names()? {
        if relative.is_empty() && name == "manifest.json" {
            continue;
        }
        let rel = if relative.is_empty() {
            name.clone()
        } else {
            format!("{relative}/{name}")
        };
        let entry = inventory
            .get(&rel)
            .ok_or_else(|| recovery("Неизвестный файл в резервной копии"))?;
        if entry["type"] == "directory" {
            let child = d.child(&name)?;
            private(&child, 0o755)?;
            prune(&child, &rel, inventory)?;
            d.unlink(&name, true)?;
        } else {
            let mode = entry["mode"]
                .as_u64()
                .ok_or_else(|| recovery("Некорректный режим"))? as u32;
            let bytes = d.read(&name, mode, 256 * MB)?;
            if json!(digest(&bytes)) != entry["sha256"] {
                return Err(recovery("Файл резервной копии изменён"));
            }
            d.unlink(&name, false)?;
        }
    }
    Ok(())
}
fn discard_payload(parent: &Dir, name: &str, manifest: &Value) -> Result<()> {
    if !parent.exists(name)? {
        return Ok(());
    }
    let d = parent.child(name)?;
    private(&d, 0o755)?;
    if d.exists("manifest.json")? {
        if d.read("manifest.json", 0o644, 8 * MB)? != serde_json::to_vec(manifest).map_err(fail)? {
            return Err(recovery("Резервная копия изменена"));
        }
        // Validate the complete remaining inventory before deleting anything.
        let remaining = scan(&d)?;
        for (k, v) in remaining.as_object().unwrap() {
            if manifest["inventory"].get(k) != Some(v) {
                return Err(recovery("Резервная копия изменена"));
            }
        }
        prune(&d, "", &manifest["inventory"])?;
        d.unlink("manifest.json", false)?;
    }
    if !d.names()?.is_empty() {
        return Err(recovery("Неизвестные файлы без manifest"));
    }
    parent.unlink(name, true)
}
fn discard_state(parent: &Dir, name: &str, expected: &str) -> Result<()> {
    if !parent.exists(name)? {
        return Ok(());
    }
    let d = parent.child(name)?;
    private(&d, 0o700)?;
    if d.exists("lock")? {
        let _lease = state_lease(parent, name, expected)?;
        for n in d.names()?.iter().filter(|n| state_temp_name(n)) {
            state_temp_file(&d, n)?;
            d.unlink(n, false)?;
        }
        d.unlink("lock", false)?;
    }
    if !d.names()?.is_empty() {
        return Err(recovery("Неизвестные файлы состояния"));
    }
    parent.unlink(name, true)
}
fn names(j: &Value) -> Result<(String, String, String)> {
    Ok((
        format!(".zapret-linux-rs.previous-{}", id(j, "operation_id")?),
        format!(
            ".zapret-linux-rs.stage-{}",
            id(&j["new"], "installation_id")?
        ),
        format!(
            ".zapret-linux-rs.state-{}",
            id(&j["new"], "installation_id")?
        ),
    ))
}
fn finish(l: &Layout, d: &Dir, j: &Value) -> Result<()> {
    let (backup, stage, state) = names(j)?;
    let committed = j["phase"] == "committed";
    let (p, s, m) = if committed {
        (&backup, &backup, &j["old"])
    } else {
        (&stage, &state, &j["new"])
    };
    discard_payload(&l.opt, p, m)?;
    discard_state(&l.state_parent, s, id(m, "installation_id")?)?;
    d.unlink(JOURNAL, false)?;
    clear_pending(l)
}
fn rollback(l: &Layout, d: &Dir, j: &mut Value, m: Option<&Manager>) -> Result<()> {
    let recovery_manager = m.map(Manager::recovery);
    let m = recovery_manager.as_ref();
    let (backup, stage, state) = names(j)?;
    phase(d, j, "restoring")?;
    if !l.verify_unit()? || l.definitions(true)? != j["enabled"].as_bool().unwrap() {
        return Err(recovery("Изменилась служба или автозапуск"));
    }
    let before = current(m)?;
    if before.as_ref().is_some_and(|s| !s.idle()) {
        m.unwrap().control("stop")?;
    }
    // Recover only the currently published identity, using its verified tools.
    if l.opt.exists(PAYLOAD)? {
        let (_, actual) = verify_payload(&l.opt, PAYLOAD)?;
        if actual != j["old"] && actual != j["new"] {
            return Err(recovery("Подменена текущая установка"));
        }
        if !l.offline
            && l.state_parent.exists(PAYLOAD)?
            && l.verify_state(id(&actual, "installation_id")?, false)
                .is_ok()
        {
            recover_service_state()?;
        }
        if actual == j["new"] {
            l.opt.rename(PAYLOAD, &l.opt, &stage)?;
        }
    }
    if l.state_parent.exists(PAYLOAD)? {
        let dstate = l.state_parent.child(PAYLOAD)?;
        let sid = dstate.read("lock", 0o600, 128)?;
        if sid == id(&j["new"], "installation_id")?.as_bytes() {
            let _lease = state_lease(&l.state_parent, PAYLOAD, id(&j["new"], "installation_id")?)?;
            l.state_parent.rename(PAYLOAD, &l.state_parent, &state)?;
        } else if sid != id(&j["old"], "installation_id")?.as_bytes() {
            return Err(recovery("Подменено состояние"));
        }
    }
    if !l.opt.exists(PAYLOAD)? {
        payload_matches(&l.opt, &backup, &j["old"])?;
        l.opt.rename(&backup, &l.opt, PAYLOAD)?;
    }
    if !l.state_parent.exists(PAYLOAD)? {
        let _lease = state_lease(&l.state_parent, &backup, id(&j["old"], "installation_id")?)?;
        l.state_parent.rename(&backup, &l.state_parent, PAYLOAD)?;
    }
    payload_matches(&l.opt, PAYLOAD, &j["old"])?;
    drop(state_lease(
        &l.state_parent,
        PAYLOAD,
        id(&j["old"], "installation_id")?,
    )?);
    if j["was_running"] == true
        && j["boot_id"] == boot()?
        && let Some(m) = m
    {
        start_preflight()?;
        m.control("start")?;
    }
    phase(d, j, "rolled_back")?;
    crate::output::record_restoration(true);
    finish(l, d, j)
}
pub(super) fn recover(l: &Layout, m: Option<&Manager>) -> Result<Value> {
    let d = directory(l)?;
    if !d.exists(JOURNAL)? {
        clear_pending(l)?;
        return Ok(report(l, "recovered", None, None, l.definitions(true)?));
    }
    let mut j = load(&d)?;
    if j["kind"] == "pause" {
        if verified(l)? != j["old"] {
            return Err(recovery("Изменилась установка"));
        }
        crate::ui_actions::recover_for_service()?;
        restore_pause(l, &d, &mut j, m)?;
        let v = verified(l)?;
        return Ok(report(
            l,
            "recovered",
            Some(&v),
            current(m)?.as_ref(),
            l.definitions(true)?,
        ));
    }
    let committed = j["phase"] == "committed";
    if committed || j["phase"] == "rolled_back" {
        let expected = if committed { &j["new"] } else { &j["old"] };
        if verified(l)? != *expected {
            return Err(recovery("Текущая установка изменена"));
        }
        current(m)?;
        finish(l, &d, &j)?;
    } else {
        rollback(l, &d, &mut j, m).map_err(|e| recovery(e.message))?;
    }
    let v = verified(l)?;
    Ok(report(
        l,
        "recovered",
        Some(&v),
        current(m)?.as_ref(),
        l.definitions(true)?,
    ))
}
fn restore_pause(l: &Layout, d: &Dir, j: &mut Value, m: Option<&Manager>) -> Result<()> {
    if verified(l)? != j["old"] || l.definitions(true)? != j["enabled"].as_bool().unwrap() {
        return Err(recovery("Установка изменилась во время проверки"));
    }
    let recovery_manager = m.map(Manager::recovery);
    let state = current(recovery_manager.as_ref())?;
    phase(d, j, "restoring")?;
    if j["was_running"] == true
        && j["boot_id"] == boot()?
        && let Some(m) = m
        && state.as_ref().is_some_and(Status::idle)
    {
        start_preflight()?;
        m.control_for_recovery("start")?;
    }
    phase(d, j, "committed")?;
    crate::output::record_restoration(true);
    d.unlink(JOURNAL, false)?;
    clear_pending(l)
}
pub(super) fn pause(
    l: &Layout,
    allow_pause: bool,
    operation: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    require_idle(l)?;
    if !l.opt.exists(PAYLOAD)? {
        if l.system.exists(UNIT)? || l.state_parent.exists(PAYLOAD)? {
            return Err(recovery("Неполная установка службы"));
        }
        return operation();
    }
    let m = l.manager()?;
    let old = verified(l)?;
    let before = current(m.as_ref())?;
    if before.as_ref().is_none_or(Status::idle) {
        return operation();
    }
    if !allow_pause {
        return Err(AppError::new(
            "pause_required",
            "Для проверки нужно временно остановить фоновый запуск",
        ));
    }
    let d = directory(l)?;
    let mut j = json!({"schema":1,"kind":"pause","phase":"prepared","operation_id":service_fs::random_id()?,"old_sha256":hash(&old)?,"old":old,"was_running":true,"enabled":l.definitions(true)?,"boot_id":boot()?});
    begin(l)?;
    write(&d, &j)?;
    let action = (|| {
        crate::output::record_restoration(false);
        phase(&d, &mut j, "stopping")?;
        m.as_ref().unwrap().control("stop")?;
        recover_service_state()?;
        drop(state_lease(
            &l.state_parent,
            PAYLOAD,
            id(&j["old"], "installation_id")?,
        )?);
        phase(&d, &mut j, "paused")?;
        operation()
    })();
    if action
        .as_ref()
        .err()
        .is_some_and(|e| e.kind == "outcome_unknown")
        || crate::output::action_result().1 == Some(false)
    {
        return Err(recovery(action.err().map(|e| e.message).unwrap_or_else(
            || "Не подтверждена очистка ручного запуска".into(),
        )));
    }
    restore_pause(l, &d, &mut j, m.as_ref()).map_err(|e| recovery(e.message))?;
    action
}
pub(super) fn apply(l: &Layout, o: &Options, m: Option<&Manager>) -> Result<Value> {
    require_idle(l)?;
    let old = verified(l)?;
    let before = current(m)?;
    let enabled = l.definitions(true)?;
    let (stage, new) = snapshot(l, o)?;
    let d = directory(l)?;
    let mut j = json!({"schema":1,"kind":"apply","phase":"prepared","operation_id":service_fs::random_id()?,"old_sha256":hash(&old)?,"new_sha256":hash(&new)?,"old":old,"new":new,"enabled":enabled,"was_running":before.as_ref().is_some_and(|s|!s.idle()),"boot_id":boot()?});
    let (backup, _, state) = names(&j)?;
    let ns = l.state_parent.mkdir(&state, 0o700)?;
    ns.write("lock", id(&j["new"], "installation_id")?.as_bytes(), 0o600)?;
    begin(l)?;
    write(&d, &j)?;
    let result = (|| {
        phase(&d, &mut j, "stopping")?;
        let now = current(m)?;
        if now.as_ref().is_some_and(|s| !s.idle()) {
            m.unwrap().control("stop")?;
        }
        if !l.offline {
            recover_service_state()?;
        }
        let lease = state_lease(&l.state_parent, PAYLOAD, id(&j["old"], "installation_id")?)?;
        payload_matches(&l.opt, PAYLOAD, &j["old"])?;
        phase(&d, &mut j, "moving_old_payload")?;
        l.opt.rename(PAYLOAD, &l.opt, &backup)?;
        phase(&d, &mut j, "moving_old_state")?;
        l.state_parent.rename(PAYLOAD, &l.state_parent, &backup)?;
        phase(&d, &mut j, "publishing_payload")?;
        l.opt.rename(&stage, &l.opt, PAYLOAD)?;
        phase(&d, &mut j, "publishing_state")?;
        l.state_parent.rename(&state, &l.state_parent, PAYLOAD)?;
        drop(lease);
        phase(&d, &mut j, "starting")?;
        if j["was_running"] == true
            && let Some(m) = m
        {
            start_preflight()?;
            m.control("start")?;
        }
        let observed = current(m)?;
        if observed
            .as_ref()
            .is_some_and(|s| s.idle() == j["was_running"].as_bool().unwrap())
        {
            return Err(recovery(
                "Режим работы службы изменился во время применения",
            ));
        }
        if l.definitions(true)? != enabled {
            return Err(recovery("Изменился автозапуск"));
        }
        phase(&d, &mut j, "committed")
    })();
    if let Err(e) = result {
        if e.kind == "outcome_unknown" || e.kind == "recovery_required" {
            return Err(recovery(e.message));
        }
        rollback(l, &d, &mut j, m).map_err(|restore| {
            recovery(format!(
                "{}; восстановление: {}",
                e.message, restore.message
            ))
        })?;
        return Err(AppError::new(
            "apply_failed_restored",
            format!(
                "Не удалось применить: {}. Прежняя установка восстановлена",
                e.message
            ),
        ));
    }
    finish(l, &d, &j).map_err(|e| recovery(e.message))?;
    Ok(report(
        l,
        "applied",
        Some(&j["new"]),
        current(m)?.as_ref(),
        enabled,
    ))
}
