use crate::{
    error::{AppError, Result},
    process::Managed,
    queue_probe,
    signals::Signals,
};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Read,
    thread,
    time::{Duration, Instant},
};

fn fail(message: impl Into<String>) -> AppError {
    AppError::new("readiness", message)
}

fn owns_all(pid: u32) -> Result<bool> {
    let mut text = String::new();
    File::open("/proc/net/netlink")
        .and_then(|f| f.take(65537).read_to_string(&mut text))
        .map_err(|e| fail(format!("Нельзя проверить netlink sockets: {e}")))?;
    if text.len() > 65536 {
        return Err(fail("Слишком большой список netlink sockets"));
    }
    let mut lines = text.lines();
    if lines
        .next()
        .map(|s| s.split_whitespace().collect::<Vec<_>>())
        != Some(vec![
            "sk", "Eth", "Pid", "Groups", "Rmem", "Wmem", "Dump", "Locks", "Drops", "Inode",
        ])
    {
        return Err(fail("Неизвестный формат /proc/net/netlink"));
    }
    let mut sockets = BTreeSet::new();
    for (index, entry) in fs::read_dir(format!("/proc/{pid}/fd"))
        .map_err(|e| fail(e.to_string()))?
        .enumerate()
    {
        if index >= 4096 {
            return Err(fail("Слишком много дескрипторов движка"));
        }
        let entry = entry.map_err(|e| fail(e.to_string()))?;
        let target = match fs::read_link(entry.path()) {
            Ok(target) => target,
            // The child can close unrelated startup descriptors during readdir.
            // A vanished socket cannot supply ownership evidence below.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(fail(error.to_string())),
        };
        if let Some(s) = target
            .to_str()
            .and_then(|s| s.strip_prefix("socket:["))
            .and_then(|s| s.strip_suffix(']'))
        {
            sockets.insert(
                s.parse::<u64>()
                    .map_err(|_| fail("Некорректный inode сокета"))?,
            );
        }
        if sockets.len() > 4096 {
            return Err(fail("Слишком много сокетов движка"));
        }
    }
    let mut count = 0;
    for line in lines {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 10 {
            return Err(fail("Некорректная строка netlink sockets"));
        }
        let number = |index: usize| {
            fields[index]
                .parse::<u64>()
                .map_err(|_| fail("Некорректное число netlink sockets"))
        };
        if number(1)? == libc::NETLINK_NETFILTER as u64 && number(2)? != 0 {
            let inode = number(9)?;
            if !sockets.contains(&inode) {
                return Err(fail(
                    "Чужой NETLINK_NETFILTER сокет: владение очередью движком не подтверждено",
                ));
            }
            count += 1;
        }
    }
    Ok(count > 0)
}

pub fn require(pid: u32) -> Result<()> {
    if owns_all(pid)? {
        Ok(())
    } else {
        Err(fail(
            "У движка нет подтверждённого NETLINK_NETFILTER сокета",
        ))
    }
}

pub fn wait(child: &mut Managed, signals: &Signals, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        signals.check()?;
        queue_probe::alive(child)?;
        if owns_all(child.id())? {
            return Ok(());
        }
        if start.elapsed() >= timeout {
            return Err(fail(
                "Движок не открыл NETLINK_NETFILTER сокет за отведённое время",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}
