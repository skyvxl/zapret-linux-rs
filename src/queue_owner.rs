use crate::{
    error::{AppError, Result},
    process::Managed,
    queue_probe,
    runtime::QUEUE_NUM,
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

enum QueuePeer {
    Unavailable,
    Unbound,
    Bound(u32),
}

fn queue_peer() -> Result<QueuePeer> {
    let file = match File::open("/proc/net/netfilter/nfnetlink_queue") {
        Ok(file) => file,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            // Some user namespaces cannot read this root-owned proc entry.
            // Retain the conservative all-sockets proof in that case.
            return Ok(QueuePeer::Unavailable);
        }
        Err(error) => return Err(fail(format!("Нельзя прочитать владельца NFQUEUE: {error}"))),
    };
    let mut text = String::new();
    file.take(65537)
        .read_to_string(&mut text)
        .map_err(|e| fail(e.to_string()))?;
    if text.len() > 65536 {
        return Err(fail("Слишком большой список NFQUEUE"));
    }
    let mut peer = None;
    for line in text.lines() {
        let fields = line
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| fail("Некорректное число в списке NFQUEUE"))?;
        if fields.len() != 9 || fields[0] > u16::MAX as u32 || fields[1] == 0 {
            return Err(fail("Неизвестный формат списка NFQUEUE"));
        }
        if fields[0] == u32::from(QUEUE_NUM) && peer.replace(fields[1]).is_some() {
            return Err(fail("Повторная запись очереди NFQUEUE"));
        }
    }
    Ok(peer.map_or(QueuePeer::Unbound, QueuePeer::Bound))
}

fn owns_queue(pid: u32) -> Result<bool> {
    let peer = match queue_peer()? {
        QueuePeer::Bound(port) => Some(port),
        QueuePeer::Unbound => return Ok(false),
        QueuePeer::Unavailable => None,
    };
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
        if number(1)? == libc::NETLINK_NETFILTER as u64
            && number(2)? != 0
            && peer.is_none_or(|port| number(2).ok() == Some(u64::from(port)))
        {
            let inode = number(9)?;
            if !sockets.contains(&inode) {
                return Err(fail(match peer {
                    Some(port) => format!("Очередь NFQUEUE {QUEUE_NUM} принадлежит другому процессу (netlink port ID {port}); сокет отсутствует у nfqws"),
                    None => "Таблица владельцев NFQUEUE недоступна, а в сети есть сторонний NETLINK_NETFILTER сокет; владение очередью подтвердить нельзя".into(),
                }));
            }
            count += 1;
        }
    }
    Ok(count > 0)
}

pub fn require(pid: u32) -> Result<()> {
    if owns_queue(pid)? {
        Ok(())
    } else {
        Err(fail(format!(
            "У движка нет подтверждённого сокета очереди NFQUEUE {QUEUE_NUM}"
        )))
    }
}

pub fn wait(child: &mut Managed, signals: &Signals, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        signals.check()?;
        queue_probe::alive(child)?;
        if owns_queue(child.id())? {
            return Ok(());
        }
        if start.elapsed() >= timeout {
            return Err(fail(format!(
                "Движок не подтвердил владение очередью NFQUEUE {QUEUE_NUM} за отведённое время"
            )));
        }
        thread::sleep(Duration::from_millis(10));
    }
}
