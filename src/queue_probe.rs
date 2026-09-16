use crate::{
    error::{AppError, Result},
    nft::Nft,
    owned_table::OwnedTable,
    process::Managed,
    runtime::QUEUE_NUM,
    signals::Signals,
};
use std::{
    io,
    net::UdpSocket,
    thread,
    time::{Duration, Instant},
};

fn network_error(error: io::Error) -> AppError {
    AppError::new("readiness", error.to_string())
}

pub fn alive(child: &mut Managed) -> Result<()> {
    if let Some(status) = child.poll()? {
        return Err(AppError::new(
            "engine",
            format!(
                "nfqws неожиданно завершился: {status}\n{}",
                child.diagnostics()
            ),
        ));
    }
    Ok(())
}

pub fn verify(
    nft: &Nft<'_>,
    child: &mut Managed,
    signals: &Signals,
    timeout: Duration,
    table: &OwnedTable,
    verify_owner: bool,
) -> Result<()> {
    let sender = UdpSocket::bind("127.0.0.1:0").map_err(network_error)?;
    let receiver = UdpSocket::bind("127.0.0.1:0").map_err(network_error)?;
    sender.set_nonblocking(true).map_err(network_error)?;
    receiver.set_nonblocking(true).map_err(network_error)?;
    let source = sender.local_addr().map_err(network_error)?;
    let target = receiver.local_addr().map_err(network_error)?;
    let batch = format!(
        "create table inet zapret_rs_probe\nadd chain inet zapret_rs_probe out {{ type filter hook output priority -150; policy accept; }}\nadd rule inet zapret_rs_probe out ip saddr 127.0.0.1 ip daddr 127.0.0.1 udp sport {} udp dport {} queue num {QUEUE_NUM}\n",
        source.port(),
        target.port()
    );
    signals.check()?;
    alive(child)?;
    table.apply(nft, "probe-apply", &batch)?;
    let result = (|| {
        let start = Instant::now();
        let payload = b"zapret-linux-rs queue readiness";
        let mut buffer = [0; 128];
        loop {
            signals.check()?;
            alive(child)?;
            if verify_owner {
                crate::queue_owner::require(child.id())?;
            }
            // With no listener the kernel can return EPERM/ECONNREFUSED.
            // Retry within the deadline while nfqws is still starting.
            if let Err(error) = sender.send_to(payload, target)
                && !matches!(
                    error.raw_os_error(),
                    Some(
                        libc::EPERM
                            | libc::ECONNREFUSED
                            | libc::ENOBUFS
                            | libc::EAGAIN
                            | libc::EINTR
                    )
                )
            {
                return Err(network_error(error));
            }
            match receiver.recv_from(&mut buffer) {
                Ok((count, peer)) if peer == source && buffer[..count] == payload[..] => {
                    alive(child)?;
                    if verify_owner {
                        crate::queue_owner::require(child.id())?;
                    }
                    return Ok(());
                }
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(network_error(error)),
            }
            if start.elapsed() >= timeout {
                return Err(AppError::new(
                    "timeout",
                    format!(
                        "nfqws readiness: очередь не вернула контрольный пакет за {} мс\n{}",
                        timeout.as_millis(),
                        child.diagnostics()
                    ),
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    })();
    crate::error::combine(result, table.remove(nft))
}
