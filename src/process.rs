use crate::error::{AppError, Result};
use std::{
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

pub struct Captured {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
}

struct RunningChild(Child);

impl Drop for RunningChild {
    fn drop(&mut self) {
        // Child::kill does nothing after a successfully reaped exit status.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn nonblocking(pipe: &impl AsRawFd) -> io::Result<()> {
    // SAFETY: the descriptor is owned by a live pipe. fcntl receives no pointers.
    unsafe {
        let flags = libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL);
        if flags == -1
            || libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) == -1
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn drain(pipe: &mut impl Read, output: &mut Vec<u8>, truncated: &mut bool) -> io::Result<()> {
    let mut buffer = [0; 4096];
    // Bound each iteration so a noisy child cannot starve the timeout check.
    for _ in 0..32 {
        match pipe.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                let retain = count.min(65536 - output.len());
                output.extend_from_slice(&buffer[..retain]);
                *truncated |= retain < count;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

pub fn capture(mut command: Command, input: &[u8], timeout: Duration) -> Result<Captured> {
    let io_error = |e: io::Error| AppError::new("process", e.to_string());
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: scalar Linux syscalls only; no allocations/locks after fork.
    unsafe {
        let parent = libc::getpid();
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                libc::_exit(125);
            }
            Ok(())
        });
    }
    let mut running = RunningChild(command.spawn().map_err(io_error)?);
    let mut stdin = running.0.stdin.take();
    let mut stdout = running
        .0
        .stdout
        .take()
        .ok_or_else(|| AppError::new("process", "Нет stdout"))?;
    let mut stderr = running
        .0
        .stderr
        .take()
        .ok_or_else(|| AppError::new("process", "Нет stderr"))?;
    nonblocking(&stdout).map_err(io_error)?;
    nonblocking(&stderr).map_err(io_error)?;
    if let Some(pipe) = &stdin {
        nonblocking(pipe).map_err(io_error)?;
    }
    let mut sent = 0;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut truncated = false;
    let start = Instant::now();
    let status = loop {
        drain(&mut stdout, &mut out, &mut truncated).map_err(io_error)?;
        drain(&mut stderr, &mut err, &mut truncated).map_err(io_error)?;
        if sent == input.len() {
            stdin.take();
        } else if let Some(pipe) = &mut stdin {
            match pipe.write(&input[sent..]) {
                Ok(0) => {
                    stdin.take();
                }
                Ok(count) => sent += count,
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                    stdin.take();
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(io_error(e)),
            }
        }
        if let Some(status) = running.0.try_wait().map_err(io_error)? {
            break status;
        }
        if start.elapsed() >= timeout {
            return Err(AppError::new(
                "timeout",
                format!(
                    "Процесс превысил {} мс; дочерний процесс остановлен",
                    timeout.as_millis()
                ),
            ));
        }
        thread::sleep(Duration::from_millis(5));
    };
    drain(&mut stdout, &mut out, &mut truncated).map_err(io_error)?;
    drain(&mut stderr, &mut err, &mut truncated).map_err(io_error)?;
    if status.success() && sent != input.len() {
        return Err(AppError::new(
            "process",
            "Процесс завершился до полной передачи stdin",
        ));
    }
    Ok(Captured {
        status,
        stdout: String::from_utf8_lossy(&out).into_owned(),
        stderr: String::from_utf8_lossy(&err).into_owned(),
        truncated,
    })
}
