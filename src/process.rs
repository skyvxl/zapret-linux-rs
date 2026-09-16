use crate::error::{AppError, Result};
use std::{
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

pub struct Captured {
    pub status: ExitStatus,
    pub stdout: String,
    pub stdout_valid_utf8: bool,
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

fn process_error(error: io::Error) -> AppError {
    AppError::new("process", error.to_string())
}

pub struct Managed {
    running: RunningChild,
    stdout: ChildStdout,
    stderr: ChildStderr,
    out: Vec<u8>,
    err: Vec<u8>,
    truncated: bool,
}

impl Managed {
    pub fn spawn(command: Command) -> Result<Self> {
        Self::with_stdin(command, Stdio::null())
    }

    fn with_stdin(mut command: Command, stdin: Stdio) -> Result<Self> {
        command
            .process_group(0)
            .stdin(stdin)
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
        let mut running = RunningChild(command.spawn().map_err(process_error)?);

        let stdout = running
            .0
            .stdout
            .take()
            .ok_or_else(|| AppError::new("process", "Нет stdout"))?;
        let stderr = running
            .0
            .stderr
            .take()
            .ok_or_else(|| AppError::new("process", "Нет stderr"))?;
        nonblocking(&stdout).map_err(process_error)?;
        nonblocking(&stderr).map_err(process_error)?;
        Ok(Self {
            running,
            stdout,
            stderr,
            out: Vec::new(),
            err: Vec::new(),
            truncated: false,
        })
    }

    pub fn id(&self) -> u32 {
        self.running.0.id()
    }

    fn drain(&mut self) -> Result<()> {
        drain(&mut self.stdout, &mut self.out, &mut self.truncated).map_err(process_error)?;
        drain(&mut self.stderr, &mut self.err, &mut self.truncated).map_err(process_error)
    }

    pub fn poll(&mut self) -> Result<Option<ExitStatus>> {
        self.drain()?;
        let status = self.running.0.try_wait().map_err(process_error)?;
        if status.is_some() {
            self.drain()?;
        }
        Ok(status)
    }

    pub fn diagnostics(&self) -> String {
        format!(
            "{}\n{}{}",
            String::from_utf8_lossy(&self.err),
            String::from_utf8_lossy(&self.out),
            if self.truncated {
                "\nВывод усечён"
            } else {
                ""
            }
        )
    }

    fn captured(&self, status: ExitStatus) -> Captured {
        Captured {
            status,
            stdout: String::from_utf8_lossy(&self.out).into_owned(),
            stdout_valid_utf8: std::str::from_utf8(&self.out).is_ok(),
            stderr: String::from_utf8_lossy(&self.err).into_owned(),
            truncated: self.truncated,
        }
    }

    pub fn stop(&mut self, grace: Duration) -> Result<(Captured, bool)> {
        if let Some(status) = self.poll()? {
            return Ok((self.captured(status), false));
        }
        // SAFETY: the child has not been reaped, so its PID cannot be reused.
        if unsafe { libc::kill(self.id() as libc::pid_t, libc::SIGTERM) } == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(process_error(error));
            }
        }
        let start = Instant::now();
        loop {
            if let Some(status) = self.poll()? {
                return Ok((self.captured(status), false));
            }
            if start.elapsed() >= grace {
                self.running.0.kill().map_err(process_error)?;
                let status = self.running.0.wait().map_err(process_error)?;
                self.drain()?;
                return Ok((self.captured(status), true));
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}

pub fn capture(command: Command, input: &[u8], timeout: Duration) -> Result<Captured> {
    let mut running = if input.is_empty() {
        Managed::spawn(command)?
    } else {
        Managed::with_stdin(command, Stdio::piped())?
    };
    let mut stdin = running.running.0.stdin.take();
    if let Some(pipe) = &stdin {
        nonblocking(pipe).map_err(process_error)?;
    }
    let mut sent = 0;
    let start = Instant::now();
    let status = loop {
        running.drain()?;
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
                Err(e) => return Err(process_error(e)),
            }
        }
        if let Some(status) = running.poll()? {
            break status;
        }
        if start.elapsed() >= timeout {
            let diagnostic = running.diagnostics();
            running.stop(Duration::ZERO)?;
            return Err(AppError::new(
                "timeout",
                format!(
                    "Процесс превысил {} мс; дочерний процесс остановлен\n{}",
                    timeout.as_millis(),
                    diagnostic
                ),
            ));
        }
        thread::sleep(Duration::from_millis(5));
    };
    if status.success() && sent != input.len() {
        return Err(AppError::new(
            "process",
            "Процесс завершился до полной передачи stdin",
        ));
    }
    Ok(running.captured(status))
}
