use crate::config::{integer, string};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, Command},
    sync::Mutex as AsyncMutex,
};

const MAX_OUTPUT: usize = 1024 * 1024;
#[derive(Default)]
struct Output {
    bytes: VecDeque<u8>,
    dropped: u64,
    cursor: usize,
}
struct Session {
    child: AsyncMutex<Child>,
    stdin: AsyncMutex<Option<ChildStdin>>,
    output: Arc<Mutex<Output>>,
    command: String,
}
#[derive(Default)]
pub struct Processes {
    sessions: AsyncMutex<HashMap<u32, Arc<Session>>>,
}

fn collect_output(reader: impl AsyncRead + Unpin + Send + 'static, output: Arc<Mutex<Output>>) {
    tokio::spawn(async move {
        let mut reader = reader;
        let mut buf = [0; 4096];
        while let Ok(n) = reader.read(&mut buf).await {
            if n == 0 {
                break;
            }
            let mut out = output.lock().expect("output lock");
            for b in &buf[..n] {
                if out.bytes.len() == MAX_OUTPUT {
                    out.bytes.pop_front();
                    out.dropped += 1;
                    out.cursor = out.cursor.saturating_sub(1);
                }
                out.bytes.push_back(*b);
            }
        }
    });
}

impl Processes {
    pub async fn start(&self, args: &Value, cwd: &std::path::Path) -> Result<Value> {
        let command = string(args, "command")?;
        ensure!(command.len() <= 32_768, "command too large");
        let wait = integer(args, "timeout_ms", 1000, 0, 30_000)? as u64;
        let mut sessions = self.sessions.lock().await;
        ensure!(
            sessions.len() < 64,
            "session limit reached; restart agent to release retained sessions"
        );
        #[cfg(windows)]
        let default_shell = "powershell.exe";
        #[cfg(not(windows))]
        let default_shell = "/bin/sh";
        let shell = if args.get("shell").is_some() {
            string(args, "shell")?
        } else {
            default_shell
        };
        let mut cmd = Command::new(shell);
        #[cfg(windows)]
        if shell.to_ascii_lowercase().contains("powershell")
            || shell.to_ascii_lowercase().contains("pwsh")
        {
            cmd.args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command,
            ]);
        } else if shell.to_ascii_lowercase().ends_with("cmd.exe")
            || shell.eq_ignore_ascii_case("cmd")
        {
            cmd.args(["/D", "/S", "/C", command]);
        } else {
            cmd.args(["-c", command]);
        }
        #[cfg(not(windows))]
        cmd.args(["-c", command]);
        #[cfg(unix)]
        cmd.process_group(0);
        let mut child = cmd
            .current_dir(cwd)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("start shell")?;
        let pid = child.id().context("missing process id")?;
        let output = Arc::new(Mutex::new(Output::default()));
        collect_output(
            child.stdout.take().context("stdout unavailable")?,
            output.clone(),
        );
        collect_output(
            child.stderr.take().context("stderr unavailable")?,
            output.clone(),
        );
        let stdin = child.stdin.take();
        sessions.insert(
            pid,
            Arc::new(Session {
                child: AsyncMutex::new(child),
                stdin: AsyncMutex::new(stdin),
                output,
                command: command.to_owned(),
            }),
        );
        drop(sessions);
        self.read(pid, &json!({"timeout_ms":wait})).await
    }
    async fn get(&self, pid: u32) -> Result<Arc<Session>> {
        self.sessions
            .lock()
            .await
            .get(&pid)
            .cloned()
            .context("unknown session; only agent-owned processes are accessible")
    }
    async fn wait(&self, session: &Session, ms: u64) -> Result<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
        loop {
            if session.child.lock().await.try_wait()?.is_some()
                || tokio::time::Instant::now() >= deadline
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok(())
    }
    pub async fn read(&self, pid: u32, args: &Value) -> Result<Value> {
        let session = self.get(pid).await?;
        let wait = integer(args, "timeout_ms", 0, 0, 30_000)? as u64;
        self.wait(&session, wait).await?;
        let status = session.child.lock().await.try_wait()?;
        let offset = integer(args, "offset", 0, -10_000, 100_000_000)?;
        let length = integer(args, "length", 1000, 1, 10_000)? as usize;
        let mut out = session.output.lock().expect("output lock");
        let data: Vec<_> = out.bytes.iter().copied().collect();
        let start = if offset == 0 {
            out.cursor.min(data.len())
        } else {
            0
        };
        let mut end = data.len();
        if offset == 0 {
            // Advance only over the returned page, not over unseen buffered output.
            let mut lines = 0;
            for (i, b) in data[start..].iter().enumerate() {
                if *b == b'\n' {
                    lines += 1;
                    if lines == length {
                        end = start + i + 1;
                        break;
                    }
                }
            }
        }
        let text = String::from_utf8_lossy(&data[start..end]);
        let text = crate::files::paginate(&text, offset, length);
        if offset == 0 {
            out.cursor = end;
        }
        Ok(
            json!({"pid":pid,"running":status.is_none(),"exitCode":status.and_then(|s|s.code()),"output":text,"droppedBytes":out.dropped}),
        )
    }
    pub async fn interact(&self, pid: u32, args: &Value) -> Result<Value> {
        let session = self.get(pid).await?;
        let input = string(args, "input")?;
        ensure!(input.len() <= 64 * 1024, "input too large");
        ensure!(
            session.child.lock().await.try_wait()?.is_none(),
            "process already exited"
        );
        let mut stdin = session.stdin.lock().await;
        let stdin = stdin.as_mut().context("stdin closed")?;
        tokio::time::timeout(Duration::from_secs(5), async {
            stdin.write_all(input.as_bytes()).await?;
            stdin.write_all(b"\n").await?;
            stdin.flush().await
        })
        .await
        .context("stdin write timed out")??;
        self.read(pid, args).await
    }
    pub async fn kill(&self, pid: u32) -> Result<Value> {
        let session = self.get(pid).await?;
        let mut child = session.child.lock().await;
        if child.try_wait()?.is_none() {
            #[cfg(windows)]
            {
                let status = tokio::time::timeout(
                    Duration::from_secs(10),
                    Command::new("taskkill.exe")
                        .args(["/PID", &pid.to_string(), "/T", "/F"])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status(),
                )
                .await??;
                ensure!(
                    status.success() || child.try_wait()?.is_some(),
                    "taskkill failed"
                );
            }
            #[cfg(unix)]
            {
                // A separate process group was created before exec; do not signal arbitrary host PIDs.
                let code = unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
                ensure!(
                    code == 0 || child.try_wait()?.is_some(),
                    "kill process group failed"
                );
            }
            let _ = child.start_kill();
            tokio::time::timeout(Duration::from_secs(5), child.wait()).await??;
        }
        Ok(json!({"pid":pid,"terminated":true}))
    }
    pub async fn list(&self) -> Result<Value> {
        let sessions: Vec<_> = self
            .sessions
            .lock()
            .await
            .iter()
            .map(|(id, s)| (*id, s.clone()))
            .collect();
        let mut result = Vec::new();
        for (pid, s) in sessions {
            let status = s.child.lock().await.try_wait()?;
            result.push(json!({"pid":pid,"command":s.command,"running":status.is_none(),"exitCode":status.and_then(|s|s.code())}));
        }
        Ok(json!({"scope":"agent-owned sessions only","sessions":result}))
    }
    pub async fn shutdown(&self) {
        let ids: Vec<_> = self.sessions.lock().await.keys().copied().collect();
        for id in ids {
            if let Err(e) = self.kill(id).await {
                eprintln!("process cleanup failed for {id}: {e}");
            }
        }
    }
}

pub fn pid(args: &Value) -> Result<u32> {
    Ok(integer(args, "pid", 0, 1, u32::MAX as i64)? as u32)
}
