pub mod system_proxy;

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use maxq_cert_probe::detect_singbox_log_pin_mismatch;
use maxq_singbox_compiler::CompiledConfig;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::broadcast;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("sing-box binary not found at {0}")]
    BinaryNotFound(PathBuf),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("sing-box process failed to start: {0}")]
    SpawnFailed(String),
    #[error("system proxy error: {0}")]
    SystemProxy(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuntimeEvent {
    Started {
        pid: u32,
        clash_api_port: u16,
        mixed_port: u16,
    },
    Stopped {
        exit_code: Option<i32>,
    },
    LogLine {
        timestamp: DateTime<Utc>,
        stream: String,
        message: String,
    },
    /// CRITICAL security event intercepted from sing-box stderr when a pinned node presents
    /// an unrecognized remote public key SPKI hash (potential MITM or server key rotation).
    CertificatePinMismatch {
        timestamp: DateTime<Utc>,
        observed_spki_b64: String,
        raw_line: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub active_node_id: Option<String>,
    pub active_node_name: Option<String>,
    pub clash_api_port: Option<u16>,
    pub mixed_port: Option<u16>,
    pub system_proxy_enabled: bool,
    pub last_mitm_alert: Option<String>,
}

impl Default for RuntimeStatus {
    fn default() -> Self {
        Self {
            running: false,
            pid: None,
            active_node_id: None,
            active_node_name: None,
            clash_api_port: None,
            mixed_port: None,
            system_proxy_enabled: false,
            last_mitm_alert: None,
        }
    }
}

const MAX_LOG_RING: usize = 500;

/// Supervises the external `sing-box` process with restricted config permissions,
/// log redaction, and real-time SPKI pin mismatch interception.
pub struct SingBoxSupervisor {
    singbox_path: PathBuf,
    runtime_dir: PathBuf,
    child: Option<Child>,
    clash_api_secret: Option<String>,
    status: Arc<Mutex<RuntimeStatus>>,
    logs: Arc<Mutex<VecDeque<String>>>,
    events_tx: broadcast::Sender<RuntimeEvent>,
}

impl SingBoxSupervisor {
    pub fn new(singbox_path: PathBuf, runtime_dir: PathBuf) -> Self {
        let (events_tx, _) = broadcast::channel(256);
        Self {
            singbox_path,
            runtime_dir,
            child: None,
            clash_api_secret: None,
            status: Arc::new(Mutex::new(RuntimeStatus::default())),
            logs: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_LOG_RING))),
            events_tx,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<RuntimeEvent> {
        self.events_tx.subscribe()
    }

    pub fn status(&self) -> RuntimeStatus {
        self.status.lock().unwrap().clone()
    }

    pub fn recent_logs(&self) -> Vec<String> {
        self.logs.lock().unwrap().iter().cloned().collect()
    }

    pub fn clash_api_secret(&self) -> Option<&str> {
        self.clash_api_secret.as_deref()
    }

    /// Writes the compiled `sing-box` config into the app-owned runtime directory and spawns `sing-box run`.
    pub async fn start(
        &mut self,
        node_id: String,
        node_name: String,
        compiled: &CompiledConfig,
        mixed_port: u16,
        clash_api_port: u16,
    ) -> Result<u32, RuntimeError> {
        self.stop().await?;

        if !self.singbox_path.exists() {
            return Err(RuntimeError::BinaryNotFound(self.singbox_path.clone()));
        }

        std::fs::create_dir_all(&self.runtime_dir)?;
        let config_path = self.runtime_dir.join("active-config.json");
        let serialized = serde_json::to_string_pretty(&compiled.json)?;
        write_restricted_file(&config_path, serialized.as_bytes())?;

        let mut cmd = Command::new(&self.singbox_path);
        cmd.args(["run", "-c"])
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        #[cfg(windows)]
        {
            // CREATE_NO_WINDOW = 0x08000000 so sing-box never flashes a console window
            cmd.creation_flags(0x0800_0000);
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| RuntimeError::SpawnFailed(e.to_string()))?;
        let pid = child.id().unwrap_or(0);

        if let Some(stdout) = child.stdout.take() {
            spawn_log_reader(
                stdout,
                "stdout",
                Arc::clone(&self.logs),
                Arc::clone(&self.status),
                self.events_tx.clone(),
            );
        }
        if let Some(stderr) = child.stderr.take() {
            spawn_log_reader(
                stderr,
                "stderr",
                Arc::clone(&self.logs),
                Arc::clone(&self.status),
                self.events_tx.clone(),
            );
        }

        self.child = Some(child);
        self.clash_api_secret = Some(compiled.clash_api_secret.clone());

        {
            let mut st = self.status.lock().unwrap();
            st.running = true;
            st.pid = Some(pid);
            st.active_node_id = Some(node_id);
            st.active_node_name = Some(node_name);
            st.clash_api_port = Some(clash_api_port);
            st.mixed_port = Some(mixed_port);
            st.last_mitm_alert = None;
        }

        let _ = self.events_tx.send(RuntimeEvent::Started {
            pid,
            clash_api_port,
            mixed_port,
        });

        Ok(pid)
    }

    pub async fn stop(&mut self) -> Result<(), RuntimeError> {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill().await;
            let exit_code = child.wait().await.ok().and_then(|s| s.code());
            {
                let mut st = self.status.lock().unwrap();
                st.running = false;
                st.pid = None;
            }
            self.clash_api_secret = None;
            let _ = self.events_tx.send(RuntimeEvent::Stopped { exit_code });
        }
        Ok(())
    }
}

fn spawn_log_reader<R: tokio::io::AsyncRead + Unpin + Send + 'static>(
    reader: R,
    stream_name: &'static str,
    logs: Arc<Mutex<VecDeque<String>>>,
    status: Arc<Mutex<RuntimeStatus>>,
    tx: broadcast::Sender<RuntimeEvent>,
) {
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let redacted = redact_log_line(&line);
            if let Some(observed_spki) = detect_singbox_log_pin_mismatch(&line) {
                {
                    let mut st = status.lock().unwrap();
                    st.last_mitm_alert = Some(observed_spki.clone());
                }
                let _ = tx.send(RuntimeEvent::CertificatePinMismatch {
                    timestamp: Utc::now(),
                    observed_spki_b64: observed_spki,
                    raw_line: redacted.clone(),
                });
            }
            {
                let mut ring = logs.lock().unwrap();
                if ring.len() >= MAX_LOG_RING {
                    ring.pop_front();
                }
                ring.push_back(redacted.clone());
            }
            let _ = tx.send(RuntimeEvent::LogLine {
                timestamp: Utc::now(),
                stream: stream_name.to_string(),
                message: redacted,
            });
        }
    });
}

/// Redacts Bearer tokens and obvious inline secret/password fields before exposing logs to UI.
pub fn redact_log_line(line: &str) -> String {
    let mut out = line.to_string();
    for marker in ["Bearer ", "secret=", "password="] {
        if let Some(pos) = out.find(marker) {
            let start = pos + marker.len();
            let end = out[start..]
                .find(|c: char| c.is_whitespace() || c == '"' || c == ',' || c == '&')
                .map(|i| start + i)
                .unwrap_or(out.len());
            out.replace_range(start..end, "<REDACTED>");
        }
    }
    out
}

fn write_restricted_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_secrets_from_runtime_logs() {
        let line = "Authorization: Bearer abcdef1234567890 password=mysecret ok";
        let redacted = redact_log_line(line);
        assert!(!redacted.contains("abcdef1234567890"));
        assert!(!redacted.contains("mysecret"));
        assert!(redacted.contains("Bearer <REDACTED>"));
        assert!(redacted.contains("password=<REDACTED>"));
    }
}
