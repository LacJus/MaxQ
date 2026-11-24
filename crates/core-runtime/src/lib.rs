pub mod system_proxy;
pub mod tun_client;

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use maxq_singbox_compiler::CompiledConfig;
pub use maxq_win_service::protocol::redact_log_line;
use maxq_win_service::protocol::detect_singbox_log_pin_mismatch;
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
    #[serde(default)]
    pub tun_active: bool,
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
            tun_active: false,
            last_mitm_alert: None,
        }
    }
}

const MAX_LOG_RING: usize = 500;

#[cfg(windows)]
struct ChildJobGuard(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
unsafe impl Send for ChildJobGuard {}
#[cfg(windows)]
unsafe impl Sync for ChildJobGuard {}

#[cfg(windows)]
impl ChildJobGuard {
    /// Creates an anonymous Windows Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
    /// and binds `proc_handle` to it so the OS kernel unconditionally terminates `sing-box.exe`
    /// whenever the guard is dropped or the parent MaxQ process exits/crashes.
    fn assign_kill_on_close(proc_handle: windows_sys::Win32::Foundation::HANDLE) -> Option<Self> {
        use std::ffi::c_void;
        use std::ptr::null;
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };

        let job = unsafe { CreateJobObjectW(null(), null()) };
        if job.is_null() {
            return None;
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let ok_set = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok_set == 0 {
            unsafe {
                CloseHandle(job);
            }
            return None;
        }
        let ok_assign = unsafe { AssignProcessToJobObject(job, proc_handle) };
        if ok_assign == 0 {
            unsafe {
                CloseHandle(job);
            }
            return None;
        }
        Some(Self(job))
    }
}

#[cfg(windows)]
impl Drop for ChildJobGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.0);
            }
            self.0 = std::ptr::null_mut();
        }
    }
}

/// Supervises the external `sing-box` process with restricted config permissions,
/// log redaction, Windows Job Object crash-safety, and real-time SPKI pin mismatch interception.
pub struct SingBoxSupervisor {
    singbox_path: PathBuf,
    runtime_dir: PathBuf,
    child: Option<Child>,
    #[cfg(windows)]
    job_guard: Option<ChildJobGuard>,
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
            #[cfg(windows)]
            job_guard: None,
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

        #[cfg(windows)]
        let job_guard = child.raw_handle().and_then(|h| {
            ChildJobGuard::assign_kill_on_close(h as windows_sys::Win32::Foundation::HANDLE)
        });

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

        // Verify sing-box stays alive briefly (catches port conflicts / bad node params BEFORE
        // the caller enables Windows System Proxy!)
        for _ in 0..5 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if let Ok(Some(exit_status)) = child.try_wait() {
                #[cfg(windows)]
                drop(job_guard);
                let _ = std::fs::remove_file(&config_path);
                let tail = self
                    .logs
                    .lock()
                    .map(|r| {
                        r.iter()
                            .rev()
                            .take(6)
                            .rev()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(" | ")
                    })
                    .unwrap_or_default();
                return Err(RuntimeError::SpawnFailed(format!(
                    "sing-box 内核启动后立即退出 ({exit_status}): {tail}"
                )));
            }
        }

        self.child = Some(child);
        #[cfg(windows)]
        {
            self.job_guard = job_guard;
        }
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

    /// Checks whether the supervised `sing-box` child process is genuinely still alive.
    /// If it crashed or was terminated externally, cleans up state + `active-config.json`
    /// and returns `false` so the caller can immediately disable Windows System Proxy.
    pub fn poll_alive(&mut self) -> bool {
        let exited = match self.child.as_mut() {
            Some(child) => match child.try_wait() {
                Ok(None) => return true,
                Ok(Some(status)) => Some(status.code()),
                Err(_) => Some(None),
            },
            None => return false,
        };

        self.child = None;
        #[cfg(windows)]
        {
            self.job_guard.take();
        }
        self.remove_active_config_file();
        self.clash_api_secret = None;
        if let Ok(mut st) = self.status.lock() {
            st.running = false;
            st.pid = None;
        }
        let _ = self.events_tx.send(RuntimeEvent::Stopped {
            exit_code: exited.flatten(),
        });
        false
    }

    fn remove_active_config_file(&self) {
        let _ = std::fs::remove_file(self.runtime_dir.join("active-config.json"));
    }

    pub async fn stop(&mut self) -> Result<(), RuntimeError> {
        let mut had_child = false;
        let mut exit_code = None;
        if let Some(mut child) = self.child.take() {
            had_child = true;
            let _ = child.kill().await;
            exit_code = child.wait().await.ok().and_then(|s| s.code());
        }
        #[cfg(windows)]
        {
            self.job_guard.take();
        }
        self.remove_active_config_file();
        if had_child {
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

    /// Synchronous best-effort termination for app shutdown, tray quit, and `Drop` paths
    /// where awaiting an async runtime is unsafe or unavailable.
    pub fn stop_sync(&mut self) {
        let mut had_child = false;
        if let Some(mut child) = self.child.take() {
            had_child = true;
            let _ = child.start_kill();
        }
        #[cfg(windows)]
        {
            // Dropping the KILL_ON_JOB_CLOSE handle forces Windows kernel to terminate sing-box immediately
            self.job_guard.take();
        }
        self.remove_active_config_file();
        if had_child {
            if let Ok(mut st) = self.status.lock() {
                st.running = false;
                st.pid = None;
            }
            self.clash_api_secret = None;
            let _ = self.events_tx.send(RuntimeEvent::Stopped { exit_code: None });
        }
    }
}

impl Drop for SingBoxSupervisor {
    fn drop(&mut self) {
        self.stop_sync();
    }
}

/// Process-wide single-instance guard preventing two concurrent MaxQ GUI instances from
/// fighting over `sysproxy-backup.json`, SQLite vault, or localhost ports.
pub struct SingleInstanceGuard {
    #[cfg(windows)]
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
unsafe impl Send for SingleInstanceGuard {}
#[cfg(windows)]
unsafe impl Sync for SingleInstanceGuard {}

impl SingleInstanceGuard {
    /// Acquires the per-user single-instance lock.
    /// Returns `None` if another MaxQ instance is already running (and brings its window to front on Windows).
    pub fn acquire_or_focus_existing(window_title: &str) -> Option<Self> {
        #[cfg(windows)]
        {
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;
            use std::ptr::null;
            use windows_sys::Win32::Foundation::{
                CloseHandle, GetLastError, ERROR_ALREADY_EXISTS,
            };
            use windows_sys::Win32::System::Threading::CreateMutexW;
            use windows_sys::Win32::UI::WindowsAndMessaging::{
                FindWindowW, SetForegroundWindow, ShowWindow, SW_RESTORE,
            };

            let to_wide = |s: &str| -> Vec<u16> {
                OsStr::new(s)
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect()
            };
            let mutex_name = to_wide(r"Local\MaxQDesktopSingleInstanceMutex");
            let handle = unsafe { CreateMutexW(null(), 0, mutex_name.as_ptr()) };
            if handle.is_null() {
                // Fail open if OS refuses mutex creation so app still starts
                return Some(Self {
                    handle: std::ptr::null_mut(),
                });
            }
            let last_err = unsafe { GetLastError() };
            if last_err == ERROR_ALREADY_EXISTS {
                unsafe {
                    CloseHandle(handle);
                }
                let title_wide = to_wide(window_title);
                let hwnd = unsafe { FindWindowW(null(), title_wide.as_ptr()) };
                if !hwnd.is_null() {
                    unsafe {
                        ShowWindow(hwnd, SW_RESTORE);
                        SetForegroundWindow(hwnd);
                    }
                }
                return None;
            }
            Some(Self { handle })
        }
        #[cfg(not(windows))]
        {
            let _ = window_title;
            Some(Self {})
        }
    }
}

#[cfg(windows)]
impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.handle);
            }
            self.handle = std::ptr::null_mut();
        }
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
