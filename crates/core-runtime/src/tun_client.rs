use std::path::Path;

use maxq_win_service::protocol::{ServiceRequest, ServiceResponse, TunServiceStatus};

use crate::RuntimeError;

/// Client for communicating with MaxQ's hardened Windows TUN Service (`MaxQTunService`)
/// over the SDDL-locked Named Pipe `\\.\pipe\maxq-tun-service-v1`.
pub struct TunServiceClient;

impl TunServiceClient {
    pub fn query_status() -> TunServiceStatus {
        match send_request(&ServiceRequest::Status) {
            Ok(ServiceResponse::Status(st)) => st,
            Ok(ServiceResponse::Error { message }) => {
                let mut st = query_scm_fallback_status();
                st.last_error = Some(message);
                st
            }
            Ok(other) => {
                let mut st = query_scm_fallback_status();
                st.last_error = Some(format!("unexpected TUN service response: {other:?}"));
                st
            }
            Err(err) => {
                let mut st = query_scm_fallback_status();
                let diag = read_diagnostic_status();
                if st.installed {
                    let detail = match diag {
                        Some(d) if !d.starts_with("OK:") => format!("{d} | IPC: {err}"),
                        _ => err.to_string(),
                    };
                    st.last_error = Some(detail);
                } else if let Some(d) = diag {
                    if !d.starts_with("OK:") {
                        st.last_error = Some(d);
                    }
                }
                st
            }
        }
    }

    pub fn start_tun(config_json: String) -> Result<u32, RuntimeError> {
        Self::start_tun_with_meta(config_json, None, None, None)
    }

    pub fn start_tun_with_meta(
        config_json: String,
        active_profile_id: Option<String>,
        active_node_id: Option<String>,
        active_node_name: Option<String>,
    ) -> Result<u32, RuntimeError> {
        match send_request(&ServiceRequest::StartTun {
            config_json,
            active_profile_id,
            active_node_id,
            active_node_name,
        })? {
            ServiceResponse::Started { pid } => Ok(pid),
            ServiceResponse::Error { message } => Err(RuntimeError::SpawnFailed(message)),
            other => Err(RuntimeError::SpawnFailed(format!(
                "unexpected TUN service response: {other:?}"
            ))),
        }
    }

    pub fn stop_tun() -> Result<(), RuntimeError> {
        match send_request(&ServiceRequest::StopTun)? {
            ServiceResponse::Stopped => Ok(()),
            ServiceResponse::Error { message } => Err(RuntimeError::SpawnFailed(message)),
            _ => Ok(()),
        }
    }

    pub fn get_logs() -> Vec<String> {
        match send_request(&ServiceRequest::GetLogs) {
            Ok(ServiceResponse::Logs { lines }) => lines,
            _ => vec![],
        }
    }

    /// Invokes `maxq-service.exe install` via Windows UAC (`ShellExecuteExW("runas", ...)`),
    /// waits for completion, and surfaces any installation error clearly.
    pub fn install_elevated(service_exe: &Path) -> Result<(), RuntimeError> {
        run_elevated_service_cmd(service_exe, "install")
    }

    /// Invokes `maxq-service.exe uninstall` via Windows UAC (`ShellExecuteExW("runas", ...)`),
    /// waits for completion, and surfaces any uninstallation error clearly.
    pub fn uninstall_elevated(service_exe: &Path) -> Result<(), RuntimeError> {
        run_elevated_service_cmd(service_exe, "uninstall")
    }
}

#[cfg(windows)]
fn read_diagnostic_status() -> Option<String> {
    use maxq_win_service::protocol::{DIAGNOSTIC_STATUS_FILE, DIAGNOSTIC_STATUS_SUBDIR};
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    let path = std::path::PathBuf::from(base)
        .join("MaxQ")
        .join(DIAGNOSTIC_STATUS_SUBDIR)
        .join(DIAGNOSTIC_STATUS_FILE);
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(not(windows))]
fn read_diagnostic_status() -> Option<String> {
    None
}

/// Read-only SCM query (works without admin rights) so the UI can distinguish
/// "service not installed" vs "service installed but stopped / unreachable".
#[cfg(windows)]
fn query_scm_fallback_status() -> TunServiceStatus {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null;
    use maxq_win_service::protocol::SERVICE_NAME;
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT,
        SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS,
    };

    let mut status = TunServiceStatus::default();
    let scm = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
    if scm.is_null() {
        return status;
    }

    let svc_name: Vec<u16> = OsStr::new(SERVICE_NAME)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let svc = unsafe { OpenServiceW(scm, svc_name.as_ptr(), SERVICE_QUERY_STATUS) };
    if !svc.is_null() {
        status.installed = true;
        let mut ss: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        if unsafe { QueryServiceStatus(svc, &mut ss) } != 0 {
            if ss.dwCurrentState == SERVICE_RUNNING {
                status.last_error =
                    Some("Windows 服务已运行，但 Named Pipe IPC 握手未就绪".to_string());
            } else if ss.dwCurrentState == SERVICE_START_PENDING {
                status.last_error = Some("MaxQTunService 正在启动中，请稍候...".to_string());
            } else {
                status.last_error = Some(format!(
                    "MaxQTunService 已安装但未运行（SCM state={}，exit_code={}）",
                    ss.dwCurrentState, ss.dwWin32ExitCode
                ));
            }
        }
        unsafe {
            CloseServiceHandle(svc);
        }
    }

    unsafe {
        CloseServiceHandle(scm);
    }
    status
}

#[cfg(not(windows))]
fn query_scm_fallback_status() -> TunServiceStatus {
    TunServiceStatus::default()
}

#[cfg(windows)]
fn send_request(req: &ServiceRequest) -> Result<ServiceResponse, RuntimeError> {
    use std::ffi::OsStr;
    use std::fs::OpenOptions;
    use std::io::{BufRead, BufReader, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::sync::{Mutex, OnceLock};
    use maxq_win_service::protocol::{NAMED_PIPE_PATH, PIPE_CLIENT_ACCESS_MASK};
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;
    use windows_sys::Win32::System::Pipes::WaitNamedPipeW;

    // Prevent concurrent frontend polls (`Promise.all`) from colliding on single-instance pipe
    static PIPE_IPC_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = PIPE_IPC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
    const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;

    let pipe_wide: Vec<u16> = OsStr::new(NAMED_PIPE_PATH)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut pipe = None;
    let mut last_err = None;
    for attempt in 0..6 {
        // CRITICAL: Use explicit `PIPE_CLIENT_ACCESS_MASK` (0x0010_0183) instead of
        // `.read(true).write(true)` so Windows does NOT expand `GENERIC_WRITE` into
        // `FILE_APPEND_DATA (0x0004)` == `FILE_CREATE_PIPE_INSTANCE` (which is stripped by PIPE_SDDL).
        match OpenOptions::new()
            .access_mode(PIPE_CLIENT_ACCESS_MASK)
            .security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION)
            .open(NAMED_PIPE_PATH)
        {
            Ok(f) => {
                pipe = Some(f);
                break;
            }
            Err(e) => {
                if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && attempt < 5 {
                    unsafe {
                        WaitNamedPipeW(pipe_wide.as_ptr(), 2_000);
                    }
                    continue;
                }
                last_err = Some(e);
                break;
            }
        }
    }

    let mut pipe = pipe.ok_or_else(|| {
        let e = last_err
            .map(|x| x.to_string())
            .unwrap_or_else(|| "pipe busy timeout".to_string());
        RuntimeError::SpawnFailed(format!(
            "MaxQ TUN 服务未运行或未安装（无法连接 Named Pipe）: {e}"
        ))
    })?;

    let payload = serde_json::to_string(req)?;
    writeln!(pipe, "{payload}")?;
    pipe.flush()?;

    let mut line = String::new();
    let mut reader = BufReader::new(pipe);
    reader.read_line(&mut line)?;
    let resp: ServiceResponse = serde_json::from_str(line.trim())?;
    Ok(resp)
}

#[cfg(not(windows))]
fn send_request(_req: &ServiceRequest) -> Result<ServiceResponse, RuntimeError> {
    Err(RuntimeError::SpawnFailed(
        "Windows TUN service is only available on Windows".into(),
    ))
}

#[cfg(any(windows, test))]
fn strip_verbatim_prefix(path: &Path) -> std::path::PathBuf {
    let raw = path.to_string_lossy();
    if let Some(after_prefix) = raw.strip_prefix(r"\\?\") {
        if after_prefix
            .get(..4)
            .is_some_and(|head| head.eq_ignore_ascii_case(r"UNC\"))
        {
            return std::path::PathBuf::from(format!(r"\\{}", &after_prefix[4..]));
        }
        return std::path::PathBuf::from(after_prefix);
    }
    path.to_path_buf()
}

#[cfg(windows)]
fn run_elevated_service_cmd(service_exe: &Path, arg: &str) -> Result<(), RuntimeError> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows_sys::Win32::UI::Shell::{
        ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    // Strip Tauri/Windows verbatim `\\?\` prefix (mapping `\\?\UNC\server\share` -> `\\server\share`)
    // so ShellExecuteExW resolves the binary cleanly.
    let cleaned_exe = strip_verbatim_prefix(service_exe);

    if !cleaned_exe.is_absolute() || !cleaned_exe.exists() {
        return Err(RuntimeError::BinaryNotFound(cleaned_exe));
    }

    let to_wide = |s: &OsStr| -> Vec<u16> { s.encode_wide().chain(std::iter::once(0)).collect() };
    let verb = to_wide(OsStr::new("runas"));
    let file = to_wide(cleaned_exe.as_os_str());
    let params = to_wide(OsStr::new(arg));

    let mut sei: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    sei.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    sei.hwnd = null_mut();
    sei.lpVerb = verb.as_ptr();
    sei.lpFile = file.as_ptr();
    sei.lpParameters = params.as_ptr();
    sei.lpDirectory = null();
    sei.nShow = SW_HIDE;

    let ok = unsafe { ShellExecuteExW(&mut sei) };
    if ok == 0 {
        let os_err = std::io::Error::last_os_error();
        return Err(RuntimeError::SpawnFailed(format!(
            "UAC 提权已取消或启动 maxq-service.exe 失败 ({}): {os_err}",
            cleaned_exe.display()
        )));
    }

    if !sei.hProcess.is_null() {
        let wait = unsafe { WaitForSingleObject(sei.hProcess, 30_000) };
        let mut exit_code: u32 = 1;
        let got_exit = unsafe { GetExitCodeProcess(sei.hProcess, &mut exit_code) } != 0;
        unsafe {
            CloseHandle(sei.hProcess);
        }

        if wait == WAIT_TIMEOUT {
            return Err(RuntimeError::SpawnFailed(format!(
                "等待 maxq-service.exe {arg} 完成超时（30秒）"
            )));
        }
        if got_exit && exit_code != 0 {
            let diag = read_diagnostic_status().unwrap_or_else(|| "无详细诊断输出".to_string());
            return Err(RuntimeError::SpawnFailed(format!(
                "maxq-service.exe {arg} 执行失败 (exit={exit_code}): {diag}"
            )));
        }
    }

    Ok(())
}

#[cfg(not(windows))]
fn run_elevated_service_cmd(_service_exe: &Path, _arg: &str) -> Result<(), RuntimeError> {
    Err(RuntimeError::SpawnFailed(
        "Windows TUN service installation is only available on Windows".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_verbatim_prefix_handles_unc_and_drive_paths() {
        assert_eq!(
            strip_verbatim_prefix(Path::new(r"\\?\UNC\fileserver\share\maxq-service.exe")),
            std::path::PathBuf::from(r"\\fileserver\share\maxq-service.exe")
        );
        assert_eq!(
            strip_verbatim_prefix(Path::new(r"\\?\unc\fileserver\share\maxq-service.exe")),
            std::path::PathBuf::from(r"\\fileserver\share\maxq-service.exe")
        );
        assert_eq!(
            strip_verbatim_prefix(Path::new(r"\\?\C:\Program Files\MaxQ\maxq-service.exe")),
            std::path::PathBuf::from(r"C:\Program Files\MaxQ\maxq-service.exe")
        );
        assert_eq!(
            strip_verbatim_prefix(Path::new(r"C:\Program Files\MaxQ\maxq-service.exe")),
            std::path::PathBuf::from(r"C:\Program Files\MaxQ\maxq-service.exe")
        );
    }
}
