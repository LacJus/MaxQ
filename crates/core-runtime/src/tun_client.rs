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
            _ => TunServiceStatus::default(),
        }
    }

    pub fn start_tun(config_json: String) -> Result<u32, RuntimeError> {
        match send_request(&ServiceRequest::StartTun { config_json })? {
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

    /// Invokes `maxq-service.exe install` via Windows UAC (`runas`) to install and start the hardened service.
    pub fn install_elevated(service_exe: &Path) -> Result<(), RuntimeError> {
        run_elevated_service_cmd(service_exe, "install")
    }

    /// Invokes `maxq-service.exe uninstall` via Windows UAC (`runas`) to stop and remove the service.
    pub fn uninstall_elevated(service_exe: &Path) -> Result<(), RuntimeError> {
        run_elevated_service_cmd(service_exe, "uninstall")
    }
}

#[cfg(windows)]
fn send_request(req: &ServiceRequest) -> Result<ServiceResponse, RuntimeError> {
    use std::fs::OpenOptions;
    use std::io::{BufRead, BufReader, Write};
    use maxq_win_service::protocol::NAMED_PIPE_PATH;

    let mut pipe = OpenOptions::new()
        .read(true)
        .write(true)
        .open(NAMED_PIPE_PATH)
        .map_err(|e| {
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

#[cfg(windows)]
fn run_elevated_service_cmd(service_exe: &Path, arg: &str) -> Result<(), RuntimeError> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    if !service_exe.is_absolute() || !service_exe.exists() {
        return Err(RuntimeError::BinaryNotFound(service_exe.to_path_buf()));
    }

    let to_wide = |s: &OsStr| -> Vec<u16> { s.encode_wide().chain(std::iter::once(0)).collect() };
    let verb = to_wide(OsStr::new("runas"));
    let file = to_wide(service_exe.as_os_str());
    let params = to_wide(OsStr::new(arg));

    let res = unsafe {
        ShellExecuteW(
            null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            params.as_ptr(),
            null(),
            SW_HIDE,
        )
    };
    if (res as isize) <= 32 {
        return Err(RuntimeError::SpawnFailed(format!(
            "UAC elevation canceled or failed (code={})",
            res as isize
        )));
    }
    Ok(())
}

#[cfg(not(windows))]
fn run_elevated_service_cmd(_service_exe: &Path, _arg: &str) -> Result<(), RuntimeError> {
    Err(RuntimeError::SpawnFailed(
        "Windows TUN service installation is only available on Windows".into(),
    ))
}
