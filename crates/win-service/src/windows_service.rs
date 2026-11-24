use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use maxq_cert_probe::detect_singbox_log_pin_mismatch;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    FlushFileBuffers, FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::IO::CancelIoEx;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::protocol::{
    ServiceRequest, ServiceResponse, TunServiceStatus, NAMED_PIPE_PATH, PIPE_SDDL,
    SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME, SERVICE_NAME, SERVICE_PROTOCOL_VERSION,
    SING_BOX_V14_4_WIN64_SHA256,
};
use crate::validator::{
    is_authorized_caller_image, validate_service_config, verify_binary_sha256, MAX_CONFIG_BYTES,
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const SDDL_REVISION_1: u32 = 1;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
const MAX_LOGS: usize = 400;

struct ServiceRuntimeState {
    child: Option<Child>,
    singbox_pid: Option<u32>,
    logs: Arc<Mutex<VecDeque<String>>>,
    last_mitm_alert: Arc<Mutex<Option<String>>>,
}

impl ServiceRuntimeState {
    fn new() -> Self {
        Self {
            child: None,
            singbox_pid: None,
            logs: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_LOGS))),
            last_mitm_alert: Arc::new(Mutex::new(None)),
        }
    }

    fn stop_singbox(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        self.singbox_pid = None;
    }

    fn is_singbox_running(&mut self) -> bool {
        if let Some(c) = self.child.as_mut() {
            match c.try_wait() {
                Ok(None) => return true,
                _ => {
                    self.child = None;
                    self.singbox_pid = None;
                }
            }
        }
        false
    }
}

pub fn install_and_start_service() -> Result<(), String> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CREATE_SERVICE | ServiceManagerAccess::CONNECT,
    )
    .map_err(|e| format!("open SCM failed (admin required): {e}"))?;

    let src_exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let src_dir = src_exe
        .parent()
        .ok_or_else(|| "cannot resolve service binary directory".to_string())?;
    let src_singbox = src_dir.join("sing-box.exe");

    // Stage service + sing-box binaries into SYSTEM/Admin-only directory
    let bin_dir = ensure_system_only_dir("service-bin")?;
    let staged_service = bin_dir.join("maxq-service.exe");
    let staged_singbox = bin_dir.join("sing-box.exe");

    // Stop existing service before replacing staged binaries
    if let Ok(existing) = manager.open_service(SERVICE_NAME, ServiceAccess::STOP) {
        let _ = existing.stop();
        std::thread::sleep(Duration::from_millis(500));
    }

    if src_exe != staged_service {
        std::fs::copy(&src_exe, &staged_service)
            .map_err(|e| format!("failed to stage maxq-service.exe: {e}"))?;
    }
    if src_singbox != staged_singbox {
        std::fs::copy(&src_singbox, &staged_singbox)
            .map_err(|e| format!("failed to stage sing-box.exe: {e}"))?;
    }

    // Verify SHA-256 AFTER copying into SYSTEM-only directory to defeat TOCTOU swap (C-4)
    if let Err(err) = verify_binary_sha256(&staged_singbox, SING_BOX_V14_4_WIN64_SHA256) {
        let _ = std::fs::remove_file(&staged_singbox);
        return Err(err);
    }

    // Record the legitimate desktop installation directory in a SYSTEM-only file
    let gui_root = if src_dir
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.eq_ignore_ascii_case("resources"))
    {
        src_dir.parent().unwrap_or(src_dir)
    } else {
        src_dir
    };
    let meta_path = bin_dir.join("authorized-gui-dir.txt");
    std::fs::write(&meta_path, gui_root.to_string_lossy().as_bytes())
        .map_err(|e| format!("failed to write authorized-gui-dir.txt: {e}"))?;

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: staged_service,
        launch_arguments: vec![OsString::from("run")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    let service = match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
    ) {
        Ok(existing) => {
            existing
                .change_config(&service_info)
                .map_err(|e| format!("update existing service failed: {e}"))?;
            existing
        }
        Err(_) => manager
            .create_service(
                &service_info,
                ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
            )
            .map_err(|e| format!("create service failed: {e}"))?,
    };

    let _ = service.set_description(SERVICE_DESCRIPTION);

    let status = service.query_status().map_err(|e| e.to_string())?;
    if status.current_state != ServiceState::Running {
        service
            .start::<&OsStr>(&[])
            .map_err(|e| format!("start service failed: {e}"))?;
    }
    Ok(())
}

pub fn stop_and_uninstall_service() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("open SCM failed (admin required): {e}"))?;
    let service = match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    ) {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };
    let _ = service.stop();
    std::thread::sleep(Duration::from_millis(600));
    service
        .delete()
        .map_err(|e| format!("delete service failed: {e}"))?;
    Ok(())
}

pub fn run_service_dispatcher() -> Result<(), String> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| format!("service dispatcher failed: {e}"))
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    let _ = run_service_loop();
}

fn run_service_loop() -> Result<(), String> {
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_for_handler = Arc::clone(&stop_flag);
    let runtime = Arc::new(Mutex::new(ServiceRuntimeState::new()));
    let runtime_for_handler = Arc::clone(&runtime);

    // Create ONE persistent Named Pipe with FILE_FLAG_FIRST_PIPE_INSTANCE (defeats pipe squatting! H-1)
    let pipe = create_hardened_named_pipe()?;
    let pipe_raw_addr = Arc::new(AtomicUsize::new(pipe as usize));
    let pipe_for_handler = Arc::clone(&pipe_raw_addr);

    let status_handle =
        service_control_handler::register(SERVICE_NAME, move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                stop_for_handler.store(true, Ordering::SeqCst);
                if let Ok(mut rt) = runtime_for_handler.lock() {
                    rt.stop_singbox();
                }
                // Cancel blocking ConnectNamedPipe cleanly without LocalSystem self-connecting (H-1)
                let raw = pipe_for_handler.load(Ordering::Acquire);
                if raw != 0 {
                    unsafe {
                        CancelIoEx(raw as HANDLE, null());
                    }
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })
        .map_err(|e| e.to_string())?;

    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .map_err(|e| e.to_string())?;

    let service_exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let runtime_dir = ensure_system_only_dir("service-runtime")?;

    while !stop_flag.load(Ordering::SeqCst) {
        let connected = unsafe { ConnectNamedPipe(pipe, null_mut()) } != 0
            || std::io::Error::last_os_error().raw_os_error() == Some(535); // ERROR_PIPE_CONNECTED

        if stop_flag.load(Ordering::SeqCst) {
            unsafe {
                DisconnectNamedPipe(pipe);
            }
            break;
        }

        if connected {
            handle_pipe_client(pipe, &service_exe, &runtime_dir, &runtime);
            unsafe {
                FlushFileBuffers(pipe);
                DisconnectNamedPipe(pipe);
            }
        } else {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pipe_raw_addr.store(0, Ordering::Release);
    unsafe {
        CloseHandle(pipe);
    }

    if let Ok(mut rt) = runtime.lock() {
        rt.stop_singbox();
    }

    let _ = status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    });

    Ok(())
}

fn to_wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn create_hardened_named_pipe() -> Result<HANDLE, String> {
    let pipe_name = to_wide_null(NAMED_PIPE_PATH);
    let sddl_wide = to_wide_null(PIPE_SDDL);
    let mut sd_ptr = null_mut();

    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_wide.as_ptr(),
            SDDL_REVISION_1,
            &mut sd_ptr,
            null_mut(),
        )
    };
    if ok == 0 || sd_ptr.is_null() {
        return Err("failed to build SDDL security descriptor for Named Pipe".into());
    }

    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd_ptr,
        bInheritHandle: 0,
    };

    let handle = unsafe {
        CreateNamedPipeW(
            pipe_name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            64 * 1024,
            64 * 1024,
            0,
            &mut sa,
        )
    };

    unsafe {
        LocalFree(sd_ptr);
    }

    if handle == INVALID_HANDLE_VALUE {
        return Err(format!(
            "CreateNamedPipeW failed (possible pipe squat): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(handle)
}

fn verify_pipe_caller_process(pipe: HANDLE, service_exe: &Path) -> Result<(), String> {
    let mut client_pid: u32 = 0;
    let ok = unsafe { GetNamedPipeClientProcessId(pipe, &mut client_pid) };
    if ok == 0 || client_pid == 0 {
        return Err("failed to query Named Pipe client PID".into());
    }

    let proc_handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, client_pid) };
    if proc_handle.is_null() {
        return Err("failed to open client process for image path verification".into());
    }

    let mut buf = vec![0u16; 4096];
    let mut len = buf.len() as u32;
    let q_ok = unsafe { QueryFullProcessImageNameW(proc_handle, 0, buf.as_mut_ptr(), &mut len) };
    unsafe {
        CloseHandle(proc_handle);
    }
    if q_ok == 0 || len == 0 {
        return Err("failed to query client process image path".into());
    }

    let caller_str = String::from_utf16_lossy(&buf[..len as usize]);
    let caller_path = PathBuf::from(&caller_str);

    if is_authorized_caller_image(service_exe, &caller_path) {
        return Ok(());
    }
    if let Some(svc_dir) = service_exe.parent() {
        if let Ok(gui_dir) = std::fs::read_to_string(svc_dir.join("authorized-gui-dir.txt")) {
            let synthetic_svc = PathBuf::from(gui_dir.trim()).join("maxq-service.exe");
            if is_authorized_caller_image(&synthetic_svc, &caller_path) {
                return Ok(());
            }
        }
    }
    Err(format!("unauthorized IPC caller rejected: {caller_str}"))
}

fn handle_pipe_client(
    pipe: HANDLE,
    service_exe: &Path,
    runtime_dir: &Path,
    runtime: &Arc<Mutex<ServiceRuntimeState>>,
) {
    let mut file =
        unsafe { std::mem::ManuallyDrop::new(std::fs::File::from_raw_handle(pipe as RawHandle)) };

    if let Err(msg) = verify_pipe_caller_process(pipe, service_exe) {
        let resp = ServiceResponse::Error { message: msg };
        let _ = writeln!(
            &mut **file,
            "{}",
            serde_json::to_string(&resp).unwrap_or_default()
        );
        return;
    }

    // Bounded read_line (MAX_CONFIG_BYTES + 64 KiB) to prevent OOM DoS (M-1)
    let mut line = String::new();
    {
        let limited = (&**file).take((MAX_CONFIG_BYTES + 65536) as u64);
        let mut reader = BufReader::new(limited);
        if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
            return;
        }
    }

    let req: ServiceRequest = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            let resp = ServiceResponse::Error {
                message: format!("invalid IPC request: {e}"),
            };
            let _ = writeln!(
                &mut **file,
                "{}",
                serde_json::to_string(&resp).unwrap_or_default()
            );
            return;
        }
    };

    let singbox_path = service_exe
        .parent()
        .map(|p| p.join("sing-box.exe"))
        .unwrap_or_else(|| PathBuf::from("sing-box.exe"));

    let resp = match req {
        ServiceRequest::Ping => {
            let verified = verify_binary_sha256(&singbox_path, SING_BOX_V14_4_WIN64_SHA256).is_ok();
            ServiceResponse::Pong {
                version: SERVICE_PROTOCOL_VERSION.to_string(),
                singbox_sha256_verified: verified,
            }
        }
        ServiceRequest::Status => {
            let mut rt = runtime.lock().unwrap_or_else(|e| e.into_inner());
            let tun_active = rt.is_singbox_running();
            let verified = verify_binary_sha256(&singbox_path, SING_BOX_V14_4_WIN64_SHA256).is_ok();
            let last_alert = rt
                .last_mitm_alert
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            ServiceResponse::Status(TunServiceStatus {
                installed: true,
                running: true,
                tun_active,
                singbox_pid: rt.singbox_pid,
                singbox_sha256_verified: verified,
                last_mitm_alert: last_alert,
                version: Some(SERVICE_PROTOCOL_VERSION.to_string()),
            })
        }
        ServiceRequest::StopTun => {
            let mut rt = runtime.lock().unwrap_or_else(|e| e.into_inner());
            rt.stop_singbox();
            ServiceResponse::Stopped
        }
        ServiceRequest::GetLogs => {
            let rt = runtime.lock().unwrap_or_else(|e| e.into_inner());
            let lines = rt
                .logs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .cloned()
                .collect();
            ServiceResponse::Logs { lines }
        }
        ServiceRequest::StartTun { config_json } => {
            match start_hardened_singbox_tun(&singbox_path, runtime_dir, &config_json, runtime) {
                Ok(pid) => ServiceResponse::Started { pid },
                Err(message) => ServiceResponse::Error { message },
            }
        }
    };

    if let Ok(encoded) = serde_json::to_string(&resp) {
        let _ = writeln!(&mut **file, "{encoded}");
    }
}

fn start_hardened_singbox_tun(
    singbox_path: &Path,
    runtime_dir: &Path,
    config_json: &str,
    runtime: &Arc<Mutex<ServiceRuntimeState>>,
) -> Result<u32, String> {
    let validated = validate_service_config(config_json)?;
    verify_binary_sha256(singbox_path, SING_BOX_V14_4_WIN64_SHA256)?;

    let (logs_arc, alert_arc) = {
        let mut rt = runtime.lock().unwrap_or_else(|e| e.into_inner());
        rt.stop_singbox();
        if let Ok(mut alert) = rt.last_mitm_alert.lock() {
            *alert = None;
        }
        (Arc::clone(&rt.logs), Arc::clone(&rt.last_mitm_alert))
    };

    let cfg_path = runtime_dir.join("active-tun.json");
    let pretty = serde_json::to_string_pretty(&validated).map_err(|e| e.to_string())?;
    std::fs::write(&cfg_path, pretty.as_bytes())
        .map_err(|e| format!("failed to write active-tun.json: {e}"))?;

    let mut child = Command::new(singbox_path)
        .args(["run", "-c"])
        .arg(&cfg_path)
        .current_dir(runtime_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("failed to spawn sing-box.exe: {e}"))?;

    let pid = child.id();

    if let Some(stdout) = child.stdout.take() {
        spawn_service_log_thread(stdout, Arc::clone(&logs_arc), Arc::clone(&alert_arc));
    }
    if let Some(stderr) = child.stderr.take() {
        spawn_service_log_thread(stderr, Arc::clone(&logs_arc), Arc::clone(&alert_arc));
    }

    let mut rt = runtime.lock().unwrap_or_else(|e| e.into_inner());
    rt.child = Some(child);
    rt.singbox_pid = Some(pid);
    Ok(pid)
}

fn spawn_service_log_thread<R: std::io::Read + Send + 'static>(
    reader: R,
    logs: Arc<Mutex<VecDeque<String>>>,
    mitm_alert: Arc<Mutex<Option<String>>>,
) {
    std::thread::spawn(move || {
        let buf = BufReader::new(reader);
        for line in buf.lines().map_while(Result::ok) {
            if let Some(spki) = detect_singbox_log_pin_mismatch(&line) {
                if let Ok(mut alert) = mitm_alert.lock() {
                    *alert = Some(spki);
                }
            }
            if let Ok(mut ring) = logs.lock() {
                if ring.len() >= MAX_LOGS {
                    ring.pop_front();
                }
                ring.push_back(line);
            }
        }
    });
}

/// Ensures `C:\ProgramData\MaxQ\<subdir>` exists without symlinks/junctions and is ACL-locked to
/// SYSTEM + Administrators only (using absolute System32\icacls.exe and locale-independent SIDs).
fn ensure_system_only_dir(subdir: &str) -> Result<PathBuf, String> {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    let root = PathBuf::from(base).join("MaxQ");
    let dir = root.join(subdir);

    // Reject NTFS junctions/symlinks (FILE_ATTRIBUTE_REPARSE_POINT) before writing as SYSTEM (C-3)
    for p in [&root, &dir] {
        if let Ok(meta) = std::fs::symlink_metadata(p) {
            if meta.file_type().is_symlink()
                || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
            {
                return Err(format!("refusing symlink/junction at '{}'", p.display()));
            }
        }
    }

    std::fs::create_dir_all(&dir).map_err(|e| format!("create {subdir} dir failed: {e}"))?;

    let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let icacls_exe = PathBuf::from(sys_root).join("System32").join("icacls.exe");

    for target in [&root, &dir] {
        let out = Command::new(&icacls_exe)
            .arg(target)
            .args([
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(OI)(CI)F",
                "/grant:r",
                "*S-1-5-32-544:(OI)(CI)F",
                "/T",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("failed to execute icacls.exe: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "icacls.exe failed on '{}' (status={})",
                target.display(),
                out.status
            ));
        }
    }

    Ok(dir)
}
