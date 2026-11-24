use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::io::{BufRead, BufReader};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};
use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
    WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    FlushFileBuffers, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
    PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, OpenProcess, QueryFullProcessImageNameW, ResetEvent, SetEvent,
    WaitForMultipleObjects, WaitForSingleObject, INFINITE, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::protocol::{
    ServiceRequest, ServiceResponse, TunServiceStatus, DIAGNOSTIC_STATUS_FILE,
    DIAGNOSTIC_STATUS_SUBDIR, NAMED_PIPE_PATH, PIPE_SDDL, SERVICE_DESCRIPTION,
    SERVICE_DISPLAY_NAME, SERVICE_NAME, SERVICE_PROTOCOL_VERSION, SING_BOX_V14_4_WIN64_SHA256,
};
use crate::validator::{
    is_authorized_caller_image, validate_service_config, verify_binary_sha256, MAX_CONFIG_BYTES,
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const SDDL_REVISION_1: u32 = 1;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
const MAX_LOGS: usize = 400;
const PIPE_IO_TIMEOUT_MS: u32 = 10_000;

struct ServiceChildJobGuard(HANDLE);

unsafe impl Send for ServiceChildJobGuard {}
unsafe impl Sync for ServiceChildJobGuard {}

impl ServiceChildJobGuard {
    fn assign_kill_on_close(proc_handle: HANDLE) -> Option<Self> {
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
                &info as *const _ as *const std::ffi::c_void,
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

impl Drop for ServiceChildJobGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
            self.0 = null_mut();
        }
    }
}

struct ServiceRuntimeState {
    child: Option<Child>,
    job_guard: Option<ServiceChildJobGuard>,
    active_config_path: Option<PathBuf>,
    singbox_pid: Option<u32>,
    logs: Arc<Mutex<VecDeque<String>>>,
    last_mitm_alert: Arc<Mutex<Option<String>>>,
}

impl ServiceRuntimeState {
    fn new() -> Self {
        Self {
            child: None,
            job_guard: None,
            active_config_path: None,
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
        self.job_guard.take();
        if let Some(cfg) = self.active_config_path.take() {
            let _ = std::fs::remove_file(cfg);
        }
        self.singbox_pid = None;
    }

    fn is_singbox_running(&mut self) -> bool {
        if let Some(c) = self.child.as_mut() {
            match c.try_wait() {
                Ok(None) => return true,
                _ => {
                    self.child = None;
                    self.job_guard.take();
                    if let Some(cfg) = self.active_config_path.take() {
                        let _ = std::fs::remove_file(cfg);
                    }
                    self.singbox_pid = None;
                }
            }
        }
        false
    }
}

pub fn install_and_start_service() -> Result<(), String> {
    let res = install_and_start_service_inner();
    match &res {
        Ok(()) => write_diagnostic_status("OK: MaxQTunService installed and running"),
        Err(err) => write_diagnostic_status(&format!("INSTALL_ERROR: {err}")),
    }
    res
}

fn install_and_start_service_inner() -> Result<(), String> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CREATE_SERVICE | ServiceManagerAccess::CONNECT,
    )
    .map_err(|e| format!("打开 Windows 服务管理器失败（需要管理员权限）: {e}"))?;

    let src_exe = strip_verbatim_prefix(
        std::env::current_exe().map_err(|e| format!("无法获取当前服务路径: {e}"))?,
    );
    let src_dir = src_exe
        .parent()
        .ok_or_else(|| "cannot resolve service binary directory".to_string())?;
    let src_singbox = src_dir.join("sing-box.exe");
    if !src_singbox.exists() {
        return Err(format!(
            "未在同目录找到 sing-box.exe: {}",
            src_singbox.display()
        ));
    }

    // Stage service + sing-box binaries into SYSTEM/Admin-only directory
    let bin_dir = ensure_system_only_dir("service-bin")?;
    let staged_service = bin_dir.join("maxq-service.exe");
    let staged_singbox = bin_dir.join("sing-box.exe");

    // Stop existing service and wait until fully Stopped so staged binaries are unlocked
    if let Ok(existing) =
        manager.open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)
    {
        let _ = existing.stop();
        let deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < deadline {
            if let Ok(st) = existing.query_status() {
                if st.current_state == ServiceState::Stopped {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    if !paths_equal_ci(&src_exe, &staged_service) {
        copy_with_retry(&src_exe, &staged_service, "maxq-service.exe")?;
    }
    if !paths_equal_ci(&src_singbox, &staged_singbox) {
        copy_with_retry(&src_singbox, &staged_singbox, "sing-box.exe")?;
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
        .map_err(|e| format!("写入 authorized-gui-dir.txt 失败: {e}"))?;

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
                .map_err(|e| format!("更新现有服务配置失败: {e}"))?;
            existing
        }
        Err(_) => manager
            .create_service(
                &service_info,
                ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
            )
            .map_err(|e| format!("注册 Windows 服务失败: {e}"))?,
    };

    let _ = service.set_description(SERVICE_DESCRIPTION);

    let status = service.query_status().map_err(|e| e.to_string())?;
    if status.current_state != ServiceState::Running {
        service
            .start::<&OsStr>(&[])
            .map_err(|e| format!("启动 MaxQTunService 失败: {e}"))?;

        // Wait up to 10s for SCM to confirm Running state
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let st = service.query_status().map_err(|e| e.to_string())?;
            match st.current_state {
                ServiceState::Running => break,
                ServiceState::Stopped => {
                    return Err(format!(
                        "MaxQTunService 启动后立即退出（exit_code={:?}）",
                        st.exit_code
                    ));
                }
                _ => {
                    if Instant::now() >= deadline {
                        return Err(format!(
                            "等待 MaxQTunService 启动超时（当前状态={:?}）",
                            st.current_state
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
    }
    Ok(())
}

pub fn stop_and_uninstall_service() -> Result<(), String> {
    let res = stop_and_uninstall_service_inner();
    match &res {
        Ok(()) => write_diagnostic_status("OK: MaxQTunService uninstalled"),
        Err(err) => write_diagnostic_status(&format!("UNINSTALL_ERROR: {err}")),
    }
    res
}

fn stop_and_uninstall_service_inner() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("打开服务管理器失败（需要管理员权限）: {e}"))?;
    let service = match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    ) {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };
    let _ = service.stop();
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if let Ok(st) = service.query_status() {
            if st.current_state == ServiceState::Stopped {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    service
        .delete()
        .map_err(|e| format!("删除 MaxQTunService 失败: {e}"))?;
    Ok(())
}

pub fn run_service_dispatcher() -> Result<(), String> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| format!("service dispatcher failed: {e}"))
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    if let Err(err) = run_service_loop() {
        write_diagnostic_status(&format!("SERVICE_ERROR: {err}"));
    }
}

fn run_service_loop() -> Result<(), String> {
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_for_handler = Arc::clone(&stop_flag);
    let runtime = Arc::new(Mutex::new(ServiceRuntimeState::new()));
    let runtime_for_handler = Arc::clone(&runtime);

    // Manual-reset stop event signaled by SCM Stop/Shutdown for instant race-free pipe wake
    let stop_event = unsafe { CreateEventW(null(), 1, 0, null()) };
    if stop_event.is_null() {
        return Err(format!(
            "CreateEventW(stop_event) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let stop_event_addr = Arc::new(AtomicUsize::new(stop_event as usize));
    let stop_event_for_handler = Arc::clone(&stop_event_addr);

    // Register SCM control handler FIRST so startup failures cleanly report ServiceState::Stopped
    let status_handle =
        service_control_handler::register(SERVICE_NAME, move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                stop_for_handler.store(true, Ordering::SeqCst);
                if let Ok(mut rt) = runtime_for_handler.lock() {
                    rt.stop_singbox();
                }
                let ev = stop_event_for_handler.load(Ordering::Acquire);
                if ev != 0 {
                    unsafe {
                        SetEvent(ev as HANDLE);
                    }
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })
        .map_err(|e| format!("register SCM handler failed: {e}"))?;

    let init_result = (|| -> Result<(HANDLE, HANDLE, PathBuf, PathBuf), String> {
        let pipe = create_hardened_named_pipe()?;
        let connect_event = unsafe { CreateEventW(null(), 1, 0, null()) };
        if connect_event.is_null() {
            unsafe {
                CloseHandle(pipe);
            }
            return Err(format!(
                "CreateEventW(connect_event) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let service_exe = strip_verbatim_prefix(
            std::env::current_exe().map_err(|e| format!("current_exe failed: {e}"))?,
        );
        let runtime_dir = ensure_system_only_dir("service-runtime")?;
        Ok((pipe, connect_event, service_exe, runtime_dir))
    })();

    let (pipe, connect_event, service_exe, runtime_dir) = match init_result {
        Ok(v) => v,
        Err(err) => {
            stop_event_addr.store(0, Ordering::Release);
            unsafe {
                CloseHandle(stop_event);
            }
            let _ = status_handle.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(1),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            });
            return Err(err);
        }
    };

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
        .map_err(|e| format!("set ServiceState::Running failed: {e}"))?;

    write_diagnostic_status("OK: MaxQTunService running and listening on Named Pipe");

    while !stop_flag.load(Ordering::SeqCst) {
        unsafe {
            ResetEvent(connect_event);
        }
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = connect_event;

        let ok = unsafe { ConnectNamedPipe(pipe, &mut ov) };
        let connected = if ok != 0 {
            true
        } else {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
            if err == ERROR_PIPE_CONNECTED {
                true
            } else if err == ERROR_IO_PENDING {
                let handles = [connect_event, stop_event];
                let wait = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) };
                if wait == WAIT_OBJECT_0 {
                    let mut transferred = 0u32;
                    unsafe { GetOverlappedResult(pipe, &ov, &mut transferred, 0) != 0 }
                } else {
                    unsafe {
                        CancelIoEx(pipe, &ov);
                    }
                    false
                }
            } else {
                std::thread::sleep(Duration::from_millis(50));
                false
            }
        };

        if stop_flag.load(Ordering::SeqCst) {
            if connected {
                unsafe {
                    DisconnectNamedPipe(pipe);
                }
            }
            break;
        }

        if connected {
            handle_pipe_client(pipe, &service_exe, &runtime_dir, &runtime);
            unsafe {
                FlushFileBuffers(pipe);
                DisconnectNamedPipe(pipe);
            }
        }
    }

    stop_event_addr.store(0, Ordering::Release);
    unsafe {
        CloseHandle(connect_event);
        CloseHandle(pipe);
        CloseHandle(stop_event);
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

fn strip_verbatim_prefix(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        path
    }
}

fn paths_equal_ci(a: &Path, b: &Path) -> bool {
    a.to_string_lossy()
        .trim_start_matches(r"\\?\")
        .eq_ignore_ascii_case(b.to_string_lossy().trim_start_matches(r"\\?\"))
}

fn copy_with_retry(src: &Path, dst: &Path, label: &str) -> Result<(), String> {
    let mut last_err = String::new();
    for attempt in 0..5 {
        match std::fs::copy(src, dst) {
            Ok(_) => return Ok(()),
            Err(e) => {
                last_err = format!("复制 {label} 到 {} 失败: {e}", dst.display());
                if attempt < 4 {
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
        }
    }
    Err(last_err)
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
        return Err(format!(
            "failed to build SDDL security descriptor for Named Pipe: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd_ptr,
        bInheritHandle: 0,
    };

    let handle = unsafe {
        CreateNamedPipeW(
            pipe_name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
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

fn read_pipe_line_overlapped(pipe: HANDLE, max_bytes: usize) -> Result<String, String> {
    let io_event = unsafe { CreateEventW(null(), 1, 0, null()) };
    if io_event.is_null() {
        return Err("CreateEventW(read) failed".into());
    }
    let mut acc = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];

    let res = loop {
        unsafe {
            ResetEvent(io_event);
        }
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = io_event;
        let mut bytes_read = 0u32;

        let ok = unsafe {
            ReadFile(
                pipe,
                chunk.as_mut_ptr(),
                chunk.len() as u32,
                &mut bytes_read,
                &mut ov,
            )
        };
        if ok == 0 {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
            if err == ERROR_IO_PENDING {
                let wait = unsafe { WaitForSingleObject(io_event, PIPE_IO_TIMEOUT_MS) };
                if wait != WAIT_OBJECT_0 {
                    unsafe {
                        CancelIoEx(pipe, &ov);
                    }
                    break Err("IPC read timeout".into());
                }
                if unsafe { GetOverlappedResult(pipe, &ov, &mut bytes_read, 0) } == 0 {
                    break Err("IPC read failed".into());
                }
            } else {
                break Err(format!("IPC ReadFile error {err}"));
            }
        }

        if bytes_read == 0 {
            break Ok(());
        }
        let slice = &chunk[..bytes_read as usize];
        if let Some(pos) = slice.iter().position(|&b| b == b'\n') {
            if acc.len() + pos > max_bytes {
                break Err("IPC request exceeded maximum allowed size".into());
            }
            acc.extend_from_slice(&slice[..pos]);
            break Ok(());
        }
        if acc.len() + slice.len() > max_bytes {
            break Err("IPC request exceeded maximum allowed size".into());
        }
        acc.extend_from_slice(slice);
    };

    unsafe {
        CloseHandle(io_event);
    }
    res?;
    String::from_utf8(acc).map_err(|_| "IPC request is not valid UTF-8".into())
}

fn write_pipe_line_overlapped(pipe: HANDLE, line: &str) {
    let io_event = unsafe { CreateEventW(null(), 1, 0, null()) };
    if io_event.is_null() {
        return;
    }
    let mut payload = Vec::with_capacity(line.len() + 1);
    payload.extend_from_slice(line.as_bytes());
    payload.push(b'\n');

    let mut offset = 0usize;
    while offset < payload.len() {
        unsafe {
            ResetEvent(io_event);
        }
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = io_event;
        let mut written = 0u32;
        let rem = &payload[offset..];
        let to_write = rem.len().min(64 * 1024) as u32;

        let ok = unsafe { WriteFile(pipe, rem.as_ptr(), to_write, &mut written, &mut ov) };
        if ok == 0 {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
            if err == ERROR_IO_PENDING {
                let wait = unsafe { WaitForSingleObject(io_event, PIPE_IO_TIMEOUT_MS) };
                if wait != WAIT_OBJECT_0 {
                    unsafe {
                        CancelIoEx(pipe, &ov);
                    }
                    break;
                }
                if unsafe { GetOverlappedResult(pipe, &ov, &mut written, 0) } == 0 {
                    break;
                }
            } else {
                break;
            }
        }
        if written == 0 {
            break;
        }
        offset += written as usize;
    }

    unsafe {
        CloseHandle(io_event);
    }
}

fn send_pipe_response(pipe: HANDLE, resp: &ServiceResponse) {
    if let Ok(encoded) = serde_json::to_string(resp) {
        write_pipe_line_overlapped(pipe, &encoded);
    }
}

fn handle_pipe_client(
    pipe: HANDLE,
    service_exe: &Path,
    runtime_dir: &Path,
    runtime: &Arc<Mutex<ServiceRuntimeState>>,
) {
    if let Err(msg) = verify_pipe_caller_process(pipe, service_exe) {
        send_pipe_response(pipe, &ServiceResponse::Error { message: msg });
        return;
    }

    // Bounded overlapped read with 10s timeout (blocks OOM & hung-client DoS)
    let line = match read_pipe_line_overlapped(pipe, MAX_CONFIG_BYTES + 65536) {
        Ok(l) if !l.trim().is_empty() => l,
        _ => return,
    };

    let req: ServiceRequest = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            send_pipe_response(
                pipe,
                &ServiceResponse::Error {
                    message: format!("invalid IPC request: {e}"),
                },
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
                last_error: None,
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

    send_pipe_response(pipe, &resp);
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
        if let Ok(mut logs) = rt.logs.lock() {
            logs.clear();
        }
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
    let job_guard = ServiceChildJobGuard::assign_kill_on_close(child.as_raw_handle() as HANDLE);

    if let Some(stdout) = child.stdout.take() {
        spawn_service_log_thread(stdout, Arc::clone(&logs_arc), Arc::clone(&alert_arc));
    }
    if let Some(stderr) = child.stderr.take() {
        spawn_service_log_thread(stderr, Arc::clone(&logs_arc), Arc::clone(&alert_arc));
    }

    // Brief check to catch immediate sing-box startup / wintun failures and return stderr clearly
    std::thread::sleep(Duration::from_millis(350));
    if let Ok(Some(exit_status)) = child.try_wait() {
        drop(job_guard);
        let _ = std::fs::remove_file(&cfg_path);
        let tail = logs_arc
            .lock()
            .map(|r| r.iter().rev().take(6).rev().cloned().collect::<Vec<_>>().join(" | "))
            .unwrap_or_default();
        return Err(format!(
            "sing-box TUN 内核启动后立即退出 ({exit_status}): {tail}"
        ));
    }

    let mut rt = runtime.lock().unwrap_or_else(|e| e.into_inner());
    rt.child = Some(child);
    rt.job_guard = job_guard;
    rt.active_config_path = Some(cfg_path);
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
            let redacted = crate::protocol::redact_log_line(&line);
            if let Some(spki) = crate::protocol::detect_singbox_log_pin_mismatch(&line) {
                if let Ok(mut alert) = mitm_alert.lock() {
                    *alert = Some(spki);
                }
            }
            if let Ok(mut ring) = logs.lock() {
                if ring.len() >= MAX_LOGS {
                    ring.pop_front();
                }
                ring.push_back(redacted);
            }
        }
    });
}

fn reject_if_reparse_point(path: &Path) -> Result<(), String> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink()
            || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
        {
            return Err(format!("refusing symlink/junction at '{}'", path.display()));
        }
    }
    Ok(())
}

fn icacls_exe_path() -> PathBuf {
    let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    PathBuf::from(sys_root).join("System32").join("icacls.exe")
}

fn program_data_maxq_root() -> PathBuf {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    PathBuf::from(base).join("MaxQ")
}

/// Writes non-secret install/service diagnostics to `%ProgramData%\MaxQ\diagnostics\last-status.txt`
/// (writable ONLY by SYSTEM + Administrators, read-only for Users so the non-elevated GUI can
/// display exact error reasons instead of failing silently).
fn write_diagnostic_status(message: &str) {
    let root = program_data_maxq_root();
    let diag_dir = root.join(DIAGNOSTIC_STATUS_SUBDIR);
    let diag_file = diag_dir.join(DIAGNOSTIC_STATUS_FILE);

    if reject_if_reparse_point(&root).is_err()
        || reject_if_reparse_point(&diag_dir).is_err()
        || reject_if_reparse_point(&diag_file).is_err()
    {
        return;
    }
    if std::fs::create_dir_all(&diag_dir).is_err() {
        return;
    }

    let icacls = icacls_exe_path();
    let _ = Command::new(&icacls)
        .arg(&diag_dir)
        .args([
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "/grant:r",
            "*S-1-5-32-544:(OI)(CI)F",
            "/grant:r",
            "*S-1-5-32-545:(OI)(CI)R",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    if reject_if_reparse_point(&diag_file).is_ok() {
        let _ = std::fs::write(&diag_file, message.as_bytes());
    }
}

/// Ensures `C:\ProgramData\MaxQ\<subdir>` exists without symlinks/junctions and is ACL-locked to
/// SYSTEM + Administrators only (using absolute System32\icacls.exe and locale-independent SIDs).
fn ensure_system_only_dir(subdir: &str) -> Result<PathBuf, String> {
    let root = program_data_maxq_root();
    let dir = root.join(subdir);

    // Reject NTFS junctions/symlinks (FILE_ATTRIBUTE_REPARSE_POINT) before writing as SYSTEM (C-3)
    reject_if_reparse_point(&root)?;
    reject_if_reparse_point(&dir)?;

    std::fs::create_dir_all(&dir).map_err(|e| format!("创建 {subdir} 目录失败: {e}"))?;

    let icacls_exe = icacls_exe_path();
    for target in [&root, &dir] {
        let out = Command::new(&icacls_exe)
            .arg(target)
            .args([
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(OI)(CI)F",
                "/grant:r",
                "*S-1-5-32-544:(OI)(CI)F",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("执行 icacls.exe 失败: {e}"))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            return Err(format!(
                "icacls.exe 锁定 '{}' 失败 (status={}): {} {}",
                target.display(),
                out.status,
                stdout.trim(),
                stderr.trim()
            ));
        }
    }

    // Also strip any pre-existing explicit permissive ACEs on existing entries inside `dir`
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            reject_if_reparse_point(&p)?;
            let _ = Command::new(&icacls_exe)
                .arg(&p)
                .args(["/reset"])
                .creation_flags(CREATE_NO_WINDOW)
                .output();
        }
    }

    Ok(dir)
}
