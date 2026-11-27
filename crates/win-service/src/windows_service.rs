use std::collections::VecDeque;
use std::ffi::{c_void, OsStr, OsString};
use std::io::{BufRead, BufReader};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
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
    CloseHandle, LocalFree, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, ERROR_SUCCESS, HANDLE,
    INVALID_HANDLE_VALUE, LUID, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
    SetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, GetSecurityDescriptorDacl, LookupPrivilegeValueW, ACL,
    DACL_SECURITY_INFORMATION, LUID_AND_ATTRIBUTES, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSID, SECURITY_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFileInformationByHandle, ReadFile, WriteFile, BY_HANDLE_FILE_INFORMATION,
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_OVERLAPPED,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
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
    CreateEventW, GetCurrentProcess, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
    ResetEvent, SetEvent, WaitForMultipleObjects, WaitForSingleObject, INFINITE,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::protocol::{
    ServiceRequest, ServiceResponse, TunServiceStatus, DIAGNOSTIC_STATUS_FILE,
    DIAGNOSTIC_STATUS_SUBDIR, NAMED_PIPE_PATH, PIPE_CLIENT_ACCESS_MASK, PIPE_SDDL,
    SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME, SERVICE_NAME, SERVICE_PROTOCOL_VERSION,
    SING_BOX_V14_4_WIN64_SHA256,
};
use crate::validator::{
    compute_file_sha256, is_authorized_caller_image, validate_service_config, verify_binary_sha256,
    CachedBinaryVerifier, MAX_CONFIG_BYTES,
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const SDDL_REVISION_1: u32 = 1;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
const MAX_LOGS: usize = 400;
const PIPE_IO_TIMEOUT_MS: u32 = 10_000;

/// LocalSystem well-known SID string used as authoritative NTFS owner on `%ProgramData%\MaxQ`.
const LOCAL_SYSTEM_SID: &str = "S-1-5-18";
/// Protected DACL granting Full Control strictly to LocalSystem (`SY`) and Administrators (`BA`).
const SYSTEM_ADMIN_DIR_SDDL: &str = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
const SYSTEM_ADMIN_FILE_SDDL: &str = "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)";
/// Protected DACL for `%ProgramData%\MaxQ\diagnostics` (SYSTEM/Admin full, Users read-only).
const DIAGNOSTICS_DIR_SDDL: &str = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)";
const DIAGNOSTICS_FILE_SDDL: &str = "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)";

/// RAII wrapper around a Win32 kernel `HANDLE` ensuring all error paths close handles cleanly.
struct OwnedHandle(HANDLE);

unsafe impl Send for OwnedHandle {}

impl OwnedHandle {
    fn new(handle: HANDLE) -> Option<Self> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(Self(handle))
        }
    }

    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
            self.0 = null_mut();
        }
    }
}

/// RAII wrapper around a `LocalAlloc`-allocated Win32 pointer freed via `LocalFree`.
struct LocalAllocGuard(*mut c_void);

impl Drop for LocalAllocGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
            self.0 = null_mut();
        }
    }
}

/// Clears and closes the shared `stop_event` under the Mutex when `run_service_loop` exits on
/// any path, guaranteeing the SCM callback can never call `SetEvent` on a closed handle.
struct StopEventSlotGuard(Arc<Mutex<Option<OwnedHandle>>>);

impl Drop for StopEventSlotGuard {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.0.lock() {
            slot.take();
        }
    }
}

struct ServiceChildJobGuard {
    _job: OwnedHandle,
}

impl ServiceChildJobGuard {
    fn assign_kill_on_close(proc_handle: HANDLE) -> Option<Self> {
        let job = OwnedHandle::new(unsafe { CreateJobObjectW(null(), null()) })?;
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let ok_set = unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok_set == 0 {
            return None;
        }
        let ok_assign = unsafe { AssignProcessToJobObject(job.raw(), proc_handle) };
        if ok_assign == 0 {
            return None;
        }
        Some(Self { _job: job })
    }
}

struct ServiceRuntimeState {
    child: Option<Child>,
    job_guard: Option<ServiceChildJobGuard>,
    active_config_path: Option<PathBuf>,
    singbox_pid: Option<u32>,
    active_profile_id: Option<String>,
    active_node_id: Option<String>,
    active_node_name: Option<String>,
    binary_verify_cache: CachedBinaryVerifier,
    gui_verify_cache: CachedBinaryVerifier,
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
            active_profile_id: None,
            active_node_id: None,
            active_node_name: None,
            binary_verify_cache: CachedBinaryVerifier::default(),
            gui_verify_cache: CachedBinaryVerifier::default(),
            logs: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_LOGS))),
            last_mitm_alert: Arc::new(Mutex::new(None)),
        }
    }

    fn clear_active_metadata(&mut self) {
        self.singbox_pid = None;
        self.active_profile_id = None;
        self.active_node_id = None;
        self.active_node_name = None;
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
        self.clear_active_metadata();
    }

    fn is_singbox_running(&mut self) -> bool {
        if let Some(c) = self.child.as_mut() {
            match c.try_wait() {
                Ok(None) => return true,
                Ok(Some(exit_status)) => {
                    if let Ok(mut ring) = self.logs.lock() {
                        if ring.len() >= MAX_LOGS {
                            ring.pop_front();
                        }
                        ring.push_back(format!(
                            "[maxq-service] sing-box TUN 进程已退出 ({exit_status})"
                        ));
                    }
                    self.child = None;
                    self.job_guard.take();
                    if let Some(cfg) = self.active_config_path.take() {
                        let _ = std::fs::remove_file(cfg);
                    }
                    self.clear_active_metadata();
                }
                Err(_) => {
                    self.child = None;
                    self.job_guard.take();
                    if let Some(cfg) = self.active_config_path.take() {
                        let _ = std::fs::remove_file(cfg);
                    }
                    self.clear_active_metadata();
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

/// Non-blocking poke on `NAMED_PIPE_PATH` to unblock any legacy v1.0.0 synchronous
/// `ConnectNamedPipe` during in-place service upgrades.
fn wake_legacy_named_pipe() {
    let pipe_wide = to_wide_null(NAMED_PIPE_PATH);
    let _handle = OwnedHandle::new(unsafe {
        CreateFileW(
            pipe_wide.as_ptr(),
            PIPE_CLIENT_ACCESS_MASK,
            0,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            null_mut(),
        )
    });
}

fn install_and_start_service_inner() -> Result<(), String> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CREATE_SERVICE | ServiceManagerAccess::CONNECT,
    )
    .map_err(|e| format!("打开 Windows 服务管理器失败（需要管理员权限）: {e}"))?;

    let src_exe = canonicalize_win_path(
        &std::env::current_exe().map_err(|e| format!("无法获取当前服务路径: {e}"))?,
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
        let stop_started = Instant::now();
        let deadline = stop_started + Duration::from_secs(8);
        let mut woke_legacy = false;
        while Instant::now() < deadline {
            if let Ok(st) = existing.query_status() {
                if st.current_state == ServiceState::Stopped {
                    break;
                }
            }
            if !woke_legacy && stop_started.elapsed() >= Duration::from_secs(2) {
                woke_legacy = true;
                wake_legacy_named_pipe();
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    if !paths_equal_ci(&src_exe, &staged_service) {
        reject_if_reparse_or_hardlink(&staged_service)?;
        copy_with_retry(&src_exe, &staged_service, "maxq-service.exe")?;
        lock_path_owner_and_dacl(&staged_service, SYSTEM_ADMIN_FILE_SDDL)?;
    }
    if !paths_equal_ci(&src_singbox, &staged_singbox) {
        reject_if_reparse_or_hardlink(&staged_singbox)?;
        copy_with_retry(&src_singbox, &staged_singbox, "sing-box.exe")?;
        lock_path_owner_and_dacl(&staged_singbox, SYSTEM_ADMIN_FILE_SDDL)?;
    }

    // Verify SHA-256 AFTER copying into SYSTEM-only directory to defeat TOCTOU swap (C-4)
    if let Err(err) = verify_binary_sha256(&staged_singbox, SING_BOX_V14_4_WIN64_SHA256) {
        let _ = std::fs::remove_file(&staged_singbox);
        return Err(err);
    }

    // Record the canonicalized legitimate desktop installation directory in a SYSTEM-only file
    let gui_root_raw = if src_dir
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.eq_ignore_ascii_case("resources"))
    {
        src_dir.parent().unwrap_or(src_dir)
    } else {
        src_dir
    };
    let gui_root = canonicalize_win_path(gui_root_raw);
    let meta_path = bin_dir.join("authorized-gui-dir.txt");
    reject_if_reparse_or_hardlink(&meta_path)?;
    std::fs::write(&meta_path, gui_root.to_string_lossy().as_bytes())
        .map_err(|e| format!("写入 authorized-gui-dir.txt 失败: {e}"))?;
    lock_path_owner_and_dacl(&meta_path, SYSTEM_ADMIN_FILE_SDDL)?;

    // Also pin the GUI binary's SHA-256 (if present) so portable user-writable installs cannot be swapped
    let gui_sha_path = bin_dir.join("authorized-gui-sha256.txt");
    reject_if_reparse_or_hardlink(&gui_sha_path)?;
    let gui_candidate = ["MaxQ.exe", "maxq-desktop.exe"]
        .iter()
        .map(|name| gui_root.join(name))
        .find(|p| p.is_file());
    if let Some(gui_exe) = gui_candidate {
        reject_if_reparse_or_hardlink(&gui_exe)?;
        let gui_sha = compute_file_sha256(&gui_exe)
            .map_err(|e| format!("计算 GUI 二进制 SHA-256 失败: {e}"))?;
        std::fs::write(&gui_sha_path, gui_sha.as_bytes())
            .map_err(|e| format!("写入 authorized-gui-sha256.txt 失败: {e}"))?;
        lock_path_owner_and_dacl(&gui_sha_path, SYSTEM_ADMIN_FILE_SDDL)?;
    } else if gui_sha_path.exists() {
        let _ = std::fs::remove_file(&gui_sha_path);
    }

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
    // On Ok(()), DO NOT call write_diagnostic_status(...) which would recreate %ProgramData%\MaxQ\diagnostics
    if let Err(err) = &res {
        write_diagnostic_status(&format!("UNINSTALL_ERROR: {err}"));
    }
    res
}

fn stop_and_uninstall_service_inner() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("打开服务管理器失败（需要管理员权限）: {e}"))?;
    if let Ok(service) = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    ) {
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
    }

    // Best-effort cleanup of `%ProgramData%\MaxQ` subdirectories and root after uninstall
    let root = program_data_maxq_root();
    if root.exists() && reject_if_reparse_or_hardlink(&root).is_ok() {
        for subdir in ["service-runtime", DIAGNOSTIC_STATUS_SUBDIR, "service-bin"] {
            let target = root.join(subdir);
            if !target.exists() || reject_if_reparse_or_hardlink(&target).is_err() {
                continue;
            }
            for attempt in 0..3 {
                if std::fs::remove_dir_all(&target).is_ok() {
                    break;
                }
                if attempt < 2 {
                    std::thread::sleep(Duration::from_millis(150));
                }
            }
        }
        let _ = std::fs::remove_dir(&root);
    }

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
    let stop_event = OwnedHandle::new(unsafe { CreateEventW(null(), 1, 0, null()) }).ok_or_else(
        || {
            format!(
                "CreateEventW(stop_event) failed: {}",
                std::io::Error::last_os_error()
            )
        },
    )?;
    let stop_event_raw = stop_event.raw();
    let stop_event_slot = Arc::new(Mutex::new(Some(stop_event)));
    let _stop_event_guard = StopEventSlotGuard(Arc::clone(&stop_event_slot));
    let stop_event_for_handler = Arc::clone(&stop_event_slot);

    // Register SCM control handler FIRST so startup failures cleanly report ServiceState::Stopped
    let status_handle =
        service_control_handler::register(SERVICE_NAME, move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                stop_for_handler.store(true, Ordering::SeqCst);
                if let Ok(mut rt) = runtime_for_handler.lock() {
                    rt.stop_singbox();
                }
                if let Ok(guard) = stop_event_for_handler.lock() {
                    if let Some(ev) = guard.as_ref() {
                        unsafe {
                            SetEvent(ev.raw());
                        }
                    }
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })
        .map_err(|e| format!("register SCM handler failed: {e}"))?;

    let init_result = (|| -> Result<(OwnedHandle, OwnedHandle, PathBuf, PathBuf), String> {
        let pipe = create_hardened_named_pipe()?;
        let connect_event = OwnedHandle::new(unsafe { CreateEventW(null(), 1, 0, null()) })
            .ok_or_else(|| {
                format!(
                    "CreateEventW(connect_event) failed: {}",
                    std::io::Error::last_os_error()
                )
            })?;
        let service_exe = canonicalize_win_path(
            &std::env::current_exe().map_err(|e| format!("current_exe failed: {e}"))?,
        );
        let runtime_dir = ensure_system_only_dir("service-runtime")?;
        // Remove any stale active-tun.json left over from a prior power loss / BSOD
        let stale_cfg = runtime_dir.join("active-tun.json");
        if stale_cfg.exists() {
            let _ = std::fs::remove_file(&stale_cfg);
        }
        Ok((pipe, connect_event, service_exe, runtime_dir))
    })();

    let (pipe, connect_event, service_exe, runtime_dir) = match init_result {
        Ok(v) => v,
        Err(err) => {
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
            ResetEvent(connect_event.raw());
        }
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = connect_event.raw();

        let ok = unsafe { ConnectNamedPipe(pipe.raw(), &mut ov) };
        let connected = if ok != 0 {
            true
        } else {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
            if err == ERROR_PIPE_CONNECTED {
                true
            } else if err == ERROR_IO_PENDING {
                let handles = [connect_event.raw(), stop_event_raw];
                let wait = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) };
                if wait == WAIT_OBJECT_0 {
                    let mut transferred = 0u32;
                    unsafe { GetOverlappedResult(pipe.raw(), &ov, &mut transferred, 0) != 0 }
                } else {
                    // Unconditionally drain the IRP via GetOverlappedResult(..., 1) before `ov`
                    // leaves the stack frame or `connect_event` is reset/closed.
                    unsafe {
                        CancelIoEx(pipe.raw(), &ov);
                        let mut dummy = 0u32;
                        GetOverlappedResult(pipe.raw(), &ov, &mut dummy, 1) != 0
                    }
                }
            } else {
                std::thread::sleep(Duration::from_millis(50));
                false
            }
        };

        if stop_flag.load(Ordering::SeqCst) {
            if connected {
                unsafe {
                    DisconnectNamedPipe(pipe.raw());
                }
            }
            break;
        }

        if connected {
            handle_pipe_client(pipe.raw(), &service_exe, &runtime_dir, &runtime);
            unsafe {
                DisconnectNamedPipe(pipe.raw());
            }
        }
    }

    drop(connect_event);
    drop(pipe);
    drop(_stop_event_guard);

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
    if s.len() >= 8 && s[..8].eq_ignore_ascii_case(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{}", &s[8..]))
    } else if let Some(stripped) = s.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        path
    }
}

fn canonicalize_win_path(path: &Path) -> PathBuf {
    match std::fs::canonicalize(path) {
        Ok(canon) => strip_verbatim_prefix(canon),
        Err(_) => strip_verbatim_prefix(path.to_path_buf()),
    }
}

fn paths_equal_ci(a: &Path, b: &Path) -> bool {
    let norm_a = strip_verbatim_prefix(a.to_path_buf())
        .to_string_lossy()
        .replace('/', "\\")
        .to_lowercase();
    let norm_b = strip_verbatim_prefix(b.to_path_buf())
        .to_string_lossy()
        .replace('/', "\\")
        .to_lowercase();
    norm_a == norm_b
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

fn create_hardened_named_pipe() -> Result<OwnedHandle, String> {
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
    let _sd_guard = LocalAllocGuard(sd_ptr);

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

    OwnedHandle::new(handle).ok_or_else(|| {
        format!(
            "CreateNamedPipeW failed (possible pipe squat): {}",
            std::io::Error::last_os_error()
        )
    })
}

fn verify_pipe_caller_process(
    pipe: HANDLE,
    service_exe: &Path,
    runtime: &Arc<Mutex<ServiceRuntimeState>>,
) -> Result<(), String> {
    let mut client_pid: u32 = 0;
    let ok = unsafe { GetNamedPipeClientProcessId(pipe, &mut client_pid) };
    if ok == 0 || client_pid == 0 {
        return Err("failed to query Named Pipe client PID".into());
    }

    let proc_handle =
        OwnedHandle::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, client_pid) })
            .ok_or_else(|| {
                "failed to open client process for image path verification".to_string()
            })?;

    let mut buf = vec![0u16; 4096];
    let mut len = buf.len() as u32;
    let q_ok =
        unsafe { QueryFullProcessImageNameW(proc_handle.raw(), 0, buf.as_mut_ptr(), &mut len) };
    drop(proc_handle);
    if q_ok == 0 || len == 0 {
        return Err("failed to query client process image path".into());
    }

    let caller_str = String::from_utf16_lossy(&buf[..len as usize]);
    // Canonicalize via GetFinalPathNameByHandleW (std::fs::canonicalize) to resolve 8.3 short paths
    // (e.g. PROGRA~1) and symlinks/junctions; fail closed if the backing binary cannot be resolved.
    let caller_canon = std::fs::canonicalize(Path::new(&caller_str))
        .map_err(|e| format!("failed to canonicalize IPC caller image '{caller_str}': {e}"))?;
    let caller_path = strip_verbatim_prefix(caller_canon);

    // Always allow the staged service binary itself
    if paths_equal_ci(&caller_path, service_exe) {
        return Ok(());
    }

    let mut path_authorized = is_authorized_caller_image(service_exe, &caller_path);
    if !path_authorized {
        if let Some(svc_dir) = service_exe.parent() {
            if let Ok(gui_dir) = std::fs::read_to_string(svc_dir.join("authorized-gui-dir.txt")) {
                let synthetic_svc = PathBuf::from(gui_dir.trim()).join("maxq-service.exe");
                if is_authorized_caller_image(&synthetic_svc, &caller_path) {
                    path_authorized = true;
                }
            }
        }
    }
    if !path_authorized {
        return Err(format!(
            "unauthorized IPC caller rejected: {}",
            caller_path.display()
        ));
    }

    // If a pinned GUI SHA-256 digest was recorded during install, verify caller image digest
    // via CachedBinaryVerifier so portable installs in user-writable dirs cannot be swapped.
    if let Some(svc_dir) = service_exe.parent() {
        let sha_file = svc_dir.join("authorized-gui-sha256.txt");
        if sha_file.exists() {
            let expected_sha = std::fs::read_to_string(&sha_file)
                .map_err(|e| format!("failed reading authorized-gui-sha256.txt: {e}"))?;
            let expected_trimmed = expected_sha.trim();
            if expected_trimmed.is_empty() {
                return Err("authorized-gui-sha256.txt is empty".into());
            }
            let mut rt = runtime.lock().unwrap_or_else(|e| e.into_inner());
            if !rt.gui_verify_cache.is_verified(&caller_path, expected_trimmed) {
                return Err(format!(
                    "IPC caller binary SHA-256 mismatch rejected: {}",
                    caller_path.display()
                ));
            }
        }
    }

    Ok(())
}

fn read_pipe_line_overlapped(pipe: HANDLE, max_bytes: usize) -> Result<String, String> {
    let io_event = OwnedHandle::new(unsafe { CreateEventW(null(), 1, 0, null()) })
        .ok_or_else(|| "CreateEventW(read) failed".to_string())?;
    let mut acc = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];

    let res = loop {
        unsafe {
            ResetEvent(io_event.raw());
        }
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = io_event.raw();
        let mut bytes_read = 0u32;

        // Pass null_mut() for lpNumberOfBytesRead on overlapped handles and retrieve transferred
        // count strictly via GetOverlappedResult to avoid asynchronous stack writes.
        let ok = unsafe {
            ReadFile(
                pipe,
                chunk.as_mut_ptr(),
                chunk.len() as u32,
                null_mut(),
                &mut ov,
            )
        };
        if ok != 0 {
            if unsafe { GetOverlappedResult(pipe, &ov, &mut bytes_read, 0) } == 0 {
                break Err("IPC read GetOverlappedResult failed".into());
            }
        } else {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
            if err == ERROR_IO_PENDING {
                let wait = unsafe { WaitForSingleObject(io_event.raw(), PIPE_IO_TIMEOUT_MS) };
                if wait != WAIT_OBJECT_0 {
                    // Unconditionally drain the canceled IRP before `ov`, `chunk`, or `io_event` drop.
                    unsafe {
                        CancelIoEx(pipe, &ov);
                        let mut dummy = 0u32;
                        GetOverlappedResult(pipe, &ov, &mut dummy, 1);
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

    res?;
    String::from_utf8(acc).map_err(|_| "IPC request is not valid UTF-8".into())
}

fn write_pipe_line_overlapped(pipe: HANDLE, line: &str) {
    let Some(io_event) = OwnedHandle::new(unsafe { CreateEventW(null(), 1, 0, null()) }) else {
        return;
    };
    let mut payload = Vec::with_capacity(line.len() + 1);
    payload.extend_from_slice(line.as_bytes());
    payload.push(b'\n');

    let mut offset = 0usize;
    while offset < payload.len() {
        unsafe {
            ResetEvent(io_event.raw());
        }
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = io_event.raw();
        let mut written = 0u32;
        let rem = &payload[offset..];
        let to_write = rem.len().min(64 * 1024) as u32;

        // Pass null_mut() for lpNumberOfBytesWritten on overlapped handles and retrieve transferred
        // count strictly via GetOverlappedResult to avoid asynchronous stack writes.
        let ok = unsafe { WriteFile(pipe, rem.as_ptr(), to_write, null_mut(), &mut ov) };
        if ok != 0 {
            if unsafe { GetOverlappedResult(pipe, &ov, &mut written, 0) } == 0 {
                break;
            }
        } else {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
            if err == ERROR_IO_PENDING {
                let wait = unsafe { WaitForSingleObject(io_event.raw(), PIPE_IO_TIMEOUT_MS) };
                if wait != WAIT_OBJECT_0 {
                    // Unconditionally drain the canceled IRP before `ov`, `payload`, or `io_event` drop.
                    unsafe {
                        CancelIoEx(pipe, &ov);
                        let mut dummy = 0u32;
                        GetOverlappedResult(pipe, &ov, &mut dummy, 1);
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
    // Reject unauthorized callers immediately WITHOUT writing to the pipe so the loop disconnects
    // cleanly without blocking on a malicious client that never reads.
    if verify_pipe_caller_process(pipe, service_exe, runtime).is_err() {
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
            let mut rt = runtime.lock().unwrap_or_else(|e| e.into_inner());
            let verified = rt
                .binary_verify_cache
                .is_verified(&singbox_path, SING_BOX_V14_4_WIN64_SHA256);
            ServiceResponse::Pong {
                version: SERVICE_PROTOCOL_VERSION.to_string(),
                singbox_sha256_verified: verified,
            }
        }
        ServiceRequest::Status => {
            let mut rt = runtime.lock().unwrap_or_else(|e| e.into_inner());
            let tun_active = rt.is_singbox_running();
            let verified = rt
                .binary_verify_cache
                .is_verified(&singbox_path, SING_BOX_V14_4_WIN64_SHA256);
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
                active_profile_id: rt.active_profile_id.clone(),
                active_node_id: rt.active_node_id.clone(),
                active_node_name: rt.active_node_name.clone(),
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
        ServiceRequest::StartTun {
            config_json,
            active_profile_id,
            active_node_id,
            active_node_name,
        } => match start_hardened_singbox_tun(
            &singbox_path,
            runtime_dir,
            &config_json,
            active_profile_id,
            active_node_id,
            active_node_name,
            runtime,
        ) {
            Ok(pid) => ServiceResponse::Started { pid },
            Err(message) => ServiceResponse::Error { message },
        },
    };

    send_pipe_response(pipe, &resp);
}

fn start_hardened_singbox_tun(
    singbox_path: &Path,
    runtime_dir: &Path,
    config_json: &str,
    active_profile_id: Option<String>,
    active_node_id: Option<String>,
    active_node_name: Option<String>,
    runtime: &Arc<Mutex<ServiceRuntimeState>>,
) -> Result<u32, String> {
    let validated = validate_service_config(config_json)?;

    let (logs_arc, alert_arc) = {
        let mut rt = runtime.lock().unwrap_or_else(|e| e.into_inner());
        // Always perform a full, uncached cryptographic SHA-256 verification right before
        // CreateProcessW, then refresh the status cache so subsequent Status polls are zero-I/O.
        rt.binary_verify_cache
            .verify_uncached_and_refresh(singbox_path, SING_BOX_V14_4_WIN64_SHA256)?;
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
    reject_if_reparse_or_hardlink(&cfg_path)?;
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
    rt.active_profile_id = active_profile_id;
    rt.active_node_id = active_node_id;
    rt.active_node_name = active_node_name;
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

/// Rejects symlinks, NTFS junctions/reparse points, and hardlinked files (`nNumberOfLinks > 1`)
/// to prevent pre-created file/directory LPE attacks under `%ProgramData%\MaxQ`.
fn reject_if_reparse_or_hardlink(path: &Path) -> Result<(), String> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(format!(
                "failed inspecting metadata for '{}': {e}",
                path.display()
            ));
        }
    };
    if meta.file_type().is_symlink()
        || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    {
        return Err(format!("refusing symlink/junction at '{}'", path.display()));
    }
    if meta.is_file() {
        let wide = to_wide_null(&path.to_string_lossy());
        let handle = OwnedHandle::new(unsafe {
            CreateFileW(
                wide.as_ptr(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        })
        .ok_or_else(|| {
            format!(
                "failed opening '{}' for hardlink verification: {}",
                path.display(),
                std::io::Error::last_os_error()
            )
        })?;
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe { GetFileInformationByHandle(handle.raw(), &mut info) };
        if ok == 0 {
            return Err(format!(
                "GetFileInformationByHandle failed for '{}': {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Err(format!("refusing reparse point at '{}'", path.display()));
        }
        if info.nNumberOfLinks > 1 {
            return Err(format!(
                "refusing hardlinked file '{}' (nNumberOfLinks={})",
                path.display(),
                info.nNumberOfLinks
            ));
        }
    }
    Ok(())
}

/// Enables `SeRestorePrivilege` and `SeTakeOwnershipPrivilege` on the current process token
/// (best-effort) so elevated Administrators as well as LocalSystem can atomically assign
/// `Owner = S-1-5-18 (LocalSystem)` via `SetNamedSecurityInfoW`.
fn enable_security_privileges() {
    let mut raw_token: HANDLE = null_mut();
    let ok = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut raw_token,
        )
    };
    if ok == 0 {
        return;
    }
    let Some(token) = OwnedHandle::new(raw_token) else {
        return;
    };
    for priv_name in ["SeRestorePrivilege", "SeTakeOwnershipPrivilege"] {
        let priv_wide = to_wide_null(priv_name);
        let mut luid: LUID = unsafe { std::mem::zeroed() };
        if unsafe { LookupPrivilegeValueW(null(), priv_wide.as_ptr(), &mut luid) } == 0 {
            continue;
        }
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        unsafe {
            AdjustTokenPrivileges(
                token.raw(),
                0,
                &tp,
                0,
                null_mut(),
                null_mut(),
            );
        }
    }
}

/// Atomically sets `Owner = S-1-5-18 (LocalSystem)` and replaces the entire DACL with a protected
/// SDDL DACL using `SetNamedSecurityInfoW`, strictly checking for `ERROR_SUCCESS`.
fn lock_path_owner_and_dacl(path: &Path, dacl_sddl: &str) -> Result<(), String> {
    enable_security_privileges();

    let sid_wide = to_wide_null(LOCAL_SYSTEM_SID);
    let mut owner_sid: PSID = null_mut();
    if unsafe { ConvertStringSidToSidW(sid_wide.as_ptr(), &mut owner_sid) } == 0
        || owner_sid.is_null()
    {
        return Err(format!(
            "ConvertStringSidToSidW(S-1-5-18) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let _owner_sid_guard = LocalAllocGuard(owner_sid);

    let sddl_wide = to_wide_null(dacl_sddl);
    let mut sd_ptr: *mut c_void = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_wide.as_ptr(),
            SDDL_REVISION_1,
            &mut sd_ptr,
            null_mut(),
        )
    } == 0
        || sd_ptr.is_null()
    {
        return Err(format!(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW failed for '{dacl_sddl}': {}",
            std::io::Error::last_os_error()
        ));
    }
    let _sd_guard = LocalAllocGuard(sd_ptr);

    let mut dacl_present = 0i32;
    let mut dacl_ptr: *mut ACL = null_mut();
    let mut dacl_defaulted = 0i32;
    if unsafe {
        GetSecurityDescriptorDacl(sd_ptr, &mut dacl_present, &mut dacl_ptr, &mut dacl_defaulted)
    } == 0
        || dacl_present == 0
        || dacl_ptr.is_null()
    {
        return Err(format!(
            "GetSecurityDescriptorDacl failed for '{dacl_sddl}': {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut path_wide = to_wide_null(&path.to_string_lossy());
    let status = unsafe {
        SetNamedSecurityInfoW(
            path_wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            owner_sid,
            null_mut(),
            dacl_ptr,
            null(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(format!(
            "SetNamedSecurityInfoW failed on '{}' (win32_error={status})",
            path.display()
        ));
    }
    Ok(())
}

fn program_data_maxq_root() -> PathBuf {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    PathBuf::from(base).join("MaxQ")
}

/// Writes non-secret install/service diagnostics to `%ProgramData%\MaxQ\diagnostics\last-status.txt`
/// (Owner=SYSTEM, writable ONLY by SYSTEM + Administrators, read-only for Users so the non-elevated
/// GUI can display exact error reasons instead of failing silently).
fn write_diagnostic_status(message: &str) {
    let root = program_data_maxq_root();
    let diag_dir = root.join(DIAGNOSTIC_STATUS_SUBDIR);
    let diag_file = diag_dir.join(DIAGNOSTIC_STATUS_FILE);

    if reject_if_reparse_or_hardlink(&root).is_err()
        || reject_if_reparse_or_hardlink(&diag_dir).is_err()
        || reject_if_reparse_or_hardlink(&diag_file).is_err()
    {
        return;
    }
    if std::fs::create_dir_all(&diag_dir).is_err() {
        return;
    }

    // Lock `%ProgramData%\MaxQ` root FIRST, then apply read-only-for-Users DACL to `diagnostics`.
    if lock_path_owner_and_dacl(&root, SYSTEM_ADMIN_DIR_SDDL).is_err() {
        return;
    }
    if lock_path_owner_and_dacl(&diag_dir, DIAGNOSTICS_DIR_SDDL).is_err() {
        return;
    }

    if reject_if_reparse_or_hardlink(&diag_file).is_ok() {
        if std::fs::write(&diag_file, message.as_bytes()).is_ok() {
            let _ = lock_path_owner_and_dacl(&diag_file, DIAGNOSTICS_FILE_SDDL);
        }
    }
}

/// Ensures `C:\ProgramData\MaxQ\<subdir>` exists without symlinks/junctions/hardlinks and is
/// atomically owned by LocalSystem (`S-1-5-18`) with a protected SYSTEM+Administrators-only DACL.
fn ensure_system_only_dir(subdir: &str) -> Result<PathBuf, String> {
    let root = program_data_maxq_root();
    let dir = root.join(subdir);

    // Reject NTFS junctions/symlinks/hardlinks before creating or writing as SYSTEM (C-3)
    reject_if_reparse_or_hardlink(&root)?;
    reject_if_reparse_or_hardlink(&dir)?;

    std::fs::create_dir_all(&dir).map_err(|e| format!("创建 {subdir} 目录失败: {e}"))?;

    // Atomically enforce Owner=LocalSystem + protected DACL on root first, then subdir
    lock_path_owner_and_dacl(&root, SYSTEM_ADMIN_DIR_SDDL)?;
    lock_path_owner_and_dacl(&dir, SYSTEM_ADMIN_DIR_SDDL)?;

    // Reject reparse points / hardlinks and replace owner+DACL on any pre-existing entries inside `dir`
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            reject_if_reparse_or_hardlink(&p)?;
            let sddl = if p.is_dir() {
                SYSTEM_ADMIN_DIR_SDDL
            } else {
                SYSTEM_ADMIN_FILE_SDDL
            };
            lock_path_owner_and_dacl(&p, sddl)?;
        }
    }

    Ok(dir)
}
