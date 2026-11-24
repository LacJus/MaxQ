use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::RuntimeError;

/// Snapshot of the user's original Windows Internet Settings before MaxQ modifies them.
/// Persisted to disk so even a sudden crash or power loss cleanly restores system proxy on next launch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemProxyBackup {
    pub proxy_enable: u32,
    pub proxy_server: Option<String>,
    pub proxy_override: Option<String>,
}

impl SystemProxyBackup {
    pub fn disabled() -> Self {
        Self {
            proxy_enable: 0,
            proxy_server: None,
            proxy_override: None,
        }
    }
}

/// Returns `true` if a Windows `ProxyServer` string points to any loopback/local interface
/// (`127.0.0.0/8`, `localhost`, `[::1]`, `0.0.0.0`, `::`), including per-scheme forms like
/// `http=127.0.0.1:17890;https=127.0.0.1:17890` or `http://127.0.0.1:7890`.
pub fn is_loopback_proxy_server(server: Option<&str>) -> bool {
    let Some(raw) = server else {
        return false;
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return false;
    }

    for entry in trimmed.split(';') {
        let mut part = entry.trim();
        if part.is_empty() {
            continue;
        }
        // Strip Windows per-protocol prefix such as `http=127.0.0.1:17890` or `socks=localhost:1080`
        if let Some((_, rhs)) = part.split_once('=') {
            part = rhs.trim();
        }
        // Strip optional URL scheme such as `http://127.0.0.1:17890`
        if let Some((_, rhs)) = part.split_once("://") {
            part = rhs.trim();
        }
        // Strip any trailing path
        if let Some((before_slash, _)) = part.split_once('/') {
            part = before_slash.trim();
        }
        // Strip optional userinfo (`user:pass@host:port`)
        if let Some((_, after_at)) = part.rsplit_once('@') {
            part = after_at.trim();
        }
        if part.is_empty() {
            continue;
        }

        let host = if let Some(rest) = part.strip_prefix('[') {
            rest.split_once(']').map(|(h, _)| h).unwrap_or(rest)
        } else if part.matches(':').count() == 1 {
            part.split_once(':').map(|(h, _)| h).unwrap_or(part)
        } else {
            part
        };

        let host = host.trim();
        if host.eq_ignore_ascii_case("localhost")
            || host.to_ascii_lowercase().ends_with(".localhost")
        {
            return true;
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            if ip.is_loopback() || ip.is_unspecified() {
                return true;
            }
        }
    }

    false
}

/// Ensures MaxQ NEVER captures or restores an enabled loopback proxy (such as `127.0.0.1:17890`)
/// or a broken `ProxyEnable=1` with an empty `ProxyServer`, preventing infinite stuck-proxy loops.
/// Legitimate non-loopback proxies (e.g. corporate `10.0.0.5:8080`) are preserved faithfully.
pub fn sanitize_backup(backup: SystemProxyBackup) -> SystemProxyBackup {
    let has_server = backup
        .proxy_server
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty());
    let points_to_loopback = is_loopback_proxy_server(backup.proxy_server.as_deref());

    if backup.proxy_enable != 0 {
        if !has_server || points_to_loopback {
            return SystemProxyBackup::disabled();
        }
        return backup;
    }

    if points_to_loopback {
        return SystemProxyBackup::disabled();
    }

    backup
}

fn is_dirty_proxy_state(backup: &SystemProxyBackup) -> bool {
    backup.proxy_enable != 0
        && (backup
            .proxy_server
            .as_deref()
            .is_none_or(|s| s.trim().is_empty())
            || is_loopback_proxy_server(backup.proxy_server.as_deref()))
}

trait ProxyPlatform {
    fn read_current(&self) -> Result<SystemProxyBackup, RuntimeError>;
    fn set_proxy(&self, server: &str, bypass: &str) -> Result<(), RuntimeError>;
    fn apply_backup(&self, backup: &SystemProxyBackup) -> Result<(), RuntimeError>;
    fn force_disable_all(&self) -> Result<(), RuntimeError>;
}

struct OsProxyPlatform;

impl ProxyPlatform for OsProxyPlatform {
    fn read_current(&self) -> Result<SystemProxyBackup, RuntimeError> {
        platform::read_current()
    }

    fn set_proxy(&self, server: &str, bypass: &str) -> Result<(), RuntimeError> {
        platform::set_proxy(server, bypass)
    }

    fn apply_backup(&self, backup: &SystemProxyBackup) -> Result<(), RuntimeError> {
        platform::apply_backup(backup)
    }

    fn force_disable_all(&self) -> Result<(), RuntimeError> {
        platform::force_disable_all()
    }
}

/// Manages Windows System Proxy (`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
/// + WinINet `INTERNET_OPTION_PER_CONNECTION_OPTION` / `DefaultConnectionSettings`)
/// with crash-safe backup, loopback self-healing, and atomic restore.
pub struct SystemProxyManager {
    backup_path: PathBuf,
    active: bool,
}

impl SystemProxyManager {
    pub fn new(runtime_dir: impl AsRef<Path>) -> Self {
        Self {
            backup_path: runtime_dir.as_ref().join("sysproxy-backup.json"),
            active: false,
        }
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Recovers from a previous crash or stuck loopback proxy on startup.
    /// Returns `Ok(true)` if system proxy settings were restored or healed.
    pub fn recover_if_dirty(&mut self) -> Result<bool, RuntimeError> {
        self.recover_if_dirty_with(&OsProxyPlatform)
    }

    /// Backs up current non-loopback settings (if not already backed up) and enables `127.0.0.1:<port>`.
    pub fn enable(&mut self, port: u16, bypass_list: &[String]) -> Result<(), RuntimeError> {
        self.enable_with(&OsProxyPlatform, port, bypass_list)
    }

    /// Restores the sanitized backed-up original settings and removes the backup file.
    /// Also self-heals if the OS is currently stuck on a loopback proxy even without a backup file.
    pub fn disable_and_restore(&mut self) -> Result<(), RuntimeError> {
        self.disable_and_restore_with(&OsProxyPlatform)
    }

    /// Emergency reset: unconditionally clears Windows System Proxy (`PROXY_TYPE_DIRECT`,
    /// `ProxyEnable=0`, removes `ProxyServer`/`ProxyOverride`) across LAN and RAS/PPPoE entries,
    /// broadcasts WinINet refresh, and deletes any stale backup file.
    pub fn force_disable(&mut self) -> Result<(), RuntimeError> {
        self.force_disable_with(&OsProxyPlatform)
    }

    fn load_sanitized_backup_from_disk(&self) -> SystemProxyBackup {
        match std::fs::read_to_string(&self.backup_path)
            .ok()
            .and_then(|raw| serde_json::from_str::<SystemProxyBackup>(&raw).ok())
        {
            Some(parsed) => sanitize_backup(parsed),
            None => SystemProxyBackup::disabled(),
        }
    }

    fn recover_if_dirty_with<P: ProxyPlatform>(&mut self, backend: &P) -> Result<bool, RuntimeError> {
        if self.backup_path.exists() {
            let safe_backup = self.load_sanitized_backup_from_disk();
            backend.apply_backup(&safe_backup)?;
            let _ = std::fs::remove_file(&self.backup_path);
            self.active = false;
            return Ok(true);
        }

        // Self-healing: even if `sysproxy-backup.json` is absent (e.g. poisoned & deleted by an older
        // version, or WinINet/Registry desync), clear any OS proxy pointing at loopback or empty server.
        if let Ok(current) = backend.read_current() {
            if is_dirty_proxy_state(&current) {
                backend.apply_backup(&SystemProxyBackup::disabled())?;
                self.active = false;
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn enable_with<P: ProxyPlatform>(
        &mut self,
        backend: &P,
        port: u16,
        bypass_list: &[String],
    ) -> Result<(), RuntimeError> {
        if let Some(parent) = self.backup_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        if self.backup_path.exists() {
            // Heal any pre-existing corrupted or loopback-poisoned backup file before proceeding
            let raw = std::fs::read_to_string(&self.backup_path).ok();
            let parsed = raw
                .as_deref()
                .and_then(|s| serde_json::from_str::<SystemProxyBackup>(s).ok());
            match parsed {
                Some(existing) => {
                    let sanitized = sanitize_backup(existing.clone());
                    if sanitized != existing {
                        std::fs::write(
                            &self.backup_path,
                            serde_json::to_string_pretty(&sanitized)?,
                        )?;
                    }
                }
                None => {
                    let safe = SystemProxyBackup::disabled();
                    std::fs::write(&self.backup_path, serde_json::to_string_pretty(&safe)?)?;
                }
            }
        } else {
            let current = backend
                .read_current()
                .unwrap_or_else(|_| SystemProxyBackup::disabled());
            let safe_backup = sanitize_backup(current);
            std::fs::write(
                &self.backup_path,
                serde_json::to_string_pretty(&safe_backup)?,
            )?;
        }

        let bypass = build_windows_bypass_string(bypass_list);
        backend.set_proxy(&format!("127.0.0.1:{port}"), &bypass)?;
        self.active = true;
        Ok(())
    }

    fn disable_and_restore_with<P: ProxyPlatform>(&mut self, backend: &P) -> Result<(), RuntimeError> {
        if self.backup_path.exists() {
            let safe_backup = self.load_sanitized_backup_from_disk();
            backend.apply_backup(&safe_backup)?;
            let _ = std::fs::remove_file(&self.backup_path);
        } else if self.active {
            backend.apply_backup(&SystemProxyBackup::disabled())?;
        } else if let Ok(current) = backend.read_current() {
            // Self-heal stuck loopback or desynced proxy even if manager was not marked active
            if is_dirty_proxy_state(&current) {
                backend.apply_backup(&SystemProxyBackup::disabled())?;
            }
        }
        self.active = false;
        Ok(())
    }

    fn force_disable_with<P: ProxyPlatform>(&mut self, backend: &P) -> Result<(), RuntimeError> {
        backend.force_disable_all()?;
        let _ = std::fs::remove_file(&self.backup_path);
        self.active = false;
        Ok(())
    }
}

impl Drop for SystemProxyManager {
    fn drop(&mut self) {
        if self.active || self.backup_path.exists() {
            let _ = self.disable_and_restore();
        }
    }
}

pub fn build_windows_bypass_string(extra_bypass: &[String]) -> String {
    let mut entries: Vec<String> = vec![
        "localhost".into(),
        "127.*".into(),
        "10.*".into(),
        "172.16.*".into(),
        "192.168.*".into(),
        "<local>".into(),
    ];
    for item in extra_bypass {
        let cleaned = item.trim();
        if !cleaned.is_empty() && !entries.iter().any(|e| e.eq_ignore_ascii_case(cleaned)) {
            entries.push(cleaned.to_string());
        }
    }
    entries.join(";")
}

#[cfg(windows)]
mod platform {
    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Networking::WinInet::{
        InternetQueryOptionW, InternetSetOptionW, INTERNET_OPTION_PER_CONNECTION_OPTION,
        INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_PER_CONN_FLAGS,
        INTERNET_PER_CONN_OPTIONW, INTERNET_PER_CONN_OPTIONW_0, INTERNET_PER_CONN_OPTION_LISTW,
        INTERNET_PER_CONN_PROXY_BYPASS, INTERNET_PER_CONN_PROXY_SERVER, PROXY_TYPE_DIRECT,
        PROXY_TYPE_PROXY,
    };
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    use super::SystemProxyBackup;
    use crate::RuntimeError;

    const INTERNET_SETTINGS_PATH: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    const INTERNET_CONNECTIONS_PATH: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";

    fn to_wide_null(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn notify_wininet() {
        unsafe {
            InternetSetOptionW(null(), INTERNET_OPTION_SETTINGS_CHANGED, null(), 0);
            InternetSetOptionW(null(), INTERNET_OPTION_REFRESH, null(), 0);
        }
    }

    fn query_wininet_flags(conn_name: Option<&str>) -> Option<u32> {
        let mut conn_wide: Option<Vec<u16>> = conn_name.map(to_wide_null);
        let mut opt = INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_FLAGS,
            Value: INTERNET_PER_CONN_OPTIONW_0 { dwValue: 0 },
        };
        let mut list = INTERNET_PER_CONN_OPTION_LISTW {
            dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
            pszConnection: conn_wide.as_mut().map_or(null_mut(), |v| v.as_mut_ptr()),
            dwOptionCount: 1,
            dwOptionError: 0,
            pOptions: &mut opt,
        };
        let mut list_size = std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32;
        let ok = unsafe {
            InternetQueryOptionW(
                null(),
                INTERNET_OPTION_PER_CONNECTION_OPTION,
                &mut list as *mut _ as *mut c_void,
                &mut list_size,
            )
        };
        let _ = &conn_wide;
        if ok != 0 {
            Some(unsafe { opt.Value.dwValue })
        } else {
            None
        }
    }

    /// Atomically updates Windows WinINet per-connection settings (including the authoritative
    /// `Connections\DefaultConnectionSettings` binary blob read by Edge/Chrome/Windows Settings).
    fn apply_wininet_per_conn(
        conn_name: Option<&str>,
        enable: bool,
        server: Option<&str>,
        bypass: Option<&str>,
    ) -> Result<(), String> {
        let existing_flags = query_wininet_flags(conn_name).unwrap_or(PROXY_TYPE_DIRECT);
        let flags = if enable {
            PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY
        } else {
            (existing_flags & !PROXY_TYPE_PROXY) | PROXY_TYPE_DIRECT
        };

        let mut conn_wide: Option<Vec<u16>> = conn_name.map(to_wide_null);
        let mut server_wide = to_wide_null(server.unwrap_or(""));
        let mut bypass_wide = to_wide_null(bypass.unwrap_or(""));

        let mut options = [
            INTERNET_PER_CONN_OPTIONW {
                dwOption: INTERNET_PER_CONN_FLAGS,
                Value: INTERNET_PER_CONN_OPTIONW_0 { dwValue: flags },
            },
            INTERNET_PER_CONN_OPTIONW {
                dwOption: INTERNET_PER_CONN_PROXY_SERVER,
                Value: INTERNET_PER_CONN_OPTIONW_0 {
                    pszValue: server_wide.as_mut_ptr(),
                },
            },
            INTERNET_PER_CONN_OPTIONW {
                dwOption: INTERNET_PER_CONN_PROXY_BYPASS,
                Value: INTERNET_PER_CONN_OPTIONW_0 {
                    pszValue: bypass_wide.as_mut_ptr(),
                },
            },
        ];

        let mut list = INTERNET_PER_CONN_OPTION_LISTW {
            dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
            pszConnection: conn_wide.as_mut().map_or(null_mut(), |v| v.as_mut_ptr()),
            dwOptionCount: options.len() as u32,
            dwOptionError: 0,
            pOptions: options.as_mut_ptr(),
        };

        let ok = unsafe {
            InternetSetOptionW(
                null(),
                INTERNET_OPTION_PER_CONNECTION_OPTION,
                &mut list as *mut _ as *const c_void,
                std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
            )
        };
        // Ensure wide-string buffers stay alive strictly until after InternetSetOptionW returns
        let _ = (&conn_wide, &server_wide, &bypass_wide);

        if ok == 0 {
            return Err(format!(
                "InternetSetOptionW(PER_CONNECTION_OPTION) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn sync_registry_values(
        enable: bool,
        server: Option<&str>,
        bypass: Option<&str>,
    ) -> Result<(), RuntimeError> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) = hkcu
            .create_subkey(INTERNET_SETTINGS_PATH)
            .map_err(|e| RuntimeError::SystemProxy(e.to_string()))?;
        let enable_dword: u32 = if enable { 1 } else { 0 };
        key.set_value("ProxyEnable", &enable_dword)
            .map_err(|e| RuntimeError::SystemProxy(e.to_string()))?;
        match server.filter(|s| !s.trim().is_empty()) {
            Some(s) => {
                key.set_value("ProxyServer", &s)
                    .map_err(|e| RuntimeError::SystemProxy(e.to_string()))?;
            }
            None => {
                let _ = key.delete_value("ProxyServer");
            }
        }
        match bypass.filter(|o| !o.trim().is_empty()) {
            Some(o) => {
                let _ = key.set_value("ProxyOverride", &o);
            }
            None => {
                let _ = key.delete_value("ProxyOverride");
            }
        }
        Ok(())
    }

    pub fn read_current() -> Result<SystemProxyBackup, RuntimeError> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let key = hkcu
            .open_subkey(INTERNET_SETTINGS_PATH)
            .map_err(|e| RuntimeError::SystemProxy(e.to_string()))?;
        let mut proxy_enable: u32 = key.get_value("ProxyEnable").unwrap_or(0);
        let proxy_server: Option<String> = key.get_value("ProxyServer").ok();
        let proxy_override: Option<String> = key.get_value("ProxyOverride").ok();

        // Also check WinINet `DefaultConnectionSettings` flags to detect Registry/WinINet desync
        if let Some(flags) = query_wininet_flags(None) {
            if (flags & PROXY_TYPE_PROXY) != 0 {
                proxy_enable = 1;
            }
        }

        Ok(SystemProxyBackup {
            proxy_enable,
            proxy_server,
            proxy_override,
        })
    }

    pub fn set_proxy(server: &str, bypass: &str) -> Result<(), RuntimeError> {
        let wininet_res = apply_wininet_per_conn(None, true, Some(server), Some(bypass));
        let reg_res = sync_registry_values(true, Some(server), Some(bypass));
        notify_wininet();
        match (wininet_res, reg_res) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(w), Err(r)) => Err(RuntimeError::SystemProxy(format!("{w}; registry: {r}"))),
            (Err(w), Ok(())) => Err(RuntimeError::SystemProxy(w)),
            (Ok(()), Err(r)) => Err(r),
        }
    }

    pub fn apply_backup(backup: &SystemProxyBackup) -> Result<(), RuntimeError> {
        let enable = backup.proxy_enable != 0
            && backup
                .proxy_server
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty());
        let server = backup.proxy_server.as_deref();
        let bypass = backup.proxy_override.as_deref();

        let wininet_res = apply_wininet_per_conn(None, enable, server, bypass);
        let reg_res = sync_registry_values(enable, server, bypass);
        notify_wininet();
        match (wininet_res, reg_res) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(w), Err(r)) => Err(RuntimeError::SystemProxy(format!("{w}; registry: {r}"))),
            (Err(w), Ok(())) => Err(RuntimeError::SystemProxy(w)),
            (Ok(()), Err(r)) => Err(r),
        }
    }

    pub fn force_disable_all() -> Result<(), RuntimeError> {
        let wininet_res = apply_wininet_per_conn(None, false, None, None);

        // Best-effort clear any dial-up / PPPoE / VPN connection profiles under `Connections`
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        if let Ok(conn_key) = hkcu.open_subkey(INTERNET_CONNECTIONS_PATH) {
            for item in conn_key.enum_values().flatten() {
                let name = item.0;
                if name.eq_ignore_ascii_case("DefaultConnectionSettings")
                    || name.eq_ignore_ascii_case("SavedLegacySettings")
                {
                    continue;
                }
                let _ = apply_wininet_per_conn(Some(&name), false, None, None);
            }
        }

        let reg_res = sync_registry_values(false, None, None);
        notify_wininet();
        match (wininet_res, reg_res) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(w), Err(r)) => Err(RuntimeError::SystemProxy(format!("{w}; registry: {r}"))),
            (Err(w), Ok(())) => Err(RuntimeError::SystemProxy(w)),
            (Ok(()), Err(r)) => Err(r),
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use super::SystemProxyBackup;
    use crate::RuntimeError;

    pub fn read_current() -> Result<SystemProxyBackup, RuntimeError> {
        Ok(SystemProxyBackup::disabled())
    }

    pub fn set_proxy(_server: &str, _bypass: &str) -> Result<(), RuntimeError> {
        Ok(())
    }

    pub fn apply_backup(_backup: &SystemProxyBackup) -> Result<(), RuntimeError> {
        Ok(())
    }

    pub fn force_disable_all() -> Result<(), RuntimeError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    struct MockProxyPlatform {
        state: RefCell<SystemProxyBackup>,
        apply_calls: RefCell<Vec<SystemProxyBackup>>,
        force_disable_calls: RefCell<usize>,
    }

    impl MockProxyPlatform {
        fn new(initial: SystemProxyBackup) -> Self {
            Self {
                state: RefCell::new(initial),
                apply_calls: RefCell::new(Vec::new()),
                force_disable_calls: RefCell::new(0),
            }
        }

        fn current(&self) -> SystemProxyBackup {
            self.state.borrow().clone()
        }
    }

    impl ProxyPlatform for MockProxyPlatform {
        fn read_current(&self) -> Result<SystemProxyBackup, RuntimeError> {
            Ok(self.state.borrow().clone())
        }

        fn set_proxy(&self, server: &str, bypass: &str) -> Result<(), RuntimeError> {
            *self.state.borrow_mut() = SystemProxyBackup {
                proxy_enable: 1,
                proxy_server: Some(server.to_string()),
                proxy_override: Some(bypass.to_string()),
            };
            Ok(())
        }

        fn apply_backup(&self, backup: &SystemProxyBackup) -> Result<(), RuntimeError> {
            self.apply_calls.borrow_mut().push(backup.clone());
            *self.state.borrow_mut() = backup.clone();
            Ok(())
        }

        fn force_disable_all(&self) -> Result<(), RuntimeError> {
            *self.force_disable_calls.borrow_mut() += 1;
            *self.state.borrow_mut() = SystemProxyBackup::disabled();
            Ok(())
        }
    }

    fn unique_tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "maxq_sysproxy_{name}_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn detects_all_loopback_proxy_server_formats() {
        assert!(is_loopback_proxy_server(Some("127.0.0.1:17890")));
        assert!(is_loopback_proxy_server(Some("127.0.0.1")));
        assert!(is_loopback_proxy_server(Some("127.0.1.1:7890")));
        assert!(is_loopback_proxy_server(Some("localhost:17890")));
        assert!(is_loopback_proxy_server(Some("LOCALHOST")));
        assert!(is_loopback_proxy_server(Some("[::1]:17890")));
        assert!(is_loopback_proxy_server(Some("::1")));
        assert!(is_loopback_proxy_server(Some("http://127.0.0.1:17890")));
        assert!(is_loopback_proxy_server(Some(
            "http=127.0.0.1:17890;https=127.0.0.1:17890;socks=127.0.0.1:17890"
        )));
        assert!(is_loopback_proxy_server(Some("socks=http://localhost:10808")));
        assert!(is_loopback_proxy_server(Some("0.0.0.0:17890")));

        // Legitimate remote/LAN corporate proxies must NOT be classified as loopback
        assert!(!is_loopback_proxy_server(None));
        assert!(!is_loopback_proxy_server(Some("")));
        assert!(!is_loopback_proxy_server(Some("10.0.0.5:8080")));
        assert!(!is_loopback_proxy_server(Some("192.168.1.2:3128")));
        assert!(!is_loopback_proxy_server(Some("proxy.corp.example:8080")));
        assert!(!is_loopback_proxy_server(Some(
            "http=proxy.corp.example:8080;https=proxy.corp.example:8443"
        )));
    }

    #[test]
    fn prevents_self_capture_loop_when_os_already_points_to_loopback() {
        let tmp_dir = unique_tmp_dir("self_capture");
        let mock = MockProxyPlatform::new(SystemProxyBackup {
            proxy_enable: 1,
            proxy_server: Some("127.0.0.1:17890".into()),
            proxy_override: Some("localhost;127.*".into()),
        });

        let mut mgr = SystemProxyManager::new(&tmp_dir);
        mgr.enable_with(&mock, 17890, &[]).unwrap();

        // Disk backup must be sanitized to disabled, NEVER recording 127.0.0.1:17890
        let saved: SystemProxyBackup = serde_json::from_str(
            &std::fs::read_to_string(tmp_dir.join("sysproxy-backup.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(saved, SystemProxyBackup::disabled());

        // Disconnecting must cleanly disable OS proxy instead of restoring 127.0.0.1:17890
        mgr.disable_and_restore_with(&mock).unwrap();
        assert_eq!(mock.current(), SystemProxyBackup::disabled());
        assert!(!tmp_dir.join("sysproxy-backup.json").exists());

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn heals_preexisting_poisoned_backup_from_older_version() {
        let tmp_dir = unique_tmp_dir("poisoned_backup");
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let poisoned = SystemProxyBackup {
            proxy_enable: 1,
            proxy_server: Some("127.0.0.1:17890".into()),
            proxy_override: Some("localhost;<local>".into()),
        };
        std::fs::write(
            tmp_dir.join("sysproxy-backup.json"),
            serde_json::to_string_pretty(&poisoned).unwrap(),
        )
        .unwrap();

        let mock = MockProxyPlatform::new(poisoned);
        let mut mgr = SystemProxyManager::new(&tmp_dir);
        assert!(mgr.recover_if_dirty_with(&mock).unwrap());
        assert_eq!(mock.current(), SystemProxyBackup::disabled());
        assert!(!tmp_dir.join("sysproxy-backup.json").exists());

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn heals_stuck_loopback_proxy_even_without_backup_file() {
        let tmp_dir = unique_tmp_dir("no_backup_self_heal");
        let mock = MockProxyPlatform::new(SystemProxyBackup {
            proxy_enable: 1,
            proxy_server: Some("127.0.0.1:17890".into()),
            proxy_override: None,
        });

        let mut mgr = SystemProxyManager::new(&tmp_dir);
        assert!(mgr.recover_if_dirty_with(&mock).unwrap());
        assert_eq!(mock.current(), SystemProxyBackup::disabled());

        // Also heals on disable_and_restore when active == false and no backup file exists
        *mock.state.borrow_mut() = SystemProxyBackup {
            proxy_enable: 1,
            proxy_server: Some("http=127.0.0.1:17890;https=127.0.0.1:17890".into()),
            proxy_override: None,
        };
        mgr.disable_and_restore_with(&mock).unwrap();
        assert_eq!(mock.current(), SystemProxyBackup::disabled());

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn handles_corrupted_backup_json_without_leaving_proxy_stuck() {
        let tmp_dir = unique_tmp_dir("corrupt_json");
        std::fs::create_dir_all(&tmp_dir).unwrap();
        std::fs::write(tmp_dir.join("sysproxy-backup.json"), "{truncated").unwrap();

        let mock = MockProxyPlatform::new(SystemProxyBackup {
            proxy_enable: 1,
            proxy_server: Some("127.0.0.1:17890".into()),
            proxy_override: None,
        });

        let mut mgr = SystemProxyManager::new(&tmp_dir);
        mgr.disable_and_restore_with(&mock).unwrap();
        assert_eq!(mock.current(), SystemProxyBackup::disabled());
        assert!(!tmp_dir.join("sysproxy-backup.json").exists());

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn preserves_legitimate_non_loopback_corporate_proxy() {
        let tmp_dir = unique_tmp_dir("corp_proxy");
        let corp = SystemProxyBackup {
            proxy_enable: 1,
            proxy_server: Some("10.0.0.5:8080".into()),
            proxy_override: Some("*.corp.internal;<local>".into()),
        };
        let mock = MockProxyPlatform::new(corp.clone());

        let mut mgr = SystemProxyManager::new(&tmp_dir);
        // Must NOT touch corporate proxy on startup recovery
        assert!(!mgr.recover_if_dirty_with(&mock).unwrap());
        assert_eq!(mock.current(), corp);

        // Enable MaxQ -> sets 127.0.0.1:17890 -> disable -> faithfully restores corporate proxy
        mgr.enable_with(&mock, 17890, &[]).unwrap();
        assert_eq!(
            mock.current().proxy_server.as_deref(),
            Some("127.0.0.1:17890")
        );
        mgr.disable_and_restore_with(&mock).unwrap();
        assert_eq!(mock.current(), corp);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn force_disable_clears_proxy_and_removes_backup() {
        let tmp_dir = unique_tmp_dir("force_disable");
        let corp = SystemProxyBackup {
            proxy_enable: 1,
            proxy_server: Some("10.0.0.5:8080".into()),
            proxy_override: None,
        };
        let mock = MockProxyPlatform::new(corp);

        let mut mgr = SystemProxyManager::new(&tmp_dir);
        mgr.enable_with(&mock, 17890, &[]).unwrap();
        assert!(tmp_dir.join("sysproxy-backup.json").exists());

        mgr.force_disable_with(&mock).unwrap();
        assert_eq!(mock.current(), SystemProxyBackup::disabled());
        assert_eq!(*mock.force_disable_calls.borrow(), 1);
        assert!(!mgr.is_active());
        assert!(!tmp_dir.join("sysproxy-backup.json").exists());

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn crash_safe_backup_and_recovery_lifecycle() {
        let tmp_dir = unique_tmp_dir("lifecycle");

        let mut mgr = SystemProxyManager::new(&tmp_dir);
        assert!(!mgr.recover_if_dirty().unwrap());

        mgr.enable(17890, &["*.local".into()]).unwrap();
        assert!(mgr.is_active());
        assert!(tmp_dir.join("sysproxy-backup.json").exists());

        // Simulate crash (forget drop by creating a second manager while backup exists)
        let mut recovered_mgr = SystemProxyManager::new(&tmp_dir);
        assert!(recovered_mgr.recover_if_dirty().unwrap());
        assert!(!tmp_dir.join("sysproxy-backup.json").exists());

        mgr.disable_and_restore().unwrap();
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
