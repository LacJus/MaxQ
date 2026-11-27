use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::RuntimeError;

const WININET_PROXY_TYPE_DIRECT: u32 = 0x1;
const WININET_PROXY_TYPE_PROXY: u32 = 0x2;
#[cfg(test)]
const WININET_PROXY_TYPE_AUTO_PROXY_URL: u32 = 0x4;
#[cfg(test)]
const WININET_PROXY_TYPE_AUTO_DETECT: u32 = 0x8;

/// Snapshot of the user's original Windows Internet Settings before MaxQ modifies them.
/// Persisted to disk so even a sudden crash or power loss cleanly restores system proxy on next launch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemProxyBackup {
    pub proxy_enable: u32,
    pub proxy_server: Option<String>,
    pub proxy_override: Option<String>,
    #[serde(default)]
    pub wininet_flags: Option<u32>,
}

impl SystemProxyBackup {
    pub fn disabled() -> Self {
        Self {
            proxy_enable: 0,
            proxy_server: None,
            proxy_override: None,
            wininet_flags: None,
        }
    }
}

fn strip_nul(s: &str) -> String {
    s.replace('\0', "")
}

#[cfg(any(windows, test))]
fn compute_wininet_flags(
    enable: bool,
    existing_flags: Option<u32>,
    restore_flags: Option<u32>,
) -> u32 {
    if enable {
        restore_flags.unwrap_or(WININET_PROXY_TYPE_DIRECT | WININET_PROXY_TYPE_PROXY)
            | WININET_PROXY_TYPE_PROXY
    } else {
        let base = restore_flags
            .or(existing_flags)
            .unwrap_or(WININET_PROXY_TYPE_DIRECT);
        (base & !WININET_PROXY_TYPE_PROXY) | WININET_PROXY_TYPE_DIRECT
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
/// Legitimate non-loopback proxies (e.g. corporate `10.0.0.5:8080`) and PAC/WPAD flags are preserved.
pub fn sanitize_backup(mut backup: SystemProxyBackup) -> SystemProxyBackup {
    backup.proxy_server = backup.proxy_server.map(|s| strip_nul(&s));
    backup.proxy_override = backup.proxy_override.map(|s| strip_nul(&s));

    let has_server = backup
        .proxy_server
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty());
    let points_to_loopback = is_loopback_proxy_server(backup.proxy_server.as_deref());
    let cleaned_disabled_flags = backup
        .wininet_flags
        .map(|f| (f & !WININET_PROXY_TYPE_PROXY) | WININET_PROXY_TYPE_DIRECT);

    if backup.proxy_enable != 0 {
        if !has_server || points_to_loopback {
            return SystemProxyBackup {
                proxy_enable: 0,
                proxy_server: None,
                proxy_override: None,
                wininet_flags: cleaned_disabled_flags,
            };
        }
        return backup;
    }

    if points_to_loopback {
        return SystemProxyBackup {
            proxy_enable: 0,
            proxy_server: None,
            proxy_override: None,
            wininet_flags: cleaned_disabled_flags,
        };
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

    fn write_backup_atomic(&self, backup: &SystemProxyBackup) -> Result<(), RuntimeError> {
        use std::io::Write;
        let payload = serde_json::to_string_pretty(backup)?;
        let tmp_path = self.backup_path.with_extension("json.tmp");
        {
            let mut file = std::fs::File::create(&tmp_path)?;
            file.write_all(payload.as_bytes())?;
            let _ = file.sync_all();
        }
        match std::fs::rename(&tmp_path, &self.backup_path) {
            Ok(()) => Ok(()),
            Err(_) => {
                // On Windows, `rename` fails if the destination already exists.
                let _ = std::fs::remove_file(&self.backup_path);
                if let Err(err) = std::fs::rename(&tmp_path, &self.backup_path) {
                    let _ = std::fs::remove_file(&tmp_path);
                    std::fs::write(&self.backup_path, payload.as_bytes()).map_err(|_| err)?;
                }
                Ok(())
            }
        }
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
                        self.write_backup_atomic(&sanitized)?;
                    }
                }
                None => {
                    let safe = SystemProxyBackup::disabled();
                    self.write_backup_atomic(&safe)?;
                }
            }
        } else {
            let current = backend
                .read_current()
                .unwrap_or_else(|_| SystemProxyBackup::disabled());
            let safe_backup = sanitize_backup(current);
            self.write_backup_atomic(&safe_backup)?;
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

fn is_safe_wininet_bypass_entry(raw: &str) -> bool {
    let s = raw.trim();
    if s.is_empty() || s.len() > 128 {
        return false;
    }
    if s.chars().any(|c| {
        c.is_control()
            || c.is_whitespace()
            || matches!(c, ';' | ',' | '\'' | '"' | '\\' | '/' | '=' | '?' | '#' | '@')
    }) {
        return false;
    }
    if s.eq_ignore_ascii_case("<local>") || s.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if s.contains('*') {
        // Allow private IPv4 prefix globs (`127.*`, `10.*`, `192.168.*`, `169.254.*`, `172.16.*`..`172.31.*`, `100.64.*`)
        if let Some(prefix) = s.strip_suffix(".*") {
            if !prefix.contains('*') {
                if matches!(prefix, "127" | "10" | "192.168" | "169.254" | "100.64") {
                    return true;
                }
                if let Some(second) = prefix.strip_prefix("172.") {
                    if second.parse::<u8>().is_ok_and(|n| (16..=31).contains(&n)) {
                        return true;
                    }
                }
            }
        }
        // Allow leading `*.` ONLY for local domains or multi-label domain suffixes (blocks `*`, `*.*`, `*.com`, `*foo*`)
        if let Some(suffix) = s.strip_prefix("*.") {
            if suffix.contains('*') || suffix.is_empty() || suffix.starts_with('.') || suffix.ends_with('.') {
                return false;
            }
            let lower = suffix.to_ascii_lowercase();
            let valid_chars = lower
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
            if !valid_chars {
                return false;
            }
            if matches!(lower.as_str(), "local" | "lan" | "internal" | "localhost") {
                return true;
            }
            // Must have at least 2 non-empty labels (e.g. `*.apple.com`, never `*.com`)
            let labels: Vec<&str> = lower.split('.').collect();
            return labels.len() >= 2 && labels.iter().all(|l| !l.is_empty());
        }
        return false;
    }

    if let Ok(ip) = s.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
        return !ip.is_unspecified();
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
}

pub fn build_windows_bypass_string(extra_bypass: &[String]) -> String {
    let mut entries: Vec<String> = vec![
        "localhost".into(),
        "127.*".into(),
        "10.*".into(),
        "172.16.*".into(),
        "172.17.*".into(),
        "172.18.*".into(),
        "172.19.*".into(),
        "172.20.*".into(),
        "172.21.*".into(),
        "172.22.*".into(),
        "172.23.*".into(),
        "172.24.*".into(),
        "172.25.*".into(),
        "172.26.*".into(),
        "172.27.*".into(),
        "172.28.*".into(),
        "172.29.*".into(),
        "172.30.*".into(),
        "172.31.*".into(),
        "192.168.*".into(),
        "169.254.*".into(),
        "<local>".into(),
    ];
    let mut total_len: usize = entries.iter().map(|s| s.len() + 1).sum();
    for item in extra_bypass {
        let cleaned = item.trim();
        if !is_safe_wininet_bypass_entry(cleaned) {
            continue;
        }
        if entries.iter().any(|e| e.eq_ignore_ascii_case(cleaned)) {
            continue;
        }
        if entries.len() >= 64 || total_len + cleaned.len() + 1 > 2048 {
            break;
        }
        total_len += cleaned.len() + 1;
        entries.push(cleaned.to_string());
    }
    entries.join(";")
}

#[cfg(windows)]
mod platform {
    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::GlobalFree;
    use windows_sys::Win32::Networking::WinInet::{
        InternetQueryOptionW, InternetSetOptionW, INTERNET_OPTION_PER_CONNECTION_OPTION,
        INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_PER_CONN_FLAGS,
        INTERNET_PER_CONN_OPTIONW, INTERNET_PER_CONN_OPTIONW_0, INTERNET_PER_CONN_OPTION_LISTW,
        INTERNET_PER_CONN_PROXY_BYPASS, INTERNET_PER_CONN_PROXY_SERVER, PROXY_TYPE_PROXY,
    };
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_USERS, KEY_READ, KEY_WRITE};
    use winreg::{RegKey, RegValue};

    use super::{compute_wininet_flags, is_loopback_proxy_server, strip_nul, SystemProxyBackup};
    use crate::RuntimeError;

    const INTERNET_SETTINGS_PATH: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    const INTERNET_CONNECTIONS_PATH: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";

    fn to_wide_null(s: &str) -> Vec<u16> {
        let cleaned = strip_nul(s);
        OsStr::new(&cleaned)
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

    fn query_wininet_proxy_server(conn_name: Option<&str>) -> Option<String> {
        let mut conn_wide: Option<Vec<u16>> = conn_name.map(to_wide_null);
        let mut opt = INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_PROXY_SERVER,
            Value: INTERNET_PER_CONN_OPTIONW_0 {
                pszValue: null_mut(),
            },
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
        if ok == 0 {
            return None;
        }
        let ptr = unsafe { opt.Value.pszValue };
        if ptr.is_null() {
            return None;
        }
        let mut len = 0usize;
        while len < 4096 && unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        let server = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ptr, len) });
        unsafe {
            GlobalFree(ptr as *mut c_void);
        }
        if server.trim().is_empty() {
            None
        } else {
            Some(server)
        }
    }

    /// Atomically updates Windows WinINet per-connection settings (including the authoritative
    /// `Connections\DefaultConnectionSettings` binary blob read by Edge/Chrome/Windows Settings).
    fn apply_wininet_per_conn(
        conn_name: Option<&str>,
        enable: bool,
        server: Option<&str>,
        bypass: Option<&str>,
        restore_flags: Option<u32>,
    ) -> Result<(), String> {
        let existing_flags = query_wininet_flags(conn_name);
        let flags = compute_wininet_flags(enable, existing_flags, restore_flags);

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
        let clean_server = server.map(strip_nul);
        match clean_server.as_deref().filter(|s| !s.trim().is_empty()) {
            Some(s) => {
                key.set_value("ProxyServer", &s)
                    .map_err(|e| RuntimeError::SystemProxy(e.to_string()))?;
            }
            None => {
                let _ = key.delete_value("ProxyServer");
            }
        }
        let clean_bypass = bypass.map(strip_nul);
        match clean_bypass.as_deref().filter(|o| !o.trim().is_empty()) {
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
        let proxy_server: Option<String> = key
            .get_value("ProxyServer")
            .ok()
            .or_else(|| query_wininet_proxy_server(None));
        let proxy_override: Option<String> = key.get_value("ProxyOverride").ok();

        // Also check WinINet `DefaultConnectionSettings` flags to detect Registry/WinINet desync
        // and capture PAC (`PROXY_TYPE_AUTO_PROXY_URL`) / WPAD (`PROXY_TYPE_AUTO_DETECT`) flags.
        let wininet_flags = query_wininet_flags(None);
        if let Some(flags) = wininet_flags {
            if (flags & PROXY_TYPE_PROXY) != 0 {
                proxy_enable = 1;
            }
        }

        Ok(SystemProxyBackup {
            proxy_enable,
            proxy_server,
            proxy_override,
            wininet_flags,
        })
    }

    pub fn set_proxy(server: &str, bypass: &str) -> Result<(), RuntimeError> {
        let wininet_res = apply_wininet_per_conn(None, true, Some(server), Some(bypass), None);
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

        let wininet_res =
            apply_wininet_per_conn(None, enable, server, bypass, backup.wininet_flags);
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
        let wininet_res = apply_wininet_per_conn(None, false, None, None, None);

        // Best-effort clear dial-up / PPPoE / VPN connection profiles under `Connections`
        // ONLY when their WinINet proxy server points to loopback — never wipe legitimate corporate VPN proxies.
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        if let Ok(conn_key) = hkcu.open_subkey(INTERNET_CONNECTIONS_PATH) {
            for item in conn_key.enum_values().flatten() {
                let name = item.0;
                if name.eq_ignore_ascii_case("DefaultConnectionSettings")
                    || name.eq_ignore_ascii_case("SavedLegacySettings")
                {
                    continue;
                }
                let conn_server = query_wininet_proxy_server(Some(&name));
                if is_loopback_proxy_server(conn_server.as_deref()) {
                    let _ = apply_wininet_per_conn(Some(&name), false, None, None, None);
                }
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

    /// Best-effort sweep used by the elevated NSIS pre-uninstall hook (`--cleanup-sysproxy`):
    /// clears loopback proxy entries across `HKCU` and all loaded user hives under `HKU\<SID>`
    /// (never touching legitimate non-loopback corporate proxies).
    pub fn cleanup_all_users_loopback() {
        let _ = force_disable_all();

        let hku = RegKey::predef(HKEY_USERS);
        for sid in hku.enum_keys().flatten() {
            if sid.eq_ignore_ascii_case(".DEFAULT")
                || sid.to_ascii_lowercase().ends_with("_classes")
            {
                continue;
            }
            let settings_path = format!(r"{sid}\{INTERNET_SETTINGS_PATH}");
            let Ok(key) = hku.open_subkey_with_flags(&settings_path, KEY_READ | KEY_WRITE) else {
                continue;
            };
            let enabled: u32 = key.get_value("ProxyEnable").unwrap_or(0);
            let server: Option<String> = key.get_value("ProxyServer").ok();
            if enabled != 0 && is_loopback_proxy_server(server.as_deref()) {
                let _ = key.set_value("ProxyEnable", &0u32);
                let _ = key.delete_value("ProxyServer");

                // Also clear PROXY_TYPE_PROXY (0x02) bit in `Connections\DefaultConnectionSettings`
                // while keeping PROXY_TYPE_DIRECT (0x01) + any PAC/WPAD flags intact.
                let conn_path = format!(r"{sid}\{INTERNET_CONNECTIONS_PATH}");
                if let Ok(conn_key) = hku.open_subkey_with_flags(&conn_path, KEY_READ | KEY_WRITE) {
                    if let Ok(mut raw) = conn_key.get_raw_value("DefaultConnectionSettings") {
                        if raw.bytes.len() >= 12 {
                            raw.bytes[8] = (raw.bytes[8] & !0x02) | 0x01;
                            let _ = conn_key.set_raw_value(
                                "DefaultConnectionSettings",
                                &RegValue {
                                    bytes: raw.bytes,
                                    vtype: raw.vtype,
                                },
                            );
                        }
                    }
                }
            }
        }
        notify_wininet();
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

    pub fn cleanup_all_users_loopback() {}
}

/// Headless uninstall helper: disables current-session WinINet proxy and sweeps any loaded
/// `HKU\<SID>` hives whose `ProxyServer` points to a loopback address (P0-5).
pub fn cleanup_all_users_loopback_proxies() {
    platform::cleanup_all_users_loopback();
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
                wininet_flags: Some(WININET_PROXY_TYPE_DIRECT | WININET_PROXY_TYPE_PROXY),
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
            wininet_flags: None,
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
            wininet_flags: None,
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
            wininet_flags: None,
        });

        let mut mgr = SystemProxyManager::new(&tmp_dir);
        assert!(mgr.recover_if_dirty_with(&mock).unwrap());
        assert_eq!(mock.current(), SystemProxyBackup::disabled());

        // Also heals on disable_and_restore when active == false and no backup file exists
        *mock.state.borrow_mut() = SystemProxyBackup {
            proxy_enable: 1,
            proxy_server: Some("http=127.0.0.1:17890;https=127.0.0.1:17890".into()),
            proxy_override: None,
            wininet_flags: None,
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
            wininet_flags: None,
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
            wininet_flags: Some(
                WININET_PROXY_TYPE_DIRECT
                    | WININET_PROXY_TYPE_PROXY
                    | WININET_PROXY_TYPE_AUTO_PROXY_URL,
            ),
        };
        let mock = MockProxyPlatform::new(corp.clone());

        let mut mgr = SystemProxyManager::new(&tmp_dir);
        // Must NOT touch corporate proxy on startup recovery
        assert!(!mgr.recover_if_dirty_with(&mock).unwrap());
        assert_eq!(mock.current(), corp);

        // Enable MaxQ -> sets 127.0.0.1:17890 -> disable -> faithfully restores corporate proxy + flags
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
            wininet_flags: None,
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
        assert!(!tmp_dir.join("sysproxy-backup.json.tmp").exists());

        // Simulate crash (forget drop by creating a second manager while backup exists)
        let mut recovered_mgr = SystemProxyManager::new(&tmp_dir);
        assert!(recovered_mgr.recover_if_dirty().unwrap());
        assert!(!tmp_dir.join("sysproxy-backup.json").exists());

        mgr.disable_and_restore().unwrap();
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn bypass_string_blocks_wildcard_and_injection_attacks() {
        let bypass = build_windows_bypass_string(&[
            "*".into(),
            "*.*".into(),
            "*.com".into(),
            "*.org".into(),
            "0.0.0.0/0".into(),
            "192.168.0.0/16".into(),
            "evil.com;*.net".into(),
            "bad\r\nhost".into(),
            "*.local".into(),
            "*.apple.com".into(),
            "172.20.*".into(),
        ]);
        let parts: Vec<&str> = bypass.split(';').collect();
        assert!(!parts.contains(&"*"));
        assert!(!parts.contains(&"*.*"));
        assert!(!parts.contains(&"*.com"));
        assert!(!parts.contains(&"*.org"));
        assert!(!parts.contains(&"0.0.0.0/0"));
        assert!(!parts.contains(&"*.net"));
        assert!(parts.contains(&"*.local"));
        assert!(parts.contains(&"*.apple.com"));
        assert!(parts.contains(&"172.20.*"));
        assert!(parts.contains(&"169.254.*"));
    }

    #[test]
    fn bypass_string_includes_full_rfc1918_172_16_through_31_range() {
        let bypass = build_windows_bypass_string(&[]);
        let parts: Vec<&str> = bypass.split(';').collect();
        for second in 16..=31 {
            let expected = format!("172.{second}.*");
            assert!(
                parts.contains(&expected.as_str()),
                "missing RFC 1918 entry {expected} in {bypass}"
            );
        }
        assert!(parts.contains(&"localhost"));
        assert!(parts.contains(&"127.*"));
        assert!(parts.contains(&"10.*"));
        assert!(parts.contains(&"192.168.*"));
        assert!(parts.contains(&"169.254.*"));
        assert!(parts.contains(&"<local>"));
    }

    #[test]
    fn strips_embedded_nul_bytes_from_backup_and_catches_nul_loopback() {
        let corp_with_nul = SystemProxyBackup {
            proxy_enable: 1,
            proxy_server: Some("10.0.0.5\0:8080".into()),
            proxy_override: Some("*.corp.internal\0;<local>".into()),
            wininet_flags: Some(WININET_PROXY_TYPE_DIRECT | WININET_PROXY_TYPE_PROXY),
        };
        let sanitized_corp = sanitize_backup(corp_with_nul);
        assert_eq!(sanitized_corp.proxy_enable, 1);
        assert_eq!(sanitized_corp.proxy_server.as_deref(), Some("10.0.0.5:8080"));
        assert_eq!(
            sanitized_corp.proxy_override.as_deref(),
            Some("*.corp.internal;<local>")
        );

        let smuggled_loopback = SystemProxyBackup {
            proxy_enable: 1,
            proxy_server: Some("127.0.0.1\0:17890".into()),
            proxy_override: Some("localhost\0".into()),
            wininet_flags: None,
        };
        assert_eq!(sanitize_backup(smuggled_loopback), SystemProxyBackup::disabled());
    }

    #[test]
    fn preserves_wininet_pac_and_wpad_flags_across_backup_and_restore() {
        let tmp_dir = unique_tmp_dir("pac_wpad_flags");
        let pac_wpad_flags = WININET_PROXY_TYPE_DIRECT
            | WININET_PROXY_TYPE_AUTO_PROXY_URL
            | WININET_PROXY_TYPE_AUTO_DETECT;

        let initial = SystemProxyBackup {
            proxy_enable: 0,
            proxy_server: None,
            proxy_override: None,
            wininet_flags: Some(pac_wpad_flags),
        };
        let mock = MockProxyPlatform::new(initial.clone());

        let mut mgr = SystemProxyManager::new(&tmp_dir);
        mgr.enable_with(&mock, 17890, &[]).unwrap();

        // While MaxQ is enabled, active flags are strictly DIRECT | PROXY
        assert_eq!(
            compute_wininet_flags(true, Some(pac_wpad_flags), None),
            WININET_PROXY_TYPE_DIRECT | WININET_PROXY_TYPE_PROXY
        );

        // Disconnecting restores original backup with PAC + WPAD flags intact
        mgr.disable_and_restore_with(&mock).unwrap();
        assert_eq!(mock.current(), initial);

        // Verify flag restoration math preserves AUTO_PROXY_URL (0x4) and AUTO_DETECT (0x8)
        let restored_disabled = compute_wininet_flags(
            false,
            Some(WININET_PROXY_TYPE_DIRECT | WININET_PROXY_TYPE_PROXY),
            Some(pac_wpad_flags | WININET_PROXY_TYPE_PROXY),
        );
        assert_eq!(restored_disabled, pac_wpad_flags);

        // Restoring an enabled corporate proxy with PAC/WPAD preserves all flags + PROXY
        let restored_corp = compute_wininet_flags(true, None, Some(pac_wpad_flags));
        assert_eq!(restored_corp, pac_wpad_flags | WININET_PROXY_TYPE_PROXY);

        // Legacy backup JSON without `wininet_flags` still deserializes cleanly
        let legacy: SystemProxyBackup = serde_json::from_str(
            r#"{"proxy_enable":0,"proxy_server":null,"proxy_override":null}"#,
        )
        .unwrap();
        assert_eq!(legacy.wininet_flags, None);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
