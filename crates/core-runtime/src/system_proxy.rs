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

/// Manages Windows System Proxy (`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`)
/// with crash-safe backup & automatic restore.
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

    /// Recovers from a previous crash if a backup file was left behind on disk.
    pub fn recover_if_dirty(&mut self) -> Result<bool, RuntimeError> {
        if !self.backup_path.exists() {
            return Ok(false);
        }
        let raw = std::fs::read_to_string(&self.backup_path)?;
        let backup: SystemProxyBackup = serde_json::from_str(&raw)?;
        platform::apply_backup(&backup)?;
        let _ = std::fs::remove_file(&self.backup_path);
        self.active = false;
        Ok(true)
    }

    /// Backs up current settings (if not already backed up) and enables `127.0.0.1:<port>`.
    pub fn enable(&mut self, port: u16, bypass_list: &[String]) -> Result<(), RuntimeError> {
        if let Some(parent) = self.backup_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if !self.backup_path.exists() {
            let current = platform::read_current()?;
            std::fs::write(&self.backup_path, serde_json::to_string_pretty(&current)?)?;
        }
        let bypass = build_windows_bypass_string(bypass_list);
        platform::set_proxy(&format!("127.0.0.1:{port}"), &bypass)?;
        self.active = true;
        Ok(())
    }

    /// Restores the backed-up original settings and removes the backup file.
    pub fn disable_and_restore(&mut self) -> Result<(), RuntimeError> {
        if self.backup_path.exists() {
            let raw = std::fs::read_to_string(&self.backup_path)?;
            let backup: SystemProxyBackup = serde_json::from_str(&raw)?;
            platform::apply_backup(&backup)?;
            let _ = std::fs::remove_file(&self.backup_path);
        } else if self.active {
            platform::apply_backup(&SystemProxyBackup {
                proxy_enable: 0,
                proxy_server: None,
                proxy_override: None,
            })?;
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for SystemProxyManager {
    fn drop(&mut self) {
        if self.active {
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
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    use super::SystemProxyBackup;
    use crate::RuntimeError;

    const INTERNET_SETTINGS_PATH: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    fn notify_wininet() {
        unsafe {
            InternetSetOptionW(null_mut(), INTERNET_OPTION_SETTINGS_CHANGED, null(), 0);
            InternetSetOptionW(null_mut(), INTERNET_OPTION_REFRESH, null(), 0);
        }
    }

    pub fn read_current() -> Result<SystemProxyBackup, RuntimeError> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let key = hkcu
            .open_subkey(INTERNET_SETTINGS_PATH)
            .map_err(|e| RuntimeError::SystemProxy(e.to_string()))?;
        let proxy_enable: u32 = key.get_value("ProxyEnable").unwrap_or(0);
        let proxy_server: Option<String> = key.get_value("ProxyServer").ok();
        let proxy_override: Option<String> = key.get_value("ProxyOverride").ok();
        Ok(SystemProxyBackup {
            proxy_enable,
            proxy_server,
            proxy_override,
        })
    }

    pub fn set_proxy(server: &str, bypass: &str) -> Result<(), RuntimeError> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) = hkcu
            .create_subkey(INTERNET_SETTINGS_PATH)
            .map_err(|e| RuntimeError::SystemProxy(e.to_string()))?;
        key.set_value("ProxyEnable", &1u32)
            .map_err(|e| RuntimeError::SystemProxy(e.to_string()))?;
        key.set_value("ProxyServer", &server)
            .map_err(|e| RuntimeError::SystemProxy(e.to_string()))?;
        key.set_value("ProxyOverride", &bypass)
            .map_err(|e| RuntimeError::SystemProxy(e.to_string()))?;
        notify_wininet();
        Ok(())
    }

    pub fn apply_backup(backup: &SystemProxyBackup) -> Result<(), RuntimeError> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) = hkcu
            .create_subkey(INTERNET_SETTINGS_PATH)
            .map_err(|e| RuntimeError::SystemProxy(e.to_string()))?;
        key.set_value("ProxyEnable", &backup.proxy_enable)
            .map_err(|e| RuntimeError::SystemProxy(e.to_string()))?;
        match &backup.proxy_server {
            Some(s) => {
                let _ = key.set_value("ProxyServer", s);
            }
            None => {
                let _ = key.delete_value("ProxyServer");
            }
        }
        match &backup.proxy_override {
            Some(o) => {
                let _ = key.set_value("ProxyOverride", o);
            }
            None => {
                let _ = key.delete_value("ProxyOverride");
            }
        }
        notify_wininet();
        Ok(())
    }
}

#[cfg(not(windows))]
mod platform {
    use super::SystemProxyBackup;
    use crate::RuntimeError;

    pub fn read_current() -> Result<SystemProxyBackup, RuntimeError> {
        Ok(SystemProxyBackup {
            proxy_enable: 0,
            proxy_server: None,
            proxy_override: None,
        })
    }

    pub fn set_proxy(_server: &str, _bypass: &str) -> Result<(), RuntimeError> {
        Ok(())
    }

    pub fn apply_backup(_backup: &SystemProxyBackup) -> Result<(), RuntimeError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crash_safe_backup_and_recovery_lifecycle() {
        let tmp_dir = std::env::temp_dir().join("maxq_sysproxy_test");
        let _ = std::fs::remove_dir_all(&tmp_dir);

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
