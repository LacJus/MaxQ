use serde::{Deserialize, Serialize};

/// Windows Service name registered with SCM.
pub const SERVICE_NAME: &str = "MaxQTunService";
pub const SERVICE_DISPLAY_NAME: &str = "MaxQ Hardened TUN Service";
pub const SERVICE_DESCRIPTION: &str =
    "Privileged minimal TUN helper for MaxQ (SDDL Named Pipe, caller image verified, SHA-256 pinned sing-box).";

/// Named Pipe path for authenticated local IPC.
pub const NAMED_PIPE_PATH: &str = r"\\.\pipe\maxq-tun-service-v1";

/// Explicit Interactive User (`IU`) access mask granted on the Named Pipe DACL.
/// Grants read/write data, attributes, EA, READ_CONTROL, and SYNCHRONIZE while STRIPPING
/// bit `0x0004` (`FILE_CREATE_PIPE_INSTANCE` / `FILE_APPEND_DATA`) to block pipe squatting.
pub const PIPE_IU_DACL_MASK: u32 = 0x0012_019b;

/// Exact `dwDesiredAccess` mask that non-elevated GUI clients MUST pass to `CreateFileW`
/// (`OpenOptionsExt::access_mode`) when connecting to `NAMED_PIPE_PATH`.
///
/// CRITICAL: Do NOT use `OpenOptions::read(true).write(true)` because Rust maps that to
/// `GENERIC_READ | GENERIC_WRITE`, and Windows expands `GENERIC_WRITE` on Named Pipes to
/// `FILE_GENERIC_WRITE` which includes `FILE_APPEND_DATA (0x0004)` == `FILE_CREATE_PIPE_INSTANCE`,
/// causing `ERROR_ACCESS_DENIED (os error 5)` against `PIPE_SDDL`!
pub const PIPE_CLIENT_ACCESS_MASK: u32 =
    0x0000_0001 // FILE_READ_DATA
    | 0x0000_0002 // FILE_WRITE_DATA
    | 0x0000_0080 // FILE_READ_ATTRIBUTES
    | 0x0000_0100 // FILE_WRITE_ATTRIBUTES
    | 0x0010_0000; // SYNCHRONIZE

/// SDDL DACL for the Named Pipe:
/// - SY (LocalSystem): Generic All
/// - BA (Built-in Administrators): Generic All
/// - IU (Interactive Logged-on User): Explicit read/write mask 0x0012019b (strips FILE_CREATE_PIPE_INSTANCE 0x4
///   to prevent unprivileged pipe squatting, further gated by caller image path verification!)
pub const PIPE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0012019b;;;IU)";

/// Read-only-for-Users diagnostics subdirectory under `%ProgramData%\MaxQ` used ONLY for
/// non-secret install/startup error text (writable strictly by SYSTEM and Administrators).
pub const DIAGNOSTIC_STATUS_SUBDIR: &str = "diagnostics";
pub const DIAGNOSTIC_STATUS_FILE: &str = "last-status.txt";

/// Hardcoded official SHA-256 digest of `sing-box v1.14.4 windows-amd64` `sing-box.exe`.
/// Verified before every `CreateProcessW` call to eliminate arbitrary binary substitution LPE.
pub const SING_BOX_V14_4_WIN64_SHA256: &str =
    "8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9";

pub const SERVICE_PROTOCOL_VERSION: &str = "1.0.1";

/// Strict zero-arbitrary-execution IPC command set.
/// NEVER accepts executable paths, CLI flags, or working directories.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum ServiceRequest {
    Ping,
    Status,
    StartTun { config_json: String },
    StopTun,
    GetLogs,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TunServiceStatus {
    pub installed: bool,
    pub running: bool,
    pub tun_active: bool,
    pub singbox_pid: Option<u32>,
    pub singbox_sha256_verified: bool,
    pub last_mitm_alert: Option<String>,
    pub version: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ServiceResponse {
    Pong {
        version: String,
        singbox_sha256_verified: bool,
    },
    Status(TunServiceStatus),
    Started {
        pid: u32,
    },
    Stopped,
    Logs {
        lines: Vec<String>,
    },
    Error {
        message: String,
    },
}

/// Parses `sing-box` runtime log lines for SPKI pin mismatch warnings
/// (`unrecognized remote public key: <base64_spki>`).
pub fn detect_singbox_log_pin_mismatch(log_line: &str) -> Option<String> {
    const NEEDLE: &str = "unrecognized remote public key:";
    let idx = log_line.find(NEEDLE)?;
    let tail = log_line[idx + NEEDLE.len()..].trim();
    let token = tail
        .split(|c: char| c.is_whitespace() || c == ',' || c == '"' || c == '\'')
        .next()?
        .trim();
    if token.len() >= 32 {
        Some(token.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_pipe_access_mask_is_strict_subset_of_sddl_without_create_pipe_instance() {
        const FILE_CREATE_PIPE_INSTANCE: u32 = 0x0000_0004;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const GENERIC_READ: u32 = 0x8000_0000;

        // Server DACL MUST strip FILE_CREATE_PIPE_INSTANCE (anti-pipe-squat)
        assert_eq!(PIPE_IU_DACL_MASK & FILE_CREATE_PIPE_INSTANCE, 0);
        // Client request mask MUST NOT request FILE_CREATE_PIPE_INSTANCE or GENERIC_READ/WRITE
        assert_eq!(PIPE_CLIENT_ACCESS_MASK & FILE_CREATE_PIPE_INSTANCE, 0);
        assert_eq!(PIPE_CLIENT_ACCESS_MASK & (GENERIC_READ | GENERIC_WRITE), 0);
        // Every requested client right MUST be granted by PIPE_IU_DACL_MASK (otherwise ERROR_ACCESS_DENIED!)
        assert_eq!(PIPE_CLIENT_ACCESS_MASK & !PIPE_IU_DACL_MASK, 0);
    }
}
