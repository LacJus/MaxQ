use serde::{Deserialize, Serialize};

/// Windows Service name registered with SCM.
pub const SERVICE_NAME: &str = "MaxQTunService";
pub const SERVICE_DISPLAY_NAME: &str = "MaxQ Hardened TUN Service";
pub const SERVICE_DESCRIPTION: &str =
    "Privileged minimal TUN helper for MaxQ (SDDL Named Pipe, caller image verified, SHA-256 pinned sing-box).";

/// Named Pipe path for authenticated local IPC.
pub const NAMED_PIPE_PATH: &str = r"\\.\pipe\maxq-tun-service-v1";

/// SDDL DACL for the Named Pipe:
/// - SY (LocalSystem): Generic All
/// - BA (Built-in Administrators): Generic All
/// - IU (Interactive Logged-on User): Explicit read/write mask 0x0012019b (strips FILE_CREATE_PIPE_INSTANCE 0x4
///   to prevent unprivileged pipe squatting, further gated by caller image path verification!)
pub const PIPE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0012019b;;;IU)";

/// Hardcoded official SHA-256 digest of `sing-box v1.14.4 windows-amd64` `sing-box.exe`.
/// Verified before every `CreateProcessW` call to eliminate arbitrary binary substitution LPE.
pub const SING_BOX_V14_4_WIN64_SHA256: &str =
    "8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9";

pub const SERVICE_PROTOCOL_VERSION: &str = "1.0.0";

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
