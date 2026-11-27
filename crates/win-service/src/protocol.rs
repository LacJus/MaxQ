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

pub const SERVICE_PROTOCOL_VERSION: &str = "1.0.4";

/// Strict zero-arbitrary-execution IPC command set.
/// NEVER accepts executable paths, CLI flags, or working directories.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum ServiceRequest {
    Ping,
    Status,
    StartTun {
        config_json: String,
        #[serde(default)]
        active_profile_id: Option<String>,
        #[serde(default)]
        active_node_id: Option<String>,
        #[serde(default)]
        active_node_name: Option<String>,
    },
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
    #[serde(default)]
    pub active_profile_id: Option<String>,
    #[serde(default)]
    pub active_node_id: Option<String>,
    #[serde(default)]
    pub active_node_name: Option<String>,
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

/// Redacts `<scheme>://<credentials>@` URL userinfo in-place across all occurrences.
fn redact_url_userinfo(out: &mut String) {
    let mut cursor = 0usize;
    while cursor < out.len() {
        let Some(rel_sep) = out[cursor..].find("://") else {
            break;
        };
        let sep_pos = cursor + rel_sep;

        // Verify there is a valid RFC-3986 URL scheme immediately preceding `://`
        let prefix = &out[..sep_pos];
        let scheme_len = prefix
            .bytes()
            .rev()
            .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
            .count();
        let has_valid_scheme = scheme_len > 0
            && prefix.as_bytes()[sep_pos - scheme_len].is_ascii_alphabetic();

        let cred_start = sep_pos + 3;
        if !has_valid_scheme || cred_start >= out.len() {
            cursor = cred_start.min(out.len());
            continue;
        }

        // Authority spans until the first delimiter terminating host[:port]
        let auth_end = out[cred_start..]
            .find(|c: char| {
                c.is_whitespace()
                    || matches!(
                        c,
                        '/' | '?' | '#' | '"' | '\'' | '<' | '>' | ',' | ';' | ')' | ']' | '}'
                    )
            })
            .map(|i| cred_start + i)
            .unwrap_or(out.len());

        if let Some(rel_at) = out[cred_start..auth_end].rfind('@') {
            let at_pos = cred_start + rel_at;
            if at_pos > cred_start && &out[cred_start..at_pos] != "<REDACTED>" {
                out.replace_range(cred_start..at_pos, "<REDACTED>");
                cursor = cred_start + "<REDACTED>".len() + 1;
            } else {
                cursor = at_pos + 1;
            }
        } else {
            cursor = auth_end.max(cred_start);
        }
    }
}

/// Case-insensitive, all-occurrences redaction of Bearer tokens, passwords, secrets,
/// UUIDs, Reality keys/short IDs, Salamander keys, URL userinfo, and auth parameters
/// before exposing runtime logs to the UI or diagnostics.
pub fn redact_log_line(line: &str) -> String {
    const MARKERS: &[&str] = &[
        "bearer ",
        "secret=",
        "\"secret\":",
        "password=",
        "\"password\":",
        "token=",
        "\"token\":",
        "auth=",
        "uuid=",
        "\"uuid\":",
        "public_key=",
        "\"public_key\":",
        "short_id=",
        "\"short_id\":",
        "salamander-password=",
        "salamander_password=",
        "\"salamander_password\":",
        "obfs-password=",
        "obfs_password=",
        "\"obfs_password\":",
        "salamander=",
        "salamander:",
        "\"salamander\":",
    ];

    let mut out = line.to_string();
    redact_url_userinfo(&mut out);

    for &marker in MARKERS {
        let mut cursor = 0usize;
        while cursor < out.len() {
            let lower_tail = out[cursor..].to_ascii_lowercase();
            let Some(rel_pos) = lower_tail.find(marker) else {
                break;
            };
            let mut val_start = cursor + rel_pos + marker.len();
            // Skip optional spaces and opening quote for JSON-style `"secret": "value"`
            let bytes = out.as_bytes();
            while val_start < bytes.len() && bytes[val_start] == b' ' {
                val_start += 1;
            }
            if val_start >= bytes.len() {
                break;
            }
            // Do not clobber nested JSON objects/arrays like `"salamander": { "password": "..." }`
            if matches!(bytes[val_start], b'{' | b'[') {
                cursor = val_start + 1;
                continue;
            }
            let quoted = bytes[val_start] == b'"';
            if quoted {
                val_start += 1;
            }
            if val_start >= out.len() {
                break;
            }
            let val_end = if quoted {
                // Respect escaped quotes `\"` inside JSON strings so redaction is not truncated early
                let b = out.as_bytes();
                let mut i = val_start;
                let mut escaped = false;
                while i < b.len() {
                    let ch = b[i];
                    if escaped {
                        escaped = false;
                    } else if ch == b'\\' {
                        escaped = true;
                    } else if ch == b'"' || ch == b'\n' || ch == b'\r' {
                        break;
                    }
                    i += 1;
                }
                i
            } else {
                out[val_start..]
                    .find(|c: char| {
                        c.is_whitespace()
                            || c == '"'
                            || c == '\''
                            || c == ','
                            || c == '&'
                            || c == ';'
                            || c == '}'
                            || c == ']'
                            || c == ')'
                    })
                    .map(|i| val_start + i)
                    .unwrap_or(out.len())
            };
            if val_end > val_start && &out[val_start..val_end] != "<REDACTED>" {
                out.replace_range(val_start..val_end, "<REDACTED>");
                cursor = val_start + "<REDACTED>".len();
            } else if val_end > val_start {
                cursor = val_end;
            } else {
                cursor = out[val_start..]
                    .chars()
                    .next()
                    .map_or(out.len(), |c| val_start + c.len_utf8());
            }
        }
    }
    out
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

    #[test]
    fn redacts_multiple_and_case_variant_secrets_from_logs() {
        let line = r#"Authorization: bearer tok12345 {"secret": "s3cr3tVal"} password=pw1&password=pw2 token=abc"#;
        let redacted = redact_log_line(line);
        assert!(!redacted.contains("tok12345"));
        assert!(!redacted.contains("s3cr3tVal"));
        assert!(!redacted.contains("pw1"));
        assert!(!redacted.contains("pw2"));
        assert!(!redacted.contains("abc"));
        assert!(redacted.contains("bearer <REDACTED>"));
        assert!(redacted.contains(r#""secret": "<REDACTED>""#));
        assert!(redacted.contains("password=<REDACTED>&password=<REDACTED>"));
    }

    #[test]
    fn redacts_uuid_reality_salamander_url_userinfo_and_escaped_quotes() {
        let line = concat!(
            r#"dial vless://550e8400-e29b-41d4-a716-446655440000@edge.example.com:443 "#,
            r#"hy2://user:p@ss99@hy2.example.com:443?obfs=salamander&obfs-password=salSecret1 "#,
            r#"{"uuid": "11111111-2222-3333-4444-555555555555", "public_key": "pubKeyXYZ", "short_id": "deadbeef", "#,
            r#""password": "a\"b\"cSecret", "salamander": "salJsonKey"} "#,
            r#"uuid=99999999-aaaa-bbbb-cccc-dddddddddddd salamander=salRawKey"#,
        );
        let redacted = redact_log_line(line);
        for leaked in [
            "550e8400-e29b-41d4-a716-446655440000",
            "user:p@ss99",
            "salSecret1",
            "11111111-2222-3333-4444-555555555555",
            "pubKeyXYZ",
            "deadbeef",
            "cSecret",
            "salJsonKey",
            "99999999-aaaa-bbbb-cccc-dddddddddddd",
            "salRawKey",
        ] {
            assert!(
                !redacted.contains(leaked),
                "leaked '{leaked}' in redacted line: {redacted}"
            );
        }
        assert!(redacted.contains("vless://<REDACTED>@edge.example.com:443"));
        assert!(redacted.contains("hy2://<REDACTED>@hy2.example.com:443"));
        assert!(redacted.contains(r#""password": "<REDACTED>""#));
        assert!(redacted.contains(r#""uuid": "<REDACTED>""#));
        assert!(redacted.contains(r#""public_key": "<REDACTED>""#));
        assert!(redacted.contains(r#""short_id": "<REDACTED>""#));
        assert!(redacted.contains(r#""salamander": "<REDACTED>""#));
        assert!(redacted.contains("uuid=<REDACTED>"));
        assert!(redacted.contains("salamander=<REDACTED>"));

        // Preserves URLs without credentials and nested JSON objects under salamander
        let safe = r#"GET https://example.com/path@v1 {"salamander": {"password": "nestedPw"}}"#;
        let safe_redacted = redact_log_line(safe);
        assert!(safe_redacted.contains("https://example.com/path@v1"));
        assert!(!safe_redacted.contains("nestedPw"));
        assert!(safe_redacted.contains(r#""salamander": {"password": "<REDACTED>"}"#));
    }
}
