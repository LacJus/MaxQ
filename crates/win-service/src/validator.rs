use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;

use serde_json::Value;
use sha2::{Digest, Sha256};

pub const MAX_CONFIG_BYTES: usize = 8 * 1024 * 1024; // 8 MiB

const ALLOWED_TOP_LEVEL_KEYS: &[&str] = &[
    "log",
    "dns",
    "inbounds",
    "outbounds",
    "route",
    "experimental",
];

const ALLOWED_OUTBOUND_TYPES: &[&str] = &[
    "direct",
    "trojan",
    "vless",
    "vmess",
    "anytls",
    "hysteria2",
    "tuic",
    "shadowsocks",
];

const FORBIDDEN_KEY_SUBSTRINGS: &[&str] = &[
    "path",
    "directory",
    "executable",
    "external_ui",
    "acme",
    "v2ray_api",
    "debug",
    "output",
];

/// Streams a binary file and verifies its SHA-256 matches `expected_hex` (case-insensitive).
pub fn verify_binary_sha256(path: &Path, expected_hex: &str) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|e| format!("failed to open '{}' for SHA-256 check: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("failed reading '{}': {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let actual = hex::encode(hasher.finalize());
    if !actual.eq_ignore_ascii_case(expected_hex.trim()) {
        return Err(format!(
            "sing-box.exe SHA-256 integrity mismatch! expected={}, actual={}",
            expected_hex.trim(),
            actual
        ));
    }
    Ok(actual)
}

/// Verifies that the IPC caller executable (`caller_exe`) belongs to the exact same
/// protected installation root as `service_exe`.
pub fn is_authorized_caller_image(service_exe: &Path, caller_exe: &Path) -> bool {
    let (svc_dir, _) = split_win_parent_and_name(&service_exe.to_string_lossy());
    let (caller_dir, caller_name) = split_win_parent_and_name(&caller_exe.to_string_lossy());
    if svc_dir.is_empty() || caller_dir.is_empty() || caller_name.is_empty() {
        return false;
    }

    let allowed_name = caller_name.eq_ignore_ascii_case("maxq-desktop.exe")
        || caller_name.eq_ignore_ascii_case("MaxQ.exe")
        || caller_name.eq_ignore_ascii_case("maxq-service.exe");
    if !allowed_name {
        return false;
    }

    if caller_dir == svc_dir {
        return true;
    }
    let (svc_parent, svc_dir_name) = split_win_parent_and_name(&svc_dir);
    if svc_dir_name.eq_ignore_ascii_case("resources")
        && !svc_parent.is_empty()
        && caller_dir == svc_parent
    {
        return true;
    }
    false
}

fn split_win_parent_and_name(raw: &str) -> (String, String) {
    let normalized = raw
        .trim()
        .trim_start_matches(r"\\?\")
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    match normalized.rsplit_once('\\') {
        Some((parent, name)) => (parent.to_string(), name.to_string()),
        None => (String::new(), normalized),
    }
}

/// Strict allowlist validator executed inside the privileged `LocalSystem` TUN service
/// BEFORE writing `active-tun.json` and launching `sing-box.exe`.
///
/// Defends against:
/// - Go `encoding/json` case-insensitive key matching bypasses (C-1)
/// - Arbitrary file write/read via `log.output`, `endpoints`, `services`, `certificate`, `rule_set`, `*_path`, `*_directory` (C-2)
/// - `pprof` / `v2ray_api` / `external_ui` / non-Tauri CORS / LAN listeners (C-2)
/// - Public CIDR or `route_address` TUN bypasses (C-2)
pub fn validate_service_config(config_json: &str) -> Result<Value, String> {
    if config_json.len() > MAX_CONFIG_BYTES {
        return Err("config JSON exceeds 8 MiB safety limit".into());
    }
    let root: Value =
        serde_json::from_str(config_json).map_err(|e| format!("invalid JSON: {e}"))?;
    let root_obj = root
        .as_object()
        .ok_or_else(|| "root config must be a JSON object".to_string())?;

    // 1. Recursive lowercase & forbidden-key walk (blocks Go encoding/json EqualFold bypasses! C-1 & C-2)
    audit_json_keys_recursively(&root, false, false)?;

    // 2. Strict top-level key allowlist (blocks `endpoints`, `services`, `certificate`, etc.)
    for key in root_obj.keys() {
        if !ALLOWED_TOP_LEVEL_KEYS.contains(&key.as_str()) {
            return Err(format!("top-level key '{key}' is not allowed in TUN service"));
        }
    }

    // 3. Validate experimental section (allow ONLY hardened `clash_api`)
    if let Some(exp) = root_obj.get("experimental") {
        let exp_obj = exp
            .as_object()
            .ok_or_else(|| "experimental must be an object".to_string())?;
        for key in exp_obj.keys() {
            if key != "clash_api" {
                return Err(format!(
                    "experimental.{key} is not allowed in TUN service"
                ));
            }
        }
        if let Some(api) = exp_obj.get("clash_api") {
            let api_obj = api
                .as_object()
                .ok_or_else(|| "clash_api must be an object".to_string())?;
            if api_obj
                .get("access_control_allow_private_network")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                return Err("clash_api.access_control_allow_private_network must be false".into());
            }
            let ctrl = api_obj
                .get("external_controller")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !ctrl.starts_with("127.0.0.1:") {
                return Err("clash_api.external_controller must bind strictly to 127.0.0.1".into());
            }
            let secret = api_obj.get("secret").and_then(|v| v.as_str()).unwrap_or("");
            if secret.len() < 32 || secret.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err("clash_api.secret must be >= 32 non-whitespace characters".into());
            }
            let origins = api_obj
                .get("access_control_allow_origin")
                .and_then(|v| v.as_array())
                .ok_or_else(|| "clash_api.access_control_allow_origin must be set".to_string())?;
            if origins.is_empty()
                || !origins.iter().all(|o| {
                    matches!(
                        o.as_str(),
                        Some("http://tauri.localhost" | "https://tauri.localhost")
                    )
                })
            {
                return Err("clash_api CORS origins must be strictly http(s)://tauri.localhost".into());
            }
        }
    }

    // 4. Validate outbounds strictly against allowed protocol types
    let outbounds = root_obj
        .get("outbounds")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing outbounds array".to_string())?;
    for (idx, ob) in outbounds.iter().enumerate() {
        let ob_type = ob
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("outbounds[{idx}] missing type"))?;
        if !ALLOWED_OUTBOUND_TYPES.contains(&ob_type) {
            return Err(format!("outbound type '{ob_type}' is not allowed in TUN service"));
        }
    }

    // 5. Forbid external route.rule_set inside SYSTEM service
    if let Some(route) = root_obj.get("route") {
        if route.get("rule_set").is_some() {
            return Err("route.rule_set is forbidden in TUN service".into());
        }
    }

    // 6. Validate inbounds strictly: ONLY `tun` (private CIDRs only, no route_address/platform) and optional loopback `mixed`
    let inbounds = root_obj
        .get("inbounds")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing inbounds array".to_string())?;
    let mut has_tun = false;
    for (idx, ib) in inbounds.iter().enumerate() {
        let ib_type = ib
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("inbounds[{idx}] missing type"))?;
        match ib_type {
            "tun" => {
                has_tun = true;
                if ib.get("route_address").is_some()
                    || ib.get("route_address_set").is_some()
                    || ib.get("route_exclude_address_set").is_some()
                    || ib.get("platform").is_some()
                {
                    return Err("forbidden tun routing override field detected".into());
                }
                if let Some(excluded) = ib.get("route_exclude_address").and_then(|v| v.as_array()) {
                    for item in excluded {
                        let cidr = item
                            .as_str()
                            .ok_or_else(|| "non-string route_exclude_address".to_string())?;
                        if !is_strictly_private_cidr(cidr) {
                            return Err(format!(
                                "non-private CIDR '{cidr}' forbidden in tun.route_exclude_address"
                            ));
                        }
                    }
                }
            }
            "mixed" => {
                let listen = ib.get("listen").and_then(|v| v.as_str()).unwrap_or("");
                if listen != "127.0.0.1" {
                    return Err("mixed inbound in TUN service must bind strictly to 127.0.0.1".into());
                }
            }
            other => {
                return Err(format!("inbound type '{other}' is not allowed in TUN service"));
            }
        }
    }
    if !has_tun {
        return Err("StartTun config must contain a tun inbound".into());
    }

    Ok(root)
}

/// Recursively audits every JSON object key in the configuration:
/// - Rejects any non-lowercase ASCII schema key (defeating Go `encoding/json` case-insensitive bypasses)
/// - Rejects any key matching dangerous file/exec/debug patterns
/// Exempts user value maps (`predefined` host map and HTTP `headers` map).
fn audit_json_keys_recursively(
    val: &Value,
    inside_freeform_map: bool,
    inside_transport: bool,
) -> Result<(), String> {
    match val {
        Value::Object(map) => {
            for (k, v) in map {
                if !inside_freeform_map {
                    if k.chars().any(|c| c.is_ascii_uppercase()) {
                        return Err(format!(
                            "non-lowercase config key '{k}' rejected (anti-EqualFold bypass)"
                        ));
                    }
                    // Allow HTTP URL path strictly inside `transport` (e.g. WebSocket `/ws`)
                    let is_safe_transport_path = inside_transport
                        && k == "path"
                        && v.as_str()
                            .is_some_and(|s| s.starts_with('/') && !s.contains('\\') && !s.contains(".."));
                    if !is_safe_transport_path {
                        let lower = k.to_ascii_lowercase();
                        for bad in FORBIDDEN_KEY_SUBSTRINGS {
                            if lower.contains(bad) {
                                return Err(format!(
                                    "forbidden config key '{k}' rejected by TUN service"
                                ));
                            }
                        }
                    }
                }
                let child_freeform = inside_freeform_map || k == "predefined" || k == "headers";
                let child_transport = k == "transport";
                audit_json_keys_recursively(v, child_freeform, child_transport)?;
            }
        }
        Value::Array(arr) => {
            for item in arr {
                audit_json_keys_recursively(item, inside_freeform_map, false)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn is_strictly_private_cidr(cidr: &str) -> bool {
    let Some((ip_part, prefix_part)) = cidr.trim().split_once('/') else {
        return false;
    };
    let Ok(ip) = ip_part.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix_part.parse::<u8>() else {
        return false;
    };
    match ip {
        IpAddr::V4(v4) => {
            if prefix > 32 {
                return false;
            }
            let o = v4.octets();
            (o[0] == 10 && prefix >= 8)
                || (o[0] == 127 && prefix >= 8)
                || (o[0] == 100 && (o[1] & 0b1100_0000) == 64 && prefix >= 10)
                || (o[0] == 169 && o[1] == 254 && prefix >= 16)
                || (o[0] == 172 && (16..=31).contains(&o[1]) && prefix >= 12)
                || (o[0] == 192 && o[1] == 168 && prefix >= 16)
                || (o[0] >= 224 && prefix >= 4)
        }
        IpAddr::V6(v6) => {
            if prefix > 128 {
                return false;
            }
            let s = v6.segments();
            (v6.is_loopback() && prefix == 128)
                || ((s[0] & 0xfe00) == 0xfc00 && prefix >= 7)
                || ((s[0] & 0xffc0) == 0xfe80 && prefix >= 10)
                || ((s[0] & 0xff00) == 0xff00 && prefix >= 8)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn verifies_authorized_caller_paths_strictly() {
        let svc = Path::new(r"C:\Program Files\MaxQ\resources\maxq-service.exe");
        assert!(is_authorized_caller_image(
            svc,
            Path::new(r"C:\Program Files\MaxQ\maxq-desktop.exe")
        ));
        assert!(is_authorized_caller_image(
            svc,
            Path::new(r"\\?\C:\Program Files\MaxQ\MaxQ.exe")
        ));
        assert!(!is_authorized_caller_image(
            svc,
            Path::new(r"C:\Users\alice\AppData\Local\Temp\maxq-desktop.exe")
        ));
        assert!(!is_authorized_caller_image(
            svc,
            Path::new(r"C:\Program Files\MaxQ\powershell.exe")
        ));
    }

    #[test]
    fn blocks_lpe_config_injection_and_case_bypass_vectors() {
        let valid_ws = json!({
            "log": { "level": "info" },
            "inbounds": [
                { "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 17890 },
                { "type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"], "route_exclude_address": ["192.168.0.0/16"] }
            ],
            "outbounds": [
                { "type": "trojan", "tag": "proxy", "server": "edge.example.com", "server_port": 443, "password": "pw", "transport": { "type": "ws", "path": "/ws", "headers": { "Host": "cdn.example.com" } } },
                { "type": "direct", "tag": "direct" }
            ],
            "experimental": {
                "clash_api": {
                    "external_controller": "127.0.0.1:19090",
                    "secret": "a".repeat(64),
                    "access_control_allow_origin": ["http://tauri.localhost"],
                    "access_control_allow_private_network": false
                }
            }
        });
        assert!(validate_service_config(&valid_ws.to_string()).is_ok());

        // C-1: Case-insensitive Go EqualFold bypass MUST be rejected
        let mut evil_case = valid_ws.clone();
        evil_case["log"]["Output"] = json!(r"C:\Windows\System32\evil.dll");
        assert!(validate_service_config(&evil_case.to_string()).is_err());

        // C-2: Disallowed top-level `endpoints` / `services` / `experimental.debug` rejected
        let mut evil_endpoints = valid_ws.clone();
        evil_endpoints["endpoints"] = json!([{ "type": "tailscale", "state_directory": "C:\\evil" }]);
        assert!(validate_service_config(&evil_endpoints.to_string()).is_err());

        let mut evil_debug = valid_ws.clone();
        evil_debug["experimental"]["debug"] = json!({ "listen": "0.0.0.0:6060" });
        assert!(validate_service_config(&evil_debug.to_string()).is_err());

        // C-2: Non-Tauri CORS rejected
        let mut evil_cors = valid_ws.clone();
        evil_cors["experimental"]["clash_api"]["access_control_allow_origin"] =
            json!(["https://attacker.example"]);
        assert!(validate_service_config(&evil_cors.to_string()).is_err());

        // C-2: Public CIDR bypass rejected
        let mut evil_tun = valid_ws.clone();
        evil_tun["inbounds"][1]["route_exclude_address"] = json!(["0.0.0.0/0"]);
        assert!(validate_service_config(&evil_tun.to_string()).is_err());

        // C-2: Disallowed outbound type (`tor` / `ssh`) rejected
        let mut evil_ob = valid_ws.clone();
        evil_ob["outbounds"] = json!([{ "type": "tor", "tag": "p" }]);
        assert!(validate_service_config(&evil_ob.to_string()).is_err());
    }
}
