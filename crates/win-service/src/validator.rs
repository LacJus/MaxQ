use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

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

/// Streams a file and returns its lowercase hexadecimal SHA-256 digest.
pub fn compute_file_sha256(path: &Path) -> Result<String, String> {
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
    Ok(hex::encode(hasher.finalize()))
}

/// Streams a binary file and verifies its SHA-256 matches `expected_hex` (case-insensitive).
pub fn verify_binary_sha256(path: &Path, expected_hex: &str) -> Result<String, String> {
    let actual = compute_file_sha256(path)?;
    if !actual.eq_ignore_ascii_case(expected_hex.trim()) {
        return Err(format!(
            "sing-box.exe SHA-256 integrity mismatch! expected={}, actual={}",
            expected_hex.trim(),
            actual
        ));
    }
    Ok(actual)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileFingerprint {
    path: PathBuf,
    len: u64,
    modified: SystemTime,
    #[cfg(windows)]
    creation_time: u64,
    #[cfg(windows)]
    last_write_time: u64,
}

#[derive(Debug, Clone)]
struct CachedVerificationEntry {
    fingerprint: FileFingerprint,
    expected_hex_lower: String,
    verified: bool,
}

fn snapshot_regular_file(path: &Path) -> Option<FileFingerprint> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return None;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return None;
        }
    }
    let modified = meta.modified().ok()?;
    Some(FileFingerprint {
        path: path.to_path_buf(),
        len: meta.len(),
        modified,
        #[cfg(windows)]
        creation_time: {
            use std::os::windows::fs::MetadataExt;
            meta.creation_time()
        },
        #[cfg(windows)]
        last_write_time: {
            use std::os::windows::fs::MetadataExt;
            meta.last_write_time()
        },
    })
}

/// Metadata-keyed cache for read-only `Ping` / `Status` SHA-256 health checks.
///
/// SECURITY INVARIANT:
/// - `is_verified()` is strictly for read-only status reporting so frequent GUI polling does not
///   re-read and hash the ~35 MB `sing-box.exe` binary every 1.8 seconds.
/// - Process launch (`StartTun`) MUST always call `verify_uncached_and_refresh()`, which performs
///   an unconditional full-file cryptographic SHA-256 check immediately before `Command::spawn()`.
/// - Symlinks and NTFS reparse points are rejected and never cached.
#[derive(Debug, Default)]
pub struct CachedBinaryVerifier {
    entry: Option<CachedVerificationEntry>,
    #[cfg(test)]
    hash_computations: usize,
}

impl CachedBinaryVerifier {
    /// Returns cached verification status when `(path, len, mtime[, creation/write_time])` is
    /// unchanged; otherwise streams and hashes the file once and caches the result if metadata
    /// remained stable across the hash.
    pub fn is_verified(&mut self, path: &Path, expected_hex: &str) -> bool {
        let Some(before) = snapshot_regular_file(path) else {
            self.entry = None;
            return false;
        };
        let expected_lower = expected_hex.trim().to_ascii_lowercase();
        if let Some(cached) = &self.entry {
            if cached.fingerprint == before && cached.expected_hex_lower == expected_lower {
                return cached.verified;
            }
        }

        #[cfg(test)]
        {
            self.hash_computations += 1;
        }
        let verified = verify_binary_sha256(path, expected_hex).is_ok();
        if let Some(after) = snapshot_regular_file(path) {
            if after == before {
                self.entry = Some(CachedVerificationEntry {
                    fingerprint: after,
                    expected_hex_lower: expected_lower,
                    verified,
                });
            } else {
                self.entry = None;
            }
        } else {
            self.entry = None;
        }
        verified
    }

    /// Always performs a full, uncached SHA-256 verification immediately before launching
    /// `sing-box.exe`, rejecting symlinks/reparse points and mid-hash TOCTOU changes, then
    /// refreshes the status cache.
    pub fn verify_uncached_and_refresh(
        &mut self,
        path: &Path,
        expected_hex: &str,
    ) -> Result<String, String> {
        let before = snapshot_regular_file(path).ok_or_else(|| {
            self.entry = None;
            format!(
                "refusing missing, non-regular, or symlink binary '{}'",
                path.display()
            )
        })?;

        #[cfg(test)]
        {
            self.hash_computations += 1;
        }
        let res = verify_binary_sha256(path, expected_hex);
        let expected_lower = expected_hex.trim().to_ascii_lowercase();
        match snapshot_regular_file(path) {
            Some(after) if after == before => {
                self.entry = Some(CachedVerificationEntry {
                    fingerprint: after,
                    expected_hex_lower: expected_lower,
                    verified: res.is_ok(),
                });
                res
            }
            _ => {
                self.entry = None;
                Err(format!(
                    "binary '{}' changed during SHA-256 verification (TOCTOU detected)",
                    path.display()
                ))
            }
        }
    }

    pub fn invalidate(&mut self) {
        self.entry = None;
    }
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

const FORBIDDEN_TUN_FIELDS: &[&str] = &[
    "route_address",
    "route_address_set",
    "route_exclude_address_set",
    "platform",
    "inet4_route_address",
    "inet6_route_address",
    "inet4_route_exclude_address",
    "inet6_route_exclude_address",
    "include_interface",
    "exclude_interface",
    "include_uid",
    "exclude_uid",
    "include_package",
    "exclude_package",
];

const ALLOWED_SHADOWSOCKS_PLUGINS: &[&str] = &["obfs-local", "v2ray-plugin"];

fn strip_win_verbatim_prefix(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.len() >= 8 && trimmed[..8].eq_ignore_ascii_case(r"\\?\UNC\") {
        format!(r"\\{}", &trimmed[8..])
    } else if let Some(stripped) = trimmed.strip_prefix(r"\\?\") {
        stripped.to_string()
    } else {
        trimmed.to_string()
    }
}

fn split_win_parent_and_name(raw: &str) -> (String, String) {
    let normalized = strip_win_verbatim_prefix(raw)
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase();
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
            let Some(port_str) = ctrl.strip_prefix("127.0.0.1:") else {
                return Err("clash_api.external_controller must bind strictly to 127.0.0.1".into());
            };
            let port = port_str.parse::<u16>().map_err(|_| {
                "clash_api.external_controller must specify a valid port on 127.0.0.1".to_string()
            })?;
            if port < 1024 {
                return Err(format!(
                    "clash_api.external_controller port {port} must be >= 1024"
                ));
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

    // 4. Validate outbounds strictly against allowed protocol types, plugin allowlist, and inline cert/key bans
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
        if ob_type == "shadowsocks" {
            if let Some(plugin_val) = ob.get("plugin").filter(|v| !v.is_null()) {
                let plugin = plugin_val.as_str().ok_or_else(|| {
                    format!("outbounds[{idx}].plugin must be a string")
                })?;
                if !ALLOWED_SHADOWSOCKS_PLUGINS.contains(&plugin) {
                    return Err(format!(
                        "shadowsocks plugin '{plugin}' is not allowed in TUN service"
                    ));
                }
            }
        }
        audit_outbound_inline_secrets(ob, false)?;
    }

    // 5. Forbid external route.rule_set inside SYSTEM service
    if let Some(route) = root_obj.get("route") {
        if route.get("rule_set").is_some() {
            return Err("route.rule_set is forbidden in TUN service".into());
        }
    }

    // 6. Validate inbounds strictly: ONLY `tun` (private/RFC-2544 CIDRs only, no routing/interface/uid/package overrides) and optional loopback `mixed`
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
                for &forbidden in FORBIDDEN_TUN_FIELDS {
                    if ib.get(forbidden).is_some() {
                        return Err(format!(
                            "forbidden tun field '{forbidden}' detected"
                        ));
                    }
                }
                for addr_field in ["address", "inet4_address", "inet6_address"] {
                    if let Some(addr_val) = ib.get(addr_field) {
                        validate_tun_address_field(addr_field, addr_val)?;
                    }
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
                if let Some(port_val) = ib.get("listen_port") {
                    let port = port_val.as_u64().ok_or_else(|| {
                        "mixed inbound listen_port must be an integer".to_string()
                    })?;
                    if !(1024..=65535).contains(&port) {
                        return Err(format!(
                            "mixed inbound listen_port {port} must be in 1024..=65535"
                        ));
                    }
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

/// Rejects inline `"certificate"` and `"key"` keys inside `outbounds` while continuing to allow
/// `"certificate_public_key_sha256"` and Reality `"public_key"`.
fn audit_outbound_inline_secrets(val: &Value, inside_freeform_map: bool) -> Result<(), String> {
    match val {
        Value::Object(map) => {
            for (k, v) in map {
                if !inside_freeform_map && (k == "certificate" || k == "key") {
                    return Err(format!(
                        "inline '{k}' key is forbidden inside outbounds in TUN service"
                    ));
                }
                let child_freeform = inside_freeform_map || k == "headers";
                audit_outbound_inline_secrets(v, child_freeform)?;
            }
        }
        Value::Array(arr) => {
            for item in arr {
                audit_outbound_inline_secrets(item, inside_freeform_map)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_tun_address_field(field: &str, val: &Value) -> Result<(), String> {
    match val {
        Value::String(cidr) => {
            if !is_allowed_tun_address_cidr(cidr) {
                return Err(format!(
                    "non-private CIDR '{cidr}' forbidden in tun.{field}"
                ));
            }
            Ok(())
        }
        Value::Array(arr) => {
            if arr.is_empty() {
                return Err(format!("tun.{field} array must not be empty"));
            }
            for item in arr {
                let cidr = item
                    .as_str()
                    .ok_or_else(|| format!("non-string entry in tun.{field}"))?;
                if !is_allowed_tun_address_cidr(cidr) {
                    return Err(format!(
                        "non-private CIDR '{cidr}' forbidden in tun.{field}"
                    ));
                }
            }
            Ok(())
        }
        _ => Err(format!("tun.{field} must be a CIDR string or array of CIDR strings")),
    }
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
            let is_https_doh_obj =
                map.get("type").and_then(|t| t.as_str()) == Some("https") && map.get("server").is_some();
            for (k, v) in map {
                if !inside_freeform_map {
                    if k.chars().any(|c| c.is_ascii_uppercase()) {
                        return Err(format!(
                            "non-lowercase config key '{k}' rejected (anti-EqualFold bypass)"
                        ));
                    }
                    // Allow HTTP URL path strictly inside `transport` (e.g. WebSocket `/ws`) or
                    // an `https` DoH DNS server object (e.g. `/dns-query`), never filesystem paths
                    let is_safe_http_url_path = (inside_transport || is_https_doh_obj)
                        && k == "path"
                        && v.as_str().is_some_and(|s| {
                            s.starts_with('/')
                                && !s.contains('\\')
                                && !s.contains("..")
                                && !s.chars().any(|c| c.is_whitespace() || c.is_control())
                        });
                    if !is_safe_http_url_path {
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

/// Validates allowed `tun.address` CIDRs strictly within RFC-1918 / RFC-6598 / RFC-2544 / RFC-4193:
/// `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `198.18.0.0/15`, `fc00::/7`.
fn is_allowed_tun_address_cidr(cidr: &str) -> bool {
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
                || (o[0] == 172 && (16..=31).contains(&o[1]) && prefix >= 12)
                || (o[0] == 192 && o[1] == 168 && prefix >= 16)
                || (o[0] == 100 && (o[1] & 0b1100_0000) == 64 && prefix >= 10)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19) && prefix >= 15)
        }
        IpAddr::V6(v6) => {
            if prefix > 128 {
                return false;
            }
            let s = v6.segments();
            (s[0] & 0xfe00) == 0xfc00 && prefix >= 7
        }
    }
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
        // UNC verbatim path mapping (`\\?\UNC\server\share` -> `\\server\share`) & Unicode case folding
        assert!(is_authorized_caller_image(
            Path::new(r"\\filesrv\ÜBER\MaxQ\resources\maxq-service.exe"),
            Path::new(r"\\?\UNC\filesrv\über\MaxQ\MaxQ.exe")
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
                {
                    "type": "trojan",
                    "tag": "proxy",
                    "server": "edge.example.com",
                    "server_port": 443,
                    "password": "pw",
                    "tls": {
                        "enabled": true,
                        "certificate_public_key_sha256": ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],
                        "reality": { "enabled": true, "public_key": "pubKeyTest", "short_id": "abcd" }
                    },
                    "transport": { "type": "ws", "path": "/ws", "headers": { "Host": "cdn.example.com" } }
                },
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

        // Allowed RFC-2544 + ULA IPv6 + CGNAT TUN addresses MUST pass
        let mut allowed_tun_addrs = valid_ws.clone();
        allowed_tun_addrs["inbounds"][1]["address"] = json!([
            "198.18.0.1/30",
            "fdfe:dcba:9876::1/126",
            "100.64.0.0/10"
        ]);
        assert!(validate_service_config(&allowed_tun_addrs.to_string()).is_ok());

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

        // C-2: Public CIDR bypass in route_exclude_address and tun.address rejected
        let mut evil_tun = valid_ws.clone();
        evil_tun["inbounds"][1]["route_exclude_address"] = json!(["0.0.0.0/0"]);
        assert!(validate_service_config(&evil_tun.to_string()).is_err());

        for bad_addr in ["8.8.8.8/32", "1.1.1.1/24", "198.20.0.1/30", "2001:db8::1/64", "10.0.0.0/7"] {
            let mut bad_tun_addr = valid_ws.clone();
            bad_tun_addr["inbounds"][1]["address"] = json!([bad_addr]);
            assert!(
                validate_service_config(&bad_tun_addr.to_string()).is_err(),
                "expected tun.address '{bad_addr}' to be rejected"
            );
        }

        // All forbidden tun override fields rejected
        for &field in FORBIDDEN_TUN_FIELDS {
            let mut bad_tun_field = valid_ws.clone();
            bad_tun_field["inbounds"][1][field] = json!(["10.0.0.0/8"]);
            assert!(
                validate_service_config(&bad_tun_field.to_string()).is_err(),
                "expected tun.{field} to be rejected"
            );
        }

        // C-2: Disallowed outbound type (`tor` / `ssh`) rejected
        let mut evil_ob = valid_ws.clone();
        evil_ob["outbounds"] = json!([{ "type": "tor", "tag": "p" }]);
        assert!(validate_service_config(&evil_ob.to_string()).is_err());

        // Shadowsocks plugin allowlist (`obfs-local` / `v2ray-plugin` allowed; arbitrary binaries rejected)
        for allowed_plugin in ["obfs-local", "v2ray-plugin"] {
            let mut ok_ss = valid_ws.clone();
            ok_ss["outbounds"] = json!([
                { "type": "shadowsocks", "tag": "ss", "server": "1.2.3.4", "server_port": 8388, "method": "aes-256-gcm", "password": "pw", "plugin": allowed_plugin },
                { "type": "direct", "tag": "direct" }
            ]);
            assert!(validate_service_config(&ok_ss.to_string()).is_ok());
        }
        for bad_plugin in [r"C:\Windows\System32\cmd.exe", "../evil", "custom-plugin", ""] {
            let mut bad_ss = valid_ws.clone();
            bad_ss["outbounds"] = json!([
                { "type": "shadowsocks", "tag": "ss", "server": "1.2.3.4", "server_port": 8388, "method": "aes-256-gcm", "password": "pw", "plugin": bad_plugin },
                { "type": "direct", "tag": "direct" }
            ]);
            assert!(
                validate_service_config(&bad_ss.to_string()).is_err(),
                "expected shadowsocks plugin '{bad_plugin}' to be rejected"
            );
        }

        // Inline `certificate` and `key` inside outbounds rejected
        let mut evil_inline_cert = valid_ws.clone();
        evil_inline_cert["outbounds"][0]["tls"]["certificate"] = json!("-----BEGIN CERTIFICATE-----");
        assert!(validate_service_config(&evil_inline_cert.to_string()).is_err());

        let mut evil_inline_key = valid_ws.clone();
        evil_inline_key["outbounds"][0]["tls"]["key"] = json!("-----BEGIN PRIVATE KEY-----");
        assert!(validate_service_config(&evil_inline_key.to_string()).is_err());

        // Privileged ports (< 1024) rejected for mixed.listen_port and clash_api.external_controller
        let mut evil_mixed_port = valid_ws.clone();
        evil_mixed_port["inbounds"][0]["listen_port"] = json!(80);
        assert!(validate_service_config(&evil_mixed_port.to_string()).is_err());

        let mut evil_clash_port = valid_ws.clone();
        evil_clash_port["experimental"]["clash_api"]["external_controller"] = json!("127.0.0.1:443");
        assert!(validate_service_config(&evil_clash_port.to_string()).is_err());
    }

    #[test]
    fn cached_binary_verifier_hashes_once_and_invalidates_on_change() {
        let dir = std::env::temp_dir().join(format!(
            "maxq_cached_verifier_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("sing-box-fake.bin");

        let good_bytes = b"maxq-singbox-authentic-payload-v1.14.4";
        std::fs::write(&bin, good_bytes).unwrap();
        let expected_sha = hex::encode(Sha256::digest(good_bytes));

        let mut verifier = CachedBinaryVerifier::default();
        for _ in 0..5 {
            assert!(verifier.is_verified(&bin, &expected_sha));
        }
        assert_eq!(
            verifier.hash_computations, 1,
            "repeated Status/Ping queries must hit metadata cache after initial hash"
        );

        // Tamper with file (different length guarantees immediate fingerprint mismatch)
        std::fs::write(&bin, b"tampered-binary-payload-longer-bytes").unwrap();
        assert!(!verifier.is_verified(&bin, &expected_sha));
        assert_eq!(verifier.hash_computations, 2);

        // Repeated status polls against an unchanged bad binary must also not spin-hash
        assert!(!verifier.is_verified(&bin, &expected_sha));
        assert_eq!(verifier.hash_computations, 2);

        // Restore authentic bytes -> detected immediately and re-verified once
        std::fs::write(&bin, good_bytes).unwrap();
        assert!(verifier.is_verified(&bin, &expected_sha));
        assert_eq!(verifier.hash_computations, 3);

        // Security-critical StartTun path MUST always re-hash unconditionally
        assert!(verifier
            .verify_uncached_and_refresh(&bin, &expected_sha)
            .is_ok());
        assert_eq!(verifier.hash_computations, 4);

        // Subsequent Status call after StartTun reuses refreshed cache without re-hashing
        assert!(verifier.is_verified(&bin, &expected_sha));
        assert_eq!(verifier.hash_computations, 4);

        // Deleting file immediately reports unverified
        std::fs::remove_file(&bin).unwrap();
        assert!(!verifier.is_verified(&bin, &expected_sha));
        assert!(verifier
            .verify_uncached_and_refresh(&bin, &expected_sha)
            .is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn cached_binary_verifier_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = std::env::temp_dir().join(format!(
            "maxq_cached_verifier_symlink_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("real.bin");
        let link = dir.join("link.bin");

        let bytes = b"authentic-target";
        std::fs::write(&target, bytes).unwrap();
        let expected_sha = hex::encode(Sha256::digest(bytes));
        symlink(&target, &link).unwrap();

        let mut verifier = CachedBinaryVerifier::default();
        assert!(!verifier.is_verified(&link, &expected_sha));
        assert!(verifier
            .verify_uncached_and_refresh(&link, &expected_sha)
            .is_err());
        assert_eq!(verifier.hash_computations, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
