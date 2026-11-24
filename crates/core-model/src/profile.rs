use serde::{Deserialize, Serialize};

use crate::node::NodeConfig;
use crate::rule::RuleEntry;
use crate::security::{HostEntry, ImportSecurityReport};

/// Parsed safe subset of Shadowrocket `[General]` settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GeneralSettings {
    #[serde(default)]
    pub bypass_system: bool,
    #[serde(default)]
    pub skip_proxy: Vec<String>,
    #[serde(default)]
    pub tun_excluded_routes: Vec<String>,
    #[serde(default)]
    pub dns_servers: Vec<String>,
    #[serde(default)]
    pub ipv6: Option<bool>,
    #[serde(default)]
    pub prefer_ipv6: Option<bool>,
    #[serde(default)]
    pub use_local_host_item_for_proxy: bool,
    #[serde(default)]
    pub udp_policy_not_supported_behaviour: Option<String>,
    #[serde(default)]
    pub update_url: Option<String>,
}

/// Raw stripped dangerous section recorded during parsing for security reporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DangerousSectionCapture {
    pub section_name: String,
    pub line_count: usize,
    /// Up to 3 redacted/truncated preview lines for user visibility (never executed).
    pub preview_lines: Vec<String>,
}

/// Raw raw-parsed host entry before sanitizer classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawHostEntry {
    pub domain: String,
    pub target: String,
}

/// Detected external dangerous override inside JSON/YAML imports (e.g. `inbounds`, `clash_api`, local paths).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DangerousOverrideCapture {
    pub key_path: String,
    pub reason: String,
}

/// Output of `maxq-parser` BEFORE passing through `maxq-sanitizer`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RawImportBundle {
    pub format_detected: ImportFormat,
    pub nodes: Vec<NodeConfig>,
    pub rules: Vec<RuleEntry>,
    pub general: GeneralSettings,
    pub raw_hosts: Vec<RawHostEntry>,
    pub dangerous_sections: Vec<DangerousSectionCapture>,
    pub dangerous_overrides: Vec<DangerousOverrideCapture>,
    pub parse_warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ImportFormat {
    #[default]
    Unknown,
    ShareLinks,
    Base64ShareLinks,
    ShadowrocketConf,
    ClashYaml,
    SingBoxJson,
}

/// Output of `maxq-sanitizer`: safe to persist and present to the user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanitizedImport {
    pub format: ImportFormat,
    pub nodes: Vec<NodeConfig>,
    pub rules: Vec<RuleEntry>,
    pub general: GeneralSettings,
    pub hosts: Vec<HostEntry>,
    pub report: ImportSecurityReport,
    pub parse_warnings: Vec<String>,
}

/// Runtime network & anti-leak settings controlled exclusively by MaxQ (never overridden by imports).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePolicy {
    pub mixed_listen_port: u16,
    /// Strictly `127.0.0.1` unless user explicitly enables LAN sharing.
    pub allow_lan: bool,
    pub clash_api_port: u16,
    /// Per-session random Bearer token (>= 32 hex/base64 chars).
    pub clash_api_secret: String,
    /// Allowed CORS origins for Clash API (never `*`).
    pub clash_api_allowed_origins: Vec<String>,
    /// Enable TUN inbound (requires privileged service on Windows).
    pub tun_enabled: bool,
    /// IPv6 handling policy for direct-node anti-leak.
    pub ipv6_mode: Ipv6Policy,
    /// Remote DoH/DoT server routed strictly via `"detour": "proxy"`.
    pub remote_dns_server: String,
    /// Direct/bootstrap DNS server IP (used for proxy hostname resolution & direct rules).
    pub direct_dns_server: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Ipv6Policy {
    /// Dual-stack TUN + block AAAA/IPv6 on proxied traffic when node is IPv4-only to prevent leak.
    #[default]
    BlockToPreventLeak,
    /// Prefer IPv4, allow IPv6 through proxy tunnel.
    PreferIpv4,
    /// Full dual-stack IPv4 + IPv6.
    DualStack,
}

impl Default for RuntimePolicy {
    fn default() -> Self {
        Self {
            mixed_listen_port: 17890,
            allow_lan: false,
            clash_api_port: 19090,
            clash_api_secret: String::new(),
            clash_api_allowed_origins: vec![
                "http://tauri.localhost".to_string(),
                "https://tauri.localhost".to_string(),
            ],
            tun_enabled: false,
            ipv6_mode: Ipv6Policy::BlockToPreventLeak,
            remote_dns_server: "1.1.1.1".to_string(),
            direct_dns_server: "223.5.5.5".to_string(),
        }
    }
}
