use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::trust::{TlsVerifyMode, TrustRecord};

/// Canonical outbound proxy node representation decoupled from any specific kernel schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeConfig {
    pub id: String,
    pub name: String,
    pub server: String,
    pub server_port: u16,
    /// Optional dial target override when the user approves a `[Host]` proxy endpoint alias
    /// (e.g. `use-local-host-item-for-proxy = true`). TLS `server_name` remains untouched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dial_override_server: Option<String>,
    pub protocol: ProtocolConfig,
    #[serde(default)]
    pub transport: TransportConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub dial: DialOptions,
    /// True for provider status pseudo-nodes like `Traffic: 29.81 GB / 100 GB` or `Expire: ...`.
    #[serde(default)]
    pub is_metadata_node: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_tag: Option<String>,
}

/// Strips surrounding whitespace and IPv6 literal brackets (`[` / `]`) from a host or SNI string.
fn strip_host_brackets(raw: &str) -> &str {
    raw.trim().trim_start_matches('[').trim_end_matches(']').trim()
}

impl NodeConfig {
    pub fn new(
        name: impl Into<String>,
        server: impl Into<String>,
        server_port: u16,
        protocol: ProtocolConfig,
    ) -> Self {
        let name = name.into();
        let server_raw = server.into();
        let server = strip_host_brackets(&server_raw).to_string();
        let is_metadata_node = detect_metadata_node_name(&name);
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            server,
            server_port,
            dial_override_server: None,
            protocol,
            transport: TransportConfig::Tcp,
            tls: TlsConfig::default(),
            dial: DialOptions::default(),
            is_metadata_node,
            source_tag: None,
        }
    }

    /// Returns the effective host to dial (approved alias override or canonical `server`).
    pub fn effective_dial_server(&self) -> &str {
        let raw = self
            .dial_override_server
            .as_deref()
            .unwrap_or(self.server.as_str());
        strip_host_brackets(raw)
    }

    /// Returns the effective TLS SNI (explicit `server_name` or fallback to `server`),
    /// always stripping IPv6 literal brackets and surrounding whitespace.
    pub fn effective_sni(&self) -> &str {
        self.tls
            .server_name
            .as_deref()
            .map(strip_host_brackets)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| strip_host_brackets(self.server.as_str()))
    }

    /// Whether this protocol uses UDP/QUIC TLS handshake rather than TCP TLS.
    pub fn is_quic_protocol(&self) -> bool {
        matches!(
            self.protocol,
            ProtocolConfig::Hysteria2 { .. } | ProtocolConfig::Tuic { .. }
        )
    }
}

/// Heuristic to recognize informational pseudo-nodes commonly emitted by subscriptions.
pub fn detect_metadata_node_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    lower.starts_with("traffic:")
        || lower.starts_with("expire:")
        || name.contains("剩余流量")
        || name.contains("套餐到期")
        || name.contains("距离下次重置")
        || name.contains("官网")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProtocolConfig {
    Trojan {
        password: String,
    },
    Vless {
        uuid: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        flow: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        packet_encoding: Option<String>,
    },
    Vmess {
        uuid: String,
        #[serde(default)]
        alter_id: u16,
        #[serde(default = "default_vmess_security")]
        security: String,
    },
    AnyTls {
        password: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        idle_session_check_interval: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        idle_session_timeout: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min_idle_session: Option<u32>,
    },
    Hysteria2 {
        password: String,
        /// Canonical `start:end` port hopping ranges (e.g. `"20000:30000"`).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        server_ports: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hop_interval: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        up_mbps: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        down_mbps: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        obfs: Option<Hysteria2Obfs>,
    },
    Tuic {
        uuid: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        congestion_control: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        udp_relay_mode: Option<String>,
        #[serde(default)]
        zero_rtt_handshake: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        heartbeat: Option<String>,
    },
    Shadowsocks {
        method: String,
        password: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        plugin: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        plugin_opts: Option<String>,
    },
}

fn default_vmess_security() -> String {
    "auto".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Hysteria2Obfs {
    Salamander { password: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TransportConfig {
    #[default]
    Tcp,
    Ws {
        path: String,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        headers: BTreeMap<String, String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_early_data: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        early_data_header_name: Option<String>,
    },
    Grpc {
        service_name: String,
    },
    HttpUpgrade {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
    },
    Http {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        host: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        method: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Normalized from `sni` > `peer` > `servername`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(default)]
    pub disable_sni: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utls_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality: Option<RealityConfig>,
    #[serde(default)]
    pub verify_mode: TlsVerifyMode,
    /// Normalized 64-char lowercase hex leaf cert SHA-256 imported from `pcs` or `pinSHA256`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported_cert_sha256_hex: Option<String>,
    /// Optional Xray `vcn` (`verifyPeerCertByName`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_peer_name: Option<String>,
    /// Populated once the node is pinned via TOFU probe or verified pin bootstrap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_record: Option<TrustRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealityConfig {
    pub public_key: String,
    #[serde(default)]
    pub short_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DialOptions {
    #[serde(default)]
    pub tcp_fast_open: bool,
    #[serde(default)]
    pub udp_relay: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_ipv6_brackets_in_constructor_and_effective_sni() {
        let mut node = NodeConfig::new(
            "IPv6 Node",
            "  [2001:db8::1]  ",
            443,
            ProtocolConfig::Trojan {
                password: "pw".into(),
            },
        );
        assert_eq!(node.server, "2001:db8::1");
        assert_eq!(node.effective_sni(), "2001:db8::1");
        assert_eq!(node.effective_dial_server(), "2001:db8::1");

        // Bracketed SNI must also be stripped
        node.tls.server_name = Some(" [2001:db8::2] ".into());
        assert_eq!(node.effective_sni(), "2001:db8::2");

        // Legacy deserialized bracketed server falls back cleanly when server_name is empty/brackets
        node.server = "[::1]".into();
        node.tls.server_name = Some("  ".into());
        assert_eq!(node.effective_sni(), "::1");
        assert_eq!(node.effective_dial_server(), "::1");
    }
}
