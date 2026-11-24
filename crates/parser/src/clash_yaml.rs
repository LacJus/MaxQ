use maxq_core_model::{
    DangerousOverrideCapture, DialOptions, Hysteria2Obfs, ImportFormat, NodeConfig, ProtocolConfig,
    RawImportBundle, RealityConfig, TlsConfig, TlsVerifyMode, TransportConfig,
};
use serde_yaml_ng::Value;

use crate::{normalize_hex_sha256_pin, normalize_port_ranges, ParseError};

/// Safely extracts proxy nodes from a Clash / Mihomo YAML subscription while recording
/// and ignoring any dangerous controller / inbound / external-ui overrides.
pub fn parse_clash_yaml(input: &str) -> Result<RawImportBundle, ParseError> {
    let doc: Value =
        serde_yaml_ng::from_str(input).map_err(|e| ParseError::InvalidYaml(e.to_string()))?;
    let mut bundle = RawImportBundle {
        format_detected: ImportFormat::ClashYaml,
        ..Default::default()
    };

    if let Some(map) = doc.as_mapping() {
        for forbidden_key in [
            "external-controller",
            "external-controller-tls",
            "external-controller-pipe",
            "external-controller-unix",
            "secret",
            "external-ui",
            "external-ui-url",
            "external-ui-name",
            "allow-lan",
            "bind-address",
            "port",
            "socks-port",
            "mixed-port",
            "redir-port",
            "tproxy-port",
            "listeners",
            "tun",
            "hosts",
            "script",
            "dns",
            "ebpf",
            "authentication",
            "rule-providers",
            "proxy-providers",
            "geox-url",
        ] {
            if map.contains_key(Value::String(forbidden_key.to_string())) {
                bundle.dangerous_overrides.push(DangerousOverrideCapture {
                    key_path: forbidden_key.to_string(),
                    reason: "External listener/controller/host/script/TUN override stripped by MaxQ"
                        .into(),
                });
            }
        }
    }

    if let Some(proxies) = doc.get("proxies").and_then(|v| v.as_sequence()) {
        for (idx, item) in proxies.iter().enumerate() {
            if yaml_str(item, "ca").is_some() {
                bundle.dangerous_overrides.push(DangerousOverrideCapture {
                    key_path: format!("proxies[{idx}].ca"),
                    reason: "External local filesystem CA path stripped".into(),
                });
            }
            match parse_clash_proxy(item) {
                Ok(node) => bundle.nodes.push(node),
                Err(msg) => bundle
                    .parse_warnings
                    .push(format!("clash proxies[{idx}]: {msg}")),
            }
        }
    }

    if bundle.nodes.is_empty() {
        return Err(ParseError::InvalidYaml(
            "no valid proxies found in Clash YAML".into(),
        ));
    }

    Ok(bundle)
}

fn yaml_str<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(|val| val.as_str()).filter(|s| !s.is_empty())
}

fn yaml_u16(v: &Value, key: &str) -> Option<u16> {
    v.get(key)
        .and_then(|val| val.as_u64())
        .and_then(|n| u16::try_from(n).ok())
}

fn yaml_bool(v: &Value, key: &str) -> bool {
    v.get(key).and_then(|val| val.as_bool()).unwrap_or(false)
}

fn parse_clash_proxy(v: &Value) -> Result<NodeConfig, String> {
    let name = yaml_str(v, "name")
        .ok_or_else(|| "missing name".to_string())?
        .to_string();
    let ptype = yaml_str(v, "type")
        .ok_or_else(|| "missing type".to_string())?
        .to_ascii_lowercase();
    let server = yaml_str(v, "server")
        .ok_or_else(|| "missing server".to_string())?
        .to_string();
    let port = yaml_u16(v, "port").ok_or_else(|| "missing port".to_string())?;

    let (protocol, tls_default) = match ptype.as_str() {
        "trojan" => (
            ProtocolConfig::Trojan {
                password: yaml_str(v, "password")
                    .ok_or_else(|| "missing password".to_string())?
                    .to_string(),
            },
            true,
        ),
        "anytls" => (
            ProtocolConfig::AnyTls {
                password: yaml_str(v, "password")
                    .ok_or_else(|| "missing password".to_string())?
                    .to_string(),
                idle_session_check_interval: v
                    .get("idle-session-check-interval")
                    .and_then(|x| x.as_u64())
                    .map(|s| format!("{s}s")),
                idle_session_timeout: v
                    .get("idle-session-timeout")
                    .and_then(|x| x.as_u64())
                    .map(|s| format!("{s}s")),
                min_idle_session: v
                    .get("min-idle-session")
                    .and_then(|x| x.as_u64())
                    .map(|n| n as u32),
            },
            true,
        ),
        "hysteria2" => {
            let obfs = match yaml_str(v, "obfs") {
                Some(o) if o.eq_ignore_ascii_case("salamander") => {
                    yaml_str(v, "obfs-password").map(|p| Hysteria2Obfs::Salamander {
                        password: p.to_string(),
                    })
                }
                _ => None,
            };
            let server_ports = yaml_str(v, "ports")
                .map(normalize_port_ranges)
                .unwrap_or_default();
            (
                ProtocolConfig::Hysteria2 {
                    password: yaml_str(v, "password")
                        .ok_or_else(|| "missing password".to_string())?
                        .to_string(),
                    server_ports,
                    hop_interval: v
                        .get("hop-interval")
                        .and_then(|x| x.as_u64())
                        .map(|s| format!("{s}s")),
                    up_mbps: None,
                    down_mbps: None,
                    obfs,
                },
                true,
            )
        }
        "tuic" => (
            ProtocolConfig::Tuic {
                uuid: yaml_str(v, "uuid")
                    .ok_or_else(|| "missing uuid".to_string())?
                    .to_string(),
                password: yaml_str(v, "password").map(str::to_string),
                congestion_control: yaml_str(v, "congestion-controller").map(str::to_string),
                udp_relay_mode: yaml_str(v, "udp-relay-mode").map(str::to_string),
                zero_rtt_handshake: yaml_bool(v, "reduce-rtt"),
                heartbeat: v
                    .get("heartbeat-interval")
                    .and_then(|x| x.as_u64())
                    .map(|ms| format!("{ms}ms")),
            },
            true,
        ),
        "vless" => (
            ProtocolConfig::Vless {
                uuid: yaml_str(v, "uuid")
                    .ok_or_else(|| "missing uuid".to_string())?
                    .to_string(),
                flow: yaml_str(v, "flow").map(str::to_string),
                packet_encoding: yaml_str(v, "packet-encoding").map(str::to_string),
            },
            false,
        ),
        "vmess" => (
            ProtocolConfig::Vmess {
                uuid: yaml_str(v, "uuid")
                    .ok_or_else(|| "missing uuid".to_string())?
                    .to_string(),
                alter_id: yaml_u16(v, "alterId").unwrap_or(0),
                security: yaml_str(v, "cipher").unwrap_or("auto").to_string(),
            },
            false,
        ),
        "ss" => (
            ProtocolConfig::Shadowsocks {
                method: yaml_str(v, "cipher")
                    .ok_or_else(|| "missing cipher".to_string())?
                    .to_string(),
                password: yaml_str(v, "password")
                    .ok_or_else(|| "missing password".to_string())?
                    .to_string(),
                plugin: yaml_str(v, "plugin").map(str::to_string),
                plugin_opts: None,
            },
            false,
        ),
        other => return Err(format!("unsupported clash proxy type '{other}'")),
    };

    let skip_cert_verify = yaml_bool(v, "skip-cert-verify");
    let imported_cert_sha256_hex = yaml_str(v, "fingerprint")
        .and_then(normalize_hex_sha256_pin);
    let reality = v.get("reality-opts").and_then(|ro| {
        yaml_str(ro, "public-key").map(|pk| RealityConfig {
            public_key: pk.to_string(),
            short_id: yaml_str(ro, "short-id").unwrap_or_default().to_string(),
        })
    });
    let tls_enabled = tls_default || yaml_bool(v, "tls") || reality.is_some();

    let verify_mode = if imported_cert_sha256_hex.is_some() {
        TlsVerifyMode::PendingPinBootstrap
    } else if skip_cert_verify {
        TlsVerifyMode::InsecureLegacy {
            user_confirmed_override: false,
        }
    } else {
        TlsVerifyMode::SystemCa
    };

    let mut node = NodeConfig::new(name, server, port, protocol);
    node.tls = TlsConfig {
        enabled: tls_enabled,
        server_name: yaml_str(v, "sni")
            .or_else(|| yaml_str(v, "servername"))
            .map(str::to_string),
        alpn: v
            .get("alpn")
            .and_then(|a| a.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        utls_fingerprint: yaml_str(v, "client-fingerprint").map(str::to_string),
        reality,
        verify_mode,
        imported_cert_sha256_hex,
        ..Default::default()
    };
    node.transport = TransportConfig::Tcp;
    node.dial = DialOptions {
        tcp_fast_open: yaml_bool(v, "tfo"),
        udp_relay: yaml_bool(v, "udp"),
    };
    Ok(node)
}
