use maxq_core_model::{
    DangerousOverrideCapture, Hysteria2Obfs, ImportFormat, NodeConfig, ProtocolConfig,
    RawImportBundle, RealityConfig, TlsConfig, TlsVerifyMode,
};
use serde_json::Value;

use crate::ParseError;

/// Safely imports proxy outbounds from an external `sing-box` JSON file while blocking
/// external `inbounds`, `experimental.clash_api`, `log.output`, and local filesystem path injections.
pub fn parse_singbox_json(input: &str) -> Result<RawImportBundle, ParseError> {
    let root: Value =
        serde_json::from_str(input).map_err(|e| ParseError::InvalidJson(e.to_string()))?;
    let mut bundle = RawImportBundle {
        format_detected: ImportFormat::SingBoxJson,
        ..Default::default()
    };

    if root.get("inbounds").is_some() {
        bundle.dangerous_overrides.push(DangerousOverrideCapture {
            key_path: "inbounds".into(),
            reason: "External inbound listeners/TUN definitions are blocked".into(),
        });
    }
    if root.get("endpoints").is_some() {
        bundle.dangerous_overrides.push(DangerousOverrideCapture {
            key_path: "endpoints".into(),
            reason: "External WireGuard/Tailscale endpoints are blocked".into(),
        });
    }
    if let Some(exp) = root.get("experimental") {
        if exp.get("clash_api").is_some() {
            bundle.dangerous_overrides.push(DangerousOverrideCapture {
                key_path: "experimental.clash_api".into(),
                reason: "External Clash API controller/secret/UI overrides are blocked".into(),
            });
        }
        if exp.get("v2ray_api").is_some() {
            bundle.dangerous_overrides.push(DangerousOverrideCapture {
                key_path: "experimental.v2ray_api".into(),
                reason: "External V2Ray API listener override blocked".into(),
            });
        }
        if exp
            .get("cache_file")
            .and_then(|c| c.get("path"))
            .and_then(|p| p.as_str())
            .is_some_and(|s| !s.is_empty())
        {
            bundle.dangerous_overrides.push(DangerousOverrideCapture {
                key_path: "experimental.cache_file.path".into(),
                reason: "External cache_file filesystem path stripped".into(),
            });
        }
    }
    if root.get("log").and_then(|l| l.get("output")).is_some() {
        bundle.dangerous_overrides.push(DangerousOverrideCapture {
            key_path: "log.output".into(),
            reason: "External log file path override blocked".into(),
        });
    }
    if let Some(rule_sets) = root
        .get("route")
        .and_then(|r| r.get("rule_set"))
        .and_then(|rs| rs.as_array())
    {
        for (idx, rs) in rule_sets.iter().enumerate() {
            if rs.get("path").and_then(|p| p.as_str()).is_some_and(|s| !s.is_empty()) {
                bundle.dangerous_overrides.push(DangerousOverrideCapture {
                    key_path: format!("route.rule_set[{idx}].path"),
                    reason: "External local rule_set filesystem path stripped".into(),
                });
            }
        }
    }

    if let Some(outbounds) = root.get("outbounds").and_then(|v| v.as_array()) {
        for (idx, ob) in outbounds.iter().enumerate() {
            let ob_type = ob.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if matches!(
                ob_type,
                "direct" | "block" | "dns" | "selector" | "urltest" | ""
            ) {
                continue;
            }
            // Detect local filesystem path injection in TLS options
            if let Some(tls) = ob.get("tls") {
                for path_key in [
                    "certificate_path",
                    "key_path",
                    "client_certificate_path",
                    "client_key_path",
                ] {
                    if tls
                        .get(path_key)
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.is_empty())
                    {
                        bundle.dangerous_overrides.push(DangerousOverrideCapture {
                            key_path: format!("outbounds[{idx}].tls.{path_key}"),
                            reason: "External local filesystem path reference stripped".into(),
                        });
                    }
                }
                if tls
                    .get("ech")
                    .and_then(|e| e.get("config_path"))
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.is_empty())
                {
                    bundle.dangerous_overrides.push(DangerousOverrideCapture {
                        key_path: format!("outbounds[{idx}].tls.ech.config_path"),
                        reason: "External ECH local config_path stripped".into(),
                    });
                }
                if tls.get("acme").is_some() {
                    bundle.dangerous_overrides.push(DangerousOverrideCapture {
                        key_path: format!("outbounds[{idx}].tls.acme"),
                        reason: "External ACME configuration stripped".into(),
                    });
                }
            }
            match parse_outbound(ob) {
                Ok(node) => bundle.nodes.push(node),
                Err(msg) => bundle
                    .parse_warnings
                    .push(format!("sing-box outbounds[{idx}]: {msg}")),
            }
        }
    }

    if bundle.nodes.is_empty() && bundle.dangerous_overrides.is_empty() {
        return Err(ParseError::InvalidJson(
            "no valid proxy outbounds found".into(),
        ));
    }

    Ok(bundle)
}

fn jstr<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(|x| x.as_str()).filter(|s| !s.is_empty())
}

fn parse_outbound(v: &Value) -> Result<NodeConfig, String> {
    let ob_type = jstr(v, "type").ok_or("missing type")?;
    let name = jstr(v, "tag").unwrap_or("unnamed").to_string();
    let server = jstr(v, "server").ok_or("missing server")?.to_string();
    let port = v
        .get("server_port")
        .and_then(|x| x.as_u64())
        .and_then(|n| u16::try_from(n).ok())
        .ok_or("missing server_port")?;

    let protocol = match ob_type {
        "trojan" => ProtocolConfig::Trojan {
            password: jstr(v, "password").ok_or("missing password")?.to_string(),
        },
        "anytls" => ProtocolConfig::AnyTls {
            password: jstr(v, "password").ok_or("missing password")?.to_string(),
            idle_session_check_interval: jstr(v, "idle_session_check_interval").map(str::to_string),
            idle_session_timeout: jstr(v, "idle_session_timeout").map(str::to_string),
            min_idle_session: v
                .get("min_idle_session")
                .and_then(|x| x.as_u64())
                .map(|n| n as u32),
        },
        "hysteria2" => {
            let obfs = v.get("obfs").and_then(|o| {
                if jstr(o, "type") == Some("salamander") {
                    jstr(o, "password").map(|p| Hysteria2Obfs::Salamander {
                        password: p.to_string(),
                    })
                } else {
                    None
                }
            });
            let server_ports = v
                .get("server_ports")
                .and_then(|x| x.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|i| i.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            ProtocolConfig::Hysteria2 {
                password: jstr(v, "password").ok_or("missing password")?.to_string(),
                server_ports,
                hop_interval: jstr(v, "hop_interval").map(str::to_string),
                up_mbps: v.get("up_mbps").and_then(|x| x.as_u64()).map(|n| n as u32),
                down_mbps: v
                    .get("down_mbps")
                    .and_then(|x| x.as_u64())
                    .map(|n| n as u32),
                obfs,
            }
        }
        "tuic" => ProtocolConfig::Tuic {
            uuid: jstr(v, "uuid").ok_or("missing uuid")?.to_string(),
            password: jstr(v, "password").map(str::to_string),
            congestion_control: jstr(v, "congestion_control").map(str::to_string),
            udp_relay_mode: jstr(v, "udp_relay_mode").map(str::to_string),
            zero_rtt_handshake: v
                .get("zero_rtt_handshake")
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
            heartbeat: jstr(v, "heartbeat").map(str::to_string),
        },
        "vless" => ProtocolConfig::Vless {
            uuid: jstr(v, "uuid").ok_or("missing uuid")?.to_string(),
            flow: jstr(v, "flow").map(str::to_string),
            packet_encoding: jstr(v, "packet_encoding").map(str::to_string),
        },
        "vmess" => ProtocolConfig::Vmess {
            uuid: jstr(v, "uuid").ok_or("missing uuid")?.to_string(),
            alter_id: v.get("alter_id").and_then(|x| x.as_u64()).unwrap_or(0) as u16,
            security: jstr(v, "security").unwrap_or("auto").to_string(),
        },
        "shadowsocks" => ProtocolConfig::Shadowsocks {
            method: jstr(v, "method").ok_or("missing method")?.to_string(),
            password: jstr(v, "password").ok_or("missing password")?.to_string(),
            plugin: jstr(v, "plugin").map(str::to_string),
            plugin_opts: jstr(v, "plugin_opts").map(str::to_string),
        },
        other => return Err(format!("unsupported sing-box outbound type '{other}'")),
    };

    let mut node = NodeConfig::new(name, server, port, protocol);
    if let Some(tls) = v.get("tls") {
        let enabled = tls.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false);
        let insecure = tls.get("insecure").and_then(|x| x.as_bool()).unwrap_or(false);
        let reality = tls.get("reality").and_then(|r| {
            if r.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false) {
                jstr(r, "public_key").map(|pk| RealityConfig {
                    public_key: pk.to_string(),
                    short_id: jstr(r, "short_id").unwrap_or_default().to_string(),
                })
            } else {
                None
            }
        });
        node.tls = TlsConfig {
            enabled,
            server_name: jstr(tls, "server_name").map(str::to_string),
            disable_sni: tls
                .get("disable_sni")
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
            alpn: tls
                .get("alpn")
                .and_then(|a| a.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
            utls_fingerprint: tls
                .get("utls")
                .and_then(|u| jstr(u, "fingerprint"))
                .map(str::to_string),
            reality,
            verify_mode: if insecure {
                TlsVerifyMode::InsecureLegacy {
                    user_confirmed_override: false,
                }
            } else {
                TlsVerifyMode::SystemCa
            },
            ..Default::default()
        };
    }

    Ok(node)
}
