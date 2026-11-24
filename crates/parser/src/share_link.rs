use std::collections::{BTreeMap, HashMap};

use maxq_core_model::{
    DialOptions, Hysteria2Obfs, NodeConfig, ProtocolConfig, RealityConfig, TlsConfig,
    TlsVerifyMode, TransportConfig,
};
use serde_json::Value;
use url::Url;

use crate::{
    decode_base64_lenient, normalize_hex_sha256_pin, normalize_port_ranges, percent_decode_str,
    ParseError,
};

pub fn is_supported_share_link(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.starts_with("trojan://")
        || lower.starts_with("vless://")
        || lower.starts_with("vmess://")
        || lower.starts_with("anytls://")
        || lower.starts_with("hysteria2://")
        || lower.starts_with("hy2://")
        || lower.starts_with("tuic://")
        || lower.starts_with("ss://")
}

/// Parses a single proxy share link (including Shadowrocket dialects) into canonical `NodeConfig`.
pub fn parse_share_link(raw: &str) -> Result<NodeConfig, ParseError> {
    let line = raw.trim();
    let (scheme_raw, _) = line
        .split_once("://")
        .ok_or_else(|| ParseError::UnsupportedScheme(line.to_string()))?;
    let scheme = scheme_raw.to_ascii_lowercase();

    match scheme.as_str() {
        "trojan" => parse_trojan(line),
        "vless" => parse_vless(line),
        "vmess" => parse_vmess(line),
        "anytls" => parse_anytls(line),
        "hysteria2" | "hy2" => parse_hysteria2(line, &scheme),
        "tuic" => parse_tuic(line),
        "ss" => parse_shadowsocks(line),
        _ => Err(ParseError::UnsupportedScheme(scheme)),
    }
}

fn parse_query_map(url: &Url) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (k, v) in url.query_pairs() {
        map.insert(k.to_ascii_lowercase(), v.into_owned());
    }
    map
}

fn is_truthy(val: Option<&String>) -> bool {
    matches!(
        val.map(|s| s.trim().to_ascii_lowercase()).as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

fn non_empty(val: Option<&String>) -> Option<String> {
    val.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn extract_host_port(url: &Url, scheme: &str, default_port: u16) -> Result<(String, u16), ParseError> {
    let host = url
        .host_str()
        .ok_or_else(|| ParseError::MalformedLink {
            scheme: scheme.to_string(),
            reason: "missing host".to_string(),
        })?
        .trim_matches(|c| c == '[' || c == ']')
        .to_string();
    let port = url.port().unwrap_or(default_port);
    Ok((host, port))
}

fn extract_node_name(url: &Url, params: &HashMap<String, String>, host: &str, port: u16) -> String {
    if let Some(frag) = url.fragment() {
        let decoded = percent_decode_str(frag).trim().to_string();
        if !decoded.is_empty() {
            return decoded;
        }
    }
    if let Some(remarks) = non_empty(params.get("remarks")) {
        return remarks;
    }
    format!("{host}:{port}")
}

/// Applies Shadowrocket & standard TLS query parameter normalization (`sni` > `peer` > `servername`,
/// `allowInsecure`/`insecure`/`skip-cert-verify`, `pcs`/`pinSHA256`, `vcn`, `alpn`, `fp`, `pbk`/`sid`).
fn build_tls_from_params(
    params: &HashMap<String, String>,
    mandatory_tls: bool,
) -> TlsConfig {
    let security = params
        .get("security")
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();

    let pbk = non_empty(params.get("pbk")).or_else(|| non_empty(params.get("publickey")));
    let sid = non_empty(params.get("sid"))
        .or_else(|| non_empty(params.get("shortid")))
        .unwrap_or_default();

    let reality = if security == "reality" || pbk.is_some() {
        pbk.map(|public_key| RealityConfig {
            public_key,
            short_id: sid,
        })
    } else {
        None
    };

    let tls_flag = is_truthy(params.get("tls"));
    // Mandatory-TLS protocols (trojan, anytls, hysteria2, tuic) CANNOT be downgraded via security=none
    let enabled = if mandatory_tls {
        true
    } else if security == "none" {
        false
    } else {
        security == "tls" || reality.is_some() || tls_flag
    };

    let server_name = non_empty(params.get("sni"))
        .or_else(|| non_empty(params.get("peer")))
        .or_else(|| non_empty(params.get("servername")));

    let alpn = params
        .get("alpn")
        .map(|raw| {
            percent_decode_str(raw)
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let utls_fingerprint = non_empty(params.get("fp"))
        .or_else(|| non_empty(params.get("client-fingerprint")))
        .or_else(|| non_empty(params.get("fingerprint")));

    let imported_cert_sha256_hex = params
        .get("pcs")
        .or_else(|| params.get("pinsha256"))
        .or_else(|| params.get("fp_sha256"))
        .and_then(|v| normalize_hex_sha256_pin(v));

    let verify_peer_name = non_empty(params.get("vcn"));

    let insecure_flag = is_truthy(params.get("allowinsecure"))
        || is_truthy(params.get("insecure"))
        || is_truthy(params.get("allow_insecure"))
        || is_truthy(params.get("skip-cert-verify"));

    let verify_mode = if imported_cert_sha256_hex.is_some() {
        TlsVerifyMode::PendingPinBootstrap
    } else if insecure_flag {
        TlsVerifyMode::InsecureLegacy {
            user_confirmed_override: false,
        }
    } else {
        TlsVerifyMode::SystemCa
    };

    TlsConfig {
        enabled,
        server_name,
        disable_sni: is_truthy(params.get("disable_sni")),
        alpn,
        utls_fingerprint,
        reality,
        verify_mode,
        imported_cert_sha256_hex,
        verify_peer_name,
        trust_record: None,
    }
}

fn build_transport_from_params(params: &HashMap<String, String>) -> TransportConfig {
    let net_type = params
        .get("type")
        .or_else(|| params.get("obfs"))
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "tcp".to_string());

    match net_type.as_str() {
        "ws" | "websocket" => {
            let path = non_empty(params.get("path")).unwrap_or_else(|| "/".to_string());
            let mut headers = BTreeMap::new();
            if let Some(host) =
                non_empty(params.get("host")).or_else(|| non_empty(params.get("obfsparam")))
            {
                headers.insert("Host".to_string(), host);
            }
            TransportConfig::Ws {
                path,
                headers,
                max_early_data: params.get("ed").and_then(|v| v.parse().ok()),
                early_data_header_name: None,
            }
        }
        "grpc" => {
            let service_name = non_empty(params.get("servicename"))
                .or_else(|| non_empty(params.get("path")))
                .unwrap_or_default();
            TransportConfig::Grpc { service_name }
        }
        "httpupgrade" => TransportConfig::HttpUpgrade {
            path: non_empty(params.get("path")).unwrap_or_else(|| "/".to_string()),
            host: non_empty(params.get("host")),
        },
        "h2" | "http" => {
            let host = non_empty(params.get("host"))
                .map(|h| {
                    h.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            TransportConfig::Http {
                path: non_empty(params.get("path")),
                host,
                method: None,
            }
        }
        _ => TransportConfig::Tcp,
    }
}

fn build_dial_from_params(params: &HashMap<String, String>) -> DialOptions {
    DialOptions {
        tcp_fast_open: is_truthy(params.get("tfo")) || is_truthy(params.get("fast-open")),
        udp_relay: is_truthy(params.get("udp")) || is_truthy(params.get("udp-relay")),
    }
}

fn parse_trojan(raw: &str) -> Result<NodeConfig, ParseError> {
    let url = Url::parse(raw).map_err(|e| ParseError::MalformedLink {
        scheme: "trojan".into(),
        reason: e.to_string(),
    })?;
    let password = percent_decode_str(url.username());
    if password.is_empty() {
        return Err(ParseError::MalformedLink {
            scheme: "trojan".into(),
            reason: "missing password".into(),
        });
    }
    let (host, port) = extract_host_port(&url, "trojan", 443)?;
    let params = parse_query_map(&url);
    let name = extract_node_name(&url, &params, &host, port);

    let mut node = NodeConfig::new(name, host, port, ProtocolConfig::Trojan { password });
    node.tls = build_tls_from_params(&params, true);
    node.transport = build_transport_from_params(&params);
    node.dial = build_dial_from_params(&params);
    Ok(node)
}

fn parse_vless(raw: &str) -> Result<NodeConfig, ParseError> {
    let url = Url::parse(raw).map_err(|e| ParseError::MalformedLink {
        scheme: "vless".into(),
        reason: e.to_string(),
    })?;
    let uuid = percent_decode_str(url.username());
    if uuid.is_empty() {
        return Err(ParseError::MalformedLink {
            scheme: "vless".into(),
            reason: "missing uuid".into(),
        });
    }
    let (host, port) = extract_host_port(&url, "vless", 443)?;
    let params = parse_query_map(&url);
    let name = extract_node_name(&url, &params, &host, port);

    let flow = non_empty(params.get("flow"));
    let packet_encoding = non_empty(params.get("packetencoding"));

    let mut node = NodeConfig::new(
        name,
        host,
        port,
        ProtocolConfig::Vless {
            uuid,
            flow,
            packet_encoding,
        },
    );
    node.tls = build_tls_from_params(&params, false);
    node.transport = build_transport_from_params(&params);
    node.dial = build_dial_from_params(&params);
    Ok(node)
}

fn parse_anytls(raw: &str) -> Result<NodeConfig, ParseError> {
    let url = Url::parse(raw).map_err(|e| ParseError::MalformedLink {
        scheme: "anytls".into(),
        reason: e.to_string(),
    })?;
    let password = percent_decode_str(url.username());
    if password.is_empty() {
        return Err(ParseError::MalformedLink {
            scheme: "anytls".into(),
            reason: "missing password".into(),
        });
    }
    let (host, port) = extract_host_port(&url, "anytls", 443)?;
    let params = parse_query_map(&url);
    let name = extract_node_name(&url, &params, &host, port);

    let mut node = NodeConfig::new(
        name,
        host,
        port,
        ProtocolConfig::AnyTls {
            password,
            idle_session_check_interval: non_empty(params.get("idle_session_check_interval")),
            idle_session_timeout: non_empty(params.get("idle_session_timeout")),
            min_idle_session: params
                .get("min_idle_session")
                .and_then(|v| v.parse::<u32>().ok()),
        },
    );
    node.tls = build_tls_from_params(&params, true);
    node.dial = build_dial_from_params(&params);
    Ok(node)
}

fn parse_hysteria2(raw: &str, scheme: &str) -> Result<NodeConfig, ParseError> {
    let url = Url::parse(raw).map_err(|e| ParseError::MalformedLink {
        scheme: scheme.into(),
        reason: e.to_string(),
    })?;
    let user = percent_decode_str(url.username());
    let password = if let Some(p) = url.password() {
        format!("{user}:{}", percent_decode_str(p))
    } else {
        user
    };
    if password.is_empty() {
        return Err(ParseError::MalformedLink {
            scheme: scheme.into(),
            reason: "missing auth password".into(),
        });
    }
    let (host, port) = extract_host_port(&url, scheme, 443)?;
    let params = parse_query_map(&url);
    let name = extract_node_name(&url, &params, &host, port);

    let obfs = match params
        .get("obfs")
        .map(|s| s.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("salamander") => non_empty(params.get("obfs-password"))
            .or_else(|| non_empty(params.get("obfsparam")))
            .map(|password| Hysteria2Obfs::Salamander { password }),
        _ => None,
    };

    let server_ports = params
        .get("mport")
        .or_else(|| params.get("ports"))
        .map(|raw| normalize_port_ranges(raw))
        .unwrap_or_default();

    let up_mbps = params
        .get("upmbps")
        .or_else(|| params.get("up"))
        .and_then(|v| v.trim_end_matches("mbps").trim().parse::<u32>().ok());
    let down_mbps = params
        .get("downmbps")
        .or_else(|| params.get("down"))
        .and_then(|v| v.trim_end_matches("mbps").trim().parse::<u32>().ok());

    let mut node = NodeConfig::new(
        name,
        host,
        port,
        ProtocolConfig::Hysteria2 {
            password,
            server_ports,
            hop_interval: non_empty(params.get("hop_interval")),
            up_mbps,
            down_mbps,
            obfs,
        },
    );
    node.tls = build_tls_from_params(&params, true);
    node.dial = build_dial_from_params(&params);
    Ok(node)
}

fn parse_tuic(raw: &str) -> Result<NodeConfig, ParseError> {
    let url = Url::parse(raw).map_err(|e| ParseError::MalformedLink {
        scheme: "tuic".into(),
        reason: e.to_string(),
    })?;
    let uuid = percent_decode_str(url.username());
    if uuid.is_empty() {
        return Err(ParseError::MalformedLink {
            scheme: "tuic".into(),
            reason: "missing uuid".into(),
        });
    }
    let password = url.password().map(percent_decode_str);
    let (host, port) = extract_host_port(&url, "tuic", 443)?;
    let params = parse_query_map(&url);
    let name = extract_node_name(&url, &params, &host, port);

    let mut node = NodeConfig::new(
        name,
        host,
        port,
        ProtocolConfig::Tuic {
            uuid,
            password,
            congestion_control: non_empty(params.get("congestion_control"))
                .or_else(|| non_empty(params.get("congestion-control"))),
            udp_relay_mode: non_empty(params.get("udp_relay_mode"))
                .or_else(|| non_empty(params.get("udp-relay-mode"))),
            zero_rtt_handshake: is_truthy(params.get("reduce_rtt"))
                || is_truthy(params.get("zero_rtt_handshake")),
            heartbeat: non_empty(params.get("heartbeat")),
        },
    );
    node.tls = build_tls_from_params(&params, true);
    node.dial = build_dial_from_params(&params);
    Ok(node)
}

fn parse_vmess(raw: &str) -> Result<NodeConfig, ParseError> {
    let body = raw
        .strip_prefix("vmess://")
        .or_else(|| raw.strip_prefix("VMESS://"))
        .ok_or_else(|| ParseError::MalformedLink {
            scheme: "vmess".into(),
            reason: "invalid prefix".into(),
        })?;

    // Check Shadowrocket URI dialect: vmess://<base64(method:uuid@host:port)>?remarks=...
    if let Some((b64_part, rest)) = body.split_once('?') {
        if let Some(decoded_bytes) = decode_base64_lenient(b64_part) {
            if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                if !decoded_str.trim_start().starts_with('{') {
                    return parse_shadowrocket_vmess(&decoded_str, rest);
                }
            }
        }
    }

    // Standard v2rayN Base64 JSON format
    let b64_clean = body.split('#').next().unwrap_or(body);
    let decoded_bytes = decode_base64_lenient(b64_clean).ok_or_else(|| ParseError::MalformedLink {
        scheme: "vmess".into(),
        reason: "invalid base64 payload".into(),
    })?;
    let json_val: Value =
        serde_json::from_slice(&decoded_bytes).map_err(|e| ParseError::MalformedLink {
            scheme: "vmess".into(),
            reason: format!("invalid json: {e}"),
        })?;

    let host = json_val
        .get("add")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ParseError::MalformedLink {
            scheme: "vmess".into(),
            reason: "missing 'add'".into(),
        })?
        .to_string();
    let port = match json_val.get("port") {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(443) as u16,
        Some(Value::String(s)) => s.trim().parse::<u16>().unwrap_or(443),
        _ => 443,
    };
    let uuid = json_val
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ParseError::MalformedLink {
            scheme: "vmess".into(),
            reason: "missing 'id'".into(),
        })?
        .to_string();
    let alter_id = match json_val.get("aid") {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0) as u16,
        Some(Value::String(s)) => s.trim().parse::<u16>().unwrap_or(0),
        _ => 0,
    };
    let security = json_val
        .get("scy")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("auto")
        .to_string();
    let name = json_val
        .get("ps")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| format!("{host}:{port}"));

    let mut params = HashMap::new();
    if let Some(net) = json_val.get("net").and_then(|v| v.as_str()) {
        params.insert("type".to_string(), net.to_string());
    }
    if let Some(path) = json_val.get("path").and_then(|v| v.as_str()) {
        params.insert("path".to_string(), path.to_string());
    }
    if let Some(h) = json_val.get("host").and_then(|v| v.as_str()) {
        params.insert("host".to_string(), h.to_string());
    }
    if let Some(sni) = json_val.get("sni").and_then(|v| v.as_str()) {
        params.insert("sni".to_string(), sni.to_string());
    }
    if let Some(alpn) = json_val.get("alpn").and_then(|v| v.as_str()) {
        params.insert("alpn".to_string(), alpn.to_string());
    }
    if let Some(fp) = json_val.get("fp").and_then(|v| v.as_str()) {
        params.insert("fp".to_string(), fp.to_string());
    }
    let tls_enabled = json_val
        .get("tls")
        .and_then(|v| v.as_str())
        .map(|s| s.eq_ignore_ascii_case("tls"))
        .unwrap_or(false);
    if tls_enabled {
        params.insert("tls".to_string(), "1".to_string());
    }
    if json_val
        .get("skip-cert-verify")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        params.insert("allowinsecure".to_string(), "1".to_string());
    }

    let mut node = NodeConfig::new(
        name,
        host,
        port,
        ProtocolConfig::Vmess {
            uuid,
            alter_id,
            security,
        },
    );
    node.tls = build_tls_from_params(&params, tls_enabled);
    node.transport = build_transport_from_params(&params);
    Ok(node)
}

fn parse_shadowrocket_vmess(decoded_creds: &str, query_and_frag: &str) -> Result<NodeConfig, ParseError> {
    // Format: method:uuid@host:port
    let (left, right) = decoded_creds
        .rsplit_once('@')
        .ok_or_else(|| ParseError::MalformedLink {
            scheme: "vmess".into(),
            reason: "invalid Shadowrocket vmess credential format".into(),
        })?;
    let (security, uuid) = left
        .split_once(':')
        .ok_or_else(|| ParseError::MalformedLink {
            scheme: "vmess".into(),
            reason: "missing security:uuid".into(),
        })?;
    let (host, port_str) = split_host_port(right).ok_or_else(|| ParseError::MalformedLink {
        scheme: "vmess".into(),
        reason: "invalid host:port".into(),
    })?;
    let port = port_str.parse::<u16>().map_err(|_| ParseError::MalformedLink {
        scheme: "vmess".into(),
        reason: "invalid port".into(),
    })?;

    let dummy_url = Url::parse(&format!("http://dummy.local/?{query_and_frag}")).map_err(|e| {
        ParseError::MalformedLink {
            scheme: "vmess".into(),
            reason: e.to_string(),
        }
    })?;
    let params = parse_query_map(&dummy_url);
    let name = extract_node_name(&dummy_url, &params, &host, port);
    let alter_id = params
        .get("alterid")
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(0);

    let mut node = NodeConfig::new(
        name,
        host,
        port,
        ProtocolConfig::Vmess {
            uuid: uuid.to_string(),
            alter_id,
            security: security.to_string(),
        },
    );
    node.tls = build_tls_from_params(&params, false);
    node.transport = build_transport_from_params(&params);
    node.dial = build_dial_from_params(&params);
    Ok(node)
}

fn parse_shadowsocks(raw: &str) -> Result<NodeConfig, ParseError> {
    let body = raw
        .strip_prefix("ss://")
        .or_else(|| raw.strip_prefix("SS://"))
        .ok_or_else(|| ParseError::MalformedLink {
            scheme: "ss".into(),
            reason: "invalid prefix".into(),
        })?;

    let (without_frag, frag) = match body.split_once('#') {
        Some((a, b)) => (a, Some(percent_decode_str(b))),
        None => (body, None),
    };
    let (main_part, query_part) = match without_frag.split_once('?') {
        Some((a, b)) => (a, Some(b)),
        None => (without_frag, None),
    };

    let (method, password, host, port) = if let Some((userinfo, hostport)) = main_part.rsplit_once('@')
    {
        let (method, password) = if let Some((m, p)) = userinfo.split_once(':') {
            (percent_decode_str(m), percent_decode_str(p))
        } else {
            let decoded = decode_base64_lenient(userinfo)
                .and_then(|b| String::from_utf8(b).ok())
                .ok_or_else(|| ParseError::MalformedLink {
                    scheme: "ss".into(),
                    reason: "invalid base64 userinfo".into(),
                })?;
            let (m, p) = decoded
                .split_once(':')
                .ok_or_else(|| ParseError::MalformedLink {
                    scheme: "ss".into(),
                    reason: "missing method:password".into(),
                })?;
            (m.to_string(), p.to_string())
        };
        let hostport_clean = hostport.trim_end_matches('/');
        let (host, port_str) =
            split_host_port(hostport_clean).ok_or_else(|| ParseError::MalformedLink {
                scheme: "ss".into(),
                reason: "invalid host:port".into(),
            })?;
        let port = port_str.parse::<u16>().map_err(|_| ParseError::MalformedLink {
            scheme: "ss".into(),
            reason: "invalid port".into(),
        })?;
        (method, password, host, port)
    } else {
        // Legacy full base64: ss://base64(method:password@host:port)
        let decoded = decode_base64_lenient(main_part.trim_end_matches('/'))
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or_else(|| ParseError::MalformedLink {
                scheme: "ss".into(),
                reason: "invalid legacy base64 ss link".into(),
            })?;
        let (creds, hostport) =
            decoded
                .rsplit_once('@')
                .ok_or_else(|| ParseError::MalformedLink {
                    scheme: "ss".into(),
                    reason: "missing @ in legacy ss link".into(),
                })?;
        let (m, p) = creds
            .split_once(':')
            .ok_or_else(|| ParseError::MalformedLink {
                scheme: "ss".into(),
                reason: "missing method:password".into(),
            })?;
        let (host, port_str) =
            split_host_port(hostport).ok_or_else(|| ParseError::MalformedLink {
                scheme: "ss".into(),
                reason: "invalid host:port".into(),
            })?;
        let port = port_str.parse::<u16>().map_err(|_| ParseError::MalformedLink {
            scheme: "ss".into(),
            reason: "invalid port".into(),
        })?;
        (m.to_string(), p.to_string(), host, port)
    };

    let mut params = HashMap::new();
    if let Some(q) = query_part {
        if let Ok(dummy) = Url::parse(&format!("http://dummy.local/?{q}")) {
            params = parse_query_map(&dummy);
        }
    }

    let (plugin, plugin_opts) = if let Some(raw_plugin) = non_empty(params.get("plugin")) {
        if let Some((p, opts)) = raw_plugin.split_once(';') {
            (Some(p.to_string()), Some(opts.to_string()))
        } else {
            (Some(raw_plugin), None)
        }
    } else if let Some(obfs) = non_empty(params.get("obfs")) {
        let host_opt = non_empty(params.get("obfs-host"))
            .map(|h| format!("obfs={obfs};obfs-host={h}"))
            .unwrap_or_else(|| format!("obfs={obfs}"));
        (Some("obfs-local".to_string()), Some(host_opt))
    } else {
        (None, None)
    };

    let name = frag
        .filter(|s| !s.trim().is_empty())
        .or_else(|| non_empty(params.get("remarks")))
        .unwrap_or_else(|| format!("{host}:{port}"));

    let mut node = NodeConfig::new(
        name,
        host,
        port,
        ProtocolConfig::Shadowsocks {
            method,
            password,
            plugin,
            plugin_opts,
        },
    );
    node.dial = build_dial_from_params(&params);
    Ok(node)
}

fn split_host_port(input: &str) -> Option<(String, &str)> {
    let trimmed = input.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = after.strip_prefix(':')?;
        Some((host.to_string(), port))
    } else {
        let (host, port) = trimmed.rsplit_once(':')?;
        Some((host.to_string(), port))
    }
}
