use std::collections::{BTreeMap, HashMap};

use maxq_core_model::{
    DangerousSectionCapture, DialOptions, Hysteria2Obfs, ImportFormat, NodeConfig, ProtocolConfig,
    RawHostEntry, RawImportBundle, RuleAction, RuleEntry, RuleMatch, TlsConfig, TlsVerifyMode,
    TransportConfig,
};

use crate::{
    extract_conf_section_header, normalize_hex_sha256_pin, normalize_node, normalize_port_ranges,
    normalize_section_key, ParseError,
};

const DANGEROUS_SECTIONS_NORM: &[&str] = &[
    "mitm",
    "script",
    "urlrewrite",
    "headerrewrite",
    "maplocal",
    "bodyrewrite",
];

/// Parses a Shadowrocket / Surge INI `.conf` file into a canonical `RawImportBundle`.
/// Dangerous sections (`[MITM]`, `[Script]`, `[URL Rewrite]`, etc.) are captured only as
/// counts/previews for `maxq-sanitizer` and NEVER imported into executable config.
pub fn parse_shadowrocket_conf(input: &str) -> Result<RawImportBundle, ParseError> {
    let mut bundle = RawImportBundle {
        format_detected: ImportFormat::ShadowrocketConf,
        ..Default::default()
    };

    let mut current_section = String::new();
    let mut dangerous_acc: HashMap<String, DangerousSectionCapture> = HashMap::new();

    for (line_idx, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with("//")
        {
            continue;
        }

        if let Some(sec_name) = extract_conf_section_header(line) {
            current_section = sec_name;
            continue;
        }

        let sec_norm = normalize_section_key(&current_section);
        if DANGEROUS_SECTIONS_NORM.contains(&sec_norm.as_str()) {
            let entry = dangerous_acc
                .entry(sec_norm.clone())
                .or_insert_with(|| DangerousSectionCapture {
                    section_name: current_section.clone(),
                    line_count: 0,
                    preview_lines: Vec::new(),
                });
            entry.line_count += 1;
            if entry.preview_lines.len() < 3 {
                let preview: String = line.chars().take(100).collect();
                entry.preview_lines.push(preview);
            }
            continue;
        }

        match sec_norm.as_str() {
            "general" => parse_general_line(line, &mut bundle),
            "proxy" => {
                if let Err(msg) = parse_proxy_line(line, &mut bundle) {
                    bundle
                        .parse_warnings
                        .push(format!("[Proxy] line {}: {}", line_idx + 1, msg));
                }
            }
            "rule" => {
                if let Some(rule) = parse_rule_line(line) {
                    bundle.rules.push(rule);
                } else {
                    bundle
                        .parse_warnings
                        .push(format!("[Rule] line {}: unrecognized rule syntax", line_idx + 1));
                }
            }
            "host" => {
                if let Some((domain, target)) = line.split_once('=') {
                    let domain = domain.trim().to_string();
                    let target = target.trim().to_string();
                    if !domain.is_empty() && !target.is_empty() {
                        bundle.raw_hosts.push(RawHostEntry { domain, target });
                    }
                }
            }
            "proxygroup" => {
                // Parsed cleanly as informational for now; selector group management in later milestone.
            }
            _ => {}
        }
    }

    let mut dangerous_sections: Vec<_> = dangerous_acc.into_values().collect();
    dangerous_sections.sort_by(|a, b| a.section_name.cmp(&b.section_name));
    bundle.dangerous_sections = dangerous_sections;

    Ok(bundle)
}

fn parse_general_line(line: &str, bundle: &mut RawImportBundle) {
    let Some((k, v)) = line.split_once('=') else {
        return;
    };
    let key = k.trim().to_ascii_lowercase();
    let val = v.trim();

    match key.as_str() {
        "bypass-system" => bundle.general.bypass_system = parse_bool(val),
        "skip-proxy" => bundle.general.skip_proxy = split_csv(val),
        "tun-excluded-routes" | "bypass-tun" => {
            bundle.general.tun_excluded_routes = split_csv(val);
        }
        "dns-server" => bundle.general.dns_servers = split_csv(val),
        "ipv6" => bundle.general.ipv6 = Some(parse_bool(val)),
        "prefer-ipv6" => bundle.general.prefer_ipv6 = Some(parse_bool(val)),
        "use-local-host-item-for-proxy" => {
            bundle.general.use_local_host_item_for_proxy = parse_bool(val);
        }
        "udp-policy-not-supported-behaviour" => {
            bundle.general.udp_policy_not_supported_behaviour = Some(val.to_string());
        }
        "update-url" => {
            if !val.is_empty() {
                bundle.general.update_url = Some(val.to_string());
            }
        }
        _ => {}
    }
}

fn parse_proxy_line(line: &str, bundle: &mut RawImportBundle) -> Result<(), String> {
    // Split on first '=' so names with ':' (e.g. `Traffic: 29.81 GB / 100 GB`) stay intact.
    let (name_raw, rhs) = line
        .split_once('=')
        .ok_or_else(|| "missing '=' separator".to_string())?;
    let name = name_raw.trim().to_string();
    let parts: Vec<&str> = rhs.split(',').map(|p| p.trim()).collect();
    if parts.is_empty() {
        return Err("empty proxy definition".into());
    }

    let proto = parts[0].to_ascii_lowercase();
    if matches!(proto.as_str(), "direct" | "reject" | "reject-tinygif") {
        return Ok(());
    }
    if parts.len() < 3 {
        return Err(format!("too few fields for protocol '{proto}'"));
    }

    let host = parts[1].to_string();
    let port = parts[2]
        .parse::<u16>()
        .map_err(|_| format!("invalid port '{}'", parts[2]))?;

    let mut kv: HashMap<String, String> = HashMap::new();
    let mut positional: Vec<String> = Vec::new();
    for &item in &parts[3..] {
        if let Some((k, v)) = item.split_once('=') {
            kv.insert(k.trim().to_ascii_lowercase(), v.trim().trim_matches('"').to_string());
        } else if !item.is_empty() {
            positional.push(item.trim_matches('"').to_string());
        }
    }

    let skip_cert_verify = kv
        .get("skip-cert-verify")
        .or_else(|| kv.get("allowinsecure"))
        .or_else(|| kv.get("insecure"))
        .map(|s| parse_bool(s))
        .unwrap_or(false);
    let sni = kv
        .get("sni")
        .or_else(|| kv.get("peer"))
        .cloned()
        .filter(|s| !s.is_empty());
    let imported_cert_sha256_hex = kv
        .get("pcs")
        .or_else(|| kv.get("pinsha256"))
        .and_then(|v| normalize_hex_sha256_pin(v));

    let verify_mode = if imported_cert_sha256_hex.is_some() {
        TlsVerifyMode::PendingPinBootstrap
    } else if skip_cert_verify {
        TlsVerifyMode::InsecureLegacy {
            user_confirmed_override: false,
        }
    } else {
        TlsVerifyMode::SystemCa
    };

    let (protocol, tls_default) = match proto.as_str() {
        "trojan" => {
            let password = kv
                .get("password")
                .cloned()
                .ok_or_else(|| "trojan missing password".to_string())?;
            (ProtocolConfig::Trojan { password }, true)
        }
        "anytls" => {
            let password = kv
                .get("password")
                .cloned()
                .ok_or_else(|| "anytls missing password".to_string())?;
            (
                ProtocolConfig::AnyTls {
                    password,
                    idle_session_check_interval: kv.get("idle-session-check-interval").cloned(),
                    idle_session_timeout: kv.get("idle-session-timeout").cloned(),
                    min_idle_session: kv.get("min-idle-session").and_then(|v| v.parse().ok()),
                },
                true,
            )
        }
        "hysteria2" | "hy2" => {
            let password = kv
                .get("password")
                .or_else(|| kv.get("auth"))
                .cloned()
                .ok_or_else(|| "hysteria2 missing password".to_string())?;
            let obfs = kv
                .get("salamander-password")
                .or_else(|| kv.get("obfs-password"))
                .map(|p| Hysteria2Obfs::Salamander {
                    password: p.clone(),
                });
            let server_ports = kv
                .get("mport")
                .or_else(|| kv.get("ports"))
                .map(|v| normalize_port_ranges(v))
                .unwrap_or_default();
            (
                ProtocolConfig::Hysteria2 {
                    password,
                    server_ports,
                    hop_interval: kv
                        .get("hop-interval")
                        .or_else(|| kv.get("hop_interval"))
                        .cloned(),
                    up_mbps: kv.get("up").and_then(|v| v.parse().ok()),
                    down_mbps: kv.get("down").and_then(|v| v.parse().ok()),
                    obfs,
                },
                true,
            )
        }
        "tuic" => {
            let uuid = kv
                .get("uuid")
                .cloned()
                .ok_or_else(|| "tuic missing uuid".to_string())?;
            (
                ProtocolConfig::Tuic {
                    uuid,
                    password: kv.get("password").cloned(),
                    congestion_control: kv
                        .get("congestion-controller")
                        .or_else(|| kv.get("congestion_control"))
                        .cloned(),
                    udp_relay_mode: kv
                        .get("udp-relay-mode")
                        .or_else(|| kv.get("udp_relay_mode"))
                        .cloned(),
                    zero_rtt_handshake: kv
                        .get("reduce-rtt")
                        .or_else(|| kv.get("zero-rtt-handshake"))
                        .map(|v| parse_bool(v))
                        .unwrap_or(false),
                    heartbeat: kv
                        .get("heartbeat-interval")
                        .or_else(|| kv.get("heartbeat"))
                        .cloned(),
                },
                true,
            )
        }
        "vmess" => {
            let uuid = kv
                .get("username")
                .or_else(|| kv.get("uuid"))
                .cloned()
                .ok_or_else(|| "vmess missing username/uuid".to_string())?;
            let security = kv
                .get("encrypt-method")
                .or_else(|| kv.get("cipher"))
                .cloned()
                .unwrap_or_else(|| "auto".into());
            (
                ProtocolConfig::Vmess {
                    uuid,
                    alter_id: kv
                        .get("alterid")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0),
                    security,
                },
                false,
            )
        }
        "vless" => {
            let uuid = kv
                .get("username")
                .or_else(|| kv.get("uuid"))
                .cloned()
                .ok_or_else(|| "vless missing uuid".to_string())?;
            (
                ProtocolConfig::Vless {
                    uuid,
                    flow: kv.get("flow").cloned(),
                    packet_encoding: None,
                },
                false,
            )
        }
        "ss" | "shadowsocks" => {
            let method = kv
                .get("encrypt-method")
                .cloned()
                .or_else(|| positional.first().cloned())
                .ok_or_else(|| "ss missing encrypt-method".to_string())?;
            let password = kv
                .get("password")
                .cloned()
                .or_else(|| positional.get(1).cloned())
                .ok_or_else(|| "ss missing password".to_string())?;
            let (plugin, plugin_opts) = if let Some(plugin_name) = kv.get("plugin") {
                (Some(plugin_name.clone()), kv.get("plugin-opts").cloned())
            } else if let Some(obfs) = kv.get("obfs") {
                let opts = kv
                    .get("obfs-host")
                    .map(|h| format!("obfs={obfs};obfs-host={h}"))
                    .unwrap_or_else(|| format!("obfs={obfs}"));
                (Some("obfs-local".to_string()), Some(opts))
            } else {
                (None, None)
            };
            (
                ProtocolConfig::Shadowsocks {
                    method,
                    password,
                    plugin,
                    plugin_opts,
                },
                false,
            )
        }
        other => return Err(format!("unsupported inline proxy type '{other}'")),
    };

    // Mandatory-TLS protocols cannot be downgraded by `tls=false`
    let tls_enabled = if tls_default {
        true
    } else {
        kv.get("tls").map(|s| parse_bool(s)).unwrap_or(false)
    };
    let alpn = kv
        .get("alpn")
        .map(|raw| {
            raw.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let utls_fingerprint = kv
        .get("fp")
        .or_else(|| kv.get("client-fingerprint"))
        .cloned()
        .filter(|s| !s.is_empty());

    let transport = match &protocol {
        ProtocolConfig::Shadowsocks { .. }
        | ProtocolConfig::Hysteria2 { .. }
        | ProtocolConfig::Tuic { .. } => TransportConfig::Tcp,
        _ => parse_shadowrocket_transport(&kv),
    };

    let mut node = NodeConfig::new(name, host, port, protocol);
    node.tls = TlsConfig {
        enabled: tls_enabled,
        server_name: sni,
        alpn,
        utls_fingerprint,
        verify_mode,
        imported_cert_sha256_hex,
        ..Default::default()
    };
    node.transport = transport;
    node.dial = DialOptions {
        tcp_fast_open: kv.get("tfo").map(|v| parse_bool(v)).unwrap_or(false),
        udp_relay: kv.get("udp-relay").map(|v| parse_bool(v)).unwrap_or(false),
    };
    normalize_node(&mut node);

    bundle.nodes.push(node);
    Ok(())
}

fn parse_shadowrocket_transport(kv: &HashMap<String, String>) -> TransportConfig {
    let obfs = kv
        .get("obfs")
        .or_else(|| kv.get("network"))
        .or_else(|| kv.get("type"))
        .map(|s| s.trim().to_ascii_lowercase());

    let is_ws_flag = kv.get("ws").is_some_and(|v| parse_bool(v));

    match obfs.as_deref() {
        Some("websocket" | "ws") => build_sr_ws_transport(kv),
        Some("grpc") => {
            let service_name = kv
                .get("servicename")
                .or_else(|| kv.get("service-name"))
                .or_else(|| kv.get("grpc-service-name"))
                .or_else(|| kv.get("path"))
                .cloned()
                .unwrap_or_default();
            TransportConfig::Grpc { service_name }
        }
        Some("httpupgrade") => {
            let path = kv
                .get("path")
                .filter(|s| !s.is_empty())
                .cloned()
                .unwrap_or_else(|| "/".to_string());
            let host = kv
                .get("obfsparam")
                .or_else(|| kv.get("obfs-param"))
                .or_else(|| kv.get("host"))
                .filter(|s| !s.is_empty())
                .cloned();
            TransportConfig::HttpUpgrade { path, host }
        }
        _ if is_ws_flag => build_sr_ws_transport(kv),
        _ => TransportConfig::Tcp,
    }
}

fn build_sr_ws_transport(kv: &HashMap<String, String>) -> TransportConfig {
    let path = kv
        .get("path")
        .or_else(|| kv.get("ws-path"))
        .filter(|s| !s.is_empty())
        .cloned()
        .unwrap_or_else(|| "/".to_string());
    let mut headers = BTreeMap::new();
    if let Some(ws_headers) = kv.get("ws-headers").filter(|s| !s.is_empty()) {
        for pair in ws_headers.split('|') {
            if let Some((k, v)) = pair.split_once(':') {
                let kt = k.trim();
                let vt = v.trim();
                if !kt.is_empty() && !vt.is_empty() {
                    headers.insert(kt.to_string(), vt.to_string());
                }
            }
        }
    }
    if !headers.contains_key("Host") {
        if let Some(host) = kv
            .get("obfsparam")
            .or_else(|| kv.get("obfs-param"))
            .or_else(|| kv.get("host"))
            .filter(|s| !s.is_empty())
        {
            headers.insert("Host".to_string(), host.clone());
        }
    }
    TransportConfig::Ws {
        path,
        headers,
        max_early_data: None,
        early_data_header_name: None,
    }
}

fn parse_rule_line(line: &str) -> Option<RuleEntry> {
    let trimmed = line.trim();
    // Handle logical OR rules like:
    // OR,((IP-ASN,44907,no-resolve),(DOMAIN-SUFFIX,example.com)),PROXY
    if trimmed.to_ascii_uppercase().starts_with("OR,") {
        return parse_or_rule(trimmed);
    }

    let parts: Vec<&str> = trimmed.split(',').map(|p| p.trim()).collect();
    if parts.is_empty() {
        return None;
    }
    let rule_type = parts[0].to_ascii_uppercase();

    if rule_type == "FINAL" || rule_type == "MATCH" {
        let action_str = parts.get(1).copied().unwrap_or("PROXY");
        return Some(RuleEntry {
            matcher: RuleMatch::Final,
            action: parse_action(action_str),
            no_resolve: false,
        });
    }

    if parts.len() < 3 {
        return None;
    }

    let value = parts[1].to_string();
    let action = parse_action(parts[2]);
    let no_resolve = parts[3..]
        .iter()
        .any(|p| p.eq_ignore_ascii_case("no-resolve"));

    let matcher = match rule_type.as_str() {
        "DOMAIN" => RuleMatch::Domain(value),
        "DOMAIN-SUFFIX" => RuleMatch::DomainSuffix(value),
        "DOMAIN-KEYWORD" => RuleMatch::DomainKeyword(value),
        "IP-CIDR" => RuleMatch::IpCidr(value),
        "IP-CIDR6" => RuleMatch::IpCidr6(value),
        "GEOIP" => RuleMatch::GeoIp(value),
        "RULE-SET" => RuleMatch::RuleSet(value),
        "PROCESS-NAME" => RuleMatch::ProcessName(value),
        _ => RuleMatch::Unsupported {
            raw_type: rule_type,
            raw_value: value,
        },
    };

    Some(RuleEntry {
        matcher,
        action,
        no_resolve,
    })
}

fn parse_or_rule(trimmed: &str) -> Option<RuleEntry> {
    // Strip leading "OR,"
    let rest = trimmed.get(3..)?.trim();
    let last_comma = rest.rfind(',')?;
    let expr = rest[..last_comma].trim();
    let action = parse_action(rest[last_comma + 1..].trim());

    let inner = expr.strip_prefix('(')?.strip_suffix(')')?;
    let mut sub_matchers = Vec::new();
    let mut depth = 0usize;
    let mut start = None;

    for (i, ch) in inner.char_indices() {
        match ch {
            '(' => {
                if depth == 0 {
                    start = Some(i + 1);
                }
                depth += 1;
            }
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    if let Some(s) = start.take() {
                        let sub = &inner[s..i];
                        let sp: Vec<&str> = sub.split(',').map(|p| p.trim()).collect();
                        if sp.len() >= 2 {
                            let st = sp[0].to_ascii_uppercase();
                            let sv = sp[1].to_string();
                            let m = match st.as_str() {
                                "DOMAIN" => RuleMatch::Domain(sv),
                                "DOMAIN-SUFFIX" => RuleMatch::DomainSuffix(sv),
                                "DOMAIN-KEYWORD" => RuleMatch::DomainKeyword(sv),
                                "IP-CIDR" => RuleMatch::IpCidr(sv),
                                "IP-CIDR6" => RuleMatch::IpCidr6(sv),
                                "GEOIP" => RuleMatch::GeoIp(sv),
                                "PROCESS-NAME" => RuleMatch::ProcessName(sv),
                                _ => RuleMatch::Unsupported {
                                    raw_type: st,
                                    raw_value: sv,
                                },
                            };
                            sub_matchers.push(m);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if sub_matchers.is_empty() {
        return None;
    }

    Some(RuleEntry {
        matcher: RuleMatch::LogicalOr(sub_matchers),
        action,
        no_resolve: true,
    })
}

fn parse_action(raw: &str) -> RuleAction {
    match raw.trim().to_ascii_uppercase().as_str() {
        "DIRECT" => RuleAction::Direct,
        "PROXY" => RuleAction::Proxy,
        "REJECT" | "REJECT-TINYGIF" | "REJECT-DROP" => RuleAction::Reject,
        _ => RuleAction::Group(raw.trim().to_string()),
    }
}

fn parse_bool(s: &str) -> bool {
    matches!(s.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes")
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}
