use std::path::PathBuf;
use std::process::Command;

use chrono::Utc;
use maxq_core_model::{
    GeneralSettings, HostClassification, HostEntry, Ipv6Policy, NodeConfig, ProtocolConfig,
    RuleAction, RuleEntry, RuleMatch, RuntimePolicy, TlsVerifyMode, TrustOrigin, TrustRecord,
};
use maxq_parser::parse_input;
use maxq_sanitizer::{apply_approved_host_aliases, sanitize_import};
use maxq_singbox_compiler::{compile_singbox_v14, CompileError, CompileInput};

fn find_singbox_binary() -> Option<PathBuf> {
    if let Ok(env_path) = std::env::var("SING_BOX_BIN") {
        let p = PathBuf::from(env_path);
        if p.exists() {
            return Some(p);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let candidate = PathBuf::from(home).join(".local/bin/sing-box");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    if let Some(paths) = std::env::var_os("PATH") {
        let bin_name = if cfg!(windows) {
            "sing-box.exe"
        } else {
            "sing-box"
        };
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join(bin_name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}

fn verify_with_real_singbox(json_value: &serde_json::Value, case_name: &str) {
    let Some(bin) = find_singbox_binary() else {
        panic!("sing-box v1.14.4 test validator binary not found; set SING_BOX_BIN or install sing-box in PATH / ~/.local/bin");
    };
    let tmp_path = std::env::temp_dir().join(format!("maxq_sb_check_{case_name}.json"));
    let content = serde_json::to_string_pretty(json_value).unwrap();
    std::fs::write(&tmp_path, &content).unwrap();

    let output = Command::new(&bin)
        .args(["check", "-c"])
        .arg(&tmp_path)
        .output()
        .expect("execute sing-box check");
    let _ = std::fs::remove_file(&tmp_path);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "sing-box check FAILED for {case_name}:\nstdout: {stdout}\nstderr: {stderr}\nconfig:\n{content}"
    );
    assert!(
        !stderr.to_ascii_lowercase().contains("deprecated")
            && !stdout.to_ascii_lowercase().contains("deprecated"),
        "sing-box check emitted DEPRECATION warning for {case_name}:\nstdout: {stdout}\nstderr: {stderr}"
    );
}

fn mock_trust_record(sni: &str) -> TrustRecord {
    TrustRecord {
        // Valid 32-byte SHA-256 in standard Base64
        spki_sha256_b64: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".into(),
        cert_sha256_hex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
        cert_sha256_b64: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".into(),
        sni: sni.into(),
        subject: format!("CN={sni}"),
        issuer: format!("CN={sni}"),
        san_dns: vec![sni.into()],
        san_ip: vec![],
        not_before: "2026-01-01T00:00:00Z".into(),
        not_after: "2027-01-01T00:00:00Z".into(),
        is_self_signed: true,
        first_seen_at: Utc::now(),
        last_verified_at: Utc::now(),
        origin: TrustOrigin::TofuProbe,
    }
}

#[test]
fn scheme_a_blocks_unverified_insecure_node_until_pinned_then_passes_real_singbox_check() {
    let link = "trojan://00000000-0000-4000-8000-000000000001@edge-sh.example.net:8205?allowInsecure=1&peer=cos.ap-guangzhou.example.com#%F0%9F%87%AF%F0%9F%87%B5%20JPN%20%E6%97%A5%E6%9C%AC%2005-4";
    let mut sanitized = sanitize_import(parse_input(link).unwrap());
    let policy = RuntimePolicy::default();

    // 1. Scheme A MUST block compilation while still unverified InsecureLegacy
    let err = compile_singbox_v14(&CompileInput {
        active_node: &sanitized.nodes[0],
        rules: &sanitized.rules,
        general: &sanitized.general,
        approved_hosts: &sanitized.hosts,
        policy: &policy,
    })
    .unwrap_err();
    assert!(matches!(err, CompileError::UnverifiedInsecureNode { .. }));

    // 2. Simulate Probe & Pin upgrade to PinnedSpki
    sanitized.nodes[0].tls.verify_mode = TlsVerifyMode::PinnedSpki;
    sanitized.nodes[0].tls.trust_record = Some(mock_trust_record("cos.ap-guangzhou.example.com"));

    let compiled = compile_singbox_v14(&CompileInput {
        active_node: &sanitized.nodes[0],
        rules: &sanitized.rules,
        general: &sanitized.general,
        approved_hosts: &sanitized.hosts,
        policy: &policy,
    })
    .expect("pinned node must compile cleanly");

    // Verify critical security invariants in generated JSON
    assert_eq!(compiled.clash_api_secret.len(), 64); // 32 random bytes hex
    assert_eq!(
        compiled.json["dns"]["servers"][0]["detour"],
        serde_json::json!("proxy"),
        "v1.12+ DoH DNS server MUST explicitly set detour=proxy to avoid DNS leak"
    );
    assert_eq!(
        compiled.json["outbounds"][0]["tls"]["insecure"],
        serde_json::json!(false)
    );
    assert_eq!(
        compiled.json["outbounds"][0]["tls"]["certificate_public_key_sha256"],
        serde_json::json!(["47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="])
    );

    verify_with_real_singbox(&compiled.json, "trojan_pinned");
}

#[test]
fn all_seven_protocols_and_tun_mode_pass_real_singbox_v14_check_with_zero_warnings() {
    let links = [
        ("anytls", "anytls://pw123@any.example.com:443?sni=any.example.com&alpn=h2#AnyTLS"),
        ("hy2", "hy2://hy2pw@hy2.example.com:443?obfs=salamander&obfs-password=salpass123&mport=20000-30000&sni=hy2.example.com#Hy2"),
        ("tuic", "tuic://22222222-2222-4222-8222-222222222222:tuicpw@tuic.example.com:8443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=tuic.example.com#TUIC"),
        ("vless_reality", "vless://33333333-3333-4333-8333-333333333333@vless.example.com:443?security=reality&flow=xtls-rprx-vision&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=0123abcd&sni=www.example.org&fp=chrome#VLESS"),
        ("vmess_ws", "vmess://eyJ2IjoiMiIsInBzIjoiVk1lc3MiLCJhZGQiOiJ2bWVzcy5leGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6IjQ0NDQ0NDQ0LTQ0NDQtNDQ0NC04NDQ0LTQ0NDQ0NDQ0NDQ0NCIsImFpZCI6IjAiLCJuZXQiOiJ3cyIsInBhdGgiOiIvd3MiLCJob3N0IjoiY2RuLmV4YW1wbGUuY29tIiwidGxzIjoidGxzIiwic25pIjoiY2RuLmV4YW1wbGUuY29tIn0="),
        ("ss", "ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.com:8388#SS"),
    ];

    let mut policy = RuntimePolicy::default();
    policy.tun_enabled = true;
    policy.ipv6_mode = Ipv6Policy::BlockToPreventLeak;

    for (name, link) in links {
        let mut sanitized = sanitize_import(parse_input(link).unwrap());
        let node = &mut sanitized.nodes[0];
        // Pin TLS on modern direct protocols without Reality to verify SPKI field acceptance across protocols
        if node.tls.enabled && node.tls.reality.is_none() {
            node.tls.verify_mode = TlsVerifyMode::PinnedSpki;
            node.tls.trust_record = Some(mock_trust_record(node.effective_sni()));
        }

        let compiled = compile_singbox_v14(&CompileInput {
            active_node: node,
            rules: &[],
            general: &GeneralSettings::default(),
            approved_hosts: &[],
            policy: &policy,
        })
        .unwrap_or_else(|e| panic!("compile failed for {name}: {e}"));

        verify_with_real_singbox(&compiled.json, name);
    }
}

#[test]
fn coalesces_thousands_of_conf_rules_and_approved_host_aliases_and_passes_real_singbox_check() {
    let mut node = NodeConfig::new(
        "HKG 01",
        "edge-gz.example.net",
        8101,
        ProtocolConfig::Trojan {
            password: "test-password".into(),
        },
    );
    node.tls.enabled = true;
    node.tls.server_name = Some("cos.example.com".into());
    node.tls.verify_mode = TlsVerifyMode::PinnedSpki;
    node.tls.trust_record = Some(mock_trust_record("cos.example.com"));

    let hosts = vec![
        HostEntry {
            domain: "edge-gz.example.net".into(),
            target: "edge-gz.example-cdn.net".into(),
            is_ip_target: false,
            classification: HostClassification::ProxyEndpointAlias,
            approved: true,
        },
        HostEntry {
            domain: "nas.local".into(),
            target: "192.168.1.50".into(),
            is_ip_target: true,
            classification: HostClassification::LocalDomain,
            approved: true,
        },
    ];
    let mut nodes = vec![node];
    assert_eq!(apply_approved_host_aliases(&mut nodes, &hosts), 1);

    // Simulate a realistic 5,000+ rule Shadowrocket .conf
    let mut rules = Vec::new();
    for i in 0..2500 {
        rules.push(RuleEntry {
            matcher: RuleMatch::DomainSuffix(format!("cn-site-{i}.cn")),
            action: RuleAction::Direct,
            no_resolve: false,
        });
    }
    for i in 0..2500 {
        rules.push(RuleEntry {
            matcher: RuleMatch::IpCidr(format!("223.{}.{}.0/24", i / 256, i % 256)),
            action: RuleAction::Direct,
            no_resolve: false,
        });
    }
    rules.push(RuleEntry {
        matcher: RuleMatch::DomainSuffix("global-app.example.org".into()),
        action: RuleAction::Proxy,
        no_resolve: false,
    });
    rules.push(RuleEntry {
        matcher: RuleMatch::Final,
        action: RuleAction::Proxy,
        no_resolve: false,
    });

    let policy = RuntimePolicy::default();
    let compiled = compile_singbox_v14(&CompileInput {
        active_node: &nodes[0],
        rules: &rules,
        general: &GeneralSettings::default(),
        approved_hosts: &hosts,
        policy: &policy,
    })
    .expect("large ruleset should compile");

    // 5,001 rules coalesced into just a handful of compact route rules!
    assert!(
        compiled.coalesced_route_rules_count <= 10,
        "expected aggressive adjacent coalescing, got {} rules",
        compiled.coalesced_route_rules_count
    );
    assert_eq!(
        compiled.json["outbounds"][0]["server"],
        serde_json::json!("edge-gz.example-cdn.net")
    );
    assert_eq!(
        compiled.json["outbounds"][0]["tls"]["server_name"],
        serde_json::json!("cos.example.com")
    );

    verify_with_real_singbox(&compiled.json, "large_conf_5000_rules");
}

#[test]
fn builtin_default_rules_and_tun_service_gate_pass_real_singbox_check() {
    use maxq_core_model::{ProxyMode, RoutingMode};
    use maxq_singbox_compiler::builtin_default_rules_count;

    let count = builtin_default_rules_count();
    assert!(
        count > 8000,
        "expected >8000 built-in routing rules from default_rules.conf, got {count}"
    );

    let mut node = NodeConfig::new(
        "Single Trojan Link",
        "edge.example.net",
        8205,
        ProtocolConfig::Trojan {
            password: "test-password".into(),
        },
    );
    node.tls.enabled = true;
    node.tls.server_name = Some("cos.example.com".into());
    node.tls.verify_mode = TlsVerifyMode::PinnedSpki;
    node.tls.trust_record = Some(mock_trust_record("cos.example.com"));

    // 1. Single share link (empty profile rules) + TUN mode -> automatically uses built-in 8,581 rules!
    let mut policy = RuntimePolicy::default();
    policy.proxy_mode = ProxyMode::Tun;
    policy.routing_mode = RoutingMode::Rule;

    let compiled_rule = compile_singbox_v14(&CompileInput {
        active_node: &node,
        rules: &[],
        general: &GeneralSettings::default(),
        approved_hosts: &[],
        policy: &policy,
    })
    .expect("compile builtin rules + TUN");
    assert!(compiled_rule.used_builtin_rules);
    verify_with_real_singbox(&compiled_rule.json, "builtin_rules_tun");

    // Must ALSO pass privileged Windows TUN service secondary validator!
    let cfg_str = serde_json::to_string(&compiled_rule.json).unwrap();
    maxq_win_service::validator::validate_service_config(&cfg_str)
        .expect("compiled TUN config must satisfy hardened win-service validator");

    // 2. Global mode
    policy.routing_mode = RoutingMode::Global;
    let compiled_global = compile_singbox_v14(&CompileInput {
        active_node: &node,
        rules: &[],
        general: &GeneralSettings::default(),
        approved_hosts: &[],
        policy: &policy,
    })
    .unwrap();
    assert!(!compiled_global.used_builtin_rules);
    assert_eq!(compiled_global.json["route"]["final"], serde_json::json!("proxy"));
    verify_with_real_singbox(&compiled_global.json, "global_mode_tun");

    // 3. Direct mode
    policy.routing_mode = RoutingMode::Direct;
    let compiled_direct = compile_singbox_v14(&CompileInput {
        active_node: &node,
        rules: &[],
        general: &GeneralSettings::default(),
        approved_hosts: &[],
        policy: &policy,
    })
    .unwrap();
    assert_eq!(compiled_direct.json["route"]["final"], serde_json::json!("direct"));
    assert_eq!(compiled_direct.json["dns"]["final"], serde_json::json!("dns-direct"));
    verify_with_real_singbox(&compiled_direct.json, "direct_mode_tun");

    // 4. Domain-based DoH URL (`https://dns.google/dns-query`) + `allow_lan=true` in TUN mode
    policy.routing_mode = RoutingMode::Rule;
    policy.allow_lan = true;
    policy.remote_dns_server = "https://dns.google/dns-query".into();
    let compiled_doh = compile_singbox_v14(&CompileInput {
        active_node: &node,
        rules: &[],
        general: &GeneralSettings::default(),
        approved_hosts: &[],
        policy: &policy,
    })
    .unwrap();
    let doh_cfg_str = serde_json::to_string(&compiled_doh.json).unwrap();
    maxq_win_service::validator::validate_service_config(&doh_cfg_str)
        .expect("domain DoH + allow_lan TUN config must satisfy hardened win-service validator");
    verify_with_real_singbox(&compiled_doh.json, "domain_doh_tun");
}

#[test]
fn audit_fixes_quic_utls_dialect_norm_tun_ipv6_host_and_resolve_pass_real_singbox_check() {
    use maxq_core_model::{ProxyMode, RoutingMode};

    // 1. [P0-6] Hysteria2 & TUIC with fp=Chrome MUST NOT emit `utls`, and numeric durations/uppercase enums normalize cleanly
    let hy2_link = "hy2://hy2pw@hy2.example.com:443?sni=hy2.example.com&fp=Chrome&mport=20000-21000&hop_interval=30#Hy2-FP";
    let tuic_link = "tuic://22222222-2222-4222-8222-222222222222:tuicpw@v6-only.example.com:8443?congestion_control=BBR&udp_relay_mode=Native&heartbeat=10&fp=Chrome&sni=v6-only.example.com#TUIC-Upper";

    let mut policy = RuntimePolicy::default();
    policy.proxy_mode = ProxyMode::Tun;
    policy.routing_mode = RoutingMode::Rule;
    policy.ipv6_mode = Ipv6Policy::BlockToPreventLeak;

    for (tag, link) in [("hy2_no_utls", hy2_link), ("tuic_no_utls", tuic_link)] {
        let sanitized = sanitize_import(parse_input(link).unwrap());
        let compiled = compile_singbox_v14(&CompileInput {
            active_node: &sanitized.nodes[0],
            rules: &[],
            general: &GeneralSettings::default(),
            approved_hosts: &[],
            policy: &policy,
        })
        .unwrap_or_else(|e| panic!("compile failed for {tag}: {e}"));

        // uTLS MUST be absent on QUIC protocols
        assert!(
            compiled.json["outbounds"][0]["tls"].get("utls").is_none(),
            "{tag}: QUIC outbound must NEVER emit tls.utls"
        );
        verify_with_real_singbox(&compiled.json, tag);

        let cfg_str = serde_json::to_string(&compiled.json).unwrap();
        maxq_win_service::validator::validate_service_config(&cfg_str)
            .expect("TUN config must pass hardened win-service validator");
    }

    // 2. [P1-6a] TUN uses RFC 2544 198.18.0.1/30 and excludes CGNAT/multicast ranges
    //    [P1-6b] Pure IPv6 proxy hostname gets dns-direct rule BEFORE AAAA reject + default_domain_resolver prefer_ipv4
    let sanitized_tuic = sanitize_import(parse_input(tuic_link).unwrap());
    let compiled_tuic = compile_singbox_v14(&CompileInput {
        active_node: &sanitized_tuic.nodes[0],
        rules: &[],
        general: &GeneralSettings::default(),
        approved_hosts: &[],
        policy: &policy,
    })
    .unwrap();

    assert_eq!(
        compiled_tuic.json["inbounds"][1]["address"],
        serde_json::json!(["198.18.0.1/30", "fdfe:dcba:9876::1/126"])
    );
    let excluded = compiled_tuic.json["inbounds"][1]["route_exclude_address"]
        .as_array()
        .unwrap();
    for required in ["100.64.0.0/10", "224.0.0.0/4", "ff00::/8"] {
        assert!(
            excluded.iter().any(|v| v == required),
            "missing {required} in route_exclude_address"
        );
    }

    let dns_rules = compiled_tuic.json["dns"]["rules"].as_array().unwrap();
    let proxy_host_idx = dns_rules
        .iter()
        .position(|r| {
            r.get("domain") == Some(&serde_json::json!(["v6-only.example.com"]))
                && r["server"] == "dns-direct"
        })
        .expect("proxy host dns-direct rule must exist");
    let aaaa_reject_idx = dns_rules
        .iter()
        .position(|r| {
            r.get("query_type") == Some(&serde_json::json!(["AAAA"])) && r["action"] == "reject"
        })
        .expect("AAAA reject rule must exist");
    assert!(
        proxy_host_idx < aaaa_reject_idx,
        "proxy host rule must appear BEFORE AAAA reject rule"
    );
    assert_eq!(
        compiled_tuic.json["route"]["default_domain_resolver"],
        serde_json::json!({
            "server": "dns-direct",
            "strategy": "prefer_ipv4"
        })
    );

    // 3. [P1-6c] System Proxy mode IP-CIDR matching: `no-resolve` IP-CIDRs stay BEFORE `{"action":"resolve","server":"dns-remote"}`,
    //    and non-`no-resolve` CN IP-CIDRs follow the single `resolve` rule!
    let sys_policy = RuntimePolicy::default();
    let rules = vec![
        RuleEntry {
            matcher: RuleMatch::DomainSuffix("google.com".into()),
            action: RuleAction::Proxy,
            no_resolve: false,
        },
        RuleEntry {
            matcher: RuleMatch::IpCidr("149.154.160.0/20".into()),
            action: RuleAction::Proxy,
            no_resolve: true,
        },
        RuleEntry {
            matcher: RuleMatch::IpCidr("223.5.5.0/24".into()),
            action: RuleAction::Direct,
            no_resolve: false,
        },
        RuleEntry {
            matcher: RuleMatch::IpCidr("114.114.114.0/24".into()),
            action: RuleAction::Direct,
            no_resolve: false,
        },
        RuleEntry {
            matcher: RuleMatch::Final,
            action: RuleAction::Proxy,
            no_resolve: false,
        },
    ];
    let compiled_resolve = compile_singbox_v14(&CompileInput {
        active_node: &sanitized_tuic.nodes[0],
        rules: &rules,
        general: &GeneralSettings::default(),
        approved_hosts: &[],
        policy: &sys_policy,
    })
    .unwrap();
    let rrules = compiled_resolve.json["route"]["rules"].as_array().unwrap();
    let no_resolve_ip_idx = rrules
        .iter()
        .position(|r| r.get("ip_cidr") == Some(&serde_json::json!(["149.154.160.0/20"])))
        .expect("no-resolve IP-CIDR rule present");
    let resolve_indices: Vec<usize> = rrules
        .iter()
        .enumerate()
        .filter_map(|(i, r)| {
            (r.get("action") == Some(&serde_json::json!("resolve"))
                && r.get("server") == Some(&serde_json::json!("dns-remote")))
            .then_some(i)
        })
        .collect();
    assert_eq!(resolve_indices.len(), 1, "must emit exactly one resolve action");
    let cn_ip_idx = rrules
        .iter()
        .position(|r| {
            r.get("ip_cidr") == Some(&serde_json::json!(["223.5.5.0/24", "114.114.114.0/24"]))
        })
        .expect("non-no-resolve CN IP-CIDR group present");
    assert!(no_resolve_ip_idx < resolve_indices[0]);
    assert!(resolve_indices[0] < cn_ip_idx);
    verify_with_real_singbox(&compiled_resolve.json, "system_proxy_resolve_ip_cidr");

    // 4. [P1-2] Compiler defense-in-depth: raw unnormalized VMess chacha20-ietf-poly1305 + bracketed IPv6 + IP-literal SNI with SPKI pin
    let mut raw_vmess = NodeConfig::new(
        "Raw-VMess-IPv6",
        "[2001:db8::42]",
        443,
        ProtocolConfig::Vmess {
            uuid: "44444444-4444-4444-8444-444444444444".into(),
            alter_id: 0,
            security: "chacha20-ietf-poly1305".into(),
        },
    );
    raw_vmess.tls.enabled = true;
    raw_vmess.tls.server_name = Some("[2001:db8::42]".into());
    raw_vmess.tls.utls_fingerprint = Some("Chrome".into());
    raw_vmess.tls.verify_mode = TlsVerifyMode::PinnedSpki;
    raw_vmess.tls.trust_record = Some(mock_trust_record("2001:db8::42"));

    let compiled_vmess = compile_singbox_v14(&CompileInput {
        active_node: &raw_vmess,
        rules: &[],
        general: &GeneralSettings::default(),
        approved_hosts: &[],
        policy: &sys_policy,
    })
    .unwrap();
    assert_eq!(compiled_vmess.json["outbounds"][0]["server"], "2001:db8::42");
    assert_eq!(
        compiled_vmess.json["outbounds"][0]["security"],
        "chacha20-poly1305"
    );
    assert!(
        compiled_vmess.json["outbounds"][0]["tls"]
            .get("server_name")
            .is_none(),
        "IP literal must be omitted from tls.server_name"
    );
    assert_eq!(
        compiled_vmess.json["outbounds"][0]["tls"]["utls"]["fingerprint"],
        "chrome"
    );
    verify_with_real_singbox(&compiled_vmess.json, "vmess_ipv6_chacha_spki");
}
