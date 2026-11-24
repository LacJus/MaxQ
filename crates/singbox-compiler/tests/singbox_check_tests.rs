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
    let fallback = PathBuf::from("/home/antigravity/.local/bin/sing-box");
    if fallback.exists() {
        return Some(fallback);
    }
    None
}

fn verify_with_real_singbox(json_value: &serde_json::Value, case_name: &str) {
    let Some(bin) = find_singbox_binary() else {
        panic!("sing-box v1.14.4 test validator binary not found at /home/antigravity/.local/bin/sing-box");
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
