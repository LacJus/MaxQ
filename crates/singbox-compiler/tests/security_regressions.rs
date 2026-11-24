use maxq_cert_probe::{evaluate_probe_against_node, parse_leaf_cert_der, ProbeError};
use maxq_core_model::{
    GeneralSettings, HostClassification, HostEntry, NodeConfig, ProtocolConfig, RuleAction,
    RuleEntry, RuleMatch, RuntimePolicy, TlsConfig, TlsVerifyMode,
};
use maxq_parser::parse_input;
use maxq_sanitizer::sanitize_import;
use maxq_singbox_compiler::{compile_singbox_v14, CompileError, CompileInput};

#[test]
fn c1_never_merges_domain_and_ip_cidr_into_same_singbox_rule() {
    let mut node = NodeConfig::new(
        "AnyTLS",
        "edge.example.com",
        443,
        ProtocolConfig::AnyTls {
            password: "pw".into(),
            idle_session_check_interval: None,
            idle_session_timeout: None,
            min_idle_session: None,
        },
    );
    node.tls.enabled = true;
    node.tls.verify_mode = TlsVerifyMode::SystemCa;

    let rules = vec![
        RuleEntry {
            matcher: RuleMatch::DomainSuffix("cn".into()),
            action: RuleAction::Direct,
            no_resolve: false,
        },
        RuleEntry {
            matcher: RuleMatch::IpCidr("114.114.114.114/32".into()),
            action: RuleAction::Direct,
            no_resolve: false,
        },
    ];

    let compiled = compile_singbox_v14(&CompileInput {
        active_node: &node,
        rules: &rules,
        general: &GeneralSettings::default(),
        approved_hosts: &[],
        policy: &RuntimePolicy::default(),
    })
    .unwrap();

    let route_rules = compiled.json["route"]["rules"].as_array().unwrap();
    for r in route_rules {
        let has_domain = r.get("domain").is_some()
            || r.get("domain_suffix").is_some()
            || r.get("domain_keyword").is_some();
        let has_ip = r.get("ip_cidr").is_some();
        assert!(
            !(has_domain && has_ip),
            "C-1 regression: domain and ip_cidr must NEVER be merged into the same sing-box rule: {r}"
        );
    }
}

#[test]
fn c2_strips_public_tun_excluded_routes_bypass() {
    let conf = r#"
[General]
tun-excluded-routes = 0.0.0.0/0, ::/0, 2000::/3, 192.168.0.0/16
[Proxy]
N1 = anytls, edge.example.com, 443, password=pw, sni=edge.example.com
"#;
    let sanitized = sanitize_import(parse_input(conf).unwrap());
    assert_eq!(sanitized.general.tun_excluded_routes, vec!["192.168.0.0/16"]);

    // Defense-in-depth inside compiler even if caller bypasses sanitizer
    let mut dirty_general = GeneralSettings::default();
    dirty_general.tun_excluded_routes = vec!["0.0.0.0/0".into(), "::/0".into()];
    let mut policy = RuntimePolicy::default();
    policy.tun_enabled = true;

    let compiled = compile_singbox_v14(&CompileInput {
        active_node: &sanitized.nodes[0],
        rules: &[],
        general: &dirty_general,
        approved_hosts: &[],
        policy: &policy,
    })
    .unwrap();

    let excluded = compiled.json["inbounds"][1]["route_exclude_address"]
        .as_array()
        .unwrap();
    assert!(!excluded.iter().any(|v| v == "0.0.0.0/0" || v == "::/0"));
}

#[test]
fn c3_pending_pin_bootstrap_fails_closed_when_hash_missing() {
    let mut node = NodeConfig::new(
        "Corrupted PCS",
        "edge.example.com",
        443,
        ProtocolConfig::Trojan {
            password: "pw".into(),
        },
    );
    node.tls = TlsConfig {
        enabled: true,
        verify_mode: TlsVerifyMode::PendingPinBootstrap,
        imported_cert_sha256_hex: None,
        ..Default::default()
    };

    // Minimal valid probed cert via dummy rcgen or mock struct
    let probed = maxq_cert_probe::ProbedCertificate {
        spki_sha256_b64: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".into(),
        cert_sha256_hex: "a".repeat(64),
        cert_sha256_b64: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".into(),
        sni: "edge.example.com".into(),
        subject: "CN=edge.example.com".into(),
        issuer: "CN=edge.example.com".into(),
        san_dns: vec![],
        san_ip: vec![],
        not_before: String::new(),
        not_after: String::new(),
        is_self_signed: true,
        hostname_matches_sni: true,
        chain_len: 1,
    };

    let err = evaluate_probe_against_node(&node, &probed).unwrap_err();
    assert!(matches!(err, ProbeError::MissingImportedPin));
    // Also verify trailing DER bytes rejected (L-2)
    assert!(parse_leaf_cert_der(b"not-der-bytes", "a", 1).is_err());
}

#[test]
fn h2_dns_rules_preserve_proxy_precedence_over_direct() {
    let mut node = NodeConfig::new(
        "AnyTLS",
        "edge.example.com",
        443,
        ProtocolConfig::AnyTls {
            password: "pw".into(),
            idle_session_check_interval: None,
            idle_session_timeout: None,
            min_idle_session: None,
        },
    );
    node.tls.enabled = true;

    let rules = vec![
        RuleEntry {
            matcher: RuleMatch::Domain("sensitive.cn".into()),
            action: RuleAction::Proxy,
            no_resolve: false,
        },
        RuleEntry {
            matcher: RuleMatch::DomainSuffix("cn".into()),
            action: RuleAction::Direct,
            no_resolve: false,
        },
    ];

    let compiled = compile_singbox_v14(&CompileInput {
        active_node: &node,
        rules: &rules,
        general: &GeneralSettings::default(),
        approved_hosts: &[],
        policy: &RuntimePolicy::default(),
    })
    .unwrap();

    let dns_rules = compiled.json["dns"]["rules"].as_array().unwrap();
    let proxy_idx = dns_rules
        .iter()
        .position(|r| r.get("domain") == Some(&serde_json::json!(["sensitive.cn"])) && r["server"] == "dns-remote")
        .expect("sensitive.cn MUST have an explicit dns-remote rule ahead of direct .cn");
    let direct_idx = dns_rules
        .iter()
        .position(|r| r.get("domain_suffix") == Some(&serde_json::json!(["cn"])) && r["server"] == "dns-direct")
        .expect("cn suffix direct DNS rule should exist");
    assert!(proxy_idx < direct_idx);
}

#[test]
fn h3_blocks_tls_stripping_on_mandatory_tls_protocols() {
    let evil_link = "trojan://pw@edge.example.com:443?security=none#Downgraded";
    let sanitized = sanitize_import(parse_input(evil_link).unwrap());
    assert!(sanitized.nodes[0].tls.enabled);

    let mut forced_off = sanitized.nodes[0].clone();
    forced_off.tls.enabled = false;
    let err = compile_singbox_v14(&CompileInput {
        active_node: &forced_off,
        rules: &[],
        general: &GeneralSettings::default(),
        approved_hosts: &[],
        policy: &RuntimePolicy::default(),
    })
    .unwrap_err();
    assert!(matches!(err, CompileError::MandatoryTlsDisabled { .. }));
}

#[test]
fn h5_proxy_endpoint_alias_ip_does_not_hijack_global_dns_hosts() {
    let mut node = NodeConfig::new(
        "AnyTLS",
        "edge.example.com",
        443,
        ProtocolConfig::AnyTls {
            password: "pw".into(),
            idle_session_check_interval: None,
            idle_session_timeout: None,
            min_idle_session: None,
        },
    );
    node.tls.enabled = true;

    let hosts = vec![HostEntry {
        domain: "edge.example.com".into(),
        target: "203.0.113.10".into(),
        is_ip_target: true,
        classification: HostClassification::ProxyEndpointAlias,
        approved: true,
    }];

    let compiled = compile_singbox_v14(&CompileInput {
        active_node: &node,
        rules: &[],
        general: &GeneralSettings::default(),
        approved_hosts: &hosts,
        policy: &RuntimePolicy::default(),
    })
    .unwrap();

    let dns_servers = compiled.json["dns"]["servers"].as_array().unwrap();
    assert!(
        !dns_servers.iter().any(|s| s["tag"] == "dns-hosts"),
        "ProxyEndpointAlias must NOT be injected into global dns-hosts"
    );
}

#[test]
fn m1_catches_inline_comment_mitm_and_hyphenated_url_rewrite_headers() {
    let conf = "\u{feff}\n[General]\nbypass-system = true\n[MITM] # sneak\nenable = true\n[URL-Rewrite] ; sneak\n^http://a http://b 302\n[Proxy]\nN1 = anytls, edge.example.com, 443, password=pw\n";
    let sanitized = sanitize_import(parse_input(conf).unwrap());
    assert_eq!(sanitized.report.stripped_sections.len(), 2);
    assert!(sanitized.report.has_high_or_critical());
}

#[test]
fn m3_and_m4_enforce_strong_secret_cors_and_final_reject() {
    let mut node = NodeConfig::new(
        "AnyTLS",
        "edge.example.com",
        443,
        ProtocolConfig::AnyTls {
            password: "pw".into(),
            idle_session_check_interval: None,
            idle_session_timeout: None,
            min_idle_session: None,
        },
    );
    node.tls.enabled = true;

    // Weak / whitespace secret rejected
    let mut bad_policy = RuntimePolicy::default();
    bad_policy.clash_api_secret = "                                ".into();
    assert!(matches!(
        compile_singbox_v14(&CompileInput {
            active_node: &node,
            rules: &[],
            general: &GeneralSettings::default(),
            approved_hosts: &[],
            policy: &bad_policy,
        }),
        Err(CompileError::WeakClashApiSecret)
    ));

    // Unsafe CORS origin rejected
    let mut bad_cors = RuntimePolicy::default();
    bad_cors.clash_api_allowed_origins = vec!["null".into()];
    assert!(matches!(
        compile_singbox_v14(&CompileInput {
            active_node: &node,
            rules: &[],
            general: &GeneralSettings::default(),
            approved_hosts: &[],
            policy: &bad_cors,
        }),
        Err(CompileError::UnsafeCorsOrigins)
    ));

    // FINAL,REJECT compiles catch-all reject rule
    let rules = vec![RuleEntry {
        matcher: RuleMatch::Final,
        action: RuleAction::Reject,
        no_resolve: false,
    }];
    let compiled = compile_singbox_v14(&CompileInput {
        active_node: &node,
        rules: &rules,
        general: &GeneralSettings::default(),
        approved_hosts: &[],
        policy: &RuntimePolicy::default(),
    })
    .unwrap();
    let last_rule = compiled.json["route"]["rules"]
        .as_array()
        .unwrap()
        .last()
        .unwrap();
    assert_eq!(last_rule["action"], serde_json::json!("reject"));
}

#[test]
fn validates_ports_endpoints_doh_urls_domain_resolver_and_tun_loopback() {
    let mut node = NodeConfig::new(
        "AnyTLS",
        "edge.example.com",
        443,
        ProtocolConfig::AnyTls {
            password: "pw".into(),
            idle_session_check_interval: None,
            idle_session_timeout: None,
            min_idle_session: None,
        },
    );
    node.tls.enabled = true;

    // 1. Colliding local ports rejected
    let mut colliding = RuntimePolicy::default();
    colliding.mixed_listen_port = 17890;
    colliding.clash_api_port = 17890;
    assert!(matches!(
        compile_singbox_v14(&CompileInput {
            active_node: &node,
            rules: &[],
            general: &GeneralSettings::default(),
            approved_hosts: &[],
            policy: &colliding,
        }),
        Err(CompileError::InvalidPortConfig { .. })
    ));

    // 2. Port 0 node rejected
    let mut bad_node = node.clone();
    bad_node.server_port = 0;
    assert!(matches!(
        compile_singbox_v14(&CompileInput {
            active_node: &bad_node,
            rules: &[],
            general: &GeneralSettings::default(),
            approved_hosts: &[],
            policy: &RuntimePolicy::default(),
        }),
        Err(CompileError::InvalidNodeEndpoint { .. })
    ));

    // 3. Full https:// DoH URL with domain name automatically emits path + domain_resolver + detour=proxy
    let mut doh_policy = RuntimePolicy::default();
    doh_policy.remote_dns_server = "https://dns.google/dns-query".into();
    doh_policy.allow_lan = true;
    doh_policy.tun_enabled = true;
    let compiled = compile_singbox_v14(&CompileInput {
        active_node: &node,
        rules: &[],
        general: &GeneralSettings::default(),
        approved_hosts: &[],
        policy: &doh_policy,
    })
    .unwrap();
    let remote_dns = &compiled.json["dns"]["servers"][0];
    assert_eq!(remote_dns["server"], "dns.google");
    assert_eq!(remote_dns["path"], "/dns-query");
    assert_eq!(remote_dns["domain_resolver"], "dns-direct");
    assert_eq!(remote_dns["detour"], "proxy");

    // 4. TUN mode forces mixed-in strictly to 127.0.0.1 even when allow_lan = true
    assert_eq!(compiled.json["inbounds"][0]["listen"], "127.0.0.1");

    // 5. Non-IP direct bootstrap DNS rejected
    let mut bad_dns = RuntimePolicy::default();
    bad_dns.direct_dns_server = "dns.alidns.com".into();
    assert!(matches!(
        compile_singbox_v14(&CompileInput {
            active_node: &node,
            rules: &[],
            general: &GeneralSettings::default(),
            approved_hosts: &[],
            policy: &bad_dns,
        }),
        Err(CompileError::InvalidDnsServer { .. })
    ));
}
