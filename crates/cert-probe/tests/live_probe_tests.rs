use std::net::UdpSocket as StdUdpSocket;
use std::process::Command;
use std::sync::Arc;

use maxq_cert_probe::salamander::{SalamanderObfuscator, SalamanderUdpSocket};
use maxq_cert_probe::{
    apply_confirmed_pin, detect_singbox_log_pin_mismatch, evaluate_probe_against_node,
    parse_leaf_cert_der, probe_certificate, ProbeError, ProbeRequest, ProbeTransport,
};
use maxq_core_model::{NodeConfig, PinCheckOutcome, ProtocolConfig, TlsConfig, TlsVerifyMode};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

fn generate_self_signed_cert(dns_names: &[&str]) -> (Vec<u8>, String, Vec<u8>) {
    let mut params = CertificateParams::new(dns_names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        .expect("cert params");
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        dns_names.first().copied().unwrap_or("maxq.local"),
    );
    let key_pair = KeyPair::generate().expect("key pair");
    let cert = params.self_signed(&key_pair).expect("self signed cert");
    let cert_der = cert.der().to_vec();
    let cert_pem = cert.pem();
    let key_der = key_pair.serialize_der();
    (cert_der, cert_pem, key_der)
}

#[test]
fn spki_sha256_matches_openssl_singbox_formula_byte_for_byte() {
    let (cert_der, cert_pem, _) = generate_self_signed_cert(&["cos.ap-guangzhou.example.com"]);
    let probed = parse_leaf_cert_der(&cert_der, "cos.ap-guangzhou.example.com", 1)
        .expect("parse leaf cert");

    assert!(probed.is_self_signed);
    assert!(probed.hostname_matches_sni);

    // Cross-check directly against the exact OpenSSL command from sing-box v1.14 docs:
    // openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
    let tmp_pem = std::env::temp_dir().join("maxq_spki_crosscheck.pem");
    std::fs::write(&tmp_pem, &cert_pem).expect("write temp pem");

    let output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "openssl x509 -in '{}' -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64",
            tmp_pem.display()
        ))
        .output()
        .expect("run openssl");
    let _ = std::fs::remove_file(&tmp_pem);

    assert!(
        output.status.success(),
        "openssl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let openssl_spki_b64 = String::from_utf8(output.stdout).unwrap().trim().to_string();
    assert_eq!(
        probed.spki_sha256_b64, openssl_spki_b64,
        "SPKI SHA-256 Base64 MUST match sing-box / OpenSSL exactly"
    );
}

#[tokio::test]
async fn probes_live_local_self_signed_tcp_tls_server_and_detects_mitm_drift() {
    let (cert_der_1, _, key_der_1) = generate_self_signed_cert(&["edge.example.com"]);
    let expected_1 = parse_leaf_cert_der(&cert_der_1, "edge.example.com", 1).unwrap();

    let server_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(cert_der_1.clone())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der_1)),
    )
    .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_task = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let _ = acceptor.accept(stream).await;
        }
    });

    let req = ProbeRequest {
        host: "127.0.0.1".into(),
        port,
        sni: "edge.example.com".into(),
        alpn: vec![],
        transport: ProbeTransport::TcpTls,
        timeout_ms: 5_000,
    };
    let probed = probe_certificate(&req)
        .await
        .expect("TCP+TLS probe must capture self-signed cert");
    let _ = server_task.await;

    assert_eq!(probed.spki_sha256_b64, expected_1.spki_sha256_b64);
    assert_eq!(probed.cert_sha256_hex, expected_1.cert_sha256_hex);

    // 1. Test cryptographic pcs -> SPKI bootstrap (matching vs MITM mismatch)
    let mut pcs_node = NodeConfig::new(
        "PCS Node",
        "127.0.0.1",
        port,
        ProtocolConfig::Trojan {
            password: "pw".into(),
        },
    );
    pcs_node.tls = TlsConfig {
        enabled: true,
        server_name: Some("edge.example.com".into()),
        verify_mode: TlsVerifyMode::PendingPinBootstrap,
        imported_cert_sha256_hex: Some(expected_1.cert_sha256_hex.clone()),
        ..Default::default()
    };
    let eval = evaluate_probe_against_node(&pcs_node, &probed).expect("matching pcs should succeed");
    assert_eq!(eval.outcome, PinCheckOutcome::Matched);
    apply_confirmed_pin(&mut pcs_node, eval.proposed_trust_record);
    assert_eq!(pcs_node.tls.verify_mode, TlsVerifyMode::PinnedSpki);

    // 2. Test MITM detection when server presents a DIFFERENT certificate
    let (cert_der_2, _, _) = generate_self_signed_cert(&["edge.example.com"]);
    let attacker_probed = parse_leaf_cert_der(&cert_der_2, "edge.example.com", 1).unwrap();
    let drift = evaluate_probe_against_node(&pcs_node, &attacker_probed).unwrap();
    assert!(matches!(
        drift.outcome,
        PinCheckOutcome::Mismatch {
            expected_spki_b64,
            observed_spki_b64,
            ..
        } if expected_spki_b64 == expected_1.spki_sha256_b64 && observed_spki_b64 == attacker_probed.spki_sha256_b64
    ));

    // 3. Test pcs bootstrap rejects mismatched cert
    let mut bad_pcs_node = NodeConfig::new(
        "Bad PCS",
        "127.0.0.1",
        port,
        ProtocolConfig::Trojan {
            password: "pw".into(),
        },
    );
    bad_pcs_node.tls = TlsConfig {
        enabled: true,
        server_name: Some("edge.example.com".into()),
        verify_mode: TlsVerifyMode::PendingPinBootstrap,
        imported_cert_sha256_hex: Some("0".repeat(64)),
        ..Default::default()
    };
    let err = evaluate_probe_against_node(&bad_pcs_node, &probed).unwrap_err();
    assert!(matches!(err, ProbeError::ImportedPinMismatch { .. }));
}

#[tokio::test]
async fn probes_live_local_quic_and_hysteria2_salamander_self_signed_servers() {
    let (cert_der, _, key_der) = generate_self_signed_cert(&["hy2.example.com"]);
    let expected = parse_leaf_cert_der(&cert_der, "hy2.example.com", 1).unwrap();

    let mut rustls_server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(cert_der.clone())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
    )
    .unwrap();
    rustls_server.alpn_protocols = vec![b"h3".to_vec()];

    let quic_server_crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(rustls_server).unwrap();
    let server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_server_crypto));

    // Part A: Plain QUIC server (TUIC / unobfuscated Hysteria2)
    let plain_endpoint = quinn::Endpoint::server(server_cfg.clone(), "127.0.0.1:0".parse().unwrap())
        .expect("bind plain QUIC server");
    let plain_port = plain_endpoint.local_addr().unwrap().port();
    let plain_task = tokio::spawn(async move {
        if let Some(incoming) = plain_endpoint.accept().await {
            let _ = incoming.await;
        }
    });

    let plain_req = ProbeRequest {
        host: "127.0.0.1".into(),
        port: plain_port,
        sni: "hy2.example.com".into(),
        alpn: vec!["h3".into()],
        transport: ProbeTransport::Quic {
            salamander_password: None,
        },
        timeout_ms: 5_000,
    };
    let plain_probed = probe_certificate(&plain_req)
        .await
        .expect("Plain QUIC probe must capture self-signed cert");
    assert_eq!(plain_probed.spki_sha256_b64, expected.spki_sha256_b64);
    plain_task.abort();

    // Part B: Salamander-obfuscated Hysteria2 QUIC server
    let psk = "salamander-test-password-2026";
    let obfs = SalamanderObfuscator::new(psk.as_bytes()).unwrap();
    let std_udp = StdUdpSocket::bind("127.0.0.1:0").unwrap();
    let sal_port = std_udp.local_addr().unwrap().port();
    let wrapped_srv = SalamanderUdpSocket::new(std_udp, obfs).unwrap();
    let sal_endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_cfg),
        Arc::new(wrapped_srv),
        quinn::default_runtime().unwrap(),
    )
    .expect("bind Salamander QUIC server");

    let sal_task = tokio::spawn(async move {
        if let Some(incoming) = sal_endpoint.accept().await {
            let _ = incoming.await;
        }
    });

    let sal_req = ProbeRequest {
        host: "127.0.0.1".into(),
        port: sal_port,
        sni: "hy2.example.com".into(),
        alpn: vec!["h3".into()],
        transport: ProbeTransport::Quic {
            salamander_password: Some(psk.into()),
        },
        timeout_ms: 5_000,
    };
    let sal_probed = probe_certificate(&sal_req)
        .await
        .expect("Salamander-obfuscated QUIC probe must capture self-signed cert");
    assert_eq!(sal_probed.spki_sha256_b64, expected.spki_sha256_b64);
    assert_eq!(sal_probed.cert_sha256_hex, expected.cert_sha256_hex);
    sal_task.abort();
}

#[test]
fn detects_singbox_runtime_log_spki_mismatch() {
    let log = r#"ERROR[0012] [12345 12ms] outbound/trojan[proxy]: unrecognized remote public key: 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="#;
    assert_eq!(
        detect_singbox_log_pin_mismatch(log).as_deref(),
        Some("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")
    );
    assert!(detect_singbox_log_pin_mismatch("INFO[0001] sing-box started").is_none());
}
