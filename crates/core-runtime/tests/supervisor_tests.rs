use std::path::PathBuf;
use std::time::Duration;

use chrono::Utc;
use maxq_core_model::{
    GeneralSettings, NodeConfig, ProtocolConfig, RuntimePolicy, TlsVerifyMode, TrustOrigin,
    TrustRecord,
};
use maxq_core_runtime::{RuntimeEvent, SingBoxSupervisor};
use maxq_singbox_compiler::{compile_singbox_v14, CompileInput};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn starts_real_singbox_enforces_clash_api_bearer_auth_and_stops_cleanly() {
    let bin = std::env::var("SING_BOX_BIN")
        .map(PathBuf::from)
        .ok()
        .filter(|p| p.exists())
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".local/bin/sing-box"))
                .filter(|p| p.exists())
        })
        .unwrap_or_else(|| PathBuf::from("/home/antigravity/.local/bin/sing-box"));
    assert!(bin.exists(), "sing-box test binary must exist");

    let mut node = NodeConfig::new(
        "Test Pinned Trojan",
        "127.0.0.1",
        59999,
        ProtocolConfig::Trojan {
            password: "test-password".into(),
        },
    );
    node.tls.enabled = true;
    node.tls.server_name = Some("edge.example.com".into());
    node.tls.verify_mode = TlsVerifyMode::PinnedSpki;
    node.tls.trust_record = Some(TrustRecord {
        spki_sha256_b64: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".into(),
        cert_sha256_hex: "a".repeat(64),
        cert_sha256_b64: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".into(),
        sni: "edge.example.com".into(),
        subject: "CN=edge.example.com".into(),
        issuer: "CN=edge.example.com".into(),
        san_dns: vec!["edge.example.com".into()],
        san_ip: vec![],
        not_before: "2026-01-01".into(),
        not_after: "2027-01-01".into(),
        is_self_signed: true,
        first_seen_at: Utc::now(),
        last_verified_at: Utc::now(),
        origin: TrustOrigin::TofuProbe,
    });

    let mut policy = RuntimePolicy::default();
    policy.mixed_listen_port = 27890;
    policy.clash_api_port = 29090;

    let compiled = compile_singbox_v14(&CompileInput {
        active_node: &node,
        rules: &[],
        general: &GeneralSettings::default(),
        approved_hosts: &[],
        policy: &policy,
    })
    .unwrap();

    let runtime_dir = std::env::temp_dir().join("maxq_supervisor_test");
    let _ = std::fs::remove_dir_all(&runtime_dir);

    let mut supervisor = SingBoxSupervisor::new(bin, runtime_dir.clone());
    let mut rx = supervisor.subscribe();

    let pid = supervisor
        .start(
            node.id.clone(),
            node.name.clone(),
            &compiled,
            policy.mixed_listen_port,
            policy.clash_api_port,
        )
        .await
        .expect("start real sing-box");
    assert!(pid > 0);

    // Wait for Started event
    let ev = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(ev, RuntimeEvent::Started { .. }));

    // Give sing-box a brief moment to bind 127.0.0.1:29090
    let mut connected = false;
    for _ in 0..20 {
        if TcpStream::connect(("127.0.0.1", policy.clash_api_port))
            .await
            .is_ok()
        {
            connected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(connected, "sing-box Clash API did not start listening");

    // 1. Unauthenticated request MUST be rejected with 401 Unauthorized
    let unauth_resp = http_get_local(policy.clash_api_port, "/version", None).await;
    assert!(
        unauth_resp.starts_with("HTTP/1.1 401"),
        "expected 401 Unauthorized without Bearer token, got:\n{unauth_resp}"
    );

    // 2. Authenticated request with per-session Bearer secret MUST return 200 OK
    let secret = supervisor.clash_api_secret().unwrap().to_string();
    let auth_resp = http_get_local(policy.clash_api_port, "/version", Some(&secret)).await;
    assert!(
        auth_resp.starts_with("HTTP/1.1 200"),
        "expected 200 OK with Bearer token, got:\n{auth_resp}"
    );
    assert!(auth_resp.contains("sing-box") || auth_resp.contains("1.14"));

    supervisor.stop().await.expect("stop sing-box");
    assert!(!supervisor.status().running);
    let _ = std::fs::remove_dir_all(&runtime_dir);
}

async fn http_get_local(port: u16, path: &str, bearer: Option<&str>) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let auth_hdr = match bearer {
        Some(tok) => format!("Authorization: Bearer {tok}\r\n"),
        None => String::new(),
    };
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth_hdr}Connection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}
