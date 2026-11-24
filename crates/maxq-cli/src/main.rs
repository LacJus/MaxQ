use std::env;
use std::fs;
use std::process;

use maxq_cert_probe::{probe_certificate, ProbeRequest};
use maxq_core_model::{HostClassification, RuntimePolicy, TlsVerifyMode, TrustOrigin};
use maxq_parser::parse_input;
use maxq_sanitizer::{apply_approved_host_aliases, sanitize_import};
use maxq_singbox_compiler::{compile_singbox_v14, CompileInput};

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "Usage:\n  maxq-cli audit <file_or_link>\n  maxq-cli probe-link <share_link>\n  maxq-cli compile-dryrun <file_or_link> <out_json_path> [--approve-proxy-hosts] [--pin-spki <b64>]"
        );
        process::exit(2);
    }

    match args[1].as_str() {
        "audit" => cmd_audit(&args[2]),
        "probe-link" => cmd_probe_link(&args[2]).await,
        "compile-dryrun" => {
            if args.len() < 4 {
                eprintln!("missing <out_json_path>");
                process::exit(2);
            }
            let approve_proxy_hosts = args.iter().any(|a| a == "--approve-proxy-hosts");
            let pin_spki = args
                .windows(2)
                .find(|w| w[0] == "--pin-spki")
                .map(|w| w[1].clone());
            cmd_compile_dryrun(&args[2], &args[3], approve_proxy_hosts, pin_spki);
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            process::exit(2);
        }
    }
}

fn load_input(arg: &str) -> String {
    if std::path::Path::new(arg).exists() {
        fs::read_to_string(arg).expect("failed to read input file")
    } else {
        arg.to_string()
    }
}

fn cmd_audit(arg: &str) {
    let content = load_input(arg);
    let raw = parse_input(&content).unwrap_or_else(|e| {
        eprintln!("parse error: {e}");
        process::exit(1);
    });
    let sanitized = sanitize_import(raw);
    println!(
        "{}",
        serde_json::to_string_pretty(&sanitized.report).unwrap()
    );
    if !sanitized.parse_warnings.is_empty() {
        eprintln!(
            "Parse warnings ({}):",
            sanitized.parse_warnings.len()
        );
        for w in sanitized.parse_warnings.iter().take(10) {
            eprintln!("  - {w}");
        }
    }
}

async fn cmd_probe_link(link: &str) {
    let raw = parse_input(link).unwrap_or_else(|e| {
        eprintln!("parse error: {e}");
        process::exit(1);
    });
    let sanitized = sanitize_import(raw);
    let Some(node) = sanitized.nodes.first() else {
        eprintln!("no node parsed");
        process::exit(1);
    };
    let req = ProbeRequest::from_node(node);
    match probe_certificate(&req).await {
        Ok(cert) => println!("{}", serde_json::to_string_pretty(&cert).unwrap()),
        Err(e) => {
            eprintln!("probe failed: {e}");
            process::exit(1);
        }
    }
}

fn cmd_compile_dryrun(
    arg: &str,
    out_path: &str,
    approve_proxy_hosts: bool,
    pin_spki: Option<String>,
) {
    let content = load_input(arg);
    let raw = parse_input(&content).unwrap_or_else(|e| {
        eprintln!("parse error: {e}");
        process::exit(1);
    });
    let mut sanitized = sanitize_import(raw);

    if approve_proxy_hosts {
        for h in &mut sanitized.hosts {
            if h.classification == HostClassification::ProxyEndpointAlias {
                h.approved = true;
            }
        }
        let applied = apply_approved_host_aliases(&mut sanitized.nodes, &sanitized.hosts);
        println!("Applied {applied} approved ProxyEndpointAlias host override(s).");
    }

    // Pick the first real (non-metadata) proxy node
    let target_idx = sanitized
        .nodes
        .iter()
        .position(|n| !n.is_metadata_node)
        .unwrap_or(0);
    let node = sanitized
        .nodes
        .get_mut(target_idx)
        .expect("no node available");

    if let Some(spki) = pin_spki {
        node.tls.verify_mode = TlsVerifyMode::PinnedSpki;
        node.tls.trust_record = Some(maxq_core_model::TrustRecord {
            spki_sha256_b64: spki,
            cert_sha256_hex: "0".repeat(64),
            cert_sha256_b64: String::new(),
            sni: node.effective_sni().to_string(),
            subject: format!("CN={}", node.effective_sni()),
            issuer: "manual".into(),
            san_dns: vec![],
            san_ip: vec![],
            not_before: String::new(),
            not_after: String::new(),
            is_self_signed: false,
            first_seen_at: chrono::Utc::now(),
            last_verified_at: chrono::Utc::now(),
            origin: TrustOrigin::Manual,
        });
    }

    let policy = RuntimePolicy::default();
    let compiled = compile_singbox_v14(&CompileInput {
        active_node: node,
        rules: &sanitized.rules,
        general: &sanitized.general,
        approved_hosts: &sanitized.hosts,
        policy: &policy,
    })
    .unwrap_or_else(|e| {
        eprintln!("compile error: {e}");
        process::exit(1);
    });

    fs::write(out_path, serde_json::to_string_pretty(&compiled.json).unwrap())
        .expect("failed to write compiled config");
    println!(
        "Compiled sing-box v1.14 config to {out_path} (coalesced_route_rules={}, skipped_rules={})",
        compiled.coalesced_route_rules_count, compiled.skipped_rules_count
    );
}
