use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use maxq_core_model::{
    HostClassification, HostEntry, ImportSecurityReport, NodeConfig, ProtocolConfig,
    RawImportBundle, RuleMatch, SanitizedImport, SecurityActionTaken, SecurityFinding,
    SecuritySeverity, TlsVerifyMode,
};
use url::Url;

/// Security Quarantine Engine (Pillar 1 + Scheme A enforcement).
///
/// Consumes an untrusted `RawImportBundle` produced by `maxq-parser` and returns
/// a safe `SanitizedImport` plus an explicit `ImportSecurityReport` for user audit.
pub fn sanitize_import(raw: RawImportBundle) -> SanitizedImport {
    let mut report = ImportSecurityReport::default();
    let mut nodes = raw.nodes;
    let mut general = raw.general;

    // 1. Enforce Scheme A (Strict Default Safe), strip untrusted pre-populated pins/overrides,
    //    and enforce mandatory TLS on Trojan / AnyTLS / Hysteria2 / TUIC.
    let mut insecure_names = Vec::new();
    let mut pending_pin_names = Vec::new();
    let mut stripped_pin_count = 0usize;
    let mut forced_tls_count = 0usize;
    let mut proxy_server_hosts: HashSet<String> = HashSet::new();

    for node in &mut nodes {
        // Strip untrusted pre-populated dial overrides and trust records (H-6)
        node.dial_override_server = None;
        if node.tls.trust_record.is_some() {
            node.tls.trust_record = None;
            stripped_pin_count += 1;
        }

        // Enforce mandatory TLS on protocols that require TLS (H-3)
        if is_mandatory_tls_protocol(&node.protocol) && !node.tls.enabled {
            node.tls.enabled = true;
            forced_tls_count += 1;
        }

        // Only real connectable nodes (not metadata pseudo-nodes) may qualify for ProxyEndpointAlias (H-5)
        if node.is_metadata_node {
            report.metadata_nodes_count += 1;
        } else {
            proxy_server_hosts.insert(node.server.trim().to_ascii_lowercase());
        }

        match &mut node.tls.verify_mode {
            TlsVerifyMode::InsecureLegacy {
                user_confirmed_override,
            } => {
                // Never allow imported content to pre-confirm insecure override!
                *user_confirmed_override = false;
                report.insecure_nodes_count += 1;
                if insecure_names.len() < 5 {
                    insecure_names.push(node.name.clone());
                }
            }
            TlsVerifyMode::PendingPinBootstrap => {
                // Fail closed if imported_cert_sha256_hex is missing/invalid (C-3)
                let valid_hex = node
                    .tls
                    .imported_cert_sha256_hex
                    .as_deref()
                    .is_some_and(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()));
                if valid_hex {
                    report.pending_pin_bootstrap_count += 1;
                    if pending_pin_names.len() < 5 {
                        pending_pin_names.push(node.name.clone());
                    }
                } else {
                    node.tls.imported_cert_sha256_hex = None;
                    node.tls.verify_mode = TlsVerifyMode::SystemCa;
                    stripped_pin_count += 1;
                }
            }
            TlsVerifyMode::PinnedSpki => {
                // Untrusted imports must never inject pre-approved PinnedSpki trust records (H-6)
                node.tls.verify_mode = TlsVerifyMode::SystemCa;
                stripped_pin_count += 1;
            }
            TlsVerifyMode::SystemCa => {}
        }
    }
    report.total_nodes_imported = nodes.len();

    if stripped_pin_count > 0 {
        report.findings.push(SecurityFinding {
            severity: SecuritySeverity::High,
            action: SecurityActionTaken::Stripped,
            category: "stripped_untrusted_pin_records".to_string(),
            summary: format!(
                "Stripped {} untrusted pre-populated TrustRecord/PinnedSpki state(s) from external import.",
                stripped_pin_count
            ),
            samples: vec![],
            count: stripped_pin_count,
        });
    }

    if forced_tls_count > 0 {
        report.findings.push(SecurityFinding {
            severity: SecuritySeverity::High,
            action: SecurityActionTaken::Flagged,
            category: "enforced_mandatory_tls".to_string(),
            summary: format!(
                "Blocked TLS downgrade attempt on {} mandatory-TLS node(s) (Trojan/AnyTLS/Hysteria2/TUIC).",
                forced_tls_count
            ),
            samples: vec![],
            count: forced_tls_count,
        });
    }

    if report.insecure_nodes_count > 0 {
        report.findings.push(SecurityFinding {
            severity: SecuritySeverity::High,
            action: SecurityActionTaken::Flagged,
            category: "tls_insecure_legacy".to_string(),
            summary: format!(
                "{} node(s) imported with allowInsecure/skip-cert-verify. Blocked from insecure dialing by default (Scheme A); use 1-click Probe & Pin (TOFU) to secure them.",
                report.insecure_nodes_count
            ),
            samples: insecure_names,
            count: report.insecure_nodes_count,
        });
    }

    if report.pending_pin_bootstrap_count > 0 {
        report.findings.push(SecurityFinding {
            severity: SecuritySeverity::Info,
            action: SecurityActionTaken::Flagged,
            category: "tls_pin_bootstrap_required".to_string(),
            summary: format!(
                "{} node(s) carry a leaf cert SHA-256 pin (pcs/pinSHA256) and require one-time cryptographic probe verification to derive sing-box SPKI pin.",
                report.pending_pin_bootstrap_count
            ),
            samples: pending_pin_names,
            count: report.pending_pin_bootstrap_count,
        });
    }

    // 2. Sanitize `tun-excluded-routes` strictly to non-public private/local CIDRs (C-2).
    if !general.tun_excluded_routes.is_empty() {
        let mut safe_excluded = Vec::new();
        let mut stripped_routes = Vec::new();
        for cidr in general.tun_excluded_routes.drain(..) {
            if is_strictly_private_cidr(&cidr) {
                safe_excluded.push(cidr);
            } else {
                stripped_routes.push(cidr);
            }
        }
        general.tun_excluded_routes = safe_excluded;
        if !stripped_routes.is_empty() {
            report.findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                action: SecurityActionTaken::Stripped,
                category: "stripped_public_tun_excluded_routes".to_string(),
                summary: format!(
                    "Stripped {} non-private/broad tun-excluded-routes CIDR(s) to prevent TUN/IPv6 bypass leaks.",
                    stripped_routes.len()
                ),
                samples: stripped_routes.iter().take(5).cloned().collect(),
                count: stripped_routes.len(),
            });
        }
    }

    // 3. Record hard-stripped dangerous .conf sections ([MITM], [Script], [URL Rewrite], etc.).
    for sec in &raw.dangerous_sections {
        report.stripped_sections.push(sec.section_name.clone());
        let severity = match sec.section_name.to_ascii_lowercase().as_str() {
            "mitm" | "script" => SecuritySeverity::Critical,
            _ => SecuritySeverity::High,
        };
        report.findings.push(SecurityFinding {
            severity,
            action: SecurityActionTaken::Stripped,
            category: format!(
                "stripped_section_{}",
                sec.section_name.to_ascii_lowercase().replace(' ', "_")
            ),
            summary: format!(
                "Stripped dangerous section [{}] ({} line(s)) to prevent MITM CA injection, script execution, or URL hijacking.",
                sec.section_name, sec.line_count
            ),
            samples: sec.preview_lines.clone(),
            count: sec.line_count,
        });
    }

    // 4. Record hard-stripped external config overrides (inbounds, clash_api, local paths).
    if !raw.dangerous_overrides.is_empty() {
        let samples = raw
            .dangerous_overrides
            .iter()
            .take(5)
            .map(|o| format!("{}: {}", o.key_path, o.reason))
            .collect();
        report.findings.push(SecurityFinding {
            severity: SecuritySeverity::Critical,
            action: SecurityActionTaken::Stripped,
            category: "stripped_external_overrides".to_string(),
            summary: format!(
                "Blocked {} unsafe external override(s) (inbound listeners, Clash API controller, or local filesystem paths).",
                raw.dangerous_overrides.len()
            ),
            samples,
            count: raw.dangerous_overrides.len(),
        });
    }

    // 5. Audit and quarantine [Host] entries (H-5, M-6).
    let mut hosts = Vec::with_capacity(raw.raw_hosts.len());
    let mut third_party_samples = Vec::new();
    let mut third_party_count = 0usize;
    let mut proxy_alias_samples = Vec::new();
    let mut proxy_alias_count = 0usize;
    let mut local_host_samples = Vec::new();
    let mut local_host_count = 0usize;
    let mut local_host_public_ip_hijack = false;

    for raw_host in raw.raw_hosts {
        let domain = raw_host.domain.trim().to_string();
        let target = raw_host.target.trim().to_string();
        if domain.is_empty() || target.is_empty() {
            continue;
        }
        let domain_lower = domain.to_ascii_lowercase();
        let parsed_ip = target.parse::<IpAddr>().ok();
        let is_ip_target = parsed_ip.is_some();

        let classification = if proxy_server_hosts.contains(&domain_lower) {
            proxy_alias_count += 1;
            if proxy_alias_samples.len() < 5 {
                proxy_alias_samples.push(format!("{domain} -> {target}"));
            }
            HostClassification::ProxyEndpointAlias
        } else if is_local_domain(&domain_lower) {
            local_host_count += 1;
            if let Some(ip) = parsed_ip {
                if !is_non_public_ip(ip) {
                    local_host_public_ip_hijack = true;
                }
            } else {
                local_host_public_ip_hijack = true;
            }
            if local_host_samples.len() < 5 {
                local_host_samples.push(format!("{domain} -> {target}"));
            }
            HostClassification::LocalDomain
        } else {
            third_party_count += 1;
            if third_party_samples.len() < 5 {
                third_party_samples.push(format!("{domain} -> {target}"));
            }
            HostClassification::ThirdPartyDomainOverride
        };

        hosts.push(HostEntry {
            domain,
            target,
            is_ip_target,
            classification,
            // Quarantined by default; requires explicit user approval.
            approved: false,
        });
    }

    report.quarantined_hosts_count = hosts.len();
    if third_party_count > 0 {
        report.findings.push(SecurityFinding {
            severity: SecuritySeverity::High,
            action: SecurityActionTaken::Quarantined,
            category: "quarantined_third_party_hosts".to_string(),
            summary: format!(
                "Quarantined {} third-party [Host] override(s) to prevent domain/update/banking hijacking. Disabled unless explicitly approved.",
                third_party_count
            ),
            samples: third_party_samples,
            count: third_party_count,
        });
    }
    if local_host_count > 0 {
        report.findings.push(SecurityFinding {
            severity: if local_host_public_ip_hijack {
                SecuritySeverity::High
            } else {
                SecuritySeverity::Medium
            },
            action: SecurityActionTaken::Quarantined,
            category: "quarantined_local_hosts".to_string(),
            summary: format!(
                "Quarantined {} local/internal [Host] entry(s). Review carefully before approving.",
                local_host_count
            ),
            samples: local_host_samples,
            count: local_host_count,
        });
    }
    if proxy_alias_count > 0 {
        report.findings.push(SecurityFinding {
            severity: SecuritySeverity::Medium,
            action: SecurityActionTaken::Quarantined,
            category: "quarantined_proxy_endpoint_aliases".to_string(),
            summary: format!(
                "Quarantined {} [Host] proxy endpoint alias(es) (used when use-local-host-item-for-proxy=true). Review and approve to apply to matching nodes.",
                proxy_alias_count
            ),
            samples: proxy_alias_samples,
            count: proxy_alias_count,
        });
    }

    // 6. Validate update_url (HTTPS only, block loopback/private SSRF).
    if let Some(ref update_url) = general.update_url {
        if let Err(reason) = validate_safe_remote_url(update_url) {
            report.findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                action: SecurityActionTaken::Stripped,
                category: "unsafe_update_url".to_string(),
                summary: format!("Stripped unsafe update-url: {reason}"),
                samples: vec![redact_url_for_report(update_url)],
                count: 1,
            });
            general.update_url = None;
        }
    }

    // 7. Validate RULE-SET URLs and block local/UNC path references unconditionally (H-1).
    let mut safe_rules = Vec::with_capacity(raw.rules.len());
    let mut blocked_rule_set_samples = Vec::new();
    let mut blocked_rule_set_count = 0usize;

    for rule in raw.rules {
        match &rule.matcher {
            RuleMatch::RuleSet(url_or_ref) => {
                let trimmed = url_or_ref.trim();
                let is_safe_named_id = !trimmed.is_empty()
                    && trimmed.len() <= 64
                    && trimmed
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
                if !is_safe_named_id {
                    if let Err(reason) = validate_safe_remote_url(trimmed) {
                        blocked_rule_set_count += 1;
                        if blocked_rule_set_samples.len() < 3 {
                            blocked_rule_set_samples
                                .push(format!("{} ({reason})", redact_url_for_report(trimmed)));
                        }
                        continue;
                    }
                }
                safe_rules.push(rule);
            }
            RuleMatch::Unsupported { .. } => {
                report.unsupported_rules_count += 1;
                safe_rules.push(rule);
            }
            _ => safe_rules.push(rule),
        }
    }

    if blocked_rule_set_count > 0 {
        report.findings.push(SecurityFinding {
            severity: SecuritySeverity::High,
            action: SecurityActionTaken::Stripped,
            category: "unsafe_rule_set_url".to_string(),
            summary: format!(
                "Stripped {} RULE-SET entry(s) with local/UNC paths or non-HTTPS/private URLs (SSRF & path traversal protection).",
                blocked_rule_set_count
            ),
            samples: blocked_rule_set_samples,
            count: blocked_rule_set_count,
        });
    }

    report.total_rules_imported = safe_rules.len();

    SanitizedImport {
        format: raw.format_detected,
        nodes,
        rules: safe_rules,
        general,
        hosts,
        report,
        parse_warnings: raw.parse_warnings,
    }
}

/// Applies user-approved `ProxyEndpointAlias` `[Host]` entries to matching nodes'
/// `dial_override_server` while preserving each node's original `tls.server_name` (SNI).
pub fn apply_approved_host_aliases(nodes: &mut [NodeConfig], hosts: &[HostEntry]) -> usize {
    let alias_map: HashMap<String, &str> = hosts
        .iter()
        .filter(|h| h.approved && h.classification == HostClassification::ProxyEndpointAlias)
        .map(|h| (h.domain.to_ascii_lowercase(), h.target.as_str()))
        .collect();

    let mut applied = 0usize;
    for node in nodes.iter_mut() {
        let key = node.server.trim().to_ascii_lowercase();
        if let Some(&target) = alias_map.get(&key) {
            // Preserve original server as SNI if TLS SNI was omitted or empty (H-5)
            if node.tls.enabled
                && node
                    .tls
                    .server_name
                    .as_deref()
                    .map_or(true, |s| s.trim().is_empty())
            {
                node.tls.server_name = Some(node.server.clone());
            }
            node.dial_override_server = Some(target.to_string());
            applied += 1;
        }
    }
    applied
}

pub fn is_mandatory_tls_protocol(protocol: &ProtocolConfig) -> bool {
    matches!(
        protocol,
        ProtocolConfig::Trojan { .. }
            | ProtocolConfig::AnyTls { .. }
            | ProtocolConfig::Hysteria2 { .. }
            | ProtocolConfig::Tuic { .. }
    )
}

/// Returns true ONLY if `cidr` is a well-formed CIDR strictly contained inside private/loopback/
/// link-local/CGNAT/ULA/multicast/reserved non-public address space (C-2).
pub fn is_strictly_private_cidr(cidr: &str) -> bool {
    let Some((ip_part, prefix_part)) = cidr.trim().split_once('/') else {
        return false;
    };
    let Ok(ip) = ip_part.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix_part.parse::<u8>() else {
        return false;
    };
    match ip {
        IpAddr::V4(v4) => {
            if prefix > 32 {
                return false;
            }
            let o = v4.octets();
            (o[0] == 10 && prefix >= 8)
                || (o[0] == 127 && prefix >= 8)
                || (o[0] == 100 && (o[1] & 0b1100_0000) == 64 && prefix >= 10)
                || (o[0] == 169 && o[1] == 254 && prefix >= 16)
                || (o[0] == 172 && (16..=31).contains(&o[1]) && prefix >= 12)
                || (o[0] == 192 && o[1] == 168 && prefix >= 16)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0 && prefix >= 24)
                || (o[0] == 192 && o[1] == 0 && o[2] == 2 && prefix >= 24)
                || (o[0] == 192 && o[1] == 88 && o[2] == 99 && prefix >= 24)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100 && prefix >= 24)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113 && prefix >= 24)
                || (o[0] >= 224 && prefix >= 4)
        }
        IpAddr::V6(v6) => {
            if prefix > 128 {
                return false;
            }
            let s = v6.segments();
            (v6.is_loopback() && prefix == 128)
                || ((s[0] & 0xfe00) == 0xfc00 && prefix >= 7) // ULA fc00::/7
                || ((s[0] & 0xffc0) == 0xfe80 && prefix >= 10) // link-local fe80::/10
                || ((s[0] & 0xff00) == 0xff00 && prefix >= 8) // multicast ff00::/8
        }
    }
}

fn is_local_domain(domain_lower: &str) -> bool {
    // Strip trailing DNS root dots to prevent `localhost.` / `foo.local.` bypass (H-1)
    let clean = domain_lower.trim_end_matches('.');
    clean == "localhost"
        || clean.ends_with(".local")
        || clean.ends_with(".lan")
        || clean.ends_with(".internal")
        || clean.ends_with(".localhost")
}

/// Validates that an external URL is strictly `https://` and does not target loopback/private/link-local hosts.
pub fn validate_safe_remote_url(raw_url: &str) -> Result<(), String> {
    let parsed = Url::parse(raw_url.trim()).map_err(|e| format!("invalid URL: {e}"))?;
    if parsed.scheme() != "https" {
        return Err(format!("scheme '{}' is not https", parsed.scheme()));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "missing host".to_string())?;
    let host_lower = host
        .trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase();
    if is_local_domain(&host_lower) {
        return Err("local/loopback domain blocked".to_string());
    }
    if let Ok(ip) = host_lower.parse::<IpAddr>() {
        if is_non_public_ip(ip) {
            return Err("private/loopback/link-local IP blocked".to_string());
        }
    }
    Ok(())
}

pub fn is_non_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_non_public_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                return is_non_public_ipv4(mapped_v4);
            }
            // Also block deprecated IPv4-compatible `::a.b.c.d` if non-public (H-1)
            #[allow(deprecated)]
            if let Some(compat_v4) = v6.to_ipv4() {
                if is_non_public_ipv4(compat_v4) {
                    return true;
                }
            }
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (s[0] == 0x0064 && s[1] == 0xff9b) // NAT64 64:ff9b::/96
                || s[0] == 0x2002 // 6to4 2002::/16
                || (s[0] == 0x2001 && s[1] == 0x0000) // Teredo 2001::/32
                || (s[0] == 0x0100 && s[1] == 0x0000 && s[2] == 0x0000 && s[3] == 0x0000) // Discard 100::/64
        }
    }
}

fn is_non_public_ipv4(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_unspecified()
        || v4.is_multicast()
        || o[0] == 0 // 0.0.0.0/8
        || (o[0] == 100 && (o[1] & 0b1100_0000) == 64) // CGNAT 100.64.0.0/10
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // Benchmarking 198.18.0.0/15
        || o[0] >= 240 // Reserved 240.0.0.0/4
}

fn redact_url_for_report(raw: &str) -> String {
    if let Ok(mut u) = Url::parse(raw.trim()) {
        if u.query().is_some() {
            u.set_query(Some("<redacted>"));
        }
        if !u.username().is_empty() || u.password().is_some() {
            let _ = u.set_username("<redacted>");
            let _ = u.set_password(None);
        }
        u.to_string()
    } else {
        "<invalid-or-local-path>".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxq_core_model::{
        DangerousOverrideCapture, DangerousSectionCapture, ImportFormat, ProtocolConfig,
        RawHostEntry, RuleAction, RuleEntry, TlsConfig,
    };

    #[test]
    fn enforces_scheme_a_and_quarantines_hosts_and_strips_dangerous_sections() {
        let mut node = NodeConfig::new(
            "JPN 01",
            "edge-sh.example.net",
            8205,
            ProtocolConfig::Trojan {
                password: "test-password".into(),
            },
        );
        node.tls = TlsConfig {
            enabled: true,
            server_name: Some("cos.example.com".into()),
            verify_mode: TlsVerifyMode::InsecureLegacy {
                user_confirmed_override: true,
            },
            ..Default::default()
        };

        let raw = RawImportBundle {
            format_detected: ImportFormat::ShadowrocketConf,
            nodes: vec![node],
            rules: vec![
                RuleEntry {
                    matcher: RuleMatch::RuleSet("http://127.0.0.1:8080/evil.list".into()),
                    action: RuleAction::Direct,
                    no_resolve: false,
                },
                RuleEntry {
                    matcher: RuleMatch::RuleSet("\\\\attacker\\share\\evil.srs".into()),
                    action: RuleAction::Direct,
                    no_resolve: false,
                },
                RuleEntry {
                    matcher: RuleMatch::RuleSet("https://[::ffff:169.254.169.254]/meta".into()),
                    action: RuleAction::Direct,
                    no_resolve: false,
                },
                RuleEntry {
                    matcher: RuleMatch::RuleSet("https://localhost./secret".into()),
                    action: RuleAction::Direct,
                    no_resolve: false,
                },
                RuleEntry {
                    matcher: RuleMatch::DomainSuffix("example.org".into()),
                    action: RuleAction::Proxy,
                    no_resolve: false,
                },
            ],
            general: maxq_core_model::GeneralSettings {
                update_url: Some("https://[::ffff:127.0.0.1]/sub".into()),
                tun_excluded_routes: vec![
                    "0.0.0.0/0".into(),
                    "::/0".into(),
                    "192.168.0.0/16".into(),
                ],
                ..Default::default()
            },
            raw_hosts: vec![
                RawHostEntry {
                    domain: "edge-sh.example.net".into(),
                    target: "edge-sh.example-cdn.net".into(),
                },
                RawHostEntry {
                    domain: "bank.example.com".into(),
                    target: "1.2.3.4".into(),
                },
                RawHostEntry {
                    domain: "localhost".into(),
                    target: "1.2.3.4".into(),
                },
            ],
            dangerous_sections: vec![
                DangerousSectionCapture {
                    section_name: "MITM".into(),
                    line_count: 3,
                    preview_lines: vec!["enable = true".into()],
                },
                DangerousSectionCapture {
                    section_name: "Script".into(),
                    line_count: 1,
                    preview_lines: vec!["evil = type=http-request,script-path=https://x/a.js".into()],
                },
            ],
            dangerous_overrides: vec![DangerousOverrideCapture {
                key_path: "experimental.clash_api.external_controller".into(),
                reason: "External API controller override blocked".into(),
            }],
            parse_warnings: vec![],
        };

        let mut sanitized = sanitize_import(raw);

        assert_eq!(
            sanitized.nodes[0].tls.verify_mode,
            TlsVerifyMode::InsecureLegacy {
                user_confirmed_override: false
            }
        );
        // SSRF & UNC paths stripped
        assert!(sanitized.general.update_url.is_none());
        assert_eq!(sanitized.rules.len(), 1);
        // Broad/public tun_excluded_routes stripped (C-2)
        assert_eq!(sanitized.general.tun_excluded_routes, vec!["192.168.0.0/16"]);
        // LocalDomain host hijack reported (M-6)
        assert!(sanitized
            .report
            .findings
            .iter()
            .any(|f| f.category == "quarantined_local_hosts"
                && f.severity == SecuritySeverity::High));
        // Hosts classified & quarantined
        assert_eq!(sanitized.hosts.len(), 3);
        assert_eq!(
            sanitized.hosts[0].classification,
            HostClassification::ProxyEndpointAlias
        );
        sanitized.hosts[0].approved = true;
        assert_eq!(
            apply_approved_host_aliases(&mut sanitized.nodes, &sanitized.hosts),
            1
        );
        assert_eq!(
            sanitized.nodes[0].dial_override_server.as_deref(),
            Some("edge-sh.example-cdn.net")
        );
    }
}
