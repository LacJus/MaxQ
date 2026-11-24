use std::collections::BTreeMap;
use std::net::IpAddr;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use maxq_core_model::{
    GeneralSettings, HostClassification, HostEntry, Hysteria2Obfs, Ipv6Policy, NodeConfig,
    ProtocolConfig, RuleAction, RuleEntry, RuleMatch, RuntimePolicy, TlsConfig, TlsVerifyMode,
    TransportConfig,
};
use rand::RngCore;
use serde_json::{json, Map, Value};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum CompileError {
    #[error("Scheme A security policy blocks compiling unverified insecure node '{node_name}'. Run Probe & Pin (TOFU) first or explicitly confirm temporary insecure override.")]
    UnverifiedInsecureNode { node_name: String },
    #[error("Node '{node_name}' has an imported leaf cert SHA-256 pin (pcs/pinSHA256) that must be verified via Probe & Pin before compiling for sing-box v1.14.")]
    PendingPinBootstrap { node_name: String },
    #[error("Node '{node_name}' is marked PinnedSpki but has no TrustRecord.")]
    MissingTrustRecord { node_name: String },
    #[error("Node '{node_name}' has invalid SPKI SHA-256 Base64 pin (must decode to 32 bytes).")]
    InvalidSpkiPin { node_name: String },
    #[error("Node '{node_name}' combines PinnedSpki with Reality, which is unsupported in sing-box.")]
    ConflictingPinAndReality { node_name: String },
    #[error("Node '{node_name}' uses a mandatory-TLS protocol (Trojan/AnyTLS/Hysteria2/TUIC) but tls.enabled is false.")]
    MandatoryTlsDisabled { node_name: String },
    #[error("Invalid Clash API secret: must be at least 32 characters with no whitespace or control characters.")]
    WeakClashApiSecret,
    #[error("Invalid CORS origins: access_control_allow_origin must contain only strict http(s)://host[:port] origins.")]
    UnsafeCorsOrigins,
}

#[derive(Debug, Clone)]
pub struct CompileInput<'a> {
    pub active_node: &'a NodeConfig,
    pub rules: &'a [RuleEntry],
    pub general: &'a GeneralSettings,
    pub approved_hosts: &'a [HostEntry],
    pub policy: &'a RuntimePolicy,
}

#[derive(Debug, Clone)]
pub struct CompiledConfig {
    pub json: Value,
    pub clash_api_secret: String,
    pub skipped_rules_count: usize,
    pub coalesced_route_rules_count: usize,
}

/// Compiles canonical MaxQ IR into a strictly modern `sing-box v1.14+` JSON configuration
/// with zero deprecated fields, Scheme A TLS enforcement, direct-node DNS/IPv6 anti-leak,
/// category-safe order-preserving rule coalescing, and hardened local Clash API settings.
pub fn compile_singbox_v14(input: &CompileInput<'_>) -> Result<CompiledConfig, CompileError> {
    // 1. Validate & prepare hardened Clash API secret (>= 32 chars) & strict CORS origins (M-3)
    let clash_api_secret = if input.policy.clash_api_secret.is_empty() {
        generate_random_secret_hex()
    } else if !is_strong_secret(&input.policy.clash_api_secret) {
        return Err(CompileError::WeakClashApiSecret);
    } else {
        input.policy.clash_api_secret.clone()
    };

    if input.policy.clash_api_allowed_origins.is_empty()
        || !input
            .policy
            .clash_api_allowed_origins
            .iter()
            .all(|o| is_valid_cors_origin(o))
    {
        return Err(CompileError::UnsafeCorsOrigins);
    }

    // 2. Compile active proxy outbound (enforces Scheme A TLS gate + mandatory TLS!)
    let proxy_outbound = compile_node_outbound(input.active_node, "proxy")?;

    // 3. Compile DNS section (v1.12+ typed servers, explicit proxy detour, order-preserving rules)
    let dns_value = build_dns_section(input);

    // 4. Compile inbounds (strictly 127.0.0.1 unless allow_lan, private-CIDR-only TUN exclusions)
    let inbounds = build_inbounds(input);

    // 5. Compile route section (v1.11+ rule actions + category-safe order-preserving coalescing)
    let (route_value, skipped_rules_count, coalesced_route_rules_count) =
        build_route_section(input);

    let config = json!({
        "log": {
            "level": "info",
            "timestamp": true
        },
        "dns": dns_value,
        "inbounds": inbounds,
        "outbounds": [
            proxy_outbound,
            {
                "type": "direct",
                "tag": "direct"
            }
        ],
        "route": route_value,
        "experimental": {
            "clash_api": {
                "external_controller": format!("127.0.0.1:{}", input.policy.clash_api_port),
                "secret": clash_api_secret,
                "access_control_allow_origin": input.policy.clash_api_allowed_origins,
                "access_control_allow_private_network": false
            }
        }
    });

    Ok(CompiledConfig {
        json: config,
        clash_api_secret,
        skipped_rules_count,
        coalesced_route_rules_count,
    })
}

fn generate_random_secret_hex() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn is_strong_secret(s: &str) -> bool {
    s.len() >= 32
        && s.chars()
            .all(|c| !c.is_whitespace() && !c.is_control())
}

fn is_valid_cors_origin(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains('*') || trimmed.eq_ignore_ascii_case("null") {
        return false;
    }
    let Ok(url) = Url::parse(trimmed) else {
        return false;
    };
    if !matches!(url.scheme(), "http" | "https") {
        return false;
    }
    if url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    if (url.path() != "/" && !url.path().is_empty()) || url.query().is_some() || url.fragment().is_some() {
        return false;
    }
    true
}

fn build_inbounds(input: &CompileInput<'_>) -> Vec<Value> {
    let listen_addr = if input.policy.allow_lan {
        "0.0.0.0"
    } else {
        "127.0.0.1"
    };
    let mut inbounds = vec![json!({
        "type": "mixed",
        "tag": "mixed-in",
        "listen": listen_addr,
        "listen_port": input.policy.mixed_listen_port
    })];

    if input.policy.tun_enabled {
        let mut excluded: Vec<String> = vec![
            "127.0.0.0/8".into(),
            "10.0.0.0/8".into(),
            "172.16.0.0/12".into(),
            "192.168.0.0/16".into(),
            "169.254.0.0/16".into(),
            "fc00::/7".into(),
            "fe80::/10".into(),
        ];
        // Defense-in-depth (C-2): ONLY allow strictly private/local CIDRs in route_exclude_address
        for cidr in &input.general.tun_excluded_routes {
            if is_strictly_private_cidr(cidr) && !excluded.contains(cidr) {
                excluded.push(cidr.clone());
            }
        }
        inbounds.push(json!({
            "type": "tun",
            "tag": "tun-in",
            "interface_name": "maxq-tun0",
            "address": [
                "172.19.0.1/30",
                "fdfe:dcba:9876::1/126"
            ],
            "auto_route": true,
            "strict_route": true,
            "route_exclude_address": excluded
        }));
    }

    inbounds
}

#[derive(Default)]
struct DnsDomainBucket {
    action: Option<RuleAction>,
    domains: Vec<String>,
    domain_suffixes: Vec<String>,
    domain_keywords: Vec<String>,
}

impl DnsDomainBucket {
    fn is_empty(&self) -> bool {
        self.domains.is_empty()
            && self.domain_suffixes.is_empty()
            && self.domain_keywords.is_empty()
    }

    fn flush_into(&mut self, out: &mut Vec<Value>) {
        if self.is_empty() {
            return;
        }
        let Some(action) = self.action.take() else {
            return;
        };
        let mut obj = Map::new();
        if !self.domains.is_empty() {
            obj.insert("domain".into(), json!(std::mem::take(&mut self.domains)));
        }
        if !self.domain_suffixes.is_empty() {
            obj.insert(
                "domain_suffix".into(),
                json!(std::mem::take(&mut self.domain_suffixes)),
            );
        }
        if !self.domain_keywords.is_empty() {
            obj.insert(
                "domain_keyword".into(),
                json!(std::mem::take(&mut self.domain_keywords)),
            );
        }
        match action {
            RuleAction::Direct => {
                obj.insert("server".into(), json!("dns-direct"));
            }
            RuleAction::Proxy | RuleAction::Group(_) => {
                obj.insert("server".into(), json!("dns-remote"));
            }
            RuleAction::Reject => {
                obj.insert("action".into(), json!("reject"));
            }
        }
        out.push(Value::Object(obj));
    }
}

fn build_dns_section(input: &CompileInput<'_>) -> Value {
    let mut servers = vec![
        // CRITICAL (sing-box v1.12+): typed DoH defaults to DIRECT unless detour is explicit!
        json!({
            "type": "https",
            "tag": "dns-remote",
            "server": input.policy.remote_dns_server,
            "detour": "proxy"
        }),
        json!({
            "type": "udp",
            "tag": "dns-direct",
            "server": input.policy.direct_dns_server
        }),
    ];

    // Add ONLY explicitly approved non-ProxyEndpointAlias exact-domain IP hosts into global dns-hosts (H-5)
    let mut predefined: BTreeMap<String, Value> = BTreeMap::new();
    for h in input.approved_hosts {
        if h.approved
            && h.is_ip_target
            && h.classification != HostClassification::ProxyEndpointAlias
            && !h.domain.contains('*')
        {
            predefined.insert(h.domain.clone(), Value::String(h.target.clone()));
        }
    }
    let mut dns_rules = Vec::new();
    if !predefined.is_empty() {
        let host_domains: Vec<String> = predefined.keys().cloned().collect();
        servers.push(json!({
            "type": "hosts",
            "tag": "dns-hosts",
            "predefined": predefined
        }));
        dns_rules.push(json!({
            "domain": host_domains,
            "server": "dns-hosts"
        }));
    }

    if input.policy.ipv6_mode == Ipv6Policy::BlockToPreventLeak {
        dns_rules.push(json!({
            "query_type": ["AAAA"],
            "action": "reject"
        }));
    }

    // Order-preserving DNS domain rules so preceding PROXY/REJECT rules are never leaked to dns-direct (H-2)
    let mut dns_bucket = DnsDomainBucket::default();
    for rule in input.rules {
        if matches!(rule.matcher, RuleMatch::Final) {
            break;
        }
        let is_domain_rule = matches!(
            rule.matcher,
            RuleMatch::Domain(_) | RuleMatch::DomainSuffix(_) | RuleMatch::DomainKeyword(_)
        );
        if !is_domain_rule {
            continue;
        }
        let norm_action = match &rule.action {
            RuleAction::Direct => RuleAction::Direct,
            RuleAction::Reject => RuleAction::Reject,
            RuleAction::Proxy | RuleAction::Group(_) => RuleAction::Proxy,
        };
        if dns_bucket.action.as_ref() != Some(&norm_action) {
            dns_bucket.flush_into(&mut dns_rules);
            dns_bucket.action = Some(norm_action);
        }
        match &rule.matcher {
            RuleMatch::Domain(d) => dns_bucket.domains.push(d.clone()),
            RuleMatch::DomainSuffix(s) => dns_bucket.domain_suffixes.push(s.clone()),
            RuleMatch::DomainKeyword(k) => dns_bucket.domain_keywords.push(k.clone()),
            _ => {}
        }
    }
    dns_bucket.flush_into(&mut dns_rules);

    let mut dns_obj = Map::new();
    dns_obj.insert("servers".into(), Value::Array(servers));
    dns_obj.insert("rules".into(), Value::Array(dns_rules));
    dns_obj.insert("final".into(), json!("dns-remote"));
    match input.policy.ipv6_mode {
        Ipv6Policy::BlockToPreventLeak => {
            dns_obj.insert("strategy".into(), json!("ipv4_only"));
        }
        Ipv6Policy::PreferIpv4 => {
            dns_obj.insert("strategy".into(), json!("prefer_ipv4"));
        }
        Ipv6Policy::DualStack => {}
    }

    Value::Object(dns_obj)
}

/// Matcher categories that can be safely OR-coalesced within a single `sing-box` route rule (C-1).
/// Mixing different categories (e.g. `domain_suffix` + `ip_cidr`) in one rule becomes logical AND in sing-box!
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatcherCategory {
    DomainGroup,
    IpCidrGroup,
    ProcessNameGroup,
}

#[derive(Default)]
struct CoalescedRuleBucket {
    action: Option<RuleAction>,
    category: Option<MatcherCategory>,
    domains: Vec<String>,
    domain_suffixes: Vec<String>,
    domain_keywords: Vec<String>,
    ip_cidrs: Vec<String>,
    process_names: Vec<String>,
}

impl CoalescedRuleBucket {
    fn is_empty(&self) -> bool {
        self.domains.is_empty()
            && self.domain_suffixes.is_empty()
            && self.domain_keywords.is_empty()
            && self.ip_cidrs.is_empty()
            && self.process_names.is_empty()
    }

    fn flush_into(&mut self, out: &mut Vec<Value>) {
        if self.is_empty() {
            return;
        }
        let Some(action) = self.action.take() else {
            return;
        };
        self.category = None;

        let mut obj = Map::new();
        if !self.domains.is_empty() {
            obj.insert("domain".into(), json!(std::mem::take(&mut self.domains)));
        }
        if !self.domain_suffixes.is_empty() {
            obj.insert(
                "domain_suffix".into(),
                json!(std::mem::take(&mut self.domain_suffixes)),
            );
        }
        if !self.domain_keywords.is_empty() {
            obj.insert(
                "domain_keyword".into(),
                json!(std::mem::take(&mut self.domain_keywords)),
            );
        }
        if !self.ip_cidrs.is_empty() {
            obj.insert("ip_cidr".into(), json!(std::mem::take(&mut self.ip_cidrs)));
        }
        if !self.process_names.is_empty() {
            obj.insert(
                "process_name".into(),
                json!(std::mem::take(&mut self.process_names)),
            );
        }
        apply_route_action(&mut obj, &action);
        out.push(Value::Object(obj));
    }
}

fn apply_route_action(obj: &mut Map<String, Value>, action: &RuleAction) {
    match action {
        RuleAction::Direct => {
            obj.insert("outbound".into(), json!("direct"));
        }
        RuleAction::Proxy | RuleAction::Group(_) => {
            obj.insert("outbound".into(), json!("proxy"));
        }
        RuleAction::Reject => {
            obj.insert("action".into(), json!("reject"));
        }
    }
}

fn build_route_section(input: &CompileInput<'_>) -> (Value, usize, usize) {
    let mut route_rules = vec![
        json!({ "action": "sniff" }),
        json!({ "protocol": "dns", "action": "hijack-dns" }),
        json!({ "ip_is_private": true, "outbound": "direct" }),
    ];

    if input.policy.ipv6_mode == Ipv6Policy::BlockToPreventLeak {
        route_rules.push(json!({
            "ip_version": 6,
            "action": "reject"
        }));
    }

    let mut final_outbound = "proxy";
    let mut final_is_reject = false;
    let mut skipped_rules = 0usize;
    let mut bucket = CoalescedRuleBucket::default();

    for rule in input.rules {
        if matches!(rule.matcher, RuleMatch::Final) {
            match rule.action {
                RuleAction::Direct => final_outbound = "direct",
                RuleAction::Reject => final_is_reject = true,
                RuleAction::Proxy | RuleAction::Group(_) => final_outbound = "proxy",
            }
            // Stop processing any trailing rules after FINAL (M-4)
            break;
        }

        let category = match &rule.matcher {
            RuleMatch::Domain(_) | RuleMatch::DomainSuffix(_) | RuleMatch::DomainKeyword(_) => {
                Some(MatcherCategory::DomainGroup)
            }
            RuleMatch::IpCidr(_) | RuleMatch::IpCidr6(_) => Some(MatcherCategory::IpCidrGroup),
            RuleMatch::ProcessName(_) => Some(MatcherCategory::ProcessNameGroup),
            _ => None,
        };

        if let Some(cat) = category {
            // Flush whenever action OR matcher category changes so sing-box NEVER ANDs incompatible matchers (C-1)
            if bucket.action.as_ref() != Some(&rule.action) || bucket.category != Some(cat) {
                bucket.flush_into(&mut route_rules);
                bucket.action = Some(rule.action.clone());
                bucket.category = Some(cat);
            }
            match &rule.matcher {
                RuleMatch::Domain(d) => bucket.domains.push(d.clone()),
                RuleMatch::DomainSuffix(s) => bucket.domain_suffixes.push(s.clone()),
                RuleMatch::DomainKeyword(k) => bucket.domain_keywords.push(k.clone()),
                RuleMatch::IpCidr(c) | RuleMatch::IpCidr6(c) => {
                    if is_valid_cidr_like(c) {
                        bucket.ip_cidrs.push(c.clone());
                    } else {
                        skipped_rules += 1;
                    }
                }
                RuleMatch::ProcessName(p) => bucket.process_names.push(p.clone()),
                _ => {}
            }
            continue;
        }

        match &rule.matcher {
            RuleMatch::LogicalOr(subs) => {
                let compiled_subs: Vec<Value> =
                    subs.iter().filter_map(compile_simple_matcher).collect();
                if compiled_subs.is_empty() {
                    skipped_rules += 1;
                } else {
                    bucket.flush_into(&mut route_rules);
                    let mut obj = Map::new();
                    obj.insert("type".into(), json!("logical"));
                    obj.insert("mode".into(), json!("or"));
                    obj.insert("rules".into(), Value::Array(compiled_subs));
                    apply_route_action(&mut obj, &rule.action);
                    route_rules.push(Value::Object(obj));
                }
            }
            RuleMatch::GeoIp(_) | RuleMatch::RuleSet(_) | RuleMatch::Unsupported { .. } => {
                skipped_rules += 1;
            }
            _ => {}
        }
    }

    bucket.flush_into(&mut route_rules);

    // Handle `FINAL,REJECT` cleanly via catch-all reject rule (M-4)
    if final_is_reject {
        route_rules.push(json!({
            "network": ["tcp", "udp"],
            "action": "reject"
        }));
    }

    let coalesced_count = route_rules.len();

    let route_obj = json!({
        "auto_detect_interface": true,
        "default_domain_resolver": "dns-direct",
        "rules": route_rules,
        "final": final_outbound
    });

    (route_obj, skipped_rules, coalesced_count)
}

fn compile_simple_matcher(m: &RuleMatch) -> Option<Value> {
    match m {
        RuleMatch::Domain(d) => Some(json!({ "domain": [d] })),
        RuleMatch::DomainSuffix(s) => Some(json!({ "domain_suffix": [s] })),
        RuleMatch::DomainKeyword(k) => Some(json!({ "domain_keyword": [k] })),
        RuleMatch::IpCidr(c) | RuleMatch::IpCidr6(c) if is_valid_cidr_like(c) => {
            Some(json!({ "ip_cidr": [c] }))
        }
        RuleMatch::ProcessName(p) => Some(json!({ "process_name": [p] })),
        _ => None,
    }
}

fn is_valid_cidr_like(s: &str) -> bool {
    let Some((ip_part, prefix_part)) = s.trim().split_once('/') else {
        return false;
    };
    let Ok(ip) = ip_part.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix_part.parse::<u8>() else {
        return false;
    };
    match ip {
        IpAddr::V4(_) => prefix <= 32,
        IpAddr::V6(_) => prefix <= 128,
    }
}

fn is_strictly_private_cidr(cidr: &str) -> bool {
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
                || (o[0] >= 224 && prefix >= 4)
        }
        IpAddr::V6(v6) => {
            if prefix > 128 {
                return false;
            }
            let s = v6.segments();
            (v6.is_loopback() && prefix == 128)
                || ((s[0] & 0xfe00) == 0xfc00 && prefix >= 7)
                || ((s[0] & 0xffc0) == 0xfe80 && prefix >= 10)
                || ((s[0] & 0xff00) == 0xff00 && prefix >= 8)
        }
    }
}

fn is_mandatory_tls(protocol: &ProtocolConfig) -> bool {
    matches!(
        protocol,
        ProtocolConfig::Trojan { .. }
            | ProtocolConfig::AnyTls { .. }
            | ProtocolConfig::Hysteria2 { .. }
            | ProtocolConfig::Tuic { .. }
    )
}

fn compile_node_outbound(node: &NodeConfig, tag: &str) -> Result<Value, CompileError> {
    if is_mandatory_tls(&node.protocol) && !node.tls.enabled {
        return Err(CompileError::MandatoryTlsDisabled {
            node_name: node.name.clone(),
        });
    }

    let mut obj = Map::new();
    obj.insert("tag".into(), json!(tag));
    obj.insert("server".into(), json!(node.effective_dial_server()));
    obj.insert("server_port".into(), json!(node.server_port));

    match &node.protocol {
        ProtocolConfig::Trojan { password } => {
            obj.insert("type".into(), json!("trojan"));
            obj.insert("password".into(), json!(password));
        }
        ProtocolConfig::Vless {
            uuid,
            flow,
            packet_encoding,
        } => {
            obj.insert("type".into(), json!("vless"));
            obj.insert("uuid".into(), json!(uuid));
            if let Some(f) = flow {
                obj.insert("flow".into(), json!(f));
            }
            if let Some(pe) = packet_encoding {
                obj.insert("packet_encoding".into(), json!(pe));
            }
        }
        ProtocolConfig::Vmess {
            uuid,
            alter_id,
            security,
        } => {
            obj.insert("type".into(), json!("vmess"));
            obj.insert("uuid".into(), json!(uuid));
            obj.insert("alter_id".into(), json!(alter_id));
            obj.insert("security".into(), json!(security));
        }
        ProtocolConfig::AnyTls {
            password,
            idle_session_check_interval,
            idle_session_timeout,
            min_idle_session,
        } => {
            obj.insert("type".into(), json!("anytls"));
            obj.insert("password".into(), json!(password));
            if let Some(v) = idle_session_check_interval {
                obj.insert("idle_session_check_interval".into(), json!(v));
            }
            if let Some(v) = idle_session_timeout {
                obj.insert("idle_session_timeout".into(), json!(v));
            }
            if let Some(v) = min_idle_session {
                obj.insert("min_idle_session".into(), json!(v));
            }
        }
        ProtocolConfig::Hysteria2 {
            password,
            server_ports,
            hop_interval,
            up_mbps,
            down_mbps,
            obfs,
        } => {
            obj.insert("type".into(), json!("hysteria2"));
            obj.insert("password".into(), json!(password));
            if !server_ports.is_empty() {
                obj.insert("server_ports".into(), json!(server_ports));
            }
            if let Some(hi) = hop_interval {
                obj.insert("hop_interval".into(), json!(hi));
            }
            if let Some(up) = up_mbps {
                obj.insert("up_mbps".into(), json!(up));
            }
            if let Some(down) = down_mbps {
                obj.insert("down_mbps".into(), json!(down));
            }
            if let Some(Hysteria2Obfs::Salamander { password: obfs_pw }) = obfs {
                obj.insert(
                    "obfs".into(),
                    json!({
                        "type": "salamander",
                        "password": obfs_pw
                    }),
                );
            }
        }
        ProtocolConfig::Tuic {
            uuid,
            password,
            congestion_control,
            udp_relay_mode,
            zero_rtt_handshake,
            heartbeat,
        } => {
            obj.insert("type".into(), json!("tuic"));
            obj.insert("uuid".into(), json!(uuid));
            if let Some(pw) = password {
                obj.insert("password".into(), json!(pw));
            }
            if let Some(cc) = congestion_control {
                obj.insert("congestion_control".into(), json!(cc));
            }
            if let Some(mode) = udp_relay_mode {
                obj.insert("udp_relay_mode".into(), json!(mode));
            }
            if *zero_rtt_handshake {
                obj.insert("zero_rtt_handshake".into(), json!(true));
            }
            if let Some(hb) = heartbeat {
                obj.insert("heartbeat".into(), json!(hb));
            }
        }
        ProtocolConfig::Shadowsocks {
            method,
            password,
            plugin,
            plugin_opts,
        } => {
            obj.insert("type".into(), json!("shadowsocks"));
            obj.insert("method".into(), json!(method));
            obj.insert("password".into(), json!(password));
            // Allowlist sing-box supported built-in Shadowsocks plugins only (L-3)
            if let Some(p) = plugin {
                if matches!(p.as_str(), "obfs-local" | "v2ray-plugin") {
                    obj.insert("plugin".into(), json!(p));
                    if let Some(opts) = plugin_opts {
                        obj.insert("plugin_opts".into(), json!(opts));
                    }
                }
            }
        }
    }

    if let Some(tls_val) = compile_tls(node, &node.tls)? {
        obj.insert("tls".into(), tls_val);
    }

    if let Some(transport_val) = compile_transport(&node.transport) {
        obj.insert("transport".into(), transport_val);
    }

    if node.dial.tcp_fast_open {
        obj.insert("tcp_fast_open".into(), json!(true));
    }

    Ok(Value::Object(obj))
}

fn compile_tls(node: &NodeConfig, tls: &TlsConfig) -> Result<Option<Value>, CompileError> {
    if !tls.enabled {
        return Ok(None);
    }

    let mut obj = Map::new();
    obj.insert("enabled".into(), json!(true));
    if tls.disable_sni {
        obj.insert("disable_sni".into(), json!(true));
    }
    if let Some(sni) = &tls.server_name {
        if !sni.is_empty() {
            obj.insert("server_name".into(), json!(sni));
        }
    }
    if !tls.alpn.is_empty() {
        obj.insert("alpn".into(), json!(tls.alpn));
    }

    match &tls.verify_mode {
        TlsVerifyMode::SystemCa => {
            obj.insert("insecure".into(), json!(false));
        }
        TlsVerifyMode::PinnedSpki => {
            if tls.reality.is_some() {
                return Err(CompileError::ConflictingPinAndReality {
                    node_name: node.name.clone(),
                });
            }
            let record = tls.trust_record.as_ref().ok_or_else(|| {
                CompileError::MissingTrustRecord {
                    node_name: node.name.clone(),
                }
            })?;
            // Validate SPKI Base64 decodes to exact 32-byte SHA-256 digest (M-7)
            let decoded = STANDARD.decode(&record.spki_sha256_b64).map_err(|_| {
                CompileError::InvalidSpkiPin {
                    node_name: node.name.clone(),
                }
            })?;
            if decoded.len() != 32 {
                return Err(CompileError::InvalidSpkiPin {
                    node_name: node.name.clone(),
                });
            }
            obj.insert("insecure".into(), json!(false));
            obj.insert(
                "certificate_public_key_sha256".into(),
                json!([record.spki_sha256_b64]),
            );
        }
        TlsVerifyMode::PendingPinBootstrap => {
            return Err(CompileError::PendingPinBootstrap {
                node_name: node.name.clone(),
            });
        }
        TlsVerifyMode::InsecureLegacy {
            user_confirmed_override,
        } => {
            if !*user_confirmed_override {
                return Err(CompileError::UnverifiedInsecureNode {
                    node_name: node.name.clone(),
                });
            }
            obj.insert("insecure".into(), json!(true));
        }
    }

    if let Some(fp) = &tls.utls_fingerprint {
        if !fp.is_empty() {
            obj.insert(
                "utls".into(),
                json!({
                    "enabled": true,
                    "fingerprint": fp
                }),
            );
        }
    }

    if let Some(reality) = &tls.reality {
        if !obj.contains_key("utls") {
            obj.insert(
                "utls".into(),
                json!({
                    "enabled": true,
                    "fingerprint": "chrome"
                }),
            );
        }
        obj.insert(
            "reality".into(),
            json!({
                "enabled": true,
                "public_key": reality.public_key,
                "short_id": reality.short_id
            }),
        );
    }

    Ok(Some(Value::Object(obj)))
}

fn compile_transport(transport: &TransportConfig) -> Option<Value> {
    match transport {
        TransportConfig::Tcp => None,
        TransportConfig::Ws {
            path,
            headers,
            max_early_data,
            early_data_header_name,
        } => {
            let mut obj = Map::new();
            obj.insert("type".into(), json!("ws"));
            obj.insert("path".into(), json!(path));
            if !headers.is_empty() {
                obj.insert("headers".into(), json!(headers));
            }
            if let Some(ed) = max_early_data {
                obj.insert("max_early_data".into(), json!(ed));
            }
            if let Some(hdr) = early_data_header_name {
                obj.insert("early_data_header_name".into(), json!(hdr));
            }
            Some(Value::Object(obj))
        }
        TransportConfig::Grpc { service_name } => Some(json!({
            "type": "grpc",
            "service_name": service_name
        })),
        TransportConfig::HttpUpgrade { path, host } => {
            let mut obj = Map::new();
            obj.insert("type".into(), json!("httpupgrade"));
            obj.insert("path".into(), json!(path));
            if let Some(h) = host {
                obj.insert("host".into(), json!(h));
            }
            Some(Value::Object(obj))
        }
        TransportConfig::Http { path, host, method } => {
            let mut obj = Map::new();
            obj.insert("type".into(), json!("http"));
            if let Some(p) = path {
                obj.insert("path".into(), json!(p));
            }
            if !host.is_empty() {
                obj.insert("host".into(), json!(host));
            }
            if let Some(m) = method {
                obj.insert("method".into(), json!(m));
            }
            Some(Value::Object(obj))
        }
    }
}
