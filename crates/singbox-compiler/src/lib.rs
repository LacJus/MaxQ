use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::OnceLock;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use maxq_core_model::{
    GeneralSettings, HostClassification, HostEntry, Hysteria2Obfs, Ipv6Policy, NodeConfig,
    ProtocolConfig, ProxyMode, RoutingMode, RuleAction, RuleEntry, RuleMatch, RuleSource,
    RuntimePolicy, TlsConfig, TlsVerifyMode, TransportConfig,
};
use rand::RngCore;
use serde_json::{json, Map, Value};
use thiserror::Error;
use url::Url;

const BUILTIN_DEFAULT_RULES_CONF: &str = include_str!("../assets/default_rules.conf");

/// Returns MaxQ's built-in sanitized default split-routing rules (8,500+ CN direct / overseas proxy rules),
/// parsed once and cached for the lifetime of the process.
pub fn builtin_default_rules() -> &'static [RuleEntry] {
    static RULES: OnceLock<Vec<RuleEntry>> = OnceLock::new();
    RULES.get_or_init(|| {
        maxq_parser::shadowrocket_conf::parse_shadowrocket_conf(BUILTIN_DEFAULT_RULES_CONF)
            .map(|b| b.rules)
            .unwrap_or_default()
    })
}

pub fn builtin_default_rules_count() -> usize {
    builtin_default_rules().len()
}

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
    #[error("Node '{node_name}' has an invalid endpoint: {reason}")]
    InvalidNodeEndpoint { node_name: String, reason: String },
    #[error("Invalid local port policy: {reason}")]
    InvalidPortConfig { reason: String },
    #[error("Invalid DNS server for {field} ('{value}'): {reason}")]
    InvalidDnsServer {
        field: &'static str,
        value: String,
        reason: String,
    },
    #[error("Invalid Clash API secret: must be at least 32 characters with no whitespace or control characters.")]
    WeakClashApiSecret,
    #[error("Invalid CORS origins: access_control_allow_origin must contain only strict http(s)://host[:port] origins.")]
    UnsafeCorsOrigins,
}

/// Validates and normalizes `RuntimePolicy` ports & DNS settings before persistence or compilation.
pub fn validate_runtime_policy(policy: &RuntimePolicy) -> Result<(), String> {
    if policy.mixed_listen_port < 1024 {
        return Err(format!(
            "Mixed 代理端口 {} 无效，请使用 1024–65535 之间的端口",
            policy.mixed_listen_port
        ));
    }
    if policy.clash_api_port < 1024 {
        return Err(format!(
            "Clash API 端口 {} 无效，请使用 1024–65535 之间的端口",
            policy.clash_api_port
        ));
    }
    if policy.mixed_listen_port == policy.clash_api_port {
        return Err(format!(
            "Mixed 代理端口与 Clash API 端口不能同为 {}",
            policy.mixed_listen_port
        ));
    }
    parse_remote_doh_server(&policy.remote_dns_server)
        .map_err(|r| format!("远端 DoH DNS 无效（{}）：{r}", policy.remote_dns_server))?;
    parse_direct_udp_dns_server(&policy.direct_dns_server)
        .map_err(|r| format!("直连 / Bootstrap DNS 无效（{}）：{r}", policy.direct_dns_server))?;
    Ok(())
}

/// Parses a remote DoH server setting: accepts bare IP (`1.1.1.1`), bare hostname (`dns.google`),
/// or full HTTPS URL (`https://dns.google/dns-query`), returning `(server, optional_port, optional_path)`.
pub fn parse_remote_doh_server(raw: &str) -> Result<(String, Option<u16>, Option<String>), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        return Err("不能为空或超过 256 字符".into());
    }
    if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("不能包含空白或控制字符".into());
    }

    let (host, port, path) = if trimmed.contains("://") {
        let url = Url::parse(trimmed).map_err(|e| format!("URL 格式无效: {e}"))?;
        if url.scheme() != "https" {
            return Err("远端 DoH URL 必须使用 https:// 协议".into());
        }
        let h = url
            .host_str()
            .ok_or_else(|| "缺少主机名".to_string())?
            .trim_matches(|c| c == '[' || c == ']')
            .to_string();
        let p = url.port();
        let path_opt = match url.path() {
            "" | "/" => None,
            p_str => Some(p_str.to_string()),
        };
        (h, p, path_opt)
    } else {
        let stripped = trimmed.trim_matches(|c| c == '[' || c == ']');
        if stripped.parse::<IpAddr>().is_ok() {
            (stripped.to_string(), None, None)
        } else if stripped
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            && !stripped.starts_with('.')
            && !stripped.ends_with('.')
        {
            (stripped.to_string(), None, None)
        } else {
            return Err("应为有效 IP、域名或 https:// DoH 地址".into());
        }
    };

    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip.is_loopback() || ip.is_unspecified() {
            return Err("远端 DoH 不能指向本机回环地址".into());
        }
    }
    Ok((host, port, path))
}

/// Parses a direct/bootstrap UDP DNS server setting (must be an IPv4/IPv6 literal, with optional `udp://` or `:port`).
pub fn parse_direct_udp_dns_server(raw: &str) -> Result<(String, Option<u16>), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        return Err("不能为空".into());
    }
    if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("不能包含空白或控制字符".into());
    }
    let body = trimmed.strip_prefix("udp://").unwrap_or(trimmed);

    if let Ok(ip) = body.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
        if ip.is_unspecified() {
            return Err("不能为 0.0.0.0 或 ::".into());
        }
        return Ok((ip.to_string(), None));
    }
    if let Ok(sock) = body.parse::<std::net::SocketAddr>() {
        if sock.ip().is_unspecified() || sock.port() == 0 {
            return Err("地址或端口无效".into());
        }
        return Ok((sock.ip().to_string(), Some(sock.port())));
    }
    Err("直连 Bootstrap DNS 必须为纯 IP 地址（例如 223.5.5.5 或 119.29.29.29）".into())
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
    pub used_builtin_rules: bool,
}

/// Compiles canonical MaxQ IR into a strictly modern `sing-box v1.14+` JSON configuration
/// with zero deprecated fields, Scheme A TLS enforcement, direct-node DNS/IPv6 anti-leak,
/// category-safe order-preserving rule coalescing, and hardened local Clash API settings.
pub fn compile_singbox_v14(input: &CompileInput<'_>) -> Result<CompiledConfig, CompileError> {
    // 0. Validate local listener ports & DNS servers up front
    if input.policy.mixed_listen_port < 1024 || input.policy.clash_api_port < 1024 {
        return Err(CompileError::InvalidPortConfig {
            reason: "mixed_listen_port and clash_api_port must be >= 1024".into(),
        });
    }
    if input.policy.mixed_listen_port == input.policy.clash_api_port {
        return Err(CompileError::InvalidPortConfig {
            reason: format!(
                "mixed_listen_port and clash_api_port cannot both be {}",
                input.policy.mixed_listen_port
            ),
        });
    }
    let remote_doh = parse_remote_doh_server(&input.policy.remote_dns_server).map_err(|reason| {
        CompileError::InvalidDnsServer {
            field: "remote_dns_server",
            value: input.policy.remote_dns_server.clone(),
            reason,
        }
    })?;
    let direct_udp = parse_direct_udp_dns_server(&input.policy.direct_dns_server).map_err(|reason| {
        CompileError::InvalidDnsServer {
            field: "direct_dns_server",
            value: input.policy.direct_dns_server.clone(),
            reason,
        }
    })?;

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

    // Resolve effective ruleset according to RoutingMode and RuleSource
    let (effective_rules, used_builtin_rules): (&[RuleEntry], bool) = match input.policy.routing_mode {
        RoutingMode::Rule => match input.policy.rule_source {
            RuleSource::BuiltinDefault => (builtin_default_rules(), true),
            RuleSource::ProfileOrBuiltin => {
                if input.rules.is_empty() {
                    (builtin_default_rules(), true)
                } else {
                    (input.rules, false)
                }
            }
        },
        RoutingMode::Global | RoutingMode::Direct => (&[], false),
    };

    // 2. Compile active proxy outbound (enforces Scheme A TLS gate + mandatory TLS + valid endpoint!)
    let proxy_outbound = compile_node_outbound(input.active_node, "proxy")?;

    // 3. Compile DNS section (v1.12+ typed servers, explicit proxy detour, order-preserving rules)
    let dns_value = build_dns_section(input, effective_rules, &remote_doh, &direct_udp);

    // 4. Compile inbounds (strictly 127.0.0.1 in TUN mode or when !allow_lan; private-CIDR-only TUN exclusions)
    let inbounds = build_inbounds(input);

    // 5. Compile route section (v1.11+ rule actions + category-safe order-preserving coalescing)
    let (route_value, skipped_rules_count, coalesced_route_rules_count) =
        build_route_section(input, effective_rules);

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
        used_builtin_rules,
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
    let enable_tun = input.policy.tun_enabled || input.policy.proxy_mode == ProxyMode::Tun;
    // Privileged TUN service strictly enforces mixed-in on 127.0.0.1 regardless of allow_lan
    let listen_addr = if input.policy.allow_lan && !enable_tun {
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

    if enable_tun {
        let mut excluded: Vec<String> = vec![
            "127.0.0.0/8".into(),
            "::1/128".into(),
            "10.0.0.0/8".into(),
            "172.16.0.0/12".into(),
            "192.168.0.0/16".into(),
            "169.254.0.0/16".into(),
            "100.64.0.0/10".into(),
            "224.0.0.0/4".into(),
            "fc00::/7".into(),
            "fe80::/10".into(),
            "ff00::/8".into(),
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
                "198.18.0.1/30",
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

fn build_dns_section(
    input: &CompileInput<'_>,
    effective_rules: &[RuleEntry],
    remote_doh: &(String, Option<u16>, Option<String>),
    direct_udp: &(String, Option<u16>),
) -> Value {
    // CRITICAL (sing-box v1.12+): typed DoH defaults to DIRECT unless detour is explicit!
    let mut remote_srv = Map::new();
    remote_srv.insert("type".into(), json!("https"));
    remote_srv.insert("tag".into(), json!("dns-remote"));
    remote_srv.insert("server".into(), json!(remote_doh.0));
    if let Some(port) = remote_doh.1 {
        remote_srv.insert("server_port".into(), json!(port));
    }
    if let Some(ref path) = remote_doh.2 {
        remote_srv.insert("path".into(), json!(path));
    }
    // If remote DoH server is a domain name (e.g. `dns.google`), sing-box v1.14 requires `domain_resolver`
    if remote_doh.0.parse::<IpAddr>().is_err() {
        remote_srv.insert("domain_resolver".into(), json!("dns-direct"));
    }
    remote_srv.insert("detour".into(), json!("proxy"));

    let mut direct_srv = Map::new();
    direct_srv.insert("type".into(), json!("udp"));
    direct_srv.insert("tag".into(), json!("dns-direct"));
    direct_srv.insert("server".into(), json!(direct_udp.0));
    if let Some(port) = direct_udp.1 {
        direct_srv.insert("server_port".into(), json!(port));
    }

    let mut servers = vec![Value::Object(remote_srv), Value::Object(direct_srv)];

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
        // Allow resolving the active proxy node's own hostname via dns-direct ahead of the AAAA reject rule
        // (paired with route.default_domain_resolver.strategy = "prefer_ipv4" to avoid pure-IPv6 self-lock
        // while complying with sing-box v1.14's removal of per-DNS-rule `strategy`).
        let proxy_host = strip_host_brackets(input.active_node.effective_dial_server());
        if !proxy_host.is_empty() && proxy_host.parse::<IpAddr>().is_err() {
            dns_rules.push(json!({
                "domain": [proxy_host],
                "server": "dns-direct"
            }));
        }
        dns_rules.push(json!({
            "query_type": ["AAAA"],
            "action": "reject"
        }));
    }

    // Order-preserving DNS domain rules so preceding PROXY/REJECT rules are never leaked to dns-direct (H-2)
    let mut dns_bucket = DnsDomainBucket::default();
    for rule in effective_rules {
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

    let dns_final = match input.policy.routing_mode {
        RoutingMode::Direct => "dns-direct",
        RoutingMode::Rule | RoutingMode::Global => "dns-remote",
    };

    let mut dns_obj = Map::new();
    dns_obj.insert("servers".into(), Value::Array(servers));
    dns_obj.insert("rules".into(), Value::Array(dns_rules));
    dns_obj.insert("final".into(), json!(dns_final));
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
    no_resolve: bool,
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

    fn flush_into(
        &mut self,
        out: &mut Vec<Value>,
        emitted_resolve_action: &mut bool,
        routing_mode: RoutingMode,
    ) {
        let cat = self.category.take();
        let no_resolve = self.no_resolve;
        self.no_resolve = false;
        if self.is_empty() {
            self.action = None;
            return;
        }
        let Some(action) = self.action.take() else {
            return;
        };

        // In sing-box v1.14, ip_cidr rules do NOT implicitly resolve domain targets from mixed-in
        // unless preceded by an explicit `resolve` action. Emit one `resolve` via `dns-remote`
        // right before the first non-`no-resolve` IP-CIDR group in Rule mode (zero ISP DNS leak!).
        if cat == Some(MatcherCategory::IpCidrGroup)
            && !no_resolve
            && !*emitted_resolve_action
            && routing_mode == RoutingMode::Rule
        {
            out.push(json!({
                "action": "resolve",
                "server": "dns-remote"
            }));
            *emitted_resolve_action = true;
        }

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

fn build_route_section(
    input: &CompileInput<'_>,
    effective_rules: &[RuleEntry],
) -> (Value, usize, usize) {
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

    let mut final_outbound = match input.policy.routing_mode {
        RoutingMode::Direct => "direct",
        RoutingMode::Rule | RoutingMode::Global => "proxy",
    };
    let mut final_is_reject = false;
    let mut skipped_rules = 0usize;
    let mut emitted_resolve_action = false;
    let mut bucket = CoalescedRuleBucket::default();

    for rule in effective_rules {
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
            let rule_no_resolve = if cat == MatcherCategory::IpCidrGroup {
                rule.no_resolve
            } else {
                false
            };
            // Flush whenever action, matcher category, or IP-CIDR `no-resolve` changes so sing-box
            // NEVER ANDs incompatible matchers (C-1) and keeps `no-resolve` rules ahead of `resolve`.
            if bucket.action.as_ref() != Some(&rule.action)
                || bucket.category != Some(cat)
                || bucket.no_resolve != rule_no_resolve
            {
                bucket.flush_into(
                    &mut route_rules,
                    &mut emitted_resolve_action,
                    input.policy.routing_mode,
                );
                bucket.action = Some(rule.action.clone());
                bucket.category = Some(cat);
                bucket.no_resolve = rule_no_resolve;
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
                    bucket.flush_into(
                        &mut route_rules,
                        &mut emitted_resolve_action,
                        input.policy.routing_mode,
                    );
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

    bucket.flush_into(
        &mut route_rules,
        &mut emitted_resolve_action,
        input.policy.routing_mode,
    );

    // Handle `FINAL,REJECT` cleanly via catch-all reject rule (M-4)
    if final_is_reject {
        route_rules.push(json!({
            "network": ["tcp", "udp"],
            "action": "reject"
        }));
    }

    let coalesced_count = route_rules.len();

    // Under BlockToPreventLeak, set prefer_ipv4 on default_domain_resolver so dialing a pure-IPv6
    // proxy node hostname succeeds while user traffic remains strictly IPv4-only.
    let default_domain_resolver = if input.policy.ipv6_mode == Ipv6Policy::BlockToPreventLeak {
        json!({
            "server": "dns-direct",
            "strategy": "prefer_ipv4"
        })
    } else {
        json!("dns-direct")
    };

    let route_obj = json!({
        "auto_detect_interface": true,
        "default_domain_resolver": default_domain_resolver,
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

fn strip_host_brackets(raw: &str) -> &str {
    raw.trim().trim_start_matches('[').trim_end_matches(']').trim()
}

fn normalize_vmess_security(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    match lower.as_str() {
        "" => "auto".to_string(),
        "chacha20-ietf-poly1305" => "chacha20-poly1305".to_string(),
        _ => lower,
    }
}

fn normalize_duration_seconds(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if s.bytes().all(|b| b.is_ascii_digit()) {
        Some(format!("{s}s"))
    } else {
        Some(s.to_string())
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
    let dial_server = strip_host_brackets(node.effective_dial_server());
    if dial_server.is_empty()
        || dial_server
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(CompileError::InvalidNodeEndpoint {
            node_name: node.name.clone(),
            reason: "server host is empty or contains whitespace/control characters".into(),
        });
    }
    if node.server_port == 0 {
        return Err(CompileError::InvalidNodeEndpoint {
            node_name: node.name.clone(),
            reason: "server_port cannot be 0".into(),
        });
    }

    let mut obj = Map::new();
    obj.insert("tag".into(), json!(tag));
    obj.insert("server".into(), json!(dial_server));
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
            obj.insert("security".into(), json!(normalize_vmess_security(security)));
        }
        ProtocolConfig::AnyTls {
            password,
            idle_session_check_interval,
            idle_session_timeout,
            min_idle_session,
        } => {
            obj.insert("type".into(), json!("anytls"));
            obj.insert("password".into(), json!(password));
            if let Some(v) = idle_session_check_interval
                .as_deref()
                .and_then(normalize_duration_seconds)
            {
                obj.insert("idle_session_check_interval".into(), json!(v));
            }
            if let Some(v) = idle_session_timeout
                .as_deref()
                .and_then(normalize_duration_seconds)
            {
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
            if let Some(hi) = hop_interval.as_deref().and_then(normalize_duration_seconds) {
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
            if let Some(cc) = congestion_control
                .as_deref()
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
            {
                obj.insert("congestion_control".into(), json!(cc));
            }
            if let Some(mode) = udp_relay_mode
                .as_deref()
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
            {
                obj.insert("udp_relay_mode".into(), json!(mode));
            }
            if *zero_rtt_handshake {
                obj.insert("zero_rtt_handshake".into(), json!(true));
            }
            if let Some(hb) = heartbeat.as_deref().and_then(normalize_duration_seconds) {
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
                let p_trimmed = p.trim();
                if matches!(p_trimmed, "obfs-local" | "v2ray-plugin") {
                    obj.insert("plugin".into(), json!(p_trimmed));
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
        let clean_sni = strip_host_brackets(sni);
        // RFC 6066 forbids IP literals in TLS SNI; omit server_name when it is an IP address
        // (sing-box still verifies IP SAN / SPKI pin against outbound `server`).
        if !clean_sni.is_empty() && clean_sni.parse::<IpAddr>().is_err() {
            obj.insert("server_name".into(), json!(clean_sni));
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

    // Never emit uTLS on QUIC protocols (Hysteria2, TUIC) — sing-box QUIC TLS rejects uTLS (P0-6).
    if !node.is_quic_protocol() {
        if let Some(fp) = &tls.utls_fingerprint {
            let fp_norm = fp.trim().to_ascii_lowercase();
            if !fp_norm.is_empty() {
                obj.insert(
                    "utls".into(),
                    json!({
                        "enabled": true,
                        "fingerprint": fp_norm
                    }),
                );
            }
        }
    }

    if let Some(reality) = &tls.reality {
        if !node.is_quic_protocol() && !obj.contains_key("utls") {
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
