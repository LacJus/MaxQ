export type TlsVerifyMode =
  | { mode: "system_ca" }
  | { mode: "pinned_spki" }
  | { mode: "pending_pin_bootstrap" }
  | { mode: "insecure_legacy"; user_confirmed_override: boolean };

export interface TrustRecord {
  spki_sha256_b64: string;
  cert_sha256_hex: string;
  cert_sha256_b64: string;
  sni: string;
  subject: string;
  issuer: string;
  san_dns: string[];
  san_ip: string[];
  not_before: string;
  not_after: string;
  is_self_signed: boolean;
  first_seen_at: string;
  last_verified_at: string;
  origin: "tofu_probe" | "verified_imported_pin" | "manual";
}

export interface TlsConfig {
  enabled: boolean;
  server_name?: string;
  disable_sni: boolean;
  alpn: string[];
  utls_fingerprint?: string;
  verify_mode: TlsVerifyMode;
  imported_cert_sha256_hex?: string;
  verify_peer_name?: string;
  trust_record?: TrustRecord;
}

export interface ProtocolConfig {
  type: "trojan" | "vless" | "vmess" | "any_tls" | "hysteria2" | "tuic" | "shadowsocks";
  [key: string]: unknown;
}

export interface NodeConfig {
  id: string;
  name: string;
  server: string;
  server_port: number;
  dial_override_server?: string;
  protocol: ProtocolConfig;
  tls: TlsConfig;
  is_metadata_node: boolean;
}

export interface HostEntry {
  domain: string;
  target: string;
  is_ip_target: boolean;
  classification: "proxy_endpoint_alias" | "local_domain" | "third_party_domain_override";
  approved: boolean;
}

export interface SecurityFinding {
  severity: "info" | "medium" | "high" | "critical";
  action: "stripped" | "quarantined" | "flagged";
  category: string;
  summary: string;
  samples: string[];
  count: number;
}

export interface ImportSecurityReport {
  total_nodes_imported: number;
  metadata_nodes_count: number;
  insecure_nodes_count: number;
  pending_pin_bootstrap_count: number;
  total_rules_imported: number;
  unsupported_rules_count: number;
  quarantined_hosts_count: number;
  stripped_sections: string[];
  findings: SecurityFinding[];
}

export interface SanitizedImport {
  format: string;
  nodes: NodeConfig[];
  hosts: HostEntry[];
  report: ImportSecurityReport;
  parse_warnings: string[];
}

export interface ProfileSummary {
  id: string;
  name: string;
  node_count: number;
  rule_count: number;
  host_count: number;
  created_at: string;
  updated_at: string;
}

export interface StoredProfile {
  id: string;
  name: string;
  nodes: NodeConfig[];
  hosts: HostEntry[];
  rules: Array<{ matcher: unknown; action: unknown; no_resolve: boolean }>;
  general: {
    skip_proxy: string[];
    tun_excluded_routes: string[];
    ipv6?: boolean;
    use_local_host_item_for_proxy: boolean;
  };
}

export interface ProbedCertificate {
  spki_sha256_b64: string;
  cert_sha256_hex: string;
  cert_sha256_b64: string;
  sni: string;
  subject: string;
  issuer: string;
  san_dns: string[];
  san_ip: string[];
  not_before: string;
  not_after: string;
  is_self_signed: boolean;
  hostname_matches_sni: boolean;
  chain_len: number;
}

export type PinCheckOutcome =
  | { status: "unpinned" }
  | { status: "matched" }
  | {
      status: "mismatch";
      expected_spki_b64: string;
      observed_spki_b64: string;
      expected_cert_hex: string;
      observed_cert_hex?: string;
    };

export interface ProbeNodeResult {
  probed: ProbedCertificate;
  outcome: PinCheckOutcome;
  proposed_trust_record: TrustRecord;
}

export interface BatchPinSummary {
  probed_endpoints: number;
  pinned_nodes: number;
  failed_nodes: number;
  errors: string[];
}

export interface BuiltinRulesInfo {
  rule_count: number;
  description: string;
}

export interface TunServiceStatus {
  installed: boolean;
  running: boolean;
  tun_active: boolean;
  singbox_pid?: number;
  singbox_sha256_verified: boolean;
  last_mitm_alert?: string;
  version?: string;
  last_error?: string;
}

export interface RuntimeStatus {
  running: boolean;
  pid?: number;
  active_node_id?: string;
  active_node_name?: string;
  clash_api_port?: number;
  mixed_port?: number;
  system_proxy_enabled: boolean;
  tun_active: boolean;
  last_mitm_alert?: string;
}

export interface LiveConnectionItem {
  id: string;
  host: string;
  port: string;
  network: string;
  rule: string;
  chain: string;
  upload: number;
  download: number;
}

export interface RuntimeTelemetry {
  connected: boolean;
  upload_bps: number;
  download_bps: number;
  upload_total: number;
  download_total: number;
  active_connections: number;
  uptime_secs: number;
  dynamic_pressure_q: number;
  recent_connections: LiveConnectionItem[];
}

export interface AboutInfo {
  app_name: string;
  app_version: string;
  engine_brand: string;
  core_version: string;
  creator: string;
  os: string;
  arch: string;
  builtin_rule_count: number;
  service_protocol_version: string;
  total_profiles: number;
  total_nodes: number;
  pinned_spki_nodes: number;
}

export type ProxyMode = "system_proxy" | "tun";
export type RoutingMode = "rule" | "global" | "direct";
export type RuleSource = "builtin_default" | "profile_or_builtin";
export type ThemeMode = "light" | "dark";
export type AccentFlavor = "periwinkle" | "glacier" | "lilac";

export interface RuntimePolicy {
  mixed_listen_port: number;
  allow_lan: boolean;
  clash_api_port: number;
  clash_api_secret: string;
  clash_api_allowed_origins: string[];
  tun_enabled: boolean;
  proxy_mode: ProxyMode;
  routing_mode: RoutingMode;
  rule_source: RuleSource;
  ipv6_mode: "block_to_prevent_leak" | "prefer_ipv4" | "dual_stack";
  remote_dns_server: string;
  direct_dns_server: string;
}
