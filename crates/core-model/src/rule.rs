use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleEntry {
    pub matcher: RuleMatch,
    pub action: RuleAction,
    #[serde(default)]
    pub no_resolve: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum RuleMatch {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    IpCidr(String),
    IpCidr6(String),
    GeoIp(String),
    RuleSet(String),
    ProcessName(String),
    LogicalOr(Vec<RuleMatch>),
    Final,
    /// Captured for transparency in audit/diagnostics (e.g. `USER-AGENT`, `URL-REGEX`, `IP-ASN`).
    Unsupported { raw_type: String, raw_value: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(tag = "kind", content = "target", rename_all = "snake_case")]
pub enum RuleAction {
    Direct,
    Proxy,
    Reject,
    Group(String),
}
