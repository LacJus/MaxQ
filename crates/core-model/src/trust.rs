use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Origin of a pinned TLS certificate/SPKI trust record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustOrigin {
    /// Pinned after explicit user confirmation on first-use probe (TOFU).
    TofuProbe,
    /// Bootstrapped by cryptographically verifying an imported `pcs`/`pinSHA256`
    /// leaf certificate SHA-256 hash against the probed server certificate.
    VerifiedImportedPin,
    /// Manually entered by the user.
    Manual,
}

/// TLS verification policy for an outbound node.
///
/// Follows Scheme A (Strict Default Safe):
/// - Imported `allowInsecure=1` / `skip-cert-verify=true` links become `InsecureLegacy`
///   with `user_confirmed_override = false`, which blocks insecure dialing until the
///   user either runs Probe & Pin (upgrading to `PinnedSpki`) or explicitly confirms
///   a temporary insecure override.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum TlsVerifyMode {
    /// Standard OS/WebPKI CA verification against SNI.
    SystemCa,
    /// Strictly pinned to `trust_record.spki_sha256_b64` (`sing-box` `certificate_public_key_sha256`).
    PinnedSpki,
    /// Imported link provided a leaf certificate SHA-256 hex pin (`pcs` / `pinSHA256`).
    /// Requires a one-time live probe that verifies `SHA256(leaf_DER) == imported_cert_sha256_hex`
    /// before deriving `spki_sha256_b64` for `sing-box v1.14`.
    PendingPinBootstrap,
    /// Legacy insecure flag imported from a share link or `.conf`.
    InsecureLegacy {
        /// Must be explicitly set `true` by the user to allow compiling `tls.insecure = true`.
        /// Defaults to `false` under Scheme A.
        #[serde(default)]
        user_confirmed_override: bool,
    },
}

impl Default for TlsVerifyMode {
    fn default() -> Self {
        Self::SystemCa
    }
}

/// Persisted certificate metadata and cryptographic fingerprints in the TOFU Trust Vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustRecord {
    /// Standard Base64 of `SHA-256(DER(SubjectPublicKeyInfo))`.
    /// Directly matches `sing-box v1.13+` `tls.certificate_public_key_sha256`.
    pub spki_sha256_b64: String,
    /// Lowercase hex of `SHA-256(DER(LeafCertificate))` (64 hex chars).
    /// Matches Xray `pcs` and Hysteria2 `pinSHA256`.
    pub cert_sha256_hex: String,
    /// Standard Base64 of `SHA-256(DER(LeafCertificate))`.
    /// Forward-compatible with `sing-box v1.15+` `tls.certificate_sha256`.
    pub cert_sha256_b64: String,
    /// SNI used when probing this certificate.
    pub sni: String,
    /// X.509 Subject summary.
    pub subject: String,
    /// X.509 Issuer summary.
    pub issuer: String,
    /// DNS Subject Alternative Names.
    #[serde(default)]
    pub san_dns: Vec<String>,
    /// IP Subject Alternative Names.
    #[serde(default)]
    pub san_ip: Vec<String>,
    /// RFC3339 validity start.
    pub not_before: String,
    /// RFC3339 validity end.
    pub not_after: String,
    /// True if Subject == Issuer.
    pub is_self_signed: bool,
    /// First time this certificate was trusted.
    pub first_seen_at: DateTime<Utc>,
    /// Last time this certificate was verified.
    pub last_verified_at: DateTime<Utc>,
    /// How this trust record was created.
    pub origin: TrustOrigin,
}

/// Result of comparing an observed peer certificate/SPKI against a pinned `TrustRecord`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PinCheckOutcome {
    /// No prior pin existed; safe to present for TOFU user confirmation.
    Unpinned,
    /// Observed SPKI matches pinned `spki_sha256_b64`.
    Matched,
    /// CRITICAL: Observed remote SPKI differs from pinned value (potential MITM or key rotation).
    Mismatch {
        expected_spki_b64: String,
        observed_spki_b64: String,
        expected_cert_hex: String,
        observed_cert_hex: Option<String>,
    },
}
