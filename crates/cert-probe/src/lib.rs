pub mod salamander;

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::Utc;
use maxq_core_model::{
    Hysteria2Obfs, NodeConfig, PinCheckOutcome, ProtocolConfig, TlsVerifyMode, TrustOrigin,
    TrustRecord,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::net::{lookup_host, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::*;

use crate::salamander::{SalamanderObfuscator, SalamanderUdpSocket};

#[derive(Debug, Error)]
pub enum ProbeError {
    #[error("DNS resolution failed for {host}:{port}: {source}")]
    DnsResolution {
        host: String,
        port: u16,
        source: std::io::Error,
    },
    #[error("no socket address resolved for {host}:{port}")]
    NoAddress { host: String, port: u16 },
    #[error("connection or handshake timed out after {0:?}")]
    Timeout(Duration),
    #[error("TCP connection failed: {0}")]
    TcpConnect(std::io::Error),
    #[error("TLS handshake failed or peer failed private-key signature proof: {0}")]
    TlsHandshake(String),
    #[error("QUIC handshake failed or peer failed private-key signature proof: {0}")]
    QuicHandshake(String),
    #[error("invalid server name '{0}'")]
    InvalidServerName(String),
    #[error("peer did not present any certificate")]
    NoCertificatePresented,
    #[error("peer failed TLS CertificateVerify private-key proof-of-possession")]
    SignatureNotVerified,
    #[error("failed to parse X.509 leaf certificate: {0}")]
    X509Parse(String),
    #[error("invalid Salamander obfuscation PSK: {0}")]
    InvalidSalamanderPsk(String),
    #[error("node requires pin bootstrap but imported leaf cert SHA-256 hex pin is missing or invalid")]
    MissingImportedPin,
    #[error("CRITICAL: imported leaf cert SHA-256 pin mismatch! expected={expected}, observed={observed}")]
    ImportedPinMismatch { expected: String, observed: String },
    #[error("VLESS Reality 节点使用 Reality 公钥认证，不能绑定常规 TLS SPKI 证书指纹")]
    RealityPinNotSupported,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeTransport {
    TcpTls,
    Quic { salamander_password: Option<String> },
}

impl fmt::Debug for ProbeTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TcpTls => write!(f, "TcpTls"),
            Self::Quic {
                salamander_password,
            } => f
                .debug_struct("Quic")
                .field(
                    "salamander_password",
                    &salamander_password.as_ref().map(|_| "[REDACTED]"),
                )
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeRequest {
    pub host: String,
    pub port: u16,
    pub sni: String,
    pub alpn: Vec<String>,
    pub transport: ProbeTransport,
    pub timeout_ms: u64,
}

fn strip_ip_brackets(raw: &str) -> String {
    let trimmed = raw.trim();
    trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed)
        .to_string()
}

impl ProbeRequest {
    pub fn from_node(node: &NodeConfig) -> Self {
        let transport = match &node.protocol {
            ProtocolConfig::Hysteria2 { obfs, .. } => {
                let salamander_password = obfs.as_ref().map(|o| match o {
                    Hysteria2Obfs::Salamander { password } => password.clone(),
                });
                ProbeTransport::Quic {
                    salamander_password,
                }
            }
            ProtocolConfig::Tuic { .. } => ProbeTransport::Quic {
                salamander_password: None,
            },
            _ => ProbeTransport::TcpTls,
        };

        let mut alpn = node.tls.alpn.clone();
        if alpn.is_empty() {
            match &node.protocol {
                ProtocolConfig::Hysteria2 { .. } | ProtocolConfig::Tuic { .. } => {
                    alpn.push("h3".to_string());
                }
                _ => {}
            }
        }

        Self {
            host: strip_ip_brackets(node.effective_dial_server()),
            port: node.server_port,
            sni: strip_ip_brackets(node.effective_sni()),
            alpn,
            transport,
            timeout_ms: 8_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbedCertificate {
    pub spki_sha256_b64: String,
    pub cert_sha256_hex: String,
    pub cert_sha256_b64: String,
    pub sni: String,
    pub subject: String,
    pub issuer: String,
    pub san_dns: Vec<String>,
    pub san_ip: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub is_self_signed: bool,
    pub hostname_matches_sni: bool,
    pub chain_len: usize,
}

impl ProbedCertificate {
    pub fn into_trust_record(&self, origin: TrustOrigin) -> TrustRecord {
        let now = Utc::now();
        TrustRecord {
            spki_sha256_b64: self.spki_sha256_b64.clone(),
            cert_sha256_hex: self.cert_sha256_hex.clone(),
            cert_sha256_b64: self.cert_sha256_b64.clone(),
            sni: self.sni.clone(),
            subject: self.subject.clone(),
            issuer: self.issuer.clone(),
            san_dns: self.san_dns.clone(),
            san_ip: self.san_ip.clone(),
            not_before: self.not_before.clone(),
            not_after: self.not_after.clone(),
            is_self_signed: self.is_self_signed,
            first_seen_at: now,
            last_verified_at: now,
            origin,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinEvaluation {
    pub outcome: PinCheckOutcome,
    pub proposed_trust_record: TrustRecord,
}

/// Evaluates a freshly probed certificate against an existing `NodeConfig`:
/// - Rejects VLESS Reality nodes (which authenticate via Reality public key, not TLS SPKI).
/// - `PendingPinBootstrap`: fails closed if `imported_cert_sha256_hex` is missing/invalid (C-3),
///   and verifies `SHA256(leaf_DER) == imported_cert_sha256_hex` before deriving `spki_sha256_b64`.
/// - `PinnedSpki`: detects SPKI drift / potential MITM without auto-rotating.
pub fn evaluate_probe_against_node(
    node: &NodeConfig,
    probed: &ProbedCertificate,
) -> Result<PinEvaluation, ProbeError> {
    if node.tls.reality.is_some() {
        return Err(ProbeError::RealityPinNotSupported);
    }
    match &node.tls.verify_mode {
        TlsVerifyMode::PendingPinBootstrap => {
            let expected_hex = node
                .tls
                .imported_cert_sha256_hex
                .as_deref()
                .filter(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()))
                .ok_or(ProbeError::MissingImportedPin)?;

            if !expected_hex.eq_ignore_ascii_case(&probed.cert_sha256_hex) {
                return Err(ProbeError::ImportedPinMismatch {
                    expected: expected_hex.to_string(),
                    observed: probed.cert_sha256_hex.clone(),
                });
            }
            Ok(PinEvaluation {
                outcome: PinCheckOutcome::Matched,
                proposed_trust_record: probed.into_trust_record(TrustOrigin::VerifiedImportedPin),
            })
        }
        TlsVerifyMode::PinnedSpki => {
            if let Some(existing) = &node.tls.trust_record {
                if existing.spki_sha256_b64 == probed.spki_sha256_b64 {
                    let mut refreshed = existing.clone();
                    refreshed.last_verified_at = Utc::now();
                    Ok(PinEvaluation {
                        outcome: PinCheckOutcome::Matched,
                        proposed_trust_record: refreshed,
                    })
                } else {
                    Ok(PinEvaluation {
                        outcome: PinCheckOutcome::Mismatch {
                            expected_spki_b64: existing.spki_sha256_b64.clone(),
                            observed_spki_b64: probed.spki_sha256_b64.clone(),
                            expected_cert_hex: existing.cert_sha256_hex.clone(),
                            observed_cert_hex: Some(probed.cert_sha256_hex.clone()),
                        },
                        proposed_trust_record: probed.into_trust_record(TrustOrigin::TofuProbe),
                    })
                }
            } else {
                Ok(PinEvaluation {
                    outcome: PinCheckOutcome::Unpinned,
                    proposed_trust_record: probed.into_trust_record(TrustOrigin::TofuProbe),
                })
            }
        }
        TlsVerifyMode::SystemCa | TlsVerifyMode::InsecureLegacy { .. } => Ok(PinEvaluation {
            outcome: PinCheckOutcome::Unpinned,
            proposed_trust_record: probed.into_trust_record(TrustOrigin::TofuProbe),
        }),
    }
}

pub fn apply_confirmed_pin(node: &mut NodeConfig, record: TrustRecord) {
    if node.tls.reality.is_some() {
        return;
    }
    node.tls.enabled = true;
    let normalized_sni = strip_ip_brackets(&record.sni);
    let sni_is_ip = normalized_sni.parse::<IpAddr>().is_ok();
    if node
        .tls
        .server_name
        .as_deref()
        .map_or(true, |s| s.trim().is_empty())
        && !normalized_sni.is_empty()
        && !sni_is_ip
    {
        node.tls.server_name = Some(normalized_sni);
    }
    node.tls.verify_mode = TlsVerifyMode::PinnedSpki;
    node.tls.trust_record = Some(record);
}

pub fn detect_singbox_log_pin_mismatch(log_line: &str) -> Option<String> {
    const MARKER: &str = "unrecognized remote public key:";
    let idx = log_line.find(MARKER)?;
    let rest = log_line[idx + MARKER.len()..].trim();
    let token = rest
        .split(|c: char| c.is_whitespace() || c == '"' || c == ',' || c == ';')
        .next()?
        .trim();
    if token.len() >= 40 {
        Some(token.to_string())
    } else {
        None
    }
}

pub async fn probe_certificate(req: &ProbeRequest) -> Result<ProbedCertificate, ProbeError> {
    // Clamp timeout between 500ms and 60s (L-2)
    let dur = Duration::from_millis(req.timeout_ms.clamp(500, 60_000));
    match timeout(dur, probe_certificate_inner(req)).await {
        Ok(res) => res,
        Err(_) => Err(ProbeError::Timeout(dur)),
    }
}

/// Measures TCP handshake RTT in milliseconds to a node's effective dial endpoint.
pub async fn probe_tcp_latency_ms(host: &str, port: u16, timeout_ms: u64) -> Result<u64, ProbeError> {
    let dur = Duration::from_millis(timeout_ms.clamp(500, 15_000));
    let addr = timeout(dur, resolve_target(host, port))
        .await
        .map_err(|_| ProbeError::Timeout(dur))??;
    let started = std::time::Instant::now();
    timeout(dur, TcpStream::connect(addr))
        .await
        .map_err(|_| ProbeError::Timeout(dur))?
        .map_err(ProbeError::TcpConnect)?;
    Ok(started.elapsed().as_millis().max(1) as u64)
}

const MAX_LEAF_CERT_DER_BYTES: usize = 64 * 1024;

#[derive(Debug, Default)]
struct CapturedLeaf {
    leaf_der: Option<Vec<u8>>,
    chain_len: usize,
}

async fn probe_certificate_inner(req: &ProbeRequest) -> Result<ProbedCertificate, ProbeError> {
    if req.host.trim().is_empty() || req.port == 0 {
        return Err(ProbeError::InvalidServerName(format!(
            "{}:{}",
            req.host, req.port
        )));
    }
    let clean_sni = strip_ip_brackets(&req.sni);
    if clean_sni.is_empty() {
        return Err(ProbeError::InvalidServerName(req.sni.clone()));
    }

    let target_addr = resolve_target(&req.host, req.port).await?;
    let captured: Arc<Mutex<CapturedLeaf>> = Arc::new(Mutex::new(CapturedLeaf::default()));
    let sig_verified = Arc::new(AtomicBool::new(false));
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let verifier = Arc::new(CapturingCertVerifier {
        captured: Arc::clone(&captured),
        sig_verified: Arc::clone(&sig_verified),
        algs: provider.signature_verification_algorithms,
    });

    let mut tls_config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| ProbeError::TlsHandshake(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    if !req.alpn.is_empty() {
        tls_config.alpn_protocols = req.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    }

    match &req.transport {
        ProbeTransport::TcpTls => {
            let server_name = ServerName::try_from(clean_sni.clone())
                .map_err(|_| ProbeError::InvalidServerName(req.sni.clone()))?;
            let tcp = TcpStream::connect(target_addr)
                .await
                .map_err(ProbeError::TcpConnect)?;
            let connector = TlsConnector::from(Arc::new(tls_config));
            let handshake_res = connector.connect(server_name, tcp).await;
            let (leaf_opt, chain_len) = {
                let g = captured.lock().unwrap_or_else(|e| e.into_inner());
                (g.leaf_der.clone(), g.chain_len)
            };
            let Some(leaf) = leaf_opt else {
                if let Err(e) = handshake_res {
                    return Err(ProbeError::TlsHandshake(e.to_string()));
                }
                return Err(ProbeError::NoCertificatePresented);
            };
            // Cryptographic proof-of-possession check: peer MUST have signed TLS CertificateVerify (H-4)
            if !sig_verified.load(Ordering::Acquire) {
                return Err(match handshake_res {
                    Err(e) => ProbeError::TlsHandshake(e.to_string()),
                    Ok(_) => ProbeError::SignatureNotVerified,
                });
            }
            parse_leaf_cert_der(&leaf, &clean_sni, chain_len)
        }
        ProbeTransport::Quic {
            salamander_password,
        } => {
            let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
                .map_err(|e| ProbeError::QuicHandshake(e.to_string()))?;
            let client_cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));

            let bind_addr: SocketAddr = match target_addr {
                SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
                SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
            };

            let endpoint = if let Some(psk) = salamander_password {
                let obfs = SalamanderObfuscator::new(psk.as_bytes())
                    .map_err(ProbeError::InvalidSalamanderPsk)?;
                let std_udp = std::net::UdpSocket::bind(bind_addr)
                    .map_err(|e| ProbeError::QuicHandshake(e.to_string()))?;
                let wrapped = SalamanderUdpSocket::new(std_udp, obfs)
                    .map_err(|e| ProbeError::QuicHandshake(e.to_string()))?;
                let runtime = quinn::default_runtime()
                    .ok_or_else(|| ProbeError::QuicHandshake("no tokio runtime".into()))?;
                quinn::Endpoint::new_with_abstract_socket(
                    quinn::EndpointConfig::default(),
                    None,
                    Arc::new(wrapped),
                    runtime,
                )
                .map_err(|e| ProbeError::QuicHandshake(e.to_string()))?
            } else {
                quinn::Endpoint::client(bind_addr)
                    .map_err(|e| ProbeError::QuicHandshake(e.to_string()))?
            };

            let connecting = endpoint
                .connect_with(client_cfg, target_addr, &clean_sni)
                .map_err(|e| ProbeError::QuicHandshake(e.to_string()))?;
            let handshake_res = connecting.await;
            endpoint.close(0u32.into(), b"probe-done");

            let (leaf_opt, chain_len) = {
                let g = captured.lock().unwrap_or_else(|e| e.into_inner());
                (g.leaf_der.clone(), g.chain_len)
            };
            let Some(leaf) = leaf_opt else {
                if let Err(e) = handshake_res {
                    return Err(ProbeError::QuicHandshake(e.to_string()));
                }
                return Err(ProbeError::NoCertificatePresented);
            };
            if !sig_verified.load(Ordering::Acquire) {
                return Err(match handshake_res {
                    Err(e) => ProbeError::QuicHandshake(e.to_string()),
                    Ok(_) => ProbeError::SignatureNotVerified,
                });
            }
            parse_leaf_cert_der(&leaf, &clean_sni, chain_len)
        }
    }
}

async fn resolve_target(host: &str, port: u16) -> Result<SocketAddr, ProbeError> {
    if let Ok(ip) = host.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut addrs = lookup_host((host, port))
        .await
        .map_err(|source| ProbeError::DnsResolution {
            host: host.to_string(),
            port,
            source,
        })?;
    addrs.next().ok_or_else(|| ProbeError::NoAddress {
        host: host.to_string(),
        port,
    })
}

pub fn parse_leaf_cert_der(
    leaf_der: &[u8],
    sni: &str,
    chain_len: usize,
) -> Result<ProbedCertificate, ProbeError> {
    let (remaining, cert) =
        X509Certificate::from_der(leaf_der).map_err(|e| ProbeError::X509Parse(format!("{e}")))?;
    // Reject trailing bytes after DER certificate to prevent cert hash smuggling (L-2)
    if !remaining.is_empty() {
        return Err(ProbeError::X509Parse(
            "unexpected trailing bytes after DER certificate".into(),
        ));
    }

    let spki_der = cert.public_key().raw;
    if spki_der.is_empty() {
        return Err(ProbeError::X509Parse("empty SPKI in leaf certificate".into()));
    }
    let spki_digest = Sha256::digest(spki_der);
    let spki_sha256_b64 = STANDARD.encode(spki_digest);

    let cert_digest = Sha256::digest(leaf_der);
    let cert_sha256_hex = hex::encode(cert_digest);
    let cert_sha256_b64 = STANDARD.encode(cert_digest);

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let is_self_signed = cert.subject() == cert.issuer();

    let mut san_dns = Vec::new();
    let mut san_ip = Vec::new();
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            match name {
                GeneralName::DNSName(dns) => san_dns.push((*dns).to_string()),
                GeneralName::IPAddress(bytes) => {
                    if bytes.len() == 4 {
                        let ip = std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
                        san_ip.push(ip.to_string());
                    } else if bytes.len() == 16 {
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(bytes);
                        let ip = std::net::Ipv6Addr::from(arr);
                        san_ip.push(ip.to_string());
                    }
                }
                _ => {}
            }
        }
    }

    let hostname_matches_sni = check_sni_match(sni, &san_dns, &san_ip);

    let not_before = cert
        .validity()
        .not_before
        .to_rfc2822()
        .unwrap_or_else(|_| cert.validity().not_before.to_string());
    let not_after = cert
        .validity()
        .not_after
        .to_rfc2822()
        .unwrap_or_else(|_| cert.validity().not_after.to_string());

    Ok(ProbedCertificate {
        spki_sha256_b64,
        cert_sha256_hex,
        cert_sha256_b64,
        sni: sni.to_string(),
        subject,
        issuer,
        san_dns,
        san_ip,
        not_before,
        not_after,
        is_self_signed,
        hostname_matches_sni,
        chain_len,
    })
}

fn check_sni_match(sni: &str, san_dns: &[String], san_ip: &[String]) -> bool {
    let target = sni.trim().trim_end_matches('.').to_ascii_lowercase();
    if target.is_empty() {
        return false;
    }
    if let Ok(target_ip) = target.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
        return san_ip
            .iter()
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .any(|ip| ip == target_ip);
    }
    for pattern in san_dns {
        let pat = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
        if pat == target {
            return true;
        }
        if let Some(suffix) = pat.strip_prefix("*.") {
            // Require at least two labels in wildcard suffix (blocks `*.com` / `*.`) (L-2)
            if suffix.contains('.') && !suffix.starts_with('.') {
                if let Some((label, rest)) = target.split_once('.') {
                    if !label.is_empty() && rest == suffix {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Custom rustls verifier used strictly for TOFU certificate probing.
/// Accepts self-signed / non-CA chains while STRICTLY verifying TLS 1.2/1.3 `CertificateVerify`
/// cryptographic signatures so an attacker without the private key cannot spoof a certificate (H-4).
#[derive(Debug)]
struct CapturingCertVerifier {
    captured: Arc<Mutex<CapturedLeaf>>,
    sig_verified: Arc<AtomicBool>,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for CapturingCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let leaf_bytes = end_entity.as_ref();
        if leaf_bytes.is_empty() || leaf_bytes.len() > MAX_LEAF_CERT_DER_BYTES {
            return Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        let mut guard = self.captured.lock().unwrap_or_else(|e| e.into_inner());
        guard.leaf_der = Some(leaf_bytes.to_vec());
        guard.chain_len = 1 + intermediates.len();
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        let res = rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)?;
        self.sig_verified.store(true, Ordering::Release);
        Ok(res)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        let res = rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)?;
        self.sig_verified.store(true, Ordering::Release);
        Ok(res)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxq_core_model::RealityConfig;

    fn sample_probed(sni: &str) -> ProbedCertificate {
        ProbedCertificate {
            spki_sha256_b64: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".into(),
            cert_sha256_hex: "a".repeat(64),
            cert_sha256_b64: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".into(),
            sni: sni.to_string(),
            subject: format!("CN={sni}"),
            issuer: format!("CN={sni}"),
            san_dns: vec![],
            san_ip: vec![],
            not_before: "2026-01-01".into(),
            not_after: "2027-01-01".into(),
            is_self_signed: true,
            hostname_matches_sni: true,
            chain_len: 1,
        }
    }

    #[test]
    fn from_node_strips_ipv6_brackets_for_host_and_sni() {
        let mut node = NodeConfig::new(
            "IPv6-Trojan",
            "[2001:db8::1]",
            443,
            ProtocolConfig::Trojan {
                password: "pw".into(),
            },
        );
        node.tls.enabled = true;
        node.tls.server_name = Some("[2001:db8::2]".into());

        let req = ProbeRequest::from_node(&node);
        assert_eq!(req.host, "2001:db8::1");
        assert_eq!(req.sni, "2001:db8::2");
        let parsed = ServerName::try_from(req.sni.clone()).expect("unbracketed IPv6 must parse");
        assert!(matches!(parsed, ServerName::IpAddress(_)));

        // Also when server_name is None (falls back to bracketed server)
        node.tls.server_name = None;
        let req_fallback = ProbeRequest::from_node(&node);
        assert_eq!(req_fallback.sni, "2001:db8::1");
        assert!(matches!(
            ServerName::try_from(req_fallback.sni),
            Ok(ServerName::IpAddress(_))
        ));
    }

    #[test]
    fn apply_confirmed_pin_does_not_write_ip_literal_into_server_name() {
        for ip_sni in ["203.0.113.10", "2001:db8::1", "[2001:db8::1]", ""] {
            let mut node = NodeConfig::new(
                "IP-Node",
                "203.0.113.10",
                443,
                ProtocolConfig::Trojan {
                    password: "pw".into(),
                },
            );
            node.tls.enabled = true;
            node.tls.server_name = None;
            let rec = sample_probed(ip_sni).into_trust_record(TrustOrigin::TofuProbe);

            apply_confirmed_pin(&mut node, rec);
            assert_eq!(
                node.tls.server_name, None,
                "IP literal or empty SNI '{ip_sni}' must not populate tls.server_name"
            );
            assert_eq!(node.tls.verify_mode, TlsVerifyMode::PinnedSpki);
            assert!(node.tls.trust_record.is_some());
        }

        // Legitimate domain SNI still populates empty server_name
        let mut domain_node = NodeConfig::new(
            "Domain-Node",
            "edge.example.com",
            443,
            ProtocolConfig::Trojan {
                password: "pw".into(),
            },
        );
        domain_node.tls.enabled = true;
        domain_node.tls.server_name = None;
        let domain_rec = sample_probed("edge.example.com").into_trust_record(TrustOrigin::TofuProbe);
        apply_confirmed_pin(&mut domain_node, domain_rec);
        assert_eq!(
            domain_node.tls.server_name.as_deref(),
            Some("edge.example.com")
        );
    }

    #[test]
    fn rejects_spki_pinning_for_vless_reality_nodes() {
        let mut node = NodeConfig::new(
            "VLESS-Reality",
            "reality.example.com",
            443,
            ProtocolConfig::Vless {
                uuid: "11111111-1111-1111-1111-111111111111".into(),
                flow: Some("xtls-rprx-vision".into()),
                packet_encoding: None,
            },
        );
        node.tls.enabled = true;
        node.tls.server_name = Some("www.microsoft.com".into());
        node.tls.reality = Some(RealityConfig {
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            short_id: "01234567".into(),
        });

        let probed = sample_probed("www.microsoft.com");
        let err = evaluate_probe_against_node(&node, &probed).unwrap_err();
        assert!(matches!(err, ProbeError::RealityPinNotSupported));
        assert!(err
            .to_string()
            .contains("VLESS Reality 节点使用 Reality 公钥认证，不能绑定常规 TLS SPKI 证书指纹"));

        // apply_confirmed_pin also refuses to mutate a Reality node
        let rec = probed.into_trust_record(TrustOrigin::TofuProbe);
        apply_confirmed_pin(&mut node, rec);
        assert_eq!(node.tls.verify_mode, TlsVerifyMode::SystemCa);
        assert!(node.tls.trust_record.is_none());
    }
}
