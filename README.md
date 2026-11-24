# MaxQ

A security-first, Windows-oriented `sing-box v1.14+` proxy client with Shadowrocket dialect compatibility, Schannel-free TLS/QUIC certificate probing & TOFU SPKI pinning, `.conf`/subscription sanitization, and direct-node leak prevention.

## Workspace Architecture (Milestone 1 — Core Engine)

- `crates/core-model`: Canonical Internal IR (`NodeConfig`, `TlsVerifyMode`, `TrustRecord`, `RuleEntry`, `HostEntry`, `RuntimePolicy`) completely decoupled from `sing-box` JSON schema churn.
- `crates/parser`: Multi-format parser covering 7 protocols (`trojan`, `vless`, `vmess`, `anytls`, `hysteria2`/`hy2`, `tuic`, `ss`) with Shadowrocket dialect normalization (`peer`, `allowInsecure`, `pcs`, `vcn`, `mport`, `obfs`, Shadowrocket `vmess://` URI), Shadowrocket `.conf` INI files, Base64 subscriptions, Clash YAML, and `sing-box` JSON.
- `crates/sanitizer`: Security Quarantine Engine that hard-strips `[MITM]`, `[Script]`, `[URL Rewrite]`, external `inbounds`/`clash_api`/local path overrides, classifies & quarantines `[Host]` entries (`ProxyEndpointAlias` vs `ThirdPartyDomainOverride`), blocks SSRF URLs, and enforces **Scheme A (Strict Default Safe)** on `allowInsecure=1` nodes.
- `crates/cert-probe`: Pure-Rust Schannel-free TLS (`rustls`) & QUIC (`quinn`) + Hysteria2 **Salamander** BLAKE2b-256 UDP obfuscation certificate prober. Computes `SPKI SHA-256 (Base64)` (matching `sing-box` `certificate_public_key_sha256`) and `Cert SHA-256 (Hex/Base64)`, performs cryptographic `pcs`/`pinSHA256` -> SPKI bootstrap verification, detects TOFU drift, and parses `sing-box` runtime `unrecognized remote public key:` MITM errors.
- `crates/singbox-compiler`: Strict `sing-box v1.14+` JSON compiler (zero deprecated fields), featuring Scheme A insecure block guard, explicit `"detour": "proxy"` on v1.12+ typed DoH DNS servers, IPv6 leak protection, order-preserving adjacent rule coalescing, and hardened `127.0.0.1` + random Bearer secret Clash API.

## Verification

```bash
cargo test --workspace
```
