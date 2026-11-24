# MaxQ

A security-first, Windows-oriented `sing-box v1.14+` proxy client with Shadowrocket dialect compatibility, Schannel-free TLS/QUIC certificate probing & TOFU SPKI pinning, `.conf`/subscription sanitization, built-in default split-routing rules, direct-node leak prevention, and an LPE-hardened Windows TUN service.

## Architecture (v0.2.0)

- `crates/core-model`: Canonical Internal IR (`NodeConfig`, `TlsVerifyMode`, `TrustRecord`, `RuleEntry`, `HostEntry`, `RuntimePolicy`, `RoutingMode`, `ProxyMode`) decoupled from `sing-box` JSON schema churn.
- `crates/parser`: Multi-format parser covering 7 protocols (`trojan`, `vless`, `vmess`, `anytls`, `hysteria2`/`hy2`, `tuic`, `ss`) with Shadowrocket dialect normalization (`peer`, `allowInsecure`, `pcs`, `vcn`, `mport`, `obfs`, Shadowrocket `vmess://` URI), Shadowrocket `.conf` INI files, Base64 subscriptions, Clash YAML, and `sing-box` JSON.
- `crates/sanitizer`: Security Quarantine Engine that hard-strips `[MITM]`, `[Script]`, `[URL Rewrite]`, external `inbounds`/`clash_api`/local path overrides, classifies & quarantines `[Host]` entries (`ProxyEndpointAlias` vs `ThirdPartyDomainOverride`), blocks SSRF/UNC URLs, restricts `tun-excluded-routes` to private CIDRs, and enforces **Scheme A (Strict Default Safe)**.
- `crates/cert-probe`: Pure-Rust Schannel-free TLS (`rustls` + real `CertificateVerify` signature verification) & QUIC (`quinn`) + Hysteria2 **Salamander** BLAKE2b-256 UDP obfuscation certificate prober & TCP latency tester.
- `crates/singbox-compiler`: Strict `sing-box v1.14+` JSON compiler with embedded sanitized default split-routing rules (`8,581` rules), `Rule` / `Global` / `Direct` modes, explicit `"detour": "proxy"` on v1.12+ typed DoH DNS, order-preserving category-safe rule coalescing, IPv6 leak blocking, dual-stack `strict_route` TUN, and hardened `127.0.0.1` + 32-byte random Bearer secret Clash API.
- `crates/storage`: Bundled SQLite WAL vault (`rusqlite`) for profiles, nodes, and TOFU `trust_vault`.
- `crates/win-service`: On-demand Windows Privileged TUN Service (`maxq-service.exe`) with SDDL DACL Named Pipe (`PIPE_REJECT_REMOTE_CLIENTS`), caller process image path verification, hardcoded `sing-box.exe` SHA-256 integrity verification, SYSTEM-only `ProgramData` runtime directory (anti-`wintun.dll` hijack), and zero arbitrary-execution IPC.
- `crates/core-runtime`: `sing-box` supervisor, Named Pipe TUN client + UAC installer wrapper, secret log redaction, real-time `unrecognized remote public key:` MITM watcher, and crash-safe Windows `WinINet` System Proxy manager.
- `apps/desktop`: Tauri v2 + React 19 + Tailwind CSS v4 desktop workstation with System Tray, unified Routing/Engine command deck, batch Probe & Pin, latency testing, and 3-mode secure import.

## Verification

```bash
cargo test --workspace
cd apps/desktop && pnpm run build
```
