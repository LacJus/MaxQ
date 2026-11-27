# Security Policy

MaxQ is built with a **security-first** threat model covering untrusted proxy configs, TLS/QUIC certificate verification, and Windows privileged TUN isolation.

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `1.0.x` | Yes (Active) |
| `< 1.0.0` | No (Pre-release previews; please upgrade to `v1.0.0+`) |

## Reporting a Vulnerability

**Please do NOT open public GitHub issues for security vulnerabilities** (especially anything involving `maxq-service.exe`, Named Pipe IPC, installer hooks, config sanitization, or certificate verification).

1. Use GitHub's **Private Vulnerability Reporting** feature on the repository's **Security → Advisories → Report a vulnerability** tab.
2. Please include:
   - Affected MaxQ version and Windows version
   - Root cause or minimal reproduction steps / PoC
   - Security impact assessment
3. We aim to acknowledge reports within 72 hours and coordinate a fix before public disclosure.

## Security Architecture Highlights

1. **Untrusted Import Sanitization**: Hard-strips Shadowrocket `[MITM]`, `[Script]`, `[URL Rewrite]`, `[Header Rewrite]`, `[Map Local]`, arbitrary local paths, unsafe Shadowsocks plugins, and external `inbounds`/`clash_api` overrides. Quarantines `[Host]` entries disabled-by-default with exact `(domain, target)` user approval.
2. **Scheme A Default-Safe TLS & Schannel-Free TOFU Pinning**: Nodes importing `allowInsecure=1` are blocked by default until probed via pure-Rust `rustls` / `quinn` (with Hysteria2 Salamander UDP obfuscation support) and pinned via `certificate_public_key_sha256` (SPKI). Runtime SPKI drift triggers an immediate MITM alert and never auto-rotates pins.
3. **Hardened Windows TUN Service (`MaxQTunService`)**:
   - Unprivileged GUI; `LocalSystem` helper service installed only on demand.
   - SDDL-locked Named Pipe (`PIPE_REJECT_REMOTE_CLIENTS`, strips `FILE_CREATE_PIPE_INSTANCE` from interactive users), canonicalized caller executable verification, and SHA-256 verification of both `sing-box.exe` and the authorized GUI binary.
   - Win32 `SetNamedSecurityInfoW` atomic Owner (`S-1-5-18`) + protected DACL locking with reparse-point and hardlink rejection on `%ProgramData%\MaxQ`.
   - Strict JSON schema & key allowlist (`validate_service_config`) blocking case-insensitive Go `EqualFold` bypasses, file-write paths, public TUN CIDRs, and low ports.
4. **Local API & System Hygiene**: Loopback-only Clash API with per-launch 32-byte random Bearer secret and strict Tauri CORS; Windows Job Objects (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`); WinINet `PER_CONNECTION_OPTION` atomic proxy restore + NSIS pre-uninstall cleanup; full log secret redaction.

## Verifying Official Binaries (SmartScreen / AV Notice)

Because MaxQ is an independent open-source project without a commercial EV code-signing certificate, Windows SmartScreen or third-party antivirus software may flag unsigned installers or `maxq-service.exe` (which uses Windows Service Control Manager and Win32 ACL APIs).

- Always download installers exclusively from **official GitHub Releases** (`https://github.com/LacJus/MaxQ/releases`).
- Verify the installer's SHA-256 hash against the `SHA256SUMS.txt` published alongside each release and inspect the public GitHub Actions build logs for full build provenance.
