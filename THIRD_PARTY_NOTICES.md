# Third-Party Notices & Open-Source Attributions

MaxQ's own source code in this repository is licensed under the **Apache License 2.0** (see [`LICENSE`](./LICENSE)).

Pre-built Windows installers and portable archives bundle or rely on the following open-source components, each governed by its own respective license:

---

## 1. sing-box (Bundled Sidecar Executable)

- **Project**: [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- **Bundled Version**: `v1.14.4` (`windows-amd64` official unmodified release binary)
- **License**: **GNU General Public License v3.0 or later (`GPL-3.0-or-later`)** with the sing-box Name-Use Exception
- **Corresponding Source Code**: <https://github.com/SagerNet/sing-box/releases/tag/v1.14.4>
- **License Text**: <https://www.gnu.org/licenses/gpl-3.0.txt>
- **Pinned SHA-256 Digest (`sing-box.exe` v1.14.4 windows-amd64)**:
  `8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9`

MaxQ interacts with `sing-box` strictly as a separate unmodified child process via JSON configuration files and the loopback Clash API. MaxQ is an independent third-party desktop client (**Powered by JaxCore · sing-box**, created by **JucStudio · Neon**) and is not affiliated with or endorsed by SagerNet.

---

## 2. Core Rust & Desktop Ecosystem Crates / Packages

- **Tauri v2** (`tauri`, `tauri-build`) — Apache-2.0 / MIT
- **Tokio** (`tokio`) — MIT
- **Rustls & Quinn** (`rustls`, `tokio-rustls`, `quinn`, `x509-parser`, `rcgen`) — Apache-2.0 / MIT / ISC
- **rusqlite** (bundled SQLite) — MIT / Public Domain
- **serde / serde_json / serde_yaml_ng** — Apache-2.0 / MIT
- **reqwest** — Apache-2.0 / MIT
- **windows-sys / windows-service / winreg** — Apache-2.0 / MIT
- **React 19 / Vite / Tailwind CSS v4 / Lucide Icons** — MIT / ISC

---

## 3. Built-in Default Split-Routing Rules

[`crates/singbox-compiler/assets/default_rules.conf`](./crates/singbox-compiler/assets/default_rules.conf) contains a sanitized, generic domain/IP-CIDR split-routing rule list (CN direct / overseas proxy) with all proxy endpoints, credentials, host overrides, MITM rules, and scripts stripped.
