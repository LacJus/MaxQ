# MaxQ

**Security-first Windows desktop proxy client · Powered by JaxCore · `sing-box v1.14.4` · Crafted by JucStudio · Neon**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-6366f1.svg)](./LICENSE)
[![Engine: sing-box v1.14.4](https://img.shields.io/badge/Engine-sing--box%20v1.14.4-8b5cf6.svg)](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4)
[![Platform: Windows x64](https://img.shields.io/badge/Platform-Windows%2010%2F11%20x64-0ea5e9.svg)](https://github.com/LacJus/MaxQ/releases)

MaxQ 是一款基于 **Rust + Tauri v2 + React 19** 构建的 Windows 安全优先代理客户端，专为 **`sing-box v1.14+`** 与 **Shadowrocket / Clash / 分享链** 生态深度打造。它以「默认安全、零残留防断网、低占用高流畅」为核心原则，兼顾硬核底层防护与扁平灵动的晴岚浅蓝紫桌面体验。

---

## 核心特性

### 1. 默认安全与防注入体系
- **外部配置强净化**：导入 Shadowrocket `.conf`、Clash YAML、sing-box JSON 及 HTTPS 订阅时，强制剥离 `[MITM]`、`[Script]`、`[URL Rewrite]`、`[Header Rewrite]`、`[Map Local]`、任意本地路径与危险 Shadowsocks `plugin`；`[Host]` 条目默认隔离，需按 `(域名, 目标)` 精确审批。
- **Scheme A 证书保护 + 无 Schannel TOFU 钉扎**：
  - 导入 `allowInsecure=1` 节点默认阻断，不静默放行；
  - 内置纯 Rust **`rustls` / `quinn`** 探测器（原生支持 Hysteria2 **Salamander** UDP 混淆），完全绕过 Windows Schannel 限制，直接提取真实叶证书 **SPKI SHA-256** 并生成唯一几何视觉徽章供人工核对；
  - 支持 `pcs` / `pinSHA256` 引导核验；运行时若检测到 `unrecognized remote public key:` 立即弹出 MITM 警报，绝不静默覆盖指纹。
- **安全日志脱敏与凭据清理**：统一脱敏日志中的 Bearer Secret、密码、UUID、Reality 密钥与 URI 凭据；退出/崩溃/启动时自动清理磁盘明文运行时配置。

### 2. 加固 Windows TUN 服务 & 零残留系统代理
- **独立按需提权 TUN 服务（`MaxQTunService`）**：
  - GUI 始终以标准低权限用户运行；系统代理模式全程无需管理员权限；
  - TUN 模式通过 SDDL 锁定 Named Pipe（禁远程连接、剥离管道抢注位）、规范化调用方进程路径与 SHA-256 绑定、`SetNamedSecurityInfoW` 原子锁定 `Owner = SYSTEM` + 保护态 DACL（拒绝符号链接/硬链接）、`sing-box.exe` 硬编码 SHA-256 启动核验及严格 JSON 配置白名单，系统性防范 Windows 代理客户端常见本地提权（LPE）风险。
- **防断网系统代理与完整生命周期闭环**：
  - 使用官方 WinINet `InternetSetOptionW(PER_CONNECTION_OPTION)` 原子同步注册表与 `DefaultConnectionSettings`，完整保留企业 PAC / WPAD 标志位；
  - 用户态与 TUN 子进程均托管于 Windows **Job Object**（`KILL_ON_JOB_CLOSE`），崩溃自动关闭系统代理自愈；
  - 内置 NSIS 安装/升级/卸载钩子：覆盖升级自动热刷新 TUN 服务，卸载自动恢复回环系统代理并彻底清理服务与 `%ProgramData%\MaxQ`。

### 3. 全协议兼容与精准分流
- **7 大主流协议深度归一化**：支持 `VLESS`（含 Reality / Vision）、`Trojan`、`VMess`、`AnyTLS`、`Hysteria2`（含 Salamander 混淆与端口跳跃）、`TUIC v5`、`Shadowsocks`；全格式支持 `ws` / `grpc` / `httpupgrade` 传输层，自动规避 QUIC 协议误开 uTLS、Shadowrocket 方言字段差异与 IPv6 方括号边界。
- **开箱即用分流引擎**：内置 **8,581 条** 脱敏默认分流规则（国内直连域名 + CN IP-CIDR + 海外代理），支持 **规则 / 全局 / 直连** 一键热切换，TUN 网段采用 RFC 2544 `198.18.0.1/30` 避让 Docker / WSL2 与 Tailscale。

### 4. 灵动体验与低静默占用
- **实时遥测与星轨雷达**：Rust 侧直连回环 Clash API（32 字节随机 Bearer Secret，WebView 零密钥暴露），提供实时上下行波形、Max-Q 动压指数、活跃连接流与并发星轨测速。
- **低功耗后台设计**：TUN 服务状态轮询走元信息缓存（0 持续读盘）、复用长连接 HTTP 客户端、窗口隐藏自动降频节流、休眠唤醒自动清理僵死连接池。

---

## 下载与校验

请前往 [**GitHub Releases**](https://github.com/LacJus/MaxQ/releases) 下载对应版本的 Windows 安装包或自包含便携包：
- `MaxQ_<version>_x64-setup.exe`（推荐 · NSIS 安装包，含自动升级/卸载清理钩子）
- `MaxQ_<version>_x64_en-US.msi`（MSI 企业部署包）
- `MaxQ-portable-win64.zip`（便携压缩包，内含 `resources/sing-box.exe` 与 `maxq-service.exe`）

> **关于 Windows SmartScreen / 杀毒软件提示**：  
> MaxQ 为独立开源项目，暂未购买商业 EV 代码签名证书，首次运行安装器或安装 TUN 服务时系统可能弹出“未知发布者”提示。请务必仅从官方 Releases 下载，对照 `SHA256SUMS.txt` 核验哈希，并可随时查阅公开的 GitHub Actions 构建日志以验证二进制可溯源性。

---

## 架构概览

```text
MaxQ/
├── crates/
│   ├── core-model/        # 节点、配置、规则、策略与信任库统一 IR 模型
│   ├── parser/            # 7 协议分享链 + Shadowrocket .conf + Clash YAML + sing-box JSON 解析与归一化
│   ├── sanitizer/         # 危险段强剥离、[Host] 隔离、Scheme A 安全降级与 SSRF 校验
│   ├── cert-probe/        # 纯 Rust rustls / quinn + Hysteria2 Salamander 无 Schannel 证书探测
│   ├── singbox-compiler/  # sing-box v1.14+ 零警告编译器 + 内置 8,581 条脱敏分流规则
│   ├── storage/           # SQLite WAL 本地信任库（Profiles / Nodes / Trust Vault）
│   ├── core-runtime/      # sing-box 进程托管、Job Object、WinINet 系统代理与 TUN IPC 客户端
│   ├── win-service/       # 加固 Windows LocalSystem TUN 服务（maxq-service.exe）
│   └── maxq-cli/          # 审计、探测与编译干跑 CLI 工具
└── apps/
    └── desktop/           # Tauri v2 + React 19 + Tailwind CSS v4 桌面端与 NSIS 钩子
```

---

## 本地开发与构建

### 前置依赖
- Rust（stable，`rustup`）
- Node.js 22+ 与 `pnpm`
- `sing-box v1.14.4`（运行集成校验测试需在 `PATH`、`$HOME/.local/bin/sing-box` 或环境变量 `SING_BOX_BIN` 指定）

### 常用命令

```bash
# 运行全部 Rust 核心单元与真实 sing-box v1.14.4 集成测试（58 项）
cargo test --workspace

# 编译前端静态资源
pnpm --dir apps/desktop install --frozen-lockfile
pnpm --dir apps/desktop run build

# Windows 下构建加固 TUN 服务与 Tauri v2 安装包
cargo build --release -p maxq-win-service --bin maxq-service
pnpm --dir apps/desktop exec tauri build
```

---

## 许可协议与开源致谢

- MaxQ 源代码采用 **[Apache License 2.0](./LICENSE)** 开源。
- 预构建安装包内嵌未修改的官方 `sing-box v1.14.4`（**GPL-3.0-or-later**），详见 **[THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md)**。
- 安全漏洞私密披露流程请参阅 **[SECURITY.md](./SECURITY.md)**。

## 免责声明

本项目仅供计算机网络技术学习、科研测试及合法的网络隐私安全保护使用，**不内置、不提供、也不推荐任何代理节点或第三方订阅服务**。使用本项目时请严格遵守您所在国家或地区的法律法规，因违规使用产生的一切后果由使用者自行承担。
