import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  FileWarning,
  Globe,
  KeyRound,
  Lock,
  Plus,
  Power,
  RefreshCw,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Trash2,
  X,
} from "lucide-react";
import { api, isTauriRuntime } from "./api";
import type {
  NodeConfig,
  ProbeNodeResult,
  ProfileSummary,
  RuntimePolicy,
  RuntimeStatus,
  SanitizedImport,
  StoredProfile,
} from "./types";

type Tab = "nodes" | "security" | "logs" | "settings";

function protocolLabel(p: NodeConfig["protocol"]["type"]): string {
  switch (p) {
    case "any_tls":
      return "AnyTLS";
    case "hysteria2":
      return "Hysteria2";
    case "tuic":
      return "TUIC";
    case "vless":
      return "VLESS";
    case "trojan":
      return "Trojan";
    case "vmess":
      return "VMess";
    case "shadowsocks":
      return "SS";
  }
}

function tlsBadge(node: NodeConfig) {
  if (!node.tls.enabled) {
    return {
      label: "No TLS",
      cls: "bg-slate-800 text-slate-300 border-slate-700",
      icon: Globe,
    };
  }
  switch (node.tls.verify_mode.mode) {
    case "pinned_spki":
      return {
        label: "SPKI Pinned (TOFU)",
        cls: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
        icon: ShieldCheck,
      };
    case "system_ca":
      return {
        label: "CA Verified",
        cls: "bg-cyan-500/15 text-cyan-300 border-cyan-500/40",
        icon: Lock,
      };
    case "pending_pin_bootstrap":
      return {
        label: "Pin Bootstrap Pending",
        cls: "bg-amber-500/15 text-amber-300 border-amber-500/40",
        icon: KeyRound,
      };
    case "insecure_legacy":
      return node.tls.verify_mode.user_confirmed_override
        ? {
            label: "Insecure Override",
            cls: "bg-orange-500/15 text-orange-300 border-orange-500/40",
            icon: AlertTriangle,
          }
        : {
            label: "Unverified TLS (Blocked)",
            cls: "bg-rose-500/15 text-rose-300 border-rose-500/40",
            icon: ShieldAlert,
          };
  }
}

export default function App() {
  const inTauri = isTauriRuntime();
  const [tab, setTab] = useState<Tab>("nodes");
  const [profiles, setProfiles] = useState<ProfileSummary[]>([]);
  const [selectedProfileId, setSelectedProfileId] = useState<string | null>(null);
  const [profile, setProfile] = useState<StoredProfile | null>(null);
  const [status, setStatus] = useState<RuntimeStatus>({
    running: false,
    system_proxy_enabled: false,
  });
  const [logs, setLogs] = useState<string[]>([]);
  const [policy, setPolicy] = useState<RuntimePolicy>({
    mixed_listen_port: 17890,
    allow_lan: false,
    clash_api_port: 19090,
    clash_api_secret: "",
    clash_api_allowed_origins: ["http://tauri.localhost", "https://tauri.localhost"],
    tun_enabled: false,
    ipv6_mode: "block_to_prevent_leak",
    remote_dns_server: "1.1.1.1",
    direct_dns_server: "223.5.5.5",
  });
  const [enableSysProxy, setEnableSysProxy] = useState(true);
  const [bannerError, setBannerError] = useState<string | null>(null);

  // Import modal state
  const [importOpen, setImportOpen] = useState(false);
  const [importName, setImportName] = useState("Imported Profile");
  const [importText, setImportText] = useState("");
  const [preview, setPreview] = useState<SanitizedImport | null>(null);
  const [approvedHostDomains, setApprovedHostDomains] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);

  // TLS TOFU Probe Drawer state
  const [inspectNode, setInspectNode] = useState<NodeConfig | null>(null);
  const [probeResult, setProbeResult] = useState<ProbeNodeResult | null>(null);
  const [probeLoading, setProbeLoading] = useState(false);
  const [probeError, setProbeError] = useState<string | null>(null);

  const refreshAll = async () => {
    if (!inTauri) return;
    try {
      const [list, st, pol, l] = await Promise.all([
        api.listProfiles(),
        api.getRuntimeStatus(),
        api.getRuntimePolicy(),
        api.getRuntimeLogs(),
      ]);
      setProfiles(list);
      setStatus(st);
      setPolicy(pol);
      setLogs(l);
      const targetId = selectedProfileId ?? list[0]?.id ?? null;
      if (targetId) {
        setSelectedProfileId(targetId);
        const full = await api.getProfile(targetId);
        setProfile(full);
      } else {
        setProfile(null);
      }
    } catch (err) {
      setBannerError(String(err));
    }
  };

  useEffect(() => {
    refreshAll();
    if (!inTauri) return;
    const timer = setInterval(async () => {
      try {
        const [st, l] = await Promise.all([api.getRuntimeStatus(), api.getRuntimeLogs()]);
        setStatus(st);
        setLogs(l);
      } catch {
        // ignore transient poll error
      }
    }, 2000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedProfileId]);

  const { metadataNodes, proxyNodes } = useMemo(() => {
    const all = profile?.nodes ?? [];
    return {
      metadataNodes: all.filter((n) => n.is_metadata_node),
      proxyNodes: all.filter((n) => !n.is_metadata_node),
    };
  }, [profile]);

  const handlePreviewImport = async () => {
    setBannerError(null);
    setBusy(true);
    try {
      const res = await api.previewImport(importText);
      setPreview(res);
      setApprovedHostDomains(new Set());
    } catch (err) {
      setBannerError(String(err));
    } finally {
      setBusy(false);
    }
  };

  const handleCommitImport = async () => {
    if (!preview) return;
    setBusy(true);
    try {
      const newId = await api.commitImport(
        importName.trim() || "Imported Profile",
        importText,
        Array.from(approvedHostDomains)
      );
      setImportOpen(false);
      setImportText("");
      setPreview(null);
      setSelectedProfileId(newId);
      await refreshAll();
    } catch (err) {
      setBannerError(String(err));
    } finally {
      setBusy(false);
    }
  };

  const handleStartNode = async (node: NodeConfig) => {
    if (!profile) return;
    setBannerError(null);
    try {
      const st = await api.startProxy(profile.id, node.id, enableSysProxy);
      setStatus(st);
    } catch (err) {
      const msg = String(err);
      setBannerError(msg);
      if (msg.includes("Scheme A") || msg.includes("PendingPinBootstrap")) {
        setInspectNode(node);
        setProbeResult(null);
        setProbeError(null);
      }
    }
  };

  const handleStopProxy = async () => {
    setBannerError(null);
    try {
      const st = await api.stopProxy();
      setStatus(st);
    } catch (err) {
      setBannerError(String(err));
    }
  };

  const handleProbeNode = async (node: NodeConfig) => {
    setInspectNode(node);
    setProbeResult(null);
    setProbeError(null);
    setProbeLoading(true);
    try {
      const res = await api.probeNodeCertificate(node.id);
      setProbeResult(res);
    } catch (err) {
      setProbeError(String(err));
    } finally {
      setProbeLoading(false);
    }
  };

  const handleConfirmPin = async () => {
    if (!inspectNode || !probeResult) return;
    try {
      const updated = await api.confirmNodePin(inspectNode.id, probeResult.proposed_trust_record);
      setInspectNode(updated);
      await refreshAll();
    } catch (err) {
      setProbeError(String(err));
    }
  };

  const handleToggleInsecureOverride = async (node: NodeConfig, confirmed: boolean) => {
    try {
      const updated = await api.setInsecureOverride(node.id, confirmed);
      setInspectNode(updated);
      await refreshAll();
    } catch (err) {
      setProbeError(String(err));
    }
  };

  const handleSavePolicy = async () => {
    try {
      const saved = await api.updateRuntimePolicy(policy);
      setPolicy(saved);
    } catch (err) {
      setBannerError(String(err));
    }
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-slate-950 text-slate-100">
      {/* Sidebar */}
      <aside className="flex w-60 flex-col border-r border-slate-800/80 bg-slate-900/60 p-4">
        <div className="mb-6 flex items-center gap-2.5 px-2">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 shadow-lg shadow-cyan-500/20">
            <Shield className="h-5 w-5 text-white" />
          </div>
          <div>
            <div className="text-base font-bold tracking-tight text-white">MaxQ</div>
            <div className="text-[11px] text-slate-400">sing-box v1.14 · Zero-Trust</div>
          </div>
        </div>

        <nav className="flex-1 space-y-1">
          {[
            { id: "nodes" as Tab, label: "节点与配置", icon: Server },
            { id: "security" as Tab, label: "安全隔离与规则", icon: ShieldCheck },
            { id: "logs" as Tab, label: "运行日志", icon: Terminal },
            { id: "settings" as Tab, label: "防泄漏与内核设置", icon: Settings },
          ].map((item) => {
            const Icon = item.icon;
            const active = tab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setTab(item.id)}
                className={`flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition ${
                  active
                    ? "bg-cyan-500/15 text-cyan-300 ring-1 ring-cyan-500/30"
                    : "text-slate-400 hover:bg-slate-800/70 hover:text-slate-200"
                }`}
              >
                <Icon className="h-4 w-4" />
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* Connection status card */}
        <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950/70 p-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">内核状态</span>
            <span
              className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-semibold ${
                status.running
                  ? "bg-emerald-500/15 text-emerald-300"
                  : "bg-slate-800 text-slate-400"
              }`}
            >
              <span
                className={`h-1.5 w-1.5 rounded-full ${
                  status.running ? "bg-emerald-400" : "bg-slate-500"
                }`}
              />
              {status.running ? "运行中" : "已停止"}
            </span>
          </div>
          <div className="mt-2 truncate text-xs text-slate-300">
            {status.active_node_name ?? "未连接节点"}
          </div>
          {status.running && (
            <button
              onClick={handleStopProxy}
              className="mt-3 flex w-full items-center justify-center gap-1.5 rounded-lg bg-rose-500/15 px-3 py-1.5 text-xs font-medium text-rose-300 ring-1 ring-rose-500/30 hover:bg-rose-500/25"
            >
              <Power className="h-3.5 w-3.5" /> 断开并恢复系统代理
            </button>
          )}
        </div>
      </aside>

      {/* Main content */}
      <main className="flex flex-1 flex-col overflow-hidden">
        {/* Global MITM Alert Banner */}
        {status.last_mitm_alert && (
          <div className="flex items-center justify-between border-b border-rose-500/40 bg-rose-950/90 px-6 py-3 text-sm text-rose-100">
            <div className="flex items-center gap-2.5">
              <ShieldAlert className="h-5 w-5 text-rose-400" />
              <span>
                <strong>高危安全告警（疑似 MITM 或服务端证书公钥变更）：</strong> 检测到未受信任的远端公钥 SPKI{" "}
                <code className="rounded bg-rose-900/80 px-1.5 py-0.5 font-mono text-xs">
                  {status.last_mitm_alert}
                </code>
              </span>
            </div>
          </div>
        )}

        {bannerError && (
          <div className="flex items-center justify-between border-b border-amber-500/30 bg-amber-950/50 px-6 py-2.5 text-xs text-amber-200">
            <span>{bannerError}</span>
            <button onClick={() => setBannerError(null)} className="text-amber-400 hover:text-white">
              <X className="h-4 w-4" />
            </button>
          </div>
        )}

        {!inTauri && (
          <div className="border-b border-cyan-500/20 bg-cyan-950/30 px-6 py-2 text-xs text-cyan-300">
            当前处于浏览器静态预览模式；运行 Tauri v2 桌面端时将自动连接 Rust 核心引擎与无 Schannel 证书探测器。
          </div>
        )}

        {/* Header */}
        <header className="flex items-center justify-between border-b border-slate-800/80 px-6 py-4">
          <div className="flex items-center gap-3">
            <h1 className="text-lg font-semibold text-white">
              {tab === "nodes" && "节点与订阅"}
              {tab === "security" && "安全隔离与 [Host] 审计"}
              {tab === "logs" && "sing-box 实时运行日志"}
              {tab === "settings" && "直连防泄漏与内核策略"}
            </h1>
            {profiles.length > 0 && tab === "nodes" && (
              <select
                value={selectedProfileId ?? ""}
                onChange={(e) => setSelectedProfileId(e.target.value)}
                className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-200 outline-none focus:border-cyan-500"
              >
                {profiles.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.node_count} 节点 · {p.rule_count} 规则)
                  </option>
                ))}
              </select>
            )}
          </div>

          <div className="flex items-center gap-3">
            <label className="flex cursor-pointer items-center gap-2 text-xs text-slate-300">
              <input
                type="checkbox"
                checked={enableSysProxy}
                onChange={(e) => setEnableSysProxy(e.target.checked)}
                className="rounded border-slate-700 bg-slate-900 accent-cyan-500"
              />
              连接时自动设置系统代理
            </label>
            <button
              onClick={() => setImportOpen(true)}
              className="flex items-center gap-1.5 rounded-lg bg-cyan-500 px-3.5 py-2 text-xs font-semibold text-slate-950 shadow-sm hover:bg-cyan-400"
            >
              <Plus className="h-4 w-4" /> 导入链接 / .conf
            </button>
          </div>
        </header>

        {/* Tab body */}
        <div className="flex-1 overflow-y-auto p-6">
          {tab === "nodes" && (
            <div className="space-y-4">
              {metadataNodes.length > 0 && (
                <div className="flex flex-wrap items-center gap-2 rounded-xl border border-slate-800 bg-slate-900/50 px-4 py-2.5 text-xs text-slate-300">
                  <Activity className="h-4 w-4 text-cyan-400" />
                  {metadataNodes.map((m) => (
                    <span
                      key={m.id}
                      className="rounded-md bg-slate-800 px-2.5 py-1 font-mono text-[11px] text-slate-200"
                    >
                      {m.name}
                    </span>
                  ))}
                </div>
              )}

              {proxyNodes.length === 0 ? (
                <div className="flex flex-col items-center justify-center rounded-2xl border border-dashed border-slate-800 py-20 text-center">
                  <Shield className="mb-3 h-10 w-10 text-slate-600" />
                  <p className="text-sm font-medium text-slate-300">尚未导入任何代理节点</p>
                  <p className="mt-1 text-xs text-slate-500">
                    支持 Shadowrocket 单条分享链（trojan / anytls / hy2 / tuic / vless / vmess / ss）、.conf 配置文件与 HTTP 订阅
                  </p>
                  <button
                    onClick={() => setImportOpen(true)}
                    className="mt-4 rounded-lg bg-slate-800 px-4 py-2 text-xs font-medium text-cyan-300 hover:bg-slate-700"
                  >
                    立即导入并执行安全审计
                  </button>
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
                  {proxyNodes.map((node) => {
                    const badge = tlsBadge(node);
                    const BadgeIcon = badge.icon;
                    const isActive = status.running && status.active_node_id === node.id;
                    return (
                      <div
                        key={node.id}
                        className={`flex flex-col justify-between rounded-xl border p-4 transition ${
                          isActive
                            ? "border-emerald-500/50 bg-emerald-950/20"
                            : "border-slate-800 bg-slate-900/50 hover:border-slate-700"
                        }`}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-cyan-300">
                                {protocolLabel(node.protocol.type)}
                              </span>
                              <h3 className="truncate text-sm font-semibold text-white">
                                {node.name}
                              </h3>
                            </div>
                            <div className="mt-1.5 truncate font-mono text-xs text-slate-400">
                              {node.dial_override_server ?? node.server}:{node.server_port}
                              {node.tls.server_name && (
                                <span className="ml-2 text-slate-500">
                                  SNI: {node.tls.server_name}
                                </span>
                              )}
                            </div>
                          </div>

                          <span
                            className={`inline-flex shrink-0 items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium ${badge.cls}`}
                          >
                            <BadgeIcon className="h-3 w-3" />
                            {badge.label}
                          </span>
                        </div>

                        <div className="mt-4 flex items-center justify-end gap-2">
                          {node.tls.enabled && (
                            <button
                              onClick={() => handleProbeNode(node)}
                              className="flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800/80 px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:border-cyan-500/50 hover:text-cyan-300"
                            >
                              <KeyRound className="h-3.5 w-3.5" /> 探测 & 固定证书
                            </button>
                          )}
                          <button
                            onClick={() => (isActive ? handleStopProxy() : handleStartNode(node))}
                            className={`flex items-center gap-1 rounded-lg px-3 py-1.5 text-xs font-semibold ${
                              isActive
                                ? "bg-rose-500/20 text-rose-300 hover:bg-rose-500/30"
                                : "bg-cyan-500/15 text-cyan-300 ring-1 ring-cyan-500/30 hover:bg-cyan-500/25"
                            }`}
                          >
                            <Power className="h-3.5 w-3.5" />
                            {isActive ? "断开" : "连接"}
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {tab === "security" && (
            <div className="space-y-6">
              <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-sm font-semibold text-white">
                      隔离的 `[Host]` 域名映射审计（默认全部禁用）
                    </h2>
                    <p className="mt-1 text-xs text-slate-400">
                      仅当节点依赖 `use-local-host-item-for-proxy` 别名连接时建议放行「代理节点别名」；第三方域名覆盖默认严禁放行。
                    </p>
                  </div>
                  {profile && (
                    <button
                      onClick={async () => {
                        await api.deleteProfile(profile.id);
                        setSelectedProfileId(null);
                        await refreshAll();
                      }}
                      className="flex items-center gap-1 rounded-lg bg-rose-500/15 px-3 py-1.5 text-xs text-rose-300 hover:bg-rose-500/25"
                    >
                      <Trash2 className="h-3.5 w-3.5" /> 删除当前配置
                    </button>
                  )}
                </div>

                <div className="mt-4 space-y-2">
                  {(profile?.hosts ?? []).length === 0 ? (
                    <div className="text-xs text-slate-500">当前配置无 `[Host]` 映射条目。</div>
                  ) : (
                    profile!.hosts.map((h, idx) => (
                      <div
                        key={`${h.domain}-${idx}`}
                        className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/70 px-3.5 py-2.5 text-xs"
                      >
                        <div>
                          <span className="font-mono text-slate-200">
                            {h.domain} → {h.target}
                          </span>
                          <span
                            className={`ml-2 rounded px-1.5 py-0.5 text-[10px] font-semibold ${
                              h.classification === "proxy_endpoint_alias"
                                ? "bg-amber-500/15 text-amber-300"
                                : h.classification === "local_domain"
                                ? "bg-slate-800 text-slate-300"
                                : "bg-rose-500/15 text-rose-300"
                            }`}
                          >
                            {h.classification === "proxy_endpoint_alias"
                              ? "代理节点别名"
                              : h.classification === "local_domain"
                              ? "本地域名"
                              : "高危第三方覆盖"}
                          </span>
                        </div>
                        <input
                          type="checkbox"
                          checked={h.approved}
                          onChange={async (e) => {
                            const updated = profile!.hosts.map((item, i) =>
                              i === idx ? { ...item, approved: e.target.checked } : item
                            );
                            const next = await api.updateProfileHosts(profile!.id, updated);
                            setProfile(next);
                          }}
                          className="h-4 w-4 accent-cyan-500"
                        />
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          )}

          {tab === "logs" && (
            <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 font-mono text-xs text-slate-300">
              {logs.length === 0 ? (
                <div className="text-slate-500">暂无运行日志（连接节点后实时展示，敏感口令自动脱敏）。</div>
              ) : (
                logs.map((line, i) => (
                  <div
                    key={i}
                    className={`border-b border-slate-900 py-1 ${
                      line.includes("unrecognized remote public key")
                        ? "bg-rose-950/70 text-rose-300"
                        : ""
                    }`}
                  >
                    {line}
                  </div>
                ))
              )}
            </div>
          )}

          {tab === "settings" && (
            <div className="max-w-2xl space-y-5 rounded-xl border border-slate-800 bg-slate-900/50 p-6">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-medium text-slate-400">本地 Mixed 代理端口 (127.0.0.1)</label>
                  <input
                    type="number"
                    value={policy.mixed_listen_port}
                    onChange={(e) =>
                      setPolicy({ ...policy, mixed_listen_port: Number(e.target.value) })
                    }
                    className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
                  />
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-400">本地 Clash API 端口 (强制随机 Bearer Secret)</label>
                  <input
                    type="number"
                    value={policy.clash_api_port}
                    onChange={(e) =>
                      setPolicy({ ...policy, clash_api_port: Number(e.target.value) })
                    }
                    className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
                  />
                </div>
              </div>

              <div>
                <label className="text-xs font-medium text-slate-400">直连场景 IPv6 防旁路泄漏策略</label>
                <select
                  value={policy.ipv6_mode}
                  onChange={(e) =>
                    setPolicy({
                      ...policy,
                      ipv6_mode: e.target.value as RuntimePolicy["ipv6_mode"],
                    })
                  }
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
                >
                  <option value="block_to_prevent_leak">
                    屏蔽 IPv6 / AAAA 防泄漏（推荐：IPv4 直连节点零旁路）
                  </option>
                  <option value="prefer_ipv4">优先 IPv4，允许双栈代理</option>
                  <option value="dual_stack">完整双栈 IPv4 + IPv6</option>
                </select>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-medium text-slate-400">远端 DoH DNS（强制 detour=proxy）</label>
                  <input
                    value={policy.remote_dns_server}
                    onChange={(e) => setPolicy({ ...policy, remote_dns_server: e.target.value })}
                    className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
                  />
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-400">直连 / 节点域名 Bootstrap DNS</label>
                  <input
                    value={policy.direct_dns_server}
                    onChange={(e) => setPolicy({ ...policy, direct_dns_server: e.target.value })}
                    className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
                  />
                </div>
              </div>

              <div className="flex items-center justify-between pt-2">
                <span className="text-xs text-slate-500">
                  所有外部配置无法覆盖此处端口、API 鉴权与防泄漏策略。
                </span>
                <button
                  onClick={handleSavePolicy}
                  className="rounded-lg bg-cyan-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-400"
                >
                  保存策略
                </button>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Import & Security Quarantine Modal */}
      {importOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="flex max-h-[90vh] w-full max-w-2xl flex-col overflow-hidden rounded-2xl border border-slate-800 bg-slate-900 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
              <div className="flex items-center gap-2">
                <FileWarning className="h-5 w-5 text-cyan-400" />
                <h2 className="text-sm font-semibold text-white">
                  安全导入（自动识别分享链 / Shadowrocket .conf / Clash / sing-box）
                </h2>
              </div>
              <button onClick={() => setImportOpen(false)} className="text-slate-400 hover:text-white">
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="flex-1 space-y-4 overflow-y-auto p-5">
              <div>
                <label className="text-xs text-slate-400">配置名称</label>
                <input
                  value={importName}
                  onChange={(e) => setImportName(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
                />
              </div>

              <div>
                <label className="text-xs text-slate-400">
                  粘贴分享链（可多行）、Base64 订阅内容或 `.conf` 全文
                </label>
                <textarea
                  rows={6}
                  value={importText}
                  onChange={(e) => {
                    setImportText(e.target.value);
                    setPreview(null);
                  }}
                  placeholder="trojan://... / anytls://... / hy2://... / [General]..."
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 p-3 font-mono text-xs text-slate-200 outline-none focus:border-cyan-500"
                />
              </div>

              {preview && (
                <div className="space-y-3 rounded-xl border border-slate-800 bg-slate-950/80 p-4">
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <span className="rounded bg-cyan-500/15 px-2 py-0.5 text-cyan-300">
                      格式: {preview.format}
                    </span>
                    <span className="rounded bg-slate-800 px-2 py-0.5 text-slate-200">
                      节点: {preview.report.total_nodes_imported}
                    </span>
                    <span className="rounded bg-slate-800 px-2 py-0.5 text-slate-200">
                      规则: {preview.report.total_rules_imported}
                    </span>
                    {preview.report.stripped_sections.length > 0 && (
                      <span className="rounded bg-rose-500/20 px-2 py-0.5 text-rose-300">
                        已硬剥离: {preview.report.stripped_sections.join(", ")}
                      </span>
                    )}
                  </div>

                  {preview.report.findings.map((f, idx) => (
                    <div
                      key={idx}
                      className={`rounded-lg border p-3 text-xs ${
                        f.severity === "critical" || f.severity === "high"
                          ? "border-rose-500/40 bg-rose-950/30 text-rose-200"
                          : "border-amber-500/30 bg-amber-950/20 text-amber-200"
                      }`}
                    >
                      <div className="font-semibold">
                        [{f.severity.toUpperCase()} · {f.action.toUpperCase()}] {f.summary}
                      </div>
                      {f.samples.length > 0 && (
                        <div className="mt-1 font-mono text-[11px] opacity-80">
                          {f.samples.slice(0, 3).join(" | ")}
                        </div>
                      )}
                    </div>
                  ))}

                  {preview.hosts.length > 0 && (
                    <div className="space-y-1.5 pt-1">
                      <div className="text-xs font-semibold text-slate-300">
                        勾选需要放行的 `[Host]` 映射（默认全部隔离）：
                      </div>
                      {preview.hosts.map((h) => (
                        <label
                          key={h.domain}
                          className="flex cursor-pointer items-center justify-between rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2 text-xs"
                        >
                          <span className="font-mono">
                            {h.domain} → {h.target}{" "}
                            <span className="text-amber-300">({h.classification})</span>
                          </span>
                          <input
                            type="checkbox"
                            checked={approvedHostDomains.has(h.domain)}
                            onChange={(e) => {
                              const next = new Set(approvedHostDomains);
                              if (e.target.checked) next.add(h.domain);
                              else next.delete(h.domain);
                              setApprovedHostDomains(next);
                            }}
                            className="accent-cyan-500"
                          />
                        </label>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="flex items-center justify-end gap-2 border-t border-slate-800 px-5 py-3">
              <button
                onClick={handlePreviewImport}
                disabled={busy || !importText.trim()}
                className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-xs font-medium text-slate-200 hover:bg-slate-700 disabled:opacity-50"
              >
                1. 安全扫描与预览
              </button>
              <button
                onClick={handleCommitImport}
                disabled={busy || !preview}
                className="rounded-lg bg-cyan-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-40"
              >
                2. 确认导入到 MaxQ
              </button>
            </div>
          </div>
        </div>
      )}

      {/* TLS TOFU Probe & Pin Inspector Drawer */}
      {inspectNode && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs">
          <div className="flex h-full w-full max-w-lg flex-col border-l border-slate-800 bg-slate-900 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
              <div>
                <h2 className="text-sm font-semibold text-white">TLS 证书探测与 TOFU 公钥固定</h2>
                <p className="text-xs text-slate-400">{inspectNode.name}</p>
              </div>
              <button onClick={() => setInspectNode(null)} className="text-slate-400 hover:text-white">
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="flex-1 space-y-4 overflow-y-auto p-5 text-xs">
              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 space-y-1.5">
                <div>
                  <span className="text-slate-400">目标地址：</span>
                  <span className="font-mono text-slate-200">
                    {inspectNode.dial_override_server ?? inspectNode.server}:{inspectNode.server_port}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400">TLS SNI：</span>
                  <span className="font-mono text-slate-200">
                    {inspectNode.tls.server_name ?? inspectNode.server}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400">探测引擎：</span>
                  <span className="text-cyan-300">
                    纯 Rust rustls / quinn（绕过 Windows Schannel，支持自签与 Hysteria2 Salamander）
                  </span>
                </div>
              </div>

              <button
                onClick={() => handleProbeNode(inspectNode)}
                disabled={probeLoading}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-500 px-4 py-2.5 text-xs font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-50"
              >
                <RefreshCw className={`h-4 w-4 ${probeLoading ? "animate-spin" : ""}`} />
                {probeLoading ? "正在握手并提取服务端证书..." : "立即探测服务端证书指纹"}
              </button>

              {probeError && (
                <div className="rounded-xl border border-rose-500/40 bg-rose-950/40 p-3 text-rose-200">
                  <strong>探测或校验失败：</strong> {probeError}
                </div>
              )}

              {probeResult && (
                <div className="space-y-3 rounded-xl border border-slate-800 bg-slate-950/80 p-4">
                  {probeResult.outcome.status === "mismatch" && (
                    <div className="rounded-lg border border-rose-500 bg-rose-950/70 p-3 text-rose-100">
                      <div className="flex items-center gap-1.5 font-bold text-rose-300">
                        <ShieldAlert className="h-4 w-4" /> 警告：证书公钥指纹发生变更（疑似 MITM）！
                      </div>
                      <div className="mt-2 font-mono text-[11px] break-all">
                        <div>预期 SPKI: {probeResult.outcome.expected_spki_b64}</div>
                        <div className="text-rose-300">
                          实测 SPKI: {probeResult.outcome.observed_spki_b64}
                        </div>
                      </div>
                    </div>
                  )}

                  {probeResult.outcome.status === "matched" && (
                    <div className="flex items-center gap-2 rounded-lg bg-emerald-500/15 p-2.5 text-emerald-300">
                      <CheckCircle2 className="h-4 w-4" /> 指纹与已有记录/导入 pin 完全一致！
                    </div>
                  )}

                  <div className="space-y-1.5 font-mono text-[11px] break-all">
                    <div>
                      <span className="text-slate-400">SPKI SHA-256 (Base64 · sing-box): </span>
                      <span className="text-emerald-300">{probeResult.probed.spki_sha256_b64}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Cert SHA-256 (Hex · pcs/hy2): </span>
                      <span className="text-slate-200">{probeResult.probed.cert_sha256_hex}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Subject: </span>
                      <span>{probeResult.probed.subject}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Issuer: </span>
                      <span>{probeResult.probed.issuer}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">有效期: </span>
                      <span>
                        {probeResult.probed.not_before} ~ {probeResult.probed.not_after}
                      </span>
                    </div>
                  </div>

                  <button
                    onClick={handleConfirmPin}
                    className="flex w-full items-center justify-center gap-1.5 rounded-lg bg-emerald-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-emerald-400"
                  >
                    <ShieldCheck className="h-4 w-4" />
                    {probeResult.outcome.status === "mismatch"
                      ? "确认风险并轮换固定为此新公钥"
                      : "信任并固定此证书公钥 (TOFU Pin)"}
                  </button>
                </div>
              )}

              {inspectNode.tls.verify_mode.mode === "insecure_legacy" && (
                <div className="rounded-xl border border-amber-500/30 bg-amber-950/20 p-4">
                  <div className="font-semibold text-amber-300">
                    Scheme A 默认安全策略提示
                  </div>
                  <p className="mt-1 text-slate-400">
                    强烈建议使用上方「探测并固定证书」消除中间人风险。仅在临时调试且明确知晓风险时，可开启单节点临时不安全放行：
                  </p>
                  <label className="mt-3 flex cursor-pointer items-center gap-2 text-amber-200">
                    <input
                      type="checkbox"
                      checked={inspectNode.tls.verify_mode.user_confirmed_override}
                      onChange={(e) =>
                        handleToggleInsecureOverride(inspectNode, e.target.checked)
                      }
                      className="accent-amber-500"
                    />
                    我已知晓 MITM 风险，临时允许此节点跳过证书验证
                  </label>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
