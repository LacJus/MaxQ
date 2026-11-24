import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Cpu,
  Download,
  FileText,
  Gauge,
  Globe,
  KeyRound,
  Link2,
  Lock,
  Network,
  Plus,
  Power,
  RefreshCw,
  Search,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Trash2,
  Upload,
  X,
} from "lucide-react";
import { api, isTauriRuntime } from "./api";
import type {
  BatchPinSummary,
  BuiltinRulesInfo,
  NodeConfig,
  ProbeNodeResult,
  ProfileSummary,
  ProxyMode,
  RoutingMode,
  RuntimePolicy,
  RuntimeStatus,
  SanitizedImport,
  StoredProfile,
  TunServiceStatus,
} from "./types";

type Tab = "nodes" | "security" | "logs" | "settings";
type ImportMethod = "paste" | "file" | "url";

const PROTOCOL_FILTERS: Array<{ id: string; label: string }> = [
  { id: "all", label: "全部" },
  { id: "trojan", label: "Trojan" },
  { id: "any_tls", label: "AnyTLS" },
  { id: "hysteria2", label: "Hysteria2" },
  { id: "tuic", label: "TUIC" },
  { id: "vless", label: "VLESS" },
  { id: "vmess", label: "VMess" },
  { id: "shadowsocks", label: "SS" },
];

function protocolLabel(p: NodeConfig["protocol"]["type"]): string {
  switch (p) {
    case "any_tls":
      return "AnyTLS";
    case "hysteria2":
      return "Hy2";
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
      label: "明文/无 TLS",
      cls: "bg-slate-800/90 text-slate-400",
      icon: Globe,
    };
  }
  switch (node.tls.verify_mode.mode) {
    case "pinned_spki":
      return {
        label: "SPKI 已固定",
        cls: "bg-emerald-500/12 text-emerald-300",
        icon: ShieldCheck,
      };
    case "system_ca":
      return {
        label: "CA 校验",
        cls: "bg-sky-500/12 text-sky-300",
        icon: Lock,
      };
    case "pending_pin_bootstrap":
      return {
        label: "待核验 pcs",
        cls: "bg-amber-500/15 text-amber-300",
        icon: KeyRound,
      };
    case "insecure_legacy":
      return node.tls.verify_mode.user_confirmed_override
        ? {
            label: "临时放行",
            cls: "bg-orange-500/15 text-orange-300",
            icon: AlertTriangle,
          }
        : {
            label: "未验证 (已阻断)",
            cls: "bg-rose-500/15 text-rose-300",
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
  const [builtinRules, setBuiltinRules] = useState<BuiltinRulesInfo>({
    rule_count: 8581,
    description: "MaxQ 内置默认分流规则",
  });
  const [tunService, setTunService] = useState<TunServiceStatus>({
    installed: false,
    running: false,
    tun_active: false,
    singbox_sha256_verified: false,
  });
  const [status, setStatus] = useState<RuntimeStatus>({
    running: false,
    system_proxy_enabled: false,
    tun_active: false,
  });
  const [logs, setLogs] = useState<string[]>([]);
  const [policy, setPolicy] = useState<RuntimePolicy>({
    mixed_listen_port: 17890,
    allow_lan: false,
    clash_api_port: 19090,
    clash_api_secret: "",
    clash_api_allowed_origins: ["http://tauri.localhost", "https://tauri.localhost"],
    tun_enabled: false,
    proxy_mode: "system_proxy",
    routing_mode: "rule",
    rule_source: "profile_or_builtin",
    ipv6_mode: "block_to_prevent_leak",
    remote_dns_server: "1.1.1.1",
    direct_dns_server: "223.5.5.5",
  });

  // Search, filter, latency & batch pin state
  const [searchQuery, setSearchQuery] = useState("");
  const [protoFilter, setProtoFilter] = useState("all");
  const [latencies, setLatencies] = useState<Record<string, number | "err" | "loading">>({});
  const [batchPinning, setBatchPinning] = useState(false);
  const [toast, setToast] = useState<{ kind: "info" | "ok" | "err"; text: string } | null>(null);

  // Import modal state
  const [importOpen, setImportOpen] = useState(false);
  const [importMethod, setImportMethod] = useState<ImportMethod>("paste");
  const [importName, setImportName] = useState("新导入配置");
  const [importText, setImportText] = useState("");
  const [subUrl, setSubUrl] = useState("");
  const [preview, setPreview] = useState<SanitizedImport | null>(null);
  const [approvedHostDomains, setApprovedHostDomains] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);

  // TLS TOFU Probe Drawer state
  const [inspectNode, setInspectNode] = useState<NodeConfig | null>(null);
  const [probeResult, setProbeResult] = useState<ProbeNodeResult | null>(null);
  const [probeLoading, setProbeLoading] = useState(false);
  const [probeError, setProbeError] = useState<string | null>(null);

  const showToast = (kind: "info" | "ok" | "err", text: string) => {
    setToast({ kind, text });
  };

  const refreshAll = async () => {
    if (!inTauri) return;
    try {
      const [list, st, pol, l, br, tunSt] = await Promise.all([
        api.listProfiles(),
        api.getRuntimeStatus(),
        api.getRuntimePolicy(),
        api.getRuntimeLogs(),
        api.getBuiltinRulesInfo(),
        api.getTunServiceStatus(),
      ]);
      setProfiles(list);
      setStatus(st);
      setPolicy(pol);
      setLogs(l);
      setBuiltinRules(br);
      setTunService(tunSt);

      const targetId = selectedProfileId ?? list[0]?.id ?? null;
      if (targetId) {
        setSelectedProfileId(targetId);
        const full = await api.getProfile(targetId);
        setProfile(full);
      } else {
        setProfile(null);
      }
    } catch (err) {
      showToast("err", String(err));
    }
  };

  useEffect(() => {
    refreshAll();
    if (!inTauri) return;
    const timer = setInterval(async () => {
      try {
        const [st, l, tunSt] = await Promise.all([
          api.getRuntimeStatus(),
          api.getRuntimeLogs(),
          api.getTunServiceStatus(),
        ]);
        setStatus(st);
        setLogs(l);
        setTunService(tunSt);
      } catch {
        // ignore transient polling error
      }
    }, 2500);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedProfileId]);

  const { metadataNodes, proxyNodes, unverifiedCount } = useMemo(() => {
    const all = profile?.nodes ?? [];
    const meta = all.filter((n) => n.is_metadata_node);
    const real = all.filter((n) => !n.is_metadata_node);
    const unverified = real.filter(
      (n) =>
        n.tls.enabled &&
        (n.tls.verify_mode.mode === "insecure_legacy" ||
          n.tls.verify_mode.mode === "pending_pin_bootstrap")
    ).length;
    return { metadataNodes: meta, proxyNodes: real, unverifiedCount: unverified };
  }, [profile]);

  const filteredNodes = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return proxyNodes.filter((n) => {
      if (protoFilter !== "all" && n.protocol.type !== protoFilter) return false;
      if (!q) return true;
      return (
        n.name.toLowerCase().includes(q) ||
        n.server.toLowerCase().includes(q) ||
        (n.tls.server_name ?? "").toLowerCase().includes(q)
      );
    });
  }, [proxyNodes, protoFilter, searchQuery]);

  const applyPolicyChange = async (patch: Partial<RuntimePolicy>, reconnectIfRunning = true) => {
    const nextPolicy: RuntimePolicy = { ...policy, ...patch };
    setPolicy(nextPolicy);
    if (!inTauri) return;
    try {
      const saved = await api.updateRuntimePolicy(nextPolicy);
      setPolicy(saved);
      if (reconnectIfRunning && status.running && profile && status.active_node_id) {
        const st = await api.startProxy(
          profile.id,
          status.active_node_id,
          saved.proxy_mode === "system_proxy"
        );
        setStatus(st);
        showToast("ok", "策略已热更新并重新应用到运行中内核");
      }
    } catch (err) {
      showToast("err", String(err));
    }
  };

  const handleSwitchProxyMode = async (mode: ProxyMode) => {
    if (mode === "tun" && inTauri && !tunService.running) {
      showToast(
        "info",
        "TUN 模式需要先安装 MaxQ 安全加固 Windows 服务（点击右侧「安装 TUN 服务」按钮触发 UAC）"
      );
      setTab("security");
      return;
    }
    await applyPolicyChange({ proxy_mode: mode, tun_enabled: mode === "tun" }, true);
  };

  const handleInstallTunService = async () => {
    try {
      const msg = await api.installTunService();
      showToast("info", msg);
      setTimeout(async () => {
        const st = await api.getTunServiceStatus();
        setTunService(st);
        if (st.running) {
          showToast("ok", "MaxQ 安全加固 TUN 服务已安装并运行（SHA-256 校验通过）");
        }
      }, 2500);
    } catch (err) {
      showToast("err", String(err));
    }
  };

  const handleUninstallTunService = async () => {
    try {
      const msg = await api.uninstallTunService();
      showToast("info", msg);
      await applyPolicyChange({ proxy_mode: "system_proxy", tun_enabled: false }, false);
      setTimeout(async () => {
        setTunService(await api.getTunServiceStatus());
      }, 2000);
    } catch (err) {
      showToast("err", String(err));
    }
  };

  const handleFetchSubUrl = async () => {
    setBusy(true);
    try {
      const body = await api.fetchSubscriptionUrl(subUrl);
      setImportText(body);
      const res = await api.previewImport(body);
      setPreview(res);
      setApprovedHostDomains(new Set());
      showToast("ok", `订阅拉取成功，已识别 ${res.report.total_nodes_imported} 个节点`);
    } catch (err) {
      showToast("err", String(err));
    } finally {
      setBusy(false);
    }
  };

  const handlePreviewImport = async () => {
    setBusy(true);
    try {
      const res = await api.previewImport(importText);
      setPreview(res);
      setApprovedHostDomains(new Set());
    } catch (err) {
      showToast("err", String(err));
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
      setSubUrl("");
      setPreview(null);
      setSelectedProfileId(newId);
      await refreshAll();
      showToast("ok", "配置已安全导入至本地 SQLite 信任库");
    } catch (err) {
      showToast("err", String(err));
    } finally {
      setBusy(false);
    }
  };

  const handleStartNode = async (node: NodeConfig) => {
    if (!profile) return;
    try {
      const st = await api.startProxy(
        profile.id,
        node.id,
        policy.proxy_mode === "system_proxy"
      );
      setStatus(st);
      showToast(
        "ok",
        `已通过 ${st.tun_active ? "TUN 虚拟网卡" : "系统代理"} 连接 ${node.name}`
      );
    } catch (err) {
      const msg = String(err);
      showToast("err", msg);
      if (msg.includes("Scheme A") || msg.includes("PendingPinBootstrap")) {
        setInspectNode(node);
        setProbeResult(null);
        setProbeError(null);
      }
    }
  };

  const handleStopProxy = async () => {
    try {
      const st = await api.stopProxy();
      setStatus(st);
      showToast("info", "已断开连接并恢复网络设置");
    } catch (err) {
      showToast("err", String(err));
    }
  };

  const handleBatchProbeAndPin = async () => {
    if (!profile) return;
    setBatchPinning(true);
    try {
      const summary: BatchPinSummary = await api.batchProbeAndPinProfile(profile.id);
      await refreshAll();
      showToast(
        summary.failed_nodes === 0 ? "ok" : "info",
        `去重探测 ${summary.probed_endpoints} 个入口，成功固定 ${summary.pinned_nodes} 个节点${
          summary.failed_nodes > 0 ? `，失败 ${summary.failed_nodes} 个` : ""
        }`
      );
    } catch (err) {
      showToast("err", String(err));
    } finally {
      setBatchPinning(false);
    }
  };

  const handleTestLatency = async (node: NodeConfig) => {
    setLatencies((prev) => ({ ...prev, [node.id]: "loading" }));
    try {
      const ms = await api.testNodeLatency(node.id);
      setLatencies((prev) => ({ ...prev, [node.id]: ms }));
    } catch {
      setLatencies((prev) => ({ ...prev, [node.id]: "err" }));
    }
  };

  const handleTestAllLatencies = async () => {
    const batch = filteredNodes.slice(0, 20);
    await Promise.all(batch.map((n) => handleTestLatency(n)));
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
      showToast("ok", `已固定 ${updated.name} 的公钥 SPKI 指纹`);
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

  const activeRuleCountLabel =
    policy.routing_mode === "global"
      ? "全局代理"
      : policy.routing_mode === "direct"
      ? "全局直连"
      : policy.rule_source === "builtin_default" || (profile?.rules.length ?? 0) === 0
      ? `内置 ${builtinRules.rule_count.toLocaleString()} 条分流`
      : `配置 ${profile?.rules.length.toLocaleString()} 条分流`;

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#090c10] text-slate-100">
      {/* Left Navigation Rail */}
      <aside className="mq-panel flex w-60 shrink-0 flex-col border-y-0 border-l-0 p-4">
        <div className="mb-6 flex items-center gap-3 px-1.5">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-sky-500/15 text-sky-400 ring-1 ring-sky-400/25">
            <Shield className="h-5 w-5" />
          </div>
          <div>
            <div className="text-[15px] font-semibold tracking-tight text-white">MaxQ</div>
            <div className="font-mono-tabular text-[11px] text-slate-400">
              v0.2 · sing-box 1.14.4
            </div>
          </div>
        </div>

        <nav className="flex-1 space-y-1">
          {[
            { id: "nodes" as Tab, label: "节点与测速", icon: Server },
            { id: "security" as Tab, label: "TUN 服务与规则", icon: ShieldCheck },
            { id: "logs" as Tab, label: "运行日志", icon: Terminal },
            { id: "settings" as Tab, label: "防泄漏与内核", icon: Settings },
          ].map((item) => {
            const Icon = item.icon;
            const active = tab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setTab(item.id)}
                className={`flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-[13px] font-medium transition ${
                  active
                    ? "bg-[#1a2433] text-white"
                    : "text-slate-400 hover:bg-[#141b26] hover:text-slate-200"
                }`}
              >
                <Icon className={`h-4 w-4 ${active ? "text-sky-400" : "text-slate-500"}`} />
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* Bottom Runtime Status Capsule */}
        <div className="mt-4 rounded-xl border border-slate-800/80 bg-[#0b0f16] p-3.5">
          <div className="flex items-center justify-between text-[11px]">
            <span className="text-slate-400">引擎状态</span>
            <span
              className={`inline-flex items-center gap-1.5 font-medium ${
                status.running ? "text-emerald-400" : "text-slate-500"
              }`}
            >
              <span
                className={`h-1.5 w-1.5 rounded-full ${
                  status.running ? "bg-emerald-400" : "bg-slate-600"
                }`}
              />
              {status.running
                ? status.tun_active
                  ? "TUN 运行中"
                  : "系统代理中"
                : "待机"}
            </span>
          </div>

          <div className="mt-2 truncate text-xs font-medium text-slate-200">
            {status.active_node_name ?? "未选择节点"}
          </div>
          <div className="mt-1 font-mono-tabular text-[11px] text-slate-500">
            {activeRuleCountLabel}
          </div>

          {status.running && (
            <button
              onClick={handleStopProxy}
              className="mt-3 flex w-full items-center justify-center gap-1.5 rounded-lg bg-rose-500/12 px-3 py-1.5 text-xs font-medium text-rose-300 hover:bg-rose-500/20"
            >
              <Power className="h-3.5 w-3.5" /> 断开连接
            </button>
          )}
        </div>
      </aside>

      {/* Main Workspace */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Global MITM Critical Alert */}
        {status.last_mitm_alert && (
          <div className="flex items-center gap-3 border-b border-rose-500/40 bg-rose-950/90 px-6 py-3 text-xs text-rose-100">
            <ShieldAlert className="h-4 w-4 shrink-0 text-rose-400" />
            <span>
              <strong>证书公钥变更 / 疑似 MITM 告警：</strong> 检测到未受信任的远端公钥{" "}
              <code className="font-mono-tabular rounded bg-rose-900/80 px-1.5 py-0.5">
                {status.last_mitm_alert}
              </code>
            </span>
          </div>
        )}

        {/* Toast feedback bar */}
        {toast && (
          <div
            className={`flex items-center justify-between border-b px-6 py-2 text-xs ${
              toast.kind === "err"
                ? "border-rose-500/30 bg-rose-950/40 text-rose-200"
                : toast.kind === "ok"
                ? "border-emerald-500/30 bg-emerald-950/40 text-emerald-200"
                : "border-sky-500/30 bg-sky-950/40 text-sky-200"
            }`}
          >
            <span>{toast.text}</span>
            <button onClick={() => setToast(null)} className="opacity-70 hover:opacity-100">
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        )}

        {/* Unified Top Command Deck */}
        <header className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/70 bg-[#0c1017] px-6 py-3.5">
          <div className="flex flex-wrap items-center gap-2.5">
            {/* Routing Mode Segmented Switch */}
            <div className="flex items-center rounded-lg border border-slate-800 bg-[#090c10] p-0.5 text-xs">
              {(
                [
                  { id: "rule", label: "规则分流" },
                  { id: "global", label: "全局" },
                  { id: "direct", label: "直连" },
                ] as Array<{ id: RoutingMode; label: string }>
              ).map((m) => (
                <button
                  key={m.id}
                  onClick={() => applyPolicyChange({ routing_mode: m.id }, true)}
                  className={`rounded-md px-2.5 py-1 font-medium transition ${
                    policy.routing_mode === m.id
                      ? "bg-[#1c2636] text-white"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {m.label}
                </button>
              ))}
            </div>

            {/* Engine Mode Segmented Switch: System Proxy vs Hardened TUN */}
            <div className="flex items-center rounded-lg border border-slate-800 bg-[#090c10] p-0.5 text-xs">
              <button
                onClick={() => handleSwitchProxyMode("system_proxy")}
                className={`flex items-center gap-1.5 rounded-md px-2.5 py-1 font-medium transition ${
                  policy.proxy_mode === "system_proxy"
                    ? "bg-[#1c2636] text-white"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                <Globe className="h-3.5 w-3.5" /> 系统代理
              </button>
              <button
                onClick={() => handleSwitchProxyMode("tun")}
                className={`flex items-center gap-1.5 rounded-md px-2.5 py-1 font-medium transition ${
                  policy.proxy_mode === "tun"
                    ? "bg-emerald-500/20 text-emerald-300"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                <Network className="h-3.5 w-3.5" /> TUN 模式
                <span
                  className={`h-1.5 w-1.5 rounded-full ${
                    tunService.running ? "bg-emerald-400" : "bg-amber-400"
                  }`}
                />
              </button>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            {!tunService.running && inTauri && (
              <button
                onClick={handleInstallTunService}
                className="flex items-center gap-1.5 rounded-lg border border-slate-700/80 bg-[#151c27] px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-sky-500/40 hover:text-sky-300"
              >
                <Cpu className="h-3.5 w-3.5" /> 安装 TUN 服务 (UAC)
              </button>
            )}
            <button
              onClick={() => setImportOpen(true)}
              className="flex items-center gap-1.5 rounded-lg bg-sky-500 px-3.5 py-1.5 text-xs font-semibold text-slate-950 hover:bg-sky-400"
            >
              <Plus className="h-3.5 w-3.5" /> 导入节点 / 订阅
            </button>
          </div>
        </header>

        {/* Main Content Viewport */}
        <main className="flex-1 overflow-y-auto px-6 py-5">
          {tab === "nodes" && (
            <div className="mx-auto max-w-6xl space-y-4">
              {/* Profile Selector & Metadata Bar */}
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex flex-wrap items-center gap-2.5">
                  {profiles.length > 0 && (
                    <select
                      value={selectedProfileId ?? ""}
                      onChange={(e) => setSelectedProfileId(e.target.value)}
                      className="rounded-lg border border-slate-800 bg-[#111722] px-3 py-1.5 text-xs font-medium text-slate-200 outline-none focus:border-sky-500"
                    >
                      {profiles.map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.name} · {p.node_count} 节点
                        </option>
                      ))}
                    </select>
                  )}

                  {metadataNodes.map((m) => (
                    <span
                      key={m.id}
                      className="font-mono-tabular inline-flex items-center gap-1.5 rounded-md border border-slate-800 bg-[#111722] px-2.5 py-1 text-[11px] text-slate-300"
                    >
                      <Activity className="h-3 w-3 text-sky-400" />
                      {m.name}
                    </span>
                  ))}
                </div>

                {proxyNodes.length > 0 && (
                  <div className="flex items-center gap-2">
                    <button
                      onClick={handleTestAllLatencies}
                      className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-[#111722] px-3 py-1.5 text-xs text-slate-300 hover:border-slate-700 hover:text-white"
                    >
                      <Gauge className="h-3.5 w-3.5" /> 批量测速
                    </button>
                    {unverifiedCount > 0 && (
                      <button
                        onClick={handleBatchProbeAndPin}
                        disabled={batchPinning}
                        className="flex items-center gap-1.5 rounded-lg bg-emerald-500/15 px-3 py-1.5 text-xs font-medium text-emerald-300 hover:bg-emerald-500/25 disabled:opacity-50"
                      >
                        <Sparkles className={`h-3.5 w-3.5 ${batchPinning ? "animate-spin" : ""}`} />
                        {batchPinning
                          ? "并发探测固定中..."
                          : `一键批量探测并固定 (${unverifiedCount})`}
                      </button>
                    )}
                  </div>
                )}
              </div>

              {/* Search & Protocol Filters */}
              {proxyNodes.length > 0 && (
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="relative w-64">
                    <Search className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
                    <input
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="搜索节点名 / 域名 / SNI..."
                      className="w-full rounded-lg border border-slate-800 bg-[#111722] py-1.5 pl-8 pr-3 text-xs text-slate-200 placeholder:text-slate-500 outline-none focus:border-sky-500"
                    />
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5">
                    {PROTOCOL_FILTERS.map((f) => (
                      <button
                        key={f.id}
                        onClick={() => setProtoFilter(f.id)}
                        className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition ${
                          protoFilter === f.id
                            ? "bg-sky-500/20 text-sky-300"
                            : "bg-[#111722] text-slate-400 hover:text-slate-200"
                        }`}
                      >
                        {f.label}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Nodes Grid */}
              {filteredNodes.length === 0 ? (
                <div className="mq-panel flex flex-col items-center justify-center rounded-2xl border-dashed py-20 text-center">
                  <Shield className="mb-3 h-9 w-9 text-slate-600" />
                  <p className="text-sm font-medium text-slate-200">
                    {proxyNodes.length === 0 ? "尚未导入任何节点" : "没有匹配的筛选节点"}
                  </p>
                  <p className="mt-1.5 max-w-md text-xs text-slate-500">
                    导入单条 Shadowrocket 链接（trojan / anytls / hy2 / tuic / vless / vmess / ss）即可自动启用内置{" "}
                    {builtinRules.rule_count.toLocaleString()} 条默认分流规则，无需手写规则文件。
                  </p>
                  <button
                    onClick={() => setImportOpen(true)}
                    className="mt-5 rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400"
                  >
                    立即导入并审计
                  </button>
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
                  {filteredNodes.map((node) => {
                    const badge = tlsBadge(node);
                    const BadgeIcon = badge.icon;
                    const isActive = status.running && status.active_node_id === node.id;
                    const lat = latencies[node.id];

                    return (
                      <div
                        key={node.id}
                        className={`mq-card flex flex-col justify-between rounded-xl p-4 ${
                          isActive ? "!border-emerald-500/45 !bg-emerald-950/15" : ""
                        }`}
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="rounded bg-[#0d121a] px-1.5 py-0.5 font-mono-tabular text-[10px] font-semibold uppercase tracking-wide text-sky-400">
                                {protocolLabel(node.protocol.type)}
                              </span>
                              <h3 className="truncate text-[13px] font-semibold text-white">
                                {node.name}
                              </h3>
                            </div>
                            <div className="font-mono-tabular mt-1.5 truncate text-[11px] text-slate-400">
                              {node.dial_override_server ?? node.server}:{node.server_port}
                              {node.tls.server_name && (
                                <span className="ml-2 text-slate-500">
                                  · {node.tls.server_name}
                                </span>
                              )}
                            </div>
                          </div>

                          <div className="flex shrink-0 items-center gap-1.5">
                            {lat !== undefined && (
                              <span
                                className={`font-mono-tabular rounded-md px-2 py-0.5 text-[11px] ${
                                  lat === "loading"
                                    ? "bg-slate-800 text-slate-400"
                                    : lat === "err"
                                    ? "bg-rose-500/15 text-rose-300"
                                    : lat < 120
                                    ? "bg-emerald-500/15 text-emerald-300"
                                    : "bg-amber-500/15 text-amber-300"
                                }`}
                              >
                                {lat === "loading"
                                  ? "..."
                                  : lat === "err"
                                  ? "超时"
                                  : `${lat} ms`}
                              </span>
                            )}
                            <span
                              className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-medium ${badge.cls}`}
                            >
                              <BadgeIcon className="h-3 w-3" />
                              {badge.label}
                            </span>
                          </div>
                        </div>

                        <div className="mt-4 flex items-center justify-end gap-2">
                          <button
                            onClick={() => handleTestLatency(node)}
                            className="rounded-lg bg-[#0d121a] px-2.5 py-1.5 text-[11px] text-slate-400 hover:text-slate-200"
                          >
                            测速
                          </button>
                          {node.tls.enabled && (
                            <button
                              onClick={() => handleProbeNode(node)}
                              className="flex items-center gap-1 rounded-lg bg-[#0d121a] px-2.5 py-1.5 text-[11px] font-medium text-slate-200 hover:bg-slate-800"
                            >
                              <KeyRound className="h-3 w-3 text-sky-400" /> 探测固定
                            </button>
                          )}
                          <button
                            onClick={() => (isActive ? handleStopProxy() : handleStartNode(node))}
                            className={`flex items-center gap-1 rounded-lg px-3 py-1.5 text-xs font-semibold ${
                              isActive
                                ? "bg-rose-500/20 text-rose-300 hover:bg-rose-500/30"
                                : "bg-sky-500/15 text-sky-300 hover:bg-sky-500/25"
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
            <div className="mx-auto max-w-4xl space-y-5">
              {/* Hardened Windows TUN Service Card */}
              <section className="mq-panel rounded-xl p-5">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <Network className="h-4 w-4 text-sky-400" />
                      <h2 className="text-sm font-semibold text-white">
                        Windows 安全加固 TUN 虚拟网卡服务（防 LPE 架构）
                      </h2>
                      <span
                        className={`rounded-md px-2 py-0.5 text-[11px] font-medium ${
                          tunService.running
                            ? "bg-emerald-500/15 text-emerald-300"
                            : "bg-slate-800 text-slate-400"
                        }`}
                      >
                        {tunService.running ? "服务运行中" : "未安装 / 未运行"}
                      </span>
                    </div>
                    <p className="mt-1.5 text-xs text-slate-400">
                      GUI 始终以普通用户运行；仅 TUN 服务按需提权。采用 SDDL DACL 锁定 Named Pipe、调用方进程路径白名单校验、
                      `sing-box.exe` 硬编码路径与 SHA-256 完整性核验、以及 SYSTEM 独占运行目录防 `wintun.dll` 劫持。
                    </p>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={async () => setTunService(await api.getTunServiceStatus())}
                      className="rounded-lg border border-slate-700 bg-[#151c27] px-3 py-1.5 text-xs text-slate-300 hover:text-white"
                    >
                      刷新
                    </button>
                    {!tunService.running ? (
                      <button
                        onClick={handleInstallTunService}
                        className="rounded-lg bg-sky-500 px-3.5 py-1.5 text-xs font-semibold text-slate-950 hover:bg-sky-400"
                      >
                        安装并启动 TUN 服务 (UAC)
                      </button>
                    ) : (
                      <button
                        onClick={handleUninstallTunService}
                        className="rounded-lg bg-rose-500/15 px-3.5 py-1.5 text-xs font-medium text-rose-300 hover:bg-rose-500/25"
                      >
                        卸载 TUN 服务 (UAC)
                      </button>
                    )}
                  </div>
                </div>

                <div className="mt-4 grid grid-cols-2 gap-3 text-xs sm:grid-cols-4">
                  {[
                    {
                      label: "Named Pipe ACL",
                      val: "SDDL + 禁远程",
                      ok: true,
                    },
                    {
                      label: "调用方进程校验",
                      val: "安装目录白名单",
                      ok: true,
                    },
                    {
                      label: "sing-box SHA-256",
                      val: tunService.running
                        ? tunService.singbox_sha256_verified
                          ? "已核验通过"
                          : "校验异常"
                        : "启动前强制核验",
                      ok: !tunService.running || tunService.singbox_sha256_verified,
                    },
                    {
                      label: "wintun 防劫持",
                      val: "SYSTEM 独占目录",
                      ok: true,
                    },
                  ].map((item) => (
                    <div
                      key={item.label}
                      className="rounded-lg border border-slate-800/80 bg-[#0b0f16] px-3 py-2.5"
                    >
                      <div className="text-[11px] text-slate-500">{item.label}</div>
                      <div
                        className={`mt-1 font-medium ${
                          item.ok ? "text-emerald-300" : "text-rose-300"
                        }`}
                      >
                        {item.val}
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              {/* Built-in Default Rules Engine Card */}
              <section className="mq-panel rounded-xl p-5">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h2 className="text-sm font-semibold text-white">
                      默认内置分流规则库（{builtinRules.rule_count.toLocaleString()} 条规则）
                    </h2>
                    <p className="mt-1 text-xs text-slate-400">
                      {builtinRules.description}。导入单条分享链时自动生效，国内流量直连、海外走代理。
                    </p>
                  </div>

                  <select
                    value={policy.rule_source}
                    onChange={(e) =>
                      applyPolicyChange(
                        { rule_source: e.target.value as RuntimePolicy["rule_source"] },
                        true
                      )
                    }
                    className="rounded-lg border border-slate-700 bg-[#0b0f16] px-3 py-1.5 text-xs text-slate-200"
                  >
                    <option value="profile_or_builtin">
                      优先使用导入 .conf 规则（无规则时自动用内置规则）
                    </option>
                    <option value="builtin_default">
                      始终强制使用 MaxQ 内置默认规则
                    </option>
                  </select>
                </div>
              </section>

              {/* Quarantined [Host] Audit Card */}
              <section className="mq-panel rounded-xl p-5">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-sm font-semibold text-white">
                      `[Host]` 域名映射隔离审计（默认全禁用）
                    </h2>
                    <p className="mt-1 text-xs text-slate-400">
                      仅放行确认为节点入口别名的 `proxy_endpoint_alias`；第三方域名覆盖默认阻断以防劫持。
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
                        className="flex items-center justify-between rounded-lg border border-slate-800/80 bg-[#0b0f16] px-3.5 py-2.5 text-xs"
                      >
                        <div>
                          <span className="font-mono-tabular text-slate-200">
                            {h.domain} → {h.target}
                          </span>
                          <span
                            className={`ml-2 rounded px-1.5 py-0.5 text-[10px] font-medium ${
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
                          className="h-4 w-4 accent-sky-500"
                        />
                      </div>
                    ))
                  )}
                </div>
              </section>
            </div>
          )}

          {tab === "logs" && (
            <div className="mx-auto max-w-6xl rounded-xl border border-slate-800 bg-[#0b0f16] p-4 font-mono-tabular text-xs text-slate-300">
              {logs.length === 0 ? (
                <div className="py-12 text-center text-slate-500">
                  暂无运行日志（连接节点后自动流式输出，敏感口令自动脱敏）。
                </div>
              ) : (
                logs.map((line, i) => (
                  <div
                    key={i}
                    className={`border-b border-slate-900/80 py-1 ${
                      line.includes("unrecognized remote public key")
                        ? "bg-rose-950/60 text-rose-300"
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
            <div className="mq-panel mx-auto max-w-2xl space-y-5 rounded-xl p-6">
              <div>
                <h2 className="text-sm font-semibold text-white">直连防泄漏与本地端口策略</h2>
                <p className="mt-1 text-xs text-slate-400">
                  外部 `.conf` 与订阅无法覆盖以下任何安全边界设置。
                </p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-xs text-slate-400">Mixed 代理端口 (127.0.0.1)</label>
                  <input
                    type="number"
                    value={policy.mixed_listen_port}
                    onChange={(e) =>
                      setPolicy({ ...policy, mixed_listen_port: Number(e.target.value) })
                    }
                    className="font-mono-tabular mt-1 w-full rounded-lg border border-slate-800 bg-[#090c10] px-3 py-2 text-sm text-white"
                  />
                </div>
                <div>
                  <label className="text-xs text-slate-400">Clash API 端口 (随机 32B Bearer)</label>
                  <input
                    type="number"
                    value={policy.clash_api_port}
                    onChange={(e) =>
                      setPolicy({ ...policy, clash_api_port: Number(e.target.value) })
                    }
                    className="font-mono-tabular mt-1 w-full rounded-lg border border-slate-800 bg-[#090c10] px-3 py-2 text-sm text-white"
                  />
                </div>
              </div>

              <div>
                <label className="text-xs text-slate-400">IPv6 防旁路泄漏策略</label>
                <select
                  value={policy.ipv6_mode}
                  onChange={(e) =>
                    setPolicy({
                      ...policy,
                      ipv6_mode: e.target.value as RuntimePolicy["ipv6_mode"],
                    })
                  }
                  className="mt-1 w-full rounded-lg border border-slate-800 bg-[#090c10] px-3 py-2 text-sm text-white"
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
                  <label className="text-xs text-slate-400">远端 DoH DNS（强制 detour=proxy）</label>
                  <input
                    value={policy.remote_dns_server}
                    onChange={(e) => setPolicy({ ...policy, remote_dns_server: e.target.value })}
                    className="font-mono-tabular mt-1 w-full rounded-lg border border-slate-800 bg-[#090c10] px-3 py-2 text-sm text-white"
                  />
                </div>
                <div>
                  <label className="text-xs text-slate-400">直连 / Bootstrap DNS</label>
                  <input
                    value={policy.direct_dns_server}
                    onChange={(e) => setPolicy({ ...policy, direct_dns_server: e.target.value })}
                    className="font-mono-tabular mt-1 w-full rounded-lg border border-slate-800 bg-[#090c10] px-3 py-2 text-sm text-white"
                  />
                </div>
              </div>

              <div className="flex justify-end pt-2">
                <button
                  onClick={() => applyPolicyChange({}, true)}
                  className="rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400"
                >
                  保存并应用策略
                </button>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* Import Modal (Paste / Local .conf / HTTPS Subscription URL) */}
      {importOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-xs">
          <div className="mq-panel flex max-h-[90vh] w-full max-w-2xl flex-col overflow-hidden rounded-2xl shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
              <h2 className="text-sm font-semibold text-white">安全导入与隔离审计</h2>
              <button onClick={() => setImportOpen(false)} className="text-slate-400 hover:text-white">
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="flex-1 space-y-4 overflow-y-auto p-5">
              {/* 3-mode selector */}
              <div className="grid grid-cols-3 gap-2 rounded-lg bg-[#090c10] p-1 text-xs">
                {[
                  { id: "paste" as ImportMethod, label: "粘贴链接 / 文本", icon: FileText },
                  { id: "file" as ImportMethod, label: "本地 .conf 文件", icon: Upload },
                  { id: "url" as ImportMethod, label: "HTTPS 订阅 URL", icon: Link2 },
                ].map((m) => {
                  const Icon = m.icon;
                  return (
                    <button
                      key={m.id}
                      onClick={() => setImportMethod(m.id)}
                      className={`flex items-center justify-center gap-1.5 rounded-md py-1.5 font-medium transition ${
                        importMethod === m.id
                          ? "bg-[#1a2433] text-white"
                          : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      <Icon className="h-3.5 w-3.5" /> {m.label}
                    </button>
                  );
                })}
              </div>

              <div>
                <label className="text-xs text-slate-400">配置名称</label>
                <input
                  value={importName}
                  onChange={(e) => setImportName(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-slate-800 bg-[#090c10] px-3 py-2 text-sm text-white"
                />
              </div>

              {importMethod === "url" && (
                <div className="flex gap-2">
                  <input
                    value={subUrl}
                    onChange={(e) => setSubUrl(e.target.value)}
                    placeholder="https://example.com/subscribe (仅允许公网 HTTPS，自动防 SSRF)"
                    className="font-mono-tabular flex-1 rounded-lg border border-slate-800 bg-[#090c10] px-3 py-2 text-xs text-white"
                  />
                  <button
                    onClick={handleFetchSubUrl}
                    disabled={busy || !subUrl.trim()}
                    className="flex items-center gap-1.5 rounded-lg bg-sky-500/20 px-3.5 py-2 text-xs font-medium text-sky-300 hover:bg-sky-500/30 disabled:opacity-40"
                  >
                    <Download className="h-3.5 w-3.5" /> 拉取并审计
                  </button>
                </div>
              )}

              {importMethod === "file" && (
                <label className="flex cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed border-slate-700 bg-[#090c10] py-8 text-xs text-slate-400 hover:border-sky-500/50 hover:text-slate-200">
                  <Upload className="mb-2 h-6 w-6 text-sky-400" />
                  <span>点击选择 Shadowrocket `.conf` / Clash `.yaml` / `sing-box` `.json` 文件</span>
                  <input
                    type="file"
                    accept=".conf,.txt,.json,.yaml,.yml"
                    className="hidden"
                    onChange={async (e) => {
                      const file = e.target.files?.[0];
                      if (!file) return;
                      const text = await file.text();
                      setImportText(text);
                      setImportName(file.name.replace(/\.[^.]+$/, ""));
                      setPreview(null);
                      const res = await api.previewImport(text);
                      setPreview(res);
                      setApprovedHostDomains(new Set());
                    }}
                  />
                </label>
              )}

              {importMethod === "paste" && (
                <textarea
                  rows={5}
                  value={importText}
                  onChange={(e) => {
                    setImportText(e.target.value);
                    setPreview(null);
                  }}
                  placeholder="trojan://... / anytls://... / hy2://... / tuic://... / vless://..."
                  className="font-mono-tabular w-full rounded-lg border border-slate-800 bg-[#090c10] p-3 text-xs text-slate-200 outline-none focus:border-sky-500"
                />
              )}

              {preview && (
                <div className="space-y-3 rounded-xl border border-slate-800 bg-[#090c10] p-4">
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <span className="rounded bg-sky-500/15 px-2 py-0.5 text-sky-300">
                      {preview.format}
                    </span>
                    <span className="rounded bg-slate-800 px-2 py-0.5 text-slate-200">
                      节点 {preview.report.total_nodes_imported}
                    </span>
                    <span className="rounded bg-slate-800 px-2 py-0.5 text-slate-200">
                      规则 {preview.report.total_rules_imported}
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
                          ? "border-rose-500/35 bg-rose-950/25 text-rose-200"
                          : "border-amber-500/30 bg-amber-950/20 text-amber-200"
                      }`}
                    >
                      <div className="font-semibold">
                        [{f.severity.toUpperCase()} · {f.action.toUpperCase()}] {f.summary}
                      </div>
                      {f.samples.length > 0 && (
                        <div className="font-mono-tabular mt-1 text-[11px] opacity-80">
                          {f.samples.slice(0, 3).join(" | ")}
                        </div>
                      )}
                    </div>
                  ))}

                  {preview.hosts.length > 0 && (
                    <div className="space-y-1.5">
                      <div className="text-xs font-medium text-slate-300">
                        勾选需要放行的 `[Host]` 映射（默认全部隔离）：
                      </div>
                      {preview.hosts.map((h) => (
                        <label
                          key={h.domain}
                          className="flex cursor-pointer items-center justify-between rounded-lg border border-slate-800 bg-[#111722] px-3 py-2 text-xs"
                        >
                          <span className="font-mono-tabular">
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
                            className="accent-sky-500"
                          />
                        </label>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="flex items-center justify-end gap-2 border-t border-slate-800 px-5 py-3">
              {importMethod === "paste" && (
                <button
                  onClick={handlePreviewImport}
                  disabled={busy || !importText.trim()}
                  className="rounded-lg border border-slate-700 bg-[#151c27] px-4 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800 disabled:opacity-40"
                >
                  1. 安全扫描与预览
                </button>
              )}
              <button
                onClick={handleCommitImport}
                disabled={busy || !preview}
                className="rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-40"
              >
                确认导入至 MaxQ
              </button>
            </div>
          </div>
        </div>
      )}

      {/* TLS TOFU Probe & Pin Inspector Drawer */}
      {inspectNode && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/65 backdrop-blur-xs">
          <div className="mq-panel flex h-full w-full max-w-lg flex-col border-y-0 border-r-0 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
              <div>
                <h2 className="text-sm font-semibold text-white">TLS 证书探测与 TOFU 公钥固定</h2>
                <p className="text-xs text-slate-400">{inspectNode.name}</p>
              </div>
              <button onClick={() => setInspectNode(null)} className="text-slate-400 hover:text-white">
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="flex-1 space-y-4 overflow-y-auto p-5 text-xs">
              <div className="space-y-1.5 rounded-xl border border-slate-800 bg-[#090c10] p-4">
                <div>
                  <span className="text-slate-400">拨号地址：</span>
                  <span className="font-mono-tabular text-slate-200">
                    {inspectNode.dial_override_server ?? inspectNode.server}:
                    {inspectNode.server_port}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400">TLS SNI：</span>
                  <span className="font-mono-tabular text-slate-200">
                    {inspectNode.tls.server_name ?? inspectNode.server}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400">探测引擎：</span>
                  <span className="text-sky-300">
                    纯 Rust rustls / quinn（绕过 Windows Schannel，校验私钥签名，支持 Hysteria2 Salamander）
                  </span>
                </div>
              </div>

              <button
                onClick={() => handleProbeNode(inspectNode)}
                disabled={probeLoading}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-sky-500 px-4 py-2.5 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50"
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
                <div className="space-y-3 rounded-xl border border-slate-800 bg-[#090c10] p-4">
                  {probeResult.outcome.status === "mismatch" && (
                    <div className="rounded-lg border border-rose-500 bg-rose-950/70 p-3 text-rose-100">
                      <div className="flex items-center gap-1.5 font-bold text-rose-300">
                        <ShieldAlert className="h-4 w-4" /> 警告：证书公钥指纹发生变更（疑似 MITM）！
                      </div>
                      <div className="font-mono-tabular mt-2 text-[11px] break-all">
                        <div>预期 SPKI: {probeResult.outcome.expected_spki_b64}</div>
                        <div className="text-rose-300">
                          实测 SPKI: {probeResult.outcome.observed_spki_b64}
                        </div>
                      </div>
                    </div>
                  )}

                  {probeResult.outcome.status === "matched" && (
                    <div className="flex items-center gap-2 rounded-lg bg-emerald-500/15 p-2.5 text-emerald-300">
                      <CheckCircle2 className="h-4 w-4" /> 指纹与已有记录 / 导入 pin 完全一致
                    </div>
                  )}

                  <div className="font-mono-tabular space-y-1.5 text-[11px] break-all">
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
                  <div className="font-semibold text-amber-300">Scheme A 默认安全策略</div>
                  <p className="mt-1 text-slate-400">
                    强烈建议使用上方「探测并固定证书」消除中间人风险；仅在临时调试且知晓风险时放行单节点：
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
