import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Check,
  Command,
  Copy,
  Cpu,
  Edit3,
  Gauge,
  Globe,
  Info,
  KeyRound,
  Lock,
  Moon,
  Network,
  Palette,
  Plus,
  Power,
  Radar,
  RefreshCw,
  Search,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Sun,
  Terminal,
  Trash2,
  X,
} from "lucide-react";
import { api, isTauriRuntime } from "./api";
import { AboutView } from "./components/AboutView";
import { CommandPalette } from "./components/CommandPalette";
import { ImportModal, type ImportMethod } from "./components/ImportModal";
import { LaunchEasterEgg } from "./components/LaunchEasterEgg";
import { MaxQLogo } from "./components/MaxQLogo";
import { OrbitalRadar } from "./components/OrbitalRadar";
import { ProbeDrawer } from "./components/ProbeDrawer";
import { SpkiSigil } from "./components/SpkiSigil";
import { TelemetryRibbon, type SpeedSample } from "./components/TelemetryRibbon";
import { playSoftTone } from "./sound";
import type {
  AboutInfo,
  AccentFlavor,
  BatchPinSummary,
  BuiltinRulesInfo,
  NodeConfig,
  ProbeNodeResult,
  ProfileSummary,
  ProxyMode,
  RoutingMode,
  RuntimePolicy,
  RuntimeStatus,
  RuntimeTelemetry,
  SanitizedImport,
  StoredProfile,
  ThemeMode,
  TunServiceStatus,
} from "./types";

type Tab = "nodes" | "radar" | "security" | "logs" | "settings" | "about";

const PROTOCOL_FILTERS: Array<{ id: string; label: string }> = [
  { id: "all", label: "全部" },
  { id: "trojan", label: "Trojan" },
  { id: "any_tls", label: "AnyTLS" },
  { id: "hysteria2", label: "Hy2" },
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
      label: "明文 / 无 TLS",
      bg: "var(--mq-subtle)",
      color: "var(--mq-ink-3)",
      icon: Globe,
    };
  }
  switch (node.tls.verify_mode.mode) {
    case "pinned_spki":
      return {
        label: "SPKI 已固定",
        bg: "var(--mq-ok-bg)",
        color: "var(--mq-ok)",
        icon: ShieldCheck,
      };
    case "system_ca":
      return {
        label: "系统 CA",
        bg: "var(--mq-accent-soft)",
        color: "var(--mq-accent-ink)",
        icon: Lock,
      };
    case "pending_pin_bootstrap":
      return {
        label: "待核验 pcs",
        bg: "var(--mq-warn-bg)",
        color: "var(--mq-warn)",
        icon: KeyRound,
      };
    case "insecure_legacy":
      return node.tls.verify_mode.user_confirmed_override
        ? {
            label: "临时放行",
            bg: "var(--mq-warn-bg)",
            color: "var(--mq-warn)",
            icon: AlertTriangle,
          }
        : {
            label: "待验证 (已阻断)",
            bg: "var(--mq-danger-bg)",
            color: "var(--mq-danger)",
            icon: ShieldAlert,
          };
  }
}

const DEFAULT_ABOUT: AboutInfo = {
  app_name: "MaxQ",
  app_version: "0.3.0",
  engine_brand: "JaxCore · sing-box",
  core_version: "1.14.4",
  creator: "JucStudio · Neon",
  os: "windows",
  arch: "x86_64",
  builtin_rule_count: 8581,
  service_protocol_version: "1.0.1",
  total_profiles: 0,
  total_nodes: 0,
  pinned_spki_nodes: 0,
};

const EMPTY_HISTORY: SpeedSample[] = Array.from({ length: 28 }, () => ({ up: 0, down: 0 }));

function loadPref<T extends string>(key: string, fallback: T): T {
  try {
    const v = localStorage.getItem(key);
    return (v as T) || fallback;
  } catch {
    return fallback;
  }
}

export default function App() {
  const inTauri = isTauriRuntime();
  const [tab, setTab] = useState<Tab>("nodes");

  // Theme & Fun Lab Preferences (persisted locally)
  const [theme, setTheme] = useState<ThemeMode>(() => loadPref<ThemeMode>("maxq.theme", "light"));
  const [accent, setAccent] = useState<AccentFlavor>(() =>
    loadPref<AccentFlavor>("maxq.accent", "periwinkle")
  );
  const [soundEnabled, setSoundEnabled] = useState<boolean>(
    () => loadPref<"on" | "off">("maxq.sound", "off") === "on"
  );
  const [logoClicks, setLogoClicks] = useState(0);
  const [launchKey, setLaunchKey] = useState(0);
  const [paletteOpen, setPaletteOpen] = useState(false);

  // Core Vault & Runtime State
  const [profiles, setProfiles] = useState<ProfileSummary[]>([]);
  const [selectedProfileId, setSelectedProfileId] = useState<string | null>(null);
  const [profile, setProfile] = useState<StoredProfile | null>(null);
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [renameDraft, setRenameDraft] = useState("");

  const [aboutInfo, setAboutInfo] = useState<AboutInfo>(DEFAULT_ABOUT);
  const [builtinRules, setBuiltinRules] = useState<BuiltinRulesInfo>({
    rule_count: 8581,
    description: "MaxQ 内置默认分流规则（国内直连域名 + CN IP-CIDR + 海外代理，已完全脱敏）",
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
  const [telemetry, setTelemetry] = useState<RuntimeTelemetry>({
    connected: false,
    upload_bps: 0,
    download_bps: 0,
    upload_total: 0,
    download_total: 0,
    active_connections: 0,
    uptime_secs: 0,
    dynamic_pressure_q: 0,
    recent_connections: [],
  });
  const [speedHistory, setSpeedHistory] = useState<SpeedSample[]>(EMPTY_HISTORY);
  const [logs, setLogs] = useState<string[]>([]);
  const [logFilter, setLogFilter] = useState("");

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

  // Search, filter, latency & batch actions
  const [searchQuery, setSearchQuery] = useState("");
  const [protoFilter, setProtoFilter] = useState("all");
  const [latencies, setLatencies] = useState<Record<string, number | "err" | "loading">>({});
  const [scanningOrbit, setScanningOrbit] = useState(false);
  const [batchPinning, setBatchPinning] = useState(false);
  const [tunBusy, setTunBusy] = useState(false);
  const [toast, setToast] = useState<{ kind: "info" | "ok" | "err"; text: string } | null>(null);

  // Import Modal State
  const [importOpen, setImportOpen] = useState(false);
  const [importMethod, setImportMethod] = useState<ImportMethod>("paste");
  const [importName, setImportName] = useState("新导入配置");
  const [importText, setImportText] = useState("");
  const [subUrl, setSubUrl] = useState("");
  const [preview, setPreview] = useState<SanitizedImport | null>(null);
  const [approvedHostDomains, setApprovedHostDomains] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);

  // TLS TOFU Probe Drawer State
  const [inspectNode, setInspectNode] = useState<NodeConfig | null>(null);
  const [probeResult, setProbeResult] = useState<ProbeNodeResult | null>(null);
  const [probeLoading, setProbeLoading] = useState(false);
  const [probeError, setProbeError] = useState<string | null>(null);

  // Apply theme & accent tokens on <html>
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    document.documentElement.setAttribute("data-accent", accent);
    try {
      localStorage.setItem("maxq.theme", theme);
      localStorage.setItem("maxq.accent", accent);
      localStorage.setItem("maxq.sound", soundEnabled ? "on" : "off");
    } catch {
      // ignore storage errors
    }
  }, [theme, accent, soundEnabled]);

  // Auto-dismiss transient info/ok toast
  useEffect(() => {
    if (!toast || toast.kind === "err") return;
    const t = setTimeout(() => setToast(null), 5000);
    return () => clearTimeout(t);
  }, [toast]);

  // Ctrl+K / Cmd+K Quick Command Palette shortcut
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((v) => !v);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const showToast = useCallback((kind: "info" | "ok" | "err", text: string) => {
    setToast({ kind, text });
  }, []);

  const triggerLaunch = useCallback(() => {
    setLaunchKey((k) => k + 1);
    if (soundEnabled) playSoftTone("launch");
  }, [soundEnabled]);

  const handleLogoTap = () => {
    const next = logoClicks + 1;
    if (next >= 5) {
      setLogoClicks(0);
      triggerLaunch();
      showToast("ok", "Max-Q 隐藏彩蛋已解锁！正在突破最大动压 🚀");
    } else {
      setLogoClicks(next);
    }
  };

  const refreshAll = async () => {
    if (!inTauri) return;
    try {
      const [list, st, pol, l, br, tunSt, ab] = await Promise.all([
        api.listProfiles(),
        api.getRuntimeStatus(),
        api.getRuntimePolicy(),
        api.getRuntimeLogs(),
        api.getBuiltinRulesInfo(),
        api.getTunServiceStatus(),
        api.getAboutInfo(),
      ]);
      setProfiles(list);
      setStatus(st);
      setPolicy(pol);
      setLogs(l);
      setBuiltinRules(br);
      setTunService(tunSt);
      setAboutInfo(ab);

      const targetId = selectedProfileId ?? list[0]?.id ?? null;
      if (targetId && list.some((p) => p.id === targetId)) {
        setSelectedProfileId(targetId);
        const full = await api.getProfile(targetId);
        setProfile(full);
      } else if (list[0]) {
        setSelectedProfileId(list[0].id);
        const full = await api.getProfile(list[0].id);
        setProfile(full);
      } else {
        setSelectedProfileId(null);
        setProfile(null);
      }
    } catch (err) {
      showToast("err", String(err));
    }
  };

  // Real-time Rust polling for runtime status, logs, TUN service, and live Clash API telemetry
  useEffect(() => {
    refreshAll();
    if (!inTauri) return;
    const timer = setInterval(async () => {
      try {
        const [st, l, tunSt, tel] = await Promise.all([
          api.getRuntimeStatus(),
          api.getRuntimeLogs(),
          api.getTunServiceStatus(),
          api.getRuntimeTelemetry(),
        ]);
        setStatus(st);
        setLogs(l);
        setTunService(tunSt);
        setTelemetry(tel);
        setSpeedHistory((prev) => [
          ...prev.slice(-27),
          {
            up: st.running ? tel.upload_bps : 0,
            down: st.running ? tel.download_bps : 0,
          },
        ]);
      } catch {
        // ignore transient poll error
      }
    }, 1800);
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

  const filteredLogs = useMemo(() => {
    const q = logFilter.trim().toLowerCase();
    if (!q) return logs;
    return logs.filter((line) => line.toLowerCase().includes(q));
  }, [logs, logFilter]);

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
      } else {
        showToast("ok", "配置策略已保存");
      }
    } catch (err) {
      showToast("err", String(err));
    }
  };

  const handleSwitchProxyMode = async (mode: ProxyMode) => {
    if (mode === "tun" && inTauri && !tunService.running) {
      showToast("info", "TUN 模式需要先安装 MaxQ 安全加固 Windows 服务，已为你跳转至安全中心。");
      setTab("security");
      return;
    }
    await applyPolicyChange({ proxy_mode: mode, tun_enabled: mode === "tun" }, true);
  };

  const handleInstallTunService = async () => {
    if (tunBusy) return;
    setTunBusy(true);
    showToast("info", "正在请求 UAC 提权并安装启动 MaxQ 安全加固 TUN 服务...");
    try {
      const msg = await api.installTunService();
      const st = await api.getTunServiceStatus();
      setTunService(st);
      showToast(st.running ? "ok" : "info", msg);
      if (st.running && soundEnabled) playSoftTone("connect");
    } catch (err) {
      const st = await api.getTunServiceStatus().catch(() => null);
      if (st) setTunService(st);
      showToast("err", String(err));
    } finally {
      setTunBusy(false);
    }
  };

  const handleUninstallTunService = async () => {
    if (tunBusy) return;
    setTunBusy(true);
    showToast("info", "正在请求 UAC 提权卸载 MaxQ TUN 服务...");
    try {
      const msg = await api.uninstallTunService();
      await applyPolicyChange({ proxy_mode: "system_proxy", tun_enabled: false }, false);
      const st = await api.getTunServiceStatus();
      setTunService(st);
      showToast("ok", msg);
    } catch (err) {
      showToast("err", String(err));
    } finally {
      setTunBusy(false);
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
      if (soundEnabled) playSoftTone("connect");
      showToast("ok", `已通过 ${st.tun_active ? "TUN 虚拟网卡" : "系统代理"} 连接 ${node.name}`);
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
      setTelemetry({
        connected: false,
        upload_bps: 0,
        download_bps: 0,
        upload_total: 0,
        download_total: 0,
        active_connections: 0,
        uptime_secs: 0,
        dynamic_pressure_q: 0,
        recent_connections: [],
      });
      if (soundEnabled) playSoftTone("disconnect");
      showToast("info", "已断开连接并恢复网络设置");
    } catch (err) {
      showToast("err", String(err));
    }
  };

  const handleCloseConnections = async () => {
    if (!inTauri) return;
    try {
      await api.closeAllConnections();
      showToast("ok", "已释放全部旧连接");
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
      if (soundEnabled) playSoftTone("ping");
    } catch {
      setLatencies((prev) => ({ ...prev, [node.id]: "err" }));
    }
  };

  const handleBatchTestLatencies = async () => {
    if (!profile || scanningOrbit) return;
    setScanningOrbit(true);
    const loadingMap: Record<string, "loading"> = {};
    for (const n of proxyNodes) loadingMap[n.id] = "loading";
    setLatencies((prev) => ({ ...prev, ...loadingMap }));
    try {
      const results = await api.batchTestLatencies(profile.id);
      const next: Record<string, number | "err"> = {};
      let okCount = 0;
      for (const [id, ms] of Object.entries(results)) {
        if (typeof ms === "number") {
          next[id] = ms;
          okCount += 1;
        } else {
          next[id] = "err";
        }
      }
      setLatencies((prev) => ({ ...prev, ...next }));
      if (soundEnabled) playSoftTone("ping");
      showToast("ok", `星轨并发测速完成：${okCount} / ${Object.keys(results).length} 个节点可达`);
    } catch (err) {
      showToast("err", String(err));
    } finally {
      setScanningOrbit(false);
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
      await api.confirmNodePin(inspectNode.id, probeResult.proposed_trust_record);
      setInspectNode(null);
      setProbeResult(null);
      await refreshAll();
      showToast("ok", `已为 ${inspectNode.name} 固定 SPKI 公钥指纹`);
    } catch (err) {
      showToast("err", String(err));
    }
  };

  const handleTemporaryOverride = async () => {
    if (!inspectNode) return;
    try {
      await api.setInsecureOverride(inspectNode.id, true);
      setInspectNode(null);
      await refreshAll();
      showToast("info", `已临时放行 ${inspectNode.name}（建议尽快固定 SPKI 指纹）`);
    } catch (err) {
      showToast("err", String(err));
    }
  };

  const handleCommitRename = async (profileId: string) => {
    const trimmed = renameDraft.trim();
    setRenamingId(null);
    if (!trimmed) return;
    try {
      await api.renameProfile(profileId, trimmed);
      await refreshAll();
      showToast("ok", `配置已重命名为「${trimmed}」`);
    } catch (err) {
      showToast("err", String(err));
    }
  };

  const handleCopyDiagnostics = async () => {
    try {
      const text = inTauri
        ? await api.exportDiagnosticsSummary()
        : `MaxQ v${aboutInfo.app_version} — Powered by JaxCore sing-box · JucStudio Neon`;
      await navigator.clipboard.writeText(text);
      showToast("ok", "已复制脱敏诊断报告至剪贴板（零密钥泄露）");
    } catch (err) {
      showToast("err", String(err));
    }
  };

  const navItems: Array<{ id: Tab; label: string; icon: typeof Server; badge?: string }> = [
    { id: "nodes", label: "节点控制", icon: Server, badge: proxyNodes.length ? String(proxyNodes.length) : undefined },
    {
      id: "radar",
      label: "星轨雷达",
      icon: Radar,
      badge: status.running && telemetry.active_connections > 0 ? String(telemetry.active_connections) : undefined,
    },
    { id: "security", label: "安全与规则", icon: Shield, badge: unverifiedCount > 0 ? `${unverifiedCount}` : undefined },
    { id: "logs", label: "运行日志", icon: Terminal },
    { id: "settings", label: "偏好与主题", icon: Settings },
    { id: "about", label: "关于 MaxQ", icon: Info },
  ];

  return (
    <div className="flex h-screen overflow-hidden" style={{ backgroundColor: "var(--mq-bg)", color: "var(--mq-ink)" }}>
      {/* Left Brand & Navigation Rail */}
      <aside className="mq-rail flex w-60 shrink-0 flex-col justify-between p-4">
        <div className="space-y-4">
          {/* Brand Header (click emblem 5x for Max-Q launch Easter egg!) */}
          <div className="flex items-center justify-between px-1">
            <div className="flex items-center gap-3">
              <MaxQLogo
                size={38}
                interactive
                onClick={handleLogoTap}
                title="MaxQ — 连点 5 次触发隐藏升空彩蛋"
              />
              <div>
                <div className="flex items-center gap-1.5">
                  <span className="text-[15px] font-bold tracking-tight" style={{ color: "var(--mq-ink)" }}>
                    MaxQ
                  </span>
                  <span
                    className="font-mono-tabular rounded-md px-1.5 py-0.5 text-[10px] font-semibold"
                    style={{
                      backgroundColor: "var(--mq-accent-soft)",
                      color: "var(--mq-accent-ink)",
                    }}
                  >
                    v{aboutInfo.app_version}
                  </span>
                </div>
                <div className="text-[11px]" style={{ color: "var(--mq-ink-3)" }}>
                  JaxCore · sing-box
                </div>
              </div>
            </div>
          </div>

          {/* Compact Live Power Status Card */}
          <div
            className="rounded-2xl border p-3 transition-colors"
            style={{
              backgroundColor: status.running ? "var(--mq-card)" : "var(--mq-subtle)",
              borderColor: status.running ? "var(--mq-accent)" : "var(--mq-border)",
            }}
          >
            <div className="flex items-center justify-between gap-2">
              <div className="flex min-w-0 items-center gap-2">
                <span className="relative flex h-2.5 w-2.5 shrink-0 items-center justify-center">
                  {status.running && (
                    <span
                      className="mq-pulse-ring absolute inline-flex h-full w-full rounded-full"
                      style={{ backgroundColor: "var(--mq-ok)" }}
                    />
                  )}
                  <span
                    className="relative inline-flex h-2 w-2 rounded-full"
                    style={{ backgroundColor: status.running ? "var(--mq-ok)" : "var(--mq-ink-3)" }}
                  />
                </span>
                <span className="truncate text-xs font-semibold" style={{ color: "var(--mq-ink)" }}>
                  {status.running ? status.active_node_name || "运行中" : "内核待命"}
                </span>
              </div>
              {status.running && (
                <button
                  onClick={handleStopProxy}
                  title="断开连接"
                  className="mq-btn shrink-0 rounded-lg p-1.5"
                  style={{
                    backgroundColor: "var(--mq-danger-bg)",
                    color: "var(--mq-danger)",
                  }}
                >
                  <Power className="h-3.5 w-3.5" />
                </button>
              )}
            </div>
            <div className="mt-1.5 flex items-center justify-between text-[11px]" style={{ color: "var(--mq-ink-3)" }}>
              <span>
                {status.running
                  ? status.tun_active
                    ? "TUN 虚拟网卡接管"
                    : "系统代理已启用"
                  : "选定节点即可秒连"}
              </span>
              {status.running && (
                <span className="font-mono-tabular" style={{ color: "var(--mq-accent-ink)" }}>
                  Q {Math.round(telemetry.dynamic_pressure_q)}%
                </span>
              )}
            </div>
          </div>

          {/* Primary Navigation */}
          <nav className="space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const active = tab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setTab(item.id)}
                  className="mq-nav-item flex w-full items-center justify-between rounded-xl px-3 py-2 text-[13px] font-medium"
                  style={
                    active
                      ? {
                          backgroundColor: "var(--mq-card)",
                          color: "var(--mq-accent-ink)",
                          border: "1px solid var(--mq-border-strong)",
                        }
                      : {
                          color: "var(--mq-ink-2)",
                          border: "1px solid transparent",
                        }
                  }
                >
                  <span className="flex items-center gap-2.5">
                    <Icon
                      className="h-4 w-4"
                      style={{ color: active ? "var(--mq-accent)" : "var(--mq-ink-3)" }}
                    />
                    {item.label}
                  </span>
                  {item.badge && (
                    <span
                      className="font-mono-tabular rounded-full px-1.5 py-0.5 text-[10px] font-semibold"
                      style={{
                        backgroundColor:
                          item.id === "security" && unverifiedCount > 0
                            ? "var(--mq-danger-bg)"
                            : "var(--mq-accent-soft)",
                        color:
                          item.id === "security" && unverifiedCount > 0
                            ? "var(--mq-danger)"
                            : "var(--mq-accent-ink)",
                      }}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Bottom Profile Vault Switcher */}
        <div
          className="space-y-2 border-t pt-3"
          style={{ borderColor: "var(--mq-border)" }}
        >
          <div className="flex items-center justify-between px-1 text-[11px] font-semibold" style={{ color: "var(--mq-ink-3)" }}>
            <span>本地配置库 ({profiles.length})</span>
            <button
              onClick={() => setImportOpen(true)}
              className="mq-btn rounded-md p-1 hover:bg-[var(--mq-card)]"
              style={{ color: "var(--mq-accent)" }}
              title="导入新配置"
            >
              <Plus className="h-3.5 w-3.5" />
            </button>
          </div>
          <div className="max-h-32 space-y-1 overflow-y-auto pr-0.5">
            {profiles.length === 0 ? (
              <div className="px-2 py-2 text-[11px]" style={{ color: "var(--mq-ink-3)" }}>
                暂无配置，点右上角导入分享链或 `.conf`
              </div>
            ) : (
              profiles.map((p) => {
                const selected = p.id === selectedProfileId;
                return (
                  <div
                    key={p.id}
                    className="group flex items-center justify-between gap-1 rounded-xl px-2.5 py-1.5 text-xs transition-colors"
                    style={
                      selected
                        ? { backgroundColor: "var(--mq-card)", color: "var(--mq-ink)" }
                        : { color: "var(--mq-ink-2)" }
                    }
                  >
                    {renamingId === p.id ? (
                      <div className="flex w-full items-center gap-1">
                        <input
                          value={renameDraft}
                          autoFocus
                          onChange={(e) => setRenameDraft(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") handleCommitRename(p.id);
                            if (e.key === "Escape") setRenamingId(null);
                          }}
                          className="w-full rounded bg-transparent text-xs font-medium focus:outline-none"
                          style={{ color: "var(--mq-ink)" }}
                        />
                        <button
                          onClick={() => handleCommitRename(p.id)}
                          style={{ color: "var(--mq-ok)" }}
                        >
                          <Check className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    ) : (
                      <>
                        <button
                          onClick={() => setSelectedProfileId(p.id)}
                          className="min-w-0 flex-1 truncate text-left font-medium"
                        >
                          {p.name}
                        </button>
                        <div className="flex shrink-0 items-center gap-1">
                          <button
                            onClick={() => {
                              setRenamingId(p.id);
                              setRenameDraft(p.name);
                            }}
                            title="重命名配置"
                            className="opacity-0 transition-opacity group-hover:opacity-100"
                            style={{ color: "var(--mq-ink-3)" }}
                          >
                            <Edit3 className="h-3 w-3" />
                          </button>
                          <span className="font-mono-tabular text-[10px]" style={{ color: "var(--mq-ink-3)" }}>
                            {p.node_count}
                          </span>
                        </div>
                      </>
                    )}
                  </div>
                );
              })
            )}
          </div>
          <div className="px-1 pt-0.5 text-[10px]" style={{ color: "var(--mq-ink-3)" }}>
            by JucStudio · Neon
          </div>
        </div>
      </aside>

      {/* Main Content Workspace */}
      <div className="flex min-w-0 flex-1 flex-col">
        {/* Flat Crisp Top Command Deck */}
        <header
          className="flex flex-wrap items-center justify-between gap-3 border-b px-6 py-3"
          style={{ backgroundColor: "var(--mq-card)", borderColor: "var(--mq-border)" }}
        >
          <div className="flex flex-wrap items-center gap-2.5">
            {/* Routing Mode Segmented Pill */}
            <div className="mq-subtle flex items-center rounded-xl p-1 text-xs">
              {(
                [
                  { id: "rule", label: "规则分流" },
                  { id: "global", label: "全局代理" },
                  { id: "direct", label: "全部直连" },
                ] as Array<{ id: RoutingMode; label: string }>
              ).map((m) => {
                const active = policy.routing_mode === m.id;
                return (
                  <button
                    key={m.id}
                    onClick={() => applyPolicyChange({ routing_mode: m.id }, true)}
                    className="mq-btn rounded-lg px-3 py-1 font-semibold"
                    style={
                      active
                        ? {
                            backgroundColor: "var(--mq-card)",
                            color: "var(--mq-accent-ink)",
                            border: "1px solid var(--mq-border-strong)",
                          }
                        : { color: "var(--mq-ink-2)", border: "1px solid transparent" }
                    }
                  >
                    {m.label}
                  </button>
                );
              })}
            </div>

            {/* Proxy Engine Mode Segmented Pill */}
            <div className="mq-subtle flex items-center rounded-xl p-1 text-xs">
              <button
                onClick={() => handleSwitchProxyMode("system_proxy")}
                className="mq-btn flex items-center gap-1.5 rounded-lg px-3 py-1 font-semibold"
                style={
                  policy.proxy_mode === "system_proxy"
                    ? {
                        backgroundColor: "var(--mq-card)",
                        color: "var(--mq-accent-ink)",
                        border: "1px solid var(--mq-border-strong)",
                      }
                    : { color: "var(--mq-ink-2)", border: "1px solid transparent" }
                }
              >
                <Globe className="h-3.5 w-3.5" /> 系统代理
              </button>
              <button
                onClick={() => handleSwitchProxyMode("tun")}
                className="mq-btn flex items-center gap-1.5 rounded-lg px-3 py-1 font-semibold"
                style={
                  policy.proxy_mode === "tun"
                    ? {
                        backgroundColor: "var(--mq-ok-bg)",
                        color: "var(--mq-ok)",
                        border: "1px solid var(--mq-ok-border)",
                      }
                    : { color: "var(--mq-ink-2)", border: "1px solid transparent" }
                }
              >
                <Network className="h-3.5 w-3.5" /> TUN 模式
                <span
                  className="h-1.5 w-1.5 rounded-full"
                  style={{ backgroundColor: tunService.running ? "var(--mq-ok)" : "var(--mq-warn)" }}
                />
              </button>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Quick Ctrl+K Command Palette */}
            <button
              onClick={() => setPaletteOpen(true)}
              className="mq-btn mq-subtle hidden items-center gap-1.5 rounded-xl px-3 py-1.5 text-xs font-medium sm:flex"
              style={{ color: "var(--mq-ink-2)" }}
              title="打开快捷指令面板 (Ctrl+K)"
            >
              <Command className="h-3.5 w-3.5" style={{ color: "var(--mq-accent)" }} />
              <span>搜索</span>
              <kbd
                className="font-mono-tabular rounded px-1 py-0.5 text-[10px]"
                style={{ backgroundColor: "var(--mq-card)", color: "var(--mq-ink-3)" }}
              >
                Ctrl K
              </kbd>
            </button>

            {/* Quick Light / Dark Periwinkle Toggle */}
            <button
              onClick={() => setTheme((t) => (t === "light" ? "dark" : "light"))}
              className="mq-btn mq-subtle rounded-xl p-2"
              style={{ color: "var(--mq-accent)" }}
              title={theme === "light" ? "切换至暮色鸢尾深色模式" : "切换至晴岚浅蓝紫浅色模式"}
            >
              {theme === "light" ? <Moon className="h-4 w-4" /> : <Sun className="h-4 w-4" />}
            </button>

            {!tunService.running && inTauri && (
              <button
                onClick={handleInstallTunService}
                disabled={tunBusy}
                className="mq-btn mq-subtle flex items-center gap-1.5 rounded-xl px-3 py-1.5 text-xs font-medium disabled:opacity-50"
                style={{ color: "var(--mq-ink)" }}
              >
                <Cpu className="h-3.5 w-3.5" style={{ color: "var(--mq-accent)" }} />
                {tunBusy ? "安装中..." : "安装 TUN 服务"}
              </button>
            )}

            <button
              onClick={() => setImportOpen(true)}
              className="mq-btn mq-btn-primary flex items-center gap-1.5 rounded-xl px-3.5 py-1.5 text-xs font-semibold"
            >
              <Plus className="h-3.5 w-3.5" /> 导入节点 / 订阅
            </button>
          </div>
        </header>

        {/* Scrollable Content Viewport */}
        <main className="flex-1 overflow-y-auto px-6 py-5">
          {/* MITM Runtime Pin Mismatch Emergency Banner */}
          {status.last_mitm_alert && (
            <div
              className="mq-enter mb-4 flex items-center justify-between gap-3 rounded-2xl border px-4 py-3 text-xs"
              style={{
                backgroundColor: "var(--mq-danger-bg)",
                borderColor: "var(--mq-danger-border)",
                color: "var(--mq-danger)",
              }}
            >
              <div className="flex items-center gap-2.5">
                <ShieldAlert className="h-4 w-4 shrink-0" />
                <span>
                  <strong>安全警报（MITM 拦截）：</strong>服务端返回了未授权的 SPKI 公钥指纹{" "}
                  <code className="font-mono-tabular font-semibold">{status.last_mitm_alert}</code>
                  ，连接已被 JaxCore sing-box 自动拒绝！
                </span>
              </div>
              <button
                onClick={() => setTab("logs")}
                className="mq-btn shrink-0 rounded-lg px-2.5 py-1 font-semibold text-white"
                style={{ backgroundColor: "var(--mq-danger)" }}
              >
                查看日志
              </button>
            </div>
          )}

          {/* Toast Feedback Banner */}
          {toast && (
            <div
              className="mq-enter mb-4 flex items-center justify-between gap-3 rounded-2xl border px-4 py-2.5 text-xs font-medium"
              style={
                toast.kind === "err"
                  ? {
                      backgroundColor: "var(--mq-danger-bg)",
                      borderColor: "var(--mq-danger-border)",
                      color: "var(--mq-danger)",
                    }
                  : toast.kind === "ok"
                  ? {
                      backgroundColor: "var(--mq-ok-bg)",
                      borderColor: "var(--mq-ok-border)",
                      color: "var(--mq-ok)",
                    }
                  : {
                      backgroundColor: "var(--mq-accent-soft)",
                      borderColor: "var(--mq-border-strong)",
                      color: "var(--mq-accent-ink)",
                    }
              }
            >
              <span className="break-all">{toast.text}</span>
              <button onClick={() => setToast(null)} className="shrink-0 opacity-70 hover:opacity-100">
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          )}

          {/* TAB 1: NODES COMMAND DECK */}
          {tab === "nodes" && (
            <div className="mx-auto max-w-6xl space-y-5">
              {/* Live Max-Q Aerodynamic Telemetry Strip */}
              <TelemetryRibbon
                connected={status.running}
                activeNodeName={status.active_node_name}
                tunActive={status.tun_active}
                telemetry={telemetry}
                history={speedHistory}
                onCloseConnections={handleCloseConnections}
              />

              {/* Metadata Info Chips (Traffic / Expire) */}
              {metadataNodes.length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {metadataNodes.map((m) => (
                    <div
                      key={m.id}
                      className="mq-panel flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium"
                      style={{ color: "var(--mq-ink-2)" }}
                    >
                      <Activity className="h-3 w-3" style={{ color: "var(--mq-accent)" }} />
                      {m.name}
                    </div>
                  ))}
                </div>
              )}

              {!profile ? (
                <div className="mq-panel mq-enter flex flex-col items-center justify-center rounded-3xl px-6 py-16 text-center">
                  <div className="mq-float mb-4">
                    <MaxQLogo size={64} interactive onClick={triggerLaunch} />
                  </div>
                  <h2 className="text-lg font-bold tracking-tight" style={{ color: "var(--mq-ink)" }}>
                    欢迎登舰 MaxQ
                  </h2>
                  <p className="mt-2 max-w-md text-xs leading-relaxed" style={{ color: "var(--mq-ink-2)" }}>
                    支持 Shadowrocket 单条分享链（`trojan://` / `vless://` / `anytls://` / `hy2://` / `tuic://`）、
                    完整 `.conf` 以及 HTTPS 订阅导入。单节点开箱自带{" "}
                    <strong style={{ color: "var(--mq-accent-ink)" }}>
                      {builtinRules.rule_count.toLocaleString()} 条脱敏默认分流规则
                    </strong>
                    ，并采用 Scheme A 默认安全防中间人策略。
                  </p>
                  <div className="mt-6 flex flex-wrap justify-center gap-2.5">
                    <button
                      onClick={() => setImportOpen(true)}
                      className="mq-btn mq-btn-primary flex items-center gap-1.5 rounded-xl px-5 py-2.5 text-xs font-semibold"
                    >
                      <Plus className="h-4 w-4" /> 导入第一个节点 / 订阅
                    </button>
                    <button
                      onClick={() => setTab("about")}
                      className="mq-btn mq-subtle flex items-center gap-1.5 rounded-xl px-4 py-2.5 text-xs font-medium"
                      style={{ color: "var(--mq-ink-2)" }}
                    >
                      <Sparkles className="h-3.5 w-3.5" style={{ color: "var(--mq-accent)" }} /> 了解 MaxQ 品牌与特性
                    </button>
                  </div>
                </div>
              ) : (
                <>
                  {/* Filter & Batch Action Bar */}
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <div className="relative">
                        <Search
                          className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5"
                          style={{ color: "var(--mq-ink-3)" }}
                        />
                        <input
                          value={searchQuery}
                          onChange={(e) => setSearchQuery(e.target.value)}
                          placeholder="搜索节点名、主机或 SNI..."
                          className="mq-panel w-56 rounded-xl py-1.5 pl-8 pr-3 text-xs focus:outline-none"
                          style={{ color: "var(--mq-ink)" }}
                        />
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {PROTOCOL_FILTERS.map((pf) => {
                          const active = protoFilter === pf.id;
                          return (
                            <button
                              key={pf.id}
                              onClick={() => setProtoFilter(pf.id)}
                              className="mq-btn rounded-lg px-2.5 py-1 text-xs font-medium"
                              style={
                                active
                                  ? {
                                      backgroundColor: "var(--mq-accent-soft)",
                                      color: "var(--mq-accent-ink)",
                                    }
                                  : { color: "var(--mq-ink-2)" }
                              }
                            >
                              {pf.label}
                            </button>
                          );
                        })}
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={handleBatchTestLatencies}
                        disabled={scanningOrbit || proxyNodes.length === 0}
                        className="mq-btn mq-panel flex items-center gap-1.5 rounded-xl px-3 py-1.5 text-xs font-medium disabled:opacity-50"
                        style={{ color: "var(--mq-ink)" }}
                      >
                        <Gauge
                          className={`h-3.5 w-3.5 ${scanningOrbit ? "animate-spin" : ""}`}
                          style={{ color: "var(--mq-accent)" }}
                        />
                        {scanningOrbit ? "并发测速中..." : "一键测速"}
                      </button>
                      {unverifiedCount > 0 && (
                        <button
                          onClick={handleBatchProbeAndPin}
                          disabled={batchPinning}
                          className="mq-btn mq-btn-primary flex items-center gap-1.5 rounded-xl px-3.5 py-1.5 text-xs font-semibold disabled:opacity-50"
                        >
                          <Sparkles className={`h-3.5 w-3.5 ${batchPinning ? "animate-spin" : ""}`} />
                          {batchPinning ? "批量固定中..." : `一键固定 ${unverifiedCount} 个待验证节点`}
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Clean Flat Node Cards Grid */}
                  <div className="grid gap-3 md:grid-cols-2">
                    {filteredNodes.map((node) => {
                      const badge = tlsBadge(node);
                      const BadgeIcon = badge.icon;
                      const isActive = status.running && status.active_node_id === node.id;
                      const lat = latencies[node.id];
                      const spki = node.tls.trust_record?.spki_sha256_b64;

                      return (
                        <div
                          key={node.id}
                          className={`flex flex-col justify-between gap-3 rounded-2xl p-4 ${
                            isActive ? "mq-card-active" : "mq-card"
                          }`}
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div className="flex min-w-0 items-start gap-3">
                              {spki ? (
                                <SpkiSigil
                                  seed={spki}
                                  size={34}
                                  className="mt-0.5 border border-[var(--mq-border)]"
                                />
                              ) : (
                                <div
                                  className="mt-0.5 flex h-[34px] w-[34px] shrink-0 items-center justify-center rounded-lg text-[11px] font-bold"
                                  style={{
                                    backgroundColor: "var(--mq-subtle)",
                                    color: "var(--mq-accent)",
                                    border: "1px solid var(--mq-border)",
                                  }}
                                >
                                  {protocolLabel(node.protocol.type).slice(0, 2)}
                                </div>
                              )}
                              <div className="min-w-0">
                                <div className="flex flex-wrap items-center gap-1.5">
                                  <span
                                    className="truncate text-sm font-semibold"
                                    style={{ color: "var(--mq-ink)" }}
                                  >
                                    {node.name}
                                  </span>
                                  <span
                                    className="rounded-md px-1.5 py-0.5 text-[10px] font-semibold uppercase"
                                    style={{
                                      backgroundColor: "var(--mq-subtle)",
                                      color: "var(--mq-ink-2)",
                                    }}
                                  >
                                    {protocolLabel(node.protocol.type)}
                                  </span>
                                </div>
                                <div
                                  className="font-mono-tabular mt-1 truncate text-[11px]"
                                  style={{ color: "var(--mq-ink-3)" }}
                                >
                                  {node.dial_override_server
                                    ? `${node.dial_override_server} (${node.server})`
                                    : node.server}
                                  :{node.server_port}
                                  {node.tls.server_name ? ` · SNI ${node.tls.server_name}` : ""}
                                </div>
                              </div>
                            </div>

                            {/* Latency Badge */}
                            <button
                              onClick={() => handleTestLatency(node)}
                              title="测试 TCP 握手延迟"
                              className="font-mono-tabular mq-btn shrink-0 rounded-lg px-2 py-1 text-[11px] font-semibold"
                              style={{
                                backgroundColor: "var(--mq-subtle)",
                                color:
                                  lat === "err"
                                    ? "var(--mq-danger)"
                                    : typeof lat === "number"
                                    ? lat < 100
                                      ? "var(--mq-ok)"
                                      : lat < 220
                                      ? "var(--mq-accent-ink)"
                                      : "var(--mq-warn)"
                                    : "var(--mq-ink-3)",
                              }}
                            >
                              {lat === "loading"
                                ? "..."
                                : lat === "err"
                                ? "超时"
                                : typeof lat === "number"
                                ? `${lat} ms`
                                : "测速"}
                            </button>
                          </div>

                          <div className="flex items-center justify-between gap-2 pt-1">
                            <span
                              className="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-[11px] font-semibold"
                              style={{ backgroundColor: badge.bg, color: badge.color }}
                            >
                              <BadgeIcon className="h-3 w-3" /> {badge.label}
                            </span>

                            <div className="flex items-center gap-1.5">
                              {node.tls.enabled && (
                                <button
                                  onClick={() => handleProbeNode(node)}
                                  className="mq-btn mq-subtle rounded-lg px-2.5 py-1.5 text-xs font-medium"
                                  style={{ color: "var(--mq-ink-2)" }}
                                >
                                  证书探测
                                </button>
                              )}
                              {isActive ? (
                                <button
                                  onClick={handleStopProxy}
                                  className="mq-btn rounded-lg px-3.5 py-1.5 text-xs font-semibold"
                                  style={{
                                    backgroundColor: "var(--mq-danger-bg)",
                                    color: "var(--mq-danger)",
                                  }}
                                >
                                  断开
                                </button>
                              ) : (
                                <button
                                  onClick={() => handleStartNode(node)}
                                  className="mq-btn mq-btn-primary rounded-lg px-3.5 py-1.5 text-xs font-semibold"
                                >
                                  连接
                                </button>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </>
              )}
            </div>
          )}

          {/* TAB 2: ORBITAL RADAR & LIVE CONNECTIONS */}
          {tab === "radar" && (
            <OrbitalRadar
              nodes={proxyNodes}
              latencies={latencies}
              activeNodeId={status.running ? status.active_node_id : undefined}
              scanning={scanningOrbit}
              connections={telemetry.recent_connections}
              connected={status.running}
              onScanAll={handleBatchTestLatencies}
              onSelectNode={handleStartNode}
              onCloseConnections={handleCloseConnections}
            />
          )}

          {/* TAB 3: SECURITY, TUN SERVICE & RULES */}
          {tab === "security" && (
            <div className="mq-enter mx-auto max-w-5xl space-y-5">
              {/* Hardened Windows TUN Service Control Card */}
              <section className="mq-panel rounded-2xl p-5">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <Network className="h-4 w-4" style={{ color: "var(--mq-accent)" }} />
                      <h2 className="text-sm font-semibold" style={{ color: "var(--mq-ink)" }}>
                        Windows 安全加固 TUN 虚拟网卡服务（防 LPE 架构）
                      </h2>
                      <span
                        className="rounded-full px-2.5 py-0.5 text-[11px] font-semibold"
                        style={
                          tunService.running
                            ? { backgroundColor: "var(--mq-ok-bg)", color: "var(--mq-ok)" }
                            : tunService.installed
                            ? { backgroundColor: "var(--mq-warn-bg)", color: "var(--mq-warn)" }
                            : { backgroundColor: "var(--mq-subtle)", color: "var(--mq-ink-3)" }
                        }
                      >
                        {tunService.running
                          ? "服务运行中"
                          : tunService.installed
                          ? "已安装 · 未运行"
                          : "未安装"}
                      </span>
                    </div>
                    <p className="mt-1.5 text-xs leading-relaxed" style={{ color: "var(--mq-ink-2)" }}>
                      GUI 始终以普通用户运行；仅 TUN 服务按需提权。采用显式最小权限 Named Pipe SDDL、调用方进程路径白名单校验、
                      `sing-box.exe` 硬编码 SHA-256 核验、全重叠 I/O 超时保护以及 SYSTEM 独占运行目录防 `wintun.dll` 劫持。
                    </p>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={async () => setTunService(await api.getTunServiceStatus())}
                      disabled={tunBusy}
                      className="mq-btn mq-subtle rounded-xl px-3 py-1.5 text-xs font-medium disabled:opacity-50"
                      style={{ color: "var(--mq-ink-2)" }}
                    >
                      <RefreshCw className="h-3.5 w-3.5" />
                    </button>
                    {!tunService.running ? (
                      <button
                        onClick={handleInstallTunService}
                        disabled={tunBusy}
                        className="mq-btn mq-btn-primary rounded-xl px-3.5 py-1.5 text-xs font-semibold disabled:opacity-50"
                      >
                        {tunBusy
                          ? "安装/启动中（等待 UAC）..."
                          : tunService.installed
                          ? "修复并启动 TUN 服务 (UAC)"
                          : "安装并启动 TUN 服务 (UAC)"}
                      </button>
                    ) : (
                      <button
                        onClick={handleUninstallTunService}
                        disabled={tunBusy}
                        className="mq-btn rounded-xl px-3.5 py-1.5 text-xs font-semibold disabled:opacity-50"
                        style={{ backgroundColor: "var(--mq-danger-bg)", color: "var(--mq-danger)" }}
                      >
                        {tunBusy ? "卸载中..." : "卸载 TUN 服务 (UAC)"}
                      </button>
                    )}
                  </div>
                </div>

                {tunService.last_error && !tunService.running && (
                  <div
                    className="mt-3 rounded-xl border px-3.5 py-2.5 text-xs"
                    style={{
                      backgroundColor: "var(--mq-warn-bg)",
                      borderColor: "var(--mq-warn-border)",
                      color: "var(--mq-warn)",
                    }}
                  >
                    <span className="font-semibold">TUN 服务诊断：</span>
                    <span className="font-mono-tabular break-all">{tunService.last_error}</span>
                  </div>
                )}

                <div className="mt-4 grid grid-cols-2 gap-3 text-xs sm:grid-cols-4">
                  {[
                    { label: "Named Pipe ACL", val: "SDDL + 禁远程", ok: true },
                    { label: "调用方进程校验", val: "安装目录白名单", ok: true },
                    {
                      label: "sing-box SHA-256",
                      val: tunService.running
                        ? tunService.singbox_sha256_verified
                          ? "已核验通过"
                          : "校验异常"
                        : "启动前强制核验",
                      ok: !tunService.running || tunService.singbox_sha256_verified,
                    },
                    { label: "wintun 防劫持", val: "SYSTEM 独占目录", ok: true },
                  ].map((item) => (
                    <div key={item.label} className="mq-subtle rounded-xl px-3.5 py-2.5">
                      <div className="text-[11px]" style={{ color: "var(--mq-ink-3)" }}>
                        {item.label}
                      </div>
                      <div
                        className="mt-1 font-semibold"
                        style={{ color: item.ok ? "var(--mq-ok)" : "var(--mq-danger)" }}
                      >
                        {item.val}
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              {/* Built-in Default Rules Engine Card */}
              <section className="mq-panel rounded-2xl p-5">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h2 className="text-sm font-semibold" style={{ color: "var(--mq-ink)" }}>
                      默认内置分流规则库（{builtinRules.rule_count.toLocaleString()} 条规则）
                    </h2>
                    <p className="mt-1 text-xs" style={{ color: "var(--mq-ink-2)" }}>
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
                    className="mq-subtle rounded-xl px-3 py-2 text-xs font-medium focus:outline-none"
                    style={{ color: "var(--mq-ink)" }}
                  >
                    <option value="profile_or_builtin">
                      优先使用导入 .conf 规则（无规则时自动用内置规则）
                    </option>
                    <option value="builtin_default">始终强制使用 MaxQ 内置默认规则</option>
                  </select>
                </div>
              </section>

              {/* Quarantined [Host] Audit Card */}
              <section className="mq-panel rounded-2xl p-5">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <h2 className="text-sm font-semibold" style={{ color: "var(--mq-ink)" }}>
                      `[Host]` 域名映射隔离审计（默认全禁用）
                    </h2>
                    <p className="mt-1 text-xs" style={{ color: "var(--mq-ink-2)" }}>
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
                      className="mq-btn flex items-center gap-1 rounded-xl px-3 py-1.5 text-xs font-semibold"
                      style={{ backgroundColor: "var(--mq-danger-bg)", color: "var(--mq-danger)" }}
                    >
                      <Trash2 className="h-3.5 w-3.5" /> 删除当前配置
                    </button>
                  )}
                </div>

                <div className="mt-4 space-y-2">
                  {(profile?.hosts ?? []).length === 0 ? (
                    <div className="text-xs" style={{ color: "var(--mq-ink-3)" }}>
                      当前配置无 `[Host]` 映射条目。
                    </div>
                  ) : (
                    profile!.hosts.map((h, idx) => (
                      <div
                        key={`${h.domain}-${idx}`}
                        className="mq-subtle flex items-center justify-between rounded-xl px-3.5 py-2.5 text-xs"
                      >
                        <div>
                          <span className="font-mono-tabular font-medium" style={{ color: "var(--mq-ink)" }}>
                            {h.domain} → {h.target}
                          </span>
                          <span
                            className="ml-2 rounded-md px-1.5 py-0.5 text-[10px] font-semibold"
                            style={
                              h.classification === "proxy_endpoint_alias"
                                ? { backgroundColor: "var(--mq-warn-bg)", color: "var(--mq-warn)" }
                                : h.classification === "local_domain"
                                ? { backgroundColor: "var(--mq-card)", color: "var(--mq-ink-2)" }
                                : { backgroundColor: "var(--mq-danger-bg)", color: "var(--mq-danger)" }
                            }
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
                          className="h-4 w-4 accent-[var(--mq-accent)]"
                        />
                      </div>
                    ))
                  )}
                </div>
              </section>
            </div>
          )}

          {/* TAB 4: LIVE KERNEL LOGS */}
          {tab === "logs" && (
            <div className="mq-enter mx-auto max-w-6xl space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="relative">
                  <Search
                    className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5"
                    style={{ color: "var(--mq-ink-3)" }}
                  />
                  <input
                    value={logFilter}
                    onChange={(e) => setLogFilter(e.target.value)}
                    placeholder="过滤日志关键词（如 error / dns / public key）..."
                    className="mq-panel w-72 rounded-xl py-1.5 pl-8 pr-3 text-xs focus:outline-none"
                    style={{ color: "var(--mq-ink)" }}
                  />
                </div>
                <button
                  onClick={async () => {
                    await navigator.clipboard.writeText(filteredLogs.join("\n"));
                    showToast("ok", `已复制 ${filteredLogs.length} 行脱敏日志`);
                  }}
                  className="mq-btn mq-panel flex items-center gap-1.5 rounded-xl px-3 py-1.5 text-xs font-medium"
                  style={{ color: "var(--mq-ink-2)" }}
                >
                  <Copy className="h-3.5 w-3.5" /> 复制日志
                </button>
              </div>

              <div
                className="font-mono-tabular rounded-2xl border p-4 text-xs"
                style={{
                  backgroundColor: "var(--mq-log-bg)",
                  borderColor: "var(--mq-border)",
                  color: "var(--mq-log-ink)",
                  minHeight: 420,
                }}
              >
                {filteredLogs.length === 0 ? (
                  <div className="py-16 text-center opacity-60">
                    暂无运行日志（连接节点后自动流式输出，敏感口令自动脱敏）。
                  </div>
                ) : (
                  filteredLogs.map((line, i) => (
                    <div
                      key={i}
                      className="border-b border-white/5 py-1.5 break-all"
                      style={
                        line.includes("unrecognized remote public key") || line.includes("FATAL")
                          ? { backgroundColor: "rgba(225, 29, 72, 0.25)", color: "#fda4af" }
                          : line.includes("ERROR")
                          ? { color: "#fca5a5" }
                          : undefined
                      }
                    >
                      {line}
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* TAB 5: PREFERENCES, THEME & NETWORK POLICY */}
          {tab === "settings" && (
            <div className="mq-enter mx-auto max-w-3xl space-y-5">
              {/* Theme & Aesthetic Customization */}
              <section className="mq-panel space-y-4 rounded-2xl p-6">
                <div className="flex items-center gap-2">
                  <Palette className="h-4 w-4" style={{ color: "var(--mq-accent)" }} />
                  <h2 className="text-sm font-semibold" style={{ color: "var(--mq-ink)" }}>
                    外观定制 · 扁平灵动浅蓝紫主题
                  </h2>
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  <button
                    onClick={() => setTheme("light")}
                    className="mq-btn flex items-center justify-between rounded-xl border p-3.5 text-left"
                    style={
                      theme === "light"
                        ? { backgroundColor: "var(--mq-accent-soft)", borderColor: "var(--mq-accent)" }
                        : { backgroundColor: "var(--mq-subtle)", borderColor: "var(--mq-border)" }
                    }
                  >
                    <div>
                      <div className="text-xs font-bold" style={{ color: "var(--mq-ink)" }}>
                        晴岚蓝紫 · Light（推荐）
                      </div>
                      <div className="mt-0.5 text-[11px]" style={{ color: "var(--mq-ink-2)" }}>
                        清透瓷白 + 柔雾浅蓝紫，清爽灵动
                      </div>
                    </div>
                    <Sun className="h-4 w-4" style={{ color: "var(--mq-accent)" }} />
                  </button>

                  <button
                    onClick={() => setTheme("dark")}
                    className="mq-btn flex items-center justify-between rounded-xl border p-3.5 text-left"
                    style={
                      theme === "dark"
                        ? { backgroundColor: "var(--mq-accent-soft)", borderColor: "var(--mq-accent)" }
                        : { backgroundColor: "var(--mq-subtle)", borderColor: "var(--mq-border)" }
                    }
                  >
                    <div>
                      <div className="text-xs font-bold" style={{ color: "var(--mq-ink)" }}>
                        暮色鸢尾 · Twilight
                      </div>
                      <div className="mt-0.5 text-[11px]" style={{ color: "var(--mq-ink-2)" }}>
                        柔和靛蓝夜色，夜间低眩光护眼
                      </div>
                    </div>
                    <Moon className="h-4 w-4" style={{ color: "var(--mq-accent-2)" }} />
                  </button>
                </div>

                <div>
                  <div className="mb-2 text-xs font-medium" style={{ color: "var(--mq-ink-2)" }}>
                    主色氛围调色盘
                  </div>
                  <div className="grid grid-cols-3 gap-2.5">
                    {(
                      [
                        { id: "periwinkle", name: "晴岚蓝紫", c1: "#6B7CFF", c2: "#9281FF" },
                        { id: "glacier", name: "冰川雾蓝", c1: "#5588FF", c2: "#769EFF" },
                        { id: "lilac", name: "丁香浅紫", c1: "#8574FF", c2: "#A98BFF" },
                      ] as Array<{ id: AccentFlavor; name: string; c1: string; c2: string }>
                    ).map((fl) => (
                      <button
                        key={fl.id}
                        onClick={() => setAccent(fl.id)}
                        className="mq-btn flex items-center gap-2.5 rounded-xl border px-3 py-2.5 text-xs font-semibold"
                        style={
                          accent === fl.id
                            ? {
                                backgroundColor: "var(--mq-accent-soft)",
                                borderColor: "var(--mq-accent)",
                                color: "var(--mq-accent-ink)",
                              }
                            : {
                                backgroundColor: "var(--mq-subtle)",
                                borderColor: "var(--mq-border)",
                                color: "var(--mq-ink-2)",
                              }
                        }
                      >
                        <span
                          className="h-4 w-4 rounded-full"
                          style={{ background: `linear-gradient(135deg, ${fl.c1}, ${fl.c2})` }}
                        />
                        {fl.name}
                      </button>
                    ))}
                  </div>
                </div>
              </section>

              {/* Direct Anti-Leak & Ports */}
              <section className="mq-panel space-y-5 rounded-2xl p-6">
                <div>
                  <h2 className="text-sm font-semibold" style={{ color: "var(--mq-ink)" }}>
                    直连防泄漏与本地端口策略
                  </h2>
                  <p className="mt-1 text-xs" style={{ color: "var(--mq-ink-2)" }}>
                    外部 `.conf` 与订阅无法覆盖以下任何安全边界设置。
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs font-medium" style={{ color: "var(--mq-ink-2)" }}>
                      Mixed 代理端口 (127.0.0.1)
                    </label>
                    <input
                      type="number"
                      value={policy.mixed_listen_port}
                      onChange={(e) =>
                        setPolicy({ ...policy, mixed_listen_port: Number(e.target.value) })
                      }
                      className="font-mono-tabular mq-subtle mt-1 w-full rounded-xl px-3.5 py-2 text-sm focus:outline-none"
                      style={{ color: "var(--mq-ink)" }}
                    />
                  </div>
                  <div>
                    <label className="text-xs font-medium" style={{ color: "var(--mq-ink-2)" }}>
                      Clash API 端口 (随机 32B Bearer)
                    </label>
                    <input
                      type="number"
                      value={policy.clash_api_port}
                      onChange={(e) =>
                        setPolicy({ ...policy, clash_api_port: Number(e.target.value) })
                      }
                      className="font-mono-tabular mq-subtle mt-1 w-full rounded-xl px-3.5 py-2 text-sm focus:outline-none"
                      style={{ color: "var(--mq-ink)" }}
                    />
                  </div>
                </div>

                <div>
                  <label className="text-xs font-medium" style={{ color: "var(--mq-ink-2)" }}>
                    IPv6 防旁路泄漏策略
                  </label>
                  <select
                    value={policy.ipv6_mode}
                    onChange={(e) =>
                      setPolicy({
                        ...policy,
                        ipv6_mode: e.target.value as RuntimePolicy["ipv6_mode"],
                      })
                    }
                    className="mq-subtle mt-1 w-full rounded-xl px-3.5 py-2 text-sm focus:outline-none"
                    style={{ color: "var(--mq-ink)" }}
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
                    <label className="text-xs font-medium" style={{ color: "var(--mq-ink-2)" }}>
                      远端 DoH DNS（强制 detour=proxy）
                    </label>
                    <input
                      value={policy.remote_dns_server}
                      onChange={(e) => setPolicy({ ...policy, remote_dns_server: e.target.value })}
                      className="font-mono-tabular mq-subtle mt-1 w-full rounded-xl px-3.5 py-2 text-sm focus:outline-none"
                      style={{ color: "var(--mq-ink)" }}
                    />
                  </div>
                  <div>
                    <label className="text-xs font-medium" style={{ color: "var(--mq-ink-2)" }}>
                      直连 / Bootstrap DNS
                    </label>
                    <input
                      value={policy.direct_dns_server}
                      onChange={(e) => setPolicy({ ...policy, direct_dns_server: e.target.value })}
                      className="font-mono-tabular mq-subtle mt-1 w-full rounded-xl px-3.5 py-2 text-sm focus:outline-none"
                      style={{ color: "var(--mq-ink)" }}
                    />
                  </div>
                </div>

                <div className="flex justify-end pt-1">
                  <button
                    onClick={() => applyPolicyChange({}, true)}
                    className="mq-btn mq-btn-primary rounded-xl px-5 py-2 text-xs font-semibold"
                  >
                    保存并应用策略
                  </button>
                </div>
              </section>
            </div>
          )}

          {/* TAB 6: ABOUT MAXQ */}
          {tab === "about" && (
            <AboutView
              about={aboutInfo}
              soundEnabled={soundEnabled}
              onToggleSound={() => setSoundEnabled((s) => !s)}
              onTriggerLaunch={triggerLaunch}
              onCopyDiagnostics={handleCopyDiagnostics}
            />
          )}
        </main>
      </div>

      {/* Modals, Drawers & Playful Overlays */}
      <ImportModal
        open={importOpen}
        onClose={() => setImportOpen(false)}
        importMethod={importMethod}
        setImportMethod={setImportMethod}
        importName={importName}
        setImportName={setImportName}
        importText={importText}
        setImportText={setImportText}
        subUrl={subUrl}
        setSubUrl={setSubUrl}
        preview={preview}
        setPreview={setPreview}
        approvedHostDomains={approvedHostDomains}
        setApprovedHostDomains={setApprovedHostDomains}
        busy={busy}
        onFetchSubUrl={handleFetchSubUrl}
        onPreviewImport={handlePreviewImport}
        onCommitImport={handleCommitImport}
      />

      <ProbeDrawer
        node={inspectNode}
        probeResult={probeResult}
        probeLoading={probeLoading}
        probeError={probeError}
        onClose={() => setInspectNode(null)}
        onReprobe={handleProbeNode}
        onConfirmPin={handleConfirmPin}
        onTemporaryOverride={handleTemporaryOverride}
      />

      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        nodes={proxyNodes}
        theme={theme}
        onConnectNode={handleStartNode}
        onSwitchRouting={(m) => applyPolicyChange({ routing_mode: m }, true)}
        onToggleTheme={() => setTheme((t) => (t === "light" ? "dark" : "light"))}
        onTriggerLaunch={triggerLaunch}
        onNavigate={(nextTab) => setTab(nextTab)}
      />

      <LaunchEasterEgg launchKey={launchKey} />
    </div>
  );
}
