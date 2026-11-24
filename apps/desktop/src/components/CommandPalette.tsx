import { useEffect, useMemo, useRef, useState } from "react";
import { Command, Globe, Moon, Network, Rocket, Search, Shield, Sun, X } from "lucide-react";
import type { NodeConfig, RoutingMode, ThemeMode } from "../types";

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  nodes: NodeConfig[];
  theme: ThemeMode;
  onConnectNode: (node: NodeConfig) => void;
  onSwitchRouting: (mode: RoutingMode) => void;
  onToggleTheme: () => void;
  onTriggerLaunch: () => void;
  onNavigate: (tab: "nodes" | "radar" | "security" | "logs" | "settings" | "about") => void;
}

interface PaletteItem {
  id: string;
  group: string;
  label: string;
  hint: string;
  run: () => void;
  icon: "node" | "route" | "theme" | "launch" | "nav";
}

export function CommandPalette({
  open,
  onClose,
  nodes,
  theme,
  onConnectNode,
  onSwitchRouting,
  onToggleTheme,
  onTriggerLaunch,
  onNavigate,
}: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setQuery("");
      setTimeout(() => inputRef.current?.focus(), 20);
    }
  }, [open]);

  const items = useMemo<PaletteItem[]>(() => {
    const actions: PaletteItem[] = [
      {
        id: "route-rule",
        group: "快捷操作",
        label: "切换路由模式：规则分流（内置 8,581 条规则）",
        hint: "Rule",
        icon: "route",
        run: () => onSwitchRouting("rule"),
      },
      {
        id: "route-global",
        group: "快捷操作",
        label: "切换路由模式：全局代理",
        hint: "Global",
        icon: "route",
        run: () => onSwitchRouting("global"),
      },
      {
        id: "route-direct",
        group: "快捷操作",
        label: "切换路由模式：全部直连",
        hint: "Direct",
        icon: "route",
        run: () => onSwitchRouting("direct"),
      },
      {
        id: "toggle-theme",
        group: "外观与彩蛋",
        label: theme === "light" ? "切换为暮色鸢尾深色主题" : "切换为晴岚浅蓝紫浅色主题",
        hint: "Theme",
        icon: "theme",
        run: onToggleTheme,
      },
      {
        id: "launch-egg",
        group: "外观与彩蛋",
        label: "触发 Max-Q 升空彩蛋序列",
        hint: "Easter Egg",
        icon: "launch",
        run: onTriggerLaunch,
      },
      {
        id: "nav-radar",
        group: "页面导航",
        label: "前往：星轨测速雷达与实时连接",
        hint: "Radar",
        icon: "nav",
        run: () => onNavigate("radar"),
      },
      {
        id: "nav-security",
        group: "页面导航",
        label: "前往：证书与安全中心（TUN 服务 / Host 隔离）",
        hint: "Security",
        icon: "nav",
        run: () => onNavigate("security"),
      },
      {
        id: "nav-about",
        group: "页面导航",
        label: "前往：关于 MaxQ（JaxCore · JucStudio Neon）",
        hint: "About",
        icon: "nav",
        run: () => onNavigate("about"),
      },
    ];

    const nodeItems: PaletteItem[] = nodes.slice(0, 40).map((n) => ({
      id: `node-${n.id}`,
      group: "一键连接节点",
      label: n.name,
      hint: `${n.server}:${n.server_port}`,
      icon: "node",
      run: () => onConnectNode(n),
    }));

    const q = query.trim().toLowerCase();
    const merged = [...actions, ...nodeItems];
    if (!q) return merged.slice(0, 14);
    return merged
      .filter(
        (it) =>
          it.label.toLowerCase().includes(q) ||
          it.hint.toLowerCase().includes(q) ||
          it.group.toLowerCase().includes(q)
      )
      .slice(0, 14);
  }, [nodes, query, theme, onConnectNode, onSwitchRouting, onToggleTheme, onTriggerLaunch, onNavigate]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/30 p-4 pt-20 backdrop-blur-[2px]"
      onClick={onClose}
    >
      <div
        className="mq-panel mq-enter w-full max-w-lg overflow-hidden rounded-2xl shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div
          className="flex items-center gap-2.5 border-b px-4 py-3"
          style={{ borderColor: "var(--mq-border)" }}
        >
          <Search className="h-4 w-4 shrink-0" style={{ color: "var(--mq-accent)" }} />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape") onClose();
              if (e.key === "Enter" && items[0]) {
                items[0].run();
                onClose();
              }
            }}
            placeholder="搜索节点、切换分流模式、外观或彩蛋..."
            className="w-full bg-transparent text-sm focus:outline-none"
            style={{ color: "var(--mq-ink)" }}
          />
          <button onClick={onClose} className="rounded-lg p-1" style={{ color: "var(--mq-ink-3)" }}>
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="max-h-80 space-y-1 overflow-y-auto p-2">
          {items.length === 0 ? (
            <div className="py-10 text-center text-xs" style={{ color: "var(--mq-ink-3)" }}>
              未找到匹配项
            </div>
          ) : (
            items.map((item) => (
              <button
                key={item.id}
                onClick={() => {
                  item.run();
                  onClose();
                }}
                className="mq-btn flex w-full items-center justify-between gap-3 rounded-xl px-3 py-2 text-left text-xs hover:bg-[var(--mq-hover)]"
              >
                <div className="flex min-w-0 items-center gap-2.5">
                  <span
                    className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg"
                    style={{ backgroundColor: "var(--mq-accent-soft)", color: "var(--mq-accent-ink)" }}
                  >
                    {item.icon === "node" ? (
                      <Network className="h-3.5 w-3.5" />
                    ) : item.icon === "route" ? (
                      <Globe className="h-3.5 w-3.5" />
                    ) : item.icon === "theme" ? (
                      theme === "light" ? <Moon className="h-3.5 w-3.5" /> : <Sun className="h-3.5 w-3.5" />
                    ) : item.icon === "launch" ? (
                      <Rocket className="h-3.5 w-3.5" />
                    ) : (
                      <Shield className="h-3.5 w-3.5" />
                    )}
                  </span>
                  <div className="min-w-0">
                    <div className="truncate font-medium" style={{ color: "var(--mq-ink)" }}>
                      {item.label}
                    </div>
                    <div className="text-[10px]" style={{ color: "var(--mq-ink-3)" }}>
                      {item.group}
                    </div>
                  </div>
                </div>
                <span className="font-mono-tabular shrink-0 text-[11px]" style={{ color: "var(--mq-ink-3)" }}>
                  {item.hint}
                </span>
              </button>
            ))
          )}
        </div>

        <div
          className="flex items-center justify-between border-t px-4 py-2 text-[11px]"
          style={{ borderColor: "var(--mq-border)", color: "var(--mq-ink-3)" }}
        >
          <span className="flex items-center gap-1">
            <Command className="h-3 w-3" /> MaxQ 快捷指令面板
          </span>
          <span>Enter 执行 · Esc 关闭</span>
        </div>
      </div>
    </div>
  );
}
