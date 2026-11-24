import { useMemo, useState } from "react";
import { Compass, Eraser, Play, Radar, RefreshCw, ShieldCheck } from "lucide-react";
import type { LiveConnectionItem, NodeConfig } from "../types";
import { formatBytes } from "./TelemetryRibbon";

interface OrbitalRadarProps {
  nodes: NodeConfig[];
  latencies: Record<string, number | "err" | "loading">;
  activeNodeId?: string;
  scanning: boolean;
  connections: LiveConnectionItem[];
  connected: boolean;
  onScanAll: () => void;
  onSelectNode: (node: NodeConfig) => void;
  onCloseConnections: () => void;
}

interface OrbitDot {
  node: NodeConfig;
  x: number;
  y: number;
  lat: number | "err" | "loading" | undefined;
  color: string;
  orbitLabel: string;
}

function stableAngle(id: string, index: number, total: number): number {
  let h = 2166136261;
  for (let i = 0; i < id.length; i++) {
    h ^= id.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  const base = (index / Math.max(1, total)) * Math.PI * 2;
  const jitter = ((h >>> 0) % 100) / 1000 - 0.05;
  return base + jitter;
}

export function OrbitalRadar({
  nodes,
  latencies,
  activeNodeId,
  scanning,
  connections,
  connected,
  onScanAll,
  onSelectNode,
  onCloseConnections,
}: OrbitalRadarProps) {
  const [hovered, setHovered] = useState<OrbitDot | null>(null);

  const dots = useMemo<OrbitDot[]>(() => {
    const cx = 160;
    const cy = 160;
    return nodes.slice(0, 36).map((node, idx) => {
      const lat = latencies[node.id];
      const angle = stableAngle(node.id, idx, Math.min(nodes.length, 36));
      let radius = 128;
      let color = "#8E97C2";
      let orbitLabel = "待测速轨道";

      if (typeof lat === "number") {
        if (lat < 80) {
          radius = 38 + (lat / 80) * 26;
          color = "#10B981";
          orbitLabel = "LEO 近地低延迟";
        } else if (lat < 180) {
          radius = 68 + ((lat - 80) / 100) * 32;
          color = "#6B7CFF";
          orbitLabel = "MEO 标准轨道";
        } else {
          radius = 104 + Math.min(1, (lat - 180) / 300) * 30;
          color = "#D97706";
          orbitLabel = "GEO 远地高延迟";
        }
      } else if (lat === "err") {
        radius = 140;
        color = "#E11D48";
        orbitLabel = "超时 / 不可达";
      }

      return {
        node,
        x: cx + Math.cos(angle) * radius,
        y: cy + Math.sin(angle) * radius,
        lat,
        color,
        orbitLabel,
      };
    });
  }, [nodes, latencies]);

  const fastest = useMemo(() => {
    let best: { node: NodeConfig; ms: number } | null = null;
    for (const n of nodes) {
      const lat = latencies[n.id];
      if (typeof lat === "number" && (!best || lat < best.ms)) {
        best = { node: n, ms: lat };
      }
    }
    return best;
  }, [nodes, latencies]);

  return (
    <div className="mq-enter mx-auto grid max-w-6xl gap-5 lg:grid-cols-12">
      {/* Left: Interactive Flat Orbital Latency Radar */}
      <section className="mq-panel flex flex-col justify-between rounded-2xl p-5 lg:col-span-6">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <div className="flex items-center gap-2">
              <Radar className="h-4 w-4" style={{ color: "var(--mq-accent)" }} />
              <h2 className="text-sm font-semibold" style={{ color: "var(--mq-ink)" }}>
                Max-Q 星轨延迟雷达
              </h2>
            </div>
            <p className="mt-1 text-xs" style={{ color: "var(--mq-ink-2)" }}>
              延迟越低越靠近核心轨道，点击任意卫星节点即可一键切线连接。
            </p>
          </div>
          <button
            onClick={onScanAll}
            disabled={scanning || nodes.length === 0}
            className="mq-btn mq-btn-primary flex items-center gap-1.5 rounded-xl px-3.5 py-2 text-xs font-semibold disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${scanning ? "animate-spin" : ""}`} />
            {scanning ? "全轨扫描中..." : "全轨并发测速"}
          </button>
        </div>

        <div className="relative my-3 flex items-center justify-center">
          <svg
            viewBox="0 0 320 320"
            className="h-72 w-72 select-none sm:h-80 sm:w-80"
            role="img"
            aria-label="MaxQ Orbital Latency Radar"
          >
            <defs>
              <linearGradient id="mqSweepGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="var(--mq-accent)" stopOpacity="0.28" />
                <stop offset="100%" stopColor="var(--mq-accent-2)" stopOpacity="0" />
              </linearGradient>
            </defs>

            {/* Concentric Flat Orbit Rings */}
            {[140, 102, 66, 34].map((r, i) => (
              <circle
                key={r}
                cx="160"
                cy="160"
                r={r}
                fill={i === 3 ? "var(--mq-accent-soft)" : "none"}
                fillOpacity={i === 3 ? 0.55 : 0}
                stroke="var(--mq-border-strong)"
                strokeDasharray={i === 0 ? "3 4" : undefined}
                strokeWidth="1"
              />
            ))}

            {/* Crosshairs */}
            <line x1="20" y1="160" x2="300" y2="160" stroke="var(--mq-border)" strokeWidth="1" />
            <line x1="160" y1="20" x2="160" y2="300" stroke="var(--mq-border)" strokeWidth="1" />

            {/* Orbit Labels */}
            <text x="164" y="99" fontSize="9" fill="var(--mq-ink-3)" className="font-mono-tabular">
              80ms
            </text>
            <text x="164" y="63" fontSize="9" fill="var(--mq-ink-3)" className="font-mono-tabular">
              180ms
            </text>
            <text x="164" y="26" fontSize="9" fill="var(--mq-ink-3)" className="font-mono-tabular">
              DEEP
            </text>

            {/* Sweeping Radar Beam when scanning or connected */}
            {(scanning || connected) && (
              <g className="mq-radar-sweep" opacity={scanning ? 0.95 : 0.35}>
                <path
                  d="M160 160 L160 20 A140 140 0 0 1 268 72 Z"
                  fill="url(#mqSweepGrad)"
                />
                <line
                  x1="160"
                  y1="160"
                  x2="160"
                  y2="20"
                  stroke="var(--mq-accent)"
                  strokeWidth="1.5"
                />
              </g>
            )}

            {/* Core MaxQ Hub */}
            <circle cx="160" cy="160" r="10" fill="var(--mq-accent)" />
            <text
              x="160"
              y="163.5"
              textAnchor="middle"
              fontSize="9"
              fontWeight="700"
              fill="#FFFFFF"
            >
              Q
            </text>

            {/* Node Satellites */}
            {dots.map((dot) => {
              const isActive = dot.node.id === activeNodeId;
              const isHover = hovered?.node.id === dot.node.id;
              return (
                <g
                  key={dot.node.id}
                  onMouseEnter={() => setHovered(dot)}
                  onMouseLeave={() => setHovered(null)}
                  onClick={() => onSelectNode(dot.node)}
                  className="cursor-pointer"
                >
                  {isActive && (
                    <circle
                      cx={dot.x}
                      cy={dot.y}
                      r="11"
                      fill="none"
                      stroke="var(--mq-accent)"
                      strokeWidth="2"
                    />
                  )}
                  <circle
                    cx={dot.x}
                    cy={dot.y}
                    r={isActive || isHover ? 6.5 : 4.8}
                    fill={isActive ? "var(--mq-accent)" : dot.color}
                    stroke="var(--mq-card)"
                    strokeWidth="1.8"
                  />
                </g>
              );
            })}
          </svg>
        </div>

        {/* Bottom Inspection Strip */}
        <div className="mq-subtle flex min-h-[56px] items-center justify-between gap-3 rounded-xl px-3.5 py-2.5 text-xs">
          {hovered ? (
            <>
              <div className="min-w-0">
                <div className="truncate font-semibold" style={{ color: "var(--mq-ink)" }}>
                  {hovered.node.name}
                </div>
                <div className="font-mono-tabular text-[11px]" style={{ color: "var(--mq-ink-2)" }}>
                  {hovered.orbitLabel} ·{" "}
                  {typeof hovered.lat === "number"
                    ? `${hovered.lat} ms`
                    : hovered.lat === "err"
                    ? "超时"
                    : "未测速"}
                </div>
              </div>
              <span
                className="flex shrink-0 items-center gap-1 rounded-lg px-2.5 py-1 text-[11px] font-medium"
                style={{ backgroundColor: "var(--mq-accent-soft)", color: "var(--mq-accent-ink)" }}
              >
                <Play className="h-3 w-3" /> 点击连接
              </span>
            </>
          ) : fastest ? (
            <>
              <div className="min-w-0">
                <div className="flex items-center gap-1.5 text-[11px]" style={{ color: "var(--mq-ink-3)" }}>
                  <Compass className="h-3.5 w-3.5" style={{ color: "var(--mq-ok)" }} /> 当前最快推荐节点
                </div>
                <div className="truncate font-semibold" style={{ color: "var(--mq-ink)" }}>
                  {fastest.node.name} ·{" "}
                  <span className="font-mono-tabular" style={{ color: "var(--mq-ok)" }}>
                    {fastest.ms} ms
                  </span>
                </div>
              </div>
              <button
                onClick={() => onSelectNode(fastest.node)}
                className="mq-btn shrink-0 rounded-lg px-3 py-1.5 text-xs font-semibold"
                style={{ backgroundColor: "var(--mq-accent-soft)", color: "var(--mq-accent-ink)" }}
              >
                直连最快
              </button>
            </>
          ) : (
            <div style={{ color: "var(--mq-ink-3)" }}>
              点击右上角「全轨并发测速」将所有节点按真实 TCP 握手延迟绘入星轨。
            </div>
          )}
        </div>
      </section>

      {/* Right: Real-Time Active Connections Stream from Rust Clash API */}
      <section className="mq-panel flex flex-col rounded-2xl p-5 lg:col-span-6">
        <div className="flex items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold" style={{ color: "var(--mq-ink)" }}>
              实时分流连接流（{connections.length}）
            </h2>
            <p className="mt-1 text-xs" style={{ color: "var(--mq-ink-2)" }}>
              由 Rust 后端直连回环 Clash API 拉取，WebView 零密钥暴露。
            </p>
          </div>
          {connected && (
            <button
              onClick={onCloseConnections}
              className="mq-btn mq-subtle flex items-center gap-1.5 rounded-xl px-3 py-1.5 text-xs font-medium"
              style={{ color: "var(--mq-ink-2)" }}
            >
              <Eraser className="h-3.5 w-3.5" /> 释放全部连接
            </button>
          )}
        </div>

        <div className="mt-4 flex-1 space-y-2 overflow-y-auto pr-1" style={{ maxHeight: 390 }}>
          {!connected ? (
            <div className="mq-subtle flex h-64 flex-col items-center justify-center rounded-xl text-center text-xs" style={{ color: "var(--mq-ink-3)" }}>
              <ShieldCheck className="mb-2 h-7 w-7 opacity-60" style={{ color: "var(--mq-accent)" }} />
              连接任意节点后，此处将实时展示每一条流量的分流去向（代理 / 直连）。
            </div>
          ) : connections.length === 0 ? (
            <div className="mq-subtle flex h-64 items-center justify-center rounded-xl text-xs" style={{ color: "var(--mq-ink-3)" }}>
              当前暂无活跃连接，浏览网页或终端请求时会自动出现。
            </div>
          ) : (
            connections.map((c, i) => {
              const isProxy = c.chain.toLowerCase().includes("proxy");
              return (
                <div
                  key={`${c.id}-${i}`}
                  className="mq-subtle flex items-center justify-between gap-3 rounded-xl px-3.5 py-2.5 text-xs"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span
                        className="rounded-md px-1.5 py-0.5 text-[10px] font-semibold uppercase"
                        style={{
                          backgroundColor: isProxy ? "var(--mq-accent-soft)" : "var(--mq-ok-bg)",
                          color: isProxy ? "var(--mq-accent-ink)" : "var(--mq-ok)",
                        }}
                      >
                        {isProxy ? "PROXY" : "DIRECT"}
                      </span>
                      <span className="font-mono-tabular truncate font-medium" style={{ color: "var(--mq-ink)" }}>
                        {c.host}
                        {c.port ? `:${c.port}` : ""}
                      </span>
                    </div>
                    <div className="mt-1 flex items-center gap-2 text-[11px]" style={{ color: "var(--mq-ink-3)" }}>
                      <span className="uppercase">{c.network}</span>
                      <span>·</span>
                      <span className="truncate">规则：{c.rule}</span>
                    </div>
                  </div>
                  <div className="font-mono-tabular shrink-0 text-right text-[11px]" style={{ color: "var(--mq-ink-2)" }}>
                    <div>↓ {formatBytes(c.download)}</div>
                    <div style={{ color: "var(--mq-ink-3)" }}>↑ {formatBytes(c.upload)}</div>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </section>
    </div>
  );
}
