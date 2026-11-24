import { ArrowDown, ArrowUp, Eraser, Gauge, Radio, Timer } from "lucide-react";
import type { RuntimeTelemetry } from "../types";

export interface SpeedSample {
  up: number;
  down: number;
}

interface TelemetryRibbonProps {
  connected: boolean;
  activeNodeName?: string;
  tunActive: boolean;
  telemetry: RuntimeTelemetry;
  history: SpeedSample[];
  onCloseConnections: () => void;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function formatRate(bps: number): string {
  return `${formatBytes(bps)}/s`;
}

function formatUptime(secs: number): string {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  return `T+${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

function pressurePhase(q: number, connected: boolean): { label: string; color: string } {
  if (!connected) return { label: "STANDBY · 待命", color: "var(--mq-ink-3)" };
  if (q >= 72) return { label: "MAX-Q PEAK · 突破最大动压", color: "var(--mq-accent-ink)" };
  if (q >= 35) return { label: "TRANSONIC · 高速巡航", color: "var(--mq-accent)" };
  return { label: "ORBIT NOMINAL · 平稳在轨", color: "var(--mq-ok)" };
}

function buildAreaPath(values: number[], maxVal: number, w: number, h: number): string {
  if (values.length < 2) return "";
  const stepX = w / (values.length - 1);
  const pts = values.map((v, i) => {
    const x = i * stepX;
    const norm = maxVal > 0 ? Math.min(1, v / maxVal) : 0;
    const y = h - 4 - norm * (h - 10);
    return { x, y };
  });

  let d = `M ${pts[0].x.toFixed(1)} ${pts[0].y.toFixed(1)}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const midX = ((pts[i].x + pts[i + 1].x) / 2).toFixed(1);
    d += ` C ${midX} ${pts[i].y.toFixed(1)}, ${midX} ${pts[i + 1].y.toFixed(1)}, ${pts[i + 1].x.toFixed(1)} ${pts[i + 1].y.toFixed(1)}`;
  }
  return d;
}

export function TelemetryRibbon({
  connected,
  activeNodeName,
  tunActive,
  telemetry,
  history,
  onCloseConnections,
}: TelemetryRibbonProps) {
  const w = 360;
  const h = 64;
  const downVals = history.map((s) => s.down);
  const upVals = history.map((s) => s.up);
  const peak = Math.max(4096, ...downVals, ...upVals);

  const downLine = buildAreaPath(downVals, peak, w, h);
  const downArea = downLine ? `${downLine} L ${w} ${h} L 0 ${h} Z` : "";
  const upLine = buildAreaPath(upVals, peak, w, h);

  const q = Math.round(connected ? telemetry.dynamic_pressure_q : 0);
  const phase = pressurePhase(q, connected);

  return (
    <section className="mq-panel mq-enter rounded-2xl p-4">
      <div className="flex flex-wrap items-center justify-between gap-4">
        {/* Left: Live Aerodynamic Status & Throughput Metrics */}
        <div className="min-w-0 flex-1 space-y-2.5">
          <div className="flex flex-wrap items-center gap-2">
            <span className="relative flex h-2.5 w-2.5 items-center justify-center">
              {connected && (
                <span
                  className="mq-pulse-ring absolute inline-flex h-full w-full rounded-full"
                  style={{ backgroundColor: "var(--mq-ok)" }}
                />
              )}
              <span
                className="relative inline-flex h-2 w-2 rounded-full"
                style={{ backgroundColor: connected ? "var(--mq-ok)" : "var(--mq-ink-3)" }}
              />
            </span>
            <span className="text-xs font-semibold tracking-tight" style={{ color: "var(--mq-ink)" }}>
              {connected ? activeNodeName || "已连接" : "未连接 · 随时起飞"}
            </span>
            <span
              className="rounded-full px-2 py-0.5 text-[11px] font-medium"
              style={{
                backgroundColor: connected ? "var(--mq-accent-soft)" : "var(--mq-subtle)",
                color: phase.color,
              }}
            >
              {phase.label}
            </span>
            {connected && (
              <span
                className="rounded-full px-2 py-0.5 text-[11px] font-medium"
                style={{
                  backgroundColor: tunActive ? "var(--mq-ok-bg)" : "var(--mq-subtle)",
                  color: tunActive ? "var(--mq-ok)" : "var(--mq-ink-2)",
                }}
              >
                {tunActive ? "TUN 虚拟网卡" : "系统代理"}
              </span>
            )}
          </div>

          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <div className="mq-subtle rounded-xl px-3 py-2">
              <div className="flex items-center gap-1 text-[11px]" style={{ color: "var(--mq-ink-3)" }}>
                <ArrowDown className="h-3 w-3" style={{ color: "var(--mq-accent)" }} /> 下行速率
              </div>
              <div className="font-mono-tabular mt-0.5 text-sm font-semibold" style={{ color: "var(--mq-ink)" }}>
                {formatRate(connected ? telemetry.download_bps : 0)}
              </div>
              <div className="font-mono-tabular text-[10px]" style={{ color: "var(--mq-ink-3)" }}>
                累计 {formatBytes(telemetry.download_total)}
              </div>
            </div>

            <div className="mq-subtle rounded-xl px-3 py-2">
              <div className="flex items-center gap-1 text-[11px]" style={{ color: "var(--mq-ink-3)" }}>
                <ArrowUp className="h-3 w-3" style={{ color: "var(--mq-accent-2)" }} /> 上行速率
              </div>
              <div className="font-mono-tabular mt-0.5 text-sm font-semibold" style={{ color: "var(--mq-ink)" }}>
                {formatRate(connected ? telemetry.upload_bps : 0)}
              </div>
              <div className="font-mono-tabular text-[10px]" style={{ color: "var(--mq-ink-3)" }}>
                累计 {formatBytes(telemetry.upload_total)}
              </div>
            </div>

            <div className="mq-subtle rounded-xl px-3 py-2">
              <div className="flex items-center gap-1 text-[11px]" style={{ color: "var(--mq-ink-3)" }}>
                <Gauge className="h-3 w-3" style={{ color: "var(--mq-accent)" }} /> 动压指数 Max-Q
              </div>
              <div className="mt-1 flex items-center gap-2">
                <span className="font-mono-tabular text-sm font-semibold" style={{ color: "var(--mq-ink)" }}>
                  {q}%
                </span>
                <div
                  className="h-1.5 flex-1 overflow-hidden rounded-full"
                  style={{ backgroundColor: "var(--mq-border)" }}
                >
                  <div
                    className="h-full rounded-full transition-all duration-300"
                    style={{
                      width: `${Math.max(connected ? 8 : 0, q)}%`,
                      background: "linear-gradient(90deg, var(--mq-accent), var(--mq-accent-2))",
                    }}
                  />
                </div>
              </div>
              <div className="font-mono-tabular mt-0.5 flex items-center gap-1 text-[10px]" style={{ color: "var(--mq-ink-3)" }}>
                <Timer className="h-2.5 w-2.5" /> {formatUptime(connected ? telemetry.uptime_secs : 0)}
              </div>
            </div>

            <div className="mq-subtle flex flex-col justify-between rounded-xl px-3 py-2">
              <div className="flex items-center justify-between text-[11px]" style={{ color: "var(--mq-ink-3)" }}>
                <span className="flex items-center gap-1">
                  <Radio className="h-3 w-3" style={{ color: "var(--mq-ok)" }} /> 活跃连接
                </span>
                {connected && (
                  <button
                    onClick={onCloseConnections}
                    title="释放所有旧连接（切换规则后常用）"
                    className="mq-btn rounded px-1 py-0.5 text-[10px] hover:opacity-80"
                    style={{ backgroundColor: "var(--mq-accent-soft)", color: "var(--mq-accent-ink)" }}
                  >
                    <Eraser className="h-3 w-3" />
                  </button>
                )}
              </div>
              <div className="font-mono-tabular text-sm font-semibold" style={{ color: "var(--mq-ink)" }}>
                {connected ? telemetry.active_connections : 0} 条
              </div>
              <div className="text-[10px]" style={{ color: "var(--mq-ink-3)" }}>
                Clash API 实时直连
              </div>
            </div>
          </div>
        </div>

        {/* Right: Flat Live SVG Waveform */}
        <div className="mq-subtle flex w-full flex-col justify-between rounded-xl p-3 lg:w-72">
          <div className="flex items-center justify-between text-[11px]" style={{ color: "var(--mq-ink-3)" }}>
            <span className="font-medium">实时流量气动波形</span>
            <span className="font-mono-tabular">峰值 {formatRate(peak)}</span>
          </div>
          <svg
            viewBox={`0 0 ${w} ${h}`}
            className="mt-1.5 h-16 w-full overflow-visible"
            preserveAspectRatio="none"
          >
            <defs>
              <linearGradient id="mqWaveGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--mq-accent)" stopOpacity="0.28" />
                <stop offset="100%" stopColor="var(--mq-accent)" stopOpacity="0.01" />
              </linearGradient>
            </defs>
            <line
              x1="0"
              y1={h - 2}
              x2={w}
              y2={h - 2}
              stroke="var(--mq-border)"
              strokeWidth="1"
            />
            {downArea && <path d={downArea} fill="url(#mqWaveGrad)" />}
            {downLine && (
              <path
                d={downLine}
                fill="none"
                stroke="var(--mq-accent)"
                strokeWidth="2.2"
                strokeLinecap="round"
              />
            )}
            {upLine && (
              <path
                d={upLine}
                fill="none"
                stroke="var(--mq-accent-2)"
                strokeWidth="1.6"
                strokeDasharray="4 4"
                strokeLinecap="round"
              />
            )}
          </svg>
        </div>
      </div>
    </section>
  );
}
