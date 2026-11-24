import { useState } from "react";
import {
  Check,
  Copy,
  Cpu,
  Fingerprint,
  Heart,
  Layers,
  Lock,
  Rocket,
  ShieldCheck,
  Sparkles,
  Volume2,
  VolumeX,
} from "lucide-react";
import type { AboutInfo } from "../types";
import { MaxQLogo } from "./MaxQLogo";
import { SpkiSigil } from "./SpkiSigil";

interface AboutViewProps {
  about: AboutInfo;
  soundEnabled: boolean;
  onToggleSound: () => void;
  onTriggerLaunch: () => void;
  onCopyDiagnostics: () => Promise<void>;
}

export function AboutView({
  about,
  soundEnabled,
  onToggleSound,
  onTriggerLaunch,
  onCopyDiagnostics,
}: AboutViewProps) {
  const [sigilInput, setSigilInput] = useState("MaxQ-JaxCore-JucStudio-Neon");
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await onCopyDiagnostics();
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div className="mq-enter mx-auto max-w-5xl space-y-5">
      {/* Brand Hero Showcase Card */}
      <section className="mq-panel relative overflow-hidden rounded-2xl p-6 sm:p-8">
        <div
          className="pointer-events-none absolute -right-12 -top-12 h-52 w-52 rounded-full opacity-25"
          style={{
            background: "radial-gradient(circle, var(--mq-accent) 0%, transparent 70%)",
          }}
        />
        <div className="relative flex flex-col items-start justify-between gap-6 sm:flex-row sm:items-center">
          <div className="flex items-center gap-5">
            <div className="mq-float">
              <MaxQLogo
                size={76}
                interactive
                onClick={onTriggerLaunch}
                title="点击触发 Max-Q 升空彩蛋！"
              />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2.5">
                <h1 className="text-2xl font-bold tracking-tight" style={{ color: "var(--mq-ink)" }}>
                  MaxQ
                </h1>
                <span
                  className="font-mono-tabular rounded-full px-2.5 py-0.5 text-xs font-semibold"
                  style={{
                    backgroundColor: "var(--mq-accent-soft)",
                    color: "var(--mq-accent-ink)",
                  }}
                >
                  v{about.app_version}
                </span>
                <span
                  className="rounded-full px-2.5 py-0.5 text-[11px] font-medium"
                  style={{
                    backgroundColor: "var(--mq-ok-bg)",
                    color: "var(--mq-ok)",
                  }}
                >
                  Scheme A 安全默认
                </span>
              </div>
              <p className="mt-1.5 text-sm font-medium" style={{ color: "var(--mq-ink-2)" }}>
                跨越最大动压 · 轻量、扁平、高安全性的新一代现代直连代理桌面客户端
              </p>
              <p className="mt-1 text-xs" style={{ color: "var(--mq-ink-3)" }}>
                名称源自航天动力学中的 <strong style={{ color: "var(--mq-ink-2)" }}>Max-Q（最大动压点）</strong>
                ——突破复杂网络阻力、进入平滑高速轨道的瞬间。
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={onTriggerLaunch}
              className="mq-btn mq-btn-primary flex items-center gap-1.5 rounded-xl px-4 py-2 text-xs font-semibold"
            >
              <Rocket className="h-3.5 w-3.5" /> 模拟 Max-Q 升空
            </button>
            <button
              onClick={handleCopy}
              className="mq-btn mq-subtle flex items-center gap-1.5 rounded-xl px-3.5 py-2 text-xs font-medium"
              style={{ color: "var(--mq-ink)" }}
            >
              {copied ? (
                <>
                  <Check className="h-3.5 w-3.5" style={{ color: "var(--mq-ok)" }} /> 已复制脱敏诊断
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5" style={{ color: "var(--mq-accent)" }} /> 复制脱敏诊断
                </>
              )}
            </button>
          </div>
        </div>

        {/* Core Attribution Banner (Required Credits) */}
        <div className="mt-6 grid gap-3 sm:grid-cols-2">
          <div
            className="flex items-center gap-3.5 rounded-xl border p-4"
            style={{
              backgroundColor: "var(--mq-accent-soft)",
              borderColor: "var(--mq-border-strong)",
            }}
          >
            <div
              className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl"
              style={{ backgroundColor: "var(--mq-card)", color: "var(--mq-accent)" }}
            >
              <Cpu className="h-5 w-5" />
            </div>
            <div>
              <div className="text-[11px] font-medium uppercase tracking-wider" style={{ color: "var(--mq-accent-ink)" }}>
                Core Runtime Attribution
              </div>
              <div className="mt-0.5 text-sm font-bold" style={{ color: "var(--mq-ink)" }}>
                Powered by JaxCore · sing-box 内核
              </div>
              <div className="font-mono-tabular mt-0.5 text-xs" style={{ color: "var(--mq-ink-2)" }}>
                sing-box v{about.core_version} · 原生 TUN + 全协议直连内核
              </div>
            </div>
          </div>

          <div
            className="flex items-center gap-3.5 rounded-xl border p-4"
            style={{
              backgroundColor: "var(--mq-accent-soft-2)",
              borderColor: "var(--mq-border-strong)",
            }}
          >
            <div
              className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl"
              style={{ backgroundColor: "var(--mq-card)", color: "var(--mq-accent-2)" }}
            >
              <Sparkles className="h-5 w-5" />
            </div>
            <div>
              <div className="text-[11px] font-medium uppercase tracking-wider" style={{ color: "var(--mq-accent-ink)" }}>
                Created & Crafted By
              </div>
              <div className="mt-0.5 text-sm font-bold" style={{ color: "var(--mq-ink)" }}>
                制作者：{about.creator}
              </div>
              <div className="mt-0.5 flex items-center gap-1 text-xs" style={{ color: "var(--mq-ink-2)" }}>
                <span>晴岚蓝紫扁平灵动设计 · Rust + Tauri v2 全栈架构</span>
                <Heart className="h-3 w-3" style={{ color: "var(--mq-accent-2)" }} />
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Real-Time Rust Environment & Architecture Cards */}
      <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {[
          {
            icon: Layers,
            label: "运行环境",
            val: `${about.os.toUpperCase()} / ${about.arch}`,
            sub: `服务协议 v${about.service_protocol_version}`,
          },
          {
            icon: ShieldCheck,
            label: "本地信任库",
            val: `${about.pinned_spki_nodes} / ${about.total_nodes} 节点`,
            sub: `共 ${about.total_profiles} 套配置已隔离存储`,
          },
          {
            icon: Lock,
            label: "内置分流规则",
            val: `${about.builtin_rule_count.toLocaleString()} 条`,
            sub: "国内直连 + CN IP-CIDR（彻底脱敏）",
          },
          {
            icon: Fingerprint,
            label: "证书探测引擎",
            val: "Rustls + Quinn",
            sub: "绕过 Schannel · 支持 Hy2 Salamander",
          },
        ].map((card) => {
          const Icon = card.icon;
          return (
            <div key={card.label} className="mq-panel rounded-2xl p-4">
              <div className="flex items-center gap-2 text-xs" style={{ color: "var(--mq-ink-3)" }}>
                <Icon className="h-3.5 w-3.5" style={{ color: "var(--mq-accent)" }} />
                {card.label}
              </div>
              <div className="font-mono-tabular mt-2 text-base font-bold" style={{ color: "var(--mq-ink)" }}>
                {card.val}
              </div>
              <div className="mt-0.5 text-[11px]" style={{ color: "var(--mq-ink-2)" }}>
                {card.sub}
              </div>
            </div>
          );
        })}
      </section>

      {/* Interactive Fun Lab (SPKI Visual Crest Playground + Chime Toggle + Tech Stack) */}
      <section className="grid gap-5 lg:grid-cols-12">
        <div className="mq-panel rounded-2xl p-5 lg:col-span-7">
          <div className="flex items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold" style={{ color: "var(--mq-ink)" }}>
                SPKI 视觉徽章实验场（Fun + Security）
              </h2>
              <p className="mt-1 text-xs" style={{ color: "var(--mq-ink-2)" }}>
                MaxQ 会把每个节点的真实 SPKI SHA-256 指纹实时映射为独一无二的 5×5 几何图腾——证书一旦被中间人替换，图腾立刻剧变。
              </p>
            </div>
          </div>

          <div className="mt-4 flex flex-col items-start gap-4 sm:flex-row sm:items-center">
            <SpkiSigil seed={sigilInput || "MaxQ"} size={72} />
            <div className="w-full flex-1 space-y-2">
              <input
                value={sigilInput}
                onChange={(e) => setSigilInput(e.target.value)}
                placeholder="输入任意指纹或文字，实时观察图腾变化..."
                className="font-mono-tabular mq-subtle w-full rounded-xl px-3.5 py-2 text-xs focus:outline-none"
                style={{ color: "var(--mq-ink)" }}
              />
              <div className="flex flex-wrap gap-1.5">
                {["MaxQ-JaxCore-JucStudio-Neon", "SPKI-Pinned-Tokyo-Edge", "MITM-Alert-Changed!"].map(
                  (preset) => (
                    <button
                      key={preset}
                      onClick={() => setSigilInput(preset)}
                      className="mq-btn rounded-lg px-2.5 py-1 text-[11px] font-medium"
                      style={{
                        backgroundColor: "var(--mq-accent-soft)",
                        color: "var(--mq-accent-ink)",
                      }}
                    >
                      {preset}
                    </button>
                  )
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="mq-panel flex flex-col justify-between rounded-2xl p-5 lg:col-span-5">
          <div>
            <h2 className="text-sm font-semibold" style={{ color: "var(--mq-ink)" }}>
              灵动实验室 & 开源致谢
            </h2>
            <p className="mt-1 text-xs" style={{ color: "var(--mq-ink-2)" }}>
              可选开启 Web Audio 轻音效（无外链资源，连接/升空时奏响轻盈和弦），随时可关。
            </p>

            <div className="mq-subtle mt-3.5 flex items-center justify-between rounded-xl px-3.5 py-2.5">
              <div className="flex items-center gap-2 text-xs font-medium" style={{ color: "var(--mq-ink)" }}>
                {soundEnabled ? (
                  <Volume2 className="h-4 w-4" style={{ color: "var(--mq-accent)" }} />
                ) : (
                  <VolumeX className="h-4 w-4" style={{ color: "var(--mq-ink-3)" }} />
                )}
                灵动微音效（连接 / 升空和弦）
              </div>
              <button
                onClick={onToggleSound}
                className="mq-btn rounded-full px-3 py-1 text-[11px] font-semibold"
                style={{
                  backgroundColor: soundEnabled ? "var(--mq-accent)" : "var(--mq-border)",
                  color: soundEnabled ? "#ffffff" : "var(--mq-ink-2)",
                }}
              >
                {soundEnabled ? "已开启" : "已静音"}
              </button>
            </div>
          </div>

          <div className="mt-4 flex flex-wrap gap-1.5 text-[11px]">
            {[
              "JaxCore · sing-box",
              "JucStudio Neon",
              "Tauri v2",
              "Rust",
              "React 19",
              "rustls / quinn",
              "WinTun",
              "SQLite WAL",
            ].map((tech) => (
              <span
                key={tech}
                className="rounded-lg px-2 py-1 font-medium"
                style={{ backgroundColor: "var(--mq-subtle)", color: "var(--mq-ink-2)" }}
              >
                {tech}
              </span>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}
