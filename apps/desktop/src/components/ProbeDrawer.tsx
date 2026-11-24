import { AlertTriangle, CheckCircle2, RefreshCw, ShieldAlert, ShieldCheck, X } from "lucide-react";
import type { NodeConfig, ProbeNodeResult } from "../types";
import { SpkiSigil } from "./SpkiSigil";

interface ProbeDrawerProps {
  node: NodeConfig | null;
  probeResult: ProbeNodeResult | null;
  probeLoading: boolean;
  probeError: string | null;
  onClose: () => void;
  onReprobe: (node: NodeConfig) => void;
  onConfirmPin: () => void;
  onTemporaryOverride: () => void;
}

export function ProbeDrawer({
  node,
  probeResult,
  probeLoading,
  probeError,
  onClose,
  onReprobe,
  onConfirmPin,
  onTemporaryOverride,
}: ProbeDrawerProps) {
  if (!node) return null;

  const activeSpki = probeResult?.probed.spki_sha256_b64 ?? node.tls.trust_record?.spki_sha256_b64;

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/25 backdrop-blur-[2px]"
      onClick={onClose}
    >
      <div
        className="mq-panel mq-enter flex h-full w-full max-w-lg flex-col border-l shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div
          className="flex items-center justify-between border-b px-5 py-4"
          style={{ borderColor: "var(--mq-border)" }}
        >
          <div className="min-w-0">
            <h2 className="text-sm font-semibold" style={{ color: "var(--mq-ink)" }}>
              TLS 证书探测与 SPKI 指纹固定（TOFU）
            </h2>
            <p className="truncate text-xs" style={{ color: "var(--mq-ink-2)" }}>
              {node.name} · {node.server}:{node.server_port}
            </p>
          </div>
          <button
            onClick={onClose}
            className="mq-btn rounded-lg p-1"
            style={{ color: "var(--mq-ink-3)" }}
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex-1 space-y-4 overflow-y-auto p-5 text-xs">
          <div
            className="flex items-center gap-3.5 rounded-xl border p-3.5"
            style={{
              backgroundColor: "var(--mq-accent-soft)",
              borderColor: "var(--mq-border-strong)",
            }}
          >
            {activeSpki ? (
              <SpkiSigil seed={activeSpki} size={46} />
            ) : (
              <div
                className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl"
                style={{ backgroundColor: "var(--mq-card)", color: "var(--mq-accent)" }}
              >
                <ShieldCheck className="h-5 w-5" />
              </div>
            )}
            <div style={{ color: "var(--mq-ink-2)" }}>
              采用内置独立 Rustls / Quinn（支持 Hysteria2 Salamander）直接完成真实 TLS 握手，
              <strong style={{ color: "var(--mq-ink)" }}>完全绕过 Windows Schannel 限制</strong>
              ，并生成唯一几何 SPKI 徽章供人工快速比对。
            </div>
          </div>

          <button
            onClick={() => onReprobe(node)}
            disabled={probeLoading}
            className="mq-btn mq-btn-primary flex w-full items-center justify-center gap-2 rounded-xl py-2.5 font-semibold disabled:opacity-50"
          >
            <RefreshCw className={`h-4 w-4 ${probeLoading ? "animate-spin" : ""}`} />
            {probeLoading ? "正在探测服务端真实证书..." : "立即执行无 Schannel 证书探测"}
          </button>

          {probeError && (
            <div
              className="rounded-xl border p-3.5"
              style={{
                backgroundColor: "var(--mq-danger-bg)",
                borderColor: "var(--mq-danger-border)",
                color: "var(--mq-danger)",
              }}
            >
              <div className="font-semibold">探测失败</div>
              <p className="mt-1 break-all">{probeError}</p>
            </div>
          )}

          {probeResult && (
            <div className="space-y-3">
              {probeResult.outcome.status === "mismatch" && (
                <div
                  className="rounded-xl border p-3.5"
                  style={{
                    backgroundColor: "var(--mq-danger-bg)",
                    borderColor: "var(--mq-danger-border)",
                    color: "var(--mq-danger)",
                  }}
                >
                  <div className="flex items-center gap-1.5 font-semibold">
                    <ShieldAlert className="h-4 w-4" /> 警告：服务端 SPKI 公钥指纹已变更！
                  </div>
                  <p className="mt-1">可能发生中间人攻击（MITM）或服务器更换证书，请人工核实。</p>
                  <div className="mt-2.5 flex items-center gap-3">
                    <div className="text-center">
                      <SpkiSigil seed={probeResult.outcome.expected_spki_b64} size={42} />
                      <div className="mt-1 text-[10px]">旧指纹</div>
                    </div>
                    <span className="text-xs font-bold">→</span>
                    <div className="text-center">
                      <SpkiSigil seed={probeResult.outcome.observed_spki_b64} size={42} />
                      <div className="mt-1 text-[10px]">新指纹</div>
                    </div>
                  </div>
                </div>
              )}

              {probeResult.outcome.status === "matched" && (
                <div
                  className="flex items-center gap-2 rounded-xl border p-3"
                  style={{
                    backgroundColor: "var(--mq-ok-bg)",
                    borderColor: "var(--mq-ok-border)",
                    color: "var(--mq-ok)",
                  }}
                >
                  <CheckCircle2 className="h-4 w-4" /> 与信任库中已固定的 SPKI 指纹完全一致！
                </div>
              )}

              <div className="mq-subtle space-y-2.5 rounded-xl p-4">
                <div>
                  <div className="text-[11px]" style={{ color: "var(--mq-ink-3)" }}>
                    SPKI SHA-256 (Base64 · JaxCore sing-box 固定字段)
                  </div>
                  <div
                    className="font-mono-tabular mt-0.5 break-all font-semibold"
                    style={{ color: "var(--mq-accent-ink)" }}
                  >
                    {probeResult.probed.spki_sha256_b64}
                  </div>
                </div>
                <div>
                  <div className="text-[11px]" style={{ color: "var(--mq-ink-3)" }}>
                    Leaf Cert SHA-256 (Hex · 兼容 Xray pcs / Hy2 pinSHA256)
                  </div>
                  <div className="font-mono-tabular mt-0.5 break-all" style={{ color: "var(--mq-ink)" }}>
                    {probeResult.probed.cert_sha256_hex}
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-2 pt-1">
                  <div>
                    <div className="text-[11px]" style={{ color: "var(--mq-ink-3)" }}>
                      SNI
                    </div>
                    <div className="font-mono-tabular break-all" style={{ color: "var(--mq-ink)" }}>
                      {probeResult.probed.sni}
                    </div>
                  </div>
                  <div>
                    <div className="text-[11px]" style={{ color: "var(--mq-ink-3)" }}>
                      证书属性
                    </div>
                    <div style={{ color: "var(--mq-ink)" }}>
                      {probeResult.probed.is_self_signed ? "自签证书" : "CA 签发"} ·{" "}
                      {probeResult.probed.hostname_matches_sni ? "域名匹配" : "域名不匹配"}
                    </div>
                  </div>
                </div>
                <div>
                  <div className="text-[11px]" style={{ color: "var(--mq-ink-3)" }}>
                    Subject / Issuer
                  </div>
                  <div className="break-all" style={{ color: "var(--mq-ink-2)" }}>
                    {probeResult.probed.subject} / {probeResult.probed.issuer}
                  </div>
                </div>
                <div>
                  <div className="text-[11px]" style={{ color: "var(--mq-ink-3)" }}>
                    有效期
                  </div>
                  <div className="font-mono-tabular" style={{ color: "var(--mq-ink-2)" }}>
                    {probeResult.probed.not_before} ~ {probeResult.probed.not_after}
                  </div>
                </div>
              </div>

              <button
                onClick={onConfirmPin}
                className="mq-btn w-full rounded-xl py-2.5 font-semibold text-white"
                style={{ backgroundColor: "var(--mq-ok)" }}
              >
                {probeResult.outcome.status === "mismatch"
                  ? "我已核实变更，更新 SPKI 信任指纹"
                  : "信任并固定此 SPKI 公钥指纹（推荐）"}
              </button>
            </div>
          )}

          {node.tls.verify_mode.mode === "insecure_legacy" && (
            <div
              className="mt-4 border-t pt-4"
              style={{ borderColor: "var(--mq-border)" }}
            >
              <button
                onClick={onTemporaryOverride}
                className="mq-btn flex w-full items-center justify-center gap-1.5 rounded-xl border py-2.5 text-xs font-medium"
                style={{
                  backgroundColor: "var(--mq-warn-bg)",
                  borderColor: "var(--mq-warn-border)",
                  color: "var(--mq-warn)",
                }}
              >
                <AlertTriangle className="h-3.5 w-3.5" />
                仅本次显式跳过证书校验（不推荐，易受 MITM 攻击）
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
