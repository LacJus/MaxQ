import { AlertTriangle, Download, FileText, Link2, Shield, Upload, X } from "lucide-react";
import type { SanitizedImport } from "../types";

export type ImportMethod = "paste" | "file" | "url";

interface ImportModalProps {
  open: boolean;
  onClose: () => void;
  importMethod: ImportMethod;
  setImportMethod: (m: ImportMethod) => void;
  importName: string;
  setImportName: (v: string) => void;
  importText: string;
  setImportText: (v: string) => void;
  subUrl: string;
  setSubUrl: (v: string) => void;
  preview: SanitizedImport | null;
  setPreview: (p: SanitizedImport | null) => void;
  approvedHostDomains: Set<string>;
  setApprovedHostDomains: (s: Set<string>) => void;
  busy: boolean;
  onFetchSubUrl: () => void;
  onPreviewImport: () => void;
  onCommitImport: () => void;
}

export function ImportModal({
  open,
  onClose,
  importMethod,
  setImportMethod,
  importName,
  setImportName,
  importText,
  setImportText,
  subUrl,
  setSubUrl,
  preview,
  setPreview,
  approvedHostDomains,
  setApprovedHostDomains,
  busy,
  onFetchSubUrl,
  onPreviewImport,
  onCommitImport,
}: ImportModalProps) {
  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4 backdrop-blur-[2px]"
      onClick={onClose}
    >
      <div
        className="mq-panel mq-enter flex max-h-[90vh] w-full max-w-2xl flex-col overflow-hidden rounded-2xl shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div
          className="flex items-center justify-between border-b px-5 py-4"
          style={{ borderColor: "var(--mq-border)" }}
        >
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4" style={{ color: "var(--mq-accent)" }} />
            <h2 className="text-sm font-semibold" style={{ color: "var(--mq-ink)" }}>
              安全导入与隔离审计（Scheme A）
            </h2>
          </div>
          <button
            onClick={onClose}
            className="mq-btn rounded-lg p-1"
            style={{ color: "var(--mq-ink-3)" }}
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-4 overflow-y-auto p-5">
          {/* Import Method Tabs */}
          <div className="mq-subtle flex gap-1 rounded-xl p-1 text-xs">
            {[
              { id: "paste" as const, label: "分享链 / 文本粘贴", icon: Link2 },
              { id: "file" as const, label: "本地 .conf / JSON", icon: FileText },
              { id: "url" as const, label: "HTTPS 订阅 URL", icon: Download },
            ].map((m) => {
              const Icon = m.icon;
              const active = importMethod === m.id;
              return (
                <button
                  key={m.id}
                  onClick={() => setImportMethod(m.id)}
                  className="mq-btn flex flex-1 items-center justify-center gap-1.5 rounded-lg py-1.5 font-medium"
                  style={
                    active
                      ? { backgroundColor: "var(--mq-card)", color: "var(--mq-accent-ink)" }
                      : { color: "var(--mq-ink-2)" }
                  }
                >
                  <Icon className="h-3.5 w-3.5" /> {m.label}
                </button>
              );
            })}
          </div>

          <div>
            <label className="text-xs font-medium" style={{ color: "var(--mq-ink-2)" }}>
              配置集名称
            </label>
            <input
              value={importName}
              onChange={(e) => setImportName(e.target.value)}
              className="mq-subtle mt-1 w-full rounded-xl px-3.5 py-2 text-sm focus:outline-none"
              style={{ color: "var(--mq-ink)" }}
            />
          </div>

          {importMethod === "url" && (
            <div className="space-y-2">
              <label className="text-xs font-medium" style={{ color: "var(--mq-ink-2)" }}>
                订阅地址（仅允许公网 HTTPS，内置 DNS 防重绑定 SSRF 与 8 MiB 流式限制）
              </label>
              <div className="flex gap-2">
                <input
                  value={subUrl}
                  onChange={(e) => setSubUrl(e.target.value)}
                  placeholder="https://example.com/sub?..."
                  className="font-mono-tabular mq-subtle flex-1 rounded-xl px-3.5 py-2 text-xs focus:outline-none"
                  style={{ color: "var(--mq-ink)" }}
                />
                <button
                  onClick={onFetchSubUrl}
                  disabled={!subUrl.trim() || busy}
                  className="mq-btn mq-btn-primary rounded-xl px-4 py-2 text-xs font-semibold disabled:opacity-50"
                >
                  {busy ? "拉取中..." : "安全拉取"}
                </button>
              </div>
            </div>
          )}

          {importMethod === "file" && (
            <label
              className="mq-subtle flex cursor-pointer flex-col items-center justify-center rounded-xl border-dashed py-8 text-xs transition hover:border-[var(--mq-accent)]"
              style={{ color: "var(--mq-ink-2)" }}
            >
              <Upload className="mb-2 h-5 w-5" style={{ color: "var(--mq-accent)" }} />
              <span>选择本地 Shadowrocket `.conf` / Clash `.yaml` / `sing-box` `.json`</span>
              <input
                type="file"
                accept=".conf,.txt,.yaml,.yml,.json"
                className="hidden"
                onChange={async (e) => {
                  const file = e.target.files?.[0];
                  if (!file) return;
                  const text = await file.text();
                  setImportText(text);
                  setImportName(file.name.replace(/\.[^.]+$/, ""));
                  setPreview(null);
                }}
              />
            </label>
          )}

          <div>
            <label className="text-xs font-medium" style={{ color: "var(--mq-ink-2)" }}>
              配置内容（支持 `trojan://` / `vless://` / `anytls://` / `hy2://` / `tuic://` / `ss://` / `vmess://` / `.conf`）
            </label>
            <textarea
              rows={5}
              value={importText}
              onChange={(e) => {
                setImportText(e.target.value);
                setPreview(null);
              }}
              placeholder="粘贴单条分享链、多行节点或完整 Shadowrocket .conf..."
              className="font-mono-tabular mq-subtle mt-1 w-full rounded-xl p-3 text-xs focus:outline-none"
              style={{ color: "var(--mq-ink)" }}
            />
          </div>

          {!preview ? (
            <button
              onClick={onPreviewImport}
              disabled={!importText.trim() || busy}
              className="mq-btn mq-btn-primary w-full rounded-xl py-2.5 text-xs font-semibold disabled:opacity-50"
            >
              {busy ? "正在运行防注入解析与安全审计..." : "第一步：解析并生成安全隔离审计报告"}
            </button>
          ) : (
            <div className="mq-subtle space-y-3 rounded-xl p-4 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-semibold" style={{ color: "var(--mq-ink)" }}>
                  识别格式：{preview.format}
                </span>
                <span className="font-mono-tabular" style={{ color: "var(--mq-ink-2)" }}>
                  {preview.report.total_nodes_imported} 节点 · {preview.report.total_rules_imported} 规则 ·{" "}
                  {preview.report.insecure_nodes_count} 待验证 TLS
                </span>
              </div>

              {preview.report.findings.map((f, i) => (
                <div
                  key={i}
                  className="rounded-xl border px-3 py-2"
                  style={
                    f.severity === "critical" || f.severity === "high"
                      ? {
                          backgroundColor: "var(--mq-danger-bg)",
                          borderColor: "var(--mq-danger-border)",
                          color: "var(--mq-danger)",
                        }
                      : {
                          backgroundColor: "var(--mq-warn-bg)",
                          borderColor: "var(--mq-warn-border)",
                          color: "var(--mq-warn)",
                        }
                  }
                >
                  <div className="flex items-center gap-1.5 font-semibold">
                    <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                    [{f.action.toUpperCase()}] {f.category} ({f.count})
                  </div>
                  <p className="mt-1 opacity-90">{f.summary}</p>
                </div>
              ))}

              {preview.hosts.length > 0 && (
                <div className="space-y-1.5 pt-1">
                  <div className="font-medium" style={{ color: "var(--mq-ink)" }}>
                    `[Host]` 域名别名隔离审批（默认全禁用）：
                  </div>
                  {preview.hosts.map((h, idx) => {
                    const hostKey = `${h.domain.trim().toLowerCase()}||${h.target.trim()}`;
                    return (
                      <label
                        key={`${hostKey}-${idx}`}
                        className="flex cursor-pointer items-center justify-between rounded-lg border px-3 py-2"
                        style={{ backgroundColor: "var(--mq-card)", borderColor: "var(--mq-border)" }}
                      >
                        <span className="font-mono-tabular" style={{ color: "var(--mq-ink)" }}>
                          {h.domain} → {h.target}{" "}
                          <span className="text-[11px]" style={{ color: "var(--mq-ink-3)" }}>
                            ({h.classification})
                          </span>
                        </span>
                        <input
                          type="checkbox"
                          checked={approvedHostDomains.has(hostKey)}
                          onChange={(e) => {
                            const next = new Set(approvedHostDomains);
                            if (e.target.checked) next.add(hostKey);
                            else next.delete(hostKey);
                            setApprovedHostDomains(next);
                          }}
                          className="h-4 w-4 accent-[var(--mq-accent)]"
                        />
                      </label>
                    );
                  })}
                </div>
              )}

              <button
                onClick={onCommitImport}
                disabled={busy}
                className="mq-btn w-full rounded-xl py-2.5 text-xs font-semibold text-white"
                style={{ backgroundColor: "var(--mq-ok)" }}
              >
                确认审计结果并安全导入
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
