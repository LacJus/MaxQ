import { invoke } from "@tauri-apps/api/core";
import type {
  AboutInfo,
  BatchPinSummary,
  BuiltinRulesInfo,
  HostEntry,
  NodeConfig,
  ProbeNodeResult,
  ProfileSummary,
  RuntimePolicy,
  RuntimeStatus,
  RuntimeTelemetry,
  SanitizedImport,
  StoredProfile,
  TrustRecord,
  TunServiceStatus,
} from "./types";

export function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export const api = {
  getBuiltinRulesInfo: () => invoke<BuiltinRulesInfo>("get_builtin_rules_info"),

  getAboutInfo: () => invoke<AboutInfo>("get_about_info"),

  exportDiagnosticsSummary: () => invoke<string>("export_diagnostics_summary"),

  getTunServiceStatus: () => invoke<TunServiceStatus>("get_tun_service_status"),

  installTunService: () => invoke<string>("install_tun_service"),

  uninstallTunService: () => invoke<string>("uninstall_tun_service"),

  fetchSubscriptionUrl: (url: string) =>
    invoke<string>("fetch_subscription_url", { url }),

  previewImport: (rawInput: string) =>
    invoke<SanitizedImport>("preview_import", { rawInput }),

  commitImport: (profileName: string, rawInput: string, approvedHostDomains: string[]) =>
    invoke<string>("commit_import", { profileName, rawInput, approvedHostDomains }),

  listProfiles: () => invoke<ProfileSummary[]>("list_profiles"),

  getProfile: (profileId: string) =>
    invoke<StoredProfile>("get_profile", { profileId }),

  deleteProfile: (profileId: string) =>
    invoke<void>("delete_profile", { profileId }),

  renameProfile: (profileId: string, newName: string) =>
    invoke<void>("rename_profile", { profileId, newName }),

  updateProfileHosts: (profileId: string, hosts: HostEntry[]) =>
    invoke<StoredProfile>("update_profile_hosts", { profileId, hosts }),

  testNodeLatency: (nodeId: string) =>
    invoke<number>("test_node_latency", { nodeId }),

  batchTestLatencies: (profileId: string) =>
    invoke<Record<string, number | null>>("batch_test_latencies", { profileId }),

  probeNodeCertificate: (nodeId: string) =>
    invoke<ProbeNodeResult>("probe_node_certificate", { nodeId }),

  batchProbeAndPinProfile: (profileId: string) =>
    invoke<BatchPinSummary>("batch_probe_and_pin_profile", { profileId }),

  confirmNodePin: (nodeId: string, trustRecord: TrustRecord) =>
    invoke<NodeConfig>("confirm_node_pin", { nodeId, trustRecord }),

  setInsecureOverride: (nodeId: string, confirmed: boolean) =>
    invoke<NodeConfig>("set_insecure_override", { nodeId, confirmed }),

  startProxy: (profileId: string, nodeId: string, enableSystemProxy: boolean) =>
    invoke<RuntimeStatus>("start_proxy", { profileId, nodeId, enableSystemProxy }),

  stopProxy: () => invoke<RuntimeStatus>("stop_proxy"),

  resetSystemProxy: () => invoke<string>("reset_system_proxy"),

  getRuntimeStatus: () => invoke<RuntimeStatus>("get_runtime_status"),

  getRuntimeTelemetry: () => invoke<RuntimeTelemetry>("get_runtime_telemetry"),

  closeAllConnections: () => invoke<void>("close_all_connections"),

  getRuntimeLogs: () => invoke<string[]>("get_runtime_logs"),

  getRuntimePolicy: () => invoke<RuntimePolicy>("get_runtime_policy"),

  updateRuntimePolicy: (policy: RuntimePolicy) =>
    invoke<RuntimePolicy>("update_runtime_policy", { policy }),
};
