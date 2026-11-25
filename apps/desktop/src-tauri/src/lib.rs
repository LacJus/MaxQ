use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use maxq_cert_probe::{
    apply_confirmed_pin, evaluate_probe_against_node, probe_certificate, probe_tcp_latency_ms,
    ProbeRequest, ProbedCertificate,
};
use maxq_core_model::{
    HostEntry, NodeConfig, PinCheckOutcome, ProxyMode, RuntimePolicy, SanitizedImport,
    TlsVerifyMode, TrustRecord,
};
use maxq_core_runtime::system_proxy::SystemProxyManager;
use maxq_core_runtime::tun_client::TunServiceClient;
use maxq_core_runtime::{RuntimeStatus, SingBoxSupervisor, SingleInstanceGuard};
use maxq_parser::parse_input;
use maxq_sanitizer::{
    apply_approved_host_aliases, is_non_public_ip, sanitize_import, validate_safe_remote_url,
};
use maxq_singbox_compiler::{
    builtin_default_rules_count, compile_singbox_v14, validate_runtime_policy, CompileInput,
};
use maxq_storage::{ProfileSummary, StoredProfile, VaultStore};
use maxq_win_service::protocol::{TunServiceStatus, SERVICE_PROTOCOL_VERSION};
use serde::Serialize;
use serde_json::Value;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Manager, State};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};

pub struct ActiveClashApiSession {
    pub port: u16,
    pub secret: String,
    pub started_at: Instant,
    pub prev_upload_total: u64,
    pub prev_download_total: u64,
    pub prev_sample_at: Option<Instant>,
}

pub struct AppState {
    pub store: Mutex<VaultStore>,
    pub supervisor: AsyncMutex<SingBoxSupervisor>,
    pub sysproxy: Mutex<SystemProxyManager>,
    pub service_exe_path: Option<PathBuf>,
    pub tun_active_node: Mutex<Option<(String, String)>>,
    pub clash_api_session: Mutex<Option<ActiveClashApiSession>>,
    /// Reusable no-proxy HTTP client strictly for loopback `127.0.0.1` Clash API telemetry/control
    /// (avoids allocating a brand-new reqwest connection pool every 1.8s poll).
    pub local_http_client: reqwest::Client,
    /// Short-lived (1s) coalescing cache so concurrent per-tick polls (`get_runtime_status`,
    /// `get_runtime_logs`, `get_tun_service_status`) share a single Named Pipe / SCM query.
    pub tun_status_cache: AsyncMutex<Option<(Instant, TunServiceStatus)>>,
    /// Serializes start/stop/reset/delete lifecycle transitions so concurrent clicks or shutdown
    /// can NEVER interleave and re-enable system proxy after disconnect/exit.
    pub lifecycle_lock: AsyncMutex<()>,
    pub shutdown_requested: AtomicBool,
    pub lifecycle_epoch: AtomicU64,
}

const TUN_STATUS_CACHE_TTL: Duration = Duration::from_millis(1000);

async fn query_tun_status_coalesced(state: &AppState, force_refresh: bool) -> TunServiceStatus {
    let mut cache = state.tun_status_cache.lock().await;
    if !force_refresh {
        if let Some((captured_at, cached)) = cache.as_ref() {
            if captured_at.elapsed() < TUN_STATUS_CACHE_TTL {
                return cached.clone();
            }
        }
    }
    let fresh = tokio::task::spawn_blocking(TunServiceClient::query_status)
        .await
        .unwrap_or_default();
    *cache = Some((Instant::now(), fresh.clone()));
    fresh
}

async fn invalidate_tun_status_cache(state: &AppState) {
    let mut cache = state.tun_status_cache.lock().await;
    *cache = None;
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeNodeResult {
    pub probed: ProbedCertificate,
    pub outcome: PinCheckOutcome,
    pub proposed_trust_record: TrustRecord,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchPinSummary {
    pub probed_endpoints: usize,
    pub pinned_nodes: usize,
    pub failed_nodes: usize,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BuiltinRulesInfo {
    pub rule_count: usize,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveConnectionItem {
    pub id: String,
    pub host: String,
    pub port: String,
    pub network: String,
    pub rule: String,
    pub chain: String,
    pub upload: u64,
    pub download: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct RuntimeTelemetry {
    pub connected: bool,
    pub upload_bps: u64,
    pub download_bps: u64,
    pub upload_total: u64,
    pub download_total: u64,
    pub active_connections: usize,
    pub uptime_secs: u64,
    /// Normalized 0..=100 aerodynamic dynamic pressure index ("Max-Q") derived from real throughput & connections.
    pub dynamic_pressure_q: f32,
    pub recent_connections: Vec<LiveConnectionItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AboutInfo {
    pub app_name: String,
    pub app_version: String,
    pub engine_brand: String,
    pub core_version: String,
    pub creator: String,
    pub os: String,
    pub arch: String,
    pub builtin_rule_count: usize,
    pub service_protocol_version: String,
    pub total_profiles: usize,
    pub total_nodes: usize,
    pub pinned_spki_nodes: usize,
}

#[tauri::command]
fn get_builtin_rules_info() -> BuiltinRulesInfo {
    BuiltinRulesInfo {
        rule_count: builtin_default_rules_count(),
        description: "MaxQ 内置默认分流规则（国内直连域名 + CN IP-CIDR + 海外代理，已完全脱敏）"
            .to_string(),
    }
}

#[tauri::command]
async fn get_tun_service_status(state: State<'_, AppState>) -> TunServiceStatus {
    query_tun_status_coalesced(&state, false).await
}

#[tauri::command]
async fn install_tun_service(state: State<'_, AppState>) -> Result<String, String> {
    let exe = state
        .service_exe_path
        .clone()
        .ok_or_else(|| {
            "未找到已打包的绝对路径 maxq-service.exe，请通过官方安装包安装 MaxQ。".to_string()
        })?;

    let result = tokio::task::spawn_blocking(move || -> Result<String, String> {
        TunServiceClient::install_elevated(&exe).map_err(|e| e.to_string())?;

        // Poll up to 4s for Named Pipe IPC to confirm service is live and authenticated
        let mut last_status = TunServiceStatus::default();
        for _ in 0..14 {
            last_status = TunServiceClient::query_status();
            if last_status.running {
                return Ok(if last_status.singbox_sha256_verified {
                    "MaxQ 安全加固 TUN 服务已安装并运行（sing-box SHA-256 校验通过）".into()
                } else {
                    "MaxQ TUN 服务已运行，但 sing-box.exe SHA-256 校验未通过，请重新安装官方安装包。".into()
                });
            }
            std::thread::sleep(Duration::from_millis(300));
        }

        let detail = last_status
            .last_error
            .unwrap_or_else(|| "服务未响应 Named Pipe IPC 握手".to_string());
        Err(format!("TUN 服务安装流程已结束但未能就绪：{detail}"))
    })
    .await
    .map_err(|e| format!("后台安装任务异常: {e}"))?;
    invalidate_tun_status_cache(&state).await;
    result
}

#[tauri::command]
async fn uninstall_tun_service(state: State<'_, AppState>) -> Result<String, String> {
    let exe = state
        .service_exe_path
        .clone()
        .ok_or_else(|| "未找到已打包的绝对路径 maxq-service.exe。".to_string())?;

    let result = tokio::task::spawn_blocking(move || -> Result<String, String> {
        let _ = TunServiceClient::stop_tun();
        TunServiceClient::uninstall_elevated(&exe).map_err(|e| e.to_string())?;
        Ok("已停止并卸载 MaxQ TUN 服务。".into())
    })
    .await
    .map_err(|e| format!("后台卸载任务异常: {e}"))?;
    invalidate_tun_status_cache(&state).await;
    result
}

#[tauri::command]
async fn fetch_subscription_url(url: String) -> Result<String, String> {
    const MAX_BYTES: usize = 8 * 1024 * 1024;
    let mut current_url = url.trim().to_string();

    for hop in 0..=3 {
        // 1. Validate URL syntax, HTTPS scheme, and literal private hosts
        validate_safe_remote_url(&current_url)?;
        let parsed = reqwest::Url::parse(&current_url).map_err(|e| e.to_string())?;
        let host = parsed
            .host_str()
            .ok_or_else(|| "missing host".to_string())?
            .to_string();
        let port = parsed.port_or_known_default().unwrap_or(443);

        // 2. Resolve DNS and verify ALL returned IPs are strictly public (blocks DNS rebinding / nip.io SSRF! H-2)
        let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|e| format!("DNS resolution failed: {e}"))?
            .collect();
        if addrs.is_empty() {
            return Err("DNS resolution returned no addresses".into());
        }
        for addr in &addrs {
            if is_non_public_ip(addr.ip()) {
                return Err(format!(
                    "blocked SSRF: host '{host}' resolved to non-public IP {}",
                    addr.ip()
                ));
            }
        }

        // 3. Pin verified SocketAddr into reqwest client, bypass OS proxy (prevents proxy-mediated
        //    SSRF bypass or broken-sysproxy deadlock), and disable auto-redirects (H-2)
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent(concat!(
                "MaxQ/",
                env!("CARGO_PKG_VERSION"),
                " (Shadowrocket compatible)"
            ))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .resolve(&host, addrs[0])
            .build()
            .map_err(|e| e.to_string())?;

        let mut resp = client
            .get(parsed.clone())
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if resp.status().is_redirection() {
            if hop == 3 {
                return Err("too many redirects (max 3)".into());
            }
            let loc = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| "redirect missing Location header".to_string())?;
            current_url = parsed
                .join(loc)
                .map_err(|e| format!("invalid redirect URL: {e}"))?
                .to_string();
            continue;
        }

        if !resp.status().is_success() {
            return Err(format!("订阅拉取失败：HTTP {}", resp.status()));
        }
        if let Some(cl) = resp.content_length() {
            if cl as usize > MAX_BYTES {
                return Err("订阅响应超过 8 MB 安全限制".into());
            }
        }

        // 4. Incremental streaming read with hard 8 MiB memory cap (M-2)
        let mut buf = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
            if buf.len() + chunk.len() > MAX_BYTES {
                return Err("订阅响应超过 8 MB 安全限制".into());
            }
            buf.extend_from_slice(&chunk);
        }
        return String::from_utf8(buf).map_err(|_| "订阅内容非有效 UTF-8 文本".into());
    }

    Err("too many redirects".into())
}

#[tauri::command]
fn preview_import(raw_input: String) -> Result<SanitizedImport, String> {
    let raw = parse_input(&raw_input).map_err(|e| e.to_string())?;
    Ok(sanitize_import(raw))
}

#[tauri::command]
fn commit_import(
    state: State<'_, AppState>,
    profile_name: String,
    raw_input: String,
    approved_host_domains: Vec<String>,
) -> Result<String, String> {
    let raw = parse_input(&raw_input).map_err(|e| e.to_string())?;
    let mut sanitized = sanitize_import(raw);

    let approved_set: HashSet<String> = approved_host_domains
        .into_iter()
        .map(|d| d.trim().to_ascii_lowercase())
        .collect();
    for h in &mut sanitized.hosts {
        if approved_set.contains(&h.domain.to_ascii_lowercase()) {
            h.approved = true;
        }
    }
    apply_approved_host_aliases(&mut sanitized.nodes, &sanitized.hosts);

    let mut store = state.store.lock().map_err(|e| e.to_string())?;
    store
        .save_sanitized_import(profile_name, &sanitized)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn list_profiles(state: State<'_, AppState>) -> Result<Vec<ProfileSummary>, String> {
    let store = state.store.lock().map_err(|e| e.to_string())?;
    store.list_profiles().map_err(|e| e.to_string())
}

#[tauri::command]
fn get_profile(state: State<'_, AppState>, profile_id: String) -> Result<StoredProfile, String> {
    let store = state.store.lock().map_err(|e| e.to_string())?;
    store.get_profile(&profile_id).map_err(|e| e.to_string())
}

#[tauri::command]
async fn delete_profile(state: State<'_, AppState>, profile_id: String) -> Result<(), String> {
    let _lifecycle = state.lifecycle_lock.lock().await;

    let active_node_ids: HashSet<String> = {
        let mut ids = HashSet::new();
        if let Ok(guard) = state.tun_active_node.lock() {
            if let Some((nid, _)) = guard.as_ref() {
                ids.insert(nid.clone());
            }
        }
        let sup = state.supervisor.lock().await;
        let st = sup.status();
        if st.running {
            if let Some(nid) = st.active_node_id {
                ids.insert(nid);
            }
        }
        ids
    };

    let affects_active = {
        let store = state.store.lock().map_err(|e| e.to_string())?;
        store
            .get_profile(&profile_id)
            .map(|p| p.nodes.iter().any(|n| active_node_ids.contains(&n.id)))
            .unwrap_or(false)
    };

    if affects_active {
        state.lifecycle_epoch.fetch_add(1, Ordering::AcqRel);
        if let Ok(mut sp) = state.sysproxy.lock() {
            if sp.disable_and_restore().is_err() {
                let _ = sp.force_disable();
            }
        }
        let _ = tokio::task::spawn_blocking(TunServiceClient::stop_tun).await;
        invalidate_tun_status_cache(&state).await;
        if let Ok(mut guard) = state.tun_active_node.lock() {
            *guard = None;
        }
        if let Ok(mut guard) = state.clash_api_session.lock() {
            *guard = None;
        }
        let mut sup = state.supervisor.lock().await;
        let _ = sup.stop().await;
    }

    let mut store = state.store.lock().map_err(|e| e.to_string())?;
    store.delete_profile(&profile_id).map_err(|e| e.to_string())
}

#[tauri::command]
fn rename_profile(
    state: State<'_, AppState>,
    profile_id: String,
    new_name: String,
) -> Result<(), String> {
    let mut store = state.store.lock().map_err(|e| e.to_string())?;
    store
        .rename_profile(&profile_id, new_name)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn get_about_info(state: State<'_, AppState>) -> Result<AboutInfo, String> {
    let store = state.store.lock().map_err(|e| e.to_string())?;
    let (total_profiles, total_nodes, pinned_spki_nodes) =
        store.vault_stats().map_err(|e| e.to_string())?;
    Ok(AboutInfo {
        app_name: "MaxQ".to_string(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        engine_brand: "JaxCore · sing-box".to_string(),
        core_version: "1.14.4".to_string(),
        creator: "JucStudio · Neon".to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        builtin_rule_count: builtin_default_rules_count(),
        service_protocol_version: SERVICE_PROTOCOL_VERSION.to_string(),
        total_profiles,
        total_nodes,
        pinned_spki_nodes,
    })
}

#[tauri::command]
async fn export_diagnostics_summary(state: State<'_, AppState>) -> Result<String, String> {
    let (stats, policy) = {
        let store = state.store.lock().map_err(|e| e.to_string())?;
        let stats = store.vault_stats().map_err(|e| e.to_string())?;
        let policy = store.load_runtime_policy().map_err(|e| e.to_string())?;
        (stats, policy)
    };
    let tun = query_tun_status_coalesced(&state, true).await;
    let summary = format!(
        "=== MaxQ Redacted Diagnostics ===\n\
         App: MaxQ v{} ({}/{})\n\
         Engine: Powered by JaxCore · sing-box v1.14.4\n\
         Creator: JucStudio · Neon\n\
         Vault: {} profiles / {} nodes / {} SPKI pinned\n\
         Builtin Rules: {} generic sanitized rules\n\
         Policy: proxy_mode={:?}, routing_mode={:?}, rule_source={:?}, ipv6={:?}\n\
         Ports: mixed=127.0.0.1:{}, clash_api=127.0.0.1:{}\n\
         TUN Service: installed={}, running={}, tun_active={}, sha256_ok={}, proto={:?}\n\
         TUN Last Error: {}\n\
         (Zero secrets, passwords, UUIDs, or private node addresses included)",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
        stats.0,
        stats.1,
        stats.2,
        builtin_default_rules_count(),
        policy.proxy_mode,
        policy.routing_mode,
        policy.rule_source,
        policy.ipv6_mode,
        policy.mixed_listen_port,
        policy.clash_api_port,
        tun.installed,
        tun.running,
        tun.tun_active,
        tun.singbox_sha256_verified,
        tun.version,
        tun.last_error.as_deref().unwrap_or("none"),
    );
    Ok(summary)
}

#[tauri::command]
fn update_profile_hosts(
    state: State<'_, AppState>,
    profile_id: String,
    hosts: Vec<HostEntry>,
) -> Result<StoredProfile, String> {
    let mut store = state.store.lock().map_err(|e| e.to_string())?;
    let mut profile = store.get_profile(&profile_id).map_err(|e| e.to_string())?;

    // Defense-in-depth: ONLY allow toggling `approved` on pre-existing quarantined host entries;
    // never let an IPC payload inject new entries or alter server-side host classification.
    let approval_map: HashMap<(String, String), bool> = hosts
        .into_iter()
        .map(|h| {
            (
                (h.domain.trim().to_ascii_lowercase(), h.target.trim().to_string()),
                h.approved,
            )
        })
        .collect();
    for existing in &mut profile.hosts {
        let key = (
            existing.domain.trim().to_ascii_lowercase(),
            existing.target.trim().to_string(),
        );
        if let Some(&approved) = approval_map.get(&key) {
            existing.approved = approved;
        }
    }

    for n in &mut profile.nodes {
        n.dial_override_server = None;
    }
    apply_approved_host_aliases(&mut profile.nodes, &profile.hosts);
    store
        .update_profile_hosts(&profile_id, &profile.hosts, &profile.nodes)
        .map_err(|e| e.to_string())?;
    store.get_profile(&profile_id).map_err(|e| e.to_string())
}

#[tauri::command]
async fn test_node_latency(state: State<'_, AppState>, node_id: String) -> Result<u64, String> {
    let node = {
        let store = state.store.lock().map_err(|e| e.to_string())?;
        store.get_node(&node_id).map_err(|e| e.to_string())?
    };
    probe_tcp_latency_ms(node.effective_dial_server(), node.server_port, 4_000)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn batch_test_latencies(
    state: State<'_, AppState>,
    profile_id: String,
) -> Result<HashMap<String, Option<u64>>, String> {
    let targets: Vec<(String, String, u16)> = {
        let store = state.store.lock().map_err(|e| e.to_string())?;
        let profile = store.get_profile(&profile_id).map_err(|e| e.to_string())?;
        profile
            .nodes
            .into_iter()
            .filter(|n| !n.is_metadata_node)
            .take(64)
            .map(|n| (n.id.clone(), n.effective_dial_server().to_string(), n.server_port))
            .collect()
    };

    let sem = Arc::new(Semaphore::new(10));
    let mut join_set = tokio::task::JoinSet::new();
    for (id, host, port) in targets {
        let sem_clone = Arc::clone(&sem);
        join_set.spawn(async move {
            let _permit = sem_clone.acquire_owned().await;
            let ms = probe_tcp_latency_ms(&host, port, 3_500).await.ok();
            (id, ms)
        });
    }

    let mut out = HashMap::new();
    while let Some(res) = join_set.join_next().await {
        if let Ok((id, ms)) = res {
            out.insert(id, ms);
        }
    }
    Ok(out)
}

#[tauri::command]
async fn probe_node_certificate(
    state: State<'_, AppState>,
    node_id: String,
) -> Result<ProbeNodeResult, String> {
    let node = {
        let store = state.store.lock().map_err(|e| e.to_string())?;
        store.get_node(&node_id).map_err(|e| e.to_string())?
    };
    let req = ProbeRequest::from_node(&node);
    let probed = probe_certificate(&req).await.map_err(|e| e.to_string())?;
    let eval = evaluate_probe_against_node(&node, &probed).map_err(|e| e.to_string())?;
    Ok(ProbeNodeResult {
        probed,
        outcome: eval.outcome,
        proposed_trust_record: eval.proposed_trust_record,
    })
}

/// Deduplicates unverified/pending TLS nodes in a profile by `(dial_host, port, sni, protocol_kind)`,
/// probes unique endpoints concurrently, verifies any `pcs`/`pinSHA256`, and pins all matching nodes.
#[tauri::command]
async fn batch_probe_and_pin_profile(
    state: State<'_, AppState>,
    profile_id: String,
) -> Result<BatchPinSummary, String> {
    let profile = {
        let store = state.store.lock().map_err(|e| e.to_string())?;
        store.get_profile(&profile_id).map_err(|e| e.to_string())?
    };

    let targets: Vec<NodeConfig> = profile
        .nodes
        .into_iter()
        .filter(|n| {
            !n.is_metadata_node
                && n.tls.enabled
                && matches!(
                    n.tls.verify_mode,
                    TlsVerifyMode::InsecureLegacy { .. } | TlsVerifyMode::PendingPinBootstrap
                )
        })
        .collect();

    // Group by unique probe key (host, port, sni, transport_desc, alpn) to avoid cross-protocol collision (M-3)
    let probe_key_for = |node: &NodeConfig| -> (String, u16, String, String, Vec<String>) {
        let req = ProbeRequest::from_node(node);
        let transport_key = match &req.transport {
            maxq_cert_probe::ProbeTransport::TcpTls => "tcp".to_string(),
            maxq_cert_probe::ProbeTransport::Quic {
                salamander_password,
            } => format!("quic:{}", salamander_password.as_deref().unwrap_or("")),
        };
        (
            req.host.to_ascii_lowercase(),
            req.port,
            req.sni.to_ascii_lowercase(),
            transport_key,
            req.alpn,
        )
    };

    let mut unique_reqs: HashMap<(String, u16, String, String, Vec<String>), ProbeRequest> =
        HashMap::new();
    for node in &targets {
        let key = probe_key_for(node);
        unique_reqs
            .entry(key)
            .or_insert_with(|| ProbeRequest::from_node(node));
    }

    let probed_endpoints = unique_reqs.len();
    let sem = Arc::new(Semaphore::new(8));
    let mut join_set = tokio::task::JoinSet::new();
    for (key, req) in unique_reqs {
        let sem_clone = Arc::clone(&sem);
        join_set.spawn(async move {
            let _permit = sem_clone.acquire_owned().await;
            (key, probe_certificate(&req).await)
        });
    }

    let mut results: HashMap<
        (String, u16, String, String, Vec<String>),
        Result<ProbedCertificate, String>,
    > = HashMap::new();
    while let Some(joined) = join_set.join_next().await {
        if let Ok((key, res)) = joined {
            results.insert(key, res.map_err(|e| e.to_string()));
        }
    }

    let mut pinned_nodes = 0usize;
    let mut failed_nodes = 0usize;
    let mut errors = Vec::new();

    let mut store = state.store.lock().map_err(|e| e.to_string())?;
    for mut node in targets {
        let key = probe_key_for(&node);
        match results.get(&key) {
            Some(Ok(probed)) => match evaluate_probe_against_node(&node, probed) {
                Ok(eval) => {
                    apply_confirmed_pin(&mut node, eval.proposed_trust_record);
                    if store.update_node(&node).is_ok() {
                        pinned_nodes += 1;
                    } else {
                        failed_nodes += 1;
                    }
                }
                Err(e) => {
                    failed_nodes += 1;
                    if errors.len() < 5 {
                        errors.push(format!("{}: {e}", node.name));
                    }
                }
            },
            Some(Err(err)) => {
                failed_nodes += 1;
                if errors.len() < 5 {
                    errors.push(format!("{}: {err}", node.name));
                }
            }
            None => failed_nodes += 1,
        }
    }

    Ok(BatchPinSummary {
        probed_endpoints,
        pinned_nodes,
        failed_nodes,
        errors,
    })
}

#[tauri::command]
fn confirm_node_pin(
    state: State<'_, AppState>,
    node_id: String,
    trust_record: TrustRecord,
) -> Result<NodeConfig, String> {
    let mut store = state.store.lock().map_err(|e| e.to_string())?;
    let mut node = store.get_node(&node_id).map_err(|e| e.to_string())?;
    apply_confirmed_pin(&mut node, trust_record);
    store.update_node(&node).map_err(|e| e.to_string())?;
    Ok(node)
}

#[tauri::command]
fn set_insecure_override(
    state: State<'_, AppState>,
    node_id: String,
    confirmed: bool,
) -> Result<NodeConfig, String> {
    let mut store = state.store.lock().map_err(|e| e.to_string())?;
    store
        .set_insecure_override(&node_id, confirmed)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn start_proxy(
    state: State<'_, AppState>,
    profile_id: String,
    node_id: String,
    enable_system_proxy: bool,
) -> Result<RuntimeStatus, String> {
    let _lifecycle = state.lifecycle_lock.lock().await;
    if state.shutdown_requested.load(Ordering::Acquire) {
        return Err("应用正在退出，已取消连接".into());
    }
    let my_epoch = state.lifecycle_epoch.fetch_add(1, Ordering::AcqRel) + 1;

    let (profile, node, mut policy) = {
        let store = state.store.lock().map_err(|e| e.to_string())?;
        let profile = store.get_profile(&profile_id).map_err(|e| e.to_string())?;
        let node = store.get_node(&node_id).map_err(|e| e.to_string())?;
        let policy = store.load_runtime_policy().map_err(|e| e.to_string())?;
        (profile, node, policy)
    };

    let use_tun = policy.proxy_mode == ProxyMode::Tun;
    policy.tun_enabled = use_tun;

    let compiled = compile_singbox_v14(&CompileInput {
        active_node: &node,
        rules: &profile.rules,
        general: &profile.general,
        approved_hosts: &profile.hosts,
        policy: &policy,
    })
    .map_err(|e| e.to_string())?;

    // Stop any previous user-mode or TUN instance cleanly first
    {
        let mut sup = state.supervisor.lock().await;
        let _ = sup.stop().await;
    }
    {
        let mut sp = state.sysproxy.lock().map_err(|e| e.to_string())?;
        if sp.disable_and_restore().is_err() {
            let _ = sp.force_disable();
        }
    }
    let _ = tokio::task::spawn_blocking(TunServiceClient::stop_tun).await;
    invalidate_tun_status_cache(&state).await;
    if let Ok(mut guard) = state.clash_api_session.lock() {
        *guard = None;
    }

    if state.shutdown_requested.load(Ordering::Acquire)
        || state.lifecycle_epoch.load(Ordering::Acquire) != my_epoch
    {
        return Err("连接已被新的断开或退出操作取消".into());
    }

    if use_tun {
        let cfg_json = serde_json::to_string(&compiled.json).map_err(|e| e.to_string())?;
        let pid = tokio::task::spawn_blocking(move || TunServiceClient::start_tun(cfg_json))
            .await
            .map_err(|e| format!("TUN 启动任务异常: {e}"))?
            .map_err(|e| e.to_string())?;
        invalidate_tun_status_cache(&state).await;
        if state.shutdown_requested.load(Ordering::Acquire)
            || state.lifecycle_epoch.load(Ordering::Acquire) != my_epoch
        {
            let _ = tokio::task::spawn_blocking(TunServiceClient::stop_tun).await;
            invalidate_tun_status_cache(&state).await;
            return Err("连接已被新的断开或退出操作取消".into());
        }
        if let Ok(mut guard) = state.tun_active_node.lock() {
            *guard = Some((node.id.clone(), node.name.clone()));
        }
        if let Ok(mut guard) = state.clash_api_session.lock() {
            *guard = Some(ActiveClashApiSession {
                port: policy.clash_api_port,
                secret: compiled.clash_api_secret.clone(),
                started_at: Instant::now(),
                prev_upload_total: 0,
                prev_download_total: 0,
                prev_sample_at: None,
            });
        }
        return Ok(RuntimeStatus {
            running: true,
            pid: Some(pid),
            active_node_id: Some(node.id),
            active_node_name: Some(node.name),
            clash_api_port: Some(policy.clash_api_port),
            mixed_port: Some(policy.mixed_listen_port),
            system_proxy_enabled: false,
            tun_active: true,
            last_mitm_alert: None,
        });
    }

    if let Ok(mut guard) = state.tun_active_node.lock() {
        *guard = None;
    }

    let mut sup = state.supervisor.lock().await;
    sup.start(
        node.id.clone(),
        node.name.clone(),
        &compiled,
        policy.mixed_listen_port,
        policy.clash_api_port,
    )
    .await
    .map_err(|e| e.to_string())?;

    // Re-check shutdown / epoch cancellation strictly BEFORE enabling Windows System Proxy!
    if state.shutdown_requested.load(Ordering::Acquire)
        || state.lifecycle_epoch.load(Ordering::Acquire) != my_epoch
    {
        let _ = sup.stop().await;
        return Err("连接已被新的断开或退出操作取消".into());
    }

    if let Ok(mut guard) = state.clash_api_session.lock() {
        *guard = Some(ActiveClashApiSession {
            port: policy.clash_api_port,
            secret: compiled.clash_api_secret.clone(),
            started_at: Instant::now(),
            prev_upload_total: 0,
            prev_download_total: 0,
            prev_sample_at: None,
        });
    }

    let mut status = sup.status();
    if enable_system_proxy {
        let enable_res = {
            let mut sp = state.sysproxy.lock().map_err(|e| e.to_string())?;
            sp.enable(policy.mixed_listen_port, &profile.general.skip_proxy)
        };
        if let Err(e) = enable_res {
            let _ = sup.stop().await;
            if let Ok(mut guard) = state.clash_api_session.lock() {
                *guard = None;
            }
            return Err(format!("启用 Windows 系统代理失败：{e}"));
        }
        status.system_proxy_enabled = true;
    }
    Ok(status)
}

#[tauri::command]
async fn stop_proxy(state: State<'_, AppState>) -> Result<RuntimeStatus, String> {
    state.lifecycle_epoch.fetch_add(1, Ordering::AcqRel);
    let _lifecycle = state.lifecycle_lock.lock().await;

    let sysproxy_err: Option<String> = {
        let mut sp = state.sysproxy.lock().map_err(|e| e.to_string())?;
        match sp.disable_and_restore() {
            Ok(()) => None,
            Err(first_err) => match sp.force_disable() {
                Ok(()) => None,
                Err(second_err) => Some(format!("{first_err}；强制清除亦失败：{second_err}")),
            },
        }
    };
    let _ = tokio::task::spawn_blocking(TunServiceClient::stop_tun).await;
    invalidate_tun_status_cache(&state).await;
    if let Ok(mut guard) = state.tun_active_node.lock() {
        *guard = None;
    }
    if let Ok(mut guard) = state.clash_api_session.lock() {
        *guard = None;
    }
    let mut sup = state.supervisor.lock().await;
    sup.stop().await.map_err(|e| e.to_string())?;
    let mut status = sup.status();
    status.system_proxy_enabled = false;
    status.tun_active = false;
    if let Some(err) = sysproxy_err {
        return Err(format!("已停止代理内核，但关闭 Windows 系统代理失败：{err}"));
    }
    Ok(status)
}

/// Emergency 1-click recovery command: stops any running proxy/TUN instance and
/// unconditionally clears Windows System Proxy (`PROXY_TYPE_DIRECT` + `ProxyEnable=0`)
/// across LAN and PPPoE/RAS entries, then broadcasts WinINet refresh.
#[tauri::command]
async fn reset_system_proxy(state: State<'_, AppState>) -> Result<String, String> {
    state.lifecycle_epoch.fetch_add(1, Ordering::AcqRel);
    let _lifecycle = state.lifecycle_lock.lock().await;

    let _ = tokio::task::spawn_blocking(TunServiceClient::stop_tun).await;
    invalidate_tun_status_cache(&state).await;
    if let Ok(mut guard) = state.tun_active_node.lock() {
        *guard = None;
    }
    if let Ok(mut guard) = state.clash_api_session.lock() {
        *guard = None;
    }
    {
        let mut sup = state.supervisor.lock().await;
        let _ = sup.stop().await;
    }
    {
        let mut sp = state.sysproxy.lock().map_err(|e| e.to_string())?;
        sp.force_disable()
            .map_err(|e| format!("强制关闭 Windows 系统代理失败：{e}"))?;
    }
    Ok("已强制关闭 Windows 系统代理并刷新 WinINet 网络配置，浏览器可立即直连恢复。".to_string())
}

/// Queries the local loopback Clash API (`/connections`) strictly from Rust with Bearer auth
/// (never exposing the Clash API secret to the WebView) and computes live throughput & Max-Q index.
#[tauri::command]
async fn get_runtime_telemetry(state: State<'_, AppState>) -> Result<RuntimeTelemetry, String> {
    let session_meta = {
        let guard = state.clash_api_session.lock().map_err(|e| e.to_string())?;
        guard
            .as_ref()
            .map(|s| (s.port, s.secret.clone(), s.started_at))
    };
    let Some((port, secret, started_at)) = session_meta else {
        return Ok(RuntimeTelemetry::default());
    };

    let url = format!("http://127.0.0.1:{port}/connections");
    let resp = match state
        .local_http_client
        .get(&url)
        .bearer_auth(&secret)
        .timeout(Duration::from_millis(1200))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        _ => {
            return Ok(RuntimeTelemetry {
                connected: true,
                uptime_secs: started_at.elapsed().as_secs(),
                ..RuntimeTelemetry::default()
            });
        }
    };

    let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    let root: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    let upload_total = root
        .get("uploadTotal")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let download_total = root
        .get("downloadTotal")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let now = Instant::now();
    let (upload_bps, download_bps) = {
        let mut guard = state.clash_api_session.lock().map_err(|e| e.to_string())?;
        if let Some(sess) = guard.as_mut() {
            let rates = if let Some(prev_at) = sess.prev_sample_at {
                let dt = now.duration_since(prev_at).as_secs_f64().max(0.25);
                let du = upload_total.saturating_sub(sess.prev_upload_total) as f64;
                let dd = download_total.saturating_sub(sess.prev_download_total) as f64;
                ((du / dt) as u64, (dd / dt) as u64)
            } else {
                (0, 0)
            };
            sess.prev_upload_total = upload_total;
            sess.prev_download_total = download_total;
            sess.prev_sample_at = Some(now);
            rates
        } else {
            (0, 0)
        }
    };

    let conns_arr = root
        .get("connections")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let active_connections = conns_arr.len();

    let mut recent_connections = Vec::with_capacity(conns_arr.len().min(15));
    for c in conns_arr.iter().rev().take(15) {
        let meta = c.get("metadata").unwrap_or(&Value::Null);
        let host = meta
            .get("host")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .or_else(|| meta.get("destinationIP").and_then(|v| v.as_str()))
            .unwrap_or("unknown")
            .to_string();
        let port = meta
            .get("destinationPort")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let network = meta
            .get("network")
            .and_then(|v| v.as_str())
            .unwrap_or("tcp")
            .to_string();
        let rule = c
            .get("rule")
            .and_then(|v| v.as_str())
            .unwrap_or("Match")
            .to_string();
        let chain = c
            .get("chains")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .unwrap_or("direct")
            .to_string();
        let id = c
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let upload = c.get("upload").and_then(|v| v.as_u64()).unwrap_or(0);
        let download = c.get("download").and_then(|v| v.as_u64()).unwrap_or(0);

        recent_connections.push(LiveConnectionItem {
            id,
            host,
            port,
            network,
            rule,
            chain,
            upload,
            download,
        });
    }

    // Max-Q Dynamic Pressure index (0..=100): smooth log-scale blend of throughput + concurrency
    let total_bps = (upload_bps + download_bps) as f64;
    let speed_factor = if total_bps <= 1.0 {
        0.0
    } else {
        ((total_bps.log10() - 2.0) / 5.5).clamp(0.0, 1.0)
    };
    let conn_factor = ((active_connections as f64) / 40.0).clamp(0.0, 1.0);
    let dynamic_pressure_q = ((speed_factor * 0.78 + conn_factor * 0.22) * 100.0) as f32;

    Ok(RuntimeTelemetry {
        connected: true,
        upload_bps,
        download_bps,
        upload_total,
        download_total,
        active_connections,
        uptime_secs: started_at.elapsed().as_secs(),
        dynamic_pressure_q,
        recent_connections,
    })
}

#[tauri::command]
async fn close_all_connections(state: State<'_, AppState>) -> Result<(), String> {
    let session_meta = {
        let guard = state.clash_api_session.lock().map_err(|e| e.to_string())?;
        guard.as_ref().map(|s| (s.port, s.secret.clone()))
    };
    let Some((port, secret)) = session_meta else {
        return Ok(());
    };
    let url = format!("http://127.0.0.1:{port}/connections");
    let _ = state
        .local_http_client
        .delete(&url)
        .bearer_auth(&secret)
        .timeout(Duration::from_secs(2))
        .send()
        .await;
    Ok(())
}

#[tauri::command]
async fn get_runtime_status(state: State<'_, AppState>) -> Result<RuntimeStatus, String> {
    let tun_st = query_tun_status_coalesced(&state, false).await;
    if tun_st.tun_active {
        let (nid, nname) = state
            .tun_active_node
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .map(|(a, b)| (Some(a), Some(b)))
            .unwrap_or((None, None));
        let clash_port = state
            .clash_api_session
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|s| s.port));
        return Ok(RuntimeStatus {
            running: true,
            pid: tun_st.singbox_pid,
            active_node_id: nid,
            active_node_name: nname,
            clash_api_port: clash_port,
            mixed_port: None,
            system_proxy_enabled: false,
            tun_active: true,
            last_mitm_alert: tun_st.last_mitm_alert,
        });
    }

    let mut sup = state.supervisor.lock().await;
    let was_running = sup.status().running;
    let alive = sup.poll_alive();

    // Auto-heal: if sing-box.exe died unexpectedly (crash / antivirus kill / OOM),
    // immediately turn OFF Windows System Proxy so the user's browser is NEVER stranded!
    if was_running && !alive {
        if let Ok(mut sp) = state.sysproxy.lock() {
            if sp.disable_and_restore().is_err() {
                let _ = sp.force_disable();
            }
        }
        if let Ok(mut guard) = state.clash_api_session.lock() {
            *guard = None;
        }
    }

    let mut status = sup.status();
    let sp = state.sysproxy.lock().map_err(|e| e.to_string())?;
    status.system_proxy_enabled = sp.is_active();
    status.tun_active = false;
    Ok(status)
}

#[tauri::command]
async fn get_runtime_logs(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let tun_st = query_tun_status_coalesced(&state, false).await;
    if tun_st.tun_active {
        let lines = tokio::task::spawn_blocking(TunServiceClient::get_logs)
            .await
            .unwrap_or_default();
        return Ok(lines);
    }
    let sup = state.supervisor.lock().await;
    Ok(sup.recent_logs())
}

#[tauri::command]
fn get_runtime_policy(state: State<'_, AppState>) -> Result<RuntimePolicy, String> {
    let store = state.store.lock().map_err(|e| e.to_string())?;
    store.load_runtime_policy().map_err(|e| e.to_string())
}

#[tauri::command]
fn update_runtime_policy(
    state: State<'_, AppState>,
    policy: RuntimePolicy,
) -> Result<RuntimePolicy, String> {
    validate_runtime_policy(&policy)?;
    let store = state.store.lock().map_err(|e| e.to_string())?;
    store
        .save_runtime_policy(&policy)
        .map_err(|e| e.to_string())?;
    store.load_runtime_policy().map_err(|e| e.to_string())
}

fn resolve_bundled_binary(app: &tauri::App, bin_name: &str) -> Option<PathBuf> {
    if let Ok(res_dir) = app.path().resource_dir() {
        let candidate = res_dir.join("resources").join(bin_name);
        if candidate.is_absolute() && candidate.exists() {
            return Some(candidate);
        }
        let direct = res_dir.join(bin_name);
        if direct.is_absolute() && direct.exists() {
            return Some(direct);
        }
    }
    None
}

/// Unified, idempotent runtime teardown executed on tray quit, window close/destroy,
/// and Tauri `RunEvent::ExitRequested` / `RunEvent::Exit` (including OS logoff/shutdown).
fn cleanup_all_runtime(app_handle: &tauri::AppHandle, is_shutdown: bool) {
    let state = app_handle.state::<AppState>();

    // Cancel any in-flight `start_proxy` FIRST so it can never re-enable system proxy after cleanup
    if is_shutdown {
        state.shutdown_requested.store(true, Ordering::Release);
    }
    state.lifecycle_epoch.fetch_add(1, Ordering::AcqRel);

    if let Ok(mut sp) = state.sysproxy.lock() {
        if sp.disable_and_restore().is_err() {
            let _ = sp.force_disable();
        }
    }

    let _ = TunServiceClient::stop_tun();
    if let Ok(mut cache) = state.tun_status_cache.try_lock() {
        *cache = None;
    }

    if let Ok(mut guard) = state.tun_active_node.lock() {
        *guard = None;
    }
    if let Ok(mut guard) = state.clash_api_session.lock() {
        *guard = None;
    }

    if let Ok(mut sup) = state.supervisor.try_lock() {
        sup.stop_sync();
    } else {
        tauri::async_runtime::block_on(async {
            let mut sup = state.supervisor.lock().await;
            sup.stop_sync();
        });
    };
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Enforce single desktop instance BEFORE touching `sysproxy-backup.json` or SQLite vault!
    let _single_instance = match SingleInstanceGuard::acquire_or_focus_existing(
        "MaxQ — Powered by JaxCore sing-box",
    ) {
        Some(guard) => guard,
        None => return,
    };

    tauri::Builder::default()
        .setup(|app| {
            let data_dir = app
                .path()
                .app_local_data_dir()
                .expect("failed to resolve app local data dir");
            std::fs::create_dir_all(&data_dir)?;

            let db_path = data_dir.join("maxq-vault.db");
            let store = VaultStore::open(&db_path).expect("failed to open MaxQ SQLite vault");

            let runtime_dir = data_dir.join("runtime");
            // Remove any stale plaintext runtime config left behind by a sudden power loss
            let _ = std::fs::remove_file(runtime_dir.join("active-config.json"));
            let mut sysproxy = SystemProxyManager::new(&runtime_dir);
            if sysproxy.recover_if_dirty().is_err() {
                let _ = sysproxy.force_disable();
            }

            let singbox_name = if cfg!(windows) {
                "sing-box.exe"
            } else {
                "sing-box"
            };
            let singbox_path = resolve_bundled_binary(app, singbox_name)
                .unwrap_or_else(|| PathBuf::from(singbox_name));
            let service_exe_path = resolve_bundled_binary(app, "maxq-service.exe");
            let supervisor = SingBoxSupervisor::new(singbox_path, runtime_dir);
            let local_http_client = reqwest::Client::builder()
                .no_proxy()
                .pool_max_idle_per_host(2)
                .build()
                .expect("failed to build loopback Clash API HTTP client");

            app.manage(AppState {
                store: Mutex::new(store),
                supervisor: AsyncMutex::new(supervisor),
                sysproxy: Mutex::new(sysproxy),
                service_exe_path,
                tun_active_node: Mutex::new(None),
                clash_api_session: Mutex::new(None),
                local_http_client,
                tun_status_cache: AsyncMutex::new(None),
                lifecycle_lock: AsyncMutex::new(()),
                shutdown_requested: AtomicBool::new(false),
                lifecycle_epoch: AtomicU64::new(0),
            });

            // Build system tray for quick show/hide, emergency proxy reset, and clean quit
            let show_item = MenuItem::with_id(app, "show", "打开 MaxQ", true, None::<&str>)?;
            let reset_proxy_item = MenuItem::with_id(
                app,
                "reset_proxy",
                "强制关闭系统代理（恢复直连）",
                true,
                None::<&str>,
            )?;
            let quit_item =
                MenuItem::with_id(app, "quit", "断开并退出 MaxQ", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_item, &reset_proxy_item, &quit_item])?;

            let mut tray_builder = TrayIconBuilder::new()
                .menu(&menu)
                .tooltip("MaxQ — Powered by JaxCore sing-box")
                .on_menu_event(|app_handle, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(w) = app_handle.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "reset_proxy" => {
                        cleanup_all_runtime(app_handle, false);
                        let state = app_handle.state::<AppState>();
                        if let Ok(mut sp) = state.sysproxy.lock() {
                            let _ = sp.force_disable();
                        };
                    }
                    "quit" => {
                        cleanup_all_runtime(app_handle, true);
                        app_handle.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        if let Some(w) = tray.app_handle().get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                });
            if let Some(icon) = app.default_window_icon().cloned() {
                tray_builder = tray_builder.icon(icon);
            }
            let _ = tray_builder.build(app);

            Ok(())
        })
        .on_window_event(|window, event| {
            if matches!(
                event,
                tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed
            ) {
                cleanup_all_runtime(window.app_handle(), true);
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_builtin_rules_info,
            get_tun_service_status,
            install_tun_service,
            uninstall_tun_service,
            fetch_subscription_url,
            preview_import,
            commit_import,
            list_profiles,
            get_profile,
            delete_profile,
            rename_profile,
            get_about_info,
            export_diagnostics_summary,
            update_profile_hosts,
            test_node_latency,
            batch_test_latencies,
            probe_node_certificate,
            batch_probe_and_pin_profile,
            confirm_node_pin,
            set_insecure_override,
            start_proxy,
            stop_proxy,
            reset_system_proxy,
            get_runtime_telemetry,
            close_all_connections,
            get_runtime_status,
            get_runtime_logs,
            get_runtime_policy,
            update_runtime_policy,
        ])
        .build(tauri::generate_context!())
        .expect("error while building MaxQ desktop application")
        .run(|app_handle, event| {
            if matches!(
                event,
                tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit
            ) {
                cleanup_all_runtime(app_handle, true);
            }
        });
}
