use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
use maxq_core_runtime::{RuntimeStatus, SingBoxSupervisor};
use maxq_parser::parse_input;
use maxq_sanitizer::{
    apply_approved_host_aliases, is_non_public_ip, sanitize_import, validate_safe_remote_url,
};
use maxq_singbox_compiler::{builtin_default_rules_count, compile_singbox_v14, CompileInput};
use maxq_storage::{ProfileSummary, StoredProfile, VaultStore};
use maxq_win_service::protocol::TunServiceStatus;
use serde::Serialize;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Manager, State};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};

pub struct AppState {
    pub store: Mutex<VaultStore>,
    pub supervisor: AsyncMutex<SingBoxSupervisor>,
    pub sysproxy: Mutex<SystemProxyManager>,
    pub service_exe_path: Option<PathBuf>,
    pub tun_active_node: Mutex<Option<(String, String)>>,
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

#[tauri::command]
fn get_builtin_rules_info() -> BuiltinRulesInfo {
    BuiltinRulesInfo {
        rule_count: builtin_default_rules_count(),
        description: "MaxQ 内置默认分流规则（国内直连域名 + CN IP-CIDR + 海外代理，已完全脱敏）"
            .to_string(),
    }
}

#[tauri::command]
fn get_tun_service_status() -> TunServiceStatus {
    TunServiceClient::query_status()
}

#[tauri::command]
fn install_tun_service(state: State<'_, AppState>) -> Result<String, String> {
    let exe = state
        .service_exe_path
        .as_ref()
        .ok_or_else(|| "未找到已打包的绝对路径 maxq-service.exe，请通过官方安装包安装 MaxQ。".to_string())?;
    TunServiceClient::install_elevated(exe).map_err(|e| e.to_string())?;
    Ok("已触发 UAC 提权安装 MaxQ 安全加固 TUN 服务，请稍候 2 秒刷新状态。".into())
}

#[tauri::command]
fn uninstall_tun_service(state: State<'_, AppState>) -> Result<String, String> {
    let _ = TunServiceClient::stop_tun();
    let exe = state
        .service_exe_path
        .as_ref()
        .ok_or_else(|| "未找到已打包的绝对路径 maxq-service.exe。".to_string())?;
    TunServiceClient::uninstall_elevated(exe).map_err(|e| e.to_string())?;
    Ok("已触发 UAC 提权卸载 MaxQ TUN 服务。".into())
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

        // 3. Pin verified SocketAddr into reqwest client and disable auto-redirects (H-2)
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("MaxQ/0.2 (Shadowrocket compatible)")
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
fn delete_profile(state: State<'_, AppState>, profile_id: String) -> Result<(), String> {
    let mut store = state.store.lock().map_err(|e| e.to_string())?;
    store.delete_profile(&profile_id).map_err(|e| e.to_string())
}

#[tauri::command]
fn update_profile_hosts(
    state: State<'_, AppState>,
    profile_id: String,
    hosts: Vec<HostEntry>,
) -> Result<StoredProfile, String> {
    let mut store = state.store.lock().map_err(|e| e.to_string())?;
    let mut profile = store.get_profile(&profile_id).map_err(|e| e.to_string())?;
    for n in &mut profile.nodes {
        n.dial_override_server = None;
    }
    apply_approved_host_aliases(&mut profile.nodes, &hosts);
    store
        .update_profile_hosts(&profile_id, &hosts, &profile.nodes)
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
        let _ = sp.disable_and_restore();
    }
    let _ = TunServiceClient::stop_tun();

    if use_tun {
        let cfg_json = serde_json::to_string(&compiled.json).map_err(|e| e.to_string())?;
        let pid = TunServiceClient::start_tun(cfg_json).map_err(|e| e.to_string())?;
        if let Ok(mut guard) = state.tun_active_node.lock() {
            *guard = Some((node.id.clone(), node.name.clone()));
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

    let mut status = sup.status();
    if enable_system_proxy {
        let mut sp = state.sysproxy.lock().map_err(|e| e.to_string())?;
        sp.enable(policy.mixed_listen_port, &profile.general.skip_proxy)
            .map_err(|e| e.to_string())?;
        status.system_proxy_enabled = true;
    }
    Ok(status)
}

#[tauri::command]
async fn stop_proxy(state: State<'_, AppState>) -> Result<RuntimeStatus, String> {
    {
        let mut sp = state.sysproxy.lock().map_err(|e| e.to_string())?;
        let _ = sp.disable_and_restore();
    }
    let _ = TunServiceClient::stop_tun();
    if let Ok(mut guard) = state.tun_active_node.lock() {
        *guard = None;
    }
    let mut sup = state.supervisor.lock().await;
    sup.stop().await.map_err(|e| e.to_string())?;
    let mut status = sup.status();
    status.system_proxy_enabled = false;
    status.tun_active = false;
    Ok(status)
}

#[tauri::command]
async fn get_runtime_status(state: State<'_, AppState>) -> Result<RuntimeStatus, String> {
    let tun_st = TunServiceClient::query_status();
    if tun_st.tun_active {
        let (nid, nname) = state
            .tun_active_node
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .map(|(a, b)| (Some(a), Some(b)))
            .unwrap_or((None, None));
        return Ok(RuntimeStatus {
            running: true,
            pid: tun_st.singbox_pid,
            active_node_id: nid,
            active_node_name: nname,
            clash_api_port: None,
            mixed_port: None,
            system_proxy_enabled: false,
            tun_active: true,
            last_mitm_alert: tun_st.last_mitm_alert,
        });
    }

    let sup = state.supervisor.lock().await;
    let mut status = sup.status();
    let sp = state.sysproxy.lock().map_err(|e| e.to_string())?;
    status.system_proxy_enabled = sp.is_active();
    status.tun_active = false;
    Ok(status)
}

#[tauri::command]
async fn get_runtime_logs(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let tun_st = TunServiceClient::query_status();
    if tun_st.tun_active {
        return Ok(TunServiceClient::get_logs());
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
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
            let mut sysproxy = SystemProxyManager::new(&runtime_dir);
            let _ = sysproxy.recover_if_dirty();

            let singbox_name = if cfg!(windows) {
                "sing-box.exe"
            } else {
                "sing-box"
            };
            let singbox_path = resolve_bundled_binary(app, singbox_name)
                .unwrap_or_else(|| PathBuf::from(singbox_name));
            let service_exe_path = resolve_bundled_binary(app, "maxq-service.exe");
            let supervisor = SingBoxSupervisor::new(singbox_path, runtime_dir);

            app.manage(AppState {
                store: Mutex::new(store),
                supervisor: AsyncMutex::new(supervisor),
                sysproxy: Mutex::new(sysproxy),
                service_exe_path,
                tun_active_node: Mutex::new(None),
            });

            // Build system tray for quick show/hide and clean quit
            let show_item = MenuItem::with_id(app, "show", "打开 MaxQ", true, None::<&str>)?;
            let quit_item =
                MenuItem::with_id(app, "quit", "断开并退出 MaxQ", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_item, &quit_item])?;

            let mut tray_builder = TrayIconBuilder::new()
                .menu(&menu)
                .tooltip("MaxQ — Secure sing-box Client")
                .on_menu_event(|app_handle, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(w) = app_handle.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "quit" => {
                        let state = app_handle.state::<AppState>();
                        if let Ok(mut sp) = state.sysproxy.lock() {
                            let _ = sp.disable_and_restore();
                        };
                        let _ = TunServiceClient::stop_tun();
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
            if let tauri::WindowEvent::Destroyed = event {
                let state = window.state::<AppState>();
                if let Ok(mut sp) = state.sysproxy.lock() {
                    let _ = sp.disable_and_restore();
                };
                let _ = TunServiceClient::stop_tun();
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
            update_profile_hosts,
            test_node_latency,
            probe_node_certificate,
            batch_probe_and_pin_profile,
            confirm_node_pin,
            set_insecure_override,
            start_proxy,
            stop_proxy,
            get_runtime_status,
            get_runtime_logs,
            get_runtime_policy,
            update_runtime_policy,
        ])
        .run(tauri::generate_context!())
        .expect("error while running MaxQ desktop application");
}
