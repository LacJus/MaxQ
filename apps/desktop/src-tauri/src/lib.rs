use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Mutex;

use maxq_cert_probe::{
    apply_confirmed_pin, evaluate_probe_against_node, probe_certificate, ProbeRequest,
    ProbedCertificate,
};
use maxq_core_model::{
    HostEntry, NodeConfig, PinCheckOutcome, RuntimePolicy, SanitizedImport, TrustRecord,
};
use maxq_core_runtime::system_proxy::SystemProxyManager;
use maxq_core_runtime::{RuntimeStatus, SingBoxSupervisor};
use maxq_parser::parse_input;
use maxq_sanitizer::{apply_approved_host_aliases, sanitize_import};
use maxq_singbox_compiler::{compile_singbox_v14, CompileInput};
use maxq_storage::{ProfileSummary, StoredProfile, VaultStore};
use serde::Serialize;
use tauri::{Manager, State};
use tokio::sync::Mutex as AsyncMutex;

pub struct AppState {
    pub store: Mutex<VaultStore>,
    pub supervisor: AsyncMutex<SingBoxSupervisor>,
    pub sysproxy: Mutex<SystemProxyManager>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeNodeResult {
    pub probed: ProbedCertificate,
    pub outcome: PinCheckOutcome,
    pub proposed_trust_record: TrustRecord,
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
    let (profile, node, policy) = {
        let store = state.store.lock().map_err(|e| e.to_string())?;
        let profile = store.get_profile(&profile_id).map_err(|e| e.to_string())?;
        let node = store.get_node(&node_id).map_err(|e| e.to_string())?;
        let policy = store.load_runtime_policy().map_err(|e| e.to_string())?;
        (profile, node, policy)
    };

    let compiled = compile_singbox_v14(&CompileInput {
        active_node: &node,
        rules: &profile.rules,
        general: &profile.general,
        approved_hosts: &profile.hosts,
        policy: &policy,
    })
    .map_err(|e| e.to_string())?;

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
    let mut sup = state.supervisor.lock().await;
    sup.stop().await.map_err(|e| e.to_string())?;
    let mut status = sup.status();
    status.system_proxy_enabled = false;
    Ok(status)
}

#[tauri::command]
async fn get_runtime_status(state: State<'_, AppState>) -> Result<RuntimeStatus, String> {
    let sup = state.supervisor.lock().await;
    let mut status = sup.status();
    let sp = state.sysproxy.lock().map_err(|e| e.to_string())?;
    status.system_proxy_enabled = sp.is_active();
    Ok(status)
}

#[tauri::command]
async fn get_runtime_logs(state: State<'_, AppState>) -> Result<Vec<String>, String> {
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

fn resolve_singbox_binary(app: &tauri::App) -> PathBuf {
    let bin_name = if cfg!(windows) {
        "sing-box.exe"
    } else {
        "sing-box"
    };
    if let Ok(res_dir) = app.path().resource_dir() {
        let candidate = res_dir.join("resources").join(bin_name);
        if candidate.exists() {
            return candidate;
        }
        let direct = res_dir.join(bin_name);
        if direct.exists() {
            return direct;
        }
    }
    PathBuf::from(bin_name)
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

            let singbox_path = resolve_singbox_binary(app);
            let supervisor = SingBoxSupervisor::new(singbox_path, runtime_dir);

            app.manage(AppState {
                store: Mutex::new(store),
                supervisor: AsyncMutex::new(supervisor),
                sysproxy: Mutex::new(sysproxy),
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                let state = window.state::<AppState>();
                if let Ok(mut sp) = state.sysproxy.lock() {
                    let _ = sp.disable_and_restore();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            preview_import,
            commit_import,
            list_profiles,
            get_profile,
            delete_profile,
            update_profile_hosts,
            probe_node_certificate,
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
