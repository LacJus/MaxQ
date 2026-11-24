use std::path::Path;

use chrono::{DateTime, Utc};
use maxq_core_model::{
    GeneralSettings, HostEntry, NodeConfig, RuleEntry, RuntimePolicy, SanitizedImport,
    TlsVerifyMode, TrustRecord,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("record not found: {0}")]
    NotFound(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSummary {
    pub id: String,
    pub name: String,
    pub node_count: usize,
    pub rule_count: usize,
    pub host_count: usize,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredProfile {
    pub id: String,
    pub name: String,
    pub general: GeneralSettings,
    pub nodes: Vec<NodeConfig>,
    pub rules: Vec<RuleEntry>,
    pub hosts: Vec<HostEntry>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Persistent SQLite store for MaxQ canonical IR profiles, nodes, and TOFU Trust Vault.
/// Uses bundled SQLite with WAL mode so Windows builds require zero external DLLs.
pub struct VaultStore {
    conn: Connection,
}

impl VaultStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<(), StorageError> {
        self.conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS profiles (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                general_json TEXT NOT NULL,
                rules_json TEXT NOT NULL,
                hosts_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY,
                profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
                sort_order INTEGER NOT NULL,
                node_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_nodes_profile ON nodes(profile_id, sort_order);

            CREATE TABLE IF NOT EXISTS trust_vault (
                node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
                spki_sha256_b64 TEXT NOT NULL,
                cert_sha256_hex TEXT NOT NULL,
                record_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS kv_settings (
                key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL
            );
            "#,
        )?;
        Ok(())
    }

    /// Saves a `SanitizedImport` as a new profile and persists all its nodes atomically.
    pub fn save_sanitized_import(
        &mut self,
        profile_name: impl Into<String>,
        import: &SanitizedImport,
    ) -> Result<String, StorageError> {
        let profile_id = Uuid::new_v4().to_string();
        let name = profile_name.into();
        let now = Utc::now().to_rfc3339();

        let general_json = serde_json::to_string(&import.general)?;
        let rules_json = serde_json::to_string(&import.rules)?;
        let hosts_json = serde_json::to_string(&import.hosts)?;

        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO profiles (id, name, general_json, rules_json, hosts_json, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
            params![profile_id, name, general_json, rules_json, hosts_json, now],
        )?;

        for (idx, node) in import.nodes.iter().enumerate() {
            let node_json = serde_json::to_string(node)?;
            tx.execute(
                "INSERT INTO nodes (id, profile_id, sort_order, node_json, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![node.id, profile_id, idx as i64, node_json, now],
            )?;
            if let Some(tr) = &node.tls.trust_record {
                let rec_json = serde_json::to_string(tr)?;
                tx.execute(
                    "INSERT INTO trust_vault (node_id, spki_sha256_b64, cert_sha256_hex, record_json, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![node.id, tr.spki_sha256_b64, tr.cert_sha256_hex, rec_json, now],
                )?;
            }
        }
        tx.commit()?;
        Ok(profile_id)
    }

    pub fn list_profiles(&self) -> Result<Vec<ProfileSummary>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT p.id, p.name, p.rules_json, p.hosts_json, p.created_at, p.updated_at,
                    (SELECT COUNT(*) FROM nodes n WHERE n.profile_id = p.id) as node_count
             FROM profiles p
             ORDER BY p.updated_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            let id: String = row.get(0)?;
            let name: String = row.get(1)?;
            let rules_json: String = row.get(2)?;
            let hosts_json: String = row.get(3)?;
            let created_str: String = row.get(4)?;
            let updated_str: String = row.get(5)?;
            let node_count: i64 = row.get(6)?;
            Ok((
                id,
                name,
                rules_json,
                hosts_json,
                created_str,
                updated_str,
                node_count,
            ))
        })?;

        let mut out = Vec::new();
        for item in rows {
            let (id, name, rules_json, hosts_json, created_str, updated_str, node_count) = item?;
            let rules: Vec<RuleEntry> = serde_json::from_str(&rules_json)?;
            let hosts: Vec<HostEntry> = serde_json::from_str(&hosts_json)?;
            out.push(ProfileSummary {
                id,
                name,
                node_count: node_count.max(0) as usize,
                rule_count: rules.len(),
                host_count: hosts.len(),
                created_at: DateTime::parse_from_rfc3339(&created_str)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                updated_at: DateTime::parse_from_rfc3339(&updated_str)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            });
        }
        Ok(out)
    }

    pub fn get_profile(&self, profile_id: &str) -> Result<StoredProfile, StorageError> {
        let row = self
            .conn
            .query_row(
                "SELECT id, name, general_json, rules_json, hosts_json, created_at, updated_at
                 FROM profiles WHERE id = ?1",
                params![profile_id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                        r.get::<_, String>(6)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| StorageError::NotFound(format!("profile {profile_id}")))?;

        let mut stmt = self.conn.prepare(
            "SELECT node_json FROM nodes WHERE profile_id = ?1 ORDER BY sort_order ASC",
        )?;
        let node_rows = stmt.query_map(params![profile_id], |r| r.get::<_, String>(0))?;
        let mut nodes = Vec::new();
        for nj in node_rows {
            nodes.push(serde_json::from_str::<NodeConfig>(&nj?)?);
        }

        Ok(StoredProfile {
            id: row.0,
            name: row.1,
            general: serde_json::from_str(&row.2)?,
            rules: serde_json::from_str(&row.3)?,
            hosts: serde_json::from_str(&row.4)?,
            nodes,
            created_at: DateTime::parse_from_rfc3339(&row.5)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(&row.6)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        })
    }

    pub fn get_node(&self, node_id: &str) -> Result<NodeConfig, StorageError> {
        let json: String = self
            .conn
            .query_row(
                "SELECT node_json FROM nodes WHERE id = ?1",
                params![node_id],
                |r| r.get(0),
            )
            .optional()?
            .ok_or_else(|| StorageError::NotFound(format!("node {node_id}")))?;
        Ok(serde_json::from_str(&json)?)
    }

    /// Persists an updated `NodeConfig` and syncs its TOFU `TrustRecord` in `trust_vault`.
    pub fn update_node(&mut self, node: &NodeConfig) -> Result<(), StorageError> {
        let now = Utc::now().to_rfc3339();
        let node_json = serde_json::to_string(node)?;
        let tx = self.conn.transaction()?;
        let affected = tx.execute(
            "UPDATE nodes SET node_json = ?1, updated_at = ?2 WHERE id = ?3",
            params![node_json, now, node.id],
        )?;
        if affected == 0 {
            return Err(StorageError::NotFound(format!("node {}", node.id)));
        }

        if let Some(tr) = &node.tls.trust_record {
            let rec_json = serde_json::to_string(tr)?;
            tx.execute(
                "INSERT INTO trust_vault (node_id, spki_sha256_b64, cert_sha256_hex, record_json, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(node_id) DO UPDATE SET
                   spki_sha256_b64 = excluded.spki_sha256_b64,
                   cert_sha256_hex = excluded.cert_sha256_hex,
                   record_json = excluded.record_json,
                   updated_at = excluded.updated_at",
                params![node.id, tr.spki_sha256_b64, tr.cert_sha256_hex, rec_json, now],
            )?;
        } else {
            tx.execute(
                "DELETE FROM trust_vault WHERE node_id = ?1",
                params![node.id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Explicitly confirms a temporary insecure override (Scheme A explicit opt-in) or revokes it.
    pub fn set_insecure_override(
        &mut self,
        node_id: &str,
        confirmed: bool,
    ) -> Result<NodeConfig, StorageError> {
        let mut node = self.get_node(node_id)?;
        node.tls.verify_mode = TlsVerifyMode::InsecureLegacy {
            user_confirmed_override: confirmed,
        };
        self.update_node(&node)?;
        Ok(node)
    }

    /// Updates the persisted `[Host]` approval state for a profile and updates affected nodes.
    pub fn update_profile_hosts(
        &mut self,
        profile_id: &str,
        hosts: &[HostEntry],
        updated_nodes: &[NodeConfig],
    ) -> Result<(), StorageError> {
        let now = Utc::now().to_rfc3339();
        let hosts_json = serde_json::to_string(hosts)?;
        let tx = self.conn.transaction()?;
        let affected = tx.execute(
            "UPDATE profiles SET hosts_json = ?1, updated_at = ?2 WHERE id = ?3",
            params![hosts_json, now, profile_id],
        )?;
        if affected == 0 {
            return Err(StorageError::NotFound(format!("profile {profile_id}")));
        }
        for node in updated_nodes {
            let node_json = serde_json::to_string(node)?;
            tx.execute(
                "UPDATE nodes SET node_json = ?1, updated_at = ?2 WHERE id = ?3",
                params![node_json, now, node.id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn delete_profile(&mut self, profile_id: &str) -> Result<(), StorageError> {
        let affected = self
            .conn
            .execute("DELETE FROM profiles WHERE id = ?1", params![profile_id])?;
        if affected == 0 {
            return Err(StorageError::NotFound(format!("profile {profile_id}")));
        }
        Ok(())
    }

    pub fn rename_profile(
        &mut self,
        profile_id: &str,
        new_name: impl Into<String>,
    ) -> Result<(), StorageError> {
        let trimmed = new_name.into().trim().to_string();
        if trimmed.is_empty() {
            return Err(StorageError::NotFound("profile name cannot be empty".into()));
        }
        let now = Utc::now().to_rfc3339();
        let affected = self.conn.execute(
            "UPDATE profiles SET name = ?1, updated_at = ?2 WHERE id = ?3",
            params![trimmed, now, profile_id],
        )?;
        if affected == 0 {
            return Err(StorageError::NotFound(format!("profile {profile_id}")));
        }
        Ok(())
    }

    /// Returns `(total_profiles, total_nodes, pinned_spki_nodes)` for the About / Telemetry overview.
    pub fn vault_stats(&self) -> Result<(usize, usize, usize), StorageError> {
        let profiles: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM profiles", [], |r| r.get(0))?;
        let nodes: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM nodes", [], |r| r.get(0))?;
        let pinned: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM trust_vault", [], |r| r.get(0))?;
        Ok((
            profiles.max(0) as usize,
            nodes.max(0) as usize,
            pinned.max(0) as usize,
        ))
    }

    pub fn get_trust_record(&self, node_id: &str) -> Result<Option<TrustRecord>, StorageError> {
        let json: Option<String> = self
            .conn
            .query_row(
                "SELECT record_json FROM trust_vault WHERE node_id = ?1",
                params![node_id],
                |r| r.get(0),
            )
            .optional()?;
        match json {
            Some(j) => Ok(Some(serde_json::from_str(&j)?)),
            None => Ok(None),
        }
    }

    pub fn load_runtime_policy(&self) -> Result<RuntimePolicy, StorageError> {
        let json: Option<String> = self
            .conn
            .query_row(
                "SELECT value_json FROM kv_settings WHERE key = 'runtime_policy'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        match json {
            Some(j) => Ok(serde_json::from_str(&j)?),
            None => Ok(RuntimePolicy::default()),
        }
    }

    pub fn save_runtime_policy(&self, policy: &RuntimePolicy) -> Result<(), StorageError> {
        let mut to_save = policy.clone();
        // Never persist ephemeral per-session Clash API secrets to disk
        to_save.clash_api_secret.clear();
        let json = serde_json::to_string(&to_save)?;
        self.conn.execute(
            "INSERT INTO kv_settings (key, value_json) VALUES ('runtime_policy', ?1)
             ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json",
            params![json],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxq_core_model::{ImportFormat, ImportSecurityReport, ProtocolConfig, TrustOrigin};

    #[test]
    fn persists_profile_nodes_trust_vault_and_runtime_policy() {
        let mut store = VaultStore::open_in_memory().unwrap();
        let mut node = NodeConfig::new(
            "AnyTLS-JP",
            "jp.example.com",
            443,
            ProtocolConfig::AnyTls {
                password: "pw".into(),
                idle_session_check_interval: None,
                idle_session_timeout: None,
                min_idle_session: None,
            },
        );
        node.tls.enabled = true;
        node.tls.verify_mode = TlsVerifyMode::InsecureLegacy {
            user_confirmed_override: false,
        };
        let node_id = node.id.clone();

        let sanitized = SanitizedImport {
            format: ImportFormat::ShareLinks,
            nodes: vec![node],
            rules: vec![],
            general: GeneralSettings::default(),
            hosts: vec![],
            report: ImportSecurityReport::default(),
            parse_warnings: vec![],
        };

        let profile_id = store.save_sanitized_import("Test Profile", &sanitized).unwrap();
        let profiles = store.list_profiles().unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].node_count, 1);

        // Pin certificate and update trust vault
        let mut loaded = store.get_node(&node_id).unwrap();
        loaded.tls.verify_mode = TlsVerifyMode::PinnedSpki;
        loaded.tls.trust_record = Some(TrustRecord {
            spki_sha256_b64: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".into(),
            cert_sha256_hex: "a".repeat(64),
            cert_sha256_b64: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".into(),
            sni: "jp.example.com".into(),
            subject: "CN=jp.example.com".into(),
            issuer: "CN=jp.example.com".into(),
            san_dns: vec!["jp.example.com".into()],
            san_ip: vec![],
            not_before: "2026-01-01".into(),
            not_after: "2027-01-01".into(),
            is_self_signed: true,
            first_seen_at: Utc::now(),
            last_verified_at: Utc::now(),
            origin: TrustOrigin::TofuProbe,
        });
        store.update_node(&loaded).unwrap();

        let vault_rec = store.get_trust_record(&node_id).unwrap().unwrap();
        assert_eq!(
            vault_rec.spki_sha256_b64,
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
        );

        // Runtime policy strips ephemeral secret before persisting
        let mut policy = RuntimePolicy::default();
        policy.clash_api_secret = "ephemeral-secret-should-not-persist".into();
        policy.mixed_listen_port = 17999;
        store.save_runtime_policy(&policy).unwrap();
        let loaded_policy = store.load_runtime_policy().unwrap();
        assert_eq!(loaded_policy.mixed_listen_port, 17999);
        assert!(loaded_policy.clash_api_secret.is_empty());

        // Cascade delete cleans up nodes & trust vault
        store.delete_profile(&profile_id).unwrap();
        assert!(store.get_trust_record(&node_id).unwrap().is_none());
    }
}
