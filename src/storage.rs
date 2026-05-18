//! RocksDB-backed persistence for proxy configs and connection history.

use crate::model::{ConnectionRecord, ProxyConfig};
use anyhow::Result;
use rocksdb::{DB, Options};
use std::path::Path;
use std::sync::Arc;

const CFG_PREFIX: &str = "cfg:";
const HIST_PREFIX: &str = "hist:";

/// Thin wrapper over a single RocksDB instance.
pub struct Storage {
    db: DB,
}

impl Storage {
    /// Open (or create) the database at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Arc<Self>> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, path)?;
        Ok(Arc::new(Self { db }))
    }

    pub fn save_config(&self, cfg: &ProxyConfig) -> Result<()> {
        let key = format!("{CFG_PREFIX}{}", cfg.id);
        self.db.put(key.as_bytes(), serde_json::to_vec(cfg)?)?;
        Ok(())
    }

    pub fn delete_config(&self, id: &str) -> Result<()> {
        self.db.delete(format!("{CFG_PREFIX}{id}").as_bytes())?;
        Ok(())
    }

    /// Load every persisted proxy configuration.
    pub fn load_configs(&self) -> Result<Vec<ProxyConfig>> {
        let mut out = Vec::new();
        for item in self.db.prefix_iterator(CFG_PREFIX.as_bytes()) {
            let (k, v) = item?;
            if !k.starts_with(CFG_PREFIX.as_bytes()) {
                break;
            }
            out.push(serde_json::from_slice(&v)?);
        }
        Ok(out)
    }

    /// Append a finished connection to the history.
    ///
    /// The key embeds a reversed timestamp so that a forward prefix scan
    /// yields the most recent connections first.
    pub fn save_history(&self, rec: &ConnectionRecord) -> Result<()> {
        let ts = rec.closed_at.unwrap_or_else(crate::model::now_ms) as u64;
        let rev = u64::MAX - ts;
        let key = format!("{HIST_PREFIX}{}:{:016x}:{}", rec.proxy_id, rev, rec.id);
        self.db.put(key.as_bytes(), serde_json::to_vec(rec)?)?;
        Ok(())
    }

    /// Load up to `limit` history records for a proxy, newest first.
    pub fn load_history(&self, proxy_id: &str, limit: usize) -> Result<Vec<ConnectionRecord>> {
        let prefix = format!("{HIST_PREFIX}{proxy_id}:");
        let mut out = Vec::new();
        for item in self.db.prefix_iterator(prefix.as_bytes()) {
            let (k, v) = item?;
            if !k.starts_with(prefix.as_bytes()) {
                break;
            }
            out.push(serde_json::from_slice(&v)?);
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    /// Delete all history belonging to a proxy (used when the proxy is removed).
    pub fn delete_history(&self, proxy_id: &str) -> Result<()> {
        let prefix = format!("{HIST_PREFIX}{proxy_id}:");
        let mut keys = Vec::new();
        for item in self.db.prefix_iterator(prefix.as_bytes()) {
            let (k, _) = item?;
            if !k.starts_with(prefix.as_bytes()) {
                break;
            }
            keys.push(k.to_vec());
        }
        for k in keys {
            self.db.delete(k)?;
        }
        Ok(())
    }
}
