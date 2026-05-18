//! Shared data structures persisted in RocksDB and exposed over the HTTP API.

use serde::{Deserialize, Serialize};

/// Username/password credentials for SOCKS5 (RFC 1929) authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

fn default_true() -> bool {
    true
}

/// Persisted configuration of a single SOCKS5 proxy instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub id: String,
    pub name: String,
    /// Address the proxy listens on, e.g. `0.0.0.0:1080`.
    pub listen_addr: String,
    /// When set, clients must authenticate with these credentials.
    #[serde(default)]
    pub auth: Option<BasicAuth>,
    /// Whether the proxy should be running.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// A finished connection, stored in the history column of RocksDB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionRecord {
    pub id: String,
    pub proxy_id: String,
    pub src_addr: String,
    pub dst_addr: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    /// Unix epoch milliseconds.
    pub started_at: i64,
    /// Unix epoch milliseconds, `None` while still open.
    pub closed_at: Option<i64>,
}

/// Current wall-clock time as Unix epoch milliseconds.
pub fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
