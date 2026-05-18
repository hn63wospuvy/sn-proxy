//! Shared data structures persisted in RocksDB and exposed over the HTTP API.

use serde::{Deserialize, Serialize};

/// Proxy protocol a listener speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// SOCKS5 (RFC 1928) with optional username/password auth.
    #[default]
    Socks5,
    /// HTTP proxy: CONNECT tunnelling plus plain HTTP forwarding.
    Http,
    /// HTTP proxy wrapped in TLS (self-signed certificate).
    Https,
    /// Shadowsocks AEAD.
    Shadowsocks,
    /// Plain TCP forwarder to a fixed destination.
    Tcp,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Socks5 => "socks5",
            Protocol::Http => "http",
            Protocol::Https => "https",
            Protocol::Shadowsocks => "shadowsocks",
            Protocol::Tcp => "tcp",
        }
    }
}

/// Username/password credentials (SOCKS5 RFC 1929 / HTTP Basic auth).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

fn default_true() -> bool {
    true
}

/// Persisted configuration of a single proxy instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub id: String,
    pub name: String,
    /// Protocol this proxy speaks. Defaults to SOCKS5 for configs written
    /// before the field existed.
    #[serde(default)]
    pub protocol: Protocol,
    /// Address the proxy listens on, e.g. `0.0.0.0:1080`.
    pub listen_addr: String,
    /// Username/password auth — used by SOCKS5, HTTP and HTTPS.
    #[serde(default)]
    pub auth: Option<BasicAuth>,
    /// Shadowsocks cipher, e.g. `aes-256-gcm` (Shadowsocks only).
    #[serde(default)]
    pub ss_method: Option<String>,
    /// Shadowsocks password / key material (Shadowsocks only).
    #[serde(default)]
    pub ss_password: Option<String>,
    /// Fixed `host:port` destination for the TCP forwarder (Tcp only).
    #[serde(default)]
    pub forward_to: Option<String>,
    /// TCP keep-alive interval in seconds (`None`/0 = off).
    #[serde(default)]
    pub keepalive_secs: Option<u64>,
    /// Close a connection after this many seconds with no traffic
    /// (`None`/0 = off).
    #[serde(default)]
    pub idle_timeout_secs: Option<u64>,
    /// Timeout in seconds when dialing the destination (`None`/0 = off).
    #[serde(default)]
    pub connect_timeout_secs: Option<u64>,
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
