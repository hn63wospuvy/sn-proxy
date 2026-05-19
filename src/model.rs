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
    /// WebSocket tunnelling proxy to a fixed destination.
    Websocket,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Socks5 => "socks5",
            Protocol::Http => "http",
            Protocol::Https => "https",
            Protocol::Shadowsocks => "shadowsocks",
            Protocol::Tcp => "tcp",
            Protocol::Websocket => "websocket",
        }
    }

    /// Whether the protocol is HTTP-family (`http` or `https`), the only
    /// protocols that support header overrides and client mTLS.
    pub fn is_http(&self) -> bool {
        matches!(self, Protocol::Http | Protocol::Https)
    }
}

/// Username/password credentials (SOCKS5 RFC 1929 / HTTP Basic auth).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

/// A single request header injected/replaced when forwarding plain HTTP.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeaderOverride {
    pub key: String,
    pub value: String,
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
    /// Username/password auth — used by SOCKS5, HTTP, HTTPS and WebSocket.
    #[serde(default)]
    pub auth: Option<BasicAuth>,
    /// Shadowsocks cipher, e.g. `aes-256-gcm` (Shadowsocks only).
    #[serde(default)]
    pub ss_method: Option<String>,
    /// Shadowsocks password / key material (Shadowsocks only).
    #[serde(default)]
    pub ss_password: Option<String>,
    /// Fixed `host:port` destination for the TCP / WebSocket forwarder.
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

    // --- HTTP/HTTPS: client-side mutual TLS toward the destination ---
    /// PKCS#12 client identity (base64-encoded `.p12` bytes) presented to
    /// upstream servers that require mutual TLS.
    #[serde(default)]
    pub client_p12: Option<String>,
    /// Password protecting `client_p12`.
    #[serde(default)]
    pub client_p12_password: Option<String>,
    /// Alias of the keystore entry to use (first private key when empty).
    #[serde(default)]
    pub client_p12_alias: Option<String>,
    /// Per-entry password, when the keystore uses one (rarely needed).
    #[serde(default)]
    pub client_p12_entry_password: Option<String>,
    /// Request headers injected/replaced when forwarding plain HTTP.
    #[serde(default)]
    pub override_headers: Vec<HeaderOverride>,

    // --- HTTPS listener: server-side TLS and optional client mTLS ---
    /// PKCS#12 keystore (base64) providing the TLS server certificate and key
    /// for an HTTPS listener. Falls back to the global certificate when empty.
    #[serde(default)]
    pub server_p12: Option<String>,
    /// Password protecting `server_p12`.
    #[serde(default)]
    pub server_p12_password: Option<String>,
    /// PKCS#12 truststore (base64) of CA certificates that validate client
    /// certificates when mTLS is required.
    #[serde(default)]
    pub server_truststore_p12: Option<String>,
    /// Password protecting `server_truststore_p12`.
    #[serde(default)]
    pub server_truststore_password: Option<String>,
    /// Require connecting clients to present a valid certificate (mutual TLS).
    #[serde(default)]
    pub mtls_required: bool,

    /// Per-proxy blocked source addresses (`IP` or `IP:port`). Refused at
    /// accept time in addition to the manager-wide blocklist.
    #[serde(default)]
    pub blocklist: Vec<String>,

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
