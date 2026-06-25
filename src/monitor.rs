//! Realtime monitoring payloads broadcast to websocket clients.

use crate::model::HeaderOverride;
use serde::Serialize;

/// A single live connection currently being relayed by a proxy.
#[derive(Debug, Clone, Serialize)]
pub struct ActiveConn {
    pub id: String,
    pub src_addr: String,
    pub dst_addr: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub started_at: i64,
}

/// Realtime view of one proxy: its status, totals and live connections.
#[derive(Debug, Clone, Serialize)]
pub struct ProxySnapshot {
    pub id: String,
    pub name: String,
    /// Protocol the proxy speaks (`socks5`, `http`, `https`, `shadowsocks`).
    pub protocol: String,
    pub listen_addr: String,
    pub running: bool,
    pub auth_enabled: bool,
    /// Username clients authenticate with, when auth is enabled.
    pub auth_username: Option<String>,
    /// Shadowsocks cipher, when the protocol is Shadowsocks.
    pub ss_method: Option<String>,
    /// TCP forwarder destination, when the protocol is Tcp.
    pub forward_to: Option<String>,
    pub keepalive_secs: Option<u64>,
    pub idle_timeout_secs: Option<u64>,
    pub connect_timeout_secs: Option<u64>,
    /// HTTP request-header overrides (HTTP/HTTPS only).
    pub override_headers: Vec<HeaderOverride>,
    /// Whether a client mTLS PKCS#12 identity is configured.
    pub has_client_p12: bool,
    /// Alias of the client keystore entry, when one was specified.
    pub client_p12_alias: Option<String>,
    /// Whether a per-proxy HTTPS server PKCS#12 keystore is configured.
    pub has_server_p12: bool,
    /// Whether a client-certificate truststore is configured.
    pub has_truststore: bool,
    /// Whether the HTTPS listener requires client certificates (mTLS).
    pub mtls_required: bool,
    /// Whether CMD=0x03 UDP ASSOCIATE is enabled (SOCKS5 only).
    pub udp_associate_enabled: bool,
    /// Whether internal/SSRF-risky UDP destinations are allowed (UNSAFE).
    pub udp_allow_private: bool,
    pub udp_bind_addr: Option<String>,
    pub udp_advertise_ip: Option<String>,
    pub udp_max_datagram: Option<usize>,
    pub udp_max_dests: Option<u32>,
    /// Source addresses blocked on this proxy specifically.
    pub blocklist: Vec<String>,
    pub total_connections: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub active_connections: Vec<ActiveConn>,
}

/// Message pushed to websocket clients.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MonitorEvent {
    /// Full state of every proxy, emitted on a fixed interval.
    Snapshot { ts: i64, proxies: Vec<ProxySnapshot> },
}
