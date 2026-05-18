//! Realtime monitoring payloads broadcast to websocket clients.

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
