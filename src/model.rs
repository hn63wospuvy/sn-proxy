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
    /// Plain UDP forwarder to a fixed destination.
    Udp,
    /// TURN relay server (RFC 8656).
    Turn,
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
            Protocol::Udp => "udp",
            Protocol::Turn => "turn",
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

/// Default cap on concurrent connections per proxy when `max_connections` is
/// unset. A deliberately high ceiling (the project favours permissive defaults
/// with a backstop over a tight limit that breaks legitimate load).
pub const DEFAULT_MAX_CONNECTIONS: u32 = 8888;

/// Resolve a `max_connections` config value into an effective cap:
/// `None` -> the built-in default, `Some(0)` -> unlimited, `Some(n)` -> `n`.
pub fn effective_max_connections(max: Option<u32>) -> Option<usize> {
    match max {
        None => Some(DEFAULT_MAX_CONNECTIONS as usize),
        Some(0) => None,
        Some(n) => Some(n as usize),
    }
}

fn default_true() -> bool {
    true
}

/// Re-export of `default_true` for `serde(default = ...)` in other modules.
pub fn model_default_true() -> bool {
    true
}

/// Default relay port range for a TURN proxy.
///
/// Deliberately NOT the RFC-recommended 49152-65535. That span is exactly the
/// Windows default dynamic port range and overlaps Linux's, so it competes with
/// every ephemeral bind this process already makes (the UDP forwarder's
/// `0.0.0.0:0`, SOCKS5's per-destination sockets, every outbound connection from
/// every other proxy). A TURN allocation flood that consumed the whole span
/// would starve the other proxies of ephemeral ports — blast radius the entire
/// process rather than the one proxy under attack.
pub const TURN_DEFAULT_MIN_PORT: u16 = 49152;
pub const TURN_DEFAULT_MAX_PORT: u16 = 51199;

/// Default ceiling on a granted allocation lifetime.
///
/// 600 would make the knob unobservable: RFC 8656 floors the granted lifetime at
/// 600, so `max(600, min(requested, 600))` is always 600 and the client's
/// LIFETIME could never do anything. libwebrtc caps its own refresh scheduling
/// at 3600, which makes 3600 the natural ceiling.
pub const TURN_DEFAULT_MAX_LIFETIME: u64 = 3600;
/// RFC 8656 floor on a granted allocation lifetime.
pub const TURN_MIN_LIFETIME: u64 = 600;

fn turn_default_transports() -> Vec<String> {
    vec!["udp".to_string(), "tcp".to_string()]
}

/// TURN settings, grouped into one struct instead of flattened into
/// [`ProxyConfig`] the way `ss_*` and `udp_*` are.
///
/// The grouping is not a style preference. `Manager::update` copies
/// configuration field by field, so a forgotten line there compiles cleanly and
/// silently discards the operator's edit — and for `static_secret` that means a
/// TURN proxy left running with no usable credential. `cfg.turn = spec.turn` has
/// nothing to forget.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TurnConfig {
    /// Listeners to bind: any subset of `udp`, `tcp`, `tls`.
    #[serde(default = "turn_default_transports")]
    pub transports: Vec<String>,
    /// Listen address for the `turns:` (TLS) listener.
    #[serde(default)]
    pub tls_listen: Option<String>,
    /// Authentication realm. Required and non-empty: libwebrtc only recomputes
    /// its credential hash when the realm CHANGES and initialises it to `""`, so
    /// a 401 carrying an empty realm never triggers the recompute — the hash
    /// stays empty and every MESSAGE-INTEGRITY afterwards is computed over an
    /// empty key. Chrome then fails 100% of the time.
    #[serde(default)]
    pub realm: String,
    /// TURN REST API shared secret. A credential-minting key: whoever holds it
    /// can issue unlimited valid credentials with arbitrary expiry. Never echoed
    /// back over the API (see [`TurnView`]) and never logged.
    #[serde(default)]
    pub static_secret: Option<String>,
    /// Concrete IP the relay sockets bind. Must not be a wildcard — ICE requires
    /// a connectivity-check response to come from the address the request was
    /// sent to, and a wildcard bind lets the kernel pick per route.
    #[serde(default)]
    pub relay_ip: Option<String>,
    /// IP substituted into XOR-RELAYED-ADDRESS for 1:1 NAT. Never feeds
    /// XOR-MAPPED-ADDRESS, which must carry the client's observed address.
    #[serde(default)]
    pub advertise_ip: Option<String>,
    #[serde(default)]
    pub relay_min_port: Option<u16>,
    #[serde(default)]
    pub relay_max_port: Option<u16>,
    #[serde(default)]
    pub max_lifetime_secs: Option<u64>,
    /// Allow internal/RFC1918/SSRF-risky peer addresses. UNSAFE when true.
    #[serde(default)]
    pub allow_private: bool,
    /// Relay read-buffer size. WebRTC media is under 1500 bytes; the 64 KiB the
    /// UDP forwarder uses would be ~555 MiB of buffers at the default cap.
    #[serde(default)]
    pub max_datagram: Option<usize>,
    #[serde(default)]
    pub max_permissions: Option<u32>,
    #[serde(default)]
    pub max_channels: Option<u32>,
    /// Allocations per userid — keyed on the userid, NOT the full REST username,
    /// whose timestamp prefix rotates every second and would make the quota a
    /// no-op.
    #[serde(default)]
    pub max_allocations_per_user: Option<u32>,
    /// Reject credentials whose embedded expiry is further out than this.
    #[serde(default)]
    pub credential_horizon_secs: Option<u64>,
}

impl Default for TurnConfig {
    fn default() -> Self {
        Self {
            transports: turn_default_transports(),
            tls_listen: None,
            realm: String::new(),
            static_secret: None,
            relay_ip: None,
            advertise_ip: None,
            relay_min_port: None,
            relay_max_port: None,
            max_lifetime_secs: None,
            allow_private: false,
            max_datagram: None,
            max_permissions: None,
            max_channels: None,
            max_allocations_per_user: None,
            credential_horizon_secs: None,
        }
    }
}

impl TurnConfig {
    /// Whether a transport (`udp` / `tcp` / `tls`) is selected.
    pub fn has(&self, transport: &str) -> bool {
        self.transports.iter().any(|t| t == transport)
    }

    /// Server ceiling on a granted allocation lifetime, never below the RFC
    /// floor (a lower value would be inert, so clamp up rather than pretend the
    /// operator configured something meaningful).
    pub fn effective_max_lifetime(&self) -> u64 {
        self.max_lifetime_secs
            .filter(|s| *s > 0)
            .unwrap_or(TURN_DEFAULT_MAX_LIFETIME)
            .max(TURN_MIN_LIFETIME)
    }

    pub fn effective_port_range(&self) -> (u16, u16) {
        (
            self.relay_min_port.unwrap_or(TURN_DEFAULT_MIN_PORT),
            self.relay_max_port.unwrap_or(TURN_DEFAULT_MAX_PORT),
        )
    }

    pub fn effective_max_datagram(&self) -> usize {
        self.max_datagram.filter(|n| *n > 0).unwrap_or(2048)
    }

    pub fn effective_max_permissions(&self) -> usize {
        self.max_permissions.filter(|n| *n > 0).unwrap_or(128) as usize
    }

    pub fn effective_max_channels(&self) -> usize {
        self.max_channels.filter(|n| *n > 0).unwrap_or(64) as usize
    }

    pub fn effective_per_user(&self) -> usize {
        self.max_allocations_per_user.filter(|n| *n > 0).unwrap_or(16) as usize
    }

    pub fn effective_horizon(&self) -> u64 {
        self.credential_horizon_secs
            .filter(|s| *s > 0)
            .unwrap_or(86_400)
    }
}

/// The snapshot projection of [`TurnConfig`]: identical except that the
/// credential-minting secret is reduced to a presence flag, mirroring the
/// `has_client_p12` / omitted-`ss_password` convention the snapshot already
/// follows for other secrets.
#[derive(Debug, Clone, Serialize)]
pub struct TurnView {
    pub transports: Vec<String>,
    pub tls_listen: Option<String>,
    pub realm: String,
    pub has_turn_secret: bool,
    pub relay_ip: Option<String>,
    pub advertise_ip: Option<String>,
    pub relay_min_port: Option<u16>,
    pub relay_max_port: Option<u16>,
    pub max_lifetime_secs: Option<u64>,
    pub allow_private: bool,
    pub max_datagram: Option<usize>,
    pub max_permissions: Option<u32>,
    pub max_channels: Option<u32>,
    pub max_allocations_per_user: Option<u32>,
    pub credential_horizon_secs: Option<u64>,
}

impl From<&TurnConfig> for TurnView {
    fn from(c: &TurnConfig) -> Self {
        Self {
            transports: c.transports.clone(),
            tls_listen: c.tls_listen.clone(),
            realm: c.realm.clone(),
            has_turn_secret: c.static_secret.as_deref().is_some_and(|s| !s.is_empty()),
            relay_ip: c.relay_ip.clone(),
            advertise_ip: c.advertise_ip.clone(),
            relay_min_port: c.relay_min_port,
            relay_max_port: c.relay_max_port,
            max_lifetime_secs: c.max_lifetime_secs,
            allow_private: c.allow_private,
            max_datagram: c.max_datagram,
            max_permissions: c.max_permissions,
            max_channels: c.max_channels,
            max_allocations_per_user: c.max_allocations_per_user,
            credential_horizon_secs: c.credential_horizon_secs,
        }
    }
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
    /// Announce the original client address to the destination with a PROXY
    /// protocol v1 header (TCP forwarder only).
    ///
    /// Off by default, and it has to stay that way: the header is written as
    /// the first bytes of the upstream connection, so a destination that does
    /// not expect it sees garbage instead of the protocol it speaks and drops
    /// the session. Only enable it once the destination is configured to trust
    /// this proxy's address.
    #[serde(default)]
    pub send_proxy_protocol: bool,

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

    /// Maximum number of concurrent connections this proxy accepts. `None`
    /// (configs written before the field existed) means the built-in default
    /// (`DEFAULT_MAX_CONNECTIONS`); `Some(0)` means unlimited; `Some(n)` caps
    /// at `n`. Enforced in the TCP accept loop.
    #[serde(default)]
    pub max_connections: Option<u32>,

    // --- SOCKS5 UDP ASSOCIATE (Protocol::Socks5 only) ---
    /// Gate CMD=0x03 UDP ASSOCIATE; when false the server replies `0x07`.
    #[serde(default = "default_true")]
    pub udp_associate_enabled: bool,
    /// Allow internal/RFC1918/SSRF-risky UDP destinations. UNSAFE when true.
    #[serde(default)]
    pub udp_allow_private: bool,
    /// Interface/IP the relay `UdpSocket` binds to (default = listener IP).
    #[serde(default)]
    pub udp_bind_addr: Option<String>,
    /// IP reported in BND.ADDR (NAT / multi-homed override).
    #[serde(default)]
    pub udp_advertise_ip: Option<String>,
    /// Max relayed datagram payload size (default 64 KiB).
    #[serde(default)]
    pub udp_max_datagram: Option<usize>,
    /// Optional cap on distinct destinations per association (unset = unlimited).
    #[serde(default)]
    pub udp_max_dests: Option<u32>,

    /// TURN settings (`Protocol::Turn` only). Grouped rather than flattened —
    /// see [`TurnConfig`] for why.
    #[serde(default)]
    pub turn: TurnConfig,

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_config_defaults_udp_fields() {
        // A config written before the udp_* fields existed must deserialize,
        // defaulting associate=ON, allow_private=OFF, the rest None.
        let json = r#"{
            "id": "x", "name": "n", "listen_addr": "0.0.0.0:1080"
        }"#;
        let cfg: ProxyConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.udp_associate_enabled);
        assert!(!cfg.udp_allow_private);
        assert_eq!(cfg.udp_bind_addr, None);
        assert_eq!(cfg.udp_advertise_ip, None);
        assert_eq!(cfg.udp_max_datagram, None);
        assert_eq!(cfg.udp_max_dests, None);
        assert_eq!(cfg.max_connections, None);
    }

    #[test]
    fn old_config_defaults_proxy_protocol_off() {
        // Enabling it on an upgrade would prepend a header the destination
        // never agreed to parse, breaking every existing TCP forwarder.
        let json = r#"{"id":"x","name":"n","listen_addr":"0.0.0.0:1080"}"#;
        let cfg: ProxyConfig = serde_json::from_str(json).unwrap();
        assert!(!cfg.send_proxy_protocol);
    }

    #[test]
    fn old_config_defaults_turn_block() {
        // A config written before `turn` existed must still deserialize, and
        // must default to a block that cannot authenticate anyone.
        let json = r#"{"id":"x","name":"n","listen_addr":"0.0.0.0:1080"}"#;
        let cfg: ProxyConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            cfg.turn.transports,
            vec!["udp".to_string(), "tcp".to_string()]
        );
        assert_eq!(cfg.turn.realm, "");
        assert_eq!(cfg.turn.static_secret, None);
        assert_eq!(cfg.turn.max_lifetime_secs, None);
        assert!(!cfg.turn.allow_private);
    }

    #[test]
    fn turn_view_never_carries_the_secret() {
        // The secret mints credentials, so the snapshot exposes only its
        // presence — the same treatment client_p12 and ss_password already get.
        let turn = TurnConfig {
            static_secret: Some("super-secret-value".into()),
            realm: "example.org".into(),
            ..TurnConfig::default()
        };
        let view = TurnView::from(&turn);
        assert!(view.has_turn_secret);
        assert_eq!(view.realm, "example.org");
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("super-secret-value"));
        // An empty string is "no secret", not "a secret that is empty".
        let blank = TurnConfig {
            static_secret: Some(String::new()),
            ..TurnConfig::default()
        };
        assert!(!TurnView::from(&blank).has_turn_secret);
    }

    #[test]
    fn turn_effective_lifetime_defaults_to_3600() {
        // 600 would make the knob inert: granted = max(600, min(x, 600)) = 600.
        assert_eq!(TurnConfig::default().effective_max_lifetime(), 3600);
        let mut t = TurnConfig::default();
        t.max_lifetime_secs = Some(1200);
        assert_eq!(t.effective_max_lifetime(), 1200);
        t.max_lifetime_secs = Some(30);
        assert_eq!(t.effective_max_lifetime(), 600);
        t.max_lifetime_secs = Some(0);
        assert_eq!(t.effective_max_lifetime(), 3600);
    }

    #[test]
    fn turn_relay_port_range_defaults_to_a_narrow_slice() {
        // NOT the RFC's 49152-65535: that is exactly the Windows dynamic port
        // range, so a flood would starve every other proxy in this process of
        // ephemeral ports.
        assert_eq!(TurnConfig::default().effective_port_range(), (49152, 51199));
    }

    #[test]
    fn turn_transport_membership() {
        let t = TurnConfig::default();
        assert!(t.has("udp"));
        assert!(t.has("tcp"));
        assert!(!t.has("tls"));
    }

    #[test]
    fn effective_max_connections_semantics() {
        // unset -> default, explicit 0 -> unlimited, explicit n -> n.
        assert_eq!(
            effective_max_connections(None),
            Some(DEFAULT_MAX_CONNECTIONS as usize)
        );
        assert_eq!(effective_max_connections(Some(0)), None);
        assert_eq!(effective_max_connections(Some(100)), Some(100));
    }
}
