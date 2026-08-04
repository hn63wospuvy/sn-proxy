//! Owns every proxy instance: lifecycle (start/stop), live connection
//! tracking and the broadcast channel feeding realtime monitoring.

use crate::model::{
    BasicAuth, HeaderOverride, Protocol, ProxyConfig, TurnConfig, effective_max_connections,
};
use crate::monitor::{ActiveConn, MonitorEvent, ProxySnapshot};
use crate::resources::ResourceSample;
use crate::storage::Storage;
use crate::{http, relay, shadowsocks, socks5, tcp, tls, ws_proxy};
use anyhow::{Result, anyhow, bail};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use dashmap::DashMap;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Semaphore, broadcast};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Live byte counters for a single in-flight connection.
pub struct ConnEntry {
    pub id: String,
    pub src_addr: String,
    pub dst_addr: String,
    /// Bytes relayed from client to destination.
    pub bytes_sent: AtomicU64,
    /// Bytes relayed from destination to client.
    pub bytes_received: AtomicU64,
    pub started_at: i64,
    /// Fires to abort this connection (admin "terminate" / "block IP").
    pub cancel: CancellationToken,
}

/// Runtime state of one proxy.
pub struct ProxyRuntime {
    pub config: Mutex<ProxyConfig>,
    pub running: AtomicBool,
    /// Cancellation token of the active accept loop, if running.
    pub cancel: Mutex<Option<CancellationToken>>,
    /// Connections currently being relayed, keyed by connection id.
    pub conns: DashMap<String, Arc<ConnEntry>>,
    pub total_connections: AtomicU64,
    pub total_sent: AtomicU64,
    pub total_received: AtomicU64,
    /// Per-proxy HTTPS acceptor built from a PKCS#12 keystore, when one is
    /// configured; otherwise the global acceptor is used.
    pub https_acceptor: Mutex<Option<TlsAcceptor>>,
    /// Client-TLS connector presenting a PKCS#12 identity to upstream servers
    /// that require mutual TLS (HTTP/HTTPS proxies only).
    pub client_connector: Mutex<Option<Arc<TlsConnector>>>,
    /// Recently-seen Shadowsocks client salts, for replay / nonce-reuse
    /// detection. Bounded FIFO (see [`SaltCache`]). Shadowsocks proxies only.
    ss_seen_salts: Mutex<SaltCache>,
}

impl ProxyRuntime {
    pub(crate) fn new(config: ProxyConfig) -> Self {
        Self {
            config: Mutex::new(config),
            running: AtomicBool::new(false),
            cancel: Mutex::new(None),
            conns: DashMap::new(),
            total_connections: AtomicU64::new(0),
            total_sent: AtomicU64::new(0),
            total_received: AtomicU64::new(0),
            https_acceptor: Mutex::new(None),
            client_connector: Mutex::new(None),
            ss_seen_salts: Mutex::new(SaltCache::new(MAX_SEEN_SALTS)),
        }
    }

    /// Record a Shadowsocks client salt, returning `true` if it is new and
    /// `false` if it has been seen recently (a replay / salt-reuse attempt).
    ///
    /// Reusing a salt re-derives the same session subkey while the AEAD nonce
    /// restarts at zero, so accepting a duplicate salt would reuse a
    /// `(key, nonce)` pair — catastrophic for AES-GCM / ChaCha20-Poly1305 — and
    /// also enables straightforward traffic replay. The cache is a bounded FIFO,
    /// so protection is best-effort over the last `MAX_SEEN_SALTS` salts.
    pub(crate) fn note_ss_salt(&self, salt: &[u8]) -> bool {
        self.ss_seen_salts.lock().unwrap().insert(salt)
    }
}

/// Largest number of recent Shadowsocks salts remembered per proxy for replay
/// detection (~32 bytes each + bookkeeping).
const MAX_SEEN_SALTS: usize = 16_384;

/// A bounded FIFO set of byte strings used for Shadowsocks salt-replay
/// detection. Once `cap` entries are stored, inserting a new one evicts the
/// oldest. Insertion reports whether the value was previously unseen.
struct SaltCache {
    set: HashSet<Vec<u8>>,
    order: std::collections::VecDeque<Vec<u8>>,
    cap: usize,
}

impl SaltCache {
    fn new(cap: usize) -> Self {
        Self {
            set: HashSet::new(),
            order: std::collections::VecDeque::with_capacity(cap.min(1024)),
            cap,
        }
    }

    /// Insert `value`; returns `true` when it was newly added, `false` when it
    /// was already present (a replay).
    fn insert(&mut self, value: &[u8]) -> bool {
        if self.set.contains(value) {
            return false;
        }
        if self.order.len() >= self.cap {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        self.set.insert(value.to_vec());
        self.order.push_back(value.to_vec());
        true
    }
}

/// Caller-supplied settings for creating or updating a proxy.
///
/// The PKCS#12 fields are tri-state on update: `None` keeps the stored value,
/// `Some("")` clears it, and `Some(bytes)` replaces it.
pub struct ProxySpec {
    pub name: String,
    pub protocol: Protocol,
    pub listen_addr: String,
    pub auth: Option<BasicAuth>,
    pub ss_method: Option<String>,
    pub ss_password: Option<String>,
    pub forward_to: Option<String>,
    pub keepalive_secs: Option<u64>,
    pub idle_timeout_secs: Option<u64>,
    pub connect_timeout_secs: Option<u64>,
    /// Announce the client address to the destination (TCP forwarder only).
    pub send_proxy_protocol: bool,
    pub client_p12: Option<String>,
    pub client_p12_password: Option<String>,
    pub client_p12_alias: Option<String>,
    pub client_p12_entry_password: Option<String>,
    pub override_headers: Vec<HeaderOverride>,
    pub server_p12: Option<String>,
    pub server_p12_password: Option<String>,
    pub server_truststore_p12: Option<String>,
    pub server_truststore_password: Option<String>,
    pub mtls_required: bool,
    pub udp_associate_enabled: bool,
    pub udp_allow_private: bool,
    pub udp_bind_addr: Option<String>,
    pub udp_advertise_ip: Option<String>,
    pub udp_max_datagram: Option<usize>,
    pub udp_max_dests: Option<u32>,
    pub max_connections: Option<u32>,
    pub turn: TurnConfig,
}

impl ProxySpec {
    /// Reject obviously invalid settings before they are persisted.
    fn validate(&self) -> Result<()> {
        let name = self.name.trim();
        if name.is_empty() {
            bail!("name is required");
        }
        // Defense in depth against stored XSS: the name is rendered in the web
        // admin. Control characters (incl. CR/LF and quotes' break-out helpers)
        // are never legitimate in a display name; reject them and cap length.
        if name.chars().any(|c| c.is_control()) {
            bail!("name must not contain control characters");
        }
        if name.chars().count() > 200 {
            bail!("name is too long (max 200 characters)");
        }
        if self.listen_addr.trim().is_empty() {
            bail!("listen address is required");
        }
        if matches!(self.protocol, Protocol::Tcp | Protocol::Websocket | Protocol::Udp)
            && self.forward_to.as_deref().unwrap_or("").is_empty()
        {
            bail!("this proxy needs a forward destination (host:port)");
        }
        if self.protocol == Protocol::Shadowsocks {
            let method = self.ss_method.as_deref().unwrap_or("");
            if !matches!(
                method,
                "aes-128-gcm" | "aes-256-gcm" | "chacha20-ietf-poly1305"
            ) {
                bail!("shadowsocks needs a cipher: aes-128-gcm, aes-256-gcm or chacha20-ietf-poly1305");
            }
            if self.ss_password.as_deref().unwrap_or("").is_empty() {
                bail!("shadowsocks needs a password");
            }
        }
        Ok(())
    }
}

/// Verify a candidate password against a stored value.
///
/// If the stored value is an argon2 PHC string (`$argon2…`) it is verified with
/// argon2 (the variant and m/t/p parameters are read from the hash itself);
/// otherwise the comparison is plaintext. A value that looks like an argon2
/// hash but fails to parse never authenticates — it does not fall back to
/// plaintext.
fn verify_password(stored: &str, candidate: &str) -> bool {
    if stored.starts_with("$argon2") {
        match PasswordHash::new(stored) {
            Ok(parsed) => Argon2::default()
                .verify_password(candidate.as_bytes(), &parsed)
                .is_ok(),
            Err(_) => false, // malformed hash never authenticates
        }
    } else {
        stored == candidate
    }
}

/// One web-admin account, optionally restricted to a network range.
pub struct Admin {
    pub username: String,
    pub password: String,
    /// When set, the admin may only log in from an IP inside this CIDR.
    pub network: Option<ipnet::IpNet>,
}

/// Per-source-IP login throttling state (a fixed window of failures).
struct LoginAttempts {
    fails: u32,
    window_start: std::time::Instant,
}

/// Max failed logins allowed from one source IP within [`LOGIN_WINDOW`] before
/// further attempts are rejected with HTTP 429.
const MAX_LOGIN_FAILS: u32 = 10;
/// Rolling window over which [`MAX_LOGIN_FAILS`] is counted.
const LOGIN_WINDOW: Duration = Duration::from_secs(60);

/// Web-admin accounts and active sessions.
///
/// When the admin list is empty the web admin is open (no login).
pub struct AdminAuth {
    admins: Vec<Admin>,
    sessions: Mutex<HashSet<String>>,
    /// Whether to mark the session cookie `Secure` (admin served over HTTPS).
    secure_cookies: bool,
    /// Per-IP failed-login counters for brute-force rate limiting.
    login_attempts: Mutex<std::collections::HashMap<IpAddr, LoginAttempts>>,
}

impl AdminAuth {
    pub fn new(admins: Vec<Admin>, secure_cookies: bool) -> Self {
        Self {
            admins,
            sessions: Mutex::new(HashSet::new()),
            secure_cookies,
            login_attempts: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Whether the web admin requires a login.
    pub fn required(&self) -> bool {
        !self.admins.is_empty()
    }

    /// Whether session cookies should carry the `Secure` attribute.
    pub fn secure_cookies(&self) -> bool {
        self.secure_cookies
    }

    /// If `ip` is currently rate-limited, return the seconds the caller should
    /// wait before retrying; otherwise `None`. Does not mutate counters.
    pub fn login_retry_after(&self, ip: IpAddr) -> Option<u64> {
        let attempts = self.login_attempts.lock().unwrap();
        let a = attempts.get(&ip)?;
        if a.fails < MAX_LOGIN_FAILS {
            return None;
        }
        let elapsed = a.window_start.elapsed();
        (elapsed < LOGIN_WINDOW).then(|| (LOGIN_WINDOW - elapsed).as_secs() + 1)
    }

    /// Record a failed login from `ip`, opening or extending its window.
    pub fn record_login_failure(&self, ip: IpAddr) {
        let now = std::time::Instant::now();
        let mut attempts = self.login_attempts.lock().unwrap();
        // Drop stale windows so the map stays bounded by active attacker count.
        attempts.retain(|_, a| now.duration_since(a.window_start) < LOGIN_WINDOW);
        let entry = attempts.entry(ip).or_insert(LoginAttempts {
            fails: 0,
            window_start: now,
        });
        if now.duration_since(entry.window_start) >= LOGIN_WINDOW {
            entry.fails = 0;
            entry.window_start = now;
        }
        entry.fails = entry.fails.saturating_add(1);
    }

    /// Clear any throttling state for `ip` after a successful login.
    pub fn record_login_success(&self, ip: IpAddr) {
        self.login_attempts.lock().unwrap().remove(&ip);
    }

    /// Verify a login attempt: credentials must match an admin, and the
    /// client IP must be inside that admin's network range if one is set.
    pub fn check(
        &self,
        user: &str,
        password: &str,
        client_ip: std::net::IpAddr,
    ) -> Result<(), &'static str> {
        let admin = self
            .admins
            .iter()
            .find(|a| a.username == user && verify_password(&a.password, password))
            .ok_or("invalid username or password")?;
        if let Some(net) = admin.network {
            if !net.contains(&client_ip) {
                return Err("login is not allowed from your network");
            }
        }
        Ok(())
    }

    /// Mint and store a new session token.
    pub fn create_session(&self) -> String {
        let token = Uuid::new_v4().to_string();
        self.sessions.lock().unwrap().insert(token.clone());
        token
    }

    /// Whether `token` is an active session (always true when auth is off).
    pub fn valid(&self, token: &str) -> bool {
        !self.required() || self.sessions.lock().unwrap().contains(token)
    }

    /// Invalidate a session token (logout).
    pub fn revoke(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
    }
}

/// The IP portion of a `host:port` (or `[ipv6]:port`) source address.
fn src_ip(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some(i) = rest.find(']') {
            return &rest[..i];
        }
    }
    match addr.rsplit_once(':') {
        Some((h, _)) => h,
        None => addr,
    }
}

/// Central registry of all proxies.
pub struct Manager {
    pub storage: Arc<Storage>,
    pub proxies: DashMap<String, Arc<ProxyRuntime>>,
    pub events: broadcast::Sender<MonitorEvent>,
    /// Host-resource samples for the realtime monitor. Demand-driven: the
    /// collector only reads `/proc` while this channel has subscribers.
    pub resource_events: broadcast::Sender<ResourceSample>,
    /// Web-admin authentication.
    pub admin: AdminAuth,
    /// Global TLS acceptor for `https` proxies without their own keystore.
    pub tls: TlsAcceptor,
    /// Client connector (no client certificate) for `https://` upstreams.
    pub default_connector: TlsConnector,
    /// Source addresses (IP or `IP:port`) refused at accept time.
    pub blocklist: Mutex<HashSet<String>>,
}

impl Manager {
    /// Build a manager, loading persisted proxies and auto-starting the
    /// ones that were enabled.
    pub async fn bootstrap(
        storage: Arc<Storage>,
        admin: AdminAuth,
        tls: TlsAcceptor,
        default_connector: TlsConnector,
    ) -> Result<Arc<Self>> {
        let (events, _) = broadcast::channel(256);
        // Small buffer: monitor clients only need the latest sample, and a
        // lagged receiver is ignored (resyncs on the next tick).
        let (resource_events, _) = broadcast::channel(16);
        let blocklist = storage.load_blocklist().unwrap_or_default();
        let manager = Arc::new(Self {
            storage: storage.clone(),
            proxies: DashMap::new(),
            events,
            resource_events,
            admin,
            tls,
            default_connector,
            blocklist: Mutex::new(blocklist),
        });
        for cfg in storage.load_configs()? {
            let enabled = cfg.enabled;
            let id = cfg.id.clone();
            manager
                .proxies
                .insert(id.clone(), Arc::new(ProxyRuntime::new(cfg)));
            if enabled {
                if let Err(e) = manager.start(&id).await {
                    tracing::error!("auto-start of proxy {id} failed: {e}");
                }
            }
        }
        Ok(manager)
    }

    fn runtime(&self, id: &str) -> Result<Arc<ProxyRuntime>> {
        self.proxies
            .get(id)
            .map(|r| r.clone())
            .ok_or_else(|| anyhow!("proxy not found"))
    }

    /// Create and persist a new (stopped) proxy.
    pub fn create(&self, spec: ProxySpec) -> Result<ProxyConfig> {
        spec.validate()?;
        let nonempty = |v: Option<String>| v.filter(|s| !s.is_empty());
        let cfg = ProxyConfig {
            id: Uuid::new_v4().to_string(),
            name: spec.name,
            protocol: spec.protocol,
            listen_addr: spec.listen_addr,
            auth: spec.auth,
            ss_method: spec.ss_method,
            ss_password: spec.ss_password,
            forward_to: spec.forward_to,
            keepalive_secs: spec.keepalive_secs,
            idle_timeout_secs: spec.idle_timeout_secs,
            connect_timeout_secs: spec.connect_timeout_secs,
            send_proxy_protocol: spec.send_proxy_protocol,
            client_p12: nonempty(spec.client_p12),
            client_p12_password: spec.client_p12_password,
            client_p12_alias: spec.client_p12_alias,
            client_p12_entry_password: spec.client_p12_entry_password,
            override_headers: spec.override_headers,
            server_p12: nonempty(spec.server_p12),
            server_p12_password: spec.server_p12_password,
            server_truststore_p12: nonempty(spec.server_truststore_p12),
            server_truststore_password: spec.server_truststore_password,
            mtls_required: spec.mtls_required,
            blocklist: Vec::new(),
            max_connections: spec.max_connections,
            udp_associate_enabled: spec.udp_associate_enabled,
            udp_allow_private: spec.udp_allow_private,
            udp_bind_addr: spec.udp_bind_addr,
            udp_advertise_ip: spec.udp_advertise_ip,
            udp_max_datagram: spec.udp_max_datagram,
            udp_max_dests: spec.udp_max_dests,
            turn: spec.turn,
            enabled: false,
        };
        self.storage.save_config(&cfg)?;
        self.proxies
            .insert(cfg.id.clone(), Arc::new(ProxyRuntime::new(cfg.clone())));
        Ok(cfg)
    }

    /// Update an existing proxy's settings, restarting it if it was running.
    pub async fn update(self: &Arc<Self>, id: &str, spec: ProxySpec) -> Result<ProxyConfig> {
        spec.validate()?;
        let runtime = self.runtime(id)?;
        let was_running = runtime.running.load(Ordering::SeqCst);
        if was_running {
            self.stop(id)?;
        }
        {
            let mut cfg = runtime.config.lock().unwrap();
            cfg.name = spec.name;
            cfg.protocol = spec.protocol;
            cfg.listen_addr = spec.listen_addr;
            cfg.auth = spec.auth;
            cfg.ss_method = spec.ss_method;
            cfg.ss_password = spec.ss_password;
            cfg.forward_to = spec.forward_to;
            cfg.keepalive_secs = spec.keepalive_secs;
            cfg.idle_timeout_secs = spec.idle_timeout_secs;
            cfg.connect_timeout_secs = spec.connect_timeout_secs;
            cfg.override_headers = spec.override_headers;
            cfg.mtls_required = spec.mtls_required;
            cfg.max_connections = spec.max_connections;
            cfg.send_proxy_protocol = spec.send_proxy_protocol;
            cfg.udp_associate_enabled = spec.udp_associate_enabled;
            cfg.udp_allow_private = spec.udp_allow_private;
            cfg.udp_bind_addr = spec.udp_bind_addr;
            cfg.udp_advertise_ip = spec.udp_advertise_ip;
            cfg.udp_max_datagram = spec.udp_max_datagram;
            cfg.udp_max_dests = spec.udp_max_dests;
            // One assignment for the whole TURN block. Every other setting here
            // is copied by hand, which is why a grouped struct is worth the
            // deviation: a forgotten line compiles and silently drops the edit.
            cfg.turn = spec.turn;

            // Tri-state PKCS#12 fields: keep / clear / replace.
            match spec.client_p12 {
                None => {}
                Some(s) if s.is_empty() => {
                    cfg.client_p12 = None;
                    cfg.client_p12_password = None;
                    cfg.client_p12_alias = None;
                    cfg.client_p12_entry_password = None;
                }
                Some(s) => {
                    cfg.client_p12 = Some(s);
                    cfg.client_p12_password = spec.client_p12_password;
                    cfg.client_p12_alias = spec.client_p12_alias;
                    cfg.client_p12_entry_password = spec.client_p12_entry_password;
                }
            }
            match spec.server_p12 {
                None => {}
                Some(s) if s.is_empty() => {
                    cfg.server_p12 = None;
                    cfg.server_p12_password = None;
                }
                Some(s) => {
                    cfg.server_p12 = Some(s);
                    cfg.server_p12_password = spec.server_p12_password;
                }
            }
            match spec.server_truststore_p12 {
                None => {}
                Some(s) if s.is_empty() => {
                    cfg.server_truststore_p12 = None;
                    cfg.server_truststore_password = None;
                }
                Some(s) => {
                    cfg.server_truststore_p12 = Some(s);
                    cfg.server_truststore_password = spec.server_truststore_password;
                }
            }
            self.storage.save_config(&cfg)?;
        }
        if was_running {
            self.start(id).await?;
        }
        let cfg = runtime.config.lock().unwrap().clone();
        Ok(cfg)
    }

    /// Stop (if needed) and permanently remove a proxy and its history.
    pub fn delete(&self, id: &str) -> Result<()> {
        let _ = self.stop(id);
        self.proxies.remove(id);
        self.storage.delete_config(id)?;
        self.storage.delete_history(id)?;
        Ok(())
    }

    /// Build the TLS material a proxy needs before its accept loop starts.
    fn prepare_tls(&self, runtime: &ProxyRuntime) -> Result<()> {
        let cfg = runtime.config.lock().unwrap().clone();

        let acceptor = match (cfg.protocol, cfg.server_p12.as_deref()) {
            (Protocol::Https, Some(p12)) if !p12.is_empty() => Some(tls::acceptor_from_p12(
                p12,
                cfg.server_p12_password.as_deref().unwrap_or(""),
                cfg.server_truststore_p12.as_deref(),
                cfg.server_truststore_password.as_deref().unwrap_or(""),
                cfg.mtls_required,
            )?),
            _ => None,
        };
        *runtime.https_acceptor.lock().unwrap() = acceptor;

        let connector = match cfg.client_p12.as_deref() {
            Some(p12) if !p12.is_empty() && cfg.protocol.is_http() => {
                Some(Arc::new(tls::client_connector(
                    p12,
                    cfg.client_p12_password.as_deref().unwrap_or(""),
                    cfg.client_p12_alias.as_deref(),
                )?))
            }
            _ => None,
        };
        *runtime.client_connector.lock().unwrap() = connector;
        Ok(())
    }

    /// Bind the listener and spawn the accept loop for a proxy.
    pub async fn start(self: &Arc<Self>, id: &str) -> Result<()> {
        let runtime = self.runtime(id)?;
        if runtime.running.load(Ordering::SeqCst) {
            return Ok(());
        }
        self.prepare_tls(&runtime)?;

        let (addr, protocol) = {
            let cfg = runtime.config.lock().unwrap();
            (cfg.listen_addr.clone(), cfg.protocol)
        };

        let token = CancellationToken::new();

        if protocol == Protocol::Udp {
            let socket = UdpSocket::bind(&addr)
                .await
                .map_err(|e| anyhow!("cannot bind {addr}: {e}"))?;
            let socket = Arc::new(socket);
            *runtime.cancel.lock().unwrap() = Some(token.clone());
            runtime.running.store(true, Ordering::SeqCst);
            {
                let mut cfg = runtime.config.lock().unwrap();
                cfg.enabled = true;
                self.storage.save_config(&cfg)?;
            }
            let manager = self.clone();
            let rt = runtime.clone();
            tokio::spawn(async move {
                crate::udp::serve(manager, rt, socket, token).await;
            });
            tracing::info!("proxy {id} listening on {addr} (udp)");
            return Ok(());
        }

        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| anyhow!("cannot bind {addr}: {e}"))?;

        *runtime.cancel.lock().unwrap() = Some(token.clone());
        runtime.running.store(true, Ordering::SeqCst);
        {
            let mut cfg = runtime.config.lock().unwrap();
            cfg.enabled = true;
            self.storage.save_config(&cfg)?;
        }

        let manager = self.clone();
        let rt = runtime.clone();
        tokio::spawn(async move {
            Self::accept_loop(manager, rt, listener, token).await;
        });
        tracing::info!("proxy {id} listening on {addr}");
        Ok(())
    }

    /// Signal the accept loop and all in-flight connections to terminate.
    pub fn stop(&self, id: &str) -> Result<()> {
        let runtime = self.runtime(id)?;
        if let Some(token) = runtime.cancel.lock().unwrap().take() {
            token.cancel();
        }
        runtime.running.store(false, Ordering::SeqCst);
        let mut cfg = runtime.config.lock().unwrap();
        cfg.enabled = false;
        self.storage.save_config(&cfg)?;
        Ok(())
    }

    /// Abort one in-flight connection by id.
    pub fn kill_conn(&self, proxy_id: &str, conn_id: &str) -> Result<()> {
        let runtime = self.runtime(proxy_id)?;
        match runtime.conns.get(conn_id) {
            Some(entry) => {
                entry.cancel.cancel();
                Ok(())
            }
            None => bail!("connection not found (it may have already closed)"),
        }
    }

    /// Block a source address (`IP` or `IP:port`): it is refused on every
    /// future accept, and any matching live connections are terminated now.
    pub fn block(&self, addr: &str) -> Result<()> {
        let addr = addr.trim().to_string();
        if addr.is_empty() {
            bail!("address is required");
        }
        {
            let mut bl = self.blocklist.lock().unwrap();
            bl.insert(addr.clone());
            self.storage.save_blocklist(&bl)?;
        }
        for proxy in self.proxies.iter() {
            for conn in proxy.value().conns.iter() {
                let src = conn.value().src_addr.as_str();
                if src == addr || src_ip(src) == addr {
                    conn.value().cancel.cancel();
                }
            }
        }
        Ok(())
    }

    /// Remove a source address from the blocklist.
    pub fn unblock(&self, addr: &str) -> Result<()> {
        let mut bl = self.blocklist.lock().unwrap();
        bl.remove(addr.trim());
        self.storage.save_blocklist(&bl)?;
        Ok(())
    }

    /// The current manager-wide blocklist, sorted.
    pub fn blocklist(&self) -> Vec<String> {
        let mut out: Vec<String> = self.blocklist.lock().unwrap().iter().cloned().collect();
        out.sort();
        out
    }

    /// Block a source address on a single proxy and drop its matching live
    /// connections on that proxy.
    pub fn block_proxy(&self, proxy_id: &str, addr: &str) -> Result<()> {
        let addr = addr.trim().to_string();
        if addr.is_empty() {
            bail!("address is required");
        }
        let runtime = self.runtime(proxy_id)?;
        {
            let mut cfg = runtime.config.lock().unwrap();
            if !cfg.blocklist.contains(&addr) {
                cfg.blocklist.push(addr.clone());
            }
            self.storage.save_config(&cfg)?;
        }
        for conn in runtime.conns.iter() {
            let src = conn.value().src_addr.as_str();
            if src == addr || src_ip(src) == addr {
                conn.value().cancel.cancel();
            }
        }
        Ok(())
    }

    /// Remove a source address from a single proxy's blocklist.
    pub fn unblock_proxy(&self, proxy_id: &str, addr: &str) -> Result<()> {
        let runtime = self.runtime(proxy_id)?;
        let mut cfg = runtime.config.lock().unwrap();
        cfg.blocklist.retain(|a| a != addr.trim());
        self.storage.save_config(&cfg)?;
        Ok(())
    }

    /// One proxy's blocklist, sorted.
    pub fn proxy_blocklist(&self, proxy_id: &str) -> Result<Vec<String>> {
        let runtime = self.runtime(proxy_id)?;
        let mut out = runtime.config.lock().unwrap().blocklist.clone();
        out.sort();
        Ok(out)
    }

    /// Whether a peer is blocked manager-wide, by full `IP:port` or bare IP.
    pub(crate) fn is_blocked(&self, peer: &SocketAddr) -> bool {
        let bl = self.blocklist.lock().unwrap();
        bl.contains(&peer.to_string()) || bl.contains(&peer.ip().to_string())
    }

    /// Whether a peer is blocked for `runtime`: the OR of the manager-wide
    /// blocklist and the proxy's own `blocklist`. The per-proxy match compares
    /// each entry against both the full `IP:port` and the bare IP, mirroring
    /// the inline check the TCP accept loop used to run.
    pub(crate) fn peer_blocked(&self, runtime: &ProxyRuntime, peer: &SocketAddr) -> bool {
        if self.is_blocked(peer) {
            return true;
        }
        let cfg = runtime.config.lock().unwrap();
        cfg.blocklist
            .iter()
            .any(|a| *a == peer.to_string() || *a == peer.ip().to_string())
    }

    /// Canonicalize a v4-embedding IPv6 to its IPv4 form: `::ffff:0:0/96`
    /// (v4-mapped), the NAT64 well-known prefix `64:ff9b::/96`, and the
    /// deprecated IPv4-compatible `::a.b.c.d`. Other addresses pass through.
    #[allow(dead_code)] // consumed by the SOCKS5 UDP relay (Tasks 6-7).
    pub(crate) fn canonicalize_ip(ip: IpAddr) -> IpAddr {
        let IpAddr::V6(v6) = ip else { return ip };
        if let Some(v4) = v6.to_ipv4_mapped() {
            return IpAddr::V4(v4);
        }
        let seg = v6.segments();
        // NAT64 64:ff9b::/96 — last 32 bits are the embedded v4.
        if seg[0] == 0x0064
            && seg[1] == 0xff9b
            && seg[2] == 0
            && seg[3] == 0
            && seg[4] == 0
            && seg[5] == 0
        {
            let o = v6.octets();
            return IpAddr::V4(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
        }
        // Deprecated IPv4-compatible ::a.b.c.d (high 96 bits zero, not ::/::1).
        if seg[0] == 0
            && seg[1] == 0
            && seg[2] == 0
            && seg[3] == 0
            && seg[4] == 0
            && seg[5] == 0
            && !(seg[6] == 0 && seg[7] == 0)
            && !(seg[6] == 0 && seg[7] == 1)
        {
            let o = v6.octets();
            return IpAddr::V4(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
        }
        ip
    }

    /// Whether a UDP destination is internal/SSRF-risky and must be blocked when
    /// `udp_allow_private` is false. Canonicalizes v4-embedding IPv6 first, then
    /// applies the v4 ruleset; otherwise applies the native v6 ranges.
    #[allow(dead_code)] // consumed by the SOCKS5 UDP relay (Task 7).
    pub(crate) fn is_internal_dest(ip: IpAddr) -> bool {
        match Self::canonicalize_ip(ip) {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_multicast()
                    || v4.is_broadcast()
                    || v4.is_unspecified()
                    || o[0] == 100 && (64..=127).contains(&o[1]) // CGNAT 100.64/10
            }
            IpAddr::V6(v6) => {
                let seg = v6.segments();
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || (seg[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                    || (seg[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                    || (seg[0] == 0x0064 && seg[1] == 0xff9b) // NAT64 prefix itself
            }
        }
    }

    /// Pure matcher: does `ip:port` match either blocklist (manager-wide set
    /// `mgr` OR per-proxy list `proxy`), by full `ip:port`/`[v6]:port` or bare
    /// `ip`? V6 uses the bracketed form to match `src_ip`'s parser.
    pub(crate) fn dest_blocked_in(
        mgr: &std::collections::HashSet<String>,
        proxy: &[String],
        ip: IpAddr,
        port: u16,
    ) -> bool {
        let bare = ip.to_string();
        let full = match ip {
            IpAddr::V4(_) => format!("{ip}:{port}"),
            IpAddr::V6(_) => format!("[{ip}]:{port}"),
        };
        let hit = |s: &str| s == bare || s == full;
        mgr.contains(&bare) || mgr.contains(&full) || proxy.iter().any(|a| hit(a))
    }

    /// Whether a UDP destination `ip:port` is blocked, ORing the manager-wide
    /// blocklist with this proxy's per-proxy blocklist (C2). Reuses the same
    /// source-blocklist namespace intentionally (a blocked address is blocked
    /// both as a source and as a UDP destination).
    #[allow(dead_code)] // consumed by the SOCKS5 UDP relay (Task 7).
    pub(crate) fn dest_blocked(&self, runtime: &ProxyRuntime, ip: IpAddr, port: u16) -> bool {
        let mgr = self.blocklist.lock().unwrap();
        let proxy = runtime.config.lock().unwrap().blocklist.clone();
        Self::dest_blocked_in(&mgr, &proxy, ip, port)
    }

    async fn accept_loop(
        manager: Arc<Self>,
        runtime: Arc<ProxyRuntime>,
        listener: TcpListener,
        token: CancellationToken,
    ) {
        // Per-proxy concurrent-connection cap. A semaphore permit is acquired
        // before spawning each connection task and held for the task's whole
        // lifetime (handshake + relay), so it also bounds slow-handshake holds.
        // `None` means unlimited (the operator explicitly set max_connections=0).
        let (proxy_id, max_conns) = {
            let cfg = runtime.config.lock().unwrap();
            (cfg.id.clone(), effective_max_connections(cfg.max_connections))
        };
        let sem = max_conns.map(|n| Arc::new(Semaphore::new(n)));
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                res = listener.accept() => match res {
                    Ok((stream, peer)) => {
                        let blocked = manager.peer_blocked(&runtime, &peer);
                        if blocked {
                            tracing::debug!("rejected blocked peer {peer}");
                            continue;
                        }
                        // Enforce the connection cap: drop the connection when no
                        // permit is available rather than queueing it.
                        let permit = match &sem {
                            Some(s) => match s.clone().try_acquire_owned() {
                                Ok(p) => Some(p),
                                Err(_) => {
                                    tracing::debug!(
                                        "proxy {proxy_id} at max_connections; rejected {peer}"
                                    );
                                    drop(stream);
                                    continue;
                                }
                            },
                            None => None,
                        };
                        let m = manager.clone();
                        let rt = runtime.clone();
                        let t = token.clone();
                        tokio::spawn(async move {
                            // Held for the connection's lifetime; releases the
                            // permit on drop (when this task ends).
                            let _permit = permit;
                            let (protocol, keepalive) = {
                                let cfg = rt.config.lock().unwrap();
                                (cfg.protocol, cfg.keepalive_secs)
                            };
                            relay::apply_keepalive(&stream, keepalive);
                            let result = match protocol {
                                Protocol::Socks5 => socks5::serve(m, rt, stream, peer, t).await,
                                Protocol::Http => http::serve(m, rt, stream, peer, t).await,
                                Protocol::Tcp => tcp::serve(m, rt, stream, peer, t).await,
                                Protocol::Websocket => {
                                    ws_proxy::serve(m, rt, stream, peer, t).await
                                }
                                Protocol::Shadowsocks => {
                                    shadowsocks::serve(m, rt, stream, peer, t).await
                                }
                                Protocol::Https => {
                                    let acceptor = rt
                                        .https_acceptor
                                        .lock()
                                        .unwrap()
                                        .clone()
                                        .unwrap_or_else(|| m.tls.clone());
                                    // Bound the TLS handshake so a client that
                                    // stalls mid-handshake cannot pin the task.
                                    match tokio::time::timeout(
                                        relay::HANDSHAKE_TIMEOUT,
                                        acceptor.accept(stream),
                                    )
                                    .await
                                    {
                                        Ok(Ok(tls_stream)) => {
                                            http::serve(m, rt, tls_stream, peer, t).await
                                        }
                                        Ok(Err(e)) => Err(anyhow!("TLS handshake failed: {e}")),
                                        Err(_) => Err(anyhow!("TLS handshake timed out")),
                                    }
                                }
                                Protocol::Udp => {
                                    // UDP is never dispatched through the TCP accept
                                    // loop; it has its own listen path (see Task 5).
                                    Err(anyhow!("udp is not a stream protocol"))
                                }
                                Protocol::Turn => {
                                    // TURN binds its own listeners in start(), so
                                    // nothing ever reaches the shared accept loop.
                                    Err(anyhow!("turn has its own listen path"))
                                }
                            };
                            if let Err(e) = result {
                                tracing::debug!("connection from {peer} ended: {e}");
                            }
                        });
                    }
                    Err(e) => tracing::warn!("accept error: {e}"),
                },
            }
        }
        runtime.running.store(false, Ordering::SeqCst);
    }

    /// Build a realtime snapshot of every proxy for the monitoring feed.
    pub fn snapshot(&self) -> Vec<ProxySnapshot> {
        let mut out = Vec::new();
        for entry in self.proxies.iter() {
            let rt = entry.value();
            let cfg = rt.config.lock().unwrap().clone();
            let mut active: Vec<ActiveConn> = rt
                .conns
                .iter()
                .map(|c| {
                    let e = c.value();
                    ActiveConn {
                        id: e.id.clone(),
                        src_addr: e.src_addr.clone(),
                        dst_addr: e.dst_addr.clone(),
                        bytes_sent: e.bytes_sent.load(Ordering::Relaxed),
                        bytes_received: e.bytes_received.load(Ordering::Relaxed),
                        started_at: e.started_at,
                    }
                })
                .collect();
            active.sort_by(|a, b| b.started_at.cmp(&a.started_at));
            // Aggregate totals = traffic of closed connections plus the
            // current counters of connections that are still open, so the
            // proxy-level figures stay consistent with the per-connection rows.
            let live_sent: u64 = active.iter().map(|c| c.bytes_sent).sum();
            let live_received: u64 = active.iter().map(|c| c.bytes_received).sum();
            out.push(ProxySnapshot {
                id: cfg.id,
                name: cfg.name,
                protocol: cfg.protocol.as_str().to_string(),
                listen_addr: cfg.listen_addr,
                running: rt.running.load(Ordering::SeqCst),
                auth_enabled: cfg.auth.is_some(),
                auth_username: cfg.auth.as_ref().map(|a| a.username.clone()),
                ss_method: cfg.ss_method.clone(),
                forward_to: cfg.forward_to.clone(),
                keepalive_secs: cfg.keepalive_secs,
                idle_timeout_secs: cfg.idle_timeout_secs,
                connect_timeout_secs: cfg.connect_timeout_secs,
                send_proxy_protocol: cfg.send_proxy_protocol,
                override_headers: cfg.override_headers.clone(),
                has_client_p12: cfg.client_p12.is_some(),
                client_p12_alias: cfg.client_p12_alias.clone(),
                has_server_p12: cfg.server_p12.is_some(),
                has_truststore: cfg.server_truststore_p12.is_some(),
                mtls_required: cfg.mtls_required,
                udp_associate_enabled: cfg.udp_associate_enabled,
                udp_allow_private: cfg.udp_allow_private,
                udp_bind_addr: cfg.udp_bind_addr.clone(),
                udp_advertise_ip: cfg.udp_advertise_ip.clone(),
                udp_max_datagram: cfg.udp_max_datagram,
                udp_max_dests: cfg.udp_max_dests,
                turn: crate::model::TurnView::from(&cfg.turn),
                max_connections: cfg.max_connections,
                blocklist: {
                    let mut bl = cfg.blocklist.clone();
                    bl.sort();
                    bl
                },
                total_connections: rt.total_connections.load(Ordering::Relaxed),
                bytes_sent: rt.total_sent.load(Ordering::Relaxed) + live_sent,
                bytes_received: rt.total_received.load(Ordering::Relaxed) + live_received,
                active_connections: active,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Protocol;
    use crate::model::ProxyConfig;
    use crate::storage::Storage;
    use std::net::SocketAddr;

    fn udp_spec(forward_to: Option<&str>) -> ProxySpec {
        ProxySpec {
            name: "u".into(),
            protocol: Protocol::Udp,
            listen_addr: "0.0.0.0:0".into(),
            auth: None,
            ss_method: None,
            ss_password: None,
            send_proxy_protocol: false,
            forward_to: forward_to.map(|s| s.to_string()),
            keepalive_secs: None,
            idle_timeout_secs: None,
            connect_timeout_secs: None,
            client_p12: None,
            client_p12_password: None,
            client_p12_alias: None,
            client_p12_entry_password: None,
            override_headers: Vec::new(),
            server_p12: None,
            server_p12_password: None,
            server_truststore_p12: None,
            server_truststore_password: None,
            mtls_required: false,
            udp_associate_enabled: true,
            udp_allow_private: false,
            udp_bind_addr: None,
            udp_advertise_ip: None,
            udp_max_datagram: None,
            udp_max_dests: None,
            max_connections: None,
            turn: TurnConfig::default(),
        }
    }

    #[test]
    fn udp_as_str_is_udp() {
        assert_eq!(Protocol::Udp.as_str(), "udp");
    }

    #[test]
    fn verify_password_plaintext() {
        assert!(verify_password("secret", "secret"));
        assert!(!verify_password("secret", "wrong"));
        assert!(!verify_password("secret", ""));
    }

    #[test]
    fn verify_password_argon2_roundtrip() {
        use argon2::password_hash::SaltString;
        use argon2::{Argon2, PasswordHasher};
        let salt = SaltString::from_b64("c29tZXNhbHQ").unwrap();
        let hash = Argon2::default()
            .hash_password(b"correct horse", &salt)
            .unwrap()
            .to_string();
        assert!(hash.starts_with("$argon2"));
        assert!(verify_password(&hash, "correct horse"));
        assert!(!verify_password(&hash, "wrong"));
        assert!(!verify_password(&hash, ""));
    }

    #[test]
    fn check_accepts_argon2_admin_and_rejects_wrong_password() {
        use argon2::password_hash::SaltString;
        use argon2::{Argon2, PasswordHasher};
        let salt = SaltString::from_b64("c29tZXNhbHQ").unwrap();
        let hash = Argon2::default()
            .hash_password(b"hunter2", &salt)
            .unwrap()
            .to_string();
        let auth = AdminAuth::new(
            vec![Admin {
                username: "alice".into(),
                password: hash,
                network: None,
            }],
            false,
        );
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        assert!(auth.check("alice", "hunter2", ip).is_ok());
        assert!(auth.check("alice", "nope", ip).is_err());
        assert!(auth.check("bob", "hunter2", ip).is_err());
    }

    #[test]
    fn verify_password_malformed_argon2_never_authenticates() {
        // Looks like a PHC hash but is unparseable: must be refused, and must
        // NOT fall back to plaintext (even when candidate equals the stored
        // string).
        assert!(!verify_password("$argon2id$broken", "anything"));
        assert!(!verify_password("$argon2id$broken", "$argon2id$broken"));
    }

    #[test]
    fn udp_validate_requires_forward_to() {
        assert!(udp_spec(None).validate().is_err());
        assert!(udp_spec(Some("")).validate().is_err());
        assert!(udp_spec(Some("1.2.3.4:53")).validate().is_ok());
    }

    #[test]
    fn validate_rejects_control_chars_and_overlong_name() {
        let mut s = udp_spec(Some("1.2.3.4:53"));
        s.name = "ok name".into();
        assert!(s.validate().is_ok());
        // CR/LF and other control chars (the XSS break-out helpers) are refused.
        s.name = "evil\r\nX".into();
        assert!(s.validate().is_err());
        s.name = "x".repeat(201);
        assert!(s.validate().is_err());
    }

    #[test]
    fn salt_cache_detects_reuse_and_evicts_oldest() {
        let mut c = SaltCache::new(2);
        assert!(c.insert(b"a")); // new
        assert!(!c.insert(b"a")); // replay -> rejected
        assert!(c.insert(b"b")); // new
        assert!(c.insert(b"c")); // new -> evicts the oldest ("a")
        assert!(!c.insert(b"c")); // still remembered
        assert!(c.insert(b"a")); // "a" was evicted, so it is new again
    }

    #[test]
    fn note_ss_salt_rejects_replayed_salt() {
        let rt = runtime_with_blocklist(Vec::new());
        assert!(rt.note_ss_salt(b"saltsaltsalt1234"));
        assert!(!rt.note_ss_salt(b"saltsaltsalt1234"));
        assert!(rt.note_ss_salt(b"a-different-salt"));
    }

    #[test]
    fn login_rate_limit_blocks_after_threshold_and_clears_on_success() {
        let auth = AdminAuth::new(
            vec![Admin {
                username: "u".into(),
                password: "p".into(),
                network: None,
            }],
            false,
        );
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(auth.login_retry_after(ip), None);
        for _ in 0..MAX_LOGIN_FAILS {
            auth.record_login_failure(ip);
        }
        assert!(auth.login_retry_after(ip).is_some());
        // A different IP is unaffected.
        let other: std::net::IpAddr = "5.6.7.8".parse().unwrap();
        assert_eq!(auth.login_retry_after(other), None);
        // A successful login clears the throttle for that IP.
        auth.record_login_success(ip);
        assert_eq!(auth.login_retry_after(ip), None);
    }

    #[test]
    fn secure_cookies_flag_is_reported() {
        assert!(!AdminAuth::new(Vec::new(), false).secure_cookies());
        assert!(AdminAuth::new(Vec::new(), true).secure_cookies());
    }

    fn temp_manager() -> Arc<Manager> {
        let dir = std::env::temp_dir().join(format!("snproxy-test-{}", Uuid::new_v4()));
        let storage = Storage::open(dir.to_str().unwrap()).unwrap();
        let (events, _) = broadcast::channel(16);
        let (resource_events, _) = broadcast::channel(16);
        Arc::new(Manager {
            storage,
            proxies: DashMap::new(),
            events,
            resource_events,
            admin: AdminAuth::new(Vec::new(), false),
            tls: crate::tls::acceptor(None, None).unwrap(),
            default_connector: crate::tls::plain_connector(),
            blocklist: Mutex::new(HashSet::new()),
        })
    }

    fn runtime_with_blocklist(list: Vec<String>) -> ProxyRuntime {
        let mut cfg = udp_spec(Some("1.2.3.4:53"));
        // ProxySpec -> a minimal ProxyConfig carrying only what peer_blocked reads.
        let config = ProxyConfig {
            id: Uuid::new_v4().to_string(),
            name: cfg.name.clone(),
            protocol: Protocol::Udp,
            listen_addr: cfg.listen_addr.clone(),
            auth: None,
            ss_method: None,
            ss_password: None,
            send_proxy_protocol: false,
            forward_to: cfg.forward_to.take(),
            keepalive_secs: None,
            idle_timeout_secs: None,
            connect_timeout_secs: None,
            client_p12: None,
            client_p12_password: None,
            client_p12_alias: None,
            client_p12_entry_password: None,
            override_headers: Vec::new(),
            server_p12: None,
            server_p12_password: None,
            server_truststore_p12: None,
            server_truststore_password: None,
            mtls_required: false,
            blocklist: list,
            max_connections: None,
            udp_associate_enabled: true,
            udp_allow_private: false,
            udp_bind_addr: None,
            udp_advertise_ip: None,
            udp_max_datagram: None,
            udp_max_dests: None,
            turn: TurnConfig::default(),
            enabled: false,
        };
        ProxyRuntime::new(config)
    }

    #[test]
    fn peer_blocked_matches_manager_wide_ip() {
        let m = temp_manager();
        m.block("9.9.9.9").unwrap();
        let rt = runtime_with_blocklist(Vec::new());
        let peer: SocketAddr = "9.9.9.9:5000".parse().unwrap();
        assert!(m.peer_blocked(&rt, &peer));
        let other: SocketAddr = "8.8.8.8:5000".parse().unwrap();
        assert!(!m.peer_blocked(&rt, &other));
    }

    #[test]
    fn peer_blocked_matches_per_proxy_ip_and_ipport() {
        let m = temp_manager();
        let peer: SocketAddr = "7.7.7.7:1234".parse().unwrap();
        // bare IP entry
        let rt_ip = runtime_with_blocklist(vec!["7.7.7.7".into()]);
        assert!(m.peer_blocked(&rt_ip, &peer));
        // full IP:port entry
        let rt_full = runtime_with_blocklist(vec!["7.7.7.7:1234".into()]);
        assert!(m.peer_blocked(&rt_full, &peer));
        // non-matching port-specific entry
        let rt_miss = runtime_with_blocklist(vec!["7.7.7.7:9999".into()]);
        assert!(!m.peer_blocked(&rt_miss, &peer));
    }

    #[tokio::test]
    async fn start_udp_binds_udp_not_tcp() {
        let m = temp_manager();
        let cfg = m.create(udp_spec(Some("127.0.0.1:65000"))).unwrap();
        let rt = m.proxies.get(&cfg.id).unwrap().clone();
        rt.config.lock().unwrap().listen_addr = "127.0.0.1:45999".into();
        m.start(&cfg.id).await.unwrap();
        assert!(rt.running.load(Ordering::SeqCst));
        // The UDP port must now be occupied (proves a UDP bind happened).
        assert!(std::net::UdpSocket::bind("127.0.0.1:45999").is_err());
        // The TCP port of the same number must still be free (proves we did
        // NOT bind a TcpListener for a UDP proxy).
        assert!(std::net::TcpListener::bind("127.0.0.1:45999").is_ok());
        m.stop(&cfg.id).unwrap();
    }
}

#[cfg(test)]
mod udp_internal_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn v4_internal_ranges_blocked() {
        assert!(Manager::is_internal_dest(v4(127, 0, 0, 1))); // loopback
        assert!(Manager::is_internal_dest(v4(10, 0, 0, 5))); // RFC1918
        assert!(Manager::is_internal_dest(v4(192, 168, 1, 1)));
        assert!(Manager::is_internal_dest(v4(172, 16, 9, 9)));
        assert!(Manager::is_internal_dest(v4(169, 254, 169, 254))); // metadata
        assert!(Manager::is_internal_dest(v4(100, 64, 0, 1))); // CGNAT
        assert!(Manager::is_internal_dest(v4(0, 0, 0, 0))); // unspecified
        assert!(Manager::is_internal_dest(v4(224, 0, 0, 1))); // multicast
        assert!(Manager::is_internal_dest(v4(255, 255, 255, 255))); // broadcast
    }

    #[test]
    fn public_v4_allowed() {
        assert!(!Manager::is_internal_dest(v4(8, 8, 8, 8)));
        assert!(!Manager::is_internal_dest(v4(1, 1, 1, 1)));
    }

    #[test]
    fn v6_native_ranges_blocked() {
        assert!(Manager::is_internal_dest(IpAddr::V6(Ipv6Addr::LOCALHOST))); // ::1
        assert!(Manager::is_internal_dest(IpAddr::V6(Ipv6Addr::UNSPECIFIED))); // ::
        assert!(Manager::is_internal_dest("fc00::1".parse().unwrap())); // ULA
        assert!(Manager::is_internal_dest("fe80::1".parse().unwrap())); // link-local
        assert!(Manager::is_internal_dest("ff02::1".parse().unwrap())); // multicast
    }

    #[test]
    fn public_v6_allowed() {
        assert!(!Manager::is_internal_dest("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn v4_mapped_v6_unmapped_and_blocked() {
        // ::ffff:7f00:1 == 127.0.0.1 ; ::ffff:a9fe:a9fe == 169.254.169.254
        assert!(Manager::is_internal_dest("::ffff:7f00:1".parse().unwrap()));
        assert!(Manager::is_internal_dest("::ffff:a9fe:a9fe".parse().unwrap()));
        // ::ffff:8.8.8.8 is still public after unmapping
        assert!(!Manager::is_internal_dest("::ffff:808:808".parse().unwrap()));
    }

    #[test]
    fn nat64_wrapper_of_internal_blocked() {
        // 64:ff9b::7f00:1 wraps 127.0.0.1
        assert!(Manager::is_internal_dest("64:ff9b::7f00:1".parse().unwrap()));
    }
}

#[cfg(test)]
mod dest_blocked_tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn matches_v4_full_and_bare() {
        let mut mgr: HashSet<String> = HashSet::new();
        mgr.insert("1.2.3.4:53".into());
        let proxy: Vec<String> = vec![];
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert!(Manager::dest_blocked_in(&mgr, &proxy, ip, 53)); // full
        assert!(!Manager::dest_blocked_in(&mgr, &proxy, ip, 54)); // wrong port
        let mut bare: HashSet<String> = HashSet::new();
        bare.insert("1.2.3.4".into());
        assert!(Manager::dest_blocked_in(&bare, &proxy, ip, 99)); // bare ip
    }

    #[test]
    fn matches_per_proxy_half() {
        let mgr: HashSet<String> = HashSet::new();
        let proxy: Vec<String> = vec!["9.9.9.9".into()];
        let ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
        // Blocked ONLY via the per-proxy list — proves the OR covers it.
        assert!(Manager::dest_blocked_in(&mgr, &proxy, ip, 853));
    }

    #[test]
    fn matches_v6_bracketed_and_bare() {
        let mut mgr: HashSet<String> = HashSet::new();
        mgr.insert("[2001:db8::1]:443".into());
        let proxy: Vec<String> = vec![];
        let ip = IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert!(Manager::dest_blocked_in(&mgr, &proxy, ip, 443));
        let mut bare: HashSet<String> = HashSet::new();
        bare.insert("2001:db8::1".into());
        assert!(Manager::dest_blocked_in(&bare, &proxy, ip, 1));
    }
}
