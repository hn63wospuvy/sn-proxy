//! Owns every proxy instance: lifecycle (start/stop), live connection
//! tracking and the broadcast channel feeding realtime monitoring.

use crate::model::{BasicAuth, Protocol, ProxyConfig};
use crate::monitor::{ActiveConn, MonitorEvent, ProxySnapshot};
use crate::storage::Storage;
use crate::{http, relay, shadowsocks, socks5, tcp};
use anyhow::{Result, anyhow, bail};
use dashmap::DashMap;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;
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
}

impl ProxyRuntime {
    fn new(config: ProxyConfig) -> Self {
        Self {
            config: Mutex::new(config),
            running: AtomicBool::new(false),
            cancel: Mutex::new(None),
            conns: DashMap::new(),
            total_connections: AtomicU64::new(0),
            total_sent: AtomicU64::new(0),
            total_received: AtomicU64::new(0),
        }
    }
}

/// Caller-supplied settings for creating or updating a proxy.
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
}

impl ProxySpec {
    /// Reject obviously invalid settings before they are persisted.
    fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            bail!("name is required");
        }
        if self.listen_addr.trim().is_empty() {
            bail!("listen address is required");
        }
        if self.protocol == Protocol::Tcp
            && self.forward_to.as_deref().unwrap_or("").is_empty()
        {
            bail!("tcp proxy needs a forward destination (host:port)");
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

/// One web-admin account, optionally restricted to a network range.
pub struct Admin {
    pub username: String,
    pub password: String,
    /// When set, the admin may only log in from an IP inside this CIDR.
    pub network: Option<ipnet::IpNet>,
}

/// Web-admin accounts and active sessions.
///
/// When the admin list is empty the web admin is open (no login).
pub struct AdminAuth {
    admins: Vec<Admin>,
    sessions: Mutex<HashSet<String>>,
}

impl AdminAuth {
    pub fn new(admins: Vec<Admin>) -> Self {
        Self {
            admins,
            sessions: Mutex::new(HashSet::new()),
        }
    }

    /// Whether the web admin requires a login.
    pub fn required(&self) -> bool {
        !self.admins.is_empty()
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
            .find(|a| a.username == user && a.password == password)
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

/// Central registry of all proxies.
pub struct Manager {
    pub storage: Arc<Storage>,
    pub proxies: DashMap<String, Arc<ProxyRuntime>>,
    pub events: broadcast::Sender<MonitorEvent>,
    /// Web-admin authentication.
    pub admin: AdminAuth,
    /// Shared TLS acceptor for `https` proxies.
    pub tls: TlsAcceptor,
}

impl Manager {
    /// Build a manager, loading persisted proxies and auto-starting the
    /// ones that were enabled.
    pub async fn bootstrap(
        storage: Arc<Storage>,
        admin: AdminAuth,
        tls: TlsAcceptor,
    ) -> Result<Arc<Self>> {
        let (events, _) = broadcast::channel(256);
        let manager = Arc::new(Self {
            storage: storage.clone(),
            proxies: DashMap::new(),
            events,
            admin,
            tls,
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

    /// Bind the listener and spawn the accept loop for a proxy.
    pub async fn start(self: &Arc<Self>, id: &str) -> Result<()> {
        let runtime = self.runtime(id)?;
        if runtime.running.load(Ordering::SeqCst) {
            return Ok(());
        }
        let addr = runtime.config.lock().unwrap().listen_addr.clone();
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| anyhow!("cannot bind {addr}: {e}"))?;

        let token = CancellationToken::new();
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

    async fn accept_loop(
        manager: Arc<Self>,
        runtime: Arc<ProxyRuntime>,
        listener: TcpListener,
        token: CancellationToken,
    ) {
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                res = listener.accept() => match res {
                    Ok((stream, peer)) => {
                        let m = manager.clone();
                        let rt = runtime.clone();
                        let t = token.clone();
                        tokio::spawn(async move {
                            let (protocol, keepalive) = {
                                let cfg = rt.config.lock().unwrap();
                                (cfg.protocol, cfg.keepalive_secs)
                            };
                            relay::apply_keepalive(&stream, keepalive);
                            let result = match protocol {
                                Protocol::Socks5 => socks5::serve(m, rt, stream, peer, t).await,
                                Protocol::Http => http::serve(m, rt, stream, peer, t).await,
                                Protocol::Tcp => tcp::serve(m, rt, stream, peer, t).await,
                                Protocol::Shadowsocks => {
                                    shadowsocks::serve(m, rt, stream, peer, t).await
                                }
                                Protocol::Https => match m.tls.clone().accept(stream).await {
                                    Ok(tls_stream) => {
                                        http::serve(m, rt, tls_stream, peer, t).await
                                    }
                                    Err(e) => Err(anyhow!("TLS handshake failed: {e}")),
                                },
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
