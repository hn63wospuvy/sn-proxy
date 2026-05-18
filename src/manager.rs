//! Owns every proxy instance: lifecycle (start/stop), live connection
//! tracking and the broadcast channel feeding realtime monitoring.

use crate::model::{BasicAuth, ProxyConfig};
use crate::monitor::{ActiveConn, MonitorEvent, ProxySnapshot};
use crate::socks5;
use crate::storage::Storage;
use anyhow::{Result, anyhow};
use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
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

/// Central registry of all proxies.
pub struct Manager {
    pub storage: Arc<Storage>,
    pub proxies: DashMap<String, Arc<ProxyRuntime>>,
    pub events: broadcast::Sender<MonitorEvent>,
}

impl Manager {
    /// Build a manager, loading persisted proxies and auto-starting the
    /// ones that were enabled.
    pub async fn bootstrap(storage: Arc<Storage>) -> Result<Arc<Self>> {
        let (events, _) = broadcast::channel(256);
        let manager = Arc::new(Self {
            storage: storage.clone(),
            proxies: DashMap::new(),
            events,
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
    pub fn create(
        &self,
        name: String,
        listen_addr: String,
        auth: Option<BasicAuth>,
    ) -> Result<ProxyConfig> {
        let cfg = ProxyConfig {
            id: Uuid::new_v4().to_string(),
            name,
            listen_addr,
            auth,
            enabled: false,
        };
        self.storage.save_config(&cfg)?;
        self.proxies
            .insert(cfg.id.clone(), Arc::new(ProxyRuntime::new(cfg.clone())));
        Ok(cfg)
    }

    /// Update an existing proxy's settings, restarting it if it was running.
    pub async fn update(
        self: &Arc<Self>,
        id: &str,
        name: String,
        listen_addr: String,
        auth: Option<BasicAuth>,
    ) -> Result<ProxyConfig> {
        let runtime = self.runtime(id)?;
        let was_running = runtime.running.load(Ordering::SeqCst);
        if was_running {
            self.stop(id)?;
        }
        {
            let mut cfg = runtime.config.lock().unwrap();
            cfg.name = name;
            cfg.listen_addr = listen_addr;
            cfg.auth = auth;
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
                            if let Err(e) = socks5::serve(m, rt, stream, peer, t).await {
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
                listen_addr: cfg.listen_addr,
                running: rt.running.load(Ordering::SeqCst),
                auth_enabled: cfg.auth.is_some(),
                auth_username: cfg.auth.as_ref().map(|a| a.username.clone()),
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
