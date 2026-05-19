//! sn-proxy — a multi-instance, multi-protocol proxy server with a realtime
//! web admin.
//!
//! Everything runs on a single Tokio runtime: each proxy has its own accept
//! loop, the Axum web admin serves the HTTP API and the websocket monitoring
//! feed, and connection history is persisted in RocksDB.

mod api;
mod http;
mod manager;
mod model;
mod monitor;
mod relay;
mod shadowsocks;
mod socks5;
mod storage;
mod tcp;
mod tls;
mod ws;
mod ws_proxy;

use anyhow::{Context, Result, anyhow};
use manager::{Admin, AdminAuth};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

const HELP: &str = "\
sn-proxy — multi-instance, multi-protocol proxy server with a web admin

USAGE:
  sn-proxy [OPTIONS]

OPTIONS:
  -c, --config <FILE>        Properties config file (key=value)
  -p, --port <[HOST:]PORT>   Web admin address; a bare port binds 0.0.0.0
  -d, --data-dir <DIR>       RocksDB data directory
  -h, --help                 Print this help and exit

CONFIG FILE KEYS (all optional):
  port             Web admin port or HOST:PORT
  data_dir         RocksDB data directory
  tls_cert         PEM certificate for the HTTPS proxy protocol
  tls_key          PEM private key for the HTTPS proxy protocol
  admin_user       Web admin login username (enables login when set)
  admin_password   Web admin login password
  admin_network    Restrict that admin's login to a CIDR, e.g. 192.168.1.0/24
  admin.<NAME>.password   Extra admin account (multi-admin form)
  admin.<NAME>.network    That admin's allowed CIDR (optional)

Command-line -p / -d override the config file. Defaults: 0.0.0.0:8080, data/.";

/// Fully resolved runtime configuration.
struct AppConfig {
    listen: String,
    data_dir: String,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    admins: Vec<Admin>,
}

/// Turn a `port` value into a full `host:port` bind address. A value
/// containing `:` is treated as `host:port`; a bare value binds `0.0.0.0`.
fn parse_listen(source: &str, raw: &str) -> String {
    let (addr, port) = match raw.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => (raw.to_string(), port),
        Some((_, port)) => (format!("0.0.0.0:{port}"), port),
        None => (format!("0.0.0.0:{raw}"), raw),
    };
    if port.parse::<u16>().is_err() {
        eprintln!("error: {source}: invalid port in {raw:?}");
        std::process::exit(2);
    }
    addr
}

/// Parse a `.properties` file (`key=value`, `#`/`!` comments, blank lines).
fn parse_properties(path: &str) -> Result<HashMap<String, String>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading config file {path}"))?;
    let mut map = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            map.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    Ok(map)
}

/// Parse a CIDR network range from a config value.
fn parse_net(raw: &str) -> Result<ipnet::IpNet> {
    raw.trim()
        .parse::<ipnet::IpNet>()
        .with_context(|| format!("invalid network CIDR {raw:?} (expected e.g. 192.168.1.0/24)"))
}

/// Collect web-admin accounts from the config file. Supports both the single
/// `admin_user` / `admin_password` / `admin_network` shorthand and any number
/// of `admin.<NAME>.password` / `admin.<NAME>.network` entries.
fn build_admins(props: &HashMap<String, String>) -> Result<Vec<Admin>> {
    let mut admins = Vec::new();

    if let (Some(user), Some(password)) = (props.get("admin_user"), props.get("admin_password")) {
        if !user.is_empty() {
            let network = match props.get("admin_network") {
                Some(n) if !n.trim().is_empty() => Some(parse_net(n)?),
                _ => None,
            };
            admins.push(Admin {
                username: user.clone(),
                password: password.clone(),
                network,
            });
        }
    }

    // admin.<NAME>.password / admin.<NAME>.network — grouped by name.
    let mut grouped: std::collections::BTreeMap<String, (Option<String>, Option<String>)> =
        std::collections::BTreeMap::new();
    for (key, value) in props {
        let Some(rest) = key.strip_prefix("admin.") else {
            continue;
        };
        let Some((name, field)) = rest.rsplit_once('.') else {
            continue;
        };
        let entry = grouped.entry(name.to_string()).or_default();
        match field {
            "password" => entry.0 = Some(value.clone()),
            "network" => entry.1 = Some(value.clone()),
            _ => {}
        }
    }
    for (name, (password, network)) in grouped {
        let password =
            password.ok_or_else(|| anyhow!("admin '{name}' is missing admin.{name}.password"))?;
        let network = match network {
            Some(n) if !n.trim().is_empty() => Some(parse_net(&n)?),
            _ => None,
        };
        admins.push(Admin {
            username: name,
            password,
            network,
        });
    }
    Ok(admins)
}

/// Return an option flag's value, or exit if it is missing.
fn require_value(flag: &str, value: Option<String>) -> String {
    value.unwrap_or_else(|| {
        eprintln!("error: {flag} requires a value");
        std::process::exit(2);
    })
}

/// Resolve config from defaults, then the config file, then CLI flags.
fn resolve_config() -> Result<AppConfig> {
    let mut config_path: Option<String> = None;
    let mut cli_port: Option<String> = None;
    let mut cli_data_dir: Option<String> = None;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-c" | "--config" => config_path = Some(require_value(&arg, it.next())),
            "-p" | "--port" => cli_port = Some(require_value(&arg, it.next())),
            "-d" | "--data-dir" => cli_data_dir = Some(require_value(&arg, it.next())),
            "-h" | "--help" => {
                println!("{HELP}");
                std::process::exit(0);
            }
            other => {
                eprintln!("error: unknown argument: {other}\n\n{HELP}");
                std::process::exit(2);
            }
        }
    }

    let mut listen = String::from("0.0.0.0:8080");
    let mut data_dir = String::from("data");
    let mut tls_cert = None;
    let mut tls_key = None;
    let mut admins = Vec::new();

    // Config file.
    if let Some(path) = &config_path {
        let props = parse_properties(path)?;
        if let Some(p) = props.get("port") {
            listen = parse_listen("config port", p);
        }
        if let Some(d) = props.get("data_dir") {
            data_dir = d.clone();
        }
        tls_cert = props.get("tls_cert").cloned();
        tls_key = props.get("tls_key").cloned();
        admins = build_admins(&props)?;
    }

    // Command-line overrides.
    if let Some(p) = &cli_port {
        listen = parse_listen("--port", p);
    }
    if let Some(d) = cli_data_dir {
        data_dir = d;
    }

    Ok(AppConfig {
        listen,
        data_dir,
        tls_cert,
        tls_key,
        admins,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("sn_proxy=info")),
        )
        .init();

    let config = resolve_config()?;
    tracing::info!("Using data dir: {}", &config.data_dir);
    // Install the process-wide rustls crypto provider before any TLS config
    // is built.
    tls::install_provider();
    // Persistence, TLS for HTTPS proxies, and the web-admin login.
    let storage = storage::Storage::open(&config.data_dir)?;
    let tls = tls::acceptor(config.tls_cert.as_deref(), config.tls_key.as_deref())?;
    let default_connector = tls::plain_connector();
    let admin_count = config.admins.len();
    let admin = AdminAuth::new(config.admins);
    if admin.required() {
        tracing::info!("web admin login is ENABLED ({admin_count} admin account(s))");
    } else {
        tracing::warn!("web admin login is DISABLED (set admin_user/admin_password in config)");
    }
    let manager = manager::Manager::bootstrap(storage, admin, tls, default_connector).await?;

    // Broadcast a fresh snapshot to websocket clients once a second.
    {
        let manager = manager.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                tick.tick().await;
                if manager.events.receiver_count() == 0 {
                    continue;
                }
                let event = monitor::MonitorEvent::Snapshot {
                    ts: model::now_ms(),
                    proxies: manager.snapshot(),
                };
                let _ = manager.events.send(event);
            }
        });
    }

    // Web admin (HTTP API + websocket).
    let listener = tokio::net::TcpListener::bind(&config.listen).await?;
    tracing::info!("web admin available at http://{}", config.listen);
    axum::serve(
        listener,
        api::router(manager).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
