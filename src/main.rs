//! sn-proxy — a multi-instance SOCKS5 proxy server with a realtime web admin.
//!
//! Everything runs on a single Tokio runtime: each proxy has its own accept
//! loop, the Axum web admin serves the HTTP API and the websocket monitoring
//! feed, and connection history is persisted in RocksDB.

mod api;
mod manager;
mod model;
mod monitor;
mod socks5;
mod storage;
mod ws;

use std::time::Duration;
use tracing_subscriber::EnvFilter;

/// Command-line configuration.
struct Args {
    /// Web admin port; the admin always binds on `0.0.0.0`.
    port: u16,
    /// RocksDB data directory.
    data_dir: String,
}

const HELP: &str = "\
sn-proxy — multi-instance SOCKS5 proxy server with a realtime web admin

USAGE:
  sn-proxy [OPTIONS]

OPTIONS:
  -p, --port <PORT>      Web admin port, bound on 0.0.0.0 (default: 8080)
  -d, --data-dir <DIR>   RocksDB data directory (default: data)
  -h, --help             Print this help and exit";

/// Parse `-p/--port` and `-d/--data-dir` from the process arguments.
fn parse_args() -> Args {
    let mut port: u16 = 8080;
    let mut data_dir = String::from("data");
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-p" | "--port" => {
                let raw = it.next().unwrap_or_else(|| {
                    eprintln!("error: {arg} requires a value");
                    std::process::exit(2);
                });
                port = raw.parse().unwrap_or_else(|_| {
                    eprintln!("error: invalid port: {raw:?}");
                    std::process::exit(2);
                });
            }
            "-d" | "--data-dir" => {
                data_dir = it.next().unwrap_or_else(|| {
                    eprintln!("error: {arg} requires a value");
                    std::process::exit(2);
                });
            }
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
    Args { port, data_dir }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("sn_proxy=info")),
        )
        .init();

    let args = parse_args();

    // Persistence + proxy registry (auto-starts proxies that were enabled).
    let storage = storage::Storage::open(&args.data_dir)?;
    let manager = manager::Manager::bootstrap(storage).await?;

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

    // Web admin (HTTP API + websocket) — always bound on 0.0.0.0.
    let admin_addr = format!("0.0.0.0:{}", args.port);
    let listener = tokio::net::TcpListener::bind(&admin_addr).await?;
    tracing::info!("web admin available at http://{admin_addr}");
    axum::serve(listener, api::router(manager)).await?;
    Ok(())
}
