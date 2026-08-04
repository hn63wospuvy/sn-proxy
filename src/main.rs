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
mod resources;
mod shadowsocks;
mod socks5;
mod stop;
mod storage;
mod stun;
mod tcp;
mod tls;
mod turn;
mod turn_alloc;
mod turn_auth;
mod turn_relay;
mod turn_rrl;
mod udp;
mod udp_socks;
mod ws;
mod ws_proxy;

use anyhow::{Context, Result, anyhow};
use manager::{Admin, AdminAuth};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::writer::MakeWriterExt;

/// Env var marking the detached child of a daemonize re-spawn. The parent sets
/// it; the child sees it and runs the server instead of re-spawning again.
const DAEMON_MARKER: &str = "SN_PROXY_DAEMONIZED";

const HELP: &str = "\
sn-proxy — multi-instance, multi-protocol proxy server with a web admin

USAGE:
  sn-proxy [OPTIONS]          Start the server (daemon by default)
  sn-proxy stop [OPTIONS]     Kill every running sn-proxy background process

OPTIONS:
  -c, --config <FILE>          Properties config file (key=value)
  -p, --port <[HOST:]PORT>     Web admin address; a bare port binds 0.0.0.0
  -d, --data-dir <DIR>         RocksDB data directory
  -m, --mode <daemon|foreground>  Run backgrounded (default) or attached
  -h, --help                   Print this help and exit

CONFIG FILE KEYS (all optional):
  port             Web admin port or HOST:PORT
  data_dir         RocksDB data directory
  tls_cert         PEM certificate for the HTTPS proxy protocol
  tls_key          PEM private key for the HTTPS proxy protocol
  admin_user       Web admin login username (enables login when set)
  admin_password   Web admin login password (plaintext or an $argon2 hash)
  admin_network    Restrict that admin's login to a CIDR, e.g. 192.168.1.0/24
  admin.<NAME>.password   Extra admin account (multi-admin form)
  admin.<NAME>.network    That admin's allowed CIDR (optional)
  admin_https      true if the admin is served over HTTPS (marks the session
                   cookie Secure); default false
  mode             daemon (background, default) or foreground
  log_file         Daily-rotated log file (dir or path); off when unset

Command-line -p / -d / -m override the config file.
Defaults: 0.0.0.0:8080, data/, mode daemon.

`stop` reads -d/--data-dir (or the config's data_dir) only to clean up the
pidfile; it terminates processes by matching the executable name, so it works
even when the pidfile is stale or missing.";

/// Which subcommand to run: start the server (default) or stop running ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    Run,
    Stop,
}

/// How the process runs: backgrounded (default) or attached to the console.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunMode {
    Daemon,
    Foreground,
}

impl RunMode {
    /// Parse a `mode` value (case-insensitive, trimmed). Accepts `daemon` or
    /// `foreground`.
    fn parse(raw: &str) -> Result<RunMode, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "daemon" => Ok(RunMode::Daemon),
            "foreground" => Ok(RunMode::Foreground),
            other => Err(format!(
                "invalid mode {other:?} (expected 'daemon' or 'foreground')"
            )),
        }
    }
}

/// Fully resolved runtime configuration.
struct AppConfig {
    listen: String,
    data_dir: String,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    admins: Vec<Admin>,
    /// Whether the web admin is served over HTTPS (e.g. behind a TLS-terminating
    /// reverse proxy). When true the session cookie is marked `Secure`.
    admin_https: bool,
    /// Daemon (background) or foreground. Defaults to daemon.
    mode: RunMode,
    /// `log_file` config value (trimmed, non-empty) — daily-rotated file
    /// logging is off when `None`.
    log_file: Option<String>,
}

/// Number of admins whose stored password is plaintext (not an argon2 hash).
/// Pure helper so the startup warning can be unit tested without `tracing`.
fn plaintext_admin_count(admins: &[Admin]) -> usize {
    admins
        .iter()
        .filter(|a| !a.password.starts_with("$argon2"))
        .count()
}

/// Resolve a `log_file` config value into a `(directory, filename_prefix)` pair
/// for the daily rolling appender. Returns `None` when the value is empty or
/// whitespace-only (logging stays off).
///
/// The rule is filesystem-state-independent:
/// - a value ending in a path separator (`/` or `\`) is the directory, with the
///   default prefix `sn-proxy`;
/// - otherwise the last path component is the filename prefix and the rest is
///   the directory (`.` when there is no separator).
fn resolve_log_target(raw: &str) -> Option<(String, String)> {
    let value = raw.trim();
    if value.is_empty() {
        return None;
    }
    // Trailing separator => the whole value is a directory, default prefix.
    if value.ends_with('/') || value.ends_with('\\') {
        let dir = value.trim_end_matches(['/', '\\']);
        let dir = if dir.is_empty() { "." } else { dir };
        return Some((dir.to_string(), "sn-proxy".to_string()));
    }
    // Otherwise split on the last separator: last component is the filename
    // prefix, the rest is the directory ("." when there is no separator).
    match value.rfind(['/', '\\']) {
        Some(i) => {
            let dir = &value[..i];
            let dir = if dir.is_empty() { "." } else { dir };
            Some((dir.to_string(), value[i + 1..].to_string()))
        }
        None => Some((".".to_string(), value.to_string())),
    }
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

/// Parse a boolean config value. Accepts `true`/`1`/`yes`/`on` (case-insensitive,
/// trimmed) as true; everything else is false.
fn parse_bool(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "yes" | "on"
    )
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

/// Resolve config from defaults, then the config file, then CLI flags. Also
/// returns the requested subcommand (`stop` as a bare argument, else `Run`).
fn resolve_config() -> Result<(Command, AppConfig)> {
    let mut command = Command::Run;
    let mut config_path: Option<String> = None;
    let mut cli_port: Option<String> = None;
    let mut cli_data_dir: Option<String> = None;
    let mut cli_mode: Option<String> = None;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-c" | "--config" => config_path = Some(require_value(&arg, it.next())),
            "-p" | "--port" => cli_port = Some(require_value(&arg, it.next())),
            "-d" | "--data-dir" => cli_data_dir = Some(require_value(&arg, it.next())),
            "-m" | "--mode" => cli_mode = Some(require_value(&arg, it.next())),
            "-h" | "--help" => {
                println!("{HELP}");
                std::process::exit(0);
            }
            "stop" => command = Command::Stop,
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
    let mut admin_https = false;
    let mut mode = RunMode::Daemon;
    let mut log_file = None;

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
        admin_https = props.get("admin_https").is_some_and(|v| parse_bool(v));
        if let Some(m) = props.get("mode") {
            mode = RunMode::parse(m).unwrap_or_else(|e| {
                eprintln!("error: config mode: {e}");
                std::process::exit(2);
            });
        }
        // Empty / whitespace-only value keeps logging off.
        log_file = props
            .get("log_file")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
    }

    // Command-line overrides.
    if let Some(p) = &cli_port {
        listen = parse_listen("--port", p);
    }
    if let Some(d) = cli_data_dir {
        data_dir = d;
    }
    if let Some(m) = &cli_mode {
        mode = RunMode::parse(m).unwrap_or_else(|e| {
            eprintln!("error: --mode: {e}");
            std::process::exit(2);
        });
    }

    Ok((
        command,
        AppConfig {
            listen,
            data_dir,
            tls_cert,
            tls_key,
            admins,
            admin_https,
            mode,
            log_file,
        },
    ))
}

/// Re-spawn the process detached from the console and exit the parent.
///
/// The child is launched with the same arguments plus the `SN_PROXY_DAEMONIZED`
/// marker so it runs the server instead of re-spawning. The parent runs a cheap
/// pre-flight bind (so the common "port in use" failure is reported before
/// anything goes to the background), writes a pid file, prints the pid, and
/// exits. It never initializes `tracing`, so there is exactly one subscriber
/// `.init()` per process — only the child's.
fn daemonize(config: &AppConfig) -> ! {
    use std::process::{Command, Stdio};

    // Pre-flight: bind the listener so port-in-use is caught on the parent's
    // stderr. A never-accepted, fully-closed listener leaves no TIME_WAIT, so
    // dropping it frees the port immediately for the child to rebind.
    match std::net::TcpListener::bind(&config.listen) {
        Ok(listener) => drop(listener),
        Err(e) => {
            eprintln!("error: cannot bind {}: {e}", config.listen);
            std::process::exit(2);
        }
    }

    if config.log_file.is_none() {
        eprintln!("warning: daemon mode: no log_file set — logs will be discarded");
    }

    let exe = std::env::current_exe().unwrap_or_else(|e| {
        eprintln!("error: cannot determine current executable: {e}");
        std::process::exit(2);
    });

    let mut cmd = Command::new(exe);
    cmd.args(std::env::args_os().skip(1))
        .env(DAEMON_MARKER, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS (0x8) gives the child no console; it is mutually
        // exclusive with CREATE_NO_WINDOW, which is intentionally not used.
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // pre_exec runs post-fork/pre-exec where only async-signal-safe calls
        // are allowed; setsid() qualifies and the closure does nothing else.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    let child = cmd.spawn().unwrap_or_else(|e| {
        eprintln!("error: failed to spawn background process: {e}");
        std::process::exit(2);
    });
    let pid = child.id();

    // Pid file is best-effort: warn but keep going if the directory or write
    // fails (create_dir_all is idempotent; the child also creates data_dir).
    let pidfile = std::path::Path::new(&config.data_dir).join("sn-proxy.pid");
    if let Err(e) = std::fs::create_dir_all(&config.data_dir) {
        eprintln!("warning: could not create data dir {:?} for pid file: {e}", config.data_dir);
    } else if let Err(e) = std::fs::write(&pidfile, pid.to_string()) {
        eprintln!("warning: could not write pid file {}: {e}", pidfile.display());
    }

    println!(
        "started in background, pid {pid} (pidfile: {})",
        pidfile.display()
    );
    std::process::exit(0);
}

/// Initialize the global tracing subscriber. When `log_file` is configured the
/// output goes to a daily-rotated file (tee to stdout as well when
/// `foreground`); otherwise it goes to stdout. The returned `WorkerGuard` (when
/// logging to a file) must be kept alive for the lifetime of the process.
///
/// Never called on the daemon parent path — that process exits without a
/// subscriber, so each process calls `.init()` exactly once.
fn init_logging(config: &AppConfig, foreground: bool) -> Result<Option<WorkerGuard>> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("sn_proxy=info"));

    match config.log_file.as_deref().and_then(resolve_log_target) {
        Some((dir, prefix)) => {
            // tracing-appender does not create the directory and would panic if
            // it is missing; create it first and surface failure as a clean
            // startup error.
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("creating log directory {dir:?}"))?;
            let appender = tracing_appender::rolling::daily(&dir, &prefix);
            let (file_writer, guard) = tracing_appender::non_blocking(appender);
            if foreground {
                tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .with_writer(file_writer.and(std::io::stdout))
                    .init();
            } else {
                tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .with_writer(file_writer)
                    .init();
            }
            Ok(Some(guard))
        }
        None => {
            tracing_subscriber::fmt().with_env_filter(filter).init();
            Ok(None)
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let (command, config) = resolve_config()?;

    // `stop` kills running daemons by process name and exits — handled before
    // any daemonize / RocksDB / bind work, none of which it needs.
    if command == Command::Stop {
        stop::run(&config.data_dir);
    }

    // Daemonize before opening RocksDB or binding the port. The child carries
    // the marker and skips this branch; the parent re-spawns and exits.
    let attached = std::env::var_os(DAEMON_MARKER).is_none();
    if config.mode == RunMode::Daemon && attached {
        daemonize(&config);
    }

    // Child (file-only) or foreground (tee to stdout). `attached` is true only
    // for a foreground run here, since the daemon parent already exited above.
    let _log_guard = init_logging(&config, attached)?;

    tracing::info!("Using data dir: {}", &config.data_dir);
    // Install the process-wide rustls crypto provider before any TLS config
    // is built.
    tls::install_provider();
    // Persistence, TLS for HTTPS proxies, and the web-admin login.
    let storage = storage::Storage::open(&config.data_dir)?;
    let tls = tls::acceptor(config.tls_cert.as_deref(), config.tls_key.as_deref())?;
    let default_connector = tls::plain_connector();
    let admin_count = config.admins.len();
    let plaintext = plaintext_admin_count(&config.admins);
    let admin_https = config.admin_https;
    let admin = AdminAuth::new(config.admins, admin_https);
    if admin.required() {
        tracing::info!("web admin login is ENABLED ({admin_count} admin account(s))");
        if plaintext > 0 {
            tracing::warn!(
                "{plaintext} admin password(s) are stored in plaintext — prefer $argon2 hashes"
            );
        }
        if !admin_https {
            tracing::warn!(
                "web admin auth is enabled but admin_https is not set — the session cookie is \
                 sent in cleartext over HTTP; serve the admin behind HTTPS and set \
                 admin_https=true so the cookie is marked Secure"
            );
        }
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

    // Host resource sampler for the realtime monitor. Demand-driven: collect_tick
    // only reads /proc while at least one viewer is subscribed; otherwise it is a
    // no-op and resets the sampler baseline on the falling edge to zero viewers.
    {
        let manager = manager.clone();
        tokio::spawn(async move {
            let mut sampler = resources::new_sampler();
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            // Skip (don't burst) missed ticks: after a runtime stall, bursting
            // would divide accumulated byte deltas by the assumed 1 s dt and
            // produce bogus rate spikes.
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut active = false;
            loop {
                tick.tick().await;
                resources::collect_tick(&mut *sampler, &manager.resource_events, &mut active);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_mode_parse_accepts_daemon_and_foreground() {
        assert_eq!(RunMode::parse("daemon"), Ok(RunMode::Daemon));
        assert_eq!(RunMode::parse("foreground"), Ok(RunMode::Foreground));
        // case-insensitive + trimmed
        assert_eq!(RunMode::parse("DAEMON"), Ok(RunMode::Daemon));
        assert_eq!(RunMode::parse("  Foreground  "), Ok(RunMode::Foreground));
        assert!(RunMode::parse("bogus").is_err());
        assert!(RunMode::parse("").is_err());
    }

    #[test]
    fn plaintext_admin_count_counts_non_argon2() {
        let admin = |pw: &str| Admin {
            username: "u".into(),
            password: pw.into(),
            network: None,
        };
        let admins = vec![
            admin("plain"),
            admin("$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaA"),
            admin("alsoplain"),
        ];
        assert_eq!(plaintext_admin_count(&admins), 2);
        assert_eq!(plaintext_admin_count(&[]), 0);
        assert_eq!(plaintext_admin_count(&[admin("$argon2id$x")]), 0);
    }

    #[test]
    fn resolve_log_target_directory_form() {
        // trailing separator => directory, default prefix
        assert_eq!(
            resolve_log_target("logs/"),
            Some(("logs".into(), "sn-proxy".into()))
        );
        assert_eq!(
            resolve_log_target("logs\\"),
            Some(("logs".into(), "sn-proxy".into()))
        );
    }

    #[test]
    fn resolve_log_target_file_form() {
        assert_eq!(
            resolve_log_target("logs/proxy.log"),
            Some(("logs".into(), "proxy.log".into()))
        );
        // Windows backslash path
        assert_eq!(
            resolve_log_target("C:\\logs\\proxy.log"),
            Some(("C:\\logs".into(), "proxy.log".into()))
        );
        // bare name => current dir
        assert_eq!(
            resolve_log_target("app.log"),
            Some((".".into(), "app.log".into()))
        );
    }

    #[test]
    fn resolve_log_target_empty_is_off() {
        assert_eq!(resolve_log_target(""), None);
        assert_eq!(resolve_log_target("   "), None);
        assert_eq!(resolve_log_target("\t"), None);
    }
}
