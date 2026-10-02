//! SMTP egress relay (`protocol = "smtp"`).
//!
//! Accepts an SMTP session from a trusted client MTA (a mail server that has
//! already queued the message), resolves the MX records of each recipient
//! domain, opens a connection to the real MX **from this host's public IP**
//! and relays the envelope synchronously. The relay keeps no queue of its own:
//! upstream replies — including rejects — are passed back to the client
//! verbatim, so the client MTA's own retry/bounce machinery keeps working.
//! This is what makes it "thin": everything an MTA needs to say (EHLO, MAIL
//! FROM, RCPT TO, DATA) is forwarded; everything an MTA must keep (queue,
//! retry schedule, DSN generation) stays on the client.
//!
//! Per connection, upstreams are pooled by recipient domain: an SMTP session
//! may carry recipients on several domains, and each gets its own upstream
//! connection sharing the session's MAIL FROM. DATA is buffered (bounded by
//! `smtp.max_message_bytes`) and replayed once per upstream that accepted at
//! least one recipient.
//!
//! Upstream TLS is opportunistic STARTTLS with real certificate verification
//! (Mozilla roots via `webpki-roots`); `require_starttls` turns a missing
//! offer into a 4xx instead of a cleartext delivery. Client-side STARTTLS is
//! offered when the proxy has a PKCS#12 server keystore (`server_p12`), and
//! client-side AUTH (PLAIN/LOGIN) is required whenever `auth` is configured.

use crate::manager::{ConnEntry, Manager, ProxyRuntime, verify_password};
use crate::model::{BasicAuth, SmtpConfig};
use crate::relay::{self, Counting};
use anyhow::{Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_util::sync::CancellationToken;

/// Longest accepted command line, terminator included (RFC 5321 limits paths
/// to ~512 bytes; the headroom tolerates SMTPUTF8 / long ESMTP parameters).
const LINE_MAX: usize = 8192;
/// Time allowed for an upstream greeting or command reply.
const UPSTREAM_REPLY_TIMEOUT: Duration = Duration::from_secs(90);
/// Time allowed for the upstream's final reply after DATA content.
const DATA_REPLY_TIMEOUT: Duration = Duration::from_secs(180);
/// Time allowed reading the client's DATA body.
const DATA_READ_TIMEOUT: Duration = Duration::from_secs(300);
/// Fallback idle timeout for client commands when `idle_timeout_secs` is unset.
const CLIENT_IDLE_DEFAULT: Duration = Duration::from_secs(300);
/// How many (MX host, IP) dials to attempt per domain before giving up.
const DIAL_ATTEMPT_CAP: usize = 4;

// ============================ DNS ============================

/// DNS lookups the relay needs, abstracted so tests can inject answers without
/// standing up a real resolver.
trait Resolve: Send + Sync {
    /// MX hostnames for `domain`, lowest preference first. Empty = fall back
    /// to the implicit MX (the domain itself).
    fn mx<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>>> + Send + 'a>>;
    /// A/AAAA addresses of `host`.
    fn ips<'a>(
        &'a self,
        host: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>>> + Send + 'a>>;
}

/// Real resolver backed by the system DNS configuration (`/etc/resolv.conf`).
struct HickoryResolve;

impl Resolve for HickoryResolve {
    fn mx<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>>> + Send + 'a>> {
        Box::pin(async move {
            let resolver = hickory_resolver()?;
            let lookup = resolver.mx_lookup(domain).await;
            match lookup {
                Ok(mx) => {
                    let mut hosts: Vec<(u16, String)> = mx
                        .iter()
                        .map(|r| {
                            (
                                r.preference(),
                                r.exchange().to_ascii().trim_end_matches('.').to_string(),
                            )
                        })
                        .collect();
                    hosts.sort_by_key(|(pref, _)| *pref);
                    Ok(hosts.into_iter().map(|(_, h)| h).collect())
                }
                // NXDOMAIN / empty answer both mean "no MX" → implicit MX.
                Err(e) if is_no_mx(&e) => Ok(Vec::new()),
                Err(e) => Err(anyhow!("MX lookup for {domain}: {e}")),
            }
        })
    }

    fn ips<'a>(
        &'a self,
        host: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>>> + Send + 'a>> {
        Box::pin(async move {
            let resolver = hickory_resolver()?;
            // Bare IP literals short-circuit DNS — legal as an implicit MX
            // target in this relay even though RFC 5321 forbids them in records.
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Ok(vec![ip]);
            }
            let lookup = resolver
                .lookup_ip(host)
                .await
                .map_err(|e| anyhow!("A/AAAA lookup for {host}: {e}"))?;
            Ok(lookup.iter().collect())
        })
    }
}

/// The process-wide resolver — built lazily so a proxy that never sees an RCPT
/// never touches the resolver configuration.
fn hickory_resolver() -> Result<&'static DnsResolver> {
    static R: OnceLock<DnsResolver> = OnceLock::new();
    if let Some(r) = R.get() {
        return Ok(r);
    }
    let r = hickory_resolver::Resolver::builder_tokio()
        .map_err(|e| anyhow!("cannot build DNS resolver from system config: {e}"))?
        .build();
    Ok(R.get_or_init(|| r))
}

type DnsResolver = hickory_resolver::Resolver<hickory_resolver::name_server::TokioConnectionProvider>;

/// Whether a hickory lookup error means "the record does not exist" (NXDOMAIN
/// or an empty NOERROR answer) rather than a real resolver failure.
fn is_no_mx(e: &hickory_resolver::ResolveError) -> bool {
    use hickory_resolver::ResolveErrorKind;
    matches!(e.kind(), ResolveErrorKind::Proto(p) if p.is_no_records_found())
}

// ============================ streams ============================

/// Client-side connection: plain TCP or post-STARTTLS TLS.
enum ClientIo {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::server::TlsStream<TcpStream>>),
}

impl AsyncRead for ClientIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ClientIo::Plain(s) => Pin::new(s).poll_read(cx, buf),
            ClientIo::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ClientIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            ClientIo::Plain(s) => Pin::new(s).poll_write(cx, data),
            ClientIo::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, data),
        }
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ClientIo::Plain(s) => Pin::new(s).poll_flush(cx),
            ClientIo::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ClientIo::Plain(s) => Pin::new(s).poll_shutdown(cx),
            ClientIo::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Upstream (MX) connection: plain TCP, or TLS negotiated via STARTTLS.
/// Each variant wraps its stream in a BufReader for line-wise replies.
enum UpstreamIo {
    Plain(BufReader<TcpStream>),
    Tls(BufReader<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl UpstreamIo {
    async fn write_raw(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            UpstreamIo::Plain(s) => s.get_mut().write_all(data).await?,
            UpstreamIo::Tls(s) => s.get_mut().write_all(data).await?,
        }
        match self {
            UpstreamIo::Plain(s) => s.get_mut().flush().await,
            UpstreamIo::Tls(s) => s.get_mut().flush().await,
        }
    }

    async fn line(&mut self, text: &str) -> std::io::Result<()> {
        self.write_raw(format!("{text}\r\n").as_bytes()).await
    }

    /// Read one (possibly multiline `250-…` / `250 …`) SMTP reply.
    /// Returns the 3-digit code and the full reply text.
    async fn reply(&mut self, timeout: Duration) -> Result<(u16, String)> {
        let fut = async {
            let mut out = String::new();
            loop {
                let mut line = Vec::new();
                let n = match self {
                    UpstreamIo::Plain(s) => s.read_until(b'\n', &mut line).await?,
                    UpstreamIo::Tls(s) => s.read_until(b'\n', &mut line).await?,
                };
                if n == 0 {
                    bail!("upstream closed the connection mid-reply");
                }
                if line.len() > LINE_MAX {
                    bail!("upstream reply line exceeds {LINE_MAX} bytes");
                }
                let text = String::from_utf8_lossy(&line);
                out.push_str(text.trim_end());
                out.push('\n');
                let line = text.trim_end();
                if line.len() < 3 {
                    continue;
                }
                // A line "NNN …" (space) ends the reply; "NNN-…" continues it.
                if line.len() < 4 || line.as_bytes()[3] == b' ' {
                    let code: u16 = line[..3].parse().unwrap_or(0);
                    return Ok((code, out.trim_end().to_string()));
                }
            }
        };
        match tokio::time::timeout(timeout, fut).await {
            Ok(r) => r,
            Err(_) => bail!("upstream reply timed out"),
        }
    }
}

/// A live connection to one recipient domain's MX.
struct Upstream {
    /// Recipient domain this connection serves.
    domain: String,
    /// MX hostname dialed (for logging/monitoring).
    host: String,
    io: UpstreamIo,
    /// The client's `MAIL FROM` was sent and accepted upstream.
    mail_sent: bool,
    /// The upstream's non-2xx `MAIL FROM` reply, replayed to the client at
    /// RCPT time — it is the actionable error (e.g. a 550 rDNS reject) and
    /// must not be flattened into a generic 451.
    mail_error: Option<String>,
    /// Recipients this upstream has already accepted (2xx on RCPT TO).
    accepted: Vec<String>,
}

// ============================ session ============================

/// Per-connection relay state, shared across the client command loop.
struct Session {
    cfg: SmtpConfig,
    auth: Option<BasicAuth>,
    acceptor: Option<tokio_rustls::TlsAcceptor>,
    connector: TlsConnector,
    resolver: Arc<dyn Resolve>,
    /// Client command idle timeout.
    idle: Duration,
    connect_timeout: Option<u64>,
    authenticated: bool,
    /// Raw `FROM:<addr> [params]` of the active mail transaction.
    mail_from: Option<String>,
    upstreams: Vec<Upstream>,
    /// Whether the client stream is already TLS (hides STARTTLS in EHLO).
    client_tls: bool,
}

/// Full list of recipient domains that currently have an upstream, for the
/// monitor's destination column (e.g. `mx:gmail.com,example.org`).
fn upstreams_label(upstreams: &[Upstream]) -> String {
    let mut domains: Vec<&str> = upstreams.iter().map(|u| u.domain.as_str()).collect();
    domains.sort_unstable();
    format!("mx:{}", domains.join(","))
}

/// Handle one accepted connection for an `smtp` proxy.
pub async fn serve(
    manager: Arc<Manager>,
    runtime: Arc<ProxyRuntime>,
    stream: TcpStream,
    peer: SocketAddr,
    token: CancellationToken,
) -> Result<()> {
    let (cfg, auth, acceptor, idle_secs, connect_timeout) = {
        let cfg = runtime.config.lock().unwrap();
        (
            cfg.smtp.clone(),
            cfg.auth.clone(),
            runtime.https_acceptor.lock().unwrap().clone(),
            cfg.idle_timeout_secs,
            cfg.connect_timeout_secs,
        )
    };
    let idle = idle_secs
        .filter(|s| *s > 0)
        .map(Duration::from_secs)
        .unwrap_or(CLIENT_IDLE_DEFAULT);

    let mut s = Session {
        cfg,
        auth,
        acceptor,
        connector: upstream_connector(),
        resolver: Arc::new(HickoryResolve),
        idle,
        connect_timeout,
        authenticated: false,
        mail_from: None,
        upstreams: Vec::new(),
        client_tls: false,
    };
    // AUTH is mandatory when credentials are configured — the listener may be
    // on a private/tailnet address, but relaying is still an open-relay shape.
    s.authenticated = s.auth.is_none();

    relay::tracked(
        &manager.storage,
        &runtime,
        peer.to_string(),
        "smtp".to_string(),
        |entry| async move {
            let io = BufReader::new(Counting::new(ClientIo::Plain(stream), entry.clone()));
            let _ = session(io, &mut s, &entry, token).await;
        },
    )
    .await;
    Ok(())
}

/// The SMTP command loop. `io` is the client stream wrapped for monitoring;
/// STARTTLS swaps its inner stream and rebuilds the wrapper in place.
async fn session(
    mut io: BufReader<Counting<ClientIo>>,
    s: &mut Session,
    entry: &Arc<ConnEntry>,
    token: CancellationToken,
) -> Result<()> {
    let greeting = format!("220 {} ESMTP sn-proxy ready", s.cfg.helo_name);
    write_line(&mut io, &greeting).await?;

    loop {
        let line = tokio::select! {
            _ = token.cancelled() => return Ok(()),
            r = tokio::time::timeout(s.idle, read_line(&mut io)) => match r {
                Ok(Ok(Some(l))) => l,
                Ok(Ok(None)) => return Ok(()),      // clean EOF
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    write_line(&mut io, "421 4.4.2 Idle timeout — closing").await.ok();
                    return Ok(());
                }
            },
        };

        let (verb, rest) = split_command(&line);
        match verb.as_str() {
            "EHLO" | "HELO" => {
                // A fresh HELO/EHLO abandons the transaction in progress
                // (RFC 5321 §4.1.1.1): drop every upstream so no half-built
                // transaction leaks into the next envelope.
                drop_upstreams(s).await;
                s.mail_from = None;
                let caps = ehlo_reply(s);
                for l in caps {
                    write_line(&mut io, &l).await?;
                }
            }
            "STARTTLS" => {
                if s.client_tls {
                    write_line(&mut io, "454 4.7.0 TLS already active").await?;
                } else if s.acceptor.is_none() {
                    write_line(&mut io, "502 5.5.1 STARTTLS not offered").await?;
                } else if !io.buffer().is_empty() {
                    // Bytes already buffered past the command would be dropped
                    // by into_inner(); refuse rather than desync the stream.
                    write_line(&mut io, "454 4.7.0 Pipelined input after STARTTLS").await?;
                } else {
                    write_line(&mut io, "220 2.0.0 Ready to start TLS").await?;
                    io = upgrade_client_tls(io, s).await?;
                    s.client_tls = true;
                }
            }
            "AUTH" => {
                handle_auth(&mut io, s, &rest).await?;
            }
            "MAIL" => {
                if !s.authenticated {
                    write_line(&mut io, "530 5.7.0 Authentication required").await?;
                    continue;
                }
                match parse_mail_from(&rest) {
                    Some(from) => {
                        s.mail_from = Some(from);
                        // A new MAIL FROM starts a new transaction: recipients
                        // and upstream state reset (RFC 5321 §4.1.1.5 — an
                        // implicit RSET on the upstreams happens lazily at the
                        // next use because we re-issue MAIL FROM there).
                        for u in &mut s.upstreams {
                            u.mail_sent = false;
                            u.mail_error = None;
                            u.accepted.clear();
                        }
                        write_line(&mut io, "250 2.1.0 Ok").await?;
                    }
                    None => {
                        write_line(&mut io, "501 5.5.4 Syntax: MAIL FROM:<address>").await?;
                    }
                }
            }
            "RCPT" => {
                if !s.authenticated {
                    write_line(&mut io, "530 5.7.0 Authentication required").await?;
                    continue;
                }
                if s.mail_from.is_none() {
                    write_line(&mut io, "503 5.5.1 Need MAIL FROM first").await?;
                    continue;
                }
                let Some(addr) = parse_path(&rest, "TO") else {
                    write_line(&mut io, "501 5.5.4 Syntax: RCPT TO:<address>").await?;
                    continue;
                };
                let Some(domain) = addr.rsplit('@').next().filter(|d| !d.is_empty() && addr.contains('@')) else {
                    write_line(&mut io, "501 5.1.3 Bad recipient address").await?;
                    continue;
                };
                let domain = domain.to_ascii_lowercase();
                match upstream_reply_for_rcpt(s, &domain, &addr).await {
                    Ok(reply) => {
                        write_line(&mut io, &reply).await?;
                    }
                    Err(e) => {
                        write_line(&mut io, &format!("451 4.3.0 Cannot reach {domain}: {e}"))
                            .await?;
                    }
                }
                // Publish the resolved destinations once known.
                if !s.upstreams.is_empty() {
                    *entry.dst_addr.lock().unwrap() = upstreams_label(&s.upstreams);
                }
            }
            "DATA" => {
                let n: usize = s.upstreams.iter().map(|u| u.accepted.len()).sum();
                if s.mail_from.is_none() || n == 0 {
                    write_line(&mut io, "503 5.5.1 Need MAIL FROM and a recipient first").await?;
                    continue;
                }
                write_line(&mut io, "354 End data with <CR><LF>.<CR><LF>").await?;
                match read_data(&mut io, s.cfg.effective_max_message()).await {
                    Ok(body) => {
                        let reply = fanout_data(s, &body).await;
                        write_line(&mut io, &reply).await?;
                        // The transaction is complete regardless of outcome —
                        // clear it; a follow-up message starts with MAIL FROM.
                        s.mail_from = None;
                        for u in &mut s.upstreams {
                            u.mail_sent = false;
                            u.mail_error = None;
                            u.accepted.clear();
                        }
                    }
                    Err(e) => {
                        write_line(&mut io, &format!("552 5.3.4 {e}")).await?;
                    }
                }
            }
            "RSET" => {
                s.mail_from = None;
                for u in &mut s.upstreams {
                    u.mail_sent = false;
                    u.mail_error = None;
                    u.accepted.clear();
                    let _ = u.io.line("RSET").await;
                    let _ = u.io.reply(UPSTREAM_REPLY_TIMEOUT).await;
                }
                write_line(&mut io, "250 2.0.0 Ok").await?;
            }
            "NOOP" => write_line(&mut io, "250 2.0.0 Ok").await?,
            "HELP" => write_line(&mut io, "214 2.0.0 sn-proxy smtp relay").await?,
            "VRFY" | "EXPN" => {
                write_line(&mut io, "252 2.5.2 Cannot VRFY user; send some mail and see").await?
            }
            "QUIT" => {
                write_line(&mut io, "221 2.0.0 Bye").await?;
                drop_upstreams(s).await;
                return Ok(());
            }
            _ => {
                write_line(&mut io, "502 5.5.1 Command unrecognized").await?;
            }
        }
    }
}

/// The EHLO capability block for the current session state.
fn ehlo_reply(s: &Session) -> Vec<String> {
    let mut lines = vec![
        format!("250-{}", s.cfg.helo_name),
        "250-8BITMIME".to_string(),
    ];
    if !s.client_tls && s.acceptor.is_some() {
        lines.push("250-STARTTLS".to_string());
    }
    if s.auth.is_some() {
        lines.push("250-AUTH LOGIN PLAIN".to_string());
    }
    lines.push(format!("250 SIZE {}", s.cfg.effective_max_message()));
    lines
}

/// `AUTH PLAIN [b64]` and `AUTH LOGIN` — both end in a user/password check
/// against the proxy's configured `auth`.
async fn handle_auth(
    io: &mut BufReader<Counting<ClientIo>>,
    s: &mut Session,
    rest: &str,
) -> Result<()> {
    if s.auth.is_none() {
        write_line(io, "502 5.5.1 AUTH not offered").await?;
        return Ok(());
    }
    if s.authenticated {
        write_line(io, "503 5.5.1 Already authenticated").await?;
        return Ok(());
    }
    let mut parts = rest.split_whitespace();
    let mech = parts.next().unwrap_or("").to_ascii_uppercase();
    let cred = match mech.as_str() {
        "PLAIN" => {
            let b64 = match parts.next() {
                Some(t) => t.to_string(),
                None => {
                    write_line(io, "334 ").await?;
                    match read_line(io).await? {
                        Some(l) => l.trim().to_string(),
                        None => bail!("client closed during AUTH PLAIN"),
                    }
                }
            };
            decode_plain(&b64)
        }
        "LOGIN" => {
            write_line(io, "334 VXNlcm5hbWU6").await?;
            let user = match read_line(io).await? {
                Some(l) => BASE64
                    .decode(l.trim())
                    .ok()
                    .map(|b| String::from_utf8_lossy(&b).to_string()),
                None => bail!("client closed during AUTH LOGIN"),
            };
            write_line(io, "334 UGFzc3dvcmQ6").await?;
            let pass = match read_line(io).await? {
                Some(l) => BASE64
                    .decode(l.trim())
                    .ok()
                    .map(|b| String::from_utf8_lossy(&b).to_string()),
                None => bail!("client closed during AUTH LOGIN"),
            };
            user.zip(pass)
        }
        _ => {
            write_line(io, "504 5.5.4 Unrecognized authentication type").await?;
            return Ok(());
        }
    };
    let Some((user, pass)) = cred else {
        write_line(io, "501 5.5.4 Malformed AUTH input").await?;
        return Ok(());
    };
    let ok = s
        .auth
        .as_ref()
        .is_some_and(|a| a.username == user && verify_password(&a.password, &pass));
    if ok {
        s.authenticated = true;
        write_line(io, "235 2.7.0 Authentication successful").await?;
    } else {
        write_line(io, "535 5.7.8 Authentication credentials invalid").await?;
    }
    Ok(())
}

/// Decode an `AUTH PLAIN` payload: `authzid \0 authcid \0 passwd`.
fn decode_plain(b64: &str) -> Option<(String, String)> {
    let raw = BASE64.decode(b64.trim()).ok()?;
    let mut it = raw.split(|b| *b == 0);
    let _authzid = it.next()?;
    let user = it.next()?;
    let pass = it.next()?;
    Some((
        String::from_utf8_lossy(user).to_string(),
        String::from_utf8_lossy(pass).to_string(),
    ))
}

// ============================ upstream plumbing ============================

/// Ensure `domain` has a live upstream (dial + EHLO + STARTTLS + MAIL FROM if
/// needed), relay `RCPT TO:<addr>` to it and return the reply line for the
/// client.
async fn upstream_reply_for_rcpt(s: &mut Session, domain: &str, addr: &str) -> Result<String> {
    if !s.upstreams.iter().any(|u| u.domain == domain) {
        let mut up = dial_domain(s, domain).await?;
        up.domain = domain.to_string();
        s.upstreams.push(up);
    }
    let idx = s.upstreams.iter().position(|u| u.domain == domain).unwrap();
    // An I/O failure drops the pooled connection so the next RCPT re-dials
    // instead of writing to a corpse.
    let mail_from = s.mail_from.clone().unwrap_or_default();
    let result = rcpt_on_upstream(&mut s.upstreams[idx], &mail_from, addr).await;
    if result.is_err() {
        s.upstreams.remove(idx);
    }
    result
}

/// `MAIL FROM` (when the upstream has not applied it yet) then `RCPT TO` on
/// one upstream connection.
async fn rcpt_on_upstream(up: &mut Upstream, mail_from: &str, addr: &str) -> Result<String> {
    if let Some(err) = &up.mail_error {
        return Ok(err.clone());
    }
    if !up.mail_sent {
        up.io.line(&format!("MAIL FROM{mail_from}")).await?;
        let (code, text) = up.io.reply(UPSTREAM_REPLY_TIMEOUT).await?;
        if !(200..300).contains(&code) {
            // The upstream's reject IS the actionable reply (e.g. a 550 rDNS
            // failure) — replay it to the client for every RCPT on this domain
            // rather than flattening it into a generic error.
            up.mail_error = Some(last_line(&text));
            return Ok(last_line(&text));
        }
        up.mail_sent = true;
    }
    up.io.line(&format!("RCPT TO:<{addr}>")).await?;
    let (code, text) = up.io.reply(UPSTREAM_REPLY_TIMEOUT).await?;
    if (200..300).contains(&code) {
        up.accepted.push(addr.to_string());
    }
    Ok(last_line(&text))
}

/// Resolve `domain` to candidate MX hosts, dial them in order, perform the
/// upstream greeting/EHLO/(STARTTLS) handshake and return the session.
async fn dial_domain(s: &Session, domain: &str) -> Result<Upstream> {
    let mut hosts = s.resolver.mx(domain).await?;
    if hosts.is_empty() {
        hosts.push(domain.to_string()); // implicit MX (RFC 5321 §5.1)
    }
    let port = s.cfg.effective_upstream_port();
    let mut errors = Vec::new();
    let mut attempts = 0usize;
    'hosts: for host in &hosts {
        let ips = match s.resolver.ips(host).await {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!("{host}: {e}"));
                continue;
            }
        };
        for ip in ips {
            if attempts >= DIAL_ATTEMPT_CAP {
                break 'hosts;
            }
            if !s.cfg.allow_private && Manager::is_internal_dest(ip) {
                errors.push(format!("{host} ({ip}): internal address refused"));
                continue;
            }
            attempts += 1;
            let addr = SocketAddr::new(ip, port);
            match dial_host(s, addr, host).await {
                Ok(u) => return Ok(u),
                Err(e) => errors.push(format!("{host} ({ip}): {e}")),
            }
        }
    }
    Err(anyhow!(
        "no MX reachable for {domain}: {}",
        errors.join("; ")
    ))
}

/// One dial attempt: TCP connect, greeting, EHLO, opportunistic STARTTLS.
async fn dial_host(s: &Session, addr: SocketAddr, host: &str) -> Result<Upstream> {
    let timeout = s
        .connect_timeout
        .filter(|t| *t > 0)
        .unwrap_or(30);
    let tcp = tokio::time::timeout(Duration::from_secs(timeout), TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow!("connect timed out"))?
        .map_err(|e| anyhow!("connect: {e}"))?;
    relay::apply_keepalive(&tcp, Some(30));

    let mut io = UpstreamIo::Plain(BufReader::new(tcp));
    let (code, text) = io.reply(UPSTREAM_REPLY_TIMEOUT).await?;
    if code != 220 {
        bail!("greeting {code} {}", last_line(&text));
    }

    let caps = ehlo_upstream(&mut io, &s.cfg.helo_name).await?;
    if caps.iter().any(|c| c.eq_ignore_ascii_case("starttls")) {
        io.line("STARTTLS").await?;
        let (code, text) = io.reply(UPSTREAM_REPLY_TIMEOUT).await?;
        if code != 220 {
            bail!("STARTTLS refused: {code} {}", last_line(&text));
        }
        io = starttls_upstream(io, host, &s.connector).await?;
        let _ = ehlo_upstream(&mut io, &s.cfg.helo_name).await?;
    } else if s.cfg.require_starttls {
        bail!("upstream offers no STARTTLS and require_starttls is on");
    }

    Ok(Upstream {
        domain: String::new(), // filled by the caller, which knows the domain
        host: format!("{host} ({addr})"),
        io,
        mail_sent: false,
        mail_error: None,
        accepted: Vec::new(),
    })
}

/// EHLO to the upstream; on a 5xx fall back to HELO (barebones MTAs).
/// Returns the offered extension keywords (uppercased comparisons elsewhere).
async fn ehlo_upstream(io: &mut UpstreamIo, helo: &str) -> Result<Vec<String>> {
    io.line(&format!("EHLO {helo}")).await?;
    let (code, text) = io.reply(UPSTREAM_REPLY_TIMEOUT).await?;
    if (200..300).contains(&code) {
        // Each "250-<KEYWORD> [params]" line after the banner is an extension.
        return Ok(text
            .lines()
            .filter_map(|l| l.get(4..))
            .skip(1)
            .filter_map(|rest| rest.split_whitespace().next().map(str::to_string))
            .collect());
    }
    io.line(&format!("HELO {helo}")).await?;
    let (code, text) = io.reply(UPSTREAM_REPLY_TIMEOUT).await?;
    if !(200..300).contains(&code) {
        bail!("EHLO/HELO rejected: {code} {}", last_line(&text));
    }
    Ok(Vec::new())
}

/// Upgrade an upstream connection to TLS after a 220 to STARTTLS.
async fn starttls_upstream(
    io: UpstreamIo,
    host: &str,
    connector: &TlsConnector,
) -> Result<UpstreamIo> {
    let UpstreamIo::Plain(rdr) = io else {
        bail!("upstream already TLS");
    };
    if !rdr.buffer().is_empty() {
        // Buffered bytes past the 220 would be lost in the upgrade — treat as
        // a desync rather than relaying a corrupted stream.
        bail!("upstream pipelined bytes after STARTTLS 220");
    }
    let tcp = rdr.into_inner();
    let name = ServerName::try_from(host.to_string())
        .map_err(|e| anyhow!("invalid TLS server name {host:?}: {e}"))?;
    let tls = tokio::time::timeout(UPSTREAM_REPLY_TIMEOUT, connector.connect(name, tcp))
        .await
        .map_err(|_| anyhow!("TLS handshake timed out"))?
        .map_err(|e| anyhow!("TLS handshake failed: {e}"))?;
    Ok(UpstreamIo::Tls(BufReader::new(tls)))
}

/// A client connector that verifies upstream MX certificates against the
/// embedded Mozilla root store. Real verification — not the accept-anything
/// connector the HTTP forwarder uses — because deliverability is the whole
/// point of this relay.
fn upstream_connector() -> TlsConnector {
    static C: OnceLock<TlsConnector> = OnceLock::new();
    C.get_or_init(|| {
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let cfg = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        TlsConnector::from(Arc::new(cfg))
    })
    .clone()
}

/// Replay the buffered DATA body to every upstream that accepted a recipient,
/// then report a single reply line to the client. Success requires every
/// upstream to accept — a partial failure returns the first non-2xx reply so
/// the client MTA retries (accepting the small re-delivery risk inherent to
/// any fan-out relay).
async fn fanout_data(s: &mut Session, body: &[u8]) -> String {
    let mut first_error: Option<String> = None;
    let mut dead: Vec<usize> = Vec::new();
    for (i, up) in s.upstreams.iter_mut().enumerate().filter(|(_, u)| !u.accepted.is_empty()) {
        let result = async {
            up.io.line("DATA").await?;
            let (code, text) = up.io.reply(UPSTREAM_REPLY_TIMEOUT).await?;
            if code != 354 {
                return Ok::<(u16, String), anyhow::Error>((code, text));
            }
            up.io.write_raw(body).await?;
            up.io.reply(DATA_REPLY_TIMEOUT).await
        }
        .await;
        match result {
            Ok((code, _)) if (200..300).contains(&code) => {}
            Ok((_, text)) => {
                if first_error.is_none() {
                    first_error = Some(last_line(&text));
                }
            }
            Err(e) => {
                dead.push(i);
                if first_error.is_none() {
                    first_error = Some(format!("451 4.3.0 Relay to {} failed: {e}", up.host));
                }
            }
        }
    }
    // Drop connections that failed mid-DATA — reuse would desync both ends.
    for i in dead.into_iter().rev() {
        s.upstreams.remove(i);
    }
    first_error.unwrap_or_else(|| "250 2.0.0 Queued for delivery".to_string())
}

/// Politely close every pooled upstream (QUIT), then drop them.
async fn drop_upstreams(s: &mut Session) {
    for u in &mut s.upstreams {
        let _ = u.io.line("QUIT").await;
    }
    s.upstreams.clear();
}

// ============================ wire helpers ============================

/// Write one CRLF-terminated reply line to the client.
async fn write_line<W: AsyncRead + AsyncWrite + Unpin>(
    io: &mut BufReader<W>,
    text: &str,
) -> Result<()> {
    io.get_mut().write_all(text.as_bytes()).await?;
    io.get_mut().write_all(b"\r\n").await?;
    io.get_mut().flush().await?;
    Ok(())
}

/// Read one client command line (CR/LF-terminated, capped).
/// Returns `Ok(None)` on clean EOF.
async fn read_line<R: AsyncRead + Unpin>(io: &mut BufReader<R>) -> Result<Option<String>> {
    let mut buf = Vec::new();
    let n = io.read_until(b'\n', &mut buf).await?;
    if n == 0 {
        return Ok(if buf.is_empty() {
            None
        } else {
            Some(String::from_utf8_lossy(&buf).trim_end().to_string())
        });
    }
    if buf.len() > LINE_MAX {
        bail!("command line exceeds {LINE_MAX} bytes");
    }
    Ok(Some(String::from_utf8_lossy(&buf).trim_end().to_string()))
}

/// Read the DATA body verbatim until the `.\r\n` terminator. The returned
/// buffer INCLUDES the terminator so it can be written to upstreams as-is.
async fn read_data<R: AsyncRead + Unpin>(
    io: &mut BufReader<R>,
    cap: usize,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    let fut = async {
        loop {
            let mut line = Vec::new();
            let n = io.read_until(b'\n', &mut line).await?;
            if n == 0 {
                bail!("client closed inside DATA");
            }
            body.extend_from_slice(&line);
            if body.len() > cap {
                bail!("message exceeds the {} byte limit", cap);
            }
            if line == b".\r\n" || line == b".\n" {
                return Ok(body);
            }
        }
    };
    match tokio::time::timeout(DATA_READ_TIMEOUT, fut).await {
        Ok(r) => r,
        Err(_) => bail!("timed out reading DATA"),
    }
}

/// Split a command line into (VERB, rest-after-verb).
fn split_command(line: &str) -> (String, &str) {
    let line = line.trim_end();
    match line.find(char::is_whitespace) {
        Some(i) => (line[..i].to_ascii_uppercase(), line[i..].trim()),
        None => (line.to_ascii_uppercase(), ""),
    }
}

/// `MAIL FROM:…` → the verbatim `:<addr> [params]` tail (kept for upstream
/// forwarding so SIZE/BODY parameters survive the relay).
fn parse_mail_from(rest: &str) -> Option<String> {
    let rest = rest.trim();
    let tail = rest.strip_prefix("FROM:").or_else(|| {
        rest.get(..4)
            .filter(|p| p.eq_ignore_ascii_case("FROM"))
            .and_then(|_| rest.get(4..))
            .and_then(|t| t.strip_prefix(':'))
    });
    tail.map(|t| format!(":{}", t.trim())).filter(|t| t.len() > 1)
}

/// `RCPT TO:<addr>` (or similar `VERB:<addr>` shapes) → the bare address.
fn parse_path(rest: &str, verb: &str) -> Option<String> {
    let rest = rest.trim();
    let tail = rest.get(..verb.len())?;
    if !tail.eq_ignore_ascii_case(verb) {
        return None;
    }
    let tail = rest.get(verb.len()..)?.trim_start().strip_prefix(':')?.trim();
    let inner = if tail.starts_with('<') {
        let end = tail.find('>')?;
        &tail[1..end]
    } else {
        tail
    };
    let inner = inner.trim();
    (!inner.is_empty()).then(|| inner.to_string())
}

/// The last line of a multiline SMTP reply — the line carrying the code.
fn last_line(text: &str) -> String {
    text.lines().last().unwrap_or("").trim().to_string()
}

/// Upgrade the client connection to TLS after STARTTLS.
async fn upgrade_client_tls(
    io: BufReader<Counting<ClientIo>>,
    s: &Session,
) -> Result<BufReader<Counting<ClientIo>>> {
    let acceptor = s.acceptor.clone().expect("checked by caller");
    let counting = io.into_inner();
    let entry = counting.entry();
    let client = counting.into_inner();
    let ClientIo::Plain(tcp) = client else {
        bail!("client already TLS");
    };
    let tls = tokio::time::timeout(relay::HANDSHAKE_TIMEOUT, acceptor.accept(tcp))
        .await
        .map_err(|_| anyhow!("client TLS handshake timed out"))?
        .map_err(|e| anyhow!("client TLS handshake failed: {e}"))?;
    Ok(BufReader::new(Counting::new(
        ClientIo::Tls(Box::new(tls)),
        entry,
    )))
}

// ============================ tests ============================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicU64;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn split_command_splits_verb_and_rest() {
        let (v, r) = split_command("MAIL FROM:<a@b> SIZE=10");
        assert_eq!(v, "MAIL");
        assert_eq!(r, "FROM:<a@b> SIZE=10");
        let (v, r) = split_command("noop");
        assert_eq!(v, "NOOP");
        assert_eq!(r, "");
    }

    #[test]
    fn parse_mail_from_keeps_params() {
        assert_eq!(
            parse_mail_from("FROM:<a@b> SIZE=10").as_deref(),
            Some(":<a@b> SIZE=10")
        );
        assert_eq!(parse_mail_from("from:<a@b>").as_deref(), Some(":<a@b>"));
        assert_eq!(parse_mail_from("FROM:<>").as_deref(), Some(":<>"));
        assert!(parse_mail_from("TO:<a@b>").is_none());
        assert!(parse_mail_from("FROM:").is_none());
    }

    #[test]
    fn parse_path_extracts_bare_address() {
        assert_eq!(parse_path("TO:<a@b>", "TO").as_deref(), Some("a@b"));
        assert_eq!(parse_path("to:<a@b> NOTIFY=NEVER", "TO").as_deref(), Some("a@b"));
        assert_eq!(parse_path("TO:a@b", "TO").as_deref(), Some("a@b"));
        assert!(parse_path("FROM:<a@b>", "TO").is_none());
        assert!(parse_path("TO:<>", "TO").is_none());
    }

    #[test]
    fn decode_plain_splits_on_nul() {
        // "\0user\0pass"
        let (u, p) = decode_plain("AHUAcw==").unwrap();
        assert_eq!(u, "u");
        assert_eq!(p, "s");
        assert!(decode_plain("not base64 !!!").is_none());
        assert!(decode_plain("aHVo").is_none()); // single field, no NULs
    }

    #[test]
    fn last_line_returns_the_coded_line() {
        assert_eq!(last_line("250-one\n250-two\n250 done"), "250 done");
        assert_eq!(last_line("550 no"), "550 no");
    }

    /// DNS stub mapping domain → MX hosts → IPs, so a session test never
    /// touches a real resolver.
    struct FakeResolve {
        mx: HashMap<String, Vec<String>>,
        ips: HashMap<String, Vec<IpAddr>>,
    }

    impl Resolve for FakeResolve {
        fn mx<'a>(
            &'a self,
            domain: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<String>>> + Send + 'a>> {
            let v = self.mx.get(domain).cloned().unwrap_or_default();
            Box::pin(async move { Ok(v) })
        }
        fn ips<'a>(
            &'a self,
            host: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>>> + Send + 'a>> {
            let v = self.ips.get(host).cloned().unwrap_or_default();
            Box::pin(async move { Ok(v) })
        }
    }

    fn entry() -> Arc<ConnEntry> {
        Arc::new(ConnEntry {
            id: "c1".into(),
            src_addr: "127.0.0.1:1".into(),
            dst_addr: Mutex::new("smtp".into()),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            started_at: 0,
            cancel: CancellationToken::new(),
        })
    }

    fn session_for(mx_port: u16, auth: Option<BasicAuth>) -> Session {
        Session {
            cfg: SmtpConfig {
                helo_name: "relay.test".into(),
                upstream_port: Some(mx_port),
                require_starttls: false,
                allow_private: true,
                max_message_bytes: None,
            },
            auth,
            acceptor: None,
            connector: upstream_connector(),
            resolver: Arc::new(FakeResolve {
                mx: HashMap::from([("example.test".into(), vec!["mx.test".into()])]),
                ips: HashMap::from([("mx.test".into(), vec![IpAddr::from([127, 0, 0, 1])])]),
            }),
            idle: Duration::from_secs(10),
            connect_timeout: Some(5),
            authenticated: false,
            mail_from: None,
            upstreams: Vec::new(),
            client_tls: false,
        }
    }

    /// A one-shot fake MX: greets, answers EHLO/MAIL/RCPT/DATA/QUIT, captures
    /// the DATA body into `got`.
    async fn fake_mx(listener: TcpListener, got: Arc<Mutex<Vec<u8>>>) {
        let (mut s, _) = listener.accept().await.unwrap();
        s.write_all(b"220 mx.test ESMTP\r\n").await.unwrap();
        let (r, mut w) = s.split();
        let mut r = BufReader::new(r);
        let mut line = String::new();
        let mut in_data = false;
        loop {
            line.clear();
            if r.read_line(&mut line).await.unwrap() == 0 {
                return;
            }
            if in_data {
                got.lock().unwrap().extend_from_slice(line.as_bytes());
                if line.trim_end() == "." {
                    w.write_all(b"250 2.0.0 Queued\r\n").await.unwrap();
                    in_data = false;
                }
                continue;
            }
            let verb = line.trim_end().to_ascii_uppercase();
            let reply = if verb.starts_with("EHLO") || verb.starts_with("HELO") {
                "250-mx.test\r\n250 SIZE\r\n"
            } else if verb.starts_with("MAIL FROM") {
                "250 2.1.0 Ok\r\n"
            } else if verb.starts_with("RCPT TO") {
                "250 2.1.5 Ok\r\n"
            } else if verb == "DATA" {
                in_data = true;
                "354 End data with <CR><LF>.<CR><LF>\r\n"
            } else if verb == "RSET" {
                "250 2.0.0 Ok\r\n"
            } else if verb == "QUIT" {
                w.write_all(b"221 2.0.0 Bye\r\n").await.unwrap();
                return;
            } else {
                "502 5.5.1 huh\r\n"
            };
            w.write_all(reply.as_bytes()).await.unwrap();
        }
    }

    async fn client_pair() -> (
        BufReader<Counting<ClientIo>>,
        tokio::net::TcpStream,
        Arc<ConnEntry>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let e = entry();
        (
            BufReader::new(Counting::new(ClientIo::Plain(server), e.clone())),
            client,
            e,
        )
    }

    async fn expect<R: AsyncRead + Unpin>(client: &mut BufReader<R>, prefix: &str) -> String {
        // SMTP replies may be multiline; the last line starts "NNN ".
        let last = loop {
            let mut line = String::new();
            assert!(client.read_line(&mut line).await.unwrap() > 0);
            let done = line.len() < 4 || line.as_bytes()[3] == b' ';
            if done {
                break line;
            }
        };
        assert!(last.starts_with(prefix), "want {prefix}, got {last}");
        last
    }

    #[tokio::test]
    async fn relays_full_message_to_resolved_mx() {
        let mx_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mx_port = mx_listener.local_addr().unwrap().port();
        let got = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn(fake_mx(mx_listener, got.clone()));

        let mut s = session_for(mx_port, None);
        s.authenticated = true; // no auth configured
        let (io, client, e) = client_pair().await;
        let token = CancellationToken::new();
        let server_task = tokio::spawn(async move { session(io, &mut s, &e, token).await });

        let (r, mut w) = client.into_split();
        let mut r = BufReader::new(r);
        expect(&mut r, "220").await;
        w.write_all(b"EHLO me.test\r\n").await.unwrap();
        expect(&mut r, "250").await;
        w.write_all(b"MAIL FROM:<me@mine.test>\r\n").await.unwrap();
        expect(&mut r, "250").await;
        w.write_all(b"RCPT TO:<you@example.test>\r\n").await.unwrap();
        expect(&mut r, "250").await;
        w.write_all(b"DATA\r\n").await.unwrap();
        expect(&mut r, "354").await;
        w.write_all(b"Subject: t\r\n\r\nhello world\r\n.\r\n").await.unwrap();
        expect(&mut r, "250").await;
        w.write_all(b"QUIT\r\n").await.unwrap();
        expect(&mut r, "221").await;
        server_task.await.unwrap().unwrap();

        let body = got.lock().unwrap().clone();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("hello world"), "mx saw: {body}");
    }

    #[tokio::test]
    async fn auth_gates_mail_from() {
        let mut s = session_for(9, Some(BasicAuth { username: "u".into(), password: "p".into() }));
        let (io, client, e) = client_pair().await;
        let token = CancellationToken::new();
        let server_task = tokio::spawn(async move { session(io, &mut s, &e, token).await });

        let (r, mut w) = client.into_split();
        let mut r = BufReader::new(r);
        expect(&mut r, "220").await;
        w.write_all(b"EHLO me.test\r\n").await.unwrap();
        expect(&mut r, "250").await;
        w.write_all(b"MAIL FROM:<me@mine.test>\r\n").await.unwrap();
        expect(&mut r, "530").await;
        // Wrong password → 535, right → 235.
        w.write_all(b"AUTH PLAIN AHUAd3Jvbmc=\r\n").await.unwrap(); // \0u\0wrong
        expect(&mut r, "535").await;
        w.write_all(b"AUTH PLAIN AHUAcA==\r\n").await.unwrap(); // \0u\0p
        expect(&mut r, "235").await;
        w.write_all(b"MAIL FROM:<me@mine.test>\r\n").await.unwrap();
        expect(&mut r, "250").await;
        w.write_all(b"QUIT\r\n").await.unwrap();
        expect(&mut r, "221").await;
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn unreachable_domain_yields_4xx() {
        // No MX and no A record for the implicit-MX fallback either.
        let mut s = session_for(9, None);
        s.authenticated = true;
        let (io, client, e) = client_pair().await;
        let token = CancellationToken::new();
        let server_task = tokio::spawn(async move { session(io, &mut s, &e, token).await });

        let (r, mut w) = client.into_split();
        let mut r = BufReader::new(r);
        expect(&mut r, "220").await;
        w.write_all(b"EHLO me.test\r\n").await.unwrap();
        expect(&mut r, "250").await;
        w.write_all(b"MAIL FROM:<me@mine.test>\r\n").await.unwrap();
        expect(&mut r, "250").await;
        w.write_all(b"RCPT TO:<you@nowhere.test>\r\n").await.unwrap();
        expect(&mut r, "451").await;
        w.write_all(b"QUIT\r\n").await.unwrap();
        expect(&mut r, "221").await;
        server_task.await.unwrap().unwrap();
    }
}
