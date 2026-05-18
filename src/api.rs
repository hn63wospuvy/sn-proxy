//! Axum HTTP API and websocket route for the web admin.

use crate::manager::{Manager, ProxySpec};
use crate::model::{BasicAuth, Protocol};
use crate::ws;
use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use fastwebsockets::upgrade::IncomingUpgrade;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;

/// Build the application router. Proxy/monitoring routes sit behind a login
/// check; the page, login and session routes stay open.
pub fn router(manager: Arc<Manager>) -> Router {
    let protected = Router::new()
        .route("/api/proxies", get(list_proxies).post(create_proxy))
        .route("/api/proxies/{id}", post(update_proxy).delete(delete_proxy))
        .route("/api/proxies/{id}/start", post(start_proxy))
        .route("/api/proxies/{id}/stop", post(stop_proxy))
        .route("/api/proxies/{id}/history", get(history).delete(clear_history))
        .route("/ws", get(ws_handler))
        .route_layer(middleware::from_fn_with_state(manager.clone(), require_auth));

    Router::new()
        .route("/", get(index))
        .route("/api/session", get(session))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .merge(protected)
        .with_state(manager)
}

/// Cookie name carrying the web-admin session token.
const SESSION_COOKIE: &str = "sn_session";

/// Extract the session token from a `Cookie` header.
fn session_token(headers: &HeaderMap) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    cookies.split(';').find_map(|c| {
        let (k, v) = c.split_once('=')?;
        (k.trim() == SESSION_COOKIE).then(|| v.trim().to_string())
    })
}

/// Middleware: reject requests without a valid session when login is enabled.
async fn require_auth(State(m): State<Arc<Manager>>, req: Request, next: Next) -> Response {
    if !m.admin.required() {
        return next.run(req).await;
    }
    let authed = session_token(req.headers())
        .map(|t| m.admin.valid(&t))
        .unwrap_or(false);
    if authed {
        next.run(req).await
    } else {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "login required" })))
            .into_response()
    }
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

/// Report whether login is required and whether this request is logged in.
async fn session(State(m): State<Arc<Manager>>, headers: HeaderMap) -> Response {
    let required = m.admin.required();
    let logged_in = !required
        || session_token(&headers)
            .map(|t| m.admin.valid(&t))
            .unwrap_or(false);
    Json(serde_json::json!({ "auth_required": required, "logged_in": logged_in })).into_response()
}

/// Verify credentials (and the caller's network) and, on success, issue a
/// session cookie.
async fn login(
    State(m): State<Arc<Manager>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(form): Json<LoginForm>,
) -> Response {
    match m.admin.check(&form.username, &form.password, addr.ip()) {
        Ok(()) => {
            let token = m.admin.create_session();
            let cookie = format!(
                "{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400"
            );
            ([(header::SET_COOKIE, cookie)], StatusCode::OK).into_response()
        }
        Err(msg) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": msg })),
        )
            .into_response(),
    }
}

/// Invalidate the current session and clear the cookie.
async fn logout(State(m): State<Arc<Manager>>, headers: HeaderMap) -> Response {
    if let Some(token) = session_token(&headers) {
        m.admin.revoke(&token);
    }
    let cleared = format!("{SESSION_COOKIE}=; HttpOnly; Path=/; Max-Age=0");
    ([(header::SET_COOKIE, cleared)], StatusCode::OK).into_response()
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

/// Map an error into a 400 JSON response.
fn fail(e: anyhow::Error) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": e.to_string() })),
    )
        .into_response()
}

/// Drop empty credentials so an empty form means "no auth".
fn normalize_auth(auth: Option<BasicAuth>) -> Option<BasicAuth> {
    auth.filter(|a| !a.username.is_empty())
}

#[derive(Deserialize)]
struct ProxyForm {
    name: String,
    #[serde(default)]
    protocol: Protocol,
    listen_addr: String,
    #[serde(default)]
    auth: Option<BasicAuth>,
    #[serde(default)]
    ss_method: Option<String>,
    #[serde(default)]
    ss_password: Option<String>,
    #[serde(default)]
    forward_to: Option<String>,
    #[serde(default)]
    keepalive_secs: Option<u64>,
    #[serde(default)]
    idle_timeout_secs: Option<u64>,
    #[serde(default)]
    connect_timeout_secs: Option<u64>,
}

impl ProxyForm {
    fn into_spec(self) -> ProxySpec {
        // Treat 0 as "unset" for the optional numeric tuning knobs.
        let nonzero = |v: Option<u64>| v.filter(|n| *n > 0);
        ProxySpec {
            name: self.name,
            protocol: self.protocol,
            listen_addr: self.listen_addr,
            auth: normalize_auth(self.auth),
            ss_method: self.ss_method.filter(|s| !s.is_empty()),
            ss_password: self.ss_password.filter(|s| !s.is_empty()),
            forward_to: self.forward_to.filter(|s| !s.is_empty()),
            keepalive_secs: nonzero(self.keepalive_secs),
            idle_timeout_secs: nonzero(self.idle_timeout_secs),
            connect_timeout_secs: nonzero(self.connect_timeout_secs),
        }
    }
}

async fn list_proxies(State(m): State<Arc<Manager>>) -> Response {
    Json(m.snapshot()).into_response()
}

async fn create_proxy(State(m): State<Arc<Manager>>, Json(form): Json<ProxyForm>) -> Response {
    match m.create(form.into_spec()) {
        Ok(cfg) => Json(cfg).into_response(),
        Err(e) => fail(e),
    }
}

async fn update_proxy(
    State(m): State<Arc<Manager>>,
    Path(id): Path<String>,
    Json(form): Json<ProxyForm>,
) -> Response {
    match m.update(&id, form.into_spec()).await {
        Ok(cfg) => Json(cfg).into_response(),
        Err(e) => fail(e),
    }
}

async fn delete_proxy(State(m): State<Arc<Manager>>, Path(id): Path<String>) -> Response {
    match m.delete(&id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => fail(e),
    }
}

async fn start_proxy(State(m): State<Arc<Manager>>, Path(id): Path<String>) -> Response {
    match m.start(&id).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => fail(e),
    }
}

async fn stop_proxy(State(m): State<Arc<Manager>>, Path(id): Path<String>) -> Response {
    match m.stop(&id) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => fail(e),
    }
}

fn default_limit() -> usize {
    20
}

#[derive(Deserialize)]
struct HistoryQuery {
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_limit")]
    limit: usize,
}

/// Return one page of history plus a `has_more` flag for the next page.
async fn history(
    State(m): State<Arc<Manager>>,
    Path(id): Path<String>,
    Query(q): Query<HistoryQuery>,
) -> Response {
    // Fetch one extra record to learn whether a further page exists.
    match m.storage.load_history(&id, q.offset, q.limit.saturating_add(1)) {
        Ok(mut records) => {
            let has_more = records.len() > q.limit;
            records.truncate(q.limit);
            Json(serde_json::json!({
                "records": records,
                "offset": q.offset,
                "limit": q.limit,
                "has_more": has_more,
            }))
            .into_response()
        }
        Err(e) => fail(e),
    }
}

/// Delete every history record for a proxy.
async fn clear_history(State(m): State<Arc<Manager>>, Path(id): Path<String>) -> Response {
    match m.storage.delete_history(&id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => fail(e),
    }
}

/// Upgrade the request to a websocket and stream monitoring events.
async fn ws_handler(State(m): State<Arc<Manager>>, ws: IncomingUpgrade) -> impl IntoResponse {
    let (response, fut) = ws.upgrade().unwrap();
    tokio::spawn(async move {
        if let Err(e) = ws::handle(fut, m).await {
            tracing::debug!("websocket closed: {e}");
        }
    });
    response
}
