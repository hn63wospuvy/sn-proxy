//! Axum HTTP API and websocket route for the web admin.

use crate::manager::Manager;
use crate::model::BasicAuth;
use crate::ws;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use fastwebsockets::upgrade::IncomingUpgrade;
use serde::Deserialize;
use std::sync::Arc;

/// Build the application router.
pub fn router(manager: Arc<Manager>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/proxies", get(list_proxies).post(create_proxy))
        .route("/api/proxies/{id}", post(update_proxy).delete(delete_proxy))
        .route("/api/proxies/{id}/start", post(start_proxy))
        .route("/api/proxies/{id}/stop", post(stop_proxy))
        .route("/api/proxies/{id}/history", get(history))
        .route("/ws", get(ws_handler))
        .with_state(manager)
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
    listen_addr: String,
    #[serde(default)]
    auth: Option<BasicAuth>,
}

async fn list_proxies(State(m): State<Arc<Manager>>) -> Response {
    Json(m.snapshot()).into_response()
}

async fn create_proxy(State(m): State<Arc<Manager>>, Json(form): Json<ProxyForm>) -> Response {
    match m.create(form.name, form.listen_addr, normalize_auth(form.auth)) {
        Ok(cfg) => Json(cfg).into_response(),
        Err(e) => fail(e),
    }
}

async fn update_proxy(
    State(m): State<Arc<Manager>>,
    Path(id): Path<String>,
    Json(form): Json<ProxyForm>,
) -> Response {
    match m
        .update(&id, form.name, form.listen_addr, normalize_auth(form.auth))
        .await
    {
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
    200
}

#[derive(Deserialize)]
struct HistoryQuery {
    #[serde(default = "default_limit")]
    limit: usize,
}

async fn history(
    State(m): State<Arc<Manager>>,
    Path(id): Path<String>,
    Query(q): Query<HistoryQuery>,
) -> Response {
    match m.storage.load_history(&id, q.limit) {
        Ok(records) => Json(records).into_response(),
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
