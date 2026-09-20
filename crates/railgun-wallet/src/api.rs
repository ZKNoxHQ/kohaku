//! HTTP API consumed by the embedded front.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};

use crate::{
    engine::{Command, Op, UnlockParams},
    shared::SharedRef,
};

const INDEX_HTML: &str = include_str!("../static/index.html");
/// js-waku light node and its glue, built from `waku-bridge/` (see its package.json).
const WAKU_BUNDLE_JS: &str = include_str!("../static/waku-bundle.js");

#[derive(Clone)]
pub struct AppState {
    pub shared: SharedRef,
    pub engine: mpsc::Sender<Command>,
    /// Origins the front may be served from (loopback only). Anything else is refused.
    pub origins: Arc<Vec<String>>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/waku-bundle.js", get(waku_bundle))
        .route("/api/waku/exchange", post(waku_exchange))
        .route("/api/defaults", get(defaults))
        .route("/api/status", get(status))
        .route("/api/unlock", post(unlock))
        .route("/api/lock", post(lock))
        .route("/api/empty-cache", post(empty_cache))
        .route("/api/op", post(op))
        .route("/api/jobs", get(jobs))
        .route("/api/jobs/{id}", get(job))
        .route("/api/logs", get(logs))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            same_origin,
        ))
        .with_state(state)
}

/// The daemon holds keys and listens on localhost: refuse cross-origin callers (a web page in
/// the same browser could otherwise POST to it) and DNS-rebinding style Host headers.
async fn same_origin(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let headers = req.headers();
    let host_ok = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| state.origins.iter().any(|o| o.ends_with(&format!("//{h}"))));
    let origin_ok = match headers.get(header::ORIGIN) {
        None => true,
        Some(o) => o
            .to_str()
            .is_ok_and(|o| state.origins.iter().any(|allowed| allowed == o)),
    };
    if !host_ok || !origin_ok {
        return err(StatusCode::FORBIDDEN, "cross-origin request refused");
    }
    next.run(req).await
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({ "error": msg.into() }))).into_response()
}

async fn index() -> impl IntoResponse {
    (
        [
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(
                    // wss: the Railgun Waku fleet, dialled by the js-waku node of this page.
                    "default-src 'none'; script-src 'self' 'unsafe-inline'; \
                     style-src 'unsafe-inline'; \
                     connect-src 'self' wss://*.rootedinprivacy.com:8000; \
                     base-uri 'none'; form-action 'none'",
                ),
            ),
        ],
        Html(INDEX_HTML),
    )
}

async fn waku_bundle() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static("text/javascript; charset=utf-8")),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        WAKU_BUNDLE_JS,
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExchangeMessage {
    content_topic: String,
    /// base64
    payload: String,
    #[serde(default)]
    timestamp_ns: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExchangeBody {
    connected: bool,
    #[serde(default)]
    peers: usize,
    #[serde(default)]
    detail: Option<String>,
    #[serde(default)]
    messages: Vec<ExchangeMessage>,
    /// Outcome of the publishes handed out at earlier exchanges.
    #[serde(default)]
    acks: Vec<ExchangeAck>,
}

#[derive(Deserialize)]
struct ExchangeAck {
    id: u64,
    #[serde(default)]
    peers: usize,
    #[serde(default)]
    error: Option<String>,
}

/// Round trip with the Waku node of the wallet tab: takes what it received, returns what it must
/// publish. Payloads are opaque here, fee messages are authenticated further down.
async fn waku_exchange(State(state): State<AppState>, Json(body): Json<ExchangeBody>) -> Response {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use railgun_broadcaster::{PublishAck, RemoteStatus, transport::WakuMessage};

    let received = body
        .messages
        .into_iter()
        .filter_map(|m| {
            Some(WakuMessage {
                content_topic: m.content_topic,
                payload: STANDARD.decode(m.payload.as_bytes()).ok()?,
                timestamp_ns: m.timestamp_ns.and_then(|t| t.parse().ok()),
            })
        })
        .collect();
    let publish: Vec<Value> = state
        .shared
        .bridge
        .exchange(
            RemoteStatus {
                connected: body.connected,
                peers: body.peers,
                detail: body.detail,
            },
            received,
            body.acks
                .into_iter()
                .map(|a| PublishAck {
                    id: a.id,
                    peers: a.peers,
                    error: a.error,
                })
                .collect(),
        )
        .into_iter()
        .map(|o| json!({ "id": o.id, "contentTopic": o.content_topic, "payload": STANDARD.encode(&o.payload) }))
        .collect();
    Json(json!({ "publish": publish })).into_response()
}

/// Non-secret defaults the front prefills the unlock form with.
async fn defaults() -> Response {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "waku": {
            "clusterId": railgun_broadcaster::wire::CLUSTER_ID,
            "shardId": railgun_broadcaster::wire::SHARD_ID,
            "bootstrapPeers": railgun_broadcaster::wire::FLEET_WSS_PEERS,
        },
        "trustedFeeSigners": railgun_broadcaster::RAILWAY_TRUSTED_FEE_SIGNERS,
        "trustedFeeSignersSource": "Railway wallet remote configuration, read 2026-09-20",
    }))
    .into_response()
}

async fn status(State(state): State<AppState>) -> Response {
    let snapshot = state.shared.status.read().map(|s| s.clone());
    let active = state.shared.jobs.lock().ok().and_then(|j| j.active());
    let legacy = state.shared.legacy.read().map(|l| l.clone()).unwrap_or_default();
    match snapshot {
        Ok(s) => Json(json!({ "status": s, "activeJob": active, "legacy": legacy })).into_response(),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "state poisoned"),
    }
}

async fn unlock(State(state): State<AppState>, Json(params): Json<UnlockParams>) -> Response {
    let (tx, rx) = oneshot::channel();
    if state
        .engine
        .send(Command::Unlock(Box::new(params), tx))
        .await
        .is_err()
    {
        return err(StatusCode::SERVICE_UNAVAILABLE, "engine stopped");
    }
    match rx.await {
        Ok(Ok(())) => Json(json!({ "ok": true })).into_response(),
        Ok(Err(e)) => err(StatusCode::BAD_REQUEST, e),
        Err(_) => err(StatusCode::SERVICE_UNAVAILABLE, "engine stopped"),
    }
}

async fn lock(State(state): State<AppState>) -> Response {
    let (tx, rx) = oneshot::channel();
    if state.engine.send(Command::Lock(tx)).await.is_err() || rx.await.is_err() {
        return err(StatusCode::SERVICE_UNAVAILABLE, "engine stopped");
    }
    Json(json!({ "ok": true })).into_response()
}

async fn empty_cache(State(state): State<AppState>) -> Response {
    // Queued behind a running job like any command: never deletes under a sync or a proof.
    let (tx, rx) = oneshot::channel();
    if state.engine.send(Command::EmptyCache(tx)).await.is_err() {
        return err(StatusCode::SERVICE_UNAVAILABLE, "engine stopped");
    }
    match rx.await {
        Ok(Ok(removed)) => Json(json!({ "ok": true, "removed": removed })).into_response(),
        Ok(Err(e)) => err(StatusCode::CONFLICT, e),
        Err(_) => err(StatusCode::SERVICE_UNAVAILABLE, "engine stopped"),
    }
}

async fn op(State(state): State<AppState>, Json(op): Json<Op>) -> Response {
    let unlocked = state.shared.status.read().map(|s| s.unlocked).unwrap_or(false);
    if !unlocked {
        return err(StatusCode::CONFLICT, "wallet is locked");
    }
    let id = match state.shared.jobs.lock() {
        Ok(mut jobs) => jobs.create(op.kind()),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "state poisoned"),
    };
    if state.engine.send(Command::Job { id, op }).await.is_err() {
        return err(StatusCode::SERVICE_UNAVAILABLE, "engine stopped");
    }
    Json(json!({ "jobId": id })).into_response()
}

async fn jobs(State(state): State<AppState>) -> Response {
    match state.shared.jobs.lock() {
        Ok(jobs) => Json(json!({ "jobs": jobs.all() })).into_response(),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "state poisoned"),
    }
}

async fn job(State(state): State<AppState>, Path(id): Path<u64>) -> Response {
    match state.shared.jobs.lock().ok().and_then(|j| j.get(id)) {
        Some(job) => Json::<Value>(json!(job)).into_response(),
        None => err(StatusCode::NOT_FOUND, "unknown job"),
    }
}

#[derive(Deserialize)]
struct LogsQuery {
    #[serde(default)]
    since: u64,
}

async fn logs(State(state): State<AppState>, Query(q): Query<LogsQuery>) -> Response {
    match state.shared.logs.lock() {
        Ok(logs) => Json(json!({ "lines": logs.since(q.since) })).into_response(),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "state poisoned"),
    }
}
