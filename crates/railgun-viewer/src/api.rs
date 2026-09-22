//! HTTP API on loopback plus the embedded front.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    response::{Html, IntoResponse},
    routing::{get, post},
};
use serde_json::{Value, json};

use crate::{
    engine::{Engine, UnlockParams},
    shared::{SharedRef, StatusView},
};

#[derive(Clone)]
pub struct AppState {
    pub engine: Engine,
    pub shared: SharedRef,
    pub version: &'static str,
    pub data_dir: Arc<String>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/status", get(status))
        .route("/api/snapshot", get(snapshot))
        .route("/api/unlock", post(unlock))
        .route("/api/sync", post(sync))
        .route("/api/refresh", post(refresh))
        .route("/api/lock", post(lock))
        .with_state(state)
}

async fn index() -> impl IntoResponse {
    Html(include_str!("../static/index.html"))
}

async fn status(State(st): State<AppState>) -> Json<StatusView> {
    let s = st.shared.lock().expect("shared");
    Json(StatusView {
        version: st.version,
        data_dir: st.data_dir.to_string(),
        unlocked: s.unlocked,
        syncing: s.syncing,
        address: s.address.clone(),
        mode: s.mode,
        chain_id: s.chain_id,
        synced_block: s.synced_block,
        last_error: s.last_error.clone(),
        log: s.log.clone(),
        updated_at: s.updated_at,
    })
}

async fn snapshot(State(st): State<AppState>) -> Json<Value> {
    let s = st.shared.lock().expect("shared");
    Json(s.snapshot.clone().unwrap_or(Value::Null))
}

async fn unlock(State(st): State<AppState>, Json(p): Json<UnlockParams>) -> Json<Value> {
    match st.engine.unlock(p).await {
        Ok(()) => Json(json!({ "ok": true })),
        Err(e) => Json(json!({ "ok": false, "error": format!("{e:#}") })),
    }
}

async fn sync(State(st): State<AppState>) -> Json<Value> {
    match st.engine.sync() {
        Ok(()) => Json(json!({ "ok": true })),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}

async fn refresh(State(st): State<AppState>) -> Json<Value> {
    match st.engine.refresh() {
        Ok(()) => Json(json!({ "ok": true })),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}

async fn lock(State(st): State<AppState>) -> Json<Value> {
    match st.engine.lock().await {
        Ok(()) => Json(json!({ "ok": true })),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}
