//! State shared between the axum handlers and the engine thread.

use std::sync::{Arc, Mutex};

use serde::Serialize;
use serde_json::Value;

#[derive(Default)]
pub struct Shared {
    pub unlocked: bool,
    pub syncing: bool,
    pub address: Option<String>,
    pub mode: Option<&'static str>,
    pub chain_id: Option<u64>,
    pub synced_block: Option<u64>,
    pub last_error: Option<String>,
    pub log: Vec<String>,
    /// Last history + graph snapshot produced by the engine.
    pub snapshot: Option<Value>,
    pub updated_at: u64,
}

pub type SharedRef = Arc<Mutex<Shared>>;

pub fn new_shared() -> SharedRef {
    Arc::new(Mutex::new(Shared::default()))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusView {
    pub version: &'static str,
    pub data_dir: String,
    pub unlocked: bool,
    pub syncing: bool,
    pub address: Option<String>,
    pub mode: Option<&'static str>,
    pub chain_id: Option<u64>,
    pub synced_block: Option<u64>,
    pub last_error: Option<String>,
    pub log: Vec<String>,
    pub updated_at: u64,
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

pub fn log(shared: &SharedRef, line: impl Into<String>) {
    let line = line.into();
    tracing::info!("{line}");
    if let Ok(mut s) = shared.lock() {
        s.log.push(line);
        if s.log.len() > 400 {
            let drop = s.log.len() - 400;
            s.log.drain(..drop);
        }
        s.updated_at = now_ms();
    }
}
