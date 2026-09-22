//! Android host for the Railgun wallet core.
//!
//! No socket, no HTTP: the front's `fetch("/api/...")` is rewritten by `dist/tauri-shim.js` into
//! `invoke("api", { path, body })`, which lands here and goes straight to `ipc::dispatch`
//! (ADR-025). `engine.rs`, `keys.rs`, `db.rs` and `shared.rs` are used unchanged.

use std::sync::OnceLock;

use railgun_wallet::ipc::{self, Ctx};
use serde_json::Value;
use tauri::{Manager, State};

mod keystore;

/// Multi-thread runtime for Waku I/O and HTTP clients. The engine thread blocks on proofs
/// (ADR-010), so it cannot host them. Leaked on purpose: it lives as long as the process.
static IO: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

struct App {
    ctx: Ctx,
}

#[tauri::command]
async fn api(
    app: State<'_, App>,
    path: String,
    body: Option<Value>,
) -> Result<Value, ApiFailure> {
    ipc::dispatch(&app.ctx, &path, body)
        .await
        .map_err(|e| ApiFailure {
            code: e.code,
            error: e.message,
        })
}

/// Serialised to the shim, which turns it back into a `Response` with the same status the daemon
/// would have answered, so the front's error handling is identical on both hosts.
#[derive(serde::Serialize)]
struct ApiFailure {
    code: u16,
    error: String,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_barcode_scanner::init())
        .plugin(tauri_plugin_biometric::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            let io = IO.get_or_init(|| {
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .worker_threads(2)
                    .thread_name("railgun-io")
                    .build()
                    .expect("io runtime")
            });

            // Sandboxed, backed by the app's private storage. `ephemeral_senders.jsonl` lives
            // here too, and funds can be stranded on it: it must be in the backup set (ADR-027).
            let data_dir = app.path().app_data_dir()?;
            let boot = ipc::boot(data_dir, io.handle().clone())?;
            app.manage(App {
                ctx: Ctx {
                    shared: boot.shared,
                    engine: boot.engine,
                },
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            api,
            keystore::store_mnemonic,
            keystore::load_mnemonic,
            keystore::forget_mnemonic,
        ])
        .run(tauri::generate_context!())
        .expect("running the Railgun wallet");
}
