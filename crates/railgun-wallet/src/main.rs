//! ZKNOX Railgun wallet: local daemon plus embedded web front on top of the kohaku Rust SDK.

mod api;
mod db;
mod engine;
mod keys;
mod shared;

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result, bail};
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use crate::shared::{FrontLogLayer, Shared};

struct Args {
    port: u16,
    data_dir: PathBuf,
}

fn parse_args() -> Result<Args> {
    let mut port = 8787u16;
    let mut data_dir = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".railgun-wallet");

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => port = args.next().context("--port needs a value")?.parse()?,
            "--data-dir" => data_dir = args.next().context("--data-dir needs a value")?.into(),
            "-h" | "--help" => {
                println!("railgun-wallet [--port 8787] [--data-dir ~/.railgun-wallet]");
                std::process::exit(0);
            }
            other => bail!("unknown argument: {other}"),
        }
    }
    Ok(Args { port, data_dir })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;
    let shared = Arc::new(Shared::default());

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,railgun=info,railgun_wallet=info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .with(FrontLogLayer(shared.clone()))
        .init();

    std::fs::create_dir_all(&args.data_dir)?;
    let engine = engine::spawn(
        shared.clone(),
        args.data_dir.clone(),
        tokio::runtime::Handle::current(),
    );

    // Loopback only: the API accepts key material.
    let addr = SocketAddr::from(([127, 0, 0, 1], args.port));
    let origin = format!("http://{addr}");
    let app = api::router(api::AppState {
        shared,
        engine,
        origins: Arc::new(vec![origin.clone(), format!("http://localhost:{}", args.port)]),
    });

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    info!("railgun-wallet listening on {origin} (data dir: {})", args.data_dir.display());
    axum::serve(listener, app).await?;
    Ok(())
}
