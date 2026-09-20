//! Wallet engine.
//!
//! A single actor, running on its own thread with a current-thread tokio runtime, owns the
//! `RailgunProvider`. It needs `&mut self` for nearly everything and its futures are not
//! guaranteed to be `Send`, so commands are serialised through an mpsc channel instead of being
//! run inside axum handlers.

use std::{
    collections::HashMap,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use alloy::{
    network::Ethereum,
    primitives::{Address, B256, U256, utils::format_units, utils::parse_units},
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner as EoaSigner,
    sol,
    sol_types::SolCall,
};
use anyhow::{Context, Result, anyhow, bail};
use eip_1193_provider::tx_data::TxData;
use railgun::{
    account::{
        address::RailgunAddress,
        signer::{PrivateKeySigner as RgSigner, RailgunSigner},
    },
    builder::RailgunBuilder,
    caip::AssetId,
    chain_config::ChainConfig,
    provider::RailgunProvider,
    transact::TransactionBuilder,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn};
use userop_kit::{
    bundler::{Bundler, pimlico::PimlicoBundler},
    user_operation::UserOperationGasEstimate,
    smart_account::simple_smart_account::{Call, SimpleSmartAccount},
};

use railgun_broadcaster::{
    BroadcastRequest, BroadcasterClient, ClientError, FeeQuote, NoQuote, NwakuRest, WakuTransport,
    PAR_RATE_WRAPPED_BASE_TOKEN, fees::now_ms as quote_now_ms, token_fee,
};

use crate::{
    db::WalletDb,
    keys::{self, Derivation},
    shared::{JobState, LegacyStatus, SharedRef, StatusSnapshot, TransportInfo, now_ms},
};

sol! {
    #[sol(rpc)]
    contract ERC20 {
        function balanceOf(address account) external view returns (uint256);
        function allowance(address owner, address spender) external view returns (uint256);
        function approve(address spender, uint256 amount) external returns (bool);
        function decimals() external view returns (uint8);
        function symbol() external view returns (string);
    }

    contract WETH9 {
        function withdraw(uint256 wad) external;
    }
}

/// Public endpoints used when the front leaves the field empty. Rate limited, fine for testing.
fn default_rpc_url(chain_id: u64) -> Option<&'static str> {
    match chain_id {
        1 => Some("https://ethereum-rpc.publicnode.com"),
        11_155_111 => Some("https://ethereum-sepolia-rpc.publicnode.com"),
        _ => None,
    }
}

fn default_bundler_url(chain_id: u64) -> String {
    format!("https://public.pimlico.io/v2/{chain_id}/rpc")
}

/// A broadcaster of the reference implementation takes its gas cost plus a margin of 10 to
/// 30%. Half as much again leaves room for that and refuses anything predatory.
const DEFAULT_MAX_FEE_RATE: &str = "1.5";

const DEFAULT_GAS_MARGIN_PERCENT: u32 = 25;
const MAX_GAS_MARGIN_PERCENT: u32 = 200;

/// Limits are rounded up to this, so the public fee says less about the transaction.
const GAS_BUCKET: u128 = 10_000;

const DEFAULT_WAKU_URL: &str = "http://127.0.0.1:8645";

/// Gas assumed for the first fee guess, before the dummy-proof estimate replaces it.
const FIRST_GUESS_GAS: u64 = 700_000;

/// Keeps the fee cache current and publishes the state of the broadcaster network for the front.
async fn fee_monitor(
    client: Arc<BroadcasterClient>,
    shared: SharedRef,
    mode: &'static str,
    waku_url: String,
) {
    let mut subscribed = false;
    loop {
        let mut status = LegacyStatus {
            mode: Some(mode.to_string()),
            waku_url: (mode == "nwaku").then(|| waku_url.clone()),
            updated_at: now_ms(),
            ..Default::default()
        };
        let result = async {
            if !subscribed {
                client.subscribe().await?;
            }
            client.pump().await
        }
        .await;
        match result {
            Ok(_) => {
                subscribed = true;
                status.reachable = true;
                status.peers = client.peer_count().await;
                status.trusted_signers = client.trusted_signer_count();
                status.authorized_fees = client
                    .authorized_fees()
                    .into_iter()
                    .map(|(token, rate)| json!({ "token": token, "feePerUnitGas": rate.to_string() }))
                    .collect();
                status.quotes = client
                    .all_quotes()
                    .into_iter()
                    .filter_map(|q| serde_json::to_value(q).ok())
                    .collect();
            }
            Err(e) => {
                subscribed = false;
                status.error = Some(e.to_string());
            }
        }
        if let Ok(mut l) = shared.legacy.write() {
            *l = status;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// Seconds to wait after an on-chain inclusion before re-syncing, so that the subsquid indexer
/// has a chance to see the new commitments.
const POST_TX_SYNC_DELAY: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// ERC-4337 UserOperation through the kohaku privacy paymaster.
    Erc4337,
    /// Railgun community broadcasters (Waku). Not implemented yet.
    Legacy,
    /// Self-broadcast from the public EOA. No sender privacy, debug only.
    Direct,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockParams {
    pub mnemonic: Option<String>,
    pub spending_key: Option<String>,
    pub viewing_key: Option<String>,
    #[serde(default)]
    pub derivation: Derivation,
    #[serde(default)]
    pub index: u32,
    pub chain_id: u64,
    /// Empty or absent: public default for the chain.
    pub rpc_url: Option<String>,
    /// Public EOA used for shielding (and for the `direct` transport).
    pub eoa_key: Option<String>,
    #[serde(default)]
    pub poi: bool,
    pub bundler_url: Option<String>,
    /// REST root of a local nwaku node on the Railgun shard, for the legacy transport.
    pub waku_url: Option<String>,
    /// "browser" (default): js-waku in the wallet tab. "nwaku": local node at `waku_url`.
    pub waku_mode: Option<String>,
    /// 0zk addresses of trusted fee signers, separated by commas, spaces or new lines. Offers of
    /// other broadcasters are then capped to a band around the signers' rates.
    pub trusted_fee_signers: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "camelCase")]
pub enum Op {
    Sync,
    #[serde(rename_all = "camelCase")]
    Shield { asset: String, amount: String },
    #[serde(rename_all = "camelCase")]
    Transfer {
        to: String,
        asset: String,
        amount: String,
        #[serde(default)]
        memo: String,
        transport: Transport,
        #[serde(default, flatten)]
        fee_limits: FeeLimits,
    },
    #[serde(rename_all = "camelCase")]
    Unshield {
        to: String,
        asset: String,
        amount: String,
        /// Unwrap the wrapped base token and deliver native currency to `to`.
        #[serde(default)]
        native: bool,
        transport: Transport,
        #[serde(default, flatten)]
        fee_limits: FeeLimits,
    },
}

/// Ceilings on what a broadcaster may charge (legacy transport). They need no trusted party:
/// the fee token is the wrapped base token, so the honest rate is the gas cost plus a margin.
#[derive(Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FeeLimits {
    /// Highest accepted rate, as a multiple of the gas cost ("1.5" = 50% over). Defaults to
    /// [`DEFAULT_MAX_FEE_RATE`] when absent or empty.
    pub max_fee_rate: Option<String>,
    /// Highest accepted fee for the whole transaction, in wrapped base token ("0.002").
    pub max_fee: Option<String>,
    /// 4337: prove once, with gas limits fixed beforehand from a learned profile plus a margin,
    /// instead of re-proving until the fee converges. One spending signature per operation,
    /// which is what a hardware or threshold signer needs.
    #[serde(default)]
    pub single_proof: bool,
    /// Margin added to the limits in single-proof mode, percent. Defaults to 25.
    pub gas_margin_percent: Option<u32>,
    /// With `single_proof`: fail rather than fall back to the iterative path when the limits
    /// cannot be simulated. For signers where several signatures are not an option.
    #[serde(default)]
    pub single_proof_strict: bool,
}

impl Op {
    pub fn kind(&self) -> &'static str {
        match self {
            Op::Sync => "sync",
            Op::Shield { .. } => "shield",
            Op::Transfer { .. } => "transfer",
            Op::Unshield { .. } => "unshield",
        }
    }
}

pub enum Command {
    Unlock(Box<UnlockParams>, oneshot::Sender<Result<(), String>>),
    Lock(oneshot::Sender<()>),
    Job { id: u64, op: Op },
}

#[derive(Clone)]
struct TokenMeta {
    symbol: String,
    decimals: u8,
}

struct Session {
    chain: ChainConfig,
    provider: DynProvider,
    eoa: Option<EoaSigner>,
    signer: Arc<RgSigner>,
    railgun: RailgunProvider,
    derivation: &'static str,
    bundler_url: String,
    data_dir: PathBuf,
    tokens: HashMap<Address, TokenMeta>,
    broadcaster: Arc<BroadcasterClient>,
    /// Limits of the operation being run, set by `Engine::run`.
    fee_limits: FeeLimits,
    /// Multi-thread runtime of the HTTP server. Waku I/O runs there: this thread's runtime is
    /// blocked while a proof is computed.
    io: tokio::runtime::Handle,
    fee_monitor: tokio::task::AbortHandle,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.fee_monitor.abort();
    }
}

pub struct Engine {
    shared: SharedRef,
    base_dir: PathBuf,
    io: tokio::runtime::Handle,
    session: Option<Session>,
}

/// Spawns the engine thread and returns the command channel.
pub fn spawn(
    shared: SharedRef,
    base_dir: PathBuf,
    io: tokio::runtime::Handle,
) -> mpsc::Sender<Command> {
    let (tx, mut rx) = mpsc::channel::<Command>(64);
    std::thread::Builder::new()
        .name("railgun-engine".into())
        // Groth16 proving recurses deep enough to be uncomfortable on the default 2 MiB.
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("engine runtime");
            rt.block_on(async move {
                let mut engine = Engine {
                    shared,
                    base_dir,
                    io,
                    session: None,
                };
                while let Some(cmd) = rx.recv().await {
                    engine.handle(cmd).await;
                }
            });
        })
        .expect("spawn engine thread");
    tx
}

struct JobCtx<'a> {
    shared: &'a SharedRef,
    id: u64,
}

impl JobCtx<'_> {
    fn step(&self, msg: impl Into<String>) {
        let msg = msg.into();
        info!(job = self.id, "{msg}");
        if let Ok(mut jobs) = self.shared.jobs.lock() {
            jobs.update(self.id, |j| j.steps.push(msg));
        }
    }
}

impl Engine {
    async fn handle(&mut self, cmd: Command) {
        match cmd {
            Command::Unlock(params, reply) => {
                let res = self.unlock(*params).await.map_err(|e| format!("{e:#}"));
                if let Err(e) = &res {
                    error!("unlock failed: {e}");
                }
                let _ = reply.send(res);
            }
            Command::Lock(reply) => {
                self.session = None;
                if let Ok(mut s) = self.shared.status.write() {
                    *s = StatusSnapshot {
                        updated_at: now_ms(),
                        ..Default::default()
                    };
                }
                if let Ok(mut l) = self.shared.legacy.write() {
                    *l = LegacyStatus::default();
                }
                info!("wallet locked");
                let _ = reply.send(());
            }
            Command::Job { id, op } => {
                self.set_job(id, |j| j.state = JobState::Running);
                let shared = self.shared.clone();
                let ctx = JobCtx {
                    shared: &shared,
                    id,
                };
                let res = self.run(&ctx, op).await;
                self.refresh_snapshot().await;
                match res {
                    Ok(value) => self.set_job(id, |j| {
                        j.state = JobState::Done;
                        j.result = Some(value);
                        j.finished_at = Some(now_ms());
                    }),
                    Err(e) => {
                        let msg = format!("{e:#}");
                        error!(job = id, "job failed: {msg}");
                        self.set_job(id, |j| {
                            j.state = JobState::Failed;
                            j.error = Some(msg);
                            j.finished_at = Some(now_ms());
                        });
                    }
                }
            }
        }
    }

    fn set_job(&self, id: u64, f: impl FnOnce(&mut crate::shared::Job)) {
        if let Ok(mut jobs) = self.shared.jobs.lock() {
            jobs.update(id, f);
        }
    }

    async fn unlock(&mut self, p: UnlockParams) -> Result<()> {
        let chain = ChainConfig::from_chain_id(p.chain_id)
            .ok_or_else(|| anyhow!("unsupported chain id {}", p.chain_id))?;

        let (keys, derivation) = match (&p.mnemonic, &p.spending_key, &p.viewing_key) {
            (Some(m), _, _) if !m.trim().is_empty() => (
                keys::derive(m, p.index, p.derivation)?,
                match p.derivation {
                    Derivation::Railgun => "railgun",
                    Derivation::Kohaku => "kohaku",
                },
            ),
            (_, Some(s), Some(v)) => (keys::from_hex(s, v)?, "raw"),
            _ => bail!("provide either a mnemonic or both spending and viewing keys"),
        };
        let signer = RgSigner::new_evm(keys.spending, keys.viewing, chain.id);
        let address = signer.address().to_string();

        let eoa = match p.eoa_key.as_deref().map(str::trim) {
            Some(k) if !k.is_empty() => {
                Some(EoaSigner::from_str(k).map_err(|e| anyhow!("invalid EOA key: {e}"))?)
            }
            _ => None,
        };

        let rpc_url = match p.rpc_url.as_deref().map(str::trim) {
            Some(u) if !u.is_empty() => u.to_string(),
            _ => default_rpc_url(chain.id)
                .ok_or_else(|| anyhow!("no default RPC for chain {}", chain.id))?
                .to_string(),
        };
        if !(rpc_url.starts_with("http://") || rpc_url.starts_with("https://")
            || rpc_url.starts_with("ws://") || rpc_url.starts_with("wss://"))
        {
            bail!("RPC URL must start with http(s):// or ws(s)://, got \"{rpc_url}\"");
        }

        let provider = match &eoa {
            Some(eoa) => ProviderBuilder::new()
                .network::<Ethereum>()
                .wallet(eoa.clone())
                .connect(&rpc_url)
                .await
                .context("connecting to RPC")?
                .erased(),
            None => ProviderBuilder::new()
                .network::<Ethereum>()
                .connect(&rpc_url)
                .await
                .context("connecting to RPC")?
                .erased(),
        };

        let rpc_chain = provider.get_chain_id().await.context("eth_chainId")?;
        if rpc_chain != chain.id {
            bail!("RPC is on chain {rpc_chain}, expected {}", chain.id);
        }

        let tag = hex::encode(&Sha256::digest(address.as_bytes())[..8]);
        let data_dir = self.base_dir.join(chain.id.to_string()).join(tag);
        let db = // v2: accounts keep spent and sent notes, the txid indexer keeps our own operations.
        // A v1 database dropped them at sync time, so it cannot be upgraded in place.
        Arc::new(WalletDb::new(data_dir.join("db-v2"))?);

        let mut builder = RailgunBuilder::new(chain.clone(), provider.clone()).with_database(db);
        if p.poi {
            builder = builder.with_poi();
        }
        let mut railgun = builder.build().await.context("building railgun provider")?;
        railgun.register(signer.clone()).await?;

        let bundler_url = p
            .bundler_url
            .filter(|u| !u.trim().is_empty())
            .unwrap_or_else(|| default_bundler_url(chain.id));

        let waku_url = p
            .waku_url
            .filter(|u| !u.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_WAKU_URL.to_string());
        // "none" is how the front says the field was cleared on purpose (test networks).
        let trusted_signers: Vec<String> = p
            .trusted_fee_signers
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.eq_ignore_ascii_case("none"))
            .unwrap_or("")
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|a| !a.is_empty())
            .map(str::to_string)
            .collect();
        let waku_mode = match p.waku_mode.as_deref().map(str::trim) {
            None | Some("") | Some("browser") => "browser",
            Some("nwaku") => "nwaku",
            Some(other) => bail!("unknown Waku mode \"{other}\" (expected browser or nwaku)"),
        };
        let transport: Arc<dyn WakuTransport> = if waku_mode == "browser" {
            self.shared.bridge.clone()
        } else {
            Arc::new(NwakuRest::new(waku_url.clone()))
        };
        let broadcaster = Arc::new(if trusted_signers.is_empty() {
            BroadcasterClient::new(transport, chain.id)
        } else {
            BroadcasterClient::with_trusted_signers(transport, chain.id, &trusted_signers)
                .map_err(|e| anyhow!("{e}"))?
        });
        // Replaces the monitor of a previous session, if any.
        self.session = None;
        let fee_monitor = self
            .io
            .spawn(fee_monitor(
                broadcaster.clone(),
                self.shared.clone(),
                waku_mode,
                waku_url,
            ))
            .abort_handle();

        info!(%address, chain = chain.id, poi = p.poi, rpc = %rpc_url, "wallet unlocked");
        self.session = Some(Session {
            chain,
            provider,
            eoa,
            signer,
            railgun,
            derivation,
            bundler_url,
            data_dir,
            tokens: HashMap::new(),
            broadcaster,
            fee_limits: FeeLimits::default(),
            io: self.io.clone(),
            fee_monitor,
        });
        self.refresh_snapshot().await;
        Ok(())
    }

    async fn run(&mut self, ctx: &JobCtx<'_>, op: Op) -> Result<Value> {
        let s = self
            .session
            .as_mut()
            .ok_or_else(|| anyhow!("wallet is locked"))?;
        match op {
            Op::Sync => {
                ctx.step("syncing UTXO tree, TXID tree and pending POI proofs");
                s.railgun.sync().await?;
                Ok(json!({ "syncedBlock": s.railgun.synced_block() }))
            }
            Op::Shield { asset, amount } => s.shield(ctx, &asset, &amount).await,
            Op::Transfer {
                to,
                asset,
                amount,
                memo,
                transport,
                fee_limits,
            } => {
                s.fee_limits = fee_limits;
                let to = RailgunAddress::from_str(to.trim())
                    .map_err(|e| anyhow!("invalid 0zk recipient: {e}"))?;
                let (asset, value, _) = s.resolve_amount(&asset, &amount).await?;
                let builder = TransactionBuilder::new().transfer(
                    s.signer.clone() as Arc<dyn RailgunSigner>,
                    to,
                    asset,
                    value,
                    &memo,
                );
                s.submit(ctx, builder, transport, Vec::new(), None).await
            }
            Op::Unshield {
                to,
                asset,
                amount,
                native,
                transport,
                fee_limits,
            } => {
                s.fee_limits = fee_limits;
                let to = Address::from_str(to.trim())
                    .map_err(|e| anyhow!("invalid 0x recipient: {e}"))?;
                s.unshield(ctx, to, &asset, &amount, native, transport).await
            }
        }
    }

    async fn refresh_snapshot(&mut self) {
        let Some(s) = self.session.as_mut() else {
            return;
        };
        let snapshot = s.snapshot().await;
        if let Ok(mut status) = self.shared.status.write() {
            *status = snapshot;
        }
    }
}

impl Session {
    /// Resolves the front's asset spec (`"native"` or an ERC-20 address) and a decimal amount
    /// into an `AssetId` and base units. Shielded native currency is the wrapped base token.
    async fn resolve_amount(&mut self, asset: &str, amount: &str) -> Result<(AssetId, u128, Address)> {
        let token = if asset.trim().eq_ignore_ascii_case("native") {
            self.chain.wrapped_base_token
        } else {
            Address::from_str(asset.trim()).map_err(|e| anyhow!("invalid token address: {e}"))?
        };
        let meta = self.token_meta(token).await;
        let value: U256 = parse_units(amount.trim(), meta.decimals)
            .map_err(|e| anyhow!("invalid amount: {e}"))?
            .get_absolute();
        let value = u128::try_from(value).map_err(|_| anyhow!("amount too large"))?;
        if value == 0 {
            bail!("amount must be positive");
        }
        Ok((AssetId::Erc20(token), value, token))
    }

    async fn token_meta(&mut self, token: Address) -> TokenMeta {
        if let Some(meta) = self.tokens.get(&token) {
            return meta.clone();
        }
        let erc20 = ERC20::new(token, self.provider.clone());
        let decimals = erc20.decimals().call().await;
        let symbol = erc20.symbol().call().await;
        let complete = decimals.is_ok() && symbol.is_ok();
        let meta = TokenMeta {
            symbol: symbol.unwrap_or_else(|_| "?".into()),
            decimals: decimals.unwrap_or(18),
        };
        // Only cache real answers, a transient RPC error must not pin 18 decimals forever.
        if complete {
            self.tokens.insert(token, meta.clone());
        } else {
            warn!(%token, "could not read ERC-20 metadata, assuming 18 decimals");
        }
        meta
    }

    async fn send_eoa(&self, ctx: &JobCtx<'_>, label: &str, tx: TxData) -> Result<B256> {
        if self.eoa.is_none() {
            bail!("no public EOA key configured, cannot send {label} transaction");
        }
        ctx.step(format!("sending {label} transaction from EOA"));
        let pending = self
            .provider
            .send_transaction(tx.into())
            .await
            .with_context(|| format!("{label}: eth_sendTransaction"))?;
        let hash = *pending.tx_hash();
        ctx.step(format!("{label} tx {hash} sent, waiting for inclusion"));
        let receipt = pending
            .get_receipt()
            .await
            .with_context(|| format!("{label}: waiting for receipt"))?;
        if !receipt.status() {
            bail!("{label} transaction {hash} reverted");
        }
        ctx.step(format!(
            "{label} included in block {}",
            receipt.block_number.unwrap_or_default()
        ));
        Ok(hash)
    }

    async fn shield(&mut self, ctx: &JobCtx<'_>, asset: &str, amount: &str) -> Result<Value> {
        let eoa = self
            .eoa
            .as_ref()
            .map(EoaSigner::address)
            .ok_or_else(|| anyhow!("shielding needs a public EOA key"))?;
        let is_native = asset.trim().eq_ignore_ascii_case("native");
        let (asset_id, value, token) = self.resolve_amount(asset, amount).await?;
        let recipient = self.signer.address();

        let mut hashes = Vec::new();
        let txs = if is_native {
            self.railgun
                .shield()
                .shield_native(recipient, value)
                .build(&mut rand::rng())?
        } else {
            let erc20 = ERC20::new(token, self.provider.clone());
            let spender = self.chain.railgun_smart_wallet;
            let balance = erc20.balanceOf(eoa).call().await?;
            if balance < U256::from(value) {
                bail!("EOA token balance {balance} is below the shield amount {value}");
            }
            let allowance = erc20.allowance(eoa, spender).call().await?;
            if allowance < U256::from(value) {
                let approve = TxData::new(
                    token,
                    ERC20::approveCall {
                        spender,
                        amount: U256::from(value),
                    }
                    .abi_encode()
                    .into(),
                    U256::ZERO,
                );
                hashes.push(self.send_eoa(ctx, "approve", approve).await?);
            }
            self.railgun
                .shield()
                .shield(recipient, asset_id, value)
                .build(&mut rand::rng())?
        };

        for tx in txs {
            hashes.push(self.send_eoa(ctx, "shield", tx).await?);
        }
        self.post_tx_sync(ctx).await;
        Ok(json!({ "txHashes": hashes.iter().map(|h| h.to_string()).collect::<Vec<_>>() }))
    }

    async fn unshield(
        &mut self,
        ctx: &JobCtx<'_>,
        to: Address,
        asset: &str,
        amount: &str,
        native: bool,
        transport: Transport,
    ) -> Result<Value> {
        let (asset_id, value, token) = self.resolve_amount(asset, amount).await?;
        let signer = self.signer.clone() as Arc<dyn RailgunSigner>;

        if !native {
            let builder = TransactionBuilder::new().unshield(signer, to, asset_id, value)?;
            return self.submit(ctx, builder, transport, Vec::new(), None).await;
        }

        if token != self.chain.wrapped_base_token {
            bail!("native unshield only applies to the wrapped base token");
        }
        if transport != Transport::Erc4337 {
            bail!(
                "native unshield is only wired for the 4337 transport (the direct path would need \
                 RelayAdapt, not implemented in the SDK yet). Unshield the wrapped token instead."
            );
        }

        // The wrapped token lands on the ephemeral 7702 sender, which unwraps it and forwards the
        // native currency during the execution phase of the same UserOperation.
        let sender = EoaSigner::random();
        let fee = value * u128::from(self.chain.unshield_fee_bps) / 10_000;
        let received = value - fee;
        let calls = vec![
            Call {
                target: token,
                value: U256::ZERO,
                data: WETH9::withdrawCall {
                    wad: U256::from(received),
                }
                .abi_encode()
                .into(),
            },
            Call {
                target: to,
                value: U256::from(received),
                data: Default::default(),
            },
        ];
        let builder = TransactionBuilder::new().unshield(signer, sender.address(), asset_id, value)?;
        self.submit(ctx, builder, transport, calls, Some(sender)).await
    }

    /// Proves and submits a private transaction over the selected transport.
    async fn submit(
        &mut self,
        ctx: &JobCtx<'_>,
        builder: TransactionBuilder,
        transport: Transport,
        calls: Vec<Call>,
        sender: Option<EoaSigner>,
    ) -> Result<Value> {
        let result = match transport {
            Transport::Legacy => {
                if !calls.is_empty() {
                    bail!(
                        "native unshield over the legacy transport needs RelayAdapt, which the \
                         SDK does not build yet. Unshield the wrapped token, or use 4337."
                    );
                }
                self.submit_legacy(ctx, builder).await?
            }
            Transport::Direct => {
                if self.eoa.is_none() {
                    bail!("direct transport needs a public EOA key");
                }
                // Exercises the dummy-proof path the legacy transport will use for fee quotes:
                // same calldata shape, zero proof, estimated from the verification bypass origin.
                match self.estimate_with_dummy_proof(builder.clone(), None).await {
                    Ok(gas) => ctx.step(format!("dummy-proof gas estimate: {gas}")),
                    Err(e) => ctx.step(format!("dummy-proof gas estimate failed (non fatal): {e:#}")),
                }
                ctx.step("building and proving (direct transport)");
                let proved = self.railgun.build(builder, &mut rand::rng()).await?;
                ctx.step(format!("proved {} operation(s)", proved.proved_operations.len()));
                let hash = self.send_eoa(ctx, "transact", proved.tx_data).await?;
                json!({ "transport": "direct", "txHash": hash.to_string() })
            }
            Transport::Erc4337 => {
                let sender = sender.unwrap_or_else(EoaSigner::random);
                let funds_transit = !calls.is_empty();
                if funds_transit {
                    // If the execution phase reverts after the paymaster phase unshielded, the
                    // funds sit on this address. Keep the key before anything is sent.
                    record_ephemeral_sender(&self.data_dir, &sender)?;
                }
                let bundler = PimlicoBundler::new(
                    self.bundler_url
                        .parse()
                        .map_err(|e| anyhow!("invalid bundler url: {e}"))?,
                );
                let account =
                    SimpleSmartAccount::new(sender.address(), self.chain.id, self.provider.clone());
                let railgun_signer = self.signer.clone() as Arc<dyn RailgunSigner>;
                let fee_token = self.chain.wrapped_base_token;
                let (signable, mode) = if self.fee_limits.single_proof {
                    let margin_percent = self
                        .fee_limits
                        .gas_margin_percent
                        .unwrap_or(DEFAULT_GAS_MARGIN_PERCENT)
                        .min(MAX_GAS_MARGIN_PERCENT);
                    match self
                        .simulate_gas_limits(ctx, &builder, &bundler, &account, &calls, margin_percent)
                        .await
                    {
                        Ok(gas) => {
                            ctx.step(format!(
                                "proving once from ephemeral sender {}",
                                sender.address()
                            ));
                            let (signable, report) = self
                                .railgun
                                .prepare_userop_single_proof(
                                    builder,
                                    &bundler as &dyn Bundler,
                                    &account,
                                    railgun_signer,
                                    fee_token,
                                    calls,
                                    gas,
                                    &mut rand::rng(),
                                )
                                .await?;
                            ctx.step(format!(
                                "proved once: paymaster verification measured {} of {} allowed",
                                report.paymaster_verification_measured,
                                report.paymaster_verification_limit
                            ));
                            (signable, "single-proof")
                        }
                        Err(e) if self.fee_limits.single_proof_strict => {
                            return Err(e.context(
                                "gas limits could not be simulated and falling back to several \
                                 signatures is disabled. Nothing was signed",
                            ));
                        }
                        Err(e) => {
                            ctx.step(format!(
                                "gas limits could not be simulated ({e:#}): falling back to the iterative estimate, which signs several times"
                            ));
                            let signable = self
                                .railgun
                                .prepare_userop(
                                    builder,
                                    &bundler as &dyn Bundler,
                                    &account,
                                    railgun_signer,
                                    fee_token,
                                    calls,
                                    &mut rand::rng(),
                                )
                                .await?;
                            (signable, "iterative")
                        }
                    }
                } else {
                    ctx.step(format!(
                        "preparing UserOperation from ephemeral sender {} (proof is regenerated until the fee converges)",
                        sender.address()
                    ));
                    let signable = self
                        .railgun
                        .prepare_userop(
                            builder,
                            &bundler as &dyn Bundler,
                            &account,
                            railgun_signer,
                            fee_token,
                            calls,
                            &mut rand::rng(),
                        )
                        .await?;
                    (signable, "iterative")
                };
                let max_fee = signable.total_gas_limit() * signable.user_op.max_fee_per_gas;
                ctx.step(format!(
                    "fee {} wrapped token ({mode})",
                    trim_decimal(format_units(U256::from(max_fee), 18u8).unwrap_or_default())
                ));
                let signed = signable.sign(&sender).await?;
                let hash = bundler.send_user_operation(&signed).await?;
                ctx.step(format!("UserOperation {:?} sent, waiting for receipt", hash.0));
                let receipt = bundler.wait_for_receipt(hash).await?;
                if !receipt.success {
                    bail!("UserOperation {:?} failed on-chain: {receipt:?}", hash.0);
                }
                json!({
                    "transport": "erc4337",
                    "userOpHash": format!("{:?}", hash.0),
                    "sender": sender.address().to_string(),
                    "maxFeeWei": max_fee.to_string(),
                    "feeMode": mode,
                })
            }
        };
        self.post_tx_sync(ctx).await;
        Ok(result)
    }

    /// Relays through a Railgun community broadcaster: quote, fee from a dummy-proof gas
    /// estimate, proof with the fee note pinned first and `minGasPrice` bound, pre-transaction
    /// POIs, sealed request over Waku.
    async fn submit_legacy(&mut self, ctx: &JobCtx<'_>, builder: TransactionBuilder) -> Result<Value> {
        // Real funds: never pay an uncapped rate. The reference client makes the trusted signer
        // mandatory everywhere; test networks stay usable without one.
        if self.chain.id == 1 && self.broadcaster.trusted_signer_count() == 0 {
            bail!(
                "on mainnet the legacy transport needs a trusted fee signer: reopen the wallet \
                 with the 0zk address of one, so broadcaster rates are capped"
            );
        }
        let fee_token = self.chain.wrapped_base_token;
        let fee_asset = AssetId::Erc20(fee_token);
        let list_keys = self.railgun.poi_list_keys();

        let rate_multiple = self
            .fee_limits
            .max_fee_rate
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .unwrap_or(DEFAULT_MAX_FEE_RATE)
            .to_string();
        // "1.5" with 18 decimals is 1.5 times the par rate of the wrapped base token.
        let max_rate: u128 = parse_units(&rate_multiple, 18u8)
            .ok()
            .and_then(|v| u128::try_from(v.get_absolute()).ok())
            .filter(|v| *v >= PAR_RATE_WRAPPED_BASE_TOKEN / 2)
            .ok_or_else(|| anyhow!("invalid maximum fee rate \"{rate_multiple}\" (expected a multiple of the gas cost such as 1.5)"))?;
        let max_fee: Option<u128> = match self.fee_limits.max_fee.as_deref().map(str::trim) {
            Some(v) if !v.is_empty() => Some(
                parse_units(v, 18u8)
                    .ok()
                    .and_then(|v| u128::try_from(v.get_absolute()).ok())
                    .ok_or_else(|| anyhow!("invalid maximum fee \"{v}\""))?,
            ),
            _ => None,
        };

        let quote: FeeQuote = match self
            .broadcaster
            .best_quote(&fee_token.to_string(), &list_keys, Some(max_rate))
        {
            Ok(quote) => quote,
            Err(NoQuote::AboveCeiling { cheapest, rejected, .. }) => bail!(
                "{rejected} broadcaster offer(s), the cheapest at {} times the gas cost, above \
                 your ceiling of {rate_multiple}. Nothing was sent. Raise the ceiling only if you \
                 accept that price.",
                format_rate(cheapest)
            ),
            Err(e @ NoQuote::PoiListMismatch { .. }) => bail!("{e}. Nothing was sent."),
            Err(NoQuote::None) => bail!(
                "no usable broadcaster offer for the wrapped base token. Either the Waku node \
                 is not on the Railgun shard, or a trusted fee signer is set and has not \
                 announced a rate yet, or every offer is outside its band"
            ),
        };
        let broadcaster_address = RailgunAddress::from_str(&quote.railgun_address)
            .map_err(|e| anyhow!("broadcaster address: {e}"))?;
        ctx.step(format!(
            "broadcaster {}… ({}), rate {} times the gas cost (ceiling {rate_multiple}), quote valid {}s",
            &quote.railgun_address[..quote.railgun_address.len().min(14)],
            quote.identifier.as_deref().unwrap_or("no identifier"),
            format_rate(quote.fee_per_unit_gas),
            quote.expiration.saturating_sub(quote_now_ms()) / 1000,
        ));

        // Broadcasters send type 1 transactions at exactly minGasPrice and refuse a price
        // under half the slow market price: take the node's price plus 10%.
        let gas_price = self.provider.get_gas_price().await.context("eth_gasPrice")? * 11 / 10;

        let signer = self.signer.clone() as Arc<dyn RailgunSigner>;
        let with_fee = |fee: u128| -> Result<TransactionBuilder> {
            Ok(builder
                .clone()
                .broadcaster_fee(signer.clone(), broadcaster_address, fee_asset, fee)?
                .min_gas_price(gas_price))
        };
        let fee_for = |gas: u64| {
            token_fee(quote.fee_per_unit_gas, gas, gas_price)
                .ok_or_else(|| anyhow!("fee overflow"))
        };

        // The fee changes note values, possibly the number of inputs, hence the gas: estimate
        // twice, the second time with a fee of the right magnitude.
        let mut fee = fee_for(FIRST_GUESS_GAS)?;
        let mut gas = 0;
        for round in 1..=2 {
            gas = self
                .estimate_with_dummy_proof(with_fee(fee)?, Some(gas_price))
                .await
                .with_context(|| format!("dummy-proof gas estimate (round {round})"))?;
            fee = fee_for(gas)?;
        }
        ctx.step(format!(
            "gas estimate {gas}, gas price {gas_price} wei, broadcaster fee {} wrapped token",
            trim_decimal(format_units(U256::from(fee), 18u8).unwrap_or_default())
        ));

        if let Some(max_fee) = max_fee {
            if fee > max_fee {
                bail!(
                    "the broadcaster fee would be {} wrapped token, above your maximum of {}. \
                     Nothing was proved or sent.",
                    trim_decimal(format_units(U256::from(fee), 18u8).unwrap_or_default()),
                    trim_decimal(format_units(U256::from(max_fee), 18u8).unwrap_or_default()),
                );
            }
        }

        ctx.step("building and proving (legacy transport)");
        let proved = self.railgun.build(with_fee(fee)?, &mut rand::rng()).await?;
        ctx.step(format!(
            "proved {} operation(s), generating pre-transaction POI",
            proved.proved_operations.len()
        ));
        let pre_transaction_pois = self
            .railgun
            .pre_transaction_pois(&proved.proved_operations)
            .await?;

        if !quote.usable_at(quote_now_ms().saturating_sub(30_000)) {
            bail!("the fee quote expired while proving, run the operation again");
        }

        let sealed = self.broadcaster.seal(
            BroadcastRequest {
                quote: quote.clone(),
                to: proved.tx_data.to.to_checksum(None),
                calldata: proved.tx_data.data.to_vec(),
                min_gas_price: gas_price,
                use_relay_adapt: false,
                pre_transaction_pois,
            },
            &mut rand::rng(),
        )?;

        ctx.step("request sealed and published, waiting for the broadcaster (up to 120s)");
        let client = self.broadcaster.clone();
        let outcome = self
            .io
            .spawn(async move { client.send(&sealed).await })
            .await
            .context("waku task")?;
        match outcome {
            Ok(tx_hash) => {
                ctx.step(format!("broadcaster sent transaction {tx_hash}"));
                Ok(json!({
                    "transport": "legacy",
                    "txHash": tx_hash,
                    "broadcaster": quote.railgun_address,
                    "fee": fee.to_string(),
                    "minGasPrice": gas_price.to_string(),
                }))
            }
            Err(ClientError::Timeout(_)) => bail!(
                "no answer from the broadcaster within 120s. It may still have sent the \
                 transaction: sync and check that the input notes are gone before retrying."
            ),
            Err(e) => Err(e.into()),
        }
    }

    /// Gas limits of the UserOperation, measured before any proof or signature.
    ///
    /// A dummy-proof UserOperation is run through `userop_kit::validation_probe`: an `eth_call`
    /// from the Railgun verification bypass origin, with the probe's code overriding the
    /// EntryPoint, executes account validation, paymaster validation (which performs the
    /// `transact`), the tail calls and `postOp`, and reports the gas of each. Two rounds, since
    /// the fee is an output note and can change the inputs selected. Only `preVerificationGas`
    /// is computed, by the reference formula: it prices inclusion, not execution, and gets twice
    /// the margin because the bundler has the last word on it.
    async fn simulate_gas_limits(
        &mut self,
        ctx: &JobCtx<'_>,
        builder: &TransactionBuilder,
        bundler: &PimlicoBundler,
        account: &SimpleSmartAccount,
        calls: &Vec<Call>,
        margin_percent: u32,
    ) -> Result<UserOperationGasEstimate> {
        use alloy::rpc::types::state::{AccountOverride, StateOverride};
        use userop_kit::validation_probe::{self as probe, pad_gas};

        let price = (bundler as &dyn Bundler)
            .gas_price()
            .await
            .context("asking the bundler for its gas price")?
            .ok_or_else(|| anyhow!("the bundler gives no gas price outside of a simulation"))?;
        let railgun_signer = self.signer.clone() as Arc<dyn RailgunSigner>;
        let fee_token = self.chain.wrapped_base_token;

        // The probe does not enforce limits: they only enter through `maxCost`, against which
        // the paymaster checks the fee. Each round therefore pays exactly its own limits, as the
        // real UserOperation will. Round one starts from plausible figures so that this fee is
        // affordable; round two uses what round one measured.
        let mut gas = UserOperationGasEstimate {
            pre_verification_gas: 150_000,
            verification_gas_limit: 100_000,
            call_gas_limit: if calls.is_empty() { 20_000 } else { 150_000 },
            paymaster_verification_gas_limit: Some(1_200_000),
            paymaster_post_op_gas_limit: Some(50_000),
            max_fee_per_gas: price.max_fee_per_gas,
            max_priority_fee_per_gas: price.max_priority_fee_per_gas,
        };
        let total_of = |g: &UserOperationGasEstimate| {
            g.pre_verification_gas
                + g.verification_gas_limit
                + g.call_gas_limit
                + g.paymaster_verification_gas_limit.unwrap_or(0)
                + g.paymaster_post_op_gas_limit.unwrap_or(0)
        };
        let mut measured = None;
        for _round in 1..=2 {
            let fee = total_of(&gas) * price.max_fee_per_gas;
            let dummy = self
                .railgun
                .dummy_userop(
                    builder.clone(),
                    account,
                    railgun_signer.clone(),
                    fee_token,
                    calls,
                    fee,
                    gas,
                    &mut rand::rng(),
                )
                .await?;
            let max_cost = U256::from(dummy.total_gas_limit()) * U256::from(price.max_fee_per_gas);
            let request = probe::request(&dummy, max_cost);

            let mut overrides = StateOverride::default();
            for (address, code) in &request.code_overrides {
                overrides.insert(*address, AccountOverride::default().with_code(code.clone()));
            }
            if let Some((from, to)) = request.copy_code_from {
                // The 7702 delegation of the fresh sender is not on-chain yet: give it the code
                // it will delegate to.
                let code = self
                    .provider
                    .get_code_at(from)
                    .await
                    .context("reading the account implementation code")?;
                overrides.insert(to, AccountOverride::default().with_code(code));
            }
            overrides.insert(
                railgun::provider::VERIFICATION_BYPASS,
                AccountOverride::default().with_balance(U256::from(10u128.pow(24))),
            );

            let call = alloy::rpc::types::TransactionRequest::default()
                .from(railgun::provider::VERIFICATION_BYPASS)
                .to(request.to)
                .input(request.data.clone().into())
                .gas_limit(25_000_000);
            let answer = self
                .provider
                .call(call)
                .overrides(overrides)
                .await
                .context("eth_call with state overrides (does this RPC support them?)")?;

            let phases = probe::decode(&answer, !calls.is_empty())?;

            let pre_verification = probe::pre_verification_gas(&dummy);
            gas.pre_verification_gas = pad_gas(pre_verification, margin_percent * 2, GAS_BUCKET);
            // The EntryPoint charges its own pre-validation work to this limit (AA26), which the
            // probe cannot see: see `ENTRY_POINT_VALIDATION_OVERHEAD`.
            gas.verification_gas_limit = pad_gas(
                phases.account_validation + probe::ENTRY_POINT_VALIDATION_OVERHEAD,
                margin_percent,
                GAS_BUCKET,
            );
            // Floors: bundlers refuse limits they find implausibly low, even for phases that do
            // nothing, and a refusal after the proof costs a signature. They cost under 3% of fee.
            gas.call_gas_limit = pad_gas(phases.call, margin_percent, GAS_BUCKET).max(30_000);
            gas.paymaster_verification_gas_limit =
                Some(pad_gas(phases.paymaster_validation, margin_percent, GAS_BUCKET));
            gas.paymaster_post_op_gas_limit = Some(if phases.post_op_called {
                pad_gas(phases.post_op, margin_percent, GAS_BUCKET).max(10_000)
            } else {
                10_000
            });
            let total = total_of(&gas);
            measured = Some((phases, pre_verification, total));
        }

        let (phases, pre_verification, total) = measured.expect("two rounds ran");
        ctx.step(format!(
            "simulated before signing: account {}, paymaster {}, calls {}, post-op {}, pre-verification {} (formula); limits with {margin_percent}% margin total {total} gas",
            phases.account_validation, phases.paymaster_validation, phases.call, phases.post_op, pre_verification
        ));
        Ok(gas)
    }

    /// `gas_price` must be the `minGasPrice` bound in the builder, if any: the Railgun contract
    /// compares it to `tx.gasprice`, which is 0 in an estimate that names no price, and reverts
    /// with "Gas price too low". The estimate then runs as the legacy (type 0) transaction the
    /// broadcaster will send.
    async fn estimate_with_dummy_proof(
        &mut self,
        builder: TransactionBuilder,
        gas_price: Option<u128>,
    ) -> Result<u64> {
        let dummy = self.railgun.build_dummy(builder, &mut rand::rng()).await?;
        let mut request: alloy::rpc::types::TransactionRequest = dummy.tx_data.into();
        request = request.from(railgun::provider::VERIFICATION_BYPASS);
        if let Some(gas_price) = gas_price {
            request = request.gas_price(gas_price);
        }
        match self.provider.estimate_gas(request.clone()).await {
            Ok(gas) => Ok(gas),
            // With a gas price, the node caps the gas by the sender's balance, and the bypass
            // address may hold nothing on this chain. Retry with a balance override.
            Err(e) if e.to_string().to_lowercase().contains("insufficient funds") => {
                use alloy::rpc::types::state::{AccountOverride, StateOverride};
                let mut overrides = StateOverride::default();
                overrides.insert(
                    railgun::provider::VERIFICATION_BYPASS,
                    AccountOverride::default().with_balance(U256::from(10u128.pow(24))),
                );
                Ok(self
                    .provider
                    .estimate_gas(request)
                    .overrides(overrides)
                    .await
                    .context("gas estimate with balance override")?)
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn post_tx_sync(&mut self, ctx: &JobCtx<'_>) {
        ctx.step(format!(
            "waiting {}s for indexing, then syncing",
            POST_TX_SYNC_DELAY.as_secs()
        ));
        tokio::time::sleep(POST_TX_SYNC_DELAY).await;
        if let Err(e) = self.railgun.sync().await {
            warn!("post-transaction sync failed (run a manual sync): {e}");
            ctx.step(format!("post-transaction sync failed: {e}"));
        }
    }

    async fn snapshot(&mut self) -> StatusSnapshot {
        let address = self.signer.address();

        let mut balances = Vec::new();
        for entry in self.railgun.balance(address).await {
            let mut view = json!({
                "asset": entry.asset.to_string(),
                "amount": entry.amount.to_string(),
                "poiStatus": entry.poi_status,
            });
            if let AssetId::Erc20(token) = entry.asset {
                let meta = self.token_meta(token).await;
                view["token"] = json!(token.to_string());
                view["symbol"] = json!(meta.symbol);
                view["decimals"] = json!(meta.decimals);
                view["formatted"] = json!(trim_decimal(
                    format_units(U256::from(entry.amount), meta.decimals).unwrap_or_default()
                ));
            }
            balances.push(view);
        }
        balances.sort_by_key(|v| v["asset"].as_str().map(str::to_owned));

        let notes = self
            .railgun
            .notes(address)
            .await
            .into_iter()
            .map(|n| {
                json!({
                    "asset": n.asset.to_string(),
                    "amount": n.amount.to_string(),
                    "poiStatus": n.poi_status,
                    "treeNumber": n.tree_number,
                    "leafIndex": n.leaf_index,
                    "blindedCommitment": n.blinded_commitment,
                    "commitmentType": n.commitment_type,
                    "memo": n.memo,
                })
            })
            .collect();

        let eoa = self.eoa.as_ref().map(EoaSigner::address);
        let eoa_balance = match eoa {
            Some(a) => self
                .provider
                .get_balance(a)
                .await
                .ok()
                .and_then(|b| format_units(b, 18u8).ok())
                .map(trim_decimal),
            None => None,
        };

        let has_paymaster =
            self.chain.privacy_paymaster.is_some() && self.chain.railgun_fee_adapter.is_some();
        let transports = vec![
            TransportInfo {
                id: "erc4337",
                label: "4337",
                enabled: has_paymaster,
                note: if has_paymaster {
                    "UserOperation via privacy paymaster, fee paid in shielded wrapped base token"
                        .into()
                } else {
                    "no privacy paymaster deployed on this chain".into()
                },
            },
            TransportInfo {
                id: "legacy",
                label: "legacy",
                // The front turns it on from the live broadcaster status.
                enabled: false,
                note: "Railgun community broadcasters over Waku, fee paid in shielded wrapped base token".into(),
            },
            TransportInfo {
                id: "direct",
                label: "direct (debug)",
                enabled: eoa.is_some(),
                note: "self-broadcast from the public EOA, links the EOA to the transaction".into(),
            },
        ];

        StatusSnapshot {
            unlocked: true,
            chain_id: Some(self.chain.id),
            address: Some(address.to_string()),
            derivation: Some(self.derivation.to_string()),
            eoa: eoa.map(|a| a.to_string()),
            eoa_balance,
            poi: self.railgun.poi_enabled(),
            poi_list_keys: self.railgun.poi_list_keys(),
            synced_block: Some(self.railgun.synced_block()),
            wrapped_base_token: Some(self.chain.wrapped_base_token.to_string()),
            railgun_smart_wallet: Some(self.chain.railgun_smart_wallet.to_string()),
            bundler_url: Some(self.bundler_url.clone()),
            transports,
            balances,
            notes,
            poi_pending: self
                .railgun
                .poi_pending()
                .into_iter()
                .filter_map(|p| serde_json::to_value(p).ok())
                .collect(),
            updated_at: now_ms(),
        }
    }
}

/// Rate as a multiple of the gas cost, two decimals: 1.12e18 -> "1.12".
fn format_rate(rate: u128) -> String {
    let hundredths = rate / (PAR_RATE_WRAPPED_BASE_TOKEN / 100);
    format!("{}.{:02}", hundredths / 100, hundredths % 100)
}

/// "1.500000" -> "1.5", "2.000" -> "2".
fn trim_decimal(s: String) -> String {
    if !s.contains('.') {
        return s;
    }
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// Appends the ephemeral sender key to `<data_dir>/ephemeral_senders.jsonl` (mode 0600).
fn record_ephemeral_sender(data_dir: &Path, sender: &EoaSigner) -> Result<()> {
    std::fs::create_dir_all(data_dir)?;
    let path = data_dir.join("ephemeral_senders.jsonl");
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&path).context("opening ephemeral sender log")?;
    let line = json!({
        "ts": now_ms(),
        "address": sender.address().to_string(),
        "privateKey": format!("0x{}", hex::encode(sender.to_bytes())),
    });
    writeln!(file, "{line}")?;
    file.sync_all()?;
    Ok(())
}
