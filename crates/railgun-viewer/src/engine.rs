//! Engine actor. One thread, one current-thread runtime, owns the `RailgunProvider` (its futures
//! are not `Send`). Commands arrive over a channel; results land in `Shared`.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
};

use alloy::{
    network::Ethereum,
    primitives::{Address, U256},
    providers::{DynProvider, Provider, ProviderBuilder},
};
use anyhow::{Context, Result, anyhow, bail};
use railgun::{
    account::{
        address::RailgunAddress,
        signer::{PrivateKeySigner as RgSigner, RailgunSigner},
    },
    builder::RailgunBuilder,
    caip::AssetId,
    chain_config::ChainConfig,
    note::{sent::SentNote, utxo::{UtxoNote, blinded_commitment}},
    provider::RailgunProvider,
};
use railgun_wallet::db::WalletDb;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info};

use crate::{
    chain::{self, ChainRef, Squid, TokenMeta},
    history::{self, NoteIn, OpIn, SentIn},
    keys::{self, Credentials, Resolved},
    shared::{SharedRef, log, now_ms},
    signer::{MasterSigner, SpubSigner},
};

fn default_rpc_url(chain_id: u64) -> Option<&'static str> {
    match chain_id {
        1 => Some("https://ethereum-rpc.publicnode.com"),
        11155111 => Some("https://ethereum-sepolia-rpc.publicnode.com"),
        _ => None,
    }
}

fn explorer(chain_id: u64) -> String {
    match chain_id {
        1 => "https://etherscan.io/tx/",
        11155111 => "https://sepolia.etherscan.io/tx/",
        137 => "https://polygonscan.com/tx/",
        42161 => "https://arbiscan.io/tx/",
        56 => "https://bscscan.com/tx/",
        _ => "",
    }
    .to_string()
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UnlockParams {
    #[serde(flatten)]
    pub credentials: Credentials,
    pub chain_id: u64,
    pub rpc_url: Option<String>,
    #[serde(default = "default_true")]
    pub poi: bool,
    #[serde(default = "default_true")]
    pub sync_now: bool,
}

fn default_true() -> bool {
    true
}

pub enum Command {
    Unlock(Box<UnlockParams>, oneshot::Sender<Result<()>>),
    Sync,
    Refresh,
    Lock(oneshot::Sender<()>),
}

#[derive(Clone)]
pub struct Engine {
    tx: mpsc::UnboundedSender<Command>,
}

impl Engine {
    pub async fn unlock(&self, p: UnlockParams) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Command::Unlock(Box::new(p), tx))
            .map_err(|_| anyhow!("engine thread is gone"))?;
        rx.await.map_err(|_| anyhow!("engine dropped the request"))?
    }

    pub fn sync(&self) -> Result<()> {
        self.tx.send(Command::Sync).map_err(|_| anyhow!("engine thread is gone"))
    }

    pub fn refresh(&self) -> Result<()> {
        self.tx.send(Command::Refresh).map_err(|_| anyhow!("engine thread is gone"))
    }

    pub async fn lock(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(Command::Lock(tx)).map_err(|_| anyhow!("engine thread is gone"))?;
        rx.await.map_err(|_| anyhow!("engine dropped the request"))
    }
}

pub fn spawn(base_dir: PathBuf, shared: SharedRef) -> Engine {
    let (tx, mut rx) = mpsc::unbounded_channel::<Command>();
    std::thread::Builder::new()
        .name("railgun-viewer-engine".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("engine runtime");
            rt.block_on(async move {
                let mut actor = Actor {
                    base_dir,
                    shared,
                    session: None,
                };
                while let Some(cmd) = rx.recv().await {
                    actor.handle(cmd).await;
                }
            });
        })
        .expect("engine thread");
    Engine { tx }
}

struct Session {
    chain: ChainConfig,
    provider: DynProvider,
    railgun: RailgunProvider,
    signer: Arc<dyn RailgunSigner>,
    address: RailgunAddress,
    mode: &'static str,
    data_dir: PathBuf,
    squid: Squid,
    tokens: HashMap<String, TokenMeta>,
    commitment_refs: HashMap<String, ChainRef>,
    nullifier_refs: HashMap<String, ChainRef>,
}

struct Actor {
    base_dir: PathBuf,
    shared: SharedRef,
    session: Option<Session>,
}

impl Actor {
    async fn handle(&mut self, cmd: Command) {
        match cmd {
            Command::Unlock(p, reply) => {
                let sync_now = p.sync_now;
                let res = self.unlock(*p).await;
                if let Err(e) = &res {
                    self.set_error(format!("unlock: {e:#}"));
                }
                let _ = reply.send(res);
                if sync_now && self.session.is_some() {
                    self.sync().await;
                }
            }
            Command::Sync => self.sync().await,
            Command::Refresh => self.refresh_snapshot().await,
            Command::Lock(reply) => {
                self.session = None;
                if let Ok(mut s) = self.shared.lock() {
                    *s = Default::default();
                    s.updated_at = now_ms();
                }
                let _ = reply.send(());
            }
        }
    }

    fn set_error(&self, msg: String) {
        error!("{msg}");
        if let Ok(mut s) = self.shared.lock() {
            s.last_error = Some(msg.clone());
            s.log.push(format!("✗ {msg}"));
            s.updated_at = now_ms();
        }
    }

    async fn unlock(&mut self, p: UnlockParams) -> Result<()> {
        let chain = ChainConfig::from_chain_id(p.chain_id)
            .ok_or_else(|| anyhow!("unsupported chain id {}", p.chain_id))?;
        let resolved = keys::resolve(&p.credentials)?;
        let mode = resolved.mode();
        let signer: Arc<dyn RailgunSigner> = match resolved {
            Resolved::Full {
                spending, viewing, ..
            } => RgSigner::new_evm(spending, viewing, chain.id),
            Resolved::ViewOnlySpub {
                viewing,
                spending_pub,
            } => SpubSigner::new(viewing, spending_pub, chain.id),
            Resolved::ViewOnlyMaster { viewing, master } => {
                MasterSigner::new(viewing, master, chain.id)
            }
        };
        let address = signer.address();

        let rpc_url = match p.rpc_url.as_deref().map(str::trim) {
            Some(u) if !u.is_empty() => u.to_string(),
            _ => default_rpc_url(chain.id)
                .ok_or_else(|| anyhow!("no default RPC for chain {}", chain.id))?
                .to_string(),
        };
        if !(rpc_url.starts_with("http://") || rpc_url.starts_with("https://")) {
            bail!("RPC URL must start with http(s)://, got \"{rpc_url}\"");
        }
        let provider = ProviderBuilder::new()
            .network::<Ethereum>()
            .connect(&rpc_url)
            .await
            .context("connecting to RPC")?
            .erased();
        let rpc_chain = provider.get_chain_id().await.context("eth_chainId")?;
        if rpc_chain != chain.id {
            bail!("RPC is on chain {rpc_chain}, expected {}", chain.id);
        }

        // Same layout as railgun-wallet: <data-dir>/<chain>/<sha256(address)[..8]>/db-v2.
        let tag = hex::encode(&Sha256::digest(address.to_string().as_bytes())[..8]);
        let data_dir = self.base_dir.join(chain.id.to_string()).join(tag);
        let db = Arc::new(WalletDb::new(data_dir.join("db-v2"))?);

        let mut builder = RailgunBuilder::new(chain.clone(), provider.clone()).with_database(db);
        if p.poi {
            builder = if mode == "full" {
                builder.with_poi()
            } else {
                builder.with_poi_read_only()
            };
        }
        let mut railgun = builder.build().await.context("building railgun provider")?;
        railgun.register(signer.clone()).await?;

        let (commitment_refs, nullifier_refs) = load_cache(&data_dir);
        info!(%address, chain = chain.id, mode, poi = p.poi, rpc = %rpc_url, "viewer unlocked");
        log(
            &self.shared,
            format!("✓ {mode} · {address} · chain {} · POI {}", chain.id, if p.poi { "on" } else { "off" }),
        );
        let squid = Squid::new(chain.subsquid_endpoint.clone());
        self.session = Some(Session {
            chain,
            provider,
            railgun,
            signer,
            address,
            mode,
            data_dir,
            squid,
            tokens: HashMap::new(),
            commitment_refs,
            nullifier_refs,
        });
        if let Ok(mut s) = self.shared.lock() {
            s.unlocked = true;
            s.address = Some(address.to_string());
            s.mode = Some(mode);
            s.chain_id = Some(p.chain_id);
            s.last_error = None;
            s.updated_at = now_ms();
        }
        Ok(())
    }

    async fn sync(&mut self) {
        let Some(session) = self.session.as_mut() else {
            self.set_error("sync: not unlocked".into());
            return;
        };
        if let Ok(mut s) = self.shared.lock() {
            s.syncing = true;
            s.updated_at = now_ms();
        }
        log(&self.shared, "sync: scanning commitments, nullifiers and POI statuses…");
        let res = session.railgun.sync().await;
        match res {
            Ok(()) => log(
                &self.shared,
                format!("✓ synced to block {}", session.railgun.synced_block()),
            ),
            Err(e) => self.set_error(format!("sync failed: {e:#}")),
        }
        self.refresh_snapshot().await;
        if let Ok(mut s) = self.shared.lock() {
            s.syncing = false;
            s.updated_at = now_ms();
        }
    }

    async fn refresh_snapshot(&mut self) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        match build_history(session).await {
            Ok(h) => {
                if let Ok(mut s) = self.shared.lock() {
                    s.synced_block = Some(session.railgun.synced_block());
                    s.snapshot = serde_json::to_value(&h).ok();
                    s.updated_at = now_ms();
                }
                log(
                    &self.shared,
                    format!(
                        "history: {} transaction(s), {} note(s), {} emitted without POI, {} pending",
                        h.transactions.len(),
                        h.notes.len(),
                        h.missing_poi.len(),
                        h.pending_poi.len()
                    ),
                );
            }
            Err(e) => self.set_error(format!("history: {e:#}")),
        }
    }
}

fn hex64(v: U256) -> String {
    format!("0x{v:064x}")
}

fn cache_path(dir: &PathBuf) -> PathBuf {
    dir.join("viewer-cache.json")
}

fn load_cache(dir: &PathBuf) -> (HashMap<String, ChainRef>, HashMap<String, ChainRef>) {
    let Ok(bytes) = std::fs::read(cache_path(dir)) else {
        return Default::default();
    };
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    let take = |k: &str| -> HashMap<String, ChainRef> {
        v.get(k)
            .cloned()
            .and_then(|x| serde_json::from_value(x).ok())
            .unwrap_or_default()
    };
    (take("commitments"), take("nullifiers"))
}

fn save_cache(session: &Session) {
    let v = serde_json::json!({
        "commitments": session.commitment_refs,
        "nullifiers": session.nullifier_refs,
    });
    if let Err(e) = std::fs::create_dir_all(&session.data_dir)
        .and_then(|_| std::fs::write(cache_path(&session.data_dir), serde_json::to_vec(&v).unwrap_or_default()))
    {
        tracing::warn!("cannot write viewer cache: {e}");
    }
}

fn note_in(n: &UtxoNote, spent: bool) -> NoteIn {
    let hash: U256 = U256::from(n.hash);
    let token = match n.asset {
        AssetId::Erc20(a) => Some(format!("{a:?}")),
        #[allow(unreachable_patterns)]
        _ => None,
    };
    NoteIn {
        hash: hex64(hash),
        tree: n.tree_number,
        leaf: n.leaf_index,
        value: n.value,
        token,
        token_hash: hex64(n.asset.hash()),
        memo: n.memo.clone(),
        commitment_type: serde_json::to_value(&n.commitment_type)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| format!("{:?}", n.commitment_type)),
        npk: hex64(n.note_public_key),
        random: format!("0x{}", hex::encode(n.random)),
        nullifier: hex64(n.nullifier),
        blinded: hex64(n.blinded_commitment),
        spent,
    }
}

fn sent_in(s: &SentNote) -> SentIn {
    SentIn {
        hash: hex64(s.hash),
        tree: s.tree_number,
        leaf: s.leaf_index,
        value: s.value,
        token_hash: hex64(s.token_hash),
        npk: hex64(s.note_public_key),
        blinded: hex64(blinded_commitment(s.hash, s.note_public_key, s.tree_number, s.leaf_index)),
    }
}

async fn build_history(session: &mut Session) -> Result<history::History> {
    let state = session
        .railgun
        .account_state(session.address)
        .ok_or_else(|| anyhow!("account not registered"))?;

    let mut notes: Vec<NoteIn> = state.notes.iter().map(|n| note_in(n, false)).collect();
    notes.extend(state.spent.iter().map(|n| note_in(n, true)));
    let sent: Vec<SentIn> = state.sent.iter().map(sent_in).collect();

    let ops: Vec<OpIn> = session
        .railgun
        .own_operations()
        .into_iter()
        .map(|(rid, op)| OpIn {
            railgun_txid: rid,
            block_number: op.block_number,
            nullifiers: op.nullifiers.iter().map(|n| hex64(*n)).collect(),
            commitments: op.commitment_hashes.iter().map(|c| hex64(*c)).collect(),
            bound_params_hash: hex64(op.bound_params_hash),
            utxo_tree_in: op.utxo_tree_in,
            utxo_tree_out: op.utxo_tree_out,
            utxo_out_start_index: op.utxo_out_start_index,
            has_unshield: op.has_unshield,
        })
        .collect();

    let mut statuses: HashMap<String, std::collections::BTreeMap<String, String>> = HashMap::new();
    for (blinded, lists) in session.railgun.poi_statuses() {
        let entry = statuses.entry(blinded).or_default();
        for (list, status) in lists {
            let s = status
                .and_then(|st| serde_json::to_value(st).ok())
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_else(|| "Unknown".into());
            entry.insert(list, s);
        }
    }
    let pending: Vec<Value> = session
        .railgun
        .poi_pending()
        .into_iter()
        .filter_map(|p| serde_json::to_value(p).ok())
        .collect();
    let list_keys = session.railgun.poi_list_keys();

    // Token addresses by token hash, and metadata.
    let mut tokens_by_hash: HashMap<String, String> = HashMap::new();
    for n in &notes {
        if let Some(t) = &n.token {
            tokens_by_hash.insert(n.token_hash.clone(), t.to_ascii_lowercase());
        }
    }
    let mut wanted: Vec<String> = tokens_by_hash.values().cloned().collect();
    wanted.push(format!("{:?}", session.chain.wrapped_base_token));
    wanted.sort();
    wanted.dedup();
    for t in wanted {
        if !session.tokens.contains_key(&t) {
            if let Ok(addr) = t.parse::<Address>() {
                let meta = chain::token_meta(&session.provider, addr).await;
                session.tokens.insert(t.clone(), meta);
            }
        }
    }

    // Chain references (subsquid), cached on disk.
    let mut missing: Vec<String> = notes
        .iter()
        .map(|n| n.hash.clone())
        .chain(sent.iter().map(|s| s.hash.clone()))
        .filter(|h| !session.commitment_refs.contains_key(h))
        .collect();
    missing.sort();
    missing.dedup();
    if !missing.is_empty() {
        let found = session.squid.commitments(&missing).await;
        session.commitment_refs.extend(found);
    }
    let mut missing_nf: Vec<String> = notes
        .iter()
        .filter(|n| n.spent)
        .map(|n| n.nullifier.clone())
        .filter(|n| !session.nullifier_refs.contains_key(n))
        .collect();
    missing_nf.sort();
    missing_nf.dedup();
    if !missing_nf.is_empty() {
        let found = session.squid.nullifiers(&missing_nf).await;
        session.nullifier_refs.extend(found);
    }
    save_cache(session);

    let mut tx_hashes: Vec<String> = ops
        .iter()
        .filter(|op| op.has_unshield)
        .filter_map(|op| {
            op.nullifiers
                .iter()
                .find_map(|n| session.nullifier_refs.get(n))
                .and_then(|r| r.transaction_hash.clone())
        })
        .collect();
    tx_hashes.sort();
    tx_hashes.dedup();
    let unshields = if tx_hashes.is_empty() {
        vec![]
    } else {
        session.squid.unshields(&tx_hashes).await
    };
    let mut token_meta = session.tokens.clone();
    for u in &unshields {
        if let Some(t) = &u.token_address {
            let t = t.to_ascii_lowercase();
            if !token_meta.contains_key(&t) {
                if let Ok(addr) = t.parse::<Address>() {
                    let meta = chain::token_meta(&session.provider, addr).await;
                    session.tokens.insert(t.clone(), meta.clone());
                    token_meta.insert(t, meta);
                }
            }
        }
    }

    let input = history::Input {
        address: session.address.to_string(),
        chain_id: session.chain.id,
        explorer: explorer(session.chain.id),
        list_keys,
        notes,
        sent,
        ops,
        statuses,
        pending,
        tokens_by_hash,
        token_meta,
        commitment_refs: session.commitment_refs.clone(),
        nullifier_refs: session.nullifier_refs.clone(),
        unshields,
    };
    let _ = &session.signer;
    let _ = session.mode;
    Ok(history::build(&input))
}
