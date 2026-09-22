//! Chain-side enrichment: block numbers, timestamps, transaction hashes and unshield details
//! from the Railgun subsquid (the SDK keeps none of them), plus ERC-20 metadata over RPC.

use std::collections::HashMap;

use alloy::{
    primitives::{Address, U256},
    providers::DynProvider,
    sol,
};
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{Value, json};

sol! {
    #[sol(rpc)]
    contract ERC20 {
        function decimals() external view returns (uint8);
        function symbol() external view returns (string);
    }
}

#[derive(Clone, Debug, Default, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenMeta {
    pub symbol: String,
    pub decimals: u8,
}

pub async fn token_meta(provider: &DynProvider, token: Address) -> TokenMeta {
    let erc20 = ERC20::new(token, provider.clone());
    let symbol = erc20.symbol().call().await.unwrap_or_else(|_| format!("{token:#x}"));
    let decimals = erc20.decimals().call().await.unwrap_or(18);
    TokenMeta { symbol, decimals }
}

/// Where a commitment or a nullifier landed on chain.
#[derive(Clone, Debug, Default, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainRef {
    pub block_number: u64,
    pub timestamp: Option<u64>,
    pub transaction_hash: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnshieldRef {
    pub transaction_hash: String,
    pub block_number: u64,
    pub timestamp: Option<u64>,
    pub to: String,
    pub token_address: Option<String>,
    pub amount: String,
    pub fee: String,
    pub event_log_index: Option<u64>,
}

/// Subsquid lookups, best effort: any failure leaves the entry absent.
pub struct Squid {
    client: reqwest::Client,
    endpoint: String,
}

#[derive(Deserialize)]
struct GqlResponse<T> {
    data: Option<T>,
    errors: Option<Vec<Value>>,
}

#[derive(Deserialize)]
struct CommitmentsData {
    commitments: Vec<SquidCommitment>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SquidCommitment {
    hash: String,
    block_number: String,
    block_timestamp: Option<String>,
    transaction_hash: Option<String>,
}
#[derive(Deserialize)]
struct NullifiersData {
    nullifiers: Vec<SquidNullifier>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SquidNullifier {
    nullifier: String,
    block_number: String,
    block_timestamp: Option<String>,
    transaction_hash: Option<String>,
}
#[derive(Deserialize)]
struct UnshieldsData {
    unshields: Vec<SquidUnshield>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SquidUnshield {
    block_number: String,
    block_timestamp: Option<String>,
    transaction_hash: String,
    to: String,
    token: Option<SquidToken>,
    amount: String,
    fee: String,
    event_log_index: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SquidToken {
    token_address: Option<String>,
}

fn parse_u64(s: &str) -> Option<u64> {
    s.trim().parse::<u64>().ok()
}

fn norm_hex(s: &str) -> String {
    let t = s.trim().trim_start_matches("0x").to_ascii_lowercase();
    format!("0x{:0>64}", t)
}

/// Subsquid stores hashes as decimal strings and nullifiers as hex.
fn to_decimal(hex_or_dec: &str) -> String {
    let t = hex_or_dec.trim();
    match U256::from_str_radix(t.trim_start_matches("0x"), 16) {
        Ok(v) if t.starts_with("0x") => v.to_string(),
        _ => t.to_string(),
    }
}

impl Squid {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            endpoint: endpoint.into(),
        }
    }

    async fn query<T: serde::de::DeserializeOwned>(&self, query: &str, vars: Value) -> Result<T> {
        let body = serde_json::to_vec(&json!({ "query": query, "variables": vars }))?;
        let resp = self
            .client
            .post(&self.endpoint)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .context("subsquid request")?;
        let bytes = resp.bytes().await.context("subsquid body")?;
        let parsed: GqlResponse<T> = serde_json::from_slice(&bytes).context("subsquid json")?;
        if let Some(errs) = parsed.errors {
            if !errs.is_empty() {
                anyhow::bail!("subsquid: {}", serde_json::to_string(&errs).unwrap_or_default());
            }
        }
        parsed.data.context("subsquid: empty data")
    }

    /// Commitment hash (0x + 64 hex) -> chain reference.
    pub async fn commitments(&self, hashes: &[String]) -> HashMap<String, ChainRef> {
        let mut out = HashMap::new();
        for chunk in hashes.chunks(200) {
            let decimals: Vec<String> = chunk.iter().map(|h| to_decimal(h)).collect();
            let q = "query Q($hashes: [BigInt!]) { commitments(where: {hash_in: $hashes}, limit: 1000) \
                     { hash blockNumber blockTimestamp transactionHash } }";
            match self.query::<CommitmentsData>(q, json!({ "hashes": decimals })).await {
                Ok(data) => {
                    for c in data.commitments {
                        let key = match U256::from_str_radix(c.hash.trim_start_matches("0x"), 10) {
                            Ok(v) => format!("0x{v:064x}"),
                            Err(_) => norm_hex(&c.hash),
                        };
                        out.insert(
                            key,
                            ChainRef {
                                block_number: parse_u64(&c.block_number).unwrap_or_default(),
                                timestamp: c.block_timestamp.as_deref().and_then(parse_u64),
                                transaction_hash: c.transaction_hash,
                            },
                        );
                    }
                }
                Err(e) => tracing::warn!("subsquid commitments lookup failed: {e}"),
            }
        }
        out
    }

    /// Nullifier (0x + 64 hex) -> chain reference.
    pub async fn nullifiers(&self, nullifiers: &[String]) -> HashMap<String, ChainRef> {
        let mut out = HashMap::new();
        for chunk in nullifiers.chunks(200) {
            let hexes: Vec<String> = chunk.iter().map(|n| norm_hex(n)).collect();
            let q = "query Q($n: [Bytes!]) { nullifiers(where: {nullifier_in: $n}, limit: 1000) \
                     { nullifier blockNumber blockTimestamp transactionHash } }";
            match self.query::<NullifiersData>(q, json!({ "n": hexes })).await {
                Ok(data) => {
                    for n in data.nullifiers {
                        out.insert(
                            norm_hex(&n.nullifier),
                            ChainRef {
                                block_number: parse_u64(&n.block_number).unwrap_or_default(),
                                timestamp: n.block_timestamp.as_deref().and_then(parse_u64),
                                transaction_hash: n.transaction_hash,
                            },
                        );
                    }
                }
                Err(e) => tracing::warn!("subsquid nullifiers lookup failed: {e}"),
            }
        }
        out
    }

    /// Unshield events of the given transaction hashes.
    pub async fn unshields(&self, tx_hashes: &[String]) -> Vec<UnshieldRef> {
        let mut out = Vec::new();
        for chunk in tx_hashes.chunks(100) {
            let q = "query Q($t: [Bytes!]) { unshields(where: {transactionHash_in: $t}, limit: 1000) \
                     { blockNumber blockTimestamp transactionHash to token { tokenAddress } amount fee eventLogIndex } }";
            match self.query::<UnshieldsData>(q, json!({ "t": chunk })).await {
                Ok(data) => {
                    for u in data.unshields {
                        out.push(UnshieldRef {
                            transaction_hash: u.transaction_hash.to_ascii_lowercase(),
                            block_number: parse_u64(&u.block_number).unwrap_or_default(),
                            timestamp: u.block_timestamp.as_deref().and_then(parse_u64),
                            to: u.to,
                            token_address: u.token.and_then(|t| t.token_address),
                            amount: u.amount,
                            fee: u.fee,
                            event_log_index: u.event_log_index.as_deref().and_then(parse_u64),
                        });
                    }
                }
                Err(e) => tracing::warn!("subsquid unshields lookup failed: {e}"),
            }
        }
        out
    }
}
