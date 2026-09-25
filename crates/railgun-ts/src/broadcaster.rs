//! Legacy transport in the browser: Railgun broadcasters reached through the Rust Waku light node
//! (`waku-light` compiled to wasm, over the browser's WebSocket), no js-waku. Same flow as the
//! native wallet engine: trusted-signer fee band, quote draw among the near-cheapest, fee
//! convergence on dummy-proof gas estimates, one real proof (one hardware signature),
//! pre-transaction POIs, sealed request, answer from the broadcaster.

use std::{str::FromStr, sync::Arc};

use railgun::{account::address::RailgunAddress, caip::AssetId, provider::VERIFICATION_BYPASS};
use railgun_broadcaster::{
    BroadcastRequest, BroadcasterClient, ClientError, LightNodeTransport, NoQuote,
    PAR_RATE_WRAPPED_BASE_TOKEN, RAILWAY_TRUSTED_FEE_SIGNERS, WakuTransport, token_fee,
};
use serde::Serialize;
use wasm_bindgen::{JsError, JsValue, prelude::wasm_bindgen};

use crate::{
    provider::JsRailgunProvider, signer::JsRailgunSigner, transaction_builder::JsTransactionBuilder,
};

/// First fee guess before the gas is known (the wallet uses the same value).
const FIRST_GUESS_GAS: u64 = 700_000;
/// Offers within this percentage of the cheapest are drawn at random.
const DRAW_PERCENT: u32 = 10;
/// Default ceiling, as a multiple of the gas cost at par for the wrapped base token.
const DEFAULT_MAX_RATE_MULTIPLE: f64 = 1.5;

fn err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn now_ms() -> f64 {
    js_sys::Date::now()
}

async fn sleep_ms(ms: u32) {
    gloo_timers::future::TimeoutFuture::new(ms).await;
}

/// Broadcaster discovery over the Rust Waku light node, one per chain.
#[wasm_bindgen(js_name = "Broadcasters")]
pub struct JsBroadcasters {
    client: Arc<BroadcasterClient>,
}

#[wasm_bindgen(js_class = "Broadcasters")]
impl JsBroadcasters {
    /// Client for `chainId`, with offers restricted to the band of Railway's trusted fee signers.
    /// The node itself starts on the first [`Self::refresh`].
    pub fn connect(#[wasm_bindgen(js_name = "chainId")] chain_id: u64) -> Result<JsBroadcasters, JsError> {
        let transport: Arc<dyn WakuTransport> = Arc::new(LightNodeTransport::for_chain(chain_id));
        let signers: Vec<String> = RAILWAY_TRUSTED_FEE_SIGNERS.iter().map(|s| s.to_string()).collect();
        let client = BroadcasterClient::with_trusted_signers(transport, chain_id, &signers).map_err(err)?;
        Ok(Self { client: Arc::new(client) })
    }

    /// Subscribes to the fee topics (retrying while the node dials the fleet, up to `timeoutMs`,
    /// 60 s by default), then collects fee messages for `listenMs`. Returns the number received.
    pub async fn refresh(
        &self,
        #[wasm_bindgen(js_name = "listenMs")] listen_ms: u32,
        #[wasm_bindgen(js_name = "timeoutMs")] timeout_ms: Option<u32>,
    ) -> Result<u32, JsError> {
        let deadline = now_ms() + timeout_ms.unwrap_or(60_000) as f64;
        loop {
            match self.client.subscribe().await {
                Ok(()) => break,
                Err(_) if now_ms() < deadline => sleep_ms(1000).await,
                Err(e) => return Err(JsError::new(&format!("Waku node not ready: {e}"))),
            }
        }
        let end = now_ms() + listen_ms as f64;
        let mut received = 0u32;
        while now_ms() < end {
            // the node reconnects by itself when a fleet node drops it: keep listening
            if let Ok(n) = self.client.pump().await {
                received += n as u32;
            }
            sleep_ms(500).await;
        }
        Ok(received)
    }

    /// Connected Waku peers, when the node can tell.
    #[wasm_bindgen(js_name = "peerCount")]
    pub async fn peer_count(&self) -> Option<u32> {
        self.client.peer_count().await.map(|p| p as u32)
    }

    /// Offers currently usable (railgunAddress, token, feePerUnitGas, expiration, …).
    pub fn quotes(&self) -> Result<JsValue, JsError> {
        serde_wasm_bindgen::to_value(&self.client.all_quotes()).map_err(err)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LegacyOutcome {
    tx_hash: String,
    broadcaster: String,
    fee: String,
    gas: u64,
    min_gas_price: String,
}

#[wasm_bindgen(js_class = "RailgunProvider")]
impl JsRailgunProvider {
    /// Sends the transaction through a Railgun broadcaster (legacy transport), over the Rust Waku
    /// node of `broadcasters`. `feePayer` pays the broadcaster in the wrapped base token; the
    /// fee is capped at `maxRateMultiple` times the gas cost (1.5 by default). The transaction is
    /// proved, hence signed on a hardware wallet, once. Resolves to
    /// `{ txHash, broadcaster, fee, gas, minGasPrice }`.
    #[wasm_bindgen(js_name = "sendViaBroadcaster")]
    pub async fn send_via_broadcaster(
        &mut self,
        builder: JsTransactionBuilder,
        broadcasters: &JsBroadcasters,
        #[wasm_bindgen(js_name = "feePayer")] fee_payer: &JsRailgunSigner,
        #[wasm_bindgen(js_name = "maxRateMultiple")] max_rate_multiple: Option<f64>,
    ) -> Result<JsValue, JsError> {
        let client = broadcasters.client.clone();
        let fee_token = self.inner.chain().wrapped_base_token;
        let fee_asset = AssetId::Erc20(fee_token);
        let list_keys = self.inner.poi_list_keys();

        let multiple = max_rate_multiple.unwrap_or(DEFAULT_MAX_RATE_MULTIPLE);
        if !(multiple.is_finite() && multiple >= 0.5) {
            return Err(JsError::new("maxRateMultiple must be at least 0.5 (a multiple of the gas cost)"));
        }
        let max_rate = (multiple * PAR_RATE_WRAPPED_BASE_TOKEN as f64) as u128;

        let quote = client
            .select_quote(&fee_token.to_string(), &list_keys, Some(max_rate), DRAW_PERCENT, &[], |n| {
                use rand::RngExt;
                rand::rng().random_range(0..n.max(1))
            })
            .map_err(|e| match e {
                NoQuote::None => JsError::new(
                    "no usable broadcaster offer for the wrapped base token (refresh the broadcasters \
                     first; a trusted fee signer may not have announced a rate yet)",
                ),
                other => JsError::new(&format!("{other}. Nothing was sent.")),
            })?;
        let broadcaster = RailgunAddress::from_str(&quote.railgun_address)
            .map_err(|e| JsError::new(&format!("broadcaster address: {e}")))?;

        // Broadcasters send at exactly minGasPrice and refuse less than half the slow market
        // price: the node's price plus 10 %, as in the wallet.
        let eth = self.inner.eth_provider();
        let gas_price = eth.gas_price().await.map_err(err)? * 11 / 10;

        let signer = fee_payer.inner();
        let with_fee = |fee: u128| {
            builder
                .inner
                .clone()
                .broadcaster_fee(signer.clone(), broadcaster, fee_asset.clone(), fee)
                .map(|b| b.min_gas_price(gas_price))
                .map_err(err)
        };
        let fee_for = |gas: u64| {
            token_fee(quote.fee_per_unit_gas, gas, gas_price).ok_or_else(|| JsError::new("fee overflow"))
        };

        // The fee changes note values, possibly the number of inputs, hence the gas: estimate
        // twice on a dummy proof (no signature), the second time with a fee of the right size.
        let mut fee = fee_for(FIRST_GUESS_GAS)?;
        let mut gas = 0u64;
        for _ in 0..2 {
            let dummy = self.inner.build_dummy(with_fee(fee)?, &mut rand::rng()).await.map_err(err)?;
            gas = eth
                .estimate_gas(dummy.tx_data.to, dummy.tx_data.data.clone(), Some(VERIFICATION_BYPASS))
                .await
                .map_err(|e| JsError::new(&format!("dummy-proof gas estimate: {e}")))?;
            fee = fee_for(gas)?;
        }

        let proved = self.inner.build(with_fee(fee)?, &mut rand::rng()).await.map_err(err)?;
        let pre_transaction_pois = self
            .inner
            .pre_transaction_pois(&proved.proved_operations)
            .await
            .map_err(err)?;
        if !quote.usable_at((now_ms() as u64).saturating_sub(30_000)) {
            return Err(JsError::new("the fee quote expired while proving, run the operation again"));
        }

        let sealed = client
            .seal(
                BroadcastRequest {
                    quote: quote.clone(),
                    to: proved.tx_data.to.to_checksum(None),
                    calldata: proved.tx_data.data.to_vec(),
                    min_gas_price: gas_price,
                    use_relay_adapt: proved.relay.is_some(),
                    pre_transaction_pois,
                },
                &mut rand::rng(),
            )
            .map_err(err)?;
        let tx_hash = client.send(&sealed).await.map_err(|e| match e {
            ClientError::Timeout(_) => JsError::new(
                "no answer from the broadcaster within 120 s: the transaction may still have been \
                 mined, check whether the input notes are spent after the next sync",
            ),
            other => err(other),
        })?;
        serde_wasm_bindgen::to_value(&LegacyOutcome {
            tx_hash,
            broadcaster: quote.railgun_address,
            fee: fee.to_string(),
            gas,
            min_gas_price: gas_price.to_string(),
        })
        .map_err(err)
    }
}
