use std::sync::Arc;

use railgun::{
    account::{
        address::RailgunAddress,
        chain::ChainId,
        signer::{PrivateKeySigner, RailgunSigner, spending_key_path, viewing_key_path},
    },
    crypto::keys::{HexKey, SpendingKey, ViewingKey},
};
use rand::random;
use wasm_bindgen::{JsError, prelude::wasm_bindgen};

#[wasm_bindgen(js_name = "RailgunSigner")]
pub struct JsRailgunSigner {
    inner: Arc<dyn RailgunSigner>,
}

#[wasm_bindgen(js_class = "RailgunSigner")]
impl JsRailgunSigner {
    /// BIP-32 derivation paths for railgun spending keys.
    ///
    /// <https://github.com/Railgun-Community/engine/blob/e2913b39e13f82f43556d23705fa20d2ece2e8ab/src/key-derivation/wallet-node.ts#L17>
    #[wasm_bindgen(js_name = "spendingKeyPath")]
    pub fn spending_key_path(#[wasm_bindgen(js_name = "keyIndex")] key_index: u32) -> String {
        spending_key_path(key_index)
    }

    /// BIP-32 derivation paths for railgun viewing keys.
    ///
    /// <https://github.com/Railgun-Community/engine/blob/e2913b39e13f82f43556d23705fa20d2ece2e8ab/src/key-derivation/wallet-node.ts#L17>
    #[wasm_bindgen(js_name = "viewingKeyPath")]
    pub fn viewing_key_path(#[wasm_bindgen(js_name = "keyIndex")] key_index: u32) -> String {
        viewing_key_path(key_index)
    }

    /// Creates a `RailgunSigner` from hex-encoded spending and viewing keys.
    #[wasm_bindgen(js_name = "privateKey")]
    pub fn new_private_key(
        #[wasm_bindgen(js_name = "spendingKey", unchecked_param_type = "`0x${string}`")]
        spending_key: String,
        #[wasm_bindgen(js_name = "viewingKey", unchecked_param_type = "`0x${string}`")] viewing_key: String,
        #[wasm_bindgen(js_name = "chainId")] chain_id: Option<u64>,
    ) -> Result<Self, JsError> {
        let spending_key = SpendingKey::from_hex(&spending_key)
            .map_err(|e| JsError::new(&format!("Invalid spending key hex: {}", e)))?;
        let viewing_key = ViewingKey::from_hex(&viewing_key)
            .map_err(|e| JsError::new(&format!("Invalid viewing key hex: {}", e)))?;

        let chain_id = match chain_id {
            Some(id) => ChainId::evm(id),
            None => ChainId::All,
        };

        Ok(Self {
            inner: PrivateKeySigner::new(spending_key, viewing_key, chain_id),
        })
    }

    /// Create a new `RailgunSigner` with random keys.
    #[wasm_bindgen(js_name = "random")]
    pub fn new_random(#[wasm_bindgen(js_name = "chainId")] chain_id: Option<u64>) -> Self {
        let chain_id = match chain_id {
            Some(id) => ChainId::evm(id),
            None => ChainId::All,
        };

        Self {
            inner: PrivateKeySigner::new(random(), random(), chain_id),
        }
    }

    #[wasm_bindgen(getter, js_name = "chainId")]
    pub fn chain_id(&self) -> Option<u64> {
        match self.inner.chain_id() {
            ChainId::Evm { id } => Some(id),
            _ => None,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn address(&self) -> RailgunAddress {
        self.inner.address()
    }
}

impl JsRailgunSigner {
    pub fn inner(&self) -> Arc<dyn RailgunSigner> {
        self.inner.clone()
    }
}

/// Ledger-over-WebUSB constructor, browser-only. The spending key stays on the
/// device; the viewing key is exported at connect and held in wasm memory.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_class = "RailgunSigner")]
impl JsRailgunSigner {
    /// Connect a Ledger over WebUSB and build a signer.
    ///
    /// Must be invoked from a user gesture (a click handler): browsers only
    /// allow `navigator.usb.requestDevice` in response to one. Opens the device
    /// picker, then prompts on-device for the spending pubkey and viewing key.
    #[wasm_bindgen(js_name = "connectLedgerWebUsb")]
    pub async fn connect_ledger_webusb(
        #[wasm_bindgen(js_name = "accountIndex")] account_index: u32,
        #[wasm_bindgen(js_name = "chainId")] chain_id: Option<u64>,
    ) -> Result<JsRailgunSigner, JsError> {
        let device = railgun_ledger::WebUsbLedger::connect()
            .await
            .map_err(|e| JsError::new(&format!("WebUSB: {e}")))?;

        // The chain id is only the advisory field on the 0zk address; the signer
        // identity itself is chain-agnostic.
        let chain = match chain_id {
            Some(id) => ChainId::evm(id),
            None => ChainId::All,
        };

        let signer = railgun_ledger::LedgerSigner::connect(device, chain, account_index)
            .await
            .map_err(|e| JsError::new(&format!("Ledger: {e}")))?;

        Ok(JsRailgunSigner { inner: signer })
    }

    /// Connect a Ledger over Web Bluetooth (Flex / Stax / Nano X) and build a
    /// signer.
    ///
    /// Like [`Self::connect_ledger_webusb`], must be called from a user gesture:
    /// browsers only allow `navigator.bluetooth.requestDevice` in response to
    /// one. Shows the device picker, then prompts on-device for the spending
    /// pubkey and viewing key.
    #[wasm_bindgen(js_name = "connectLedgerWebBle")]
    pub async fn connect_ledger_web_ble(
        #[wasm_bindgen(js_name = "accountIndex")] account_index: u32,
        #[wasm_bindgen(js_name = "chainId")] chain_id: Option<u64>,
    ) -> Result<JsRailgunSigner, JsError> {
        let device = railgun_ledger::WebBleLedger::connect()
            .await
            .map_err(|e| JsError::new(&format!("Web Bluetooth: {e}")))?;

        let chain = match chain_id {
            Some(id) => ChainId::evm(id),
            None => ChainId::All,
        };

        let signer = railgun_ledger::LedgerSigner::connect(device, chain, account_index)
            .await
            .map_err(|e| JsError::new(&format!("Ledger: {e}")))?;

        Ok(JsRailgunSigner { inner: signer })
    }
}
