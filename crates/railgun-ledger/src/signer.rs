//! [`RailgunSigner`] backed by a Ledger device.

use std::sync::Arc;

use ruint::aliases::U256;
use thiserror::Error;
use tracing::info;

use railgun::{
    account::{
        chain::ChainId,
        signer::{RailgunSigner, RailgunSignerError},
    },
    crypto::keys::{SpendingPublicKey, SpendingSignature, ViewingKey},
};

use crate::{
    protocol::{self, ProtocolError},
    transport::Exchange,
};

#[derive(Debug, Error)]
#[error(transparent)]
pub struct LedgerError(#[from] ProtocolError);

/// A Railgun signer whose spending key lives on a Ledger device.
///
/// [`LedgerSigner::connect`] fetches the public material once — the spending public key and
/// the viewing seed — so address derivation, note scanning and gas estimation never touch
/// the device again. Only [`RailgunSigner::sign`] does, and each call is a user confirmation.
pub struct LedgerSigner<E> {
    device: E,
    account_index: u32,
    chain_id: ChainId,
    spending_pubkey: SpendingPublicKey,
    viewing_key: ViewingKey,
}

impl<E: Exchange> LedgerSigner<E> {
    pub async fn connect(
        device: E,
        chain_id: ChainId,
        account_index: u32,
    ) -> Result<Arc<Self>, LedgerError> {
        let version = protocol::get_version(&device).await?;
        let spending_pubkey =
            protocol::get_spending_public_key(&device, account_index, false).await?;
        let viewing_key = protocol::export_viewing_key(&device, account_index).await?;
        info!(
            app_version = format!("{}.{}.{}", version.0, version.1, version.2),
            account_index, "connected to Ledger Railgun app"
        );

        Ok(Arc::new(Self {
            device,
            account_index,
            chain_id,
            spending_pubkey,
            viewing_key,
        }))
    }

    /// Show the spending public key on the device screen for out-of-band verification.
    pub async fn verify_on_device(&self) -> Result<SpendingPublicKey, LedgerError> {
        Ok(protocol::get_spending_public_key(&self.device, self.account_index, true).await?)
    }
}

#[cfg_attr(native, async_trait::async_trait)]
#[cfg_attr(wasm, async_trait::async_trait(?Send))]
impl<E: Exchange> RailgunSigner for LedgerSigner<E> {
    fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    fn viewing_key(&self) -> ViewingKey {
        self.viewing_key
    }

    fn spending_public_key(&self) -> SpendingPublicKey {
        self.spending_pubkey
    }

    async fn sign(&self, inputs: U256) -> Result<SpendingSignature, RailgunSignerError> {
        protocol::sign_hash(&self.device, self.account_index, inputs)
            .await
            .map_err(RailgunSignerError::new)
    }
}
