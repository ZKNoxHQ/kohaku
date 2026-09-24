//! View-only signers. They satisfy `RailgunSigner` for the read paths of the SDK (note
//! decryption, nullifiers, addresses) and refuse to sign. The placeholder spending key is random
//! and only ever reaches code that is disabled in view-only mode (`with_poi_read_only`).

use std::sync::Arc;

use railgun::{
    account::{
        chain::ChainId,
        signer::{RailgunSigner, RailgunSignerError},
    },
    crypto::keys::{MasterPublicKey, SpendingKey, SpendingPublicKey, SpendingSignature, ViewingKey},
};
use alloy::primitives::U256;

/// Viewing key + master public key (discovered on chain). The spending public key is unknown:
/// only the master key is used by the read paths.
pub struct MasterSigner {
    viewing: ViewingKey,
    master: MasterPublicKey,
    placeholder: SpendingKey,
    chain: ChainId,
}

impl MasterSigner {
    pub fn new(viewing: ViewingKey, master: MasterPublicKey, chain_id: u64) -> Arc<Self> {
        Arc::new(Self {
            viewing,
            master,
            placeholder: rand::random(),
            chain: ChainId::evm(chain_id),
        })
    }
}

impl RailgunSigner for MasterSigner {
    fn chain_id(&self) -> ChainId {
        self.chain
    }
    fn viewing_key(&self) -> ViewingKey {
        self.viewing
    }
    fn spending_key(&self) -> SpendingKey {
        self.placeholder
    }
    fn spending_pubkey(&self) -> SpendingPublicKey {
        self.placeholder.public_key()
    }
    fn master_public_key(&self) -> MasterPublicKey {
        self.master
    }
    fn sign(&self, _inputs: U256) -> Result<SpendingSignature, RailgunSignerError> {
        Err(RailgunSignerError::new("view-only signer: no spending key"))
    }
}
