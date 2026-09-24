use std::sync::Arc;

use eip_1193_provider::provider::{Eip1193Provider, IntoEip1193Provider};
use kohaku_db::{Database, memory::MemoryDatabase};

use crate::{
    chain_config::ChainConfig,
    circuit::groth16_prover::Groth16Prover,
    crypto::keys::{MasterPublicKey, ViewingKey},
    indexer::{
        syncer::{ChainedSyncer, RpcSyncer, SubsquidSyncer, SyncEvent, UtxoSyncer},
        utxo_indexer::UtxoIndexer,
    },
    note::utxo::discover_master_key,
    merkle_tree::SmartWalletUtxoVerifier,
    poi::provider::PoiProvider,
    provider::{RailgunProvider, RailgunProviderError},
};

/// Builder for constructing a `RailgunProvider`.
pub struct RailgunBuilder {
    chain: ChainConfig,
    provider: Arc<dyn Eip1193Provider>,
    db: Option<Arc<dyn Database>>,
    utxo_syncer: Option<Arc<dyn UtxoSyncer>>,
    poi: bool,
    /// ZKNOX viewer: POI statuses and txid tree without proof generation or submission.
    poi_read_only: bool,
}

impl RailgunBuilder {
    #[must_use]
    pub fn new(chain: ChainConfig, provider: impl IntoEip1193Provider) -> Self {
        Self {
            chain,
            provider: provider.into_eip1193(),
            db: None,
            utxo_syncer: None,
            poi: false,
            poi_read_only: false,
        }
    }

    /// Sets a custom database for the provider. If not set, an in-memory database
    /// will be used.
    ///
    /// Providers will use the database for storing synced UTXO data, POI proofs, and other internal
    /// state. Sensitive data such as a user's unencrypted notes will be stored. Private key
    /// material will never be stored in the database.
    #[must_use]
    pub fn with_database(mut self, db: Arc<dyn Database>) -> Self {
        self.db = Some(db);
        self
    }

    /// Sets a custom UTXO syncer for the provider. If not set, a default subsquid + RPC syncer will
    /// be used.
    #[must_use]
    pub fn with_utxo_syncer(mut self, syncer: Arc<dyn UtxoSyncer>) -> Self {
        self.utxo_syncer = Some(syncer);
        self
    }

    /// Enables POI (Proof of innocence) support for the provider.
    ///
    /// Uses the default chain-specific POI endpoints and list keys from the chain config. Enabling
    /// this tells the builder to submit POI proofs when spending notes and to only spend
    /// notes that have been marked as `spendable` by the POI provider.
    #[must_use]
    pub fn with_poi(mut self) -> Self {
        self.poi = true;
        self
    }

    /// ZKNOX viewer: master public key of an account known only by its viewing key, read from the
    /// first transact note that decrypts with it and reproduces its on-chain hash. Scans the
    /// chain's commitments from `from_block` (default: the deployment block) to the head with the
    /// same syncer chain as [`Self::build`]; `progress(scanned_to, head)` is called per chunk.
    /// Returns the key with the block timestamp of the note. `None` when no such note exists (an
    /// account that only ever received shields, or whose senders all revealed themselves).
    pub async fn discover_master_key(
        &self,
        viewing_key: ViewingKey,
        from_block: Option<u64>,
        progress: &(dyn Fn(u64, u64) + Sync),
    ) -> Result<Option<(MasterPublicKey, u64)>, Box<dyn std::error::Error + Send + Sync>> {
        let syncer: Arc<dyn UtxoSyncer> = match &self.utxo_syncer {
            Some(s) => s.clone(),
            None => Arc::new(
                ChainedSyncer::new()
                    .then(SubsquidSyncer::new(&self.chain.subsquid_endpoint))
                    .then(RpcSyncer::new(self.chain.clone(), self.provider.clone())),
            ),
        };
        let head = syncer.latest_block().await?;
        let mut from = from_block.unwrap_or(self.chain.deployment_block);
        const CHUNK: u64 = 50_000;
        while from <= head {
            let to = (from + CHUNK - 1).min(head);
            let events = syncer.sync(from, to).await?;
            for event in &events {
                if let SyncEvent::Transact(t, timestamp) = event {
                    if let Some(master) = discover_master_key(viewing_key, t) {
                        return Ok(Some((master, *timestamp)));
                    }
                }
            }
            progress(to, head);
            from = to + 1;
        }
        Ok(None)
    }

    /// ZKNOX viewer: like [`Self::with_poi`], but the provider only reads statuses and syncs the
    /// txid tree. It never generates, recovers or submits a proof. For view-only signers.
    #[must_use]
    pub fn with_poi_read_only(mut self) -> Self {
        self.poi = true;
        self.poi_read_only = true;
        self
    }

    /// Builds the `RailgunProvider` with the specified configuration.
    #[must_use]
    pub async fn build(self) -> Result<RailgunProvider, RailgunProviderError> {
        let db = self.db.unwrap_or_else(|| Arc::new(MemoryDatabase::new()));

        let utxo_syncer = self.utxo_syncer.unwrap_or_else(|| {
            Arc::new(
                ChainedSyncer::new()
                    .then(SubsquidSyncer::new(&self.chain.subsquid_endpoint))
                    .then(RpcSyncer::new(self.chain.clone(), self.provider.clone())),
            )
        });

        let utxo_verifier = Arc::new(SmartWalletUtxoVerifier::new(
            self.chain.railgun_smart_wallet,
            self.provider.clone(),
        ));

        let utxo_indexer = UtxoIndexer::new(db.clone(), utxo_syncer, utxo_verifier).await?;

        let prover = Groth16Prover::new();

        let poi_provider = if self.poi {
            let txid_syncer = Arc::new(SubsquidSyncer::new(&self.chain.subsquid_endpoint));

            let poi_provider = PoiProvider::new(
                self.chain.id,
                db,
                txid_syncer,
                self.chain.poi_endpoint.clone(),
                self.chain.list_keys.clone(),
            )
            .await?;
            let mut poi_provider = poi_provider;
            poi_provider.set_read_only(self.poi_read_only);
            Some(poi_provider)
        } else {
            None
        };

        RailgunProvider::new(
            self.chain,
            self.provider,
            utxo_indexer,
            prover,
            poi_provider,
        )
        .await
    }
}
