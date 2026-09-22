# railgun-viewer — journal des versions

## 0.1.0 — 2026-09-22

Première version : crate séparée, exécutable `railgun-viewer` (daemon axum sur loopback + front embarqué).

### Ajouté
- Chargement depuis une mnémonique (dérivation railgun / kohaku, index), depuis une clé de visualisation privée + adresse 0zk, ou depuis la clé partageable de l'engine Railgun (msgpack `{vpriv, spub}`, point BabyJubJub dépaqueté à la circomlib).
- Signers view-only (`SpubSigner`, `MasterSigner`) satisfaisant `RailgunSigner` pour les chemins de lecture du SDK et refusant de signer.
- Resync via le SDK (`RailgunBuilder` + `WalletDb`, même disposition de données que `railgun-wallet`), POI en lecture seule pour les modes view-only.
- Historique : toutes les transactions du compte, émises et reçues, avec entrées, sorties, unshields, bilan par jeton, statut POI par liste, hash de tx et date via subsquid (cache disque), mémo par note et par transaction (panneau de détail).
- Onglet Arbre des notes : rendu NOXAKU réutilisé tel quel sur un snapshot `noxaku-notes-snapshot` construit côté Rust.
- Onglet POI manquantes : transactions émises sans `ProofSubmitted`/`Valid` sur aucune sortie, avec la raison, et file locale des preuves en attente.

### Modifié (crates/railgun, fork ZKNOX)
- `RailgunSigner` : méthodes par défaut `spending_pubkey()` et `master_public_key()`, `address()` passe par le master key ; `RailgunSignerError::new`.
- `UtxoNote::new` : npk calculé depuis `signer.master_public_key()` (`note_public_key_from_master`, public).
- `UtxoIndexer::account_state`, `RailgunProvider::{account_state, own_operations, poi_statuses}`, ré-exports `IndexedAccountState` et `Operation` (rendu public).
- `PoiProvider::{set_read_only, own_operations, statuses}` ; `RailgunBuilder::with_poi_read_only` (aucune génération, récupération ni soumission de preuve).
- Les appels `spending_key().public_key()` des chemins de lecture passent par `spending_pubkey()` ; ceux des circuits (`transact_inputs`) sont inchangés.

### Non validé
- Compilation à faire sur la machine cible (pas de toolchain Rust dans l'environnement de rédaction) ; les signatures alloy 1.x utilisées : `ProviderBuilder::new().network::<Ethereum>().connect().erased()`, `sol!` `#[sol(rpc)]` avec retours directs.
- Noms des champs subsquid (`blockTimestamp`, `transactionHash`, `unshields.token.tokenAddress`, `eventLogIndex`) : toute divergence laisse date, hash ou unshield vides, sans bloquer.
