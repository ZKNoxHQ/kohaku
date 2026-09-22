# railgun-viewer — décisions d'architecture

## ADR-001 — Crate séparée sur le même SDK et le même format de données que le wallet

Le viewer est un binaire distinct de `railgun-wallet` mais dépend de lui comme bibliothèque
(`default-features = false` : pas d'axum du wallet) pour la dérivation des clés et la base sur disque.
Il partage la disposition `<chain>/<sha256(adresse)[..8]>/db-v2`, ce qui permet de pointer
`--data-dir ~/.railgun-wallet` et d'éviter un second scan. Le prix : ne pas faire tourner les deux
sur le même répertoire simultanément (stockage fichier-par-clé, sans verrou).

## ADR-002 — View-only par le master key de l'adresse, pas par la clé de dépense publique

`npk = poseidon(mpk, random)` et `mpk = poseidon(spub.x, spub.y, nk)`. Une clé de visualisation
seule ne permet ni de recalculer les npk, ni les hashes, ni les blinded commitments (donc pas de
statut POI). Plutôt que d'exiger la clé de dépense publique, le viewer prend l'adresse 0zk, qui
contient le master key. Cela demande au SDK une méthode `master_public_key()` sur `RailgunSigner`,
utilisée par `UtxoNote::new` et `address()`. La clé partageable de l'engine Railgun, qui embarque
`spub`, reste acceptée (dépaquetage circomlib du point BabyJubJub).

## ADR-003 — POI en lecture seule pour les signers view-only

Le fork récupère et soumet les preuves POI manquantes au sync (`recover_missing`,
`submit_pending`). Un signer view-only produirait des entrées de preuve invalides (clé de dépense
publique factice). `RailgunBuilder::with_poi_read_only` garde le txid-tree et les statuts, coupe
génération, récupération et soumission. En mode mnémonique le viewer conserve le comportement du
wallet : il répare les POI manquantes.

## ADR-004 — Références chaîne par subsquid, pas par `eth_getLogs`

Le SDK ne conserve ni hash de transaction, ni timestamp, ni détail d'unshield. Les récupérer par
logs RPC demanderait de connaître les blocs des shields (inconnus) ou de balayer l'historique. Le
subsquid Railgun répond par hash de commitment et par nullifier en une requête, et sert déjà au
sync. Les réponses sont mises en cache (`viewer-cache.json`) ; toute défaillance laisse les champs
vides sans bloquer l'historique.

## ADR-005 — Front : rendu de lignée réutilisé, modèle calculé en Rust

Le graphe reprend le script NOXAKU tel quel (contrat `noxaku-notes-snapshot` v1) ; le snapshot est
produit par `history::graph_snapshot`. Tout le modèle métier (transactions, sens, bilans, POI par
liste, détection des émissions sans preuve) est en Rust, testable sans moteur ; le front ne fait
qu'afficher.
