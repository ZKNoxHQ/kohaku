# railgun-viewer

Read-only companion of `railgun-wallet`: resyncs a Railgun account and shows the history of every
transaction it took part in (shields, transfers sent and received, unshields), the memo of each
note, the full note lineage graph, and a tab listing the transactions this account emitted
without a submitted proof of innocence. It never spends: no bundler, no broadcaster, no prover.

## Run

```bash
cargo run --release -p railgun-viewer            # http://127.0.0.1:8790
cargo run --release -p railgun-viewer -- --port 8791 --data-dir ~/.railgun-viewer
```

Data layout is the wallet's (`<data-dir>/<chain>/<sha256(address)[..8]>/db-v2`), so
`--data-dir ~/.railgun-wallet` reuses an already synced database. Do not run the wallet and the
viewer on the same directory at the same time.

## Keys

| Source | Mode | POI |
|---|---|---|
| BIP-39 mnemonic (railgun or kohaku derivation, index) | full: both keys derived, same as the wallet | statuses read, missing proofs rebuilt and submitted like the wallet does |
| viewing private key + 0zk address | view-only: the address carries the master public key | statuses and txid tree only (`with_poi_read_only`) |
| shareable viewing key (`hex(msgpack({vpriv, spub}))`, the Railgun engine export) | view-only: spending public key unpacked from it | statuses and txid tree only |

A bare viewing key without the address is refused: note public keys are `poseidon(masterKey, random)`
and the master key is `poseidon(spendingPubkey, nullifyingKey)`; the viewing key alone cannot
recompute them, the address can.

## Tabs

* **Historique**: one row per transaction, newest first: date and block, kind, amounts in / out /
  unshield per token, best POI status per list over the outputs, chain tx link, memo. Clicking a row
  opens the detail: memos, inputs and outputs with their own POI chips, unshield destination and fee,
  railgun txid, link to the same transaction in the lineage graph.
* **Arbre des notes**: the NOXAKU lineage renderer (same JS), fed with a snapshot built from the
  SDK state.
* **POI manquantes**: transactions emitted by this account whose outputs carry no
  `ProofSubmitted` / `Valid` status on any list, with the reason, plus the local queue of proofs
  waiting for txid validation.

## Data sources

* SDK (`crates/railgun`, ZKNOX fork): unspent, spent and sent notes of the account, own operations
  kept in full by the txid indexer, POI statuses per blinded commitment, pending proofs.
* Subsquid (`chain_config.subsquid_endpoint`): block numbers, timestamps and transaction hashes of
  commitments and nullifiers, unshield events (to, amount, fee). Cached in
  `<account dir>/viewer-cache.json`.
* RPC: ERC-20 symbol and decimals.

## API (loopback)

`GET /api/status`, `GET /api/snapshot`, `POST /api/unlock` (json: `chainId`, `rpcUrl`, `poi`,
`syncNow`, and either `mnemonic`+`derivation`+`index`, or `viewingKey`+`address`, or
`shareableKey`), `POST /api/sync`, `POST /api/refresh`, `POST /api/lock`.
