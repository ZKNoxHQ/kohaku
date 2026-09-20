# Changelog

## 0.8.1 (2026-09-20)

Documentation only. The 4337 "prove once" path is validated on Sepolia: a transfer in the default
mode recorded the gas profile of its shape, the same transfer with "prove once" then went through
with a single proof, limits accepted by the paymaster and the bundler. The margin (25%) has not
been tuned against the measured figures yet.

## 0.8.0 (2026-09-20)

Aimed at hardware and threshold signers, where every spending signature is a confirmation on the
device or a signing ceremony.

* Fix (SDK fork): `build_dummy` no longer reaches the signer. It went through
  `TransactCircuitInputs::from_inputs`, which signs; invisible with a software key, one
  confirmation per gas estimate with a Ledger. New `from_inputs_unsigned`, and a unit test with a
  counting signer. The legacy path now costs one signature per operation instead of three.
* 4337 "prove once" option (SDK fork: `RailgunProvider::prepare_userop_single_proof`): gas
  limits are fixed before proving, from the dummy-proof gas of the `transact` call, a
  `UserOpGasProfile` learned on an earlier operation of the same shape, and a margin (default
  25%, limits rounded up to 10k gas). The fee follows from the limits, so the paymaster check
  passes by construction. After proving, the paymaster verification gas is measured on the real
  proof and the bundler's own estimate is compared with the limits; if one is too low the
  operation stops before anything is sent.
* Profiles are learned from every converged iterative estimate and kept in
  `<data-dir>/<chain>/gas_profiles.json`, keyed by shape (`1x2+2x3|calls=0`). Without a profile
  for a shape, "prove once" falls back to the iterative path for that transaction and says so.
* userop-kit fork: `Bundler::gas_price`, the bundler's price without a simulation
  (`pimlico_getUserOperationGasPrice`).
* If the dummy-proof estimate fails in the default mode, the operation carries on without
  learning: the path validated on Sepolia is unchanged.

Checked here: unit tests (54 in `railgun`), API and front. Not checked: the single-proof path on
a chain. It needs a learned profile, so the first live run is: one 4337 transfer in the default
mode (records the profile), then the same with "prove once".

## 0.7.3 (2026-09-20)

Documentation only. Legacy transport validated end to end on Sepolia: private transfer and
token unshield relayed by a community broadcaster, pre-transaction POIs accepted, and
post-transaction POIs validated (change notes spendable again after sync). README and ADR-009
no longer list these as unverified. Still open: native unshield over legacy (RelayAdapt),
mainnet.

## 0.7.2 (2026-09-20)

* Fix: the legacy gas estimate reverted with "RailgunSmartWallet: Gas price too low". The
  dummy-proof transaction binds `minGasPrice`, and an `eth_estimateGas` that names no price runs
  with `tx.gasprice = 0`. The estimate now carries `gasPrice = minGasPrice`, as the type 0
  transaction the broadcaster sends. Found on the first live run (Sepolia); the offline tests
  could not reach this step, which needs shielded notes and a real node.
* If the node then answers "insufficient funds" (it caps the gas by the balance of the bypass
  address once a price is named), the estimate is retried with a balance override.

## 0.7.1 (2026-09-20)

* Fix: every legacy operation failed with "no usable broadcaster offer" on the real network.
  The wallet passed its POI list keys as `ListKey(…)` (the type's `Display` is a debug form), so
  no broadcaster's `requiredPOIListKeys` ever matched. `RailgunProvider::poi_list_keys` now
  returns the wire form. The mock broadcaster required no list, which is why tests missed it;
  it can now require lists and a regression test covers the case.
* The front applies the same POI list filter as the engine (`poiListKeys` in the status), so it
  no longer counts as usable an offer the engine will refuse.
* A mismatch of POI lists has its own error, naming the lists required and the wallet's.

First run against the live Railgun fleet (Sepolia, 2026-09-20): the js-waku node in the tab
connected to 3 peers, received offers, and the four Railway trusted signers do announce a rate
there.

## 0.7.0 (2026-09-20)

* The Waku node of the legacy transport runs in the wallet tab by default: js-waku light node
  (`@waku/sdk` 0.0.36, as the reference web client), filter to receive, light push to send,
  dialling the three fixed wss peers of the Railgun fleet. No nwaku, no docker. The previous mode
  stays available ("Local nwaku over REST" at unlock).
* `static/waku-bundle.js` (832 kB, no WebAssembly, no eval) is embedded in the binary and served
  at `/waku-bundle.js`; sources and build command are in `waku-bridge/`.
* `POST /api/waku/exchange`: once a second the tab hands over what it received and takes what
  it must publish. The daemon reports the transport unreachable when the tab stops calling
  (8 s) or while its node is not connected, with the node's own state in the message.
* CSP: `script-src` gains `'self'`, `connect-src` gains `wss://*.rootedinprivacy.com:8000` and
  nothing else, since there is no DNS discovery.
* Diagnostics of the legacy tab describe the state of the tab's node (loading, dialling,
  subscribing, connected, error with retry every 30 s).

Checked here: bundle loads under the CSP without violation, the node starts and dials the three
fleet peers (blocked by this environment's network, so the time-out and retry path is what ran),
the daemon sees the tab's state, offers carried through `/api/waku/exchange` are authenticated
and listed, the transport goes unreachable when the tab disappears. Not checked: a real
connection to the fleet.

## 0.6.0 (2026-09-20)

* Fee ceilings on the legacy transport, independent of any trusted signer:
  * highest rate accepted, as a multiple of the gas cost (default 1.5). Offers above it are
    ignored at selection; if none is left the operation fails before anything is proved, with
    the cheapest rate refused.
  * optional highest fee for the whole transaction, in wrapped token, checked after the gas
    estimate and before proving.
  Both are sent with each operation (`maxFeeRate`, `maxFee`) and remembered by the front.
* Rates are shown as multiples of the gas cost instead of raw per-1e18 values; offers over the
  ceiling are tagged in the table and no longer count as usable.
* The fee in the job steps is shown in token units.
* Before this version a legacy operation went from quote to broadcast with no bound on the fee
  other than the shielded balance when no trusted signer was set.

## 0.5.2 (2026-09-20)

* Transport tabs are always selectable. An unusable transport is marked "(unavailable)" and,
  once selected, says why and what to do; only the Transfer and Unshield buttons are disabled.
  Before, the legacy tab was simply greyed out with the reason hidden in a tooltip.
* Legacy diagnostics: no Waku node at the URL (with the `fake_network` command), node without
  peers, trusted signers that have not announced a rate, offers outside the band, no offer yet.

## 0.5.1 (2026-09-20)

* Trusted fee signers prefilled with the four signers of the Railway wallet
  (`railgun_broadcaster::RAILWAY_TRUSTED_FEE_SIGNERS`, served by `GET /api/defaults`).
* "none" in the field disables the cap, for test networks where these signers may not announce.

## 0.5.0 (2026-09-19)

* Trusted fee signers for the legacy transport (`railgun-broadcaster` 0.2.0): field at unlock
  (one or several 0zk addresses), saved with the other non-secret preferences.
* The legacy panel shows the number of signers, the authorized rate and the accepted range, or
  says that offers are held back until a signer announces.
* Mainnet refuses the legacy transport without a trusted signer. Sepolia works without.
* A malformed signer address fails the unlock with an explicit message.

## 0.4.0 (2026-09-19)

* Legacy transport through the new `railgun-broadcaster` crate. The transport is chosen per
  operation between 4337, legacy and direct.
* Unlock takes a Waku node REST URL (default `http://127.0.0.1:8645`). A monitor task keeps the
  broadcaster offers current; `/api/status` returns the live state under `legacy`.
* The legacy tab turns on when at least one usable offer exists for the wrapped base token, and
  lists the offers. When the node is unreachable the reason is shown.
* `submit_legacy`: best quote, gas price from the node plus 10%, two dummy-proof gas estimates,
  fee note pinned first, `minGasPrice` bound, proof, pre-transaction POIs, sealed request, wait
  for the transaction hash. A timeout says to sync and check the inputs before retrying.
* Native unshield is refused over legacy (needs RelayAdapt).
* Fork: `RailgunProvider::poi_list_keys`.

Checked here: unit and end-to-end tests of the crate, wallet against the `fake_network` example
over real HTTP (subscription, offers authenticated, tab and table in the front, flow up to
`eth_gasPrice`). Not checked: proving on this path and a live broadcaster.

## 0.3.0 (2026-09-19)

SDK prerequisites for the legacy (broadcaster) transport. No transport code yet, the legacy tab
stays disabled. All in the `crates/railgun` fork, all opt-in:

* `TransactionBuilder::min_gas_price(wei)`: sets `BoundParams.minGasPrice` (was hardcoded 0).
  Default 0, so existing proofs are bit-identical.
* `TransactionBuilder::broadcaster_fee(from, to, asset, value)`: a transfer whose note is
  guaranteed to be `transactions[0].commitments[0]`. Refused if it would span two UTXO trees or
  if one is already set. Without it the layout is unchanged.
* `RailgunProvider::build_dummy`: same calldata with an all-zero proof, for `eth_estimateGas`
  from `VERIFICATION_BYPASS` (0x…dEaD). No proving, no POI registration.
* `RailgunProvider::pre_transaction_pois`: pre-transaction POI per list key and txid leaf hash
  (pre-inclusion UTXO position 199999/199999, dummy txid proof with zero siblings).
  `PoiCircuitInputs::from_inputs_with_txid_proof`, `TxidLeafHash::dummy_proof`.
* `crypto::aes`, `SharedKey` and `ViewingKey::derive_shared_key` are public, for the
  wallet-to-broadcaster ECDH channel.
* Wallet: the `direct` transport logs a dummy-proof gas estimate before proving, to exercise
  the new path on a live chain.

Tests: 6 new unit tests (default layout unchanged, fee pinned first including across groups and
trees, fee rules, minGasPrice bound and zero proof, dummy txid proof). `cargo test -p railgun
--lib`: 51 passed. `railgun-ts` and the wallet compile against the fork.

## 0.2.0 (2026-09-19)

* POI recovery for operations this process did not build (wallet restored from its keys,
  transactions made with another wallet). Change notes stuck in "waiting for proof" now get
  their proof rebuilt and submitted during sync. Implemented in the `crates/railgun` fork:
  * `IndexedAccount` keeps spent notes and decrypts, as sender, the outputs addressed to other
    wallets (`note/sent.rs`).
  * `TxidIndexer` retains the full record of operations spending one of our nullifiers;
    `Operation` carries `has_unshield` (subsquid `hasUnshield`).
  * `PoiProvider::recover_missing` rebuilds a `PendingPoiEntry` per past operation whose outputs
    the POI node reports as `Missing`, oldest first.
* Database directory moves to `db-v2`: a v1 database discarded the data above, the first sync
  after the upgrade is a full one.

## 0.1.2 (2026-09-19)

* Default endpoints: public RPC per network (publicnode) and the public Pimlico bundler,
  prefilled in the front and applied by the daemon when the field is empty. Switching network
  swaps the defaults and leaves custom values alone.
* Recovery phrase prefilled with the public test phrase ("yellow" x12), flagged as test only.
* Empty or scheme-less RPC URL now gives an explicit error instead of `relative URL without a
  base`.

## 0.1.1 (2026-09-19)

* `WalletDb` replaces `kohaku_db::fs::FilesystemDatabase`: file name is `sha256(key)`, writes
  are atomic (temp file then rename), directory mode 0700. Fixes `File name too long (os error
  36)` raised by `RailgunProvider::register` on any filesystem-backed database.
* Balances and EOA balance shown without trailing zeros.
* Verified: unit tests (key derivation vector from the Railgun engine, long-key database),
  daemon smoke test against a mock RPC (unlock, register, snapshot, origin/host refusal, legacy
  refusal, sync failure surfaced), front driven with Chromium against the real daemon.

## 0.1.0 (2026-09-19)

* New crate `railgun-wallet`: loopback daemon (axum) and embedded front.
* Engine actor on a dedicated thread owning `RailgunProvider`; job queue, step log, SDK log
  mirrored to the front.
* Operations: sync, shield (ERC-20 with approval, native through RelayAdapt), private transfer,
  unshield (token, or native with unwrap over 4337).
* Transports: `erc4337` (privacy paymaster), `direct` (debug), `legacy` declared and disabled.
* Mnemonic derivation: Railgun engine scheme and kohaku BIP-32 scheme.
* POI: enabled through `RailgunBuilder::with_poi`, per-note status and pending submissions shown.
* Fork patch in `crates/railgun`: read-only accessors `RailgunProvider::{chain, synced_block,
  poi_enabled, poi_pending}` and `PoiProvider::pending_summaries`.
