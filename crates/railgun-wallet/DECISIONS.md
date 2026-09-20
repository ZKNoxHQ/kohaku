# Architecture decisions

## ADR-001: native daemon plus web front, not wasm in the browser

`crates/railgun-ts` already exposes the SDK to the browser. The wallet uses the native crate
behind a loopback HTTP API instead. Reasons: native Groth16 proving (and the `parallel` feature)
is much faster than wasm; the on-disk database survives restarts; the next step, the legacy
broadcaster transport, is a native Rust crate talking to a Waku node, which is awkward from wasm.
Cost: key material crosses a localhost HTTP call at unlock. Mitigated by binding to 127.0.0.1,
refusing foreign `Origin`/`Host`, a strict CSP on the front, and never persisting keys.

## ADR-002: single engine actor on its own thread

`RailgunProvider` needs `&mut self` for sync, balance and build, and its futures are not
guaranteed `Send`. One actor on a current-thread runtime serialises all access. HTTP reads are
served from a snapshot the actor refreshes after every command, so the front stays responsive
during a proof. Consequence: one operation at a time; a sync requested during a proof queues.

## ADR-003: transport is a per-operation parameter

`Transport { Erc4337, Legacy, Direct }` is passed with each transfer/unshield rather than fixed
at unlock. A proof binds `adaptContract`/`adaptParams` to one transport (the fee adapter requires
`adaptParams == sender`, Railgun requires `adaptContract == msg.sender`), so switching transport
means proving again, never resubmitting. `Session::submit` is the single place to add `Legacy`.

## ADR-004: `direct` transport kept as a debug path

Not requested by the product, but it isolates SDK bugs (note selection, proof, POI) from
paymaster and bundler behaviour while stabilising. Labelled as debug in the front because it
links the public EOA to the private transaction.

## ADR-005: two mnemonic derivations

kohaku derives Railgun keys with standard secp256k1 BIP-32; the Railgun engine uses a
hardened-only HMAC-SHA512 chain keyed with "babyjubjub seed". Same phrase, different 0zk
address. Default is the Railgun scheme so existing Railway wallets open with their funds.

## ADR-006: minimal fork surface in `crates/railgun`

Only read-only accessors were added, grouped under a `ZKNOX fork` marker, to keep rebases on
upstream trivial and to make the later PR a pure addition.

## ADR-007: own `Database` implementation instead of patching `kohaku-db`

`FilesystemDatabase` stores each entry as `hex(key)`. Indexer keys embed the 0zk address (127
characters), so the file name passes 255 bytes and `register` fails on ext4, APFS and NTFS. The
trait only has get/set/delete, no listing, so hashing the key loses nothing. Implemented in the
wallet (`src/db.rs`) rather than in `kohaku-db` to keep the fork surface small; the upstream fix
is a separate PR. Writes are atomic because the store holds Merkle trees and pending POI
entries, and a truncated file would force a full resync or lose a proof to submit.

## ADR-008: POI recovery from chain data, inside the SDK fork

Upstream only proves POI for operations registered at build time (`register_ops`). After a
restore, or for transactions made elsewhere, change notes stay `Missing` forever. The Railgun
community wallet recovers because its engine keeps spent TXOs, sent commitments and all railgun
transactions. The fork keeps the minimum equivalent: spent notes, sender-decrypted outputs and
the operations spending our nullifiers (not every operation: on mainnet that would be tens of
megabytes). The receiver master key encoding differs between the Railgun engine (XOR with the
sender key unless hidden) and kohaku (plain); both candidates are tried and the on-chain
commitment hash decides, so annotation data never has to be parsed.

Limits: the unshield-only operation without change is not probed (no note of ours depends on
it); an operation whose outputs straddle two UTXO trees is skipped; an operation spending the
change of another unproved one only succeeds after the POI node has accepted the first, that is
on a later sync.

The logic lives in `crates/railgun` because it needs the indexers' private state. This is the
first non-additive fork patch: `PoiProvider::sync_to` takes the account history, and
`IndexedAccountState`/`TxidIndexerState` gain serde-defaulted fields.

## ADR-009: broadcaster prerequisites are opt-in builder features

The five SDK changes needed by the legacy transport are added without touching the ERC-4337
path: `prepare_userop` calls none of them. `minGasPrice` stays 0 there on purpose, the Railgun
contract compares it to `tx.gasprice`, which is the bundler's. The fee pin is a separate builder
method rather than a change to `transfer(.., "fee")`: the fee adapter scans every commitment, so
4337 needs no ordering, while broadcasters read `transactions[0].commitments[0]` only. The pin
is implemented as a stable sort key, so a builder without it produces the historical order,
which a unit test freezes.

The dummy proof is a distinct entry point and is never used inside the `prepare_userop` loop:
the bundler simulates `validatePaymasterUserOp`, which verifies the SNARK with its own origin.

Pre-transaction POI follows the Railgun engine (`createDummyMerkleProof`, pre-inclusion
position 199999). Accepted by live broadcasters on Sepolia on 2026-09-20, for a transfer and for
an operation with an unshield (`railgunTxidIfHasUnshield`).

## ADR-010: Waku I/O on the server runtime, not the engine thread

The engine thread's runtime is blocked while a proof is computed, so the fee monitor would
starve and offers would expire unseen. The monitor and `send()` run on the HTTP server's
multi-thread runtime through a `Handle` given to the engine; the engine awaits the join handle.
The live broadcaster state sits in `Shared::legacy`, read directly by `/api/status`, because the
engine snapshot is only refreshed after a command.

## ADR-011: fee from two dummy-proof estimates

The fee is an output note, so it changes the inputs selected and possibly their number, hence
the gas. Round one uses a guess (700k gas) to get a realistic estimate, round two re-estimates
with a fee of the right size. The final proof is not re-estimated: the 20% gas limit margin in
the fee formula and the broadcaster's own variance buffer absorb the difference.

## ADR-012: trusted fee signer mandatory on mainnet only

The reference client requires a trusted signer everywhere. Here it is required where real funds
are at stake and optional on test networks, so the legacy path can be exercised on Sepolia
without knowing who signs rates there. No default signer is shipped: the address in use by the
Railgun wallets was not verified, and a wrong default would silently disable the transport.

## ADR-013: Railway's trusted fee signers as the default

The four addresses come from the `trustedFeeSigner` field of Railway's remote configuration
(`https://www.railway.xyz/config/railway-config-v3.3.json`, read on 2026-09-20). They are in no
GitHub repository: Railway loads them at start-up, and applies them to every network. The same
file confirms the relay shard `/waku/2/rs/5/1` and lists no additional direct peer.

Shipped as a prefilled, editable field rather than a hidden default, because it delegates the
reference rate to one wallet team and because the list can change upstream without this code
knowing. It is a snapshot: if legacy offers stop being accepted on mainnet, compare with the live
file first. Supersedes the "no default signer" part of ADR-012.

## ADR-014: fee ceilings that trust nobody

The legacy fee token is the wrapped base token, so the par rate is known: one base unit per wei
of gas (`PAR_RATE_WRAPPED_BASE_TOKEN`). The reference broadcaster adds a margin of 10 to 30%.
A ceiling at 1.5 times par therefore refuses a predatory or misconfigured broadcaster without
an oracle and without trusted signers, on every chain, and also when a trusted signer itself is
compromised. It complements the trust policy, it does not replace it: the band protects against
collusion at rates under the ceiling, the ceiling against everything above.

The absolute maximum covers what the rate cannot: a large gas estimate or a gas price spike.
It is checked after the dummy-proof estimate, the first moment the fee is known, and before the
proof, the first expensive step.

Both limits travel with the operation rather than the session: they are a per-payment decision,
and the front shows the offers they exclude while the user edits them. The wallet still does not
ask for a confirmation between quote and broadcast; the limits are what makes that acceptable.

Limit: this reasoning only holds for the wrapped base token. Another fee token needs a price.

## ADR-015: Waku light node in the wallet tab

Requested over a Node sidecar, to need nothing but the wallet binary and a browser. js-waku is
the only maintained light client and is what Railgun web wallets use. The tab is a dumb pipe:
it moves opaque payloads between the fleet and `BrowserBridge`; authentication of offers,
encryption of requests and every decision stay in the daemon. A hostile page cannot reach
`/api/waku/exchange` (Origin and Host checks), and what it could inject there would be unsigned
offers, dropped at verification.

Accepted cost: the legacy transport only works while the tab is open. Offers stop being
refreshed when it closes, and a broadcaster's answer arriving then is lost; the operation then
ends on the time-out, which already tells the user to sync and check the inputs before retrying.

No DNS discovery and no peer exchange, unlike the reference client: three fixed wss peers keep
`connect-src` to one domain and the bundle small. If the fleet changes its peers the constant
`FLEET_WSS_PEERS` has to follow; Railway's remote configuration lists no additional peer today.

The bundle is committed as a build artefact so that `cargo build` needs no Node toolchain.
Rebuild: `cd crates/railgun-wallet/waku-bridge && npm ci && npm run build`.

## ADR-016: one proof on the 4337 path, by fixing the gas limits first

`prepare_userop` re-proves until the fee matches the bundler's estimate, because the estimate
needs a valid proof and the proof binds the fee. Each round is a spending signature over
(merkle root, bound params, nullifiers, commitments): up to five confirmations on a Ledger, five
ceremonies with FROST.

A dummy proof cannot replace the rounds: the bundler simulates `validatePaymasterUserOp`, whose
caller must be the EntryPoint, so `tx.origin` cannot be the verification bypass address. What a
dummy proof can measure is the bare `transact` call. The paymaster verification limit is that
gas plus an overhead (fee note check, price quote, decoding) which depends on calldata size,
learned once per shape. The other limits barely move for a given shape and come from the same
profile.

The privacy paymaster requires `fee >= quote(maxCost)`, `maxCost` being limits times
`maxFeePerGas`, so choosing the limits determines the fee exactly. Cost of the approach: the
margin, never refunded (the Railgun adapter sets no refund recipient). Failure modes and their
handling:

* limits too low: detected on the real proof before sending; costs a second signature;
* tail calls out of gas after a native unshield: the only case that strands funds, on the
  ephemeral sender whose key the wallet records; the call limit is learned from real
  transactions of the same shape and padded by the margin;
* the fee is public in `paymasterData` and fee / maxFeePerGas gives the total gas. Limits padded
  by a fixed margin tell a single-proof wallet from an iterative one. Rounding to 10k gas hides
  the exact transaction, not the wallet family. Only a rule shared by all wallets would.

Not done: a gas table shipped with the wallet, which would remove the learning transaction. It
needs measurements on each chain. And `RailgunSigner` still exposes `spending_key()`, which a
hardware signer cannot implement: `TransactCircuitInputs` only needs the public key, a change
for the hardware integration itself.
