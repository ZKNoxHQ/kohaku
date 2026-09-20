# Architecture decisions

## ADR-001: protocol crate, no proving

The crate stops at `BroadcastRequest`: calldata, `minGasPrice` and pre-transaction POIs come in
ready-made. Proving needs `&mut RailgunProvider`, gas estimation needs an RPC; both belong to
the application. The crate depends on `railgun` only for the 0zk address decoder and the
`PreTransactionPois` type.

## ADR-002: own channel cryptography, not `railgun::crypto::SharedKey`

Notes use `sha256(scalar * EdwardsPoint)`. The broadcaster channel uses noble's
`getSharedSecret`, an X25519 exchange with the raw output as key. Found by reading the wallet
SDK while writing this crate; the earlier plan to reuse `SharedKey` was wrong, and the
visibility change made for it in `railgun` 0.3.0 is unused.

## ADR-003: Waku through a local nwaku over REST

No mature Rust implementation of Waku relay or light push exists. nwaku is what broadcasters
themselves run, its REST API is small and stable, and the trait keeps a libwaku FFI or a js-waku
bridge possible. Cost: the user runs a node. `poll()` drains every content topic at once because
that is how the REST cache works; the client routes fees and responses from the single drain.

## ADR-004: one drain, two consumers

The fee monitor and `send()` both call `pump()`. Responses are kept in a short backlog rather
than handed to whoever polled, so a response drained by the monitor is still found by `send()`.
`send()` clears the backlog first: nothing older than the request can be its answer.

## ADR-005: trusted fee signers follow the reference, with one deviation

Implemented as in `waku-broadcaster-client`: authorized rate from the trusted signers (average),
band of 10% under and 30% over with the same integer rounding, filter on arrival and at
selection, nothing usable without an authorized rate. Kept as is, including the consequence that
with several signers far apart, a signer's own offer can fall outside the band of the average.

Deviation: the reference compares lowercase address strings. A 0zk address has a chain-agnostic
and a chain-scoped encoding of the same keys, and broadcasters announce the scoped one, so a
signer configured from what a wallet displays would never match. Signers are compared on
(master public key, viewing public key).

The policy is optional in the crate. Requiring it is the application's call: the wallet requires
it on mainnet only.
