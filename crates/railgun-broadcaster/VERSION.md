# Changelog

## 0.4.1 (2026-09-20)

* `NoQuote::PoiListMismatch`: offers exist but require POI lists the caller does not prove
  against. Before, this case was reported as an empty market.
* `MockBroadcaster::required_poi_list_keys`, and a regression test for list matching.

## 0.4.0 (2026-09-20)

* `BrowserBridge` transport: the Waku node runs elsewhere (js-waku in a browser tab) and calls
  `exchange()` to hand over received messages and take the ones to publish. Reports itself
  unreachable when the remote node stops calling or is not connected; queued publishes expire
  after 30 s.
* `TransportError::Remote`, `wire::{CLUSTER_ID, SHARD_ID, FLEET_WSS_PEERS}`.

## 0.3.0 (2026-09-20)

* `BroadcasterClient::best_quote(token, list_keys, max_rate)` and `FeeCache::best_quote`:
  cheapest usable offer under an optional rate ceiling. `NoQuote::AboveCeiling` reports the
  cheapest rate refused, so a caller can tell an empty market from an expensive one.
* `PAR_RATE_WRAPPED_BASE_TOKEN`: the rate at which the fee equals the gas cost when the fee
  token is the wrapped base token.
* `fake_network` takes the announced rate as a fourth argument, in hundredths of the gas cost
  (default 112).

## 0.2.1 (2026-09-20)

* `RAILWAY_TRUSTED_FEE_SIGNERS`: the four trusted fee signers of the Railway wallet, from its
  remote configuration read on 2026-09-20. Exported, never applied implicitly. A unit test checks
  that each entry is a valid 0zk address and that the four keys are distinct.

## 0.2.0 (2026-09-19)

* Trusted fee signers, after `trustedFeeSigner` of the reference client:
  `BroadcasterClient::with_trusted_signers`, `TrustPolicy`, `authorized_fees()`.
  * A trusted signer's announcements set the authorized rate per token, averaged over the
    signers with a live announcement (one expiring within 40 s does not count).
  * Other broadcasters are kept only within `[authorized - 10%, authorized + 30%]`, checked on
    arrival and again at selection, since the authorized rate moves.
  * With signers set and no authorized rate for a token, no offer is usable for it.
  * Signers are matched on their keys, not on the address string, so a chain-agnostic address
    in the configuration matches a chain-scoped one on the wire.
* `FeeError::TrustedSigner` for a configuration entry that is not a 0zk address.

## 0.1.0 (2026-09-19)

* First version: wire format, channel cryptography, fee cache and selection, client with retry
  schedule, nwaku REST transport, in-memory hub, mock broadcaster, `fake_network` example.
