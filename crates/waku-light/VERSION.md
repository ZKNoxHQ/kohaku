# Changelog

## 0.1.4 (2026-09-23)

* Validated against the Railgun fleet (example `fleet`, Sepolia): 10 fee announcements from 3
  broadcasters in 60 s, no duplicate, relay-b and client-edge subscribed within 4 s. All three
  fleet nodes present identities other than the ones the reference client pins.
* `Config::dial_timeout`, 45 s by default instead of a fixed 20 s: relay-a took about 10 s to
  complete a dial and went past 20 s twice in a row.
* `Status::last_error` is cleared when a filter subscription succeeds, so a notice about an
  earlier dial or a dropped pin does not stay on a working node.

## 0.1.3 (2026-09-23)

* TLS and noise now pass against the fleet (0.1.1 fix confirmed). New failure on relay-a:
  `Unexpected peer ID 16Uiu2HAmMkCL…9AsR`, where the reference client, including 10.0.0 published
  on 2026-09-22, still pins `16Uiu2HAmFbD2…tG7x`. The fleet rotated that node's key.
* A pinned `/wss` bootstrap peer that answers with another identity is kept: the pin is
  dropped, logged at warn level with both ids, and the address is redialled at once without it.
  The certificate already authenticated the host. `Config::accept_rotated_wss_identity`
  (default true) turns this off.
* `/p2p/<id>` may be left out on `/wss` bootstrap addresses; it stays mandatory on any other
  address, and a pin on a non-wss address is always enforced (test `wrong_pin_on_ws_is_refused`).
* Dials are tracked by connection id, so an unpinned dial is matched to its bootstrap entry.

## 0.1.2 (2026-09-23)

* Example `probe`: dials one multiaddr and logs how far the connection gets (TLS, noise, muxer,
  identify, filter). For peers other than the fleet defaults, and for diagnosis.
* The TLS 1.2 fix of 0.1.1 was checked against the BearSSL that nwaku links (status-im/BearSSL
  7bea48e, `brssl server`, EC key, TLS 1.1 to 1.2, same negotiation as the fleet:
  ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 over Curve25519). Without `tls12` the dial ends in
  `received fatal alert: HandshakeFailure`, as reported on the fleet; with it the handshake
  completes.

## 0.1.1 (2026-09-23)

* Fix: every wss dial to the Railgun fleet failed with `received fatal alert: HandshakeFailure`.
  libp2p-websocket builds rustls without its `tls12` feature, so the client offered TLS 1.3
  only, and nwaku serves wss through nim-websock on BearSSL, which stops at TLS 1.2. `rustls`
  is now a direct dependency with `tls12`, which Cargo unifies into the one libp2p uses.
* Test `wss_client_offers_tls12` so the feature cannot silently drop out again.

## 0.1.0 (2026-09-23)

* Light node on rust-libp2p 0.57: WebSocket (ws/wss) over DNS and TCP, noise, yamux or mplex,
  identify, ping.
* Filter v2 client: subscribe, unsubscribe, unsubscribe all, subscriber ping every 60 s,
  resubscription when a ping or a subscribe fails, content topics sent in chunks of 100.
* Inbound filter push: pubsub topic and content topic checked, deduplicated by the RFC 14
  deterministic hash (several service nodes push the same message), bounded inbox.
* Light push v3, v2 when the peer does not announce v3 or refuses it as unsupported; sent to up
  to 3 peers at once, `PublishReport` with accepted count and per-peer failures.
* Metadata v1 served and queried; a peer on another cluster is ignored.
* Bootstrap peers only, redial with backoff 5 to 60 s. DNS falls back to Cloudflare without a
  system configuration.
* Protobufs derived by hand with prost, no protoc.
* Example `fleet`: passive listen on the Railgun fleet.
