# Architecture decisions

## ADR-001: a Waku light client of our own on rust-libp2p

No Rust Waku client exists; the alternatives were a local nwaku (the user runs a node), libwaku
over FFI (Nim toolchain, heavy on Android) or js-waku in a browser tab (what the wallet did until
now, the tab must stay open). A light node only needs four request/response protocols on top of
libp2p, each a single length-prefixed protobuf per stream direction, so writing them is small and
removes the JavaScript dependency.

## ADR-002: raw streams (`libp2p-stream`), not `request-response`

Waku protocols open one stream per exchange, and filter push is inbound without an answer. With
`libp2p-stream` each protocol is a short async function over a stream, callable from any task
through a cloned `Control`; the swarm task only dials, tracks connections and reads identify.

## ADR-003: yamux and mplex, both offered

The js-waku bundle negotiates mplex only, which proves the fleet accepts it; nwaku also speaks
yamux. Offering yamux first and mplex second keeps the maintained muxer while staying compatible
with a node that would only take mplex.

## ADR-004: metadata served and queried

On a sharded cluster nwaku queries every new peer's metadata and disconnects on failure or on
a different cluster. Shards are written unpacked, as nwaku writes them.

## ADR-005: deduplicate by the deterministic message hash

The node subscribes with every connected service node for resilience, so each message arrives
several times. The RFC 14 hash (pubsub topic, payload, content topic, meta, timestamp) is the
identity nwaku itself uses.

## ADR-006: TLS 1.2 enabled for wss

libp2p-websocket depends on rustls with only `ring` and `std`; its client config asks for the
safe default protocol versions, which without `tls12` means TLS 1.3 alone. The fleet's wss
endpoints are nwaku over nim-websock and BearSSL, TLS 1.2 at most: the server answers the
ClientHello with a handshake_failure alert. Browsers were fine because they offer both. We turn
the feature on from this crate rather than build our own TLS config, which would mean replacing
the websocket transport's TLS setup for one flag. rustls still refuses the weak TLS 1.2 suites
(no CBC, no RSA key exchange); if a peer only offered those, the dial would fail the same way.
Reproduced locally with `brssl server` built from status-im/BearSSL (the copy vendored by
nim-bearssl): HandshakeFailure without the feature, full handshake with it.

## ADR-007: a rotated identity on a wss bootstrap peer is accepted, not refused

relay-a.rootedinprivacy.com answers with a libp2p key other than the one every copy of the
reference client pins, up to 10.0.0. Refusing it would cost one of three fleet nodes until a new
client release, and a release would not help nodes already shipped. Over `/wss` the TLS
certificate, checked against the webpki roots, already authenticates the host name the fleet
operator controls; the libp2p pin adds protection only against someone holding a valid
certificate for that name. On `/ws` or `/tcp` the pin is the only authentication, so there it is
enforced. The change of identity is logged with both ids so that a real key change can be told
apart from an attack after the fact.
