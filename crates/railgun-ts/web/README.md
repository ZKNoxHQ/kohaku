# Railgun web wallet (static page)

`index.html` drives the `railgun-ts` wasm bindings: sync and balance (IndexedDB), Ledger over WebUSB
or Bluetooth, transfers through ERC-4337 (Pimlico bundler, privacy paymaster) or through a Railgun
broadcaster reached by the Rust Waku light node running in the page (`Broadcasters`,
`RailgunProvider.sendViaBroadcaster`). No server and no proxy.

    bash crates/railgun-ts/build-web.sh            # -> crates/railgun-ts/dist
    python3 -m http.server 8000 -d crates/railgun-ts/dist

WebUSB and Web Bluetooth need a secure context: `http://localhost` or an https host. The whole site
(wallet + viewer) is built by `web-site/build.sh`.
