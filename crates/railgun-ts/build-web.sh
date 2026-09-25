#!/usr/bin/env bash
# Railgun web wallet: builds the static page into crates/railgun-ts/dist (index.html, pkg/).
# Needs the wasm32-unknown-unknown target and wasm-bindgen-cli at the lockfile's version
# (0.2.108); wasm-opt is used when present. No server, no proxy: the page talks to the RPC, the
# POI node, the bundler and the Waku network directly.
#   LTO=false bash crates/railgun-ts/build-web.sh     (faster, larger)
set -eu
cd "$(dirname "$0")/../.."
CARGO=${CARGO:-cargo}
WASM_BINDGEN=${WASM_BINDGEN:-wasm-bindgen}
OUT=crates/railgun-ts/dist
WASM=target/wasm32-unknown-unknown/release/railgun_ts.wasm

CARGO_PROFILE_RELEASE_LTO=${LTO:-true} CARGO_PROFILE_RELEASE_CODEGEN_UNITS=${CODEGEN_UNITS:-1} \
  $CARGO build --release --target wasm32-unknown-unknown -p railgun-ts ${CARGO_EXTRA:-}

rm -rf "$OUT"
mkdir -p "$OUT"
$WASM_BINDGEN --target web --no-typescript --out-dir "$OUT/pkg" --out-name index "$WASM"
if command -v wasm-opt >/dev/null 2>&1; then
  wasm-opt -O2 --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext \
    --enable-mutable-globals --enable-reference-types "$OUT/pkg/index_bg.wasm" -o "$OUT/pkg/index_bg.wasm"
fi
cp crates/railgun-ts/web/index.html "$OUT/index.html"
ls -la "$OUT" "$OUT/pkg"
