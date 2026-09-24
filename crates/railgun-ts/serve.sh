#!/usr/bin/env bash
# Release the browser wallet test page: rebuild wasm, (re)start the dev server
# (static + /poi proxy) on :8000, (re)start the cloudflared tunnel, print the URL.
set -euo pipefail
cd "$(dirname "$0")"   # crates/railgun-ts

echo "==> building wasm (wasm-pack)"
~/.cargo/bin/wasm-pack build --target web --out-name index --out-dir pkg

echo "==> (re)starting dev server on :8000"
fuser -k 8000/tcp 2>/dev/null || true
sleep 1
nohup python3 dev-server.py >/tmp/railgun-httpd.log 2>&1 & disown

echo "==> (re)starting cloudflared tunnel"
pkill -f "cloudflared tunnel --url http://localhost:8000" 2>/dev/null || true
: >/tmp/railgun-tunnel.log
sleep 1
nohup ~/.local/bin/cloudflared tunnel --url http://localhost:8000 >/tmp/railgun-tunnel.log 2>&1 & disown

echo "==> waiting for tunnel URL..."
url=""
for _ in $(seq 1 30); do
  url=$(grep -oE "https://[a-z0-9-]+\.trycloudflare\.com" /tmp/railgun-tunnel.log | head -1 || true)
  [ -n "$url" ] && break
  sleep 1
done

echo
if [ -n "$url" ]; then
  echo "Wallet URL:  $url/test-wallet.html"
  echo "Ledger test: $url/test-ledger.html"
else
  echo "tunnel URL not found yet — check /tmp/railgun-tunnel.log"
fi
