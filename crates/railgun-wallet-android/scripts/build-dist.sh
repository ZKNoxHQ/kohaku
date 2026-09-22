#!/bin/sh
# Builds dist/ from the desktop front. The HTML is copied, never forked: only a stylesheet and
# the IPC shim are injected into <head>.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
src="$here/../railgun-wallet/static"

[ -f "$src/index.html" ] || { echo "missing $src/index.html" >&2; exit 1; }

cp "$src/waku-bundle.js" "$here/dist/waku-bundle.js"
sed 's#</head>#<link rel="stylesheet" href="mobile.css">\n<script src="tauri-shim.js"></script>\n</head>#' \
  "$src/index.html" > "$here/dist/index.html"

grep -q 'tauri-shim.js' "$here/dist/index.html" || { echo "injection failed" >&2; exit 1; }
echo "dist/ built from $src"
