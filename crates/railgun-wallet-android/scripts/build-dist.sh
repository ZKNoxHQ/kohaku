#!/bin/sh
# Builds dist/ from the desktop front plus front/. Everything in dist/ is generated, which is why
# it is not committed: the repository's root .gitignore holds `dist/`.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
src="$here/../railgun-wallet/static"

[ -f "$src/index.html" ] || { echo "missing $src/index.html" >&2; exit 1; }
[ -f "$here/front/tauri-shim.js" ] || { echo "missing front/tauri-shim.js" >&2; exit 1; }

mkdir -p "$here/dist"
cp "$here/front/tauri-shim.js" "$here/front/mobile.css" "$here/dist/"
cp "$src/waku-bundle.js" "$here/dist/waku-bundle.js"
sed 's#</head>#<link rel="stylesheet" href="mobile.css">\n<script src="tauri-shim.js"></script>\n</head>#' \
  "$src/index.html" > "$here/dist/index.html"

grep -q 'tauri-shim.js' "$here/dist/index.html" || { echo "injection failed" >&2; exit 1; }
echo "dist/ built from $src and front/"
