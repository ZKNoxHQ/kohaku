#!/usr/bin/env bash
# Static site with the two pages: web-site/dist/{index.html, wallet/, viewer/}. Any static host
# works (GitHub Pages, Netlify Drop, a folder of an existing site): no server, no proxy.
#   LTO=false bash web-site/build.sh     (faster, larger)
set -eu
cd "$(dirname "$0")/.."
bash crates/railgun-viewer-web/build.sh
bash crates/railgun-ts/build-web.sh
OUT=web-site/dist
rm -rf "$OUT"
mkdir -p "$OUT"
cp -r crates/railgun-viewer-web/dist "$OUT/viewer"
cp -r crates/railgun-ts/dist "$OUT/wallet"
cp web-site/index.html "$OUT/index.html"
touch "$OUT/.nojekyll"
du -sh "$OUT" "$OUT/wallet" "$OUT/viewer"
