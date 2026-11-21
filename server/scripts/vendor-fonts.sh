#!/usr/bin/env sh
# Vendors Source Serif 4 (SIL OFL) into server/fonts for deterministic, offline PDF rendering.
# Pin the release; after first download, record sha256 sums in fonts/SHA256SUMS and verify on every build.
set -eu
DIR="$(cd "$(dirname "$0")/.." && pwd)/fonts"
VER="4.005R"
mkdir -p "$DIR"
TMP="$(mktemp -d)"
curl -fsSL "https://github.com/adobe-fonts/source-serif/releases/download/${VER}/source-serif-${VER}.zip" -o "$TMP/ss.zip"
unzip -q "$TMP/ss.zip" -d "$TMP"
for f in SourceSerif4-Regular SourceSerif4-Semibold SourceSerif4-It; do
  cp "$(find "$TMP" -path '*WOFF2*' -name "$f.otf.woff2" | head -n1)" "$DIR/$f.woff2"
done
rm -rf "$TMP"
cd "$DIR"
if [ -f SHA256SUMS ]; then sha256sum -c SHA256SUMS; else sha256sum *.woff2 > SHA256SUMS; echo "Recorded SHA256SUMS — commit it."; fi
