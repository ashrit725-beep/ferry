#!/usr/bin/env bash
# CONNECTED SIDE ONLY. Downloads the demo model from a pinned Hugging Face
# revision and checks it against the SHA-256 that Hugging Face publishes for that
# file. Nothing on the disconnected side ever runs this script.
set -euo pipefail
cd "$(dirname "$0")/.."

REPO="Qwen/Qwen2.5-0.5B-Instruct-GGUF"
REV="9217f5db79a29953eb74d5343926648285ec7e67"
FILE="qwen2.5-0.5b-instruct-q4_k_m.gguf"
SHA256="74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db"
DEST=".cache/upstream/qwen2.5-0.5b-instruct-gguf"
BASE="https://huggingface.co/$REPO/resolve/$REV"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

mkdir -p "$DEST"
if [ ! -f "$DEST/$FILE" ]; then
  echo "Downloading $FILE (491,400,032 bytes) from $REPO at revision $REV"
  curl -fL --retry 3 -o "$DEST/$FILE.part" "$BASE/$FILE"
  mv "$DEST/$FILE.part" "$DEST/$FILE"
fi
[ -f "$DEST/LICENSE" ] || curl -fsSL --retry 3 -o "$DEST/LICENSE" "$BASE/LICENSE"

actual="$(sha256_of "$DEST/$FILE")"
if [ "$actual" != "$SHA256" ]; then
  echo "SHA-256 mismatch for $DEST/$FILE: expected $SHA256, got $actual" >&2
  exit 1
fi
echo "OK: $DEST/$FILE matches the published SHA-256 $SHA256"
