#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL_DIR="${SCRIPT_DIR}/model_int8"
ARCHIVE="${SCRIPT_DIR}/packguard-stage2-v6-onnx.tar.gz"
URL="https://github.com/asembarhoush-dotcom/PackGuard/releases/download/v2.0-model/packguard-stage2-v6-onnx.tar.gz"
EXPECTED_SHA256="9f6b70019ecee915e4c39c697e1199f8d6a664ea6ebb3f9101b7e2bf8cf415a7"

mkdir -p "${MODEL_DIR}"
echo "[PackGuard Stage 2 v6] Downloading ONNX INT8 model + real ModernBERT tokenizer (12.41 MB)..."
curl -fL --retry 3 -o "${ARCHIVE}" "${URL}"

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_SHA256="$(sha256sum "${ARCHIVE}" | awk '{print $1}')"
else
  ACTUAL_SHA256="$(shasum -a 256 "${ARCHIVE}" | awk '{print $1}')"
fi
if [ "${ACTUAL_SHA256}" != "${EXPECTED_SHA256}" ]; then
  echo "ERROR: SHA-256 mismatch! expected=${EXPECTED_SHA256} actual=${ACTUAL_SHA256}" >&2
  rm -f "${ARCHIVE}"
  exit 1
fi

tar -xzf "${ARCHIVE}" -C "${MODEL_DIR}"
rm -f "${ARCHIVE}"

echo "[PackGuard Stage 2 v6] Installed to ${MODEL_DIR} (SHA-256 verified)."
ls -lh "${MODEL_DIR}"
