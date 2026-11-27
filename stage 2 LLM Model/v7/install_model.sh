#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL_DIR="${SCRIPT_DIR}/model_int8"
ARCHIVE="${SCRIPT_DIR}/packguard-stage2-v7-onnx.tar.gz"
URL="${PACKGUARD_V7_MODEL_URL:-https://github.com/asembarhoush-dotcom/PackGuard/releases/download/v2.0-model/packguard-stage2-v7-onnx.tar.gz}"
EXPECTED_SHA256="${PACKGUARD_V7_SHA256:-f3e2881aa71b1b20f7d51f16e4ae02cbc67bdad481d6eaa923126b174e9a83d4}"

mkdir -p "${MODEL_DIR}"
echo "[PackGuard Stage 2 v7] Downloading ONNX INT8 model + real ModernBERT tokenizer..."
curl -fL --retry 3 -o "${ARCHIVE}" "${URL}"

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_SHA256="$(sha256sum "${ARCHIVE}" | awk '{print $1}')"
else
  ACTUAL_SHA256="$(shasum -a 256 "${ARCHIVE}" | awk '{print $1}')"
fi

if [ "${EXPECTED_SHA256}" != "PENDING_V7_RELEASE_SHA256" ] && [ "${ACTUAL_SHA256}" != "${EXPECTED_SHA256}" ]; then
  echo "ERROR: SHA-256 mismatch! expected=${EXPECTED_SHA256} actual=${ACTUAL_SHA256}" >&2
  rm -f "${ARCHIVE}"
  exit 1
fi

tar -xzf "${ARCHIVE}" -C "${MODEL_DIR}"
rm -f "${ARCHIVE}"

echo "[PackGuard Stage 2 v7] Installed to ${MODEL_DIR} (sha256=${ACTUAL_SHA256})."
ls -lh "${MODEL_DIR}"
