#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PG_PYTHON:-$HOME/pg-venv/bin/python}"
PACKAGES="${1:-$HOME/pg-scan/packages}"
OUT_DIR="${2:-$HOME/pg-scan/stage2}"
exec "$PYTHON" "$SCRIPT_DIR/stage2_scan_folder.py" --packages "$PACKAGES" --out-dir "$OUT_DIR"
