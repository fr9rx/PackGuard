#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-$HOME/pg-test-sets}"
SEED="${SEED:-20261106}"
DERIVED="${DERIVED:-600}"
PER_CATEGORY="${PER_CATEGORY:-300}"
KNOWN_REAL="${KNOWN_REAL:-1200}"
THREADS="${THREADS:-32}"

mkdir -p "$OUT"

python3 "$HERE/generate_invented.py" \
    --derived-bases "$DERIVED" \
    --per-category "$PER_CATEGORY" \
    --seed "$SEED" \
    --known-out "$OUT/known/invented" \
    --new-out "$OUT/new/invented" \
    --manifest "$OUT/manifest_invented.json"

python3 "$HERE/build_real.py" \
    --out "$OUT" \
    --cache "$OUT/cache" \
    --known-count "$KNOWN_REAL" \
    --seed "$SEED" \
    --threads "$THREADS" \
    "$@"

python3 "$HERE/summarize.py" \
    --manifest "$OUT/manifest_invented.json" \
    --manifest "$OUT/manifest_real.json" \
    --json-out "$OUT/stats.json"

du -sh "$OUT" 2>/dev/null || true
