#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-$HOME/pg-test-sets}"
REFS="${REFS:-$HOME/packguard-data/combined/malware_js}"
BENIGN="${BENIGN:-$HOME/packguard-data/v7/benign_refs}"
THREADS="${THREADS:-4}"
MODE="${1:-new}"
SETS="${2:-${SETS:-new known}}"
KINDS="${KINDS:-invented real}"
CATEGORIES="${CATEGORIES:-}"
LIMIT="${LIMIT:-0}"

mkdir -p "$OUT/reports"

scan_category() {
    local set_name="$1" kind="$2" category="$3"
    local source="$OUT/$set_name/$kind/$category"
    [ -d "$source" ] || return 0
    local dest="$OUT/reports/$set_name/$kind/$category"
    mkdir -p "$dest"
    local targets=("$source"/*)
    [ -e "${targets[0]}" ] || return 0
    if [ "$LIMIT" -gt 0 ]; then
        targets=("${targets[@]:0:$LIMIT}")
    fi
    echo "[scan] $MODE $set_name/$kind/$category ${#targets[@]} packages"
    if [ "$MODE" = "known" ]; then
        packguard --mode known -j "$THREADS" -B "$BENIGN" -d "$dest" "$REFS" "${targets[@]}"
    else
        packguard --mode new -j "$THREADS" -d "$dest" "$REFS" "${targets[@]}"
    fi
}

for set_name in $SETS; do
    for kind in $KINDS; do
        base="$OUT/$set_name/$kind"
        [ -d "$base" ] || continue
        if [ -n "$CATEGORIES" ]; then
            for category in $CATEGORIES; do
                scan_category "$set_name" "$kind" "$category"
            done
        else
            for category in "$base"/*; do
                [ -d "$category" ] || continue
                scan_category "$set_name" "$kind" "$(basename "$category")"
            done
        fi
    done
done

python3 "$HERE/summarize.py" --reports "$OUT/reports" --json-out "$OUT/report_stats.json"
