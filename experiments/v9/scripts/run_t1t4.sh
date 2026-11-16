#!/usr/bin/env bash
set -uo pipefail

if [ "$#" -ne 3 ]; then
    echo "usage: run_t1t4.sh <label> <malware_ref_dir> <benign_ref_dir>" >&2
    exit 2
fi

LABEL="$1"
MAL="$2"
BEN="$3"
OUT="${OUT:-$HOME/pg-t1t4}"
THREADS="${THREADS:-3}"
PACKGUARD="${PACKGUARD:-packguard}"
HERE="$(cd "$(dirname "$0")" && pwd)"
BASE="$OUT/$LABEL"

mkdir -p "$BASE"
mal_count=$(find "$MAL" -mindepth 1 -maxdepth 1 -type d | wc -l)
ben_count=$(find "$BEN" -mindepth 1 -maxdepth 1 -type d | wc -l)
echo "$mal_count $ben_count" > "$BASE/refs.txt"

failed=0
for dir in "$OUT"/test/*/; do
    tier="$(basename "$dir")"
    report="$BASE/reports/$tier"
    if [ -e "$report.done" ]; then
        echo "$(date -Is) $LABEL $tier skip (done)"
        continue
    fi
    echo "$(date -Is) $LABEL $tier start"
    rm -rf "$report"
    mkdir -p "$report"
    start=$(date +%s)
    "$PACKGUARD" --mode known -j "$THREADS" -B "$BEN" -d "$report" "$MAL" "$OUT/test/$tier"/* >/dev/null 2>"$report.log"
    status=$?
    secs=$(( $(date +%s) - start ))
    if [ "$status" -eq 0 ]; then
        echo "$secs $status" > "$report.done"
        echo "$(date -Is) $LABEL $tier finished ${secs}s status=$status"
    else
        failed=1
        echo "$(date -Is) $LABEL $tier FAILED status=$status after ${secs}s"
    fi
done

python3 "$HERE/summarize_t1t4.py" --out "$OUT"
echo "DONE $LABEL failed=$failed $(date -Is)"
exit "$failed"
