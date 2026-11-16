#!/usr/bin/env bash
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-$HOME/pg-curve}"
THREADS="${THREADS:-3}"
PACKGUARD="${PACKGUARD:-packguard}"
FRACTIONS="${FRACTIONS:-010 025 050 075 100}"

for seed in "$@"; do
    for f in $FRACTIONS; do
        base="$OUT/seed$seed/p$f"
        for dir in "$OUT"/test/*/; do
            cat="$(basename "$dir")"
            report="$base/reports/$cat"
            if [ -e "$report.done" ]; then
                echo "$(date -Is) seed=$seed p$f $cat skip (done)"
                continue
            fi
            echo "$(date -Is) seed=$seed p$f $cat start"
            rm -rf "$report"
            mkdir -p "$report"
            start=$(date +%s)
            "$PACKGUARD" --mode known -j "$THREADS" -B "$base/benign" -d "$report" "$base/malware" "$OUT/test/$cat"/* >/dev/null 2>"$report.log"
            status=$?
            secs=$(( $(date +%s) - start ))
            if [ "$status" -eq 0 ]; then
                echo "$secs $status" > "$report.done"
                echo "$(date -Is) seed=$seed p$f $cat finished ${secs}s status=$status"
            else
                echo "$(date -Is) seed=$seed p$f $cat FAILED status=$status after ${secs}s"
            fi
        done
    done
done

python3 "$HERE/summarize_curve.py" --out "$OUT"
echo "ALL DONE $(date -Is)"
