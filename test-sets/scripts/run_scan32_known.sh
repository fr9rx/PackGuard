#!/usr/bin/env bash
set -euo pipefail
cd /home/fr9rx/packguard

packguard-cli \
  --mode known \
  --refs /home/fr9rx/packguard-data/combined/malware_js \
  --benign /home/fr9rx/packguard-data/v7/benign_refs \
  --scan-dir /home/fr9rx/pg-test-sets/known/flat \
  --reports /home/fr9rx/pg-test-sets/reports-32-known \
  --threads 32 \
  --stage2 \
  --stage2-model "/home/fr9rx/packguard/stage 2 LLM Model/v3/model_int8" \
  --stage2-python /home/fr9rx/pg-venv/bin/python \
  --stage2-script "/home/fr9rx/packguard/stage 2 LLM Model/v3/stage2_filter.py"
