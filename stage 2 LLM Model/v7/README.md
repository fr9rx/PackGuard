# PackGuard Stage 2 `v7` — Pretrained RoPE Student, Static AST De-obfuscator & 25-Feature Neural MIL

Stage 2 `v7` closes the obfuscation-recall and benign false-alarm gaps documented in Stage 2 `v6` ([`v6/results.json`](../v6/results.json)) while remaining **100% pure neural (`rules_override: false`)**, **CPU-only (`CPUExecutionProvider`)**, **`39.41 MB` INT8 ONNX**, and **zero-overlap verified** against all `22,684` untouched held-out sandbox packages (`zero_chunk_malware_count = 0`).

---

## 1. Full 22,684-Package Real Linux Sandbox Results (Standalone, Zero Stage 1, Zero Rules)

Evaluated strictly on CPU (`CPUExecutionProvider`) across all `22,684` untouched held-out packages (`2,549` benign npm packages, `11,050` known malware, `9,085` zero-day `new` malware; full breakdown in [`results.json`](results.json)):

| Metric | Stage 2 `v3` (`254 MB`) | Stage 2 `v5` (`8.5 MB`, sample) | Stage 2 `v6` (`13.21 MB`, `tau=0.945`) | **Stage 2 `v7` (`39.41 MB`, `tau=0.50`)** | **Stage 2 `v7` (`tau=0.62`)** |
|---|---:|---:|---:|---:|---:|
| **Network-Only ROC-AUC** | — | `0.271–0.392` | `0.97768` | **`0.99131`** | **`0.99131`** |
| **Benign Specificity (`2,549` pkgs)** | `84.7%` (`15.3%` FPR) | `72.0%` (`n=500`) | `96.59%` (`87` FPs / `3.41%` FPR) | **`98.90%` (`28` FPs / `1.10%` FPR)** | **`99.33%` (`17` FPs / `0.67%` FPR)** |
| **`known` Malware Recall (`11,050` pkgs)** | `79.8%` | — | `86.06%` (`9,510/11,050`) | **`91.86%` (`10,150/11,050`)** | — |
| **`new` Malware Recall (`9,085` pkgs)** | `84.7%` | — | `85.71%` (`7,787/9,085`) | **`92.90%` (`8,440/9,085`)** | — |
| **Overall Malware Recall (`20,135` pkgs)** | `82.0%` | `93.9%` (regex-driven) | `85.91%` (`17,297/20,135`) | **`92.33%` (`18,590/20,135`)** | **`90.60%` (`18,242/20,135`)** |
| **Precision / F1** | — | — | `99.50%` / `0.9220` | **`99.85%` / `0.9594`** | — |
| **Benign / Malware Median Prob** | — | `0.999` / `0.998` | `0.0400` / `0.9994` | **`0.0030` / `0.9631`** | **`0.0030` / `0.9631`** |
| **Rules / Allowlist Overrides** | Yes | Yes | None (`false`) | **None (`rules_override: false`)** | **None (`rules_override: false`)** |

- **Inference Latency:** Single-file snippets take `~2.3–12.9 ms` on CPU (`stage2_filter.py --self-test`); dedicated 4-thread ONNX CPU evaluation on `500` multi-file real packages measured **`76.72 ms` median / `96.24 ms` mean / `164.89 ms` P95** (`latency_4thr_sample.json`; 12-worker concurrent full-corpus sweep median `168.05 ms/pkg`).
- **Two Ready Operating Points (`best_threshold.json`):** At default `threshold = 0.50`, `v7` reduces benign false alarms by **`3.1x`** vs `v6` (`28` vs `87` FPs, and **`12.4x`** vs `v6` @ `0.50` with `346` FPs) while detecting **`+1,293` more malware packages**. Using `--threshold 0.62` cuts held-out FPs **`5.1x`** (`17` FPs = **`99.33%` specificity**) while still holding **`90.60%` recall**.

### Threshold Operating Sweep (All 22,684 Held-Out Packages)

| Threshold | Recall (`20,135` mal) | Benign Specificity (`2,549` ben) | Benign FPs (FPR) | Precision | F1 |
|---:|---:|---:|---:|---:|---:|
| `0.30` | `95.14%` | `97.41%` | `66` (`2.59%`) | — | — |
| `0.40` | `93.36%` | `98.19%` | `46` (`1.81%`) | — | — |
| **`0.50` (default)** | **`92.33%`** | **`98.90%`** | **`28` (`1.10%`)** | **`99.85%`** | **`0.9594`** |
| **`0.62` (high-precision)** | **`90.60%`** | **`99.33%`** | **`17` (`0.67%`)** | — | — |
| `0.70` | `88.33%` | `99.53%` | `12` (`0.47%`) | — | — |
| `0.80` | `82.03%` | `99.72%` | `7` (`0.28%`) | — | — |
| `0.90` | `69.56%` | `99.80%` | `5` (`0.20%`) | — | — |
| `0.95` | `56.20%` | `99.92%` | `2` (`0.08%`) | — | — |

---

## 2. Key Upgrades Over Stage 2 `v6` & Category Improvements

| Gap Identified in `v6` | Root Cause in `v6` | How `v7` Solves It |
|---|---|---|
| **`encoded_loader` (`1.17%`), `split_payload` (`5.33%`), `eval_decode` (`19.33%`)** | `v6` only folded adjacent literals up to `80` chars (`{1,80}`) and missed multi-variable concat, `_0x` string tables, reversed Base64, URI encoding, and XOR/Caesar `fromCharCode` maps. | [`ast_deobfuscator.py`](ast_deobfuscator.py): zero-dependency static JS constant-folder & multi-layer decoder (no 80-char cap, symbol table for vars/arrays/templates, reversed/URI/XOR/shift/nested Base64 & Hex). **`encoded_loader`, `split_payload`, and `eval_decode` all jump to `100.0%` recall.** |
| **`T2_rename` (`48.49%`), `crypto_miner` (`64.67%`), `env_dump` (`70.67%`), `stream_clone` (`37.67%`)** | Formatting bloat cut off code at 2,200 chars; random-init `384d` Student lacked 2T-token JS priors and `T1`/`T2`/skimmer coverage. | Security-density windowing + symmetric evasion augmentation + **pretrained 6-layer ModernBERT-base RoPE + GeGLU (`768d`, Rank-160 SVD)** ([`model_v7.py`](model_v7.py)): **`T2_rename` `93.96%`, `crypto_miner` `100.0%`, `env_dump` `89.67%`, `env_exec_net` `100.0%`, `telegram_bot` `100.0%`.** |
| **High Benign False Alarms on Utilities & Multi-File Packages** | Raw `max(window_probs)` flagged single benign `os`/`axios`/utility files and lacked HTTP-vs-exfil context or KL regularization. | **25-feature `PackageMILAggregator` (`25 -> 24 -> 1`)** ([`metrics_v7.py`](metrics_v7.py)) fusing window-logit stats `[0..9]`, 8-class tactic logits `[10..15]`, and package-wide source-vs-sink / HTTP-only capability features `[16..24]`, plus **centered `(logit - 1.3493) / 1.35` calibration on `dev_val`** (`810/811` = `99.88%` dev_val spec) and KL-anchored LoRA (`lora_patch_summary.json`). |
| **`chunks: 0` Zero-Score Risk & `99.99.99` Dependency Confusion** | Extensionless CLIs, renamed files, and metadata-only packages were skipped in earlier parsers. | [`record_builder.py`](record_builder.py) inspects `package.json` entrypoints, shebang extensionless scripts, and name-neutral `// [PACKAGE_META]` fallbacks → **`zero_chunk_malware_count = 0`** and **`script_dependency_confusion = 100.0%`**. |
| **Explainability** | Binary score only. | Dual-output INT8 ONNX (`binary_logits [B, 2]` + 8-class `tactic_logits [B, 8]`) + `top_window_file` provenance + optional `--stage1-fusion`. |

### Transparent Remaining Gaps (`results.json`)
- Tightening centered `dev_val` calibration to `810/811` (`98.90%–99.33%` held-out specificity) reduced recall on heavy padding/custom-encoded outliers compared to `v6` (`known/T3_padding`: `100.0% -> 50.94%`, `new/mal_encoded`: `96.25% -> 66.75%`, `new/stream_clone`: `55.67%`), while **`32` evaluated groups (`31` at `100.0%`)** hit `99.6%–100.0%` recall (`0` zero-chunk malware misses).

---

## 3. Architecture & Training Summary

- **Dataset (`dataset_manifest.json`):** `4,492` real benign + `2,639` real malware packages → `26,490` 50/50 windows (`train`), `11,396` MIL bags, `1,368` `dev_val` packages (`811` benign / `557` malware), `leakage_verified_zero_overlap = true` against all `22,684` held-out test packages.
- **KL-LoRA Teacher & Hard Benign Patch (`lora_patch_summary.json`):** Raised `dev_val` `@0.50` specificity from `91.74%` → `94.33%` (ROC-AUC `0.97886` → `0.98008`; calibrated recall `89.77%` → `91.92%` at `98.64%` specificity).
- **Student (`quality`, shipped ONNX):** 6-layer `ModernBERT-base` RoPE + GeGLU (`768d`, 12 heads, Rank-160 SVD embeddings) quantized via dynamic INT8 ONNX to **`39.411 MB`** (`41,325,323` bytes, down from `153.95 MB` FP32), achieving `14/14` self-test pass at both `0.50` (`axios` = `0.4661`, benign utilities `0.0059–0.1632`, malicious probes `0.9648–0.9933`) and `0.62`.

---

## 4. Usage

### Install Released ONNX Bundle & Verify (`14/14` CPU Self-Test)
See [`MODEL_DOWNLOAD.md`](MODEL_DOWNLOAD.md) for checksums and direct asset links.
```bash
# Linux / macOS
bash "stage 2 LLM Model/v7/install_model.sh"

# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File "stage 2 LLM Model/v7/install_model.ps1"

# Verify 14/14 regression & obfuscation probes on CPU (default tau=0.50 and strict tau=0.62)
python "stage 2 LLM Model/v7/stage2_filter.py" --self-test
python "stage 2 LLM Model/v7/stage2_filter.py" --self-test --threshold 0.62
python "stage 2 LLM Model/v7/test_v7_local.py"
```

### Scan a Folder of Packages or `.tgz` Archives (Standalone)
```bash
python "stage 2 LLM Model/v7/stage2_scan_folder.py" \
  --packages /path/to/packages \
  --out-dir /path/to/out \
  --threads 4
```

### Chain After Stage 1 (`packguard-cli --stage2`)
```bash
packguard-cli scan /path/to/packages \
  --stage2 \
  --stage2-script "stage 2 LLM Model/v7/stage2_filter.py" \
  --stage2-model "stage 2 LLM Model/v7/model_int8"
```
