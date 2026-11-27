# Stage 2 v6: standalone test and check against the v3 and v5 flaws (2026-11-25)

## What was run

Stage 2 v6 (`packguard_v6_nano_int8.onnx`, SHA-256 `0a0ed0783067b5386df88d94b234570a752bc2c420257b17d71aa18ab4970ae2`, threshold 0.945) scored every package directly, with no Stage 1 gate, on the same 3-vCPU Debian server and the same sets as the v3 and v5 tests:

| Set | Packages |
|---|---|
| `known` (malicious) | 11,050 |
| `new` (malicious) | 9,085 |
| `benign` (v7 benign references) | 2,549 |

- The model was installed with `install_model.sh`; the archive and ONNX checksums match `MODEL_DOWNLOAD.md`.
- Packages were read with v6's own `package_dir_to_record()` and `build_package_windows()` and scored one at a time with 3 ONNX threads, so the latency is per package.
- v3 figures are its full-set run (`~/pg-test-sets/stage2/`). v5 figures are its stratified sample (30 per category and 500 benign, `~/pg-test-sets/diag5/`). v6 was also scored on that exact sample.
- Categories come from `test-sets/manifest_*.json`; 7 packages (4 `known`, 3 `new`) do not map to a category and are only in the totals.
- Harness: `flaw_check_v6.py score probes transforms padding leak report`. Raw rows and summaries are in `~/pg-test-sets/diag6/` on the server.

Limits: this is Stage 2 alone, not the pipeline. The benign set has no install scripts (0 of 2,549), so benign install hooks were only probed by hand. Training was not rerun; training-side claims were checked in the code.

## Result

| | v3 (full sets, 0.62) | v5 (sample, 0.62) | **v6 (full sets, 0.945)** | v6 (full sets, 0.62) |
|---|---|---|---|---|
| `known` recall | 8,822/11,050 (79.8%) | — | **9,508/11,050 (86.0%)** | 10,243/11,050 (92.7%) |
| `new` recall | 7,696/9,085 (84.7%) | — | **7,786/9,085 (85.7%)** | 8,863/9,085 (97.6%) |
| All malicious | 16,518/20,135 (82.0%) | 1,267/1,350 (93.9%) | **17,294/20,135 (85.9%)** | 19,106/20,135 (94.9%) |
| **Benign flagged** | 390/2,549 (15.3%) | 140/500 (28.0%) | **87/2,549 (3.41%)** | 283/2,549 (11.1%) |
| AUC | 0.886 (final score) | 0.27–0.39 (network) | **0.978** | 0.978 |
| Median latency per package | 844 ms | 5 ms | **69 ms** | 69 ms |

On the exact v5 sample (1,350 malicious, 500 benign):

| | Malicious flagged | Benign flagged |
|---|---|---|
| v5 at 0.62 | 1,267 (93.9%) | 140 (28.0%) |
| v6 at 0.945 | 1,165 (86.3%) | 18 (3.6%) |
| v6 at 0.62 | 1,280 (94.8%) | 57 (11.4%) |

The published v6 figures reproduce: AUC 0.97768, 87 benign flagged, and `known`/`new` within 3 packages of `results.json`. That gap comes from scoring one package at a time instead of in batches of 16.

### Network-only operating points (all 22,684 packages)

| Threshold | Benign flagged | Recall (all) | `known` | `new` | Precision |
|---|---|---|---|---|---|
| 0.50 | 344 (13.5%) | 96.1% | 94.2% | 98.4% | 98.3% |
| 0.62 | 283 (11.1%) | 94.9% | 92.7% | 97.6% | 98.5% |
| 0.80 | 194 (7.6%) | 91.7% | 89.2% | 94.8% | 99.0% |
| 0.90 | 123 (4.8%) | 88.7% | 87.5% | 90.2% | 99.3% |
| **0.945** | **87 (3.41%)** | **85.9%** | **86.0%** | **85.7%** | **99.5%** |

| Benign false-alarm rate | Recall |
|---|---|
| 1.0% | 75.5% |
| 2.2% | 82.3% |
| 2.4% | 83.3% |
| 5.0% | 88.8% |

## Results per category

Lowest v6 recall first. v5 is out of 30 per category.

| Set | Category | Packages | v3 | v5 | **v6 at 0.945** | v6 at 0.62 |
|---|---|---|---|---|---|---|
| known | `encoded_loader` | 600 | 46.7% | 0/30 | **1.2%** | 42.0% |
| new | `split_payload` | 300 | 89.7% | 30/30 | **5.3%** | 72.7% |
| new | `eval_decode` | 300 | 26.7% | 30/30 | **19.3%** | 78.3% |
| new | `stream_clone` | 300 | 0.0% | 30/30 | **38.0%** | 97.0% |
| known | `T2_rename` | 530 | 68.9% | 23/30 | **48.5%** | 78.1% |
| new | `crypto_miner` | 300 | 100.0% | 30/30 | **64.7%** | 98.3% |
| new | `env_dump` | 300 | 100.0% | 30/30 | **70.7%** | 100.0% |
| known | `T1_format` | 530 | 77.7% | 26/30 | **74.5%** | 85.5% |
| new | `env_exec_net` | 300 | 100.0% | 30/30 | **81.7%** | 100.0% |
| known | `mal_known` | 722 | 82.7% | 24/30 | **84.1%** | 90.3% |
| new | `mal_stream` | 899 | 91.2% | 30/30 | **84.4%** | 97.3% |
| known | `mal_newver` | 498 | 90.4% | 27/30 | **85.7%** | 91.8% |
| new | `mal_shape` | 284 | 95.1% | 29/30 | **85.9%** | 92.6% |
| new | `mal_scripts` | 299 | 93.3% | 27/30 | **86.3%** | 97.0% |
| new | `obfuscated` | 300 | 61.0% | 30/30 | **86.7%** | 100.0% |
| known | `mal_newname` | 2,497 | 82.9% | 24/30 | **88.3%** | 95.2% |
| known | `mal_scripts` | 479 | 96.2% | 29/30 | **89.4%** | 93.7% |
| new | `telegram_bot` | 300 | 100.0% | 30/30 | **90.0%** | 99.7% |
| new | `script_net_encoding` | 300 | 90.0% | 30/30 | **94.3%** | 100.0% |
| new | `obfuscated_loader` | 300 | 16.0% | 30/30 | **95.3%** | 100.0% |
| new | `mal_encoded` | 400 | 93.5% | 26/30 | **96.2%** | 98.5% |
| known | `payload_base64` | 265 | 3.8% | 27/30 | **96.6%** | 98.5% |
| known | `multi_stage` | 600 | 99.5% | 30/30 | **99.5%** | 100.0% |
| new | `reverse_shell` | 300 | 100.0% | 30/30 | **99.7%** | 100.0% |
| known | `T3_padding` | 530 | 71.3% | 23/30 | **100.0%** | 100.0% |
| known | `T4_base64` | 530 | 70.2% | 27/30 | **100.0%** | 100.0% |
| known | `padded_loader` | 600 | 52.2% | 30/30 | **100.0%** | 100.0% |
| known | `payload_hex` | 265 | 42.3% | 25/30 | **100.0%** | 100.0% |
| new | `credential_harvest` | 300 | 0.0% | 30/30 | **100.0%** | 100.0% |
| | 16 more categories | 6,000 | 100.0% | 30/30 | **100.0%** | 100.0% |

The 16 categories at 100% in every version are `dropper`, `install_scripts`, `stealer` and `typosquat` (`known`), and `discord_webhook`, `dns_beacon`, `hex_loader`, `net_host`, `net_sensitive`, `wallet_stealer`, `webhook_exec`, `script_dependency_confusion`, `script_env_exfil`, `script_net_host`, `script_net_sensitive` and `script_reverse_shell` (`new`).

`T3_padding`, `T4_base64` and `padded_loader` at 100% do not show that v6 recognises those families; see new flaw 1.

## v3 flaws

| # | v3 flaw | v6 code | v6 measured | Status |
|---|---|---|---|---|
| 1 | Rule layer overrides the network and causes most false alarms | Removed; the verdict is `max(window_probs) >= threshold` | Benign flagged 15.3% → 3.41%. Benign packages with `exec`/`spawn`/`child_process`: v3 196/381 (51.4%), v6 26/381 (6.8%). With `axios`/`fetch(`/`discord`/`telegram`/`webhook`: 91/144 (63.2%) → 7/144 (4.9%). "Trojan" words: 5/10 → 0/10. `git rev-parse`: 5/5 → 0/5. | **Fixed** |
| 2 | Rules hide real malware and are easy to evade | No caps or allowlist | The three v3 evasion packages are caught (0.991, 0.9997, 1.000). `stream_clone` 0% → 38.0%, `credential_harvest` 0% → 100%, `payload_base64` 3.8% → 96.6%. | **Mostly fixed** (`stream_clone` still 62% missed) |
| 3 | Module names guessed from their length | No length heuristic anywhere in v6 | — | **Fixed** |
| 4 | The network sees less than half of a normal package | Up to 10 windows of 2,200 characters, up to 24 files of 64 KiB | Benign code seen (character estimate): mean 47% → 59% (median 65%). Still 2,052/2,549 (80.5%) benign packages not fully seen. 2,028 (79.6%) have at least one window cut at 512 tokens, because 2,200 characters of real code are often more than 512 tokens. 585 (23%) hit the 10-window cap and 244 have more than 24 code files. Benign flagged when cut 84/2,052 (4.1%), when it fits 3/497 (0.6%); v3 was 19.8% and 1.9%. Malware recall when cut 89.8%, when it fits 84.2%; v3 was 50% and 90%. | **Partly fixed** (recall fixed; coverage and the false-alarm gap remain) |
| 5 | The network alone cannot reach a low false-alarm rate | Network only | Recall at 2.4% false alarms: 65.1% → 83.3%. At 1%: 75.5%; at 5%: 88.8%. Stage 1 v6 is 94–98% at 2.2%. | **Improved, not solved** |
| 6 | Validation leaks; published numbers are optimistic | Package-disjoint dev split; names and fingerprints of all 22,684 test packages excluded; no marker stripping; no hand-fitted rules | The standalone figures reproduce. But the guard compares only names and one code fingerprint, and the T1–T4 transforms change both. Rerunning v6's guard on the combined corpus, the source package of 307/530 (57.9%) of each T1–T4 tier and 145/265 of each payload tier passes and is eligible for training. Effect measured: T1 75.9% when the source is eligible vs 72.6% when not; T2 50.8% vs 45.3%. The held-out set also steered decisions (new flaw 3), and T3/T4/`padded_loader` are detected by the transform (new flaw 1). | **Partly fixed** |
| 7 | Training and inference input built differently | One `record_builder.py` for training, evaluation and inference | — | **Fixed** (malware training windows are still picked by a keyword regex, top 1–2 per package, while benign packages use all windows) |
| 8 | Speed: 16.5 ms claimed, 844 ms measured | Small 6-layer student, one ONNX batch per package | Median 69 ms, mean 156 ms, p95 557 ms, max 3.3 s per package; benign median 305 ms. 61.5 minutes for all 22,684 packages (v3: about 6 hours). The README states 8.04 ms median, measured as a batch-of-16 average on another machine: 8.6× below this test. | **Improved; claim not reproduced** |

## v5 flaws

| # | v5 flaw | v6 code | v6 measured | Status |
|---|---|---|---|---|
| 1 | The network does not separate benign from malicious (AUC 0.27–0.39) | Teacher, LoRA and distilled student retrained | AUC 0.978 on all 22,684 packages and 0.977 on the exact v5 sample. Median probability: benign 0.040, malicious 0.999 (v5: 0.999 and 0.998). | **Fixed** |
| 1a | Wrong tokenizer at inference (FNV hash, 256 tokens) | `tokenizers` loads `tokenizer.json`, 512 tokens per window | Same vocabulary (50,368) and the same token ids as v3's ModernBERT tokenizer. The only file difference is v3's saved 512-token padding. | **Fixed** |
| 1b | Distillation broken: unshuffled corpus, silent fallbacks, no student evaluation | Fails loudly on a missing or unbalanced dataset; teacher AUC gate 0.92; ONNX AUC gate 0.95 on `dev_val` | Not rerun | **Fixed in code** |
| 2 | A regex classifier with fixed scores | No fast path | 10,192 distinct scores over 22,684 packages. The most common, 0.999982 on 473 packages (2.1%), is a saturated network output, not a constant. | **Fixed** |
| 3 | `is_v5_false_alarm_benign()` causes almost every miss | Removed | The categories it hid are still missed, now by the network: `encoded_loader` 7/600 (1.2%; v3 46.7%, v5 0/30), `split_payload` 5.3% (v3 89.7%, v5 30/30), `eval_decode` 19.3% (v3 26.7%, v5 30/30). | **Code fixed, outcome not** |
| 4 | Positive rules flag ordinary code | No rules | `git rev-parse` helper 0.195 (v3 0.86, v5 0.95). URL on `.me` plus `while (true)`: 0.0095. Benign packages with a `.me`/`.is`/`.pro`/`.link`/`.to`/`.shop`/`.work`/`.cn`/`.ru` URL: 2/16 flagged; with `while (true)`: 3/73. | **Fixed** |
| 5 | Published numbers | SHA-256 published and checked by the installer; `--self-test` exits non-zero on any failure | Checksums match; self-test 6/6; recall, false alarms and AUC reproduce on all 22,684 packages. Latency (8 ms vs 69 ms) does not reproduce, and "zero training overlap" does not hold for T1–T4 sources (v3 flaw 6). | **Mostly fixed** |

## New flaws found in v6

### 1. The benchmark transforms are detected by their shape, not by the family

The 500 benign packages of the v5 sample were transformed the way the test generator transforms malware, and T1/T3 malware was scored with the transform undone.

| Benign sample (500) | Flagged at 0.945 | Median probability |
|---|---|---|
| Unchanged | 18 (3.6%) | 0.043 |
| T1: `/* reformatted */` + indent | 16 (3.2%) | 0.036 |
| T1: indent only | 19 (3.8%) | 0.048 |
| T2: identifiers, strings, numbers renamed | 89 (17.8%) | 0.399 |
| T3: 320 `_pg_pad_N` functions on each side | **500 (100%)** | 0.999 |
| T3 without the `/* padded */` line | **500 (100%)** | 0.999 |
| T3 shape with neutral function names (`getValue3(){var x=…;return x;}`) | **314 (62.8%)** | 0.959 |
| 10 `_pg_pad_N` functions in front | 71 (14.2%) | 0.712 |
| 1 `_pg_pad_N` function in front | 25 (5.0%) | 0.072 |
| T4: whole file behind `eval(Buffer.from(…,"base64"))` | **476 (95.2%)** | 0.996 |
| Identifiers renamed to `_0x…` names | **226 (45.2%)** | 0.935 |

| Malware | As shipped | Transform undone |
|---|---|---|
| `T1_format` (530) | 395 (74.5%) | marker removed: 425 (80.2%) |
| `T3_padding` (530) | 530 (100%) | marker removed: 530 (100%); marker and padding removed: 440 (83.0%) |

- Any package padded like T3 is flagged, whatever the code. The repeated dead-code shape alone flags 62.8% of benign packages, and the `_pg_pad_` name takes it to 100%; ten such functions already move the benign median from 0.043 to 0.712. `T3_padding` and `padded_loader` (same padding) at 100% measure the padding, not the family; without it T3 recall is 83.0%.
- `T4_base64` at 100% likewise measures the `eval(base64)` wrapper: 95.2% of wrapped benign packages are flagged. That wrapper is suspicious in itself, but the category no longer shows recognition of the hidden family.
- Obfuscated-looking code is flagged without any malicious behaviour (45.2% with `_0x` names). `prepare_v6_dataset.py` applies `javascript-obfuscator` to malware only and lists "NEVER" for benign obfuscation, so the network learned obfuscation as a malware signal. Real packages ship obfuscated or minified vendor code; `@fingerprintjs/fingerprintjs@5.3.0` is among the 87 benign false alarms.
- T2 renaming raises benign false alarms five times (3.6% → 17.8%) and still misses half of T2 malware (48.5%).
- T1 shows no marker shortcut: the comment changes nothing on benign code, and removing it raises recall.

### 2. Recall regressed on several new-campaign categories

Against v3 at its operating point, v6 at 0.945 loses `split_payload` (89.7% → 5.3%), `crypto_miner` (100% → 64.7%), `env_dump` (100% → 70.7%), `env_exec_net` (100% → 81.7%), `telegram_bot` (100% → 90.0%) and `T2_rename` (68.9% → 48.5%). Most come back at 0.62, where benign false alarms are 11.1%. The 0.945 threshold was chosen for 97.5% specificity on `dev_val`, which costs these categories most.

### 3. The held-out set was used to steer the model

- The README compares a post-evaluation LoRA patch with the shipped checkpoint on the full held-out set and keeps the one with the higher held-out AUC.
- `lora_patch_v6.py` targets "the 5 weak generalization families identified in Round 3 sandbox testing" (`encoded_loader`, `split_payload`, `eval_decode`, `stream_clone`, T2, `crypto_miner`), which are test-set categories.

The shipped model is the pre-patch checkpoint, so the direct effect is small. The 22,684 packages are no longer an untouched test set for v7: a v7 needs a fresh held-out set, or at least a held-out split of it that no decision has looked at.

### 4. Install hooks are untested on benign code

None of the 2,549 benign test packages has a `package.json` lifecycle script, and v6 reads nine hooks (`prepare`, `prepublishOnly`, `prepack` and the uninstall hooks besides the three install hooks). A hand probe of 11 common benign hooks on a small benign file was clean: `husky install`, `npm run build`, `node-gyp rebuild`, `prebuild-install || node-gyp rebuild`, `patch-package`, `opencollective-postinstall`, `npx only-allow pnpm`, `node install.js` and others all scored 0.003–0.088. A benign set with real `package.json` files is still needed.

## Suggested fixes, in order of expected effect

1. Train on benign packages that carry the same transforms as the malware: padding, `javascript-obfuscator`, renaming and base64 wrappers. Report the transformed-benign false-alarm rate next to every T1–T4 figure, as `docs/v4-suggestions.md` asked for Stage 1.
2. Cover whole packages: size windows in tokens, not characters, so no window is cut at 512 tokens, and score every file rather than the first 24 or the first 10 windows.
3. Extend the leakage guard to code shape (`base_group`) and to the `base` package of every derived test variant, and freeze a fresh held-out set that no checkpoint choice has seen.
4. Add a benign set with real `package.json` lifecycle scripts and obfuscated or minified vendor code.
5. Report latency as one package at a time on a stated CPU, next to the batched figure.
