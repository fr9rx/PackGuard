# Stage 2 v5: sample test and where it fails (2026-11-12)

## What was run

Stage 2 v5 (`packguard_v5_nano_int8.onnx`, threshold 0.62) scored a stratified sample directly, with no Stage 1 gate, on a 3-vCPU Debian server: 30 packages from each of the 45 malicious categories (1,350) and 500 random benign packages. For every package the deciding path (`reason`) and, where the network ran, its raw probability were recorded.

Limits: this is a sample, so a per-category figure is out of 30 and can move by several points. The malicious total weights every category equally, so it is not directly comparable to the v3 full-set figure. It is Stage 2 alone, not the pipeline.

## Result

| Set | Sample | Flagged | Rate |
|---|---|---|---|
| Malicious | 1,350 | 1,267 | 93.9% recall |
| Benign | 500 | 140 | 28.0% false alarms |

v3 on the full sets gave 82.0% recall and 15.3% false alarms. v5 catches more and raises almost twice as many false alarms.

Categories below 100%:

| Set | Category | Flagged |
|---|---|---|
| known | `encoded_loader` | 0/30 |
| known | `T2_rename` | 23/30 |
| known | `T3_padding` | 23/30 |
| known | `mal_known` | 24/30 |
| known | `mal_newname` | 24/30 |
| known | `payload_hex` | 25/30 |
| known | `T1_format` | 26/30 |
| new | `mal_encoded` | 26/30 |
| known | `T4_base64` | 27/30 |
| known | `mal_newver` | 27/30 |
| known | `payload_base64` | 27/30 |
| new | `mal_scripts` | 27/30 |
| known | `mal_scripts` | 29/30 |
| new | `mal_shape` | 29/30 |

## Flaw 1: the neural network does not separate benign from malicious

The network only runs when no regex rule decides first. On the packages that reached it:

| | Reached the network | Raw probability ≥ 0.62 | Median raw probability |
|---|---|---|---|
| Benign | 82 | 81 (99%) | 0.999 |
| Malicious | 333 | 273 (82%) | 0.998 |

It scores benign code higher than malware. 78 of the 140 benign false alarms come from this path.

### The network alone, on the whole sample

To separate the network from the rules, all 1,850 sampled packages were scored by the network only, with the shipped tokenizer and with the real ModernBERT tokenizer. AUC is the chance that a malicious package scores higher than a benign one: 1.0 is perfect, 0.5 is a coin flip.

| Tokenizer | AUC | Benign median | Malicious median | False alarms at 0.62 | Recall at 0.62 |
|---|---|---|---|---|---|
| Shipped hash tokenizer, 256 tokens | 0.287 | 0.999 | 0.999 | 97.0% | 84.6% |
| Real ModernBERT tokenizer, 256 tokens | 0.392 | 0.988 | 0.961 | 83.6% | 71.9% |
| Real ModernBERT tokenizer, 512 tokens | 0.271 | 0.998 | 0.997 | 95.6% | 88.1% |

All three are below 0.5. The network says "malicious" to almost everything and is slightly more confident on benign code. Fixing the tokenizer does not fix it, so the network itself came out of training or distillation without learning the task.

### Two separate bugs

1. **Wrong tokenizer at inference.** Training and distillation use the real ModernBERT tokenizer (`AutoTokenizer` in `train_modernbert_v5.py` and `quantize_and_distill_v5.py`). `stage2_filter.py` feeds the model with `fast_cpu_tokenize()`, which splits on a regex and turns each token into an FNV hash modulo the vocabulary size. Those ids have no relation to the trained ones. It also reads only the first 256 tokens.
2. **The distilled network is broken regardless.** Candidates in `quantize_and_distill_v5.py`, none confirmed because the training data and logs are not in the repository:
   - `load_distillation_samples()` takes the first 6,000 lines of a file named `v4_10gb_malware_corpus.jsonl`, in file order, with no shuffling or class balancing. If the head of that file is mostly malware, the student learns to answer "malicious" for everything, which is what it does.
   - If the corpus has fewer than 64 usable records, the function silently trains on 6 hard-coded snippets repeated.
   - If the teacher checkpoint fails to load, the script prints a warning and trains the student without it.
   - The student is never evaluated after distillation. `results.json` has no validation metric for it, so a broken student could not have been noticed.

## Flaw 2: v5 is a regex classifier with fixed scores

- 83.6% of benign and 75.3% of malicious packages were decided by the "Fast-Path AST Gate" without the network.
- The scores are constants: 0.95 (611 packages), 0.05 (435), 0.98 (191), 0.96 (174), 0.84 (55).
- There is no AST: the gate is regular expressions over concatenated text.

## Flaw 3: one allowlist function causes almost every miss

79 of the 83 missed malicious packages returned 0.05 from `is_v5_false_alarm_benign()` (`stage1_false_alarm_short_circuit`). It runs first, and its rule 3 passes anything with no install hook and no regex hit for exec, network or eval.

- `encoded_loader` is 0/30 through this path: the payload is encoded, so no keyword is visible.
- The function's rules are written around named benchmark packages (`mime-db`, `hasown`, `vue-pretty-logger`, `form-data-lite`, `react-intl-currency-input-fork`). Rule 7 passes any file containing the words `FormData` and `CombinedStream`.
- Every benign package that passed (356 of 360) also passed through this function. Benign verdicts and missed malware come from the same door.

## Flaw 4: the positive rules flag ordinary code

Benign false alarms by deciding rule, besides the 78 from the network:

| Rule | Benign flagged |
|---|---|
| `multisignal_exec_sink` | 25 |
| `trojan_signature` | 9 |
| `c2_exfiltration_endpoint` | 7 |
| `shell_exfil_command` | 6 |
| `obfuscator_loop` | 5 |
| others | 10 |

- A three-line helper that runs `git rev-parse HEAD` is flagged at 0.95 (`multisignal_exec_sink`). v3 flagged the same file.
- `c2_exfiltration_endpoint` matches any URL on a long list of top-level domains that includes `.me`, `.is`, `.pro`, `.link`, `.to`, `.shop`, `.work`, `.cn` and `.ru`.
- `obfuscator_loop` matches `while (true) {`.

## Flaw 5: published numbers

- Recall of 97.8–99.3% is on 139 packages, and the false-alarm figure on 20 packages that the allowlist rules were written for.
- The README states 0.14 ms per package. Measured: median 5 ms, mean 18 ms, maximum 329 ms. That is far faster than v3 (median 844 ms), because the network rarely runs.
- The self-test printed `Latency: 1.472 ms (Target: < 0.15 ms on CPU) — PASS`: the check passes while missing its own target.
- No checksum is published for the v5 model. The file tested has SHA-256 `5d7957e9e5e7f14962c88b4521c8df2cff7fe733be84bc19c568290b187f6381`.

## What improved over v3

The three inert evasion samples that v3's rules released are caught by v5 (install hook with a dev-tool word, browser cookie beacon, `child_process` loaded through a split string), all at 0.95 by regex rules.

## Suggested fixes

1. Evaluate the student network alone, with the real tokenizer, on held-out benign and malicious packages, and print AUC, recall and false alarms at the end of every training and distillation run. Do not ship a model whose network-only AUC is below about 0.95.
2. Fix the distillation data: shuffle, balance the classes, fail loudly when the corpus or the teacher is missing instead of falling back.
3. Use the real tokenizer at inference.
2. Remove `is_v5_false_alarm_benign()` from the verdict path, or let it only lower a score, never short-circuit.
3. Replace fixed-score rules with features the network reads, and report network-only and rules-only results separately.
4. Stop fitting rules to the 20 benchmark false alarms; hold out a benign set that no rule has been tuned on.
