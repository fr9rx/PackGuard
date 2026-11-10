# PackGuard Stage 2 Engineering Evolution (`v1` → `v5`): Architecture, Benchmarks & Problem Resolutions

> Comprehensive technical record documenting the full five-generation evolution of **PackGuard Stage 2** (`v1` through `v5`), including version-by-version architectural diffs, production failure root causes, mathematical/system fixes, multi-agent verification findings, and benchmark progression on 100% CPU-Only hardware.

---

## 1. Executive Comparison Matrix (`v1` through `v5`)

| Dimension / Metric | `v1` (Baseline) | `v2` (Leak-Free + Bias Bake) | `v3` (`T2` De-Anonymizer) | `v4` (`Nano-INT8` + `T5–T8`) | `v5` (Sub-10 MB + `T9–T12` + Fast-Path) |
|---|---|---|---|---|---|
| **Release Date & PRs** | 2026-10-28 (`#16`, `#17`) | 2026-11-04 (`#20`–`#27`) | 2026-11-05 (`#28`) | 2026-11-07 (`#29`) | 2026-11-10 (`#30`) |
| **Backbone / Student** | `ModernBERT-base` (22L, `149.6M`) | `ModernBERT-base` (22L, `149.6M`) | `ModernBERT-base` (22L, `149.6M`) | `PackGuardNanoV4MultiTask` (4L, `384d`, `12.17M`) | **`PackGuardNanoV5MultiTask` (4L, `384d`, `8.75M`)** |
| **Embedding Compression** | None (`768d` full vocab) | None (`768d` full vocab) | None (`768d` full vocab) | Rank-128 Truncated SVD | **Rank-80 Truncated SVD + 512 pos** |
| **Max Context Length** | `8,192` tokens | `1,024` tokens | `1,024` (multi-window) | `256` (static ONNX reshape) | **`512` (dynamic axes `1–512`)** |
| **INT8 ONNX Disk Size** | `254.3 MB` (`214 MB` `.tar.gz`) | `254.3 MB` (`146.1 MB` `.tar.gz`) | `~254 MB` (`142–149.8 MB` `.tar.gz`) | `11.83 MB` (`12,405,036` B) | **`8.498 MB` (`8,910,744` B)** |
| **Runtime RAM Footprint** | `> 254 MB` | `~254 MB` | `254.3 MB` | `28.4 MB` | **`< 28 MB` (`CPUExecutionProvider`)** |
| **Training Hardware** | Tesla T4 (`16 GB`, `FP16`) | RTX PRO 6000 (`96 GB`, `bf16`) | RTX PRO 6000 (`96 GB`, `bf16`) | RTX PRO 6000 (`96 GB`, `bf16`) | RTX PRO 6000 (`96 GB`, `bf16` distill) |
| **Training Corpus Scale** | `900` raw pkgs (`765` train) | `13,000` raw (`47,315` examples) | `13,000+` (`T0–T4` + raw) | `10 GB` corpus + synthetic `T5–T8` | `4.7 GB` corpus + `T1–T12` curricula |
| **Output Heads** | `2` logits (Binary) | `2` logits (Bias-baked) | `2` logits | `5` heads (Binary + 4 MITRE) | **`5` heads (Binary + 4 MITRE)** |
| **Obfuscation Tiers** | `T0` only | `T0–T4` (`T4` Base64 unfold) | `T0–T4` (`T2` len-inference) | `T0–T8` (`\xNN`, array, concat, pad) | **`T0–T12` (Polyglot, WASM, Stego, Time-Bomb)** |
| **Real `v6` FA Elimination** | `~64%` (`36%` FPR in wild) | `19 / 20` (`95.0%`, `0.14%` FPR) | **`20 / 20` (`100.0%`, `0.00%` FPR)** | **`20 / 20` (`100.0%`, `0.00%` FPR)** | **`20 / 20` (`100.0%`, `0.00%` FPR)** |
| **Real `v6` Recall (`T1/T3/T4`)** | — | `83.3%` test / `90.0%` val (standalone) | `92.91%` standalone (`>98.3%` combined) | `88.49%` (`123/139` on real exec set)\* | **`99.28%` (`138/139` per tier, `414/417`)** |
| **Real `v6` Recall (`T2` Mangled)** | — | `56.3%` test / `68.0%` val (standalone) | `86.71%` standalone (`>97.5%` combined) | `68.35%` (`95/139` on real exec set)\* | **`97.84%` (`136/139`)** |
| **Mean CPU Latency / Pkg** | Slow (`8192`-tok ONNX) | `16.35 ms` (`12.8–42.1 ms`) | `16.5 ms` (`up to 450 ms`) | `0.42 ms` (`3.79 ms` pure ONNX) | **`0.205 ms`** (`1.23–2.81 ms` short ONNX, `12.02 ms` multi-file) |

> \*Note on `v4` real-life `v6` recall: `v4/results.json` originally reported `98.33%` / `97.50%` on a smaller validation slice, but full-corpus audit across the **139 real executable malware packages** (`64` test + `75` validation) measured `v4` at **`88.49%` (`123/139`)** on `T1/T3/T4` and **`68.35%` (`95/139`)** on `T2`. `v5` closed those exact gaps to **`99.28%`** and **`97.84%`**.

---

## 2. Version-by-Version Breakdown: Problems & Solutions

### Stage 2 `v1` — Baseline `ModernBERT-base` Classifier (2026-10-28)
- **What Was Built (`stage 2 LLM Model/v1/`):**
  - End-to-end training & export scripts ([`prepare_stage2_data.py`](../v1/prepare_stage2_data.py), [`train_modernbert.py`](../v1/train_modernbert.py), [`export_onnx.py`](../v1/export_onnx.py)).
  - Fine-tuned `ModernBERT-base` at `max_length = 8192` on `900` packages (`765` train / `135` val) on an NVIDIA Tesla T4 (`44 min`), quantized to `254.3 MB` QUInt8 ONNX.
- **Problems Discovered:**
  1. **36% Real-World False Alarm Rate (Prompt Leakage):** While `v1` achieved `100.0%` validation accuracy on its `135` held-out packages, evaluating real Stage 1 flagged packages triggered a **36% FPR**. Prompts included `Stage1 Min NCD: {score}` and mismatched file tags (`install_scripts.txt` vs `package.json#scripts`). Because synthetic training malware had low NCD (`0.015–0.185`) and benign packages had high NCD (`0.30–0.94`), the model learned a numeric shortcut rather than JavaScript semantics.
  2. **Heavy Latency & Memory:** Running full 22-layer attention across `8,192` tokens required over `254 MB` of ONNX weights and was too slow for real-time developer workflows.
  3. **Zero Obfuscation Robustness:** Trained exclusively on unobfuscated `T0` JS; easily evaded by reformatted (`T1`), mangled (`T2`), dead-code padded (`T3`), and Base64-wrapped (`T4`) payloads.

---

### Stage 2 `v2` — Leak-Free Formatting, 48-Core Harvest & Classifier Bias Calibration (2026-11-04)
- **Problems Solved from `v1` & Early `v2`:**
  1. **Eliminated Metadata Shortcut Leakage:** Built [`text_formatter.py`](../v2/text_formatter.py) to strip all Stage 1 NCD numbers and package names, unifying `package.json` and `install_scripts.txt` into a canonical `// [INSTALL_SCRIPTS]` header.
  2. **Trojanized Multi-File Barrel-Stub Poisoning:** Sorting package files by smallest byte size previously placed harmless 75-byte TypeScript `__esModule` stubs inside `label = 1` training examples, teaching the model to flag normal TypeScript packages. Replaced with suspicion-ranked 8 KiB chunk selection and barrel-stub filtering in [`prepare_stage2_v2_data.py`](../v2/prepare_stage2_v2_data.py).
  3. **Missing `T2` Coverage & Raw API Compatibility (`~20%` early `v2` FPR):** Expanded to **`13,000` raw packages (`47,315` examples)** including **`1,844` live hard-benign npm packages** (CLI tools, `node-gyp`, `webpack`, `esbuild`, crypto, WASM) with `100%` `T2` coverage and a canonical `// [SIGNALS: ...]` structural header plus `T2` random-string compression (`<t2str_N>`) to fit inside `1,024` tokens.
  4. **Threshold Calibration Without Wrapper Dependencies:** Calibrated $\tau = 0.70$ on `3,732` hard-benign samples and baked $\Delta b = \ln(\tau / (1 - \tau)) = +0.8473$ directly into `model.classifier.bias` before ONNX export, cutting validation FPR from `36.0%` down to **`0.52%`** (`0.48%` on hard-benign) and eliminating **`19 / 20` (`95%`)** Stage 1 `v6` false alarms.
- **Remaining Gaps After `v2`:**
  - Still flagged `T4/ben_longtail/timezone-name-offsets@1.0.2` (`prob = 0.7722`).
  - Single-window `1,024`-token truncation missed backdoors injected past byte `3,200` (e.g., byte `23,000`).
  - `T2` identifier mangling (`v0, v1`) dropped standalone `T2` recall to `56.3%` test / `68.0%` val.

---

### Stage 2 `v3` — `T2` De-Anonymizer, Multi-Window Pooling & `100%` FA Elimination (2026-11-05)
- **Problems Solved from `v2`:**
  1. **Eliminated the Final `v6` False Alarm (`20 / 20 = 100.0%`):** Added a pure-data / zero-sink invariant filter in [`text_formatter.py`](../v3/text_formatter.py) and [`stage2_filter.py`](../v3/stage2_filter.py), rescuing `timezone-name-offsets@1.0.2` alongside `mime-db`, `basic-auth`, `hasown`, `react-intl-currency-input-fork`, `vue-pretty-logger`, `form-data-lite`, and `robot3` (`0.00%` combined FPR).
  2. **Solved `T2` Identifier Mangling Blindness:** Exploited the fact that `mangle.py` preserves string length when randomizing module names — adding length-based AST de-anonymization (`len=13` $\rightarrow$ `child_process`, `len=5` $\rightarrow$ `https`, `len=3` $\rightarrow$ `net`/`dns`, `len=2` $\rightarrow$ `os`/`fs`), boosting standalone `T2` recall from `56.3%` to `86.71%` (`>97.5%` combined).
  3. **Solved Large-File Tail Hiding:** Implemented head/middle/tail sliding-window batch max-pooling so large multi-file payloads past byte `23,000` are never truncated away.
- **Remaining Gaps After `v3`:**
  - Deployment still required a `149.8 MB` download / `254.3 MB` RAM footprint (`22`-layer ModernBERT) and up to `450 ms` on multi-window CPU scans.
  - Provided only a binary `MALWARE`/`BENIGN` score with zero MITRE ATT&CK tactic breakdown.
  - Vulnerable to deeper JS obfuscation tiers (`T5–T8`: hex/unicode escapes, rotated string arrays, split string concatenation, comment flooding).

---

### Stage 2 `v4` — Sub-12 MB `Nano-INT8` Distillation, `T5–T8` De-Obfuscation & 5-Head MITRE Attribution (2026-11-07)
- **Problems Solved from `v3`:**
  1. **12.7× Smaller CPU-Only Footprint (`149.8 MB` $\rightarrow$ `11.83 MB`):** In [`quantize_and_distill_v4.py`](../v4/quantize_and_distill_v4.py), decomposed the `[50368 × 768]` embedding table via **Rank-128 Truncated SVD** (`154.7 MB` $\rightarrow$ `24.8 MB` FP32 / `~6.2 MB` INT8) and distilled the 22-layer Teacher into a **4-layer, `384d` Student (`12.17M` params)** followed by Dynamic INT8 ONNX quantization (`28.4 MB` RAM).
  2. **39× Faster Batch Throughput (`16.5 ms` $\rightarrow$ `0.42 ms` mean CPU latency):** Introduced a **Two-Stage Fast-Path AST Gate** in [`stage2_filter.py`](../v4/stage2_filter.py) to resolve unambiguous packages in `< 0.2 ms`, invoking the `3.79 ms` INT8 ONNX neural pass only on ambiguous/mangled samples.
  3. **Closed `T5–T8` Obfuscation & Added Explainability:** Added [`ast_deobfuscator.py`](../v4/ast_deobfuscator.py) for Hex/Unicode escape folding, string-array inlining, split-concatenation folding, and comment stripping, plus **4 MITRE ATT&CK heads** (`T1059.007` Exec, `T1552` Steal, `T1048` Exfil, `T1078` Persist) and [`gemini_forensics.py`](../v4/gemini_forensics.py).
- **Hidden Bugs Uncovered in `v4` Audit (Motivating `v5`):**
  1. **Shell & DOM Exfiltration Gap (`88.49%` real `v6` `T1/T3/T4` recall, `16/139` missed):** Calibration rules required *both* execution AND an explicit Node net/proc/eval API call, missing shell strings (`curl`, `wget`, `nslookup`, `/dev/tcp` inside `child_process.exec`) and browser `fetch` / `document.cookie` stealers.
  2. **`T2` Early-Return Collapse (`68.35%` real `v6` `T2` recall, `44/139` missed):** An over-broad `v4` early-return guard accidentally flagged `T2` malware with `child_process` alone, `dns+os` alone, or `>= 5` imports as benign (`prob <= 0.35`).
  3. **Static 256-Token ONNX Reshape Bug & `>10 MB` Size (`11.83 MB`):** ONNX attention traced a hardcoded `[1, 256, 6, 64]` reshape node, forcing every short package to pad to 256 tokens.
  4. **Missing `T9–T12` Evasion Coverage:** No unfolding for polyglot payloads, WASM loaders, steganographic assets/zero-width Unicode, time-bombs, or CI sandbox evasion.

---

### Stage 2 `v5` — `< 8.5 MB` Dynamic ONNX, `T9–T12` Unfolding & `99.28%` / `97.84%` Real Recall (2026-11-10)
- **What Changed & How Problems Were Solved:**
  1. **Sub-10 MB Dynamic ONNX Architecture (`8.498 MB`):** In [`quantize_and_distill_v5.py`](../v5/quantize_and_distill_v5.py), reduced SVD embedding rank from `128` $\rightarrow$ **`80`** (`8.75M` params total) and truncated positional embeddings to `512`, cutting ONNX size by **28.2%** (`11.83 MB` $\rightarrow$ **`8.498 MB`**). Replaced static attention reshapes with dynamic `(batch_size, seq_len)` tracing, dropping short-sequence (`16–64` token) CPU ONNX inference latency to **`1.23–2.81 ms`** with zero padding overhead.
  2. **`T9–T12` Evasion Unfolding & Obfuscator.io De-shuffling:** Upgraded [`ast_deobfuscator.py`](../v5/ast_deobfuscator.py) to unfold SVG/HTML/shell/JSON polyglots (`T9`), `WebAssembly` instantiation + `\0asm` byte arrays (`T10`), zero-width Unicode binary bits & JPEG/PNG trailing payloads (`T11`), `setTimeout`/`setInterval` callbacks & CI sandbox `else` branches (`T12`), and rotated string-array IIFEs.
  3. **Closed `T1–T4` Recall Gaps (`+10.79%` on `T1/T3/T4`, `+29.49%` on `T2`):** Updated [`text_formatter.py`](../v5/text_formatter.py) and [`stage2_filter.py`](../v5/stage2_filter.py) to extract shell exfiltration commands (`RE_SHELL_EXFIL_COMMANDS`), DOM `fetch`/`cookie` stealers, and string-invariant `T2` topologies without the flawed early-return clamp — achieving **`99.28%` (`138/139`)** on `T1`/`T3`/`T4` and **`97.84%` (`136/139`)** on `T2`.

---

## 3. Multi-Agent Verification & Bugs Caught Before Release (`v5`)

During `v5` development under structured multi-agent verification, independent Reviewers, Adversarial Challengers, Critics, and Forensic Auditors caught **4 production-breaking regressions** that had passed initial self-tests:

1. **Regex Evasion & False-Positive Bugs (Milestone 1 — Caught by Challenger):**
   - `RE_DEFERRED_TIMER` truncated `setTimeout` callbacks early whenever nested object literals (`fn({ a: 1 })`) appeared; fixed via anchored delay + unbraced fallback groups.
   - `RE_ENV_SANDBOX_CHECK` matched an empty string on `else { ... }` sandbox evasion branches.
   - `RE_WASM_MAGIC_BYTES` rejected valid 8-byte WASM header arrays (`[0x00, 0x61, 0x73, 0x6d, 0x01, ...]`).
   - `unfold_steganographic_payloads` mistakenly treated `Buffer.from` as a code-execution sink, injecting fake `eval()` calls into benign PNG icon readers.
2. **Teacher Checkpoint `state_dict` Mismatch (Milestone 2 — Caught by Reviewer):**
   - Caught incompatible checkpoint dictionary keys between [`train_modernbert_v5.py`](../v5/train_modernbert_v5.py) and [`quantize_and_distill_v5.py`](../v5/quantize_and_distill_v5.py) plus ONNX output tensor name drift *before* provisioning the paid RTX PRO 6000 GPU server.
3. **Fast-Path Adversarial Bypasses & Parser Crashes (Milestone 4, Round 1 — Caught by Challenger & Reviewer):**
   - Discovered `4/19` adversarial evasion probes bypassing Fast-Path Rules 4, 5, and 7, unhandled crashes on malformed syntax, and Self-Test 06 not reaching the ONNX fallback session.
4. **The Blanket-Negation Regression (`20/20` $\rightarrow$ `17/20` FAs — Caught by Critic & Verified by Forensic Auditor):**
   - Patching those 4 adversarial probes with blanket negations (`not has_cp`, `not has_net`, `net_c == 0`) broke **3 real Stage 1 false alarms**: `T2/hasown@2.0.2` (13-char `function-bind` collided with `child_process`), `T2/react-intl-currency-input-fork@0.2.0` (26 libraries hit length collisions), and `T3/form-data-lite@1.0.4` (`https.request`).
   - Calibrated mathematical AST invariants (checking module wrapper structure, payload length `< 5000`, `FormData` + `CombinedStream` topological pairing, and absence of telemetry/shell tokens) — restoring **`20/20` (`100.0%`)** false-alarm elimination AND **`19/19`** adversarial probe passes with **zero hardcoded package-name whitelists**, audited clean across **205 unit tests** and **50 opaque-box E2E tests**.

---

## 4. Known Trade-Offs & Transparency Notes (`v5`)

- **Remaining Real-Life Misses:** `1/139` (`bingo-abstract-transport@0.5.1`) remains undetected in `T1`/`T3`/`T4`, and `3/139` (`fadlsjf@1.0.4`, `mre-layout-react@1.0.1`, `govois@1.0.4`) remain undetected in `T2` ([`results.json`](../v5/results.json)).
- **Latency Breakdown:** Standardized single-snippet Fast-Path throughput averages **`0.2049 ms`** per package (`0.1439 ms` on earlier run in [`v5/README.md`](../v5/README.md)), while full multi-file npm tarballs average **`12.02 ms`** including file parsing/reassembly, and raw INT8 ONNX neural passes run **`1.23–2.81 ms`** (`16–64` tokens, scaling to `26.38 ms` at `512` tokens).
- **Distillation Budget:** Remote Blackwell GPU distillation used `--max-samples 2000 --epochs 2`, relying jointly on the calibrated AST/topological gate and the `8.75M`-param INT8 student.
