# PackGuard

**Lightweight two-stage detection of malicious npm packages using compression similarity and a small AI filter.**

> ⚠️ **Research project in progress** (ISEF, Computer Science & Software). Results, interfaces and settings may change between versions. No results are reported here until evaluation is complete.

---

## Why PackGuard?

npm is the backbone of modern web development: nearly every website, web app and JavaScript tool is built from packages downloaded through it. Attackers regularly slip malicious packages into the registry, and a single bad package can spread into thousands of projects.

Existing detectors force a trade-off:

- **Rule-based scanners** are lightweight but miss disguised (obfuscated) malware.
- **Machine-learning detectors** catch more but need powerful hardware and constant retraining.

PackGuard tests whether we can have both: accurate detection that runs on an ordinary computer.

## How it works

```mermaid
flowchart LR
    A[npm package] --> B[Unpack & split files<br/>8 KB overlapping chunks for large files]
    B --> C[Stage 1: Compression scanner<br/>NCD vs. known malware, raw LZMA2]
    C -->|not suspicious| D[Clean]
    C -->|flagged| E[Stage 2: AI filter<br/>fine-tuned ModernBERT]
    E -->|false alarm| D
    E -->|confirmed| F[Malicious]
```

**Stage 1 – Compression scanner (C).** Malicious code tends to share hidden patterns with known malware, even when disguised. PackGuard measures this with **Normalized Compression Distance (NCD)**: two files that compress much better *together* than *separately* are similar.

```
NCD(x, y) = (C(xy) − min(C(x), C(y))) / max(C(x), C(y))
```

Values near 0 mean very similar; near 1 means unrelated. Each package is scored by its most suspicious file or chunk, with a threshold tuned to catch ~99% of malware.

**Stage 2 – AI false-alarm filter (Python → ONNX).** A pretrained, code-aware model (ModernBERT) reviews **only** the packages flagged by stage 1. A hierarchical design lets it read whole packages, guided by the suspicious regions found in stage 1. The trained model is exported to ONNX, quantized to 8-bit and runs on a standard CPU through the ONNX Runtime C API, inside the same C scanner.

## Repository structure (planned)

```
PackGuard/
├── src/                        # C scanner (stage 1 + ONNX inference)
│   ├── main.c                  # Command-line entry point
│   ├── lzma_ncd.c / .h         # NCD via liblzma raw LZMA2 + cached malware references
│   ├── chunker.c / .h          # Per-file split into 8 KB overlapping chunks
│   ├── ai_filter.c / .h        # Stage 2 inference (ONNX Runtime C API)
│   └── report.c / .h           # JSON output per package
├── training/
│   └── finetune_packguard.py   # Stage 2 fine-tuning (Hugging Face)
├── data/                       # NOT committed – see "Datasets"
├── experiments/                # Configs and result logs per version
├── docs/                       # Project log, design notes
├── Makefile                    # Build configuration
├── Dockerfile                  # Containerised scanner build
└── README.md
```

## Requirements

| Component | Version |
|---|---|
| C compiler | C17: GCC 11+ or Clang 14+ |
| GNU Make | 4.x |
| liblzma (xz) | 5.4.x or a recent 5.8.x — **never 5.6.0 or 5.6.1** (CVE-2024-3094 backdoor) |
| ONNX Runtime | 1.20+ (C API, prebuilt release) |
| Python | 3.10+ |
| Python packages | `transformers`, `datasets`, `torch`, `scikit-learn`, `pandas`, `optimum` |
| GPU | Only for training (e.g. free Google Colab T4). Detection runs on CPU. |

## Getting started

### 1. Install a C toolchain and liblzma

```bash
# Linux (Debian/Ubuntu)
sudo apt install build-essential pkg-config liblzma-dev
# macOS
xcode-select --install
brew install xz pkg-config
```

On Windows, use WSL and follow the Linux commands.

Check the installed liblzma version is not 5.6.0 or 5.6.1:

```bash
xz --version
```

### 2. Install ONNX Runtime (C API)

Download the prebuilt package for your platform from <https://github.com/microsoft/onnxruntime/releases> (e.g. `onnxruntime-linux-x64-<version>.tgz`) and extract it, e.g. to `/opt/onnxruntime`. On macOS, `brew install onnxruntime` also works.

### 3. Build the scanner

```bash
make ONNXRUNTIME_ROOT=/opt/onnxruntime   # produces build/packguard
make clean                               # removes build output
```

For a single self-contained binary, link liblzma statically (`liblzma.a`); it is small and has no further dependencies.

### 4. Or build with Docker

```bash
docker build -t packguard .
docker run --rm --network none -v "$PWD/samples:/work:ro" packguard <args>
```

`--network none` and a read-only mount keep samples isolated (the scanner's command-line arguments are still being defined).

### 5. Train the AI filter

```bash
pip install -r training/requirements.txt
python training/finetune_packguard.py
```

## Scanner output format

The scanner writes one JSON file per package, which stage 2 reads:

```json
{
  "package": "example-pkg",
  "version": "1.0.2",
  "score": 0.41,
  "chunks": [
    { "file": "install.js", "start": 0, "ncd": 0.41, "text": "..." }
  ]
}
```

Lower `ncd` = more similar to known malware.

## Default configuration (v1)

| Setting | Value |
|---|---|
| Comparison unit | Per file; files > 16 KB split into 8 KB chunks with 4 KB overlap |
| Compressor | Raw LZMA2 (liblzma), preset 6 (extreme off), 1 MB dictionary, `lc = 3` |
| Package score | Most suspicious file/chunk (minimum NCD) |
| Stage 1 threshold | Tuned for ~99% malware recall on validation data |
| Stage 2 model | ModernBERT-base, fine-tuned, 8-bit quantized ONNX |

## Datasets

Malware is **not** included in this repository. Sources used:

- [DataDog malicious software packages dataset](https://github.com/DataDog/malicious-software-packages-dataset)
- Backstabber's Knife Collection (Ohm et al., 2020)
- MalwareBench (access on request)
- [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) (used to confirm live-scan detections)

Benign packages are downloaded from the public npm registry. Near-duplicates are removed and data is **split by publication date** to simulate detecting unseen attacks.

## Evaluation

- **Metrics:** precision, recall, F1, false alarm rate, processing time, memory use
- **Baseline:** GuardDog, evaluated on the same test data
- **Experiments:** compressor (xz vs. zstd vs. PPMd), chunk size (4 / 8 / 16 KB), with vs. without the AI filter
- **Live test:** 30-day scan of newly published npm packages, confirmed via npm security takedowns and OpenSSF reports

## ⚠️ Safety

This project handles **real, active malware**.

- Never run `npm install` on any sample.
- Keep samples in their encrypted archives until needed; extract only inside a virtual machine.
- Malware is read strictly as text; PackGuard never executes package code.
- Suspicious live-scan findings are reported responsibly to npm's security team.

## Team

| Member | Role |
|---|---|
| Mayar | AI filter (Python): fine-tuning, evaluation, graphs |
| Fahad | Compression scanner (C): NCD engine, liblzma integration, live scan |

## License

_To be decided._ Third-party components: liblzma (public domain / 0BSD), ModernBERT (Apache 2.0), ONNX Runtime (MIT).
