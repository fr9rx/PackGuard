# PackGuard Stage 2 `v7` — Model Download & Verification

Heavy ONNX binaries are hosted on GitHub Releases (`v2.0-model`) rather than committed to Git.

## Verified Bundle (`packguard-stage2-v7-onnx.tar.gz`)

| Artifact | Size | SHA-256 |
|---|---:|---|
| `packguard-stage2-v7-onnx.tar.gz` | `31,219,102` bytes (`29.77 MB`) | `f3e2881aa71b1b20f7d51f16e4ae02cbc67bdad481d6eaa923126b174e9a83d4` |
| `packguard_v7_int8.onnx` (inside tarball) | `41,325,323` bytes (`39.41 MB`) | `ae1a5dc4380e2e671bda44644e9e61f688319d8fa8966c1d3e758152c9e774fc` |
| `tokenizer.json` (real ModernBERT BPE) | `3,583,326` bytes (`3.42 MB`) | Bundled inside tarball |
| `tokenizer_config.json` | `380` bytes | Bundled inside tarball |
| `best_threshold.json` (`threshold = 0.50`, 25-feat MIL) | `22,335` bytes | Bundled inside tarball |

- **Direct Download URL:**
  `https://github.com/asembarhoush-dotcom/PackGuard/releases/download/v2.0-model/packguard-stage2-v7-onnx.tar.gz`

## 1-Command Setup

**Linux / macOS:**
```bash
bash "stage 2 LLM Model/v7/install_model.sh"
```

**Windows (PowerShell):**
```powershell
powershell -ExecutionPolicy Bypass -File "stage 2 LLM Model/v7/install_model.ps1"
```

## Runtime Requirements (100% CPU-Only — Zero PyTorch / GPU Needed)
```bash
pip install onnxruntime tokenizers numpy
python "stage 2 LLM Model/v7/stage2_filter.py" --self-test
python "stage 2 LLM Model/v7/stage2_filter.py" --self-test --threshold 0.62
```
