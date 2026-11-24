# PackGuard Stage 2 v6 — Model Download & Verification

Heavy ONNX binaries are hosted on GitHub Releases (`v2.0-model`) rather than committed to Git.

## Verified Bundle (`packguard-stage2-v6-onnx.tar.gz`)

| Artifact | Size | SHA-256 |
|---|---|---|
| `packguard-stage2-v6-onnx.tar.gz` | `13,010,103` bytes (`12.41 MB`) | `9f6b70019ecee915e4c39c697e1199f8d6a664ea6ebb3f9101b7e2bf8cf415a7` |
| `packguard_v6_nano_int8.onnx` (inside tarball) | `13,848,054` bytes (`13.21 MB`) | `0a0ed0783067b5386df88d94b234570a752bc2c420257b17d71aa18ab4970ae2` |
| `tokenizer.json` (real ModernBERT BPE) | `3,583,326` bytes (`3.42 MB`) | Bundled inside tarball |
| `best_threshold.json` (`threshold = 0.945`) | `963` bytes | Bundled inside tarball |

- **Direct Download URL:**
  `https://github.com/asembarhoush-dotcom/PackGuard/releases/download/v2.0-model/packguard-stage2-v6-onnx.tar.gz`

## 1-Command Setup

**Linux / macOS:**
```bash
bash "stage 2 LLM Model/v6/install_model.sh"
```

**Windows (PowerShell):**
```powershell
pwsh "stage 2 LLM Model/v6/install_model.ps1"
```

## Runtime Requirements (100% CPU-Only — Zero PyTorch / GPU Needed)
```bash
pip install onnxruntime tokenizers numpy
python "stage 2 LLM Model/v6/stage2_filter.py" --self-test
```
