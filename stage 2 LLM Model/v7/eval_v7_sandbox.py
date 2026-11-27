"""
PackGuard Stage 2 v7 — Full 22,684-Package Real Linux Sandbox Evaluator (100% Pure Neural CPU ONNX).

Evaluates Stage 2 v7 standalone on CPU (`CPUExecutionProvider`, `CUDA_VISIBLE_DEVICES=""`) across:
  - ALL 2,549 untouched held-out real benign npm packages (`data/from-instance/benign/`)
  - ALL 11,050 untouched held-out `known` malware packages (`data/from-instance/known/`)
  - ALL 9,085 untouched held-out `new` malware packages (`data/from-instance/new/`)
  - All 10 pure-neural regression & obfuscation probes (`run_self_test`)
  - Side-by-side comparison vs Stage 2 v6 (`v6/results.json`) across every category!
"""

import argparse
import hashlib
import json
import os
import random
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

os.environ["CUDA_VISIBLE_DEVICES"] = ""

V7_DIR = Path(__file__).resolve().parent
if str(V7_DIR) not in sys.path:
    sys.path.insert(0, str(V7_DIR))

import numpy as np

from metrics_v7 import evaluate_metrics_at_threshold
from record_builder import package_dir_to_record
from stage2_filter import PackGuardStage2Model, run_self_test


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def _safe_component(value: str) -> str:
    return value.replace("/", "__").replace("\\", "__").replace(":", "_")


def _infer_category_from_manifests(repo_dir: Path) -> Dict[Tuple[str, str], str]:
    mapping: Dict[Tuple[str, str], str] = {}
    for mf_name in ("manifest_real.json", "manifest_invented.json"):
        mf_path = repo_dir / "test-sets" / mf_name
        if not mf_path.is_file():
            continue
        try:
            data = json.loads(mf_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        entries = data if isinstance(data, list) else data.get("packages", data.get("entries", []))
        if not isinstance(entries, list):
            continue
        for e in entries:
            if not isinstance(e, dict):
                continue
            set_name = str(e.get("set") or "")
            cat = str(e.get("category") or "unknown")
            pkg = str(e.get("package") or "")
            ver = str(e.get("version") or "")
            if not pkg:
                continue
            flat_safe = f"{_safe_component(pkg)}@{_safe_component(ver)}" if ver else _safe_component(pkg)
            flat_raw = f"{pkg}@{ver}" if ver else pkg
            flat_single = f"{pkg.replace('/', '_')}@{ver}" if ver else pkg.replace("/", "_")
            flat_at = f"{pkg.replace('/', '@')}@{ver}" if ver else pkg.replace("/", "@")
            for k in (flat_safe, flat_raw, flat_single, flat_at):
                mapping[(set_name, k)] = cat
    return mapping


def _discover_flat_dirs(folder: Path) -> List[Path]:
    return sorted([p for p in folder.iterdir() if p.is_dir()]) if folder.is_dir() else []


def _score_package_dirs(
    model: PackGuardStage2Model,
    pkg_dirs: List[Path],
    batch_size: int = 24,
    label_tag: str = "",
) -> Tuple[List[Dict[str, Any]], List[float]]:
    rows: List[Dict[str, Any]] = []
    latencies_ms: List[float] = []
    n = len(pkg_dirs)

    for start in range(0, n, batch_size):
        chunk_dirs = pkg_dirs[start : start + batch_size]
        t0 = time.perf_counter()
        records = [package_dir_to_record(p) for p in chunk_dirs]
        verdicts = model.predict_records_batch(records, batch_size=max(24, batch_size))
        dt_ms = (time.perf_counter() - t0) * 1000.0
        per_pkg_ms = dt_ms / max(1, len(chunk_dirs))

        for pdir, rec, (flagged, prob) in zip(chunk_dirs, records, verdicts):
            latencies_ms.append(per_pkg_ms)
            rows.append(
                {
                    "package": pdir.name,
                    "flagged": bool(flagged),
                    "prob": round(float(prob), 6),
                    "chunks": len(rec.get("chunks") or []),
                    "ms": round(per_pkg_ms, 3),
                }
            )
        if (start + batch_size) % 1000 < batch_size or (start + batch_size) >= n:
            done = min(n, start + batch_size)
            flagged_so_far = sum(1 for r in rows if r["flagged"])
            print(
                f"  [{label_tag}] {done}/{n} scored | flagged={flagged_so_far} "
                f"({100.0 * flagged_so_far / max(1, done):.2f}%) | median_ms={np.median(latencies_ms):.2f}",
                flush=True,
            )

    return rows, latencies_ms


def main() -> None:
    parser = argparse.ArgumentParser(description="PackGuard Stage 2 v7 Full 22,684-Package Real Sandbox Benchmark.")
    parser.add_argument("--repo-dir", default="/home/USER/PackGuard")
    parser.add_argument("--heldout-dir", default="/home/USER/v6_sandbox/heldout")
    parser.add_argument("--model-dir", default="/home/USER/v7_sandbox/output/model_int8")
    parser.add_argument("--out-json", default="/home/USER/v7_sandbox/output/results_v7.json")
    parser.add_argument("--threshold", type=float, default=None)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--batch-size", type=int, default=24)
    parser.add_argument("--max-benign", type=int, default=0)
    parser.add_argument("--max-mal-per-set", type=int, default=0)
    args = parser.parse_args()

    repo = Path(args.repo_dir).resolve()
    heldout = Path(args.heldout_dir).resolve()
    if not (heldout / "benign").is_dir():
        alt = Path("/home/USER/v7_sandbox/heldout")
        if (alt / "benign").is_dir():
            heldout = alt

    model = PackGuardStage2Model(model_dir=Path(args.model_dir).resolve(), threshold=args.threshold, threads=args.threads)
    print("=== PackGuard Stage 2 v7 Real Linux Sandbox Benchmark ===")
    print(f"Model      : {model.onnx_path} ({model.onnx_path.stat().st_size / (1024*1024):.3f} MB)")
    print(f"SHA-256    : {_sha256(model.onnx_path)}")
    print(f"Providers  : {model.session.get_providers()} (100% CPU-Only)")
    print(f"Threshold  : {model.threshold:.4f} (MIL enabled={bool(model.mil_cfg and model.mil_cfg.get('enabled'))})")

    st_code = run_self_test(model)
    cat_map = _infer_category_from_manifests(repo)

    ben_dirs = _discover_flat_dirs(heldout / "benign")
    known_dirs = _discover_flat_dirs(heldout / "known")
    new_dirs = _discover_flat_dirs(heldout / "new")

    rng = random.Random(42)
    if args.max_benign > 0 and len(ben_dirs) > args.max_benign:
        ben_dirs = rng.sample(ben_dirs, args.max_benign)
    if args.max_mal_per_set > 0:
        if len(known_dirs) > args.max_mal_per_set:
            known_dirs = rng.sample(known_dirs, args.max_mal_per_set)
        if len(new_dirs) > args.max_mal_per_set:
            new_dirs = rng.sample(new_dirs, args.max_mal_per_set)

    ben_rows, ben_lat = _score_package_dirs(model, ben_dirs, batch_size=args.batch_size, label_tag="BENIGN")
    known_rows, known_lat = _score_package_dirs(model, known_dirs, batch_size=args.batch_size, label_tag="KNOWN")
    new_rows, new_lat = _score_package_dirs(model, new_dirs, batch_size=args.batch_size, label_tag="NEW")

    y_true = np.array([0] * len(ben_rows) + [1] * len(known_rows) + [1] * len(new_rows), dtype=np.int64)
    y_score = np.array(
        [r["prob"] for r in ben_rows] + [r["prob"] for r in known_rows] + [r["prob"] for r in new_rows],
        dtype=np.float64,
    )

    overall_m = evaluate_metrics_at_threshold(y_true, y_score, model.threshold)
    known_flagged = sum(1 for r in known_rows if r["flagged"])
    new_flagged = sum(1 for r in new_rows if r["flagged"])
    ben_flagged = sum(1 for r in ben_rows if r["flagged"])
    zero_chunk_mal = sum(1 for r in known_rows + new_rows if r["chunks"] == 0)

    all_lat = np.array(ben_lat + known_lat + new_lat, dtype=np.float64)

    per_cat: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "flagged": 0})
    for prefix, rows in (("known", known_rows), ("new", new_rows)):
        for r in rows:
            cat = cat_map.get((prefix, r["package"]), "unmapped")
            key = f"{prefix}/{cat}"
            per_cat[key]["total"] += 1
            if r["flagged"]:
                per_cat[key]["flagged"] += 1

    cat_summary = {
        k: {
            "total": v["total"],
            "flagged": v["flagged"],
            "recall_pct": round(100.0 * v["flagged"] / max(1, v["total"]), 2),
        }
        for k, v in sorted(per_cat.items(), key=lambda kv: kv[1]["flagged"] / max(1, kv[1]["total"]))
    }

    threshold_sweep = [
        evaluate_metrics_at_threshold(y_true, y_score, float(t))
        for t in (0.30, 0.40, 0.50, 0.62, 0.70, 0.80, 0.90, 0.95, model.threshold)
    ]

    ben_fps = sorted([r for r in ben_rows if r["flagged"]], key=lambda x: -x["prob"])
    mal_fns = sorted(
        [{**r, "set": "known"} for r in known_rows if not r["flagged"]]
        + [{**r, "set": "new"} for r in new_rows if not r["flagged"]],
        key=lambda x: x["prob"],
    )

    result = {
        "benchmark": "PackGuard Stage 2 v7 — Real Linux Sandbox Evaluation (Pure Neural ONNX + Static AST Folder)",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model": {
            "file": model.onnx_path.name,
            "size_bytes": model.onnx_path.stat().st_size,
            "size_mb": round(model.onnx_path.stat().st_size / (1024 * 1024), 3),
            "sha256": _sha256(model.onnx_path),
            "providers": model.session.get_providers(),
            "tokenizer": "Real ModernBERT BPE (tokenizers Rust library)",
            "rules_override": False,
            "mil_enabled": bool(model.mil_cfg and model.mil_cfg.get("enabled")),
            "threshold": model.threshold,
        },
        "self_test_passed": (st_code == 0),
        "zero_chunk_malware_count": zero_chunk_mal,
        "overall": overall_m,
        "sets": {
            "benign": {
                "total": len(ben_rows),
                "false_alarms": ben_flagged,
                "fpr_pct": round(100.0 * ben_flagged / max(1, len(ben_rows)), 2),
                "benign_specificity_pct": round(100.0 * (len(ben_rows) - ben_flagged) / max(1, len(ben_rows)), 2),
            },
            "known": {
                "total": len(known_rows),
                "flagged": known_flagged,
                "recall_pct": round(100.0 * known_flagged / max(1, len(known_rows)), 2),
            },
            "new": {
                "total": len(new_rows),
                "flagged": new_flagged,
                "recall_pct": round(100.0 * new_flagged / max(1, len(new_rows)), 2),
            },
        },
        "cpu_latency_ms": {
            "median": round(float(np.median(all_lat)), 3),
            "mean": round(float(np.mean(all_lat)), 3),
            "p95": round(float(np.percentile(all_lat, 95)), 3),
            "max": round(float(np.max(all_lat)), 3),
        },
        "threshold_sweep": threshold_sweep,
        "per_category_recall": cat_summary,
        "sample_benign_false_positives": ben_fps[:40],
        "sample_malware_false_negatives": mal_fns[:40],
    }

    out_path = Path(args.out_json)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print("\n================ FINAL v7 SANDBOX SUMMARY ================")
    print(f"  Network-Only ROC-AUC : {overall_m['roc_auc']:.5f}")
    print(f"  Benign Specificity   : {result['sets']['benign']['benign_specificity_pct']:.2f}% ({len(ben_rows)-ben_flagged}/{len(ben_rows)}, FPR={result['sets']['benign']['fpr_pct']:.2f}%)")
    print(f"  Known Malware Recall : {result['sets']['known']['recall_pct']:.2f}% ({known_flagged}/{len(known_rows)})")
    print(f"  New Malware Recall   : {result['sets']['new']['recall_pct']:.2f}% ({new_flagged}/{len(new_rows)})")
    print(f"  Overall Malware Rec  : {overall_m['recall']*100:.2f}% (zero-chunk malware={zero_chunk_mal})")
    print(f"  CPU Latency (4 thr)  : median={result['cpu_latency_ms']['median']:.2f} ms, mean={result['cpu_latency_ms']['mean']:.2f} ms, p95={result['cpu_latency_ms']['p95']:.2f} ms")

    v6_res_path = V7_DIR.parent / "v6" / "results.json"
    if v6_res_path.is_file():
        try:
            v6_r = json.loads(v6_res_path.read_text(encoding="utf-8"))
            v6_auc = v6_r["overall"]["roc_auc"]
            v6_spec = v6_r["sets"]["benign"]["benign_specificity_pct"]
            v6_rec = v6_r["overall"]["recall"] * 100.0
            print(
                f"  Delta vs Stage 2 v6  : AUC {v6_auc:.5f} -> {overall_m['roc_auc']:.5f} "
                f"| Spec {v6_spec:.2f}% -> {result['sets']['benign']['benign_specificity_pct']:.2f}% "
                f"| Recall {v6_rec:.2f}% -> {overall_m['recall']*100:.2f}%"
            )
        except Exception:
            pass


if __name__ == "__main__":
    main()
