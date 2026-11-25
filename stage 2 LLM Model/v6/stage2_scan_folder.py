"""
PackGuard Stage 2 v6 — Standalone Folder / Archive Scanner.
Drop-in parity with `stage 2 LLM Model/v3/stage2_scan_folder.py`.
"""

import argparse
import csv
import json
import os
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

V6_DIR = Path(__file__).resolve().parent
if str(V6_DIR) not in sys.path:
    sys.path.insert(0, str(V6_DIR))

from record_builder import package_dir_to_record
from stage2_filter import PackGuardStage2Model

ARCHIVE_EXT = (".tgz", ".tar.gz")


def find_package_root(extracted: Path) -> Path:
    entries = list(extracted.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return extracted


def iter_package_records(packages_dir: Path) -> Iterator[Tuple[str, Dict[str, Any]]]:
    for entry in sorted(packages_dir.iterdir()):
        if entry.is_dir():
            record = package_dir_to_record(entry)
            record["package"] = entry.name
            yield entry.name, record
        elif entry.is_file() and entry.name.endswith(ARCHIVE_EXT):
            with tempfile.TemporaryDirectory(prefix="pg-stage2-v6-") as tmp:
                try:
                    with tarfile.open(entry, "r:gz") as tar:
                        try:
                            tar.extractall(tmp, filter="data")
                        except TypeError:
                            tar.extractall(tmp)
                except (tarfile.TarError, OSError) as exc:
                    yield entry.name, {"package": entry.name, "chunks": [], "error": str(exc)}
                    continue
                record = package_dir_to_record(find_package_root(Path(tmp)))
                record["package"] = entry.name
                yield entry.name, record


def main() -> None:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Run PackGuard Stage 2 v6 on every package in a folder.")
    parser.add_argument("--packages", default="~/pg-scan/packages", help="Folder of package directories or .tgz archives.")
    parser.add_argument("--out-dir", default="~/pg-scan/stage2_v6", help="Folder for results.json and results.csv.")
    parser.add_argument("--model-dir", default=str(here / "model_int8"), help="Folder with ONNX model and tokenizer.json.")
    parser.add_argument("--threshold", type=float, default=None, help="Override calibrated threshold.")
    parser.add_argument("--threads", type=int, default=os.cpu_count() or 4, help="ONNX Runtime CPU threads.")
    parser.add_argument("--batch-size", type=int, default=16, help="Packages scored per batch.")
    args = parser.parse_args()

    packages_dir = Path(os.path.expanduser(args.packages)).resolve()
    out_dir = Path(os.path.expanduser(args.out_dir)).resolve()
    if not packages_dir.is_dir():
        raise SystemExit(f"Package folder not found: {packages_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)

    model = PackGuardStage2Model(Path(args.model_dir), threshold=args.threshold, threads=args.threads)

    rows: List[Dict[str, Any]] = []
    batch: List[Tuple[str, Dict[str, Any]]] = []
    started = time.perf_counter()

    def flush() -> None:
        if not batch:
            return
        t0 = time.perf_counter()
        verdicts = model.predict_records_batch([rec for _, rec in batch], batch_size=args.batch_size)
        per_pkg_ms = (time.perf_counter() - t0) * 1000.0 / len(batch)
        for (name, rec), (flagged, prob) in zip(batch, verdicts):
            row = {
                "package": name,
                "stage2_flagged": flagged,
                "stage2_prob": round(prob, 6),
                "chunks": len(rec.get("chunks") or []),
                "ms": round(per_pkg_ms, 2),
                "error": rec.get("error", ""),
            }
            rows.append(row)
            verdict = "MALICIOUS" if flagged else "BENIGN"
            note = "  (no JS or install scripts)" if not row["chunks"] else ""
            print(f"{verdict:<9} {prob:.4f}  {name}{note}", flush=True)
        batch.clear()

    for item in iter_package_records(packages_dir):
        batch.append(item)
        if len(batch) >= args.batch_size:
            flush()
    flush()

    total_seconds = time.perf_counter() - started
    flagged_count = sum(1 for r in rows if r["stage2_flagged"])
    summary = {
        "model": model.onnx_path.name,
        "packages": len(rows),
        "flagged": flagged_count,
        "flagged_rate": (flagged_count / len(rows)) if rows else 0.0,
        "empty_packages": sum(1 for r in rows if not r["chunks"]),
        "threshold": model.threshold,
        "seconds": round(total_seconds, 2),
        "results": rows,
    }
    (out_dir / "results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    with (out_dir / "results.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["package", "stage2_flagged", "stage2_prob", "chunks", "ms", "error"])
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    main()
