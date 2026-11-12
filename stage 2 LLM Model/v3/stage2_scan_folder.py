import argparse
import csv
import json
import os
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

from stage2_filter import PackGuardStage2Model, package_dir_to_record

ARCHIVE_EXT = (".tgz", ".tar.gz")


# Returns the package root inside an extracted npm tarball: the single top
# folder (usually `package/`) when there is exactly one, else the folder itself.
def find_package_root(extracted: Path) -> Path:
    entries = [p for p in extracted.iterdir()]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return extracted


# Yields (name, record) for every package in the drop folder. A package is a
# sub-directory or a .tgz/.tar.gz archive; archives are unpacked as data only
# into a temporary folder that is removed after the record is built.
def iter_package_records(packages_dir: Path) -> Iterator[Tuple[str, Dict[str, Any]]]:
    for entry in sorted(packages_dir.iterdir()):
        if entry.is_dir():
            record = package_dir_to_record(entry)
            record["package"] = entry.name
            yield entry.name, record
        elif entry.is_file() and entry.name.endswith(ARCHIVE_EXT):
            with tempfile.TemporaryDirectory(prefix="pg-stage2-") as tmp:
                try:
                    with tarfile.open(entry, "r:gz") as tar:
                        tar.extractall(tmp, filter="data")
                except (tarfile.TarError, OSError) as exc:
                    yield entry.name, {"package": entry.name, "chunks": [], "error": str(exc)}
                    continue
                record = package_dir_to_record(find_package_root(Path(tmp)))
                record["package"] = entry.name
                yield entry.name, record


# Scores every package in the drop folder with the Stage 2 model alone (no
# Stage 1 gate), prints one line per package and writes results.json and
# results.csv to the output folder. Package code is only read as text.
def main() -> None:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Run the PackGuard Stage 2 model on every package in a folder.")
    parser.add_argument("--packages", default="~/pg-scan/packages", help="Folder of package directories or .tgz archives.")
    parser.add_argument("--out-dir", default="~/pg-scan/stage2", help="Folder for results.json and results.csv.")
    parser.add_argument("--model-dir", default=str(here / "model_int8"), help="Folder with the ONNX model and tokenizer.")
    parser.add_argument("--threshold", type=float, default=None, help="Override the calibrated threshold.")
    parser.add_argument("--threads", type=int, default=os.cpu_count() or 4, help="ONNX Runtime CPU threads.")
    parser.add_argument("--batch-size", type=int, default=8, help="Packages scored per batch.")
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
                "stage2_prob": prob,
                "chunks": len(rec.get("chunks") or []),
                "ms": round(per_pkg_ms, 1),
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
        "packages": len(rows),
        "flagged": flagged_count,
        "flagged_rate": (flagged_count / len(rows)) if rows else 0.0,
        "empty_packages": sum(1 for r in rows if not r["chunks"]),
        "threshold": model.threshold,
        "seconds": round(total_seconds, 2),
    }
    (out_dir / "results.json").write_text(
        json.dumps({"summary": summary, "packages": rows}, indent=2), encoding="utf-8"
    )
    with open(out_dir / "results.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["package", "stage2_flagged", "stage2_prob", "chunks", "ms", "error"])
        writer.writeheader()
        writer.writerows(rows)

    print(json.dumps(summary))
    print(f"Results: {out_dir / 'results.json'}")


if __name__ == "__main__":
    main()
