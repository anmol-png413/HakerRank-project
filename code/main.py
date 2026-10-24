#!/usr/bin/env python3
"""Ghost Data Still Exists - deletion audit agent.

Usage (from the repository root):
    python3 code/main.py                       # dataset/deletion_requests.csv -> output.csv
    python3 code/main.py --requests dataset/sample_deletion_requests.csv --output sample_pred.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ghost.engine import Engine  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", type=Path, default=ROOT / "dataset")
    ap.add_argument("--requests", type=Path, default=None)
    ap.add_argument("--output", type=Path, default=ROOT / "output.csv")
    args = ap.parse_args(argv)
    requests_path = args.requests or args.dataset / "deletion_requests.csv"

    engine = Engine(args.dataset)
    with open(requests_path, encoding="utf-8", newline="") as fh:
        requests = list(csv.DictReader(fh))
    # Public sample requests and evaluation requests are linked together so that resources
    # are attributed exclusively (one resource belongs to one request).
    wanted = {r["case_id"] for r in requests}
    context = []
    for name in ("sample_deletion_requests.csv", "deletion_requests.csv"):
        path = args.dataset / name
        if path.exists():
            with open(path, encoding="utf-8", newline="") as fh:
                context += [r for r in csv.DictReader(fh) if r["case_id"] not in wanted]
            wanted |= {r["case_id"] for r in context}
    results = engine.audit_all(requests + context)
    rows = []
    for req in requests:
        status, steps = results[req["case_id"]]
        rows.append((req["case_id"], status, json.dumps(steps, separators=(",", ":"), ensure_ascii=False)))
    rows.sort(key=lambda r: r[0])
    with open(args.output, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["case_id", "deletion_status", "steps_json"])
        w.writerows(rows)
    print(f"wrote {len(rows)} rows to {args.output}")


if __name__ == "__main__":
    main()
