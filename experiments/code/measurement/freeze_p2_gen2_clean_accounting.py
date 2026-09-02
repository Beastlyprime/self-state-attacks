#!/usr/bin/env python3
"""Freeze P2 gen2 clean-training or held-out accounting.

This does not score detectors and does not mutate gen1 freezes.  It records a
new generation's admitted clean runs after live collection, bridge derivation,
and readiness gates have already run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TASK_RE = re.compile(r"(W[1-4]_C\d+_V\d+)")
PROFILES = ("W1", "W2", "W3", "W4")


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def task_id(text: str | None) -> str | None:
    if not text:
        return None
    match = TASK_RE.search(text)
    return match.group(1) if match else None


def iter_batch_runs(source_batch: Path) -> list[Path]:
    runs = source_batch / "runs"
    if not runs.is_dir():
        raise FileNotFoundError(runs)
    return sorted(path for path in runs.iterdir() if path.is_dir())


def bridge_path_for(run_dir: Path, derived_batch: Path | None) -> Path:
    if derived_batch is None:
        return run_dir / "five_source_graph_bridge.json"
    return derived_batch / "runs" / run_dir.name / "five_source_graph_bridge.json"


def readiness_path_for(run_dir: Path, derived_batch: Path | None) -> Path:
    if derived_batch is None:
        return run_dir / "recollection_readiness.json"
    return derived_batch / "runs" / run_dir.name / "recollection_readiness.json"


def graph_root_for(run_dir: Path, derived_batch: Path | None) -> Path:
    if derived_batch is None:
        return run_dir / "graph" / "reattributed" / "resolution_spine_effective"
    return derived_batch / "runs" / run_dir.name / "graph" / "reattributed" / "resolution_spine_effective"


def make_record(run_dir: Path, derived_batch: Path | None) -> dict[str, Any]:
    gt_path = run_dir / "ground_truth.json"
    bridge_path = bridge_path_for(run_dir, derived_batch)
    readiness_path = readiness_path_for(run_dir, derived_batch)
    graph_root = graph_root_for(run_dir, derived_batch)
    syscalls_path = graph_root / "syscalls.jsonl"
    gt = load(gt_path) if gt_path.is_file() else {}
    bridge = load(bridge_path) if bridge_path.is_file() else {}
    readiness = load(readiness_path) if readiness_path.is_file() else {}
    run_id = run_dir.name
    tid = gt.get("task_id") or task_id(gt.get("case_id")) or task_id(run_id)
    profile = gt.get("profile") or (tid.split("_", 1)[0] if isinstance(tid, str) and tid.startswith("W") else None)
    checks = {
        "ground_truth_exists": gt_path.is_file(),
        "variant_clean": gt.get("variant") == "clean",
        "pipeline_valid_attempt": gt.get("pipeline_status") == "valid_attempt",
        "profile_valid": profile in PROFILES,
        "task_id_present": isinstance(tid, str),
        "bridge_exists": bridge_path.is_file(),
        "bridge_passed": bridge.get("passed") is True or bridge.get("acceptance_line", {}).get("passed") is True,
        "fd_path_resolved_rate_ge_0_95": (
            (bridge.get("acceptance_line") or {}).get("spine_rate")
            if isinstance(bridge.get("acceptance_line"), dict) else None
        ) is not None and float(bridge["acceptance_line"]["spine_rate"]) >= 0.95,
        "writes_excluded_zero": bridge.get("coverage_resolution_spine", {}).get("writes_excluded") == 0,
        "effective_provenance_evaluable": bridge.get("coverage_resolution_spine_effective", {}).get("provenance_evaluable") is True,
        "readiness_exists": readiness_path.is_file(),
        "readiness_passed": readiness.get("passed") is True,
        "normalized_syscalls_exists": syscalls_path.is_file(),
    }
    if checks["normalized_syscalls_exists"]:
        syscalls_sha = sha(syscalls_path)
    else:
        syscalls_sha = None
    record = {
        "profile": profile,
        "task_id": tid,
        "case_id": gt.get("case_id"),
        "run_id": run_id,
        "run_dir": str(run_dir.resolve()),
        "derived_run_dir": str((derived_batch / "runs" / run_id).resolve()) if derived_batch else str(run_dir.resolve()),
        "graph_root": str(graph_root.resolve()),
        "normalized_syscalls_path": str(syscalls_path.resolve()) if syscalls_path.is_file() else None,
        "normalized_syscalls_sha256": syscalls_sha,
        "branch_outcome": gt.get("branch_outcome"),
        "pipeline_status": gt.get("pipeline_status"),
        "ground_truth_sha256": sha(gt_path) if gt_path.is_file() else None,
        "bridge_sha256": sha(bridge_path) if bridge_path.is_file() else None,
        "readiness_sha256": sha(readiness_path) if readiness_path.is_file() else None,
        "spine_rate": bridge.get("acceptance_line", {}).get("spine_rate") if bridge else None,
        "writes_excluded": bridge.get("coverage_resolution_spine", {}).get("writes_excluded") if bridge else None,
        "checks": checks,
        "passed": all(checks.values()),
    }
    return record


def load_base_records(path: Path | None) -> list[dict[str, Any]]:
    if not path:
        return []
    data = load(path)
    records = data.get("records")
    if not isinstance(records, list):
        raise ValueError(f"{path} has no records list")
    out: list[dict[str, Any]] = []
    for record in records:
        copied = dict(record)
        copied["source_freeze"] = str(path)
        copied["passed"] = bool(record.get("passed", True))
        out.append(copied)
    return out


def parse_expected(value: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for part in value.split(","):
        key, sep, raw = part.partition("=")
        if sep != "=" or key not in PROFILES:
            raise argparse.ArgumentTypeError("expected counts must be W1=N,W2=N,W3=N,W4=N")
        out[key] = int(raw)
    if set(out) != set(PROFILES):
        raise argparse.ArgumentTypeError("expected counts must include W1-W4")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", required=True, choices=["training", "heldout"])
    parser.add_argument("--generation-id", required=True)
    parser.add_argument("--base-freeze", type=Path)
    parser.add_argument("--source-batch", action="append", type=Path, default=[])
    parser.add_argument("--derived-batch", action="append", type=Path, default=[])
    parser.add_argument("--expected-profile-counts", required=True, type=parse_expected)
    parser.add_argument(
        "--admit-passed-only",
        action="store_true",
        help=(
            "For source batches, freeze only runs that pass all clean/readiness checks "
            "and retain failed runs in excluded_records. Base-freeze records are still "
            "required to be passed."
        ),
    )
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.derived_batch and len(args.source_batch) != len(args.derived_batch):
        raise SystemExit("source-batch and derived-batch counts differ")
    derived_batches: list[Path | None]
    if args.derived_batch:
        derived_batches = args.derived_batch
    else:
        derived_batches = [None] * len(args.source_batch)

    records = load_base_records(args.base_freeze)
    new_records: list[dict[str, Any]] = []
    excluded_records: list[dict[str, Any]] = []
    for source, derived in zip(args.source_batch, derived_batches):
        for run_dir in iter_batch_runs(source):
            record = make_record(run_dir, derived)
            record["source_batch"] = str(source)
            record["derived_batch"] = str(derived) if derived else None
            if args.admit_passed_only and not record["passed"]:
                excluded_records.append(record)
            else:
                new_records.append(record)
    records.extend(new_records)

    failures = [
        {"run_id": row.get("run_id"), "failed_checks": [key for key, ok in (row.get("checks") or {}).items() if not ok]}
        for row in records
        if row.get("passed") is False or (row.get("checks") and not all(row["checks"].values()))
    ]
    profile_counts = Counter(row.get("profile") for row in records)
    profile_counts.pop(None, None)
    run_ids = [row.get("run_id") for row in records]
    syscalls_paths = [row.get("normalized_syscalls_path") for row in records if row.get("normalized_syscalls_path")]
    invariants = {
        "expected_profile_counts": dict(sorted(profile_counts.items())) == args.expected_profile_counts,
        "all_checks_passed": not failures,
        "unique_run_ids": len(set(run_ids)) == len(run_ids),
        "no_duplicate_normalized_syscalls_paths": len(set(syscalls_paths)) == len(syscalls_paths),
    }
    report = {
        "schema_version": f"assa.p2_gen2_clean_{args.role}_freeze.v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "generation_id": args.generation_id,
        "role": args.role,
        "base_freeze": str(args.base_freeze) if args.base_freeze else None,
        "base_freeze_sha256": sha(args.base_freeze) if args.base_freeze else None,
        "source_batches": [str(path) for path in args.source_batch],
        "derived_batches": [str(path) for path in args.derived_batch],
        "counts": {
            "total": len(records),
            "new_records": len(new_records),
            "excluded_records": len(excluded_records),
            "by_profile": dict(sorted(profile_counts.items())),
            "by_branch_outcome": dict(sorted(Counter(str(row.get("branch_outcome")) for row in records).items())),
        },
        "expected_profile_counts": args.expected_profile_counts,
        "invariants": invariants,
        "freeze_passed": all(invariants.values()),
        "failures": failures,
        "excluded_records": [
            {
                "profile": row.get("profile"),
                "task_id": row.get("task_id"),
                "case_id": row.get("case_id"),
                "run_id": row.get("run_id"),
                "run_dir": row.get("run_dir"),
                "branch_outcome": row.get("branch_outcome"),
                "pipeline_status": row.get("pipeline_status"),
                "failed_checks": [key for key, ok in (row.get("checks") or {}).items() if not ok],
            }
            for row in excluded_records
        ],
        "records": records,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output.resolve()), "passed": report["freeze_passed"], "counts": report["counts"]}, sort_keys=True))
    return 0 if report["freeze_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
