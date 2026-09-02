#!/usr/bin/env python3
"""Freeze the readiness-admitted P2 held-out clean/FPR corpus."""

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


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def task_id(text: str) -> str | None:
    match = TASK_RE.search(text)
    return match.group(1) if match else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split-manifest", required=True, type=Path)
    parser.add_argument("--source-batch", required=True, action="append", type=Path)
    parser.add_argument("--derived-batch", required=True, action="append", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if len(args.source_batch) != len(args.derived_batch):
        raise SystemExit("source-batch and derived-batch counts differ")

    split = load(args.split_manifest)
    registered = {row["task_id"]: row for row in split["heldout_clean"]}
    records: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    for source_batch, derived_batch in zip(args.source_batch, args.derived_batch):
        for run_dir in sorted((source_batch / "runs").iterdir()):
            if not run_dir.is_dir():
                continue
            derived_run = derived_batch / "runs" / run_dir.name
            ground_truth_path = run_dir / "ground_truth.json"
            bridge_path = derived_run / "five_source_graph_bridge.json"
            readiness_path = derived_run / "recollection_readiness.json"
            gt = load(ground_truth_path) if ground_truth_path.is_file() else {}
            bridge = load(bridge_path) if bridge_path.is_file() else {}
            readiness = load(readiness_path) if readiness_path.is_file() else {}
            tid = task_id(run_dir.name)
            checks = {
                "registered_heldout_task": tid in registered,
                "ground_truth_exists": ground_truth_path.is_file(),
                "variant_clean": gt.get("variant") == "clean",
                "pipeline_valid_attempt": gt.get("pipeline_status") == "valid_attempt",
                "bridge_exists": bridge_path.is_file(),
                "bridge_passed": bridge.get("passed") is True,
                "spine_rate_one": bridge.get("acceptance_line", {}).get("spine_rate") == 1.0,
                "writes_excluded_zero": bridge.get("coverage_resolution_spine", {}).get("writes_excluded") == 0,
                "effective_provenance_evaluable": bridge.get("coverage_resolution_spine_effective", {}).get("provenance_evaluable") is True,
                "readiness_exists": readiness_path.is_file(),
                "readiness_passed": readiness.get("passed") is True,
            }
            record = {
                "profile": registered.get(tid, {}).get("profile"),
                "task_id": tid,
                "registered_case_id": registered.get(tid, {}).get("case_id"),
                "run_id": run_dir.name,
                "source_run_dir": str(run_dir),
                "derived_run_dir": str(derived_run),
                "branch_outcome": gt.get("branch_outcome"),
                "pipeline_status": gt.get("pipeline_status"),
                "ground_truth_sha256": sha(ground_truth_path) if ground_truth_path.is_file() else None,
                "bridge_sha256": sha(bridge_path) if bridge_path.is_file() else None,
                "readiness_sha256": sha(readiness_path) if readiness_path.is_file() else None,
                "normalized_syscalls_sha256": sha(derived_run / "stage_g_v6/normalized/syscalls.jsonl")
                if (derived_run / "stage_g_v6/normalized/syscalls.jsonl").is_file() else None,
                "checks": checks,
                "passed": all(checks.values()),
            }
            records.append(record)
            if not record["passed"]:
                failures.append({"run_id": run_dir.name, "failed_checks": [key for key, ok in checks.items() if not ok]})

    observed_tasks = [row["task_id"] for row in records]
    profiles = Counter(row["profile"] for row in records)
    outcomes = Counter(str(row["branch_outcome"]) for row in records)
    invariants = {
        "registered_count_20": len(records) == 20,
        "five_per_profile": dict(sorted(profiles.items())) == {"W1": 5, "W2": 5, "W3": 5, "W4": 5},
        "all_registered_tasks_present_once": sorted(observed_tasks) == sorted(registered),
        "unique_run_ids": len({row["run_id"] for row in records}) == len(records),
        "all_disk_and_readiness_checks_passed": not failures,
        "not_used_for_training": True,
    }
    report = {
        "schema_version": "assa.p2_heldout_clean_freeze.v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "role": "heldout_clean_FPR_only",
        "split_manifest_path": str(args.split_manifest),
        "split_manifest_sha256": sha(args.split_manifest),
        "source_batches": [str(path) for path in args.source_batch],
        "derived_batches": [str(path) for path in args.derived_batch],
        "counts": {"total": len(records), "by_profile": dict(sorted(profiles.items())), "by_branch_outcome": dict(sorted(outcomes.items()))},
        "invariants": invariants,
        "freeze_passed": all(invariants.values()),
        "failures": failures,
        "records": records,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "counts": report["counts"], "passed": report["freeze_passed"]}, sort_keys=True))
    return 0 if report["freeze_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
