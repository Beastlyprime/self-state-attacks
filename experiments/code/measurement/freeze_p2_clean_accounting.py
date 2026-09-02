#!/usr/bin/env python3
"""Freeze one disk-aligned accounting of the admitted P2 clean-training corpus.

The final STIDE checkpoints are the authoritative admission lists.  Older
``report_accepted*.json`` files are intentionally not consulted because they
are point-in-time reports and may lag the final on-disk corpus.
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


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _task_id(value: str) -> str | None:
    match = TASK_RE.search(value)
    return match.group(1) if match else None


def _checkpoint_inputs(profile: str, checkpoint: dict[str, Any]) -> list[dict[str, Any]]:
    if profile == "W1":
        return [item for batch in checkpoint["batches"] for item in batch["inputs"]]
    return checkpoint["discovery_inputs"] + checkpoint["cumulative_postfreeze_inputs_after_batch"]


def _heldout_ids(split: dict[str, Any]) -> set[str]:
    found: set[str] = set()

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"task_id", "source_task_id"} and isinstance(child, str):
                    task = _task_id(child)
                    if task:
                        found.add(task)
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    # The split manifest also contains train and reserve roles.  Only the
    # preregistered held-out branch is forbidden from the training freeze.
    walk(split.get("heldout_clean", []))
    return found


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split-manifest", type=Path, required=True)
    parser.add_argument("--w1-checkpoint", type=Path, required=True)
    parser.add_argument("--w2-checkpoint", type=Path, required=True)
    parser.add_argument("--w3-checkpoint", type=Path, required=True)
    parser.add_argument("--w4-checkpoint", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    split = _load(args.split_manifest)
    heldout = _heldout_ids(split)
    checkpoints = {
        "W1": args.w1_checkpoint,
        "W2": args.w2_checkpoint,
        "W3": args.w3_checkpoint,
        "W4": args.w4_checkpoint,
    }

    records: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    seen_run_ids: set[str] = set()

    for profile, checkpoint_path in checkpoints.items():
        checkpoint = _load(checkpoint_path)
        for item in _checkpoint_inputs(profile, checkpoint):
            syscall_path = Path(item["path"])
            run_dir = syscall_path.parents[2]
            run_id = run_dir.name
            task_id = _task_id(run_id)
            ground_truth_path = run_dir / "ground_truth.json"
            bridge_path = run_dir / "five_source_graph_bridge.json"
            checks: dict[str, bool] = {
                "syscalls_exists": syscall_path.is_file(),
                "ground_truth_exists": ground_truth_path.is_file(),
                "bridge_exists": bridge_path.is_file(),
                "unique_syscalls_path": str(syscall_path) not in seen_paths,
                "unique_run_id": run_id not in seen_run_ids,
                "task_id_parsed": task_id is not None,
                "heldout_disjoint": task_id not in heldout if task_id else False,
            }
            actual_sha = _sha256(syscall_path) if checks["syscalls_exists"] else None
            checks["syscalls_sha256_matches"] = actual_sha == item["sha256"]

            ground_truth: dict[str, Any] = _load(ground_truth_path) if checks["ground_truth_exists"] else {}
            checks["variant_is_clean"] = ground_truth.get("variant") == "clean"
            checks["pipeline_status_valid_attempt"] = ground_truth.get("pipeline_status") == "valid_attempt"
            case_id = ground_truth.get("case_id")
            checks["case_id_matches_run"] = isinstance(case_id, str) and run_id.startswith(case_id + "__clean")

            bridge: dict[str, Any] = _load(bridge_path) if checks["bridge_exists"] else {}
            acceptance = bridge.get("acceptance_line", {})
            checks["bridge_acceptance_passed"] = acceptance.get("passed") is True
            checks["bridge_writes_excluded_zero"] = (
                bridge.get("coverage_resolution_spine", {}).get("writes_excluded") == 0
            )

            record = {
                "profile": profile,
                "task_id": task_id,
                "case_id": case_id,
                "run_id": run_id,
                "run_dir": str(run_dir),
                "normalized_syscalls_path": str(syscall_path),
                "normalized_syscalls_sha256_expected": item["sha256"],
                "normalized_syscalls_sha256_actual": actual_sha,
                "eligible_syscalls": item.get("eligible_syscalls"),
                "branch_outcome": ground_truth.get("branch_outcome"),
                "pipeline_status": ground_truth.get("pipeline_status"),
                "checks": checks,
                "passed": all(checks.values()),
            }
            records.append(record)
            if not record["passed"]:
                failures.append({
                    "run_id": run_id,
                    "failed_checks": sorted(key for key, passed in checks.items() if not passed),
                })
            seen_paths.add(str(syscall_path))
            seen_run_ids.add(run_id)

    counts = Counter(record["profile"] for record in records)
    outcome_counts = Counter(str(record["branch_outcome"]) for record in records)
    report = {
        "schema_version": "assa.p2_clean_training_freeze.v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "role": "authoritative_disk_aligned_clean_training_accounting",
        "source_policy": {
            "authoritative": "final_STIDE_checkpoint_admission_lists",
            "excluded_as_authority": "report_accepted*.json point-in-time snapshots",
            "heldout_clean_used_for_training": False,
        },
        "checkpoint_paths": {profile: str(path) for profile, path in checkpoints.items()},
        "checkpoint_sha256": {profile: _sha256(path) for profile, path in checkpoints.items()},
        "split_manifest_path": str(args.split_manifest),
        "split_manifest_sha256": _sha256(args.split_manifest),
        "heldout_task_ids": sorted(heldout),
        "counts": {
            "total": len(records),
            "by_profile": dict(sorted(counts.items())),
            "by_branch_outcome": dict(sorted(outcome_counts.items())),
            "failures": len(failures),
        },
        "invariants": {
            "expected_total_156": len(records) == 156,
            "expected_profile_counts": dict(sorted(counts.items())) == {"W1": 25, "W2": 45, "W3": 51, "W4": 35},
            "all_disk_and_metadata_checks_passed": not failures,
            "no_duplicate_normalized_paths": len(seen_paths) == len(records),
            "no_duplicate_run_ids": len(seen_run_ids) == len(records),
            "training_heldout_task_overlap_zero": all(record["checks"]["heldout_disjoint"] for record in records),
        },
        "disk_alignment_passed": False,
        "failures": failures,
        "records": records,
    }
    report["disk_alignment_passed"] = all(report["invariants"].values())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "counts": report["counts"], "passed": report["disk_alignment_passed"]}, sort_keys=True))
    return 0 if report["disk_alignment_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
