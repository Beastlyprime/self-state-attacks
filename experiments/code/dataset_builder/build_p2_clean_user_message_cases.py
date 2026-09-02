#!/usr/bin/env python3
"""Adapt selected P2 clean cases to their natural user-message carrier."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "assa.p2_clean_user_message_cases.v1"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build(source_root: Path, output_root: Path, case_ids: list[str]) -> Path:
    if output_root.exists():
        raise FileExistsError(output_root)
    if not case_ids or len(case_ids) != len(set(case_ids)):
        raise ValueError("case_ids must be a non-empty unique list")

    output_root.mkdir(parents=True)
    rows = []
    for source_case_id in case_ids:
        source_case_dir = source_root / "cases" / source_case_id
        source_case = _load(source_case_dir / "case.json")
        task = _load(source_case_dir / "task.json")
        new_case_id = source_case_id + "_user_message"
        case_dir = output_root / "cases" / new_case_id
        (case_dir / "variants").mkdir(parents=True)

        task = dict(task)
        task["prompt_must_run_verbatim"] = False
        task["session_a_message_supplied_by_gateway_variant"] = True
        _write(case_dir / "task.json", task)
        shutil.copy2(source_case_dir / "consequence.json", case_dir / "consequence.json")

        source_checkpoint = source_root / source_case["checkpoint"]["workspace"]
        destination_checkpoint = output_root / "checkpoints" / new_case_id / "workspace"
        shutil.copytree(source_checkpoint, destination_checkpoint)
        source_manifest = source_root / source_case["checkpoint"]["manifest"]
        destination_manifest = destination_checkpoint.parent / "workspace_manifest.json"
        shutil.copy2(source_manifest, destination_manifest)

        message = str(task["prompt"])
        encoded = message.encode("utf-8")
        variant = {
            "schema_version": "assa.user_message_variant.v1",
            "case_id": new_case_id,
            "variant": "clean",
            "channel": "user_message",
            "message": message,
            "message_sha256": _sha(encoded),
            "message_bytes": len(encoded),
            "semantic_slot_id": "clean_curated_task_prompt",
            "slot_label": "clean_no_attack",
            "filesystem_artifact_delivered_to_workspace": False,
            "clean_poisoned_symmetry": "not_applicable_clean_only_corpus",
        }
        _write(case_dir / "variants" / "clean.json", variant)

        case = dict(source_case)
        case["case_id"] = new_case_id
        case["carrier_path"] = "user_message:session_a"
        case["delivery"] = {
            "channel": "user_message",
            "fixture_process": "gateway_user_message",
            "filesystem_ingestion_observable": False,
            "ingestion_observation_type": "no_filesystem_ingestion_observable",
            "ordinary_task_seed_files": [row["path"] for row in task.get("seed_files", [])],
        }
        case["task"] = task
        case["checkpoint"] = dict(case["checkpoint"])
        case["checkpoint"].update({
            "workspace": f"checkpoints/{new_case_id}/workspace",
            "manifest": f"checkpoints/{new_case_id}/workspace_manifest.json",
        })
        case["variants"] = {
            "clean": {
                "artifact": "variants/clean.json",
                "sha256": variant["message_sha256"],
                "bytes": variant["message_bytes"],
            }
        }
        case["source_provenance"] = dict(case["source_provenance"])
        case["source_provenance"].update({
            "source_case_id": source_case_id,
            "relationship": "clean-only natural-channel correction",
            "adapter_authorship": "benchmark_authors_envelope_only",
            "message_content_origin": "verbatim curated task prompt",
        })
        _write(case_dir / "case.json", case)
        rows.append({
            "case_id": new_case_id,
            "source_case_id": source_case_id,
            "task_id": case["task_id"],
            "split_role": case["split_role"],
            "channel": "user_message",
            "message_sha256": variant["message_sha256"],
            "checkpoint_manifest_sha256": case["checkpoint"]["manifest_sha256"],
        })

    _write(output_root / "source_manifest.json", {
        "schema_version": "assa.source_manifest.v2",
        "cases": [row["case_id"] for row in rows],
        "channel_counts": {"user_message": len(rows)},
        "carrier_files_materialized": False,
        "source_root": str(source_root),
        "records": rows,
    })
    _write(output_root / "input_root_manifest.json", {
        "schema_version": SCHEMA_VERSION,
        "cases": [row["case_id"] for row in rows],
        "clean_only": True,
        "hard_red_lines": {
            "task_prompt_verbatim_in_gateway_message": True,
            "ordinary_seed_files_preserved": True,
            "no_filesystem_carrier_claim": True,
            "no_poisoned_variant_generated": True,
        },
    })
    return output_root


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--case-id", action="append", required=True)
    args = parser.parse_args()
    print(build(args.source_root.resolve(), args.output.resolve(), args.case_id))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
