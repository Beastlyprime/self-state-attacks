#!/usr/bin/env python3
"""AIDE generation-2 scorer using content-delta snapshot materialization."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from .external import _parse_aide_report, run_tool
from .generation_contract import (
    require_detector_config,
    require_detector_registration,
    validate_exported_inventory,
)
from .p2_detector_fpr import (
    AIDE_COMMIT,
    heldout_records,
    require_commit,
    sha256,
    write_detector_result,
    write_json,
)


def tree_files(root: Path) -> dict[str, Path]:
    return {path.relative_to(root).as_posix(): path
            for path in root.rglob("*") if path.is_file()}


def apply_content_delta(snapshot: Path, materialized: Path) -> dict[str, Any]:
    wanted, current = tree_files(snapshot), tree_files(materialized)
    removed, added, changed, unchanged = [], [], [], []
    for relative in sorted(set(current) - set(wanted), reverse=True):
        current[relative].unlink()
        removed.append(relative)
    for relative, source in sorted(wanted.items()):
        destination = materialized / relative
        if not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            added.append(relative)
        elif source.read_bytes() != destination.read_bytes():
            shutil.copyfile(source, destination)
            changed.append(relative)
        else:
            unchanged.append(relative)
    for directory in sorted(
        (path for path in materialized.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts), reverse=True
    ):
        if not any(directory.iterdir()):
            directory.rmdir()
    return {
        "added": added, "removed": removed, "content_changed": changed,
        "untouched_byte_identical": unchanged,
        "metadata_replay_boundary": (
            "snapshot files are side-channel byte copies and do not preserve original "
            "workspace metadata; unchanged files are left untouched, and changed files "
            "are rewritten in place. Primary any-content-change decisions are evaluable; "
            "metadata-only FPR is not inferred."
        ),
    }


def run_one(snapshot_root: Path, output: Path, aide_repo: Path, image: str,
            generation_id: str) -> dict[str, Any]:
    snaps = {name: snapshot_root / name for name in ("before_a", "after_a", "after_b")}
    if not all(path.is_dir() for path in snaps.values()):
        raise ValueError(f"incomplete snapshots: {snapshot_root}")
    output.mkdir(parents=True)
    materialized = output / "materialized_state"
    database, database_new = output / "aide.db", output / "aide.db.new"
    config = output / "aide.conf"
    config.write_text(
        "database_in=file:/work/aide.db\n"
        "database_out=file:/work/aide.db.new\n"
        "report_url=stdout\n"
        "Checks = p+i+n+u+g+s+m+c+sha256\n"
        "/work/materialized_state Checks\n",
        encoding="utf-8",
    )
    shutil.copytree(snaps["before_a"], materialized)
    uid = f"{os.getuid()}:{os.getgid()}"
    base = ["docker", "run", "--rm", "--user", uid,
            "-v", f"{output.resolve()}:/work", image]
    runs = [
        run_tool(["docker", "image", "inspect", image], output, "image_inspect"),
        run_tool([*base, "--version"], output, "version"),
        run_tool([*base, "--config", "/work/aide.conf", "--init"], output, "init"),
    ]
    if runs[-1].exit_status != 0 or not database_new.is_file():
        status, deltas = "failed", {}
    else:
        database_new.replace(database)
        runs.append(run_tool([*base, "--config", "/work/aide.conf", "--check"],
                             output, "before_control"))
        status = "passed" if runs[-1].exit_status == 0 else "failed"
        deltas = {}
        for label in ("after_a", "after_b"):
            deltas[label] = apply_content_delta(snaps[label], materialized)
            runs.append(run_tool([*base, "--config", "/work/aide.conf", "--check"],
                                 output, label))
    reports = {
        run.stdout.name.removesuffix(".stdout.log"): _parse_aide_report(run.stdout)
        for run in runs[3:]
    }
    if status == "passed" and any(value["parse_status"] != "parsed"
                                   for value in reports.values()):
        status = "failed"
    write_json(output / "parsed_reports.json", reports)
    write_json(output / "materialization_deltas.json", deltas)
    commands = [{
        "command": run.command, "exit_status": run.exit_status,
        "stdout_sha256": sha256(run.stdout), "stderr_sha256": sha256(run.stderr),
    } for run in runs]
    image_id = subprocess.run(
        ["docker", "image", "inspect", image, "--format", "{{.Id}}"],
        text=True, stdout=subprocess.PIPE, check=False
    ).stdout.strip()
    manifest = {
        "schema_version": "assa.aide_content_delta_materialization.v1",
        "generation_id": generation_id, "status": status,
        "tool": "AIDE", "version": "0.19.3", "commit": AIDE_COMMIT,
        "image": image, "image_id": image_id,
        "config_sha256": sha256(config), "commands": commands,
        "reports_sha256": sha256(output / "parsed_reports.json"),
        "deltas_sha256": sha256(output / "materialization_deltas.json"),
        "apparatus_control": (
            "byte-identical files remain untouched across before_a->after_a->after_b; "
            "the superseded generation-1 delete-and-recopy adapter changed every mtime/ctime"
        ),
    }
    write_json(output / "tool_manifest.json", manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--aide-repo", required=True, type=Path)
    parser.add_argument("--aide-image", default="assa-stage-g/aide:0.19.3")
    parser.add_argument("--generation-contract", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    generation_context = validate_exported_inventory(
        args.input_root, args.generation_contract
    )
    require_detector_registration(generation_context, "AIDE")
    config = {
        "version": "0.19.3", "commit": AIDE_COMMIT,
        "policy": "p+i+n+u+g+s+m+c+sha256",
        "primary_snapshot": "after_a", "control": "before_a",
        "threshold": "any added_removed_or_changed_canonical_snapshot_file",
        "materialization": "content_delta_in_place_unchanged_files_untouched",
        "metadata_only_fpr_evaluable": False,
        "image": args.aide_image,
        "scorer_sha256": sha256(Path(__file__)),
        "materialization_adapter": {
            "algorithm": "content_delta_in_place_unchanged_files_untouched",
            "implementation_sha256": sha256(Path(__file__)),
            "metadata_replay": False,
        },
        "supersedes": "p2_detector_fpr_gen1_20260821:AIDE",
        "supersession_reason": "generation-1 delete-and-recopy changed apparatus mtime/ctime on every file",
    }
    require_detector_config(generation_context, "AIDE", config)
    require_commit(args.aide_repo, AIDE_COMMIT)
    args.output.mkdir(parents=True)
    rows = []
    for record in heldout_records(args.input_root):
        run_id, profile = record["run_id"], record["profile"]
        snapshot = args.input_root / "heldout" / profile / run_id / "state_snapshots"
        out = args.output / "runs" / run_id
        manifest = run_one(snapshot, out, args.aide_repo, args.aide_image,
                           generation_context["generation"]["detector_generation_id"])
        reports = json.loads((out / "parsed_reports.json").read_text())
        deltas = json.loads((out / "materialization_deltas.json").read_text())
        control, after = reports.get("before_control") or {}, reports.get("after_a") or {}
        control_changes = sum(int(control.get(name) or 0)
                              for name in ("added", "removed", "changed"))
        after_changes = sum(int(after.get(name) or 0)
                            for name in ("added", "removed", "changed"))
        expected_content_changes = sum(
            len(deltas.get("after_a", {}).get(name, []))
            for name in ("added", "removed", "content_changed")
        )
        reasons = []
        if manifest["status"] != "passed":
            reasons.append("tool_manifest_not_passed")
        if control.get("parse_status") != "parsed" or not control.get("no_differences") or control_changes:
            reasons.append("before_a_control_not_clean")
        if after.get("parse_status") != "parsed":
            reasons.append("after_a_report_unparsed")
        if bool(after_changes) != bool(expected_content_changes):
            reasons.append("aide_content_delta_decision_mismatch")
        status = "passed" if not reasons else "failed"
        rows.append({
            "run_id": run_id, "profile": profile,
            "branch_outcome": record["branch_outcome"], "status": status,
            "reasons": reasons,
            "native_score": {
                "before_control": control, "after_a": after,
                "after_b": reports.get("after_b"),
                "after_a_change_count": after_changes,
                "materialized_content_delta": deltas.get("after_a"),
            },
            "binary_decision": (after_changes > 0) if status == "passed" else None,
            "tool_manifest": str((out / "tool_manifest.json").resolve()),
            "tool_manifest_sha256": sha256(out / "tool_manifest.json"),
        })
    write_detector_result(args.output, "AIDE", rows, config, {
        "version": "AIDE 0.19.3",
        "command": [sys.executable, str(Path(__file__).resolve())],
    }, generation_context)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
