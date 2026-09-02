#!/usr/bin/env python3
"""Assemble the frozen P2 held-out-clean FPR report without rescoring."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any

from .generation_contract import (
    generation_stamp,
    validate_exported_inventory,
    validate_result_payload,
)


PROFILES = ("W1", "W2", "W3", "W4")
OUTCOMES = ("natural_write", "clean_no_write")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def pct(value: float | None) -> str:
    return "NA" if value is None else f"{100 * value:.1f}%"


def interval(cell: dict[str, Any]) -> str:
    if cell.get("rate") is None:
        return "NA"
    return f"{pct(cell['rate'])} [{pct(cell['lower'])}, {pct(cell['upper'])}]"


def wilson(k: int, n: int, z: float = 1.959963984540054) -> dict[str, Any]:
    if n == 0:
        return {"positive": k, "n": n, "rate": None, "lower": None, "upper": None}
    p = k / n
    denominator = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denominator
    half = z * math.sqrt((p * (1 - p) + z * z / (4 * n)) / n) / denominator
    return {"positive": k, "n": n, "rate": p,
            "lower": max(0.0, center - half), "upper": min(1.0, center + half)}


def expected_cell(rows: list[dict[str, Any]]) -> dict[str, Any]:
    evaluable = [row for row in rows if row["status"] == "passed"]
    cell = wilson(sum(row["binary_decision"] is True for row in evaluable), len(evaluable))
    return {**cell, "registered": len(rows),
            "data_insufficient": sum(row["status"] == "data_insufficient" for row in rows),
            "failed": sum(row["status"] == "failed" for row in rows)}


def validate_summary(path: Path, result: dict[str, Any]) -> None:
    rows, summary = result["rows"], result["summary"]
    expected = {
        "pooled_primary": expected_cell(rows),
        "by_profile_descriptive_underpowered": {
            profile: expected_cell([row for row in rows if row["profile"] == profile])
            for profile in PROFILES
        },
        "by_clean_outcome": {
            outcome: expected_cell([row for row in rows if row["branch_outcome"] == outcome])
            for outcome in OUTCOMES
        },
    }
    for section, value in expected.items():
        observed = summary.get(section)
        if section == "pooled_primary":
            if observed != value:
                raise RuntimeError(f"{path}: pooled summary does not reconcile with rows")
            continue
        for key, cell in value.items():
            if observed.get(key) != cell:
                raise RuntimeError(f"{path}: {section}/{key} does not reconcile with rows")


def validate_result(path: Path, result: dict[str, Any], expected_count: int) -> set[str]:
    rows = result.get("rows") or []
    run_ids = [row.get("run_id") for row in rows]
    if len(rows) != expected_count or len(set(run_ids)) != expected_count or None in run_ids:
        raise RuntimeError(
            f"{path}: expected exactly {expected_count} unique held-out rows"
        )
    if result.get("scope") != "heldout_clean_FPR_only":
        raise RuntimeError(f"{path}: non-clean scope {result.get('scope')!r}")
    for row in rows:
        if row.get("profile") not in PROFILES:
            raise RuntimeError(f"{path}: unknown profile in {row}")
        if row.get("branch_outcome") not in OUTCOMES:
            raise RuntimeError(f"{path}: non-clean outcome in {row}")
        if row.get("status") != "passed" and row.get("binary_decision") is not None:
            raise RuntimeError(f"{path}: non-evaluable row has a binary decision")
    return set(run_ids)


def detector_entry(path: Path, generation_context: dict[str, Any]) -> dict[str, Any]:
    result = read_json(path)
    validate_result_payload(result, generation_context, where=str(path))
    run_ids = validate_result(path, result, generation_context["heldout_count"])
    validate_summary(path, result)
    rows = result["rows"]
    command = result.get("command") or result.get("command_template")
    if command is None and result.get("detector") == "UNICORN":
        command = {
            "per_graph_parser_and_analyzer":
                "rows[*].native_score.graph_execution.{parser_command,analyzer_command}",
            "profile_modeler": "rows[status=passed].command",
        }
    return {
        "detector": result["detector"],
        **generation_stamp(generation_context["contract"]),
        "result_path": str(path.resolve()),
        "result_sha256": sha256(path),
        "version": result.get("version"),
        "command": command,
        "config": result.get("config"),
        "config_sha256": result.get("config_sha256"),
        "summary": result.get("summary"),
        "registered_run_ids": sorted(run_ids),
        "rows": rows,
    }


def markdown(report: dict[str, Any]) -> str:
    heldout_count = report["heldout_registered"]
    profile_counts = report["heldout_by_profile"]
    lines = [
        "# P2 Four-Detector Held-Out Clean FPR Report",
        "",
        "This report is a read-only aggregation of detector-native outputs over the",
        "held-out clean corpus frozen before scoring. The pooled corpus-level FPR",
        f"(n={heldout_count}) is primary. Per-profile counts are "
        f"{profile_counts}; estimates are descriptive and",
        "underpowered; their wide Wilson intervals are reported without stronger claims.",
        "No attack run appears in this report, and the held-out set must not be expanded",
        "after these scores were observed.",
        "",
        "## Primary results",
        "",
        "| Detector | Evaluable / registered | False positives | Pooled FPR (95% Wilson CI) | Natural-write FPR | Clean-no-write FPR |",
        "|---|---:|---:|---|---|---|",
    ]
    for entry in report["detectors"]:
        summary = entry["summary"]
        pooled = summary["pooled_primary"]
        natural = summary["by_clean_outcome"]["natural_write"]
        no_write = summary["by_clean_outcome"]["clean_no_write"]
        lines.append(
            f"| {entry['detector']} | {pooled['n']} / {pooled['registered']} | "
            f"{pooled['positive']} | {interval(pooled)} | {interval(natural)} | "
            f"{interval(no_write)} |"
        )
    lines.extend(["", "## Descriptive per-profile results", ""])
    for entry in report["detectors"]:
        lines.extend([
            f"### {entry['detector']}",
            "",
            "| Profile | Evaluable / registered | False positives | FPR (95% Wilson CI) | Status |",
            "|---|---:|---:|---|---|",
        ])
        for profile in PROFILES:
            cell = entry["summary"]["by_profile_descriptive_underpowered"][profile]
            lines.append(
                f"| {profile} | {cell['n']} / {cell['registered']} | {cell['positive']} | "
                f"{interval(cell)} | descriptive / underpowered |"
            )
        lines.append("")
    lines.extend([
        "## Detector provenance and native decisions",
        "",
        "Each referenced result JSON records the exact command (or command template),",
        "tool version, frozen configuration and its hash, native score, exit status,",
        "and per-run binary decision. Rows with no usable native result remain",
        "`data_insufficient`; they are not counted as negatives.",
        "",
    ])
    for entry in report["detectors"]:
        lines.extend([
            f"- **{entry['detector']}**: generation "
            f"`{entry['detector_generation_id']}`, config",
            f"  `{entry['config_sha256']}`, result `{entry['result_sha256']}`.",
        ])
    lines.extend([
        "",
        "## Superseded attempts and boundaries",
        "",
        "- AIDE generation 1 is superseded because delete-and-recopy changed apparatus",
        "  mtime/ctime on every file. Generation 2 uses byte-delta materialization and",
        "  does not infer metadata-only FPR from side-channel snapshots.",
        "- UNICORN generation 1 attempts are execution failures, not negative decisions:",
        "  one had a pre-score volume-path error and one exposed GraphChi assertion",
        "  failures. Generation 2 gives each graph one attempt and marks a failed graph",
        "  `data_insufficient` without retrying it to success.",
        "- STIDE is the preregistered bounded, not-saturated-under-budget model. Its held-out",
        "  false positives are an honest consequence of that frozen condition, not a",
        "  post-score implementation adjustment.",
        "- TPR and attack-event detection are outside this artifact and remain blocked on",
        "  the separately collected, human-confirmed attack-landed corpus.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--aide", type=Path, required=True)
    parser.add_argument("--falco", type=Path, required=True)
    parser.add_argument("--stide", type=Path, required=True)
    parser.add_argument("--unicorn", type=Path, required=True)
    parser.add_argument("--heldout-freeze", type=Path, required=True)
    parser.add_argument("--preregistration", type=Path, required=True)
    parser.add_argument("--input-root", type=Path, required=True)
    parser.add_argument("--generation-contract", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--output-md", type=Path, required=True)
    args = parser.parse_args()

    generation_context = validate_exported_inventory(
        args.input_root, args.generation_contract
    )
    entries = [
        detector_entry(path, generation_context)
        for path in (args.aide, args.falco, args.stide, args.unicorn)
    ]
    membership = [set(entry["registered_run_ids"]) for entry in entries]
    if any(item != membership[0] for item in membership[1:]):
        raise RuntimeError("detector held-out memberships differ")
    frozen = read_json(args.heldout_freeze)
    frozen_ids = {row["run_id"] for row in frozen["records"]}
    if membership[0] != frozen_ids:
        raise RuntimeError("scored membership differs from held-out freeze")
    if sha256(args.heldout_freeze) != generation_context["contract"]["heldout_freeze_sha256"]:
        raise RuntimeError("held-out freeze differs from generation contract")

    report = {
        "schema_version": "assa.p2_four_detector_clean_fpr_report.v2",
        **generation_stamp(generation_context["contract"]),
        "generation_contract_path": generation_context["contract_path"],
        "generation_contract_sha256": generation_context["contract_sha256"],
        "input_inventory_path": generation_context["inventory_path"],
        "input_inventory_sha256": generation_context["inventory_sha256"],
        "scope": "heldout_clean_FPR_only",
        "heldout_locked_before_scoring": True,
        "heldout_post_score_expansion_forbidden": True,
        "heldout_registered": generation_context["heldout_count"],
        "heldout_by_profile": {
            profile: sum(
                row["profile"] == profile
                for row in generation_context["inventory"]["records"]
                if row["role"] == "heldout"
            )
            for profile in PROFILES
        },
        "pooled_corpus_level_FPR_is_primary": True,
        "per_profile_FPR_is_descriptive_underpowered": True,
        "confidence_interval": "Wilson score 95%",
        "heldout_freeze": {
            "path": str(args.heldout_freeze.resolve()),
            "sha256": sha256(args.heldout_freeze),
        },
        "preregistration": {
            "path": str(args.preregistration.resolve()),
            "sha256": sha256(args.preregistration),
        },
        "detectors": entries,
        "attack_side_status": "not_scored_waiting_for_stageg_attack_landed_and_human_polarity",
        "attack_collection_started_on_guest": False,
        "superseded": [
            {"detector": "AIDE", "generation": 1,
             "reason": "apparatus_delete_recopy_metadata_artifact"},
            {"detector": "UNICORN", "generation": 1, "attempt": 1,
             "reason": "pre_score_relative_output_volume_error"},
            {"detector": "UNICORN", "generation": 1, "attempt": 2,
             "reason": "official_graphchi_assertion_for_some_graphs_whole_batch_aborted"},
        ],
    }
    write_json(args.output_json, report)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.write_text(markdown(report), encoding="utf-8")
    checksum_path = args.output_json.parent / "P2_FOUR_DETECTOR_CLEAN_FPR_REPORT_SHA256SUMS.txt"
    checksum_path.write_text(
        f"{sha256(args.output_json)}  {args.output_json.name}\n"
        f"{sha256(args.output_md)}  {args.output_md.resolve()}\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "output_json": str(args.output_json), "output_json_sha256": sha256(args.output_json),
        "output_md": str(args.output_md), "output_md_sha256": sha256(args.output_md),
        "checksum": str(checksum_path), "checksum_sha256": sha256(checksum_path),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
