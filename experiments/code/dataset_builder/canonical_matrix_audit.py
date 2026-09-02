#!/usr/bin/env python3
"""Build and audit the 23-cell / 43-operation canonical matrix."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# Runnable straight from a checkout: put the code tree on the path so `attacks`
# and `workload` resolve without an ambient PYTHONPATH.
_CODE_ROOT = str(Path(__file__).resolve().parents[1])
if _CODE_ROOT not in sys.path:
    sys.path.insert(0, _CODE_ROOT)

from attacks.canonical_v4 import (  # noqa: E402
    CANONICAL_ATTACKS,
    EXPECTED_ATTACK_ENTRY_COUNT,
    EXPECTED_PAPER_CELL_COUNT,
    paper_cell_id,
    validate_canonical_suite,
)
from workload import taxonomy as tax  # noqa: E402


def _target_selector(target_file: str) -> str:
    if target_file.startswith("workspace/memory/") and target_file.endswith(".md"):
        return "workspace/memory/*.md"
    return target_file


def _route_requirement(mechanism: str) -> str:
    return "A_preferred_B_fallback" if mechanism in {"M1", "M2"} else "B_required"


def _required_trace_event(mechanism: str) -> str:
    return {"M1": "write", "M2": "write", "M3": "delete", "M4": "attrib"}[mechanism]


def _load_bindings(paths: Iterable[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".jsonl":
            values = [json.loads(line) for line in text.splitlines() if line.strip()]
        else:
            value = json.loads(text)
            if isinstance(value, list):
                values = value
            elif isinstance(value, dict):
                values = value.get("matrix_route_coverage") or value.get("instances") or value.get("bindings") or [value]
            else:
                raise ValueError(f"unsupported binding container in {path}")
        for value in values:
            if isinstance(value, dict):
                row = dict(value)
                row["_binding_source"] = str(path)
                rows.append(row)
    return rows


def _binding_status(binding: dict[str, Any]) -> tuple[str, list[str]]:
    route = binding.get("route")
    level = binding.get("semantic_bypass_level")
    reasons: list[str] = []
    if route == "not_realizable" or binding.get("label") == "not_realizable":
        return "documented_not_realizable", reasons
    if level == "L3" or binding.get("admissible_for_provenance_analysis") is False:
        return "excluded_legacy_or_inadmissible", reasons
    if route == "L0" or level == "L0":
        return "production_covered", reasons
    if route == "A":
        if level != "L1":
            reasons.append("route_A_requires_L1")
        return ("production_covered" if not reasons else "invalid_binding"), reasons
    if route == "B":
        if level != "L2":
            reasons.append("route_B_requires_L2")
        if binding.get("admissible_for_provenance_analysis") is not True:
            reasons.append("route_B_L2_requires_provenance_admissible_true")
        return ("production_covered" if not reasons else "invalid_binding"), reasons
    reasons.append("route_must_be_L0_A_B_or_not_realizable")
    return "invalid_binding", reasons


def _observed_support(qa_report: Path | None) -> tuple[set[str], set[tuple[str, str]]]:
    if qa_report is None:
        return set(), set()
    value = json.loads(qa_report.read_text(encoding="utf-8"))
    summary = value.get("summary") or {}
    paths = set(summary.get("observed_logical_paths") or [])
    pairs = {
        (row["logical_path"], row["event"])
        for row in summary.get("observed_logical_path_events") or []
        if isinstance(row, dict)
        and isinstance(row.get("logical_path"), str)
        and isinstance(row.get("event"), str)
    }
    return paths, pairs


def build_matrix_audit(
    *,
    bindings: Iterable[dict[str, Any]] = (),
    observed_logical_paths: Iterable[str] = (),
    observed_logical_path_events: Iterable[tuple[str, str]] = (),
) -> dict[str, Any]:
    validate_canonical_suite()
    observed = {
        _target_selector(tax.canonical_path(path) or path)
        for path in observed_logical_paths
        if isinstance(path, str) and path
    }
    observed_events = {
        (_target_selector(tax.canonical_path(path) or path), event)
        for path, event in observed_logical_path_events
    }
    bindings_by_attack: dict[str, list[dict[str, Any]]] = defaultdict(list)
    orphan_bindings: list[dict[str, Any]] = []
    for binding in bindings:
        attack_id = binding.get("attack_id")
        if attack_id in CANONICAL_ATTACKS:
            bindings_by_attack[str(attack_id)].append(binding)
        else:
            orphan_bindings.append({
                "attack_id": attack_id,
                "cell_id": binding.get("cell_id"),
                "binding_source": binding.get("_binding_source"),
                "reason": "unknown_or_missing_concrete_attack_id",
            })

    operations = []
    binding_issues: list[dict[str, Any]] = []
    for attack_id in sorted(CANONICAL_ATTACKS):
        cell = CANONICAL_ATTACKS[attack_id]
        selector = _target_selector(cell.target_file)
        required_event = _required_trace_event(cell.mechanism)
        rows = []
        for binding in bindings_by_attack.get(attack_id, []):
            status, reasons = _binding_status(binding)
            declared_target = binding.get("target_file") or binding.get("state_object")
            if isinstance(declared_target, str):
                declared_selector = _target_selector(declared_target)
                if not (declared_selector == selector or declared_target.endswith(cell.target_file)):
                    reasons.append("target_file_mismatch")
                    status = "invalid_binding"
            for field, expected in (("mechanism", cell.mechanism), ("granularity", cell.granularity), ("op_type", cell.op_type)):
                if binding.get(field) is not None and binding.get(field) != expected:
                    reasons.append(f"{field}_mismatch")
                    status = "invalid_binding"
            row = {
                "instance_id": binding.get("instance_id") or binding.get("run_id"),
                "route": binding.get("route"),
                "semantic_bypass_level": binding.get("semantic_bypass_level"),
                "admissible_for_provenance_analysis": binding.get("admissible_for_provenance_analysis"),
                "status": status,
                "reasons": sorted(set(reasons)),
                "binding_source": binding.get("_binding_source"),
            }
            rows.append(row)
            if status == "invalid_binding":
                binding_issues.append({"attack_id": attack_id, **row})
        statuses = Counter(row["status"] for row in rows)
        if statuses["production_covered"]:
            coverage_status = "production_covered"
        elif statuses["documented_not_realizable"]:
            coverage_status = "documented_not_realizable"
        elif statuses["invalid_binding"]:
            coverage_status = "invalid_binding"
        elif statuses["excluded_legacy_or_inadmissible"]:
            coverage_status = "excluded_only"
        else:
            coverage_status = "unbound"
        operations.append({
            "attack_id": attack_id,
            "paper_cell_id": paper_cell_id(cell),
            "target_class": cell.target,
            "mechanism": cell.mechanism,
            "granularity": cell.granularity,
            "target_file": cell.target_file,
            "target_selector": selector,
            "op_type": cell.op_type,
            "description": cell.description,
            "legacy_source": cell.legacy_source,
            "route_requirement": _route_requirement(cell.mechanism),
            "required_trace_event": required_event,
            "legitimate_trace_support_observed": (
                (selector, required_event) in observed_events
                if observed_events
                else selector in observed or cell.target_file in observed
            ),
            "coverage_status": coverage_status,
            "bindings": rows,
        })

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for operation in operations:
        grouped[operation["paper_cell_id"]].append(operation)
    paper_cells = []
    for cell_id, entries in sorted(grouped.items()):
        statuses = Counter(entry["coverage_status"] for entry in entries)
        paper_cells.append({
            "paper_cell_id": cell_id,
            "target_class": entries[0]["target_class"],
            "mechanism": entries[0]["mechanism"],
            "granularity": entries[0]["granularity"],
            "route_requirement": entries[0]["route_requirement"],
            "operation_count": len(entries),
            "attack_ids": [entry["attack_id"] for entry in entries],
            "production_covered_operations": statuses["production_covered"],
            "documented_not_realizable_operations": statuses["documented_not_realizable"],
            "unresolved_operations": sum(statuses[key] for key in ("unbound", "excluded_only", "invalid_binding")),
            "fully_resolved": all(entry["coverage_status"] in {"production_covered", "documented_not_realizable"} for entry in entries),
        })

    coverage = Counter(operation["coverage_status"] for operation in operations)
    summary = {
        "paper_cells": len(paper_cells),
        "concrete_operations": len(operations),
        "counts_by_target": dict(sorted(Counter(operation["target_class"] for operation in operations).items())),
        "counts_by_mechanism": dict(sorted(Counter(operation["mechanism"] for operation in operations).items())),
        "counts_by_granularity": dict(sorted(Counter(operation["granularity"] for operation in operations).items())),
        "route_requirements": dict(sorted(Counter(operation["route_requirement"] for operation in operations).items())),
        "coverage_status": dict(sorted(coverage.items())),
        "fully_resolved_paper_cells": sum(cell["fully_resolved"] for cell in paper_cells),
        "operations_with_legitimate_trace_support": sum(operation["legitimate_trace_support_observed"] for operation in operations),
        "orphan_bindings": len(orphan_bindings),
        "invalid_bindings": len(binding_issues),
    }
    structural_passed = (
        len(paper_cells) == EXPECTED_PAPER_CELL_COUNT
        and len(operations) == EXPECTED_ATTACK_ENTRY_COUNT
        and not orphan_bindings
        and not binding_issues
    )
    production_complete = all(cell["fully_resolved"] for cell in paper_cells)
    return {
        "schema_version": "assa.canonical_matrix_audit.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "gate": {
            "structural_passed": structural_passed,
            "production_complete": production_complete,
            "structural_definition": "exactly 23 paper cells and 43 concrete operations, with no orphan or invalid explicit bindings",
            "production_definition": "every concrete operation has an admissible L0/L1/L2 binding or an explicit not_realizable record",
        },
        "summary": summary,
        "paper_cells": paper_cells,
        "operations": operations,
        "orphan_bindings": orphan_bindings,
        "binding_issues": binding_issues,
    }


def _write_csv(path: Path, operations: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "attack_id", "paper_cell_id", "target_class", "mechanism", "granularity",
        "target_file", "target_selector", "op_type", "route_requirement", "required_trace_event",
        "legitimate_trace_support_observed", "coverage_status", "description",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for operation in operations:
            writer.writerow({field: operation.get(field) for field in fields})


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit the canonical 23-cell / 43-operation matrix")
    parser.add_argument("--bindings", action="append", type=Path, default=[], help="Explicit L0/L1/L2 binding JSON/JSONL; repeatable")
    parser.add_argument("--qa-report", type=Path, help="Optional dataset_qa.v1 report for legitimate trace support")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--csv", type=Path)
    parser.add_argument("--require-production-complete", action="store_true")
    args = parser.parse_args()
    observed_paths, observed_path_events = _observed_support(args.qa_report)
    report = build_matrix_audit(
        bindings=_load_bindings(args.bindings),
        observed_logical_paths=observed_paths,
        observed_logical_path_events=observed_path_events,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.csv:
        _write_csv(args.csv, report["operations"])
    print(json.dumps({"output": str(args.output), "csv": str(args.csv) if args.csv else None, "gate": report["gate"], "summary": report["summary"]}, indent=2, sort_keys=True))
    if not report["gate"]["structural_passed"]:
        return 1
    return 1 if args.require_production_complete and not report["gate"]["production_complete"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
