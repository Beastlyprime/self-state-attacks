from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[4]
CODE_ROOT = PROJECT_ROOT / "experiments" / "code"
if str(CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(CODE_ROOT))

from dataset_builder.canonical_matrix_audit import build_matrix_audit  # noqa: E402


def test_matrix_inventory_is_23_cells_and_43_operations() -> None:
    report = build_matrix_audit(
        observed_logical_paths=["MEMORY.md", "memory/2026-08-09.md"],
        observed_logical_path_events=[
            ("MEMORY.md", "write"),
            ("memory/2026-08-09.md", "write"),
        ],
    )
    assert report["gate"]["structural_passed"] is True
    assert report["gate"]["production_complete"] is False
    assert report["summary"]["paper_cells"] == 23
    assert report["summary"]["concrete_operations"] == 43
    assert report["summary"]["coverage_status"] == {"unbound": 43}
    assert report["summary"]["operations_with_legitimate_trace_support"] == 12
    assert {row["route_requirement"] for row in report["operations"]} == {
        "A_preferred_B_fallback",
        "B_required",
    }


def test_matrix_excludes_l3_and_accepts_admissible_l2() -> None:
    bindings = [
        {
            "attack_id": "Mem-M3-G1-MEM",
            "instance_id": "prod-1",
            "route": "B",
            "semantic_bypass_level": "L2",
            "admissible_for_provenance_analysis": True,
        },
        {
            "attack_id": "Mem-M3-G1-MSUB",
            "instance_id": "legacy-1",
            "route": "B",
            "semantic_bypass_level": "L3",
            "admissible_for_provenance_analysis": False,
        },
    ]
    report = build_matrix_audit(bindings=bindings)
    by_id = {row["attack_id"]: row for row in report["operations"]}
    assert by_id["Mem-M3-G1-MEM"]["coverage_status"] == "production_covered"
    assert by_id["Mem-M3-G1-MSUB"]["coverage_status"] == "excluded_only"
    assert report["gate"]["structural_passed"] is True


def test_matrix_rejects_invalid_route_level_binding() -> None:
    report = build_matrix_audit(bindings=[{
        "attack_id": "Cfg-M4-G1-CFG",
        "route": "B",
        "semantic_bypass_level": "L1",
        "admissible_for_provenance_analysis": True,
    }])
    assert report["gate"]["structural_passed"] is False
    assert report["summary"]["invalid_bindings"] == 1
