"""Five-source readiness gates: SCAP + provenance-graph additions.

These exercise only the additions layered on top of the four-source contract:
that they fire when a SCAP capture is present, read the acceptance-line verdict
from the graph bridge, and stay absent on four-source runs (backward compat).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

CODE_ROOT = Path(__file__).resolve().parents[2]
if str(CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(CODE_ROOT))

from dataset_builder import recollection_readiness as r  # noqa: E402


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _make_five_source_run(tmp_path: Path, *, acceptance_passed: bool, rate: float) -> Path:
    run_dir = tmp_path / "run"
    (run_dir / "raw").mkdir(parents=True)
    (run_dir / "raw" / "capture.scap").write_bytes(b"\x00scap-nonempty")
    (run_dir / "raw" / "ebpf_lifecycle.jsonl").write_text('{"e":1}\n', encoding="utf-8")
    _write(run_dir / "scap.stop.json", {"valid": True, "drop_count": 0, "event_count": 4854})
    _write(run_dir / "five_source_graph_bridge.json", {
        "schema_version": "assa.five_source_graph_bridge.v2",
        "file_identity_source": "libsinsp",
        "coverage_post_reattribution": {
            "coverage_view": "raw_all_evidence_rows",
            "provenance_evaluable": acceptance_passed,
            "fd_path_resolved_rate": rate,
        },
        "coverage_resolution_spine_effective": {
            "provenance_evaluable": acceptance_passed,
        },
        "coverage_resolution_spine": {"writes_excluded": 0},
        "acceptance_line": {"threshold": 0.95, "passed": acceptance_passed},
    })
    _write(run_dir / "graph/reattributed/resolution_spine_effective/coverage.json", {
        "coverage_view": "resolution_spine_effective",
        "provenance_evaluable": acceptance_passed,
        "writes_excluded": 0,
    })
    return run_dir


def _five_source_check_names() -> set[str]:
    return {
        "scap_capture_present_and_valid",
        "ebpf_lifecycle_present",
        "provenance_graph_bridge_ran",
        "provenance_graph_evaluable",
        "fd_path_resolved_rate_acceptance_line",
        "file_identity_from_libsinsp",
        "raw_effective_coverage_reconciled",
    }


def test_five_source_gates_pass_when_acceptance_line_cleared(tmp_path):
    run_dir = _make_five_source_run(tmp_path, acceptance_passed=True, rate=0.9899)
    checks: list[dict] = []
    r._validate_five_source(run_dir, checks)
    by_name = {c["name"]: c for c in checks}
    assert _five_source_check_names() <= set(by_name)
    assert all(by_name[name]["passed"] for name in _five_source_check_names())
    assert r._is_five_source_run(run_dir) is True


def test_five_source_gates_fail_when_below_acceptance_line(tmp_path):
    run_dir = _make_five_source_run(tmp_path, acceptance_passed=False, rate=0.9351)
    checks: list[dict] = []
    r._validate_five_source(run_dir, checks)
    by_name = {c["name"]: c for c in checks}
    # capture present and libsinsp identity still hold; the acceptance line does not.
    assert by_name["scap_capture_present_and_valid"]["passed"] is True
    assert by_name["file_identity_from_libsinsp"]["passed"] is True
    assert by_name["provenance_graph_evaluable"]["passed"] is False
    assert by_name["fd_path_resolved_rate_acceptance_line"]["passed"] is False


def test_missing_bridge_fails_graph_gate_but_not_capture(tmp_path):
    run_dir = _make_five_source_run(tmp_path, acceptance_passed=True, rate=0.99)
    (run_dir / "five_source_graph_bridge.json").unlink()
    checks: list[dict] = []
    r._validate_five_source(run_dir, checks)
    by_name = {c["name"]: c for c in checks}
    assert by_name["scap_capture_present_and_valid"]["passed"] is True
    assert by_name["provenance_graph_bridge_ran"]["passed"] is False
    assert by_name["provenance_graph_evaluable"]["passed"] is False


def test_missing_effective_coverage_fails_reconciliation_gate(tmp_path):
    run_dir = _make_five_source_run(tmp_path, acceptance_passed=True, rate=0.99)
    effective = run_dir / "graph/reattributed/resolution_spine_effective/coverage.json"
    effective.unlink()
    checks: list[dict] = []
    r._validate_five_source(run_dir, checks)
    by_name = {c["name"]: c for c in checks}
    assert by_name["provenance_graph_evaluable"]["passed"] is True
    assert by_name["raw_effective_coverage_reconciled"]["passed"] is False
    assert by_name["raw_effective_coverage_reconciled"]["artifact"] == str(effective)


def test_overlay_bridge_is_used_without_mutating_source_run(tmp_path):
    run_dir = _make_five_source_run(tmp_path, acceptance_passed=True, rate=0.99)
    overlay = tmp_path / "derived" / "run"
    overlay_effective = (
        overlay / "graph/reattributed/resolution_spine_effective/coverage.json"
    )
    overlay_effective.parent.mkdir(parents=True)
    (run_dir / "five_source_graph_bridge.json").replace(
        overlay / "five_source_graph_bridge.json"
    )
    source_effective = (
        run_dir / "graph/reattributed/resolution_spine_effective/coverage.json"
    )
    source_effective.replace(overlay_effective)
    assert not (run_dir / "five_source_graph_bridge.json").exists()
    checks: list[dict] = []
    r._validate_five_source(
        run_dir, checks,
        bridge_path=overlay / "five_source_graph_bridge.json",
        effective_path=overlay_effective,
    )
    by_name = {c["name"]: c for c in checks}
    assert by_name["raw_effective_coverage_reconciled"]["passed"] is True


def test_four_source_run_gets_no_five_source_gates(tmp_path):
    run_dir = tmp_path / "run4"
    (run_dir / "raw").mkdir(parents=True)  # no capture.scap
    assert r._is_five_source_run(run_dir) is False
    checks: list[dict] = []
    # validate_run must not add any five-source check for a four-source run.
    report = r.validate_run(run_dir)
    names = {c["name"] for c in report["checks"]}
    assert not (_five_source_check_names() & names)
    assert report["five_source_run"] is False
