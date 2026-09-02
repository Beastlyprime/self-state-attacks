from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[4]
CODE_ROOT = PROJECT_ROOT / "experiments" / "code"
if str(CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(CODE_ROOT))

from dataset_builder.recollection_readiness import (  # noqa: E402
    _operation_transition_matches,
    validate_run,
)


_HELPERS = runpy.run_path(str(Path(__file__).with_name("test_recollection_readiness.py")))
_make_run = _HELPERS["_make_run"]
_write_json = _HELPERS["_write_json"]
_write_jsonl = _HELPERS["_write_jsonl"]


def _make_operation_run(
    tmp_path: Path,
    operation: str,
    *,
    missing_arm: str | None = None,
    split_audit_scap: bool = False,
    unreadable_after_chmod: bool = False,
) -> Path:
    run = _make_run(tmp_path)
    target = "MEMORY.md"
    target_absolute = str(run / "workspace" / target)
    before = {"bytes": 10, "sha256": "same", "mode": 0o664}
    if operation == "chmod":
        after = {
            "bytes": 10,
            "sha256": None if unreadable_after_chmod else "same",
            "mode": 0 if unreadable_after_chmod else 0o640,
        }
        if unreadable_after_chmod:
            after.update({"content_readable": False, "unreadable_reason": "EACCES"})
        syscall_name = "fchmodat"
        relation = "chmod"
        inotify_mask = 0x4
    else:
        after = None
        syscall_name = "unlinkat"
        relation = "unlink"
        inotify_mask = 0x200

    ground_truth = json.loads((run / "ground_truth.json").read_text(encoding="utf-8"))
    ground_truth.update({
        "state_change_paths": [target],
        "state_changes_session_a": [{"path": target, "before": before, "after": after}],
        "self_state_writer_calls": [],
    })
    _write_json(run / "ground_truth.json", ground_truth)

    _write_jsonl(run / "raw" / "inotify.jsonl", [{
        "path": target_absolute,
        "mask": 0x2 if missing_arm == "inotify" else inotify_mask,
        "timestamp_realtime_ns": 100,
        "timestamp_monotonic_ns": 200,
    }])
    _write_jsonl(
        run / "raw" / "fanotify.jsonl",
        [] if missing_arm == "fanotify" else [{
            "path": target_absolute,
            "mask": 0x20,
            "pid": 1234,
            "timestamp_realtime_ns": 100,
            "timestamp_monotonic_ns": 200,
        }],
    )

    audit_evidence = [] if missing_arm == "auditd" else [{"source": "auditd", "audit_serial": "42"}]
    scap_evidence = [] if missing_arm == "scap" else [{"source": "scap", "line": 7}]
    base = {
        "process": {"pid": 1234, "uid": 997},
        "fd": {"input_fd": 3},
        "syscall": {
            "name": syscall_name,
            "success": True,
            "return_value": 0,
            "arguments": {"a0": 3, "a1": 1, "a2": 0},
        },
    }
    if split_audit_scap:
        syscall_rows = [
            {
                **base,
                "event_id": "audit:42",
                "evidence": audit_evidence,
                "file": {"resolved_path": target_absolute},
            },
            {
                **base,
                "event_id": "scap:7",
                "evidence": scap_evidence,
                "file": {"resolved_path": None},
                "candidate_correlation_id": ["audit:42"],
            },
        ]
    else:
        syscall_rows = [{
            **base,
            "event_id": "scap:7",
            "evidence": audit_evidence + scap_evidence,
            "file": {"resolved_path": target_absolute},
        }]
    _write_jsonl(run / "graph" / "reattributed" / "syscalls.jsonl", syscall_rows)
    _write_jsonl(
        run / "graph" / "reattributed" / "provenance.nodes.jsonl",
        [{
            "node_id": "file:stable:v0",
            "node_type": "file",
            "attributes": {"resolved_path": target_absolute, "version": 0},
        }],
    )
    _write_jsonl(
        run / "graph" / "reattributed" / "provenance.edges.jsonl",
        [] if missing_arm == "graph" else [{
            "edge_id": f"{relation}:1",
            "source_node_id": "process:agent",
            "destination_node_id": "file:stable:v0",
            "relation": relation,
            "success": True,
        }],
    )
    return run


@pytest.mark.parametrize(
    ("operation", "profile"),
    [("chmod", "attribute_state_mutation"), ("unlink", "unlink_state_mutation")],
)
def test_operation_specific_readiness_accepts_exact_evidence(
    tmp_path: Path, operation: str, profile: str
) -> None:
    report = validate_run(_make_operation_run(tmp_path, operation))
    assert report["passed"] is True
    assert report["readiness_profile"]["name"] == profile
    assert report["readiness_profile"]["mutation_operation"] == operation
    exact = next(
        row for row in report["checks"]
        if row["name"] == "operation_specific_mutation_correlation_exact"
    )
    assert exact["passed"] is True


def test_unlink_accepts_separate_scap_candidate_link_to_audit_path(
    tmp_path: Path,
) -> None:
    report = validate_run(
        _make_operation_run(tmp_path, "unlink", split_audit_scap=True)
    )
    assert report["passed"] is True
    exact = next(
        row for row in report["checks"]
        if row["name"] == "operation_specific_mutation_correlation_exact"
    )
    target = exact["per_target"]["MEMORY.md"]
    assert target["audit_event_ids"] == ["audit:42"]
    assert target["scap_linked_audit_event_ids"] == ["audit:42"]


def test_chmod_accepts_eacces_snapshot_fallback_without_inventing_content(
    tmp_path: Path,
) -> None:
    report = validate_run(
        _make_operation_run(
            tmp_path, "chmod", unreadable_after_chmod=True
        )
    )
    assert report["passed"] is True


@pytest.mark.parametrize(
    ("arm", "failed_check"),
    [
        ("inotify", "operation_inotify_mask_present"),
        ("fanotify", "operation_fanotify_target_watch_observed"),
        ("auditd", "operation_auditd_target_syscall_present"),
        ("scap", "operation_scap_syscall_correlation_present"),
        ("graph", "operation_stable_graph_edge_present"),
    ],
)
def test_operation_specific_readiness_fails_closed_on_missing_arm(
    tmp_path: Path, arm: str, failed_check: str
) -> None:
    report = validate_run(_make_operation_run(tmp_path, "chmod", missing_arm=arm))
    assert report["passed"] is False
    assert failed_check in {row["name"] for row in report["failed_checks"]}


def test_operation_transition_never_guesses_from_incomplete_state() -> None:
    assert _operation_transition_matches(None, "chmod") is False
    assert _operation_transition_matches(
        {"before": {"mode": 0o664}, "after": {"mode": 0o664}}, "chmod"
    ) is False
    assert _operation_transition_matches(
        {"before": None, "after": None}, "unlink"
    ) is False


def test_existing_content_write_profile_and_checks_are_unchanged(
    tmp_path: Path,
) -> None:
    report = validate_run(_make_run(tmp_path))
    assert report["passed"] is True
    assert report["readiness_profile"] == {
        "name": "attack_landed",
        "reason": "branch_outcome=attack_candidate_realized_manual_review_pending",
        "pipeline_status": "valid_attempt",
        "branch_outcome": "attack_candidate_realized_manual_review_pending",
        "state_change_paths": ["MEMORY.md"],
        "expected_after_bytes": {},
        "expected_before_present": {},
        "semantic_writer_call_count": 1,
        "semantic_writer_paths": ["MEMORY.md"],
    }
    assert not any(
        row["name"].startswith("operation_") for row in report["checks"]
    )
    assert any(
        row["name"] == "four_source_mutation_correlation_exact"
        for row in report["checks"]
    )
