from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[4]
CODE_ROOT = PROJECT_ROOT / "experiments" / "code"
if str(CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(CODE_ROOT))

from dataset_builder.recollection_readiness import O_TRUNC, validate_run  # noqa: E402


_HELPERS = runpy.run_path(str(Path(__file__).with_name("test_recollection_readiness.py")))
_make_run = _HELPERS["_make_run"]
_write_json = _HELPERS["_write_json"]
_write_jsonl = _HELPERS["_write_jsonl"]


def _make_truncate_run(
    tmp_path: Path,
    *,
    syscall_name: str = "openat",
    flags: int = O_TRUNC | 0x1,
    include_ebpf: bool = True,
) -> Path:
    run = _make_run(tmp_path)
    target = "MEMORY.md"
    companion = "memory/2026-08-23.md"
    target_absolute = str(run / "workspace" / target)
    before = {"bytes": 173, "sha256": "before", "mode": 0o664}
    after = {"bytes": 0, "sha256": "after", "mode": 0o664}
    ground_truth = json.loads((run / "ground_truth.json").read_text(encoding="utf-8"))
    ground_truth.update({
        "case_id": "C1_w3_memory_truncate_wipe",
        "state_change_paths": [target, companion],
        "state_changes_session_a": [
            {"path": target, "before": before, "after": after},
            {
                "path": companion,
                "before": None,
                "after": {"bytes": 185, "sha256": "companion", "mode": 0o664},
            },
        ],
        "self_state_writer_calls": [],
    })
    _write_json(run / "ground_truth.json", ground_truth)

    _write_jsonl(run / "raw" / "inotify.jsonl", [{
        "path": target_absolute,
        "mask": 0x2,
        "timestamp_realtime_ns": 100,
        "timestamp_monotonic_ns": 200,
    }])
    _write_jsonl(run / "raw" / "fanotify.jsonl", [{
        "path": target_absolute,
        "mask": 0x20,
        "pid": 1234,
        "timestamp_realtime_ns": 100,
        "timestamp_monotonic_ns": 200,
    }])
    sources = ["auditd", "scap"] + (["ebpf"] if include_ebpf else [])
    argument_name = "a2" if syscall_name == "openat" else "a1"
    arguments = {argument_name: flags, "a0": 3}
    if syscall_name == "ftruncate":
        arguments = {"a0": 3, "a1": 0}
    _write_jsonl(run / "graph" / "reattributed" / "syscalls.jsonl", [{
        "event_id": "scap:truncate:1",
        "process": {"pid": 1234, "uid": 997},
        "fd": {"input_fd": 3},
        "file": {
            "resolved_path": target_absolute,
            "dev": "fd:01",
            "inode": 5936280,
            "identity_resolution_method": "libsinsp_fd_table",
        },
        "syscall": {
            "name": syscall_name,
            "success": True,
            "return_value": 3 if syscall_name in {"open", "openat"} else 0,
            "arguments": arguments,
        },
        "evidence": [{"source": source} for source in sources],
    }])
    _write_jsonl(
        run / "graph" / "reattributed" / "provenance.nodes.jsonl",
        [{
            "node_id": "file:boot:fd:01:5936280:v0",
            "node_type": "file",
            "attributes": {"resolved_path": target_absolute, "version": 0},
        }],
    )
    _write_jsonl(run / "graph" / "reattributed" / "provenance.edges.jsonl", [])
    return run


def test_truncate_profile_accepts_openat_o_trunc_without_write_edge(tmp_path: Path) -> None:
    report = validate_run(_make_truncate_run(tmp_path))
    assert report["passed"] is True
    assert report["readiness_profile"]["name"] == "truncate_state_mutation"
    assert report["readiness_profile"]["mutation_operation"] == "truncate"
    assert report["readiness_profile"]["operation_target_paths"] == ["MEMORY.md"]
    exact = next(
        row for row in report["checks"]
        if row["name"] == "operation_specific_mutation_correlation_exact"
    )
    assert exact["passed"] is True
    assert exact["per_target"]["MEMORY.md"]["operation_edges"] == []


def test_truncate_profile_accepts_target_resolved_ftruncate(tmp_path: Path) -> None:
    report = validate_run(_make_truncate_run(tmp_path, syscall_name="ftruncate"))
    assert report["passed"] is True


def test_truncate_profile_rejects_open_without_o_trunc(tmp_path: Path) -> None:
    report = validate_run(_make_truncate_run(tmp_path, flags=0x1))
    assert report["passed"] is False
    assert "operation_auditd_target_syscall_present" in {
        row["name"] for row in report["failed_checks"]
    }


def test_truncate_profile_rejects_missing_ebpf_arm(tmp_path: Path) -> None:
    report = validate_run(_make_truncate_run(tmp_path, include_ebpf=False))
    assert report["passed"] is False
    assert "operation_ebpf_syscall_correlation_present" in {
        row["name"] for row in report["failed_checks"]
    }


def test_unregistered_size_shrink_does_not_select_truncate(tmp_path: Path) -> None:
    run = _make_truncate_run(tmp_path)
    ground_truth = json.loads((run / "ground_truth.json").read_text(encoding="utf-8"))
    ground_truth["case_id"] = "unregistered_content_write"
    _write_json(run / "ground_truth.json", ground_truth)
    report = validate_run(run)
    assert report["readiness_profile"].get("mutation_operation") is None
    assert report["readiness_profile"]["name"] == "attack_landed"
