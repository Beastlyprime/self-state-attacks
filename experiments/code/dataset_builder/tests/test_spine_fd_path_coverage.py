"""Resolution-spine fd->path coverage in the five-source graph bridge.

The acceptance line must be measured on the SCAP/merged resolution spine, not on
a denominator that double-counts audit read observations of SCAP-resolved reads.
Writes are never excluded (a self-state write is the detection target).
"""
from __future__ import annotations

import sys
from pathlib import Path

CODE_ROOT = Path(__file__).resolve().parents[2]
for p in (str(CODE_ROOT), str(CODE_ROOT / "measurement")):
    if p not in sys.path:
        sys.path.insert(0, p)

from argparse import Namespace

import pytest

from dataset_builder.five_source_graph_bridge import (
    _derive_run_params,
    _resolution_spine_coverage_view,
    _spine_fd_path_coverage,
)


def _op(event_id, name, fd, inode=None, corr=None, socket=None):
    row = {
        "event_id": event_id,
        "syscall": {"name": name, "success": True, "return_value": 1},
        "fd": {"input_fd": fd},
        "file": {"inode": inode, "dev": "fd:01"} if inode else {},
        "process": {
            "boot_id": "boot", "pid": 100, "tid": 100, "ppid": 1,
            "identity_key": "boot:100:start:0", "identity_status": "complete",
        },
        "order": {"merged": int(event_id.rsplit(":", 1)[-1])},
        "evidence": [],
        "completeness": {
            "process_identity": "complete", "path": "complete" if inode else "unresolved",
            "socket": "not_applicable",
        },
    }
    if corr:
        row["correlation"] = {"status": corr}
    if socket is not None:
        row["socket"] = socket
        row["completeness"]["socket"] = "identity_incomplete"
    return row


def test_pure_audit_reads_excluded_writes_kept():
    rows = [
        _op("r:scap:1", "read", 3, inode=5031),        # spine, resolved
        _op("r:scap:2", "read", 3),                    # spine, unresolved
        _op("r:audit:1", "read", 3),                   # pure-audit read -> excluded
        _op("r:audit:2", "read", 3),                   # pure-audit read -> excluded
        _op("r:audit:3", "write", 9),                  # pure-audit WRITE -> kept (fail-safe)
        _op("r:audit:4", "read", 4, inode=7001, corr="matched"),  # merged -> spine
        _op("r:scap:5", "read", 5, inode=1, socket={"family": "x"}),  # socket -> not operand
    ]
    cov = _spine_fd_path_coverage(rows)
    assert cov["all_operand_denominator"] == 6
    assert cov["spine_operand_denominator"] == 4          # scap1, scap2, write, merged4
    assert cov["spine_operand_numerator"] == 2            # scap1, merged4
    assert cov["pure_audit_read_duplicates_excluded"] == 2
    assert cov["writes_excluded"] == 0
    assert cov["excluded_event_ids"] == ["r:audit:1", "r:audit:2"]


def test_complete_spine_rate_is_one_when_all_spine_resolved():
    rows = [_op(f"r:scap:{i}", "read", 3, inode=100 + i) for i in range(10)]
    rows += [_op(f"r:audit:{i}", "read", 3) for i in range(5)]  # pure-audit dilution
    cov = _spine_fd_path_coverage(rows)
    assert cov["fd_path_resolved_rate_spine"] == 1.0
    assert round(cov["fd_path_resolved_rate_all_operands"], 4) == round(10 / 15, 4)
    assert cov["pure_audit_read_duplicates_excluded"] == 5


def test_unmatched_audit_write_stays_and_can_fail_the_line():
    # a pure-audit unresolved WRITE must remain in the denominator, never excluded.
    rows = [_op("r:scap:1", "read", 3, inode=1),
            _op("w:audit:1", "write", 7)]  # pure-audit, unresolved write
    cov = _spine_fd_path_coverage(rows)
    assert cov["spine_operand_denominator"] == 2
    assert cov["fd_path_resolved_rate_spine"] == 0.5
    assert cov["writes_excluded"] == 0


def test_effective_view_rebuilds_nodes_but_keeps_writes_and_socket_unknown():
    rows = [
        _op("r:scap:1", "read", 3, inode=101),
        _op("r:audit:2", "read", 3),
        _op("r:audit:3", "write", 4, inode=202),
        _op("r:scap:4", "connect", 5, socket={"family": None}),
    ]
    view = _resolution_spine_coverage_view(rows, "run")
    assert [row["event_id"] for row in view["rows"]] == [
        "r:scap:1", "r:audit:3", "r:scap:4",
    ]
    assert view["spine"]["writes_excluded"] == 0
    assert view["coverage"]["provenance_evaluable"] is True
    assert view["coverage"]["coverage_view"] == "resolution_spine_effective"
    assert view["coverage"]["excluded_pure_audit_read_duplicates"] == 1
    assert any(
        node["node_type"] == "socket_unknown" for node in view["graph"]["nodes"]
    )



def _args(**overrides):
    values = {
        "run_id": None,
        "boot_id": "boot-test",
        "runner_uid": None,
        "cgroup_id": None,
        "cgroup_path": None,
    }
    values.update(overrides)
    return Namespace(**values)


def test_runner_uid_derives_from_safety_attestation(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    (run / "run_safety_attestation.json").write_text(
        '{"agent_identity":{"uid":997,"cgroup_id":123,"cgroup_path":"/sys/fs/cgroup/oc"}}\n',
        encoding="utf-8",
    )
    params = _derive_run_params(run, _args())
    assert params["runner_uid"] == 997
    assert params["cgroup_id"] == 123
    assert params["cgroup_path"] == "/sys/fs/cgroup/oc"


def test_runner_uid_missing_fails_closed(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    with pytest.raises(SystemExit, match="runner uid not found"):
        _derive_run_params(run, _args())
