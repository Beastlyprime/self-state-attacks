from __future__ import annotations

import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[4]
CODE_ROOT = PROJECT_ROOT / "experiments" / "code"
if str(CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(CODE_ROOT))

from dataset_builder.recollection_readiness import validate_run  # noqa: E402


SOURCES = ("inotify", "fanotify", "auditd", "ebpf")


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def _event(source: str, *, correlation_id: str = "cid-1") -> dict:
    row = {
        "schema_version": "assa.trace_event.v1",
        "source": source,
        "run_id": "case__poisoned",
        "event": "write",
        "timestamp_realtime_ns": 100,
        "timestamp_monotonic_ns": 200,
        "logical_path": "MEMORY.md",
        "correlation_id": correlation_id,
        "mutation": {
            "preimage": {"bytes": 1, "sha256": "pre", "data": "cA==", "complete": True},
            "postimage": {"bytes": 2, "sha256": "post", "data": "cG8=", "complete": True},
        },
    }
    if source == "auditd":
        row.update({
            "syscall_name": "write",
            "syscall_number": 1,
            "syscall_pid": 1234,
            "syscall_fd": 3,
            "syscall_exit": 2,
            "syscall_byte_count": 2,
            "syscall_arguments": {"a0": 3, "a1": 123, "a2": 2},
        })
    if source == "ebpf":
        row["attribution_method"] = "buffer_prefix_semantic_tool_write_match"
        row["mutation"]["write_buffer"] = {
            "buffer_prefix_capacity_bytes": 16_384,
            "buffer_prefix_captured_bytes": 2,
            "buffer_prefix_encoding": "base64",
            "buffer_prefix": "cG8=",
            "requested_count": 2,
            "actual_count": 2,
            "capture_truncated": False,
        }
    return row


def _make_run(tmp_path: Path, *, audit_write: bool = True, missing_ebpf_id: bool = False, missing_normalized_audit_fields: bool = False) -> Path:
    run = tmp_path / "case__poisoned"
    _write_json(run / "run_safety_attestation.json", {
        "preflight_passed": True,
        "auditd_pid_scoped_syscall_rule": {"installed": True, "worker_pid": 1234},
    })
    _write_json(run / "auditd_capture_config.json", {
        "worker_pid": 1234,
        "worker_pid_syscall_rule_installed": True,
        "pid_syscall_rule_stage": "installed_while_launch_wrapper_blocked_before_agent_exec",
        "global_uid_syscall_rule_installed": False,
    })
    _write_json(run / "ground_truth.json", {
        "pipeline_status": "valid_attempt",
        "branch_outcome": "attack_candidate_realized_manual_review_pending",
        "state_change_paths": ["MEMORY.md"],
        "self_state_writer_calls": [{"path": "MEMORY.md", "tool": "write"}],
        "delivery": {"channel": "workspace_file", "fixture_process": "workspace seeder"},
        "ingestion": {"channel": "workspace_file"},
        "session_b": {"consequence_candidate_observed": False},
    })
    _write_json(run / "runtime_state_capture.json", {
        "schema_version": "assa.runtime_state_capture.v1",
        "process_state": {},
        "filesystem_state": {},
        "fd_state": {},
        "syscall_state": {},
        "policy_state": {},
        "snapshot_state": {},
        "agent_execution_state": {},
        "retained_field_groups": [
            "pid_start_time_lineage_uid_auid_ses_cgroup_namespace",
            "self_state_path_inode_dev_mode_uid_gid_mtime_ctime_xattr",
            "open_flags_fd_inode_offset_close_lifetime_or_buffer_attribution",
            "syscall_args_return_errno_for_read_write_rename_unlink_chmod",
            "active_dac_immutable_apparmor_landlock_audit_network_policy_state",
            "before_after_consequence_snapshot_manifest_with_full_bytes",
            "tool_calls_session_logs_model_proxy_requests_and_gateway_messages",
        ],
    })
    for name in ("before_a", "after_a", "after_b"):
        path = run / "state_snapshots" / name / "MEMORY.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(name, encoding="utf-8")
    sources: dict[str, dict] = {}
    for source in SOURCES:
        raw = run / "raw" / f"{source}.jsonl"
        normalized = run / "normalized" / f"{source}.jsonl"
        health = {
            "collector_started_realtime_ns": 1,
            "collector_started_monotonic_ns": 1,
            "collector_stopped_realtime_ns": 2,
            "collector_stopped_monotonic_ns": 2,
            "events_emitted": 1,
            "drop_count": 0,
            "overflow_count": 0,
            "queue_high_water_mark": 1,
        }
        _write_jsonl(raw, [{"timestamp_realtime_ns": 1, "timestamp_monotonic_ns": 1}])
        event = _event(source, correlation_id="ebpf-only" if missing_ebpf_id and source == "ebpf" else "cid-1")
        if source == "auditd" and not audit_write:
            event.pop("syscall_name", None)
            event.pop("syscall_arguments", None)
        if source == "auditd" and missing_normalized_audit_fields:
            for field in ("syscall_pid", "syscall_fd", "syscall_exit", "syscall_byte_count"):
                event.pop(field, None)
        _write_jsonl(normalized, [event])
        sources[source] = {
            "raw_stream_retained": True,
            "raw_stream_path": str(raw),
            "normalized_stream_path": str(normalized),
            "health": health,
        }
    _write_json(run / "raw_trace_bundle.json", {
        "run_time_anchor": {"boot_id": "boot"},
        "sources": sources,
    })
    return run



def _make_automatic_runtime_write_run(
    tmp_path: Path,
    *,
    missing_file_source: str | None = None,
    include_audit_write: bool = True,
    advancing_chain: bool = True,
    before_present: bool = False,
) -> Path:
    run = _make_run(tmp_path)
    target = "memory/2026-08-20.md"
    target_absolute = str(run / "workspace" / target)
    ground_truth = json.loads((run / "ground_truth.json").read_text(encoding="utf-8"))
    ground_truth.update({
        "branch_outcome": "natural_write",
        "state_change_paths": [target],
        "state_changes_session_a": [{
            "path": target,
            "before": {"bytes": 1} if before_present else None,
            "after": {"bytes": 2},
        }],
        "self_state_writer_calls": [],
    })
    _write_json(run / "ground_truth.json", ground_truth)

    for source, mask in (("inotify", 2), ("fanotify", 8)):
        rows = [] if missing_file_source == source else [{
            "record_type": f"{source}_event",
            "source": source,
            "path": target_absolute,
            "mask": mask,
            "pid": 1234 if source == "fanotify" else None,
            "timestamp_realtime_ns": 100,
            "timestamp_monotonic_ns": 200,
        }]
        _write_jsonl(run / "raw" / f"{source}.jsonl", rows)

    audit_evidence = [{
        "source": "auditd",
        "audit_serial": "42",
        "raw_path": str(run / "raw" / "auditd_ausearch.log"),
        "raw_sha256": "audit-sha",
        "line_start": 1,
        "line_end": 2,
    }]
    syscalls = [{
        "event_id": "audit:42",
        "evidence": audit_evidence,
        "process": {"pid": 1234, "uid": 997},
        "fd": {"input_fd": 3},
        "file": {"resolved_path": target_absolute},
        "order": {"audit_serial": "42"},
        "syscall": {
            "name": "write",
            "success": True,
            "return_value": 2,
        },
    }] if include_audit_write else []
    _write_jsonl(run / "graph" / "reattributed" / "syscalls.jsonl", syscalls)

    versions = [1, 2] if advancing_chain else [1]
    nodes = [{
        "schema_version": "assa.provenance_node.v2",
        "node_id": f"file:stable:v{version}",
        "node_type": "file",
        "attributes": {
            "resolved_path": target_absolute,
            "version": version,
        },
    } for version in versions]
    edges = [{
        "schema_version": "assa.provenance_edge.v3",
        "edge_id": f"write:{version}",
        "source_node_id": "process:agent",
        "destination_node_id": f"file:stable:v{version}",
        "relation": "write",
        "success": True,
        "byte_count": 2,
    } for version in versions]
    _write_jsonl(run / "graph" / "reattributed" / "provenance.nodes.jsonl", nodes)
    _write_jsonl(run / "graph" / "reattributed" / "provenance.edges.jsonl", edges)
    return run

def test_recollection_readiness_accepts_complete_four_source_run(tmp_path: Path) -> None:
    report = validate_run(_make_run(tmp_path))
    assert report["passed"] is True


def test_recollection_readiness_rejects_missing_auditd_write_layer(tmp_path: Path) -> None:
    report = validate_run(_make_run(tmp_path, audit_write=False))
    assert report["passed"] is False
    assert "auditd_worker_write_syscall_present" in {row["name"] for row in report["failed_checks"]}




def test_recollection_readiness_rejects_missing_normalized_audit_syscall_fields(tmp_path: Path) -> None:
    report = validate_run(_make_run(tmp_path, missing_normalized_audit_fields=True))
    assert report["passed"] is False
    assert "auditd_normalized_write_syscall_fields_non_null" in {row["name"] for row in report["failed_checks"]}

def test_recollection_readiness_rejects_cross_source_id_mismatch(tmp_path: Path) -> None:
    report = validate_run(_make_run(tmp_path, missing_ebpf_id=True))
    assert report["passed"] is False
    assert "four_source_mutation_correlation_exact" in {row["name"] for row in report["failed_checks"]}



def _add_stage_g_union_graph_write(
    run: Path, *, include_audit: bool = True
) -> None:
    target = str(run / "workspace" / "MEMORY.md")
    ground_truth = json.loads(
        (run / "ground_truth.json").read_text(encoding="utf-8")
    )
    ground_truth["state_changes_session_a"] = [{
        "path": "MEMORY.md",
        "before": {"bytes": 1},
        "after": {"bytes": 2},
    }]
    _write_json(run / "ground_truth.json", ground_truth)
    _write_jsonl(run / "normalized" / "auditd.jsonl", [])
    evidence = [{"source": "scap", "line": 1}]
    if include_audit:
        evidence.append({"source": "auditd", "audit_serial": "42"})
    _write_jsonl(
        run / "stage_g_v6" / "normalized" / "syscalls.jsonl",
        [{
            "event_id": "scap:7",
            "evidence": evidence,
            "process": {"pid": 1234, "uid": 997},
            "fd": {"input_fd": 3},
            "file": {"resolved_path": target},
            "order": {"audit_serial": "42" if include_audit else None},
            "syscall": {
                "name": "write",
                "success": True,
                "return_value": 2,
                "arguments": {"a0": 3, "a1": 123, "a2": 2},
                "arguments_raw": {"a0": "3", "a1": "7b", "a2": "2"},
            },
        }],
    )
    _write_jsonl(
        run / "stage_g_v6" / "normalized" / "provenance.nodes.jsonl",
        [
            {
                "node_id": "file:stable:v0",
                "node_type": "file",
                "attributes": {"resolved_path": target, "version": 0},
            },
            {
                "node_id": "file:stable:v1",
                "node_type": "file",
                "attributes": {"resolved_path": target, "version": 1},
            },
        ],
    )
    _write_jsonl(
        run / "stage_g_v6" / "normalized" / "provenance.edges.jsonl",
        [{
            "edge_id": "write:1",
            "source_node_id": "process:agent",
            "destination_node_id": "file:stable:v1",
            "relation": "write",
            "success": True,
            "byte_count": 2,
        }],
    )


def test_semantic_mutation_accepts_stage_g_union_audit_graph_fallback(
    tmp_path: Path,
) -> None:
    run = _make_run(tmp_path)
    _add_stage_g_union_graph_write(run)
    report = validate_run(run)
    assert report["passed"] is True
    exact = next(
        row
        for row in report["checks"]
        if row["name"] == "four_source_mutation_correlation_exact"
    )
    assert (
        exact["correlation_mode"]
        == "semantic_three_source_plus_stage_g_union_audit_graph"
    )
    audit = next(
        row
        for row in report["checks"]
        if row["name"] == "auditd_worker_write_syscall_present"
    )
    assert audit["audit_evidence_mode"] == "stage_g_declared_key_union_graph"


def test_semantic_mutation_rejects_stage_g_graph_without_audit_evidence(
    tmp_path: Path,
) -> None:
    run = _make_run(tmp_path)
    _add_stage_g_union_graph_write(run, include_audit=False)
    report = validate_run(run)
    assert report["passed"] is False
    assert {
        "four_source_mutation_correlation_exact",
        "auditd_worker_write_syscall_present",
    }.issubset({row["name"] for row in report["failed_checks"]})



def _add_split_automatic_companion(
    run: Path,
    *,
    include_second_audit: bool = True,
    second_count: int = 1,
    include_open_v0: bool = False,
    write_realtime_ns: tuple[int, int] | None = None,
) -> None:
    """Add an absent-file create+append companion to a semantic mutation."""
    _add_stage_g_union_graph_write(run)
    target = "memory/2026-08-20.md"
    target_absolute = str(run / "workspace" / target)
    ground_truth = json.loads(
        (run / "ground_truth.json").read_text(encoding="utf-8")
    )
    ground_truth["state_change_paths"] = ["MEMORY.md", target]
    ground_truth["state_changes_session_a"].append({
        "path": target,
        "before": None,
        "after": {"bytes": 2},
    })
    ground_truth["self_state_writer_calls"] = [
        {"path": "MEMORY.md", "tool": "write"}
    ]
    _write_json(run / "ground_truth.json", ground_truth)

    for source, mask in (("inotify", 2), ("fanotify", 8)):
        _write_jsonl(run / "raw" / f"{source}.jsonl", [{
            "record_type": f"{source}_event",
            "source": source,
            "path": target_absolute,
            "mask": mask,
            "pid": 1234 if source == "fanotify" else None,
            "timestamp_realtime_ns": 100,
            "timestamp_monotonic_ns": 200,
        }])

    syscall_path = run / "stage_g_v6" / "normalized" / "syscalls.jsonl"
    syscall_rows = [
        json.loads(line)
        for line in syscall_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    for index, count in enumerate((1, second_count), 1):
        evidence = [{"source": "scap", "line": index + 1}]
        if index == 1 or include_second_audit:
            evidence.append({
                "source": "auditd",
                "audit_serial": str(42 + index),
            })
        syscall_rows.append({
            "event_id": f"scap:companion-{index}",
            "evidence": evidence,
            "process": {"pid": 1234, "uid": 997},
            "fd": {"input_fd": 4},
            "file": {"resolved_path": target_absolute},
            "order": {
                "audit_serial": str(42 + index)
                if index == 1 or include_second_audit
                else None,
                **(
                    {"timestamp_realtime_ns": write_realtime_ns[index - 1]}
                    if write_realtime_ns is not None
                    else {}
                ),
            },
            "syscall": {
                "name": "write",
                "success": True,
                "return_value": count,
                "arguments": {"a0": 4, "a1": 124, "a2": count},
                "arguments_raw": {"a0": "4", "a1": "7c", "a2": hex(count)},
            },
        })
    _write_jsonl(syscall_path, syscall_rows)

    node_path = run / "stage_g_v6" / "normalized" / "provenance.nodes.jsonl"
    node_rows = [
        json.loads(line)
        for line in node_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    versions = (0, 1, 2) if include_open_v0 else (1, 2)
    node_rows.extend({
        "node_id": f"file:companion:v{version}",
        "node_type": "file",
        "attributes": {"resolved_path": target_absolute, "version": version},
    } for version in versions)
    _write_jsonl(node_path, node_rows)

    edge_path = run / "stage_g_v6" / "normalized" / "provenance.edges.jsonl"
    edge_rows = [
        json.loads(line)
        for line in edge_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    edge_rows.extend({
        "edge_id": f"write:companion-{index}",
        "source_node_id": "process:agent",
        "destination_node_id": f"file:companion:v{index}",
        "relation": "write",
        "success": True,
        "byte_count": count,
        **(
            {"order": {"timestamp_realtime_ns": write_realtime_ns[index - 1]}}
            if write_realtime_ns is not None
            else {}
        ),
    } for index, count in enumerate((1, second_count), 1))
    _write_jsonl(edge_path, edge_rows)


def test_semantic_mutation_accepts_audit_backed_split_automatic_companion(
    tmp_path: Path,
) -> None:
    run = _make_run(tmp_path)
    _add_split_automatic_companion(run)
    report = validate_run(run)
    assert report["passed"] is True
    exact = next(
        row for row in report["checks"]
        if row["name"] == "four_source_mutation_correlation_exact"
    )
    companion = exact["per_target"]["memory/2026-08-20.md"]
    assert companion["target_role"] == "automatic_companion_state_write"
    assert companion["transition_evidence"]["mode"] == "split_absent_file_creation"
    assert companion["transition_evidence"]["observed_write_total"] == 2
    assert len(companion["matching_audit_scap_write_rows"]) == 2


def test_semantic_mutation_accepts_absent_companion_with_open_v0(
    tmp_path: Path,
) -> None:
    run = _make_run(tmp_path)
    _add_split_automatic_companion(run, include_open_v0=True)
    report = validate_run(run)
    assert report["passed"] is True
    exact = next(
        row for row in report["checks"]
        if row["name"] == "four_source_mutation_correlation_exact"
    )
    companion = exact["per_target"]["memory/2026-08-20.md"]
    assert companion["version_transition_passed"] is True
    assert companion["stable_versions_by_identity"]["file:companion"] == [0, 1, 2]


def test_semantic_mutation_rejects_noncontiguous_absent_companion_versions(
    tmp_path: Path,
) -> None:
    run = _make_run(tmp_path)
    _add_split_automatic_companion(run, include_open_v0=True)
    nodes = run / "stage_g_v6" / "normalized" / "provenance.nodes.jsonl"
    _write_jsonl(nodes, [
        row
        for row in map(json.loads, nodes.read_text(encoding="utf-8").splitlines())
        if row.get("node_id") != "file:companion:v1"
    ])
    report = validate_run(run)
    assert report["passed"] is False
    assert "four_source_mutation_correlation_exact" in {
        row["name"] for row in report["failed_checks"]
    }


def test_semantic_mutation_accepts_single_write_automatic_companion_as_v1(
    tmp_path: Path,
) -> None:
    run = _make_run(tmp_path)
    _add_split_automatic_companion(run)

    ground_truth = json.loads(
        (run / "ground_truth.json").read_text(encoding="utf-8")
    )
    companion_change = ground_truth["state_changes_session_a"][1]
    companion_change["after"]["bytes"] = 1
    _write_json(run / "ground_truth.json", ground_truth)

    syscalls = run / "stage_g_v6" / "normalized" / "syscalls.jsonl"
    _write_jsonl(syscalls, [
        row
        for row in map(json.loads, syscalls.read_text(encoding="utf-8").splitlines())
        if row.get("event_id") != "scap:companion-2"
    ])
    nodes = run / "stage_g_v6" / "normalized" / "provenance.nodes.jsonl"
    _write_jsonl(nodes, [
        row
        for row in map(json.loads, nodes.read_text(encoding="utf-8").splitlines())
        if row.get("node_id") != "file:companion:v2"
    ])
    edges = run / "stage_g_v6" / "normalized" / "provenance.edges.jsonl"
    _write_jsonl(edges, [
        row
        for row in map(json.loads, edges.read_text(encoding="utf-8").splitlines())
        if row.get("edge_id") != "write:companion-2"
    ])

    report = validate_run(run)
    assert report["passed"] is True
    exact = next(
        row for row in report["checks"]
        if row["name"] == "four_source_mutation_correlation_exact"
    )
    companion = exact["per_target"]["memory/2026-08-20.md"]
    assert companion["transition_evidence"]["mode"] == "single_full_file_write"
    assert companion["version_transition_passed"] is True
    assert companion["version_transition_mode"] == "absent_file_created_as_stable_v1"


def test_semantic_split_companion_rejects_missing_audit_piece(
    tmp_path: Path,
) -> None:
    run = _make_run(tmp_path)
    _add_split_automatic_companion(run, include_second_audit=False)
    report = validate_run(run)
    assert report["passed"] is False
    assert "four_source_mutation_correlation_exact" in {
        row["name"] for row in report["failed_checks"]
    }


def test_semantic_split_companion_rejects_byte_sum_mismatch(
    tmp_path: Path,
) -> None:
    run = _make_run(tmp_path)
    _add_split_automatic_companion(run, second_count=2)
    report = validate_run(run)
    assert report["passed"] is False
    assert "four_source_mutation_correlation_exact" in {
        row["name"] for row in report["failed_checks"]
    }


def test_semantic_companion_scopes_cross_phase_write_to_session_a(
    tmp_path: Path,
) -> None:
    run = _make_run(tmp_path)
    _add_split_automatic_companion(
        run,
        second_count=5,
        write_realtime_ns=(100, 200),
    )
    ground_truth = json.loads(
        (run / "ground_truth.json").read_text(encoding="utf-8")
    )
    ground_truth["state_changes_session_a"][1]["after"]["bytes"] = 1
    _write_json(run / "ground_truth.json", ground_truth)
    _write_jsonl(run / "session_a.jsonl", [
        {"type": "session_start", "timestamp_realtime_ns": 90},
        {"type": "session_end", "timestamp_realtime_ns": 150},
    ])

    report = validate_run(run)
    assert report["passed"] is True
    exact = next(
        row for row in report["checks"]
        if row["name"] == "four_source_mutation_correlation_exact"
    )
    main = exact["per_target"]["MEMORY.md"]
    companion = exact["per_target"]["memory/2026-08-20.md"]
    assert "phase_window_scope" not in main
    assert companion["phase_window_scope"]["applied"] is True
    assert companion["phase_window_scope"]["phase"] == "session_a"
    assert companion["transition_evidence"]["mode"] == "single_full_file_write"
    assert companion["transition_evidence"]["observed_write_total"] == 1
    assert len(companion["matching_audit_scap_write_rows"]) == 1


def test_recollection_readiness_rejects_missing_runtime_state_capture(tmp_path: Path) -> None:
    run = _make_run(tmp_path)
    (run / "runtime_state_capture.json").unlink()
    report = validate_run(run)
    assert report["passed"] is False
    assert "runtime_state_capture_manifest_present" in {row["name"] for row in report["failed_checks"]}



def test_automatic_runtime_write_requires_three_positive_evidence_arms(tmp_path: Path) -> None:
    report = validate_run(_make_automatic_runtime_write_run(tmp_path))
    assert report["passed"] is True
    assert report["readiness_profile"]["name"] == "automatic_runtime_state_write"
    names = {row["name"] for row in report["checks"]}
    assert "four_source_mutation_correlation_exact_not_applicable" in names
    assert "automatic_state_write_raw_file_events_present" in names
    assert "automatic_state_write_auditd_write_rows_present" in names
    assert "automatic_state_write_stable_version_chain_advances" in names


def test_automatic_runtime_write_rejects_missing_raw_file_arm(tmp_path: Path) -> None:
    report = validate_run(
        _make_automatic_runtime_write_run(tmp_path, missing_file_source="fanotify")
    )
    assert report["passed"] is False
    assert "automatic_state_write_raw_file_events_present" in {
        row["name"] for row in report["failed_checks"]
    }


def test_automatic_runtime_write_rejects_missing_audit_write_arm(tmp_path: Path) -> None:
    report = validate_run(
        _make_automatic_runtime_write_run(tmp_path, include_audit_write=False)
    )
    assert report["passed"] is False
    assert "automatic_state_write_auditd_write_rows_present" in {
        row["name"] for row in report["failed_checks"]
    }



def test_automatic_runtime_write_rejects_unrelated_fd_reuse_write_size(tmp_path: Path) -> None:
    run = _make_automatic_runtime_write_run(tmp_path)
    ground_truth = json.loads((run / "ground_truth.json").read_text(encoding="utf-8"))
    ground_truth["state_changes_session_a"][0]["after"]["bytes"] = 999
    _write_json(run / "ground_truth.json", ground_truth)
    report = validate_run(run)
    assert report["passed"] is False
    failed = {row["name"] for row in report["failed_checks"]}
    assert "automatic_state_write_auditd_write_rows_present" in failed
    assert "automatic_state_write_stable_version_chain_advances" in failed

def test_automatic_runtime_write_rejects_nonadvancing_graph_arm(tmp_path: Path) -> None:
    report = validate_run(
        _make_automatic_runtime_write_run(
            tmp_path, advancing_chain=False, before_present=True
        )
    )
    assert report["passed"] is False
    assert "automatic_state_write_stable_version_chain_advances" in {
        row["name"] for row in report["failed_checks"]
    }


def test_automatic_runtime_write_accepts_absent_file_created_as_v1(
    tmp_path: Path,
) -> None:
    report = validate_run(
        _make_automatic_runtime_write_run(tmp_path, advancing_chain=False)
    )
    assert report["passed"] is True
    check = next(
        row
        for row in report["checks"]
        if row["name"]
        == "automatic_state_write_stable_version_chain_advances"
    )
    assert (
        check["per_target"]["memory/2026-08-20.md"]["transition_mode"]
        == "absent_file_created_as_stable_v1"
    )


def _make_external_content_run(tmp_path: Path, *, fetch_evidence: bool = True) -> Path:
    run = _make_run(tmp_path)
    access = run / "trace" / "fixture_http.access.jsonl"
    _write_jsonl(access, [{
        "schema_version": "assa.fixture_http_access.v1",
        "timestamp_realtime_ns": 10,
        "timestamp_monotonic_ns": 20,
        "client_ip": "127.0.0.1",
        "server_ip": "127.0.0.1",
        "status": 200,
        "artifact_sha256": "artifact",
    }])
    bundle = json.loads((run / "raw_trace_bundle.json").read_text(encoding="utf-8"))
    bundle["fixture_http_access_log"] = str(access)
    _write_json(run / "raw_trace_bundle.json", bundle)
    evidence = {
        "all_external_content_evidence_passed": fetch_evidence,
        "checks": {
            "fixture_metadata_present": True,
            "fixture_url_loopback": True,
            "fetch_tool_call_observed": fetch_evidence,
            "fixture_http_access_observed": True,
            "fixture_artifact_sha_matches_fetch": fetch_evidence,
        },
    }
    _write_json(run / "ground_truth.json", {
        "pipeline_status": "valid_attempt",
        "branch_outcome": "attack_candidate_realized_manual_review_pending",
        "state_change_paths": ["MEMORY.md"],
        "self_state_writer_calls": [{"path": "MEMORY.md", "tool": "write"}],
        "delivery": {"channel": "external_content", "fixture_process": "local_http_fixture_server"},
        "ingestion": {
            "channel": "external_content",
            "carrier_read_observed": False,
            "filesystem_ingestion_observable": False,
            "external_content_evidence": evidence,
        },
        "route_a_anchor_evidence": {"external_content_provenance_evidence": evidence},
        "session_b": {"consequence_candidate_observed": False},
    })
    return run


def test_recollection_readiness_accepts_external_content_http_and_fetch_evidence(tmp_path: Path) -> None:
    report = validate_run(_make_external_content_run(tmp_path))
    assert report["passed"] is True


def test_recollection_readiness_rejects_external_content_without_fetch_evidence(tmp_path: Path) -> None:
    report = validate_run(_make_external_content_run(tmp_path, fetch_evidence=False))
    assert report["passed"] is False
    assert "external_content_fetch_tool_evidence_present" in {row["name"] for row in report["failed_checks"]}
