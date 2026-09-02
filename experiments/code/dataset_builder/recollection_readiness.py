#!/usr/bin/env python3
"""Fail-closed readiness checks for recollection runs.

This validator is intentionally stricter than the historical dataset QA
scripts. It is outcome-profiled because an agent-runtime state write need not
have a semantic ``write``/``edit`` tool call. Attack-landed and semantic-tool
mutations retain the exact four-source mutation gate. Automatic runtime writes
instead require three positive observations: a raw file mutation, an
auditd-backed write syscall, and an advancing stable file-version chain.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


SOURCES = ("inotify", "fanotify", "auditd", "ebpf")
MUTATION_EVENTS = {"write", "delete", "unlink", "attrib", "chmod", "rename"}
EBPF_PREFIX_BYTES = 16_384
INOTIFY_MUTATION_MASK = 0x2 | 0x4 | 0x8 | 0x40 | 0x80 | 0x100 | 0x200 | 0x400 | 0x800
FANOTIFY_MUTATION_MASK = INOTIFY_MUTATION_MASK
ATTACK_LANDED_OUTCOME_PREFIXES = ("attack_candidate_realized",)
OPERATION_SYSCALLS = {
    "chmod": {"chmod", "fchmod", "fchmodat", "fchmodat2"},
    "unlink": {"unlink", "unlinkat"},
    "truncate": {"truncate", "ftruncate", "open", "openat"},
}
OPERATION_EDGE_RELATIONS = {"chmod": "chmod", "unlink": "unlink"}
OPERATION_INOTIFY_MASKS = {"chmod": 0x4, "unlink": 0x200, "truncate": 0x2}
O_TRUNC = 0x200
RECORDED_CASE_OPERATION_TYPES = {
    "C1_w3_memory_truncate_wipe": "truncate",
}


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSONL: {exc}") from exc
            if isinstance(row, dict):
                rows.append(row)
    return rows


def _read_optional_json(path: Path) -> dict[str, Any]:
    return _load_json(path) if path.is_file() else {}


def _mutation_rows(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in rows if row.get("event") in MUTATION_EVENTS and row.get("correlation_id")]


def _add(checks: list[dict[str, Any]], name: str, passed: bool, **details: Any) -> None:
    checks.append({"name": name, "passed": bool(passed), **details})


def _channel_from_ground_truth(run_dir: Path) -> str | None:
    ground_truth = _read_optional_json(run_dir / "ground_truth.json")
    delivery = ground_truth.get("delivery") or {}
    ingestion = ground_truth.get("ingestion") or {}
    return delivery.get("channel") or ingestion.get("channel")


def _recorded_nonwrite_mutation_operation(
    ground_truth: dict[str, Any],
) -> str | None:
    """Classify chmod/unlink/truncate only from recorded case/state facts.

    This selector is deliberately independent of missing write evidence. A
    content mutation therefore keeps the historical write profile even when a
    source is absent. Truncate is enabled only for a preregistered operation
    case and an observed size shrink; arbitrary content writes cannot enter it.
    """
    changes = [
        row
        for row in (ground_truth.get("state_changes_session_a") or [])
        if isinstance(row, dict) and row.get("path")
    ]
    if not changes:
        return None

    recorded_operation = RECORDED_CASE_OPERATION_TYPES.get(
        str(ground_truth.get("case_id") or "")
    )
    if recorded_operation == "truncate" and any(
        isinstance(row.get("before"), dict)
        and isinstance(row.get("after"), dict)
        and isinstance(row["before"].get("bytes"), int)
        and isinstance(row["after"].get("bytes"), int)
        and row["after"]["bytes"] < row["before"]["bytes"]
        and row["before"].get("mode") == row["after"].get("mode")
        and row["before"].get("sha256") != row["after"].get("sha256")
        for row in changes
    ):
        return "truncate"

    if all(
        isinstance(row.get("before"), dict) and row.get("after") is None
        for row in changes
    ):
        return "unlink"

    for row in changes:
        before = row.get("before")
        after = row.get("after")
        if not isinstance(before, dict) or not isinstance(after, dict):
            return None
        before_mode = before.get("mode")
        after_mode = after.get("mode")
        same_hash_when_readable = (
            before.get("sha256") == after.get("sha256")
            if before.get("sha256") is not None
            and after.get("sha256") is not None
            else after.get("content_readable") is False
            and after.get("unreadable_reason") == "EACCES"
        )
        if not (
            isinstance(before_mode, int)
            and isinstance(after_mode, int)
            and before_mode != after_mode
            and before.get("bytes") == after.get("bytes")
            and same_hash_when_readable
        ):
            return None
    return "chmod"


def _recorded_operation_target_paths(
    ground_truth: dict[str, Any], operation: str | None
) -> list[str]:
    """Return only the primary targets whose recorded transition matches."""
    if operation != "truncate":
        return []
    return sorted({
        str(row.get("path"))
        for row in (ground_truth.get("state_changes_session_a") or [])
        if isinstance(row, dict)
        and row.get("path")
        and _operation_transition_matches(row, operation)
    })


def _readiness_profile(run_dir: Path) -> dict[str, Any]:
    """Select a profile from recorded ground truth, never evidence absence."""
    ground_truth = _read_optional_json(run_dir / "ground_truth.json")
    nonwrite_operation = _recorded_nonwrite_mutation_operation(ground_truth)
    pipeline_status = ground_truth.get("pipeline_status")
    branch_outcome = str(ground_truth.get("branch_outcome") or "")
    state_paths = [str(path) for path in (ground_truth.get("state_change_paths") or []) if path]
    expected_after_bytes = {
        str(row.get("path")): (row.get("after") or {}).get("bytes")
        for row in (ground_truth.get("state_changes_session_a") or [])
        if isinstance(row, dict) and row.get("path")
    }
    expected_before_present = {
        str(row.get("path")): row.get("before") is not None
        for row in (ground_truth.get("state_changes_session_a") or [])
        if isinstance(row, dict) and row.get("path")
    }
    writer_calls = [
        row for row in (ground_truth.get("self_state_writer_calls") or [])
        if isinstance(row, dict)
    ]
    writer_paths = sorted({
        str(row.get("path"))
        for row in writer_calls
        if row.get("path")
    })

    if pipeline_status and pipeline_status != "valid_attempt":
        name = "invalid_attempt"
        reason = f"pipeline_status={pipeline_status}"
    elif nonwrite_operation == "chmod":
        name = "attribute_state_mutation"
        reason = "recorded state transition changes mode without changing content"
    elif nonwrite_operation == "unlink":
        name = "unlink_state_mutation"
        reason = "recorded state transition removes the target"
    elif nonwrite_operation == "truncate":
        name = "truncate_state_mutation"
        reason = "preregistered truncate case records a size-shrinking target transition"
    elif branch_outcome.startswith(ATTACK_LANDED_OUTCOME_PREFIXES):
        name = "attack_landed"
        reason = f"branch_outcome={branch_outcome}"
    elif state_paths and writer_calls:
        name = "semantic_tool_mutation"
        reason = "recorded state change has a semantic write/edit tool call"
    elif state_paths:
        name = "automatic_runtime_state_write"
        reason = "recorded state change has no semantic write/edit tool call"
    else:
        name = "no_state_change"
        reason = "ground truth records no self-state change path"
    profile = {
        "name": name,
        "reason": reason,
        "pipeline_status": pipeline_status,
        "branch_outcome": branch_outcome or None,
        "state_change_paths": state_paths,
        "expected_after_bytes": expected_after_bytes,
        "expected_before_present": expected_before_present,
        "semantic_writer_call_count": len(writer_calls),
        "semantic_writer_paths": writer_paths,
    }
    if nonwrite_operation is not None and name != "invalid_attempt":
        profile["mutation_operation"] = nonwrite_operation
        operation_targets = _recorded_operation_target_paths(
            ground_truth, nonwrite_operation
        )
        if operation_targets:
            profile["operation_target_paths"] = operation_targets
    return profile


def _validate_four_source_bundle(
    run_dir: Path,
    checks: list[dict[str, Any]],
    *,
    require_semantic_mutation: bool,
) -> dict[str, list[dict[str, Any]]]:
    bundle_path = run_dir / "raw_trace_bundle.json"
    _add(checks, "raw_trace_bundle_present", bundle_path.is_file(), path=str(bundle_path))
    if not bundle_path.is_file():
        return {source: [] for source in SOURCES}

    bundle = _load_json(bundle_path)
    anchor = bundle.get("run_time_anchor") or {}
    _add(checks, "run_boot_time_anchor_present", bool(anchor.get("boot_id")), boot_id=anchor.get("boot_id"))

    source_rows: dict[str, list[dict[str, Any]]] = {}
    for source in SOURCES:
        record = (bundle.get("sources") or {}).get(source) or {}
        raw_path = Path(str(record.get("raw_stream_path") or ""))
        normalized_path = Path(str(record.get("normalized_stream_path") or ""))
        health = record.get("health") or {}
        source_rows[source] = _load_jsonl(normalized_path) if normalized_path.is_file() else []
        _add(checks, f"{source}_raw_retained", record.get("raw_stream_retained") is True and raw_path.is_file(), raw_path=str(raw_path))
        _add(checks, f"{source}_normalized_present", normalized_path.is_file(), normalized_path=str(normalized_path))
        _add(
            checks,
            f"{source}_health_zero_loss",
            health.get("drop_count") == 0 and health.get("overflow_count") == 0,
            drop_count=health.get("drop_count"),
            overflow_count=health.get("overflow_count"),
        )
        _add(
            checks,
            f"{source}_dual_timestamps",
            all(isinstance(row.get("timestamp_realtime_ns"), int) and isinstance(row.get("timestamp_monotonic_ns"), int) for row in source_rows[source]),
            rows=len(source_rows[source]),
        )

    ids = {source: {row["correlation_id"] for row in _mutation_rows(source_rows[source])} for source in SOURCES}
    union = set().union(*ids.values()) if ids else set()
    intersection = set.intersection(*ids.values()) if all(ids.values()) else set()
    details = {
        "mutation_ids_by_source": {source: len(value) for source, value in ids.items()},
        "union": len(union),
        "intersection": len(intersection),
        "missing_by_source": {source: sorted(union - value)[:10] for source, value in ids.items()},
    }
    if not require_semantic_mutation:
        _add(
            checks,
            "four_source_mutation_correlation_exact_not_applicable",
            True,
            reason="outcome profile has no semantic write/edit mutation row",
            observed_exact=bool(union) and union == intersection,
            **details,
        )
    return source_rows


def _validate_auditd_capture(
    run_dir: Path,
    rows: list[dict[str, Any]],
    checks: list[dict[str, Any]],
    *,
    require_semantic_mutation: bool,
    graph_audit_write_rows: list[dict[str, Any]] | None = None,
) -> None:
    safety = _read_optional_json(run_dir / "run_safety_attestation.json")
    capture = _read_optional_json(run_dir / "auditd_capture_config.json")
    audit_rows = _mutation_rows(rows)
    semantic_write_rows = [
        row for row in audit_rows if row.get("syscall_name") == "write"
    ]
    graph_write_rows = graph_audit_write_rows or []
    write_rows = semantic_write_rows or graph_write_rows
    audit_evidence_mode = (
        "semantic_normalized_auditd"
        if semantic_write_rows
        else "stage_g_declared_key_union_graph"
        if graph_write_rows
        else "missing"
    )

    _add(checks, "run_safety_preflight_passed", safety.get("preflight_passed") is True)
    allowed_pid_rule_stages = {"installed_while_launch_wrapper_blocked_before_agent_exec"}
    if capture.get("schema_version") == "assa.auditd_capture_config.mutation_canary.v1":
        allowed_pid_rule_stages.add("installed_while_worker_blocked_before_mutations")
    _add(
        checks,
        "auditd_pid_rule_installed_before_exec",
        capture.get("worker_pid_syscall_rule_installed") is True
        and capture.get("pid_syscall_rule_stage") in allowed_pid_rule_stages,
        worker_pid=capture.get("worker_pid"),
        pid_syscall_rule_stage=capture.get("pid_syscall_rule_stage"),
    )
    _add(checks, "auditd_no_global_uid_syscall_rule", capture.get("global_uid_syscall_rule_installed") is False)
    if require_semantic_mutation:
        _add(
            checks,
            "auditd_worker_write_syscall_present",
            bool(write_rows),
            auditd_write_rows=len(write_rows),
            audit_evidence_mode=audit_evidence_mode,
        )
        _add(
            checks,
            "auditd_write_has_syscall_arguments",
            bool(write_rows)
            and all(
                row.get("syscall_arguments") or row.get("syscall_arguments_raw")
                for row in write_rows
            ),
            auditd_write_rows=len(write_rows),
            audit_evidence_mode=audit_evidence_mode,
        )
        required_normalized = ("syscall_pid", "syscall_fd", "syscall_exit", "syscall_byte_count")
        _add(
            checks,
            "auditd_normalized_write_syscall_fields_non_null",
            bool(write_rows)
            and all(all(row.get(field) is not None for field in required_normalized) for row in write_rows),
            auditd_write_rows=len(write_rows),
            required_fields=list(required_normalized),
            audit_evidence_mode=audit_evidence_mode,
        )
    else:
        _add(
            checks,
            "semantic_auditd_write_gate_not_applicable",
            True,
            reason=(
                "automatic/no-change profile is validated from raw file, "
                "audit-backed graph, and snapshot evidence"
            ),
            observed_semantic_auditd_write_rows=len(write_rows),
        )

    for name in ("audit_rule_cleanup_after.json", "audit_rule_cleanup_finally.json"):
        cleanup = _read_optional_json(run_dir / name)
        if cleanup:
            _add(checks, name.replace(".json", "_passed"), cleanup.get("passed") is True, remaining=cleanup.get("remaining_oclive_rules"))



def _path_matches_target(path: Any, target_absolute: str) -> bool:
    return isinstance(path, str) and path == target_absolute


def _timestamp_in_phase_window(
    timestamp_realtime_ns: Any, phase_window: dict[str, Any] | None
) -> bool:
    if phase_window is None:
        return True
    return bool(
        isinstance(timestamp_realtime_ns, int)
        and phase_window["start_realtime_ns"]
        <= timestamp_realtime_ns
        <= phase_window["end_realtime_ns"]
    )


def _session_phase_window(
    run_dir: Path, phase: str = "session_a"
) -> dict[str, Any] | None:
    """Return an observed session-log window; never infer missing bounds."""
    candidates = (
        run_dir / f"{phase}.jsonl",
        run_dir / "semantic" / f"{phase}.jsonl",
    )
    path = next((candidate for candidate in candidates if candidate.is_file()), None)
    if path is None:
        return None
    rows = _load_jsonl(path)
    realtime = [
        row.get("timestamp_realtime_ns")
        for row in rows
        if isinstance(row.get("timestamp_realtime_ns"), int)
    ]
    if not realtime:
        return None
    return {
        "phase": phase,
        "source_path": str(path),
        "start_realtime_ns": min(realtime),
        "end_realtime_ns": max(realtime),
        "timestamped_record_count": len(realtime),
    }


def _raw_file_mutation_evidence(
    run_dir: Path,
    target_absolute: str,
    *,
    phase_window: dict[str, Any] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    evidence: dict[str, list[dict[str, Any]]] = {"inotify": [], "fanotify": []}
    for source, mask_bits in (
        ("inotify", INOTIFY_MUTATION_MASK),
        ("fanotify", FANOTIFY_MUTATION_MASK),
    ):
        path = run_dir / "raw" / f"{source}.jsonl"
        if not path.is_file():
            continue
        for row in _load_jsonl(path):
            mask = row.get("mask")
            if (
                _path_matches_target(row.get("path"), target_absolute)
                and isinstance(mask, int)
                and mask & mask_bits
                and _timestamp_in_phase_window(
                    row.get("timestamp_realtime_ns"), phase_window
                )
            ):
                evidence[source].append(
                    {
                        "timestamp_realtime_ns": row.get("timestamp_realtime_ns"),
                        "timestamp_monotonic_ns": row.get("timestamp_monotonic_ns"),
                        "mask": mask,
                        "pid": row.get("pid"),
                    }
                )
    return evidence


def _graph_state_write_evidence(
    run_dir: Path,
    target_absolute: str,
    *,
    phase_window: dict[str, Any] | None = None,
) -> dict[str, Any]:
    graph_roots = (
        run_dir / "stage_g_v6" / "normalized",
        run_dir / "graph" / "reattributed",
    )
    candidates = [
        root
        for root in graph_roots
        if (root / "syscalls.jsonl").is_file()
        and (root / "provenance.nodes.jsonl").is_file()
        and (root / "provenance.edges.jsonl").is_file()
    ]
    graph_root = candidates[0] if candidates else graph_roots[-1]
    syscall_path = graph_root / "syscalls.jsonl"
    node_path = graph_root / "provenance.nodes.jsonl"
    edge_path = graph_root / "provenance.edges.jsonl"
    syscalls = _load_jsonl(syscall_path) if syscall_path.is_file() else []
    nodes = _load_jsonl(node_path) if node_path.is_file() else []
    edges = _load_jsonl(edge_path) if edge_path.is_file() else []

    audit_write_rows = []
    for row in syscalls:
        syscall = row.get("syscall") or {}
        file_record = row.get("file") or {}
        sources = {
            item.get("source")
            for item in (row.get("evidence") or [])
            if isinstance(item, dict)
        }
        if (
            syscall.get("name") == "write"
            and syscall.get("success") is True
            and _path_matches_target(file_record.get("resolved_path"), target_absolute)
            and "auditd" in sources
            and _timestamp_in_phase_window(
                (row.get("order") or {}).get("timestamp_realtime_ns"),
                phase_window,
            )
        ):
            audit_write_rows.append(
                {
                    "event_id": row.get("event_id"),
                    "pid": (row.get("process") or {}).get("pid"),
                    "uid": (row.get("process") or {}).get("uid"),
                    "fd": (row.get("fd") or {}).get("input_fd"),
                    "return_value": syscall.get("return_value"),
                    "audit_serial": (row.get("order") or {}).get("audit_serial"),
                    "syscall_pid": (row.get("process") or {}).get("pid"),
                    "syscall_fd": (row.get("fd") or {}).get("input_fd"),
                    "syscall_exit": syscall.get("return_value"),
                    "syscall_byte_count": syscall.get("return_value"),
                    "syscall_arguments": syscall.get("arguments"),
                    "syscall_arguments_raw": syscall.get("arguments_raw"),
                    "evidence_sources": sorted(source for source in sources if source),
                }
            )

    target_nodes = [
        row
        for row in nodes
        if row.get("node_type") == "file"
        and _path_matches_target(
            (row.get("attributes") or {}).get("resolved_path"), target_absolute
        )
        and str(row.get("node_id") or "").startswith("file:")
    ]
    target_node_ids = {row.get("node_id") for row in target_nodes}
    write_edges = [
        row
        for row in edges
        if row.get("relation") == "write"
        and row.get("success") is True
        and row.get("destination_node_id") in target_node_ids
        and _timestamp_in_phase_window(
            (row.get("order") or {}).get("timestamp_realtime_ns"),
            phase_window,
        )
    ]
    identities: dict[str, set[int]] = {}
    for row in target_nodes:
        node_id = str(row.get("node_id") or "")
        base, separator, version_text = node_id.rpartition(":v")
        version = (row.get("attributes") or {}).get("version")
        if separator and isinstance(version, int) and version_text == str(version):
            identities.setdefault(base, set()).add(version)
    advancing = {
        base: sorted(versions)
        for base, versions in identities.items()
        if len(versions) >= 2
        and sorted(versions) == list(range(min(versions), max(versions) + 1))
    }
    return {
        "graph_root": str(graph_root),
        "audit_write_rows": audit_write_rows,
        "stable_target_node_ids": sorted(
            node_id for node_id in target_node_ids if node_id
        ),
        "write_edges": [
            {
                "edge_id": row.get("edge_id"),
                "destination_node_id": row.get("destination_node_id"),
                "byte_count": row.get("byte_count"),
            }
            for row in write_edges
        ],
        "advancing_version_chains": advancing,
        "stable_versions_by_identity": {
            base: sorted(versions) for base, versions in identities.items()
        },
    }



def _operation_transition_matches(
    change: dict[str, Any] | None, operation: str
) -> bool:
    if not isinstance(change, dict):
        return False
    before = change.get("before")
    after = change.get("after")
    if operation == "unlink":
        return isinstance(before, dict) and after is None
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    if operation == "truncate":
        return bool(
            isinstance(before.get("bytes"), int)
            and isinstance(after.get("bytes"), int)
            and after["bytes"] < before["bytes"]
            and before.get("mode") == after.get("mode")
            and before.get("sha256") != after.get("sha256")
        )
    if operation != "chmod":
        return False
    before_hash = before.get("sha256")
    after_hash = after.get("sha256")
    content_unchanged = (
        before_hash == after_hash
        if before_hash is not None and after_hash is not None
        else after.get("content_readable") is False
        and after.get("unreadable_reason") == "EACCES"
    )
    return bool(
        isinstance(before.get("mode"), int)
        and isinstance(after.get("mode"), int)
        and before["mode"] != after["mode"]
        and before.get("bytes") == after.get("bytes")
        and content_unchanged
    )


def _raw_operation_file_evidence(
    run_dir: Path, target_absolute: str, operation: str
) -> dict[str, Any]:
    expected_mask = OPERATION_INOTIFY_MASKS[operation]
    result: dict[str, Any] = {
        "expected_inotify_mask": expected_mask,
        "inotify_exact": [],
        "fanotify_target_observations": [],
    }
    inotify_path = run_dir / "raw" / "inotify.jsonl"
    if inotify_path.is_file():
        for row in _load_jsonl(inotify_path):
            mask = row.get("mask")
            if (
                _path_matches_target(row.get("path"), target_absolute)
                and isinstance(mask, int)
                and mask & expected_mask
            ):
                result["inotify_exact"].append({
                    "mask": mask,
                    "timestamp_realtime_ns": row.get("timestamp_realtime_ns"),
                    "timestamp_monotonic_ns": row.get("timestamp_monotonic_ns"),
                })
    fanotify_path = run_dir / "raw" / "fanotify.jsonl"
    if fanotify_path.is_file():
        for row in _load_jsonl(fanotify_path):
            if _path_matches_target(row.get("path"), target_absolute):
                result["fanotify_target_observations"].append({
                    "mask": row.get("mask"),
                    "pid": row.get("pid"),
                    "timestamp_realtime_ns": row.get("timestamp_realtime_ns"),
                    "timestamp_monotonic_ns": row.get("timestamp_monotonic_ns"),
                })
    return result


def _operation_candidate_ids(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {str(item) for item in value if item}
    return set()


def _syscall_integer_argument(syscall: dict[str, Any], name: str) -> int | None:
    arguments = syscall.get("arguments") or {}
    value = arguments.get(name) if isinstance(arguments, dict) else None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _operation_syscall_matches(syscall: dict[str, Any], operation: str) -> bool:
    name = str(syscall.get("name") or "")
    if name not in OPERATION_SYSCALLS[operation]:
        return False
    if operation != "truncate" or name in {"truncate", "ftruncate"}:
        return True
    flag_argument = "a1" if name == "open" else "a2"
    flags = _syscall_integer_argument(syscall, flag_argument)
    return isinstance(flags, int) and bool(flags & O_TRUNC)


def _graph_state_operation_evidence(
    run_dir: Path, target_absolute: str, operation: str
) -> dict[str, Any]:
    graph_roots = (
        run_dir / "stage_g_v6" / "normalized",
        run_dir / "graph" / "reattributed",
    )
    candidates = [
        root
        for root in graph_roots
        if (root / "syscalls.jsonl").is_file()
        and (root / "provenance.nodes.jsonl").is_file()
        and (root / "provenance.edges.jsonl").is_file()
    ]
    graph_root = candidates[0] if candidates else graph_roots[-1]
    syscalls = _load_jsonl(graph_root / "syscalls.jsonl") if (graph_root / "syscalls.jsonl").is_file() else []
    nodes = _load_jsonl(graph_root / "provenance.nodes.jsonl") if (graph_root / "provenance.nodes.jsonl").is_file() else []
    edges = _load_jsonl(graph_root / "provenance.edges.jsonl") if (graph_root / "provenance.edges.jsonl").is_file() else []

    operation_rows: list[dict[str, Any]] = []
    audit_rows: list[dict[str, Any]] = []
    for row in syscalls:
        syscall = row.get("syscall") or {}
        if not _operation_syscall_matches(syscall, operation) or syscall.get("success") is not True:
            continue
        sources = {
            item.get("source")
            for item in (row.get("evidence") or [])
            if isinstance(item, dict) and item.get("source")
        }
        summary = {
            "event_id": row.get("event_id"),
            "syscall_name": syscall.get("name"),
            "return_value": syscall.get("return_value"),
            "resolved_path": (row.get("file") or {}).get("resolved_path"),
            "evidence_sources": sorted(sources),
            "candidate_correlation_ids": sorted(
                _operation_candidate_ids(row.get("candidate_correlation_id"))
            ),
            "arguments_present": bool(
                syscall.get("arguments") or syscall.get("arguments_raw")
            ),
        }
        if operation == "truncate":
            summary.update({
                "file_dev": (row.get("file") or {}).get("dev"),
                "file_inode": (row.get("file") or {}).get("inode"),
                "identity_resolution_method": (row.get("file") or {}).get(
                    "identity_resolution_method"
                ),
            })
        operation_rows.append(summary)
        if (
            "auditd" in sources
            and _path_matches_target(summary["resolved_path"], target_absolute)
        ):
            audit_rows.append(summary)

    audit_ids = {str(row["event_id"]) for row in audit_rows if row.get("event_id")}
    linked_audit_ids: set[str] = set()
    correlated_scap_rows: list[dict[str, Any]] = []
    for row in operation_rows:
        sources = set(row["evidence_sources"])
        candidates_for_row = set(row["candidate_correlation_ids"])
        linked = candidates_for_row & audit_ids
        if (
            {"auditd", "scap"}.issubset(sources)
            and _path_matches_target(row["resolved_path"], target_absolute)
            and row.get("event_id")
        ):
            linked.add(str(row["event_id"]))
        if "scap" in sources and linked:
            linked_audit_ids.update(linked)
            correlated_scap_rows.append(row)

    target_nodes = [
        row
        for row in nodes
        if row.get("node_type") == "file"
        and _path_matches_target(
            (row.get("attributes") or {}).get("resolved_path"), target_absolute
        )
        and str(row.get("node_id") or "").startswith("file:")
        and not str(row.get("node_id") or "").startswith("file_unknown:")
    ]
    target_node_ids = {row.get("node_id") for row in target_nodes}
    relation = OPERATION_EDGE_RELATIONS.get(operation)
    operation_edges = [
        row
        for row in edges
        if relation is not None
        and row.get("relation") == relation
        and row.get("success") is True
        and row.get("destination_node_id") in target_node_ids
    ]
    target_rows = [
        row
        for row in operation_rows
        if _path_matches_target(row["resolved_path"], target_absolute)
    ]
    result = {
        "graph_root": str(graph_root),
        "audit_target_rows": audit_rows,
        "correlated_scap_rows": correlated_scap_rows,
        "audit_event_ids": sorted(audit_ids),
        "scap_linked_audit_event_ids": sorted(linked_audit_ids),
        "all_audit_events_scap_correlated": bool(audit_ids)
        and audit_ids.issubset(linked_audit_ids)
        and len(correlated_scap_rows) >= len(audit_ids),
        "stable_target_node_ids": sorted(
            str(node_id) for node_id in target_node_ids if node_id
        ),
        "operation_edges": [
            {
                "edge_id": row.get("edge_id"),
                "destination_node_id": row.get("destination_node_id"),
                "relation": row.get("relation"),
            }
            for row in operation_edges
        ],
    }
    if operation == "truncate":
        result.update({
            "ebpf_target_rows": [
                row for row in target_rows if "ebpf" in row["evidence_sources"]
            ],
            "target_file_identity_observed": any(
                row.get("file_dev") is not None and row.get("file_inode") is not None
                for row in target_rows
            ),
        })
    return result


def _validate_operation_specific_mutation(
    run_dir: Path, profile: dict[str, Any], checks: list[dict[str, Any]]
) -> None:
    operation = str(profile["mutation_operation"])
    ground_truth = _read_optional_json(run_dir / "ground_truth.json")
    changes = {
        str(row.get("path")): row
        for row in (ground_truth.get("state_changes_session_a") or [])
        if isinstance(row, dict) and row.get("path")
    }
    per_target: dict[str, Any] = {}
    for logical_path in profile.get(
        "operation_target_paths", profile["state_change_paths"]
    ):
        target_absolute = str(run_dir / "workspace" / logical_path)
        raw = _raw_operation_file_evidence(run_dir, target_absolute, operation)
        graph = _graph_state_operation_evidence(
            run_dir, target_absolute, operation
        )
        per_target[logical_path] = {
            "target_absolute": target_absolute,
            "snapshot_transition_exact": _operation_transition_matches(
                changes.get(logical_path), operation
            ),
            "raw_operation_evidence": raw,
            **graph,
        }

    requirements = {
        "operation_snapshot_transition_exact": lambda evidence: evidence["snapshot_transition_exact"],
        "operation_inotify_mask_present": lambda evidence: bool(
            evidence["raw_operation_evidence"]["inotify_exact"]
        ),
        "operation_fanotify_target_watch_observed": lambda evidence: bool(
            evidence["raw_operation_evidence"]["fanotify_target_observations"]
        ),
        "operation_auditd_target_syscall_present": lambda evidence: bool(
            evidence["audit_target_rows"]
        )
        and all(row["arguments_present"] for row in evidence["audit_target_rows"]),
        "operation_scap_syscall_correlation_present": lambda evidence: evidence[
            "all_audit_events_scap_correlated"
        ],
    }
    if operation == "truncate":
        requirements.update({
            "operation_ebpf_syscall_correlation_present": lambda evidence: bool(
                evidence["ebpf_target_rows"]
            ),
            "operation_stable_graph_target_present": lambda evidence: bool(
                evidence["stable_target_node_ids"]
                and evidence["target_file_identity_observed"]
            ),
        })
    else:
        requirements["operation_stable_graph_edge_present"] = lambda evidence: bool(
            evidence["stable_target_node_ids"] and evidence["operation_edges"]
        )
    requirement_results: dict[str, bool] = {}
    for name, predicate in requirements.items():
        passed = bool(per_target) and all(predicate(value) for value in per_target.values())
        requirement_results[name] = passed
        _add(
            checks,
            name,
            passed,
            operation=operation,
            per_target=per_target,
        )
    _add(
        checks,
        "operation_specific_mutation_correlation_exact",
        all(requirement_results.values()),
        operation=operation,
        evidence_roles=(
            {
                "snapshot": "exact recorded size-shrinking before/after transition",
                "inotify": "exact IN_MODIFY target mask",
                "fanotify": "target watch coverage for the truncating open",
                "auditd": "successful target-resolved truncate/ftruncate or open with O_TRUNC",
                "scap": "same syscall, merged or candidate-correlated to auditd",
                "ebpf": "same target-resolved truncating syscall evidence",
                "graph": "stable target node and observed dev/inode; no truncate edge is synthesized",
            }
            if operation == "truncate"
            else {
                "snapshot": "exact recorded before/after transition",
                "inotify": "exact IN_ATTRIB or IN_DELETE target mask",
                "fanotify": "target watch coverage; this collector exposes no ATTRIB/DELETE mask",
                "auditd": "successful target-resolved syscall with arguments",
                "scap": "same syscall, merged or candidate-correlated to auditd",
                "graph": "stable target node with successful operation edge",
                "ebpf": "collector health only; paired-live eBPF has no chmod/unlink hook",
            }
        ),
        requirement_results=requirement_results,
        per_target=per_target,
    )


def _absent_file_creation_version_observed(evidence: dict[str, Any]) -> bool:
    """Accept both observable version shapes for a newly created file.

    Depending on whether the graph observes the empty file immediately after
    ``open(O_CREAT)``, an absent preimage is represented either as ``v1`` at
    the first write or as an empty ``v0`` followed by write-created versions.
    The latter must be contiguous and must advance beyond ``v0``.
    """
    for versions in evidence["stable_versions_by_identity"].values():
        ordered = sorted(set(versions))
        if not ordered:
            continue
        if ordered[0] == 1:
            return True
        if (
            ordered[0] == 0
            and ordered[-1] >= 1
            and ordered == list(range(ordered[-1] + 1))
        ):
            return True
    return False


def _target_write_transition_matches(
    evidence: dict[str, Any],
    *,
    expected_after_bytes: Any,
    expected_before_present: Any,
    allow_split_creation: bool,
) -> dict[str, Any]:
    """Match a transition to auditd+SCAP writes and graph edges.

    A semantic ``write``/``edit`` target still needs one exact full-file write.
    An automatic companion may create an absent file through multiple writes
    (for example, a runtime create followed by a shell append). In that one
    case, the dual-source writes and versioned edges must each sum to the exact
    postimage size. A size-only projection never passes this gate.
    """
    if not isinstance(expected_after_bytes, int):
        return {
            "passed": False,
            "mode": "missing_expected_after_bytes",
            "matching_rows": [],
            "matching_edges": [],
        }

    dual_source_rows = [
        row
        for row in evidence["audit_write_rows"]
        if {"auditd", "scap"}.issubset(set(row.get("evidence_sources") or []))
        and isinstance(row.get("return_value"), int)
        and row.get("return_value") >= 0
    ]
    exact_rows = [
        row for row in dual_source_rows
        if row.get("return_value") == expected_after_bytes
    ]
    exact_edges = [
        edge for edge in evidence["write_edges"]
        if edge.get("byte_count") == expected_after_bytes
    ]
    multi_write_creation = (
        allow_split_creation
        and expected_before_present is False
        and (len(dual_source_rows) > 1 or len(evidence["write_edges"]) > 1)
    )
    if exact_rows and exact_edges and not multi_write_creation:
        return {
            "passed": True,
            "mode": "single_full_file_write",
            "matching_rows": exact_rows,
            "matching_edges": exact_edges,
            "observed_write_total": expected_after_bytes,
        }

    split_allowed = allow_split_creation and expected_before_present is False
    edge_counts = [
        edge.get("byte_count")
        for edge in evidence["write_edges"]
        if isinstance(edge.get("byte_count"), int) and edge.get("byte_count") >= 0
    ]
    row_counts = [row["return_value"] for row in dual_source_rows]
    stable_creation = _absent_file_creation_version_observed(evidence)
    split_matches = (
        split_allowed
        and len(row_counts) >= 2
        and len(edge_counts) >= 2
        and sum(row_counts) == expected_after_bytes
        and sum(edge_counts) == expected_after_bytes
        and sorted(row_counts) == sorted(edge_counts)
        and stable_creation
    )
    return {
        "passed": split_matches,
        "mode": (
            "split_absent_file_creation"
            if split_matches
            else "no_exact_observed_transition"
        ),
        "matching_rows": dual_source_rows if split_matches else [],
        "matching_edges": evidence["write_edges"] if split_matches else [],
        "observed_row_counts": row_counts,
        "observed_edge_counts": edge_counts,
        "observed_write_total": sum(row_counts),
        "expected_after_bytes": expected_after_bytes,
        "expected_before_present": expected_before_present,
        "stable_creation": stable_creation,
    }



def _validate_semantic_tool_mutation(
    run_dir: Path,
    profile: dict[str, Any],
    source_rows: dict[str, list[dict[str, Any]]],
    checks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Validate a semantic mutation without changing its normalizer.

    Historical semantic streams contain audit mutation rows only when the
    single live audit partition happened to carry the write. Stage-G instead
    normalizes the safety-attested declared-key union. When the semantic audit
    row is absent, require the other three semantic rows to correlate exactly
    and require the Stage-G union graph to prove the same target/byte-count
    write with auditd+SCAP evidence. This is a readiness projection only.
    """
    ids = {
        source: {row["correlation_id"] for row in _mutation_rows(rows)}
        for source, rows in source_rows.items()
    }
    semantic_sources = ("inotify", "fanotify", "ebpf")
    semantic_sets = [ids.get(source, set()) for source in semantic_sources]
    semantic_union = set().union(*semantic_sets) if semantic_sets else set()
    semantic_intersection = (
        set.intersection(*semantic_sets) if all(semantic_sets) else set()
    )
    semantic_exact = (
        bool(semantic_union) and semantic_union == semantic_intersection
    )
    all_source_sets = [ids.get(source, set()) for source in SOURCES]
    all_union = set().union(*all_source_sets) if all_source_sets else set()
    all_intersection = (
        set.intersection(*all_source_sets) if all(all_source_sets) else set()
    )
    legacy_exact = bool(all_union) and all_union == all_intersection

    per_target: dict[str, Any] = {}
    graph_rows: list[dict[str, Any]] = []
    semantic_writer_paths = set(profile.get("semantic_writer_paths") or [])
    for logical_path in profile["state_change_paths"]:
        target_absolute = str(run_dir / "workspace" / logical_path)
        expected_after_bytes = profile["expected_after_bytes"].get(logical_path)
        expected_before_present = profile["expected_before_present"].get(
            logical_path
        )
        evidence = _graph_state_write_evidence(run_dir, target_absolute)
        is_semantic_writer_target = logical_path in semantic_writer_paths
        transition = _target_write_transition_matches(
            evidence,
            expected_after_bytes=expected_after_bytes,
            expected_before_present=expected_before_present,
            allow_split_creation=not is_semantic_writer_target,
        )
        raw_evidence = _raw_file_mutation_evidence(run_dir, target_absolute)
        raw_companion_passed = (
            is_semantic_writer_target
            or (
                bool(raw_evidence["inotify"])
                and bool(raw_evidence["fanotify"])
            )
        )
        phase_window_scope: dict[str, Any] | None = None
        if not is_semantic_writer_target and not transition["passed"]:
            session_a_window = _session_phase_window(run_dir)
        else:
            session_a_window = None
        if session_a_window is not None:
            scoped_evidence = _graph_state_write_evidence(
                run_dir,
                target_absolute,
                phase_window=session_a_window,
            )
            scoped_transition = _target_write_transition_matches(
                scoped_evidence,
                expected_after_bytes=expected_after_bytes,
                expected_before_present=expected_before_present,
                allow_split_creation=True,
            )
            scoped_raw_evidence = _raw_file_mutation_evidence(
                run_dir,
                target_absolute,
                phase_window=session_a_window,
            )
            scoped_raw_passed = bool(scoped_raw_evidence["inotify"]) and bool(
                scoped_raw_evidence["fanotify"]
            )
            phase_window_scope = {
                **session_a_window,
                "reason": (
                    "automatic companion has writes outside the session-A "
                    "state-change window"
                ),
                "applied": bool(scoped_transition["passed"] and scoped_raw_passed),
                "unscoped_transition_evidence": transition,
                "scoped_raw_companion_passed": scoped_raw_passed,
            }
            if phase_window_scope["applied"]:
                evidence = scoped_evidence
                transition = scoped_transition
                raw_evidence = scoped_raw_evidence
                raw_companion_passed = scoped_raw_passed
        version_transition_passed = (
            bool(evidence["advancing_version_chains"])
            if expected_before_present is True
            else _absent_file_creation_version_observed(evidence)
            if expected_before_present is False
            else False
        )
        graph_rows.extend(transition["matching_rows"])
        per_target[logical_path] = {
            "target_absolute": target_absolute,
            "expected_after_bytes": expected_after_bytes,
            "expected_before_present": expected_before_present,
            "target_role": (
                "semantic_writer_target"
                if is_semantic_writer_target
                else "automatic_companion_state_write"
            ),
            "graph_root": evidence["graph_root"],
            "matching_audit_scap_write_rows": transition["matching_rows"],
            "matching_write_edges": transition["matching_edges"],
            "transition_evidence": transition,
            "raw_companion_file_mutations": {
                source: len(rows) for source, rows in raw_evidence.items()
            },
            "raw_companion_passed": raw_companion_passed,
            "advancing_version_chains": evidence["advancing_version_chains"],
            "stable_versions_by_identity": evidence[
                "stable_versions_by_identity"
            ],
            "version_transition_passed": version_transition_passed,
            "version_transition_mode": (
                "existing_file_contiguous_version_chain"
                if expected_before_present is True
                else "absent_file_created_as_stable_v1"
                if expected_before_present is False
                else "missing_before_state"
            ),
        }
        if phase_window_scope is not None:
            per_target[logical_path]["phase_window_scope"] = phase_window_scope
    union_graph_exact = (
        semantic_exact
        and bool(per_target)
        and all(
            value["transition_evidence"]["passed"]
            and value["raw_companion_passed"]
            and value["version_transition_passed"]
            for value in per_target.values()
        )
    )
    _add(
        checks,
        "four_source_mutation_correlation_exact",
        legacy_exact or union_graph_exact,
        correlation_mode=(
            "semantic_rows_all_four_sources"
            if legacy_exact
            else "semantic_three_source_plus_stage_g_union_audit_graph"
            if union_graph_exact
            else "unresolved"
        ),
        mutation_ids_by_source={
            source: len(ids.get(source, set())) for source in SOURCES
        },
        semantic_three_source_exact=semantic_exact,
        per_target=per_target,
    )
    return graph_rows


def _validate_automatic_runtime_write(
    run_dir: Path, profile: dict[str, Any], checks: list[dict[str, Any]]
) -> None:
    per_target: dict[str, Any] = {}
    for logical_path in profile["state_change_paths"]:
        target_absolute = str(run_dir / "workspace" / logical_path)
        raw_evidence = _raw_file_mutation_evidence(run_dir, target_absolute)
        graph_evidence = _graph_state_write_evidence(run_dir, target_absolute)
        expected_after_bytes = profile["expected_after_bytes"].get(logical_path)
        expected_before_present = profile["expected_before_present"].get(
            logical_path
        )
        per_target[logical_path] = {
            "target_absolute": target_absolute,
            "expected_after_bytes": expected_after_bytes,
            "expected_before_present": expected_before_present,
            "raw_file_mutations": {
                source: len(rows) for source, rows in raw_evidence.items()
            },
            **graph_evidence,
        }

    _add(
        checks,
        "automatic_state_write_raw_file_events_present",
        bool(per_target)
        and all(
            evidence["raw_file_mutations"]["inotify"] > 0
            and evidence["raw_file_mutations"]["fanotify"] > 0
            for evidence in per_target.values()
        ),
        per_target=per_target,
    )
    _add(
        checks,
        "automatic_state_write_auditd_write_rows_present",
        bool(per_target)
        and all(
            isinstance(evidence["expected_after_bytes"], int)
            and any(
                row["return_value"] == evidence["expected_after_bytes"]
                for row in evidence["audit_write_rows"]
            )
            for evidence in per_target.values()
        ),
        per_target={
            key: {
                "expected_after_bytes": value["expected_after_bytes"],
                "matching_rows": [
                    row
                    for row in value["audit_write_rows"]
                    if row["return_value"] == value["expected_after_bytes"]
                ],
                "all_audit_write_rows": value["audit_write_rows"],
            }
            for key, value in per_target.items()
        },
    )
    _add(
        checks,
        "automatic_state_write_stable_version_chain_advances",
        bool(per_target)
        and all(
            (
                evidence["advancing_version_chains"]
                if evidence["expected_before_present"] is True
                else any(
                    versions and min(versions) == 1
                    for versions in evidence[
                        "stable_versions_by_identity"
                    ].values()
                )
                if evidence["expected_before_present"] is False
                else False
            )
            and isinstance(evidence["expected_after_bytes"], int)
            and any(
                edge["byte_count"] == evidence["expected_after_bytes"]
                for edge in evidence["write_edges"]
            )
            for evidence in per_target.values()
        ),
        per_target={
            key: {
                "expected_after_bytes": value["expected_after_bytes"],
                "expected_before_present": value["expected_before_present"],
                "stable_target_node_ids": value["stable_target_node_ids"],
                "write_edges": value["write_edges"],
                "advancing_version_chains": value["advancing_version_chains"],
                "stable_versions_by_identity": value[
                    "stable_versions_by_identity"
                ],
                "transition_mode": (
                    "existing_file_contiguous_version_chain"
                    if value["expected_before_present"] is True
                    else "absent_file_created_as_stable_v1"
                    if value["expected_before_present"] is False
                    else "missing_before_state"
                ),
            }
            for key, value in per_target.items()
        },
    )


def _snapshot_manifest(root: Path) -> dict[str, str]:
    import hashlib

    if not root.is_dir():
        return {}
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _validate_no_state_change(run_dir: Path, checks: list[dict[str, Any]]) -> None:
    before = _snapshot_manifest(run_dir / "state_snapshots" / "before_a")
    after = _snapshot_manifest(run_dir / "state_snapshots" / "after_a")
    changed = sorted(
        set(before) ^ set(after)
        | {
            path
            for path in set(before) & set(after)
            if before[path] != after[path]
        }
    )
    _add(
        checks,
        "no_state_change_snapshot_equality",
        bool(before) and before == after,
        before_files=len(before),
        after_files=len(after),
        changed_paths=changed,
    )

def _validate_ebpf(rows: list[dict[str, Any]], checks: list[dict[str, Any]]) -> None:
    write_rows = [row for row in _mutation_rows(rows) if row.get("event") == "write"]
    _add(
        checks,
        "ebpf_write_prefix_capacity_frozen",
        all(((row.get("mutation") or {}).get("write_buffer") or {}).get("buffer_prefix_capacity_bytes") == EBPF_PREFIX_BYTES for row in write_rows),
        ebpf_write_rows=len(write_rows),
    )
    _add(
        checks,
        "ebpf_self_state_attribution_recorded",
        all(row.get("attribution_method") for row in write_rows),
        ebpf_write_rows=len(write_rows),
    )


def _validate_channel(run_dir: Path, checks: list[dict[str, Any]]) -> None:
    ground_truth = _read_optional_json(run_dir / "ground_truth.json")
    ingestion = ground_truth.get("ingestion") or {}
    route_a = ground_truth.get("route_a_anchor_evidence") or {}
    channel = _channel_from_ground_truth(run_dir)
    _add(checks, "delivery_channel_recorded", isinstance(channel, str) and bool(channel), channel=channel)

    if channel == "user_message":
        user_msg = ingestion.get("user_message_evidence") or route_a.get("user_message_provenance_evidence") or {}
        _add(checks, "user_message_no_filesystem_carrier_read", ingestion.get("carrier_read_observed") is False, carrier_read_observed=ingestion.get("carrier_read_observed"))
        _add(checks, "user_message_gateway_evidence_present", user_msg.get("all_user_message_evidence_passed") is True)
    elif channel == "external_content":
        bundle = _read_optional_json(run_dir / "raw_trace_bundle.json")
        access_log = bundle.get("fixture_http_access_log")
        access_rows = _load_jsonl(Path(access_log)) if isinstance(access_log, str) and Path(access_log).is_file() else []
        external_evidence = ingestion.get("external_content_evidence") or route_a.get("external_content_provenance_evidence") or {}
        _add(checks, "external_content_local_http_access_log_present", bool(access_rows), access_log=access_log)
        _add(
            checks,
            "external_content_http_loopback_only",
            bool(access_rows) and all(row.get("client_ip") in {"127.0.0.1", "::1"} and row.get("status") == 200 for row in access_rows),
            statuses=Counter(row.get("status") for row in access_rows),
        )
        _add(
            checks,
            "external_content_fetch_tool_evidence_present",
            external_evidence.get("all_external_content_evidence_passed") is True,
            evidence_checks=external_evidence.get("checks"),
        )
        _add(
            checks,
            "external_content_no_workspace_file_carrier_read",
            ingestion.get("carrier_read_observed") is False and ingestion.get("filesystem_ingestion_observable") is False,
            carrier_read_observed=ingestion.get("carrier_read_observed"),
            filesystem_ingestion_observable=ingestion.get("filesystem_ingestion_observable"),
        )
    elif channel == "supply_chain":
        delivery = ground_truth.get("delivery") or {}
        capture = _read_optional_json(run_dir / "auditd_capture_config.json")
        worker_pid = capture.get("worker_pid")
        delivery_rows = [row for row in (delivery.get("files") or []) if isinstance(row, dict)]
        process_types = [
            str(value)
            for value in [delivery.get("delivery_process_type"), delivery.get("fixture_process")]
            + [row.get("delivery_process_type") for row in delivery_rows]
            if value
        ]
        process_type = "; ".join(process_types)
        standard = any(token in process_type.lower() for token in ("pip", "tar", "package", "installer"))
        delivery_pids = sorted({row.get("pid") for row in delivery_rows if row.get("pid") is not None})
        independent_delivery_pids = [pid for pid in delivery_pids if pid != worker_pid]
        _add(checks, "supply_chain_separate_delivery_process_recorded", bool(process_types), delivery_process_type=process_type, delivery_process_types=process_types)
        _add(checks, "supply_chain_standard_local_install_mechanism", standard, delivery_process_type=process_type, delivery_process_types=process_types)
        _add(
            checks,
            "supply_chain_delivery_pid_independent_from_agent_worker",
            bool(independent_delivery_pids) and worker_pid is not None,
            worker_pid=worker_pid,
            delivery_pids=delivery_pids,
            independent_delivery_pids=independent_delivery_pids,
        )



def _validate_runtime_state_capture(run_dir: Path, checks: list[dict[str, Any]]) -> None:
    manifest_path = run_dir / "runtime_state_capture.json"
    manifest = _read_optional_json(manifest_path)
    _add(checks, "runtime_state_capture_manifest_present", manifest_path.is_file(), path=str(manifest_path))
    required_sections = (
        "process_state",
        "filesystem_state",
        "fd_state",
        "syscall_state",
        "policy_state",
        "snapshot_state",
        "agent_execution_state",
    )
    _add(
        checks,
        "runtime_state_capture_sections_complete",
        all(isinstance(manifest.get(section), dict) for section in required_sections),
        missing=[section for section in required_sections if not isinstance(manifest.get(section), dict)],
    )
    retained = set(manifest.get("retained_field_groups") or [])
    required_groups = {
        "pid_start_time_lineage_uid_auid_ses_cgroup_namespace",
        "self_state_path_inode_dev_mode_uid_gid_mtime_ctime_xattr",
        "open_flags_fd_inode_offset_close_lifetime_or_buffer_attribution",
        "syscall_args_return_errno_for_read_write_rename_unlink_chmod",
        "active_dac_immutable_apparmor_landlock_audit_network_policy_state",
        "before_after_consequence_snapshot_manifest_with_full_bytes",
        "tool_calls_session_logs_model_proxy_requests_and_gateway_messages",
    }
    _add(
        checks,
        "runtime_state_capture_retained_field_groups_complete",
        required_groups.issubset(retained),
        missing=sorted(required_groups - retained),
    )

def _validate_recovery_observability(run_dir: Path, checks: list[dict[str, Any]]) -> None:
    snapshots = run_dir / "state_snapshots"
    ground_truth = _read_optional_json(run_dir / "ground_truth.json")
    session_b = ground_truth.get("session_b") or {}
    _add(checks, "pre_attack_state_snapshot_present", (snapshots / "before_a").is_dir(), path=str(snapshots / "before_a"))
    _add(checks, "post_attack_state_snapshot_present", (snapshots / "after_a").is_dir(), path=str(snapshots / "after_a"))
    _add(checks, "post_consequence_state_snapshot_present", (snapshots / "after_b").is_dir(), path=str(snapshots / "after_b"))
    _add(checks, "session_b_consequence_recorded", "consequence_candidate_observed" in session_b, consequence=session_b.get("consequence_candidate_observed"))


def _is_five_source_run(run_dir: Path) -> bool:
    """A run collected with paired_live --five-source retains a SCAP capture."""
    return (run_dir / "raw" / "capture.scap").is_file()


def _validate_five_source(
    run_dir: Path,
    checks: list[dict[str, Any]],
    *,
    bridge_path: Path | None = None,
    effective_path: Path | None = None,
) -> None:
    """Gate the SCAP + provenance-graph additions on top of the four sources.

    Only fires for five-source runs; four-source runs are unaffected. The graph
    verdict is read from the five_source_graph_bridge manifest, whose file
    identity comes from libsinsp (the legacy fd resolver was refuted 72-0 on
    2026-08-19), with auditd retained only as the adjudication channel.
    """
    capture = run_dir / "raw" / "capture.scap"
    scap_stop = _read_optional_json(run_dir / "scap.stop.json")
    _add(
        checks, "scap_capture_present_and_valid",
        capture.is_file() and capture.stat().st_size > 0
        and scap_stop.get("valid") is True and scap_stop.get("drop_count") == 0,
        drop_count=scap_stop.get("drop_count"), valid=scap_stop.get("valid"),
    )
    lifecycle = run_dir / "raw" / "ebpf_lifecycle.jsonl"
    _add(checks, "ebpf_lifecycle_present", lifecycle.is_file() and lifecycle.stat().st_size > 0,
         path=str(lifecycle))

    bridge_path = bridge_path or (run_dir / "five_source_graph_bridge.json")
    bridge = _read_optional_json(bridge_path)
    _add(checks, "provenance_graph_bridge_ran", bool(bridge),
         path=str(bridge_path))
    # The acceptance line is measured on the resolution spine (SCAP/merged); the
    # raw coverage's provenance_evaluable is diluted by double-counted audit read
    # observations, so the graph-evaluable verdict follows the spine acceptance.
    acceptance = bridge.get("acceptance_line") or {}
    _add(checks, "provenance_graph_evaluable", acceptance.get("passed") is True,
         spine_rate=acceptance.get("spine_rate"), all_operand_rate=acceptance.get("all_operand_rate"))
    _add(checks, "fd_path_resolved_rate_acceptance_line", acceptance.get("passed") is True,
         threshold=acceptance.get("threshold"), spine_rate=acceptance.get("spine_rate"))
    effective_summary = bridge.get("coverage_resolution_spine_effective") or {}
    spine_summary = bridge.get("coverage_resolution_spine") or {}
    effective_path = effective_path or (
        run_dir / "graph/reattributed/resolution_spine_effective/coverage.json"
    )
    effective_artifact = _read_optional_json(effective_path)
    reconciled = (
        bridge.get("schema_version") == "assa.five_source_graph_bridge.v2"
        and effective_summary.get("provenance_evaluable") is acceptance.get("passed")
        and effective_artifact.get("coverage_view") == "resolution_spine_effective"
        and effective_artifact.get("provenance_evaluable") is acceptance.get("passed")
        and effective_artifact.get("writes_excluded") == 0
        and spine_summary.get("writes_excluded") == 0
    )
    _add(
        checks, "raw_effective_coverage_reconciled", reconciled,
        artifact=str(effective_path),
        raw_provenance_evaluable=(bridge.get("coverage_post_reattribution") or {}).get("provenance_evaluable"),
        effective_provenance_evaluable=effective_summary.get("provenance_evaluable"),
        writes_excluded=effective_artifact.get("writes_excluded"),
    )
    _add(checks, "file_identity_from_libsinsp", bridge.get("file_identity_source") == "libsinsp",
         source=bridge.get("file_identity_source"))


def validate_run(
    run_dir: Path, *, five_source_overlay: Path | None = None
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    profile = _readiness_profile(run_dir)
    _add(
        checks,
        "readiness_outcome_profile_valid",
        profile["name"] != "invalid_attempt",
        profile=profile,
    )
    require_semantic_mutation = profile["name"] in {
        "attack_landed",
        "semantic_tool_mutation",
    }
    source_rows = _validate_four_source_bundle(
        run_dir,
        checks,
        require_semantic_mutation=require_semantic_mutation,
    )
    graph_audit_write_rows: list[dict[str, Any]] = []
    if require_semantic_mutation:
        graph_audit_write_rows = _validate_semantic_tool_mutation(
            run_dir, profile, source_rows, checks
        )
    _validate_auditd_capture(
        run_dir,
        source_rows.get("auditd", []),
        checks,
        require_semantic_mutation=require_semantic_mutation,
        graph_audit_write_rows=graph_audit_write_rows,
    )
    if profile.get("mutation_operation") in OPERATION_SYSCALLS:
        _validate_operation_specific_mutation(run_dir, profile, checks)
    elif profile["name"] == "automatic_runtime_state_write":
        _validate_automatic_runtime_write(run_dir, profile, checks)
    elif profile["name"] == "no_state_change":
        _validate_no_state_change(run_dir, checks)
    _validate_ebpf(source_rows.get("ebpf", []), checks)
    _validate_channel(run_dir, checks)
    _validate_runtime_state_capture(run_dir, checks)
    _validate_recovery_observability(run_dir, checks)
    five_source = _is_five_source_run(run_dir)
    if five_source:
        overlay = five_source_overlay.resolve() if five_source_overlay else None
        _validate_five_source(
            run_dir,
            checks,
            bridge_path=(overlay / "five_source_graph_bridge.json") if overlay else None,
            effective_path=(
                overlay / "graph/reattributed/resolution_spine_effective/coverage.json"
            ) if overlay else None,
        )
    failed = [check for check in checks if not check["passed"]]
    return {
        "schema_version": "assa.recollection_readiness.v2",
        "run_dir": str(run_dir.resolve()),
        "readiness_profile": profile,
        "passed": not failed,
        "failed_checks": failed,
        "checks": checks,
        "five_source_run": five_source,
        "five_source_overlay": str(five_source_overlay.resolve()) if five_source_overlay else None,
        "experiment_support": {
            "detection_main_table": not failed,
            "provenance": not failed and _channel_from_ground_truth(run_dir) != "user_message",
            "provenance_graph_evaluable": five_source and not failed,
            "provenance_graph_note": "graph/UNICORN/STIDE/acceptance-line require a five-source run whose SCAP capture cleared the acceptance line; four-source runs cannot support them",
            "provenance_note": "user_message has gateway/model-request provenance but no OS-visible carrier read",
            "recovery_input_observability": any(check["name"] == "post_consequence_state_snapshot_present" and check["passed"] for check in checks),
            "prevention": "requires separate interventional run under active kernel policy; observational readiness is not sufficient",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate a recollected branch under its recorded outcome profile."
    )
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--five-source-overlay",
        type=Path,
        help="derived v2 bridge root; keeps original run artifacts immutable",
    )
    args = parser.parse_args()
    report = validate_run(args.run_dir, five_source_overlay=args.five_source_overlay)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "failed": [row["name"] for row in report["failed_checks"]]}, indent=2, sort_keys=True))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
