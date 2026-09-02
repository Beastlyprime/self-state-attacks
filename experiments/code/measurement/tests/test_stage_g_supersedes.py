from __future__ import annotations

import json
from pathlib import Path

from measurement.stage_g_harness import PROVENANCE_EDGE_SCHEMA_VERSION
from measurement.stage_g_harness.normalize import Normalizer, ProvenanceBuilder


def _event(
    serial: int,
    syscall: int,
    *,
    records: list[str],
    args: tuple[str, str, str, str] = ("0", "0", "0", "0"),
    exit_value: int = 0,
) -> str:
    timestamp = f"1700000000.{serial:03d}"
    lines = [
        f'type=SYSCALL msg=audit({timestamp}:{serial}): arch=c000003e '
        f'syscall={syscall} success=yes exit={exit_value} '
        f'a0={args[0]} a1={args[1]} a2={args[2]} a3={args[3]} '
        'a4=0 a5=0 ppid=1 pid=100 auid=1000 uid=2001 euid=2001 '
        'gid=2001 comm="benign" exe="/usr/bin/benign" key="clean"'
    ]
    lines.extend(records)
    lines.append(f"type=EOE msg=audit({timestamp}:{serial}):")
    return "\n".join(lines)


def _path(serial: int, item: int, name: str, inode: int, nametype: str) -> str:
    return (
        f'type=PATH msg=audit(1700000000.{serial:03d}:{serial}): item={item} '
        f'name="{name}" inode={inode} dev=08:01 mode=0100600 nametype={nametype}'
    )


def _normalize(tmp_path: Path, events: list[str]) -> dict:
    audit = tmp_path / "audit.log"
    audit.write_text("\n".join(events) + "\n", encoding="utf-8")
    return Normalizer(
        run_id="clean-supersedes",
        boot_id="boot-clean",
        runner_uid=2001,
        process_catalog={"100": {"process_start_time_ticks": 500}},
    ).normalize(audit, tmp_path / "normalized")


def _supersedes(result: dict) -> list[dict]:
    return [
        edge for edge in result["graph"]["edges"]
        if edge["relation"] == "supersedes"
    ]


def _node(result: dict, node_id: str) -> dict:
    return next(node for node in result["graph"]["nodes"] if node["node_id"] == node_id)


def test_rename_overwrite_builds_evidence_backed_supersedes_edge(tmp_path: Path) -> None:
    target = "/tmp/clean/state.json"
    result = _normalize(tmp_path, [_event(10, 82, records=[
        _path(10, 0, "/tmp/clean/", 1, "PARENT"),
        _path(10, 1, "/tmp/clean/", 1, "PARENT"),
        _path(10, 2, "/tmp/clean/.state.tmp", 20, "DELETE"),
        _path(10, 3, target, 10, "DELETE"),
        _path(10, 4, target, 20, "CREATE"),
    ])])

    edges = _supersedes(result)
    assert len(edges) == 1
    edge = edges[0]
    assert edge["schema_version"] == "assa.provenance_edge.v3"
    assert edge["supersede_resolution_status"] == "resolved_rename_overwrite"
    assert edge["supersede_evidence"]["audit_serial"] == "10"
    assert edge["supersede_evidence"]["old_path_record"]["item"] == 3
    assert edge["supersede_evidence"]["new_path_record"]["item"] == 4
    assert _node(result, edge["source_node_id"])["attributes"]["inode"] == 10
    assert _node(result, edge["destination_node_id"])["attributes"]["inode"] == 20
    assert result["coverage"]["schema_version"] == "assa.provenance_coverage.v3"
    assert result["coverage"]["provenance_schema"] == {
        "node_schema_version": "assa.provenance_node.v2",
        "edge_schema_version": "assa.provenance_edge.v3",
        "supersedes_supported": True,
        "supersedes_enabled": True,
        "supersedes_artifact": "provenance.supersedes.json",
        "supersedes_schema_version": "assa.provenance_supersedes.v1",
        "supersedes_edge_count": 1,
        "supersedes_status_counts": {"resolved_rename_overwrite": 1},
    }
    artifact = json.loads(
        (tmp_path / "normalized/provenance.supersedes.json").read_text(encoding="utf-8")
    )
    assert artifact["temporal_proximity_inference"] is False
    assert artifact["edge_count"] == 1
    assert PROVENANCE_EDGE_SCHEMA_VERSION == "assa.provenance_edge.v3"


def test_unlink_exact_path_open_create_builds_supersedes_edge(tmp_path: Path) -> None:
    target = "/tmp/clean/state.json"
    result = _normalize(tmp_path, [
        _event(20, 87, records=[
            _path(20, 0, "/tmp/clean/", 1, "PARENT"),
            _path(20, 1, target, 10, "DELETE"),
        ]),
        _event(21, 257, exit_value=3, args=("ffffff9c", "7fff", "c1", "180"), records=[
            _path(21, 0, "/tmp/clean/", 1, "PARENT"),
            _path(21, 1, target, 20, "CREATE"),
        ]),
    ])

    edges = _supersedes(result)
    assert len(edges) == 1
    edge = edges[0]
    assert edge["supersede_resolution_status"] == "resolved_unlink_recreate"
    assert edge["supersede_evidence"]["unlink_audit_serial"] == "20"
    assert edge["supersede_evidence"]["create_audit_serial"] == "21"
    assert [item["audit_serial"] for item in edge["evidence"]] == ["20", "21"]
    assert _node(result, edge["source_node_id"])["attributes"]["inode"] == 10
    assert _node(result, edge["destination_node_id"])["attributes"]["inode"] == 20


def test_unlink_recreate_path_must_be_byte_exact(tmp_path: Path) -> None:
    result = _normalize(tmp_path, [
        _event(30, 87, records=[_path(30, 0, "/tmp/clean/state.json", 10, "DELETE")]),
        _event(31, 257, exit_value=3, args=("ffffff9c", "7fff", "c1", "180"), records=[
            _path(31, 0, "/tmp/clean/./state.json", 20, "CREATE")
        ]),
    ])
    assert _supersedes(result) == []
    assert result["graph"]["supersedes"]["status_counts"] == {
        "unlink_without_subsequent_exact_path_recreate": 1
    }


def test_intervening_same_path_operation_blocks_unlink_recreate(tmp_path: Path) -> None:
    target = "/tmp/clean/state.json"
    result = _normalize(tmp_path, [
        _event(40, 87, records=[_path(40, 0, target, 10, "DELETE")]),
        _event(41, 90, records=[_path(41, 0, target, 10, "NORMAL")]),
        _event(42, 257, exit_value=3, args=("ffffff9c", "7fff", "c1", "180"), records=[
            _path(42, 0, target, 20, "CREATE")
        ]),
    ])
    assert _supersedes(result) == []
    outcome = result["graph"]["supersedes"]["outcomes"][0]
    assert outcome["supersede_resolution_status"] == (
        "unlink_recreate_interrupted_by_same_path_event"
    )
    assert outcome["interfering_event_id"].endswith(":audit:41")


def test_unlink_without_recreate_remains_explicitly_unresolved(tmp_path: Path) -> None:
    result = _normalize(tmp_path, [
        _event(50, 87, records=[_path(50, 0, "/tmp/clean/state.json", 10, "DELETE")])
    ])
    assert _supersedes(result) == []
    outcome = result["graph"]["supersedes"]["outcomes"][0]
    assert outcome["supersede_resolution_status"] == (
        "unlink_without_subsequent_exact_path_recreate"
    )


def test_rename_missing_before_after_evidence_does_not_supersede(tmp_path: Path) -> None:
    result = _normalize(tmp_path, [
        _event(60, 82, records=[
            _path(60, 0, "/tmp/clean/state.json", 20, "CREATE")
        ])
    ])
    assert _supersedes(result) == []
    outcome = result["graph"]["supersedes"]["outcomes"][0]
    assert outcome["supersede_resolution_status"] == "rename_path_evidence_incomplete"


def test_builder_ablation_removes_only_additive_supersedes_relation(tmp_path: Path) -> None:
    target = "/tmp/clean/state.json"
    result = _normalize(tmp_path, [_event(70, 82, records=[
        _path(70, 0, "/tmp/clean/", 1, "PARENT"),
        _path(70, 1, "/tmp/clean/", 1, "PARENT"),
        _path(70, 2, "/tmp/clean/.state.tmp", 20, "DELETE"),
        _path(70, 3, target, 10, "DELETE"),
        _path(70, 4, target, 20, "CREATE"),
    ])])
    ablated = ProvenanceBuilder(
        "clean-supersedes", enable_supersedes=False
    ).build(result["syscalls"])
    retained = [
        edge["relation"] for edge in result["graph"]["edges"]
        if edge["relation"] != "supersedes"
    ]
    assert [edge["relation"] for edge in ablated["edges"]] == retained
    assert ablated["supersedes"]["enabled"] is False
    assert ablated["supersedes"]["edge_count"] == 0
    assert ablated["supersedes"]["outcomes"] == []
