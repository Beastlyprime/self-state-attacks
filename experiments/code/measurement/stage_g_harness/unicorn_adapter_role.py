"""UNICORN generation-5 adapter with arm-blind, role-only node types.

The graph topology, node identities, relation types, and event order are kept
unchanged.  Only the node type descriptor changes: it is the role assigned by
``unicorn_role_typing`` rather than a path-derived value.  This is the adapter
preregistered in ``paper/P2_UNICORN_GEN5_ROLE_TYPING_PREREGISTRATION_20260823.md``.
"""
from __future__ import annotations

import json
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Iterable

import xxhash

from .io import write_json
from .unicorn_role_typing import (
    assign_role,
    canonical_path,
    g1_arm_blind,
    g3_non_degenerate,
)


SCHEMA_VERSION = "assa.unicorn_adapter.role.v1"
TYPING_VARIANT = "ROLE_ONLY"
ROLE_TABLE_VERSION = "assa.unicorn_role_table.v1.1-final-amendment"
_ATTACHMENT_SUFFIXES = {
    ".csv", ".doc", ".docx", ".json", ".md", ".pdf", ".rtf", ".txt", ".xlsx",
}


def _hash(parts: Iterable[str]) -> int:
    hasher = xxhash.xxh64()
    for part in parts:
        hasher.update(part)
    return hasher.intdigest()


def assign_role_final(node: dict[str, Any]) -> str:
    """Apply three table-completion rules recorded before model scoring."""
    attrs = node.get("attributes") or {}
    raw = attrs.get("resolved_path") or attrs.get("exe") or attrs.get("raw_path") or ""
    path = canonical_path(raw)
    if path.startswith("/lib64/"):
        return "system.library"
    if path == "stage_g_v6" or path.startswith("stage_g_v6/"):
        return "apparatus.collection"
    if (
        node.get("node_type", "").startswith("file")
        and path
        and not path.startswith("/")
        and "/" not in path
        and PurePosixPath(path).suffix.lower() in _ATTACHMENT_SUFFIXES
    ):
        return "external_input"
    return assign_role(node)


def adapt_records(
    nodes_iter: Iterable[dict[str, Any]],
    edges_iter: Iterable[dict[str, Any]],
    output_dir: Path,
    coverage: dict[str, Any] | None,
    *,
    source_description: str,
) -> dict[str, Any]:
    """Write an official-UNICORN edgelist from normalized graph records."""
    nodes = {row["node_id"]: row for row in nodes_iter}
    edges = sorted(
        edges_iter,
        key=lambda row: ((row.get("order") or {}).get("merged", 0), row["edge_id"]),
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    prepared = output_dir / "assa.edgelist"

    roles = {node_id: assign_role_final(node) for node_id, node in nodes.items()}
    g1 = g1_arm_blind(roles.values())
    # Match the pilot definition: the histogram is over edge endpoints, not
    # merely over the set of graph nodes.
    emitted_roles: list[str] = []
    node_mapping: dict[str, dict[str, Any]] = {}
    edge_types: dict[str, int] = {}
    with prepared.open("w", encoding="ascii") as handle:
        for logical_order, edge in enumerate(edges, 1):
            source_id_raw = edge["source_node_id"]
            target_id_raw = edge["destination_node_id"]
            if source_id_raw not in nodes or target_id_raw not in nodes:
                raise RuntimeError(f"edge {edge['edge_id']} references an absent node")
            source_role = roles[source_id_raw]
            target_role = roles[target_id_raw]
            emitted_roles.extend((source_role, target_role))
            relation = str(edge.get("relation") or "other")
            source_id = _hash([source_id_raw])
            target_id = _hash([target_id_raw])
            source_type = _hash([source_role])
            target_type = _hash([target_role])
            edge_type = edge_types.setdefault(relation, _hash([relation, "N/A"]))
            handle.write(
                f"{source_id}\t{target_id}\t"
                f"{source_type}:{target_type}:{edge_type}:{logical_order}\n"
            )
            node_mapping[source_id_raw] = {
                "unicorn_id": source_id,
                "unicorn_type": source_type,
                "role": source_role,
            }
            node_mapping[target_id_raw] = {
                "unicorn_id": target_id,
                "unicorn_type": target_type,
                "role": target_role,
            }

    node_hashes = [value["unicorn_id"] for value in node_mapping.values()]
    if len(node_hashes) != len(set(node_hashes)):
        raise RuntimeError("xxhash collision in UNICORN node identities")
    if len(edge_types.values()) != len(set(edge_types.values())):
        raise RuntimeError("xxhash collision in UNICORN relation types")

    coverage = coverage or {}
    fd_rate = coverage.get("fd_path_resolved_rate")
    threshold = coverage.get("fd_path_resolved_threshold", 0.95)
    provenance_evaluable = bool(
        coverage.get("provenance_evaluable")
        and fd_rate is not None
        and fd_rate >= threshold
    )
    g3 = g3_non_degenerate(emitted_roles)
    run_ids = sorted({str(node.get("run_id")) for node in nodes.values() if node.get("run_id")})
    report = {
        "schema_version": SCHEMA_VERSION,
        "role_table_version": ROLE_TABLE_VERSION,
        "typing_variant": TYPING_VARIANT,
        "source_description": source_description,
        "input_nodes": len(nodes),
        "input_edges": len(edges),
        "output_edges": len(edges),
        "dropped_edges": 0,
        "prepared_edgelist": str(prepared.resolve()),
        "node_roles": node_mapping,
        "edge_types": edge_types,
        "role_vocabulary": sorted(set(roles.values())),
        "g1_arm_blindness": g1,
        "g3_non_degeneracy": g3,
        "run_ids": run_ids,
        "fd_path_resolved_rate": fd_rate,
        "fd_path_resolved_threshold": threshold,
        "provenance_evaluable": provenance_evaluable,
        "status": "passed" if provenance_evaluable and g1["passed"] and g3["passed"] else "data_insufficient",
        "status_basis": "coverage_and_preregistered_G1_G3",
        "hash_implementation": f"xxhash {getattr(xxhash, 'VERSION', 'unknown')}",
    }
    write_json(output_dir / "adapter_report.json", report)
    return report


def _read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def adapt_graph(
    nodes_path: Path,
    edges_path: Path,
    output_dir: Path,
    coverage_path: Path | None = None,
) -> dict[str, Any]:
    selected_coverage = coverage_path or nodes_path.with_name("coverage.json")
    coverage = (
        json.loads(selected_coverage.read_text(encoding="utf-8"))
        if selected_coverage.is_file()
        else None
    )
    return adapt_records(
        _read_jsonl(nodes_path),
        _read_jsonl(edges_path),
        output_dir,
        coverage,
        source_description=str(nodes_path.resolve()),
    )
