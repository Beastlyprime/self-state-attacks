"""Rebuild the provenance graph with file identity taken from libsinsp.

Kernel evidence refuted our resolver's per-event file attribution (72-0 on the
decidable disputed events; see
``data/stage_g_libsinsp_comparison_clean_20260819/ADJUDICATION.md``).
This replaces the refuted part and nothing else.

**Only the ``file`` block is replaced.** Process identity is left as-is: libsinsp
reports ``proc.pid.ts`` on only 3.4% of events in capture replay, so it does not
supply process-instance identity, and the existing eBPF/audit-derived identity
remains the better source. Scope the correction to what was actually refuted.

Rows are joined on ``(pid, timestamp_realtime_ns, syscall_name)``, the key that
matched 4679 of 4679 of our SCAP-derived rows with no duplicate keys on either
side.
"""

from __future__ import annotations

import argparse
import bisect
import collections
import json
from pathlib import Path
from typing import Any

from .normalize import ProvenanceBuilder, build_coverage, READ_CALLS, WRITE_CALLS
from .io import write_json


SCHEMA_VERSION = "assa.libsinsp_reattribution.v1"

# File read/write operands, matching build_coverage's fd_path denominator
# (truncate carries no fd operand there).
_FD_OPERAND_CALLS = READ_CALLS | (WRITE_CALLS - {"truncate"})


def _key(row: dict[str, Any]) -> tuple:
    order = row.get("order") or {}
    process = row.get("process") or {}
    return (process.get("pid"),
            order.get("timestamp_realtime_ns"),
            (row.get("syscall") or {}).get("name"))


def _dev_string(major: int | None, minor: int | None) -> str | None:
    """Render dev as the ``fd:01`` hex form the graph's identity string uses."""
    if major is None or minor is None:
        return None
    return f"{major:02x}:{minor:02x}"


def reattribute(rows: list[dict[str, Any]],
                libsinsp_events: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return rows with libsinsp file identity substituted, plus a change report.

    A row is rewritten only where libsinsp supplies an inode. Where it does not,
    the original block is kept unchanged rather than blanked -- withdrawing
    identity we already had would trade one error for another.
    """
    index = {_key(event): event for event in libsinsp_events}
    stats = collections.Counter()
    corrected: list[dict[str, Any]] = []
    changes: list[dict[str, Any]] = []

    for row in rows:
        event = index.get(_key(row))
        if event is None:
            stats["no_libsinsp_counterpart"] += 1
            corrected.append(row)
            continue

        lib_file = event.get("file") or {}
        inode = lib_file.get("inode")
        if inode is None:
            stats["libsinsp_has_no_inode"] += 1
            corrected.append(row)
            continue

        original = row.get("file") or {}
        dev = _dev_string(lib_file.get("dev_major"), lib_file.get("dev_minor"))
        new_file = {
            **original,
            "path": lib_file.get("path"),
            "resolved_path": lib_file.get("path"),
            "inode": inode,
            "dev": dev,
            "resolution_method": "libsinsp_fd_table",
            "resolution_status": "libsinsp",
            "superseded_attribution": {
                "path": original.get("resolved_path") or original.get("path") or original.get("raw_path"),
                "inode": original.get("inode"),
                "dev": original.get("dev"),
                "resolution_method": original.get("resolution_method"),
            } if original else None,
        }

        prev_path = original.get("resolved_path") or original.get("path") or original.get("raw_path")
        prev_inode = original.get("inode")
        # Distinguish an identity we got *wrong* from one we simply lacked.
        # Conflating them would overstate the correction.
        if prev_inode is None and prev_path is None:
            stats["filled_previously_unresolved"] += 1
        elif prev_inode is None:
            stats["inode_added_to_existing_path"] += 1
            if prev_path is not None and prev_path != lib_file.get("path"):
                stats["path_also_changed"] += 1
        elif str(prev_inode) != str(inode):
            stats["identity_corrected"] += 1
            if len(changes) < 200:
                changes.append({
                    "event_id": row.get("event_id"),
                    "syscall": (row.get("syscall") or {}).get("name"),
                    "was": {"path": prev_path, "inode": prev_inode},
                    "now": {"path": lib_file.get("path"), "inode": inode},
                })
        else:
            stats["unchanged"] += 1

        corrected.append({**row, "file": new_file})

    bracket_stats = _resolve_via_fd_bracket(corrected, libsinsp_events)
    merged = dict(stats)
    merged.update(bracket_stats)
    return corrected, {"counts": merged, "corrections_sample": changes}


def _resolve_via_fd_bracket(rows: list[dict[str, Any]],
                            libsinsp_events: list[dict[str, Any]]) -> dict[str, int]:
    """Resolve file read/write operands the exact-key join could not, in place.

    The exact ``(pid, ts, syscall)`` join only matches SCAP-derived rows against
    libsinsp; audit-derived rows carry a different-source timestamp and never
    match, so their fd operands stay unresolved even though libsinsp holds the
    fd->file binding (e.g. every ``fd=3`` library read). This pass resolves such
    a row via libsinsp's own ``(pid, fd)`` timeline, but only when the libsinsp
    events *bracketing* the read -- the nearest one before and the nearest one
    after on the same ``(pid, fd)`` -- agree on the same ``(inode, dev)``. That
    is fd-reuse-safe: a rebind between the brackets makes them disagree and the
    row is left unresolved rather than bound by mere temporal proximity (the
    substitution failure mode recorded in the findings' section 7).
    """
    timeline: dict[tuple, list[tuple]] = collections.defaultdict(list)
    for event in libsinsp_events:
        fd = event.get("fd") or {}
        lib_file = event.get("file") or {}
        fd_num, inode = fd.get("num"), lib_file.get("inode")
        if fd.get("type") != "file" or fd_num is None or inode is None:
            continue
        pid = (event.get("process") or {}).get("pid")
        ts = (event.get("order") or {}).get("timestamp_realtime_ns")
        if pid is None or ts is None:
            continue
        dev = _dev_string(lib_file.get("dev_major"), lib_file.get("dev_minor"))
        timeline[(pid, fd_num)].append((ts, inode, dev, lib_file.get("path")))
    for entries in timeline.values():
        entries.sort(key=lambda item: item[0])

    stats: collections.Counter = collections.Counter()
    for row in rows:
        syscall = row.get("syscall") or {}
        if not syscall.get("success") or syscall.get("name") not in _FD_OPERAND_CALLS:
            continue
        fd = row.get("fd") or {}
        fd_num = fd.get("input_fd")
        if fd_num is None or row.get("socket"):
            continue
        current = row.get("file") or {}
        if current.get("inode") is not None and current.get("dev") is not None:
            continue  # already resolved (exact-key pass or normalizer)
        pid = (row.get("process") or {}).get("pid")
        ts = (row.get("order") or {}).get("timestamp_realtime_ns")
        entries = timeline.get((pid, fd_num))
        if not entries or ts is None:
            stats["fd_bracket_no_timeline"] += 1
            continue
        idx = bisect.bisect_left([item[0] for item in entries], ts)
        before = entries[idx - 1] if idx > 0 else None
        after = entries[idx] if idx < len(entries) else None
        if not (before and after) or (before[1], before[2]) != (after[1], after[2]):
            stats["fd_bracket_ambiguous"] += 1
            continue
        _, inode, dev, path = before
        row["file"] = {
            **current,
            "path": path,
            "resolved_path": path,
            "inode": inode,
            "dev": dev,
            "resolution_method": "libsinsp_fd_bracket",
            "resolution_status": "libsinsp_fd_bracket",
            "superseded_attribution": {
                "path": current.get("resolved_path") or current.get("path") or current.get("raw_path"),
                "inode": current.get("inode"),
                "dev": current.get("dev"),
                "resolution_method": current.get("resolution_method"),
            } if current else None,
        }
        stats["fd_bracket_resolved"] += 1
    return dict(stats)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rows", type=Path, required=True, help="normalized syscalls.jsonl")
    ap.add_argument("--libsinsp", type=Path, required=True, help="libsinsp_events.jsonl")
    ap.add_argument("--output-dir", type=Path, required=True)
    ap.add_argument("--run-id", required=True)
    args = ap.parse_args()

    rows = [json.loads(line) for line in args.rows.open(encoding="utf-8")]
    events = [json.loads(line) for line in args.libsinsp.open(encoding="utf-8")]
    corrected, report = reattribute(rows, events)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    with (args.output_dir / "syscalls.jsonl").open("w", encoding="utf-8") as handle:
        for row in corrected:
            handle.write(json.dumps(row, sort_keys=True) + "\n")

    graph = ProvenanceBuilder(args.run_id).build(corrected)
    coverage = build_coverage(corrected, graph, [])

    for name, payload in (("provenance.nodes.jsonl", graph["nodes"]),
                          ("provenance.edges.jsonl", graph["edges"])):
        with (args.output_dir / name).open("w", encoding="utf-8") as handle:
            for item in payload:
                handle.write(json.dumps(item, sort_keys=True) + "\n")

    write_json(args.output_dir / "coverage.json", coverage)
    write_json(args.output_dir / "reattribution_report.json",
               {"schema_version": SCHEMA_VERSION, **report})

    print(json.dumps({
        "reattribution": report["counts"],
        "fd_path_resolved_rate": coverage.get("fd_path_resolved_rate"),
        "fd_path_resolved": [coverage.get("fd_path_resolved_numerator"),
                             coverage.get("fd_path_operand_denominator")],
        "provenance_evaluable": coverage.get("provenance_evaluable"),
        "unknown_node_fraction": coverage.get("unknown_node_fraction"),
        "nodes": len(graph["nodes"]), "edges": len(graph["edges"]),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
