"""Compare our normalizer's file attribution against libsinsp's, event by event.

Both streams derive from the same SCAP capture, so they can be joined exactly
rather than compared as aggregate rates. The join key is
``(pid, timestamp_realtime_ns, syscall_name)``: nanosecond timestamps taken from
the same capture make accidental collisions implausible, and the joiner asserts
key uniqueness within each stream instead of assuming it.

This reports disagreement. It does **not** decide which side is correct --
neither stream is ground truth for the other. Adjudication needs independent
evidence, for which auditd PATH records (dev/inode straight from the kernel) are
the intended source.
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "assa.libsinsp_comparison.v1"


def _key(row: dict[str, Any]) -> tuple:
    order = row.get("order") or {}
    process = row.get("process") or {}
    return (process.get("pid"),
            order.get("timestamp_realtime_ns"),
            (row.get("syscall") or {}).get("name"))


def _our_path(row: dict[str, Any]) -> str | None:
    f = row.get("file") or {}
    return f.get("resolved_path") or f.get("path") or f.get("raw_path")


def _lib_path(row: dict[str, Any]) -> str | None:
    return (row.get("file") or {}).get("path")


def _inode(row: dict[str, Any]) -> int | None:
    value = (row.get("file") or {}).get("inode")
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def load_ours(path: Path, *, source_tag: str = ":scap:") -> tuple[dict, int]:
    """Load our normalized rows, restricted to those derived from the capture.

    Only rows carrying ``source_tag`` are comparable: libsinsp sees the SCAP
    capture and nothing else, so auditd-only rows have no counterpart and their
    absence is not a disagreement.
    """
    rows, duplicates = {}, 0
    for line in path.open(encoding="utf-8"):
        row = json.loads(line)
        if source_tag not in (row.get("event_id") or ""):
            continue
        key = _key(row)
        if key in rows:
            duplicates += 1
        rows[key] = row
    return rows, duplicates


def load_libsinsp(path: Path) -> tuple[dict, int]:
    rows, duplicates = {}, 0
    for line in path.open(encoding="utf-8"):
        row = json.loads(line)
        key = _key(row)
        if key in rows:
            duplicates += 1
        rows[key] = row
    return rows, duplicates


def compare(ours_path: Path, libsinsp_path: Path, *, sample: int = 25) -> dict[str, Any]:
    ours, our_dupes = load_ours(ours_path)
    lib, lib_dupes = load_libsinsp(libsinsp_path)
    matched = set(ours) & set(lib)

    resolution = collections.Counter()
    adjudicable: list[dict[str, Any]] = []
    inode_agreement = collections.Counter()

    for key in matched:
        a, b = ours[key], lib[key]
        pa, pb = _our_path(a), _lib_path(b)
        resolution[(pa is not None, pb is not None)] += 1
        if not (pa and pb):
            continue
        ia, ib = _inode(a), _inode(b)
        same_path = pa == pb
        if ia is None or ib is None:
            inode_agreement[("same_path" if same_path else "different_path", "inode_missing")] += 1
            continue
        same_inode = ia == ib
        inode_agreement[("same_path" if same_path else "different_path",
                         "inode_same" if same_inode else "inode_different")] += 1
        if not same_path and not same_inode and len(adjudicable) < sample:
            adjudicable.append({
                "pid": key[0], "timestamp_realtime_ns": key[1], "syscall": key[2],
                "ours": {"path": pa, "inode": ia},
                "libsinsp": {"path": pb, "inode": ib},
            })

    return {
        "schema_version": SCHEMA_VERSION,
        "join_key": "(pid, timestamp_realtime_ns, syscall_name)",
        "our_rows_compared": len(ours),
        "our_duplicate_keys": our_dupes,
        "libsinsp_events": len(lib),
        "libsinsp_duplicate_keys": lib_dupes,
        "matched": len(matched),
        "unmatched_ours": len(set(ours) - set(lib)),
        "unmatched_libsinsp": len(set(lib) - set(ours)),
        "resolution": {
            "both_resolved": resolution[(True, True)],
            "ours_only": resolution[(True, False)],
            "libsinsp_only": resolution[(False, True)],
            "neither": resolution[(False, False)],
        },
        "path_inode_agreement": {f"{k[0]}/{k[1]}": v for k, v in sorted(inode_agreement.items())},
        "adjudicable_disagreements_sample": adjudicable,
        "note": ("Neither stream is ground truth. 'different_path/inode_different' "
                 "entries name genuinely different files; which side is correct "
                 "requires independent adjudication."),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ours", type=Path, required=True, help="normalized syscalls.jsonl")
    ap.add_argument("--libsinsp", type=Path, required=True, help="libsinsp_events.jsonl")
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    report = compare(args.ours, args.libsinsp)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = {k: report[k] for k in ("matched", "unmatched_ours", "unmatched_libsinsp",
                                      "resolution", "path_inode_agreement")}
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
