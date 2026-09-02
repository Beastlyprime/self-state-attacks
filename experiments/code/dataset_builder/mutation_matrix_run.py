#!/usr/bin/env python3
"""Run the 16-cell mutation matrix through the proven five-source collector.

Design choice: the five-source collector
(`mutation_canary_five_source.py`) is left untouched. This module swaps the op
list and the worker body at import time -- both are module-level in gen1 and
read at call time -- and then derives per-cell witnesses *post hoc* from the
landed artifacts. Nothing in the collection path changes, so the run that
already passed stays the reference.

Why per-cell analysis has to be done here rather than by gen1's `_normalize`:
`_normalize` keys `op_checks` by `op_type`, so 4 mechanisms x 4 target roles
collapse to 4 entries. Worse, its per-source matchers differ in whether they can
attribute a mutation to a *file*:

  inotify   path-aware (mask + path suffix)                     -> per-cell OK
  auditd    path-aware for non-write (path or basename in the record) -> per-cell OK
  fanotify  path-aware for write/chmod; for rename/unlink it accepts
            any row of the right mask                            -> NOT per-cell
  eBPF      the smoke probe emits kind/pid/fd/counts/buffer_prefix
            and no path; writes are separable by payload prefix,
            rename/chmod/unlink are not                          -> write only
  graph     libsinsp resolves fd -> path                         -> per-cell OK

So a source that cannot attribute a cell is recorded as
`not_path_attributable`, never as observed. The per-cell verdict rests on the
sources that can attribute, with the merged graph as the decisive one.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

import mutation_matrix_canary as mmc
import mutation_op_canary as gen1

SPINE = Path("graph/reattributed/resolution_spine_effective")
# Which (source, mechanism) pairs can name the *file* a mutation hit.
# Measured, not assumed -- see REPORT.md for the run that establishes each row.
#
#   inotify   mask + path suffix for all four mechanisms, but carries no pid,
#             so it names the file and not the actor.
#   auditd    the syscall record carries the path for chmod/rename/unlink; a
#             write(2) record carries only the fd (the path was resolved at
#             open time), so auditd cannot say which file a write hit. gen1's
#             own matcher special-cases exactly this.
#   fanotify  path-bearing for write and chmod; for rename/unlink gen1 falls
#             back to accepting any row of the right mask.
#   ebpf      the smoke probe emits kind/pid/fd/counts/buffer_prefix and no
#             path, so only writes separate, by payload prefix.
PER_CELL_ATTRIBUTABLE = {
    "inotify": ("write", "rename", "chmod", "unlink"),
    "auditd": ("rename", "chmod", "unlink"),
    "fanotify": ("write", "chmod"),
    "ebpf": ("write",),
}


def _worker_script_matrix(workspace: Path, ready: Path, release: Path,
                          result_fd: int) -> str:
    """gen1's scaffold with the generated 16-cell body spliced in."""
    body = mmc.worker_body(mmc.build_matrix())
    return """
import json, os, pathlib, time, hashlib
workspace = pathlib.Path(%r)
ready = pathlib.Path(%r)
release = pathlib.Path(%r)
result_fd = %d
ready.write_text(json.dumps({"pid": os.getpid(), "created_realtime_ns": time.time_ns(), "created_monotonic_ns": time.monotonic_ns()}, sort_keys=True) + "\\n", encoding="utf-8")
while not release.exists():
    time.sleep(0.02)
results = []
def record(op, path, before_exists, after_exists, extra=None):
    row = {"op_type": op, "path": path, "before_exists": before_exists, "after_exists": after_exists, "timestamp_realtime_ns": time.time_ns(), "timestamp_monotonic_ns": time.monotonic_ns()}
    if extra:
        row.update(extra)
    results.append(row)
%s
os.write(result_fd, json.dumps({"pid": os.getpid(), "operations": results}, sort_keys=True).encode("utf-8"))
os.close(result_fd)
time.sleep(0.2)
""" % (str(workspace), str(ready), str(release), result_fd, body)


def install() -> list[dict[str, Any]]:
    """Point gen1 at the 16-cell matrix. Must run before the collector."""
    specs = mmc.build_matrix()
    gen1.OP_SPECS = specs
    gen1._worker_script = _worker_script_matrix
    return specs


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]


def per_cell_witness(run_dir: Path, workspace_rel: str = "workspace") -> dict[str, Any]:
    """Derive per-cell source coverage from the landed artifacts."""
    specs = mmc.build_matrix()
    raw = run_dir / "raw"
    worker = json.loads((run_dir / "worker.stdout").read_text() or "{}") \
        if (run_dir / "worker.stdout").is_file() else {}
    ready = run_dir / "control" / "worker.ready.json"
    pid = json.loads(ready.read_text())["pid"] if ready.is_file() else -1

    inotify_rows = _read_jsonl(raw / "inotify.jsonl")
    fanotify_rows = _read_jsonl(raw / "fanotify.jsonl")
    ebpf_rows = _read_jsonl(raw / "ebpf.jsonl")
    audit_text = (raw / "auditd_ausearch.log").read_text(
        encoding="utf-8", errors="replace") if (raw / "auditd_ausearch.log").is_file() else ""
    anchor_path = run_dir / "run_time_anchor.json"
    anchor = json.loads(anchor_path.read_text()) if anchor_path.is_file() else {}
    audit_groups = (gen1._audit_groups(audit_text, anchor)
                    if audit_text and anchor else [])

    # graph edges: (relation, resolved leaf) -> identity_status
    graph_hits: Counter[tuple[str, str]] = Counter()
    nodes_path, edges_path = run_dir / SPINE / "provenance.nodes.jsonl", run_dir / SPINE / "provenance.edges.jsonl"
    if nodes_path.is_file() and edges_path.is_file():
        nodes = {r["node_id"]: r for r in _read_jsonl(nodes_path)}
        marker = f"/{workspace_rel}/"
        for edge in _read_jsonl(edges_path):
            rel = edge.get("relation")
            if rel not in ("write", "rename", "chmod", "unlink"):
                continue
            for key in ("source_node_id", "destination_node_id"):
                node = nodes.get(edge[key]) or {}
                attrs = node.get("attributes") or {}
                path = str(attrs.get("resolved_path") or "")
                if (node.get("node_type") == "file"
                        and marker in path
                        and node.get("identity_status") == "complete"):
                    graph_hits[(rel, path.split(marker, 1)[1])] += 1

    cells: dict[str, dict[str, Any]] = {}
    for spec in specs:
        op, rel, cid = spec["op_type"], spec["path"], spec["cell_id"]
        checks: dict[str, Any] = {}
        # inotify / fanotify via gen1's path-aware matcher
        for source, rows in (("inotify", inotify_rows), ("fanotify", fanotify_rows)):
            if op not in PER_CELL_ATTRIBUTABLE[source]:
                checks[source] = "not_path_attributable"
                continue
            try:
                checks[source] = gen1._mask_match(source, rows, spec, pid) is not None
            except KeyError:
                checks[source] = "not_path_attributable"
        # auditd: pid + syscall number + the path or its basename in the record.
        # A write(2) record carries only the fd, so writes are not attributable.
        if op not in PER_CELL_ATTRIBUTABLE["auditd"]:
            checks["auditd"] = "not_path_attributable"
        else:
            hit = False
            for group in audit_groups:
                joined = "\n".join(group["raw_records"])
                if gen1._parse_audit_value(joined, "pid") != pid:
                    continue
                if gen1._parse_audit_value(joined, "syscall") not in gen1.AUDIT_SYSCALLS[op]:
                    continue
                if rel in joined or Path(rel).name in joined:
                    hit = True
                    break
            checks["auditd"] = hit
        # eBPF: only writes carry a discriminating payload prefix
        if op == "write":
            want = spec["payload"].hex()
            checks["ebpf"] = any(
                r.get("kind") == "write" and r.get("pid") == pid
                and r.get("buffer_prefix_hex") == want for r in ebpf_rows)
        else:
            checks["ebpf"] = "not_path_attributable"
        # graph: the decisive per-cell channel
        checks["graph"] = graph_hits.get((op, rel), 0) > 0

        attributable = [k for k, v in checks.items() if isinstance(v, bool)]
        cells[cid] = {
            "op_type": op, "target_role": spec["target_role"], "path": rel,
            "checks": checks,
            "attributable_sources": attributable,
            "observed_on_all_attributable": all(checks[k] for k in attributable),
            "graph_witnessed": checks["graph"] is True,
        }

    worker_ops = {(o.get("op_type"), o.get("path")) for o in (worker.get("operations") or [])}
    return {
        "schema_version": "assa.mutation_matrix_per_cell_witness.v1",
        "cell_count": len(cells),
        "worker_reported_ops": len(worker_ops),
        "cells": cells,
        "per_source_attributability": {
            k: list(v) for k, v in PER_CELL_ATTRIBUTABLE.items()},
        "summary": {
            "graph_witnessed": sum(1 for c in cells.values() if c["graph_witnessed"]),
            "all_attributable_observed": sum(
                1 for c in cells.values() if c["observed_on_all_attributable"]),
            "all_cells_graph_witnessed": all(
                c["graph_witnessed"] for c in cells.values()),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Collect the 16-cell mutation matrix (five-source) or analyse a run")
    parser.add_argument("--output-root", type=Path,
                        default=gen1.PROJECT_ROOT / "data/mutation_matrix_five_source")
    parser.add_argument("--falco-config", type=Path, default=Path("/etc/falco/falco.yaml"))
    parser.add_argument("--analyse-only", type=Path, default=None,
                        help="skip collection; derive per-cell witness from this run dir")
    args = parser.parse_args()

    if args.analyse_only:
        run_dir = args.analyse_only
        witness = per_cell_witness(run_dir)
    else:
        specs = install()
        import mutation_canary_five_source as five
        run_dir = five.run(args.output_root, args.falco_config)
        witness = per_cell_witness(run_dir)
        witness["installed_cells"] = [s["cell_id"] for s in specs]
    # Always persist, so an analysis-only pass leaves the same artifact a
    # collection pass would have.
    (run_dir / "per_cell_witness.json").write_text(
        json.dumps(witness, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    witness["run_dir"] = str(run_dir)
    print(json.dumps(witness.get("summary", {}), indent=2, sort_keys=True))
    if "run_dir" in witness:
        print("run_dir:", witness["run_dir"])
    return 0 if witness.get("summary", {}).get("all_cells_graph_witnessed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
