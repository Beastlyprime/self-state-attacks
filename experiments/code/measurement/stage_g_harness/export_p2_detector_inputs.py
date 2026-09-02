#!/usr/bin/env python3
"""Materialize immutable P2 detector inputs without changing observations."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any

from .generation_contract import (
    generation_stamp,
    load_generation_contract,
    stamp_record,
    validate_freezes,
)

GRAPH_FILES = ("syscalls.jsonl", "provenance.nodes.jsonl", "provenance.edges.jsonl", "coverage.json")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def link_file(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise FileNotFoundError(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(source, destination)
    except OSError:
        shutil.copy2(source, destination)


def link_tree(source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise FileNotFoundError(source)
    for item in sorted(source.rglob("*")):
        if item.is_file():
            link_file(item, destination / item.relative_to(source))


def graph_root(run_dir: Path) -> Path:
    return run_dir / "graph" / "reattributed" / "resolution_spine_effective"


def record_tree(root: Path) -> dict[str, Any]:
    rows = []
    tree = hashlib.sha256()
    for path in sorted(x for x in root.rglob("*") if x.is_file()):
        relative = path.relative_to(root).as_posix()
        digest = sha256(path)
        size = path.stat().st_size
        tree.update(f"{relative}\0{size}\0{digest}\n".encode())
        rows.append({"path": relative, "bytes": size, "sha256": digest})
    return {"files": rows, "file_count": len(rows), "tree_sha256": tree.hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--training-freeze", required=True, type=Path)
    parser.add_argument("--heldout-freeze", required=True, type=Path)
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--generation-contract", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    training = json.loads(args.training_freeze.read_text())
    heldout = json.loads(args.heldout_freeze.read_text())
    contract = load_generation_contract(args.generation_contract)
    validate_freezes(contract, args.training_freeze, args.heldout_freeze)
    args.output.mkdir(parents=True)

    rows = []
    for role, manifest in (("training", training), ("heldout", heldout)):
        for record in manifest["records"]:
            profile, run_id = record["profile"], record["run_id"]
            source_graph = graph_root(Path(record["run_dir"] if role == "training" else record["derived_run_dir"]))
            destination_graph = args.output / role / profile / run_id / "graph"
            for name in GRAPH_FILES:
                link_file(source_graph / name, destination_graph / name)
            item = {
                "role": role,
                "profile": profile,
                "run_id": run_id,
                "branch_outcome": record["branch_outcome"],
                "graph_source": str(source_graph.resolve()),
            }
            if role == "heldout":
                source_run = args.repository_root / record["source_run_dir"]
                link_tree(source_run / "state_snapshots",
                          args.output / role / profile / run_id / "state_snapshots")
                item["source_run_dir"] = str(source_run.resolve())
                captures = sorted((source_run / "raw").glob("*.scap"))
                if len(captures) != 1:
                    raise RuntimeError(f"expected one SCAP capture for {run_id}, got {captures}")
                item["capture_path"] = str(captures[0].resolve())
                item["workspace_root"] = str((source_run / "workspace").resolve())
            rows.append(stamp_record(item, contract))

    link_file(args.training_freeze, args.output / "manifests" / args.training_freeze.name)
    link_file(args.heldout_freeze, args.output / "manifests" / args.heldout_freeze.name)
    inventory = {
        "schema_version": "assa.p2_detector_input_export.v2",
        "observation_mutated": False,
        **generation_stamp(contract),
        "training_freeze_sha256": contract["training_freeze_sha256"],
        "heldout_freeze_sha256": contract["heldout_freeze_sha256"],
        "records": rows,
        "tree": None,
    }
    (args.output / "input_inventory.json").write_text(
        json.dumps(inventory, indent=2, sort_keys=True) + "\n")
    inventory["tree"] = record_tree(args.output)
    (args.output / "input_inventory.json").write_text(
        json.dumps(inventory, indent=2, sort_keys=True) + "\n")
    final = record_tree(args.output)
    (args.output / "SHA256SUMS").write_text(
        "".join(f"{row['sha256']}  {row['path']}\n"
                for row in final["files"] if row["path"] != "SHA256SUMS"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
