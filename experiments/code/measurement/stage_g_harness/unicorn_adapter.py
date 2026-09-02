from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import xxhash

from .external import git_head, record_tool_manifest, run_tool
from .io import file_record, read_jsonl, write_json


PARSER_COMMIT = "8ae2d9e9c187cc78d8127b3abe1366a7ebc56e23"
ANALYZER_COMMIT = "3026e8cbd6b0b7a0db07c0a815f064a69b924ff1"
MODELER_COMMIT = "648e8605c4305c0f98d33d11d48d5719c555ac0b"


def _hash(parts: list[str]) -> int:
    hasher = xxhash.xxh64()
    for part in parts:
        hasher.update(part)
    return hasher.intdigest()


def adapt_graph(
    nodes_path: Path, edges_path: Path, output_dir: Path,
    coverage_path: Path | None = None,
) -> dict[str, Any]:
    nodes = {row["node_id"]: row for row in read_jsonl(nodes_path)}
    edges = sorted(read_jsonl(edges_path), key=lambda row: (row["order"]["merged"], row["edge_id"]))
    output_dir.mkdir(parents=True, exist_ok=True)
    prepared = output_dir / "assa.edgelist"
    mapping = {"nodes": {}, "edge_types": {}}
    with prepared.open("w", encoding="ascii") as handle:
        for logical_order, edge in enumerate(edges, 1):
            source = nodes[edge["source_node_id"]]
            target = nodes[edge["destination_node_id"]]
            source_attrs = source.get("attributes") or {}
            target_attrs = target.get("attributes") or {}
            source_type = _hash([source["node_type"], "N/A", str(source_attrs.get("mode", "N/A")),
                                 str(source_attrs.get("resolved_path") or source_attrs.get("exe") or "N/A")])
            target_type = _hash([target["node_type"], "N/A", str(target_attrs.get("mode", "N/A")),
                                 str(target_attrs.get("resolved_path") or target_attrs.get("exe") or "N/A")])
            edge_type = _hash([edge["relation"], "N/A"])
            source_id = _hash([source["node_id"]])
            target_id = _hash([target["node_id"]])
            handle.write(f"{source_id}\t{target_id}\t{source_type}:{target_type}:{edge_type}:{logical_order}\n")
            mapping["nodes"][source["node_id"]] = {"unicorn_id": source_id, "unicorn_type": source_type}
            mapping["nodes"][target["node_id"]] = {"unicorn_id": target_id, "unicorn_type": target_type}
            mapping["edge_types"][edge["relation"]] = edge_type
    node_hashes = [value["unicorn_id"] for value in mapping["nodes"].values()]
    edge_hashes = list(mapping["edge_types"].values())
    if len(node_hashes) != len(set(node_hashes)) or len(edge_hashes) != len(set(edge_hashes)):
        raise RuntimeError("xxhash collision in UNICORN adapter mapping")
    incomplete_nodes = [node["node_id"] for node in nodes.values()
                        if node["identity_status"] != "complete" or node["node_type"].endswith("unknown")]
    selected_coverage = coverage_path or nodes_path.with_name("coverage.json")
    coverage = (
        json.loads(selected_coverage.read_text(encoding="utf-8"))
        if selected_coverage.is_file() else None
    )
    fd_rate = coverage.get("fd_path_resolved_rate") if coverage else None
    threshold = coverage.get("fd_path_resolved_threshold", 0.95) if coverage else 0.95
    provenance_evaluable = bool(
        coverage and coverage.get("provenance_evaluable")
        and fd_rate is not None and fd_rate >= threshold
    )
    report = {
        "schema_version": "assa.unicorn_adapter.v2", "input_nodes": len(nodes),
        "input_edges": len(edges), "output_edges": len(edges), "dropped_edges": 0,
        "prepared_edgelist": str(prepared.resolve()), "mapping": mapping,
        "semantics": "UNICORN on SCAP/audit/eBPF-derived provenance",
        # The frozen contract's admission gate is the coverage artifact's
        # fd-path threshold. Unknown nodes remain in the edge list and are
        # reported below; they are not a second, undocumented zero-unknown
        # gate. This matters for the resolution-spine-effective view, which
        # deliberately retains unresolved sockets while still satisfying the
        # registered file-identity threshold.
        "status": "passed" if provenance_evaluable else "data_insufficient",
        "status_basis": "coverage_provenance_evaluable_fd_path_threshold",
        "incomplete_nodes_retained": True,
        "coverage_path": str(selected_coverage.resolve()) if coverage else None,
        "fd_path_resolved_rate": fd_rate,
        "fd_path_resolved_threshold": threshold,
        "provenance_evaluable": provenance_evaluable,
        "incomplete_node_count": len(incomplete_nodes),
        "incomplete_node_ids": incomplete_nodes,
        "hash_implementation": f"xxhash {getattr(xxhash, 'VERSION', 'unknown')}",
    }
    write_json(output_dir / "adapter_report.json", report)
    return report


def _python_inventory(python: str, output_dir: Path, prefix: str, *, cwd: Path,
                      env: dict[str, str] | None = None) -> list[Any]:
    return [
        run_tool([python, "--version"], output_dir, f"{prefix}_python_version", cwd=cwd, env=env),
        run_tool([python, "-m", "pip", "freeze"], output_dir, f"{prefix}_pip_freeze", cwd=cwd, env=env),
    ]

def run_official_parser(report: dict[str, Any], parser_repo: Path, output_dir: Path,
                        *, python2: str = "python2", base_size: int | None = None,
                        env: dict[str, str] | None = None, runtime_artifacts: list[Path] | None = None) -> dict[str, Any]:
    prepared = Path(report["prepared_edgelist"])
    if report.get("status") == "data_insufficient":
        return record_tool_manifest(
            output_dir, tool="UNICORN parser", version=PARSER_COMMIT,
            status="data_insufficient", runs=[],
            inputs=[prepared, *(runtime_artifacts or [])], configs=[],
            repository=parser_repo, expected_commit=PARSER_COMMIT,
            extra={"reason": "provenance coverage gate not met",
                   "fd_path_resolved_rate": report.get("fd_path_resolved_rate"),
                   "fd_path_resolved_threshold": report.get("fd_path_resolved_threshold")},
        )
    edge_count = int(report["output_edges"])
    if edge_count < 2:
        return record_tool_manifest(
            output_dir, tool="UNICORN parser", version=PARSER_COMMIT, status="data_insufficient", runs=[],
            inputs=[prepared, *(runtime_artifacts or [])], configs=[], repository=parser_repo, expected_commit=PARSER_COMMIT,
            extra={"reason": "UNICORN base/stream split requires at least two edges",
                   "base_size": None, "base": None, "stream": None},
        )
    selected_base_size = base_size or max(1, edge_count // 10)
    selected_base_size = min(selected_base_size, edge_count - 1)
    base, stream = output_dir / "base.txt", output_dir / "stream.txt"
    command = [python2, str(parser_repo / "camflow" / "parse.py"), "-i", str(prepared),
               "-b", str(selected_base_size), "-B", str(base), "-S", str(stream)]
    runtime_runs = _python_inventory(python2, output_dir, "parser", cwd=parser_repo / "camflow", env=env)
    run = run_tool(command, output_dir, "official_parser", cwd=parser_repo / "camflow", env=env)
    runs = [*runtime_runs, run]
    status = "passed" if all(item.exit_status == 0 for item in runs) and base.is_file() and stream.is_file() else "failed"
    manifest = record_tool_manifest(
        output_dir, tool="UNICORN parser", version=PARSER_COMMIT, status=status, runs=runs,
        inputs=[prepared, *(runtime_artifacts or [])], configs=[], repository=parser_repo, expected_commit=PARSER_COMMIT,
        extra={"base_size": selected_base_size,
               "base": file_record(base) if base.is_file() else None,
               "stream": file_record(stream) if stream.is_file() else None, "python": python2},
    )
    return manifest


def run_official_analyzer(analyzer_repo: Path, base: Path, stream: Path, output_dir: Path,
                          *, batch_size: int = 2000) -> dict[str, Any]:
    build = run_tool(["make", "sb"], output_dir, "make_sb", cwd=analyzer_repo)
    binary = analyzer_repo / "bin" / "unicorn" / "main"
    runs = [build]
    sketch = output_dir / "sketch.txt"
    if build.exit_status == 0 and binary.is_file():
        runs.append(run_tool([
            str(binary), "filetype", "edgelist", "base", str(base.resolve()), "stream", str(stream.resolve()),
            "decay", "500", "lambda", "0.02", "batch", str(batch_size), "sketch", str(sketch.resolve()),
            "chunkify", "1", "chunk_size", "50",
        ], output_dir, "analyzer", cwd=analyzer_repo))
    status = "passed" if len(runs) == 2 and runs[-1].exit_status == 0 and sketch.is_file() else "failed"
    return record_tool_manifest(
        output_dir, tool="UNICORN analyzer", version=ANALYZER_COMMIT, status=status, runs=runs,
        inputs=[base, stream], configs=[], repository=analyzer_repo, expected_commit=ANALYZER_COMMIT,
        extra={"sketch": file_record(sketch) if sketch.is_file() else None,
               "binary": file_record(binary) if binary.is_file() else None,
               "compile_profile": "sb", "batch_size": batch_size},
    )


def run_official_examples(parser_repo: Path, modeler_repo: Path, output_dir: Path, *,
                          parser_python: str | None = None, modeler_python: str | None = None,
                          env: dict[str, str] | None = None,
                          runtime_artifacts: list[Path] | None = None) -> dict[str, Any]:
    heads = {"parser": git_head(parser_repo), "modeler": git_head(modeler_repo)}
    expected = {"parser": PARSER_COMMIT, "modeler": MODELER_COMMIT}
    if heads != expected:
        raise RuntimeError(f"UNICORN example commit mismatch: expected {expected}, got {heads}")
    parser_run = run_tool(["make", "example"], output_dir, "parser_make_example",
                          cwd=parser_repo / "camflow" / "example", env=env)
    modeler_run = run_tool(["make", "example"], output_dir, "modeler_make_example",
                           cwd=modeler_repo, env=env)
    runs = [parser_run, modeler_run]
    if parser_python is not None:
        runs.extend(_python_inventory(parser_python, output_dir, "parser_example",
                                      cwd=parser_repo / "camflow", env=env))
    if modeler_python is not None:
        runs.extend(_python_inventory(modeler_python, output_dir, "modeler_example",
                                      cwd=modeler_repo, env=env))
    status = "passed" if all(run.exit_status == 0 for run in runs) else "failed"
    return record_tool_manifest(
        output_dir, tool="UNICORN official examples", version=f"parser={PARSER_COMMIT};modeler={MODELER_COMMIT}",
        status=status, runs=runs, inputs=runtime_artifacts or [], configs=[],
        extra={"parser_repository": str(parser_repo.resolve()), "parser_commit": PARSER_COMMIT,
               "modeler_repository": str(modeler_repo.resolve()), "modeler_commit": MODELER_COMMIT,
               "parser_python": parser_python, "modeler_python": modeler_python},
    )


def run_official_modeler(modeler_repo: Path, train_dir: Path, test_dir: Path, output_dir: Path,
                         *, python2: str = "python2", env: dict[str, str] | None = None,
                         runtime_artifacts: list[Path] | None = None) -> dict[str, Any]:
    runs = _python_inventory(python2, output_dir, "modeler", cwd=modeler_repo, env=env)
    runs.append(run_tool(["make", "example"], output_dir, "make_example", cwd=modeler_repo, env=env))
    runs.append(run_tool([
        python2, str(modeler_repo / "model.py"), "-t", str(train_dir.resolve()),
        "-u", str(test_dir.resolve()), "-m", "mean", "-c", "0", "-S", "98765432",
    ], output_dir, "model", cwd=modeler_repo, env=env))
    status = "passed" if all(run.exit_status == 0 for run in runs) else "failed"
    inputs = sorted(path for path in [*train_dir.iterdir(), *test_dir.iterdir()] if path.is_file())
    return record_tool_manifest(
        output_dir, tool="UNICORN modeler", version=MODELER_COMMIT, status=status, runs=runs,
        inputs=[*inputs, *(runtime_artifacts or [])], configs=[], repository=modeler_repo, expected_commit=MODELER_COMMIT,
        extra={"metric": "mean", "cross_validation": 0, "random_seed": 98765432,
               "python": python2},
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nodes", required=True, type=Path)
    parser.add_argument("--edges", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--coverage", type=Path)
    args = parser.parse_args()
    print(json.dumps(
        adapt_graph(args.nodes, args.edges, args.output_dir, args.coverage),
        indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
