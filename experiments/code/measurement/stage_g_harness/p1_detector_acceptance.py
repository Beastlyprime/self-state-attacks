#!/usr/bin/env python3
"""Run the frozen four-detector engineering acceptance on one admitted generation.

This is an offline acceptance runner, not a detector-effectiveness experiment.
It never trains on poisoned input and never emits TPR/FPR claims.  The source
batch is immutable; every output is written below a new, non-existing root and
bound to its observation-generation identifier.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from .external import _parse_aide_report, _parse_falco_json, record_tool_manifest, run_stide, run_tool
from .falco_rules import write_self_state_rules
from .io import file_record, write_json
from .unicorn_adapter import adapt_graph

AIDE_COMMIT = "2278f6b45fd9fc06859a771e84d44672523a4c18"
FALCO_COMMIT = "a078853fe47db0199ed2c5ca58cb548754017aa1"
FALCO_RULES_COMMIT = "6cbb113dd3fbcaf157c077414a57d2180f3e0eec"
STIDE_COMMIT = "587d15870843961acb78fbb4b8fcd0ede28eabcc"
UNICORN_PARSER_COMMIT = "8ae2d9e9c187cc78d8127b3abe1366a7ebc56e23"
UNICORN_MODELER_COMMIT = "648e8605c4305c0f98d33d11d48d5719c555ac0b"
UNICORN_ANALYZER_COMMIT = "3026e8cbd6b0b7a0db07c0a815f064a69b924ff1"
EXPECTED_RUNS = 12


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_record(path: Path) -> dict[str, Any]:
    files = sorted(x for x in path.rglob("*") if x.is_file())
    h = hashlib.sha256()
    total = 0
    for item in files:
        rel = item.relative_to(path).as_posix()
        digest = sha256(item)
        size = item.stat().st_size
        h.update(f"{rel}\0{size}\0{digest}\n".encode())
        total += size
    return {"kind": "directory_tree", "path": str(path.resolve()), "files": len(files),
            "bytes": total, "sha256": h.hexdigest()}


def write_sha256s(root: Path) -> Path:
    out = root / "SHA256SUMS"
    files = sorted(x for x in root.rglob("*") if x.is_file() and x != out)
    out.write_text("".join(f"{sha256(x)}  {x.relative_to(root)}\n" for x in files), encoding="utf-8")
    return out


def run_aide_container(snapshot_root: Path, output: Path, *, image: str, source_repo: Path,
                       generation_id: str) -> dict[str, Any]:
    if subprocess.run(["git", "-C", str(source_repo), "rev-parse", "HEAD"], text=True,
                      stdout=subprocess.PIPE, check=False).stdout.strip() != AIDE_COMMIT:
        raise RuntimeError("AIDE source commit mismatch")
    snaps = {name: snapshot_root / name for name in ("before_a", "after_a", "after_b")}
    if not all(p.is_dir() for p in snaps.values()):
        raise ValueError(f"incomplete snapshots: {snapshot_root}")
    output.mkdir(parents=True)
    materialized = output / "materialized_state"
    database = output / "aide.db"
    database_new = output / "aide.db.new"
    config = output / "aide.conf"
    config.write_text(
        "database_in=file:/work/aide.db\n"
        "database_out=file:/work/aide.db.new\n"
        "report_url=stdout\n"
        "Checks = p+i+n+u+g+s+m+c+sha256\n"
        "/work/materialized_state Checks\n", encoding="utf-8")
    uid = f"{os.getuid()}:{os.getgid()}"
    base = ["docker", "run", "--rm", "--user", uid, "-v", f"{output.resolve()}:/work", image]
    runs = [run_tool(["docker", "image", "inspect", image], output, "image_inspect"),
            run_tool([*base, "--version"], output, "version")]
    shutil.copytree(snaps["before_a"], materialized)
    runs.append(run_tool([*base, "--config", "/work/aide.conf", "--init"], output, "init"))
    status = "passed"
    if runs[-1].exit_status != 0 or not database_new.is_file():
        status = "failed"
    else:
        database_new.replace(database)
        runs.append(run_tool([*base, "--config", "/work/aide.conf", "--check"], output, "before_control"))
        if runs[-1].exit_status != 0:
            status = "failed"
        for name in ("after_a", "after_b"):
            shutil.rmtree(materialized)
            shutil.copytree(snaps[name], materialized)
            runs.append(run_tool([*base, "--config", "/work/aide.conf", "--check"], output, name))
    reports = {r.stdout.name.removesuffix(".stdout.log"): _parse_aide_report(r.stdout) for r in runs[3:]}
    if status == "passed" and any(x["parse_status"] != "parsed" for x in reports.values()):
        status = "failed"
    write_json(output / "parsed_reports.json", reports)
    image_id = subprocess.run(["docker", "image", "inspect", image, "--format", "{{.Id}}"],
                              text=True, stdout=subprocess.PIPE, check=False).stdout.strip()
    return record_tool_manifest(
        output, tool="AIDE", version="AIDE 0.19.3", status=status, runs=runs,
        inputs=[], configs=[config], repository=source_repo, expected_commit=AIDE_COMMIT,
        extra={"container_image": image, "container_image_id": image_id,
               "observation_generation_id": generation_id,
               "snapshot_inputs": {k: tree_record(v) for k, v in snaps.items()},
               "parsed_reports": file_record(output / "parsed_reports.json"),
               "database": file_record(database) if database.is_file() else None,
               "acceptance_only_not_effectiveness": True})


def qemu_falco_prefix(qemu: Path, prefix: Path, falco: Path) -> list[str]:
    return [str(qemu), "-L", str(prefix), str(falco)]


def run_falco_capture(capture: Path, output: Path, *, rules: Path, config: Path,
                      qemu: Path, prefix: Path, falco: Path, source_repo: Path,
                      workspace_root: Path, generation_id: str) -> dict[str, Any]:
    output.mkdir(parents=True)
    write_self_state_rules(rules, monitored_root=workspace_root, runner_uid=997)
    base = qemu_falco_prefix(qemu, prefix, falco)
    runs = [run_tool([*base, "--version"], output, "version"),
            run_tool([*base, "-c", str(config), "-V", str(rules)], output, "validate"),
            run_tool([*base, "-c", str(config), "--dry-run", "-r", str(rules)], output, "compile"),
            run_tool([*base, "-c", str(config), "-r", str(rules),
                      "-o", "engine.kind=replay", "-o", f"engine.replay.capture_file={capture}",
                      "-o", "json_output=true", "-o", "syslog_output.enabled=false"],
                     output, "replay")]
    events = _parse_falco_json(runs[-1].stdout)
    write_json(output / "parsed_events.json", events)
    status = "passed" if all(r.exit_status == 0 for r in runs) else "failed"
    return record_tool_manifest(
        output, tool="Falco", version="Falco 0.44.0", status=status, runs=runs,
        inputs=[capture], configs=[config, rules], repository=source_repo,
        expected_commit=FALCO_COMMIT,
        extra={"falco_rules_commit_sha": FALCO_RULES_COMMIT,
               "input_transport": "native_libscap", "runner_uid": 997,
               "workspace_root": str(workspace_root), "parsed_event_count": len(events),
               "parsed_events": file_record(output / "parsed_events.json"),
               "observation_generation_id": generation_id,
               "acceptance_only_not_effectiveness": True})


def filter_executable(source: Path, destination: Path, executable: str) -> dict[str, int]:
    counts = Counter()
    with source.open(encoding="utf-8") as src, destination.open("w", encoding="utf-8") as dst:
        for line in src:
            row = json.loads(line)
            process = row.get("process") or {}
            actual = process.get("exe") or process.get("comm") or "<unknown>"
            if actual != executable:
                continue
            dst.write(json.dumps(row, sort_keys=True) + "\n")
            counts["rows"] += 1
            counts["sequence_eligible"] += int(bool(row.get("sequence_eligible")))
    return dict(counts)


def run_unicorn(input_dir: Path, output: Path, *, generation_id: str, parser_repo: Path,
                native_parser: Path, modeler_repo: Path, native_modeler: Path,
                analyzer_repo: Path, image: str) -> dict[str, Any]:
    from .external import record_tool_manifest
    nodes = input_dir / "provenance.nodes.jsonl"
    edges = input_dir / "provenance.edges.jsonl"
    coverage = input_dir / "coverage.json"
    adapter_dir = output / "adapter"
    pipeline = output / "pipeline"
    pipeline.mkdir(parents=True)
    adapter = adapt_graph(nodes, edges, adapter_dir, coverage)
    uid = f"{os.getuid()}:{os.getgid()}"
    runs = [run_tool(["make", "example"], output, "native_parser_make_example",
                     cwd=native_parser / "camflow/example", timeout=300),
            run_tool(["make", "example"], output, "native_modeler_make_example",
                     cwd=native_modeler, timeout=300),
            run_tool(["docker", "image", "inspect", image], output, "runtime_image_inspect"),
            run_tool(["docker", "run", "--rm", image, "python", "--version"], output, "python2_version")]
    parser_mount = ["docker", "run", "--rm", "--user", uid, "-e", "HOME=/tmp",
                    "-v", f"{parser_repo}:/repo", "-w", "/repo/camflow/example", image]
    modeler_mount = ["docker", "run", "--rm", "--user", uid, "-e", "HOME=/tmp",
                     "-v", f"{modeler_repo}:/repo", "-w", "/repo", image]
    runs += [run_tool([*parser_mount, "virtualenv", "--system-site-packages", "venv"], output, "parser_venv"),
             run_tool([*parser_mount, "make", "example"], output, "parser_make_example_py2", timeout=300),
             run_tool([*modeler_mount, "virtualenv", "--system-site-packages", "venv"], output, "modeler_venv"),
             run_tool([*modeler_mount, "make", "example"], output, "modeler_make_example_py2", timeout=300)]
    parser_pipeline = ["docker", "run", "--rm", "--user", uid, "-e", "HOME=/tmp",
                       "-v", f"{parser_repo}:/repo:ro", "-v", f"{output}:/out", "-w", "/repo/camflow", image,
                       "python", "/repo/camflow/parse.py", "-i", "/out/adapter/assa.edgelist",
                       "-b", "1", "-B", "/out/pipeline/base.txt", "-S", "/out/pipeline/stream.txt"]
    runs.append(run_tool(parser_pipeline, output, "official_parser_pipeline", timeout=300))
    binary = analyzer_repo / "bin/unicorn/main"
    runs.append(run_tool(["make", "sb"], output, "analyzer_make_sb", cwd=analyzer_repo, timeout=300))
    sketch = pipeline / "sketch.txt"
    runs.append(run_tool([str(binary), "filetype", "edgelist", "base", str((pipeline / "base.txt").resolve()),
                          "stream", str((pipeline / "stream.txt").resolve()), "decay", "500", "lambda", "0.02",
                          "batch", "1", "sketch", str(sketch.resolve()), "chunkify", "1", "chunk_size", "50"],
                         output, "official_analyzer_pipeline", cwd=analyzer_repo, timeout=300))
    train_dir, test_dir = pipeline / "model_train", pipeline / "model_test"
    train_dir.mkdir(); test_dir.mkdir()
    lines = sketch.read_text(encoding="utf-8").splitlines() if sketch.is_file() else []
    train, test = train_dir / "clean_training_graph.txt", test_dir / "heldout_clean_graph.txt"
    if len(lines) >= 2:
        train.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
        test.write_text(lines[-1] + "\n", encoding="utf-8")
    model_command = ["docker", "run", "--rm", "--user", uid, "-e", "HOME=/tmp",
                     "-v", f"{modeler_repo}:/repo:ro", "-v", f"{output}:/out", "-w", "/repo", image,
                     "python", "/repo/model.py", "-t", "/out/pipeline/model_train", "-u", "/out/pipeline/model_test",
                     "-m", "mean", "-c", "0", "-S", "98765432"]
    runs.append(run_tool(model_command, output, "official_modeler_pipeline", timeout=300))
    report = {"schema_version": "assa.unicorn_generation_acceptance.v1",
              "adapter_status": adapter["status"], "input_edges": adapter["input_edges"],
              "output_edges": adapter["output_edges"], "dropped_edges": adapter["dropped_edges"],
              "incomplete_node_count": adapter["incomplete_node_count"],
              "incomplete_nodes_retained": adapter["incomplete_nodes_retained"],
              "base_edges": len((pipeline / "base.txt").read_text().splitlines()) if (pipeline / "base.txt").is_file() else 0,
              "stream_edges": len((pipeline / "stream.txt").read_text().splitlines()) if (pipeline / "stream.txt").is_file() else 0,
              "analyzer_batch_size": 1,
              "sketches": len(lines), "training_sketches": max(0, len(lines)-1),
              "heldout_sketches": int(len(lines) >= 2),
              "effectiveness_note": "Acceptance only; abnormal output is not a performance result."}
    write_json(output / "pipeline_report.json", report)
    required = runs[2:]
    status = "passed" if (adapter["status"] == "passed" and all(r.exit_status == 0 for r in required)
                           and report["base_edges"] >= 1 and report["stream_edges"] >= 1
                           and report["sketches"] >= 2) else ("data_insufficient" if adapter["status"] == "data_insufficient" else "failed")
    return record_tool_manifest(
        output, tool="UNICORN", version="parser=8ae2d9e;modeler=648e860;analyzer=3026e8c",
        status=status, runs=runs,
        inputs=[nodes, edges, coverage, adapter_dir / "assa.edgelist"],
        configs=[adapter_dir / "adapter_report.json"], repository=parser_repo,
        expected_commit=UNICORN_PARSER_COMMIT,
        extra={"parser_commit_sha": UNICORN_PARSER_COMMIT,
               "modeler_repository": str(modeler_repo.resolve()), "modeler_commit_sha": UNICORN_MODELER_COMMIT,
               "analyzer_repository": str(analyzer_repo.resolve()), "analyzer_commit_sha": UNICORN_ANALYZER_COMMIT,
               "runtime_image": image, "native_host_expected_compatibility_failure": True,
               "native_host_status": "passed" if all(r.exit_status == 0 for r in runs[:2]) else "failed",
               "adapter_report": file_record(adapter_dir / "adapter_report.json"),
               "pipeline_report": file_record(output / "pipeline_report.json"),
               "observation_generation_id": generation_id,
               "acceptance_only_not_effectiveness": True})


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source-root", required=True, type=Path)
    ap.add_argument("--derived-root", required=True, type=Path)
    ap.add_argument("--output-root", required=True, type=Path)
    ap.add_argument("--aide-repo", required=True, type=Path)
    ap.add_argument("--aide-image", default="assa-stage-g/aide:0.19.3")
    ap.add_argument("--falco-repo", required=True, type=Path)
    ap.add_argument("--falco", required=True, type=Path)
    ap.add_argument("--qemu", required=True, type=Path)
    ap.add_argument("--qemu-prefix", required=True, type=Path)
    ap.add_argument("--falco-config", required=True, type=Path)
    ap.add_argument("--stide-repo", required=True, type=Path)
    ap.add_argument("--unicorn-parser", required=True, type=Path)
    ap.add_argument("--unicorn-native-parser", required=True, type=Path)
    ap.add_argument("--unicorn-modeler", required=True, type=Path)
    ap.add_argument("--unicorn-native-modeler", required=True, type=Path)
    ap.add_argument("--unicorn-analyzer", required=True, type=Path)
    ap.add_argument("--unicorn-image", default="assa-stage-g/unicorn-python2:2.7.18")
    args = ap.parse_args()
    if args.output_root.exists():
        raise FileExistsError(f"refusing to overwrite: {args.output_root}")
    args.output_root.mkdir(parents=True)
    generation = json.loads((args.derived_root / "observation_generation.json").read_text())
    generation_id = generation["generation_id"]
    runs = sorted((args.source_root / "runs").iterdir())
    if len(runs) != EXPECTED_RUNS:
        raise RuntimeError(f"expected {EXPECTED_RUNS} runs, got {len(runs)}")
    derived_runs = args.derived_root / "runs"
    aide, falco = {}, {}
    for run in runs:
        aide[run.name] = run_aide_container(run / "state_snapshots", args.output_root / "aide" / run.name,
                                             image=args.aide_image, source_repo=args.aide_repo,
                                             generation_id=generation_id)
        effective = derived_runs / run.name / "graph/reattributed/resolution_spine_effective"
        workspace = None
        for line in (effective / "syscalls.jsonl").open():
            row = json.loads(line); path = ((row.get("file") or {}).get("resolved_path"))
            if path and "/workspace/" in path:
                workspace = Path(path.split("/workspace/", 1)[0] + "/workspace")
                break
        if workspace is None:
            raise RuntimeError(f"workspace not found for {run.name}")
        falco_dir = args.output_root / "falco" / run.name
        falco[run.name] = run_falco_capture(
            run / "raw/capture.scap", falco_dir,
            rules=falco_dir / "assa_self_state_rules.yaml", config=args.falco_config,
            qemu=args.qemu, prefix=args.qemu_prefix, falco=args.falco,
            source_repo=args.falco_repo, workspace_root=workspace, generation_id=generation_id)
    clean = [r for r in runs if r.name.endswith("__clean")]
    train_runs, test_runs = clean[:3], clean[3:]
    stide_dir = args.output_root / "stide"; stide_dir.mkdir()
    train, test, filters = [], [], {}
    for split, selected, target in (("train", train_runs, train), ("heldout_clean", test_runs, test)):
        for run in selected:
            src = derived_runs / run.name / "graph/reattributed/resolution_spine_effective/syscalls.jsonl"
            dst = stide_dir / f"{split}.{run.name}.python3_10.jsonl"
            filters[run.name] = filter_executable(src, dst, "/usr/bin/python3.10")
            target.append(dst)
    stide = run_stide(args.stide_repo, train, test, stide_dir)
    stide["observation_generation_id"] = generation_id
    stide["selected_executable"] = "/usr/bin/python3.10"
    stide["split"] = {"train": [r.name for r in train_runs], "heldout_clean": [r.name for r in test_runs],
                      "poisoned_training_runs": 0, "filters": filters}
    write_json(stide_dir / "tool_manifest.json", stide)
    unicorn_run = next(r for r in clean if r.name.startswith("C512_"))
    unicorn = run_unicorn(
        derived_runs / unicorn_run.name / "graph/reattributed/resolution_spine_effective",
        args.output_root / "unicorn", generation_id=generation_id,
        parser_repo=args.unicorn_parser, native_parser=args.unicorn_native_parser,
        modeler_repo=args.unicorn_modeler, native_modeler=args.unicorn_native_modeler,
        analyzer_repo=args.unicorn_analyzer, image=args.unicorn_image)
    statuses = {"aide": Counter(x["status"] for x in aide.values()),
                "falco": Counter(x["status"] for x in falco.values()),
                "stide": stide["status"], "unicorn": unicorn["status"]}
    source_roles = {"collected_sources": ["inotify", "fanotify", "auditd", "ebpf", "scap"],
                    "normalized_graph_sources": generation["contract"]["normalized_graph_sources"],
                    "inotify_role": generation["contract"]["inotify_role"],
                    "fanotify_role": generation["contract"]["fanotify_role"]}
    passed = (statuses["aide"] == {"passed": EXPECTED_RUNS}
              and statuses["falco"] == {"passed": EXPECTED_RUNS}
              and statuses["stide"] == "passed" and statuses["unicorn"] == "passed")
    report = {"schema_version": "assa.p1_detector_acceptance.v1", "passed": passed,
              "observation_generation_id": generation_id, "run_count": len(runs),
              "source_roles": source_roles, "statuses": {k: dict(v) if isinstance(v, Counter) else v for k,v in statuses.items()},
              "aide": {k: {"status": v["status"], "manifest": file_record(args.output_root / "aide" / k / "tool_manifest.json")} for k,v in aide.items()},
              "falco": {k: {"status": v["status"], "events": v["parsed_event_count"],
                             "manifest": file_record(args.output_root / "falco" / k / "tool_manifest.json")} for k,v in falco.items()},
              "stide": {"status": stide["status"], "manifest": file_record(stide_dir / "tool_manifest.json")},
              "unicorn": {"status": unicorn["status"], "manifest": file_record(args.output_root / "unicorn/tool_manifest.json"),
                          "run_id": unicorn_run.name},
              "scope": "engineering acceptance on admitted generation; no FPR/TPR or separability claim",
              "poisoned_data_used_for_training_or_tuning": False}
    write_json(args.output_root / "p1_detector_acceptance_report.json", report)
    write_sha256s(args.output_root)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
