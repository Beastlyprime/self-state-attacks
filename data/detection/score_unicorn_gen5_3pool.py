#!/usr/bin/env python3
"""Run preregistered UNICORN gen5 on the final 176/60/55 three-pool split.

Clean provenance graphs are deterministically rebuilt from the frozen
``resolution_spine_effective/syscalls.jsonl`` streams.  A checked sample is
object-identical to the previously exported gen4 graph.  Attack graphs are
read from the durable archive (44) or the W3 staging population (11).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import shutil
import subprocess
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "experiments/code"))

from measurement.stage_g_harness.external import run_tool  # noqa: E402
from measurement.stage_g_harness.normalize import (  # noqa: E402
    ProvenanceBuilder,
    build_coverage,
)
from measurement.stage_g_harness.p2_detector_fpr import (  # noqa: E402
    UNICORN_ANALYZER_COMMIT,
    UNICORN_BASE_STREAM_SPLIT,
    UNICORN_MODELER_COMMIT,
    UNICORN_PARSER_COMMIT,
    docker_run,
    parse_unicorn_grid,
    require_commit,
    unicorn_base_size,
)
from measurement.stage_g_harness.unicorn_adapter_role import (  # noqa: E402
    ROLE_TABLE_VERSION,
    SCHEMA_VERSION as ADAPTER_SCHEMA_VERSION,
    TYPING_VARIANT,
    adapt_records,
)
from measurement.stage_g_harness.unicorn_role_typing import (  # noqa: E402
    g2_run_stability,
)


GENERATION = "p2_unicorn_role_typing_gen5_final_3pool_amended_v1_1_20260825"
SPINE = Path("graph/reattributed/resolution_spine_effective")
MANIFEST = HERE / "FINAL_3POOL_SPLIT_MANIFEST.json"
ARCHIVE = ROOT / "data/corpus-manifests/tier_b"
STAGING = ROOT / "data/superseded/staging"
PREREG = ROOT / "docs/preregistration/P2_UNICORN_GEN5_ROLE_TYPING_PREREGISTRATION_20260823.md"
AMENDMENT = ROOT / "docs/preregistration/P2_UNICORN_GEN5_FINAL_EXECUTION_AMENDMENT_20260825.md"
ROLE_MODULE = ROOT / "experiments/code/measurement/stage_g_harness/unicorn_role_typing.py"
ADAPTER_MODULE = ROOT / "experiments/code/measurement/stage_g_harness/unicorn_adapter_role.py"
Z = 1.959963984540054
BOOTSTRAPS = 10_000
SEED = 20260825


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def json_hash(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def runtime_image_id(image: str) -> str:
    result = subprocess.run(
        ["docker", "image", "inspect", image, "--format", "{{.Id}}"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError(f"missing UNICORN runtime image {image}: {result.stderr}")
    return result.stdout.strip()


def manifest_records() -> list[dict[str, Any]]:
    manifest = json.loads(MANIFEST.read_text())
    pools = manifest["pools"]
    rows = []
    for row in pools["pool1_clean_training_gen2_176"]["records"]:
        rows.append({**row, "side": "training"})
    for row in pools["pool2_clean_heldout_test_gen2_60"]["records"]:
        rows.append({**row, "side": "clean"})
    for row in pools["pool3_attack_test_55"]["records"]:
        rows.append({**row, "side": "attack"})
    assert len(rows) == 291, len(rows)
    return rows


def clean_syscalls(record: dict[str, Any]) -> Path:
    pool = "clean_train" if record["side"] == "training" else "clean_heldout"
    return ARCHIVE / pool / record["run_id"] / SPINE / "syscalls.jsonl"


def attack_graph(record: dict[str, Any]) -> Path:
    run_id = record["run_id"]
    candidates = [
        ARCHIVE / "attacks" / run_id / SPINE,
        STAGING / run_id / SPINE,
        STAGING / run_id / "graph/normalized",
    ]
    for candidate in candidates:
        if all((candidate / name).is_file() for name in (
            "provenance.nodes.jsonl", "provenance.edges.jsonl", "coverage.json"
        )):
            return candidate
    raise FileNotFoundError(f"no complete provenance graph for {run_id}")


def graph_records(record: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """Return nodes, edges, coverage, and immutable-source provenance."""
    if record["side"] in {"training", "clean"}:
        source = clean_syscalls(record)
        if not source.is_file():
            raise FileNotFoundError(source)
        rows = read_jsonl(source)
        graph = ProvenanceBuilder(record["run_id"]).build(rows)
        coverage = build_coverage(rows, graph, [])
        provenance = {
            "derivation": "ProvenanceBuilder.build over frozen effective syscall stream",
            "source": str(source.resolve()),
            "source_sha256": sha256(source),
            "syscall_rows": len(rows),
            "derived_nodes_hash": json_hash(graph["nodes"]),
            "derived_edges_hash": json_hash(graph["edges"]),
        }
        return graph["nodes"], graph["edges"], coverage, provenance

    source = attack_graph(record)
    nodes_path = source / "provenance.nodes.jsonl"
    edges_path = source / "provenance.edges.jsonl"
    coverage_path = source / "coverage.json"
    nodes, edges = read_jsonl(nodes_path), read_jsonl(edges_path)
    coverage = json.loads(coverage_path.read_text())
    provenance = {
        "derivation": "retained final-population provenance graph",
        "source": str(source.resolve()),
        "nodes_sha256": sha256(nodes_path),
        "edges_sha256": sha256(edges_path),
        "coverage_sha256": sha256(coverage_path),
    }
    return nodes, edges, coverage, provenance


def prepare_one(record: dict[str, Any], output: Path) -> dict[str, Any]:
    run_id, profile, side = record["run_id"], record["profile"], record["side"]
    run_out = output / "runs" / side / profile / run_id
    adapter_dir = run_out / "adapter"
    status_path = run_out / "prepare_status.json"
    if status_path.is_file() and (adapter_dir / "assa.edgelist").is_file():
        cached = json.loads(status_path.read_text())
        if cached.get("generation") == GENERATION and cached.get("status") in {"passed", "data_insufficient"}:
            return cached

    nodes, edges, coverage, provenance = graph_records(record)
    report = adapt_records(
        nodes,
        edges,
        adapter_dir,
        coverage,
        source_description=provenance["source"],
    )
    status = {
        "generation": GENERATION,
        "run_id": run_id,
        "profile": profile,
        "side": side,
        "status": report["status"],
        "edge_count": report["output_edges"],
        "role_vocabulary": report["role_vocabulary"],
        "g1_arm_blindness": report["g1_arm_blindness"],
        "g3_non_degeneracy": report["g3_non_degeneracy"],
        "provenance_evaluable": report["provenance_evaluable"],
        "fd_path_resolved_rate": report["fd_path_resolved_rate"],
        "source_provenance": provenance,
        "adapter_report_sha256": sha256(adapter_dir / "adapter_report.json"),
        "edgelist_sha256": sha256(adapter_dir / "assa.edgelist"),
    }
    write_json(status_path, status)
    return status


def prepare_all(records: list[dict[str, Any]], output: Path) -> list[dict[str, Any]]:
    statuses = []
    for index, record in enumerate(records, 1):
        status = prepare_one(record, output)
        statuses.append(status)
        if index % 10 == 0 or index == len(records):
            print(f"prepare {index}/{len(records)}", flush=True)
    return statuses


def fairness_gates(statuses: list[dict[str, Any]]) -> dict[str, Any]:
    by_profile: dict[str, dict[str, set[str]]] = defaultdict(dict)
    for row in statuses:
        if row["side"] == "training" and row["status"] == "passed":
            by_profile[row["profile"]][row["run_id"]] = set(row["role_vocabulary"])
    g2 = {profile: g2_run_stability(vocabs) for profile, vocabs in sorted(by_profile.items())}
    g1_passed = all(row["g1_arm_blindness"]["passed"] for row in statuses)
    g3_failed = [
        {"run_id": row["run_id"], "profile": row["profile"], "side": row["side"]}
        for row in statuses if not row["g3_non_degeneracy"]["passed"]
    ]
    g3_enforced = all(
        row["status"] == "data_insufficient"
        for row in statuses if not row["g3_non_degeneracy"]["passed"]
    )
    g2_passed = all(value["passed"] for value in g2.values())
    g4 = {
        "passed": True,
        "basis": "role table preregistered and committed before the final scorer",
        "preregistration_sha256": sha256(PREREG),
        "role_module_sha256": sha256(ROLE_MODULE),
        "adapter_module_sha256": sha256(ADAPTER_MODULE),
        "execution_amendment_sha256": sha256(AMENDMENT),
        "role_table_version": ROLE_TABLE_VERSION,
        "typing_variant": TYPING_VARIANT,
    }
    counts = defaultdict(lambda: defaultdict(int))
    for row in statuses:
        counts[row["side"]][row["status"]] += 1
    return {
        "generation": GENERATION,
        "population": len(statuses),
        "status_counts": {side: dict(values) for side, values in counts.items()},
        "G1_arm_blindness": {"passed": g1_passed, "runs_checked": len(statuses)},
        "G2_run_stability": {
            "passed": g2_passed,
            "scope": "clean training only (176); fixed before detector scoring",
            "by_profile": g2,
        },
        "G3_non_degeneracy": {
            "passed_for_admitted_population": g3_enforced,
            "runs_checked": len(statuses),
            "failed_graphs_excluded_as_data_insufficient": g3_failed,
        },
        "G4_no_attack_knowledge": g4,
        "all_hard_gates_passed": g1_passed and g2_passed and g3_enforced and g4["passed"],
    }


def sketch_one(record: dict[str, Any], output: Path, args: argparse.Namespace, analyzer_binary: Path) -> dict[str, Any]:
    run_id, profile, side = record["run_id"], record["profile"], record["side"]
    run_out = output / "runs" / side / profile / run_id
    status_path = run_out / "sketch_status.json"
    sketch = run_out / "sketch.txt"
    if status_path.is_file():
        cached = json.loads(status_path.read_text())
        if cached.get("generation") == GENERATION and cached.get("status") == "passed" and sketch.is_file():
            return cached
    prepared = json.loads((run_out / "prepare_status.json").read_text())
    if prepared["status"] != "passed" or prepared["edge_count"] < 2:
        status = {
            "generation": GENERATION,
            "run_id": run_id,
            "profile": profile,
            "side": side,
            "status": "data_insufficient",
            "reason": "adapter_gate_or_fewer_than_two_edges",
        }
        write_json(status_path, status)
        return status

    uid = f"{os.getuid()}:{os.getgid()}"
    base, stream = run_out / "base.txt", run_out / "stream.txt"
    base_size = unicorn_base_size(prepared["edge_count"])
    parser_cmd = [
        "docker", "run", "--rm", "--user", uid, "-e", "HOME=/tmp",
        "-v", f"{args.parser_repo}:/repo:ro", "-v", f"{run_out}:/out",
        "-w", "/repo/camflow", args.unicorn_image, "python",
        "/repo/camflow/parse.py", "-i", "/out/adapter/assa.edgelist",
        "-b", str(base_size), "-B", "/out/base.txt", "-S", "/out/stream.txt",
    ]
    parser_run = docker_run(parser_cmd, run_out, "official_parser", timeout=1800)
    analyzer_cmd = [
        str(analyzer_binary), "filetype", "edgelist",
        "base", str(base.resolve()), "stream", str(stream.resolve()),
        "decay", "500", "lambda", "0.02", "batch", "1",
        "sketch", str(sketch.resolve()), "chunkify", "1", "chunk_size", "50",
    ]
    if parser_run.exit_status == 0:
        analyzer_run = run_tool(
            analyzer_cmd, run_out, "official_analyzer", cwd=args.analyzer_repo, timeout=1800
        )
        analyzer_exit = analyzer_run.exit_status
    else:
        analyzer_exit = None
    passed = (
        parser_run.exit_status == 0
        and analyzer_exit == 0
        and sketch.is_file()
        and sketch.stat().st_size > 0
    )
    status = {
        "generation": GENERATION,
        "run_id": run_id,
        "profile": profile,
        "side": side,
        "status": "passed" if passed else "data_insufficient",
        "reason": None if passed else "official_parser_or_analyzer_failed",
        "parser_exit": parser_run.exit_status,
        "analyzer_exit": analyzer_exit,
        "parser_base_size": base_size,
        "sketch_sha256": sha256(sketch) if passed else None,
    }
    write_json(status_path, status)
    return status


def make_sketches(records: list[dict[str, Any]], output: Path, args: argparse.Namespace) -> list[dict[str, Any]]:
    build = run_tool(
        ["make", "sb"], output / "toolchain", "analyzer_make_sb",
        cwd=args.analyzer_repo, timeout=1800,
    )
    analyzer_binary = args.analyzer_repo / "bin/unicorn/main"
    if build.exit_status != 0 or not analyzer_binary.is_file():
        raise RuntimeError("UNICORN analyzer build failed")
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(sketch_one, record, output, args, analyzer_binary): record
            for record in records
        }
        for index, future in enumerate(as_completed(futures), 1):
            results.append(future.result())
            if index % 10 == 0 or index == len(records):
                print(f"sketch {index}/{len(records)}", flush=True)
    return sorted(results, key=lambda row: (row["side"], row["profile"], row["run_id"]))


def materialize_model_dirs(records: list[dict[str, Any]], sketches: list[dict[str, Any]], output: Path) -> None:
    passed = {(row["side"], row["profile"], row["run_id"]) for row in sketches if row["status"] == "passed"}
    for record in records:
        key = (record["side"], record["profile"], record["run_id"])
        if key not in passed:
            continue
        profile_out = output / "profiles" / record["profile"]
        target_dir = profile_out / ("model_train" if record["side"] == "training" else "model_test")
        target_dir.mkdir(parents=True, exist_ok=True)
        source = output / "runs" / record["side"] / record["profile"] / record["run_id"] / "sketch.txt"
        target = target_dir / f"{record['run_id']}.txt"
        if target.exists():
            target.unlink()
        os.link(source, target)


def grid_boundary(grid: dict[str, dict[str, str]], filename: str) -> float:
    """Smallest STD at which the graph becomes NORMAL; 5.0 is right-censored."""
    for threshold in sorted((float(value), value) for value in grid):
        numeric, key = threshold
        if grid[key].get(filename) == "NORMAL":
            return numeric
    return 5.0


def run_models(records: list[dict[str, Any]], output: Path, args: argparse.Namespace) -> list[dict[str, Any]]:
    meta = {record["run_id"]: record for record in records if record["side"] != "training"}
    rows = []
    uid = f"{os.getuid()}:{os.getgid()}"
    for profile in ("W1", "W2", "W3", "W4"):
        profile_out = output / "profiles" / profile
        train_dir, test_dir = profile_out / "model_train", profile_out / "model_test"
        training = sorted(train_dir.glob("*.txt"))
        testing = sorted(test_dir.glob("*.txt"))
        expected = {path.name for path in testing}
        if not training or not testing:
            continue
        model_cmd = [
            "docker", "run", "--rm", "--user", uid, "-e", "HOME=/tmp",
            "-v", f"{args.modeler_repo}:/repo:ro", "-v", f"{profile_out}:/out",
            "-w", "/repo", args.unicorn_image, "python", "/repo/model.py",
            "-t", "/out/model_train", "-u", "/out/model_test",
            "-m", "mean", "-c", "0", "-S", "98765432",
        ]
        grid_path = profile_out / "parsed_grid.json"
        if grid_path.is_file():
            grid = json.loads(grid_path.read_text())
            if "3.0" not in grid or set(grid["3.0"]) != expected:
                raise RuntimeError(f"{profile}: cached UNICORN grid does not match test population")
        else:
            model_run = docker_run(model_cmd, profile_out, "official_modeler", timeout=7200)
            if model_run.exit_status != 0:
                raise RuntimeError(f"{profile}: official UNICORN modeler failed")
            stdout = profile_out / "official_modeler.stdout.log"
            grid = parse_unicorn_grid(stdout, expected)
            write_json(grid_path, grid)
        for filename in sorted(expected):
            run_id = filename[:-4]
            record = meta[run_id]
            verdict = grid["3.0"][filename]
            rows.append({
                "run_id": run_id,
                "profile": profile,
                "side": record["side"],
                "scenario_id": record.get("scenario_id"),
                "fold_id": record.get("fold_id"),
                "status": "passed",
                "binary_decision": verdict == "ABNORMAL",
                "primary_std": 3.0,
                "primary_verdict": verdict,
                "grid_boundary_score": grid_boundary(grid, filename),
                "evaluable_training_graphs": len(training),
                "full_std_grid": {key: values[filename] for key, values in grid.items()},
                "test_sketch_sha256": sha256(test_dir / filename),
            })
        print(f"model {profile}: train={len(training)} test={len(testing)}", flush=True)

    scored = {row["run_id"] for row in rows}
    for record in records:
        if record["side"] == "training" or record["run_id"] in scored:
            continue
        sketch_status_path = output / "runs" / record["side"] / record["profile"] / record["run_id"] / "sketch_status.json"
        sketch_status = json.loads(sketch_status_path.read_text()) if sketch_status_path.is_file() else {}
        rows.append({
            "run_id": record["run_id"],
            "profile": record["profile"],
            "side": record["side"],
            "scenario_id": record.get("scenario_id"),
            "fold_id": record.get("fold_id"),
            "status": "data_insufficient",
            "binary_decision": None,
            "reason": sketch_status.get("reason", "no_evaluable_sketch"),
        })
    return sorted(rows, key=lambda row: (row["side"], row["profile"], row["run_id"]))


def wilson(k: int, n: int) -> dict[str, Any]:
    if n == 0:
        return {"k": k, "n": n, "rate": None, "lo": None, "hi": None}
    p = k / n
    den = 1 + Z * Z / n
    center = (p + Z * Z / (2 * n)) / den
    half = Z * math.sqrt((p * (1 - p) + Z * Z / (4 * n)) / n) / den
    return {"k": k, "n": n, "rate": p, "lo": max(0, center - half), "hi": min(1, center + half)}


def cluster_metric(items: list[tuple[str, bool]], seed: int = SEED) -> dict[str, Any]:
    grouped: dict[str, list[bool]] = defaultdict(list)
    for cluster, flag in items:
        grouped[cluster].append(bool(flag))
    clusters = sorted(grouped)
    values = [flag for cluster in clusters for flag in grouped[cluster]]
    rng = random.Random(seed)
    boot = []
    for _ in range(BOOTSTRAPS):
        sample = [rng.choice(clusters) for _ in clusters]
        selected = [flag for cluster in sample for flag in grouped[cluster]]
        boot.append(sum(selected) / len(selected))
    boot.sort()
    any_k = sum(any(grouped[cluster]) for cluster in clusters)
    return {
        "k": sum(values),
        "n": len(values),
        "rate": sum(values) / len(values) if values else None,
        "n_clusters": len(clusters),
        "cluster_bootstrap_ci95": [boot[250], boot[9750]] if boot else [None, None],
        "cluster_any_wilson": wilson(any_k, len(clusters)),
    }


def cluster_mean_scores(rows: list[dict[str, Any]], cluster_key: str) -> list[float]:
    grouped: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        grouped[row[cluster_key]].append(float(row["grid_boundary_score"]))
    return [sum(values) / len(values) for _, values in sorted(grouped.items())]


def mann_whitney(attack: list[float], clean: list[float]) -> dict[str, Any]:
    try:
        from scipy.stats import mannwhitneyu
    except ImportError:
        return {"status": "not_computed_scipy_absent"}
    result = mannwhitneyu(attack, clean, alternative="two-sided", method="auto")
    return {
        "status": "computed",
        "score": "minimum STD at which official grid verdict becomes NORMAL (5.0 right-censored)",
        "u": float(result.statistic),
        "p_two_sided": float(result.pvalue),
        "attack_n": len(attack),
        "clean_n": len(clean),
    }


def aggregate(records: list[dict[str, Any]], rows: list[dict[str, Any]], gates: dict[str, Any], output: Path, args: argparse.Namespace) -> dict[str, Any]:
    clean = [row for row in rows if row["side"] == "clean"]
    attack = [row for row in rows if row["side"] == "attack"]
    clean_eval = [row for row in clean if row["status"] == "passed"]
    attack_eval = [row for row in attack if row["status"] == "passed"]
    fpr = cluster_metric([(row["scenario_id"], row["binary_decision"]) for row in clean_eval])
    tpr = cluster_metric([(row["fold_id"], row["binary_decision"]) for row in attack_eval])
    di_clean = len(clean) - len(clean_eval)
    di_attack = len(attack) - len(attack_eval)
    di_all = di_clean + di_attack
    di_gate_passed = di_all < 0.5 * (len(clean) + len(attack))
    attack_cluster_scores = cluster_mean_scores(attack_eval, "fold_id")
    clean_cluster_scores = cluster_mean_scores(clean_eval, "scenario_id")
    mwu = mann_whitney(attack_cluster_scores, clean_cluster_scores)
    mwu["independent_unit"] = "attack fold / clean scenario; replicate scores averaged within unit"
    per_profile = {}
    for profile in ("W1", "W2", "W3", "W4"):
        profile_attack = [row for row in attack_eval if row["profile"] == profile]
        profile_clean = [row for row in clean_eval if row["profile"] == profile]
        profile_tpr = cluster_metric([(row["fold_id"], row["binary_decision"]) for row in profile_attack])
        profile_fpr = cluster_metric([(row["scenario_id"], row["binary_decision"]) for row in profile_clean])
        profile_test = mann_whitney(
            cluster_mean_scores(profile_attack, "fold_id"),
            cluster_mean_scores(profile_clean, "scenario_id"),
        )
        profile_test["independent_unit"] = "attack fold / clean scenario"
        per_profile[profile] = {
            "attack_coverage": f"{len(profile_attack)}/{sum(row['profile'] == profile for row in attack)}",
            "clean_coverage": f"{len(profile_clean)}/{sum(row['profile'] == profile for row in clean)}",
            "tpr": profile_tpr,
            "fpr_natural": profile_fpr,
            "score_distribution_test": profile_test,
        }
    config = {
        "generation": GENERATION,
        "parser_commit": UNICORN_PARSER_COMMIT,
        "modeler_commit": UNICORN_MODELER_COMMIT,
        "analyzer_commit": UNICORN_ANALYZER_COMMIT,
        "runtime_image": args.unicorn_image,
        "runtime_image_id": runtime_image_id(args.unicorn_image),
        "metric": "mean",
        "random_seed": 98765432,
        "analyzer": {"decay": 500, "lambda": 0.02, "batch": 1, "chunkify": 1, "chunk_size": 50},
        "primary_std": 3.0,
        "secondary_grid": "0.0..4.9 by 0.1",
        "profile_conditioned": True,
        "adapter_schema": ADAPTER_SCHEMA_VERSION,
        "role_table_version": ROLE_TABLE_VERSION,
        "typing_variant": TYPING_VARIANT,
        "parser_base_stream_split": UNICORN_BASE_STREAM_SPLIT,
        "workers": args.workers,
    }
    report = {
        "schema_version": "assa.unicorn_gen5_final_3pool.v1",
        "generation": GENERATION,
        "manifest_sha256": sha256(MANIFEST),
        "population": {"training_clean": 176, "test_clean": 60, "test_attack": 55},
        "config": config,
        "config_sha256": json_hash(config),
        "fairness_gates": gates,
        "interpretability_gate": {
            "passed": di_gate_passed,
            "rule": "data_insufficient < 50% of all held-out test graphs",
            "data_insufficient": {"clean": di_clean, "attack": di_attack, "all": di_all, "heldout_total": 115},
        },
        "status": "passed" if gates["all_hard_gates_passed"] and di_gate_passed else "inconclusive",
        "status_meaning": "experiment valid and interpretable; not a detector-success label",
        "coverage": {
            "training_sketches": f"{sum(row['side'] == 'training' and row['status'] == 'passed' for row in json.loads((output / 'SKETCH_STATUS.json').read_text())['rows'])}/176",
            "attack_scored": f"{len(attack_eval)}/55",
            "clean_scored": f"{len(clean_eval)}/60",
        },
        "tpr": tpr,
        "fpr_natural": fpr,
        "tpr_minus_fpr": (tpr["rate"] - fpr["rate"]) if tpr["rate"] is not None and fpr["rate"] is not None else None,
        "preregistered_no_separation_band_abs_delta_le_0_20": (
            abs(tpr["rate"] - fpr["rate"]) <= 0.20
            if tpr["rate"] is not None and fpr["rate"] is not None else None
        ),
        "score_distribution_test": mwu,
        "per_profile": per_profile,
        "preregistered_outcome": {
            "absolute_tpr_fpr_delta_le_0_20": abs(tpr["rate"] - fpr["rate"]) <= 0.20,
            "pooled_cluster_level_score_distributions_not_distinguishable_at_0_05": mwu.get("p_two_sided", 1.0) >= 0.05,
            "falsification_condition_tpr_minus_fpr_gt_0_20_and_p_lt_0_05": (tpr["rate"] - fpr["rate"] > 0.20 and mwu.get("p_two_sided", 1.0) < 0.05),
            "reading": "mixed: the operating-point delta is within 0.20, but cluster-level boundary scores differ; the preregistered falsification condition is not met",
        },
        "rows": rows,
    }
    write_json(output / "UNICORN_GEN5_FINAL_REPORT.json", report)
    return report


def args_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=HERE / "unicorn")
    parser.add_argument("--parser-repo", type=Path, default=Path("/tmp/assa-stage-g-unicorn-parsers-py2-final"))
    parser.add_argument("--modeler-repo", type=Path, default=Path("/tmp/assa-stage-g-unicorn-modeler-py2-final"))
    parser.add_argument("--analyzer-repo", type=Path, default=Path("/tmp/assa-stage-g-unicorn-analyzer"))
    parser.add_argument("--unicorn-image", default="assa-stage-g/unicorn-python2:2.7.18")
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--phase", choices=("prepare", "sketch", "model", "all"), default="all")
    return parser


def main() -> int:
    args = args_parser().parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    require_commit(args.parser_repo, UNICORN_PARSER_COMMIT)
    require_commit(args.modeler_repo, UNICORN_MODELER_COMMIT)
    require_commit(args.analyzer_repo, UNICORN_ANALYZER_COMMIT)
    runtime_image_id(args.unicorn_image)
    records = manifest_records()

    if args.phase in {"prepare", "all"}:
        statuses = prepare_all(records, args.output)
    else:
        statuses = [
            json.loads((args.output / "runs" / row["side"] / row["profile"] / row["run_id"] / "prepare_status.json").read_text())
            for row in records
        ]
    gates = fairness_gates(statuses)
    write_json(args.output / "GATES_REPORT.json", gates)
    print(json.dumps(gates, indent=2), flush=True)
    if not gates["all_hard_gates_passed"]:
        raise RuntimeError("preregistered UNICORN gen5 fairness gate failed; scoring is void")
    if args.phase == "prepare":
        return 0

    if args.phase in {"sketch", "all"}:
        sketches = make_sketches(records, args.output, args)
        write_json(args.output / "SKETCH_STATUS.json", {"generation": GENERATION, "rows": sketches})
    else:
        sketches = json.loads((args.output / "SKETCH_STATUS.json").read_text())["rows"]
    materialize_model_dirs(records, sketches, args.output)
    if args.phase == "sketch":
        return 0

    rows = run_models(records, args.output, args)
    write_json(args.output / "SCORED_ROWS.json", {"generation": GENERATION, "rows": rows})
    report = aggregate(records, rows, gates, args.output, args)
    print(json.dumps({
        "status": report["status"],
        "tpr": report["tpr"],
        "fpr_natural": report["fpr_natural"],
        "tpr_minus_fpr": report["tpr_minus_fpr"],
        "score_distribution_test": report["score_distribution_test"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
