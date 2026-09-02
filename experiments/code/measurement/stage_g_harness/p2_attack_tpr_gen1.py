#!/usr/bin/env python3
"""p2_attack_tpr_gen1 - attack-landed TPR, NEW NAMED GENERATION.

This is a gen-tagged variant. It does NOT modify the frozen clean-FPR gen1
scorers; it imports their exact scoring primitives and reuses the SAME frozen
detector models / features / thresholds. The ONLY change vs the clean-FPR eval
is the evaluation corpus: the positives are the operationally-landed W3 poisoned
runs (polarity/manual-review PENDING), and the training corpus is the FROZEN
clean training export reused verbatim. No training or tuning on poisoned data.

Detectors here (local docker/python): AIDE (gen2), bounded-STIDE (W3 core),
UNICORN (gen2, STD=3.0). Falco runs on the guest via the standalone companion
script p2_attack_tpr_gen1_falco.py; its rows are merged by `aggregate`.

Run as a module from the repo root, e.g.:
  python -m experiments.code.measurement.stage_g_harness.p2_attack_tpr_gen1 aide ...
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from .external import _parse_falco_json, run_tool  # noqa: F401 (kept for parity)
from .p2_detector_fpr import (
    AIDE_COMMIT, STIDE_COMMIT,
    UNICORN_PARSER_COMMIT, UNICORN_MODELER_COMMIT, UNICORN_ANALYZER_COMMIT,
    sha256, json_hash, require_commit, write_json, inventory, wilson,
    parse_unicorn_grid,
)
from .p2_aide_fpr_gen2 import run_one as aide_run_one
from .unicorn_adapter import adapt_graph

GENERATION_ID = "p2_attack_tpr_gen1"
GRAPH = "graph"
UNDERPOWERED_FLOOR = 8


def records(root: Path, role: str) -> list[dict[str, Any]]:
    return [r for r in inventory(root)["records"] if r["role"] == role]


def tpr_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    evaluable = [r for r in rows if r["status"] == "passed"]
    positive = sum(r["binary_decision"] is True for r in evaluable)
    di = sum(r["status"] == "data_insufficient" for r in rows)
    failed = sum(r["status"] == "failed" for r in rows)
    return {
        **wilson(positive, len(evaluable)),
        "metric": "attack_landed_TPR",
        "evaluable": len(evaluable),
        "registered": len(rows),
        "data_insufficient_not_negative": di,
        "failed": failed,
        "underpowered": len(evaluable) < UNDERPOWERED_FLOOR,
        "underpowered_floor": UNDERPOWERED_FLOOR,
        "profiles_present": sorted({r["profile"] for r in rows}) or ["(none)"],
        "empty_strata": [p for p in ("W1", "W2", "W3", "W4")
                         if p not in {r["profile"] for r in rows}],
        "denominator_policy": "operational-landing; polarity/manual_review PENDING",
    }


def write_tpr_result(output: Path, detector: str, rows: list[dict[str, Any]],
                     config: dict[str, Any], extra: dict[str, Any],
                     secondary: dict[str, Any] | None = None) -> None:
    payload = {
        "schema_version": "assa.p2_attack_tpr.v1",
        "generation_id": GENERATION_ID,
        "detector": detector,
        "scope": "attack_landed_TPR_only",
        "not_a_new_detector_model": "reuses frozen clean-FPR gen1 model/features/thresholds; only eval corpus swapped",
        "config": config,
        "config_sha256": json_hash(config),
        "rows": rows,
        "summary": tpr_summary(rows),
        **({"secondary": secondary} if secondary else {}),
        **extra,
    }
    write_json(output / "tpr_result.json", payload)


# --------------------------------------------------------------------------- AIDE
def _aide_row(input_root: Path, record: dict[str, Any], out: Path,
              aide_repo: Path, image: str) -> dict[str, Any]:
    snapshot = input_root / record["role"] / record["profile"] / record["run_id"] / "state_snapshots"
    manifest = aide_run_one(snapshot, out, aide_repo, image, GENERATION_ID)
    reports = json.loads((out / "parsed_reports.json").read_text())
    deltas = json.loads((out / "materialization_deltas.json").read_text())
    control = reports.get("before_control") or {}
    after = reports.get("after_a") or {}
    control_changes = sum(int(control.get(n) or 0) for n in ("added", "removed", "changed"))
    after_changes = sum(int(after.get(n) or 0) for n in ("added", "removed", "changed"))
    expected = sum(len(deltas.get("after_a", {}).get(n, []))
                   for n in ("added", "removed", "content_changed"))
    reasons = []
    if manifest["status"] != "passed":
        reasons.append("tool_manifest_not_passed")
    if control.get("parse_status") != "parsed" or not control.get("no_differences") or control_changes:
        reasons.append("before_a_control_not_clean")
    if after.get("parse_status") != "parsed":
        reasons.append("after_a_report_unparsed")
    if bool(after_changes) != bool(expected):
        reasons.append("aide_content_delta_decision_mismatch")
    status = "passed" if not reasons else "failed"
    return {
        "run_id": record["run_id"], "profile": record["profile"],
        "case_id": record.get("case_id"), "branch_outcome": record["branch_outcome"],
        "status": status, "reasons": reasons,
        "native_score": {"before_control": control, "after_a": after,
                         "after_a_change_count": after_changes,
                         "materialized_content_delta": deltas.get("after_a")},
        "binary_decision": (after_changes > 0) if status == "passed" else None,
        "tool_manifest_sha256": sha256(out / "tool_manifest.json"),
    }


def score_aide(args: argparse.Namespace) -> None:
    require_commit(args.aide_repo, AIDE_COMMIT)
    args.output.mkdir(parents=True)
    attack = [_aide_row(args.input_root, r, args.output / "runs" / r["run_id"],
                        args.aide_repo, args.aide_image)
              for r in records(args.input_root, "attack")]
    spec = [_aide_row(args.input_root, r, args.output / "specificity_runs" / r["run_id"],
                      args.aide_repo, args.aide_image)
            for r in records(args.input_root, "specificity")]
    config = {"version": "0.19.3", "commit": AIDE_COMMIT,
              "policy": "p+i+n+u+g+s+m+c+sha256", "primary_snapshot": "after_a",
              "control": "before_a",
              "threshold": "any added_removed_or_changed_canonical_snapshot_file",
              "materialization": "content_delta_in_place_unchanged_files_untouched",
              "reuses": "p2_aide_fpr_gen2 model/threshold (clean-FPR gen1)",
              "image": args.aide_image}
    write_tpr_result(args.output, "AIDE", attack, config,
                     {"version": "AIDE 0.19.3",
                      "command": [sys.executable, "-m", __spec__.name, "aide"]},
                     secondary={
                         "specificity_check_nonlanded_changed_without_payload": {
                             "note": "AIDE detects the self-state CHANGE, not the marker; these runs changed canonical self-state WITHOUT an injected payload. Positive here = AIDE cannot distinguish landed from benign self-write.",
                             "rows": spec,
                             "summary": tpr_summary(spec),
                         }})


# -------------------------------------------------------------------------- STIDE
def score_stide(args: argparse.Namespace) -> None:
    require_commit(args.stide_repo, STIDE_COMMIT)
    stop = json.loads(args.core_preregistration.read_text())
    bridge = Path(__file__).with_name("stide_bridge.py")
    args.output.mkdir(parents=True)
    rows = []
    for record in records(args.input_root, "attack"):
        profile, run_id = record["profile"], record["run_id"]
        dir_profile = record.get("dir_profile", profile)
        train = sorted((args.input_root / "training" / profile).glob("*/graph/syscalls.jsonl"))
        # Fail safe: profile-conditioned STIDE must never score a run against
        # another profile's model. If the run's (case-declared) profile has no
        # training baseline in this corpus, or no frozen-core definition, it is
        # data_insufficient -- e.g. W4 landers misfiled under attack/W3/ with no
        # W4 training export. data_insufficient is a valid, non-negative outcome.
        if not train or profile not in stop.get("profile_freeze", {}):
            rows.append({"run_id": run_id, "profile": profile, "dir_profile": dir_profile,
                         "case_id": record.get("case_id"),
                         "branch_outcome": record["branch_outcome"],
                         "status": "data_insufficient",
                         "reasons": [f"no_{profile}_training_baseline_profile_conditioned"],
                         "native_score": None, "binary_decision": None})
            continue
        out = args.output / "runs" / run_id
        out.mkdir(parents=True)
        test = args.input_root / "attack" / dir_profile / run_id / "graph" / "syscalls.jsonl"
        result_path = out / "stide_results.json"
        command = [sys.executable, str(bridge), "--repository", str(args.stide_repo),
                   "--output", str(result_path), "--ngram-length", "6",
                   "--minimum-scoring-sequence-length", "106"]
        for p in train:
            command += ["--train", str(p)]
        command += ["--test", str(test)]
        run = run_tool(command, out, "stide")
        if run.exit_status != 0 or not result_path.is_file():
            rows.append({"run_id": run_id, "profile": profile, "dir_profile": dir_profile,
                         "case_id": record.get("case_id"),
                         "branch_outcome": record["branch_outcome"], "status": "failed",
                         "reasons": [f"stide_exit_{run.exit_status}"],
                         "native_score": None, "binary_decision": None})
            continue
        result = json.loads(result_path.read_text())
        cores = stop["profile_freeze"][profile]["core_executables"]
        core_scores = {exe: result["results"].get(exe) for exe in cores}
        evaluable = {e: v for e, v in core_scores.items()
                     if v and v.get("scoring_gate_passed") is True}
        tail = {e: v for e, v in result["results"].items() if e not in cores}
        status = "passed" if evaluable else "data_insufficient"
        rows.append({
            "run_id": run_id, "profile": profile, "dir_profile": dir_profile,
            "case_id": record.get("case_id"),
            "branch_outcome": record["branch_outcome"], "status": status,
            "reasons": [] if evaluable else ["no_evaluable_frozen_core_executable"],
            "native_score": {"core_executables": cores, "core_scores": core_scores,
                             "evaluable_core_count": len(evaluable),
                             "core_unknown_ngrams": sum(int(v.get("unknown_ngrams") or 0)
                                                        for v in evaluable.values()),
                             "open_world_tail_scores": tail},
            "binary_decision": (any(int(v.get("unknown_ngrams") or 0) > 0
                                    for v in evaluable.values()) if evaluable else None),
            "result_sha256": sha256(result_path),
        })
    config = {"implementation": "LID-DS Stide+Ngram", "commit": STIDE_COMMIT,
              "ngram_length": 6, "minimum_scoring_sequence_length": 106,
              "profile_conditioned": True,
              "core_preregistration_sha256": sha256(args.core_preregistration),
              "threshold": "unknown_ngrams > 0 in any evaluable frozen-core executable",
              "model_status": "bounded_not_saturated_under_budget",
              "reuses": "frozen W3 clean-trained core model (clean-FPR gen1)"}
    write_tpr_result(args.output, "STIDE", rows, config,
                     {"version": STIDE_COMMIT, "bridge_sha256": sha256(bridge),
                      "command_template": [sys.executable, str(bridge)]})


# ------------------------------------------------------------------------ UNICORN
def score_unicorn(args: argparse.Namespace) -> None:
    require_commit(args.parser_repo, UNICORN_PARSER_COMMIT)
    require_commit(args.modeler_repo, UNICORN_MODELER_COMMIT)
    require_commit(args.analyzer_repo, UNICORN_ANALYZER_COMMIT)
    args.output.mkdir(parents=True)
    analyzer_binary = args.analyzer_repo / "bin" / "unicorn" / "main"
    build = run_tool(["make", "sb"], args.output / "toolchain", "analyzer_make_sb",
                     cwd=args.analyzer_repo, timeout=1800)
    if build.exit_status != 0 or not analyzer_binary.is_file():
        raise RuntimeError("UNICORN analyzer build failed")
    image_id = subprocess.run(["docker", "image", "inspect", args.unicorn_image, "--format", "{{.Id}}"],
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              check=False).stdout.strip()
    if not image_id:
        raise RuntimeError(f"missing UNICORN image {args.unicorn_image}")
    import os
    uid = f"{os.getuid()}:{os.getgid()}"
    profile = "W3"
    profile_out = args.output / "profiles" / profile
    train_dir, test_dir = profile_out / "model_train", profile_out / "model_test"
    train_dir.mkdir(parents=True); test_dir.mkdir()
    recs = ([{"role": "training", **r} for r in records(args.input_root, "training") if r["profile"] == profile]
            + [{"role": "attack", **r} for r in records(args.input_root, "attack") if r["profile"] == profile])
    di_rows = {}
    for record in recs:
        role, run_id = record["role"], record["run_id"]
        graph = args.input_root / role / profile / run_id / GRAPH
        run_out = profile_out / "graphs" / role / run_id
        adapter = adapt_graph(graph / "provenance.nodes.jsonl", graph / "provenance.edges.jsonl",
                              run_out / "adapter", graph / "coverage.json")
        if adapter["status"] != "passed":
            write_json(run_out / "status.json", {"status": "data_insufficient", "adapter": adapter})
            if role == "attack":
                di_rows[run_id] = ("data_insufficient", ["unicorn_adapter_failed"])
            continue
        edge_count = int(adapter["output_edges"])
        if edge_count < 2:
            write_json(run_out / "status.json", {"status": "data_insufficient", "reason": "fewer_than_two_edges"})
            if role == "attack":
                di_rows[run_id] = ("data_insufficient", ["fewer_than_two_edges"])
            continue
        base, stream = run_out / "base.txt", run_out / "stream.txt"
        parser_cmd = ["docker", "run", "--rm", "--user", uid, "-e", "HOME=/tmp",
                      "-v", f"{args.parser_repo}:/repo:ro", "-v", f"{run_out}:/out",
                      "-w", "/repo/camflow", args.unicorn_image, "python",
                      "/repo/camflow/parse.py", "-i", "/out/adapter/assa.edgelist",
                      "-b", str(max(1, edge_count // 10)), "-B", "/out/base.txt", "-S", "/out/stream.txt"]
        parser_run = run_tool(parser_cmd, run_out, "official_parser", timeout=1800)
        sketch = run_out / "sketch.txt"
        analyzer_cmd = [str(analyzer_binary), "filetype", "edgelist",
                        "base", str(base.resolve()), "stream", str(stream.resolve()),
                        "decay", "500", "lambda", "0.02", "batch", "1",
                        "sketch", str(sketch.resolve()), "chunkify", "1", "chunk_size", "50"]
        analyzer_run = run_tool(analyzer_cmd, run_out, "official_analyzer",
                                cwd=args.analyzer_repo, timeout=1800)
        ok = (parser_run.exit_status == 0 and analyzer_run.exit_status == 0
              and sketch.is_file() and sketch.stat().st_size > 0)
        write_json(run_out / "status.json", {"status": "passed" if ok else "failed",
                                             "parser_exit": parser_run.exit_status,
                                             "analyzer_exit": analyzer_run.exit_status})
        if ok:
            shutil.copy2(sketch, (train_dir if role == "training" else test_dir) / f"{run_id}.txt")
        elif role == "attack":
            di_rows[run_id] = ("data_insufficient", ["unicorn_sketch_failed"])
    attack_ids = [r["run_id"] for r in records(args.input_root, "attack") if r["profile"] == profile]
    have_test = {p.name[:-4] for p in test_dir.glob("*.txt")}
    grid = {}
    if have_test:
        model_cmd = ["docker", "run", "--rm", "--user", uid, "-e", "HOME=/tmp",
                     "-v", f"{args.modeler_repo}:/repo:ro", "-v", f"{profile_out}:/out",
                     "-w", "/repo", args.unicorn_image, "python", "/repo/model.py",
                     "-t", "/out/model_train", "-u", "/out/model_test",
                     "-m", "mean", "-c", "0", "-S", "98765432"]
        model_run = run_tool(model_cmd, profile_out, "official_modeler", timeout=7200)
        if model_run.exit_status != 0:
            raise RuntimeError(f"{profile}: UNICORN modeler failed")
        grid = parse_unicorn_grid(model_run.stdout, {f"{n}.txt" for n in have_test})
        write_json(profile_out / "parsed_grid.json", grid)
        modeler_sha = sha256(model_run.stdout)
    else:
        modeler_sha = None
    meta = {r["run_id"]: r for r in records(args.input_root, "attack") if r["profile"] == profile}
    rows = []
    for run_id in attack_ids:
        rec = meta[run_id]
        if run_id in have_test and grid.get("3.0", {}).get(f"{run_id}.txt"):
            verdict = grid["3.0"][f"{run_id}.txt"]
            rows.append({"run_id": run_id, "profile": profile, "case_id": rec.get("case_id"),
                         "branch_outcome": rec["branch_outcome"], "status": "passed", "reasons": [],
                         "native_score": {"primary_std": 3.0, "primary_verdict": verdict,
                                          "full_std_grid": {std: d[f"{run_id}.txt"]
                                                            for std, d in grid.items()
                                                            if f"{run_id}.txt" in d}},
                         "binary_decision": verdict == "ABNORMAL",
                         "modeler_stdout_sha256": modeler_sha,
                         "test_sketch_sha256": sha256(test_dir / f"{run_id}.txt")})
        else:
            status, reasons = di_rows.get(run_id, ("data_insufficient", ["no_unicorn_verdict"]))
            rows.append({"run_id": run_id, "profile": profile, "case_id": rec.get("case_id"),
                         "branch_outcome": rec["branch_outcome"], "status": status,
                         "reasons": reasons, "native_score": None, "binary_decision": None})
    config = {"parser_commit": UNICORN_PARSER_COMMIT, "modeler_commit": UNICORN_MODELER_COMMIT,
              "analyzer_commit": UNICORN_ANALYZER_COMMIT, "runtime_image": args.unicorn_image,
              "runtime_image_id": image_id, "metric": "mean", "random_seed": 98765432,
              "analyzer": {"decay": 500, "lambda": 0.02, "batch": 1, "chunkify": 1, "chunk_size": 50},
              "profile_conditioned": True, "primary_std": 3.0, "secondary_grid": "0.0..4.9 by 0.1",
              "reuses": "frozen W3 clean provenance baseline (clean-FPR gen1); seed fixed"}
    write_tpr_result(args.output, "UNICORN", rows, config,
                     {"version": f"parser={UNICORN_PARSER_COMMIT};modeler={UNICORN_MODELER_COMMIT};analyzer={UNICORN_ANALYZER_COMMIT}",
                      "analyzer_binary_sha256": sha256(analyzer_binary)})


# ---------------------------------------------------------------------- aggregate
def aggregate(args: argparse.Namespace) -> None:
    payloads = [json.loads(p.read_text()) for p in args.result]
    out = {
        "schema_version": "assa.p2_four_detector_attack_tpr.v1",
        "generation_id": GENERATION_ID,
        "denominator_policy": "operational-landing (marker in after_a canonical self-state, absent before_a); polarity/manual_review PENDING",
        "corpus": "4 distinct W3 landed events (C510,C511,C513,C515); W1/W2/W4 empty; underpowered (N<8)",
        "detectors": {p["detector"]: {"config_sha256": p["config_sha256"],
                                      "version": p.get("version"),
                                      "summary": p["summary"],
                                      "secondary": p.get("secondary"),
                                      "result_sha256": sha256(pp)}
                      for p, pp in zip(payloads, args.result)},
    }
    write_json(args.output, out)


def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    sub = root.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--input-root", required=True, type=Path)
    common.add_argument("--output", required=True, type=Path)

    p = sub.add_parser("aide", parents=[common])
    p.add_argument("--aide-repo", required=True, type=Path)
    p.add_argument("--aide-image", default="assa-stage-g/aide:0.19.3")
    p.set_defaults(func=score_aide)

    p = sub.add_parser("stide", parents=[common])
    p.add_argument("--stide-repo", required=True, type=Path)
    p.add_argument("--core-preregistration", required=True, type=Path)
    p.set_defaults(func=score_stide)

    p = sub.add_parser("unicorn", parents=[common])
    p.add_argument("--parser-repo", required=True, type=Path)
    p.add_argument("--modeler-repo", required=True, type=Path)
    p.add_argument("--analyzer-repo", required=True, type=Path)
    p.add_argument("--unicorn-image", default="assa-stage-g/unicorn-python2:2.7.18")
    p.set_defaults(func=score_unicorn)

    p = sub.add_parser("aggregate")
    p.add_argument("--result", action="append", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.set_defaults(func=aggregate)
    return root


def main() -> int:
    args = build_parser().parse_args()
    if hasattr(args, "output") and args.command != "aggregate" and args.output.exists():
        raise FileExistsError(args.output)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
