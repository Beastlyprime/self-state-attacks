#!/usr/bin/env python3
"""Score AIDE + STIDE on the D3 partial population (arm64, offline).
AIDE: docker image (arm64), snapshots. STIDE: pinned repo + frozen profile
training + core-executable freeze, on synced resolution_spine_effective syscalls.
Frozen heldout-20 reuse the frozen FPR rows; everything else is scored fresh.
"""
from __future__ import annotations
import glob, json, sys
from pathlib import Path

OUT = Path(__file__).resolve().parent
RES = OUT.parent
ROOT = RES.parent.parent
STAGE = OUT / "staging"
sys.path.insert(0, str(ROOT))
from experiments.code.measurement.stage_g_harness.p2_aide_fpr_gen2 import run_one as aide_run_one
from experiments.code.measurement.stage_g_harness.stide_bridge import run as stide_run

FPR = RES / "p2_detection_20260820/P2_DETECTOR_FPR_GEN1_20260821"
CORE = json.loads((RES / "p2_detection_20260820/P2_STIDE_STOPPING_RULE_PREREGISTRATION.json").read_text())
TRAIN = Path("/tmp/p2_detector_fpr_inputs_20260821_v1/training")
STIDE_REPO = Path("/tmp/assa-stage-g-lid-ds")
AIDE_IMAGE = "assa-stage-g/aide:0.19.3"
GEN = "headtohead_partial_20260825"


def read(p): return json.loads(Path(p).read_text())


def local_fileop_run(case):
    hits = [h for h in glob.glob(str(RES / f"p2_mass_attack_lane*/**/runs/{case}__poisoned"), recursive=True)
            if Path(h).is_dir() and "/.openclaw/" not in h]
    return Path(sorted(hits, key=len)[0]) if hits else None


def snap_root(run_dir: Path) -> Path | None:
    for c in (run_dir / "state_snapshots", run_dir / "semantic/state_snapshots"):
        if (c / "before_a").is_dir():
            return c
    return None


# ---------------- AIDE ----------------
def aide_one(run_id, snap, outdir):
    if snap is None:
        return {"status": "data_insufficient", "reasons": ["no_snapshots"], "binary_decision": None, "native_score": None}
    try:
        manifest = aide_run_one(snap, outdir, Path("/tmp"), AIDE_IMAGE, GEN)
    except Exception as e:
        return {"status": "failed", "reasons": [f"aide_exc:{type(e).__name__}:{e}"], "binary_decision": None, "native_score": None}
    reports = read(outdir / "parsed_reports.json"); deltas = read(outdir / "materialization_deltas.json")
    control = reports.get("before_control") or {}; after = reports.get("after_a") or {}
    cc = sum(int(control.get(k) or 0) for k in ("added", "removed", "changed"))
    ac = sum(int(after.get(k) or 0) for k in ("added", "removed", "changed"))
    reasons = []
    if manifest["status"] != "passed": reasons.append("tool_manifest_not_passed")
    if control.get("parse_status") != "parsed" or not control.get("no_differences") or cc: reasons.append("before_a_control_not_clean")
    if after.get("parse_status") != "parsed": reasons.append("after_a_report_unparsed")
    return {"status": "passed" if not reasons else "failed", "reasons": reasons,
            "binary_decision": (ac > 0) if not reasons else None,
            "native_score": {"after_a_change_count": ac, "before_control_change_count": cc}}


def score_aide(pop):
    rows = []
    frozen = {r["run_id"]: r for r in read(FPR / "aide_gen2/fpr_result.json")["rows"]}
    # attacks: 18 graph + 26 fileop
    for r in pop["attacks_graph_present"]:
        run = STAGE / r["run_id"]; snap = snap_root(run)
        res = aide_one(r["run_id"], snap, ROOT / "data/detection/aide-fixtures/attack" / r["run_id"])
        rows.append({**meta(r), **res})
    for r in pop["attacks_aide_only_fileop"]:
        run = local_fileop_run(r["case_id"]); snap = snap_root(run) if run else None
        res = aide_one(r["run_id"], snap, ROOT / "data/detection/aide-fixtures/attack" / r["run_id"])
        rows.append({**meta(r), **res})
    # clean-40
    for r in pop["clean_heldout_40"]:
        if r["source"] == "P2_HELDOUT_CLEAN_FREEZE_20260821":
            x = frozen[r["run_id"]]
            rows.append({**meta(r), "status": x["status"], "binary_decision": x["binary_decision"],
                         "reasons": x.get("reasons", []), "reuse": "frozen_aide_gen2", "native_score": x.get("native_score")})
        else:
            run = STAGE / r["run_id"]; snap = snap_root(run)
            res = aide_one(r["run_id"], snap, ROOT / "data/detection/aide-fixtures/attack" / r["run_id"])
            rows.append({**meta(r), **res})
    return rows


# ---------------- STIDE ----------------
def stide_one(run_id, profile, syscalls: Path):
    trains = sorted(TRAIN.glob(f"{profile}/*/graph/syscalls.jsonl"))
    pf = CORE.get("profile_freeze", {})
    if not trains or profile not in pf or not syscalls.is_file():
        return {"status": "data_insufficient", "reasons": ["missing_train_or_effective_graph"], "binary_decision": None, "native_score": None}
    result = stide_run(STIDE_REPO, trains, [syscalls], 6, 106)
    cores = pf[profile]["core_executables"]
    cs = {e: result["results"].get(e) for e in cores}
    ev = {e: v for e, v in cs.items() if v and v.get("scoring_gate_passed") is True}
    status = "passed" if ev else "data_insufficient"
    return {"status": status, "reasons": [] if ev else ["no_evaluable_frozen_core_executable"],
            "binary_decision": any(int(v.get("unknown_ngrams") or 0) > 0 for v in ev.values()) if ev else None,
            "native_score": {"evaluable_core_count": len(ev),
                             "core_unknown_ngrams": sum(int(v.get("unknown_ngrams") or 0) for v in ev.values())}}


def score_stide(pop):
    rows = []
    frozen = {r["run_id"]: r for r in read(FPR / "stide/fpr_result.json")["rows"]}
    RSPINE = "graph/reattributed/resolution_spine_effective/syscalls.jsonl"
    for r in pop["attacks_graph_present"]:
        res = stide_one(r["run_id"], r["profile"], STAGE / r["run_id"] / RSPINE)
        rows.append({**meta(r), **res})
    for r in pop["attacks_aide_only_fileop"]:
        rows.append({**meta(r), "status": "non_evaluable", "binary_decision": None,
                     "reasons": ["no_offline_graph_derivation_D1_pending"], "native_score": None})
    for r in pop["clean_heldout_40"]:
        if r["source"] == "P2_HELDOUT_CLEAN_FREEZE_20260821":
            x = frozen[r["run_id"]]
            rows.append({**meta(r), "status": x["status"], "binary_decision": x["binary_decision"],
                         "reasons": x.get("reasons", []), "reuse": "frozen_stide", "native_score": x.get("native_score")})
        else:
            res = stide_one(r["run_id"], r["profile"], STAGE / r["run_id"] / RSPINE)
            rows.append({**meta(r), **res})
    return rows


def meta(r):
    return {"run_id": r["run_id"], "population_id": r["population_id"], "label": r["label"],
            "op_signature": r["op_signature"], "profile": r["profile"],
            "memory_poisoning": r.get("memory_poisoning_Mem_M1", False)}


def main():
    pop = read(OUT / "PARTIAL_LOCKED_POPULATION.json")
    which = sys.argv[1] if len(sys.argv) > 1 else "both"
    if which in ("aide", "both"):
        rows = score_aide(pop)
        (OUT / "scored_aide.json").write_text(json.dumps({"detector": "AIDE", "rows": rows}, indent=2) + "\n")
        print("AIDE rows", len(rows))
    if which in ("stide", "both"):
        rows = score_stide(pop)
        (OUT / "scored_stide.json").write_text(json.dumps({"detector": "STIDE", "rows": rows}, indent=2) + "\n")
        print("STIDE rows", len(rows))


if __name__ == "__main__":
    main()
