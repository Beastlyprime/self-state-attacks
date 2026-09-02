#!/usr/bin/env python3
"""FULL head-to-head scoring on the FROZEN POPULATION MANIFEST (offline).

Reuses the dry-run-verified detector primitives verbatim:
  - ours B1/B2 : score_ours.{extract_ops,fit_baseline,run_decision}  (paper Eq.1 z-score)
  - STIDE      : stide_bridge.run  (LID-DS, n=6, min-seq 106, profile-conditioned frozen core)
  - AIDE       : p2_aide_fpr_gen2.run_one  (arm64 docker, canonical snapshot delta)
Falco is merged from the D2 precompute in aggregate (do NOT re-run Falco).

Detector definability (ruling 2): ours-B1/B2 scores only marker_write_resolved
landers; the 32 no-resolved-write landers are N/A (not a miss). STIDE/AIDE score
all landers with the requisite substrate. FPR = clean-40 (ruling 4).
"""
from __future__ import annotations
import json, sys, importlib.util
from pathlib import Path

OUT = Path(__file__).resolve().parent
RES = OUT.parent
ROOT = RES.parent.parent
STAGE = OUT / "staging"
sys.path.insert(0, str(ROOT))
from experiments.code.measurement.stage_g_harness.p2_aide_fpr_gen2 import run_one as aide_run_one
from experiments.code.measurement.stage_g_harness.stide_bridge import run as stide_run

# ours primitives (import module without running its main)
_spec = importlib.util.spec_from_file_location("score_ours", OUT / "score_ours.py")
so = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(so)

FPR = RES / "p2_detection_20260820/P2_DETECTOR_FPR_GEN1_20260821"
CORE = json.loads((RES / "p2_detection_20260820/P2_STIDE_STOPPING_RULE_PREREGISTRATION.json").read_text())
TRAIN = Path("/tmp/p2_detector_fpr_inputs_20260821_v1/training")
STIDE_REPO = Path("/tmp/assa-stage-g-lid-ds")
AIDE_IMAGE = "assa-stage-g/aide:0.19.3"
MAN = json.loads((OUT / "FROZEN_POPULATION_MANIFEST.json").read_text())
GEN = MAN["derivation_generation"]


def read(p): return json.loads(Path(p).read_text())


def snap_root(run_dir: Path):
    for c in (run_dir / "state_snapshots", run_dir / "semantic/state_snapshots"):
        if (c / "before_a").is_dir():
            return c
    return None


def attack_snap(a):
    if a.get("aide_snapshot_source") == "local_repo":
        return snap_root(Path(a["local_run_dir"]))
    return snap_root(STAGE / a["run_id"])


def stide_test_path(a):
    stream = a.get("stide_stream", "resolution_spine_effective")
    if stream == "normalized":
        return STAGE / a["run_id"] / "graph/normalized/syscalls.jsonl"
    return STAGE / a["run_id"] / "graph/reattributed/resolution_spine_effective/syscalls.jsonl"


# ------------------------------------------------------------------ STIDE
def stide_one(run_id, profile, syscalls: Path):
    trains = sorted(TRAIN.glob(f"{profile}/*/graph/syscalls.jsonl"))
    pf = CORE.get("profile_freeze", {})
    if not trains or profile not in pf or not syscalls.is_file():
        return {"status": "data_insufficient", "reasons": ["missing_train_or_graph"],
                "binary_decision": None, "native_score": None}
    result = stide_run(STIDE_REPO, trains, [syscalls], 6, 106)
    cores = pf[profile]["core_executables"]
    cs = {e: result["results"].get(e) for e in cores}
    ev = {e: v for e, v in cs.items() if v and v.get("scoring_gate_passed") is True}
    status = "passed" if ev else "data_insufficient"
    return {"status": status, "reasons": [] if ev else ["no_evaluable_frozen_core_executable"],
            "binary_decision": any(int(v.get("unknown_ngrams") or 0) > 0 for v in ev.values()) if ev else None,
            "native_score": {"evaluable_core_count": len(ev),
                             "core_unknown_ngrams": sum(int(v.get("unknown_ngrams") or 0) for v in ev.values())}}


def score_stide():
    rows = []
    frozen = {r["run_id"]: r for r in read(FPR / "stide/fpr_result.json")["rows"]}
    for a in MAN["attacks"]:
        res = stide_one(a["run_id"], a["profile"], stide_test_path(a))
        rows.append({**ameta(a), "side": "attack", **res})
    for c in MAN["clean_heldout_40"]:
        if c["source"] == "P2_HELDOUT_CLEAN_FREEZE_20260821":
            x = frozen[c["run_id"]]
            rows.append({"run_id": c["run_id"], "profile": c["profile"], "side": "clean",
                         "status": x["status"], "binary_decision": x["binary_decision"],
                         "reasons": x.get("reasons", []), "reuse": "frozen_stide"})
        else:
            sp = STAGE / c["run_id"] / "graph/reattributed/resolution_spine_effective/syscalls.jsonl"
            res = stide_one(c["run_id"], c["profile"], sp)
            rows.append({"run_id": c["run_id"], "profile": c["profile"], "side": "clean", **res})
    (OUT / "full_scored_stide.json").write_text(json.dumps({"detector": "STIDE", "rows": rows}, indent=2) + "\n")
    print("STIDE done", len(rows), "rows")
    return rows


# ------------------------------------------------------------------- AIDE
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


def score_aide():
    rows = []
    frozen = {r["run_id"]: r for r in read(FPR / "aide_gen2/fpr_result.json")["rows"]}
    for a in MAN["attacks"]:
        snap = attack_snap(a)
        res = aide_one(a["run_id"], snap, OUT / "aide-fixtures-full-population" / a["run_id"])
        rows.append({**ameta(a), "side": "attack", **res})
    for c in MAN["clean_heldout_40"]:
        if c["source"] == "P2_HELDOUT_CLEAN_FREEZE_20260821":
            x = frozen[c["run_id"]]
            rows.append({"run_id": c["run_id"], "profile": c["profile"], "side": "clean",
                         "status": x["status"], "binary_decision": x["binary_decision"],
                         "reasons": x.get("reasons", []), "reuse": "frozen_aide_gen2"})
        else:
            snap = snap_root(STAGE / c["run_id"])
            res = aide_one(c["run_id"], snap, OUT / "aide-fixtures-full-population" / c["run_id"])
            rows.append({"run_id": c["run_id"], "profile": c["profile"], "side": "clean", **res})
    (OUT / "full_scored_aide.json").write_text(json.dumps({"detector": "AIDE", "rows": rows}, indent=2) + "\n")
    print("AIDE done", len(rows), "rows")
    return rows


# -------------------------------------------------------------- ours B1/B2
def score_ours():
    sc = so.self_check(); assert sc["match"], sc
    clean = MAN["clean_heldout_40"]
    clean_recs = {c["run_id"]: so.extract_ops(c["run_id"]) for c in clean}
    prof_of = {c["run_id"]: c["profile"] for c in clean}
    global_pool = [(rid, r) for rid, r in clean_recs.items() if r is not None]
    from collections import defaultdict
    by_prof = defaultdict(list)
    for rid, r in clean_recs.items():
        if r is not None: by_prof[prof_of[rid]].append((rid, r))
    B1 = so.fit_baseline(global_pool)
    B2 = {p: so.fit_baseline(by_prof[p]) for p in by_prof}

    out = {"detector": "ours_B1B2", "self_check": sc, "tau": so.TAU,
           "method": "per-run z-score (paper Eq.1); baseline=clean-40 (B1 global / B2 per-profile); "
                     "FPR=clean-40 leave-one-run-out; N/A for no-resolved-marker-write (ruling 2)",
           "B1": {"attack_tpr": [], "clean_fpr": []}, "B2": {"attack_tpr": [], "clean_fpr": []}}
    for a in MAN["attacks"]:
        if not a["marker_write_resolved"]:
            nev = {"status": "N/A", "binary_decision": None,
                   "reasons": ["no_resolved_marker_write_ruling2 (%s)" % a["op_signature"]]}
            out["B1"]["attack_tpr"].append({**ameta(a), **nev})
            out["B2"]["attack_tpr"].append({**ameta(a), **nev})
            continue
        recs = so.extract_ops(a["run_id"])
        out["B1"]["attack_tpr"].append({**ameta(a), **so.run_decision(recs, B1)})
        out["B2"]["attack_tpr"].append({**ameta(a), **so.run_decision(recs, B2.get(a["profile"], {}))})
    for c in clean:
        rid = c["run_id"]; recs = clean_recs[rid]; p = c["profile"]
        b1 = so.fit_baseline([x for x in global_pool if x[0] != rid])
        b2 = so.fit_baseline([x for x in by_prof[p] if x[0] != rid])
        cm = {"run_id": rid, "profile": p, "op_signature": "background_clean"}
        out["B1"]["clean_fpr"].append({**cm, **so.run_decision(recs, b1)})
        out["B2"]["clean_fpr"].append({**cm, **so.run_decision(recs, b2)})
    (OUT / "full_scored_ours.json").write_text(json.dumps(out, indent=2) + "\n")
    for arm in ("B1", "B2"):
        t = [x for x in out[arm]["attack_tpr"] if x["status"] == "passed"]
        f = [x for x in out[arm]["clean_fpr"] if x["status"] == "passed"]
        print(arm, "definable-TPR", sum(bool(x["binary_decision"]) for x in t), "/", len(t),
              "| FPR", sum(bool(x["binary_decision"]) for x in f), "/", len(f))
    return out


def ameta(a):
    return {"run_id": a["run_id"], "op_signature": a["op_signature"], "profile": a["profile"],
            "witness_tier": a["witness_tier"], "marker_write_resolved": a["marker_write_resolved"]}


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which in ("ours", "all"): score_ours()
    if which in ("stide", "all"): score_stide()
    if which in ("aide", "all"): score_aide()
