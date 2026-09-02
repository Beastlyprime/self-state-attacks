#!/usr/bin/env python3
"""STIDE on 3-pool: train per-profile on gen2-176, test 55 attacks + gen2-60 heldout.
Batched per profile (test instances scored independently -> identical to per-run calls, faster).
Reuses stide_bridge.run verbatim; frozen preregistration core executables."""
import json, sys, os
from pathlib import Path
from collections import defaultdict

ROOT = Path(os.environ.get("ASSA_ROOT", str(Path(__file__).resolve().parents[2])))
HH = ROOT / "data/superseded"
OUT = HH / "final_3pool"
SCR = Path(os.environ.get("ASSA_SCRATCH", str(ROOT / ".scratch")))
POOLS = SCR / "pools"
STAGE = HH / "staging"
sys.path.insert(0, str(ROOT))
from experiments.code.measurement.stage_g_harness.stide_bridge import run as stide_run

STIDE_REPO = Path("/tmp/assa-stage-g-lid-ds")
CORE = json.loads((HH.parent / "p2_detection_20260820/P2_STIDE_STOPPING_RULE_PREREGISTRATION.json").read_text())
PF = CORE["profile_freeze"]
MAN = json.load(open(OUT / "FINAL_3POOL_SPLIT_MANIFEST.json"))
REATTR_REL = "graph/reattributed/resolution_spine_effective/syscalls.jsonl"
STREAM_REL = {
    "resolution_spine_effective": REATTR_REL,
    "normalized": "graph/normalized/syscalls.jsonl",
}


def idkeys(path):
    ks = set()
    for line in open(path):
        r = json.loads(line)
        if not r.get("sequence_eligible"):
            continue
        pr = r.get("process") or {}
        ks.add(pr.get("identity_key") or f"{r['run_id']}:{pr.get('pid')}:identity_incomplete")
    return ks


def main():
    pool1 = MAN["pools"]["pool1_clean_training_gen2_176"]["records"]
    pool2 = MAN["pools"]["pool2_clean_heldout_test_gen2_60"]["records"]
    pool3 = MAN["pools"]["pool3_attack_test_55"]["records"]

    train_by_prof = defaultdict(list)
    for r in pool1:
        train_by_prof[r["profile"]].append(POOLS / "train" / r["run_id"] / REATTR_REL)

    # test runs per profile with their substrate path + side
    test_runs = []
    for a in pool3:
        stream = a["stide_stream"]
        test_runs.append((a["run_id"], a["profile"], "attack",
                          STAGE / a["run_id"] / STREAM_REL[stream], a))
    for c in pool2:
        test_runs.append((c["run_id"], c["profile"], "clean",
                          POOLS / "heldout" / c["run_id"] / REATTR_REL, c))

    rows = []
    for prof in ("W1", "W2", "W3", "W4"):
        cores = PF[prof]["core_executables"]
        train_paths = train_by_prof[prof]
        prof_tests = [t for t in test_runs if t[1] == prof]
        test_paths = [t[3] for t in prof_tests if t[3].is_file()]
        # map identity_key -> run_id
        key2run = {}
        for rid, _, _, path, _ in prof_tests:
            if path.is_file():
                for k in idkeys(path):
                    key2run[k] = rid
        res = stide_run(STIDE_REPO, train_paths, test_paths, 6, 106)
        exres = res["results"]
        # per run: collect core-exec instances belonging to it
        for rid, p, side, path, meta in prof_tests:
            if not path.is_file():
                rows.append({"run_id": rid, "profile": p, "side": side, "status": "data_insufficient",
                             "reasons": ["missing_substrate"], "binary_decision": None,
                             "stide_stream": meta.get("stide_stream", "resolution_spine_effective")}); continue
            evaluable_instances = 0; unknown_hit = False; total_unknown = 0
            for exe in cores:
                er = exres.get(exe)
                if not er or not er.get("normal_database_ngrams"):
                    continue
                for ik, inst in (er.get("instances") or {}).items():
                    if key2run.get(ik) != rid:
                        continue
                    if inst.get("evaluated_ngrams", 0) > 0:
                        evaluable_instances += 1
                        total_unknown += int(inst.get("unknown_ngrams") or 0)
                        if int(inst.get("unknown_ngrams") or 0) > 0:
                            unknown_hit = True
            if evaluable_instances == 0:
                rows.append({"run_id": rid, "profile": p, "side": side, "status": "data_insufficient",
                             "reasons": ["no_evaluable_frozen_core_executable"], "binary_decision": None,
                             "op_signature": meta.get("op_signature", "clean"),
                             "stide_stream": meta.get("stide_stream", "resolution_spine_effective")})
            else:
                rows.append({"run_id": rid, "profile": p, "side": side, "status": "passed",
                             "binary_decision": bool(unknown_hit),
                             "core_evaluable_instances": evaluable_instances, "core_unknown_ngrams": total_unknown,
                             "op_signature": meta.get("op_signature", "clean"),
                             "stide_stream": meta.get("stide_stream", "resolution_spine_effective"),
                             "performs_write": meta.get("performs_self_state_write"),
                             "scenario_id": meta.get("scenario_id"), "tier": meta.get("tier")})
        print(f"{prof}: trained {len(train_paths)} tested {len(test_paths)}")

    (OUT / "scored_stide_3pool.json").write_text(json.dumps(
        {"detector": "STIDE", "design": "3pool: train gen2-176 per-profile / test 55+gen2-60; frozen core; n=6 minseq=106",
         "rows": rows}, indent=2) + "\n")
    # summary
    atk = [r for r in rows if r["side"] == "attack"]
    cl = [r for r in rows if r["side"] == "clean"]
    ae = [r for r in atk if r["status"] == "passed"]; ce = [r for r in cl if r["status"] == "passed"]
    cw = [r for r in ce if r.get("performs_write")]; cnw = [r for r in ce if not r.get("performs_write")]
    print(f"STIDE TPR {sum(bool(r['binary_decision']) for r in ae)}/{len(ae)} evaluable (of {len(atk)})")
    print(f"STIDE FPR-all {sum(bool(r['binary_decision']) for r in ce)}/{len(ce)} evaluable (of 60)"
          f" | FPR-write {sum(bool(r['binary_decision']) for r in cw)}/{len(cw)}"
          f" | FPR-nowrite {sum(bool(r['binary_decision']) for r in cnw)}/{len(cnw)}")


if __name__ == "__main__":
    main()
