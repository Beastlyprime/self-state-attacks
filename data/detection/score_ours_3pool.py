#!/usr/bin/env python3
"""ours-B1/B2 on the 3-pool split: FIT on gen2-176 training, TEST on 55 attacks + gen2-60 heldout.
Reuses verbatim detector math from score_ours (fit_baseline/run_decision/score_record/self_check).
extract_ops is reimplemented base-dir-aware (I/O plumbing only; identical logic)."""
import json, os, math, os, statistics, sys, random
from collections import defaultdict
from pathlib import Path
from pathlib import Path as _Path
_REPO_ROOT = str(_Path(__file__).resolve().parents[2])

ROOT = Path(_REPO_ROOT)
HH = ROOT / "data/superseded"
OUT = ROOT / "data/detection"
SCR = Path(os.environ.get("ASSA_SCRATCH", "/tmp/assa-scratch"))   # scorer working area
POOLS = ROOT / "data/corpus-manifests/tier_b"                      # unpacked corpus
STAGE = HH / "staging"
sys.path.insert(0, str(HH))
import importlib.util
_spec = importlib.util.spec_from_file_location("score_ours", HH / "score_ours.py")
so = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(so)
sys.path.insert(0, str(ROOT / "experiments/code"))
from workload.taxonomy import canonical_path, bucket_key, layer_of

WRITE = so.WRITE
MAN = json.load(open(OUT / "FINAL_3POOL_SPLIT_MANIFEST.json"))


def extract_ops_base(rundir: Path):
    """base-aware clone of score_ours.extract_ops."""
    f = rundir / "graph/libsinsp/libsinsp_events.jsonl"
    if not f.is_file():
        return None
    rid = rundir.name
    buckets = defaultdict(lambda: {"ts": [], "canon": None, "first_dated": None})
    for line in f.open():
        e = json.loads(line); sc = e.get("syscall", {})
        if sc.get("name") not in WRITE or sc.get("result") != "SUCCESS":
            continue
        path = (e.get("file") or {}).get("path")
        if not path:
            continue
        k = f"/{rid}/"; i = path.find(k)
        if i < 0:
            continue
        rel = path[i + len(k):]
        cp = canonical_path(rel)
        if cp is None:
            continue
        bk = bucket_key(cp); b = buckets[bk]
        b["ts"].append(e["order"]["timestamp_realtime_ns"] / 1e9)
        if b["canon"] is None:
            b["canon"] = cp
        if b["first_dated"] is None and "*" in bk:
            b["first_dated"] = cp[len("workspace/"):] if cp.startswith("workspace/") else cp
    recs = []
    for bk, b in buckets.items():
        rel = b["first_dated"] if "*" in bk else (bk[len("workspace/"):] if bk.startswith("workspace/") else bk)
        ba = rundir / "state_snapshots" / "before_a" / rel
        aa = rundir / "state_snapshots" / "after_a" / rel
        sb = so.fsize(ba); sa = so.fsize(aa)
        if sb is None and sa is not None: sb = 0
        if sa is None and sb is not None: sa = 0
        recs.append({"bucket": bk, "op": f"{layer_of(b['canon'])}_write", "layer": layer_of(b["canon"]),
                     "canon": b["canon"], "ts_sec": sorted(b["ts"]), "size_before": sb, "size_after": sa,
                     "size_valid": (sb is not None and sa is not None)})
    return recs


def fail_closed(message: str):
    """Refuse to score rather than overwrite a frozen output with an empty result.

    This scorer reads per-run detector staging trees that the anonymous release
    does not ship. Without them the clean-training fit sees no operations, every
    decision collapses to a negative, and the 0/23 and 0/60 that follow would
    otherwise be written out as legitimate and destroy the published evidence.
    """
    sys.exit(f"fail-closed: {message}\n"
             "  Nothing was written. See ANON_EXPORT_README.md, section\n"
             "  'What can be reproduced here, and what cannot'.")


def train_dir(rid): return POOLS / "clean_train" / rid
def held_dir(rid): return POOLS / "clean_heldout" / rid
def attack_dir(rid): return STAGE / rid


def main():
    sc = so.self_check(); assert sc["match"], sc
    missing = [str(p) for p in (POOLS / "clean_train", POOLS / "clean_heldout", STAGE) if not p.is_dir()]
    if missing:
        fail_closed("required input roots are absent: " + ", ".join(missing))
    pool1 = MAN["pools"]["pool1_clean_training_gen2_176"]["records"]
    pool2 = MAN["pools"]["pool2_clean_heldout_test_gen2_60"]["records"]
    pool3 = MAN["pools"]["pool3_attack_test_55"]["records"]

    # FIT on gen2-176
    train_recs = {r["run_id"]: extract_ops_base(train_dir(r["run_id"])) for r in pool1}
    prof = {r["run_id"]: r["profile"] for r in pool1}
    global_pool = [(rid, rr) for rid, rr in train_recs.items() if rr is not None]
    by_prof = defaultdict(list)
    for rid, rr in train_recs.items():
        if rr is not None:
            by_prof[prof[rid]].append((rid, rr))
    if not global_pool:
        fail_closed(f"the clean-training fit resolved 0 of {len(pool1)} runs; "
                    "the staging trees are present but yielded no write operations")
    B1 = so.fit_baseline(global_pool)
    B2 = {p: so.fit_baseline(by_prof[p]) for p in by_prof}
    fit_meta = {"n_train_with_libsinsp": len(global_pool), "by_profile": {p: len(v) for p, v in by_prof.items()}}

    out = {"detector": "ours_B1B2", "design": "3pool: fit gen2-176 / test 55+gen2-60 (NO leave-one-out; test disjoint)",
           "self_check": sc, "tau": so.TAU, "fit_meta": fit_meta,
           "B1": {"attack": [], "clean_fpr": []}, "B2": {"attack": [], "clean_fpr": []}}

    def ameta(a):
        return {"run_id": a["run_id"], "op_signature": a["op_signature"], "profile": a["profile"],
                "tier": a["tier"], "b1b2_definable": a["b1b2_definable"]}

    # attacks
    for a in pool3:
        if not a["b1b2_definable"]:
            nev = {"status": "N/A", "binary_decision": None, "reasons": ["no_resolved_marker_write_ruling2"]}
            out["B1"]["attack"].append({**ameta(a), **nev}); out["B2"]["attack"].append({**ameta(a), **nev})
            continue
        recs = extract_ops_base(attack_dir(a["run_id"]))
        out["B1"]["attack"].append({**ameta(a), **so.run_decision(recs, B1)})
        out["B2"]["attack"].append({**ameta(a), **so.run_decision(recs, B2.get(a["profile"], {}))})

    # clean heldout FPR (no leave-one-out)
    for c in pool2:
        recs = extract_ops_base(held_dir(c["run_id"]))
        cm = {"run_id": c["run_id"], "profile": c["profile"], "scenario_id": c["scenario_id"],
              "performs_write": c["performs_self_state_write"]}
        out["B1"]["clean_fpr"].append({**cm, **so.run_decision(recs, B1)})
        out["B2"]["clean_fpr"].append({**cm, **so.run_decision(recs, B2.get(c["profile"], {}))})

    # ---- balanced ablation: 35/profile x4 = 140, reseeded
    abl = {"design": "35/profile x4 =140 reseeded; B1 pooled-140 vs B2 profile-140; TPR on 23 definable, FPR on gen2-60",
           "seeds": []}
    definable_att = [a for a in pool3 if a["b1b2_definable"]]
    att_recs = {a["run_id"]: extract_ops_base(attack_dir(a["run_id"])) for a in definable_att}
    held_recs = {c["run_id"]: extract_ops_base(held_dir(c["run_id"])) for c in pool2}
    for seed in (11, 23, 42, 101, 2026):
        rng = random.Random(seed)
        bal = []
        for p in ("W1", "W2", "W3", "W4"):
            pl = list(by_prof[p]); rng.shuffle(pl); bal.extend(pl[:35])
        b1 = so.fit_baseline(bal)
        b2 = {p: so.fit_baseline([x for x in bal if prof[x[0]] == p]) for p in ("W1", "W2", "W3", "W4")}
        def tpr_fpr(fitter_pooled, fitter_prof):
            tp = sum(1 for a in definable_att if (so.run_decision(att_recs[a["run_id"]], fitter_pooled if fitter_prof is None else fitter_prof.get(a["profile"], {}))).get("binary_decision"))
            fp = sum(1 for c in pool2 if (so.run_decision(held_recs[c["run_id"]], fitter_pooled if fitter_prof is None else fitter_prof.get(c["profile"], {}))).get("binary_decision"))
            return tp, fp
        b1_tp, b1_fp = tpr_fpr(b1, None)
        b2_tp, b2_fp = tpr_fpr(None, b2)
        abl["seeds"].append({"seed": seed, "n_bal": len(bal),
                             "B1_140": {"tpr": f"{b1_tp}/{len(definable_att)}", "fpr": f"{b1_fp}/60"},
                             "B2_140": {"tpr": f"{b2_tp}/{len(definable_att)}", "fpr": f"{b2_fp}/60"}})
    out["balanced_ablation"] = abl

    (OUT / "scored_ours_3pool.json").write_text(json.dumps(out, indent=2) + "\n")

    # print summary
    for arm in ("B1", "B2"):
        t = [x for x in out[arm]["attack"] if x["status"] == "passed"]
        f = out[arm]["clean_fpr"]
        fw = [x for x in f if x["performs_write"]]; fnw = [x for x in f if not x["performs_write"]]
        print(f"{arm}: definable-TPR {sum(bool(x['binary_decision']) for x in t)}/{len(t)}"
              f" | FPR-all {sum(bool(x['binary_decision']) for x in f)}/60"
              f" | FPR-write {sum(bool(x['binary_decision']) for x in fw)}/{len(fw)}"
              f" | FPR-nowrite {sum(bool(x['binary_decision']) for x in fnw)}/{len(fnw)}")
    print("balanced ablation B1_140 TPR/FPR per seed:", [(s["seed"], s["B1_140"]) for s in abl["seeds"]])
    print("balanced ablation B2_140 TPR/FPR per seed:", [(s["seed"], s["B2_140"]) for s in abl["seeds"]])


if __name__ == "__main__":
    main()
