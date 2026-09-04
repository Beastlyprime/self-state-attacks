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
sys.path.insert(0, str(ROOT / "experiments/code"))   # score_ours imports workload.taxonomy at module level
from workload.taxonomy import canonical_path, bucket_key, layer_of
import importlib.util
_spec = importlib.util.spec_from_file_location("score_ours", HH / "score_ours.py")
so = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(so)

WRITE = so.WRITE
MAN = json.load(open(OUT / "FINAL_3POOL_SPLIT_MANIFEST.json"))


# Per-stream audit, filled in by extract_ops_base and read by the gates in main().
# Presence of a file is not evidence that it is the right file: an empty stream and
# another run's stream both parse fine and both silently change the result, so bind
# every stream to the run it is supposed to describe.
STREAM_AUDIT: dict = {}


def extract_ops_base(rundir: Path):
    """base-aware clone of score_ours.extract_ops."""
    f = rundir / "graph/libsinsp/libsinsp_events.jsonl"
    if not f.is_file():
        return None
    rid = rundir.name
    audit = STREAM_AUDIT.setdefault(rid, {"path": str(f), "records": 0, "foreign_run_ids": set()})
    buckets = defaultdict(lambda: {"ts": [], "canon": None, "first_dated": None})
    for line in f.open():
        e = json.loads(line); sc = e.get("syscall", {})
        audit["records"] += 1
        if e.get("run_id") != rid:
            audit["foreign_run_ids"].add(e.get("run_id"))
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
    """Refuse to score rather than overwrite a frozen output with a partial result.

    Every input this scorer reads is a per-run telemetry tree that travels in the
    corpus, not in this repository. When a tree is missing, extract_ops_base
    returns None, the decision collapses to a negative, and a short population
    would otherwise be written out as a legitimate lower TPR -- destroying the
    published evidence. A missing input means the corpus is incomplete, not that
    the detector performed worse, so refuse the write instead of guessing.
    """
    sys.exit(f"fail-closed: {message}\n"
             "  Nothing was written. See REPRODUCE.md, 'Level 3 -- what needs\n"
             "  the corpus', for what this scorer still cannot reach.")


def audit_streams(rids):
    """Every stream read so far must be non-empty and carry only its own run id.

    This is what the existence checks miss. Blanking a stream leaves a parseable
    file and moves the numbers; handing a run another run's stream leaves every
    record parseable and moves them differently. Both are indistinguishable from
    a real result downstream, so refuse before fitting or writing. Each libsinsp
    record names its own run, which is the binding used here -- it catches whole
    -stream substitution and truncation to nothing, not a stream spliced record
    by record from the right run's events.
    """
    empty, foreign = [], []
    for rid in rids:
        a = STREAM_AUDIT.get(rid)
        if a is None:
            continue
        if a["records"] == 0:
            empty.append(rid)
        if a["foreign_run_ids"]:
            foreign.append(f"{rid} carries {sorted(x for x in a['foreign_run_ids'] if x)[:2]}")
    if empty or foreign:
        fail_closed(("empty streams: " + ", ".join(empty[:6]) + ". " if empty else "")
                    + ("streams belonging to another run: " + "; ".join(foreign[:6]) + "." if foreign else ""))


def train_dir(rid): return POOLS / "clean_train" / rid
def held_dir(rid): return POOLS / "clean_heldout" / rid


# The eleven W3 C-series attacks were resolved out of the detector staging tree
# when these rows were frozen. The staging volume no longer carries its own copy
# of them -- the same trees are published under tier_b/attacks_lockedpop_cseries,
# byte-identical on both streams this scorer reads -- so try staging first, for
# the runs that do live there, and fall through to the attack pools.
ATTACK_POOL_DIRS = ("attacks", "attacks_lockedpop_cseries")


def attack_dir(rid):
    stream = "graph/libsinsp/libsinsp_events.jsonl"
    for cand in (STAGE / rid, *(POOLS / sub / rid for sub in ATTACK_POOL_DIRS)):
        if (cand / stream).is_file():
            return cand
    return STAGE / rid          # keep the historical path in the error message


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
    # Fail closed on the whole population, not just on the empty case. The fit is
    # defined over all 176 training runs and the test over all 23 b1b2-definable
    # attacks and all 60 held-out clean runs; a short input is an incomplete
    # corpus, and scoring it would silently republish different numbers under the
    # frozen filename.
    if len(global_pool) != len(pool1):
        unresolved = sorted(rid for rid, rr in train_recs.items() if rr is None)
        fail_closed(f"the clean-training fit resolved {len(global_pool)} of {len(pool1)} runs. "
                    f"Unresolved: {', '.join(unresolved[:8])}"
                    f"{' ...' if len(unresolved) > 8 else ''}")
    definable_ids = [a["run_id"] for a in pool3 if a["b1b2_definable"]]
    missing_att = [rid for rid in definable_ids
                   if not (attack_dir(rid) / "graph/libsinsp/libsinsp_events.jsonl").is_file()]
    if missing_att:
        fail_closed(f"{len(definable_ids) - len(missing_att)} of {len(definable_ids)} b1b2-definable "
                    f"attacks resolved. Unresolved: {', '.join(missing_att)}")
    missing_held = [c["run_id"] for c in pool2
                    if not (held_dir(c["run_id"]) / "graph/libsinsp/libsinsp_events.jsonl").is_file()]
    if missing_held:
        fail_closed(f"{len(pool2) - len(missing_held)} of {len(pool2)} held-out clean runs resolved. "
                    f"Unresolved: {', '.join(missing_held[:8])}"
                    f"{' ...' if len(missing_held) > 8 else ''}")
    audit_streams(train_recs.keys())
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
    att_recs, held_recs = {}, {}
    for a in pool3:
        if not a["b1b2_definable"]:
            nev = {"status": "N/A", "binary_decision": None, "reasons": ["no_resolved_marker_write_ruling2"]}
            out["B1"]["attack"].append({**ameta(a), **nev}); out["B2"]["attack"].append({**ameta(a), **nev})
            continue
        recs = att_recs[a["run_id"]] = extract_ops_base(attack_dir(a["run_id"]))
        out["B1"]["attack"].append({**ameta(a), **so.run_decision(recs, B1)})
        out["B2"]["attack"].append({**ameta(a), **so.run_decision(recs, B2.get(a["profile"], {}))})

    # clean heldout FPR (no leave-one-out)
    for c in pool2:
        recs = held_recs[c["run_id"]] = extract_ops_base(held_dir(c["run_id"]))
        cm = {"run_id": c["run_id"], "profile": c["profile"], "scenario_id": c["scenario_id"],
              "performs_write": c["performs_self_state_write"]}
        out["B1"]["clean_fpr"].append({**cm, **so.run_decision(recs, B1)})
        out["B2"]["clean_fpr"].append({**cm, **so.run_decision(recs, B2.get(c["profile"], {}))})

    # Now that every stream has been read, re-audit: the attack and held-out
    # streams were not covered by the pre-fit pass.
    audit_streams(STREAM_AUDIT.keys())

    # Bind on outcome as well as on input. A b1b2-definable attack is definable
    # because a marker write resolves in its stream, and a clean run flagged as
    # performing a self-state write must show one; if either yields nothing, the
    # stream is not the one these rows were computed from, whatever it contains.
    no_ops_att = [rid for rid, r in att_recs.items() if not r]
    no_ops_clean = [c["run_id"] for c in pool2 if c["performs_self_state_write"]
                    and not held_recs.get(c["run_id"])]
    if no_ops_att or no_ops_clean:
        fail_closed(("b1b2-definable attacks with no resolved self-state write: "
                     + ", ".join(no_ops_att) + ". " if no_ops_att else "")
                    + ("clean runs recorded as performing a self-state write but showing none: "
                       + ", ".join(no_ops_clean[:6]) + "." if no_ops_clean else ""))
    for arm in ("B1", "B2"):
        undecided_att = [x["run_id"] for x in out[arm]["attack"]
                         if x["b1b2_definable"] and x["status"] != "passed"]
        undecided_clean = [x["run_id"] for x in out[arm]["clean_fpr"] if x["status"] != "passed"]
        if undecided_att or undecided_clean:
            fail_closed(f"{arm}: {len(undecided_att)} of {len(definable_ids)} definable attacks and "
                        f"{len(undecided_clean)} of {len(pool2)} clean runs did not reach a decision. "
                        + ", ".join((undecided_att + undecided_clean)[:6]))

    # ---- balanced ablation: 35/profile x4 = 140, reseeded
    abl = {"design": "35/profile x4 =140 reseeded; B1 pooled-140 vs B2 profile-140; TPR on 23 definable, FPR on gen2-60",
           "seeds": []}
    definable_att = [a for a in pool3 if a["b1b2_definable"]]
    # att_recs / held_recs were built above and cover exactly these runs -- the
    # ablation used to re-extract them, which re-read a gigabyte for no reason.
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
