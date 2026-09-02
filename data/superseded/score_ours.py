#!/usr/bin/env python3
"""ours-B1/B2 size+timing z-score detector on the D3 partial population.

Method: verbatim per-(file,op) z-score from exp2b_anomaly.compute_anomaly_score
(paper §5.1 Eq.1: score = max(|Δsize-μ|/σ_s, |logΔt-μ|/σ_t)), TAU=2.0. Same
feature code as p2_b1b2_size_timing_libsinsp_20260822 (self-checked vs library).

Difference from that run: the baseline pool is the NATURAL held-out clean-40
(now synced locally), not the paired twins. FPR is the natural held-out 40 with
leave-one-run-out; TPR baseline is the full clean-40. Decision is PER-RUN and
comparable to AIDE/STIDE/Falco: flag if ANY canonical self-state write op in the
run scores >= TAU (combined). We also record how many attacks had no self-state
write witnessed at all (the syscall write-witnessing gap).
"""
from __future__ import annotations
import json, math, os, statistics, sys
from collections import defaultdict
from pathlib import Path

OUT = Path(__file__).resolve().parent
RES = OUT.parent
ROOT = RES.parent.parent
STAGE = OUT / "staging"
sys.path.insert(0, str(ROOT / "experiments/code"))
from workload.taxonomy import canonical_path, bucket_key, layer_of
from measurement.exp2b_anomaly import compute_anomaly_score as LIB_SCORE, UNSEEN_KEY_SCORE, FileStatistics, BaselineModel

TAU = 2.0
WRITE = {"write", "pwrite", "pwritev", "writev", "pwrite64"}


def libsinsp_path(rid): return STAGE / rid / "graph/libsinsp/libsinsp_events.jsonl"
def snap_dir(rid): return STAGE / rid / "state_snapshots"


def fsize(p):
    try: return os.path.getsize(p)
    except OSError: return None


def snapshot_delta(rid, canon, first_dated_rel):
    rel = first_dated_rel if "*" in canon else (canon[len("workspace/"):] if canon.startswith("workspace/") else canon)
    ba = snap_dir(rid) / "before_a" / rel; aa = snap_dir(rid) / "after_a" / rel
    sb, sa = fsize(ba), fsize(aa)
    if sb is None and sa is not None: sb = 0
    if sa is None and sb is not None: sa = 0
    return sb, sa


def extract_ops(rid):
    f = libsinsp_path(rid)
    if not f.is_file(): return None
    buckets = defaultdict(lambda: {"ts": [], "canon": None, "first_dated": None})
    for line in f.open():
        e = json.loads(line); sc = e.get("syscall", {})
        if sc.get("name") not in WRITE or sc.get("result") != "SUCCESS": continue
        path = (e.get("file") or {}).get("path")
        if not path: continue
        k = f"/{rid}/"; i = path.find(k)
        if i < 0: continue
        rel = path[i + len(k):]
        cp = canonical_path(rel)
        if cp is None: continue
        bk = bucket_key(cp); b = buckets[bk]
        b["ts"].append(e["order"]["timestamp_realtime_ns"] / 1e9)
        if b["canon"] is None: b["canon"] = cp
        if b["first_dated"] is None and "*" in bk:
            b["first_dated"] = cp[len("workspace/"):] if cp.startswith("workspace/") else cp
    recs = []
    for bk, b in buckets.items():
        sb, sa = snapshot_delta(rid, bk, b["first_dated"])
        recs.append({"bucket": bk, "op": f"{layer_of(b['canon'])}_write", "layer": layer_of(b["canon"]),
                     "canon": b["canon"], "ts_sec": sorted(b["ts"]), "size_before": sb, "size_after": sa,
                     "size_valid": (sb is not None and sa is not None)})
    return recs


def fit_baseline(run_recs):
    size_samples = defaultdict(list); logdt = defaultdict(list)
    for _, recs in run_recs:
        for r in recs:
            key = (r["bucket"], r["op"])
            if r["size_valid"]: size_samples[key].append(r["size_after"] - r["size_before"])
            ts = r["ts_sec"]
            for i in range(1, len(ts)):
                dt = ts[i] - ts[i - 1]; dt = dt if dt > 1e-3 else 1e-3
                logdt[key].append(math.log(dt))
    stats = {}
    for key in set(list(size_samples) + list(logdt)):
        st = FileStatistics(target_file=key[0], op_type=key[1])
        d = size_samples.get(key, []); st.count = len(d)
        if d:
            st.size_mean = statistics.mean(d); st.size_std = statistics.stdev(d) if len(d) > 1 else 0.0
        ld = logdt.get(key, []); st.time_log_count = len(ld)
        if len(ld) >= 2: st.time_log_mean = statistics.mean(ld); st.time_log_std = statistics.stdev(ld)
        elif len(ld) == 1: st.time_log_mean = ld[0]; st.time_log_std = 0.0
        stats[key] = st
    return stats


def score_record(rec, stats, want="combined"):
    key = (rec["bucket"], rec["op"]); st = stats.get(key)
    if st is None: return (UNSEEN_KEY_SCORE, False)
    size_z = None
    if rec["size_valid"] and st.count > 0:
        sd = rec["size_after"] - rec["size_before"]
        sigma = max(st.size_std, abs(st.size_mean) * 0.1, 1.0)
        size_z = abs(sd - st.size_mean) / sigma
    timing_z = None; tavail = False; ts = rec["ts_sec"]
    if len(ts) >= 2 and st.time_log_count >= 2:
        dt = ts[-1] - ts[-2]; dt = dt if dt > 1e-3 else 1e-3; logdt = math.log(dt)
        if st.time_log_std > 0: timing_z = abs(logdt - st.time_log_mean) / st.time_log_std; tavail = True
        elif logdt != st.time_log_mean: timing_z = 5.0; tavail = True
        else: timing_z = 0.0; tavail = True
    if want == "size": return (size_z, tavail)
    if want == "timing": return ((timing_z, tavail) if tavail else (None, tavail))
    vals = [v for v in (size_z, timing_z) if v is not None]
    return (max(vals) if vals else None, tavail)


def self_check():
    st = FileStatistics(target_file="workspace/MEMORY.md", op_type="memory_write")
    st.count = 5; st.size_mean = 117.0; st.size_std = 52.0; st.time_log_count = 0
    bl = BaselineModel(profile_name="x", profile_source="x", n_ops=5, timestamp="t",
                       file_stats={("workspace/MEMORY.md", "memory_write"): st})
    ev = {"op_type": "memory_write", "target_file": "workspace/MEMORY.md", "size_before": 173, "size_after": 361}
    lib = LIB_SCORE(ev, bl, prev_ts_by_key=None)
    rec = {"bucket": "workspace/MEMORY.md", "op": "memory_write", "size_before": 173, "size_after": 361,
           "size_valid": True, "ts_sec": []}
    mine, _ = score_record(rec, bl.file_stats, "combined")
    return {"library": round(lib, 6), "mine": round(mine, 6), "match": abs(lib - mine) < 1e-9}


def run_decision(recs, stats):
    """Per-run: flag if ANY canonical self-state write op scores >= TAU (combined)."""
    if recs is None: return {"status": "data_insufficient", "reasons": ["no_libsinsp"], "binary_decision": None}
    scored = []
    for r in recs:
        s, _ = score_record(r, stats, "combined")
        if s is not None: scored.append((r["canon"], s))
    n_writes = len(recs)
    if not scored:
        # detector ran but witnessed no scorable self-state write => negative
        return {"status": "passed", "binary_decision": False, "reasons": ["no_selfstate_write_witnessed"],
                "n_selfstate_writes": n_writes, "max_score": None}
    mx = max(s for _, s in scored)
    return {"status": "passed", "binary_decision": bool(mx >= TAU), "n_selfstate_writes": n_writes,
            "max_score": round(mx, 4), "unseen_key": bool(mx >= UNSEEN_KEY_SCORE)}


def main():
    sc = self_check(); assert sc["match"], sc
    pop = json.loads((OUT / "PARTIAL_LOCKED_POPULATION.json").read_text())

    # baseline pools from clean-40
    clean = pop["clean_heldout_40"]
    clean_recs = {c["run_id"]: extract_ops(c["run_id"]) for c in clean}
    prof_of = {c["run_id"]: c["profile"] for c in clean}
    global_pool = [(rid, r) for rid, r in clean_recs.items() if r is not None]
    by_prof = defaultdict(list)
    for rid, r in clean_recs.items():
        if r is not None: by_prof[prof_of[rid]].append((rid, r))

    B1 = fit_baseline(global_pool)
    B2 = {p: fit_baseline(by_prof[p]) for p in by_prof}

    def meta(r, lbl):
        return {"run_id": r["run_id"], "label": lbl, "op_signature": r["op_signature"],
                "profile": r["profile"], "memory_poisoning": r.get("memory_poisoning_Mem_M1", False)}

    out = {"detector": "ours_B1B2", "self_check": sc, "tau": TAU,
           "method": "per-run z-score (paper Eq.1); baseline=natural clean-40 (B1 global / B2 per-profile); "
                     "FPR=clean-40 leave-one-run-out; decision=any canonical self-state write >= TAU",
           "B1": {"attack_tpr": [], "clean_fpr": []}, "B2": {"attack_tpr": [], "clean_fpr": []}}

    # TPR: 18 graph attacks (file-ops non-evaluable: no libsinsp)
    for r in pop["attacks_graph_present"]:
        recs = extract_ops(r["run_id"])
        out["B1"]["attack_tpr"].append({**meta(r, "attack_landed"), **run_decision(recs, B1)})
        out["B2"]["attack_tpr"].append({**meta(r, "attack_landed"), **run_decision(recs, B2.get(r["profile"], {}))})
    for r in pop["attacks_aide_only_fileop"]:
        nev = {"status": "non_evaluable", "binary_decision": None, "reasons": ["no_offline_libsinsp_D1_pending"]}
        out["B1"]["attack_tpr"].append({**meta(r, "attack_landed"), **nev})
        out["B2"]["attack_tpr"].append({**meta(r, "attack_landed"), **nev})

    # FPR: clean-40 leave-one-run-out
    for c in clean:
        rid = c["run_id"]; recs = clean_recs[rid]; p = c["profile"]
        b1 = fit_baseline([x for x in global_pool if x[0] != rid])
        b2 = fit_baseline([x for x in by_prof[p] if x[0] != rid])
        out["B1"]["clean_fpr"].append({**meta(c, "clean"), **run_decision(recs, b1)})
        out["B2"]["clean_fpr"].append({**meta(c, "clean"), **run_decision(recs, b2)})

    (OUT / "scored_ours.json").write_text(json.dumps(out, indent=2) + "\n")
    print("self_check", sc)
    for arm in ("B1", "B2"):
        t = out[arm]["attack_tpr"]; f = out[arm]["clean_fpr"]
        tev = [x for x in t if x["status"] == "passed"]; fev = [x for x in f if x["status"] == "passed"]
        print(arm, "TPR", sum(x["binary_decision"] for x in tev), "/", len(tev),
              "| FPR", sum(x["binary_decision"] for x in fev), "/", len(fev))


if __name__ == "__main__":
    main()
