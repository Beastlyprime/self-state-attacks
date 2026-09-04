#!/usr/bin/env python3
"""
FROZEN RECORD -- NOT RUNNABLE FROM THIS RELEASE.

This is the script that produced the frozen generation beside it (REPORT.json,
REPORT.md), published so the derivation is inspectable rather than asserted. Its
paths are the ones that existed when it ran, before the release layout was
rebuilt: `<REPO_ROOT>` was the collection host's checkout and the census sits
elsewhere now, so executing this file here fails on a missing input by design.
The four scorers under `data/detection/supervised/` assert their populations
against REPORT.json instead of re-running it.

B1/B2 size+timing anomaly detector recomputed on REAL pinned libsinsp traces.

NEW derivation generation: p2_b1b2_size_timing_libsinsp_20260822.
NOT comparable to any prior generation. The prior size+timing numbers were
produced on SYNTHETIC WorkloadGeneratorV4 ops + SYNTHETIC gamma timestamps
(exp2b_temporal.generate_timestamps) and are withdrawn-class. This run feeds
the SAME z-score method (paper §5.1 Eq.1) real write syscalls + real ns
timestamps from graph/libsinsp/libsinsp_events.jsonl and real net size deltas
from state_snapshots/{before_a,after_a}.

Method fidelity: feature/threshold formulas are copied verbatim from
  experiments/code/measurement/exp2b_anomaly.py  (compute_anomaly_score)
  experiments/code/measurement/trace_baseline.py (fit_baseline_from_train_events)
and cross-checked at runtime against the imported library scorer (SELF_CHECK).

Defensive analysis. Offline, read-only on sources. No network, no VM,
no payload execution.
"""
import json, os, glob, math, statistics, hashlib, sys
from collections import defaultdict

CODE="<REPO_ROOT>/experiments/code"
sys.path.insert(0, CODE)
from workload.taxonomy import canonical_path, bucket_key, layer_of
# library refs for self-check / constants
from measurement.exp2b_anomaly import compute_anomaly_score as LIB_SCORE, UNSEEN_KEY_SCORE
from measurement.exp2b_anomaly import FileStatistics, BaselineModel

RES="<REPO_ROOT>/experiments/results"
OUT=f"{RES}/p2_b1b2_size_timing_libsinsp_20260822"
TAU=2.0
WRITE={"write","pwrite","pwritev","writev","pwrite64"}
CLASS_OF={"instruction":"Instruction","config":"Configuration","memory":"Memory"}

census=json.load(open(f"{RES}/p2_attack_tpr_expanded_v2_20260822/EXPANDED_LANDED_CENSUS_V2_20260822.json"))

# ---- index libsinsp run bundles ----
# DEDUP (freeze prerequisite): multiple attempt dirs can share a run basename.
# We resolve deterministically (shortest canonical path wins) and RECORD every
# dropped duplicate rather than silently last-writer-wins.
libs=glob.glob(f"{RES}/p2_l0_*_20260822/**/graph/libsinsp/libsinsp_events.jsonl",recursive=True)
_cand=defaultdict(list)
for p in libs:
    rd=os.path.dirname(os.path.dirname(os.path.dirname(p)))
    _cand[os.path.basename(rd)].append(rd)
byrun={}
basename_dedup_drops=[]
for bn,dirs in _cand.items():
    chosen=sorted(dirs, key=lambda d:(len(d),d))[0]
    byrun[bn]=chosen
    for d in dirs:
        if d!=chosen:
            basename_dedup_drops.append({"run_basename":bn,"kept":chosen,"dropped":d})

def run_rel(path, run_id):
    k=f"/{run_id}/"; i=path.find(k)
    return None if i<0 else path[i+len(k):]

def fsize(p):
    try: return os.path.getsize(p)
    except OSError: return None

def snapshot_delta(rundir, canon, first_dated_rel):
    """Return (size_before, size_after) from local state_snapshots, or (None,None)."""
    if "*" in canon:  # memory bucket -> use the actual dated file written
        rel=first_dated_rel
    else:
        rel=canon[len("workspace/"):] if canon.startswith("workspace/") else canon
    ba=os.path.join(rundir,"state_snapshots","before_a",rel)
    aa=os.path.join(rundir,"state_snapshots","after_a",rel)
    sb=fsize(ba); sa=fsize(aa)
    if sb is None and sa is not None: sb=0          # created during run
    if sa is None and sb is not None: sa=0          # deleted during run
    return sb,sa

def extract_ops(run_id):
    """Return list of operation records for one run:
       {bucket, op, layer, canon, ts_sec:[...], size_before, size_after, size_valid}
       One record per (self-state file bucket) written in the run.
       ts_sec = sorted seconds timestamps of each write syscall to that bucket."""
    rd=byrun.get(run_id)
    if not rd: return None, None
    f=os.path.join(rd,"graph","libsinsp","libsinsp_events.jsonl")
    buckets=defaultdict(lambda:{"ts":[], "canon":None, "first_dated":None})
    with open(f) as fh:
        for line in fh:
            e=json.loads(line); sc=e.get("syscall",{})
            if sc.get("name") not in WRITE or sc.get("result")!="SUCCESS": continue
            fl=e.get("file") or {}; path=fl.get("path")
            if not path: continue
            rel=run_rel(path, run_id)
            if rel is None: continue
            cp=canonical_path(rel)
            if cp is None: continue
            bk=bucket_key(cp)
            b=buckets[bk]
            b["ts"].append(e["order"]["timestamp_realtime_ns"]/1e9)
            if b["canon"] is None: b["canon"]=cp
            if b["first_dated"] is None and "*" in bk:
                b["first_dated"]=cp[len("workspace/"):] if cp.startswith("workspace/") else cp
    recs=[]
    for bk,b in buckets.items():
        layer=layer_of(b["canon"])
        sb,sa=snapshot_delta(rd,bk,b["first_dated"])
        recs.append({
            "bucket":bk,"op":f"{layer}_write","layer":layer,"canon":b["canon"],
            "ts_sec":sorted(b["ts"]),
            "size_before":sb,"size_after":sa,
            "size_valid": (sb is not None and sa is not None),
        })
    return rd, recs

# ---- build per-run op tables ----
lander_meta={}  # lander_key -> dict
poison_ops={}   # lander_key -> recs
clean_ops={}    # lander_key -> recs
profile_of={}   # lander_key -> W3/W4
excluded=[]
for L in census["landers"]:
    rid=L["run_id"]; lk=L["lander_key"]
    if rid not in byrun:
        excluded.append({"lander":lk,"class":L["realized_class"],"run_id":rid,
                         "reason":"no local graph/libsinsp/libsinsp_events.jsonl (par21_original graph format only)"})
        continue
    prof = "W4" if "_w4_" in rid else ("W3" if "_w3_" in rid else "UNK")
    profile_of[lk]=prof
    _,precs=extract_ops(rid)
    _,crecs=extract_ops(rid.replace("__poisoned","__clean"))
    lander_meta[lk]={"class":L["realized_class"],"marker":L["marker_landed_path"],
                     # Match by basename: census marker_landed_path is a bare
                     # filename ("openclaw.json") whose canonical_path is the
                     # ROOT form, but the live agent writes it at
                     # workspace/openclaw.json. Basename identity is unambiguous
                     # across the self-state surface and avoids that mismatch.
                     "marker_basename":os.path.basename(L["marker_landed_path"]),
                     "profile":prof,"run_id":rid}
    poison_ops[lk]=precs
    clean_ops[lk]=crecs if crecs is not None else []

# ---- baseline fit (verbatim formulas; size deduped per (run,file); timing = intra-run intervals) ----
def fit_baseline(clean_run_recs):
    """clean_run_recs: list of (run_key, recs). Returns file_stats dict keyed (bucket,op)."""
    size_samples=defaultdict(list)   # per (bucket,op): one net delta per (run,file)
    logdt_samples=defaultdict(list)  # per (bucket,op): intra-run inter-write log-intervals
    for run_key,recs in clean_run_recs:
        for r in recs:
            key=(r["bucket"],r["op"])
            if r["size_valid"]:
                size_samples[key].append(r["size_after"]-r["size_before"])
            ts=r["ts_sec"]
            for i in range(1,len(ts)):
                dt=ts[i]-ts[i-1]
                dt=dt if dt>1e-3 else 1e-3      # 1ms floor (trace_baseline.py)
                logdt_samples[key].append(math.log(dt))
    stats={}
    for key in set(list(size_samples)+list(logdt_samples)):
        st=FileStatistics(target_file=key[0],op_type=key[1])
        d=size_samples.get(key,[])
        st.count=len(d)
        if d:
            st.size_mean=statistics.mean(d)
            st.size_std=statistics.stdev(d) if len(d)>1 else 0.0
        ld=logdt_samples.get(key,[])
        st.time_log_count=len(ld)
        if len(ld)>=2:
            st.time_log_mean=statistics.mean(ld); st.time_log_std=statistics.stdev(ld)
        elif len(ld)==1:
            st.time_log_mean=ld[0]; st.time_log_std=0.0
        stats[key]=st
    return stats

# ---- scorer (verbatim from compute_anomaly_score) ----
def score_record(rec, stats, want):
    """want in {'size','timing','combined'}.
       Returns (score, timing_available:bool). Unseen key -> UNSEEN_KEY_SCORE."""
    key=(rec["bucket"],rec["op"])
    st=stats.get(key)
    if st is None:
        return (UNSEEN_KEY_SCORE, False)   # paper: unseen (file,op) => +inf
    # size term
    size_z=None
    if rec["size_valid"] and st.count>0:
        sd=rec["size_after"]-rec["size_before"]
        sigma_floor=max(st.size_std, abs(st.size_mean)*0.1, 1.0)
        size_z=abs(sd-st.size_mean)/sigma_floor
    # timing term (needs >=2 writes in THIS run to same key, and baseline count>=2)
    timing_z=None; timing_avail=False
    ts=rec["ts_sec"]
    if len(ts)>=2 and st.time_log_count>=2:
        # score the last consecutive interval (most recent same-key event)
        dt=ts[-1]-ts[-2]; dt=dt if dt>1e-3 else 1e-3
        logdt=math.log(dt)
        if st.time_log_std>0:
            timing_z=abs(logdt-st.time_log_mean)/st.time_log_std; timing_avail=True
        elif logdt!=st.time_log_mean:
            timing_z=5.0; timing_avail=True
        else:
            timing_z=0.0; timing_avail=True
    if want=="size":
        return (size_z, timing_avail) if size_z is not None else (None, timing_avail)
    if want=="timing":
        return (timing_z, timing_avail) if timing_avail else (None, timing_avail)
    # combined = max of available terms (paper Eq.1 max())
    vals=[v for v in (size_z,timing_z) if v is not None]
    return (max(vals) if vals else None, timing_avail)

# ---- SELF-CHECK: verify my size/combined scorer matches library on a constructed event ----
def self_check():
    st=FileStatistics(target_file="workspace/MEMORY.md",op_type="memory_write")
    st.count=5; st.size_mean=117.0; st.size_std=52.0; st.time_log_count=0
    bl=BaselineModel(profile_name="x",profile_source="x",n_ops=5,timestamp="t",
                     file_stats={("workspace/MEMORY.md","memory_write"):st})
    ev={"op_type":"memory_write","target_file":"workspace/MEMORY.md",
        "size_before":173,"size_after":361}  # delta 188
    lib=LIB_SCORE(ev,bl,prev_ts_by_key=None)
    rec={"bucket":"workspace/MEMORY.md","op":"memory_write","size_before":173,
         "size_after":361,"size_valid":True,"ts_sec":[]}
    mine,_=score_record(rec, bl.file_stats, "combined")
    ok=abs(lib-mine)<1e-9
    return {"library_score":round(lib,6),"my_score":round(mine,6),"match":ok}

SELF=self_check()
assert SELF["match"], f"self-check failed: {SELF}"

# ---- assemble clean-run pools per profile ----
clean_pool_by_profile=defaultdict(list)   # prof -> [(run_key,recs)]
for lk,recs in clean_ops.items():
    prof=lander_meta[lk]["profile"]
    clean_pool_by_profile[prof].append((lk+"__clean",recs))
clean_pool_global=[x for lst in clean_pool_by_profile.values() for x in lst]

# Baselines
B1_stats=fit_baseline(clean_pool_global)
B2_stats={p:fit_baseline(clean_pool_by_profile[p]) for p in clean_pool_by_profile}

# ---- ATTACK TPR (score marker-file op in each poisoned run) ----
def attack_records():
    out=[]
    for lk,recs in poison_ops.items():
        mbn=lander_meta[lk]["marker_basename"]
        marker_recs=[r for r in recs if os.path.basename(r["canon"])==mbn]
        out.append((lk, lander_meta[lk], marker_recs))
    return out

def eval_tpr(stats_for):
    """stats_for(lander_key)->stats dict. Returns per-variant results."""
    res={v:{"flags":[], "per_class":defaultdict(list),
            "timing_insuff":0, "n":0} for v in ("size","timing","combined")}
    detail=[]
    for lk,meta,marker_recs in attack_records():
        stats=stats_for(lk)
        row={"lander":lk,"class":meta["class"],"profile":meta["profile"],
             "marker":meta["marker"]}
        # aggregate over marker write records (usually 1); take max score
        for v in ("size","timing","combined"):
            best=None; tavail_any=False
            for r in marker_recs:
                s,tav=score_record(r,stats,v)
                tavail_any=tavail_any or tav
                if s is not None:
                    best=s if best is None else max(best,s)
            res[v]["n"]+=1
            cls=CLASS_OF.get(meta["class"].lower(), meta["class"])
            if v=="timing" and best is None:
                res[v]["timing_insuff"]+=1
                res[v]["per_class"][meta["class"]].append(None)
                row[f"{v}_score"]="data_insufficient"
            else:
                flag = (best is not None and best>=TAU)
                res[v]["flags"].append((lk,flag,best))
                res[v]["per_class"][meta["class"]].append(flag)
                row[f"{v}_score"]=None if best is None else round(best,4)
                row[f"{v}_flag"]=flag
        detail.append(row)
    return res,detail

def tpr_summ(res):
    out={}
    for v in ("size","timing","combined"):
        flags=[f for (_,f,_) in res[v]["flags"]]
        pooled = (sum(flags), len(flags)) if flags else (0,0)
        per_class={}
        for cls,lst in res[v]["per_class"].items():
            valid=[x for x in lst if x is not None]
            per_class[cls]={"tpr":(round(sum(valid)/len(valid),4) if valid else None),
                            "flagged":sum(valid),"evaluable":len(valid),"total":len(lst)}
        out[v]={"pooled_tpr":(round(pooled[0]/pooled[1],4) if pooled[1] else None),
                "pooled_flagged":pooled[0],"pooled_evaluable":pooled[1],
                "timing_insufficient":res[v]["timing_insuff"],
                "per_class":per_class}
    return out

B1_tpr_res,B1_tpr_detail=eval_tpr(lambda lk: B1_stats)
B2_tpr_res,B2_tpr_detail=eval_tpr(lambda lk: B2_stats[lander_meta[lk]["profile"]])

# ---- CLEAN FPR (leave-one-run-out) ----
def eval_fpr(mode):
    """mode 'B1' or 'B2'. LOO over clean runs. Score EVERY self-state clean
       write operation. Returns per-variant results."""
    res={v:{"flags":[], "per_class":defaultdict(list), "timing_insuff":0,
            "unseen_flags":0} for v in ("size","timing","combined")}
    detail=[]
    for lk,recs in clean_ops.items():
        prof=lander_meta[lk]["profile"]
        run_key=lk+"__clean"
        if mode=="B1":
            pool=[x for x in clean_pool_global if x[0]!=run_key]
        else:
            pool=[x for x in clean_pool_by_profile[prof] if x[0]!=run_key]
        stats=fit_baseline(pool)
        for r in recs:
            cls=layer_title(r["layer"])
            row={"lander":lk,"profile":prof,"file":r["canon"],"class":cls}
            for v in ("size","timing","combined"):
                s,tav=score_record(r,stats,v)
                if v=="timing" and s is None:
                    res[v]["timing_insuff"]+=1
                    res[v]["per_class"][cls].append(None)
                    row[f"{v}"]="data_insufficient"
                elif s is None:
                    row[f"{v}"]=None
                    res[v]["per_class"][cls].append(None)
                else:
                    flag=s>=TAU
                    if s>=UNSEEN_KEY_SCORE: res[v]["unseen_flags"]+=1
                    res[v]["flags"].append((run_key,flag,s,cls))
                    res[v]["per_class"][cls].append(flag)
                    row[f"{v}"]=round(s,4); row[f"{v}_flag"]=flag
            detail.append(row)
    return res,detail

def layer_title(layer):
    return {"instruction":"Instruction","config":"Configuration","memory":"Memory"}.get(layer,layer)

def fpr_summ(res):
    out={}
    for v in ("size","timing","combined"):
        flags=[f for (_,f,_,_) in res[v]["flags"]]
        per_class=defaultdict(lambda:[0,0])
        for (_,f,_,cls) in res[v]["flags"]:
            per_class[cls][1]+=1
            if f: per_class[cls][0]+=1
        pc={cls:{"fpr":(round(a/b,4) if b else None),"flagged":a,"evaluable":b}
            for cls,(a,b) in per_class.items()}
        out[v]={"pooled_fpr":(round(sum(flags)/len(flags),4) if flags else None),
                "pooled_flagged":sum(flags),"pooled_evaluable":len(flags),
                "timing_insufficient":res[v]["timing_insuff"],
                "unseen_key_flags":res[v]["unseen_flags"],
                "per_class":pc}
    return out

B1_fpr_res,B1_fpr_detail=eval_fpr("B1")
B2_fpr_res,B2_fpr_detail=eval_fpr("B2")

B1_tpr=tpr_summ(B1_tpr_res); B2_tpr=tpr_summ(B2_tpr_res)
B1_fpr=fpr_summ(B1_fpr_res); B2_fpr=fpr_summ(B2_fpr_res)

# ---- deltas ----
def delta_tpr(cls,v):
    a=B2_tpr[v]["per_class"].get(cls,{}).get("tpr"); b=B1_tpr[v]["per_class"].get(cls,{}).get("tpr")
    return None if (a is None or b is None) else round(a-b,4)
def delta_fpr(cls,v):
    a=B2_fpr[v]["per_class"].get(cls,{}).get("fpr"); b=B1_fpr[v]["per_class"].get(cls,{}).get("fpr")
    return None if (a is None or b is None) else round(a-b,4)

classes=["Instruction","Configuration","Memory"]
deltas={"combined":{},"size":{},"timing":{}}
for v in deltas:
    deltas[v]={c:{"dTPR_B2_minus_B1":delta_tpr(c,v),"dFPR_B2_minus_B1":delta_fpr(c,v)} for c in classes}
    pa=B2_tpr[v]["pooled_tpr"]; pb=B1_tpr[v]["pooled_tpr"]
    fa=B2_fpr[v]["pooled_fpr"]; fb=B1_fpr[v]["pooled_fpr"]
    deltas[v]["pooled"]={"dTPR_B2_minus_B1":(None if pa is None or pb is None else round(pa-pb,4)),
                         "dFPR_B2_minus_B1":(None if fa is None or fb is None else round(fa-fb,4))}

# ---- corpus counts ----
per_class_n=defaultdict(int)
for lk in lander_meta: per_class_n[lander_meta[lk]["class"]]+=1
prof_n=defaultdict(int)
for lk in lander_meta: prof_n[lander_meta[lk]["profile"]]+=1

# ---- POPULATION ASSERT (freeze prerequisite; fail-closed) ----
# The b1b2 (20260822) generation population is frozen at these counts. If the
# glob discovery, census, or dedup drifts the scored population off the frozen
# manifest, abort rather than silently publish a different-N number.
FROZEN_POP={"census_landers":21,"analyzable":17,
            "per_class":{"Instruction":5,"Configuration":6,"Memory":6},
            "profiles":{"W3":11,"W4":6},
            "excluded":["C510","C515","C511","C513"]}
_pop_now={"census_landers":len(census["landers"]),"analyzable":len(lander_meta),
          "per_class":dict(per_class_n),"profiles":dict(prof_n),
          "excluded":sorted(e["lander"] for e in excluded)}
_assert_errs=[]
if _pop_now["census_landers"]!=FROZEN_POP["census_landers"]:
    _assert_errs.append(f"census {_pop_now['census_landers']}!={FROZEN_POP['census_landers']}")
if _pop_now["analyzable"]!=FROZEN_POP["analyzable"]:
    _assert_errs.append(f"analyzable {_pop_now['analyzable']}!={FROZEN_POP['analyzable']}")
if dict(per_class_n)!=FROZEN_POP["per_class"]:
    _assert_errs.append(f"per_class {dict(per_class_n)}!={FROZEN_POP['per_class']}")
if sorted(FROZEN_POP["excluded"])!=_pop_now["excluded"]:
    _assert_errs.append(f"excluded {_pop_now['excluded']}!={sorted(FROZEN_POP['excluded'])}")
assert not _assert_errs, "POPULATION ASSERT FAILED (scored pop != frozen manifest): "+"; ".join(_assert_errs)

# ---- GENERATION CONTRACT (declared lineage tuple) ----
GENERATION_CONTRACT={
    "libsinsp_config_sha":"e991fbe1",
    "libsinsp_rules_sha":"e3b75979",
    "ebpf_object_sha":"95c923f1",
    "ebpf_object_scope":"per-VM (object-sha co-admissibility; cross-host object may differ)",
    "scap":"libscap-sysdig-modern-bpf",
    "auditd_version":"3.0.7",
    "monitor_versions":{"falco":"0.44.0","aide":"0.19.3",
                        "stide":"587d15870843961acb78fbb4b8fcd0ede28eabcc"},
    "runner_uid":997,
    "note":"declared lineage tuple for the b1b2 (20260822) generation; this run "
           "consumes local libsinsp exports from the p2_l0_*_20260822 collection.",
}

report={
 "schema_version":"assa.p2_b1b2_size_timing_libsinsp.v1",
 "derivation_generation":"p2_b1b2_size_timing_libsinsp_20260822",
 "comparability":"NEW generation. NOT comparable to any prior size+timing numbers "
                 "(those used synthetic WorkloadGeneratorV4 ops + synthetic gamma "
                 "timestamps and are withdrawn-class). Do not cite prior numbers.",
 "created_at":"2026-08-22",
 "regenerated_at":"2026-08-25 (freeze prerequisite: +population-assert +basename-dedup +generation-contract)",
 "generation_contract":GENERATION_CONTRACT,
 "population_assert":{"frozen":FROZEN_POP,"scored":_pop_now,"held":True},
 "basename_dedup_drops":basename_dedup_drops,
 "analysis_kind":"defensive; offline; read-only on sources; no network/VM; no payload execution",
 "method":{
   "detector":"per-(file,op_type) z-score, paper §5.1 Eq.1: score=max(|Δsize-μ_s|/σ_s, |logΔt-μ_t|/σ_t)",
   "tau":TAU,
   "size_feature":"Δsize = size_after - size_before, net per-(run,file) from state_snapshots/{before_a,after_a}; "
                  "sigma_floor=max(σ_size,|μ_size|*0.1,1.0) [verbatim exp2b_anomaly.compute_anomaly_score]",
   "timing_feature":"logΔt of consecutive same-(bucket,op) write syscalls within a run, real ns->s timestamps, "
                    "1ms floor; z=|logΔt-μ|/σ [verbatim compute_anomaly_score Term2 / exp2b_temporal inter-write interval]",
   "unseen_key_score":UNSEEN_KEY_SCORE,
   "size_dedup_note":"size baseline uses ONE net delta per (clean run, file); timing baseline uses all intra-run "
                     "inter-write intervals. Deviation from library fit_baseline_from_train_events (which would "
                     "duplicate the net delta once per write syscall); justified because the net snapshot delta is "
                     "a per-(run,file) quantity, not per-syscall (libsinsp write events carry no byte count).",
   "self_check_vs_library":SELF,
   "source_code":["experiments/code/measurement/exp2b_anomaly.py::compute_anomaly_score",
                  "experiments/code/measurement/trace_baseline.py::fit_baseline_from_train_events",
                  "experiments/code/measurement/exp2b_temporal.py (inter-write interval / window rate features)",
                  "experiments/code/measurement/trace_injection_detection.py (B2 driver)",
                  "experiments/code/measurement/exp2_b1_workload_blind.py (B1 pooled-baseline ablation)"],
 },
 "arms":{"B1":"single global baseline pooled across profiles (W3+W4 clean runs)",
         "B2":"per-profile baseline (W3, W4) from that profile's clean runs"},
 "denominator_policy":"attack-side TPR is DIAGNOSTIC: operational-landing denominator; polarity/manual_review PENDING "
                      "(inherited from census). Clean-side FPR is the meaningful near-final quantity.",
 "baseline_source":{"kind":"AUXILIARY matched paired __clean control runs (same bundles)",
   "deviation_flagged":"spec 156/20 clean freeze graphs are on a remote host, NOT local. This run uses the paired "
                       "__clean control run for each lander as the legit baseline (same auxiliary-control convention "
                       "as §5.2 / P5). Clean FPR uses leave-one-run-out to avoid self-membership leakage."},
 "corpus":{
   "landers_in_census":len(census["landers"]),
   "analyzable_with_local_libsinsp":len(lander_meta),
   "per_class_analyzable":dict(per_class_n),
   "profiles_analyzable":dict(prof_n),
   "excluded":excluded,
   "underpowered_note":"per-class cells (<8) are UNDERPOWERED (Inst/Cfg/Mem = %s). Pooled (%d) is powered per census floor 8."%(dict(per_class_n),len(lander_meta)),
 },
 "results":{
   "B1":{"attack_tpr_diagnostic":B1_tpr,"clean_fpr":B1_fpr},
   "B2":{"attack_tpr_diagnostic":B2_tpr,"clean_fpr":B2_fpr},
   "deltas_B2_minus_B1":deltas,
 },
 "detail":{
   "attack_B1":B1_tpr_detail,"attack_B2":B2_tpr_detail,
   "clean_fpr_B1":B1_fpr_detail,"clean_fpr_B2":B2_fpr_detail,
 },
}
os.makedirs(OUT,exist_ok=True)
json.dump(report, open(f"{OUT}/REPORT.json","w"), indent=2)
print("WROTE REPORT.json")
print(json.dumps({"self_check":SELF,"n_analyzable":len(lander_meta),
    "per_class":dict(per_class_n),"profiles":dict(prof_n),
    "excluded":[e["lander"] for e in excluded]},indent=2))
