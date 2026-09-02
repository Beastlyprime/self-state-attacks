#!/usr/bin/env python3
"""
Expanded substrate-A design matrix (design SUPERVISED_ARM_DESIGN_20260823.md §3A;
coordinator ruling 2026-08-25).

Locked-pop 17 pos + 43 neg are loaded VERBATIM from the frozen
p2_supervised_arm_20260823 feature matrix (byte-identical, guaranteed co-admissible
and comparable). NEW substrate-A positives = the write-resolved landers only, per the
D-B definability ruling: MUI 6 + MCAW 3 (MCAW102/202/401). File-op (26) and MUC (6)
are N/A for substrate A (no resolved marker write) and are NOT fabricated here.
Negatives = every self-state write op of each new lander's paired __clean twin.

Defensive analysis. Offline, read-only. No network/VM/payload execution.
"""
import json, os, glob, math, re, sys, collections
from pathlib import Path as _Path
_REPO_ROOT = str(_Path(__file__).resolve().parents[3])
CODE = _REPO_ROOT + "/experiments/code"; sys.path.insert(0, CODE)
from workload.taxonomy import canonical_path, bucket_key, layer_of

RES = _REPO_ROOT + "/data"
HERE = os.path.dirname(os.path.abspath(__file__))
FROZEN = f"{RES}/p2_supervised_arm_20260823/features_substrate_a.json"
OUT = f"{HERE}/features_substrate_a.json"
LOCKED_COPY = f"{HERE}/features_substrate_a_lockedpop.json"
WRITE = {"write", "pwrite", "pwritev", "writev", "pwrite64"}
DT = 1e-3
LAYER_TITLE = {"instruction": "Instruction", "config": "Configuration", "memory": "Memory"}

# substrate-A-eligible NEW landers (write-resolved per B3 diagnostic); MCAW102/202/401 only
NEW_A = {"MUI01","MUI02","MUI03","MUI04","MUI05","MUI06","MCAW102","MCAW202","MCAW401"}


def run_rel(p, rid):
    k = f"/{rid}/"; i = p.find(k); return None if i < 0 else p[i+len(k):]

def fsize(p):
    try: return os.path.getsize(p)
    except OSError: return None

def snapshot_delta(rundir, canon, first_dated_rel):
    rel = first_dated_rel if "*" in canon else (canon[len("workspace/"):] if canon.startswith("workspace/") else canon)
    sb = fsize(os.path.join(rundir, "state_snapshots", "before_a", rel))
    sa = fsize(os.path.join(rundir, "state_snapshots", "after_a", rel))
    if sb is None and sa is not None: sb = 0
    if sa is None and sb is not None: sa = 0
    return sb, sa

def extract_ops(rundir, run_id):
    f = os.path.join(rundir, "graph", "libsinsp", "libsinsp_events.jsonl")
    if not os.path.exists(f): return None
    buckets = collections.defaultdict(lambda: {"ts": [], "canon": None, "first_dated": None})
    with open(f) as fh:
        for line in fh:
            e = json.loads(line); sc = e.get("syscall", {})
            if sc.get("name") not in WRITE or sc.get("result") != "SUCCESS": continue
            path = (e.get("file") or {}).get("path")
            if not path: continue
            rel = run_rel(path, run_id)
            if rel is None: continue
            cp = canonical_path(rel)
            if cp is None: continue
            bk = bucket_key(cp); b = buckets[bk]
            b["ts"].append(e["order"]["timestamp_realtime_ns"] / 1e9)
            if b["canon"] is None: b["canon"] = cp
            if b["first_dated"] is None and "*" in bk:
                b["first_dated"] = cp[len("workspace/"):] if cp.startswith("workspace/") else cp
    recs = []
    for bk, b in buckets.items():
        sb, sa = snapshot_delta(rundir, bk, b["first_dated"])
        recs.append({"bucket": bk, "layer": layer_of(b["canon"]), "canon": b["canon"],
                     "ts_sec": sorted(b["ts"]), "size_before": sb, "size_after": sa,
                     "size_valid": (sb is not None and sa is not None)})
    return recs

def features(rec):
    ts = rec["ts_sec"]; n = len(ts)
    dts = [math.log(max(ts[i]-ts[i-1], DT)) for i in range(1, n)]
    d = (rec["size_after"] - rec["size_before"]) if rec["size_valid"] else None
    return {"delta_size": d, "abs_delta_size": (abs(d) if d is not None else None),
            "size_before": rec["size_before"], "size_after": rec["size_after"], "n_writes": n,
            "log_dt_last": (dts[-1] if dts else None),
            "log_dt_mean": (sum(dts)/len(dts) if dts else None),
            "write_span_sec": (ts[-1]-ts[0] if n >= 2 else 0.0),
            "has_timing": int(bool(dts)), "layer": LAYER_TITLE.get(rec["layer"], rec["layer"]),
            "bucket": rec["bucket"], "canon": rec["canon"]}

def profile_of(rid):
    for w in ("w1","w2","w3","w4"):
        if f"_{w}_" in rid: return w.upper()
    return "UNK"

def base_scenario(lk):
    # strip M<fam><num>_w<n>_ prefix -> descriptive base case (channel/profile variants share a fold)
    m = re.match(r"^M[A-Z]+\d+_w\d+_(.+)$", lk)
    return m.group(1) if m else lk

def find_run(rid):
    hits = glob.glob(f"{RES}/p2_mass_attack_lane*/**/{rid}", recursive=True)
    hits = [h for h in hits if h.endswith(rid) and os.path.isdir(os.path.join(h, "graph"))]
    return hits[0] if hits else None


def main():
    frozen = json.load(open(FROZEN))
    rows = list(frozen["rows"])
    landers = list(frozen["landers"])
    json.dump(frozen, open(LOCKED_COPY, "w"), indent=2)  # keep the locked-pop matrix for reference

    new_landers, excluded = [], []
    # discover new poisoned runs for the substrate-A-eligible set
    poisoned = {}
    for d in glob.glob(f"{RES}/p2_mass_attack_lane*/**/*__poisoned", recursive=True):
        b = os.path.basename(d)
        case = re.match(r"^(M[A-Z]+\d+)", b)
        if case and case.group(1) in NEW_A and os.path.exists(os.path.join(d, "graph/libsinsp/libsinsp_events.jsonl")):
            poisoned.setdefault(b, d)

    for rid, pdir in sorted(poisoned.items()):
        case = re.match(r"^(M[A-Z]+\d+)", rid).group(1)
        lk = re.sub(r"__poisoned$", "", rid)
        gt = json.load(open(os.path.join(pdir, "ground_truth.json")))
        markers = set(os.path.basename(h["path"]) for h in gt.get("attack_marker_evidence", {}).get("hits", []) if h.get("path"))
        cls = (gt.get("changed_logical_classes") or ["?"])[0]
        prof = profile_of(rid); scen = base_scenario(lk)
        precs = extract_ops(pdir, rid)
        cid = rid.replace("__poisoned", "__clean")
        cdir = os.path.join(os.path.dirname(pdir), cid)
        crecs = extract_ops(cdir, cid)
        if precs is None or crecs is None:
            excluded.append({"lander": lk, "reason": "missing libsinsp (poisoned or twin)"}); continue
        marker_recs = [r for r in precs if os.path.basename(r["canon"]) in markers]
        if not marker_recs:
            excluded.append({"lander": lk, "reason": "no resolved marker write op (substrate A undefined)"}); continue
        new_landers.append({"lander": lk, "class": cls, "profile": prof,
                            "marker": sorted(markers)[0] if markers else "", "scenario": scen})
        for r in marker_recs:
            f = features(r); f.update({"label": 1, "lander": lk, "profile": prof, "scenario": scen,
                                       "run_kind": "poisoned", "realized_class": cls,
                                       "n_marker_recs": len(marker_recs)})
            rows.append(f)
        for r in crecs:
            f = features(r); f.update({"label": 0, "lander": lk, "profile": prof, "scenario": scen,
                                       "run_kind": "clean",
                                       "realized_class": LAYER_TITLE.get(r["layer"], r["layer"]),
                                       "n_marker_recs": None})
            rows.append(f)

    scen = sorted({r["scenario"] for r in rows})
    out = {
        "schema_version": "assa.p2_supervised_arm.features_a.v1",
        "derivation_generation": "p2_supervised_arm_expanded_20260825",
        "comparability": "EXPANDED. Locked-pop 17 pos/43 neg loaded verbatim from frozen "
                         "p2_supervised_arm_20260823; new rows appended for the write-resolved "
                         "substrate-A landers (MUI 6 + MCAW 3) and their paired __clean twins.",
        "new_substrate_a_eligible": sorted(NEW_A),
        "cv_grouping": {"scheme": "leave-one-scenario-out; channel/profile variants share a fold",
                        "n_groups": len(scen), "groups": scen},
        "counts": {"positives": sum(r["label"] == 1 for r in rows),
                   "negatives": sum(r["label"] == 0 for r in rows),
                   "locked_pos": 17, "locked_neg": 43,
                   "new_pos": sum(r["label"] == 1 and r["run_kind"] == "poisoned" for r in rows) - 17,
                   "landers_total": len(landers) + len(new_landers),
                   "new_landers_added": len(new_landers)},
        "excluded_new": excluded,
        "landers": landers + new_landers,
        "rows": rows,
    }
    json.dump(out, open(OUT, "w"), indent=2)
    print(json.dumps(out["counts"], indent=2))
    print("new landers added:", [l["lander"] for l in new_landers])
    print("excluded new:", excluded)
    print("scenarios:", scen)
    print(f"WROTE {OUT}")


if __name__ == "__main__":
    main()
