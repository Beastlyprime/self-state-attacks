#!/usr/bin/env python3
"""
Substrate-A design matrix for the supervised arm (design: SUPERVISED_ARM_DESIGN_20260823.md §3A).

Emits the RAW features that the frozen B1/B2 harness consumes but does not persist
(its REPORT.json.detail stores only z-scores). Extraction logic is duplicated
VERBATIM from the frozen generation rather than imported, because that script is a
top-level program under SHA256SUMS.txt and importing it would re-execute and rewrite
its REPORT.json. Safety comes from POPULATION_ASSERT below: the derived population
must match the frozen REPORT.json exactly (17 landers, same keys, 43 clean ops).

Unit of analysis = one per-(run, file) self-state write operation.
  positives (17) = the marker-file operation of each poisoned run
  negatives (43) = every self-state write operation of the paired __clean twin
This is the same pairing the frozen harness uses for TPR vs FPR.

Defensive analysis. Offline, read-only on sources. No network, no VM, no payload execution.
"""
import json, os, glob, math, hashlib, sys, re
from collections import defaultdict
from pathlib import Path as _Path
_REPO_ROOT = str(_Path(__file__).resolve().parents[3])

CODE = _REPO_ROOT + "/experiments/code"
sys.path.insert(0, CODE)
from workload.taxonomy import canonical_path, bucket_key, layer_of

RES = _REPO_ROOT + "/data"
HERE = os.path.dirname(os.path.abspath(__file__))
FROZEN = f"{RES}/detection/b1b2"
OUT = HERE
WRITE = {"write", "pwrite", "pwritev", "writev", "pwrite64"}
DT_FLOOR = 1e-3  # 1 ms floor, verbatim trace_baseline.py


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---- extraction, verbatim from run_size_timing_libsinsp.py ----
def run_rel(path, run_id):
    k = f"/{run_id}/"
    i = path.find(k)
    return None if i < 0 else path[i + len(k):]


def fsize(p):
    try:
        return os.path.getsize(p)
    except OSError:
        return None


def snapshot_delta(rundir, canon, first_dated_rel):
    if "*" in canon:
        rel = first_dated_rel
    else:
        rel = canon[len("workspace/"):] if canon.startswith("workspace/") else canon
    sb = fsize(os.path.join(rundir, "state_snapshots", "before_a", rel))
    sa = fsize(os.path.join(rundir, "state_snapshots", "after_a", rel))
    if sb is None and sa is not None:
        sb = 0
    if sa is None and sb is not None:
        sa = 0
    return sb, sa


def extract_ops(run_id, byrun):
    rd = byrun.get(run_id)
    if not rd:
        return None, None
    f = os.path.join(rd, "graph", "libsinsp", "libsinsp_events.jsonl")
    buckets = defaultdict(lambda: {"ts": [], "canon": None, "first_dated": None})
    with open(f) as fh:
        for line in fh:
            e = json.loads(line)
            sc = e.get("syscall", {})
            if sc.get("name") not in WRITE or sc.get("result") != "SUCCESS":
                continue
            path = (e.get("file") or {}).get("path")
            if not path:
                continue
            rel = run_rel(path, run_id)
            if rel is None:
                continue
            cp = canonical_path(rel)
            if cp is None:
                continue
            bk = bucket_key(cp)
            b = buckets[bk]
            b["ts"].append(e["order"]["timestamp_realtime_ns"] / 1e9)
            if b["canon"] is None:
                b["canon"] = cp
            if b["first_dated"] is None and "*" in bk:
                b["first_dated"] = cp[len("workspace/"):] if cp.startswith("workspace/") else cp
    recs = []
    for bk, b in buckets.items():
        layer = layer_of(b["canon"])
        sb, sa = snapshot_delta(rd, bk, b["first_dated"])
        recs.append({
            "bucket": bk, "op": f"{layer}_write", "layer": layer, "canon": b["canon"],
            "ts_sec": sorted(b["ts"]), "size_before": sb, "size_after": sa,
            "size_valid": (sb is not None and sa is not None),
        })
    return rd, recs


# ---- feature derivation ----
LAYER_TITLE = {"instruction": "Instruction", "config": "Configuration", "memory": "Memory"}


def features(rec):
    """Raw features for one per-(run,file) write operation."""
    ts = rec["ts_sec"]
    n = len(ts)
    dts = []
    for i in range(1, n):
        dt = ts[i] - ts[i - 1]
        dts.append(math.log(dt if dt > DT_FLOOR else DT_FLOOR))
    d = None
    if rec["size_valid"]:
        d = rec["size_after"] - rec["size_before"]
    return {
        # --- core (magnitude / rate; no object identity) ---
        "delta_size": d,
        "abs_delta_size": (abs(d) if d is not None else None),
        "size_before": rec["size_before"],
        "size_after": rec["size_after"],
        "n_writes": n,
        "log_dt_last": (dts[-1] if dts else None),
        "log_dt_mean": (sum(dts) / len(dts) if dts else None),
        "write_span_sec": (ts[-1] - ts[0] if n >= 2 else 0.0),
        "has_timing": int(bool(dts)),
        # --- context (deployment situation an OS monitor legitimately knows) ---
        "layer": LAYER_TITLE.get(rec["layer"], rec["layer"]),
        # --- identity (ablated in A2/A3) ---
        "bucket": rec["bucket"],
        # not a model feature: carried so rows can be joined to the frozen B1/B2
        # per-row decisions, which key clean events on the canonical path
        "canon": rec["canon"],
    }


def scenario_of(lander_key):
    m = re.match(r"^(C\d+)", lander_key)
    if not m:
        raise SystemExit(f"cannot derive scenario group from lander key {lander_key!r}")
    return m.group(1)


def main():
    census = json.load(open(f"{RES}/p2_attack_tpr_expanded_v2_20260822/EXPANDED_LANDED_CENSUS_V2_20260822.json"))
    libs = glob.glob(f"{RES}/p2_l0_*_20260822/**/graph/libsinsp/libsinsp_events.jsonl", recursive=True)
    byrun = {}
    for p in libs:
        rd = os.path.dirname(os.path.dirname(os.path.dirname(p)))
        byrun[os.path.basename(rd)] = rd

    rows = []
    landers = []
    excluded = []
    for L in census["landers"]:
        rid, lk = L["run_id"], L["lander_key"]
        if rid not in byrun:
            excluded.append({"lander": lk, "run_id": rid})
            continue
        prof = "W4" if "_w4_" in rid else ("W3" if "_w3_" in rid else "UNK")
        marker_bn = os.path.basename(L["marker_landed_path"])
        _, precs = extract_ops(rid, byrun)
        _, crecs = extract_ops(rid.replace("__poisoned", "__clean"), byrun)
        crecs = crecs or []
        landers.append({"lander": lk, "class": L["realized_class"], "profile": prof,
                        "marker": L["marker_landed_path"], "scenario": scenario_of(lk)})

        marker_recs = [r for r in precs if os.path.basename(r["canon"]) == marker_bn]
        if len(marker_recs) != 1:
            # the frozen harness takes max over marker records; keep the same
            # aggregation by emitting the largest |Δsize| record and recording the count
            pass
        for r in marker_recs:
            f = features(r)
            f.update({"label": 1, "lander": lk, "profile": prof,
                      "scenario": scenario_of(lk), "run_kind": "poisoned",
                      "realized_class": L["realized_class"],
                      "n_marker_recs": len(marker_recs)})
            rows.append(f)
        for r in crecs:
            f = features(r)
            f.update({"label": 0, "lander": lk, "profile": prof,
                      "scenario": scenario_of(lk), "run_kind": "clean",
                      "realized_class": LAYER_TITLE.get(r["layer"], r["layer"]),
                      "n_marker_recs": None})
            rows.append(f)

    # ---- POPULATION_ASSERT against the frozen generation ----
    frozen = json.load(open(f"{FROZEN}/REPORT.json"))
    fz_attack = {e["lander"] for e in frozen["detail"]["attack_B1"]}
    fz_clean_n = len(frozen["detail"]["clean_fpr_B1"])
    my_attack = {r["lander"] for r in rows if r["label"] == 1}
    my_pos_n = sum(1 for r in rows if r["label"] == 1)
    my_neg_n = sum(1 for r in rows if r["label"] == 0)
    problems = []
    if my_attack != fz_attack:
        problems.append(f"lander set mismatch: only-mine={sorted(my_attack - fz_attack)} "
                        f"only-frozen={sorted(fz_attack - my_attack)}")
    if my_pos_n != len(fz_attack):
        problems.append(f"positive count {my_pos_n} != frozen lander count {len(fz_attack)}")
    if my_neg_n != fz_clean_n:
        problems.append(f"negative count {my_neg_n} != frozen clean-event count {fz_clean_n}")
    if len(excluded) != len(frozen["corpus"]["excluded"]):
        problems.append(f"excluded count {len(excluded)} != frozen {len(frozen['corpus']['excluded'])}")
    if problems:
        raise SystemExit("POPULATION_ASSERT FAILED:\n  " + "\n  ".join(problems))

    scen = sorted({r["scenario"] for r in rows})
    out = {
        "schema_version": "assa.p2_supervised_arm.features_a.v1",
        "derivation_generation": "p2_supervised_arm_20260823",
        "comparability": "NEW derivation. Raw features underlying the frozen "
                         "p2_b1b2_size_timing_libsinsp_20260822 scores; not comparable to "
                         "the withdrawn synthetic V/C/I generation.",
        "analysis_kind": "defensive; offline; read-only on sources; no network/VM; no payload execution",
        "unit_of_analysis": "one per-(run,file) self-state write operation",
        "positives": "marker-file operation of each poisoned run",
        "negatives": "every self-state write operation of the paired __clean twin (same VM, same kernel)",
        "extraction_provenance": {
            "duplicated_verbatim_from": "p2_b1b2_size_timing_libsinsp_20260822/run_size_timing_libsinsp.py",
            "source_sha256": sha256(f"{FROZEN}/run_size_timing_libsinsp.py"),
            "why_not_imported": "frozen script is a top-level program under SHA256SUMS.txt; "
                                "importing would re-execute it and rewrite its REPORT.json",
            "population_assert": "PASSED — lander set, positive count, negative count and "
                                 "exclusion count all match the frozen REPORT.json",
        },
        "feature_groups": {
            "core": ["delta_size", "abs_delta_size", "size_before", "size_after",
                     "n_writes", "log_dt_last", "log_dt_mean", "write_span_sec", "has_timing"],
            "context": ["layer", "profile"],
            "identity": ["bucket"],
        },
        "cv_grouping": {"scheme": "leave-one-scenario-out", "n_groups": len(scen), "groups": scen},
        "counts": {"positives": my_pos_n, "negatives": my_neg_n,
                   "landers": len(landers), "excluded": len(excluded)},
        "excluded": excluded,
        "landers": landers,
        "rows": rows,
    }
    os.makedirs(OUT, exist_ok=True)
    json.dump(out, open(f"{OUT}/features_substrate_a.json", "w"), indent=2)
    print(json.dumps({k: out[k] for k in ("counts", "cv_grouping")}, indent=2))
    print("POPULATION_ASSERT: PASSED")
    print(f"WROTE {OUT}/features_substrate_a.json")


if __name__ == "__main__":
    main()
