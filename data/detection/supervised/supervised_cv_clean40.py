#!/usr/bin/env python3
"""
Supervised arm (substrate A) RE-SCORED with negatives = the frozen NATURAL
held-out clean-40 (split 42baa6a9), instead of the paired __clean twins.

Coordinator correction 2026-08-25: the UNIFIED head-to-head puts every detector
on the SAME data (positives = 55 attack landers, negatives = clean-40). The
supervised arm's native positive support is the WRITE-RESOLVED (D-B definable)
subset only -- substrate A is a write size+timing detector and is undefined for
attacks with no resolved marker write (chmod/unlink/truncate/semantic_inversion +
MUC atomic-rename). So its positives are the same 27 marker-write rows / 26
definable landers as the frozen expanded arm; ONLY the negatives change here.

WORKLOAD-UNMATCHED CAVEAT (flag, do not change): clean-40 are natural held-out
runs on DIFFERENT tasks than the attacks. A discriminative model can therefore
exploit task / target-selection structure rather than attack signal. The C2
marker-file placebo quantifies exactly this inflation and is reported beside the
main AUC. (The confound-safe twin-based number is in the frozen REPORT.md.)

Positives: verbatim label==1 rows from features_substrate_a.json (expanded).
Negatives: every canonical self-state write op of each clean-40 run
           (staging/<rid>/graph/libsinsp + state_snapshots), extracted with the
           SAME extract_ops/features primitives as emit_features_expanded.

Defensive analysis. Offline, read-only. No network/VM/payload execution.
Global RNG seed pinned before every fit (supervised_cv.SEED).
"""
import json, os, sys, math, collections, warnings
import numpy as np
from pathlib import Path as _Path
_REPO_ROOT = str(_Path(__file__).resolve().parents[3])

warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
CODE = _REPO_ROOT + "/experiments/code"; sys.path.insert(0, CODE)
from workload.taxonomy import canonical_path, bucket_key, layer_of
import matrix as M
import supervised_cv as SV          # reuse loso_oof, evaluate, boot_auc_ci, tpr_at_fpr, make_models, readable_models, SEED
from sklearn.metrics import roc_auc_score, roc_curve
from scipy import stats

HH = _REPO_ROOT + "/data/superseded"
STAGE = os.path.join(HH, "staging")
MAN = json.load(open(os.path.join(HH, "W3THICK_POPULATION_MANIFEST.json")))
FEAT = f"{HERE}/features_substrate_a.json"          # expanded (twin-based) matrix; we reuse its positives + landers
OUT_FEAT = f"{HERE}/features_substrate_a_clean40.json"
OUT = f"{HERE}/supervised_cv_clean40.json"
SEED = SV.SEED

WRITE = {"write", "pwrite", "pwritev", "writev", "pwrite64"}
DT = 1e-3
LAYER_TITLE = {"instruction": "Instruction", "config": "Configuration", "memory": "Memory"}


# ----- clean-40 negative extraction (identical to emit_features_expanded) -----
def run_rel(p, rid):
    k = f"/{rid}/"; i = p.find(k); return None if i < 0 else p[i + len(k):]

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
    for line in open(f):
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
    dts = [math.log(max(ts[i] - ts[i - 1], DT)) for i in range(1, n)]
    d = (rec["size_after"] - rec["size_before"]) if rec["size_valid"] else None
    return {"delta_size": d, "abs_delta_size": (abs(d) if d is not None else None),
            "size_before": rec["size_before"], "size_after": rec["size_after"], "n_writes": n,
            "log_dt_last": (dts[-1] if dts else None),
            "log_dt_mean": (sum(dts) / len(dts) if dts else None),
            "write_span_sec": (ts[-1] - ts[0] if n >= 2 else 0.0),
            "has_timing": int(bool(dts)), "layer": LAYER_TITLE.get(rec["layer"], rec["layer"]),
            "bucket": rec["bucket"], "canon": rec["canon"]}


def build_matrix():
    exp = json.load(open(FEAT))
    pos = [dict(r) for r in exp["rows"] if r["label"] == 1]     # 27 marker-write positives, verbatim
    landers = exp["landers"]
    marker_bn = {L["lander"]: os.path.basename(L["marker"]) for L in landers}

    neg = []
    clean_meta = {}
    zero_write, no_lib = [], []
    for c in MAN["clean_heldout_40"]:
        rid = c["run_id"]; prof = c["profile"]; rd = os.path.join(STAGE, rid)
        recs = extract_ops(rd, rid)
        clean_meta[rid] = {"profile": prof, "n_write_ops": (len(recs) if recs is not None else None)}
        if recs is None:
            no_lib.append(rid); continue
        if not recs:
            zero_write.append(rid); continue
        for r in recs:
            f = features(r)
            f.update({"label": 0, "lander": rid, "profile": prof, "scenario": rid,   # each clean run = own CV group
                      "run_kind": "clean40", "realized_class": LAYER_TITLE.get(r["layer"], r["layer"]),
                      "n_marker_recs": None})
            neg.append(f)

    rows = pos + neg
    out = {
        "schema_version": "assa.p2_supervised_arm.features_a_clean40.v1",
        "derivation_generation": "p2_supervised_arm_clean40_20260825",
        "negatives_basis": "NATURAL held-out clean-40 (split 42baa6a9); NOT paired twins",
        "workload_unmatched_caveat": "clean-40 are different tasks than the attacks; a discriminative "
                                     "model may exploit task/target-selection structure. C2 placebo quantifies it.",
        "positives_basis": "verbatim label==1 marker-write rows from the expanded (twin-based) matrix; "
                           "write-resolved / D-B definable subset only (substrate A undefined for the 32 "
                           "no-resolved-marker-write attacks: chmod/unlink/truncate/semantic_inversion + MUC)",
        "counts": {"positives": len(pos), "negatives": len(neg),
                   "pos_landers": len({r["lander"] for r in pos}),
                   "clean40_runs_total": len(MAN["clean_heldout_40"]),
                   "clean40_runs_with_write_ops": len({r["lander"] for r in neg}),
                   "clean40_runs_zero_write_ops": len(zero_write),
                   "clean40_runs_no_libsinsp": len(no_lib)},
        "clean40_zero_write_runs": zero_write,
        "clean40_no_libsinsp_runs": no_lib,
        "clean40_per_run": clean_meta,
        "landers": landers,
        "marker_basenames": sorted(set(marker_bn.values())),
        "rows": rows,
    }
    json.dump(out, open(OUT_FEAT, "w"), indent=2)
    return out


def lander_level(rows, oof, pos_landers, clean_runs):
    """Aggregate row OOF prob -> per-lander max; build (attack-definable vs clean-40) ROC.
    clean-40 runs with 0 write ops / no OOF row are automatic non-fires (score 0)."""
    by = collections.defaultdict(list)
    for r, p in zip(rows, oof):
        if not np.isnan(p):
            by[r["lander"]].append(p)
    y, s, ids = [], [], []
    for L in sorted(pos_landers):
        y.append(1); s.append(max(by.get(L, [0.0]))); ids.append(L)
    for rid in sorted(clean_runs):
        y.append(0); s.append(max(by.get(rid, [0.0]))); ids.append(rid)   # 0.0 if no scorable write
    y = np.array(y); s = np.array(s)
    auc = float(roc_auc_score(y, s))
    fpr, tpr, thr = roc_curve(y, s)
    npos = int((y == 1).sum()); nneg = int((y == 0).sum())

    def counts_at(target_fpr):
        ok = fpr <= target_fpr + 1e-12
        if not ok.any():
            return None
        j = np.where(ok)[0][np.argmax(tpr[ok])]
        t = thr[j]
        tp = int(((s >= t) & (y == 1)).sum()); fp = int(((s >= t) & (y == 0)).sum())
        return {"threshold": round(float(t), 6), "tpr_n": tp, "tpr_den": npos,
                "fpr_n": fp, "fpr_den": nneg,
                "tpr": round(tp / npos, 4), "fpr": round(fp / nneg, 4)}

    # also a natural p>=0.5 operating point
    tp5 = int(((s >= 0.5) & (y == 1)).sum()); fp5 = int(((s >= 0.5) & (y == 0)).sum())
    return {
        "lander_auc": round(auc, 4),
        "n_pos_landers": npos, "n_clean40": nneg,
        "op_point_fpr_le_0125": counts_at(0.125),   # matched to ours-B1/B2 clean-40 FPR (5/40)
        "op_point_fpr_le_010": counts_at(0.10),
        "op_point_prob_ge_050": {"tpr_n": tp5, "tpr_den": npos, "fpr_n": fp5, "fpr_den": nneg,
                                  "tpr": round(tp5 / npos, 4), "fpr": round(fp5 / nneg, 4)},
    }


def clean40_marker_placebo(feat):
    """clean-40-NATIVE marker placebo: among clean-40 write rows, label 1 iff the write hits
    one of the attack-marker files. High separation => the clean-40 arm's signal is
    target-selection / file-identity, not attack. (Complements the twin-based C2.)"""
    markers = set(feat["marker_basenames"])
    crows = [r for r in feat["rows"] if r["label"] == 0]
    yc = np.array([1 if os.path.basename(r["canon"]) in markers else 0 for r in crows], dtype=int)
    n1 = int(yc.sum())
    res = {"markers": sorted(markers), "n_marker_rows": n1, "n_clean40_rows": len(crows)}
    if len(set(yc)) < 2 or n1 < 2:
        res["status"] = "not_evaluable_single_or_sparse_class"
        return res
    gc = np.array([r["scenario"] for r in crows])
    res["status"] = "evaluable"
    res["results"] = {v: SV.evaluate(crows, yc, gc, v, "clean40-marker-placebo") for v in ("A2", "A3", "A4")}
    return res


def main():
    feat = build_matrix()
    rows = feat["rows"]
    y = M.labels(rows); g = M.groups(rows)
    rng = np.random.default_rng(SEED)
    pos_landers = {r["lander"] for r in rows if r["label"] == 1}
    clean_runs = {c["run_id"] for c in MAN["clean_heldout_40"]}
    n_pos, n_neg = int((y == 1).sum()), int((y == 0).sum())

    print("[counts]", feat["counts"])
    print("[main] real labels, negatives=clean-40")
    main_res = {v: SV.evaluate(rows, y, g, v, "clean40-real") for v in ("A1", "A2", "A3", "A4")}

    print("[C1a] globally permuted labels")
    yglob = rng.permutation(y)
    c1a = {v: SV.evaluate(rows, yglob, g, v, "C1a") for v in ("A2", "A3", "A4")}

    print("[C1b] labels permuted within group")
    yperm = y.copy()
    for grp in sorted(set(g)):
        idx = np.where(g == grp)[0]
        yperm[idx] = rng.permutation(y[idx])
    c1b = {v: SV.evaluate(rows, yperm, g, v, "C1b") for v in ("A2", "A3", "A4")}

    print("[C3] positive control")
    d_eff = 0.95
    synth = (d_eff * y + rng.normal(0, 1, size=len(y))).reshape(-1, 1)
    c3 = {v: SV.evaluate(rows, y, g, v, "C3", extra_cols=synth) for v in ("A3",)}

    print("[C2-clean40] clean-40-native marker placebo")
    c2_native = clean40_marker_placebo(feat)

    print("[lander-level ROC for unified table]")
    # recompute A4 (|Δsize|) and A2 (L1 primary named rule) OOF for lander aggregation
    ll = {}
    for v, model in (("A4", "l1_logreg"), ("A3", "l1_logreg"), ("A2", "l1_logreg")):
        oof = SV.loso_oof(rows, y, g, v, SV.make_models()[model])
        ll[f"{v}_{model}"] = lander_level(rows, oof, pos_landers, clean_runs)
        print(f"    {v}/{model} lander AUC={ll[f'{v}_{model}']['lander_auc']} "
              f"op@fpr<=.125 {ll[f'{v}_{model}']['op_point_fpr_le_0125']}")

    # power/MDES at the NEW N
    z_a = stats.norm.ppf(1 - 0.05 / 2); z_b = stats.norm.ppf(0.80)
    se0 = math.sqrt((n_pos + n_neg + 1) / (12.0 * n_pos * n_neg))
    a = 0.5
    for _ in range(500):
        q1 = max(a, 0.5001) / (2 - max(a, 0.5001)); q2 = 2 * max(a, 0.5001) ** 2 / (1 + max(a, 0.5001))
        var = (max(a, 0.5001) * (1 - max(a, 0.5001)) + (n_pos - 1) * (q1 - max(a, 0.5001) ** 2) +
               (n_neg - 1) * (q2 - max(a, 0.5001) ** 2)) / (n_pos * n_neg)
        new = 0.5 + z_a * se0 + z_b * math.sqrt(var)
        if abs(new - a) < 1e-9: break
        a = new

    out = {
        "schema_version": "assa.p2_supervised_arm.cv_clean40.v1",
        "derivation_generation": "p2_supervised_arm_clean40_20260825",
        "analysis_kind": "defensive; offline; read-only; no network/VM/payload execution",
        "negatives_basis": "NATURAL held-out clean-40 (split 42baa6a9); NOT paired twins",
        "seed": SEED,
        "workload_unmatched_caveat": feat["workload_unmatched_caveat"],
        "positives_basis": feat["positives_basis"],
        "counts": feat["counts"],
        "cv": {"scheme": "leave-one-group-out (attack scenario | clean-40 run); pooled OOF; "
                         "imputation + one-hot levels fit on train fold only",
               "n_groups": len(set(g))},
        "reference_operating_points": {"B1": SV.B1_REF, "B2": SV.B2_REF},
        "power_mdes": {"n_pos": n_pos, "n_neg": n_neg, "auc_mdes": round(a, 4),
                       "majority_floor": round(n_neg / (n_pos + n_neg), 4)},
        "main": main_res,
        "control_C1a_permuted_global": {"intent": "plumbing check; expect ~0.5", "results": c1a},
        "control_C1b_permuted_within_group": {"intent": "within-group base-rate structure", "results": c1b},
        "control_C2_marker_placebo_twin_based": {
            "note": "carried VERBATIM from the frozen twin-based arm (supervised_cv.json). Clean-only "
                    "diagnostic of target-selection structure; independent of the negatives choice. "
                    "This is THE inflation reference to read beside the clean-40 main AUC.",
            "placebo_positives_of_clean_rows": "24 of 54 (twin clean rows)",
            "auc_A2": {"l1_logreg": 0.6292, "cart_d3": 0.7792, "figs": 0.7875},
            "auc_A3": {"l1_logreg": 0.6083, "cart_d3": 0.7389, "figs": 0.8125},
            "auc_A4_abs_delta_size": {"l1_logreg": 0.3542},
            "reading": "tree arms hit 0.78-0.81 AUC on pure target-selection structure (CIs exclude 0.5); "
                       "only the named |Δsize|/L1 rule survives (A4 0.354, A2/A3 L1 0.61-0.63, CIs include 0.5).",
        },
        "control_C2_marker_placebo_clean40_native": c2_native,
        "control_C3_positive": {"intent": "known-separable feature just above MDES", "results": c3},
        "lander_level_for_unified_table": ll,
        "reading": "On workload-UNMATCHED clean-40 negatives the |Δsize|/L1 rule's AUC rises vs the "
                   "confound-safe twin baseline; the C2 placebo shows how much of any tree separation "
                   "is target-selection, not attack signal.",
    }
    json.dump(out, open(OUT, "w"), indent=2)
    print(f"WROTE {OUT}")
    print("MAIN AUC:", {v: {m: main_res[v][m].get("auc") for m in main_res[v]} for v in main_res})
    print("MDES:", round(a, 4), "floor", round(n_neg / (n_pos + n_neg), 4))


if __name__ == "__main__":
    main()
