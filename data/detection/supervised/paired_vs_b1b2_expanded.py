#!/usr/bin/env python3
"""
Expanded paired comparison: our |Δsize| LOSO rule vs B1/B2 z-score on the SAME operations.

B1/B2 are re-fit on the EXPANDED clean pool (locked-pop 43 + new twin write ops) using the
verbatim frozen formulas (score = max(|Δsize-μ|/σ_floor, |logΔt_last-μ_t|/σ_t), tau=2.0,
sigma_floor = max(σ_size, |μ_size|*0.1, 1.0); unseen (file,op) => +inf). Clean rows use
leave-one-run-out. Size deltas are exact; the timing term scores log_dt_last (the last
inter-write interval), exactly the quantity frozen score_record uses.

VALIDATION: the scorer must reproduce the frozen locked-pop operating point
(B1 TPR 0.3529 / FPR 0.1395) on the locked-pop subset, else the expanded paired test is
reported with that caveat.

Defensive analysis. Offline, read-only. No network/VM/payload execution.
"""
import json, os, sys, math, statistics
import numpy as np
from scipy import stats as sps
HERE = os.path.dirname(os.path.abspath(__file__))
FEAT = f"{HERE}/features_substrate_a.json"
OUT = f"{HERE}/paired_vs_b1b2_expanded.json"
TAU = 2.0; UNSEEN = 1e6; B1_FPR_TARGET = 0.1395


def op_of(row):
    return f"{row['layer'].lower()}_write"

def fit(rows_subset):
    size = {}; tim = {}
    for r in rows_subset:
        k = (r["bucket"], op_of(r))
        if r["delta_size"] is not None:
            size.setdefault(k, []).append(float(r["delta_size"]))
        if r.get("has_timing") and r.get("log_dt_last") is not None:
            tim.setdefault(k, []).append(float(r["log_dt_last"]))
    st = {}
    for k in set(list(size) + list(tim)):
        d = size.get(k, []); ld = tim.get(k, [])
        st[k] = {
            "n": len(d),
            "smean": statistics.mean(d) if d else 0.0,
            "sstd": statistics.stdev(d) if len(d) > 1 else 0.0,
            "tn": len(ld),
            "tmean": statistics.mean(ld) if ld else 0.0,
            "tstd": statistics.stdev(ld) if len(ld) > 1 else 0.0,
        }
    return st

def score(row, st):
    k = (row["bucket"], op_of(row))
    s = st.get(k)
    if s is None:
        return UNSEEN
    vals = []
    if row["delta_size"] is not None and s["n"] > 0:
        sf = max(s["sstd"], abs(s["smean"]) * 0.1, 1.0)
        vals.append(abs(float(row["delta_size"]) - s["smean"]) / sf)
    if row.get("has_timing") and row.get("log_dt_last") is not None and s["tn"] >= 2:
        if s["tstd"] > 0:
            vals.append(abs(float(row["log_dt_last"]) - s["tmean"]) / s["tstd"])
        elif float(row["log_dt_last"]) != s["tmean"]:
            vals.append(5.0)
        else:
            vals.append(0.0)
    return max(vals) if vals else None

def b_flags(rows, per_profile):
    """Return list of bool flags aligned to rows. Clean rows: leave-one-run-out."""
    clean = [r for r in rows if r["label"] == 0]
    if per_profile:
        pools = {}
        for p in sorted({r["profile"] for r in rows}):
            pools[p] = [r for r in clean if r["profile"] == p]
    flags = []
    full = fit(clean)
    full_by_p = {p: fit(pool) for p, pool in pools.items()} if per_profile else None
    for r in rows:
        if r["label"] == 0:  # LORO: drop this row's own lander from the pool
            pool = [c for c in (pools[r["profile"]] if per_profile else clean)
                    if c["lander"] != r["lander"]]
            st = fit(pool)
        else:
            st = (full_by_p.get(r["profile"], full) if per_profile else full)
        sc = score(r, st)
        flags.append(bool(sc is not None and sc >= TAU))
    return flags

def loso_rule(rows, target_fpr):
    y = np.array([r["label"] for r in rows]); g = np.array([r["scenario"] for r in rows])
    v = np.array([r["abs_delta_size"] if r["abs_delta_size"] is not None else 0.0 for r in rows])
    pred = np.zeros(len(y), dtype=int)
    for grp in sorted(set(g)):
        te = np.where(g == grp)[0]; tr = np.where(g != grp)[0]
        best = None
        for t in sorted(set(v[tr]), reverse=True):
            if (v[tr] >= t)[y[tr] == 0].mean() <= target_fpr:
                best = t
            else:
                break
        if best is not None:
            pred[te] = (v[te] >= best).astype(int)
    return pred

def mcnemar(b, c):
    n = b + c
    p = float(sps.binomtest(b, n, 0.5).pvalue) if n else 1.0
    return {"b_ours_only": b, "c_theirs_only": c, "n_discordant": n, "p_value": round(p, 4)}

def rate(flags, rows, label):
    idx = [i for i, r in enumerate(rows) if r["label"] == label]
    return round(sum(flags[i] for i in idx) / len(idx), 4) if idx else None


def main():
    rows = json.load(open(FEAT))["rows"]
    pred = loso_rule(rows, B1_FPR_TARGET)
    out = {"schema_version": "assa.p2_supervised_arm.paired.v1",
           "derivation_generation": "p2_supervised_arm_expanded_20260825",
           "analysis_kind": "defensive; offline; read-only",
           "method": "B1/B2 re-fit on expanded clean pool (verbatim frozen formulas, tau=2.0); "
                     "our rule = |Δsize|>=t per-fold at FPR<=0.1395 (LOSO)",
           "test": "McNemar exact two-sided on discordant pairs"}

    for tag, per_p in (("B1", False), ("B2", True)):
        flags = b_flags(rows, per_p)
        # validation on locked-pop subset (scenarios starting with 'C')
        lp = [i for i, r in enumerate(rows) if r["scenario"].startswith("C") and r["scenario"][1:].isdigit()]
        lp_att = [i for i in lp if rows[i]["label"] == 1]; lp_cln = [i for i in lp if rows[i]["label"] == 0]
        val = {"lockedpop_TPR": round(sum(flags[i] for i in lp_att)/len(lp_att), 4),
               "lockedpop_FPR": round(sum(flags[i] for i in lp_cln)/len(lp_cln), 4),
               "frozen_reference": {"B1": {"TPR": 0.3529, "FPR": 0.1395},
                                    "B2": {"TPR": 0.3529, "FPR": 0.2093}}[tag]}
        # expanded operating point
        op = {"expanded_TPR": rate(flags, rows, 1), "expanded_FPR": rate(flags, rows, 0),
              "ours_expanded_TPR": round(sum(pred[i] for i, r in enumerate(rows) if r["label"] == 1)/
                                         sum(r["label"] == 1 for r in rows), 4),
              "ours_expanded_FPR": round(sum(pred[i] for i, r in enumerate(rows) if r["label"] == 0)/
                                         sum(r["label"] == 0 for r in rows), 4)}
        # paired McNemar (expanded, all rows)
        ba = ca = bn = cn = 0
        for i, r in enumerate(rows):
            ours, theirs = bool(pred[i]), flags[i]
            if r["label"] == 1:
                ba += int(ours and not theirs); ca += int(theirs and not ours)
            else:
                bn += int(ours and not theirs); cn += int(theirs and not ours)
        out[f"vs_{tag}"] = {"validation": val, "operating_points": op,
                            "attack_side": mcnemar(ba, ca), "clean_side": mcnemar(bn, cn)}
        print(f"[{tag}] lockedpop TPR/FPR={val['lockedpop_TPR']}/{val['lockedpop_FPR']} "
              f"(frozen {val['frozen_reference']}) | expanded theirs TPR/FPR={op['expanded_TPR']}/{op['expanded_FPR']} "
              f"ours={op['ours_expanded_TPR']}/{op['ours_expanded_FPR']}")
        print(f"     attack McNemar {out[f'vs_{tag}']['attack_side']}  clean {out[f'vs_{tag}']['clean_side']}")

    json.dump(out, open(OUT, "w"), indent=2)
    print(f"WROTE {OUT}")


if __name__ == "__main__":
    main()
