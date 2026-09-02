#!/usr/bin/env python3
"""
Paired comparison of the |Δsize| rule against B1/B2 on the SAME operations.

AUC and rate differences with n=17 have wide CIs; the informative test is paired,
because every operation is scored by both detectors. McNemar's exact test on the
discordant pairs is therefore the primary statistic.

Defensive analysis. Offline, read-only. No network/VM/payload execution.
"""
import json, os, sys
import numpy as np
from scipy import stats

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import matrix as M
from pathlib import Path as _Path
_REPO_ROOT = str(_Path(__file__).resolve().parents[3])

RES = _REPO_ROOT + "/data"
FROZEN = f"{RES}/p2_b1b2_size_timing_libsinsp_20260822/REPORT.json"
FEAT = f"{HERE}/features_substrate_a.json"
OUT = f"{HERE}/paired_vs_b1b2.json"
B1_FPR_TARGET = 0.1395


def mcnemar_exact(b, c):
    """b = ours-only hits, c = theirs-only hits. Two-sided exact binomial."""
    n = b + c
    if n == 0:
        return {"b": b, "c": c, "p_value": 1.0, "note": "no discordant pairs"}
    p = float(stats.binomtest(b, n, 0.5, alternative="two-sided").pvalue)
    return {"b_ours_only": b, "c_theirs_only": c, "n_discordant": n, "p_value": round(p, 4)}


def loso_rule_predictions(rows, y, g, v, target_fpr):
    pred = np.zeros(len(y), dtype=int)
    for grp in sorted(set(g)):
        te = np.where(g == grp)[0]
        tr = np.where(g != grp)[0]
        best = None
        for t in sorted(set(v[tr]), reverse=True):
            if (v[tr] >= t)[y[tr] == 0].mean() <= target_fpr:
                best = t
            else:
                break
        if best is not None:
            pred[te] = (v[te] >= best).astype(int)
    return pred


def main():
    fz = json.load(open(FROZEN))
    d = json.load(open(FEAT))
    rows = d["rows"]
    y = M.labels(rows)
    g = M.groups(rows)
    v = np.array([r["abs_delta_size"] for r in rows], dtype=float)
    pred = loso_rule_predictions(rows, y, g, v, B1_FPR_TARGET)

    # --- align to the frozen per-row decisions ---
    b1_att = {e["lander"]: bool(e.get("combined_flag")) for e in fz["detail"]["attack_B1"]}
    b2_att = {e["lander"]: bool(e.get("combined_flag")) for e in fz["detail"]["attack_B2"]}
    b1_cln = {(e["lander"], e["file"]): bool(e.get("combined_flag")) for e in fz["detail"]["clean_fpr_B1"]}
    b2_cln = {(e["lander"], e["file"]): bool(e.get("combined_flag")) for e in fz["detail"]["clean_fpr_B2"]}

    out = {
        "schema_version": "assa.p2_supervised_arm.paired.v1",
        "derivation_generation": "p2_supervised_arm_20260823",
        "analysis_kind": "defensive; offline; read-only; no network/VM/payload execution",
        "ours": "|Δsize| >= t, t selected per fold on training scenarios at an FPR target "
                f"of {B1_FPR_TARGET} (leave-one-scenario-out)",
        "theirs": "B1/B2 per-(file,op) z-score at the frozen tau=2.0",
        "test": "McNemar exact (two-sided) on discordant pairs; same operations scored by both",
        "unmatched": {},
    }

    for tag, att, cln in (("B1", b1_att, b1_cln), ("B2", b2_att, b2_cln)):
        # positives: attack detections
        b = c = 0
        unmatched = 0
        for i, r in enumerate(rows):
            if r["label"] != 1:
                continue
            if r["lander"] not in att:
                unmatched += 1
                continue
            ours, theirs = bool(pred[i]), att[r["lander"]]
            b += int(ours and not theirs)
            c += int(theirs and not ours)
        pos = mcnemar_exact(b, c)
        # negatives: false alarms (fewer is better, so orient as "ours-only false alarm")
        bn = cn = 0
        for i, r in enumerate(rows):
            if r["label"] != 0:
                continue
            k = (r["lander"], r["canon"])
            if k not in cln:
                unmatched += 1
                continue
            ours, theirs = bool(pred[i]), cln[k]
            bn += int(ours and not theirs)
            cn += int(theirs and not ours)
        neg = mcnemar_exact(bn, cn)
        out[f"vs_{tag}"] = {
            "attack_side": {**pos,
                            "interpretation": "b = attacks only our rule catches, "
                                              "c = attacks only the z-score catches"},
            "clean_side": {**neg,
                           "interpretation": "b = clean writes only our rule falsely flags, "
                                             "c = clean writes only the z-score falsely flags"},
        }
        out["unmatched"][tag] = unmatched

    json.dump(out, open(OUT, "w"), indent=2)
    print(json.dumps({k: out[k] for k in out if k.startswith("vs_") or k == "unmatched"}, indent=2))
    print(f"WROTE {OUT}")


if __name__ == "__main__":
    main()
