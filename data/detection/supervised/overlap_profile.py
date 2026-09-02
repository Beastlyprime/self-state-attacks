#!/usr/bin/env python3
"""
Model-free class-overlap profile of substrate A (design §4, §9 step 2).

Ho-Basu / Lorena data complexity measures via problexity (pinned 0.5.11).
No training, no CV, no threshold. Reports the measures for all three feature
variants so the identity-shortcut contribution is visible as a delta.

Defensive analysis. Offline, read-only. No network/VM/payload execution.
"""
import json, os, sys, warnings
import numpy as np

warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import matrix as M

from problexity import ComplexityCalculator

FEAT = f"{HERE}/features_substrate_a.json"
OUT = f"{HERE}/overlap_profile.json"

# measures whose reading matters most here; the calculator reports all 22
KEY = {
    "f1": "Maximum Fisher's discriminant ratio (higher = more separable on the best single feature)",
    "f1v": "Directional-vector Fisher discriminant ratio",
    "f2": "Volume of overlapping region across features (higher = more overlap)",
    "f3": "Maximum individual feature efficiency",
    "f4": "Collective feature efficiency",
    "n1": "Fraction of borderline points on the class-boundary MST (higher = more interleaved)",
    "n2": "Ratio of intra- to inter-class nearest-neighbour distance (higher = more overlap)",
    "n3": "Leave-one-out 1NN error rate — standard nonparametric Bayes-error proxy",
    "n4": "Non-linearity of the 1NN classifier",
    "t1": "Fraction of hyperspheres covering data",
    "lsc": "Local set average cardinality",
}


def main():
    d = json.load(open(FEAT))
    rows = d["rows"]
    y = M.labels(rows)
    out = {
        "schema_version": "assa.p2_supervised_arm.overlap.v1",
        "derivation_generation": "p2_supervised_arm_20260823",
        "analysis_kind": "defensive; offline; read-only; model-free (no training, no CV, no threshold)",
        "implementation": {"package": "problexity", "version": "0.5.11",
                           "citation": "Ho & Basu, IEEE TPAMI 2002; Lorena et al. 2019; "
                                       "Komorniczak & Ksieniewicz 2022"},
        "population": {"positives": int(y.sum()), "negatives": int((1 - y).sum())},
        "imputation_note": "missing log_dt_last/log_dt_mean (single-write operations, 28/60 rows) "
                           "imputed with the global median alongside the has_timing indicator; "
                           "no train/test split exists here so global imputation introduces no leakage",
        "measure_glossary": KEY,
        "variants": {},
    }
    for variant in ("A1", "A2", "A3"):
        X, names = M.build(rows, variant)
        cc = ComplexityCalculator()
        cc.fit(X, y)
        rep = cc.report()
        vals = {m: (None if v is None or (isinstance(v, float) and np.isnan(v)) else round(float(v), 6))
                for m, v in zip(cc._metrics(), cc.complexity)} if hasattr(cc, "_metrics") else {}
        if not vals:
            vals = {k: (None if v is None else round(float(v), 6))
                    for k, v in rep.get("complexities", {}).items()}
        out["variants"][variant] = {
            "features": names,
            "n_features": len(names),
            "measures": vals,
            "score": round(float(cc.score()), 6),
        }
        print(f"[{variant}] {len(names)} features  score={cc.score():.4f}")
        for k in ("f1", "f2", "f3", "n1", "n2", "n3", "t1"):
            if k in vals:
                print(f"    {k:4s} = {vals[k]}")
    json.dump(out, open(OUT, "w"), indent=2)
    print(f"WROTE {OUT}")


if __name__ == "__main__":
    main()
