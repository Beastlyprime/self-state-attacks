#!/usr/bin/env python3
"""
Reproducibility check on the fitted models.

A T2 detector's parameters must be recomputable by a third party. This measures
whether each model returns the same fit across repeated runs with the same seed and
the same data. Discovered during implementation: imodels' FIGSClassifier does NOT,
despite accepting random_state.

Defensive analysis. Offline, read-only. No network/VM/payload execution.
"""
import json, os, sys, warnings
import numpy as np

warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import matrix as M

from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import roc_auc_score
from imodels import FIGSClassifier, RuleFitClassifier

SEED = 20260823
REPEATS = 24
OUT = f"{HERE}/determinism_check.json"


def main():
    d = json.load(open(f"{HERE}/features_substrate_a.json"))
    rows = d["rows"]
    y = M.labels(rows)
    X, _ = M.build(rows, "A3")

    models = {
        "l1_logreg": lambda: LogisticRegression(penalty="l1", solver="liblinear",
                                                C=0.5, max_iter=5000),
        "cart_d3": lambda: DecisionTreeClassifier(max_depth=3, min_samples_leaf=3,
                                                  random_state=SEED),
        "figs": lambda: FIGSClassifier(max_rules=4, random_state=SEED),
        "rulefit": lambda: RuleFitClassifier(max_rules=8, random_state=SEED),
    }
    out = {
        "schema_version": "assa.p2_supervised_arm.determinism.v1",
        "derivation_generation": "p2_supervised_arm_20260823",
        "analysis_kind": "defensive; offline; read-only; no network/VM/payload execution",
        "protocol": f"same data, same seed, {REPEATS} repeated fits in one process; "
                    "in-sample AUC compared",
        "why": "a model whose parameters cannot be recomputed from the pinned inputs "
               "does not meet the T2 (analytically transparent) admissibility bar, "
               "whatever its accuracy",
        "models": {},
    }
    for name, fn in models.items():
        aucs = []
        for rep in range(REPEATS):
            # deliberately advance the global RNG between fits: a model that respects its
            # own random_state is unaffected, one that reads the global RNG is not. Without
            # this the check gives a FALSE PASS whenever the repeats happen to land inside
            # a single block of the global stream (that happened on the first attempt).
            np.random.rand(rep + 1)
            try:
                m = fn().fit(X, y)
                p = m.predict_proba(X)
                p = p[:, 1] if getattr(p, "ndim", 1) > 1 and p.shape[1] > 1 else np.ravel(p)
                aucs.append(round(float(roc_auc_score(y, p)), 6))
            except Exception as exc:
                aucs.append(f"{type(exc).__name__}: {exc}")
        distinct = sorted(set(a for a in aucs if isinstance(a, float)))
        out["models"][name] = {
            "in_sample_auc_per_fit": aucs,
            "distinct_values": distinct,
            "deterministic": len(distinct) <= 1,
            "spread": (round(max(distinct) - min(distinct), 6) if len(distinct) > 1 else 0.0),
        }
        print(f"{name:12s} deterministic={out['models'][name]['deterministic']} "
              f"distinct={distinct}")
    fixed = {}
    for name, fn in models.items():
        aucs = []
        for rep in range(REPEATS):
            np.random.rand(rep + 1)
            np.random.seed(SEED)
            try:
                m = fn().fit(X, y)
                pp = m.predict_proba(X)
                pp = pp[:, 1] if getattr(pp, "ndim", 1) > 1 and pp.shape[1] > 1 else np.ravel(pp)
                aucs.append(round(float(roc_auc_score(y, pp)), 6))
            except Exception as exc:
                aucs.append(f"{type(exc).__name__}: {exc}")
        dv = sorted(set(a for a in aucs if isinstance(a, float)))
        fixed[name] = {"distinct_values": dv, "deterministic": len(dv) <= 1}
        print(f"{name:12s} WITH global-seed pin: deterministic={len(dv) <= 1} {dv}")
    out["with_global_seed_pinned_before_each_fit"] = fixed
    out["diagnosis"] = ("imodels FIGSClassifier accepts random_state but does not use it; "
                        "it draws from the global NumPy RNG. Seeding np.random immediately "
                        "before each fit restores reproducibility, and that is what the "
                        "harness does.")

    nd = [k for k, v in out["models"].items() if not v["deterministic"]]
    out["nondeterministic_models"] = nd
    still_bad = [k for k, v in fixed.items() if not v["deterministic"]]
    out["consequence"] = (
        ("Unpinned, these are nondeterministic: " + ", ".join(nd) + ". "
         if nd else "Unpinned, all models reproduce. ")
        + ("With the global seed pinned before each fit all models reproduce exactly, "
           "and the harness does exactly that."
           if not still_bad else
           "Still nondeterministic even with the pin: " + ", ".join(still_bad) +
           " - results from these are flagged and are not treated as reproducible evidence.")
    )
    json.dump(out, open(OUT, "w"), indent=2)
    print(f"WROTE {OUT}")


if __name__ == "__main__":
    main()
