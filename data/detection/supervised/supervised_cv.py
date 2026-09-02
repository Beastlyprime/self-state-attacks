#!/usr/bin/env python3
"""
Supervised arm on substrate A: leave-one-scenario-out CV with the controls
required by the design (§5, §9 step 4).

Models are all T2 (analytically transparent): L1 logistic regression, FIGS,
depth-limited CART. A majority-class predictor is the floor.

Controls
  C1 permuted labels    : labels shuffled within scenario groups. Validates the CV
                          plumbing; expected pooled AUC ~ 0.5.
  C2 marker-file placebo: CLEAN ROWS ONLY, pseudo-labelling the operation on the file
                          the attack would have targeted. No attack is present, so any
                          separation here is target-selection structure, not attack signal.
  C3 positive control   : a synthetic feature with a calibrated effect size injected
                          into the real design matrix. Guards against reporting a null
                          that is really a broken harness or insufficient n.
Identity ablation is the A1/A2/A3 variant comparison.

Defensive analysis. Offline, read-only. No network/VM/payload execution.
"""
import json, os, sys, warnings
import numpy as np

warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import matrix as M

from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier, export_text
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, roc_curve
from imodels import FIGSClassifier

FEAT = f"{HERE}/features_substrate_a.json"
OUT = f"{HERE}/supervised_cv.json"
SEED = 20260823
# frozen B1/B2 operating points from p2_b1b2_size_timing_libsinsp_20260822/REPORT.json
B1_REF = {"tpr": 0.3529, "fpr": 0.1395}
B2_REF = {"tpr": 0.3529, "fpr": 0.2093}


def make_models():
    return {
        "l1_logreg": lambda: LogisticRegression(penalty="l1", solver="liblinear",
                                                C=0.5, max_iter=5000,
                                                random_state=SEED),
        "cart_d3": lambda: DecisionTreeClassifier(max_depth=3, min_samples_leaf=3,
                                                  random_state=SEED),
        "figs": lambda: FIGSClassifier(max_rules=4, random_state=SEED),
    }


def loso_oof(rows, y, g, variant, model_fn, extra_cols=None):
    """Pooled out-of-fold probabilities under leave-one-scenario-out CV.
    Imputation and one-hot levels are fit on the TRAIN fold only."""
    oof = np.full(len(rows), np.nan)
    for grp in sorted(set(g)):
        te = np.where(g == grp)[0]
        tr = np.where(g != grp)[0]
        if len(set(y[tr])) < 2:
            continue
        tr_rows = [rows[i] for i in tr]
        Xtr, names = M.build(tr_rows, variant, impute_from=tr_rows)
        Xte, _ = M.build([rows[i] for i in te], variant, impute_from=tr_rows)
        if extra_cols is not None:
            Xtr = np.hstack([Xtr, extra_cols[tr]])
            Xte = np.hstack([Xte, extra_cols[te]])
        sc = StandardScaler().fit(Xtr)
        m = model_fn()
        np.random.seed(SEED)  # FIGS ignores random_state and draws from the global RNG
        m.fit(sc.transform(Xtr), y[tr])
        p = m.predict_proba(sc.transform(Xte))
        oof[te] = p[:, 1] if p.ndim > 1 and p.shape[1] > 1 else np.ravel(p)
    return oof


def tpr_at_fpr(y, s, target_fpr):
    fpr, tpr, thr = roc_curve(y, s)
    ok = fpr <= target_fpr + 1e-12
    return (round(float(tpr[ok].max()), 4) if ok.any() else 0.0)


def boot_auc_ci(y, s, g, n=2000, seed=SEED):
    """Bootstrap over scenarios — the independent unit — not over rows."""
    rng = np.random.default_rng(seed)
    groups = sorted(set(g))
    idx_by_g = {k: np.where(g == k)[0] for k in groups}
    vals = []
    for _ in range(n):
        pick = rng.choice(groups, size=len(groups), replace=True)
        idx = np.concatenate([idx_by_g[k] for k in pick])
        yy, ss = y[idx], s[idx]
        if len(set(yy)) == 2 and not np.isnan(ss).any():
            vals.append(roc_auc_score(yy, ss))
    if not vals:
        return (None, None)
    return (round(float(np.percentile(vals, 2.5)), 4),
            round(float(np.percentile(vals, 97.5)), 4))


def evaluate(rows, y, g, variant, tag, extra_cols=None):
    res = {}
    for name, fn in make_models().items():
        oof = loso_oof(rows, y, g, variant, fn, extra_cols)
        valid = ~np.isnan(oof)
        if len(set(y[valid])) < 2:
            res[name] = {"status": "not_evaluable_single_class_oof"}
            continue
        yv, sv, gv = y[valid], oof[valid], g[valid]
        auc = float(roc_auc_score(yv, sv))
        lo, hi = boot_auc_ci(yv, sv, gv)
        res[name] = {
            "auc": round(auc, 4),
            "auc_ci95_bootstrap_over_scenarios": [lo, hi],
            "tpr_at_fpr_matched_B1": tpr_at_fpr(yv, sv, B1_REF["fpr"]),
            "tpr_at_fpr_matched_B2": tpr_at_fpr(yv, sv, B2_REF["fpr"]),
            "n_scored": int(valid.sum()),
        }
        print(f"    {tag:22s} {variant} {name:10s} AUC={auc:.4f} "
              f"CI=[{lo},{hi}] TPR@B1fpr={res[name]['tpr_at_fpr_matched_B1']}")
    return res


def readable_models(rows, y, variant):
    """Refit on the full population purely to expose what the model says.
    Descriptive only — not a performance estimate."""
    X, names = M.build(rows, variant)
    sc = StandardScaler().fit(X)
    Xs = sc.transform(X)
    out = {}
    np.random.seed(SEED)
    lr = LogisticRegression(penalty="l1", solver="liblinear", C=0.5,
                            max_iter=5000, random_state=SEED).fit(Xs, y)
    coef = {n: round(float(c), 4) for n, c in zip(names, lr.coef_[0]) if abs(c) > 1e-8}
    out["l1_logreg_nonzero_coefficients_standardised"] = dict(
        sorted(coef.items(), key=lambda kv: -abs(kv[1])))
    np.random.seed(SEED)
    ct = DecisionTreeClassifier(max_depth=3, min_samples_leaf=3, random_state=SEED).fit(X, y)
    out["cart_d3_tree"] = export_text(ct, feature_names=list(names)).strip().split("\n")
    np.random.seed(SEED)
    fg = FIGSClassifier(max_rules=4, random_state=SEED).fit(X, y, feature_names=list(names))
    out["figs_model"] = str(fg).strip().split("\n")
    return out


def main():
    d = json.load(open(FEAT))
    rows = d["rows"]
    y = M.labels(rows)
    g = M.groups(rows)
    rng = np.random.default_rng(SEED)

    out = {
        "schema_version": "assa.p2_supervised_arm.cv.v1",
        "derivation_generation": "p2_supervised_arm_20260823",
        "analysis_kind": "defensive; offline; read-only; no network/VM/payload execution",
        "cv": {"scheme": "leave-one-scenario-out", "n_folds": len(set(g)),
               "imputation": "fold-train median; one-hot levels fit on train fold only",
               "ci": "bootstrap over scenarios (independent unit), 2000 resamples"},
        "models": {"l1_logreg": "L1 logistic regression (sklearn 1.8.0), C=0.5",
                   "cart_d3": "CART depth<=3, min_samples_leaf=3 (sklearn 1.8.0)",
                   "figs": "FIGS max_rules=4 (imodels 3.0.0; Singh et al. JOSS 2021)"},
        "variants": {"A1": "core+context+identity", "A2": "core+context (identity ablated)",
                     "A3": "core only", "A4": "abs_delta_size alone - reducible to one threshold rule"},
        "reference_operating_points": {"B1": B1_REF, "B2": B2_REF,
                                       "source": "p2_b1b2_size_timing_libsinsp_20260822/REPORT.json"},
        "mdes_reference": "power_mdes.json — AUC MDES 0.7285 at alpha=.05/power=.80",
    }

    print("[main] real labels")
    out["main"] = {v: evaluate(rows, y, g, v, "real") for v in ("A1", "A2", "A3", "A4")}

    print("[C1a] globally permuted labels")
    yglob = rng.permutation(y)
    out["control_C1a_permuted_global"] = {
        "intent": "destroys all label structure including per-scenario base rates; "
                  "the primary plumbing check. Expected AUC ~0.5.",
        "results": {v: evaluate(rows, yglob, g, v, "C1a-perm-global") for v in ("A2", "A3", "A4")},
    }

    print("[C1b] labels permuted within scenario")
    yperm = y.copy()
    for grp in sorted(set(g)):
        idx = np.where(g == grp)[0]
        yperm[idx] = rng.permutation(y[idx])
    out["control_C1b_permuted_within_scenario"] = {
        "intent": "permuting inside a scenario PRESERVES that scenario's positive rate, so a "
                  "model that can recognise the scenario from its features can still beat 0.5. "
                  "Reported for exactly that reason: elevation here measures per-scenario "
                  "base-rate structure, not a CV leak.",
        "results": {v: evaluate(rows, yperm, g, v, "C1b-perm-within") for v in ("A2", "A3", "A4")},
    }

    print("[C2] marker-file placebo (clean rows only, no attack present)")
    marker_bn = {L["lander"]: os.path.basename(L["marker"]) for L in d["landers"]}
    clean_rows, yc = [], []
    for r in rows:
        if r["label"] != 0:
            continue
        clean_rows.append(r)
        yc.append(1 if os.path.basename(r["bucket"]).replace("*.md", "") and
                  os.path.basename(r["bucket"]) == marker_bn.get(r["lander"]) else 0)
    yc = np.array(yc, dtype=int)
    gc = M.groups(clean_rows)
    print(f"    placebo positives={int(yc.sum())} of {len(yc)} clean rows")
    if len(set(yc)) == 2:
        out["control_C2_marker_placebo"] = {
            "intent": "clean-only; separates the file the attack targeted from other clean "
                      "self-state writes. High AUC here means the real result is driven by "
                      "target selection, not by the attack.",
            "placebo_positives": int(yc.sum()), "n_rows": len(yc),
            "results": {v: evaluate(clean_rows, yc, gc, v, "C2-placebo") for v in ("A2", "A3", "A4")},
        }
    else:
        out["control_C2_marker_placebo"] = {"status": "not_evaluable_single_class"}

    print("[C3] positive control (calibrated synthetic feature)")
    # inject one feature = d*label + N(0,1), d chosen so true AUC ~= 0.75 (just above MDES)
    d_eff = 0.95
    synth = (d_eff * y + rng.normal(0, 1, size=len(y))).reshape(-1, 1)
    out["control_C3_positive"] = {
        "intent": "a known-separable feature at an effect size just above the frozen MDES; "
                  "if the pipeline cannot recover this, a null elsewhere is uninformative",
        "injected_effect_cohens_d": d_eff,
        "implied_true_auc": round(float(0.5 * (1 + np.math.erf(d_eff / 2))), 4)
        if hasattr(np, "math") else round(float(__import__("math").erf(d_eff / 2) / 2 + 0.5), 4),
        "results": {v: evaluate(rows, y, g, v, "C3-positive", extra_cols=synth) for v in ("A3",)},
    }

    print("[readable] refit on full population (descriptive only)")
    out["readable_models"] = {v: readable_models(rows, y, v) for v in ("A2", "A3", "A4")}

    json.dump(out, open(OUT, "w"), indent=2)
    print(f"WROTE {OUT}")


if __name__ == "__main__":
    main()
