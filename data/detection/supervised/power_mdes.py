#!/usr/bin/env python3
"""
Power / minimum-detectable-effect for the supervised arm, computed and frozen
BEFORE any model is fitted (design §5.5, §9 step 3).

The point of running this first is that a null result must be reportable as
"no effect larger than X was detectable", with X fixed in advance rather than
chosen after seeing the outcome.

Defensive analysis. Offline, read-only. No network/VM/payload execution.
"""
import json, os, math
from scipy import stats

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = f"{HERE}/power_mdes.json"

N_POS, N_NEG = 27, 54
ALPHA, POWER = 0.05, 0.80


def hanley_mcneil_var(a, n1, n2):
    q1 = a / (2 - a)
    q2 = 2 * a * a / (1 + a)
    return (a * (1 - a) + (n1 - 1) * (q1 - a * a) + (n2 - 1) * (q2 - a * a)) / (n1 * n2)


def mdes_auc(n1, n2, alpha=ALPHA, power=POWER):
    """Smallest true AUC separable from 0.5 at the given alpha/power."""
    z_a = stats.norm.ppf(1 - alpha / 2)
    z_b = stats.norm.ppf(power)
    se0 = math.sqrt((n1 + n2 + 1) / (12.0 * n1 * n2))  # Mann-Whitney null SE
    a = 0.5
    for _ in range(500):
        se1 = math.sqrt(hanley_mcneil_var(max(a, 0.5001), n1, n2))
        new = 0.5 + z_a * se0 + z_b * se1
        if abs(new - a) < 1e-9:
            break
        a = new
    return a, se0


def wilson(k, n, alpha=ALPHA):
    if n == 0:
        return (None, None)
    z = stats.norm.ppf(1 - alpha / 2)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(max(0.0, c - h), 4), round(min(1.0, c + h), 4))


def fisher_mdes(n1, n2, alpha=ALPHA, power=POWER, fpr=0.10):
    """Smallest TPR that a Fisher exact test separates from the given FPR."""
    best = None
    for k in range(0, n1 + 1):
        tpr = k / n1
        fp = round(fpr * n2)
        table = [[k, n1 - k], [fp, n2 - fp]]
        p = stats.fisher_exact(table, alternative="greater")[1]
        if p < alpha:
            best = tpr
            break
    return best


def main():
    auc, se0 = mdes_auc(N_POS, N_NEG)
    out = {
        "schema_version": "assa.p2_supervised_arm.power.v1",
        "derivation_generation": "p2_supervised_arm_20260823",
        "frozen_before_modelling": True,
        "analysis_kind": "defensive; offline; read-only; analytic power calculation only",
        "population": {"positives": N_POS, "negatives": N_NEG,
                       "majority_class_accuracy_floor": round(N_NEG / (N_POS + N_NEG), 4)},
        "assumptions": {"alpha": ALPHA, "power": POWER, "two_sided": True},
        "auc": {
            "null_se_mann_whitney": round(se0, 4),
            "mdes": round(auc, 4),
            "variance_model": "Hanley & McNeil 1982",
            "reading": f"Only a true AUC of at least {auc:.3f} is detectable at "
                       f"alpha={ALPHA}, power={POWER}. An observed AUC below this is "
                       f"'no large effect', NOT 'no effect'.",
        },
        "tpr_precision": {
            "wilson_ci_at_0_of_17": wilson(0, N_POS),
            "wilson_ci_at_9_of_17": wilson(9, N_POS),
            "wilson_ci_at_17_of_17": wilson(17, N_POS),
            "reading": "With 17 positives the TPR estimate is coarse: even a perfect "
                       "17/17 has a 95% lower bound of "
                       f"{wilson(17, N_POS)[0]}, and 0/17 has an upper bound of "
                       f"{wilson(0, N_POS)[1]}.",
        },
        "fisher_mdes_tpr_vs_fpr": {
            f"vs_fpr_{int(f*100):02d}": fisher_mdes(N_POS, N_NEG, fpr=f)
            for f in (0.05, 0.10, 0.20)
        },
        "cv_caveat": "13 leave-one-scenario-out folds hold out ~1.3 positives each, so "
                     "per-fold metrics are uninterpretable. Only pooled out-of-fold "
                     "predictions are scored, and CIs are bootstrapped over scenarios "
                     "(the independent unit), not over rows.",
        "per_class_caveat": "Instruction/Configuration/Memory cells are 5/6/6 positives, "
                            "all below the census power floor of 8. Per-class numbers are "
                            "reported as descriptive only; the pooled 17 is the inferential unit.",
    }
    json.dump(out, open(OUT, "w"), indent=2)
    print(json.dumps({k: out[k] for k in ("population", "auc", "tpr_precision",
                                          "fisher_mdes_tpr_vs_fpr")}, indent=2))
    print(f"WROTE {OUT}")


if __name__ == "__main__":
    main()
