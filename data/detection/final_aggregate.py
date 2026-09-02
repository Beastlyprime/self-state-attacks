#!/usr/bin/env python3
"""Assemble the audited final three-pool detector report and tables."""
import hashlib
import json
import math
import random
from collections import defaultdict
from pathlib import Path

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]
Z = 1.959963984540054
SEED = 20260825
BOOTSTRAPS = 10000


def load(name):
    return json.loads((OUT / name).read_text())


def wilson(k, n):
    if n == 0:
        return {"k": k, "n": n, "rate": None, "lo": None, "hi": None}
    p = k / n
    den = 1 + Z * Z / n
    center = (p + Z * Z / (2 * n)) / den
    half = Z * math.sqrt((p * (1 - p) + Z * Z / (4 * n)) / n) / den
    return {
        "k": int(k), "n": int(n), "rate": round(p, 4),
        "lo": round(max(0, center - half), 4),
        "hi": round(min(1, center + half), 4),
    }


def cluster_metric(flags, seed=SEED, B=BOOTSTRAPS):
    """Marginal observation rate with cluster-aware uncertainty.

    `flags` contains (independent_cluster_id, binary_observation). The point
    estimate remains per execution/attack operation. Percentile bootstrap
    resamples independent clusters and retains all observations in each sampled
    cluster. `cluster_any_wilson` is also included to provide a finite upper or
    lower bound when a bootstrap cell is all-zero or all-one.
    """
    grouped = defaultdict(list)
    for cluster, flag in flags:
        grouped[cluster].append(bool(flag))
    clusters = sorted(grouped)
    values = [flag for cluster in clusters for flag in grouped[cluster]]
    k, n = sum(values), len(values)
    rng = random.Random(seed)
    rates = []
    for _ in range(B):
        sample = [rng.choice(clusters) for _ in clusters]
        sampled_values = [flag for cluster in sample for flag in grouped[cluster]]
        rates.append(sum(sampled_values) / len(sampled_values))
    rates.sort()
    any_k = sum(any(grouped[cluster]) for cluster in clusters)
    return {
        "k": k,
        "n": n,
        "rate": round(k / n, 4) if n else None,
        "n_clusters": len(clusters),
        "cluster_bootstrap_ci95": [
            round(rates[int(0.025 * B)], 4),
            round(rates[int(0.975 * B)], 4),
        ] if rates else [None, None],
        "cluster_any_wilson": wilson(any_k, len(clusters)),
    }


MAN = load("FINAL_3POOL_SPLIT_MANIFEST.json")
AIDE = load("scored_aide_3pool.json")
FALCO = load("scored_falco_3pool.json")
STIDE = load("scored_stide_3pool.json")
OURS = load("scored_ours_3pool.json")
SUP = load("FINAL_3POOL_SUPERVISED.json")
UNICORN = load("unicorn/UNICORN_GEN5_FINAL_REPORT.json")

POOL2 = MAN["pools"]["pool2_clean_heldout_test_gen2_60"]["records"]
POOL3 = MAN["pools"]["pool3_attack_test_55"]["records"]
CLEAN_META = {row["run_id"]: row for row in POOL2}
ATTACK_META = {row["run_id"]: row for row in POOL3}


def clean_block(rows):
    evaluable = [
        row for row in rows
        if row["run_id"] in CLEAN_META
        and row.get("status", "passed") == "passed"
        and row.get("binary_decision") is not None
    ]
    def metric(predicate):
        subset = [row for row in evaluable if predicate(CLEAN_META[row["run_id"]])]
        return cluster_metric([
            (CLEAN_META[row["run_id"]]["scenario_id"], row["binary_decision"])
            for row in subset
        ])
    return {
        "overall": metric(lambda _: True),
        "write_conditional": metric(lambda meta: meta["performs_self_state_write"]),
        "no_write": metric(lambda meta: not meta["performs_self_state_write"]),
    }


def attack_metric(rows, include_undefined_as_negative=False):
    selected = []
    for row in rows:
        if row["run_id"] not in ATTACK_META:
            continue
        if row.get("status") == "passed" and row.get("binary_decision") is not None:
            selected.append((row["run_id"], bool(row["binary_decision"])))
        elif include_undefined_as_negative:
            selected.append((row["run_id"], False))
    return cluster_metric([
        (ATTACK_META[run_id]["fold_id"], decision)
        for run_id, decision in selected
    ])


def rows_for_side(payload, side):
    return [row for row in payload["rows"] if row.get("side") == side]


aide_tpr = attack_metric(rows_for_side(AIDE, "attack"))
aide_fpr = clean_block(rows_for_side(AIDE, "clean"))
falco_tpr = attack_metric(rows_for_side(FALCO, "attack"))
falco_fpr = clean_block(rows_for_side(FALCO, "clean"))
stide_tpr = attack_metric(rows_for_side(STIDE, "attack"))
stide_fpr = clean_block(rows_for_side(STIDE, "clean"))
unicorn_tpr = attack_metric(rows_for_side(UNICORN, "attack"))
unicorn_fpr = clean_block(rows_for_side(UNICORN, "clean"))


def ours_block(arm):
    attacks = OURS[arm]["attack"]
    conditional = attack_metric(attacks)
    end_to_end = attack_metric(attacks, include_undefined_as_negative=True)
    return {
        "definable_n": conditional["n"],
        "definable_folds": conditional["n_clusters"],
        "conditional_tpr": conditional,
        "end_to_end_recall_55": end_to_end,
        "fpr_natural": clean_block(OURS[arm]["clean_fpr"]),
    }


ours_b1 = ours_block("B1")
ours_b2 = ours_block("B2")


def supervised_block(payload):
    rows = payload["rows"]
    attacks = [row for row in rows if row["side"] == "attack"]
    clean = [row for row in rows if row["side"] == "clean"]
    conditional = attack_metric(attacks)
    represented = {row["run_id"] for row in attacks}
    augmented = attacks + [
        {
            "run_id": run_id,
            "status": "data_insufficient",
            "binary_decision": None,
        }
        for run_id in ATTACK_META
        if run_id not in represented
    ]
    return {
        "tier": "supervised write size and timing",
        "coverage": payload["coverage"],
        "training": payload["training"],
        "feature_variant": payload["feature_variant"],
        "conditional_tpr": conditional,
        "end_to_end_recall_55": attack_metric(
            augmented, include_undefined_as_negative=True,
        ),
        "fpr_natural": clean_block(clean),
        "auc_status": payload["auc_status"],
    }


supervised_primary = {
    "Supervised_L1_Logistic": supervised_block(SUP["supervised_primary"]["l1_logreg"]),
    "Supervised_CART": supervised_block(SUP["supervised_primary"]["cart_d3"]),
    "Supervised_FIGS": supervised_block(SUP["supervised_primary"]["figs"]),
}
assert (aide_tpr["k"], aide_tpr["n"]) == (52, 55)
assert (falco_tpr["k"], falco_tpr["n"]) == (43, 55)
assert (stide_tpr["k"], stide_tpr["n"]) == (55, 55)
assert (unicorn_tpr["k"], unicorn_tpr["n"]) == (35, 41)
assert (unicorn_fpr["overall"]["k"], unicorn_fpr["overall"]["n"]) == (35, 47)
assert (ours_b1["conditional_tpr"]["k"], ours_b1["conditional_tpr"]["n"]) == (19, 23)
assert (ours_b2["conditional_tpr"]["k"], ours_b2["conditional_tpr"]["n"]) == (20, 23)

leaky = {
    "status": "invalid_as_heldout_estimate",
    "reason": "20 of 40 continuation_train runs overlap the gen2-176 training freeze",
    "prior_values_for_provenance_only": {
        "AIDE": "26/40 (0.650)", "Falco": "27/40 (0.675)",
        "STIDE": "38/40 (0.950)", "ours_B1": "5/40 (0.125)",
        "ours_B2": "5/40 (0.125)",
    },
    "interpretation": "Do not infer a direction of bias by comparing this invalid set with gen2-60.",
}

supervised = {
    "status": "secondary_write_resolved_subset",
    "scope": "canonical 23/55 write-resolved attacks and 23 recovered matched twins; 20 independent scenarios",
    "population": SUP["population"],
    "b1b2_validation": SUP["b1b2_validation"],
    "twin_base": {
        "N": SUP["substrate_a_twin_base"]["N"],
        "nested_cv_auc": SUP["substrate_a_twin_base"]["nested_cv_auc"],
        "auc_ci95": SUP["substrate_a_twin_base"]["auc_ci95"],
        "operating_point": SUP["substrate_a_twin_base"]["supervised_operating_point"],
        "paired_mcnemar_vs_b1b2": SUP["substrate_a_twin_base"]["paired_mcnemar_vs_b1b2"],
        "controls": SUP["substrate_a_twin_base"]["controls"],
    },
    "gen2_60_base": SUP["substrate_a_gen2_60_base"],
    "ngram_twin_base": SUP["substrate_b_twin_base"],
    "interpretation": (
        "On matched twins, the nested-CV AUC interval includes chance. The much higher AUC against "
        "gen2-60 is reported only as a confounded secondary contrast because the workload-placebo "
        "control is also high."
    ),
}

headline = (
    "Across held-out natural workloads, the evaluated OS baselines exhibit a coverage--false-alarm "
    "tradeoff rather than a uniformly dominant detector. AIDE is evaluable on all 55 attacks and "
    "detects 52, but flags every observed clean self-state write; Falco lowers the marginal false-"
    "positive rate while missing "
    "attack classes; STIDE detects all attacks after applying its frozen per-run stream selection but "
    "flags nearly all clean executions. UNICORN exposes a workload-dependent graph signal on 41 "
    "evaluable attacks, but its 35/41 detections coincide with 35/47 natural-clean alarms. The "
    "write-specific B1/B2 baselines have lower marginal false-"
    "positive rates but are defined for only 23 of 55 attacks. Thus OS event streams provide useful "
    "operational evidence, while the evaluated baselines do not yet combine broad attack coverage "
    "with a low false-alarm burden."
)

report = {
    "schema_version": "assa.final_3pool_report.v3",
    "created": "2026-08-25",
    "manifest_content_address": MAN["manifest_content_address"],
    "design": MAN["design"],
    "independent_units": {
        "clean": "20 held-out scenarios, 3 replicates each (60 executions)",
        "attack": "52 folds for 55 confirmed attack landings",
        "write_conditional_clean": "12 scenarios, 32 executions",
        "no_write_clean": "11 scenarios, 28 executions",
        "b1b2_definable_attack": "20 folds, 23 attack operations",
        "unicorn_evaluable": "39 attack folds / 41 operations and 20 clean scenarios / 47 executions",
    },
    "uncertainty_policy": (
        "Point estimates are per execution/attack operation. Confidence intervals resample the "
        "independent scenario or attack fold and retain all correlated observations. For boundary "
        "cells, cluster-any Wilson intervals are also reported because percentile bootstrap intervals "
        "degenerate when every cluster has the same outcome."
    ),
    "detectors": {
        "AIDE": {"tier": "snapshot delta", "coverage": "55/55", "tpr": aide_tpr, "fpr_natural": aide_fpr},
        "Falco": {
            "tier": "rule based", "coverage": "55/55", "tpr": falco_tpr,
            "fpr_natural": falco_fpr,
            "provenance": "55 attack rows materialized from frozen D2 38 + D2-.69 6 + W3 11; fresh clean replay",
            "version": FALCO["version"], "threshold": FALCO["threshold"],
            "falco_config_sha256": FALCO["falco_config_sha256"],
            "scorer_config_sha256": FALCO["scorer_config_sha256"],
            "binary_sha256": FALCO["binary_sha256"],
        },
        "STIDE": {
            "tier": "sequence anomaly", "coverage": "55/55", "tpr": stide_tpr,
            "fpr_natural": stide_fpr,
            "stream_policy": "frozen per-run selection: 54 resolution_spine_effective + MCAW402 normalized",
        },
        "UNICORN": {
            "tier": "provenance graph anomaly",
            "coverage": "41/55 attack; 47/60 natural clean; 134/176 training sketches",
            "tpr": unicorn_tpr,
            "fpr_natural": unicorn_fpr,
            "score_distribution_test": UNICORN["score_distribution_test"],
            "per_profile": UNICORN["per_profile"],
            "interpretability_gate": UNICORN["interpretability_gate"],
            "preregistered_outcome": UNICORN["preregistered_outcome"],
            "generation": UNICORN["generation"],
        },
        "ours_B1_pooled": {"tier": "write size and timing", **ours_b1},
        "ours_B2_per_profile": {"tier": "write size and timing", **ours_b2},
        **supervised_primary,
    },
    "balanced_ablation": OURS["balanced_ablation"],
    "matched_control_analysis": supervised,
    "primary_staged_twin_availability": MAN["pools"]["pool3_attack_test_55"]["twin_availability"],
    "twin_availability_note": MAN["twin_note"],
    "leaky_clean40_appendix": leaky,
    "headline": headline,
}
canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
report["report_content_address"] = hashlib.sha256(canonical).hexdigest()[:12]
(OUT / "FINAL_3POOL_REPORT.json").write_text(json.dumps(report, indent=2) + "\n")


def fmt(metric):
    lo, hi = metric["cluster_bootstrap_ci95"]
    return f"{metric['k']}/{metric['n']} ({metric['rate']:.4f}) [{lo:.4f}, {hi:.4f}], {metric['n_clusters']} clusters"


def fmt_boundary(metric):
    base = fmt(metric)
    if metric["k"] in (0, metric["n"]):
        w = metric["cluster_any_wilson"]
        base += f"; cluster-any Wilson [{w['lo']:.4f}, {w['hi']:.4f}]"
    return base


md = []
md.append("# Audited final three-pool detector results (2026-08-25)\n")
md.append(f"Manifest `{MAN['manifest_content_address']}` · Report `{report['report_content_address']}`.\n")
md.append("Point estimates use executions/attack operations; bracketed intervals are cluster bootstraps over the independent scenario/fold. Boundary cells additionally report cluster-any Wilson intervals.\n")
md.append("## Primary detector comparison\n")
md.append("| Detector | Training data | Attack coverage | Attack TPR / end-to-end recall | Natural-clean FPR |")
md.append("|---|---|---:|---:|---:|")
md.append(f"| AIDE | None | 55/55 | {fmt_boundary(aide_tpr)} | {fmt_boundary(aide_fpr['overall'])} |")
md.append(f"| Falco | None (frozen rules) | 55/55 | {fmt_boundary(falco_tpr)} | {fmt_boundary(falco_fpr['overall'])} |")
md.append(f"| STIDE | 176 clean | 55/55 | {fmt_boundary(stide_tpr)} | {fmt_boundary(stide_fpr['overall'])} |")
md.append(f"| UNICORN | 134/176 clean sketches | 41/55 evaluable | {fmt_boundary(unicorn_tpr)} | {fmt_boundary(unicorn_fpr['overall'])} |")
md.append(f"| B1 pooled | 176 clean | 23/55 definable | conditional {fmt_boundary(ours_b1['conditional_tpr'])}; end-to-end {fmt_boundary(ours_b1['end_to_end_recall_55'])} | {fmt_boundary(ours_b1['fpr_natural']['overall'])} |")
md.append(f"| B2 per-profile | 176 clean | 23/55 definable | conditional {fmt_boundary(ours_b2['conditional_tpr'])}; end-to-end {fmt_boundary(ours_b2['end_to_end_recall_55'])} | {fmt_boundary(ours_b2['fpr_natural']['overall'])} |")
for label, key in [
    ("Supervised L1 logistic", "Supervised_L1_Logistic"),
    ("Supervised CART", "Supervised_CART"),
    ("Supervised FIGS", "Supervised_FIGS"),
]:
    block = supervised_primary[key]
    md.append(f"| {label} | 176 clean + four attack folds | 23/55 definable | grouped 5-fold {fmt_boundary(block['conditional_tpr'])}; end-to-end {fmt_boundary(block['end_to_end_recall_55'])} | {fmt_boundary(block['fpr_natural']['overall'])} |")
md.append("\n## Natural-clean write decomposition\n")
md.append("| Detector | Write executions (12 scenarios) | No-write executions (11 scenarios) |")
md.append("|---|---:|---:|")
for name, block in [("AIDE", aide_fpr), ("Falco", falco_fpr), ("STIDE", stide_fpr),
                    ("UNICORN", unicorn_fpr),
                    ("B1 pooled", ours_b1["fpr_natural"]), ("B2 per-profile", ours_b2["fpr_natural"]),
                    ("Supervised L1 logistic", supervised_primary["Supervised_L1_Logistic"]["fpr_natural"]),
                    ("Supervised CART", supervised_primary["Supervised_CART"]["fpr_natural"]),
                    ("Supervised FIGS", supervised_primary["Supervised_FIGS"]["fpr_natural"])]:
    md.append(f"| {name} | {fmt_boundary(block['write_conditional'])} | {fmt_boundary(block['no_write'])} |")

md.append("\n## Matched-control validation\n")
sa = supervised["twin_base"]
op = sa["operating_point"]
md.append("This analysis is restricted to the canonical 23/55 write-resolved attacks and 23 recovered matched twins (20 scenarios); it is not an all-55 head-to-head row.\n")
md.append("| Substrate / negative base | Population | Result | Interpretation |")
md.append("|---|---:|---:|---|")
md.append(f"| Size/timing, matched twins | 23 attack + 23 twin | nested-CV AUC {sa['nested_cv_auc']:.4f} [{sa['auc_ci95'][0]:.4f}, {sa['auc_ci95'][1]:.4f}]; TPR {op['TPR']:.4f}, FPR {op['FPR_twin']:.4f} | CI includes chance |")
ng = supervised["ngram_twin_base"]
md.append(f"| Syscall n-grams, matched twins | {ng['N']['pos']} attack + {ng['N']['neg_twin']} twin | L1-LR AUC {ng['auc']['l1_logreg']:.4f}; RuleFit AUC {ng['auc']['rulefit']:.4f} | At chance |")

md.append("\n## Balanced training-size ablation\n")
md.append("| Seed | B1 TPR / FPR | B2 TPR / FPR |")
md.append("|---:|---:|---:|")
for seed in OURS["balanced_ablation"]["seeds"]:
    md.append(f"| {seed['seed']} | {seed['B1_140']['tpr']} / {seed['B1_140']['fpr']} | {seed['B2_140']['tpr']} / {seed['B2_140']['fpr']} |")

md.append("\n## Interpretation\n")
md.append(headline)
md.append("\nThe former clean-40 comparison is retained only for provenance and must not be used to infer the direction of FPR bias because half of that set overlaps the training freeze.")
(OUT / "FINAL_3POOL_HEADTOHEAD_TABLE.md").write_text("\n".join(md) + "\n")

frag = []
frag.append("### Matched-control validation on the write-resolved subset\n")
frag.append("Population: 23 write-resolved attacks and 23 recovered matched twins, grouped into 20 independent scenarios. This is a 23/55 secondary subset, not an all-55 detector row.\n")
frag.append(f"Matched-twin nested-CV AUC: **{sa['nested_cv_auc']:.4f} [{sa['auc_ci95'][0]:.4f}, {sa['auc_ci95'][1]:.4f}]**. At its LOSO operating point, TPR={op['TPR']:.4f} and twin-FPR={op['FPR_twin']:.4f}. The interval includes chance.\n")
frag.append(f"On matched syscall n-grams, L1-LR AUC={ng['auc']['l1_logreg']:.4f} and RuleFit AUC={ng['auc']['rulefit']:.4f}.")
(OUT / "FINAL_3POOL_SUPERVISED_TABLEFRAG.md").write_text("\n".join(frag) + "\n")

checksum_files = [
    "FINAL_3POOL_HEADTOHEAD_TABLE.md", "FINAL_3POOL_REPORT.json",
    "FINAL_3POOL_SPLIT_MANIFEST.json", "FINAL_3POOL_SUPERVISED.json",
    "FINAL_3POOL_SUPERVISED_TABLEFRAG.md", "FRESH_AVAILABILITY_MATRIX_POSTD1.json",
    "build_manifest.py", "falco_remote.py", "final_aggregate.py", "merge_falco_3pool.py",
    "pull_pool.py", "rebuild_supervised_3pool.py", "score_aide_3pool.py",
    "score_ours_3pool.py", "score_stide_3pool.py", "scored_aide_3pool.json",
    "scored_falco_3pool.json", "scored_ours_3pool.json", "scored_stide_3pool.json",
    "score_unicorn_gen5_3pool.py", "unicorn/UNICORN_GEN5_FINAL_REPORT.json",
    "unicorn/SKETCH_STATUS.json", "unicorn/SCORED_ROWS.json",
]
checksum_lines = []
for name in checksum_files:
    checksum_lines.append(f"{hashlib.sha256((OUT / name).read_bytes()).hexdigest()}  {name}")
(OUT / "FINAL_3POOL_SHA256SUMS.txt").write_text("\n".join(checksum_lines) + "\n")
print("\n".join(md))
