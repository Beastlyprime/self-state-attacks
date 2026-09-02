#!/usr/bin/env python3
"""
Expanded substrate B: syscall n-gram rule models over normalized streams (design §3B).
Unit = one run. Pool all co-admissible pairs (locked-pop 17 + um 12 + file-op 26 + MCAW 3);
the 3 lineage-divergent MCAW poisoned (MCAW101/201/402: libsinsp rules.sha 30982105 != locked
e3b75979) are ISOLATED in a separate expanded-only stratum, never pooled silently.

Reuses run_ngrams / build_matrix / loso_oof_b / evaluate_b verbatim from substrate_b.py
(byte-identical eligibility: sequence_eligible AND syscall.success, n=6, min-df=2, vocab on
train fold only). CORELS optimality certificate remains lost (BRL substitute).

Defensive analysis. Offline, read-only. No network/VM/payload execution.
"""
import json, os, sys, glob, re, warnings
import numpy as np
warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
from substrate_b import run_ngrams, evaluate_b, NGRAM_N, MIN_DF
from sklearn.linear_model import LogisticRegression
from imodels import RuleFitClassifier, BayesianRuleListClassifier
from supervised_cv import SEED
from pathlib import Path as _Path
_REPO_ROOT = str(_Path(__file__).resolve().parents[3])

RES = _REPO_ROOT + "/data"
OUT = f"{HERE}/substrate_b.json"
DIVERGENT = {"MCAW101", "MCAW201", "MCAW402"}  # lineage-divergent poisoned (rules.sha 30982105)


def find_norm(run_id):
    hits = glob.glob(f"{RES}/**/{run_id}/graph/normalized/syscalls.jsonl", recursive=True)
    return hits[0] if hits else None

def base_scenario(lk):
    m = re.match(r"^M[A-Z]+\d+_w\d+_(.+)$", lk)
    if m: return m.group(1)
    m = re.match(r"^(C\d+)", lk)
    return m.group(1) if m else lk

def collect(run_ids):
    """run_ids: list of poisoned run_id. Returns (run_sets,y,g,meta) for pairs with both twins."""
    run_sets, y, g, meta = [], [], [], []
    for rid in run_ids:
        cid = rid.replace("__poisoned", "__clean")
        pp, cp = find_norm(rid), find_norm(cid)
        if not pp or not cp:
            continue
        lk = re.sub(r"__poisoned$", "", rid)
        scen = base_scenario(lk)
        for run_id, path, label in ((rid, pp, 1), (cid, cp, 0)):
            s, elig = run_ngrams(path)
            run_sets.append(s); y.append(label); g.append(scen)
            meta.append({"run_id": run_id, "lander": lk, "label": label, "scenario": scen,
                         "eligible_syscalls": elig, "n_unique_ngrams": len(s)})
    return run_sets, np.array(y, dtype=int), np.array(g), meta


def main():
    # locked-pop 17 poisoned run_ids (from frozen b1b2 detail) + new poisoned run_ids
    fz = json.load(open(f"{RES}/detection/b1b2/REPORT.json"))
    # map frozen lander_key -> run_id via census
    census = json.load(open(f"{RES}/p2_attack_tpr_expanded_v2_20260822/EXPANDED_LANDED_CENSUS_V2_20260822.json"))
    lk2rid = {L["lander_key"]: L["run_id"] for L in census["landers"]}
    locked_lk = [e["lander"] for e in fz["detail"]["attack_B1"]]
    locked_rids = [lk2rid[lk] for lk in locked_lk if lk in lk2rid]

    new_rids = []
    for d in glob.glob(f"{RES}/p2_mass_attack_lane*/**/*__poisoned", recursive=True):
        b = os.path.basename(d)
        if re.match(r"^(MUI|MUC|MCAW|MCH|MSI|MTR|MUL)\d", b) and \
           os.path.exists(os.path.join(d, "graph/normalized/syscalls.jsonl")):
            new_rids.append(b)
    new_rids = sorted(set(new_rids))
    pooled_new = [r for r in new_rids if re.match(r"^(M[A-Z]+\d+)", r).group(1) not in DIVERGENT]
    isolated_new = [r for r in new_rids if re.match(r"^(M[A-Z]+\d+)", r).group(1) in DIVERGENT]

    # BRL (BayesianRuleList) did NOT terminate within a 500s wall-clock bound on the
    # expanded pooled set (58 pairs / 116 runs); dropped and marked non-terminating,
    # the same caveat class as the locked-pop CORELS substitution. L1-LR + RuleFit only.
    models = {
        "l1_logreg": lambda: LogisticRegression(penalty="l1", solver="liblinear", C=0.5,
                                                max_iter=5000, random_state=SEED),
        "rulefit": lambda: RuleFitClassifier(max_rules=8, random_state=SEED),
    }
    CAPS = {}

    rs, y, g, meta = collect(locked_rids + pooled_new)
    pos_e = [m["eligible_syscalls"] for m in meta if m["label"] == 1]
    neg_e = [m["eligible_syscalls"] for m in meta if m["label"] == 0]
    pos_v = [m["n_unique_ngrams"] for m in meta if m["label"] == 1]
    neg_v = [m["n_unique_ngrams"] for m in meta if m["label"] == 0]

    out = {"schema_version": "assa.p2_supervised_arm.substrate_b.v1",
           "derivation_generation": "p2_supervised_arm_expanded_20260825",
           "analysis_kind": "defensive; offline; read-only",
           "substrate": {"source": "graph/normalized/syscalls.jsonl",
                         "eligibility": "sequence_eligible AND syscall.success, exec>process instance",
                         "ngram_length": NGRAM_N, "min_document_frequency": MIN_DF,
                         "unit_of_analysis": "one run"},
           "corels_substitution": {"consequence": "OPTIMALITY CERTIFICATE LOST; a null means "
                                   "'these searches found no rule', not 'no rule exists'"},
           "lineage_isolation": {"divergent_poisoned": sorted(DIVERGENT),
                                 "reason": "libsinsp rules.sha256 30982105 != locked-pop e3b75979; "
                                           "kept in a separate expanded-only stratum, not pooled"},
           "population_pooled": {"runs": len(y), "poisoned": int(y.sum()),
                                 "clean": int((1 - y).sum()), "scenarios": len(set(g))},
           "volume_diagnostic": {
               "eligible_syscalls_median": {"poisoned": float(np.median(pos_e)),
                                            "clean": float(np.median(neg_e))},
               "unique_ngrams_median": {"poisoned": float(np.median(pos_v)),
                                        "clean": float(np.median(neg_v))}},
           "runs": meta}

    print("[pooled] real labels")
    out["main"] = evaluate_b(rs, y, g, "real", models, caps=CAPS)
    print("[pooled] C1a permuted")
    rng = np.random.default_rng(SEED)
    out["control_C1a_permuted_global"] = {"intent": "plumbing; expect ~0.5",
        "results": evaluate_b(rs, rng.permutation(y), g, "C1a", models, caps=CAPS)}

    # isolated divergent stratum: report volume only (too few to fit alone)
    ris, yis, gis, mis = collect(isolated_new)
    out["isolated_divergent_stratum"] = {
        "runs": len(yis), "poisoned": int(yis.sum()), "clean": int((1 - yis).sum()),
        "note": "reported separately (lineage-divergent); not fit — 3 pairs is underpowered",
        "volume": {"pos_eligible_median": float(np.median([m["eligible_syscalls"] for m in mis if m["label"]==1])) if mis else None,
                   "neg_eligible_median": float(np.median([m["eligible_syscalls"] for m in mis if not m["label"]])) if mis else None}}

    json.dump(out, open(OUT, "w"), indent=2)
    print("pooled runs:", len(y), "poisoned", int(y.sum()), "clean", int((1-y).sum()), "scenarios", len(set(g)))
    print("isolated divergent runs:", len(yis))
    print(json.dumps(out["volume_diagnostic"], indent=2))
    print(f"WROTE {OUT}")


if __name__ == "__main__":
    main()
