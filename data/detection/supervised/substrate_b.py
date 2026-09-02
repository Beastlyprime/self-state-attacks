#!/usr/bin/env python3
"""
Substrate B: supervised rule models over syscall n-gram indicators (design §3B, §4, §9 step 5).

Reads the SAME pinned libsinsp stream and applies the SAME eligibility convention as
the frozen STIDE path (`sequence_eligible` + `syscall.success`, grouped by executable
then process instance, n=6), so this arm and STIDE consume byte-identical input.
Unit of analysis = one run. 17 poisoned (label 1) vs their 17 paired __clean twins.

CORELS was the design's first choice for its optimality certificate, but `corels`
fails to build on this Python 3.13 host and imodels 3.0.0 does not vendor it.
Substituted BayesianRuleListClassifier (Letham et al. 2015), the same rule-list family.
THE OPTIMALITY CERTIFICATE IS LOST — a null here means "these searches found no rule",
not "no rule of this complexity exists".

Defensive analysis. Offline, read-only. No network/VM/payload execution.
"""
import json, os, sys, glob, warnings, time
from collections import defaultdict
import numpy as np

warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from supervised_cv import tpr_at_fpr, boot_auc_ci, SEED

from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from imodels import RuleFitClassifier, BayesianRuleListClassifier
from pathlib import Path as _Path
_REPO_ROOT = str(_Path(__file__).resolve().parents[3])

RES = _REPO_ROOT + "/data"
OUT = f"{HERE}/substrate_b.json"
NGRAM_N = 6
MIN_DF = 2  # an n-gram seen in a single run is memorisation, not a generalisable feature


def ngrams(seq, n):
    if len(seq) < n:
        return set()
    return {tuple(seq[i:i + n]) for i in range(len(seq) - n + 1)}


def run_ngrams(path):
    """Verbatim eligibility/grouping convention of stide_core_tail._load_sequences."""
    grouped = defaultdict(lambda: defaultdict(list))
    eligible = 0
    with open(path) as fh:
        for line in fh:
            if not line.strip():
                continue
            row = json.loads(line)
            if not row.get("sequence_eligible", False):
                continue
            if not row.get("syscall", {}).get("success"):
                continue
            p = row.get("process") or {}
            ex = p.get("exe") or p.get("comm") or "<unknown>"
            ident = p.get("identity_key") or f"{row['run_id']}:{p.get('pid')}:identity_incomplete"
            grouped[ex][f"{row['run_id']}::{ident}"].append(row["syscall"]["name"])
            eligible += 1
    vals = set()
    for instances in grouped.values():
        for seq in instances.values():
            vals.update(ngrams(seq, NGRAM_N))
    return vals, eligible


def build_matrix(run_sets, vocab):
    idx = {g: i for i, g in enumerate(vocab)}
    X = np.zeros((len(run_sets), len(vocab)), dtype=float)
    for r, s in enumerate(run_sets):
        for g in s:
            j = idx.get(g)
            if j is not None:
                X[r, j] = 1.0
    return X


def loso_oof_b(run_sets, y, g, model_fn, max_features=None, dropped=None):
    """Vocabulary is rebuilt on the TRAIN fold only — otherwise held-out n-grams leak.
    max_features caps the vocabulary to the most frequent training n-grams; the number
    dropped is recorded, never silently discarded."""
    oof = np.full(len(y), np.nan)
    for grp in sorted(set(g)):
        te = np.where(g == grp)[0]
        tr = np.where(g != grp)[0]
        if len(set(y[tr])) < 2:
            continue
        df = defaultdict(int)
        for i in tr:
            for gram in run_sets[i]:
                df[gram] += 1
        vocab = sorted([k for k, c in df.items() if c >= MIN_DF])
        if max_features is not None and len(vocab) > max_features:
            if dropped is not None:
                dropped.append({"fold": grp, "vocabulary": len(vocab),
                                "kept": max_features, "dropped": len(vocab) - max_features})
            vocab = sorted(sorted(vocab, key=lambda k: -df[k])[:max_features])
        if not vocab:
            continue
        Xtr = build_matrix([run_sets[i] for i in tr], vocab)
        Xte = build_matrix([run_sets[i] for i in te], vocab)
        m = model_fn()
        try:
            np.random.seed(SEED)  # FIGS/RuleFit draw from the global RNG, not random_state
            m.fit(Xtr, y[tr])
            p = m.predict_proba(Xte)
            oof[te] = p[:, 1] if getattr(p, "ndim", 1) > 1 and p.shape[1] > 1 else np.ravel(p)
        except Exception as exc:  # a model that cannot fit this fold is recorded, not hidden
            oof[te] = np.nan
            print(f"      fold {grp}: {type(exc).__name__}: {exc}")
    return oof


def evaluate_b(run_sets, y, g, tag, models, caps=None):
    res = {}
    caps = caps or {}
    for name, fn in models.items():
        t0 = time.time()
        dropped = []
        oof = loso_oof_b(run_sets, y, g, fn, max_features=caps.get(name), dropped=dropped)
        valid = ~np.isnan(oof)
        if valid.sum() < 4 or len(set(y[valid])) < 2:
            res[name] = {"status": "not_evaluable", "n_scored": int(valid.sum())}
            print(f"    {tag:16s} {name:14s} not evaluable")
            continue
        yv, sv, gv = y[valid], oof[valid], g[valid]
        auc = float(roc_auc_score(yv, sv))
        lo, hi = boot_auc_ci(yv, sv, gv)
        res[name] = {"auc": round(auc, 4), "auc_ci95_bootstrap_over_scenarios": [lo, hi],
                     "tpr_at_fpr_0_14": tpr_at_fpr(yv, sv, 0.1395),
                     "n_scored": int(valid.sum()), "seconds": round(time.time() - t0, 1)}
        if caps.get(name):
            res[name]["feature_cap"] = {"max_features": caps[name], "per_fold": dropped}
        print(f"    {tag:16s} {name:14s} AUC={auc:.4f} CI=[{lo},{hi}] "
              f"n={int(valid.sum())} ({time.time()-t0:.0f}s)")
    return res


def main():
    census = json.load(open(f"{RES}/p2_attack_tpr_expanded_v2_20260822/EXPANDED_LANDED_CENSUS_V2_20260822.json"))
    # STIDE's substrate is the NORMALIZED syscall stream: graph/libsinsp/libsinsp_events.jsonl
    # (schema assa.libsinsp_events.v1) carries neither `sequence_eligible` nor
    # `syscall.success`, so it cannot reproduce STIDE's eligibility gate. The field pair
    # lives in graph/normalized/syscalls.jsonl, written by stage_g_harness/scap.py.
    libs = glob.glob(f"{RES}/p2_l0_*_20260822/**/graph/normalized/syscalls.jsonl", recursive=True)
    byrun = {os.path.basename(os.path.dirname(os.path.dirname(os.path.dirname(p)))): p for p in libs}

    import re
    run_sets, y, g, meta = [], [], [], []
    for L in census["landers"]:
        rid, lk = L["run_id"], L["lander_key"]
        cid = rid.replace("__poisoned", "__clean")
        if rid not in byrun or cid not in byrun:
            continue
        scen = re.match(r"^(C\d+)", lk).group(1)
        for run_id, label in ((rid, 1), (cid, 0)):
            s, elig = run_ngrams(byrun[run_id])
            run_sets.append(s)
            y.append(label)
            g.append(scen)
            meta.append({"run_id": run_id, "lander": lk, "label": label,
                         "scenario": scen, "eligible_syscalls": elig, "n_unique_ngrams": len(s)})
        print(f"  loaded {lk}: poisoned {meta[-2]['n_unique_ngrams']} grams / "
              f"clean {meta[-1]['n_unique_ngrams']} grams")
    y = np.array(y, dtype=int)
    g = np.array(g)

    # volume diagnostic: is run size itself class-dependent?
    pos_e = [m["eligible_syscalls"] for m in meta if m["label"] == 1]
    neg_e = [m["eligible_syscalls"] for m in meta if m["label"] == 0]
    pos_v = [m["n_unique_ngrams"] for m in meta if m["label"] == 1]
    neg_v = [m["n_unique_ngrams"] for m in meta if m["label"] == 0]

    models = {
        "l1_logreg": lambda: LogisticRegression(penalty="l1", solver="liblinear",
                                                C=0.5, max_iter=5000,
                                                random_state=SEED),
        "rulefit": lambda: RuleFitClassifier(max_rules=8, random_state=SEED),
        "brl": lambda: BayesianRuleListClassifier(listlengthprior=2, max_iter=2000,
                                                  class1label="attack", verbose=False),
    }

    out = {
        "schema_version": "assa.p2_supervised_arm.substrate_b.v1",
        "derivation_generation": "p2_supervised_arm_20260823",
        "analysis_kind": "defensive; offline; read-only; no network/VM/payload execution",
        "substrate": {"source": "graph/normalized/syscalls.jsonl (the stream carrying sequence_eligible + syscall.success; graph/libsinsp/libsinsp_events.jsonl carries neither and cannot reproduce STIDE eligibility)",
                      "eligibility": "sequence_eligible AND syscall.success, grouped by "
                                     "executable then process instance — verbatim "
                                     "stide_core_tail._load_sequences convention",
                      "ngram_length": NGRAM_N, "min_document_frequency": MIN_DF,
                      "unit_of_analysis": "one run"},
        "corels_substitution": {
            "planned": "CORELS (Angelino et al. 2017) for its optimality certificate",
            "actual": "BayesianRuleListClassifier (Letham et al. 2015)",
            "reason": "`corels` fails to build on this Python 3.13 host; imodels 3.0.0 "
                      "does not vendor it",
            "consequence": "THE OPTIMALITY CERTIFICATE IS LOST. A null result on this "
                           "substrate means 'these searches found no rule', not 'no rule "
                           "of this complexity exists'.",
        },
        "population": {"runs": len(y), "poisoned": int(y.sum()), "clean": int((1 - y).sum()),
                       "scenarios": len(set(g))},
        "volume_diagnostic": {
            "eligible_syscalls_median": {"poisoned": float(np.median(pos_e)),
                                         "clean": float(np.median(neg_e))},
            "unique_ngrams_median": {"poisoned": float(np.median(pos_v)),
                                     "clean": float(np.median(neg_v))},
            "note": "if these differ sharply the n-gram arm can separate on run volume "
                    "rather than on attack structure",
        },
        "runs": meta,
    }

    CAPS = {"brl": 200}
    out["feature_caps"] = {
        "brl": 200,
        "why": "BayesianRuleListClassifier mines frequent itemsets and does not terminate "
               "in reasonable time on the full ~5k-gram vocabulary. Its input is capped to "
               "the 200 most frequent TRAINING-fold n-grams. l1_logreg and rulefit see the "
               "full vocabulary. The per-fold number of dropped n-grams is recorded under "
               "each capped result; this cap is declared, not silent.",
    }

    print("[main] real labels")
    out["main"] = evaluate_b(run_sets, y, g, "real", models, caps=CAPS)

    print("[C1a] globally permuted labels")
    rng = np.random.default_rng(SEED)
    out["control_C1a_permuted_global"] = {
        "intent": "plumbing check; expected AUC ~0.5",
        "results": evaluate_b(run_sets, rng.permutation(y), g, "C1a-perm", models, caps=CAPS),
    }

    json.dump(out, open(OUT, "w"), indent=2)
    print(json.dumps(out["volume_diagnostic"], indent=2))
    print(f"WROTE {OUT}")


if __name__ == "__main__":
    main()
