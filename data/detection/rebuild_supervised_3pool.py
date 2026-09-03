#!/usr/bin/env python3
"""
Rebuild the supervised size-and-timing baselines on the frozen three-pool design.

The primary positive population is the 23/55 write-resolved subset scored by B1/B2.
Each attack prediction comes from a fixed-seed five-fold cross-validation split that
keeps all executions of one task scenario together and approximately stratifies by
workload profile. For each outer fold, the remaining attacks and all 176 clean training
executions fit the model; an inner scenario-grouped five-fold procedure selects the
training-only Youden-J threshold. Natural-workload FPR is evaluated once on the
independent 60-execution clean test set after refitting on all 23 attacks and 176 clean
training executions.

The 23 recovered matched-clean twins are never used for primary model fitting. They
support only the secondary paired AUC, McNemar, syscall n-gram, and workload-placebo
checks. B1/B2 are independently validated against the frozen reference scores.

Offline and read-only with respect to source traces; no network, VM, or payload execution.
"""
import importlib.util
import json, os, sys, glob, math, statistics, warnings
from pathlib import Path
from collections import Counter, defaultdict
import numpy as np
warnings.filterwarnings("ignore")
from scipy import stats as sps
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, roc_curve
from sklearn.model_selection import StratifiedGroupKFold
from imodels import FIGSClassifier

ROOT = Path(os.environ.get("ASSA_ROOT", str(Path(__file__).resolve().parents[2])))
RES = ROOT / "data"
HH = RES / "superseded"                       # frozen generation: score_ours.py, staging trees
STAGE = HH / "staging"                        # selfstate-corpus-staging.tar.zst unpacks here
OUTDIR = ROOT / "data/detection"
POOLS = Path(os.environ.get("ASSA_SCRATCH", str(ROOT / ".scratch"))) / "pools"
ARCHIVE = RES / "corpus-manifests/tier_b"     # selfstate-corpus-tier_b-*.tar.zst unpack here
SEED = 20260825
sys.path.insert(0, str(ROOT / "experiments/code"))
from workload.taxonomy import canonical_path, bucket_key, layer_of
_spec = importlib.util.spec_from_file_location("score_ours", HH / "score_ours.py")
so = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(so)
WRITE = so.WRITE
DT = 1e-3
TAU = so.TAU
LAYER_TITLE = {"instruction": "Instruction", "config": "Configuration", "memory": "Memory"}

MAN = json.load(open(OUTDIR / "FINAL_3POOL_SPLIT_MANIFEST.json"))
SUB = MAN["definable_write_resolved_subset"]["run_ids"]
FOLD = MAN["fold_map_attack_loso"]


def all_ops(rundir):
    f = Path(rundir) / "graph/libsinsp/libsinsp_events.jsonl"
    if not f.is_file():
        return None
    rid = Path(rundir).name
    bk = defaultdict(lambda: {"ts": [], "canon": None, "first_dated": None})
    for line in f.open():
        e = json.loads(line); sc = e.get("syscall", {})
        if sc.get("name") not in WRITE or sc.get("result") != "SUCCESS":
            continue
        p = (e.get("file") or {}).get("path"); k = f"/{rid}/"; i = p.find(k) if p else -1
        if i < 0:
            continue
        cp = canonical_path(p[i + len(k):])
        if cp is None:
            continue
        b = bk[bucket_key(cp)]
        b["ts"].append(e["order"]["timestamp_realtime_ns"] / 1e9)
        if b["canon"] is None:
            b["canon"] = cp
        if b["first_dated"] is None and "*" in bucket_key(cp):
            b["first_dated"] = cp[len("workspace/"):] if cp.startswith("workspace/") else cp
    ops = []
    for key, b in bk.items():
        rel = b["first_dated"] if "*" in key else (key[len("workspace/"):] if key.startswith("workspace/") else key)
        sb = Path(rundir) / "state_snapshots/before_a" / rel
        sa = Path(rundir) / "state_snapshots/after_a" / rel
        s0 = os.path.getsize(sb) if sb.exists() else (0 if sa.exists() else None)
        s1 = os.path.getsize(sa) if sa.exists() else (0 if sb.exists() else None)
        if s0 is None and s1 is not None: s0 = 0
        if s1 is None and s0 is not None: s1 = 0
        ts = sorted(b["ts"]); n = len(ts)
        dts = [math.log(max(ts[i] - ts[i - 1], DT)) for i in range(1, n)]
        ops.append({"bucket": key, "op": f"{layer_of(b['canon'])}_write", "layer": layer_of(b["canon"]),
                    "canon": b["canon"], "n_writes": n, "ts_sec": ts, "dts": dts,
                    "size_before": s0, "size_after": s1,
                    "size_valid": (s0 is not None and s1 is not None)})
    return ops


def run_feature(rundir, scenario, profile, label, run_kind):
    ops = all_ops(rundir)
    if ops is None:
        return None, None
    valid = [o for o in ops if o["size_valid"]]
    if valid:
        o = max(valid, key=lambda x: abs(x["size_after"] - x["size_before"]))
        d = o["size_after"] - o["size_before"]
        feat = {"delta_size": d, "abs_delta_size": abs(d), "size_before": o["size_before"],
                "size_after": o["size_after"], "n_writes": o["n_writes"],
                "log_dt_last": (o["dts"][-1] if o["dts"] else None),
                "log_dt_mean": (sum(o["dts"]) / len(o["dts"]) if o["dts"] else None),
                "write_span_sec": (o["ts_sec"][-1] - o["ts_sec"][0] if o["n_writes"] >= 2 else 0.0),
                "has_timing": int(bool(o["dts"])), "layer": LAYER_TITLE.get(o["layer"], o["layer"]),
                "bucket": o["bucket"], "canon": o["canon"]}
    else:  # no size-valid write (e.g. clean_no_write) -> non-flaggable negative
        feat = {"delta_size": 0, "abs_delta_size": 0, "size_before": 0, "size_after": 0,
                "n_writes": 0, "log_dt_last": None, "log_dt_mean": None, "write_span_sec": 0.0,
                "has_timing": 0, "layer": "None", "bucket": "none", "canon": "none"}
    feat.update({"label": label, "scenario": scenario, "profile": profile, "run_kind": run_kind,
                 "run_id": Path(rundir).name})
    return feat, ops


# tier_b subdirectories that a run can live in once the corpus is unpacked
ARCHIVE_SUBDIRS = ("attacks", "attacks_lockedpop_cseries",
                   "twins", "twins_lockedpop_cseries",
                   "clean_train", "clean_heldout")


def locate(rid):
    """Find a run's libsinsp substrate.

    The collection-host trees (p2_mass_attack_lane*, p2_l0_*) are not published;
    the same runs travel in the corpus under tier_b, which is where the 23
    matched twins live. Staging first, so runs that were scored from it keep
    resolving there.
    """
    candidates = [STAGE / rid]
    candidates += [Path(p) for p in glob.glob(str(RES / f"p2_mass_attack_lane*/**/{rid}"), recursive=True)]
    candidates += [Path(p) for p in glob.glob(str(RES / f"p2_l0_*/**/{rid}"), recursive=True)]
    candidates += [ARCHIVE / sub / rid for sub in ARCHIVE_SUBDIRS]
    for c in candidates:
        if c.is_dir() and (c / "graph/libsinsp/libsinsp_events.jsonl").is_file():
            return c
    return None

def clean_pool_dir(role, rid):
    """Locate an immutable clean run without requiring the scratch cache."""
    scratch_role = "train" if role == "training" else "heldout"
    archive_role = "clean_train" if role == "training" else "clean_heldout"
    candidates = [POOLS / scratch_role / rid, ARCHIVE / archive_role / rid]
    for candidate in candidates:
        if (candidate / "graph/libsinsp/libsinsp_events.jsonl").is_file():
            return candidate
    raise FileNotFoundError(f"missing {role} clean substrate for {rid}")



# ---------- B1/B2 (fit gen2-176), verbatim formulas ----------
def fit_b(train_ops_by_run, by_profile=None):
    """Use the exact frozen B1/B2 implementation; do not maintain a local clone."""
    global_stats = so.fit_baseline(list(train_ops_by_run.items()))
    if by_profile is None:
        return global_stats
    grouped = defaultdict(list)
    for rid, ops in train_ops_by_run.items():
        grouped[by_profile[rid]].append((rid, ops))
    return {profile: so.fit_baseline(rows) for profile, rows in grouped.items()}, global_stats


def b_flag(ops, stats):
    result = so.run_decision(ops, stats)
    return bool(result.get("binary_decision"))


# ---------- matrix builder (per-run rows) ----------
CORE = ["delta_size", "abs_delta_size", "size_before", "size_after", "n_writes",
        "log_dt_last", "log_dt_mean", "write_span_sec", "has_timing"]
VARIANTS = {"A1": (CORE, ["layer", "profile", "bucket"]), "A2": (CORE, ["layer", "profile"]),
            "A3": (CORE, []), "A4": (["abs_delta_size"], [])}


def build(rows, variant, impute_from=None):
    num, cats = VARIANTS[variant]
    src = impute_from if impute_from is not None else rows
    med = {f: (float(np.median([r[f] for r in src if r[f] is not None])) if any(r[f] is not None for r in src) else 0.0) for f in num}
    levels = {c: sorted({r[c] for r in src}) for c in cats}
    names, cols = [], []
    for f in num:
        names.append(f); cols.append([float(r[f]) if r[f] is not None else med[f] for r in rows])
    for c in cats:
        for lv in levels[c]:
            names.append(f"{c}={lv}"); cols.append([1.0 if r[c] == lv else 0.0 for r in rows])
    return np.array(cols, dtype=float).T, names


def model(name):
    if name == "l1_logreg":
        return LogisticRegression(penalty="l1", solver="liblinear", C=0.5, max_iter=5000, random_state=SEED)
    if name == "cart_d3":
        return DecisionTreeClassifier(max_depth=3, min_samples_leaf=3, random_state=SEED)
    return FIGSClassifier(max_rules=4, random_state=SEED)


MODELS = ["l1_logreg", "cart_d3", "figs"]


def fit_predict(tr_rows, te_rows, variant, mname):
    Xtr, names = build(tr_rows, variant, impute_from=tr_rows)
    Xte, _ = build(te_rows, variant, impute_from=tr_rows)
    sc = StandardScaler().fit(Xtr)
    m = model(mname)
    np.random.seed(SEED)
    m.fit(sc.transform(Xtr), np.array([r["label"] for r in tr_rows]))
    p = m.predict_proba(sc.transform(Xte))
    return p[:, 1] if p.ndim > 1 and p.shape[1] > 1 else np.ravel(p)


def grouped_training_scores(rows, variant, mname):
    """Training-only out-of-fold scores used to select an operating point."""
    y = np.array([r["label"] for r in rows])
    groups = np.array([r["scenario"] for r in rows])
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED)
    scores = np.full(len(rows), np.nan)
    dummy = np.zeros((len(rows), 1))
    for tr, te in splitter.split(dummy, y, groups):
        if len(set(y[tr])) < 2:
            continue
        scores[te] = fit_predict(
            [rows[i] for i in tr], [rows[i] for i in te], variant, mname,
        )
    return scores


def training_threshold(rows, variant, mname):
    """Choose a training-only Youden-J operating point."""
    y = np.array([r["label"] for r in rows])
    scores = grouped_training_scores(rows, variant, mname)
    valid = ~np.isnan(scores)
    if len(set(y[valid])) < 2:
        raise RuntimeError("training threshold requires both polarity classes")
    fpr, tpr, thresholds = roc_curve(y[valid], scores[valid])
    order = sorted(
        range(len(thresholds)),
        key=lambda i: (tpr[i] - fpr[i], -fpr[i], thresholds[i]),
        reverse=True,
    )
    selected = order[0]
    return float(thresholds[selected]), {
        "criterion": "maximum_Youden_J_on_5fold_scenario_grouped_training_predictions",
        "training_oof_tpr": round(float(tpr[selected]), 4),
        "training_oof_fpr": round(float(fpr[selected]), 4),
        "training_oof_auc": round(float(roc_auc_score(y[valid], scores[valid])), 4),
    }


def randomized_attack_group_folds(rows):
    """Build a fixed five-fold split while keeping each attack scenario intact."""
    profiles = np.array([row["profile"] for row in rows])
    groups = np.array([row["scenario"] for row in rows])
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED)
    dummy = np.zeros((len(rows), 1))
    splits, fold_by_index, composition = [], {}, []
    for fold_id, (tr, te) in enumerate(splitter.split(dummy, profiles, groups), start=1):
        train_scenarios = {groups[i] for i in tr}
        test_scenarios = {groups[i] for i in te}
        if train_scenarios & test_scenarios:
            raise RuntimeError(f"fold {fold_id}: scenario leakage")
        splits.append((list(tr), list(te)))
        for index in te:
            if int(index) in fold_by_index:
                raise RuntimeError(f"attack row {index} assigned to multiple folds")
            fold_by_index[int(index)] = fold_id
        heldout = [rows[i] for i in te]
        composition.append({
            "fold": fold_id,
            "attack_executions": len(te),
            "attack_scenarios": len(test_scenarios),
            "heldout_scenarios": sorted(test_scenarios),
            "by_profile": dict(sorted(Counter(row["profile"] for row in heldout).items())),
            "by_op_signature": dict(sorted(Counter(row["op_signature"] for row in heldout).items())),
        })
    if sorted(fold_by_index) != list(range(len(rows))):
        raise RuntimeError("five-fold assignment does not cover every attack execution exactly once")
    return splits, fold_by_index, composition


def primary_supervised_results(atk_rows, clean_train_rows, clean_test_rows):
    """Evaluate fixed supervised baselines on the common test populations."""
    results = {}
    outer_splits, fold_by_index, fold_composition = randomized_attack_group_folds(atk_rows)
    for mname in MODELS:
        variant = "A1"
        attack_scores = np.full(len(atk_rows), np.nan)
        attack_flags = np.zeros(len(atk_rows), dtype=int)
        outer_folds = []
        for fold_id, (tr, te) in enumerate(outer_splits, start=1):
            tr_attack = [atk_rows[i] for i in tr]
            training = tr_attack + clean_train_rows
            threshold, threshold_meta = training_threshold(training, variant, mname)
            scores = fit_predict(training, [atk_rows[i] for i in te], variant, mname)
            for position, index in enumerate(te):
                attack_scores[index] = scores[position]
                attack_flags[index] = int(scores[position] >= threshold)
            outer_folds.append({
                "fold": fold_id,
                "heldout_scenarios": sorted({atk_rows[i]["scenario"] for i in te}),
                "threshold": threshold,
                **threshold_meta,
            })

        final_training = atk_rows + clean_train_rows
        final_threshold, final_threshold_meta = training_threshold(
            final_training, variant, mname,
        )
        clean_scores = fit_predict(final_training, clean_test_rows, variant, mname)
        clean_flags = (clean_scores >= final_threshold).astype(int)
        if np.isnan(attack_scores).any():
            raise RuntimeError(f"{mname}: incomplete grouped five-fold predictions")

        attack_output = [
            {
                "run_id": row["run_id"], "profile": row["profile"],
                "scenario_id": row["scenario"], "side": "attack",
                "outer_fold": fold_by_index[i],
                "status": "passed", "score": float(attack_scores[i]),
                "binary_decision": bool(attack_flags[i]),
            }
            for i, row in enumerate(atk_rows)
        ]
        clean_output = [
            {
                "run_id": row["run_id"], "profile": row["profile"],
                "scenario_id": row["scenario"], "side": "clean",
                "status": "passed", "score": float(clean_scores[i]),
                "binary_decision": bool(clean_flags[i]),
            }
            for i, row in enumerate(clean_test_rows)
        ]
        results[mname] = {
            "feature_variant": variant,
            "training": {
                "benign_executions": len(clean_train_rows),
                "malicious_executions": len(atk_rows),
                "attack_evaluation": "randomized_five_fold_scenario_grouped_cross_validation",
                "outer_random_seed": SEED,
                "outer_stratification": "approximately_by_workload_profile",
                "outer_fold_composition": fold_composition,
                "threshold_selection": final_threshold_meta["criterion"],
                "heldout_natural_workload_used_for_training_or_threshold": False,
                "matched_twins_used_for_training": False,
            },
            "coverage": f"{len(atk_rows)}/55",
            "attack_tpr": round(float(attack_flags.mean()), 4),
            "natural_workload_fpr": round(float(clean_flags.mean()), 4),
            "auc_status": "not_reported_scores_come_from_distinct_outer_models",
            "final_threshold": final_threshold,
            "final_threshold_training_diagnostics": final_threshold_meta,
            "outer_folds": outer_folds,
            "rows": attack_output + clean_output,
        }
    return results


def nested_oof(rows):
    """Secondary matched-control helper: outer scenario LOSO with inner model selection."""
    y = np.array([r["label"] for r in rows]); g = np.array([r["scenario"] for r in rows])
    oof = np.full(len(rows), np.nan); chosen = []
    scen = sorted(set(g))
    for grp in scen:
        te = np.where(g == grp)[0]; tr = np.where(g != grp)[0]
        if len(set(y[tr])) < 2:
            continue
        tr_scen = sorted(set(g[tr]))
        best, bestauc = None, -1
        for variant in ("A1", "A2", "A3", "A4"):
            for mname in MODELS:
                inner = np.full(len(tr), np.nan)
                for ig in tr_scen:
                    ite = np.where(g[tr] == ig)[0]; itr = np.where(g[tr] != ig)[0]
                    if len(set(y[tr][itr])) < 2:
                        continue
                    inner[ite] = fit_predict([rows[tr[i]] for i in itr], [rows[tr[i]] for i in ite], variant, mname)
                v = ~np.isnan(inner)
                if len(set(y[tr][v])) == 2:
                    a = roc_auc_score(y[tr][v], inner[v])
                    if a > bestauc:
                        bestauc, best = a, (variant, mname)
        if best is None:
            best = ("A4", "l1_logreg")
        oof[te] = fit_predict([rows[i] for i in tr], [rows[i] for i in te], best[0], best[1])
        chosen.append({"scenario": grp, "variant": best[0], "model": best[1], "inner_auc": round(bestauc, 4)})
    return oof, chosen


def boot_ci(y, s, g, n=2000):
    rng = np.random.default_rng(SEED); groups = sorted(set(g))
    idx = {k: np.where(g == k)[0] for k in groups}; vals = []
    for _ in range(n):
        pick = rng.choice(groups, size=len(groups), replace=True)
        ii = np.concatenate([idx[k] for k in pick]); yy, ss = y[ii], s[ii]
        if len(set(yy)) == 2 and not np.isnan(ss).any():
            vals.append(roc_auc_score(yy, ss))
    return [round(float(np.percentile(vals, 2.5)), 4), round(float(np.percentile(vals, 97.5)), 4)] if vals else [None, None]


def tpr_at_fpr(y, s, tfpr):
    fpr, tpr, thr = roc_curve(y, s); ok = fpr <= tfpr + 1e-12
    return round(float(tpr[ok].max()), 4) if ok.any() else 0.0


def loso_threshold_pred(rows, oof, tfpr):
    """per outer fold, pick |Δsize| threshold at FPR<=tfpr on train, apply to test (for McNemar)."""
    y = np.array([r["label"] for r in rows]); g = np.array([r["scenario"] for r in rows])
    v = np.array([r["abs_delta_size"] for r in rows], dtype=float)
    pred = np.zeros(len(rows), dtype=int)
    for grp in sorted(set(g)):
        te = np.where(g == grp)[0]; tr = np.where(g != grp)[0]
        best = None
        for t in sorted(set(v[tr]), reverse=True):
            if (v[tr] >= t)[y[tr] == 0].mean() <= tfpr:
                best = t
            else:
                break
        if best is not None:
            pred[te] = (v[te] >= best).astype(int)
    return pred


def mcnemar(b, c):
    n = b + c
    return {"b_ours_only": int(b), "c_theirs_only": int(c), "n_discordant": int(n),
            "p_value": round(float(sps.binomtest(b, n, 0.5).pvalue), 4) if n else 1.0}


def main():
    # ---- load pools ----
    pool1 = MAN["pools"]["pool1_clean_training_gen2_176"]["records"]
    pool2 = MAN["pools"]["pool2_clean_heldout_test_gen2_60"]["records"]
    attack_manifest = {r["run_id"]: r for r in MAN["pools"]["pool3_attack_test_55"]["records"]}
    prof176 = {r["run_id"]: r["profile"] for r in pool1}

    train_ops = {}
    for r in pool1:
        ops = all_ops(clean_pool_dir("training", r["run_id"]))
        if ops is not None:
            train_ops[r["run_id"]] = ops
    # B1 global baseline, B2 per-profile
    b1_st = fit_b(train_ops)
    b2_by_p, _ = fit_b(train_ops, by_profile=prof176)

    # ---- attack rows (23) + twin rows (23) ----
    atk_rows, twin_rows, atk_ops, twin_ops = [], [], {}, {}
    scen_of = {}
    for rid in SUB:
        scen = FOLD.get(rid, rid)
        prof = ("W1" if "_w1_" in rid else "W2" if "_w2_" in rid else "W3" if "_w3_" in rid else "W4")
        d = locate(rid); f, ops = run_feature(d, scen, prof, 1, "attack")
        f["op_signature"] = attack_manifest[rid]["op_signature"]
        atk_rows.append(f); atk_ops[rid] = ops; scen_of[rid] = scen
        tid = rid.replace("__poisoned", "__clean"); td = locate(tid)
        tf, tops = run_feature(td, scen, prof, 0, "twin")
        twin_rows.append(tf); twin_ops[tid] = tops

    # ---- gen2-60 rows ----
    g60_rows, g60_ops = [], {}
    for r in pool2:
        d = clean_pool_dir("heldout", r["run_id"])
        f, ops = run_feature(d, "natural::" + r["scenario_id"], r["profile"], 0, "heldout_natural")
        g60_rows.append(f); g60_ops[r["run_id"]] = ops

    # ---- validate B1/B2 vs scored_ours_3pool ----
    b1_atk = sum(b_flag(atk_ops[r], b1_st) for r in SUB)
    b2_atk = sum(b_flag(atk_ops[r], b2_by_p.get(atk_rows[i]["profile"], b1_st))
                 for i, r in enumerate(SUB))
    b1_g60 = sum(b_flag(g60_ops[r["run_id"]], b1_st) for r in pool2)
    b2_g60 = sum(b_flag(g60_ops[r["run_id"]], b2_by_p.get(r["profile"], b1_st)) for r in pool2)
    observed = (b1_atk, b2_atk, b1_g60, b2_g60)
    expected = (19, 20, 10, 7)
    assert observed == expected, f"B1/B2 validation mismatch: observed={observed}, expected={expected}"
    validation = {
        "status": "passed",
        "b1_attack_flagged": f"{b1_atk}/23",
        "b2_attack_flagged": f"{b2_atk}/23",
        "b1_gen2_60_flagged": f"{b1_g60}/60",
        "b2_gen2_60_flagged": f"{b2_g60}/60",
        "reference": "scored_ours_3pool.json",
    }

    out = {"schema_version": "assa.final_3pool_supervised.v1", "created": "2026-08-25",
           "supersedes": "the reused p2_supervised_arm_expanded_20260825 (58-pair) supervised row",
           "population": {"positives_canonical23": 23, "twin_negatives_recovered": 23,
                          "twin_recovery_note": "11 W3 content_append twins recovered from the frozen locked-pop source; MUI06 recovered from an additional local frozen source rather than the primary staged twin pool; 6 MCAW + 5 MUI full",
                          "gen2_60_negatives": 60, "gen2_60_with_size_valid_write": 18,
                          "substrate_a_unit": "per run: max-|Δsize| self-state write op (the op the size detector keys on)"},
           "b1b2_validation": validation,
           "population_status": "frozen final split",
           "polarity_status": "complete",
           "provisional_flags": []}

    # ================= SUBSTRATE A =================
    # ---- base (a) TWIN ----
    rows_a = atk_rows + twin_rows
    oof, chosen = nested_oof(rows_a)
    y = np.array([r["label"] for r in rows_a]); g = np.array([r["scenario"] for r in rows_a])
    valid = ~np.isnan(oof)
    auc_a = round(float(roc_auc_score(y[valid], oof[valid])), 4)
    ci_a = boot_ci(y[valid], oof[valid], g[valid])
    # supervised per-run flags at twin-FPR target matched to B1 gen2 (0.1667) and a strict 0.10
    b1_g60_fpr = b1_g60 / 60.0
    pred_a = loso_threshold_pred(rows_a, oof, b1_g60_fpr)
    sup_tpr_twin = round(sum(pred_a[i] for i, r in enumerate(rows_a) if r["label"] == 1) / 23, 4)
    sup_fpr_twin = round(sum(pred_a[i] for i, r in enumerate(rows_a) if r["label"] == 0) / 23, 4)
    # McNemar vs B1 and B2 on 23 attacks + 23 twins (same ops)
    def bflags(which):
        af = [b_flag(atk_ops[r], b1_st if which == "B1" else b2_by_p.get(atk_rows[i]["profile"], b1_st)) for i, r in enumerate(SUB)]
        tf = [b_flag(twin_ops[SUB[i].replace("__poisoned", "__clean")], b1_st if which == "B1" else b2_by_p.get(twin_rows[i]["profile"], b1_st)) for i in range(23)]
        return af, tf
    mcn = {}
    for which in ("B1", "B2"):
        af, tf = bflags(which)
        ba = sum(int(bool(pred_a[i]) and not af[i]) for i in range(23))
        ca = sum(int(af[i] and not bool(pred_a[i])) for i in range(23))
        bn = sum(int(bool(pred_a[23 + i]) and not tf[i]) for i in range(23))
        cn = sum(int(tf[i] and not bool(pred_a[23 + i])) for i in range(23))
        mcn[which] = {"theirs_TPR": round(sum(af) / 23, 4), "theirs_FPR_twin": round(sum(tf) / 23, 4),
                      "attack_side": mcnemar(ba, ca), "twin_side": mcnemar(bn, cn)}

    out["substrate_a_twin_base"] = {
        "N": {"pos": 23, "neg_twin": 23, "scenarios": len(set(g))},
        "nested_cv_auc": auc_a, "auc_ci95": ci_a, "inner_selections": chosen,
        "supervised_operating_point": {"TPR": sup_tpr_twin, "FPR_twin": sup_fpr_twin,
                                       "fpr_target_matched_to_B1_gen2": round(b1_g60_fpr, 4)},
        "paired_mcnemar_vs_b1b2": mcn}

    # ---- controls (twin base) ----
    rng = np.random.default_rng(SEED)
    ctrl = {}
    # C1a global perm
    yp = rng.permutation(y)
    rows_perm = [dict(r, label=int(yp[i])) for i, r in enumerate(rows_a)]
    o2, _ = nested_oof(rows_perm); v2 = ~np.isnan(o2)
    ctrl["C1a_global_perm_auc"] = round(float(roc_auc_score(yp[v2], o2[v2])), 4)
    # C1b within-scenario perm
    yw = y.copy()
    for grp in sorted(set(g)):
        idx = np.where(g == grp)[0]; yw[idx] = rng.permutation(y[idx])
    rows_w = [dict(r, label=int(yw[i])) for i, r in enumerate(rows_a)]
    o3, _ = nested_oof(rows_w); v3 = ~np.isnan(o3)
    ctrl["C1b_within_perm_auc"] = round(float(roc_auc_score(yw[v3], o3[v3])), 4) if len(set(yw[v3])) == 2 else None
    # C2 workload/marker placebo: negatives only -> twin(1) vs gen2-60(0); AUC>0.5 = attack-scenario
    # clean writes distinguishable from natural clean (workload confound)
    plac = [dict(r, label=1, scenario=r["scenario"]) for r in twin_rows] + \
           [dict(r, label=0) for r in g60_rows]
    yp2 = np.array([r["label"] for r in plac]); gp2 = np.array([r["scenario"] for r in plac])
    op2, _ = nested_oof(plac); vp2 = ~np.isnan(op2)
    ctrl["C2_workload_placebo_auc"] = round(float(roc_auc_score(yp2[vp2], op2[vp2])), 4) if len(set(yp2[vp2])) == 2 else None
    ctrl["C2_note"] = "twin(=attack-scenario clean) vs gen2-60(natural clean); >0.5 ⇒ workload confound in the FPR comparison"
    # C3 positive control
    synth = (0.95 * y + rng.normal(0, 1, len(y))).reshape(-1, 1)
    rows_c3 = [dict(r) for r in rows_a]
    for i, r in enumerate(rows_c3):
        r["_synth"] = float(synth[i, 0])
    # quick: add synth as extra feature via A3 + column
    def c3_oof():
        yy = np.array([r["label"] for r in rows_c3]); gg = np.array([r["scenario"] for r in rows_c3])
        oofc = np.full(len(rows_c3), np.nan)
        for grp in sorted(set(gg)):
            te = np.where(gg == grp)[0]; tr = np.where(gg != grp)[0]
            if len(set(yy[tr])) < 2: continue
            Xtr, nm = build([rows_c3[i] for i in tr], "A3", impute_from=[rows_c3[i] for i in tr])
            Xte, _ = build([rows_c3[i] for i in te], "A3", impute_from=[rows_c3[i] for i in tr])
            Xtr = np.hstack([Xtr, synth[tr]]); Xte = np.hstack([Xte, synth[te]])
            scl = StandardScaler().fit(Xtr); np.random.seed(SEED)
            m = model("l1_logreg").fit(scl.transform(Xtr), yy[tr])
            oofc[te] = m.predict_proba(scl.transform(Xte))[:, 1]
        return yy, gg, oofc
    yy, gg, oofc = c3_oof(); vc = ~np.isnan(oofc)
    ctrl["C3_positive_auc"] = round(float(roc_auc_score(yy[vc], oofc[vc])), 4)
    # identity ablation: A1 (with bucket) vs A3 (core) fixed-variant nested by model only
    def fixed_auc(variant):
        oofx = np.full(len(rows_a), np.nan)
        for grp in sorted(set(g)):
            te = np.where(g == grp)[0]; tr = np.where(g != grp)[0]
            if len(set(y[tr])) < 2: continue
            oofx[te] = fit_predict([rows_a[i] for i in tr], [rows_a[i] for i in te], variant, "l1_logreg")
        vx = ~np.isnan(oofx)
        return round(float(roc_auc_score(y[vx], oofx[vx])), 4)
    ctrl["identity_ablation"] = {"A1_with_identity_l1": fixed_auc("A1"), "A3_core_l1": fixed_auc("A3"),
                                 "A4_absdsize_l1": fixed_auc("A4")}
    out["substrate_a_twin_base"]["controls"] = ctrl

    # ---- base (b) gen2-60 ----
    # Secondary absolute-delta contrast retained for provenance; it is not the primary model row.
    # Its attack score uses scenario LOSO and its FPR denominator is the natural-clean test pool.
    g176_rows = []
    for r in pool1:
        if r["run_id"] in train_ops:
            f, _ = run_feature(clean_pool_dir("training", r["run_id"]), "train::" + r["scenario_id"], r["profile"], 0, "clean_training")
            g176_rows.append(f)
    out["supervised_primary"] = primary_supervised_results(atk_rows, g176_rows, g60_rows)

    rows_b = atk_rows + g176_rows
    yb = np.array([r["label"] for r in rows_b]); gb = np.array([r["scenario"] for r in rows_b])
    # Secondary attack predictions only; the primary supervised rows use grouped five-fold CV above.
    atk_scen = sorted(set(r["scenario"] for r in atk_rows))
    oofb = np.full(23, np.nan)
    for grp in atk_scen:
        te = [i for i, r in enumerate(atk_rows) if r["scenario"] == grp]
        tr_atk = [i for i, r in enumerate(atk_rows) if r["scenario"] != grp]
        tr_rows = [atk_rows[i] for i in tr_atk] + g176_rows
        pr = fit_predict(tr_rows, [atk_rows[i] for i in te], "A4", "l1_logreg")
        for j, i in enumerate(te):
            oofb[i] = pr[j]
    # threshold on |Δsize| at FPR<=b1_g60_fpr over gen2-176
    v176 = np.array([r["abs_delta_size"] for r in g176_rows], dtype=float)
    thr = None
    for t in sorted(set(v176), reverse=True):
        if (v176 >= t).mean() <= b1_g60_fpr:
            thr = t
        else:
            break
    va = np.array([r["abs_delta_size"] for r in atk_rows], dtype=float)
    v60 = np.array([r["abs_delta_size"] for r in g60_rows], dtype=float)
    sup_tpr_b = round(float((va >= thr).mean()), 4) if thr is not None else None
    sup_fpr_60 = round(float((v60 >= thr).mean()), 4) if thr is not None else None
    auc_b = round(float(roc_auc_score(np.r_[np.ones(23), np.zeros(len(g60_rows))],
                                      np.r_[va, v60])), 4)
    out["substrate_a_gen2_60_base"] = {
        "N": {"pos": 23, "neg_gen2_60": 60},
        "abs_delta_size_threshold": (float(thr) if thr is not None else None),
        "supervised_TPR": sup_tpr_b, "supervised_FPR_gen2_60": sup_fpr_60,
        "auc_vs_gen2_60": auc_b,
        "b1_gen2_60": {"TPR": round(b1_atk / 23, 4), "FPR": round(b1_g60 / 60, 4)},
        "b2_gen2_60": {"TPR": round(b2_atk / 23, 4), "FPR": round(b2_g60 / 60, 4)},
        "C2_workload_placebo_auc_beside": ctrl["C2_workload_placebo_auc"],
        "caveat": "gen2-60 is natural clean on the same host; C2 workload placebo beside it quantifies residual workload confound"}

    # ================= SUBSTRATE B (twin base) =================
    out["substrate_b_twin_base"] = run_substrate_b()

    # Never overwrite the published numbers. Substrate A recomputes exactly from
    # the released corpus. Substrate B does not, and cannot: its stream selector
    # was an unordered glob, and six of the 46 streams it reads have more than
    # one distinct copy on disk -- sixteen, for C512's clean twin. Which copy the
    # published fit used was never recorded. The selector here is deterministic
    # now, which makes the release self-consistent but does not recover the
    # shipped figures. See docs/results.md, "Section 5.2: substrate A reproduces
    # exactly; substrate B cannot".
    shipped = OUTDIR / "FINAL_3POOL_SUPERVISED.json"
    if shipped.exists() and json.load(open(shipped)) != out:
        side = OUTDIR / "FINAL_3POOL_SUPERVISED.recomputed.json"
        json.dump(out, open(side, "w"), indent=2)
        _verdict = (f"\nrecomputation DIFFERS from the shipped file -- wrote {side.name} "
                    f"and left the published one untouched.\n"
                    f"  shipped    nested-CV AUC {json.load(open(shipped))['substrate_a_twin_base']['nested_cv_auc']}\n"
                    f"  recomputed nested-CV AUC {out['substrate_a_twin_base']['nested_cv_auc']}\n"
                    f"  substrate A should match exactly; a substrate B difference is expected --\n"
                    f"  see docs/results.md, 'Section 5.2: substrate A reproduces exactly'.")
    else:
        json.dump(out, open(shipped, "w"), indent=2)
        _verdict = "\nrecomputation matches the shipped file"
    print(json.dumps({"validation": validation,
                      "A_twin": {"auc": auc_a, "ci": ci_a, "TPR": sup_tpr_twin, "FPR_twin": sup_fpr_twin,
                                 "mcnemar": {k: {"attack": mcn[k]["attack_side"], "twin": mcn[k]["twin_side"]} for k in mcn}},
                      "A_gen60": {"TPR": sup_tpr_b, "FPR": sup_fpr_60, "auc": auc_b},
                      "controls": ctrl}, indent=2))
    print(_verdict)


def run_substrate_b():
    """n-gram L1-LR + RuleFit on 23 attack + 23 twin (BRL non-terminating, dropped)."""
    from sklearn.linear_model import LogisticRegression as LR
    from imodels import RuleFitClassifier
    N = 6; MINDF = 2
    def ngr(path):
        grouped = defaultdict(lambda: defaultdict(list))
        with open(path) as fh:
            for line in fh:
                if not line.strip(): continue
                r = json.loads(line)
                if not r.get("sequence_eligible", False): continue
                if not r.get("syscall", {}).get("success"): continue
                p = r.get("process") or {}
                ex = p.get("exe") or p.get("comm") or "?"
                ident = p.get("identity_key") or f"{r.get('run_id')}:{p.get('pid')}"
                grouped[ex][f"{r.get('run_id')}::{ident}"].append(r["syscall"]["name"])
        s = set()
        for insts in grouped.values():
            for seq in insts.values():
                if len(seq) >= N:
                    for i in range(len(seq) - N + 1):
                        s.add(tuple(seq[i:i + N]))
        return s
    def findnorm(rid):
        """Deterministic, in the same order as locate().

        The original was glob("**/<rid>/graph/normalized/...")[0], whose result
        depends on directory traversal order whenever a run has more than one
        copy on disk -- which several do. Fix the order explicitly: staging is
        the substrate the published rows were scored from, then the corpus
        pools, then whatever the collection-host trees still offer.
        """
        rel = "graph/normalized/syscalls.jsonl"
        cands = [STAGE / rid / rel]
        cands += [ARCHIVE / sub / rid / rel for sub in ARCHIVE_SUBDIRS]
        for c in cands:
            if c.is_file():
                return str(c)
        h = sorted(glob.glob(str(RES / f"**/{rid}/{rel}"), recursive=True))
        return h[0] if h else None
    run_sets, y, g = [], [], []
    for rid in SUB:
        pp = findnorm(rid); cp = findnorm(rid.replace("__poisoned", "__clean"))
        if not pp or not cp: continue
        scen = FOLD.get(rid, rid)
        run_sets.append(ngr(pp)); y.append(1); g.append(scen)
        run_sets.append(ngr(cp)); y.append(0); g.append(scen)
    y = np.array(y); g = np.array(g)
    def oof_b(mfac):
        oof = np.full(len(y), np.nan)
        for grp in sorted(set(g)):
            te = np.where(g == grp)[0]; tr = np.where(g != grp)[0]
            if len(set(y[tr])) < 2: continue
            df = defaultdict(int)
            for i in tr:
                for gm in run_sets[i]: df[gm] += 1
            vocab = sorted([k for k, c in df.items() if c >= MINDF])
            if not vocab: continue
            idx = {gm: j for j, gm in enumerate(vocab)}
            Xtr = np.zeros((len(tr), len(vocab))); Xte = np.zeros((len(te), len(vocab)))
            for a, i in enumerate(tr):
                for gm in run_sets[i]:
                    if gm in idx: Xtr[a, idx[gm]] = 1
            for a, i in enumerate(te):
                for gm in run_sets[i]:
                    if gm in idx: Xte[a, idx[gm]] = 1
            np.random.seed(SEED)
            m = mfac().fit(Xtr, y[tr])
            oof[te] = m.predict_proba(Xte)[:, 1]
        return oof
    res = {}
    for nm, fac in (("l1_logreg", lambda: LR(penalty="l1", solver="liblinear", C=0.5, max_iter=5000, random_state=SEED)),
                    ("rulefit", lambda: RuleFitClassifier(max_rules=8, random_state=SEED))):
        oof = oof_b(fac); v = ~np.isnan(oof)
        res[nm] = round(float(roc_auc_score(y[v], oof[v])), 4) if len(set(y[v])) == 2 else None
    return {"N": {"pos": int(y.sum()), "neg_twin": int((1 - y).sum()), "scenarios": len(set(g))},
            "auc": res, "brl": "NON-TERMINATING (dropped; same caveat as CORELS substitution)",
            "note": "gen2-60 base unavailable for substrate B (pool carries reattr, not normalized stream)"}


if __name__ == "__main__":
    main()
