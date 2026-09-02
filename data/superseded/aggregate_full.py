#!/usr/bin/env python3
"""FULL head-to-head aggregation -> FULL_HEADTOHEAD_{TABLE.md,REPORT.json}.

Rows: AIDE, Falco, STIDE, ours-B1, ours-B2, supervised(|Δsize|/L1), UNICORN(status).
Cols: tier, definability (scored set / N/A), TPR (+op slices), FPR, notes.
Every TPR flagged provisional-pending-polarity (ruling 5). FPR denominator =
clean-40 for the unsupervised arms (ruling 4); supervised uses paired twins.
"""
from __future__ import annotations
import json, math, hashlib
from collections import defaultdict
from pathlib import Path

OUT = Path(__file__).resolve().parent
RES = OUT.parent
TMP = Path("<SCRATCH>")
MAN = json.loads((OUT / "FROZEN_POPULATION_MANIFEST.json").read_text())
GEN = MAN["derivation_generation"]
UNDERPOWERED = 8


def wilson(pos, n):
    if n == 0:
        return {"rate": None, "n": 0, "positive": pos, "lower": None, "upper": None}
    z = 1.959963985
    p = pos / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return {"rate": round(p, 4), "n": n, "positive": pos,
            "lower": round((c - h) / d, 4), "upper": round((c + h) / d, 4)}


def slice_by_op(rows, decide, evaluable):
    out = {}
    by = defaultdict(list)
    for r in rows:
        by[r["op_signature"]].append(r)
    for op, rs in by.items():
        ev = [r for r in rs if evaluable(r)]
        pos = sum(1 for r in ev if decide(r))
        out[op] = {**wilson(pos, len(ev)), "total": len(rs),
                   "underpowered": len(ev) < UNDERPOWERED}
    return out


def load(p):
    return json.loads(Path(p).read_text())


# ------------------------------------------------------------------ ours
def agg_ours():
    d = load(OUT / "full_scored_ours.json")
    res = {}
    for arm in ("B1", "B2"):
        att = d[arm]["attack_tpr"]
        defin = [r for r in att if r["status"] == "passed"]  # only definable rows are 'passed'/'N/A'
        na = [r for r in att if r["status"] == "N/A"]
        pos = sum(1 for r in defin if r["binary_decision"])
        fpr = [r for r in d[arm]["clean_fpr"] if r["status"] == "passed"]
        fp = sum(1 for r in fpr if r["binary_decision"])
        res[arm] = {
            "tier": "T2", "auditable": True, "fit_free": False,
            "definability": {
                "scored_n": len(defin), "na_n": len(na),
                "scored_set": "write-resolved landers (MUI 6 + MCAW 6)",
                "na_set": "26 file-op (chmod/unlink/truncate/semantic_inversion) + MUC 6 (atomic-rename unresolved)",
            },
            "TPR": {**wilson(pos, len(defin)), "underpowered": len(defin) < UNDERPOWERED,
                    "by_op": slice_by_op(defin, lambda r: r["binary_decision"], lambda r: True)},
            "FPR": {**wilson(fp, len(fpr)), "denominator": "clean-40 leave-one-run-out"},
            "provisional": "TPR provisional-pending-polarity (ruling 5)",
        }
    return res


# ----------------------------------------------------------------- STIDE
def agg_stide():
    d = load(OUT / "full_scored_stide.json")
    att = [r for r in d["rows"] if r["side"] == "attack"]
    cln = [r for r in d["rows"] if r["side"] == "clean"]
    ev = [r for r in att if r["status"] == "passed"]
    di = [r for r in att if r["status"] == "data_insufficient"]
    pos = sum(1 for r in ev if r["binary_decision"])
    cev = [r for r in cln if r["status"] == "passed"]
    fp = sum(1 for r in cev if r["binary_decision"])
    return {
        "tier": "T2", "auditable": True, "fit_free": False,
        "definability": {"scored_n": len(att), "evaluable_n": len(ev),
                         "data_insufficient_n": len(di),
                         "scored_set": "all 44 (spine_effective; MCAW402 aligned normalized); data_insufficient is non-negative",
                         "na_set": "none (profile-conditioned; DI where no evaluable frozen-core executable)"},
        "TPR": {**wilson(pos, len(ev)), "underpowered": len(ev) < UNDERPOWERED,
                "data_insufficient_not_negative": len(di),
                "by_op": slice_by_op(att, lambda r: r["binary_decision"],
                                     lambda r: r["status"] == "passed")},
        "FPR": {**wilson(fp, len(cev)), "denominator": "clean-40 (frozen 20 reuse + topup 20 fresh)",
                "data_insufficient": sum(1 for r in cln if r["status"] == "data_insufficient")},
        "provisional": "TPR provisional-pending-polarity (ruling 5)",
    }


# ------------------------------------------------------------------ AIDE
def agg_aide():
    d = load(OUT / "full_scored_aide.json")
    att = [r for r in d["rows"] if r["side"] == "attack"]
    cln = [r for r in d["rows"] if r["side"] == "clean"]
    ev = [r for r in att if r["status"] == "passed"]
    pos = sum(1 for r in ev if r["binary_decision"])
    cev = [r for r in cln if r["status"] == "passed"]
    fp = sum(1 for r in cev if r["binary_decision"])
    return {
        "tier": "T1", "auditable": True, "fit_free": True,
        "definability": {"scored_n": len(att), "evaluable_n": len(ev),
                         "scored_set": "all 44 (canonical self-state snapshot delta); natural detector for metadata canaries",
                         "na_set": "none"},
        "TPR": {**wilson(pos, len(ev)), "underpowered": len(ev) < UNDERPOWERED,
                "failed_n": sum(1 for r in att if r["status"] == "failed"),
                "by_op": slice_by_op(att, lambda r: r["binary_decision"],
                                     lambda r: r["status"] == "passed")},
        "FPR": {**wilson(fp, len(cev)), "denominator": "clean-40 (frozen 20 reuse + topup 20 fresh)"},
        "provisional": "TPR provisional-pending-polarity (ruling 5)",
        "note": "AIDE detects the self-state CHANGE, not intent: fires on any canonical write incl benign self-writes.",
    }


# ----------------------------------------------------------------- Falco
def agg_falco():
    d91 = load(TMP / "d2_report.json")
    d69 = load(TMP / "d2_report_69.json")
    rows = []
    for r in d91["per_lander"]:
        rows.append({"run_id": r["run_id"], "op_signature": r["op_signature"],
                     "binary_decision": r["binary_decision"], "status": r["status"]})
    for r in d69["per_lander"]:
        rows.append({"run_id": r["run_id"], "op_signature": r["op_signature"],
                     "binary_decision": r["binary_decision"], "status": r["status"]})
    ev = [r for r in rows if r["status"] == "passed"]
    pos = sum(1 for r in ev if r["binary_decision"])
    # FPR: reuse frozen falco gen1 (20 heldout clean); topup 20 offline-non-evaluable
    fz = load(RES / "p2_detection_20260820/P2_DETECTOR_FPR_GEN1_20260821/falco/fpr_result.json")
    frows = [r for r in fz["rows"] if r.get("status") == "passed"]
    fp = sum(1 for r in frows if r["binary_decision"])
    return {
        "tier": "T1", "auditable": True, "fit_free": True,
        "definability": {"scored_n": len(rows), "evaluable_n": len(ev),
                         "scored_set": "all 44 (D2 precompute: 38 on .91 + 6 MCAW on .69; frozen rules 0.44.0)",
                         "na_set": "none for TPR"},
        "TPR": {**wilson(pos, len(ev)), "underpowered": len(ev) < UNDERPOWERED,
                "by_op": slice_by_op(rows, lambda r: r["binary_decision"],
                                     lambda r: r["status"] == "passed")},
        "FPR": {**wilson(fp, len(frows)),
                "denominator": "frozen 20 heldout clean ONLY (topup 20 offline-non-evaluable: needs x86-64 replay)",
                "coverage": "20/40 clean (partial)"},
        "provisional": "TPR provisional-pending-polarity (ruling 5)",
        "note": "fires on the mutation syscall; misses chmod (0/6) and unlink (1/7) canaries (metadata/namespace, relative-path operands).",
    }


# ------------------------------------------------------------- supervised
def agg_supervised():
    sup = load(RES / "p2_supervised_arm_expanded_20260825/REPORT.json")
    return sup


# ---------------------------------------------------------------- UNICORN
def agg_unicorn():
    hist = load(RES / "p2_unicorn_role_typing_gen5_20260823/ROLE_HISTOGRAM_CONTROL.json")
    ro = hist["ROLE_ONLY"]
    return {
        "tier": "T2 (provenance-graph anomaly); T3 sketch pipeline excluded-as-opaque",
        "status": "non_evaluable_on_this_population",
        "reason": "official sketch/model pipeline not re-scored on the 44-lander frozen population; "
                  "reusable finding = gen5 role-typing (on the prior content-append C-series landers).",
        "reusable_gen5_role_typing": {
            "attack_vs_own_clean_L1_mean": ro["paired_attack_vs_own_clean"]["L1_mean"],
            "clean_vs_clean_L1_mean": ro["control_clean_vs_clean"]["L1_mean"],
            "reading": "attack moves the provenance role histogram 3.2x LESS than natural benign "
                       "variation (%.4f vs %.4f) -> corroborates non-separability" % (
                           ro["paired_attack_vs_own_clean"]["L1_mean"],
                           ro["control_clean_vs_clean"]["L1_mean"]),
        },
    }


def main():
    ours = agg_ours()
    report = {
        "schema_version": "assa.p2_full_headtohead.v1",
        "derivation_generation": GEN,
        "manifest_content_address": MAN["manifest_content_address"],
        "provisional_flags": {
            "population_not_frozen_signed": True,
            "polarity": "CONFIRMED-BY-USER for the 18 um/MCAW landers (signed 18-lander v2 worksheet "
                        "2026-08-25, sha 5b61cff8cbb8e782559b353a4cd2784b2b11c0d90659c5c3fd5113c10260ca36); "
                        "file-op canaries (MSI/MCH/MTR/MUL) are structural malice (file-op ruling). "
                        "No score changes (provisional-all-malicious already applied).",
        },
        "polarity": MAN.get("polarity"),
        "population_counts": MAN["counts"],
        "fpr_denominator": "clean-40 natural held-out for unsupervised arms (ruling 4); "
                           "supervised arm uses paired __clean twins (confound-safe)",
        "detectors": {
            "AIDE": agg_aide(),
            "Falco": agg_falco(),
            "STIDE": agg_stide(),
            "ours_B1": ours["B1"],
            "ours_B2": ours["B2"],
            "supervised_expanded": {"ref": "p2_supervised_arm_expanded_20260825/REPORT.json",
                                    "bottom_line": "non-separability HOLDS (McNemar vs B1 p=0.388, vs B2 p=0.581); "
                                                   "adding aligned/new landers made substrate LESS separable "
                                                   "(N3 0.20->0.395, AUC 0.82->0.82/down)",
                                    "ruling3_pooled_mcaw_delta": (lambda d: {
                                        "n3_isolated": d["overlap_isolated"]["n3"],
                                        "n3_pooled": d["overlap_pooled"]["n3"],
                                        "delta_n3": d["delta"]["n3"],
                                        "pooled_counts": d["pooled_counts"],
                                        "marker_abs_delta_size": d["pooled_mcaw_marker_abs_delta_size"],
                                        "reading": d["reading"],
                                    })(load(OUT / "POOLED_MCAW_DELTA.json"))},
            "UNICORN": agg_unicorn(),
        },
        "layered_witness_reading": (
            "Write-detectors (ours-B1/B2, Falco open-write, STIDE) catch T1 write markers "
            "(um/MCAW/MSI) but are blind to T2 metadata/namespace canaries (chmod=Δsize0, "
            "unlink=removal, truncate=shrink): ours is N/A (structural), Falco misses chmod 0/6 "
            "and unlink 1/7. AIDE is the natural detector for the T2 metadata canaries (fires on "
            "any snapshot change) but cannot state intent (fires on benign self-writes too)."),
        "non_separability_headline": (
            "Under the confound-safe paired-twin baseline the supervised/ours arms do NOT separate "
            "malicious from benign self-state writes (McNemar n.s.; UNICORN role-histogram moves 3.2x "
            "LESS for attacks than benign variation). ours-B1/B2 on the clean-40 background baseline "
            "posts high TPR (12/12) at low FPR (5/40), but that separation is a WORKLOAD/TARGET-SELECTION "
            "confound: 13/40 clean-40 background runs never write self-state at all, so any attack write "
            "to a self-state file is unseen-key/high-z. It measures 'this task touches self-state', not "
            "'this write is malicious' — the same operation-detected != intent-separated limit as AIDE/Falco."),
    }
    (OUT / "FULL_HEADTOHEAD_REPORT.json").write_text(json.dumps(report, indent=2) + "\n")
    print("wrote FULL_HEADTOHEAD_REPORT.json")
    return report


if __name__ == "__main__":
    main()
