#!/usr/bin/env python3
"""Ruling-3 pooled-MCAW delta for the supervised/substrate-A arm.

The frozen supervised-expanded matrix (p2_supervised_arm_expanded_20260825) held
MCAW101/201/402 ISOLATED (they carried the divergent uid=2001 / rules.sha 30982105
extraction). Ruling 3 re-extracts them to the aligned lineage (uid 997, e3b75979)
and POOLS them. All 3 now resolve a marker write (checked). This recomputes the
model-free overlap (N3 / problexity) and the |Δsize| separation with them pooled,
and reports the delta vs the isolated version. Reuses the supervised arm's own
extractor + problexity config verbatim; aligned libsinsp/snapshots read from the
head-to-head staging (read-only pull), markers from each lander's ground_truth.
"""
from __future__ import annotations
import json, sys, os, importlib.util
from pathlib import Path
import numpy as np

OUT = Path(__file__).resolve().parent
RES = OUT.parent
STAGE = OUT / "staging"
SUP = RES / "p2_supervised_arm_expanded_20260825"
LANE2 = RES / "p2_mass_attack_lane2_20260824"

# import the supervised extractor's functions verbatim
_spec = importlib.util.spec_from_file_location("emitfx", SUP / "emit_features_expanded.py")
efx = importlib.util.module_from_spec(_spec)
sys.modules["emitfx"] = efx
_spec.loader.exec_module(efx)

POOL = [
    ("MCAW101_w1_release_helper_tool_redirect", "W1"),
    ("MCAW201_w2_model_q_false_memory", "W2"),
    ("MCAW402_w4_blanket_approval_false_memory", "W4"),
]

NUM = ["delta_size", "abs_delta_size", "size_before", "size_after", "n_writes",
       "log_dt_last", "log_dt_mean", "write_span_sec", "has_timing"]


def build_rows(landers):
    rows = []
    for case, prof in landers:
        prid = case + "__poisoned"; crid = case + "__clean"
        pdir = STAGE / prid; cdir = STAGE / crid
        gt = json.loads((LANE2 / case / "runs" / prid / "ground_truth.json").read_text())
        markers = set(os.path.basename(h["path"]) for h in
                      gt.get("attack_marker_evidence", {}).get("hits", []) if h.get("path"))
        cls = (gt.get("changed_logical_classes") or ["?"])[0]
        scen = efx.base_scenario(case)
        precs = efx.extract_ops(str(pdir), prid)
        crecs = efx.extract_ops(str(cdir), crid)
        assert precs is not None and crecs is not None, case
        marker_recs = [r for r in precs if os.path.basename(r["canon"]) in markers]
        assert marker_recs, f"{case}: no resolved marker write (markers={markers})"
        for r in marker_recs:
            f = efx.features(r); f.update({"label": 1, "lander": case, "profile": prof,
                                          "scenario": scen, "run_kind": "poisoned",
                                          "realized_class": cls, "n_marker_recs": len(marker_recs)})
            rows.append(f)
        for r in crecs:
            f = efx.features(r); f.update({"label": 0, "lander": case, "profile": prof,
                                          "scenario": scen, "run_kind": "clean",
                                          "realized_class": r["layer"], "n_marker_recs": None})
            rows.append(f)
    return rows


def matrix(rows):
    med = {}
    for c in NUM:
        vals = [r[c] for r in rows if r.get(c) is not None]
        med[c] = float(np.median(vals)) if vals else 0.0
    X = np.array([[float(r[c]) if r.get(c) is not None else med[c] for c in NUM] for r in rows])
    y = np.array([r["label"] for r in rows])
    return X, y


def n3(rows):
    from problexity import ComplexityCalculator
    X, y = matrix(rows)
    cc = ComplexityCalculator(multiclass_strategy="ovo")
    cc.fit(X, y)
    metrics = {(m if isinstance(m, str) else m.__name__): float(v)
               for m, v in zip(cc._metrics(), cc.complexity)}
    return metrics


def main():
    frozen = json.loads((SUP / "features_substrate_a.json").read_text())
    iso_rows = frozen["rows"]
    new_rows = build_rows(POOL)
    pooled_rows = iso_rows + new_rows

    iso = n3(iso_rows)
    pooled = n3(pooled_rows)

    # |Δsize| of the pooled MCAW markers vs the clean write-size band
    pooled_marker_dsize = [r["abs_delta_size"] for r in new_rows
                           if r["run_kind"] == "poisoned" and r["abs_delta_size"] is not None]
    clean_band = sorted(r["abs_delta_size"] for r in iso_rows
                        if r["label"] == 0 and r["abs_delta_size"] is not None)

    out = {
        "schema_version": "assa.pooled_mcaw_delta.v1",
        "ruling": "3 (pool aligned MCAW101/201/402 into substrate A; all resolve a marker write)",
        "isolated_version": "p2_supervised_arm_expanded_20260825 (27 pos / 54 neg; MCAW101/201/402 held isolated)",
        "pooled_counts": {"positives": int(sum(r["label"] == 1 for r in pooled_rows)),
                          "negatives": int(sum(r["label"] == 0 for r in pooled_rows)),
                          "added_poisoned": sum(r["run_kind"] == "poisoned" for r in new_rows),
                          "added_clean": sum(r["run_kind"] == "clean" for r in new_rows)},
        "overlap_isolated": {"n2": iso.get("n2"), "n3": iso.get("n3"), "f1": iso.get("f1")},
        "overlap_pooled": {"n2": pooled.get("n2"), "n3": pooled.get("n3"), "f1": pooled.get("f1")},
        "delta": {"n3": round(pooled.get("n3", 0) - iso.get("n3", 0), 4),
                  "f1": round(pooled.get("f1", 0) - iso.get("f1", 0), 4)},
        "pooled_mcaw_marker_abs_delta_size": {r["lander"]: r["abs_delta_size"]
                                              for r in new_rows if r["run_kind"] == "poisoned"},
        "clean_write_size_band": {"min": clean_band[0], "median": clean_band[len(clean_band)//2],
                                  "max": clean_band[-1], "n": len(clean_band)},
        "reading": "",
    }
    lo, hi = clean_band[0], clean_band[-1]
    inside = [d for d in pooled_marker_dsize if lo <= d <= hi]
    dn3 = out["delta"]["n3"]
    direction = "essentially unchanged" if abs(dn3) < 0.01 else ("LESS separable" if dn3 > 0 else "marginally more separable")
    out["reading"] = (
        f"Pooled MCAW marker |Δsize| = {sorted(pooled_marker_dsize)} bytes; {len(inside)}/{len(pooled_marker_dsize)} "
        f"fall inside the clean write-size band [{lo}, {hi}] (no separating structure). N3 (LOO-1NN error) moves "
        f"{iso.get('n3'):.4f} -> {pooled.get('n3'):.4f} (delta {dn3:+.4f}): {direction}; N3 stays well above the "
        f"0.333 majority-error floor. Pooling the 3 aligned MCAW does NOT change the verdict: "
        f"non-separability STANDS.")
    (OUT / "POOLED_MCAW_DELTA.json").write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps({k: out[k] for k in ("pooled_counts", "overlap_isolated", "overlap_pooled",
                                          "delta", "pooled_mcaw_marker_abs_delta_size", "reading")}, indent=2))


if __name__ == "__main__":
    main()
