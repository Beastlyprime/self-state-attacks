"""Shared design-matrix builder for the supervised arm (substrate A).

Feature variants (design §5.4, identity ablation):
  A1 = core + context + identity   (bucket one-hot included)
  A2 = core + context              (identity ablated)  <- substantive arm
  A3 = core                        (context ablated too)
"""
import json
import numpy as np

CORE = ["delta_size", "abs_delta_size", "size_before", "size_after",
        "n_writes", "log_dt_last", "log_dt_mean", "write_span_sec", "has_timing"]
CONTEXT_CAT = ["layer", "profile"]
IDENTITY_CAT = ["bucket"]
SINGLE = ["abs_delta_size"]
VARIANTS = {"A1": (CORE, CONTEXT_CAT + IDENTITY_CAT),
            "A2": (CORE, CONTEXT_CAT),
            "A3": (CORE, []),
            "A4": (SINGLE, [])}  # single named feature -> reducible to one threshold rule


def load(path):
    return json.load(open(path))


def build(rows, variant, impute_from=None):
    """Return (X, names). impute_from: rows to take medians from (train fold);
    None => impute from `rows` themselves (only valid when there is no split)."""
    num, cats = VARIANTS[variant]
    src = impute_from if impute_from is not None else rows
    med = {}
    for f in num:
        vals = [r[f] for r in src if r[f] is not None]
        med[f] = float(np.median(vals)) if vals else 0.0
    levels = {c: sorted({r[c] for r in src}) for c in cats}

    names, cols = [], []
    for f in num:
        names.append(f)
        cols.append([float(r[f]) if r[f] is not None else med[f] for r in rows])
    for c in cats:
        for lv in levels[c]:
            names.append(f"{c}={lv}")
            cols.append([1.0 if r[c] == lv else 0.0 for r in rows])
    return np.array(cols, dtype=float).T, names


def labels(rows):
    return np.array([r["label"] for r in rows], dtype=int)


def groups(rows):
    return np.array([r["scenario"] for r in rows])
