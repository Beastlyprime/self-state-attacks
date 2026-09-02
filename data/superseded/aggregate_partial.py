#!/usr/bin/env python3
"""Aggregate the D3 partial head-to-head into a TPR+FPR table (per method, pooled +
per op-signature + granularity), FPR against the natural held-out 40. Falco deferred,
UNICORN non-evaluable, file-op cells graph-detector-non-evaluable (AIDE-only)."""
from __future__ import annotations
import json, math
from pathlib import Path

OUT = Path(__file__).resolve().parent
RES = OUT.parent


def read(p): return json.loads(Path(p).read_text())


def wilson(k, n, z=1.959963984540054):
    if not n: return {"k": k, "n": 0, "rate": None, "lo": None, "hi": None}
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt((p * (1 - p) + z * z / (4 * n)) / n) / d
    return {"k": k, "n": n, "rate": round(p, 4), "lo": round(max(0, c - h), 4), "hi": round(min(1, c + h), 4)}


def grp(rows):
    ev = [r for r in rows if r["status"] == "passed"]
    k = sum(1 for r in ev if r["binary_decision"] is True)
    w = wilson(k, len(ev))
    w["non_evaluable"] = sum(1 for r in rows if r["status"] != "passed")
    return w


def slice_by(rows, key):
    keys = sorted({r.get(key) for r in rows if r.get(key)})
    return {kk: grp([r for r in rows if r.get(key) == kk]) for kk in keys}


def granularity_map():
    cov = read(OUT / "COVERAGE_23CELL_RECOMPUTE.json")
    m = {}
    for r in cov.get("new_lander_labels", []):
        if r.get("local") and r.get("cell"):
            m[r["case_id"] + "__poisoned"] = {"cell": r["cell"], "granularity": r["granularity"]}
    # file-ops granularity from the frozen labels file
    try:
        g = read(RES / "p2_mass_attack_collection_20260823/GRANULARITY_LABELS_20260824.json")["labels"]
        for case, lab in g.items():
            m.setdefault(case + "__poisoned", {"cell": f"{lab.get('target','?')[:3]}-{lab['mechanism']}-{lab['granularity']}",
                                               "granularity": lab["granularity"]})
    except Exception:
        pass
    return m


def build_method(name, tpr_rows, fpr_rows, gmap, note=""):
    for r in tpr_rows:
        r["granularity"] = gmap.get(r["run_id"], {}).get("granularity")
    return {
        "method": name, "note": note,
        "pooled": {"TPR": grp(tpr_rows), "FPR": grp(fpr_rows)},
        "TPR_by_op_signature": slice_by(tpr_rows, "op_signature"),
        "TPR_by_granularity": slice_by([r for r in tpr_rows if r.get("granularity")], "granularity"),
        "FPR_by_profile": slice_by(fpr_rows, "profile"),
        "TPR_memory_poisoning": grp([r for r in tpr_rows if r.get("memory_poisoning")]),
    }


def main():
    gmap = granularity_map()
    methods = {}

    # AIDE
    if (OUT / "scored_aide.json").is_file():
        a = read(OUT / "scored_aide.json")["rows"]
        methods["AIDE"] = build_method("AIDE",
            [r for r in a if r["label"] == "attack_landed"],
            [r for r in a if r["label"] == "clean"], gmap,
            "content-delta snapshot AIDE; covers ALL 44 attacks incl file-ops; arm64 docker; offline")
    # STIDE
    if (OUT / "scored_stide.json").is_file():
        s = read(OUT / "scored_stide.json")["rows"]
        methods["STIDE"] = build_method("STIDE",
            [r for r in s if r["label"] == "attack_landed"],
            [r for r in s if r["label"] == "clean"], gmap,
            "frozen profile-conditioned STIDE; 18 graph-present attacks evaluable, 26 file-ops NON-EVALUABLE (no offline graph)")
    # ours B1/B2
    if (OUT / "scored_ours.json").is_file():
        o = read(OUT / "scored_ours.json")
        for arm in ("B1", "B2"):
            methods[f"ours_{arm}"] = build_method(f"ours-{arm}",
                o[arm]["attack_tpr"], o[arm]["clean_fpr"], gmap,
                "size+timing z-score; baseline=natural clean-40; 18 graph attacks evaluable, 26 file-ops NON-EVALUABLE; "
                "per-run decision (any self-state write >= TAU)")
    # Falco + UNICORN
    methods["Falco"] = {"method": "Falco", "status": "DEFERRED_D2",
                        "note": "requires x86-64 falco replay; no precomputed rows for new landers; offline-non-evaluable"}
    methods["UNICORN"] = {"method": "UNICORN", "status": "non_evaluable_no_rescore"}

    report = {
        "schema_version": "assa.headtohead_partial_report.v1", "created": "2026-08-25",
        "LABEL": "PARTIAL — graph detectors (STIDE, ours-B1/B2) cover the 18 um/content-injection landers + 40 clean; "
                 "file-op cells (chmod/semantic_inversion/truncate/unlink, 26) are AIDE-only; Falco deferred (D2); "
                 "NOT the full same-population comparison.",
        "polarity": "FINAL-all-malicious PROVISIONAL (um + content-injection await morning sign-off; file-op 26 user-signed)",
        "fpr_denominator": "natural held-out clean 40 (frozen 20 + admitted top-up 20); NOT paired twins",
        "population_counts": read(OUT / "PARTIAL_LOCKED_POPULATION.json")["counts"],
        "methods": methods,
    }
    (OUT / "PARTIAL_HEADTOHEAD_REPORT.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    # compact markdown
    def fmt(w):
        if not w or w.get("rate") is None: return f"n/a (n={w.get('n',0) if w else 0})"
        return f"{w['rate']:.3f} [{w['lo']:.2f},{w['hi']:.2f}] {w['k']}/{w['n']}" + (f" (+{w['non_evaluable']}NE)" if w.get('non_evaluable') else "")
    lines = ["# PARTIAL head-to-head (#33) — expanded corpus, offline (2026-08-25)", "",
             report["LABEL"], "", f"Polarity: {report['polarity']}", f"FPR denominator: {report['fpr_denominator']}", "",
             "| Method | pooled TPR | pooled FPR | um_cfg TPR | um_inst TPR | content_injection TPR | Mem-poison TPR |",
             "|---|---|---|---|---|---|---|"]
    for name in ("AIDE", "STIDE", "ours_B1", "ours_B2"):
        if name not in methods or "pooled" not in methods[name]: continue
        m = methods[name]; op = m["TPR_by_op_signature"]
        lines.append(f"| {name} | {fmt(m['pooled']['TPR'])} | {fmt(m['pooled']['FPR'])} | "
                     f"{fmt(op.get('um_cfg'))} | {fmt(op.get('um_inst'))} | {fmt(op.get('content_injection'))} | {fmt(m['TPR_memory_poisoning'])} |")
    lines += ["| Falco | DEFERRED (D2: x86-64 replay) | — | — | — | — | — |",
              "| UNICORN | non-evaluable | — | — | — | — | — |", ""]
    # AIDE file-op slices
    if "AIDE" in methods and "pooled" in methods["AIDE"]:
        lines.append("## AIDE file-op cells (AIDE-only; graph detectors non-evaluable here)")
        op = methods["AIDE"]["TPR_by_op_signature"]
        for k in ("chmod", "semantic_inversion", "truncate", "unlink"):
            lines.append(f"- {k}: TPR {fmt(op.get(k))}")
    (OUT / "PARTIAL_HEADTOHEAD_TABLE.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
