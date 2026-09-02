#!/usr/bin/env python3
import json
from pathlib import Path
OUT = Path(__file__).resolve().parent
d = json.load(open(OUT / "FULL_HEADTOHEAD_REPORT.json"))
det = d["detectors"]
c = d["population_counts"]


def rate(x):
    r = x.get("rate")
    return "n/a" if r is None else f"{r:.3f}"


def cell(x):
    return f"{x['positive']}/{x['n']} ({rate(x)})"


L = []
L.append("# FULL head-to-head detector table (2026-08-25)")
L.append("")
L.append(f"**Generation** `{d['derivation_generation']}` (manifest content-address "
         f"`{d['manifest_content_address']}`).")
L.append("")
L.append("> **PROVISIONAL** — population is NOT frozen-signed. **Polarity: CONFIRMED-BY-USER** for the "
         "18 um/MCAW landers (signed 18-lander v2 worksheet 2026-08-25, "
         "sha `5b61cff8…0260ca36`); file-op canaries (MSI/MCH/MTR/MUL) are structural malice (file-op "
         "ruling). Scores unchanged (provisional-all-malicious was already applied).")
L.append("")
L.append("## Population (frozen manifest)")
L.append("")
L.append(f"- **Attack 44** by witness tier: **T1 writes 24** "
         f"(um_cfg 6, um_inst 6, content_injection/MCAW 6, semantic_inversion/MSI 6) + "
         f"**T2 metadata/namespace canaries 20** (chmod 6, truncate 7, unlink 7).")
L.append(f"- **Clean-40** natural held-out (split 42baa6a9): W1 11 / W2 12 / W3 8 / W4 9 "
         f"(FPR denominator for the unsupervised arms; NOT re-split).")
L.append(f"- **ours-B1/B2 definable = {c['b1b2_definable_n']}** (write-resolved: MUI 6 + MCAW 6, "
         f"incl aligned 101/201/402); **N/A = {c['b1b2_na_n']}** (26 file-op + MUC 6).")
L.append("")
L.append("## Head-to-head (TPR and FPR together)")
L.append("")
L.append("| detector | tier | fit-free | scored set / N/A | TPR (attack) | FPR |")
L.append("|---|---|---|---|---|---|")


def row(name, x, scored, tpr, fpr):
    ff = "yes" if x.get("fit_free") else "no"
    tier = x["tier"].split(" ")[0]
    L.append(f"| {name} | {tier} | {ff} | {scored} | {tpr} | {fpr} |")


row("AIDE", det["AIDE"], "all 44 / none",
    cell(det["AIDE"]["TPR"]), cell(det["AIDE"]["FPR"]) + " (clean-40)")
row("Falco", det["Falco"], "all 44 / none",
    cell(det["Falco"]["TPR"]), cell(det["Falco"]["FPR"]) + " (frozen-20 only; topup non-eval)")
row("STIDE", det["STIDE"], f"all 44 / DI {det['STIDE']['TPR']['data_insufficient_not_negative']}",
    cell(det["STIDE"]["TPR"]), cell(det["STIDE"]["FPR"]) + " (clean-40)")
row("ours-B1", det["ours_B1"], "12 write-resolved / 32 N/A",
    cell(det["ours_B1"]["TPR"]), cell(det["ours_B1"]["FPR"]) + " (clean-40 LOO)")
row("ours-B2", det["ours_B2"], "12 write-resolved / 32 N/A",
    cell(det["ours_B2"]["TPR"]), cell(det["ours_B2"]["FPR"]) + " (clean-40 LOO)")
L.append("| supervised (\\|Δsize\\|/L1) | T2 | no | 27 pos / 54 neg twins | 0.444 @ B1-FPR | 0.148 (paired twins) |")
L.append("| UNICORN | T2* | no | non-evaluable on this population | — | — |")
L.append("")
L.append("\\* UNICORN sketch/model pipeline (opaque) is excluded-class; the reusable gen5 "
         "role-typing reading is reported below, not re-scored on the 44.")
L.append("")
L.append("## Per-op-signature TPR (all N<8 underpowered)")
L.append("")
L.append("| op (tier) | N | AIDE | Falco | STIDE | ours-B1/B2 |")
L.append("|---|---|---|---|---|---|")
ops = [("um_cfg", "T1"), ("um_inst", "T1"), ("content_injection", "T1"),
       ("semantic_inversion", "T1"), ("chmod", "T2"), ("truncate", "T2"), ("unlink", "T2")]
falco_op = {"um_cfg": "user_message", "um_inst": "user_message"}
for op, tier in ops:
    n = c["by_op_signature"][op]

    def g(dname, key=op):
        by = det[dname]["TPR"]["by_op"]
        if key not in by:
            return "—"
        s = by[key]
        return f"{s['positive']}/{s['n']}"
    fk = falco_op.get(op, op)
    fcell = "—"
    if fk in det["Falco"]["TPR"]["by_op"]:
        s = det["Falco"]["TPR"]["by_op"][fk]
        fcell = f"{s['positive']}/{s['n']}" + (" (um pooled)" if op in falco_op else "")
    ours = f"{det['ours_B1']['TPR']['by_op'][op]['positive']}/{det['ours_B1']['TPR']['by_op'][op]['n']}" \
        if op in det["ours_B1"]["TPR"]["by_op"] else "N/A"
    L.append(f"| {op} ({tier}) | {n} | {g('AIDE')} | {fcell} | {g('STIDE')} | {ours} |")
L.append("")
L.append("## Layered-witness reading")
L.append("")
L.append(d["layered_witness_reading"])
L.append("")
L.append("## Non-separability headline")
L.append("")
L.append(d["non_separability_headline"])
L.append("")
L.append("## UNICORN (reusable gen5 role-typing)")
L.append("")
u = det["UNICORN"]["reusable_gen5_role_typing"]
L.append(f"- attack vs own-clean role-histogram L1 = **{u['attack_vs_own_clean_L1_mean']}**; "
         f"clean vs clean L1 = **{u['clean_vs_clean_L1_mean']}**.")
L.append(f"- {u['reading']}.")
L.append(f"- Status: {det['UNICORN']['status']} — {det['UNICORN']['reason']}")
L.append("")
L.append("## Supervised arm (expanded) + ruling-3 pooled-MCAW delta")
L.append("")
L.append("- " + d["detectors"]["supervised_expanded"]["bottom_line"])
pd = d["detectors"]["supervised_expanded"]["ruling3_pooled_mcaw_delta"]
L.append(f"- **Pooled MCAW101/201/402** (aligned, all resolve a marker write): "
         f"{pd['pooled_counts']['positives']} pos / {pd['pooled_counts']['negatives']} neg. "
         f"N3 {pd['n3_isolated']:.4f} → {pd['n3_pooled']:.4f} (Δ {pd['delta_n3']:+.4f}).")
L.append(f"- {pd['reading']}")
(OUT / "FULL_HEADTOHEAD_TABLE.md").write_text("\n".join(L) + "\n")
print("wrote FULL_HEADTOHEAD_TABLE.md")
