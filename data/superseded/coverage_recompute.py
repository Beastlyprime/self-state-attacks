#!/usr/bin/env python3
"""STEP 4: recompute 23-cell coverage after um + content-injection + memory
poisoning landed. Uses the SAME labeling rule as GRANULARITY_LABELS_20260824
(target from changed file, mechanism from diff rem/add, granularity from the
changed byte region), applied to the new landers' LOCAL state_diffs +
ground_truth clean-twin pre/post image byte counts.
"""
from __future__ import annotations
import json, glob, re
from pathlib import Path

RES = Path(__file__).resolve().parents[1]
OUT = Path(__file__).resolve().parent
GLAB = RES / "p2_mass_attack_collection_20260823/GRANULARITY_LABELS_20260824.json"

NEW = [
    # (case_id, target_hint) ; target computed from changed file below
    "MCAW101_w1_release_helper_tool_redirect",
    "MCAW102_w1_automerge_instruction_backdoor",
    "MCAW201_w2_model_q_false_memory",
    "MCAW202_w2_citation_tool_redirect",
    "MCAW401_w4_engagement_persona_drift",
    "MCAW402_w4_blanket_approval_false_memory",
    "MUC01_w1_provider_relay_um", "MUC02_w1_schedule_mail_um",
    "MUC03_w2_provider_relay_um", "MUC04_w2_schedule_mail_um",
    "MUC05_w4_provider_relay_um", "MUC06_w4_schedule_mail_um",
    "MUI01_w1_tools_cred_relay_um", "MUI02_w1_agents_post_mirror_um",
    "MUI03_w2_tools_cred_relay_um", "MUI04_w2_agents_post_mirror_um",
    "MUI05_w4_tools_cred_relay_um", "MUI06_w4_agents_post_mirror_um",
]

TARGET = {"MEMORY.md": "Mem", "openclaw.json": "Cfg",
          "AGENTS.md": "Inst", "TOOLS.md": "Inst"}


def find_poisoned(case_id):
    hits = [h for h in glob.glob(str(RES / f"p2_mass_attack_lane*/**/runs/{case_id}__poisoned"), recursive=True)
            if Path(h).is_dir() and "/.openclaw/" not in h]
    return Path(sorted(hits, key=len)[0]) if hits else None


def diff_bytes(diff_path: Path):
    """Return (added, removed) bytes from a unified diff."""
    add = rem = 0
    for line in diff_path.read_text(errors="replace").splitlines():
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue
        if line.startswith("+"):
            add += len(line) - 1
        elif line.startswith("-"):
            rem += len(line) - 1
    return add, rem


def granularity(region, file_bytes):
    if file_bytes and region >= 0.8 * file_bytes:
        return "G1"
    if region >= 257:
        return "G2"
    if region >= 17:
        return "G3"
    return "G4"


def label(case_id):
    p = find_poisoned(case_id)
    if not p:
        return {"case_id": case_id, "local": False, "cell": None,
                "note": "not locally mirrored; label deferred (needs bundle)"}
    diffs = list((p / "state_diffs").glob("*.diff")) if (p / "state_diffs").is_dir() else []
    gt = json.loads((p / "ground_truth.json").read_text())
    # target file
    changed = diffs[0].name.replace(".diff", "") if diffs else None
    target = TARGET.get(changed, "Inst" if changed and changed.endswith(".md") else ("Cfg" if changed and changed.endswith(".json") else "?"))
    add, rem = diff_bytes(diffs[0]) if diffs else (0, 0)
    # clean-twin pre/post for file size + append-vs-modify
    pre = post = None
    try:
        cand = (gt.get("route_a_anchor_evidence", {}).get("candidates") or [{}])[0]
        pre = cand.get("clean_twin", {}).get("preimage", {}).get("bytes")
        post = cand.get("clean_twin", {}).get("postimage", {}).get("bytes")
    except Exception:
        pass
    mech = "M1" if rem > 0 else "M2"   # in-place modify vs pure add/append
    region = max(add, rem)
    gran = granularity(region, post or pre or 0)
    cell = f"{target}-{mech}-{gran}"
    return {"case_id": case_id, "local": True, "changed_file": changed,
            "target": target, "mechanism": mech, "granularity": gran,
            "added_bytes": add, "removed_bytes": rem, "preimage_bytes": pre,
            "postimage_bytes": post, "cell": cell}


def main():
    g = json.loads(GLAB.read_text())["coverage_after_labeling"]
    covered_before = set(g["cells_covered_after"])          # 10
    missing_before = set(g["cells_still_missing"])           # 13
    all_cells = covered_before | missing_before             # 23
    assert len(all_cells) == 23, len(all_cells)

    new_labels = [label(c) for c in NEW]
    new_cells_local = {r["cell"] for r in new_labels if r.get("local") and r.get("cell")}
    filled = (new_cells_local & missing_before)
    covered_after = covered_before | (new_cells_local & all_cells)
    still_missing = all_cells - covered_after

    payload = {
        "schema_version": "assa.headtohead_coverage_recompute.v1",
        "created": "2026-08-25",
        "labeling_rule_source": "GRANULARITY_LABELS_20260824.json (same rule reused)",
        "provisional": "um + content-injection polarity await morning sign-off; the 26 file-op verdicts are user-signed",
        "coverage_before": {"covered": f"{len(covered_before)}/23", "cells": sorted(covered_before)},
        "new_lander_labels": new_labels,
        "new_cells_observed_local": sorted(new_cells_local),
        "cells_newly_filled_by_new_landers": sorted(filled),
        "coverage_after": {"covered": f"{len(covered_after)}/23", "cells": sorted(covered_after)},
        "cells_still_missing_after": sorted(still_missing),
        "caveats": {
            "not_local_deferred": [r["case_id"] for r in new_labels if not r["local"]],
            "note": "cells outside the 23-cell frame (if any new label lands on an off-matrix combo) are listed in new_cells_observed_local but not counted toward /23.",
            "off_matrix_new_cells": sorted(new_cells_local - all_cells),
        },
    }
    (OUT / "COVERAGE_23CELL_RECOMPUTE.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print("coverage_before:", payload["coverage_before"]["covered"])
    print("coverage_after :", payload["coverage_after"]["covered"])
    print("newly filled   :", payload["cells_newly_filled_by_new_landers"])
    print("still missing  :", payload["cells_still_missing_after"])
    print("off-matrix new :", payload["caveats"]["off_matrix_new_cells"])
    print("deferred(not local):", payload["caveats"]["not_local_deferred"])


if __name__ == "__main__":
    main()
