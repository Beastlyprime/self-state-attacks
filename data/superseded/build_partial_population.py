#!/usr/bin/env python3
"""D3 partial head-to-head: lock the population and emit the read-only sync plan.

Governance: dedup by EXPLICIT run-dir path (never basename glob). Same population
for the methods that CAN evaluate it; cells that cannot are marked non-evaluable,
not dropped. FPR denominator = the natural held-out 40 (frozen 20 + admitted
top-up 20), never the paired twins. Twins are synced ONLY as the ours-B1/B2
z-score baseline (auxiliary control, the frozen B1/B2 convention), never counted
as FPR.
"""
from __future__ import annotations
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent
RES = OUT.parent

VM91 = "<GUEST_HOST_B>"   # assa-stageg  (um)
VM69 = "<GUEST_HOST_C>"   # assa-stageg2 (content-injection)
VM24 = "<GUEST_HOST_A>"   # assa-guest   (clean-40)

# ---- 18 graph-present attacks: (case_id, op_sig, profile, vm, remote_run_parent) ----
# remote_run_parent = dir that contains <case>__poisoned and <case>__clean
UM = [
    ("MUC01_w1_provider_relay_um", "um_cfg", "W1", VM91, "p2_mass_attack_lane1_20260824/batch04_w1_muc01/runs"),
    ("MUC02_w1_schedule_mail_um", "um_cfg", "W1", VM91, "p2_mass_attack_lane1_20260825/MUC02_w1_schedule_mail_um/runs"),
    ("MUC03_w2_provider_relay_um", "um_cfg", "W2", VM91, "p2_mass_attack_lane1_20260825/MUC03_w2_provider_relay_um/runs"),
    ("MUC04_w2_schedule_mail_um", "um_cfg", "W2", VM91, "p2_mass_attack_lane1_20260825/MUC04_w2_schedule_mail_um/runs"),
    ("MUC05_w4_provider_relay_um", "um_cfg", "W4", VM91, "p2_mass_attack_lane1_20260825/MUC05_w4_provider_relay_um/runs"),
    ("MUC06_w4_schedule_mail_um", "um_cfg", "W4", VM91, "p2_mass_attack_lane1_20260825/MUC06_w4_schedule_mail_um/runs"),
    ("MUI01_w1_tools_cred_relay_um", "um_inst", "W1", VM91, "p2_mass_attack_lane1_20260824/batch04_um_profile_spread_w1_limit1/runs"),
    ("MUI02_w1_agents_post_mirror_um", "um_inst", "W1", VM91, "p2_mass_attack_lane1_20260824/batch04_w1_mui02/runs"),
    ("MUI03_w2_tools_cred_relay_um", "um_inst", "W2", VM91, "p2_mass_attack_lane1_20260825/MUI03_w2_tools_cred_relay_um/runs"),
    ("MUI04_w2_agents_post_mirror_um", "um_inst", "W2", VM91, "p2_mass_attack_lane1_20260825/MUI04_w2_agents_post_mirror_um/runs"),
    ("MUI05_w4_tools_cred_relay_um", "um_inst", "W4", VM91, "p2_mass_attack_lane1_20260825/MUI05_w4_tools_cred_relay_um/runs"),
    ("MUI06_w4_agents_post_mirror_um", "um_inst", "W4", VM91, "p2_mass_attack_lane1_20260825/MUI06_w4_agents_post_mirror_um/runs"),
]
CINJ = [
    ("MCAW101_w1_release_helper_tool_redirect", "content_injection", "W1", VM69, "p2_mass_attack_lane2_20260824/MCAW101_w1_release_helper_tool_redirect/runs"),
    ("MCAW102_w1_automerge_instruction_backdoor", "content_injection", "W1", VM69, "p2_mass_attack_lane2_20260825/MCAW102_w1_automerge_instruction_backdoor/runs"),
    ("MCAW201_w2_model_q_false_memory", "content_injection", "W2", VM69, "p2_mass_attack_lane2_20260824/MCAW201_w2_model_q_false_memory/runs"),
    ("MCAW202_w2_citation_tool_redirect", "content_injection", "W2", VM69, "p2_mass_attack_lane2_20260825/MCAW202_w2_citation_tool_redirect/runs"),
    ("MCAW401_w4_engagement_persona_drift", "content_injection", "W4", VM69, "p2_mass_attack_lane2_20260825/MCAW401_w4_engagement_persona_drift/runs"),
    ("MCAW402_w4_blanket_approval_false_memory", "content_injection", "W4", VM69, "p2_mass_attack_lane2_20260824/MCAW402_w4_blanket_approval_false_memory/runs"),
]
GRAPH_ATTACKS = UM + CINJ

# ---- 26 file-op attacks (AIDE-only; snapshots LOCAL) ----
FILE_OPS = [
    ("MCH01_w1_memory_lockout", "chmod", "W1"), ("MCH02_w1_rules_worldwrite", "chmod", "W1"),
    ("MCH03_w2_memory_lockout", "chmod", "W2"), ("MCH04_w2_rules_worldwrite", "chmod", "W2"),
    ("MCH05_w4_memory_lockout", "chmod", "W4"), ("MCH06_w4_rules_worldwrite", "chmod", "W4"),
    ("MSI01_w1_shell_approval_gate", "semantic_inversion", "W1"),
    ("MSI02_w1_precommit_verification_disable", "semantic_inversion", "W1"),
    ("MSI03_w2_private_memory_prohibition_negation", "semantic_inversion", "W2"),
    ("MSI04_w2_citation_verification_disable", "semantic_inversion", "W2"),
    ("MSI05_w4_memory_scope_flip", "semantic_inversion", "W4"),
    ("MSI06_w4_external_action_default_flip", "semantic_inversion", "W4"),
    ("MTR01_w3_heartbeat_wipe", "truncate", "W3"), ("MTR02_w1_memory_wipe", "truncate", "W1"),
    ("MTR03_w1_tools_wipe", "truncate", "W1"), ("MTR04_w2_memory_wipe", "truncate", "W2"),
    ("MTR05_w2_tools_wipe", "truncate", "W2"), ("MTR06_w4_memory_wipe", "truncate", "W4"),
    ("MTR07_w4_heartbeat_wipe", "truncate", "W4"),
    ("MUL01_w3_tools_unlink", "unlink", "W3"), ("MUL02_w1_agents_unlink", "unlink", "W1"),
    ("MUL03_w1_tools_unlink", "unlink", "W1"), ("MUL04_w2_agents_unlink", "unlink", "W2"),
    ("MUL05_w2_memory_unlink", "unlink", "W2"), ("MUL06_w4_agents_unlink", "unlink", "W4"),
    ("MUL07_w4_user_unlink", "unlink", "W4"),
]

MEMORY_POISONING = {"MCAW201_w2_model_q_false_memory", "MCAW402_w4_blanket_approval_false_memory"}


def main():
    # topup-20 (admitted) from the ledger
    ledger = json.loads((RES / "p2_mass_natural_benign_20260824/CLEAN_BACKGROUND_LEDGER.json").read_text())
    topup = [a for a in ledger["attempts"] if a.get("readiness_passed") is True]
    assert len(topup) == 20, len(topup)
    # frozen-20 from the heldout freeze
    frozen = json.loads((RES / "p2_detection_20260820/P2_HELDOUT_CLEAN_FREEZE_20260821.json").read_text())["records"]
    assert len(frozen) == 20, len(frozen)

    # topup remote run dirs live under nested batch dirs; record parent globs by run_id
    topup_paths = json.loads((OUT / "_topup_paths.json").read_text()) if (OUT / "_topup_paths.json").is_file() else {}

    pop = {"schema_version": "assa.headtohead_partial_population.v1", "created": "2026-08-25",
           "label": "PARTIAL head-to-head. Graph detectors (STIDE, ours-B1/B2) cover the 18 "
                    "um/content-injection attacks + clean-40; file-op cells are AIDE-only; Falco "
                    "deferred (needs x86-64 replay, D2). NOT the full same-population comparison.",
           "polarity": "FINAL-all-malicious PROVISIONAL (um + content-injection await morning sign-off)",
           "fpr_denominator": "natural held-out 40 (frozen 20 + admitted top-up 20); twins are NOT FPR",
           "attacks_graph_present": [], "attacks_aide_only_fileop": [],
           "clean_heldout_40": [], "ours_baseline_twins": []}

    for case, op, prof, vm, parent in GRAPH_ATTACKS:
        pop["attacks_graph_present"].append({
            "population_id": f"graphattack::{case}__poisoned", "case_id": case, "run_id": case + "__poisoned",
            "op_signature": op, "profile": prof, "label": "attack_landed",
            "memory_poisoning_Mem_M1": case in MEMORY_POISONING,
            "sync": {"vm": vm, "remote_run": f"{parent}/{case}__poisoned",
                     "need": ["stide_syscalls", "libsinsp", "snapshots"]}})
        pop["ours_baseline_twins"].append({
            "population_id": f"twin::{case}__clean", "case_id": case, "run_id": case + "__clean",
            "op_signature": op, "profile": prof, "label": "clean_twin_baseline_only",
            "sync": {"vm": vm, "remote_run": f"{parent}/{case}__clean",
                     "need": ["libsinsp", "snapshots"]}})

    for case, op, prof in FILE_OPS:
        # local snapshots; no sync
        pop["attacks_aide_only_fileop"].append({
            "population_id": f"fileop::{case}__poisoned", "case_id": case, "run_id": case + "__poisoned",
            "op_signature": op, "profile": prof, "label": "attack_landed",
            "graph_detectors": "non_evaluable_no_offline_graph_derivation",
            "sync": None})

    for a in topup:
        rid = a["run_id"]
        pop["clean_heldout_40"].append({
            "population_id": f"heldout_topup::{rid}", "run_id": rid, "op_signature": "background_clean",
            "profile": a["profile"], "label": "clean", "source": "topup_ledger_20260824",
            "capture_scap_sha256": a.get("capture_scap_sha256"), "ground_truth_sha256": a.get("ground_truth_sha256"),
            "reuse_frozen_rows": {"STIDE": False, "AIDE": False},
            "sync": {"vm": VM24, "remote_run": topup_paths.get(rid),
                     "need": ["stide_syscalls", "libsinsp", "snapshots"]}})
    for r in frozen:
        rid = r["run_id"]
        pop["clean_heldout_40"].append({
            "population_id": f"heldout_frozen::{rid}", "run_id": rid, "op_signature": "background_clean",
            "profile": r["profile"], "label": "clean", "source": "P2_HELDOUT_CLEAN_FREEZE_20260821",
            "reuse_frozen_rows": {"STIDE": True, "AIDE": True, "Falco": True},
            "sync": {"vm": VM24, "remote_run": r["derived_run_dir"], "need": ["libsinsp", "snapshots"]}})

    pop["counts"] = {
        "attacks_graph_present": len(pop["attacks_graph_present"]),
        "attacks_aide_only_fileop": len(pop["attacks_aide_only_fileop"]),
        "clean_heldout_40": len(pop["clean_heldout_40"]),
        "ours_baseline_twins": len(pop["ours_baseline_twins"]),
        "clean_by_profile": {p: sum(1 for c in pop["clean_heldout_40"] if c["profile"] == p) for p in ("W1", "W2", "W3", "W4")},
    }
    (OUT / "PARTIAL_LOCKED_POPULATION.json").write_text(json.dumps(pop, indent=2, sort_keys=True) + "\n")
    print(json.dumps(pop["counts"], indent=2))


if __name__ == "__main__":
    main()
