#!/usr/bin/env python3
"""FULL head-to-head: build the FROZEN POPULATION MANIFEST (44 attack + clean-40).

Culminating offline pass. Tiered-witness admission (ruling 1), D-B definability
(ruling 2), aligned-MCAW pooling (ruling 3), clean-40 FPR denominator (ruling 4),
provisional-all-malicious polarity (ruling 5). Content-addressed generation id.
"""
from __future__ import annotations
import json, os, hashlib, importlib.util
from pathlib import Path

OUT = Path(__file__).resolve().parent
RES = OUT.parent
STAGE = OUT / "staging"

# ---- op-signature -> (witness_tier, witness_mechanism, marker_write_resolved) ----
WIT = {
    "um_cfg":            ("T1", "four_source",             False),  # MUC atomic-rename unresolved
    "um_inst":           ("T1", "four_source",             True),
    "content_injection": ("T1", "four_source",             True),   # MCAW (incl aligned 101/201/402)
    "semantic_inversion":("T1", "three_source_exact",      False),  # MSI: auditd write never captured
    "chmod":             ("T2", "metadata_namespace_canary", False),
    "truncate":          ("T2", "metadata_namespace_canary", False),
    "unlink":            ("T2", "metadata_namespace_canary", False),
}

# ---- 18 graph attacks (um + MCAW), from the partial population ----
UM = [
    ("MUC01_w1_provider_relay_um", "um_cfg"), ("MUC02_w1_schedule_mail_um", "um_cfg"),
    ("MUC03_w2_provider_relay_um", "um_cfg"), ("MUC04_w2_schedule_mail_um", "um_cfg"),
    ("MUC05_w4_provider_relay_um", "um_cfg"), ("MUC06_w4_schedule_mail_um", "um_cfg"),
    ("MUI01_w1_tools_cred_relay_um", "um_inst"), ("MUI02_w1_agents_post_mirror_um", "um_inst"),
    ("MUI03_w2_tools_cred_relay_um", "um_inst"), ("MUI04_w2_agents_post_mirror_um", "um_inst"),
    ("MUI05_w4_tools_cred_relay_um", "um_inst"), ("MUI06_w4_agents_post_mirror_um", "um_inst"),
]
MCAW = [
    ("MCAW101_w1_release_helper_tool_redirect", "content_injection"),
    ("MCAW102_w1_automerge_instruction_backdoor", "content_injection"),
    ("MCAW201_w2_model_q_false_memory", "content_injection"),
    ("MCAW202_w2_citation_tool_redirect", "content_injection"),
    ("MCAW401_w4_engagement_persona_drift", "content_injection"),
    ("MCAW402_w4_blanket_approval_false_memory", "content_injection"),
]
# aligned-MCAW pooling (ruling 3): 101/201 re-extracted to uid997/e3b75979; 402 aligned
# sequence stream but bridge acceptance-line stale (benign coverage-divergence).
MCAW_ALIGNED_NOTE = {
    "MCAW101_w1_release_helper_tool_redirect": "re-extracted uid997 rules.sha e3b75979 (6625 eligible); pooled",
    "MCAW201_w2_model_q_false_memory": "re-extracted uid997 rules.sha e3b75979 (6610 eligible); pooled",
    "MCAW402_w4_blanket_approval_false_memory": "aligned sequence stream (4156 eligible, uid997) but "
        "five_source_graph_bridge.json acceptance-line stale (rc=1 benign coverage-divergence, MUI06-class); "
        "graph features valid, STIDE uses aligned normalized stream",
}
MCAW402 = "MCAW402_w4_blanket_approval_false_memory__poisoned"

MEMORY_POISONING = {"MCAW201_w2_model_q_false_memory", "MCAW402_w4_blanket_approval_false_memory"}

def profile_of(run_id):
    for p in ("w1", "w2", "w3", "w4"):
        if f"_{p}_" in run_id:
            return p.upper()
    return "UNK"

def stage_paths(rid):
    return {
        "spine": STAGE / rid / "graph/reattributed/resolution_spine_effective/syscalls.jsonl",
        "normalized": STAGE / rid / "graph/normalized/syscalls.jsonl",
        "libsinsp": STAGE / rid / "graph/libsinsp/libsinsp_events.jsonl",
        "snap": STAGE / rid / "state_snapshots/before_a",
    }

def libsinsp_nonempty(p):
    try:
        return p.is_file() and p.stat().st_size > 0
    except OSError:
        return False

def main():
    # local file-op run dirs (from d1_report paths)
    d1 = json.loads((Path("<SCRATCH>/d1_report.json")).read_text())
    fileop = {}
    for L in d1["landers"]:
        fileop[L["run_id"]] = {"op": L["op_signature"], "path": L["path"],
                               "spine_edges": L["spine_effective"]["graph_edges"],
                               "three_source_exact": L["semantic_three_source_exact"] == "true"}

    attacks = []
    # --- um + MCAW (graph attacks) ---
    for case, op in UM + MCAW:
        rid = case + "__poisoned"
        tier, mech, mres = WIT[op]
        sp = stage_paths(rid)
        stide_stream = "resolution_spine_effective"
        if rid == MCAW402:
            stide_stream = "normalized"  # ruling 3 note
        row = {
            "run_id": rid, "case_id": case, "op_signature": op, "profile": profile_of(rid),
            "witness_tier": tier, "witness_mechanism": mech,
            "marker_write_resolved": bool(mres),
            "has_libsinsp_graph": libsinsp_nonempty(sp["libsinsp"]),
            "has_syscalls": sp["spine"].is_file() or sp["normalized"].is_file(),
            "stide_stream": stide_stream,
            "lineage_sha_ok": True,
            "memory_poisoning_Mem_M1": case in MEMORY_POISONING,
            "aide_snapshot_source": "staging",
        }
        if case in MCAW_ALIGNED_NOTE:
            row["aligned_note"] = MCAW_ALIGNED_NOTE[case]
        attacks.append(row)

    # --- file-op (MSI/MCH/MTR/MUL); STIDE via D1 spine (pulled to staging), AIDE via local snapshots ---
    for rid, info in fileop.items():
        op = info["op"]; tier, mech, mres = WIT[op]
        sp = stage_paths(rid)
        row = {
            "run_id": rid, "case_id": rid.replace("__poisoned", ""), "op_signature": op,
            "profile": profile_of(rid), "witness_tier": tier, "witness_mechanism": mech,
            "marker_write_resolved": bool(mres),
            "has_libsinsp_graph": libsinsp_nonempty(sp["libsinsp"]),
            "has_syscalls": sp["spine"].is_file(),
            "stide_stream": "resolution_spine_effective",
            "lineage_sha_ok": True,
            "local_run_dir": str(RES.parent.parent / info["path"]) if not str(info["path"]).startswith("/") else info["path"],
            "aide_snapshot_source": "local_repo",
            "d1_three_source_exact": info["three_source_exact"],
        }
        attacks.append(row)

    # ---- clean-40 (carry from partial; DO NOT re-split; ruling 4) ----
    partial = json.loads((OUT / "PARTIAL_LOCKED_POPULATION.json").read_text())
    clean = []
    for c in partial["clean_heldout_40"]:
        clean.append({"run_id": c["run_id"], "profile": c["profile"],
                      "source": c["source"], "reuse_frozen_rows": c.get("reuse_frozen_rows", {})})

    # ---- B1/B2-definable set (ruling 2): write-resolved landers only ----
    b1b2_definable = [a["run_id"] for a in attacks if a["marker_write_resolved"]]
    b1b2_na = [a["run_id"] for a in attacks if not a["marker_write_resolved"]]

    from collections import Counter
    by_op = Counter(a["op_signature"] for a in attacks)
    by_tier = Counter(a["witness_tier"] for a in attacks)
    by_op_tier = {}
    for a in attacks:
        by_op_tier.setdefault(a["op_signature"], {"tier": a["witness_tier"], "n": 0})
        by_op_tier[a["op_signature"]]["n"] += 1

    manifest = {
        "schema_version": "assa.headtohead_frozen_population.v1",
        "created": "2026-08-25",
        "label": "FULL head-to-head FROZEN POPULATION. 44 attack landers (tiered-witness "
                 "admission) + clean-40 natural held-out. Culminating offline pass.",
        "provisional": {
            "population_not_frozen_signed": True,
            "polarity": "CONFIRMED for the 18 um/MCAW landers (see polarity block); file-op canaries structural",
        },
        "polarity": {
            "confirmed_18": {
                "landers": "um_cfg 6 (MUC) + um_inst 6 (MUI) + content_injection 6 (MCAW)",
                "verdict": "18/18 malicious, no reversals",
                "authority": "user (polarity authority) signed 18-lander v2 worksheet 2026-08-25",
                "signed_file": "data/p2_mass_attack_collection_20260823/"
                               "POLARITY_VERDICTS_NEW_LANDERS_V2_SIGNED_20260825.json",
                "signed_file_sha256": "5b61cff8cbb8e782559b353a4cd2784b2b11c0d90659c5c3fd5113c10260ca36",
                "status": "CONFIRMED-BY-USER (not provisional)",
            },
            "file_op_canaries_26": {
                "landers": "semantic_inversion 6 (MSI) + chmod 6 (MCH) + truncate 7 (MTR) + unlink 7 (MUL)",
                "status": "structural malice (user-signed file-op ruling); not in the 18-lander worksheet",
                "note": "polarity note unchanged",
            },
        },
        "rulings_applied": {
            "1_tiered_witness": "T1 writes (four-source um/MCAW + three-source-exact MSI) + "
                                "T2 metadata/namespace canaries (chmod/unlink/truncate)",
            "2_definability": "ours-B1/B2 = WRITE size+timing detector; N/A for no-resolved-marker-write "
                              "= 26 file-op + MUC 6; definable = MUI 6 + MCAW 6 (all resolve incl aligned 101/201/402)",
            "3_mcaw_pooled": "MCAW101/201/402 re-extracted to aligned lineage (uid997, rules.sha e3b75979); pooled",
            "4_fpr_denominator": "clean-40 natural held-out (split 42baa6a9 W1 11/W2 12/W3 8/W4 9); NOT re-split; twins separate",
            "5_polarity": "provisional-all-malicious; every TPR flagged provisional-pending-polarity",
        },
        "counts": {
            "attack_total": len(attacks),
            "by_op_signature": dict(by_op),
            "by_op_tier": by_op_tier,
            "by_witness_tier": dict(by_tier),
            "clean_40": len(clean),
            "clean_40_by_profile": dict(Counter(c["profile"] for c in clean)),
            "b1b2_definable_n": len(b1b2_definable),
            "b1b2_na_n": len(b1b2_na),
        },
        "b1b2_definable_run_ids": sorted(b1b2_definable),
        "b1b2_na_run_ids": sorted(b1b2_na),
        "generation_contract": {
            "libsinsp_config_sha": "e991fbe1", "libsinsp_rules_sha": "e3b75979",
            "ebpf_object_sha": "95c923f1 (per-VM)", "scap": "libscap-sysdig-modern-bpf",
            "auditd_version": "3.0.7",
            "monitor_versions": {"falco": "0.44.0", "aide": "0.19.3",
                                 "stide": "587d15870843961acb78fbb4b8fcd0ede28eabcc"},
            "runner_uid": 997,
        },
        "attacks": attacks,
        "clean_heldout_40": clean,
    }
    # content-address the manifest core (attacks + clean + counts)
    core = json.dumps({"attacks": attacks, "clean": clean, "counts": manifest["counts"]},
                      sort_keys=True).encode()
    gen = hashlib.sha256(core).hexdigest()[:12]
    manifest["derivation_generation"] = f"p2_headtohead_full_{gen}"
    manifest["manifest_content_address"] = gen

    (OUT / "FROZEN_POPULATION_MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print("generation_id:", manifest["derivation_generation"])
    print(json.dumps(manifest["counts"], indent=2))
    print("B1/B2-definable:", sorted(b1b2_definable))


if __name__ == "__main__":
    main()
