#!/usr/bin/env python3
"""Freeze the expanded head-to-head population and census its per-detector
offline scorability.

This does STEP 1a (dedup, explicit run-dir enumeration) and STEP 2 (freeze
identity SHAs) faithfully for the NEW mass landers. It does NOT score: the
per-detector scorability matrix records which detectors CAN be run offline on
this host, given the arch/derivation blockers documented in BLOCKER_REPORT.md.

VM graph-availability is recorded from a read-only remote census performed on
2026-08-25 (see BLOCKER_REPORT.md for the queries); it is embedded here as data
because the graphs are not local and cannot be re-derived offline on aarch64.
"""
from __future__ import annotations
import hashlib, json, glob
from pathlib import Path

RES = Path(__file__).resolve().parents[1]
OUT = Path(__file__).resolve().parent

# ---- NEW attack landers: (case_id, op_signature, profile, lane_dir_glob) ----
# op_signature vocab matches the frozen harness slices.
FILE_OPS = [
    ("MCH01_w1_memory_lockout", "chmod", "W1"),
    ("MCH02_w1_rules_worldwrite", "chmod", "W1"),
    ("MCH03_w2_memory_lockout", "chmod", "W2"),
    ("MCH04_w2_rules_worldwrite", "chmod", "W2"),
    ("MCH05_w4_memory_lockout", "chmod", "W4"),
    ("MCH06_w4_rules_worldwrite", "chmod", "W4"),
    ("MSI01_w1_shell_approval_gate", "semantic_inversion", "W1"),
    ("MSI02_w1_precommit_verification_disable", "semantic_inversion", "W1"),
    ("MSI03_w2_private_memory_prohibition_negation", "semantic_inversion", "W2"),
    ("MSI04_w2_citation_verification_disable", "semantic_inversion", "W2"),
    ("MSI05_w4_memory_scope_flip", "semantic_inversion", "W4"),
    ("MSI06_w4_external_action_default_flip", "semantic_inversion", "W4"),
    ("MTR01_w3_heartbeat_wipe", "truncate", "W3"),
    ("MTR02_w1_memory_wipe", "truncate", "W1"),
    ("MTR03_w1_tools_wipe", "truncate", "W1"),
    ("MTR04_w2_memory_wipe", "truncate", "W2"),
    ("MTR05_w2_tools_wipe", "truncate", "W2"),
    ("MTR06_w4_memory_wipe", "truncate", "W4"),
    ("MTR07_w4_heartbeat_wipe", "truncate", "W4"),
    ("MUL01_w3_tools_unlink", "unlink", "W3"),
    ("MUL02_w1_agents_unlink", "unlink", "W1"),
    ("MUL03_w1_tools_unlink", "unlink", "W1"),
    ("MUL04_w2_agents_unlink", "unlink", "W2"),
    ("MUL05_w2_memory_unlink", "unlink", "W2"),
    ("MUL06_w4_agents_unlink", "unlink", "W4"),
    ("MUL07_w4_user_unlink", "unlink", "W4"),
]
UM = [
    ("MUC01_w1_provider_relay_um", "um_cfg", "W1"),
    ("MUC02_w1_schedule_mail_um", "um_cfg", "W1"),
    ("MUC03_w2_provider_relay_um", "um_cfg", "W2"),
    ("MUC04_w2_schedule_mail_um", "um_cfg", "W2"),
    ("MUC05_w4_provider_relay_um", "um_cfg", "W4"),
    ("MUC06_w4_schedule_mail_um", "um_cfg", "W4"),
    ("MUI01_w1_tools_cred_relay_um", "um_inst", "W1"),
    ("MUI02_w1_agents_post_mirror_um", "um_inst", "W1"),
    ("MUI03_w2_tools_cred_relay_um", "um_inst", "W2"),
    ("MUI04_w2_agents_post_mirror_um", "um_inst", "W2"),
    ("MUI05_w4_tools_cred_relay_um", "um_inst", "W4"),
    ("MUI06_w4_agents_post_mirror_um", "um_inst", "W4"),
]
CINJ = [
    ("MCAW101_w1_release_helper_tool_redirect", "content_injection", "W1"),
    ("MCAW102_w1_automerge_instruction_backdoor", "content_injection", "W1"),
    ("MCAW201_w2_model_q_false_memory", "content_injection", "W2"),
    ("MCAW202_w2_citation_tool_redirect", "content_injection", "W2"),
    ("MCAW401_w4_engagement_persona_drift", "content_injection", "W4"),
    ("MCAW402_w4_blanket_approval_false_memory", "content_injection", "W4"),
]

# read-only VM census 2026-08-25: run_ids whose graph/reattributed/
# resolution_spine_effective/syscalls.jsonl exists (poisoned).
GRAPH_ON_VM = {
    # um -- host assa-stageg (.91), all 12 present
    **{c + "__poisoned": "<GUEST_HOST_B>" for c, _, _ in UM},
    # content-injection -- host assa-stageg2 (.69), all 6 present
    **{c + "__poisoned": "<GUEST_HOST_C>" for c, _, _ in CINJ},
}
# memory-poisoning content-injection landers (Mem-M1) per lane2 batch05 design
MEMORY_POISONING = {"MCAW201_w2_model_q_false_memory", "MCAW402_w4_blanket_approval_false_memory"}


def sha_file(p: Path) -> str | None:
    if not p.is_file():
        return None
    h = hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def find_poisoned(case_id: str) -> Path | None:
    hits = glob.glob(str(RES / f"p2_mass_attack_lane*/**/runs/{case_id}__poisoned"), recursive=True)
    hits = [h for h in hits if Path(h).is_dir() and "/.openclaw/" not in h]
    return Path(sorted(hits, key=len)[0]) if hits else None


def scorability(local_path, graph_vm, snap_present):
    # AIDE: needs state_snapshots (local) + arm64 docker -> works whenever snapshots local
    aide = "scorable_offline" if snap_present else "blocked_no_snapshots"
    # STIDE / ours-B1B2: need effective syscall graph / libsinsp_events.
    #   present only on a VM (must sync, read-only OK); cannot be derived offline
    #   on aarch64 (pinned falco is x86-64, no qemu, no sysdig).
    if graph_vm:
        graph_state = f"scorable_after_readonly_sync_from_{graph_vm}"
    else:
        graph_state = "blocked_no_graph_anywhere_cannot_derive_offline_aarch64"
    stide = ours = graph_state
    # Falco detector: requires x86-64 falco replay; no precomputed rows for new
    #   landers; blocked on this host regardless of graph availability.
    falco = "blocked_requires_x86_64_falco_no_precomputed_rows"
    return {"AIDE": aide, "STIDE": stide, "ours_B1B2": ours, "Falco": falco, "UNICORN": "non_evaluable_no_rescore"}


def build_group(rows, group_name):
    out = []
    for case_id, op, profile in rows:
        p = find_poisoned(case_id)
        local = str(p.relative_to(RES)) if p else None
        cap = p / "raw/capture.scap" if p else None
        gt = p / "ground_truth.json" if p else None
        snap = bool(p and ((p / "state_snapshots/before_a").is_dir() or (p / "semantic/state_snapshots/before_a").is_dir()))
        run_id = case_id + "__poisoned"
        graph_vm = GRAPH_ON_VM.get(run_id)
        rec = {
            "population_id": f"{group_name}::{run_id}",
            "case_id": case_id,
            "run_id": run_id,
            "op_signature": op,
            "profile": profile,
            "group": group_name,
            "polarity": "malicious_provisional",
            "local_mirror": local,
            "local_present": p is not None,
            "capture_scap_sha256": sha_file(cap) if cap else None,
            "ground_truth_sha256": sha_file(gt) if gt else None,
            "state_snapshots_local": snap,
            "graph_reattributed_present_on": graph_vm,
            "graph_local": False,
            "memory_poisoning_Mem_M1": case_id in MEMORY_POISONING,
            "scorable": scorability(local, graph_vm, snap),
        }
        out.append(rec)
    return out


def main():
    file_ops = build_group(FILE_OPS, "lane1_fileop")
    um = build_group(UM, "lane1_um")
    cinj = build_group(CINJ, "lane2_content_injection")
    allrows = file_ops + um + cinj

    def count(pred):
        return sum(1 for r in allrows if pred(r))

    payload = {
        "schema_version": "assa.headtohead_expanded_census.v1",
        "created": "2026-08-25",
        "host_arch": "aarch64",
        "note": "STEP 1a/2 freeze of NEW mass landers + per-detector OFFLINE scorability census. "
                "Scoring (STEP 3) is BLOCKED offline; see BLOCKER_REPORT.md. "
                "Frozen-reusable rows (content_append 17, heldout clean 20) are referenced there, not re-enumerated.",
        "population_new_attack_landers": allrows,
        "counts": {
            "new_attack_landers_enumerated": len(allrows),
            "by_op_signature": {op: count(lambda r, op=op: r["op_signature"] == op)
                                 for op in sorted({r["op_signature"] for r in allrows})},
            "local_present": count(lambda r: r["local_present"]),
            "local_missing": count(lambda r: not r["local_present"]),
            "graph_present_on_vm": count(lambda r: r["graph_reattributed_present_on"]),
            "graph_absent_everywhere": count(lambda r: not r["graph_reattributed_present_on"]),
            "aide_scorable_offline": count(lambda r: r["scorable"]["AIDE"] == "scorable_offline"),
            "stide_ours_scorable_after_sync": count(lambda r: r["scorable"]["STIDE"].startswith("scorable")),
            "stide_ours_blocked": count(lambda r: r["scorable"]["STIDE"].startswith("blocked")),
            "falco_scorable_offline": count(lambda r: r["scorable"]["Falco"].startswith("scorable")),
            "memory_poisoning_landers": count(lambda r: r["memory_poisoning_Mem_M1"]),
        },
    }
    (OUT / "DERIVATION_AVAILABILITY_MATRIX.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps(payload["counts"], indent=2))


if __name__ == "__main__":
    main()
