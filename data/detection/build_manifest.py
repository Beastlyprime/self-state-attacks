#!/usr/bin/env python3
"""Build FINAL_3POOL_SPLIT_MANIFEST.json (Phase 1) with anti-leakage asserts + availability matrix."""
import json, hashlib, os
from pathlib import Path
from collections import defaultdict, Counter

ROOT = Path(os.environ.get("ASSA_ROOT", str(Path(__file__).resolve().parents[2])))
SCR = Path(os.environ.get("ASSA_SCRATCH", str(ROOT / ".scratch")))
POOLS = SCR / "pools"
HH = ROOT / "data/superseded"
OUT = ROOT / "data/detection"
OUT.mkdir(exist_ok=True)

TRAIN = json.load(open(SCR / "P2_CLEAN_TRAINING_FREEZE_GEN2.json"))
HELD = json.load(open(SCR / "P2_HELDOUT_CLEAN_FREEZE_GEN2.json"))
W3 = json.load(open(HH / "W3THICK_POPULATION_MANIFEST.json"))

CONTRACT = W3["generation_contract"]  # config e991fbe1 / rules e3b75979 / uid 997


def scenario_of(case_id):
    s = case_id
    for suf in ("_user_message", "_external_content"):
        if s.endswith(suf):
            s = s[: -len(suf)]
    return s


def exists(*p):
    return os.path.exists(os.path.join(*p))


def uid_of_syscalls(path):
    """modal process.uid over a sample (co-admissibility runner-uid check; ignores root setup rows)."""
    from collections import Counter
    c = Counter()
    try:
        with open(path) as f:
            for i, line in enumerate(f):
                if i > 30000:
                    break
                r = json.loads(line)
                u = (r.get("process") or {}).get("uid")
                if u is not None:
                    c[int(u)] += 1
    except Exception:
        return None
    return c.most_common(1)[0][0] if c else None


# ---------------- POOL 1: clean training gen2-176
pool1 = []
for r in TRAIN["records"]:
    rid = r["run_id"]
    d = POOLS / "train" / rid
    pool1.append({
        "run_id": rid, "profile": r["profile"], "scenario_id": r["task_id"], "task_id": r["task_id"],
        "tier": "clean", "polarity": "benign", "role": "training_fit_only",
        "branch_outcome": r["branch_outcome"],
        "marker_write_resolved": (r["branch_outcome"] == "natural_write"),
        "lineage": {"config_sha": CONTRACT["libsinsp_config_sha"], "rules_sha": CONTRACT["libsinsp_rules_sha"],
                    "runner_uid": CONTRACT["runner_uid"], "generation_id": TRAIN["generation_id"]},
        "local": {"libsinsp": exists(d, "graph/libsinsp/libsinsp_events.jsonl"),
                  "reattr_syscalls": exists(d, "graph/reattributed/resolution_spine_effective/syscalls.jsonl"),
                  "snapshots": exists(d, "state_snapshots/before_a")},
    })

# ---------------- POOL 2: clean heldout TEST gen2-60 (20 scenarios x 3 replicates)
pool2 = []
rep_ctr = defaultdict(int)
for r in HELD["records"]:
    rid = r["run_id"]; scn = r["task_id"]; rep_ctr[scn] += 1
    d = POOLS / "heldout" / rid
    pool2.append({
        "run_id": rid, "profile": r["profile"], "scenario_id": scn, "task_id": scn,
        "replicate_index": rep_ctr[scn], "fold_id": f"scn::{scn}",
        "tier": "clean", "polarity": "benign", "role": "fpr_test_only",
        "branch_outcome": r["branch_outcome"],
        "performs_self_state_write": (r["branch_outcome"] == "natural_write"),
        "lineage": {"config_sha": CONTRACT["libsinsp_config_sha"], "rules_sha": CONTRACT["libsinsp_rules_sha"],
                    "runner_uid": CONTRACT["runner_uid"], "generation_id": HELD["generation_id"]},
        "local": {"libsinsp": exists(d, "graph/libsinsp/libsinsp_events.jsonl"),
                  "reattr_syscalls": exists(d, "graph/reattributed/resolution_spine_effective/syscalls.jsonl"),
                  "snapshots": exists(d, "state_snapshots/before_a")},
    })

# ---------------- POOL 3: attack TEST 55 + twins
STAGE = HH / "staging"
definable = set(W3["b1b2_definable_run_ids"])
pool3 = []
twin_avail = {"full": 0, "snapshots_only": 0, "none": 0}
for a in W3["attacks"]:
    rid = a["run_id"]; case = a["case_id"]; scn = scenario_of(case)
    stide_stream = a["stide_stream"]
    fileop = a["aide_snapshot_source"] == "local_repo"
    # attack substrate presence
    if fileop:
        lr = a["local_run_dir"]
        atk_reattr = exists(STAGE, rid, "graph/reattributed/resolution_spine_effective/syscalls.jsonl")
        atk_norm = exists(STAGE, rid, "graph/normalized/syscalls.jsonl")
        atk_snap = exists(lr, "state_snapshots/before_a") or exists(lr, "semantic/state_snapshots/before_a")
        atk_lib = exists(STAGE, rid, "graph/libsinsp/libsinsp_events.jsonl")
        tw_dir = lr.replace("__poisoned", "__clean")
        tw_reattr = exists(tw_dir, "graph/reattributed/resolution_spine_effective/syscalls.jsonl")
        tw_lib = exists(tw_dir, "graph/libsinsp/libsinsp_events.jsonl")
        tw_snap = exists(tw_dir, "state_snapshots/before_a") or exists(tw_dir, "semantic/state_snapshots/before_a")
    else:
        atk_reattr = exists(STAGE, rid, "graph/reattributed/resolution_spine_effective/syscalls.jsonl")
        atk_norm = exists(STAGE, rid, "graph/normalized/syscalls.jsonl")
        atk_snap = exists(STAGE, rid, "state_snapshots/before_a")
        atk_lib = exists(STAGE, rid, "graph/libsinsp/libsinsp_events.jsonl")
        twd = POOLS / "twins" / rid.replace("__poisoned", "__clean")
        tw_reattr = exists(twd, "graph/reattributed/resolution_spine_effective/syscalls.jsonl")
        tw_lib = exists(twd, "graph/libsinsp/libsinsp_events.jsonl")
        tw_snap = exists(twd, "state_snapshots/before_a")
    if tw_reattr and tw_lib:
        tw_status = "full"
    elif tw_snap:
        tw_status = "snapshots_only"
    else:
        tw_status = "none"
    twin_avail[tw_status] += 1
    pool3.append({
        "run_id": rid, "case_id": case, "scenario_id": scn, "fold_id": f"scn::{scn}",
        "profile": a["profile"], "op_signature": a["op_signature"], "tier": a["witness_tier"],
        "polarity": "malicious", "witness_mechanism": a["witness_mechanism"],
        "marker_write_resolved": a["marker_write_resolved"],
        "b1b2_definable": rid in definable,
        "stide_stream": stide_stream,
        "aide_snapshot_source": a["aide_snapshot_source"],
        "twin_run_id": rid.replace("__poisoned", "__clean"),
        "twin_status": tw_status,
        "lineage": {"config_sha": CONTRACT["libsinsp_config_sha"], "rules_sha": CONTRACT["libsinsp_rules_sha"],
                    "runner_uid": CONTRACT["runner_uid"], "object_sha": CONTRACT["ebpf_object_sha"]},
        "attack_substrate": {
            "reattr_syscalls": atk_reattr,
            "normalized_syscalls": atk_norm,
            "stide_selected_stream_available": (
                atk_norm if stide_stream == "normalized" else atk_reattr
            ),
            "snapshots": atk_snap,
            "libsinsp": atk_lib,
        },
    })

# ---------------- ANTI-LEAKAGE ASSERTS
tr_tasks = set(x["task_id"] for x in pool1); ho_tasks = set(x["task_id"] for x in pool2)
tr_ids = set(x["run_id"] for x in pool1); ho_ids = set(x["run_id"] for x in pool2)
asserts = {
    "train_heldout_task_disjoint": sorted(tr_tasks & ho_tasks) == [],
    "train_heldout_runid_disjoint": (tr_ids & ho_ids) == set(),
    "pool1_count_176": len(pool1) == 176,
    "pool2_count_60": len(pool2) == 60,
    "pool2_scenarios_20": len(set(x["scenario_id"] for x in pool2)) == 20,
    "pool2_replicates_3each": all(v == 3 for v in Counter(x["scenario_id"] for x in pool2).values()),
    "pool3_count_55": len(pool3) == 55,
    "attack_stide_substrate_55of55": sum(
        1 for x in pool3 if x["attack_substrate"]["stide_selected_stream_available"]
    ) == 55,
    "fileop_attack_graphs_26of26": sum(1 for x in pool3 if x["aide_snapshot_source"] == "local_repo"
                                       and x["attack_substrate"]["reattr_syscalls"]) == 26,
    "b1b2_definable_23of55": sum(1 for x in pool3 if x["b1b2_definable"]) == 23,
    "attack_snapshots_55of55": sum(1 for x in pool3 if x["attack_substrate"]["snapshots"]) == 55,
    "train_substrate_complete_176": all(x["local"]["libsinsp"] and x["local"]["reattr_syscalls"] for x in pool1),
    "heldout_substrate_complete_60": all(x["local"]["libsinsp"] and x["local"]["reattr_syscalls"] and x["local"]["snapshots"] for x in pool2),
}

# uid co-admissibility spot check (sample 6 train, 6 heldout, 6 attack)
uid_checks = []
for grp, items, base in [("train", pool1[:3] + pool1[-3:], POOLS / "train"),
                         ("heldout", pool2[:3] + pool2[-3:], POOLS / "heldout")]:
    for it in items:
        p = base / it["run_id"] / "graph/reattributed/resolution_spine_effective/syscalls.jsonl"
        uid_checks.append({"pool": grp, "run_id": it["run_id"], "uid": uid_of_syscalls(p)})
for it in pool3[:3] + pool3[-3:]:
    p = STAGE / it["run_id"] / "graph/reattributed/resolution_spine_effective/syscalls.jsonl"
    uid_checks.append({"pool": "attack", "run_id": it["run_id"], "uid": uid_of_syscalls(p)})
asserts["uid_997_spotcheck_all"] = all(c["uid"] == 997 for c in uid_checks)

manifest = {
    "schema_version": "assa.final_3pool_split.v1",
    "created": "2026-08-25",
    "design": "user-approved codex 3-pool: clean TRAIN gen2-176 (fit only), natural clean TEST gen2-60 (FPR only, scenario-clustered), attack TEST 55 (+twins secondary). Supersedes leaky clean-40 leave-one-out.",
    "generation_contract": CONTRACT,
    "pools": {
        "pool1_clean_training_gen2_176": {"role": "fit_only", "n": len(pool1),
            "by_profile": dict(Counter(x["profile"] for x in pool1)),
            "by_branch_outcome": dict(Counter(x["branch_outcome"] for x in pool1)),
            "records": pool1},
        "pool2_clean_heldout_test_gen2_60": {"role": "fpr_test_only", "n": len(pool2),
            "n_scenarios": len(set(x["scenario_id"] for x in pool2)),
            "by_profile": dict(Counter(x["profile"] for x in pool2)),
            "write_conditional": {"write_runs": sum(1 for x in pool2 if x["performs_self_state_write"]),
                                  "nowrite_runs": sum(1 for x in pool2 if not x["performs_self_state_write"])},
            "records": pool2},
        "pool3_attack_test_55": {"role": "tpr_test", "n": len(pool3),
            "by_profile": dict(Counter(x["profile"] for x in pool3)),
            "by_op_signature": dict(Counter(x["op_signature"] for x in pool3)),
            "by_tier": dict(Counter(x["tier"] for x in pool3)),
            "b1b2_definable_n": sum(1 for x in pool3 if x["b1b2_definable"]),
            "twin_availability": twin_avail,
            "records": pool3},
    },
    "definable_write_resolved_subset": {
        "detectors": ["ours_B1", "ours_B2", "supervised(size)"],
        "n": 23, "run_ids": sorted(W3["b1b2_definable_run_ids"]),
        "note": "definition-limited (write-specific size/timing), NOT a data gap; 32/55 have no resolved self-state marker write.",
    },
    "fold_map_attack_loso": {x["run_id"]: x["fold_id"] for x in pool3},
    "n_attack_folds": len(set(x["fold_id"] for x in pool3)),
    "anti_leakage_asserts": asserts,
    "uid_spotcheck": uid_checks,
    "twin_note": ("Primary staged substrate: 17 graph-attack twins are full, 26 file-op twins are "
                  "snapshots-only, and 12 attacks have no twin in this staging pool. The supervised "
                  "canonical-23 rebuild separately recovers size-feature twins from additional frozen "
                  "local sources, including MUI06 and 11 W3 content_append cases. Primary natural-clean "
                  "FPR uses gen2-60 and is independent of twin availability."),
}

# content address
canon = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
addr = hashlib.sha256(canon).hexdigest()[:12]
manifest["manifest_content_address"] = addr
(OUT / "FINAL_3POOL_SPLIT_MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")

print("=== FINAL_3POOL manifest content-address:", addr)
print("POOL1 (train):", len(pool1), dict(Counter(x["profile"] for x in pool1)))
print("POOL2 (heldout):", len(pool2), "scenarios", len(set(x["scenario_id"] for x in pool2)),
      "write/nowrite", manifest["pools"]["pool2_clean_heldout_test_gen2_60"]["write_conditional"])
print("POOL3 (attack):", len(pool3), "definable", sum(1 for x in pool3 if x["b1b2_definable"]))
print("twin availability:", twin_avail)
print("attack folds:", manifest["n_attack_folds"])
print("\n=== ASSERTS ===")
for k, v in asserts.items():
    print(f"  [{'PASS' if v else 'FAIL'}] {k}")
print("\nall asserts pass:", all(asserts.values()))
