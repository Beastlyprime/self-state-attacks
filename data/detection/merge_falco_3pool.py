#!/usr/bin/env python3
"""Materialize Falco clean and attack decisions for the final three-pool evaluation.

The fresh Falco replay file contains the 60 held-out clean runs. Attack decisions
come from the frozen D2 replays (38 + 6 runs) and the compatible W3 expansion
(11 runs). This merger selects exactly the 55 manifest attacks, rejects missing
or conflicting decisions, and drops acquisition-host paths from the release row.
"""
import hashlib
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]
MANIFEST = OUT / "FINAL_3POOL_SPLIT_MANIFEST.json"
SCORED = OUT / "scored_falco_3pool.json"
ATTACK_SOURCES = [
    ROOT / "data/corpus-manifests/tier_a/job_reports/d2_tpr_result.json",
    ROOT / "data/corpus-manifests/tier_a/job_reports/d2_tpr_result_69.json",
    ROOT / "data/p2_attack_tpr_expanded_v2_20260822/scored/falco/tpr_result.json",
]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    manifest = json.loads(MANIFEST.read_text())
    current = json.loads(SCORED.read_text())
    clean_meta = {
        row["run_id"]: row
        for row in manifest["pools"]["pool2_clean_heldout_test_gen2_60"]["records"]
    }
    attack_meta = {
        row["run_id"]: row
        for row in manifest["pools"]["pool3_attack_test_55"]["records"]
    }

    clean_rows = []
    for row in current["rows"]:
        rid = row["run_id"]
        if rid not in clean_meta:
            continue
        meta = clean_meta[rid]
        clean_rows.append({
            "run_id": rid,
            "profile": meta["profile"],
            "side": "clean",
            "scenario_id": meta["scenario_id"],
            "fold_id": meta["fold_id"],
            "branch_outcome": meta["branch_outcome"],
            "performs_write": meta["performs_self_state_write"],
            "status": row["status"],
            "exit_status": row.get("exit_status"),
            "binary_decision": row["binary_decision"],
            "all_custom_rule_events": row.get("all_custom_rule_events"),
            "qualifying_canonical_mutation_events": row.get("qualifying_canonical_mutation_events"),
            "qualifying_rule_counts": row.get("qualifying_rule_counts", {}),
            "rules_sha256": row.get("rules_sha256"),
        })

    selected = {}
    source_meta = []
    for source in ATTACK_SOURCES:
        payload = json.loads(source.read_text())
        rel = source.relative_to(ROOT).as_posix()
        source_meta.append({"path": rel, "sha256": sha256(source)})
        for row in payload["rows"]:
            rid = row["run_id"]
            if rid not in attack_meta or row.get("status") != "passed":
                continue
            decision = bool(row["binary_decision"])
            if rid in selected and selected[rid]["binary_decision"] != decision:
                raise AssertionError(f"conflicting Falco decision for {rid}")
            meta = attack_meta[rid]
            selected[rid] = {
                "run_id": rid,
                "profile": meta["profile"],
                "side": "attack",
                "scenario_id": meta["scenario_id"],
                "fold_id": meta["fold_id"],
                "op_signature": meta["op_signature"],
                "tier": meta["tier"],
                "status": "passed",
                "binary_decision": decision,
                "native_score": row.get("native_score"),
                "rules_sha256": row.get("rules_sha256"),
                "source_result": rel,
                "source_generation": payload.get("generation_id"),
            }

    missing = sorted(set(attack_meta) - set(selected))
    assert len(clean_rows) == 60, f"expected 60 clean rows, got {len(clean_rows)}"
    assert not missing, f"missing Falco attack rows: {missing}"
    assert len(selected) == 55, len(selected)
    assert sum(row["binary_decision"] for row in selected.values()) == 43

    output = {
        "schema_version": "assa.falco.final_3pool.v2",
        "detector": "Falco",
        "version": current["version"],
        "config": current["config"],
        "threshold": current["threshold"],
        "runner_uid": current.get("runner_uid", 997),
        "falco_config_sha256": json.loads(ATTACK_SOURCES[0].read_text())["config"]["falco_config_sha256"],
        "scorer_config_sha256": json.loads(ATTACK_SOURCES[0].read_text())["config_sha256"],
        "binary_sha256": json.loads(ATTACK_SOURCES[0].read_text())["binary_sha256"],
        "design": "fresh held-out clean replay plus frozen compatible attack replays; exact manifest population",
        "source_results": source_meta,
        "rows": sorted(clean_rows + list(selected.values()), key=lambda row: (row["side"], row["run_id"])),
    }
    SCORED.write_text(json.dumps(output, indent=2) + "\n")
    print("Falco clean", sum(bool(r["binary_decision"]) for r in clean_rows), "/", len(clean_rows))
    print("Falco attack", sum(bool(r["binary_decision"]) for r in selected.values()), "/", len(selected))


if __name__ == "__main__":
    main()
