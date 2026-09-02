"""Profile derivation robustness + STIDE profile-conditioned fail safe.

Regression tests for the W3/W4 profile-mislabel bug: all attack landers were
physically filed under attack/W3/, so a genuinely-W4 lander (run_id token
`_w4_`) was labeled profile=W3 and scored against the W3 model. Correct
behaviour: the run resolves to profile=W4 and, because the corpus ships no W4
training baseline, becomes data_insufficient -- never scored cross-profile.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

HARNESS_ROOT = Path(__file__).resolve().parents[2]
if str(HARNESS_ROOT) not in sys.path:
    sys.path.insert(0, str(HARNESS_ROOT))

from stage_g_harness import p2_attack_tpr_gen1 as gen1
from stage_g_harness.external import ToolRun
from stage_g_harness.p2_detector_fpr import (
    inventory,
    profile_from_run_id,
    reconcile_record_profile,
)


# --------------------------------------------------------------------- derivation
def test_profile_from_run_id_reads_token():
    assert profile_from_run_id("C302_w4_calendar_sleeper_exfil__poisoned") == "W4"
    assert profile_from_run_id("C510_w3_db_query_vendor_package__poisoned") == "W3"
    assert profile_from_run_id("no_token_here") is None
    assert profile_from_run_id(None) is None


def test_reconcile_overrides_misfiled_directory():
    # W4 lander physically filed under W3: token wins, dir kept.
    rec = reconcile_record_profile(
        {"profile": "W3", "run_id": "C302_w4_x__poisoned", "role": "attack"}
    )
    assert rec["profile"] == "W4"
    assert rec["dir_profile"] == "W3"
    assert rec["profile_source"] == "run_id_token_override_dir"


def test_reconcile_leaves_consistent_records_alone():
    rec = reconcile_record_profile(
        {"profile": "W3", "run_id": "C510_w3_x__poisoned", "role": "attack"}
    )
    assert rec["profile"] == "W3"
    assert rec["dir_profile"] == "W3"
    assert rec["profile_source"] == "run_id_token"


def test_inventory_reconciles_from_disk(tmp_path):
    (tmp_path / "input_inventory.json").write_text(json.dumps({"records": [
        {"profile": "W3", "run_id": "C302_w4_x__poisoned", "role": "attack",
         "branch_outcome": "b"},
        {"profile": "W3", "run_id": "C510_w3_y__poisoned", "role": "attack",
         "branch_outcome": "b"},
    ]}))
    recs = {r["run_id"]: r for r in inventory(tmp_path)["records"]}
    assert recs["C302_w4_x__poisoned"]["profile"] == "W4"
    assert recs["C510_w3_y__poisoned"]["profile"] == "W3"


# ------------------------------------------------------------------- STIDE guard
def _write_graph(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"syscall": {"name": "read"}}\n')


def _build_corpus(root: Path) -> None:
    # One correctly-filed W3 lander and one W4 lander misfiled under attack/W3/.
    (root / "input_inventory.json").write_text(json.dumps({"records": [
        {"profile": "W3", "run_id": "C777_w3_ok__poisoned", "role": "attack",
         "branch_outcome": "attack_candidate_realized_manual_review_pending",
         "case_id": "C777"},
        {"profile": "W3", "run_id": "C999_w4_sleeper__poisoned", "role": "attack",
         "branch_outcome": "attack_candidate_realized_manual_review_pending",
         "case_id": "C999"},
    ]}))
    _write_graph(root / "training" / "W3" / "train01" / "graph" / "syscalls.jsonl")
    # NOTE: no training/W4 baseline is exported -> W4 must be data_insufficient.
    _write_graph(root / "attack" / "W3" / "C777_w3_ok__poisoned" / "graph" / "syscalls.jsonl")
    _write_graph(root / "attack" / "W3" / "C999_w4_sleeper__poisoned" / "graph" / "syscalls.jsonl")


def test_stide_failsafe_w4_under_w3_dir_is_data_insufficient(tmp_path, monkeypatch):
    input_root = tmp_path / "inputs"
    input_root.mkdir()
    _build_corpus(input_root)

    # core preregistration defines BOTH W3 and W4 frozen cores; the discriminator
    # is the absence of a W4 *training baseline*, not the frozen-core definition.
    prereg = tmp_path / "prereg.json"
    prereg.write_text(json.dumps({"profile_freeze": {
        "W3": {"core_executables": ["/usr/bin/python3.10"]},
        "W4": {"core_executables": ["/usr/bin/python3.10"]},
    }}))

    called_run_ids: list[str] = []

    def fake_run_tool(command, out, name, **kwargs):
        # Determine which run this is from the --test path, and satisfy --output.
        test_idx = command.index("--test")
        called_run_ids.append(Path(command[test_idx + 1]).parents[1].name)
        out_idx = command.index("--output")
        Path(command[out_idx + 1]).write_text(json.dumps({
            "results": {"/usr/bin/python3.10": {"scoring_gate_passed": False,
                                                "unknown_ngrams": 0}}
        }))
        return ToolRun(command, 0, out / "stide.stdout.log", out / "stide.stderr.log", 0, 0)

    monkeypatch.setattr(gen1, "require_commit", lambda *a, **k: None)
    monkeypatch.setattr(gen1, "run_tool", fake_run_tool)

    args = SimpleNamespace(
        input_root=input_root,
        output=tmp_path / "out",
        stide_repo=tmp_path / "fake_stide_repo",
        core_preregistration=prereg,
    )
    gen1.score_stide(args)

    result = json.loads((args.output / "tpr_result.json").read_text())
    rows = {r["run_id"]: r for r in result["rows"]}

    w4 = rows["C999_w4_sleeper__poisoned"]
    assert w4["profile"] == "W4"
    assert w4["dir_profile"] == "W3"
    assert w4["status"] == "data_insufficient"
    assert w4["binary_decision"] is None
    assert w4["native_score"] is None
    assert "no_W4_training_baseline_profile_conditioned" in w4["reasons"]

    # The W4 run must NEVER reach the tool (would be a cross-profile score).
    assert "C999_w4_sleeper__poisoned" not in called_run_ids
    assert called_run_ids == ["C777_w3_ok__poisoned"]

    # Summary reflects the fail safe: W4 counted as data_insufficient, W3 present.
    assert result["summary"]["data_insufficient_not_negative"] >= 1
    assert "W4" in result["summary"]["profiles_present"]
