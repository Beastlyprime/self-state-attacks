from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from experiments.code.measurement.stage_g_harness.generation_contract import (
    validate_exported_inventory,
    validate_result_payload,
)


REPO = Path(__file__).resolve().parents[4]
ROOT = REPO / "data/p2_attack_tpr_expanded_v2_20260822"
SCRIPT = ROOT / "rebless_corrected_stide_gen2.py"
OUTPUT = ROOT / "STIDE_TPR_GEN2_PROFILE_CORRECTED_20260823"


def load_rebless_module():
    spec = importlib.util.spec_from_file_location("rebless_corrected_stide_gen2", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_profile_authority_is_the_run_id_token() -> None:
    module = load_rebless_module()
    assert module.profile_from_run_id("case_W3_variant") == "W3"
    assert module.profile_from_run_id("A1_w4_clean") == "W4"
    with pytest.raises(RuntimeError, match="cannot derive one workload profile"):
        module.profile_from_run_id("ambiguous_W3_W4_case")


def test_reblessed_stide_is_f5_bound_and_profile_corrected() -> None:
    context = validate_exported_inventory(
        OUTPUT / "inputs", OUTPUT / "generation_contract.json"
    )
    result = json.loads((OUTPUT / "stide_tpr_result.json").read_text(encoding="utf-8"))
    validate_result_payload(result, context, where="reblessed STIDE result")

    rows = result["rows"]
    w3 = [row for row in rows if row["profile"] == "W3"]
    w4 = [row for row in rows if row["profile"] == "W4"]
    assert len(w3) == 15
    assert all(row["status"] == "passed" and row["binary_decision"] for row in w3)
    assert len(w4) == 6
    assert all(row["status"] == "data_insufficient" for row in w4)
    assert all(row["binary_decision"] is None for row in w4)


def test_unicorn_reconciliation_is_descriptive_not_scored() -> None:
    payload = json.loads(
        (OUTPUT / "unicorn_profile_reconciliation.json").read_text(encoding="utf-8")
    )
    assert payload["artifact_class"] == (
        "profile_reconciliation_non_evaluable__not_a_detector_result"
    )
    assert payload["source_reported_fraction"] == "6/10"
    assert payload["corrected_w3_only_descriptive_fraction"] == "3/7"
    assert payload["w4_registered"] == 6
    assert payload["status"] == "non_evaluable_no_rescore"
    assert payload["detector_rerun"] is False
    assert payload["binary_decisions_changed"] is False
