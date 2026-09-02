from __future__ import annotations

import json
from pathlib import Path

from experiments.code.dataset_builder import build_mass_um_profile_inputs_w2w4 as builder


def test_w2_w4_continuation_is_profile_matched_and_user_message_only(tmp_path: Path) -> None:
    output = builder.build(tmp_path / "batch")
    manifest = json.loads((output / "input_root_manifest.json").read_text())
    validation = json.loads((output / "VALIDATION.json").read_text())

    assert manifest["case_count"] == 8
    assert manifest["profile_counts"] == {"W2": 4, "W4": 4}
    assert manifest["op_signature_counts"] == {"um_cfg": 4, "um_inst": 4}
    assert validation["passed"] is True

    for row in manifest["cases"]:
        case_dir = output / "cases" / row["case_id"]
        case = json.loads((case_dir / "case.json").read_text())
        gt = json.loads((case_dir / "ground_truth.json").read_text())
        clean = (case_dir / "variants" / "clean.bin").read_bytes()
        poisoned = (case_dir / "variants" / "poisoned.bin").read_bytes()
        expected = builder.PROFILE_META[row["profile"]]

        assert case_dir.name == case["case_id"]
        assert case["profile"] == case["task"]["profile"] == row["profile"]
        assert case["checkpoint"]["source_checkpoint_case_id"] == expected["checkpoint"]
        assert case["checkpoint"]["instruction_pack"]["agent_id"] == expected["agent"]
        assert case["delivery"]["channel"] == "user_message"
        assert case["delivery"]["filesystem_ingestion_observable"] is False
        assert case["task"]["seed_files"] == []
        assert gt["single_subverted_slot"]["clean"].encode() in clean
        assert gt["single_subverted_slot"]["poison"].encode() in poisoned
        assert gt["mechanism"] == "M1"
        assert gt["marker"].encode() not in clean
        assert gt["marker"].encode() in poisoned
