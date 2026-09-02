from __future__ import annotations

import json
from pathlib import Path

from experiments.code.dataset_builder import build_mass_um_profile_inputs as builder


def test_w1_incremental_root_preserves_user_message_and_profile_invariants(
    tmp_path: Path,
) -> None:
    output = builder.build(tmp_path / "batch")
    manifest = json.loads((output / "input_root_manifest.json").read_text())
    validation = json.loads((output / "VALIDATION.json").read_text())

    assert manifest["case_count"] == 4
    assert manifest["op_signature_counts"] == {"um_cfg": 2, "um_inst": 2}
    assert validation["passed"] is True
    assert validation["agent_or_collector_started"] is False
    assert validation["network_request_made"] is False

    for case_id in manifest["case_ids"]:
        case_dir = output / "cases" / case_id
        case = json.loads((case_dir / "case.json").read_text())
        ground_truth = json.loads((case_dir / "ground_truth.json").read_text())
        clean = (case_dir / "variants" / "clean.bin").read_bytes()
        poisoned = (case_dir / "variants" / "poisoned.bin").read_bytes()

        assert case_dir.name == case["case_id"] == case_id
        assert case["profile"] == case["task"]["profile"] == "W1"
        assert case["delivery"]["channel"] == "user_message"
        assert case["delivery"]["filesystem_ingestion_observable"] is False
        assert case["checkpoint"]["source_checkpoint_case_id"] == "U000_W1_C1_V4"
        assert not case["task"]["seed_files"]
        assert clean != poisoned
        assert ground_truth["single_subverted_slot"]["clean"].encode() in clean
        assert ground_truth["single_subverted_slot"]["poison"].encode() in poisoned
        assert ground_truth["mechanism"] == "M1"
        assert ground_truth["marker"].encode() not in clean
        assert ground_truth["marker"].encode() in poisoned
        assert (output / case["checkpoint"]["workspace"]).is_dir()
        assert (output / case["checkpoint"]["manifest"]).is_file()


def test_reviewed_carrier_templates_are_reused_verbatim() -> None:
    specs = (
        (builder.base.I1_CARRIER, builder.base.I1_CLEAN_SLOT, builder.base.I1_POISON_SLOT),
        (builder.base.I2_CARRIER, builder.base.I2_CLEAN_SLOT, builder.base.I2_POISON_SLOT),
        (builder.base.Cfg1_CARRIER, builder.base.Cfg1_CLEAN_SLOT, builder.base.Cfg1_POISON_SLOT),
        (builder.base.Cfg2_CARRIER, builder.base.Cfg2_CLEAN_SLOT, builder.base.Cfg2_POISON_SLOT),
    )
    for template, clean_slot, poison_slot in specs:
        assert template.count("{slot}") == 1
        clean = template.format(slot=clean_slot)
        poison = template.format(slot=poison_slot)
        prefix, suffix = template.split("{slot}")
        assert clean == prefix + clean_slot + suffix
        assert poison == prefix + poison_slot + suffix
