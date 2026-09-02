import json

from experiments.code.dataset_builder.build_mass_profile_content_append_inputs import CASES, build


def test_build_w1_content_append_increment(tmp_path):
    out = build(tmp_path / "out")
    validation = json.loads((out / "VALIDATION.json").read_text())
    assert validation["passed"] is True
    manifest = json.loads((out / "input_root_manifest.json").read_text())
    assert manifest["case_count"] == 2
    assert {row["profile"] for row in manifest["cases"]} == {"W1"}
    assert {row["semantic_subtype"] for row in manifest["cases"]} == {
        "tool_redirection", "backdoor_instruction_injection"
    }
    for spec in (row for row in CASES if row["profile"] == "W1"):
        case_dir = out / "cases" / spec["case_id"]
        assert json.loads((case_dir / "case.json").read_text())["case_id"] == case_dir.name
        gt = json.loads((case_dir / "ground_truth.json").read_text())
        assert gt["op_signature"] == "content_append"
        assert gt["mechanism"] == "M1"
        assert gt["semantic_subtype"] == spec["semantic_subtype"]
        assert gt["landing_predicate"]["marker"] == spec["marker"]
    assert (out / "regeneration_provenance.json").is_file()
    assert (out / "SHA256SUMS.txt").is_file()


def test_build_full_content_append_spread(tmp_path):
    out = build(tmp_path / "full", ("W1", "W2", "W4"))
    manifest = json.loads((out / "input_root_manifest.json").read_text())
    assert json.loads((out / "VALIDATION.json").read_text())["passed"] is True
    assert manifest["case_count"] == 6
    assert {row["profile"] for row in manifest["cases"]} == {"W1", "W2", "W4"}
    assert {row["channel"] for row in manifest["cases"]} == {"workspace_file", "user_message"}
    assert {row["semantic_subtype"] for row in manifest["cases"]} == {
        "tool_redirection", "backdoor_instruction_injection",
        "false_memory_fact_poisoning", "persona_goal_drift",
    }
    for row in manifest["cases"]:
        gt = json.loads(
            (out / "cases" / row["case_id"] / "ground_truth.json").read_text()
        )
        assert gt["op_signature"] == "content_append"
        assert gt["mechanism"] == "M1"
