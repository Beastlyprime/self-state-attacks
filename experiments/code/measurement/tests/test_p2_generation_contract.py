from __future__ import annotations

import json
import sys
from argparse import Namespace
from copy import deepcopy
from pathlib import Path

import pytest

from experiments.code.measurement.stage_g_harness.export_p2_detector_inputs import (
    main as export_main,
)
from experiments.code.measurement.stage_g_harness.generation_contract import (
    SCHEMA_VERSION,
    GenerationContractError,
    bind_result,
    generation_stamp,
    json_hash,
    load_generation_contract,
    require_detector_config,
    require_detector_registration,
    sha256,
    validate_exported_inventory,
    validate_result_payload,
)
from experiments.code.measurement.stage_g_harness.p2_detector_fpr import (
    UNICORN_BASE_STREAM_SPLIT,
    aggregate,
    unicorn_base_size,
    write_detector_result,
)
from experiments.code.measurement.stage_g_harness.p2_unicorn_fpr_gen2 import (
    UNICORN_BASE_STREAM_SPLIT as UNICORN_GEN2_BASE_STREAM_SPLIT,
)


IDS = {
    "observation_generation_id": "obs:test-v1",
    "derivation_generation_id": "derive:test-v1",
    "input_generation_id": "input:test-v1",
    "detector_generation_id": "detector:test-v1",
}


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def make_context(
    tmp_path: Path, configs: dict[str, dict] | None = None,
) -> tuple[dict, Path, Path]:
    input_root = tmp_path / "inputs"
    input_root.mkdir()
    contract = {
        "schema_version": SCHEMA_VERSION,
        **IDS,
        "training_freeze_sha256": "1" * 64,
        "heldout_freeze_sha256": "2" * 64,
        "heldout_count": 1,
    }
    records = [
        {"role": "training", "profile": "W1", "run_id": "train", **IDS},
        {"role": "heldout", "profile": "W1", "run_id": "held", **IDS},
    ]
    inventory = {
        "schema_version": "assa.p2_detector_input_export.v2",
        **IDS,
        "training_freeze_sha256": contract["training_freeze_sha256"],
        "heldout_freeze_sha256": contract["heldout_freeze_sha256"],
        "records": records,
    }
    inventory_path = input_root / "input_inventory.json"
    write_json(inventory_path, inventory)
    contract["input_inventory_sha256"] = sha256(inventory_path)
    contract["detector_config_sha256"] = {
        detector: json_hash(config) for detector, config in (configs or {}).items()
    }
    contract_path = tmp_path / "generation_contract.json"
    write_json(contract_path, contract)
    return validate_exported_inventory(input_root, contract_path), input_root, contract_path


def result_payload(context: dict, detector: str, config: dict) -> dict:
    rows = [{
        "run_id": "held", "profile": "W1", "branch_outcome": "natural_write",
        "status": "passed", "binary_decision": False,
    }]
    return bind_result({
        "schema_version": "assa.p2_detector_fpr.v2",
        "detector": detector,
        "scope": "heldout_clean_FPR_only",
        "config": config,
        "config_sha256": json_hash(config),
        "summary": {},
    }, rows, context)


def test_contract_rejects_missing_generation_id(tmp_path: Path) -> None:
    path = tmp_path / "contract.json"
    write_json(path, {
        "schema_version": SCHEMA_VERSION,
        **{key: value for key, value in IDS.items() if key != "observation_generation_id"},
        "training_freeze_sha256": "1" * 64,
        "heldout_freeze_sha256": "2" * 64,
    })
    with pytest.raises(GenerationContractError, match="observation_generation_id"):
        load_generation_contract(path)


def test_scoring_rejects_contract_without_inventory_hash(tmp_path: Path) -> None:
    context, input_root, contract_path = make_context(tmp_path)
    contract = context["contract"]
    contract.pop("input_inventory_sha256")
    write_json(contract_path, contract)
    with pytest.raises(GenerationContractError, match="missing input_inventory_sha256"):
        validate_exported_inventory(input_root, contract_path)


def test_inventory_rejects_per_record_generation_mismatch(tmp_path: Path) -> None:
    context, input_root, contract_path = make_context(tmp_path)
    inventory_path = input_root / "input_inventory.json"
    inventory = json.loads(inventory_path.read_text())
    inventory["records"][1]["derivation_generation_id"] = "derive:other"
    write_json(inventory_path, inventory)
    contract = context["contract"]
    contract["input_inventory_sha256"] = sha256(inventory_path)
    write_json(contract_path, contract)
    with pytest.raises(GenerationContractError, match="generation mismatch"):
        validate_exported_inventory(input_root, contract_path)


def test_result_writer_binds_every_row_and_top_level(tmp_path: Path) -> None:
    config = {"threshold": "fixed"}
    context, _, _ = make_context(tmp_path, {"Falco": config})
    output = tmp_path / "result"
    output.mkdir()
    rows = [{
        "run_id": "held", "profile": "W1", "branch_outcome": "natural_write",
        "status": "passed", "binary_decision": False,
    }]
    write_detector_result(output, "Falco", rows, config, {}, context)
    payload = json.loads((output / "fpr_result.json").read_text())
    assert generation_stamp(payload) == IDS
    assert generation_stamp(payload["rows"][0]) == IDS
    assert payload["input_inventory_sha256"] == context["inventory_sha256"]
    validate_result_payload(payload, context, where="written result")


@pytest.mark.parametrize(
    "location,field",
    [("top", "derivation_generation_id"), ("row", "observation_generation_id")],
)
def test_result_validation_rejects_absent_generation_fields(
    tmp_path: Path, location: str, field: str,
) -> None:
    config = {"threshold": "fixed"}
    context, _, _ = make_context(tmp_path, {"Falco": config})
    payload = result_payload(context, "Falco", config)
    target = payload if location == "top" else payload["rows"][0]
    target.pop(field)
    with pytest.raises(GenerationContractError, match=field):
        validate_result_payload(payload, context, where="result")


def test_aggregate_rejects_cross_generation_row(tmp_path: Path) -> None:
    config = {"threshold": "fixed"}
    context, input_root, contract_path = make_context(tmp_path, {"Falco": config})
    payload = result_payload(context, "Falco", config)
    payload["rows"][0]["observation_generation_id"] = "obs:other"
    result_path = tmp_path / "falco.json"
    write_json(result_path, payload)
    args = Namespace(
        generation_context=context,
        input_root=input_root,
        generation_contract=contract_path,
        result=[result_path],
        output=tmp_path / "aggregate.json",
    )
    with pytest.raises(GenerationContractError, match="generation mismatch"):
        aggregate(args)
    assert not args.output.exists()


def test_aggregate_stamps_bound_generation(tmp_path: Path) -> None:
    config = {"threshold": "fixed"}
    context, input_root, contract_path = make_context(tmp_path, {"Falco": config})
    result_path = tmp_path / "falco.json"
    write_json(result_path, result_payload(context, "Falco", config))
    output = tmp_path / "aggregate.json"
    aggregate(Namespace(
        generation_context=context,
        input_root=input_root,
        generation_contract=contract_path,
        result=[result_path],
        output=output,
    ))
    payload = json.loads(output.read_text())
    assert generation_stamp(payload) == IDS
    assert payload["input_inventory_sha256"] == context["inventory_sha256"]


def test_result_rejects_duplicate_or_missing_bound_membership(tmp_path: Path) -> None:
    config = {"threshold": "fixed"}
    context, _, _ = make_context(tmp_path, {"Falco": config})
    payload = result_payload(context, "Falco", config)
    payload["rows"][0]["run_id"] = "not-held"
    with pytest.raises(GenerationContractError, match="membership differs"):
        validate_result_payload(payload, context, where="result")


def test_effective_config_drift_is_fail_closed(tmp_path: Path) -> None:
    frozen = {"threshold": "fixed", "adapter": {"mode": "one"}}
    context, _, _ = make_context(tmp_path, {"STIDE": frozen})
    changed = deepcopy(frozen)
    changed["adapter"]["mode"] = "two"
    with pytest.raises(GenerationContractError, match="effective config mismatch"):
        require_detector_config(context, "STIDE", changed)


def test_unregistered_detector_is_rejected_before_scoring(tmp_path: Path) -> None:
    context, _, _ = make_context(tmp_path, {"Falco": {"threshold": "fixed"}})
    with pytest.raises(GenerationContractError, match="no config hash for detector AIDE"):
        require_detector_registration(context, "AIDE")


def test_unicorn_split_is_behavioral_config_and_drift_changes_hash(tmp_path: Path) -> None:
    assert UNICORN_GEN2_BASE_STREAM_SPLIT == UNICORN_BASE_STREAM_SPLIT
    config = {"parser_base_stream_split": deepcopy(UNICORN_BASE_STREAM_SPLIT)}
    context, _, _ = make_context(tmp_path, {"UNICORN": config})
    assert unicorn_base_size(2) == 1
    assert unicorn_base_size(100) == 10
    assert unicorn_base_size(11) == 1
    require_detector_config(context, "UNICORN", config)
    changed = deepcopy(config)
    changed["parser_base_stream_split"]["fraction_denominator"] = 5
    assert json_hash(changed) != json_hash(config)
    with pytest.raises(GenerationContractError, match="effective config mismatch"):
        require_detector_config(context, "UNICORN", changed)


def create_graph(root: Path) -> None:
    for name in ("syscalls.jsonl", "provenance.nodes.jsonl", "provenance.edges.jsonl"):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8")
    write_json(root / "coverage.json", {"provenance_evaluable": True})


def test_exporter_binds_generation_to_inventory_and_each_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    training_run = tmp_path / "training_run"
    heldout_derived = tmp_path / "heldout_derived"
    create_graph(training_run / "graph/reattributed/resolution_spine_effective")
    create_graph(heldout_derived / "graph/reattributed/resolution_spine_effective")
    repository = tmp_path / "repository"
    source = repository / "heldout_source"
    (source / "state_snapshots/before_a").mkdir(parents=True)
    (source / "state_snapshots/before_a/MEMORY.md").write_text("clean\n")
    (source / "raw").mkdir()
    (source / "raw/capture.scap").write_bytes(b"scap")
    (source / "workspace").mkdir()
    training_freeze = tmp_path / "training.json"
    heldout_freeze = tmp_path / "heldout.json"
    write_json(training_freeze, {"records": [{
        "profile": "W1", "run_id": "train", "branch_outcome": "natural_write",
        "run_dir": str(training_run),
    }]})
    write_json(heldout_freeze, {"records": [{
        "profile": "W1", "run_id": "held", "branch_outcome": "clean_no_write",
        "derived_run_dir": str(heldout_derived), "source_run_dir": "heldout_source",
    }]})
    contract = {
        "schema_version": SCHEMA_VERSION,
        **IDS,
        "training_freeze_sha256": sha256(training_freeze),
        "heldout_freeze_sha256": sha256(heldout_freeze),
        "heldout_count": 1,
    }
    contract_path = tmp_path / "export_contract.json"
    write_json(contract_path, contract)
    output = tmp_path / "exported"
    monkeypatch.setattr(sys, "argv", [
        "export_p2_detector_inputs.py",
        "--training-freeze", str(training_freeze),
        "--heldout-freeze", str(heldout_freeze),
        "--repository-root", str(repository),
        "--generation-contract", str(contract_path),
        "--output", str(output),
    ])
    assert export_main() == 0
    inventory = json.loads((output / "input_inventory.json").read_text())
    assert inventory["schema_version"] == "assa.p2_detector_input_export.v2"
    assert generation_stamp(inventory) == IDS
    assert all(generation_stamp(record) == IDS for record in inventory["records"])
    assert inventory["training_freeze_sha256"] == sha256(training_freeze)
    assert inventory["heldout_freeze_sha256"] == sha256(heldout_freeze)
