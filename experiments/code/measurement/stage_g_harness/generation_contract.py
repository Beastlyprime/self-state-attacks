"""Fail-closed generation binding for P2 detector inputs and results."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


SCHEMA_VERSION = "assa.p2_detector_generation_contract.v1"
GENERATION_FIELDS = (
    "observation_generation_id",
    "derivation_generation_id",
    "input_generation_id",
    "detector_generation_id",
)
FREEZE_HASH_FIELDS = ("training_freeze_sha256", "heldout_freeze_sha256")


class GenerationContractError(RuntimeError):
    """A generation binding is absent, malformed, or inconsistent."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def json_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _required_string(mapping: Mapping[str, Any], field: str, where: str) -> str:
    value = mapping.get(field)
    if not isinstance(value, str) or not value.strip():
        raise GenerationContractError(f"{where}: missing or empty {field}")
    return value


def generation_ids(mapping: Mapping[str, Any], where: str) -> dict[str, str]:
    return {field: _required_string(mapping, field, where) for field in GENERATION_FIELDS}


def load_generation_contract(path: Path) -> dict[str, Any]:
    try:
        contract = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GenerationContractError(f"cannot read generation contract {path}: {exc}") from exc
    if contract.get("schema_version") != SCHEMA_VERSION:
        raise GenerationContractError(
            f"{path}: expected schema_version {SCHEMA_VERSION!r}, "
            f"got {contract.get('schema_version')!r}"
        )
    generation_ids(contract, str(path))
    for field in FREEZE_HASH_FIELDS:
        value = _required_string(contract, field, str(path))
        if len(value) != 64:
            raise GenerationContractError(f"{path}: malformed {field}")
    return contract


def generation_stamp(contract: Mapping[str, Any]) -> dict[str, str]:
    return generation_ids(contract, "generation contract")


def validate_freezes(
    contract: Mapping[str, Any], training_freeze: Path, heldout_freeze: Path,
) -> None:
    observed = {
        "training_freeze_sha256": sha256(training_freeze),
        "heldout_freeze_sha256": sha256(heldout_freeze),
    }
    for field, digest in observed.items():
        if contract.get(field) != digest:
            raise GenerationContractError(
                f"generation contract {field} mismatch: expected {contract.get(field)}, got {digest}"
            )


def stamp_record(record: Mapping[str, Any], contract: Mapping[str, Any]) -> dict[str, Any]:
    return {**record, **generation_stamp(contract)}


def _validate_stamp(
    value: Mapping[str, Any], expected: Mapping[str, str], where: str,
) -> None:
    observed = generation_ids(value, where)
    if observed != dict(expected):
        raise GenerationContractError(
            f"{where}: generation mismatch: expected {dict(expected)}, got {observed}"
        )


def validate_exported_inventory(
    input_root: Path, contract_path: Path, *, require_inventory_hash: bool = True,
) -> dict[str, Any]:
    contract = load_generation_contract(contract_path)
    inventory_path = input_root / "input_inventory.json"
    try:
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GenerationContractError(f"cannot read input inventory {inventory_path}: {exc}") from exc
    expected = generation_stamp(contract)
    _validate_stamp(inventory, expected, str(inventory_path))
    records = inventory.get("records")
    if not isinstance(records, list) or not records:
        raise GenerationContractError(f"{inventory_path}: records must be a non-empty list")
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise GenerationContractError(f"{inventory_path}: record {index} is not an object")
        _validate_stamp(record, expected, f"{inventory_path}:records[{index}]")
    for field in FREEZE_HASH_FIELDS:
        if inventory.get(field) != contract.get(field):
            raise GenerationContractError(
                f"{inventory_path}: {field} differs from generation contract"
            )
    actual_inventory_hash = sha256(inventory_path)
    expected_inventory_hash = contract.get("input_inventory_sha256")
    if require_inventory_hash:
        if not isinstance(expected_inventory_hash, str) or not expected_inventory_hash:
            raise GenerationContractError(
                f"{contract_path}: missing input_inventory_sha256; scoring is forbidden"
            )
        if actual_inventory_hash != expected_inventory_hash:
            raise GenerationContractError(
                "input inventory hash mismatch: "
                f"expected {expected_inventory_hash}, got {actual_inventory_hash}"
            )
    elif expected_inventory_hash is not None and actual_inventory_hash != expected_inventory_hash:
        raise GenerationContractError(
            "input inventory hash mismatch: "
            f"expected {expected_inventory_hash}, got {actual_inventory_hash}"
        )
    heldout_count = sum(record.get("role") == "heldout" for record in records)
    training_count = sum(record.get("role") == "training" for record in records)
    if heldout_count < 1 or training_count < 1:
        raise GenerationContractError(
            f"{inventory_path}: both training and heldout records are required"
        )
    declared_heldout = contract.get("heldout_count")
    if not isinstance(declared_heldout, int) or declared_heldout != heldout_count:
        raise GenerationContractError(
            f"heldout_count mismatch: contract={declared_heldout}, inventory={heldout_count}"
        )
    return {
        "contract": contract,
        "contract_path": str(contract_path.resolve()),
        "contract_sha256": sha256(contract_path),
        "inventory": inventory,
        "inventory_path": str(inventory_path.resolve()),
        "inventory_sha256": actual_inventory_hash,
        "generation": expected,
        "heldout_count": heldout_count,
        "training_count": training_count,
    }


def require_detector_config(
    context: Mapping[str, Any], detector: str, effective_config: Mapping[str, Any],
) -> str:
    expected = require_detector_registration(context, detector)
    actual = json_hash(effective_config)
    if actual != expected:
        raise GenerationContractError(
            f"{detector} effective config mismatch: expected {expected}, got {actual}"
        )
    return actual


def require_detector_registration(context: Mapping[str, Any], detector: str) -> str:
    expected_configs = context["contract"].get("detector_config_sha256")
    if not isinstance(expected_configs, dict):
        raise GenerationContractError(
            "generation contract missing detector_config_sha256 mapping"
        )
    expected = expected_configs.get(detector)
    if not isinstance(expected, str) or len(expected) != 64:
        raise GenerationContractError(
            f"generation contract has no config hash for detector {detector}"
        )
    return expected


def bind_result(
    payload: Mapping[str, Any], rows: list[dict[str, Any]], context: Mapping[str, Any],
) -> dict[str, Any]:
    stamp = dict(context["generation"])
    stamped_rows = []
    for index, row in enumerate(rows):
        for field in GENERATION_FIELDS:
            if field in row and row[field] != stamp[field]:
                raise GenerationContractError(
                    f"result row {index}: pre-existing {field} conflicts with contract"
                )
        stamped_rows.append({**row, **stamp})
    return {
        **payload,
        **stamp,
        "generation_contract_path": context["contract_path"],
        "generation_contract_sha256": context["contract_sha256"],
        "input_inventory_path": context["inventory_path"],
        "input_inventory_sha256": context["inventory_sha256"],
        "training_freeze_sha256": context["contract"]["training_freeze_sha256"],
        "heldout_freeze_sha256": context["contract"]["heldout_freeze_sha256"],
        "rows": stamped_rows,
    }


def validate_result_payload(
    payload: Mapping[str, Any], context: Mapping[str, Any], *, where: str,
) -> None:
    expected = context["generation"]
    _validate_stamp(payload, expected, where)
    fixed = {
        "generation_contract_sha256": context["contract_sha256"],
        "input_inventory_sha256": context["inventory_sha256"],
        "training_freeze_sha256": context["contract"]["training_freeze_sha256"],
        "heldout_freeze_sha256": context["contract"]["heldout_freeze_sha256"],
    }
    for field, expected_value in fixed.items():
        if payload.get(field) != expected_value:
            raise GenerationContractError(
                f"{where}: {field} mismatch: expected {expected_value}, got {payload.get(field)}"
            )
    detector = _required_string(payload, "detector", where)
    config = payload.get("config")
    if not isinstance(config, dict):
        raise GenerationContractError(f"{where}: missing effective config")
    config_hash = require_detector_config(context, detector, config)
    if payload.get("config_sha256") != config_hash:
        raise GenerationContractError(f"{where}: config_sha256 does not match config")
    rows = payload.get("rows")
    if not isinstance(rows, list):
        raise GenerationContractError(f"{where}: rows is not a list")
    run_ids = [row.get("run_id") for row in rows if isinstance(row, dict)]
    frozen_heldout = {
        row["run_id"] for row in context["inventory"]["records"]
        if row["role"] == "heldout"
    }
    if (
        len(rows) != context["heldout_count"]
        or len(set(run_ids)) != context["heldout_count"]
        or set(run_ids) != frozen_heldout
    ):
        raise GenerationContractError(
            f"{where}: result membership differs from bound held-out inventory"
        )
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise GenerationContractError(f"{where}: row {index} is not an object")
        _validate_stamp(row, expected, f"{where}:rows[{index}]")
