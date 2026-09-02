"""Deterministic benchmark release point for self-state mutations.

The semantic decision is intentionally bypassed, but the mutation is dispatched
through the same ``build_default_tool_registry`` used by normal agent sessions.
This module writes no result files: the caller captures its single JSON object
from stdout after the agent process exits, keeping labeling I/O outside the
agent's target-file write path.

This entry point is benchmark-only and is never enabled by a normal session.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Optional

from .session.runner import build_default_tool_registry
from .trace.schema import full_byte_snapshot, process_identity


SPEC_SCHEMA = "assa.release.v1"


def _validate_spec(spec: dict[str, Any]) -> None:
    if spec.get("schema_version") != SPEC_SCHEMA:
        raise ValueError(f"schema_version must be {SPEC_SCHEMA!r}")
    for field in ("run_id", "pair_id", "variant", "target_file", "tool"):
        if not isinstance(spec.get(field), str) or not spec[field]:
            raise ValueError(f"{field} must be a non-empty string")
    if spec["variant"] not in {"benign", "attack"}:
        raise ValueError("variant must be benign or attack")
    expected_label = 1 if spec["variant"] == "attack" else 0
    if spec.get("label") != expected_label:
        raise ValueError("label does not match variant")
    if spec["tool"] not in {"write", "edit"}:
        raise ValueError("pilot release supports write/edit only")
    args = spec.get("arguments")
    if not isinstance(args, dict):
        raise ValueError("arguments must be an object")
    if args.get("path") != spec["target_file"]:
        raise ValueError("arguments.path must equal target_file")
    if spec["tool"] == "write" and not isinstance(args.get("content"), str):
        raise ValueError("write requires string content")
    if spec["tool"] == "edit" and not all(
        isinstance(args.get(key), str) for key in ("old_text", "new_text")
    ):
        raise ValueError("edit requires string old_text and new_text")


def execute_release(workspace_root: str, spec: dict[str, Any]) -> dict[str, Any]:
    """Execute one validated operation through the real agent tool registry."""
    _validate_spec(spec)
    root = Path(workspace_root).resolve()
    target = (root / spec["target_file"]).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise ValueError("target_file escapes workspace_root") from exc

    identity = process_identity()
    registry = build_default_tool_registry(str(root))
    before_raw = target.read_bytes() if target.exists() else b""

    start_wall_ns = time.time_ns()
    start_mono_ns = time.monotonic_ns()
    tool_result = registry[spec["tool"]](**spec["arguments"])
    end_mono_ns = time.monotonic_ns()
    end_wall_ns = time.time_ns()
    after_raw = target.read_bytes() if target.exists() else b""

    if is_dataclass(tool_result):
        serialized_result: Any = asdict(tool_result)
    elif isinstance(tool_result, dict):
        serialized_result = tool_result
    else:
        serialized_result = {"value": str(tool_result)}

    ok = bool(serialized_result.get("ok", False))

    return {
        "schema_version": "assa.ground_truth.v1",
        "run_id": spec["run_id"],
        "pair_id": spec["pair_id"],
        "variant": spec["variant"],
        "label": spec["label"],
        "target_file": spec["target_file"],
        "tool": spec["tool"],
        "process": identity,
        "preimage": full_byte_snapshot(before_raw),
        "postimage": full_byte_snapshot(after_raw),
        "timing": {
            "start_wall_ns": start_wall_ns,
            "end_wall_ns": end_wall_ns,
            "start_monotonic_ns": start_mono_ns,
            "end_monotonic_ns": end_mono_ns,
            "elapsed_ns": end_mono_ns - start_mono_ns,
        },
        "tool_result": serialized_result,
        "success": ok,
    }


def load_spec(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("release spec must be a JSON object")
    return payload


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run one agent-native benchmark release")
    parser.add_argument("workspace")
    parser.add_argument("--spec", required=True, help="Validated release-spec JSON")
    args = parser.parse_args(argv)
    try:
        result = execute_release(args.workspace, load_spec(args.spec))
    except Exception as exc:  # noqa: BLE001 - CLI must emit machine-readable failure
        result = {
            "schema_version": "assa.ground_truth.v1",
            "success": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    sys.exit(main())
