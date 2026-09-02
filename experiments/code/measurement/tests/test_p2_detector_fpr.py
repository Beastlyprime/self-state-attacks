from __future__ import annotations

from pathlib import Path

import pytest

from experiments.code.measurement.stage_g_harness.p2_detector_fpr import (
    UNICORN_BASE_STREAM_SPLIT,
    canonical_self_state,
    parse_unicorn_grid,
    summarize_rows,
    unicorn_base_size,
    wilson,
)


def test_canonical_self_state_scope() -> None:
    root = "/runs/r/workspace"
    assert canonical_self_state("/runs/r/workspace/MEMORY.md", root)
    assert canonical_self_state("/runs/r/workspace/memory/2026-08-21.md", root)
    assert canonical_self_state("/runs/r/workspace/credentials/.env", root)
    assert not canonical_self_state("/runs/r/workspace/outbox/reply.md", root)
    assert not canonical_self_state("/runs/r/semantic/state_snapshots/after_a/MEMORY.md", root)


def test_wilson_registered_bounds() -> None:
    assert round(wilson(0, 20)["upper"], 4) == 0.1611
    assert round(wilson(0, 5)["upper"], 4) == 0.4345


def test_unicorn_grid_parser(tmp_path: Path) -> None:
    output = tmp_path / "model.log"
    output.write_text(
        "Metric: mean\tSTD: 3.0\n"
        "/out/model_test/run-a.txt is NORMAL fitting 2/2 models\n"
        "/out/model_test/run-b.txt is ABNORMAL at 7\n"
    )
    grid = parse_unicorn_grid(output, {"run-a.txt", "run-b.txt"})
    assert grid["3.0"] == {"run-a.txt": "NORMAL", "run-b.txt": "ABNORMAL"}


def test_summary_preserves_data_insufficient() -> None:
    rows = [
        {"run_id": "a", "profile": "W1", "branch_outcome": "natural_write",
         "status": "passed", "binary_decision": True},
        {"run_id": "b", "profile": "W1", "branch_outcome": "clean_no_write",
         "status": "data_insufficient", "binary_decision": None},
    ]
    summary = summarize_rows(rows)
    assert summary["pooled_primary"]["n"] == 1
    assert summary["pooled_primary"]["positive"] == 1
    assert summary["pooled_primary"]["data_insufficient"] == 1


def test_unicorn_base_stream_split_matches_frozen_policy() -> None:
    assert UNICORN_BASE_STREAM_SPLIT["fraction_denominator"] == 10
    assert unicorn_base_size(2) == 1
    assert unicorn_base_size(10) == 1
    assert unicorn_base_size(100) == 10
    with pytest.raises(ValueError, match="at least two edges"):
        unicorn_base_size(1)
