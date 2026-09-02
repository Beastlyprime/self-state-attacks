"""Tests for the mutation-matrix canary plan (canary gen2).

Covers everything that does not need root: the matrix, the seed plan, the
role inverse, the generated worker body, and the per-cell aggregation.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import mutation_matrix_canary as mmc  # noqa: E402
import mutation_op_canary as gen1  # noqa: E402


def test_matrix_is_the_full_cross_product():
    specs = mmc.build_matrix()
    assert len(specs) == len(mmc.MECHANISMS) * len(mmc.TARGET_ROLES) == 16
    pairs = {(s["op_type"], s["target_role"]) for s in specs}
    assert pairs == {(m, r) for m in mmc.MECHANISMS for r in mmc.TARGET_ROLES}


def test_cell_ids_are_unique_and_identity_free():
    specs = mmc.build_matrix()
    ids = [s["cell_id"] for s in specs]
    assert len(ids) == len(set(ids))
    for cid in ids:
        for banned in ("__poisoned", "__clean", "/runs/", "20260"):
            assert banned not in cid


def test_gen1_mechanisms_are_preserved_with_matching_syscalls():
    assert set(mmc.MECHANISMS) == set(gen1.AUDIT_SYSCALLS)
    for op, mech in mmc.MECHANISMS.items():
        assert mech["syscalls"] == gen1.AUDIT_SYSCALLS[op]


def test_spec_shape_matches_gen1_so_mask_match_applies():
    gen1_keys = {k for spec in gen1.OP_SPECS for k in spec}
    for spec in mmc.build_matrix():
        assert {"op_type", "event", "path", "logical_path"} <= set(spec)
        assert set(spec) >= {"op_type", "path"}
        # every key gen1's helpers read must be present for the same op_type
        for ref in gen1.OP_SPECS:
            if ref["op_type"] == spec["op_type"]:
                assert set(ref) - {"logical_path"} <= set(spec) | {"logical_path"}
        assert gen1_keys  # guard against an empty gen1 list


def test_each_cell_gets_a_private_target_file():
    specs = mmc.build_matrix()
    paths = [s["path"] for s in specs]
    assert len(paths) == len(set(paths)), "cells must not share a target file"


def test_instanced_paths_still_classify_to_the_intended_role():
    for spec in mmc.build_matrix():
        assert mmc.role_of(spec["path"]) == spec["target_role"], spec["path"]


def test_memory_log_instancing_keeps_the_date_leaf_shape():
    spec = next(s for s in mmc.build_matrix()
                if s["target_role"] == "self_state.memory.log"
                and s["op_type"] == "unlink")
    assert spec["path"].startswith("memory/")
    assert spec["path"].endswith("2026-01-01.md")


def test_role_table_agrees_with_the_detector_role_vocabulary():
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "code"))
    from measurement.stage_g_harness import unicorn_role_typing as urt

    for role in mmc.TARGET_ROLES:
        assert role in {
            "self_state.memory.root", "self_state.memory.log",
            "self_state.instruction", "self_state.config",
        }
        node = {"node_type": "file",
                "attributes": {"resolved_path": f"/x/runs/r1/workspace/"
                                                f"{mmc.TARGET_ROLES[role]}"}}
        assert urt.assign_role(node) == role


def test_seed_plan_covers_every_cell_target():
    plan = mmc.seed_plan()
    assert set(plan) == {s["path"] for s in mmc.build_matrix()}
    assert all(isinstance(v, bytes) and v for v in plan.values())


def test_worker_body_is_valid_python_and_touches_every_cell():
    specs = mmc.build_matrix()
    body = mmc.worker_body(specs)
    ast.parse(body)  # syntax must be valid in isolation
    for spec in specs:
        assert repr(spec["path"]) in body
        assert repr(spec["cell_id"]) in body


def test_worker_body_pins_the_same_syscalls_gen1_pins():
    """Load-bearing: auditd rules match on syscall number.

    Going through os.chmod / Path.unlink would emit a different syscall than
    the installed rule matches, and the cell would read as unobserved.
    """
    body = mmc.worker_body(mmc.build_matrix())
    assert "SYS_renameat2 = 316" in body
    assert "SYS_fchmodat = 268" in body
    assert "SYS_unlinkat = 263" in body
    for wrapper in ("os.rename", "os.unlink", "os.chmod", "p.unlink()"):
        assert wrapper not in body, wrapper


def test_pinned_syscall_numbers_are_in_gen1s_audit_rule_set():
    for op, (_name, number) in mmc.PINNED_SYSCALLS.items():
        assert number in gen1.AUDIT_SYSCALLS[op], (op, number)


def test_write_cells_use_a_plain_buffered_write_like_gen1():
    body = mmc.worker_body(
        [s for s in mmc.build_matrix() if s["op_type"] == "write"])
    assert 'with open(p, "wb") as handle:' in body


def test_worker_body_unlink_cells_do_not_reuse_another_cells_file():
    specs = mmc.build_matrix()
    unlinked = {s["path"] for s in specs if s["op_type"] == "unlink"}
    others = {s["path"] for s in specs if s["op_type"] != "unlink"}
    assert not (unlinked & others)


def test_aggregation_requires_all_five_sources():
    full = {s["cell_id"]: {src: True for src in
                           ("inotify", "fanotify", "auditd", "ebpf", "scap")}
            for s in mmc.build_matrix()}
    out = mmc.aggregate_cell_checks(full)
    assert out["all_cells_five_source_observed"] is True
    assert out["cells_missing_sources"] == {}
    assert out["cells_absent_entirely"] == []


def test_aggregation_flags_a_four_source_run_as_incomplete():
    """A gen1-shaped run (no SCAP) must not pass gen2's bar."""
    four = {s["cell_id"]: {src: True for src in
                           ("inotify", "fanotify", "auditd", "ebpf")}
            for s in mmc.build_matrix()}
    out = mmc.aggregate_cell_checks(four)
    assert out["all_cells_five_source_observed"] is False
    assert all(m == ["scap"] for m in out["cells_missing_sources"].values())


def test_aggregation_flags_missing_cells_rather_than_passing_silently():
    specs = mmc.build_matrix()
    partial = {s["cell_id"]: {src: True for src in
                              ("inotify", "fanotify", "auditd", "ebpf", "scap")}
               for s in specs[:10]}
    out = mmc.aggregate_cell_checks(partial)
    assert out["all_cells_five_source_observed"] is False
    assert len(out["cells_absent_entirely"]) == 6


def test_aggregation_of_nothing_is_not_success():
    out = mmc.aggregate_cell_checks({})
    assert out["all_cells_five_source_observed"] is False


def test_plan_is_serializable_and_declares_the_integration_gap():
    import json

    plan = mmc.plan()
    json.dumps(plan)  # must not raise
    assert plan["cell_count"] == 16
    assert "NOT implemented" in plan["five_source_integration"]["status"]
    assert plan["supersedes"].startswith("mutation_op_canary")


@pytest.mark.parametrize("field", ["reuse", "call_sites_in_gen1_flow", "acceptance"])
def test_integration_spec_names_concrete_targets(field):
    assert mmc.FIVE_SOURCE_INTEGRATION[field]
