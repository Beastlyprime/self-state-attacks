#!/usr/bin/env python3
"""Mutation-matrix canary (canary gen2): every mechanism against every target row.

The gen1 canary (`mutation_op_canary.py`, landed 2026-08-12 as
`stage_g_auditd_mutation_canary_20260812`) witnesses four mechanisms against one
target file each, over four sources with no SCAP and no merged graph. It
therefore underwrites sensor achievability only for the snapshot and
feature-tuple detectors -- see
`paper/ATTACK_SAMPLE_ADMISSIBILITY_20260823.md` section 4a.

This module supplies what gen2 needs, in two halves:

  * The parts that are pure data or pure codegen -- the mechanism x target-role
    matrix, the workspace seed plan, and the worker script generated from the
    matrix. These are testable without root and are covered by
    tests/test_mutation_matrix_canary.py.

  * The collection wiring (SCAP sidecar, capture decode, graph bridge) is
    SPECIFIED here in `FIVE_SOURCE_INTEGRATION` but deliberately NOT
    implemented, because it drives root-only kernel facilities that cannot be
    exercised or tested on the analysis host. Implementing it blind would risk a
    scarce VM run. The spec names the exact helpers, call sites and contracts,
    verified against the current source, so the remaining edit is small.

gen1 is not modified. This is a separate generation.
"""
from __future__ import annotations

import json
from typing import Any

# --- the matrix -------------------------------------------------------------

# Target rows, named by the role vocabulary in
# experiments/code/measurement/stage_g_harness/unicorn_role_typing.py so a
# witness can be joined to a detector-visible role.
TARGET_ROLES: dict[str, str] = {
    "self_state.memory.root": "MEMORY.md",
    "self_state.memory.log": "memory/2026-01-01.md",
    "self_state.instruction": "TOOLS.md",
    "self_state.config": "openclaw.json",
}

# Mechanism axis, as the canonical matrix names it, with the syscall family each
# one exercises. Numbers match AUDIT_SYSCALLS in mutation_op_canary.
MECHANISMS: dict[str, dict[str, Any]] = {
    "write": {"cell": "M1/M2", "event": "write", "syscalls": {1}},
    "rename": {"cell": "M1-atomic", "event": "rename", "syscalls": {82, 264, 316}},
    "unlink": {"cell": "M3", "event": "unlink", "syscalls": {87, 263}},
    "chmod": {"cell": "M4", "event": "chmod", "syscalls": {90, 268}},
}

# Files that must exist, with initial content, before the worker runs. Every
# target of every mechanism needs a pre-image; unlink needs one it can remove.
SEED_MODE = 0o600
WORKSPACE_MODE = 0o700


def cell_id(op_type: str, role: str) -> str:
    """Stable per-cell witness key. Carries no run identity."""
    return f"{op_type}@{role}"


def build_matrix() -> list[dict[str, Any]]:
    """The mechanism x target-role cross product, 4 x 4 = 16 specs.

    Shape matches mutation_op_canary.OP_SPECS so the existing
    `_mask_match` / `_normalize` helpers apply per spec unchanged; only the
    aggregation key changes, from op_type to cell_id.
    """
    specs: list[dict[str, Any]] = []
    for op_type, mech in MECHANISMS.items():
        for role, rel_path in TARGET_ROLES.items():
            spec: dict[str, Any] = {
                "op_type": op_type,
                "event": mech["event"],
                "cell": mech["cell"],
                "target_role": role,
                "cell_id": cell_id(op_type, role),
                # Each cell gets its own copy of the target so that one
                # mechanism's unlink cannot invalidate another's pre-image.
                "logical_path": rel_path,
                "path": _instanced_path(rel_path, op_type),
            }
            if op_type == "write":
                spec["payload"] = f"canary write postimage {role}\n".encode()
            elif op_type == "rename":
                spec["payload"] = f"canary rename postimage {role}\n".encode()
                spec["tmp_path"] = spec["path"] + ".tmp"
            elif op_type == "chmod":
                spec["mode_after"] = 0o640
            specs.append(spec)
    return specs


def _instanced_path(rel_path: str, op_type: str) -> str:
    """Give each (mechanism, target) cell a private file under the same role.

    `memory/2026-01-01.md` under op `unlink` becomes
    `memory/unlink__2026-01-01.md`, which keeps the role classification (the
    role table matches on the `memory/` prefix and the `<DATE>.md` leaf shape)
    while isolating cells from each other.
    """
    if "/" in rel_path:
        head, leaf = rel_path.rsplit("/", 1)
        return f"{head}/{op_type}__{leaf}"
    return f"{op_type}__{rel_path}"


def seed_plan() -> dict[str, bytes]:
    """Files to create, chowned to the agent account, before the worker runs."""
    plan: dict[str, bytes] = {}
    for spec in build_matrix():
        plan[spec["path"]] = f"initial {spec['target_role']}\n".encode()
    return plan


def role_of(path: str) -> str | None:
    """Inverse of the instancing, for checking a witness lands in the right row."""
    for role, rel in TARGET_ROLES.items():
        if "/" in rel:
            head, leaf = rel.rsplit("/", 1)
            if path.startswith(head + "/") and path.endswith(leaf):
                return role
        elif path.endswith(rel):
            return role
    return None


# --- worker codegen ---------------------------------------------------------

# Syscall numbers are pinned exactly as gen1 pins them. This is load-bearing:
# the auditd rules match on syscall number, and the legacy rename(2) tracepoint
# is not attachable on the pinned guest. Going through os.chmod / Path.unlink
# instead would emit a different syscall than the installed rule matches, and
# the cell would silently read as unobserved.
PINNED_SYSCALLS: dict[str, tuple[str, int]] = {
    "rename": ("renameat2", 316),
    "chmod": ("fchmodat", 268),
    "unlink": ("unlinkat", 263),
}
AT_FDCWD = -100

WORKER_PREAMBLE = """import ctypes
libc = ctypes.CDLL(None, use_errno=True)
AT_FDCWD = %d
SYS_renameat2 = %d
SYS_fchmodat = %d
SYS_unlinkat = %d

def _syscall(number, *args):
    ret = libc.syscall(ctypes.c_long(number), *args)
    if ret != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), "syscall %%d" %% number)
    return ret
""" % (AT_FDCWD, PINNED_SYSCALLS["rename"][1], PINNED_SYSCALLS["chmod"][1],
       PINNED_SYSCALLS["unlink"][1])


def worker_body(specs: list[dict[str, Any]]) -> str:
    """Generate the per-cell mutation body executed by the demoted worker.

    Mirrors gen1's worker exactly on syscall shape: write goes through a plain
    buffered write, while rename, chmod and unlink go through `libc.syscall`
    with the numbers pinned in `PINNED_SYSCALLS`, so the auditd syscall rules
    match. Emitted as source for splicing into gen1's `_worker_script` scaffold.
    """
    lines = [WORKER_PREAMBLE]
    for spec in specs:
        rel, op, cid = spec["path"], spec["op_type"], spec["cell_id"]
        lines.append(f"# cell {cid}")
        lines.append(f"p = workspace / {rel!r}")
        if op == "write":
            lines += [
                'before = p.read_bytes() if p.exists() else b""',
                'with open(p, "wb") as handle:',
                f"    actual = handle.write({spec['payload']!r})",
                f"record({op!r}, {rel!r}, True, p.exists(), {{"
                f"'cell_id': {cid!r}, 'actual': actual, "
                "'pre_sha256': hashlib.sha256(before).hexdigest(), "
                "'post_sha256': hashlib.sha256(p.read_bytes()).hexdigest()})",
            ]
        elif op == "rename":
            lines += [
                f"tmp = workspace / {spec['tmp_path']!r}",
                f"tmp.write_bytes({spec['payload']!r})",
                "_syscall(SYS_renameat2, ctypes.c_int(AT_FDCWD), ctypes.c_char_p(bytes(tmp)),",
                "         ctypes.c_int(AT_FDCWD), ctypes.c_char_p(bytes(p)), ctypes.c_uint(0))",
                f"record({op!r}, {rel!r}, True, p.exists(), {{"
                f"'cell_id': {cid!r}, 'tmp_path': {spec['tmp_path']!r}, "
                "'rename_syscall': 'renameat2', "
                "'post_sha256': hashlib.sha256(p.read_bytes()).hexdigest()})",
            ]
        elif op == "chmod":
            lines += [
                "before_mode = p.stat().st_mode & 0o7777",
                "_syscall(SYS_fchmodat, ctypes.c_int(AT_FDCWD), ctypes.c_char_p(bytes(p)),",
                f"         ctypes.c_int({spec['mode_after']:#o}), ctypes.c_int(0))",
                f"record({op!r}, {rel!r}, True, p.exists(), {{"
                f"'cell_id': {cid!r}, 'chmod_syscall': 'fchmodat', "
                "'mode_before': before_mode, "
                "'mode_after': p.stat().st_mode & 0o7777})",
            ]
        elif op == "unlink":
            lines += [
                "before_sha = hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None",
                "_syscall(SYS_unlinkat, ctypes.c_int(AT_FDCWD), ctypes.c_char_p(bytes(p)),",
                "         ctypes.c_int(0))",
                f"record({op!r}, {rel!r}, True, p.exists(), {{"
                f"'cell_id': {cid!r}, 'unlink_syscall': 'unlinkat', "
                "'pre_sha256': before_sha})",
            ]
        lines.append("")
    return "\n".join(lines)


def aggregate_cell_checks(
    per_cell_source_checks: dict[str, dict[str, bool]],
    required_sources: tuple[str, ...] = ("inotify", "fanotify", "auditd", "ebpf", "scap"),
) -> dict[str, Any]:
    """Roll per-cell/per-source observations into a readiness verdict.

    gen1 aggregated by op_type over four sources. gen2 aggregates by cell over
    five, so an unwitnessed (mechanism, target row) pair cannot be hidden by a
    sibling cell of the same mechanism.
    """
    coverage = {
        cid: all(checks.get(src, False) for src in required_sources)
        for cid, checks in per_cell_source_checks.items()
    }
    missing = {
        cid: sorted(src for src in required_sources if not checks.get(src, False))
        for cid, checks in per_cell_source_checks.items()
        if not coverage[cid]
    }
    expected = {spec["cell_id"] for spec in build_matrix()}
    return {
        "required_sources": list(required_sources),
        "cell_source_checks": per_cell_source_checks,
        "cell_coverage": coverage,
        "cells_missing_sources": missing,
        "cells_absent_entirely": sorted(expected - set(per_cell_source_checks)),
        "all_cells_five_source_observed": (
            bool(coverage) and all(coverage.values())
            and not (expected - set(per_cell_source_checks))
        ),
    }


# --- what still needs a root VM --------------------------------------------

FIVE_SOURCE_INTEGRATION: dict[str, Any] = {
    "status": "specified, NOT implemented -- needs a root VM to develop against",
    "why_not_implemented": (
        "SCAP capture, auditd rule installation, eBPF load and the graph bridge "
        "all require root plus auditd/bpffs/clang/sysdig, none present on the "
        "analysis host. Writing this blind risks the VM run it is meant to serve."
    ),
    "reuse": {
        "scap_sidecar": (
            "experiments/code/measurement/stage_g_harness/sidecars.py::ScapSidecar.sysdig("
            "output_dir, engine='modern-bpf', scope_mode=...) then .start()/.stop(); "
            "writes raw/capture.scap plus raw/scap.{stdout,stderr}.log"
        ),
        "decoder": (
            "experiments/code/measurement/stage_g_harness/scap.py::decode_capture("
            "capture_path, raw/scap.events.jsonl, runner_uid=<agent uid>, "
            "allowed_pids={worker_pid}, sysdig=<binary>)"
        ),
        "graph": (
            "experiments/code/dataset_builder/five_source_graph_bridge.py::main -- "
            "emits graph/{provenance.nodes,provenance.edges,syscalls}.jsonl, "
            "coverage.json and five_source_graph_bridge.json "
            "(schema assa.five_source_graph_bridge.v2)"
        ),
        "collectors_and_audit": (
            "import unchanged from mutation_op_canary: _inotify_collector, "
            "_fanotify_fid_collector, _fanotify_watchdog, _compile_ebpf, "
            "_audit_rule_commands, _spawn_worker, _snapshot_state, _normalize, "
            "_mask_match, _write_minimal_records"
        ),
    },
    "call_sites_in_gen1_flow": {
        "start_scap": (
            "after the eBPF loader is ready and the auditd rules are installed, "
            "BEFORE release.write_text('go') -- mutation_op_canary.py:379"
        ),
        "stop_scap": (
            "after worker.communicate() and the post snapshots, alongside the "
            "eBPF SIGINT -- mutation_op_canary.py:381-383"
        ),
        "decode": "immediately after stop, before _normalize",
        "graph_bridge": "after _normalize, before validate_run",
    },
    "acceptance": {
        "per_cell": "all 16 cells observed on all five sources",
        "spine": "five_source_graph_bridge acceptance_line.passed true, spine_rate >= 0.95",
        "cleanup": "sudo auditctl -l prints 'No rules' after the run",
        "unchanged": "gen1 artifacts under stage_g_auditd_mutation_canary_20260812 untouched",
    },
    "cost": "one VM run",
}


def plan() -> dict[str, Any]:
    """Machine-readable description of what gen2 would collect."""
    specs = build_matrix()
    return {
        "schema_version": "assa.mutation_matrix_canary_plan.v1",
        "supersedes": "mutation_op_canary (gen1), which is left unmodified",
        "mechanisms": sorted(MECHANISMS),
        "target_roles": TARGET_ROLES,
        "cell_count": len(specs),
        "cells": [s["cell_id"] for s in specs],
        "seed_files": sorted(seed_plan()),
        "five_source_integration": FIVE_SOURCE_INTEGRATION,
    }


def main() -> int:
    print(json.dumps(plan(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
