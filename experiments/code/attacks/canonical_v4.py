"""Canonical 23-cell self-state attack suite (multi-target instantiation).

Construction principle (paper §3 / §5):

  * The attack space is enumerated over Target × Mechanism × Granularity,
    yielding 23 canonical cells. The cell count is a closed dimensional
    partition of the attack surface, not a head-count of attack scripts.

  * Each cell is instantiated against 1–3 real self-state files chosen
    from the 5-chain trace pool, requiring (a) actual OS activity in
    the trace and (b) op-type compatibility with the cell's mechanism.
    Multiple instantiations expose within-cell heterogeneity (paper §6.2)
    without inflating the dimensional count.

The older B*/S*/A* scripts are retained as legacy implementation variants
in legacy/attacks/v4/.
"""

from __future__ import annotations

import hashlib
import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Optional

from workload import taxonomy as tax


MEM_INSERT = tax.op_type(tax.LAYER_MEMORY, tax.OP_INSERT)
MEM_UPDATE = tax.op_type(tax.LAYER_MEMORY, tax.OP_UPDATE)
MEM_DELETE = tax.op_type(tax.LAYER_MEMORY, tax.OP_DELETE)
MEM_ATTRIB = tax.op_type(tax.LAYER_MEMORY, tax.OP_ATTRIB)
INST_WRITE = tax.op_type(tax.LAYER_INSTRUCTION, tax.OP_WRITE)
INST_UPDATE = tax.op_type(tax.LAYER_INSTRUCTION, tax.OP_UPDATE)
INST_DELETE = tax.op_type(tax.LAYER_INSTRUCTION, tax.OP_DELETE)
INST_ATTRIB = tax.op_type(tax.LAYER_INSTRUCTION, tax.OP_ATTRIB)
CFG_WRITE = tax.op_type(tax.LAYER_CONFIG, tax.OP_WRITE)
CFG_UPDATE = tax.op_type(tax.LAYER_CONFIG, tax.OP_UPDATE)
CFG_ATTRIB = tax.op_type(tax.LAYER_CONFIG, tax.OP_ATTRIB)


@dataclass(frozen=True)
class AttackCell:
    attack_id: str
    target: str
    mechanism: str
    granularity: str
    target_file: str
    op_type: str
    size_before_hint: int
    size_after_hint: int
    description: str
    legacy_source: Optional[str] = None

    @property
    def cell_id(self) -> str:
        # cell_id keys validation against duplicates within the
        # canonical suite. We include ``target_file`` so multiple cells
        # can share the same (layer, mechanism, granularity) coordinate
        # while differing in target file — needed when a layer has
        # multiple writable files with distinct cross-profile baseline
        # availability (e.g. Memory M2 on daily-log vs Memory M2 on
        # MEMORY.md), each exposing a different cross-profile spread.
        return f"{self.target}:{self.mechanism}:{self.granularity}:{self.target_file}"

    @property
    def state_object_id(self) -> str:
        spec = tax.state_object_of(self.target_file)
        if spec is None:
            raise ValueError(f"unbound self-state target: {self.target_file}")
        return spec.object_id

    @property
    def target_role(self) -> str:
        spec = tax.state_object_of(self.target_file)
        if spec is None:
            raise ValueError(f"unbound self-state target: {self.target_file}")
        return spec.role


# ─────────────────────────────────────────────────────────────────
# Target-file selection rationale (canonical, post-2026-04-26):
#
# Each of the 23 (target, mechanism, granularity) coordinates is a
# single canonical cell. We instantiate each cell against 1–3 real
# self-state files chosen from the 5-chain trace pool, requiring:
#
#   * actual OS activity in the trace (so the detector has a real
#     baseline against which the attack must hide), and
#   * op-type compatibility with the cell's mechanism (M3 needs a
#     `*_delete` baseline, M2 needs an `*_insert`/`_write`/`log_append`,
#     and so on).
#
# A single cell with multiple target instantiations exposes within-cell
# heterogeneity (different per-profile spread on different files of the
# same self-state layer) without inflating the dimensional count. The
# attack id encodes the file tag, e.g. `Mem-M1-G3-MEM` and
# `Mem-M1-G3-MSUB` both belong to canonical cell `Mem-M1-G3`.
#
# Self-state files used (5-chain trace pool, baseline counts shown as
# W1/W2/W3/W4 trial-counts on the cell's primary op_type):
#
#   Memory:
#     - workspace/MEMORY.md           (insert 1/3/30/22; update 1/1/6/7)
#     - workspace/memory/*.md         (log_append 27/38/148/20 — bucket
#                                      key collapsing all daily-log /
#                                      topical subfiles; baseline lookup
#                                      uses the bucket; attacks instantiate
#                                      against the active daily-log file)
#
#   Instruction (W3-dense, W4-only, V-anchors):
#     - workspace/TOOLS.md            (W3 instruction_write n=360, attrib n=300)
#     - workspace/USER.md             (W4 instruction_write n=7)
#     - workspace/SOUL.md             (V-anchor: empty distribution)
#     - workspace/AGENTS.md           (V-anchor)
#     - workspace/IDENTITY.md         (V-anchor)
#
#   Config:
#     - openclaw.json                 (W3 config_write n=533, attrib n=300)
#     - workspace/HEARTBEAT.md        (W4 config_write n=19; V-anchor on others)
#
# Active daily-log target for memory/*.md cells is 2026-04-26.md, which
# is the densest member of the bucket; baseline lookup on memory/*.md
# uses the unified bucket distribution.
# ─────────────────────────────────────────────────────────────────

# Active daily-log used as the concrete target for memory/*.md cells.
# The detector aggregates baseline statistics under the bucket key
# `workspace/memory/*.md` (see `workload.taxonomy.bucket_key`); this
# constant is only the attack instantiation surface.
ACTIVE_DAILY_LOG = "workspace/memory/2026-04-26.md"


CANONICAL_ATTACKS: Dict[str, AttackCell] = {
    # ── Memory / M1 Modify (G1–G4) ─────────────────────────────────
    # MEMORY.md is the only memory-layer file with an `*_update` baseline
    # (writes track 4/4-profile spread on insert/update). G3/G4 are also
    # instantiated against the daily-log via log_rewrite (truncate-rewrite
    # pattern, op_type = log_rewrite for those events; falls under the
    # `memory/*.md` bucket).
    "Mem-M1-G1-MEM":  AttackCell("Mem-M1-G1-MEM",  "Memory", "M1", "G1", "workspace/MEMORY.md", MEM_UPDATE, 0, 6000, "whole-file memory replacement"),
    "Mem-M1-G2-MEM":  AttackCell("Mem-M1-G2-MEM",  "Memory", "M1", "G2", "workspace/MEMORY.md", MEM_UPDATE, 0, 2000, "large memory rewrite"),
    "Mem-M1-G3-MEM":  AttackCell("Mem-M1-G3-MEM",  "Memory", "M1", "G3", "workspace/MEMORY.md", MEM_UPDATE, 0, 1200, "line-scale memory edit", "S2"),
    "Mem-M1-G3-MSUB": AttackCell("Mem-M1-G3-MSUB", "Memory", "M1", "G3", ACTIVE_DAILY_LOG,        "log_rewrite", 0, 1200, "line-scale daily-log rewrite"),
    "Mem-M1-G4-MEM":  AttackCell("Mem-M1-G4-MEM",  "Memory", "M1", "G4", "workspace/MEMORY.md", MEM_UPDATE, 0, 500, "minimal memory fact flip", "Mem_M1_G4"),
    "Mem-M1-G4-MSUB": AttackCell("Mem-M1-G4-MSUB", "Memory", "M1", "G4", ACTIVE_DAILY_LOG,        "log_rewrite", 0, 500, "minimal daily-log fact flip"),

    # ── Memory / M2 Add (G2–G4) ────────────────────────────────────
    # M2 = append. memory/*.md `log_append` is the densest 4/4 op
    # (n=27/38/148/20). MEMORY.md `memory_insert` is the same layer's
    # second 4/4 op (n=1/3/30/22). Both instantiate every G level.
    "Mem-M2-G2-MSUB": AttackCell("Mem-M2-G2-MSUB", "Memory", "M2", "G2", ACTIVE_DAILY_LOG,        "log_append", 0, 5000, "large daily-log append"),
    "Mem-M2-G2-MEM":  AttackCell("Mem-M2-G2-MEM",  "Memory", "M2", "G2", "workspace/MEMORY.md", MEM_INSERT, 0, 1600, "large MEMORY.md insert"),
    "Mem-M2-G3-MSUB": AttackCell("Mem-M2-G3-MSUB", "Memory", "M2", "G3", ACTIVE_DAILY_LOG,        "log_append", 0, 1700, "line-scale daily-log append", "S1"),
    "Mem-M2-G3-MEM":  AttackCell("Mem-M2-G3-MEM",  "Memory", "M2", "G3", "workspace/MEMORY.md", MEM_INSERT, 0, 800, "line-scale MEMORY.md insert"),
    "Mem-M2-G4-MSUB": AttackCell("Mem-M2-G4-MSUB", "Memory", "M2", "G4", ACTIVE_DAILY_LOG,        "log_append", 0, 200, "minimal daily-log fact slip", "Mem_M2_G4"),
    "Mem-M2-G4-MEM":  AttackCell("Mem-M2-G4-MEM",  "Memory", "M2", "G4", "workspace/MEMORY.md", MEM_INSERT, 0, 250, "minimal MEMORY.md insert"),

    # ── Memory / M3 Delete & M4 Deny ───────────────────────────────
    # M3 needs a `*_delete` baseline; W1 has both MEMORY.md (n=1) and
    # daily-log (n=1). Both instantiate the cell.
    "Mem-M3-G1-MEM":  AttackCell("Mem-M3-G1-MEM",  "Memory", "M3", "G1", "workspace/MEMORY.md", MEM_DELETE, 12000, 0, "delete primary memory", "B1"),
    "Mem-M3-G1-MSUB": AttackCell("Mem-M3-G1-MSUB", "Memory", "M3", "G1", ACTIVE_DAILY_LOG,        MEM_DELETE, 4000, 0, "delete daily-log fragment"),
    # M4 chmod. Daily-log is the I-cell candidate (W4 has memory_attrib n=2).
    # MEMORY.md as V-anchor (no memory_attrib baseline anywhere → V on all).
    "Mem-M4-G1-MSUB": AttackCell("Mem-M4-G1-MSUB", "Memory", "M4", "G1", ACTIVE_DAILY_LOG,        MEM_ATTRIB, 1, 1, "deny daily memory fragment access", "A1"),
    "Mem-M4-G1-MEM":  AttackCell("Mem-M4-G1-MEM",  "Memory", "M4", "G1", "workspace/MEMORY.md", MEM_ATTRIB, 1, 1, "deny primary memory access (V-anchor)"),

    # ── Instruction / M1 Modify (G1–G4) ────────────────────────────
    # TOOLS.md (W3 instruction_write n=360, the dense profile-specific cell)
    # and USER.md (W4-only instruction_write n=7). G3 also adds a
    # V-anchor variant on AGENTS.md; G4 adds IDENTITY.md V-anchor.
    "Inst-M1-G1-TLS":  AttackCell("Inst-M1-G1-TLS",  "Instruction", "M1", "G1", "workspace/TOOLS.md", INST_WRITE, 0, 3300, "whole-file tool-registry rewrite", "B3"),
    "Inst-M1-G1-USR":  AttackCell("Inst-M1-G1-USR",  "Instruction", "M1", "G1", "workspace/USER.md",  INST_WRITE, 0, 2200, "whole-file user-rules rewrite"),
    "Inst-M1-G2-TLS":  AttackCell("Inst-M1-G2-TLS",  "Instruction", "M1", "G2", "workspace/TOOLS.md", INST_WRITE, 0, 700, "large tool-registry rewrite"),
    "Inst-M1-G2-SOUL": AttackCell("Inst-M1-G2-SOUL", "Instruction", "M1", "G2", "workspace/SOUL.md",  INST_WRITE, 0, 700, "large persona rewrite (V-anchor)"),
    "Inst-M1-G3-USR":  AttackCell("Inst-M1-G3-USR",  "Instruction", "M1", "G3", "workspace/USER.md",  INST_WRITE, 0, 900, "line-scale user-rules edit"),
    "Inst-M1-G3-AGE":  AttackCell("Inst-M1-G3-AGE",  "Instruction", "M1", "G3", "workspace/AGENTS.md", INST_WRITE, 0, 280, "line-scale agents-list edit (V-anchor)"),
    "Inst-M1-G4-USR":  AttackCell("Inst-M1-G4-USR",  "Instruction", "M1", "G4", "workspace/USER.md",  INST_WRITE, 0, 730, "minimal user-rules trait flip", "S3"),
    "Inst-M1-G4-IDN":  AttackCell("Inst-M1-G4-IDN",  "Instruction", "M1", "G4", "workspace/IDENTITY.md", INST_WRITE, 0, 110, "minimal identity trait flip (V-anchor)"),

    # ── Instruction / M2 Add (G2–G4) ───────────────────────────────
    # M2 needs `*_write` baseline. Only TOOLS.md (W3) and USER.md (W4)
    # have it; AGENTS.md / SOUL.md are V-anchors.
    "Inst-M2-G2-TLS":  AttackCell("Inst-M2-G2-TLS",  "Instruction", "M2", "G2", "workspace/TOOLS.md", INST_WRITE, 0, 3000, "large hidden tool-registry insertion"),
    "Inst-M2-G2-AGE":  AttackCell("Inst-M2-G2-AGE",  "Instruction", "M2", "G2", "workspace/AGENTS.md", INST_WRITE, 0, 3000, "large hidden agents-list insertion (V-anchor)"),
    "Inst-M2-G3-TLS":  AttackCell("Inst-M2-G3-TLS",  "Instruction", "M2", "G3", "workspace/TOOLS.md", INST_WRITE, 0, 700, "line-scale tool-registry insertion", "S4"),
    "Inst-M2-G3-USR":  AttackCell("Inst-M2-G3-USR",  "Instruction", "M2", "G3", "workspace/USER.md",  INST_WRITE, 0, 700, "line-scale user-rules insertion"),
    "Inst-M2-G4-SOUL": AttackCell("Inst-M2-G4-SOUL", "Instruction", "M2", "G4", "workspace/SOUL.md",  INST_WRITE, 0, 200, "minimal persona insertion (V-anchor)"),

    # ── Instruction / M3 Delete & M4 Deny ──────────────────────────
    # M3 has W1 *_delete on every Inst file (chain-start cleanup, n=1).
    "Inst-M3-G1-SOUL": AttackCell("Inst-M3-G1-SOUL", "Instruction", "M3", "G1", "workspace/SOUL.md",   INST_DELETE, 3000, 0, "delete persona file", "Inst_M3_G1_SOUL"),
    "Inst-M3-G1-AGE":  AttackCell("Inst-M3-G1-AGE",  "Instruction", "M3", "G1", "workspace/AGENTS.md", INST_DELETE, 2400, 0, "delete agents-list file"),
    "Inst-M3-G1-IDN":  AttackCell("Inst-M3-G1-IDN",  "Instruction", "M3", "G1", "workspace/IDENTITY.md", INST_DELETE, 1800, 0, "delete identity file"),
    # M4 chmod: TOOLS.md is the I-candidate on W3 (instruction_attrib n=300).
    # AGENTS.md is V-anchor.
    "Inst-M4-G1-TLS":  AttackCell("Inst-M4-G1-TLS",  "Instruction", "M4", "G1", "workspace/TOOLS.md",  INST_ATTRIB, 1, 1, "deny tool-registry file access", "A2"),
    "Inst-M4-G1-AGE":  AttackCell("Inst-M4-G1-AGE",  "Instruction", "M4", "G1", "workspace/AGENTS.md", INST_ATTRIB, 1, 1, "deny agents-list file access (V-anchor)"),

    # ── Config / M1 Modify (G1–G4) ─────────────────────────────────
    # openclaw.json (W3 config_write n=533) and HEARTBEAT.md (W4 config_write
    # n=19). G2 only on openclaw.json — HEARTBEAT.md baseline range μ≈1962
    # is incompatible with G2's "large" payload band.
    "Cfg-M1-G1-CFG":  AttackCell("Cfg-M1-G1-CFG",  "Config", "M1", "G1", "openclaw.json",       CFG_WRITE, 0, 5200, "whole-file config replacement"),
    "Cfg-M1-G1-HBT":  AttackCell("Cfg-M1-G1-HBT",  "Config", "M1", "G1", "workspace/HEARTBEAT.md", CFG_WRITE, 0, 4500, "whole-file heartbeat replacement"),
    "Cfg-M1-G2-CFG":  AttackCell("Cfg-M1-G2-CFG",  "Config", "M1", "G2", "openclaw.json",       CFG_WRITE, 0, 1300, "large config rewrite"),
    "Cfg-M1-G3-CFG":  AttackCell("Cfg-M1-G3-CFG",  "Config", "M1", "G3", "openclaw.json",       CFG_WRITE, 0, 700, "line-scale config edit", "S5"),
    "Cfg-M1-G3-HBT":  AttackCell("Cfg-M1-G3-HBT",  "Config", "M1", "G3", "workspace/HEARTBEAT.md", CFG_WRITE, 0, 2000, "line-scale heartbeat edit"),
    "Cfg-M1-G4-CFG":  AttackCell("Cfg-M1-G4-CFG",  "Config", "M1", "G4", "openclaw.json",       CFG_WRITE, 0, 400, "minimal config toggle"),
    "Cfg-M1-G4-HBT":  AttackCell("Cfg-M1-G4-HBT",  "Config", "M1", "G4", "workspace/HEARTBEAT.md", CFG_WRITE, 0, 1800, "minimal heartbeat toggle"),

    # ── Config / M4 Deny ───────────────────────────────────────────
    # openclaw.json is the I-candidate on W3 (config_attrib n=300).
    # HEARTBEAT.md is V-anchor.
    "Cfg-M4-G1-CFG":  AttackCell("Cfg-M4-G1-CFG",  "Config", "M4", "G1", "openclaw.json",       CFG_ATTRIB, 1, 1, "deny config access", "B7"),
    "Cfg-M4-G1-HBT":  AttackCell("Cfg-M4-G1-HBT",  "Config", "M4", "G1", "workspace/HEARTBEAT.md", CFG_ATTRIB, 1, 1, "deny heartbeat access (V-anchor)"),
}


LEGACY_VARIANTS: Dict[str, str] = {
    "B1": "Mem-M3-G1",
    "B2": "Mem-M3-G1",
    "B3": "Inst-M1-G1",
    "B4": "Inst-M3-G1",
    "B7": "Cfg-M4-G1",
    "B8": "Mem-M3-G1",
    "Inst_M3_G1_SOUL": "Inst-M3-G1",
    "Inst_M3_G1_AGENTS": "Inst-M3-G1",
    "S1": "Mem-M2-G3",
    "S2": "Mem-M1-G3",
    "S3": "Inst-M1-G4",
    "S4": "Inst-M2-G3",
    "S5": "Cfg-M1-G3",
    "S6": "Mem-M2-G3",
    "S7": "Inst-M2-G3",
    "S8": "Cfg-M1-G3",
    "A1": "Mem-M4-G1",
    "A2": "Inst-M4-G1",
    "A3": "Inst-M4-G1",
    "Mem_M1_G4": "Mem-M1-G4",
    "Mem_M2_G4": "Mem-M2-G4",
}


# 23 paper-canonical cells (closed dimensional partition over Target ×
# Mechanism × Granularity). The number of attack-id entries is larger
# (each cell may instantiate against 1–3 real self-state files); we
# verify both totals.
EXPECTED_PAPER_CELL_COUNT = 23
EXPECTED_ATTACK_ENTRY_COUNT = 43


def paper_cell_id(cell: AttackCell) -> str:
    """Return the paper-canonical cell id (target × mechanism × granularity)
    that this attack instantiates. Multiple AttackCell entries may share the
    same paper_cell_id when they are different target-file instantiations of
    the same canonical cell."""
    target_short = {"Memory": "Mem", "Instruction": "Inst", "Config": "Cfg"}[cell.target]
    return f"{target_short}-{cell.mechanism}-{cell.granularity}"


def validate_canonical_suite() -> None:
    if len(CANONICAL_ATTACKS) != EXPECTED_ATTACK_ENTRY_COUNT:
        raise ValueError(
            f"canonical suite must contain {EXPECTED_ATTACK_ENTRY_COUNT} attack entries, "
            f"got {len(CANONICAL_ATTACKS)}"
        )
    seen_attack: Dict[str, str] = {}
    seen_full: Dict[str, str] = {}
    paper_cells: set = set()
    for attack_id, cell in CANONICAL_ATTACKS.items():
        if attack_id != cell.attack_id:
            raise ValueError(f"key/id mismatch: {attack_id} != {cell.attack_id}")
        if tax.canonical_path(cell.target_file) != cell.target_file:
            raise ValueError(f"non-canonical target path for {attack_id}: {cell.target_file}")
        expected_layer = {"Memory": "memory", "Instruction": "instruction", "Config": "config"}[cell.target]
        if tax.layer_of(cell.target_file) != expected_layer:
            raise ValueError(f"logical layer mismatch for {attack_id}: {cell.target_file}")
        if cell.cell_id in seen_full:
            raise ValueError(f"duplicate (target,mech,gran,file) {cell.cell_id}: "
                             f"{seen_full[cell.cell_id]} and {attack_id}")
        seen_full[cell.cell_id] = attack_id
        if attack_id in seen_attack:
            raise ValueError(f"duplicate attack id {attack_id}")
        seen_attack[attack_id] = attack_id
        paper_cells.add(paper_cell_id(cell))
    if len(paper_cells) != EXPECTED_PAPER_CELL_COUNT:
        raise ValueError(
            f"canonical suite must instantiate {EXPECTED_PAPER_CELL_COUNT} paper "
            f"cells, got {len(paper_cells)}: {sorted(paper_cells)}"
        )


validate_canonical_suite()


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _payload(cell: AttackCell, size: int) -> bytes:
    header = f"# injected {cell.attack_id}\n{cell.description}\n".encode("utf-8")
    if len(header) >= size:
        return header[:size]
    return header + (b"x" * (size - len(header)))


def _target_path(agent_dir: str, cell: AttackCell) -> Path:
    return Path(agent_dir) / cell.target_file


def execute_cell(agent_dir: str, attack_id: str) -> dict:
    cell = CANONICAL_ATTACKS[attack_id]
    target = _target_path(agent_dir, cell)
    target.parent.mkdir(parents=True, exist_ok=True)

    before = target.read_bytes() if target.exists() else b""
    size_before = len(before)
    hash_before = _hash_bytes(before) if target.exists() else None

    result = {
        "attack_id": cell.attack_id,
        "target_file": str(target),
        "op_type": cell.op_type,
        "target_layer": tax.layer_of(cell.target_file),
        "target_role": cell.target_role,
        "state_object_id": cell.state_object_id,
        "size_before": size_before,
        "size_after": None,
        "hash_before": hash_before,
        "hash_after": None,
        "success": False,
    }

    try:
        if cell.mechanism == "M3":
            if target.exists():
                target.unlink()
            result["size_after"] = 0
            result["hash_after"] = None
        elif cell.mechanism == "M4":
            if not target.exists():
                target.write_bytes(_payload(cell, max(cell.size_before_hint, 64)))
                before = target.read_bytes()
                result["size_before"] = len(before)
                result["hash_before"] = _hash_bytes(before)
            os.chmod(target, 0)
            result["size_after"] = result["size_before"]
            result["hash_after"] = result["hash_before"]
        elif cell.mechanism == "M2":
            delta = max(1, cell.size_after_hint - cell.size_before_hint)
            target.write_bytes(before + _payload(cell, delta))
            after = target.read_bytes()
            result["size_after"] = len(after)
            result["hash_after"] = _hash_bytes(after)
        elif cell.mechanism == "M1":
            if cell.granularity == "G1":
                after_bytes = _payload(cell, max(cell.size_after_hint, 1))
            else:
                delta = cell.size_after_hint - cell.size_before_hint
                if not before:
                    before = _payload(cell, cell.size_before_hint)
                if delta >= 0:
                    after_bytes = before + _payload(cell, delta)
                else:
                    after_bytes = before[:max(1, len(before) + delta)]
            target.write_bytes(after_bytes)
            after = target.read_bytes()
            result["size_after"] = len(after)
            result["hash_after"] = _hash_bytes(after)
        else:
            raise ValueError(f"unsupported mechanism: {cell.mechanism}")
        result["success"] = True
    except Exception as exc:
        result["error"] = str(exc)
    return result


def _make_executor(attack_id: str) -> Callable[[str], dict]:
    def _execute(agent_dir: str) -> dict:
        return execute_cell(agent_dir, attack_id)

    return _execute


ATTACKS: Dict[str, Callable[[str], dict]] = {
    attack_id: _make_executor(attack_id) for attack_id in CANONICAL_ATTACKS
}


__all__ = [
    "ATTACKS",
    "CANONICAL_ATTACKS",
    "LEGACY_VARIANTS",
    "AttackCell",
    "execute_cell",
    "validate_canonical_suite",
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one canonical 23-cell attack")
    parser.add_argument("agent_dir", help="Path to agent directory")
    parser.add_argument("attack_id", choices=sorted(CANONICAL_ATTACKS), help="Canonical attack id")
    args = parser.parse_args()
    result = execute_cell(args.agent_dir, args.attack_id)
    print(json.dumps(result, indent=2))
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    sys.exit(main())
