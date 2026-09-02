#!/usr/bin/env python3
"""
Workload Profiles for SELFSTATE v4

Defines 4 workload profiles representing distinct agent usage patterns.
W1 (Coding) and W4 (General) are empirically grounded from Claude Code
and OpenClaw traces respectively. W2 (Knowledge) and W3 (DevOps) are
derived profiles with parameters inferred from architectural analysis.

Each profile specifies:
  - Operation type distribution (weights)
  - Per-file write frequency (writes per session)
  - Write size distribution per file (mean, std in bytes)
  - Temporal pattern (burst factor, ops per session)
  - Anomaly detection thresholds per self-state layer
    (Instruction / Memory / Config — see workload/taxonomy.py)

Layer taxonomy is centralized in ``workload.taxonomy``. The three-layer
decomposition (Instruction / Memory / Config) is the paper's current
naming. The legacy ``identity_write_rate`` field is kept as a backwards
compatible alias for ``instruction_write_rate`` so downstream code does
not break mid-refactor; new call sites should use
``instruction_write_rate``.
"""

from dataclasses import dataclass, field
from typing import Dict, Tuple

try:
    from . import taxonomy as _tax
except ImportError:  # when loaded as top-level module (e.g. via generator_v4's sys.path hack)
    import taxonomy as _tax


@dataclass
class WorkloadProfile:
    """A workload profile parameterizing agent state-access behavior."""
    name: str
    description: str
    source: str  # "empirical" or "derived"

    # Operation type distribution (weights, sum to 1.0)
    # Keys: memory_insert, memory_update, memory_read, memory_delete,
    #        identity_read, identity_write, config_read, config_write,
    #        log_append, heartbeat_write
    # (``identity_*`` op-weight keys are retained for legacy code; they
    # refer to the Instruction layer in current terminology. The
    # ``heartbeat_write`` key is retained for legacy generators but should
    # be 0 in current profiles: HEARTBEAT.md is recurring-task config and
    # is only modified by explicit user/task requests.)
    op_weights: Dict[str, float]

    # Per-file write frequency: expected writes per session.
    # Keys are relative paths within agent workspace (bare filename or
    # ``workspace/`` prefixed). Use ``writes_by_layer()`` for layer
    # aggregates.
    write_freq: Dict[str, float]

    # Write size distribution per file: (mean_bytes, std_bytes)
    write_size: Dict[str, Tuple[float, float]]

    # Temporal pattern
    burst_factor: float = 1.0       # 1.0 = steady, >1.0 = bursty
    ops_per_session: float = 50.0   # average total operations per session

    # For anomaly detection baseline calibration.
    # Layer-level rates follow taxonomy.WRITE_RATE_FIELD.
    # ``identity_write_rate`` is retained as a backwards-compatible alias
    # for the Instruction layer.
    instruction_write_rate: float = 0.0  # expected writes/session to Instruction files
    identity_write_rate: float = 0.0     # LEGACY alias of instruction_write_rate
    config_write_rate: float = 0.0       # expected writes/session to config files
    memory_insert_rate: float = 0.0      # expected inserts/session to MEMORY.md
    memory_update_rate: float = 0.0      # expected updates/session to MEMORY.md
    log_append_rate: float = 0.0         # expected appends/session to daily logs

    def __post_init__(self) -> None:
        # Keep ``instruction_write_rate`` and the legacy
        # ``identity_write_rate`` synchronized. Whichever was set by the
        # caller wins; if both are set and agree, leave them; if both are
        # set and disagree, prefer ``instruction_write_rate``.
        if self.instruction_write_rate and not self.identity_write_rate:
            self.identity_write_rate = self.instruction_write_rate
        elif self.identity_write_rate and not self.instruction_write_rate:
            self.instruction_write_rate = self.identity_write_rate

    # ------------------------------------------------------------------
    # Layer-aware helpers (use taxonomy.layer_of to aggregate write_freq)
    # ------------------------------------------------------------------

    def writes_by_layer(self) -> Dict[str, float]:
        """Sum expected writes/session grouped by self-state layer.

        Files outside the three layers (e.g. task-artifact paths) are
        ignored. Returns a dict keyed by ``taxonomy.LAYER_*`` constants.
        """
        totals = {layer: 0.0 for layer in _tax.LAYERS}
        for path, rate in self.write_freq.items():
            layer = _tax.layer_of(path)
            if layer is not None:
                totals[layer] += float(rate)
        return totals

    def memory_write_rate(self) -> float:
        """Total expected Memory-layer writes/session (MEMORY + memory/*.md)."""
        return self.writes_by_layer()[_tax.LAYER_MEMORY]


# =============================================================================
# W1: Coding Assistant (empirically grounded from Claude Code traces)
# =============================================================================
# Claude Code's state architecture (mapped to 3-layer taxonomy):
#   - Instruction: CLAUDE.md, .claude/rules/*.md — user-edited, agent read-only
#   - Session logs: <uuid>.jsonl — 1 file created per session (conversation record)
#   - Auto memory: memory/MEMORY.md + topic files — agent writes, but infrequently
#   - Config: settings.json — user-edited, essentially static
#
# Trace data: 30 real Claude Code sessions on SWE-bench Verified issues
# (10 simple, 10 medium, 10 complex) across 12 open-source repos.
# Key measurements:
#   - Session log writes/session: 1.0 (always: 1 JSONL file per session)
#   - Auto-memory writes/session: 0.0 (not triggered in --print mode)
#   - Instruction writes/session: 0.0 (confirmed)
#   - Config writes/session: 0.0 (confirmed)
#
# Session logs are persistent conversation records that function as
# unfiltered memory — the agent uses past sessions for context.
# We count session log creation as 1 memory write per session.

W1_CODING = WorkloadProfile(
    name="W1_coding",
    description="Coding assistant (Claude Code-like): mostly reads, 1 session-log write/session",
    source="empirical",  # grounded from 30 real Claude Code sessions on SWE-bench (Apr 2026)
    op_weights={
        "memory_insert":   0.05,    # session log creation
        "memory_update":   0.00,    # not observed
        "memory_read":     0.30,
        "memory_delete":   0.00,
        "identity_read":   0.20,
        "identity_write":  0.00,    # agent never writes identity files
        "config_read":     0.15,
        "config_write":    0.00,    # agent never writes config
        "log_append":      0.30,
        "heartbeat_write": 0.00,
    },
    write_freq={
        "workspace/MEMORY.md":          1.0,    # 1 session log per session (measured)
        "workspace/SOUL.md":            0.0,    # never (confirmed)
        "workspace/AGENTS.md":          0.0,    # never (confirmed)
        "workspace/IDENTITY.md":        0.0,    # never (confirmed)
        "workspace/USER.md":            0.0,    # never (confirmed)
        "workspace/TOOLS.md":           0.0,    # never (confirmed)
        "workspace/HEARTBEAT.md":       0.0,    # recurring-task config; explicit task only
        "workspace/memory/daily.md":    1.0,    # 1 session log per session
        "openclaw.json":                0.0,    # never (confirmed)
        "credentials/.env":             0.0,    # never (confirmed)
    },
    write_size={
        "workspace/MEMORY.md":          (120.0, 40.0),
        "workspace/memory/daily.md":    (150.0, 60.0),
    },
    burst_factor=1.2,
    ops_per_session=30.0,
    instruction_write_rate=0.0,
    identity_write_rate=0.0,    # legacy alias
    config_write_rate=0.0,
    memory_insert_rate=1.0,     # 1 session log write (measured)
    memory_update_rate=0.0,     # not observed
    log_append_rate=1.0,        # 1 session log per session
)


# =============================================================================
# W2: Knowledge Assistant (derived from W4 + amplified memory writes)
# =============================================================================
# RAG-heavy agent: frequently reads and writes memory as it processes
# and indexes information. Config is mostly static. Instruction layer rarely changes.
# Derived: based on OpenClaw patterns with higher memory write frequency.

W2_KNOWLEDGE = WorkloadProfile(
    name="W2_knowledge",
    description="Knowledge assistant (RAG-heavy): frequent memory writes, rare config changes",
    source="derived",
    op_weights={
        "memory_insert":   0.25,
        "memory_update":   0.10,
        "memory_read":     0.25,
        "memory_delete":   0.02,
        "identity_read":   0.08,
        "identity_write":  0.00,
        "config_read":     0.05,
        "config_write":    0.00,
        "log_append":      0.25,
        "heartbeat_write": 0.00,
    },
    write_freq={
        "workspace/MEMORY.md":          4.0,    # ~4 writes per session (heavy indexing)
        "workspace/SOUL.md":            0.0,
        "workspace/AGENTS.md":          0.0,
        "workspace/IDENTITY.md":        0.0,
        "workspace/USER.md":            0.0,
        "workspace/TOOLS.md":           0.0,
        "workspace/HEARTBEAT.md":       0.0,    # recurring-task config; explicit task only
        "workspace/memory/daily.md":    6.0,    # frequent log appends
        "openclaw.json":                0.0,
        "credentials/.env":             0.0,
    },
    write_size={
        "workspace/MEMORY.md":          (200.0, 80.0),   # longer knowledge entries
        "workspace/memory/daily.md":    (180.0, 70.0),
    },
    burst_factor=1.5,   # bursty: research phases generate many writes at once
    ops_per_session=70.0,
    instruction_write_rate=0.0,
    identity_write_rate=0.0,    # legacy alias
    config_write_rate=0.0,
    memory_insert_rate=4.0,
    memory_update_rate=1.0,
    log_append_rate=6.0,
)


# =============================================================================
# W3: DevOps Agent (derived from OpenClaw + amplified config writes)
# =============================================================================
# Manages infrastructure: frequently reads/writes config files, modifies
# environment variables, updates tool definitions. Memory writes are moderate.
# Derived: based on OpenClaw patterns with higher config write frequency.

W3_DEVOPS = WorkloadProfile(
    name="W3_devops",
    description="DevOps agent: frequent config changes, moderate memory, tool updates",
    source="derived",
    op_weights={
        "memory_insert":   0.10,
        "memory_update":   0.05,
        "memory_read":     0.15,
        "memory_delete":   0.01,
        "identity_read":   0.08,
        "identity_write":  0.00,
        "config_read":     0.20,
        "config_write":    0.23,   # key differentiator: DevOps modifies config
        "log_append":      0.18,
        "heartbeat_write": 0.00,
    },
    write_freq={
        "workspace/MEMORY.md":          1.5,
        "workspace/SOUL.md":            0.0,
        "workspace/AGENTS.md":          0.0,
        "workspace/IDENTITY.md":        0.0,
        "workspace/USER.md":            0.0,
        "workspace/TOOLS.md":           0.1,    # occasional tool registration
        "workspace/HEARTBEAT.md":       0.0,    # recurring-task config; explicit task only
        "workspace/memory/daily.md":    5.0,
        "openclaw.json":                0.8,    # frequent config tweaks
        "credentials/.env":             0.2,    # occasional credential rotation
    },
    write_size={
        "workspace/MEMORY.md":          (140.0, 50.0),
        "workspace/TOOLS.md":           (100.0, 30.0),
        "workspace/memory/daily.md":    (160.0, 55.0),
        "openclaw.json":                (30.0, 15.0),    # small config changes
        "credentials/.env":             (40.0, 10.0),
    },
    burst_factor=1.8,   # very bursty: deploy events trigger cascading changes
    ops_per_session=60.0,
    instruction_write_rate=0.1,  # occasional TOOLS.md registration
    identity_write_rate=0.1,     # legacy alias
    config_write_rate=0.8,
    memory_insert_rate=1.5,
    memory_update_rate=0.5,
    log_append_rate=5.0,
)


# =============================================================================
# W4: General Assistant (grounded from real Gemini-driven OpenClaw traces)
# =============================================================================
# Conversational agent: moderate memory writes (learning + task records),
# occasional config reads, daily log maintenance. Instruction layer is static.
#
# Trace data: 30 real Gemini-driven sessions (10 simple, 10 medium, 10 complex)
# collected via polling-based trace_collector monitoring OpenClaw workspace.
# Gemini 2.5 Flash single-turn: each session = 1 API call + state update.
# Key measurements (write-only; reads not captured by collector):
#   - MEMORY.md writes/session: 0.80 ± 0.41
#   - Daily log appends/session: 1.00 ± 0.00
#   - HEARTBEAT.md writes/session: 0.0 in the current model (recurring-task
#     config is edited only by explicit tasks)
#   - Instruction writes/session: 0.0 (confirmed)
#   - Total write events/session: 4.80 ± 0.41 (incl. collector start/stop)
#   - Burst factor (CV+1 of inter-event times): 1.88
#
# ops_per_session (15) includes estimated reads (~2x write rate for a
# single-turn assistant); write-only rate is ~2.8/session.

W4_GENERAL = WorkloadProfile(
    name="W4_general",
    description="General assistant (OpenClaw-like): moderate memory writes, varied operations",
    source="empirical",  # grounded from 30 real Gemini-driven sessions (Apr 2026)
    op_weights={
        "memory_insert":   0.02,    # rare: only when MEMORY.md doesn't exist yet
        "memory_update":   0.29,    # primary memory write mode (28.6% of observed writes)
        "memory_read":     0.22,
        "memory_delete":   0.01,
        "identity_read":   0.10,
        "identity_write":  0.00,
        "config_read":     0.08,
        "config_write":    0.00,    # not observed in real traces
        "log_append":      0.28,    # 35.7% of observed writes (scaled w/ reads)
        "heartbeat_write": 0.00,
    },
    write_freq={
        "workspace/MEMORY.md":          0.8,    # 0.80 ± 0.41 measured
        "workspace/SOUL.md":            0.0,
        "workspace/AGENTS.md":          0.0,
        "workspace/IDENTITY.md":        0.0,
        "workspace/USER.md":            0.0,
        "workspace/TOOLS.md":           0.0,
        "workspace/HEARTBEAT.md":       0.0,    # recurring-task config; explicit task only
        "workspace/memory/daily.md":    1.0,    # 1.00 ± 0.00 measured
        "openclaw.json":                0.0,    # not observed in real traces
        "credentials/.env":             0.0,
    },
    write_size={
        "workspace/MEMORY.md":          (160.0, 60.0),
        "workspace/memory/daily.md":    (170.0, 65.0),
    },
    burst_factor=1.9,       # 1.88 measured from real traces
    ops_per_session=15.0,   # total incl. estimated reads; write-only ≈ 2.8/session
    instruction_write_rate=0.0,
    identity_write_rate=0.0,    # legacy alias
    config_write_rate=0.0,      # not observed in real traces
    memory_insert_rate=0.0,     # appends are updates, not inserts
    memory_update_rate=0.8,     # 0.80 ± 0.41 measured
    log_append_rate=1.0,        # 1.00 ± 0.00 measured
)


# =============================================================================
# Profile Registry
# =============================================================================

ALL_PROFILES = {
    "W1": W1_CODING,
    "W2": W2_KNOWLEDGE,
    "W3": W3_DEVOPS,
    "W4": W4_GENERAL,
}


def get_profile(name: str) -> WorkloadProfile:
    """Get a profile by name (W1, W2, W3, W4). Case-insensitive."""
    key = name.strip().upper()
    if key not in ALL_PROFILES:
        available = ", ".join(ALL_PROFILES.keys())
        raise ValueError(f"Unknown profile: {name!r}. Available profiles: {available}")
    return ALL_PROFILES[key]


def profile_summary() -> str:
    """Return a human-readable summary of all profiles."""
    lines = ["Profile Summary:", "=" * 60]
    for key, p in ALL_PROFILES.items():
        lines.append(f"\n{key}: {p.name} ({p.source})")
        lines.append(f"  {p.description}")
        lines.append(f"  ops/session: {p.ops_per_session}, burst: {p.burst_factor}")
        layer_totals = p.writes_by_layer()
        lines.append(
            "  writes/session by layer: "
            + ", ".join(
                f"{_tax.LAYER_TITLE[layer]}={layer_totals[layer]:.2f}"
                for layer in _tax.LAYERS
            )
        )
        lines.append(f"  memory_insert_rate: {p.memory_insert_rate}/session")
        lines.append(f"  config_write_rate: {p.config_write_rate}/session")
        lines.append(f"  instruction_write_rate: {p.instruction_write_rate}/session")
        # Show writable files
        writable = {k: v for k, v in p.write_freq.items() if v > 0}
        lines.append(f"  writable files: {writable}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(profile_summary())
