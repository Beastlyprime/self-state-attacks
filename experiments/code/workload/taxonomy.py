#!/usr/bin/env python3
"""
SELFSTATE Self-State Taxonomy
====================================

Compatibility API for the three top-level self-state target classes used
across the paper, profiles, attacks, and measurement code:

    Instruction  - identity, policy, user-model, and capability guidance.
    Memory       - durable, episodic, and topic-scoped retained state.
    Config       - runtime, automation, and capability-binding parameters.

Concrete filenames are not part of this taxonomy. They are supplied by a
StateSchema for the selected agent adapter. The shipped default schema maps
these logical roles to the OpenClaw-compatible layout. Legacy constants such
as INSTRUCTION_FILES remain derived compatibility views for existing callers.

Layer names are lowercase string constants for stable JSON fields. Attack-ID
prefixes remain Inst, Mem, and Cfg because the paper's 23-cell matrix uses the
three top-level layers; logical roles refine target selection within a cell.
"""

from __future__ import annotations

from typing import Optional

try:
    from .state_schema import (
        DEFAULT_STATE_SCHEMA,
        StateObjectSpec,
    )
except ImportError:  # Legacy scripts import this module as top-level taxonomy.
    from state_schema import (  # type: ignore
        DEFAULT_STATE_SCHEMA,
        StateObjectSpec,
    )

# =============================================================================
# Layer names (paper terminology — authoritative)
# =============================================================================

LAYER_INSTRUCTION: str = "instruction"
LAYER_MEMORY: str = "memory"
LAYER_CONFIG: str = "config"

LAYERS: tuple[str, ...] = (LAYER_INSTRUCTION, LAYER_MEMORY, LAYER_CONFIG)

# Human-readable title case for paper tables / figure captions.
LAYER_TITLE = {
    LAYER_INSTRUCTION: "Instruction",
    LAYER_MEMORY: "Memory",
    LAYER_CONFIG: "Config",
}


# The top-level target classes remain stable across adapters. Concrete paths
# and finer-grained roles come from the selected state schema.
def _legacy_relative(path: str) -> str:
    return path[len("workspace/"):] if path.startswith("workspace/") else path


INSTRUCTION_FILES: tuple[str, ...] = tuple(
    _legacy_relative(path)
    for path in DEFAULT_STATE_SCHEMA.exact_paths(LAYER_INSTRUCTION)
)
MEMORY_FILES: tuple[str, ...] = tuple(
    _legacy_relative(path)
    for path in DEFAULT_STATE_SCHEMA.exact_paths(LAYER_MEMORY)
)
MEMORY_GLOB: str = _legacy_relative(
    DEFAULT_STATE_SCHEMA.object("memory.topic_scoped").globs[0]
)
CONFIG_FILES: tuple[str, ...] = tuple(
    _legacy_relative(path)
    for path in DEFAULT_STATE_SCHEMA.exact_paths(LAYER_CONFIG)
)

# Compatibility view for older consumers. New code should use
# state_object_of or role_of so it does not discard the role level.
FILE_TO_LAYER: dict[str, str] = {
    **{f: LAYER_INSTRUCTION for f in INSTRUCTION_FILES},
    **{f: LAYER_MEMORY for f in MEMORY_FILES},
    **{f: LAYER_CONFIG for f in CONFIG_FILES},
}


def state_object_of(path: str) -> Optional[StateObjectSpec]:
    """Return the logical state-object specification bound to path."""
    return DEFAULT_STATE_SCHEMA.object_for(path)


def layer_of(path: str) -> Optional[str]:
    """Return the top-level self-state layer bound to path.

    >>> layer_of("SOUL.md")
    'instruction'
    >>> layer_of("workspace/MEMORY.md")
    'memory'
    >>> layer_of("memory/2026-04-24.md")
    'memory'
    >>> layer_of("outbox/reply.md") is None
    True
    """
    return DEFAULT_STATE_SCHEMA.layer_of(path)


def role_of(path: str) -> Optional[str]:
    """Return the finer-grained logical role bound to path."""
    return DEFAULT_STATE_SCHEMA.role_of(path)


# =============================================================================
# Attack ID naming convention
# =============================================================================
#
# Format: <LayerPrefix>_<Mechanism>_<Granularity>[_<FileTag>]
#
#   LayerPrefix:  Inst | Mem | Cfg
#   Mechanism:    M1 (Modify) | M2 (Add) | M3 (Delete/unlink) | M4 (Deny/chmod)
#   Granularity:  G1 (whole-file) | G2 (large-delta)
#                 | G3 (small/line) | G4 (minimal, ≤4B)
#   FileTag:      optional, uppercase filename root (SOUL, AGENTS, MEMORY, ...).
#                 Used when the same <Layer,Mechanism,Granularity> cell has
#                 multiple instances on different files. Example:
#                 ``Inst_M3_G1_SOUL`` vs ``Inst_M3_G1_AGENTS``.
#
# Legacy blunt/subtle attack IDs (B1, S5, A2, ...) predate this scheme
# and are preserved for continuity; the paper's Table attack-matrix
# maps each legacy ID to its canonical cell.

ATTACK_PREFIX: dict[str, str] = {
    LAYER_INSTRUCTION: "Inst",
    LAYER_MEMORY: "Mem",
    LAYER_CONFIG: "Cfg",
}


def attack_id(
    layer: str,
    mechanism: str,
    granularity: str,
    file_tag: Optional[str] = None,
) -> str:
    """Compose a canonical attack ID.

    >>> attack_id(LAYER_INSTRUCTION, "M3", "G1", "SOUL")
    'Inst_M3_G1_SOUL'
    >>> attack_id(LAYER_MEMORY, "M1", "G4")
    'Mem_M1_G4'
    """
    prefix = ATTACK_PREFIX[layer]
    parts = [prefix, mechanism, granularity]
    if file_tag:
        parts.append(file_tag.upper())
    return "_".join(parts)


# =============================================================================
# Profile / measurement field names (keep JSON keys consistent)
# =============================================================================
#
# Profile rates are named ``<layer>_write_rate`` uniformly. This replaces
# the old mixed scheme (``identity_write_rate``, ``memory_insert_rate``,
# ``memory_update_rate``, ``log_append_rate``, ``config_write_rate``).

WRITE_RATE_FIELD: dict[str, str] = {
    LAYER_INSTRUCTION: "instruction_write_rate",
    LAYER_MEMORY: "memory_write_rate",
    LAYER_CONFIG: "config_write_rate",
}


# =============================================================================
# Detector op_type naming (shared by trace baseline + attack specs)
# =============================================================================

OP_WRITE: str = "write"
OP_INSERT: str = "insert"
OP_UPDATE: str = "update"
OP_DELETE: str = "delete"
OP_ATTRIB: str = "attrib"


def op_type(layer: str, action: str) -> str:
    """Return the canonical detector op_type for a self-state layer/action.

    >>> op_type(LAYER_INSTRUCTION, OP_WRITE)
    'instruction_write'
    >>> op_type(LAYER_CONFIG, OP_ATTRIB)
    'config_attrib'
    """
    return f"{layer}_{action}"


def canonical_path(path: str) -> Optional[str]:
    """Return the canonical detector path for a self-state path.

    Workspace files are keyed with a ``workspace/`` prefix. Root-level config
    files keep their root-relative form. Returns ``None`` for non-self-state
    task artifacts.

    >>> canonical_path("SOUL.md")
    'workspace/SOUL.md'
    >>> canonical_path("workspace/HEARTBEAT.md")
    'workspace/HEARTBEAT.md'
    >>> canonical_path("openclaw.json")
    'openclaw.json'
    >>> canonical_path("outbox/reply.md") is None
    True
    """
    return DEFAULT_STATE_SCHEMA.canonical_path(path)


def bucket_key(path: str) -> str:
    """Map a self-state path to its baseline-aggregation bucket key.

    The detector keys its (μ_size, σ_size) and (μ_log_dt, σ_log_dt)
    statistics by ``(target_file, op_type)``. Some self-state files have
    structurally identical roles but distinct file names — most notably
    ``workspace/memory/*.md`` daily logs, topical notes, and topic-
    sharded subfiles, which the agent creates ad hoc with names like
    ``2026-04-26.md`` or ``han-people.md``. These should share a single
    baseline distribution so detection isn't fragmented by date or
    topic-string accidents in the agent's naming choices.

    ``bucket_key`` collapses every ``workspace/memory/<X>.md`` to the
    canonical bucket ``workspace/memory/*.md`` for baseline lookup.
    All other paths pass through unchanged.

    NB. ``canonical_path`` and ``bucket_key`` serve different axes:
    ``canonical_path`` normalizes a raw filesystem path to its
    self-state surface (``./SOUL.md`` → ``workspace/SOUL.md``). It is
    the path the attack instantiates against and the path stored on
    each event for reporting. ``bucket_key`` is the second-stage
    collapse that the baseline aggregator and the score lookup share,
    so two events with different ``target_file`` values but the same
    ``bucket_key`` count toward the same statistical distribution.

    >>> bucket_key("workspace/MEMORY.md")
    'workspace/MEMORY.md'
    >>> bucket_key("workspace/memory/2026-04-26.md")
    'workspace/memory/*.md'
    >>> bucket_key("workspace/memory/han-people.md")
    'workspace/memory/*.md'
    >>> bucket_key("openclaw.json")
    'openclaw.json'
    """
    return DEFAULT_STATE_SCHEMA.bucket_key(path)


def infer_op_type(
    canonical_self_state_path: str,
    *,
    was_created: bool = False,
    fs_event: Optional[str] = None,
    delta: Optional[int] = None,
    mode_changed: bool = False,
) -> str:
    """Infer the canonical detector op_type from path + observable FS event.

    The result is intentionally VFS-oriented. For example, appending bytes to
    ``MEMORY.md`` is ``memory_insert`` while a same-file shrink/rewrite is
    ``memory_update``. Instruction files use ``instruction_*`` naming, with
    ``identity_*`` retained only in legacy result files.
    """
    layer = layer_of(canonical_self_state_path)
    if layer is None:
        return "unknown_write"

    if fs_event == "IN_ATTRIB" or mode_changed:
        return op_type(layer, OP_ATTRIB)
    if fs_event in {"IN_DELETE", "IN_MOVED_FROM"}:
        return op_type(layer, OP_DELETE)

    rel = canonical_self_state_path[len("workspace/"):] if canonical_self_state_path.startswith("workspace/") else canonical_self_state_path

    if layer == LAYER_MEMORY:
        if rel.startswith("memory/"):
            return "log_append"
        if rel == "MEMORY.md":
            return op_type(
                LAYER_MEMORY,
                OP_INSERT if was_created or (delta is not None and delta > 0) else OP_UPDATE,
            )

    if layer == LAYER_INSTRUCTION:
        return op_type(LAYER_INSTRUCTION, OP_WRITE)

    if layer == LAYER_CONFIG:
        return op_type(LAYER_CONFIG, OP_WRITE)

    return "unknown_write"


# =============================================================================
# Agent identity (aligns with OpenClaw upstream multi-agent layout)
# =============================================================================
#
# Upstream OpenClaw registers agents under ``<stateDir>/agents/<agentId>/``
# with ``agent/`` and ``workspace/`` subdirectories. Each registered agent
# has its own SOUL/IDENTITY/AGENTS/TOOLS/USER files seeded from templates
# and then specialized by the operator. See:
#
#   - src/routing/session-key.ts          (DEFAULT_AGENT_ID = "main")
#   - src/agents/agent-scope-config.ts    (resolveAgentDir / resolveAgentWorkspaceDir)
#   - src/agents/workspace.ts:393-404     (writeFileIfMissing from templates)
#
# We treat each workload profile as a distinct registered agent. Profile
# name maps 1:1 to agent id via PROFILE_AGENT_ID. This makes the claim in
# section 2.2 ("workload is a profile-dependent property of the deployed
# agent") concrete: W3 DevOps is not "the default agent under DevOps
# traffic", it is the ``w3_devops`` sub-agent with a specialized AGENTS.md
# that encodes the DevOps workflow.
#
# Agent IDs are lowercase snake_case to match upstream normalizeAgentId
# (src/routing/session-key.ts:107).

AGENTS_ROOT: str = "experiments/agent_packs"  # repo-root-relative directory containing agent packs

PROFILE_AGENT_ID: dict[str, str] = {
    "W1": "w1_coding",
    "W2": "w2_knowledge",
    "W3": "w3_devops",
    "W4": "w4_general",
}

# Inverse: agent id → profile name.
AGENT_ID_TO_PROFILE: dict[str, str] = {v: k for k, v in PROFILE_AGENT_ID.items()}

# Files seeded into each agent's workspace on first run (Instruction
# layer). Mirrors the upstream DEFAULT_*_FILENAME exports in
# ``src/agents/workspace.ts:26-30``.
INSTRUCTION_PACK_FILES: tuple[str, ...] = (
    "SOUL.md",
    "IDENTITY.md",
    "USER.md",
    "AGENTS.md",
    "TOOLS.md",
)


def agent_id_for(profile: str) -> str:
    """Return the canonical agent id for a profile name (``W1`` ...).

    Profile names are uppercase (``W1``/``W2``/...); agent ids are
    lowercase snake_case (``w1_coding``/...). Raises ``KeyError`` for
    unknown profiles.

    >>> agent_id_for("W3")
    'w3_devops'
    """
    return PROFILE_AGENT_ID[profile.strip().upper()]


def profile_for_agent(agent_id: str) -> Optional[str]:
    """Inverse of ``agent_id_for``: return profile name given agent id.

    Returns ``None`` if the id is not a known profile-mapped agent.
    """
    return AGENT_ID_TO_PROFILE.get(agent_id.strip().lower())


# =============================================================================
# Convenience: all-in-one summary (for __main__ inspection)
# =============================================================================


def summary() -> str:
    """Return a human-readable dump of the taxonomy."""
    lines = ["Self-state taxonomy (three-layer)", "=" * 40]
    for layer in LAYERS:
        title = LAYER_TITLE[layer]
        prefix = ATTACK_PREFIX[layer]
        rate_field = WRITE_RATE_FIELD[layer]
        lines.append(f"\n{title}  (attack prefix: {prefix}, field: {rate_field})")
        if layer == LAYER_INSTRUCTION:
            lines.append("  files: " + ", ".join(INSTRUCTION_FILES))
        elif layer == LAYER_MEMORY:
            lines.append(
                "  files: "
                + ", ".join(MEMORY_FILES)
                + f" + {MEMORY_GLOB} (glob)"
            )
        elif layer == LAYER_CONFIG:
            lines.append("  files: " + ", ".join(CONFIG_FILES))
    return "\n".join(lines)


if __name__ == "__main__":
    print(summary())
