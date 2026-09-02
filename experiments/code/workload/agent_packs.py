#!/usr/bin/env python3
"""
Per-agent Instruction pack seeding.
===================================

Mirrors OpenClaw upstream's per-agent template seeding. Each registered
agent (``w1_coding``, ``w2_knowledge``, ``w3_devops``, ``w4_general``)
ships its own workload-specialized copy of the five Instruction-layer
files (``SOUL.md``, ``IDENTITY.md``, ``USER.md``, ``AGENTS.md``,
``TOOLS.md``). Before a pilot session starts, these files are seeded
into the pilot workspace using **write-if-missing** semantics — the same
behavior as OpenClaw's ``writeFileIfMissing`` at
``src/agents/workspace.ts:393-404``.

Layering
--------

The bench already calls ``openclaw_core.workspace.ensure_agent_workspace``
to seed neutral default templates into a fresh workspace. The helper in
this module layers **on top** of that: after the neutral seed, we call
``seed_instruction_pack(workspace, profile)`` which *overlays* the
per-agent specialized files. Because both layers use write-if-missing,
the pack files win when the workspace is fresh, and on subsequent chain
tasks nothing is re-seeded (the earlier write stuck).

Example
-------

>>> from workload.agent_packs import seed_instruction_pack
>>> seed_instruction_pack("/tmp/pilot-123", profile="W3")
{'agent_id': 'w3_devops', 'pack_dir': '.../experiments/agent_packs/w3_devops/workspace',
 'seeded': ['SOUL.md', 'IDENTITY.md', 'USER.md', 'AGENTS.md', 'TOOLS.md'],
 'skipped': []}

The returned dict is a record of which files were seeded vs skipped
(already present), useful for pilot_runner diagnostics.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Optional

from . import taxonomy as _tax


# Repo-root-relative directory that holds per-agent packs.
# Resolved at import time against this module's location so callers can
# invoke us from any cwd.
_REPO_ROOT: Path = Path(__file__).resolve().parents[3]
AGENT_PACKS_ROOT: Path = _REPO_ROOT / _tax.AGENTS_ROOT


class InstructionPackError(RuntimeError):
    """Raised when the on-disk pack for an agent is missing or malformed."""


def pack_dir_for(agent_id: str) -> Path:
    """Return the on-disk workspace directory for a registered agent.

    >>> pack_dir_for("w3_devops").name
    'workspace'
    """
    return AGENT_PACKS_ROOT / agent_id / "workspace"


def pack_dir_for_profile(profile: str) -> Path:
    """Return the pack dir given a profile name (``W1`` ...).

    >>> pack_dir_for_profile("W4").parts[-2]
    'w4_general'
    """
    return pack_dir_for(_tax.agent_id_for(profile))


def _copy_if_missing(src: Path, dst: Path) -> bool:
    """write-if-missing semantics. Returns True if the file was newly
    written, False if it already existed or the source was absent."""
    if dst.exists():
        return False
    if not src.exists():
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    return True


def seed_instruction_pack(
    workspace_root: str | Path,
    *,
    profile: Optional[str] = None,
    agent_id: Optional[str] = None,
    strict: bool = True,
) -> dict:
    """Seed the per-agent Instruction pack into a pilot workspace.

    Call this *after* ``openclaw_core.workspace.ensure_agent_workspace``
    has initialized the workspace with default templates. Files that
    already exist (because they were just seeded from the default
    template, or because this is the second task of a chain) are left
    untouched. Files that don't exist are overwritten from the pack.

    Caveat: because ``ensure_agent_workspace`` seeds neutral defaults
    first, the caller needs to **delete** the default Instruction files
    before calling this function to actually get the per-agent content.
    Use ``seed_instruction_pack(..., overwrite_defaults=True)`` for that
    — or, preferred, call this function as an **override** step that
    accepts an explicit overwrite flag.

    Parameters
    ----------
    workspace_root : str | Path
        The pilot workspace directory (already initialized by
        ``ensure_agent_workspace``).
    profile : str, optional
        Profile name (``W1``, ``W2``, ``W3``, ``W4``). Mutually exclusive
        with ``agent_id``.
    agent_id : str, optional
        Canonical agent id (``w3_devops`` etc.). Mutually exclusive with
        ``profile``.
    strict : bool, default True
        If True, raise ``InstructionPackError`` when the pack dir or any
        ``INSTRUCTION_PACK_FILES`` member is missing. If False, silently
        skip missing source files.

    Returns
    -------
    dict with keys:
        ``agent_id`` : str
        ``pack_dir`` : str
        ``seeded``   : list[str]   (filenames written this call)
        ``skipped``  : list[str]   (filenames that already existed)
        ``missing``  : list[str]   (filenames the source pack lacked,
                                    empty if strict=True — that path
                                    raises instead)
    """
    if (profile is None) == (agent_id is None):
        raise ValueError("Pass exactly one of profile= or agent_id=")
    if agent_id is None:
        agent_id = _tax.agent_id_for(profile)  # type: ignore[arg-type]

    ws = Path(workspace_root)
    if not ws.exists():
        raise InstructionPackError(
            f"Workspace does not exist: {ws}. Call ensure_agent_workspace first."
        )

    pack = pack_dir_for(agent_id)
    if not pack.is_dir():
        raise InstructionPackError(
            f"Instruction pack missing for agent_id={agent_id!r}: {pack}"
        )

    seeded: list[str] = []
    skipped: list[str] = []
    missing: list[str] = []

    for filename in _tax.INSTRUCTION_PACK_FILES:
        src = pack / filename
        dst = ws / filename
        if not src.exists():
            if strict:
                raise InstructionPackError(
                    f"Pack {agent_id!r} missing required file: {filename}"
                )
            missing.append(filename)
            continue
        if _copy_if_missing(src, dst):
            seeded.append(filename)
        else:
            skipped.append(filename)

    return {
        "agent_id": agent_id,
        "pack_dir": str(pack),
        "seeded": seeded,
        "skipped": skipped,
        "missing": missing,
    }


def apply_instruction_pack(
    workspace_root: str | Path,
    *,
    profile: Optional[str] = None,
    agent_id: Optional[str] = None,
    overwrite_defaults: bool = True,
    strict: bool = True,
) -> dict:
    """Apply the per-agent Instruction pack, overwriting the neutral
    defaults that ``ensure_agent_workspace`` wrote.

    In production (upstream OpenClaw), each registered agent has its
    own ``agentDir`` and the templates are specialized before they ever
    reach the workspace. In the bench, ``ensure_agent_workspace`` uses
    a single shared template dir, so we need an extra step to overlay
    the per-agent version.

    When ``overwrite_defaults=True`` (the common case), this function:

    1. Deletes any existing Instruction-pack file in the workspace
       (``SOUL.md`` etc.) that matches the neutral default.
    2. Calls ``seed_instruction_pack`` to write the per-agent copy.

    The result reports which files were overwritten vs skipped.
    """
    if (profile is None) == (agent_id is None):
        raise ValueError("Pass exactly one of profile= or agent_id=")
    if agent_id is None:
        agent_id = _tax.agent_id_for(profile)  # type: ignore[arg-type]

    ws = Path(workspace_root)
    if overwrite_defaults:
        for filename in _tax.INSTRUCTION_PACK_FILES:
            dst = ws / filename
            if dst.exists():
                dst.unlink()

    return seed_instruction_pack(ws, agent_id=agent_id, strict=strict)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Seed / apply a per-agent Instruction pack into a workspace.",
    )
    parser.add_argument("workspace", help="workspace root to seed into")
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--profile", help="workload profile name (W1/W2/W3/W4)")
    g.add_argument("--agent-id", dest="agent_id", help="canonical agent id")
    parser.add_argument(
        "--apply", action="store_true",
        help="overwrite default-template Instruction files with the per-agent pack",
    )
    args = parser.parse_args()

    fn = apply_instruction_pack if args.apply else seed_instruction_pack
    result = fn(args.workspace, profile=args.profile, agent_id=args.agent_id)
    print(result)
