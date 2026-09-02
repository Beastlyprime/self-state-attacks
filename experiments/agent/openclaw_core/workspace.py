"""Workspace bootstrap and file cache — port of workspace.ts.

Implements SPEC §1-2, §5:
- Canonical workspace file constants
- Bootstrap file read order (AGENTS → SOUL → TOOLS → IDENTITY → USER → HEARTBEAT
  → BOOTSTRAP → MEMORY.md | memory.md)
- File cache with identity-based invalidation
- Setup state machine via .openclaw/workspace-state.json
- MINIMAL_BOOTSTRAP_ALLOWLIST for subagent/heartbeat/memory-flush sessions

Source reference: mnt/openclaw/src/agents/workspace.ts
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from typing import Optional

from .boundary import BoundaryError, file_identity, read_boundary_file
from .state import (
    mark_bootstrap_seeded,
    mark_setup_completed,
    read_workspace_state,
)

# Canonical filenames (SPEC §1). Match constants in workspace.ts.
DEFAULT_SOUL_FILENAME = "SOUL.md"
DEFAULT_AGENTS_FILENAME = "AGENTS.md"
DEFAULT_IDENTITY_FILENAME = "IDENTITY.md"
DEFAULT_USER_FILENAME = "USER.md"
DEFAULT_TOOLS_FILENAME = "TOOLS.md"
DEFAULT_HEARTBEAT_FILENAME = "HEARTBEAT.md"
DEFAULT_BOOTSTRAP_FILENAME = "BOOTSTRAP.md"
DEFAULT_MEMORY_FILENAME = "MEMORY.md"
DEFAULT_MEMORY_ALT_FILENAME = "memory.md"  # legacy lowercase fallback

# Bootstrap read order (SPEC §2, workspace.ts:503-563).
# Order matters for context assembly.
BOOTSTRAP_ORDER: tuple[str, ...] = (
    DEFAULT_AGENTS_FILENAME,
    DEFAULT_SOUL_FILENAME,
    DEFAULT_TOOLS_FILENAME,
    DEFAULT_IDENTITY_FILENAME,
    DEFAULT_USER_FILENAME,
    DEFAULT_HEARTBEAT_FILENAME,
    DEFAULT_BOOTSTRAP_FILENAME,
    # MEMORY.md (with memory.md fallback) handled specially — see
    # resolve_memory_bootstrap_entry below.
)

# Subset loaded for subagent / heartbeat / memory-flush sessions (SPEC §2).
# workspace.ts:565-571 MINIMAL_BOOTSTRAP_ALLOWLIST.
MINIMAL_BOOTSTRAP_ALLOWLIST: tuple[str, ...] = (
    DEFAULT_AGENTS_FILENAME,
    DEFAULT_TOOLS_FILENAME,
    DEFAULT_SOUL_FILENAME,
    DEFAULT_IDENTITY_FILENAME,
    DEFAULT_USER_FILENAME,
)

# Path to the templates directory bundled with this package.
_TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")

# Files that get seeded into a fresh workspace.
TEMPLATE_FILES: tuple[str, ...] = (
    DEFAULT_SOUL_FILENAME,
    DEFAULT_AGENTS_FILENAME,
    DEFAULT_IDENTITY_FILENAME,
    DEFAULT_USER_FILENAME,
    DEFAULT_TOOLS_FILENAME,
    DEFAULT_HEARTBEAT_FILENAME,
    DEFAULT_BOOTSTRAP_FILENAME,
    DEFAULT_MEMORY_FILENAME,
)


@dataclass
class BootstrapEntry:
    """One entry in the bootstrap read sequence.

    Attributes:
        filename: The workspace-relative filename (e.g. "SOUL.md").
        content: File contents, or None if the file was missing/unreadable.
        identity: Cache identity string, or None if file was unreadable.
    """
    filename: str
    content: Optional[str]
    identity: Optional[str]


@dataclass
class WorkspaceFileCache:
    """Map from absolute canonical path to (content, identity).

    Port of workspaceFileCache in workspace.ts:50.
    """
    entries: dict[str, tuple[str, str]] = field(default_factory=dict)

    def get(self, absolute_path: str) -> Optional[tuple[str, str]]:
        return self.entries.get(absolute_path)

    def put(self, absolute_path: str, content: str, identity: str) -> None:
        self.entries[absolute_path] = (content, identity)

    def invalidate(self, absolute_path: str) -> None:
        self.entries.pop(absolute_path, None)

    def clear(self) -> None:
        self.entries.clear()


def resolve_memory_bootstrap_entry(
    workspace_root: str,
    cache: Optional[WorkspaceFileCache] = None,
) -> Optional[BootstrapEntry]:
    """Resolve the MEMORY.md / memory.md entry — prefer MEMORY.md.

    Matches workspace.ts:491-501 resolveMemoryBootstrapEntry. To avoid
    case-insensitive filesystem ambiguity, we pick one or the other, never
    both.
    """
    for candidate in (DEFAULT_MEMORY_FILENAME, DEFAULT_MEMORY_ALT_FILENAME):
        path = os.path.join(workspace_root, candidate)
        if os.path.exists(path):
            entry = _read_bootstrap_file(path, candidate, workspace_root, cache)
            return entry
    return None


def _read_bootstrap_file(
    absolute_path: str,
    filename: str,
    workspace_root: str,
    cache: Optional[WorkspaceFileCache],
) -> BootstrapEntry:
    """Read a single bootstrap file through boundary checks and cache it.

    Returns a BootstrapEntry. If file is missing or fails validation, returns
    an entry with content=None, identity=None.
    """
    if not os.path.exists(absolute_path):
        return BootstrapEntry(filename=filename, content=None, identity=None)

    try:
        identity = file_identity(absolute_path)
    except OSError:
        return BootstrapEntry(filename=filename, content=None, identity=None)

    if cache is not None:
        cached = cache.get(os.path.realpath(absolute_path))
        if cached is not None:
            cached_content, cached_identity = cached
            if cached_identity == identity:
                return BootstrapEntry(
                    filename=filename,
                    content=cached_content,
                    identity=cached_identity,
                )

    try:
        content = read_boundary_file(absolute_path, workspace_root)
    except BoundaryError:
        # Path escape / validation / io — cache miss, no content.
        return BootstrapEntry(filename=filename, content=None, identity=None)

    if cache is not None:
        cache.put(os.path.realpath(absolute_path), content, identity)

    return BootstrapEntry(filename=filename, content=content, identity=identity)


def load_workspace_bootstrap_files(
    workspace_root: str,
    *,
    minimal: bool = False,
    cache: Optional[WorkspaceFileCache] = None,
) -> list[BootstrapEntry]:
    """Load bootstrap files in canonical order.

    Args:
        workspace_root: Absolute path to workspace root.
        minimal: If True, load only MINIMAL_BOOTSTRAP_ALLOWLIST (for subagent /
            heartbeat / memory-flush sessions).
        cache: Optional WorkspaceFileCache. If provided, cache hits skip re-read.

    Returns:
        List of BootstrapEntry in read order. Files that are missing produce
        entries with content=None (so callers can distinguish "missing" from
        "empty").
    """
    order = MINIMAL_BOOTSTRAP_ALLOWLIST if minimal else BOOTSTRAP_ORDER
    entries: list[BootstrapEntry] = []
    for filename in order:
        abs_path = os.path.join(workspace_root, filename)
        entries.append(_read_bootstrap_file(abs_path, filename, workspace_root, cache))

    # MEMORY.md / memory.md only loaded in full mode (not minimal).
    if not minimal:
        memory_entry = resolve_memory_bootstrap_entry(workspace_root, cache)
        if memory_entry is not None:
            entries.append(memory_entry)

    return entries


def ensure_agent_workspace(workspace_root: str, *, mark_setup_done: bool = True) -> None:
    """Port of ensureAgentWorkspace (workspace.ts:341-481).

    For the harness we take a simplified "used agent" path (SPEC §5):
    1. Create workspace_root if it doesn't exist.
    2. Seed all template files that are missing.
    3. Set .openclaw/workspace-state.json with bootstrapSeededAt + (optionally)
       setupCompletedAt, both at current time.

    If `mark_setup_done=True` (default), set setupCompletedAt so the workspace
    appears as a "used agent" rather than a freshly-onboarded one. This matches
    the lifecycle state we want for trace collection — we do NOT want the
    harness to trigger onboarding flow every session.
    """
    os.makedirs(workspace_root, exist_ok=True)

    # Seed missing template files.
    for filename in TEMPLATE_FILES:
        target = os.path.join(workspace_root, filename)
        if os.path.exists(target):
            continue
        src = os.path.join(_TEMPLATES_DIR, filename)
        if not os.path.exists(src):
            # Template missing — fall back to empty file.
            with open(target, "w", encoding="utf-8") as f:
                f.write(f"# {filename[:-3]}\n")
            continue
        shutil.copyfile(src, target)

    # Create memory/ directory (for per-date logs).
    os.makedirs(os.path.join(workspace_root, "memory"), exist_ok=True)

    # Write workspace-state.json.
    state = read_workspace_state(workspace_root)
    if state is None or "bootstrapSeededAt" not in state:
        mark_bootstrap_seeded(workspace_root)
    if mark_setup_done:
        state = read_workspace_state(workspace_root) or {}
        if "setupCompletedAt" not in state:
            mark_setup_completed(workspace_root)
        # After marking setup, BOOTSTRAP.md is no longer needed — real
        # OpenClaw deletes it at this point. Ensure reused workspaces cannot
        # keep a stale onboarding file around.
        bootstrap_path = os.path.join(workspace_root, DEFAULT_BOOTSTRAP_FILENAME)
        if os.path.exists(bootstrap_path):
            os.unlink(bootstrap_path)
