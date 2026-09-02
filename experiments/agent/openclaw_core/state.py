"""Atomic state mutations — port of workspace.ts:282-296 writeWorkspaceSetupState.

This module handles OpenClaw's "internal state" write path (SPEC §4.2):
- .openclaw/workspace-state.json
- Session store files

Uses the atomic `.tmp-<pid>-<base36_ts>` + `os.rename` pattern.

LLM-facing writes (write/edit tool) do NOT use this module — see pi_tools/write.py
and pi_tools/edit.py for the direct-write path (SPEC §4.1).

Source reference: mnt/openclaw/src/agents/workspace.ts:282-296
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Optional

from .boundary import BoundaryError, resolve_boundary_path

# Current workspace-state.json schema version (SPEC §5).
WORKSPACE_STATE_VERSION = 1


def _tmp_suffix() -> str:
    """Generate a .tmp-<pid>-<base36_ts> suffix matching OpenClaw's format.

    Matches workspace.ts:282-296:
        `${targetPath}.tmp-${pid}-${Date.now().toString(36)}`

    Where `Date.now()` returns milliseconds since epoch, `.toString(36)` is
    base-36 alphanumeric.
    """
    pid = os.getpid()
    ms = int(time.time() * 1000)
    # base36 encoding of an integer (Python stdlib has no builtin base36).
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    if ms == 0:
        b36 = "0"
    else:
        out = []
        n = ms
        while n:
            out.append(digits[n % 36])
            n //= 36
        b36 = "".join(reversed(out))
    return f".tmp-{pid}-{b36}"


def atomic_write(
    target_path: str,
    content: str,
    *,
    encoding: str = "utf-8",
    mode: int = 0o644,
) -> None:
    """Write `content` to `target_path` atomically.

    Produces inotify signature: CREATE <tmp> + MOVED_FROM <tmp> + MOVED_TO <target>.
    This is the distinguishing signature of OpenClaw *internal* state writes
    (§4.2). LLM-facing writes go through pi_tools/write.py and produce a single
    MODIFY/CREATE event.

    On failure: best-effort unlink of tmp, then re-raise.
    """
    os.makedirs(os.path.dirname(target_path) or ".", exist_ok=True)
    tmp_path = target_path + _tmp_suffix()

    try:
        # Write and fsync the tmp file before rename, matching the integrity
        # guarantees of fs.writeFileSync + fs.renameSync on POSIX.
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            with os.fdopen(fd, "w", encoding=encoding, closefd=True) as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            # If fdopen fails after os.open, make sure fd is closed.
            try:
                os.close(fd)
            except OSError:
                pass
            raise

        os.rename(tmp_path, target_path)
    except Exception:
        # Best-effort tmp cleanup (matches workspace.ts:294 catch-unlink-ignore).
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        except OSError:
            pass
        raise


def atomic_write_json(target_path: str, data: Any, *, indent: Optional[int] = 2) -> None:
    """Serialize `data` as JSON and write atomically.

    Matches workspace.ts writeWorkspaceSetupState which uses JSON.stringify(obj, null, 2).
    """
    content = json.dumps(data, indent=indent, ensure_ascii=False, sort_keys=False)
    if not content.endswith("\n"):
        content += "\n"
    atomic_write(target_path, content)


# ----- Workspace state file (SPEC §5) -----


def _now_iso() -> str:
    """ISO-8601 timestamp in UTC with 'Z' suffix, matches OpenClaw Date.toISOString()."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def workspace_state_path(workspace_root: str) -> str:
    """Path to .openclaw/workspace-state.json inside the workspace."""
    return os.path.join(workspace_root, ".openclaw", "workspace-state.json")


def read_workspace_state(workspace_root: str) -> Optional[dict]:
    """Read .openclaw/workspace-state.json. Returns None if file doesn't exist.

    Does NOT go through boundary checks — this is an internal-state read
    on a fixed path, and boundary checks are primarily for LLM-controlled paths.
    """
    path = workspace_state_path(workspace_root)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write_workspace_state(
    workspace_root: str,
    *,
    bootstrap_seeded_at: Optional[str] = None,
    setup_completed_at: Optional[str] = None,
) -> None:
    """Write .openclaw/workspace-state.json atomically.

    SPEC §5 schema:
        {"version": 1, "bootstrapSeededAt": "...", "setupCompletedAt": "..."}

    Unspecified timestamps are preserved from existing state if present.
    """
    existing = read_workspace_state(workspace_root) or {}
    state: dict[str, Any] = {"version": WORKSPACE_STATE_VERSION}
    # Preserve existing timestamps if not overridden.
    if bootstrap_seeded_at is not None:
        state["bootstrapSeededAt"] = bootstrap_seeded_at
    elif "bootstrapSeededAt" in existing:
        state["bootstrapSeededAt"] = existing["bootstrapSeededAt"]

    if setup_completed_at is not None:
        state["setupCompletedAt"] = setup_completed_at
    elif "setupCompletedAt" in existing:
        state["setupCompletedAt"] = existing["setupCompletedAt"]

    # Ensure .openclaw/ exists (boundary check: must be inside workspace).
    openclaw_dir = os.path.join(workspace_root, ".openclaw")
    os.makedirs(openclaw_dir, exist_ok=True)

    # Sanity check: target path is inside workspace root.
    try:
        resolve_boundary_path(workspace_state_path(workspace_root), workspace_root)
    except BoundaryError:
        # Path is inside a directory we just created — this should not happen
        # unless workspace_root is itself a symlink that resolves elsewhere.
        raise

    atomic_write_json(workspace_state_path(workspace_root), state)


def mark_bootstrap_seeded(workspace_root: str) -> None:
    """Set bootstrapSeededAt to now. Preserves setupCompletedAt if set."""
    write_workspace_state(workspace_root, bootstrap_seeded_at=_now_iso())


def mark_setup_completed(workspace_root: str) -> None:
    """Set setupCompletedAt to now. Preserves bootstrapSeededAt if set."""
    write_workspace_state(workspace_root, setup_completed_at=_now_iso())
