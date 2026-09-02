"""edit tool — port of pi-coding-agent/src/core/tools/edit.ts.

SPEC §4.1 — read → exact string-replace → direct fs.writeFile. Like `write`,
this is NOT atomic. Single MODIFY event on the target (no .tmp-* precursor).

Semantics:
- `old_text` must appear EXACTLY once in the file. Zero or multiple matches → error.
- Replacement is literal string replacement (no regex).
- Empty `old_text` is not allowed (it would match infinitely).
- If the file doesn't exist, the tool fails (use `write` instead).

Differences from upstream:
- We reuse write_tool's symlink rejection for consistency.
- Upstream uses `replaceFirst` with a uniqueness check; we implement the
  uniqueness check explicitly.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from ..boundary import (
    BoundaryError,
    open_boundary_file,
)
from .mutation_queue import FileMutationQueue, default_queue


@dataclass
class ToolEditResult:
    """Return value for `edit` tool invocations.

    Attributes:
        ok: True on success.
        error: Structured error message on failure.
        resolved_path: absolute canonical path.
        bytes_before: original file size in bytes.
        bytes_after: new file size in bytes after edit.
        match_count: number of occurrences of `old_text` in the original.
    """

    ok: bool
    error: Optional[str] = None
    resolved_path: Optional[str] = None
    bytes_before: int = 0
    bytes_after: int = 0
    match_count: int = 0


def _resolve_input_path(path: str, workspace_root: str) -> str:
    if os.path.isabs(path):
        return path
    return os.path.join(workspace_root, path)


def edit_tool(
    path: str,
    old_text: str,
    new_text: str,
    *,
    workspace_root: str,
    queue: Optional[FileMutationQueue] = None,
) -> ToolEditResult:
    """Execute the `edit` tool.

    Args:
        path: absolute or workspace-relative path.
        old_text: exact substring to replace. Must be non-empty and appear
            exactly once in the file.
        new_text: replacement.
        workspace_root: absolute workspace root.
        queue: per-path mutation queue; defaults to the process-wide queue.

    Returns:
        ToolEditResult.
    """
    if queue is None:
        queue = default_queue()

    if old_text == "":
        return ToolEditResult(
            ok=False,
            error="validation: old_text must not be empty",
        )

    absolute = _resolve_input_path(path, workspace_root)

    # Serialize read+write as a single atomic-to-LLM operation. Two concurrent
    # edits must not interleave (otherwise uniqueness guarantees break).
    with queue.acquire(absolute):
        # Read existing content through the boundary guard.
        try:
            fd, stat_result, resolved = open_boundary_file(absolute, workspace_root)
        except BoundaryError as exc:
            return ToolEditResult(ok=False, error=f"{exc.reason}: {exc}")
        except FileNotFoundError:
            return ToolEditResult(
                ok=False,
                error="file not found (use write to create new files)",
            )
        except OSError as exc:
            return ToolEditResult(ok=False, error=f"io: {exc}")

        read_error: Optional[str] = None
        raw: bytes = b""
        try:
            raw = os.read(fd, stat_result.st_size)
        except OSError as exc:
            read_error = f"io: read failed: {exc}"
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

        if read_error is not None:
            return ToolEditResult(
                ok=False,
                error=read_error,
                resolved_path=resolved.canonical,
            )

        try:
            original = raw.decode("utf-8")
        except UnicodeDecodeError:
            return ToolEditResult(
                ok=False,
                error="file is not valid UTF-8",
                resolved_path=resolved.canonical,
            )

        count = original.count(old_text)
        if count == 0:
            return ToolEditResult(
                ok=False,
                error="old_text not found in file",
                resolved_path=resolved.canonical,
                bytes_before=len(raw),
                match_count=0,
            )
        if count > 1:
            return ToolEditResult(
                ok=False,
                error=(
                    f"old_text matches {count} times; must be unique. "
                    "Include more surrounding context to disambiguate."
                ),
                resolved_path=resolved.canonical,
                bytes_before=len(raw),
                match_count=count,
            )

        new_content = original.replace(old_text, new_text, 1)
        encoded = new_content.encode("utf-8")

        # Direct write — NO .tmp+rename. Matches pi-coding-agent.
        try:
            with open(resolved.canonical, "wb") as f:
                f.write(encoded)
        except OSError as exc:
            return ToolEditResult(
                ok=False,
                error=f"io: write failed: {exc}",
                resolved_path=resolved.canonical,
                bytes_before=len(raw),
                match_count=1,
            )

        return ToolEditResult(
            ok=True,
            resolved_path=resolved.canonical,
            bytes_before=len(raw),
            bytes_after=len(encoded),
            match_count=1,
        )
