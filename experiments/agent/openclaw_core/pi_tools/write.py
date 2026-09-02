"""write tool — port of pi-coding-agent/src/core/tools/write.ts.

SPEC §4.1 — direct (non-atomic) fs.writeFile semantics. Auto-creates parent
directories. Produces a single CREATE or MODIFY inotify event on the target
(no .tmp-* precursor).

Serialization: per-canonical-path via FileMutationQueue. No atomicity — that
is intentional (matches upstream) and critical for trace fidelity since
detection experiments rely on the signature dichotomy between LLM writes
(direct) and internal state writes (.tmp+rename).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from ..boundary import (
    BoundaryError,
    resolve_boundary_path,
)
from .mutation_queue import FileMutationQueue, default_queue


@dataclass
class ToolWriteResult:
    """Return value for `write` tool invocations.

    Attributes:
        ok: True on successful write.
        error: Structured error message on failure.
        resolved_path: absolute canonical path that was (or would have been) written.
        bytes_written: number of bytes written on success.
        created: True if target was newly created, False if it was overwritten.
    """

    ok: bool
    error: Optional[str] = None
    resolved_path: Optional[str] = None
    bytes_written: int = 0
    created: bool = False


def _resolve_input_path(path: str, workspace_root: str) -> str:
    if os.path.isabs(path):
        return path
    return os.path.join(workspace_root, path)


def write_tool(
    path: str,
    content: str,
    *,
    workspace_root: str,
    queue: Optional[FileMutationQueue] = None,
) -> ToolWriteResult:
    """Execute the `write` tool.

    Args:
        path: absolute or workspace-relative path.
        content: full file contents (UTF-8).
        workspace_root: absolute workspace root.
        queue: optional mutation queue for per-path serialization. Defaults to
            the process-wide queue.

    Returns:
        ToolWriteResult describing success or failure.
    """
    if queue is None:
        queue = default_queue()

    absolute = _resolve_input_path(path, workspace_root)

    # Boundary containment check. We allow the target to be missing (write
    # creates it), so we do resolve_boundary_path against the parent
    # directory's expected location rather than open_boundary_file (which
    # requires an existing file).
    try:
        resolved = resolve_boundary_path(absolute, workspace_root)
    except BoundaryError as exc:
        return ToolWriteResult(ok=False, error=f"{exc.reason}: {exc}")

    # We ALSO validate that any existing symlink on the SUPPLIED path is
    # safe. If the supplied path is a symlink (regardless of whether the
    # target lives inside or outside the workspace), refuse — upstream
    # pi-coding-agent uses open(path, "w") which would follow symlinks and
    # could clobber unexpected files. We follow O_NOFOLLOW semantics here
    # for fidelity to our boundary guarantees.
    #
    # We check both `absolute` (what the LLM supplied, pre-realpath) and
    # `resolved.canonical` (post-realpath). The pre-realpath check catches
    # symlinks-pointing-inside-the-workspace which our containment check
    # allows but should not transparently follow.
    import stat as stat_module

    if os.path.lexists(absolute):
        try:
            supplied_st = os.lstat(absolute)
        except OSError as exc:
            return ToolWriteResult(
                ok=False,
                error=f"io: lstat failed: {exc}",
                resolved_path=resolved.canonical,
            )
        if stat_module.S_ISLNK(supplied_st.st_mode):
            return ToolWriteResult(
                ok=False,
                error="validation: target is a symlink; refusing to follow",
                resolved_path=resolved.canonical,
            )

    if os.path.lexists(resolved.canonical):
        try:
            st = os.lstat(resolved.canonical)
        except OSError as exc:
            return ToolWriteResult(
                ok=False,
                error=f"io: lstat failed: {exc}",
                resolved_path=resolved.canonical,
            )
        if not stat_module.S_ISREG(st.st_mode):
            return ToolWriteResult(
                ok=False,
                error=f"validation: target is not a regular file "
                f"(mode=0o{st.st_mode:o})",
                resolved_path=resolved.canonical,
            )

    created = not os.path.exists(resolved.canonical)

    # Serialize against concurrent writes to the same path.
    try:
        with queue.acquire(resolved.canonical):
            # Auto-create parent directories (pi-coding-agent's mkdir -p).
            parent = os.path.dirname(resolved.canonical)
            if parent:
                try:
                    os.makedirs(parent, exist_ok=True)
                except OSError as exc:
                    return ToolWriteResult(
                        ok=False,
                        error=f"io: mkdir failed: {exc}",
                        resolved_path=resolved.canonical,
                    )

            # Direct write — NO .tmp+rename. This is the whole point.
            encoded = content.encode("utf-8")
            try:
                with open(resolved.canonical, "wb") as f:
                    f.write(encoded)
            except OSError as exc:
                return ToolWriteResult(
                    ok=False,
                    error=f"io: write failed: {exc}",
                    resolved_path=resolved.canonical,
                )
    except OSError as exc:
        return ToolWriteResult(
            ok=False,
            error=f"io: {exc}",
            resolved_path=resolved.canonical,
        )

    return ToolWriteResult(
        ok=True,
        resolved_path=resolved.canonical,
        bytes_written=len(content.encode("utf-8")),
        created=created,
    )
