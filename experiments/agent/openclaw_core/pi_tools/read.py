"""read tool — port of pi-coding-agent/src/core/tools/read.ts.

Reads a file relative to the workspace root through the boundary guard and
returns contents with 1-indexed line numbers. Matches pi-tools read behavior:
- Default reads up to 2000 lines starting at line 1
- `offset` is 1-indexed (line number), `limit` is a line count
- Lines are returned with ``{lineno:>6}\\t{content}`` prefix (matches Claude Code's
  cat-n style used upstream)

Implementation notes:
- Path resolution: if `path` is relative, join against workspace_root; if
  absolute, pass through unchanged. Boundary guard enforces containment.
- We do not implement image return semantics — the harness is text-only.
- We do not implement Jupyter cell splitting — out of scope.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from ..boundary import (
    BoundaryError,
    DEFAULT_MAX_BYTES,
    open_boundary_file,
)


DEFAULT_READ_LIMIT = 2000


@dataclass
class ToolReadResult:
    """Return value for `read` tool invocations.

    Attributes:
        ok: True on success, False if the boundary guard or IO rejected.
        content: rendered content (with line numbers) on success, None otherwise.
        error: structured error message on failure (None on success).
        resolved_path: absolute canonical path that was read (None on failure).
        total_lines: total lines in the file (independent of offset/limit).
        returned_lines: number of lines included in `content`.
    """

    ok: bool
    content: Optional[str] = None
    error: Optional[str] = None
    resolved_path: Optional[str] = None
    total_lines: int = 0
    returned_lines: int = 0


def _resolve_input_path(path: str, workspace_root: str) -> str:
    """Produce an absolute path from a user-supplied path.

    Relative paths resolve against `workspace_root`. Absolute paths pass
    through. Actual containment check happens inside open_boundary_file.
    """
    if os.path.isabs(path):
        return path
    return os.path.join(workspace_root, path)


def _format_with_line_numbers(lines: list[str], start_lineno: int) -> str:
    """Prefix each line with ``{lineno:>6}\\t``. Matches upstream cat-n style."""
    rendered = []
    for idx, line in enumerate(lines):
        lineno = start_lineno + idx
        # Preserve trailing newlines already in content; add when missing.
        if line.endswith("\n"):
            rendered.append(f"{lineno:>6}\t{line}")
        else:
            rendered.append(f"{lineno:>6}\t{line}\n")
    return "".join(rendered)


def read_tool(
    path: str,
    *,
    workspace_root: str,
    offset: Optional[int] = None,
    limit: Optional[int] = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> ToolReadResult:
    """Execute the `read` tool.

    Args:
        path: absolute or workspace-relative path.
        workspace_root: absolute path to the workspace root.
        offset: 1-indexed starting line. Default 1.
        limit: maximum number of lines to return. Default 2000.
        max_bytes: size cap for boundary file open.

    Returns:
        ToolReadResult with either rendered content or an error message.
    """
    if offset is None:
        offset = 1
    if limit is None:
        limit = DEFAULT_READ_LIMIT
    if offset < 1:
        return ToolReadResult(
            ok=False,
            error="offset must be >= 1 (lines are 1-indexed)",
        )
    if limit < 1:
        return ToolReadResult(ok=False, error="limit must be >= 1")

    absolute = _resolve_input_path(path, workspace_root)

    try:
        fd, stat_result, resolved = open_boundary_file(
            absolute, workspace_root, max_bytes=max_bytes
        )
    except BoundaryError as exc:
        return ToolReadResult(ok=False, error=f"{exc.reason}: {exc}")
    except FileNotFoundError:
        return ToolReadResult(ok=False, error="file not found")
    except OSError as exc:
        return ToolReadResult(ok=False, error=f"io: {exc}")

    read_error: Optional[str] = None
    raw: bytes = b""
    try:
        # open_boundary_file already validated size; read the full file.
        raw = os.read(fd, stat_result.st_size)
    except OSError as exc:
        read_error = f"io: {exc}"
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

    if read_error is not None:
        return ToolReadResult(
            ok=False,
            error=read_error,
            resolved_path=resolved.canonical,
        )

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return ToolReadResult(
            ok=False,
            error="file is not valid UTF-8",
            resolved_path=resolved.canonical,
        )

    # Split preserving line terminators so round-trip byte counts make sense.
    # str.splitlines(keepends=True) keeps trailing "\n" in each entry and also
    # handles final line without terminator correctly.
    lines = text.splitlines(keepends=True)
    total = len(lines)

    start_idx = offset - 1  # convert 1-indexed -> 0-indexed
    if start_idx >= total:
        # Offset past EOF — return empty content but not an error
        # (matches upstream "read after EOF returns empty").
        return ToolReadResult(
            ok=True,
            content="",
            resolved_path=resolved.canonical,
            total_lines=total,
            returned_lines=0,
        )
    end_idx = min(start_idx + limit, total)
    selected = lines[start_idx:end_idx]
    rendered = _format_with_line_numbers(selected, start_lineno=offset)

    return ToolReadResult(
        ok=True,
        content=rendered,
        resolved_path=resolved.canonical,
        total_lines=total,
        returned_lines=end_idx - start_idx,
    )
