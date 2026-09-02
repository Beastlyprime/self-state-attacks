"""Tool wrappers — port of mnt/openclaw/src/agents/pi-tools.read.ts.

Implements:
- wrap_tool_workspace_root_guard (SPEC §6.2): pre-execution containment check
- wrap_tool_memory_flush_append_only (SPEC §6.4): restricts memory-flush
  sessions to read/write, and coerces writes on the memory target to append.

Our primary tool functions (read_tool/write_tool/edit_tool) already call
boundary guards internally, so wrap_tool_workspace_root_guard here is a
thin, additional early-reject path — matching the upstream pattern where the
wrapper rejects before delegating. We keep it because (a) fidelity to the
OpenClaw call graph matters for trace experiments; (b) it gives us a single
point to add policy hooks if needed later.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..boundary import BoundaryError, resolve_boundary_path
from .read import ToolReadResult, read_tool
from .schema import MEMORY_FLUSH_ALLOWED_TOOL_NAMES
from .write import ToolWriteResult, write_tool


class WorkspaceRootGuardError(Exception):
    """Raised when a tool is invoked with a path outside the workspace root."""

    def __init__(self, path: str, root: str, reason: str = "path"):
        super().__init__(f"{reason}: {path} not contained in {root}")
        self.path = path
        self.root = root
        self.reason = reason


def _resolve_input_path(path: str, workspace_root: str) -> str:
    if os.path.isabs(path):
        return path
    return os.path.join(workspace_root, path)


def wrap_tool_workspace_root_guard(
    tool_fn: Callable[..., Any],
    workspace_root: str,
) -> Callable[..., Any]:
    """Wrap a tool so it rejects any path argument outside workspace_root.

    The returned callable has the same signature as `tool_fn`. If the first
    argument is a `path`, we validate it against workspace_root before
    delegating. This mirrors the upstream wrapper, which rejects with a
    structured error before the actual tool executes.
    """

    def _wrapped(path: str, *args: Any, **kwargs: Any) -> Any:
        absolute = _resolve_input_path(path, workspace_root)
        try:
            resolve_boundary_path(absolute, workspace_root)
        except BoundaryError as exc:
            # Re-raise as a structured exception; callers can catch it and
            # convert to a structured tool error for the LLM.
            raise WorkspaceRootGuardError(
                path=path,
                root=workspace_root,
                reason=exc.reason,
            ) from exc
        # Force workspace_root kwarg so inner tool can't be called with a
        # different one by accident.
        kwargs["workspace_root"] = workspace_root
        return tool_fn(path, *args, **kwargs)

    return _wrapped


@dataclass
class MemoryFlushContext:
    """Configuration for a memory-flush session.

    Attributes:
        root: workspace root.
        relative_path: path (relative to root) that the memory-flush session
            is allowed to write to. Typically "MEMORY.md" or
            "memory/YYYY-MM-DD.md".
    """

    root: str
    relative_path: str


def wrap_tool_memory_flush_append_only(
    tool_name: str,
    tool_fn: Callable[..., Any],
    ctx: MemoryFlushContext,
) -> Optional[Callable[..., Any]]:
    """Wrap a tool for memory-flush sessions.

    Returns:
        - None if the tool is not allowed during memory-flush (caller should
          NOT expose it to the LLM).
        - A wrapped callable for read (pass-through) and write (coerced to
          append semantics against ctx.relative_path only).

    Port of wrapToolMemoryFlushAppendOnlyWrite in pi-tools.read.ts.
    """
    if tool_name not in MEMORY_FLUSH_ALLOWED_TOOL_NAMES:
        return None

    if tool_name == "read":
        # read is allowed with no further restriction (but still subject to
        # workspace-root guard if the caller composed them).
        return tool_fn

    if tool_name == "write":
        target_abs = os.path.join(ctx.root, ctx.relative_path)

        def _append_only_write(
            path: str,
            content: str,
            **kwargs: Any,
        ) -> ToolWriteResult:
            # Resolve the supplied path and verify it matches the memory target.
            supplied_abs = _resolve_input_path(path, ctx.root)
            try:
                supplied_resolved = resolve_boundary_path(supplied_abs, ctx.root)
                target_resolved = resolve_boundary_path(target_abs, ctx.root)
            except BoundaryError as exc:
                return ToolWriteResult(
                    ok=False,
                    error=f"{exc.reason}: {exc}",
                )
            if supplied_resolved.canonical != target_resolved.canonical:
                return ToolWriteResult(
                    ok=False,
                    error=(
                        "validation: memory-flush writes are restricted to "
                        f"{ctx.relative_path}"
                    ),
                )

            # Coerce to append. Read the existing content (if any) and
            # concatenate `content` after it. Upstream preserves existing
            # bytes and inserts exactly one newline only when the existing
            # file lacks a trailing newline and the incoming content does
            # not start with one.
            existing = ""
            if os.path.exists(target_resolved.canonical):
                read_result: ToolReadResult = read_tool(
                    ctx.relative_path,
                    workspace_root=ctx.root,
                )
                if not read_result.ok:
                    return ToolWriteResult(
                        ok=False,
                        error=f"memory-flush read failed: {read_result.error}",
                        resolved_path=target_resolved.canonical,
                    )
                # read_tool returns line-numbered content; we need the raw
                # text, so read the file directly instead.
                try:
                    with open(target_resolved.canonical, "rb") as f:
                        existing = f.read().decode("utf-8", errors="replace")
                except OSError as exc:
                    return ToolWriteResult(
                        ok=False,
                        error=f"io: {exc}",
                        resolved_path=target_resolved.canonical,
                    )

            separator = (
                "\n"
                if existing
                and not existing.endswith("\n")
                and not content.startswith("\n")
                else ""
            )
            combined = f"{existing}{separator}{content}"

            # Delegate to write_tool. Note: it's the underlying direct-write
            # path, so the inotify signature is still a single MODIFY event.
            kwargs["workspace_root"] = ctx.root
            return write_tool(
                ctx.relative_path,
                combined,
                **kwargs,
            )

        return _append_only_write

    # Defensive: MEMORY_FLUSH_ALLOWED_TOOL_NAMES already filters, but in case
    # the set is expanded in the future without updating this function.
    return None


@dataclass
class WrappedToolSet:
    """Collection of tool callables as exposed to the LLM in a session.

    Attributes:
        read: read callable (workspace-guarded).
        write: write callable (workspace-guarded).
        edit: edit callable (workspace-guarded) or None in memory-flush mode.
        bash: bash callable or None in memory-flush mode.
    """

    read: Callable[..., Any]
    write: Callable[..., Any]
    edit: Optional[Callable[..., Any]] = None
    bash: Optional[Callable[..., Any]] = None
    exposed_names: tuple[str, ...] = field(default_factory=tuple)
