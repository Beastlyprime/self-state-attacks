"""LLM-facing tool layer — port of pi-coding-agent tools.

Implements SPEC §4.1 and §6:
- read, write, edit, bash tools with direct (non-atomic) file semantics
- Per-path serialization via mutation_queue
- Workspace boundary guard (wrapToolWorkspaceRootGuard)
- Memory-flush append-only wrapper (wrapToolMemoryFlushAppendOnlyWrite)

Source reference:
- pi-coding-agent/src/core/tools/{read,write,edit,bash}.ts
- mnt/openclaw/src/agents/pi-tools.ts
- mnt/openclaw/src/agents/pi-tools.read.ts
"""

from .bash import bash_tool, ToolBashResult
from .edit import edit_tool, ToolEditResult
from .mutation_queue import FileMutationQueue
from .read import read_tool, ToolReadResult
from .schema import (
    BASH_TOOL_SCHEMA,
    EDIT_TOOL_SCHEMA,
    MEMORY_FLUSH_ALLOWED_TOOL_NAMES,
    READ_TOOL_SCHEMA,
    WRITE_TOOL_SCHEMA,
    get_default_tool_schemas,
)
from .write import write_tool, ToolWriteResult
from .wrappers import (
    MemoryFlushContext,
    WorkspaceRootGuardError,
    wrap_tool_memory_flush_append_only,
    wrap_tool_workspace_root_guard,
)

__all__ = [
    "BASH_TOOL_SCHEMA",
    "EDIT_TOOL_SCHEMA",
    "FileMutationQueue",
    "MEMORY_FLUSH_ALLOWED_TOOL_NAMES",
    "MemoryFlushContext",
    "READ_TOOL_SCHEMA",
    "ToolBashResult",
    "ToolEditResult",
    "ToolReadResult",
    "ToolWriteResult",
    "WRITE_TOOL_SCHEMA",
    "WorkspaceRootGuardError",
    "bash_tool",
    "edit_tool",
    "get_default_tool_schemas",
    "read_tool",
    "wrap_tool_memory_flush_append_only",
    "wrap_tool_workspace_root_guard",
    "write_tool",
]
