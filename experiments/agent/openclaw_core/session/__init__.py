"""Session layer — LLM loop, bootstrap context assembly, session logging.

Public surface:
- SessionRunner: main LLM loop (prompt → tool call → prompt → ...)
- build_bootstrap_context: assembles system prompt from bootstrap files
- SessionLogger: append-only jsonl session log writer
- MemoryFlushDecision / should_run_memory_flush: token-gated flush helper
"""

from .bootstrap import (
    BootstrapContext,
    build_bootstrap_context,
    render_system_prompt,
)
from .log import SessionLogger, new_session_key
from .memory_flush import (
    MemoryFlushDecision,
    compute_context_hash,
    should_run_memory_flush,
)
from .runner import (
    SessionResult,
    SessionRunner,
    ToolExecutionRecord,
)

__all__ = [
    "BootstrapContext",
    "MemoryFlushDecision",
    "SessionLogger",
    "SessionResult",
    "SessionRunner",
    "ToolExecutionRecord",
    "build_bootstrap_context",
    "compute_context_hash",
    "new_session_key",
    "render_system_prompt",
    "should_run_memory_flush",
]
