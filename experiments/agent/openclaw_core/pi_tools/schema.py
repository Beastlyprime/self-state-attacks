"""Tool schemas exposed to the LLM — OpenAI function-calling / tool-use format.

SPEC §6.1 — exact parameter shapes as the LLM sees them.

All schemas use standard JSON Schema. We do not normalize for Gemini because
the harness routes through OpenRouter's OpenAI-compatible endpoint, which
handles provider-specific cleanup upstream (SPEC §6.3).
"""

from __future__ import annotations

# Subset of tools exposed during memory-flush sessions (SPEC §6.4).
# Matches MEMORY_FLUSH_ALLOWED_TOOL_NAMES in mnt/openclaw/src/agents/pi-tools.ts:74.
MEMORY_FLUSH_ALLOWED_TOOL_NAMES: frozenset[str] = frozenset({"read", "write"})


READ_TOOL_SCHEMA: dict = {
    "type": "function",
    "function": {
        "name": "read",
        "description": (
            "Read a file by absolute path or path relative to the workspace "
            "root. Returns the file contents with 1-indexed line numbers, "
            "up to `limit` lines starting at `offset`. Default limit is 2000 "
            "lines from the start of the file. Use `offset` and `limit` to "
            "page through large files."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Absolute path, or path relative to the workspace root."
                    ),
                },
                "offset": {
                    "type": "integer",
                    "description": (
                        "1-indexed line number to start reading from. Default 1."
                    ),
                    "minimum": 1,
                },
                "limit": {
                    "type": "integer",
                    "description": (
                        "Maximum number of lines to read. Default 2000."
                    ),
                    "minimum": 1,
                },
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
}


WRITE_TOOL_SCHEMA: dict = {
    "type": "function",
    "function": {
        "name": "write",
        "description": (
            "Create or overwrite a file. Parent directories are created "
            "automatically. The entire file is replaced with `content`. Use "
            "`edit` for surgical changes to existing files."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Absolute path, or path relative to the workspace root."
                    ),
                },
                "content": {
                    "type": "string",
                    "description": "Full file contents (UTF-8).",
                },
            },
            "required": ["path", "content"],
            "additionalProperties": False,
        },
    },
}


EDIT_TOOL_SCHEMA: dict = {
    "type": "function",
    "function": {
        "name": "edit",
        "description": (
            "Replace an exact substring in a file. `old_text` must match "
            "exactly (including whitespace) and must occur exactly once in "
            "the file. Fails if `old_text` is missing or appears multiple "
            "times. Use `write` for creating files or full rewrites."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Absolute path, or path relative to the workspace root."
                    ),
                },
                "old_text": {
                    "type": "string",
                    "description": "Exact substring to replace (must be unique).",
                },
                "new_text": {
                    "type": "string",
                    "description": "Replacement text.",
                },
            },
            "required": ["path", "old_text", "new_text"],
            "additionalProperties": False,
        },
    },
}


BASH_TOOL_SCHEMA: dict = {
    "type": "function",
    "function": {
        "name": "bash",
        "description": (
            "Run a shell command synchronously. Working directory defaults "
            "to the workspace root. Returns stdout, stderr, and exit code. "
            "Default timeout is 60 seconds."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to execute.",
                },
                "timeout": {
                    "type": "integer",
                    "description": (
                        "Timeout in seconds (default 60, max 600)."
                    ),
                    "minimum": 1,
                    "maximum": 600,
                },
            },
            "required": ["command"],
            "additionalProperties": False,
        },
    },
}


def get_default_tool_schemas() -> list[dict]:
    """Tool schemas exposed in a standard (non-memory-flush) session.

    Order matches the OpenClaw default ordering.
    """
    return [
        READ_TOOL_SCHEMA,
        WRITE_TOOL_SCHEMA,
        EDIT_TOOL_SCHEMA,
        BASH_TOOL_SCHEMA,
    ]
