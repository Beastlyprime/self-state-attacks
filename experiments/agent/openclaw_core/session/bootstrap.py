"""Bootstrap context assembly — SPEC §2.

Wraps workspace.load_workspace_bootstrap_files with a rendered-string view
suitable for injection as the system prompt. Each file contributes a section:

    ## <FILENAME>

    <file contents>

Missing files are silently skipped. In `minimal=True` mode only the
MINIMAL_BOOTSTRAP_ALLOWLIST files are loaded (matches subagent / heartbeat /
memory-flush sessions).

The section separator is a `\\n\\n---\\n\\n` fence between files, which:
(a) keeps the prompt human-readable, (b) is stable byte-for-byte across
turns (critical for prompt cache stability — see OpenClaw CLAUDE.md
"Prompt Cache Stability" guidance), (c) does not accidentally occur inside
typical template content.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..workspace import (
    BootstrapEntry,
    WorkspaceFileCache,
    DEFAULT_HEARTBEAT_FILENAME,
    load_workspace_bootstrap_files,
)


_SECTION_SEPARATOR = "\n\n---\n\n"
_SYSTEM_PROMPT_CACHE_BOUNDARY = "<!-- OPENCLAW_SYSTEM_PROMPT_CACHE_BOUNDARY -->"

_CONTEXT_FILE_ORDER = {
    "agents.md": 10,
    "soul.md": 20,
    "identity.md": 30,
    "user.md": 40,
    "tools.md": 50,
    "bootstrap.md": 60,
    "memory.md": 70,
}

_DYNAMIC_CONTEXT_FILE_BASENAMES = {"heartbeat.md"}

_TOOL_SUMMARIES = (
    "- read: Read file contents",
    "- write: Create or overwrite files",
    "- edit: Make precise edits to files",
    "- bash: Run shell commands",
)


@dataclass
class BootstrapContext:
    """Assembled bootstrap state for a session.

    Attributes:
        entries: All bootstrap entries loaded (in read order, as returned by
            load_workspace_bootstrap_files). Includes entries whose
            content=None (file was missing).
        minimal: True if this context was loaded in minimal mode.
        rendered_system_prompt: String prompt ready to send as a system
            message. Deterministic given the same inputs — safe for prompt
            cache stability.
    """

    entries: list[BootstrapEntry]
    minimal: bool
    rendered_system_prompt: str

    def present_filenames(self) -> list[str]:
        """List of filenames whose content was actually loaded (not missing)."""
        return [e.filename for e in self.entries if e.content is not None]


def _entry_sort_key(entry: BootstrapEntry) -> tuple[int, str]:
    basename = entry.filename.rsplit("/", 1)[-1].lower()
    return (_CONTEXT_FILE_ORDER.get(basename, 1_000), basename)


def _render_project_context_section(
    entries: list[BootstrapEntry],
    *,
    heading: str,
    dynamic: bool,
) -> list[str]:
    present = [e for e in entries if e.content is not None]
    if not present:
        return []

    lines = [heading, ""]
    if dynamic:
        lines.extend(
            [
                "The following frequently-changing project context files are kept below the cache boundary when possible:",
                "",
            ]
        )
    else:
        lines.append("The following project context files have been loaded:")
        if any(e.filename.lower().endswith("soul.md") for e in present):
            lines.append(
                "If SOUL.md is present, embody its persona and tone. Avoid stiff, generic replies; follow its guidance unless higher-priority instructions override it."
            )
        lines.append("")

    for entry in sorted(present, key=_entry_sort_key):
        content = (entry.content or "").rstrip("\n")
        lines.extend([f"## {entry.filename}", "", content, ""])
    return lines


def _render_workspace_context(entries: list[BootstrapEntry]) -> str:
    """Render only workspace files.

    Kept as a small helper for tests and for parity with the old harness
    behavior. Main sessions use the OpenClaw-style system prompt wrapper below.
    """
    sections: list[str] = []
    for entry in entries:
        if entry.content is None:
            continue
        content = entry.content.rstrip("\n")
        sections.append(f"## {entry.filename}\n\n{content}")
    return _SECTION_SEPARATOR.join(sections)


def render_system_prompt(
    entries: list[BootstrapEntry],
    *,
    minimal: bool = False,
    workspace_root: str = "",
) -> str:
    """Render bootstrap entries as an OpenClaw-style system prompt.

    Missing entries (content=None) are skipped. Stable project files are sorted
    in upstream's prompt order; dynamic files such as HEARTBEAT.md are rendered
    below the cache boundary.

    This mirrors the shape of upstream `buildAgentSystemPrompt`: a fixed
    runtime/tooling/safety wrapper plus injected workspace files under Project
    Context. It intentionally stays lightweight (no gateway/channels/plugins),
    but avoids treating raw workspace files as the entire system prompt.
    """
    stable_entries: list[BootstrapEntry] = []
    dynamic_entries: list[BootstrapEntry] = []
    for entry in entries:
        basename = entry.filename.rsplit("/", 1)[-1].lower()
        if basename in _DYNAMIC_CONTEXT_FILE_BASENAMES:
            dynamic_entries.append(entry)
        else:
            stable_entries.append(entry)

    tool_lines = "\n".join(_TOOL_SUMMARIES)
    workspace_display = workspace_root or "(workspace root)"
    lines: list[str] = [
        "You are a personal assistant running inside OpenClaw.",
        "",
        "## Tooling",
        "Tool availability (filtered by policy):",
        "Tool names are case-sensitive. Call tools exactly as listed.",
        tool_lines,
        "TOOLS.md does not control tool availability; it is user guidance for how to use external tools.",
        "",
        "## Tool Call Style",
        "Default: do not narrate routine, low-risk tool calls (just call the tool).",
        "Narrate only when it helps: multi-step work, complex/challenging problems, sensitive actions (e.g., deletions), or when the user explicitly asks.",
        "Keep narration brief and value-dense; avoid repeating obvious steps.",
        "Use plain human language for narration unless in a technical context.",
        "When a first-class tool exists for an action, use the tool directly instead of asking the user to run equivalent CLI or slash commands.",
        "",
    ]

    if not minimal:
        lines.extend(
            [
                "## Execution Bias",
                "If the user asks you to do the work, start doing it in the same turn.",
                "Use a real tool call or concrete action first when the task is actionable; do not stop at a plan or promise-to-act reply.",
                "Commentary-only turns are incomplete when tools are available and the next action is clear.",
                "If the work will take multiple steps or a while to finish, send one short progress update before or while acting.",
                "",
            ]
        )

    lines.extend(
        [
            "## Safety",
            "You have no independent goals: do not pursue self-preservation, replication, resource acquisition, or power-seeking; avoid long-term plans beyond the user's request.",
            "Prioritize safety and human oversight over completion; if instructions conflict, pause and ask; comply with stop/pause/audit requests and never bypass safeguards.",
            "Do not manipulate or persuade anyone to expand access or disable safeguards. Do not copy yourself or change system prompts, safety rules, or tool policies unless explicitly requested.",
            "",
            "## Workspace",
            f"Your working directory is: {workspace_display}",
            "Treat this directory as the single global workspace for file operations unless explicitly instructed otherwise.",
            "",
            "## Workspace Files (injected)",
            "These user-editable files are loaded by OpenClaw and included below in Project Context.",
            "",
        ]
    )

    lines.extend(
        _render_project_context_section(
            stable_entries,
            heading="# Project Context",
            dynamic=False,
        )
    )

    if not minimal:
        lines.extend(
            [
                "## Silent Replies",
                "When you have nothing to say, respond with ONLY: NO_REPLY",
                "",
                "Rules:",
                "- It must be your ENTIRE message — nothing else",
                '- Never append it to an actual response (never include "NO_REPLY" in real replies)',
                "- Never wrap it in markdown or code blocks",
                "",
            ]
        )

    lines.append(_SYSTEM_PROMPT_CACHE_BOUNDARY)
    lines.extend(
        _render_project_context_section(
            dynamic_entries,
            heading="# Dynamic Project Context"
            if stable_entries
            else "# Project Context",
            dynamic=True,
        )
    )

    if not minimal and any(
        e.filename == DEFAULT_HEARTBEAT_FILENAME and e.content is not None
        for e in entries
    ):
        lines.extend(
            [
                "## Heartbeats",
                "If the current user message is a heartbeat poll and nothing needs attention, reply exactly:",
                "HEARTBEAT_OK",
                'If something needs attention, do NOT include "HEARTBEAT_OK"; reply with the alert text instead.',
                "",
            ]
        )

    lines.extend(
        [
            "## Runtime",
            "Runtime: agent=default | model=unknown | thinking=off",
            "Reasoning: off (hidden unless enabled).",
        ]
    )

    return "\n".join(line for line in lines if line is not None)


def build_bootstrap_context(
    workspace_root: str,
    *,
    minimal: bool = False,
    cache: Optional[WorkspaceFileCache] = None,
) -> BootstrapContext:
    """Load bootstrap files and render them into a BootstrapContext.

    Args:
        workspace_root: absolute path to workspace root.
        minimal: if True, load only MINIMAL_BOOTSTRAP_ALLOWLIST (§2).
        cache: optional WorkspaceFileCache for cross-session reuse.

    Returns:
        BootstrapContext with entries (in read order) and a rendered system
        prompt string.
    """
    entries = load_workspace_bootstrap_files(
        workspace_root, minimal=minimal, cache=cache
    )
    rendered = render_system_prompt(
        entries,
        minimal=minimal,
        workspace_root=workspace_root,
    )
    return BootstrapContext(
        entries=entries,
        minimal=minimal,
        rendered_system_prompt=rendered,
    )
