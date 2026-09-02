"""Session log writer — SPEC §10.

Append-only jsonl at `{state_root}/sessions/<session_key>.jsonl`.
One JSON object per line. Each record carries role, content, tool metadata,
and an ISO-8601 timestamp.

Fidelity notes:
- Real OpenClaw stores session logs at `~/.openclaw/agents/<id>/sessions/`.
  The harness mirrors that shape by defaulting to a sibling state directory:
  `<parent-of-workspace>/.openclaw/agents/<agent-id-or-workspace-name>/sessions/`.
  Session transcripts are operational logs, not part of the paper's in-matrix
  self-state targets.
- Records are appended via direct open("a").write — NOT atomic. This is
  intentional: inotify trace signature for session-log writes should be a
  single MODIFY per append, consistent with how real OpenClaw does it
  (fsAppendFile in session store). Do NOT switch to .tmp+rename here.
- Each append is flushed + fsynced so crashes do not lose tail records.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


OPENCLAW_STATE_DIR = ".openclaw"
AGENTS_SUBDIR = "agents"
SESSIONS_SUBDIR = "sessions"


def _now_iso() -> str:
    """Return ISO-8601 UTC timestamp with millisecond precision."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def new_session_key(*, prefix: str = "session") -> str:
    """Generate a new session key: ``<prefix>-YYYYMMDDThhmmss-<random6>``.

    The timestamp prefix makes logs sortable; the random suffix avoids
    collisions when multiple sessions start in the same second.
    """
    ts = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    suffix = secrets.token_hex(3)  # 6 hex chars
    return f"{prefix}-{ts}-{suffix}"


def _safe_agent_dir_name(value: str) -> str:
    """Return a filesystem-safe agent directory name."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    cleaned = cleaned.strip(".-")
    return cleaned or "agent"


def default_state_root(workspace_root: str, *, agent_id: Optional[str] = None) -> str:
    """Resolve the default OpenClaw-style state root for a workspace.

    If ``workspace_root`` is ``.../agent/workspace`` this yields
    ``.../agent/.openclaw/agents/<agent>/``; for a bare workspace tempdir it
    yields ``<parent>/.openclaw/agents/<workspace-name>/``.
    """
    abs_workspace = os.path.abspath(workspace_root)
    parent = os.path.dirname(abs_workspace)
    workspace_name = os.path.basename(abs_workspace)
    if agent_id:
        raw_agent = agent_id
    elif workspace_name == "workspace" and os.path.basename(parent):
        raw_agent = os.path.basename(parent)
    else:
        raw_agent = workspace_name or "agent"
    return os.path.join(
        parent,
        OPENCLAW_STATE_DIR,
        AGENTS_SUBDIR,
        _safe_agent_dir_name(raw_agent),
    )


def _sessions_dir(state_root: str) -> str:
    return os.path.join(state_root, SESSIONS_SUBDIR)


def session_log_path(
    workspace_root: str,
    session_key: str,
    *,
    state_root: Optional[str] = None,
    agent_id: Optional[str] = None,
) -> str:
    """Resolve the jsonl path for a session key."""
    root = os.path.abspath(state_root) if state_root else default_state_root(
        workspace_root,
        agent_id=agent_id,
    )
    return os.path.join(_sessions_dir(root), f"{session_key}.jsonl")


@dataclass
class SessionLogger:
    """Append-only jsonl session log.

    Usage:
        logger = SessionLogger.create(workspace_root)
        logger.log_user("please read x.txt")
        logger.log_assistant(content="reading now", tool_calls=[...])
        logger.log_tool_result(tool_call_id="tc1", content='{"ok":true}')
        logger.close()

    Attributes:
        workspace_root: absolute workspace root.
        state_root: absolute OpenClaw-style state root for operational logs.
        session_key: unique session identifier (see new_session_key).
        log_path: absolute path of the jsonl file.
        meta: additional fields stamped into every record (e.g. model, profile).
    """

    workspace_root: str
    state_root: str
    session_key: str
    log_path: str
    meta: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        workspace_root: str,
        *,
        session_key: Optional[str] = None,
        state_root: Optional[str] = None,
        meta: Optional[dict[str, Any]] = None,
    ) -> "SessionLogger":
        meta_dict = dict(meta or {})
        key = session_key or new_session_key()
        resolved_state_root = os.path.abspath(
            state_root
            or default_state_root(
                workspace_root,
                agent_id=meta_dict.get("agent_id"),
            )
        )
        sess_dir = _sessions_dir(resolved_state_root)
        os.makedirs(sess_dir, exist_ok=True)
        log_path = os.path.join(sess_dir, f"{key}.jsonl")
        logger = cls(
            workspace_root=os.path.abspath(workspace_root),
            state_root=resolved_state_root,
            session_key=key,
            log_path=log_path,
            meta=meta_dict,
        )
        # Stamp a session-start record so the file is non-empty and the
        # meta fields can be recovered without re-scanning.
        logger._append_record(
            {
                "type": "session_start",
                "session_key": key,
                "workspace_root": logger.workspace_root,
                "state_root": logger.state_root,
                "meta": logger.meta,
            }
        )
        return logger

    # ---- record writers -----

    def log_user(self, content: str) -> None:
        self._append_record({"role": "user", "content": content})

    def log_assistant(
        self,
        *,
        content: str,
        tool_calls: Optional[list[dict[str, Any]]] = None,
        finish_reason: Optional[str] = None,
        usage: Optional[dict[str, Any]] = None,
    ) -> None:
        record: dict[str, Any] = {"role": "assistant", "content": content}
        if tool_calls:
            record["tool_calls"] = tool_calls
        if finish_reason is not None:
            record["finish_reason"] = finish_reason
        if usage is not None:
            record["usage"] = usage
        self._append_record(record)

    def log_tool_result(
        self,
        *,
        tool_call_id: str,
        name: str,
        content: str,
        ok: bool,
        error: Optional[str] = None,
    ) -> None:
        record: dict[str, Any] = {
            "role": "tool",
            "tool_call_id": tool_call_id,
            "name": name,
            "content": content,
            "ok": ok,
        }
        if error is not None:
            record["error"] = error
        self._append_record(record)

    def log_event(self, event_type: str, **fields: Any) -> None:
        """Log a non-message event (e.g. memory-flush trigger, heartbeat tick)."""
        record: dict[str, Any] = {"type": event_type}
        for k, v in fields.items():
            record[k] = v
        self._append_record(record)

    def log_compaction_summary(
        self,
        *,
        summary: str,
        tokens_before: int,
        tokens_after: int,
        route: str,
        messages_summarized: int,
        messages_preserved: int,
    ) -> None:
        """Append an OpenClaw-style compaction marker to the session log."""
        self._append_record(
            {
                "type": "compaction",
                "role": "compactionSummary",
                "summary": summary,
                "tokens_before": tokens_before,
                "tokens_after": tokens_after,
                "route": route,
                "messages_summarized": messages_summarized,
                "messages_preserved": messages_preserved,
            }
        )

    def close(self) -> None:
        """Stamp a session_end record. No-op if already closed."""
        self._append_record({"type": "session_end"})

    # ---- io -----

    def _append_record(self, record: dict[str, Any]) -> None:
        """Append one JSON line with timestamp + flush + fsync.

        Matches OpenClaw session-store signature: single CREATE or MODIFY
        event, no .tmp+rename.
        """
        record.setdefault("timestamp", _now_iso())
        record.setdefault("timestamp_realtime_ns", time.time_ns())
        record.setdefault("timestamp_monotonic_ns", time.monotonic_ns())
        line = json.dumps(record, ensure_ascii=False) + "\n"
        # Open-append-close per record so concurrent sessions on the same
        # file (rare in harness) don't interleave via buffered writers.
        # This mirrors the inotify signature we want: one MODIFY per write.
        fd = os.open(
            self.log_path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o644,
        )
        try:
            os.write(fd, line.encode("utf-8"))
            try:
                os.fsync(fd)
            except OSError:
                # fsync can fail on some filesystems (e.g. tmpfs in CI);
                # don't escalate — the write itself succeeded.
                pass
        finally:
            os.close(fd)
