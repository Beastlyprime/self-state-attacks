"""Heartbeat runner — SPEC §8.

A heartbeat is a periodic, minimal-bootstrap session that lets the agent
check whether scheduled work is due. Semantics mirror real OpenClaw
(src/auto-reply/heartbeat.ts, src/agents/workspace.ts filterBootstrapFilesForSession).

Harness model (SPEC §8.5):
- Interval: 30 minutes by default (real OpenClaw uses device-id hash for
  phase; we use agent_id + a caller-supplied scheduler_seed).
- Context: MINIMAL bootstrap — AGENTS/TOOLS/SOUL/IDENTITY/USER only (see
  workspace.MINIMAL_BOOTSTRAP_ALLOWLIST; matches cron/subagent sessions).
  MEMORY.md and HEARTBEAT.md are NOT in bootstrap — the agent reads
  HEARTBEAT.md via a tool call if the prompt tells it to.
- Tools: FULL set (read/write/edit/bash). The agent may decide to
  update files based on HEARTBEAT.md instructions, but nothing in the
  prompt forces a write.
- Prompt: DEFAULT_HEARTBEAT_PROMPT matches OpenClaw's HEARTBEAT_PROMPT
  byte-for-byte. A heartbeat on an empty HEARTBEAT.md should no-op
  ("HEARTBEAT_OK"), producing zero filesystem writes — that's the
  expected W4-profile signature for quiet periods.
- Trigger tagging: every heartbeat session is logged with
  trigger="heartbeat" in session-log meta, so trace analysis can
  distinguish heartbeat-originated file operations from user-originated
  ones.

Scheduling is done in `scheduler.py`. This module only needs to KNOW
how to fire *one* heartbeat when asked — the outer loop decides when.

We provide two driving options:
1. `run_one_heartbeat(...)` — synchronous, caller drives timing.
2. `HeartbeatLoop(...)` — background threading.Timer, fires
   asynchronously. Use for long-running experiments.
"""

from __future__ import annotations

import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..llm.openai_compat import ChatClient
from ..session.bootstrap import build_bootstrap_context
from ..session.log import SessionLogger
from ..session.runner import (
    SessionResult,
    SessionRunner,
    build_default_tool_registry,
)
from ..workspace import WorkspaceFileCache
from .scheduler import (
    DEFAULT_HEARTBEAT_INTERVAL_MS,
    compute_next_heartbeat_phase_due_ms,
    is_within_active_hours,
    resolve_heartbeat_phase_ms,
)


# Verbatim from real OpenClaw: src/auto-reply/heartbeat.ts:14-15 (HEARTBEAT_PROMPT).
# The prompt is intentionally terse — it tells the agent to READ HEARTBEAT.md via
# a tool call (not to auto-update it), and to reply HEARTBEAT_OK if there's
# nothing to do. Keeping this byte-identical matters because profile signatures
# are sensitive to whether heartbeats write anything by default.
DEFAULT_HEARTBEAT_PROMPT = (
    "Read HEARTBEAT.md if it exists (workspace context). "
    "Follow it strictly. Do not infer or repeat old tasks from prior chats. "
    "If nothing needs attention, reply HEARTBEAT_OK."
)


def is_heartbeat_content_effectively_empty(content: Optional[str]) -> bool:
    """Return True when HEARTBEAT.md has no actionable content.

    Port of OpenClaw's isHeartbeatContentEffectivelyEmpty: ignore whitespace,
    Markdown ATX headers, fence markers, and empty list stubs. Missing content
    is not considered empty because upstream lets the LLM decide when the file
    is absent.
    """
    if content is None:
        return False
    if not isinstance(content, str):
        return False
    for line in content.split("\n"):
        trimmed = line.strip()
        if not trimmed:
            continue
        if re.match(r"^#+(\s|$)", trimmed):
            continue
        if re.match(r"^[-*+]\s*(\[[\sXx]?\]\s*)?$", trimmed):
            continue
        if re.match(r"^```[A-Za-z0-9_-]*$", trimmed):
            continue
        return False
    return True


def _read_heartbeat_content_if_exists(workspace_root: str) -> Optional[str]:
    path = os.path.join(workspace_root, "HEARTBEAT.md")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


# ------------------------------------------------------ one-shot


def run_one_heartbeat(
    *,
    workspace_root: str,
    client: ChatClient,
    agent_id: str,
    scheduler_seed: str = "openclaw",
    prompt: str = DEFAULT_HEARTBEAT_PROMPT,
    context_window_tokens: int = 0,
    max_turns: int = 8,
    temperature: Optional[float] = None,
    max_tokens: Optional[int] = None,
    cache: Optional[WorkspaceFileCache] = None,
    extra_meta: Optional[dict[str, Any]] = None,
) -> SessionResult:
    """Fire a single heartbeat session synchronously.

    Args:
        workspace_root: absolute workspace root.
        client: OpenAI-compatible client.
        agent_id: agent identifier — stamped into session log meta.
        scheduler_seed: used by caller to track experiment identity; stamped
            into meta for trace analysis.
        prompt: the heartbeat user-message prompt. Defaults to
            DEFAULT_HEARTBEAT_PROMPT.
        context_window_tokens: forwarded to SessionRunner memory-flush
            gate. Usually 0 for heartbeats (they're short).
        max_turns: safety stop. Heartbeats are meant to be quick.
        temperature / max_tokens: forwarded to the LLM client.
        cache: optional WorkspaceFileCache for cross-heartbeat reuse.
        extra_meta: merged into session-log meta.

    Returns:
        SessionResult for the heartbeat session.
    """
    heartbeat_content = _read_heartbeat_content_if_exists(workspace_root)
    if is_heartbeat_content_effectively_empty(heartbeat_content):
        return SessionResult(
            messages=[],
            finish_reason="heartbeat_empty",
            stopped_reason="heartbeat_empty",
        )

    bootstrap = build_bootstrap_context(
        workspace_root, minimal=True, cache=cache
    )

    meta: dict[str, Any] = {
        "trigger": "heartbeat",
        "agent_id": agent_id,
        "scheduler_seed": scheduler_seed,
    }
    if extra_meta:
        meta.update(extra_meta)

    logger = SessionLogger.create(workspace_root, meta=meta)
    tools = build_default_tool_registry(workspace_root)

    runner = SessionRunner(
        client=client,
        bootstrap=bootstrap,
        tools=tools,
        logger=logger,
        context_window_tokens=context_window_tokens,
        max_turns=max_turns,
        temperature=temperature,
        max_tokens=max_tokens,
        # Heartbeat sessions intentionally do NOT execute memory-flush
        # sub-sessions — upstream OpenClaw gates flushes on
        # `!params.isHeartbeat` (see agent-runner-memory.ts:551). A
        # heartbeat trying to flush would recurse on stale bootstrap
        # state and produce spurious MEMORY.md writes. Keeping
        # workspace_root unset here preserves signal-only behavior:
        # the gate still logs `memory_flush_triggered` for analysis,
        # but no sub-session fires.
        workspace_root=None,
    )
    return runner.run(prompt)


# ------------------------------------------------------ background loop


@dataclass
class HeartbeatLoop:
    """Background threading.Timer-based heartbeat driver.

    NOT asyncio-based — our harness stays single-process and the LLM
    client is synchronous. One thread sleeps, fires, then reschedules.

    Usage:
        loop = HeartbeatLoop(
            workspace_root=root,
            client=client,
            agent_id="agent-a",
            scheduler_seed="exp-01",
        )
        loop.start()
        ... run experiment ...
        loop.stop()

    Attributes:
        workspace_root / client / agent_id / scheduler_seed: as in run_one_heartbeat
        interval_ms: heartbeat cadence. Default 30 minutes.
        active_hours_start / active_hours_end: optional gating (§8.1). None
            = always fire.
        tz_offset_minutes: local-time offset for active-hour evaluation.
        prompt: heartbeat prompt string.
        on_result: optional callback(SessionResult) invoked after each fire.
            Useful for tests or for accumulating traces.
        context_window_tokens / max_turns / temperature / max_tokens: forwarded.
        cache: optional WorkspaceFileCache shared across heartbeats.
    """

    workspace_root: str
    client: ChatClient
    agent_id: str
    scheduler_seed: str = "openclaw"
    interval_ms: int = DEFAULT_HEARTBEAT_INTERVAL_MS
    active_hours_start: Optional[int] = None
    active_hours_end: Optional[int] = None
    tz_offset_minutes: int = 0
    prompt: str = DEFAULT_HEARTBEAT_PROMPT
    on_result: Optional[Callable[[SessionResult], None]] = None
    context_window_tokens: int = 0
    max_turns: int = 8
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    cache: Optional[WorkspaceFileCache] = None

    # Internal state (don't set directly).
    _timer: Optional[threading.Timer] = field(default=None, init=False, repr=False)
    _stop_event: threading.Event = field(default_factory=threading.Event, init=False, repr=False)
    _fires_count: int = field(default=0, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    # ---- public API ----

    def next_fire_ms(self, *, now_ms: Optional[int] = None) -> int:
        """Compute the next scheduled fire time in epoch ms."""
        now = now_ms if now_ms is not None else int(time.time() * 1000)
        phase = resolve_heartbeat_phase_ms(
            scheduler_seed=self.scheduler_seed,
            agent_id=self.agent_id,
            interval_ms=self.interval_ms,
        )
        return compute_next_heartbeat_phase_due_ms(
            now_ms=now, interval_ms=self.interval_ms, phase_ms=phase
        )

    def start(self) -> None:
        """Begin the background loop. Idempotent — second call is no-op."""
        with self._lock:
            if self._timer is not None:
                return
            self._stop_event.clear()
            self._schedule_next_locked()

    def stop(self, *, join_timeout: Optional[float] = None) -> None:
        """Stop the loop. Cancels any pending timer.

        Args:
            join_timeout: optional seconds to wait for an in-flight heartbeat
                to finish. Defaults to None = don't join.
        """
        with self._lock:
            self._stop_event.set()
            t = self._timer
            self._timer = None
        if t is not None:
            t.cancel()
        # Note: a heartbeat currently IN its LLM call will not be
        # interrupted — the API call is synchronous and not cancelable.
        # Callers who need tight shutdown should set join_timeout.
        if join_timeout is not None:
            # We don't track the LLM worker thread directly; the caller
            # waits by sleeping up to join_timeout.
            self._stop_event.wait(join_timeout)

    @property
    def fires_count(self) -> int:
        return self._fires_count

    # ---- internals ----

    def _schedule_next_locked(self) -> None:
        """Arm a Timer for the next fire. Must be called under self._lock."""
        now_ms = int(time.time() * 1000)
        next_ms = self.next_fire_ms(now_ms=now_ms)
        delay_sec = max(0.0, (next_ms - now_ms) / 1000.0)
        t = threading.Timer(delay_sec, self._on_fire)
        t.daemon = True
        t.start()
        self._timer = t

    def _on_fire(self) -> None:
        """Timer callback: check gating, fire, reschedule."""
        if self._stop_event.is_set():
            return

        now_ms = int(time.time() * 1000)
        within_active = is_within_active_hours(
            now_ms=now_ms,
            start_hour=self.active_hours_start,
            end_hour=self.active_hours_end,
            tz_offset_minutes=self.tz_offset_minutes,
        )

        if within_active:
            try:
                result = run_one_heartbeat(
                    workspace_root=self.workspace_root,
                    client=self.client,
                    agent_id=self.agent_id,
                    scheduler_seed=self.scheduler_seed,
                    prompt=self.prompt,
                    context_window_tokens=self.context_window_tokens,
                    max_turns=self.max_turns,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                    cache=self.cache,
                )
                self._fires_count += 1
                if self.on_result is not None:
                    try:
                        self.on_result(result)
                    except Exception:  # noqa: BLE001 — never crash the loop on caller bugs
                        pass
            except Exception:  # noqa: BLE001 — heartbeat errors are logged; don't kill the loop
                # The session logger already stamped llm_error / exception
                # details where possible. Swallow here so a single bad
                # heartbeat doesn't stop future ones.
                pass

        # Reschedule regardless of whether we fired (active-hour gate
        # should still tick the clock; otherwise we'd stall forever).
        with self._lock:
            if self._stop_event.is_set() or self._timer is None:
                # stop() was called during fire.
                return
            self._schedule_next_locked()
