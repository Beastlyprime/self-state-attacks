"""Session runner — main LLM loop.

Composes every lower layer:
- Workspace bootstrap (workspace.py) → system prompt (session/bootstrap.py)
- Tool schemas + implementations (pi_tools/)
- OpenAI-compatible client (llm/openai_compat.py)
- jsonl session log (session/log.py)
- Memory-flush gate (session/memory_flush.py)

Control flow per turn:
1. Send transcript to the LLM with tool schemas.
2. If the response has tool_calls, execute them **sequentially** in the
   order returned (user decision 2026-04-22 — parallel execution would
   create trace race conditions that could confuse anomaly detection).
3. Append each tool result as a tool-role message.
4. Loop until finish_reason != "tool_calls" OR max_turns reached OR the LLM
   produces no tool_calls.
5. (Optional) Check memory-flush gate between turns.

Tool exec model:
- Tool dispatch is by name against a caller-supplied ToolRegistry.
- Each tool call is wrapped in a try/except so one bad call doesn't kill
  the session.
- Tool results are serialized to a string for the tool-role content field;
  the default serializer emits JSON with a few select fields (ok, error,
  content, exit_code, stdout, stderr, bytes_written, ...).

Out of scope for this layer:
- Parallel tool execution (explicitly rejected by user)
- Streaming (non-streaming client)
- Approval UI / policy gates (research harness, tools exposed by default)
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any, Callable, Optional

from ..llm.openai_compat import (
    ChatClient,
    ChatClientError,
    ChatMessage,
    ChatResponse,
    ToolCall,
)
from ..pi_tools import (
    bash_tool,
    edit_tool,
    get_default_tool_schemas,
    read_tool,
    write_tool,
)
from ..pi_tools.mutation_queue import FileMutationQueue, default_queue
from .bootstrap import BootstrapContext
from .compaction import (
    compact_messages,
    log_compaction_end,
    log_compaction_start,
    log_compaction_summary,
    should_preemptively_compact,
)
from .log import SessionLogger
from .memory_flush import (
    SILENT_REPLY_TOKEN,
    MemoryFlushDecision,
    build_memory_flush_prompt,
    build_memory_flush_relative_path,
    build_memory_flush_system_prompt,
    compute_context_hash,
    has_already_flushed_for_current_compaction,
    should_run_memory_flush,
)


DEFAULT_MAX_TURNS = 32


# Simple alias — tool callables take kwargs and return anything JSON-serializable.
ToolCallable = Callable[..., Any]


# ---------------------------------------------------- tool registry


def build_default_tool_registry(
    workspace_root: str,
    *,
    mutation_queue: Optional[FileMutationQueue] = None,
) -> dict[str, ToolCallable]:
    """Wire up the default four tools (read/write/edit/bash) against a workspace.

    Each returned callable accepts kwargs from the LLM's tool-call arguments
    and returns the tool's result dataclass. The runner converts to JSON for
    the tool-role message.
    """
    queue = mutation_queue or default_queue()

    def _read(**kwargs: Any) -> Any:
        path = kwargs.get("path")
        if not isinstance(path, str):
            return {"ok": False, "error": "validation: path must be a string"}
        offset = kwargs.get("offset")
        limit = kwargs.get("limit")
        return read_tool(
            path,
            workspace_root=workspace_root,
            offset=offset if isinstance(offset, int) else None,
            limit=limit if isinstance(limit, int) else None,
        )

    def _write(**kwargs: Any) -> Any:
        path = kwargs.get("path")
        content = kwargs.get("content")
        if not isinstance(path, str):
            return {"ok": False, "error": "validation: path must be a string"}
        if not isinstance(content, str):
            return {"ok": False, "error": "validation: content must be a string"}
        return write_tool(
            path, content, workspace_root=workspace_root, queue=queue
        )

    def _edit(**kwargs: Any) -> Any:
        path = kwargs.get("path")
        old_text = kwargs.get("old_text")
        new_text = kwargs.get("new_text")
        if not all(isinstance(v, str) for v in (path, old_text, new_text)):
            return {
                "ok": False,
                "error": "validation: path/old_text/new_text must all be strings",
            }
        assert isinstance(path, str) and isinstance(old_text, str) and isinstance(new_text, str)
        return edit_tool(
            path,
            old_text,
            new_text,
            workspace_root=workspace_root,
            queue=queue,
        )

    def _bash(**kwargs: Any) -> Any:
        command = kwargs.get("command")
        timeout = kwargs.get("timeout")
        if not isinstance(command, str):
            return {
                "ok": False,
                "error": "validation: command must be a string",
            }
        return bash_tool(
            command,
            workspace_root=workspace_root,
            timeout=timeout if isinstance(timeout, int) else None,
        )

    return {
        "read": _read,
        "write": _write,
        "edit": _edit,
        "bash": _bash,
    }


def _serialize_tool_result(result: Any) -> str:
    """Serialize a tool result to a compact JSON string for the LLM."""
    if is_dataclass(result):
        payload = asdict(result)
    elif isinstance(result, dict):
        payload = result
    else:
        payload = {"value": result}
    try:
        return json.dumps(payload, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return json.dumps({"ok": False, "error": "non-serializable tool result"})


def _subsession_replied_silently(sub_result: "SessionResult") -> bool:
    """Detect whether a memory-flush sub-session emitted SILENT_REPLY_TOKEN.

    Upstream convention: when the sub-session has nothing durable to
    persist, its final assistant message is the sentinel token (possibly
    with surrounding whitespace). We scan the sub-session's final
    assistant turn's content because intermediate tool-call turns may have
    empty content.
    """
    for msg in reversed(sub_result.messages):
        if msg.role != "assistant":
            continue
        content = msg.content
        if not isinstance(content, str):
            return False
        return SILENT_REPLY_TOKEN in content
    return False


# ------------------------------------------------------ runner


@dataclass
class ToolExecutionRecord:
    """One tool invocation inside a session turn.

    Attributes:
        tool_call_id: the LLM-provided id (echoed in the tool-role reply).
        name: tool name.
        raw_arguments: JSON string as returned by the LLM (before parsing).
        parsed_arguments: parsed dict, or None on JSON parse error.
        ok: True on successful invocation (tool's own `ok` flag when
            available; False on dispatch / parse error).
        elapsed_ms: wall-clock time spent in the tool.
        result_json: serialized result string as sent back to the LLM.
        error: short human-readable error string if ok=False.
    """

    tool_call_id: str
    name: str
    raw_arguments: str
    parsed_arguments: Optional[dict[str, Any]]
    ok: bool
    elapsed_ms: int
    result_json: str
    start_realtime_ns: int
    end_realtime_ns: int
    start_monotonic_ns: int
    end_monotonic_ns: int
    error: Optional[str] = None


@dataclass
class SessionResult:
    """Summary returned by SessionRunner.run().

    Attributes:
        messages: final transcript (including system, user, assistant, tool roles).
        tool_executions: flat list of every tool invocation across turns.
        turns_used: number of assistant turns (LLM responses) produced.
        total_prompt_tokens / total_completion_tokens: summed over all turns.
        finish_reason: finish_reason of the last assistant turn.
        memory_flush_triggered: True if the gate fired at least once.
        hit_max_turns: True if loop stopped at max_turns.
        session_key: logger's session key (for joining with log file).
        compaction_count: number of mid-session compactions performed.
        stopped_reason: why the loop exited. One of:
            - "stop": LLM produced a final (non-tool) response
            - "max_turns": safety stop hit max_turns
            - "max_tokens": budget guard hit max_total_tokens
            - "error": LLM client raised ChatClientError
            None if the loop has not yet terminated (should not occur in
            returned results, but kept Optional to match field default).
    """

    messages: list[ChatMessage]
    tool_executions: list[ToolExecutionRecord] = field(default_factory=list)
    turns_used: int = 0
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    finish_reason: Optional[str] = None
    memory_flush_triggered: bool = False
    hit_max_turns: bool = False
    session_key: Optional[str] = None
    compaction_count: int = 0
    # Number of memory-flush sub-sessions actually executed. Distinct from
    # `memory_flush_triggered` (which is a boolean fired-at-least-once flag)
    # and from `memory_flush_compaction_count` (the per-compaction-cycle
    # dedup counter that mirrors upstream's SessionEntry field).
    memory_flush_count: int = 0
    # Number of memory-flush sub-sessions that replied with SILENT_REPLY_TOKEN
    # (upstream convention for "nothing durable to persist"). Tracked
    # separately so analysis can tell "gate fired but sub-session decided
    # not to write" apart from "gate fired and sub-session wrote".
    memory_flush_silent_count: int = 0
    # Compaction count recorded at the last successful memory flush. Mirrors
    # upstream's SessionEntry.memoryFlushCompactionCount — used by the gate
    # to skip further flushes within the same compaction cycle.
    memory_flush_compaction_count: Optional[int] = None
    stopped_reason: Optional[str] = None


@dataclass
class SessionCarryState:
    """State the caller carries from one `SessionRunner.run()` to the next
    when they want multiple user turns to share ONE session.

    Upstream's equivalent state lives externally (transcript JSONL on disk +
    dedup counters on `SessionEntry`). We just pass it explicitly so the
    runner itself stays stateless — same outcome, no global/instance
    mutation.

    Build one via `SessionCarryState.from_result(prev_result)` after a
    previous `run(..., close_logger=False)` call.

    Fields:
        messages: full transcript so far (system + all prior turns). The
            next run() will append the new user message to this list.
        result: the accumulator SessionResult. Token counters, compaction
            count, memory-flush dedup fields all carry forward.
        last_flush_hash: context-hash of the last successful memory flush
            (used by `should_run_memory_flush` to skip no-op re-flushes
            when the transcript hasn't grown meaningfully).
    """

    messages: list[ChatMessage]
    result: SessionResult
    last_flush_hash: Optional[str] = None

    @classmethod
    def from_result(cls, result: SessionResult) -> "SessionCarryState":
        """Build a carry-state from a completed `run()` result.

        Pulls `last_flush_hash` off the private attribute the runner stashes
        there. Safe to call whether or not a memory flush actually fired.
        """
        last_flush_hash = getattr(result, "_last_flush_hash", None)
        return cls(
            messages=result.messages,
            result=result,
            last_flush_hash=last_flush_hash,
        )


@dataclass
class SessionRunner:
    """Drive an LLM loop against a bootstrapped workspace.

    Attributes:
        client: OpenAI-compatible LLM client.
        bootstrap: assembled bootstrap context (system prompt + entries).
        tools: name-to-callable registry. If None, built from workspace_root.
        tool_schemas: tool schemas for the LLM. Defaults to pi_tools default set.
        logger: optional SessionLogger. If None, session is not logged to disk.
        context_window_tokens: memory-flush gate input (0 disables the gate).
        max_turns: safety stop.
        temperature / max_tokens: passed to the LLM client.
    """

    client: ChatClient
    bootstrap: BootstrapContext
    tools: dict[str, ToolCallable]
    tool_schemas: list[dict[str, Any]] = field(
        default_factory=get_default_tool_schemas
    )
    logger: Optional[SessionLogger] = None
    context_window_tokens: int = 0
    max_turns: int = DEFAULT_MAX_TURNS
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    seed: Optional[int] = None
    # Compaction config — only applies when context_window_tokens > 0.
    compaction_reserve_tokens: int = 8_000
    compaction_enabled: bool = True
    # Runaway-loop budget protection — total prompt+completion tokens across
    # all turns. 0 disables the guard. Checked at the top of each turn.
    max_total_tokens: int = 0
    # Optional workspace root — required if you want the memory-flush gate to
    # actually execute a flush sub-session (SPEC §7). When None, a triggered
    # gate logs `memory_flush_triggered` but performs no flush (useful for
    # the tests that don't want subsession bootstrap IO). Callers in the
    # pipeline (pilot_runner, CLI, heartbeat) MUST pass this.
    workspace_root: Optional[str] = None
    # Memory-flush target (relative path inside workspace_root). If None
    # (default), the runner computes `memory/YYYY-MM-DD.md` at flush time
    # via `build_memory_flush_relative_path` — matches upstream
    # `buildMemoryFlushPlan` behavior. Tests that want a deterministic
    # target can set this explicitly.
    memory_flush_relative_path: Optional[str] = None
    # Memory-flush sub-session prompt. If None (default), the runner uses
    # upstream's DEFAULT_MEMORY_FLUSH_PROMPT with YYYY-MM-DD substituted
    # to the computed target's date stamp. Tests can override.
    memory_flush_prompt: Optional[str] = None
    # Memory-flush sub-session SYSTEM prompt (the second prompt in
    # upstream's flush-plan.ts). If None, the runner uses upstream's
    # DEFAULT_MEMORY_FLUSH_SYSTEM_PROMPT, routed through the same
    # `ensure_*` safety wrappers as the user prompt. Tests can override.
    memory_flush_system_prompt: Optional[str] = None
    # Hard turn cap for the memory-flush sub-session. Must stay small — the
    # sub-session is a summarization step, not a task loop. Upstream tops
    # out similarly low.
    memory_flush_max_turns: int = 6

    # ----- public API

    def run(
        self,
        user_message: str,
        *,
        carry: Optional["SessionCarryState"] = None,
        close_logger: bool = True,
    ) -> SessionResult:
        """Run the main loop for one user turn.

        Mirrors upstream's "each user turn rebuilds a request, state is
        persisted externally" model (see `runAgentTurnWithFallback` in
        `mnt/openclaw/src/auto-reply/reply/agent-runner.ts` — upstream
        hydrates transcript from `sessionFile` JSONL and reads dedup
        counters from `SessionEntry`). We stay stateless on the runner;
        callers pass `carry` to continue a prior turn in the same session.

        Args:
            user_message: the user turn text.
            carry: optional carry-state from a previous `run()` call against
                the same session. When provided:
                  - the bootstrap system prompt is NOT re-stamped (already
                    logged on the first turn);
                  - `carry.messages` is used as the transcript prefix and
                    extended with the new user message (same list instance
                    — compaction may rebind it and the returned result's
                    `.messages` will point at the new list);
                  - `carry.result` accumulates — token counters, compaction
                    count, memory-flush dedup fields all carry forward;
                  - `carry.last_flush_hash` feeds the memory-flush gate so
                    context-unchanged flushes are deduplicated across turns.
                When None, a fresh transcript + fresh SessionResult are
                built (normal single-turn mode).
            close_logger: if True (default), stamp session_end on the logger
                after the loop exits. Set False when you plan to continue
                this session with another `run(..., carry=...)` call —
                you must call `SessionLogger.close()` yourself when done.

        Returns a SessionResult whose `messages` is the full transcript
        (system + all user/assistant/tool turns so far) — suitable for
        building the next `SessionCarryState` via
        `SessionCarryState.from_result(result, last_flush_hash=...)`.
        """
        system_prompt = self.bootstrap.rendered_system_prompt

        if carry is None:
            # Fresh session: build [system, user].
            messages: list[ChatMessage] = []
            if system_prompt:
                messages.append(ChatMessage(role="system", content=system_prompt))
            messages.append(ChatMessage(role="user", content=user_message))

            if self.logger is not None:
                # Bootstrap is stamped once per session (not per turn).
                self.logger.log_event(
                    "bootstrap",
                    minimal=self.bootstrap.minimal,
                    files=self.bootstrap.present_filenames(),
                    system_prompt_chars=len(system_prompt),
                )
                self.logger.log_user(user_message)

            result = SessionResult(
                messages=messages,
                session_key=(
                    self.logger.session_key if self.logger else None
                ),
            )
            last_flush_hash: Optional[str] = None
        else:
            # Continuation: append user turn to prior transcript, preserve
            # the SessionResult accumulator and the flush-hash dedup.
            messages = carry.messages
            messages.append(ChatMessage(role="user", content=user_message))
            if self.logger is not None:
                self.logger.log_user(user_message)
            result = carry.result
            result.messages = messages
            # Reset per-turn terminal flags — they should reflect THIS
            # turn's exit condition, not the previous turn's.
            result.finish_reason = None
            result.hit_max_turns = False
            result.stopped_reason = None
            last_flush_hash = carry.last_flush_hash

        messages, last_flush_hash = self._drive_loop(
            messages=messages,
            result=result,
            last_flush_hash=last_flush_hash,
            system_prompt=system_prompt,
        )
        # `messages` may have been rebound by compaction — make sure the
        # returned result reflects the final transcript.
        result.messages = messages

        if close_logger and self.logger is not None:
            self.logger.close()

        # Stash the final flush-hash on the result so callers can recover
        # it without a separate return channel. Not a public field on
        # SessionResult (upstream keeps it on SessionEntry, not on the
        # per-turn result) — use a private attribute instead.
        result._last_flush_hash = last_flush_hash  # type: ignore[attr-defined]

        return result

    def _drive_loop(
        self,
        *,
        messages: list[ChatMessage],
        result: SessionResult,
        last_flush_hash: Optional[str],
        system_prompt: str,
    ) -> tuple[list[ChatMessage], Optional[str]]:
        """Drive the main LLM loop. Returns (final_messages, final_flush_hash).

        `messages` may be rebound mid-loop by compaction; the returned list
        is the one the caller should carry forward.
        """
        for turn in range(self.max_turns):
            # Runaway-loop budget guard — if total cumulative tokens have
            # exceeded the configured ceiling, stop the loop cleanly. This
            # is our last-ditch cost protection in case compaction + max_turns
            # both failed (e.g. an LLM stuck in a tight tool-call feedback
            # loop that doesn't grow the transcript fast enough to trip
            # compaction but still burns tokens per turn).
            if self.max_total_tokens > 0:
                cumulative = (
                    result.total_prompt_tokens + result.total_completion_tokens
                )
                if cumulative >= self.max_total_tokens:
                    if self.logger is not None:
                        self.logger.log_event(
                            "max_tokens_exceeded",
                            max_total_tokens=self.max_total_tokens,
                            cumulative_tokens=cumulative,
                            turn=turn,
                        )
                    result.stopped_reason = "max_tokens"
                    break

            # Preemptive compaction gate — runs before every LLM call when
            # context_window_tokens is configured. Matches OpenClaw's
            # `shouldPreemptivelyCompactBeforePrompt` behavior: if the
            # assembled next request would overflow the budget, summarize
            # older transcript in place and continue.
            #
            # We deliberately do NOT gate on `turn > 0`. Upstream's
            # attempt.ts:2072 runs the gate unconditionally before every
            # prompt submission. In chain/carry mode, `messages` on turn 0
            # of a continued task may already carry the prior tasks'
            # transcript and be far over budget — that is exactly when we
            # need to compact, before paying for an inflated request. On
            # a fresh session, `messages = [system, user]` is tiny and
            # `should_preemptively_compact` returns `route=fits`, so
            # running the gate at turn 0 is harmless in that case.
            if (
                self.compaction_enabled
                and self.context_window_tokens > 0
            ):
                # Our transcript is already fully assembled for this request:
                # fresh runs contain [system, user], carry runs append the new
                # user message before entering the loop, and tool loops append
                # assistant/tool replies in place. Upstream's helper receives
                # systemPrompt + prompt separately because those have not yet
                # been submitted to the active session; here passing them again
                # would double-count them and compact too early.
                decision = should_preemptively_compact(
                    messages=messages,
                    next_user_prompt="",
                    system_prompt=None,
                    context_window_tokens=self.context_window_tokens,
                    reserve_tokens=self.compaction_reserve_tokens,
                )
                if decision.should_compact:
                    log_compaction_start(
                        self.logger, decision=decision, messages_in=len(messages)
                    )
                    comp_result = compact_messages(
                        client=self.client,
                        messages=messages,
                        context_window_tokens=self.context_window_tokens,
                        route=decision.route,
                    )
                    if comp_result.messages_summarized > 0:
                        log_compaction_summary(self.logger, result=comp_result)
                        messages = list(comp_result.messages)
                        result.messages = messages
                        result.compaction_count += 1
                    log_compaction_end(self.logger, result=comp_result)
            try:
                response: ChatResponse = self.client.chat(
                    messages=messages,
                    tools=self.tool_schemas,
                    tool_choice="auto",
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                    extra_body={"seed": self.seed} if self.seed is not None else None,
                )
            except ChatClientError as exc:
                # Surface as a terminal turn. The transcript still includes
                # what we sent; the caller can retry with the same messages.
                if self.logger is not None:
                    self.logger.log_event(
                        "llm_error",
                        message=str(exc),
                        status=exc.status,
                    )
                result.finish_reason = "error"
                result.stopped_reason = "error"
                break

            result.turns_used += 1
            result.total_prompt_tokens += response.usage.prompt_tokens
            result.total_completion_tokens += response.usage.completion_tokens
            result.finish_reason = response.finish_reason

            # Assistant message (may carry both content AND tool_calls).
            assistant_msg = response.message
            messages.append(assistant_msg)

            if self.logger is not None:
                self.logger.log_assistant(
                    content=assistant_msg.content,
                    tool_calls=(
                        [
                            {
                                "id": tc.id,
                                "type": tc.type,
                                "function": {
                                    "name": tc.function.name,
                                    "arguments": tc.function.arguments,
                                },
                            }
                            for tc in (assistant_msg.tool_calls or [])
                        ]
                        if assistant_msg.tool_calls
                        else None
                    ),
                    finish_reason=response.finish_reason,
                    usage={
                        "prompt_tokens": response.usage.prompt_tokens,
                        "completion_tokens": response.usage.completion_tokens,
                        "total_tokens": response.usage.total_tokens,
                    },
                )

            # If no tool calls, we're done for this turn.
            if not assistant_msg.tool_calls:
                result.stopped_reason = "stop"
                break

            # Execute tool calls sequentially.
            for tc in assistant_msg.tool_calls:
                exec_record = self._execute_tool_call(tc)
                result.tool_executions.append(exec_record)
                # Append tool role regardless of success — the LLM expects
                # EVERY tool_call_id to get a reply; otherwise subsequent
                # chat() calls will fail validation.
                messages.append(
                    ChatMessage(
                        role="tool",
                        content=exec_record.result_json,
                        tool_call_id=tc.id,
                        name=tc.function.name,
                    )
                )
                if self.logger is not None:
                    self.logger.log_tool_result(
                        tool_call_id=tc.id,
                        name=tc.function.name,
                        content=exec_record.result_json,
                        ok=exec_record.ok,
                        error=exec_record.error,
                    )

            # Memory-flush gate (between turns).
            if self.context_window_tokens > 0:
                # Per-compaction dedup (upstream
                # `hasAlreadyFlushedForCurrentCompaction`): at most one
                # flush per compaction cycle. We check this BEFORE the
                # token gate so the cheap path short-circuits.
                already_flushed = has_already_flushed_for_current_compaction(
                    compaction_count=result.compaction_count,
                    memory_flush_compaction_count=(
                        result.memory_flush_compaction_count
                    ),
                )
                if not already_flushed:
                    # Upstream gates on fresh-session/projected context
                    # usage, not just the latest API response. Our closest
                    # harness equivalent is the cumulative usage after this
                    # turn, especially in carry/chain sessions.
                    current_tokens = (
                        result.total_prompt_tokens
                        + result.total_completion_tokens
                    )
                    decision = should_run_memory_flush(
                        total_tokens=current_tokens,
                        context_window_tokens=self.context_window_tokens,
                        messages=[
                            m for m in messages if m.role != "system"
                        ],
                        last_flushed_hash=last_flush_hash,
                    )
                    if decision.should_flush:
                        result.memory_flush_triggered = True
                        last_flush_hash = decision.context_hash
                        if self.logger is not None:
                            self.logger.log_event(
                                "memory_flush_triggered",
                                current_tokens=decision.current_tokens,
                                threshold_tokens=decision.threshold_tokens,
                                context_hash=decision.context_hash,
                            )
                        # Actually execute the memory-flush sub-session
                        # (SPEC §7). Requires workspace_root; when unset,
                        # we fall back to signal-only behavior.
                        if self.workspace_root is not None:
                            try:
                                self._run_memory_flush_subsession(
                                    parent_messages=messages,
                                    result=result,
                                )
                            except Exception as exc:  # noqa: BLE001
                                # Never let a sub-session failure kill the
                                # main loop — log and continue.
                                if self.logger is not None:
                                    self.logger.log_event(
                                        "memory_flush_error",
                                        error=f"{type(exc).__name__}: {exc}",
                                    )

        else:
            # Loop hit max_turns without breaking.
            result.hit_max_turns = True
            result.stopped_reason = "max_turns"
            if self.logger is not None:
                self.logger.log_event(
                    "max_turns_reached",
                    max_turns=self.max_turns,
                )

        return messages, last_flush_hash

    # ----- memory-flush sub-session (SPEC §7)

    def _run_memory_flush_subsession(
        self,
        *,
        parent_messages: list[ChatMessage],
        result: SessionResult,
    ) -> None:
        """Execute a memory-flush sub-session.

        A faithful minimal port of upstream `runMemoryFlushIfNeeded`
        (`mnt/openclaw/src/auto-reply/reply/agent-runner-memory.ts`) plus
        `buildMemoryFlushPlan` (`extensions/memory-core/src/flush-plan.ts`):

        - Build a separate SessionRunner with:
            * minimal bootstrap (MINIMAL_BOOTSTRAP_ALLOWLIST, SPEC §2)
            * tool registry restricted to read + write via
              `wrap_tool_memory_flush_append_only` (SPEC §6.4) — the write
              tool only accepts the computed dated path and coerces
              to append semantics.
            * a dedicated SessionLogger with trigger="memory" (so the
              session log's opening `session_start` record plus the
              child's `bootstrap` event carry the flush trigger — this is
              the signal the paper's §7 detector picks up to distinguish
              memory-flush writes from arbitrary LLM writes).
            * low max_turns — summarization, not a task loop.
            * NO compaction / NO memory-flush recursion in the sub-session.
        - Target file: `memory/YYYY-MM-DD.md` (upstream canonical). We do
          NOT write back into bootstrap/reference files (MEMORY.md,
          DREAMS.md, SOUL.md, TOOLS.md, AGENTS.md) — those are read-only.
        - Prompt: upstream DEFAULT_MEMORY_FLUSH_PROMPT with YYYY-MM-DD
          substituted, including SILENT_REPLY_TOKEN so the sub-session
          knows it can reply "nothing to store" cleanly.
        - Do NOT mutate the parent session's transcript. Upstream semantics:
          the flush executes out-of-band; the parent continues from where
          it was (the NEXT preemptive compaction still consumes the tail
          of the transcript; this is intentional — it lets the main task
          proceed with fresh context after the next compaction).
        - On completion, record the current compaction count on `result`
          so the gate skips further flushes in this cycle (upstream
          `hasAlreadyFlushedForCurrentCompaction`).

        This method never raises to the main loop — the caller wraps it in
        try/except.
        """
        assert self.workspace_root is not None  # caller guarded

        # 0. Resolve the dated target and prompt. Caller may have overridden
        #    either or both (tests use this to pin deterministic values);
        #    otherwise compute from upstream defaults at flush time so
        #    sessions that cross midnight correctly bucket into the new
        #    date's file.
        #
        #    If the caller supplied a custom `memory_flush_prompt`, we
        #    still route it through `build_memory_flush_prompt` via
        #    `base_prompt=` so the upstream `ensure_*` safety wrappers
        #    (hint bolt-on + silent-reply sentinel) apply. This matches
        #    upstream's `buildMemoryFlushPlan` where the user-supplied
        #    prompt is always passed through `ensureMemoryFlushSafetyHints`
        #    and `ensureNoReplyHint` before use.
        flush_relative_path = (
            self.memory_flush_relative_path
            or build_memory_flush_relative_path()
        )
        flush_prompt = build_memory_flush_prompt(
            flush_relative_path,
            base_prompt=self.memory_flush_prompt,
        )
        flush_system_prompt = build_memory_flush_system_prompt(
            flush_relative_path,
            base_system_prompt=self.memory_flush_system_prompt,
        )

        # 1. Minimal bootstrap for the sub-session (matches upstream's
        #    embedded-agent invocation which disables most bootstrap files
        #    for trigger="memory" sessions). Append the flush system prompt
        #    as an extra section on top of the MINIMAL_BOOTSTRAP_ALLOWLIST
        #    content — upstream attaches it as its own system-role message;
        #    injecting it as a fenced section preserves the single-system-
        #    message contract of our ChatMessage API while keeping the
        #    prompt bytes deterministic (prompt-cache-safe).
        from .bootstrap import (  # local — avoid cycle
            BootstrapContext,
            build_bootstrap_context,
        )
        from ..pi_tools import (
            MemoryFlushContext,
            wrap_tool_memory_flush_append_only,
        )

        _base_flush_bootstrap = build_bootstrap_context(
            self.workspace_root,
            minimal=True,
        )
        _bootstrap_body = _base_flush_bootstrap.rendered_system_prompt
        _system_section = f"## MEMORY_FLUSH_SYSTEM_PROMPT\n\n{flush_system_prompt}"
        _merged_system_prompt = (
            f"{_bootstrap_body}\n\n---\n\n{_system_section}"
            if _bootstrap_body
            else _system_section
        )
        flush_bootstrap = BootstrapContext(
            entries=_base_flush_bootstrap.entries,
            minimal=_base_flush_bootstrap.minimal,
            rendered_system_prompt=_merged_system_prompt,
        )

        # 2. Wrapped tool registry. We rebuild the registry from the *raw*
        #    pi-tools rather than reusing self.tools, because self.tools
        #    may already be wrapped/shimmed by the parent caller in a way
        #    that's incompatible with append-only semantics. Going to the
        #    raw functions keeps the sub-session's behavior faithful to
        #    the spec regardless of how the parent built its registry.
        ctx = MemoryFlushContext(
            root=self.workspace_root,
            relative_path=flush_relative_path,
        )
        wrapped_read = wrap_tool_memory_flush_append_only(
            "read",
            lambda **kwargs: read_tool(
                path=kwargs["path"],
                workspace_root=self.workspace_root,  # type: ignore[arg-type]
                offset=kwargs.get("offset"),
                limit=kwargs.get("limit"),
            ),
            ctx,
        )
        wrapped_write = wrap_tool_memory_flush_append_only(
            "write", write_tool, ctx
        )
        assert wrapped_read is not None and wrapped_write is not None

        flush_tools: dict[str, ToolCallable] = {
            "read": wrapped_read,
            "write": wrapped_write,
        }
        # Only expose the schemas for the allowed tools — passing the full
        # default set would let the LLM attempt bash/edit and get back
        # structured errors, wasting tokens.
        from ..pi_tools.schema import READ_TOOL_SCHEMA, WRITE_TOOL_SCHEMA
        flush_schemas = [READ_TOOL_SCHEMA, WRITE_TOOL_SCHEMA]

        # 3. Dedicated logger — same OpenClaw state root as the parent's,
        #    but a distinct session_key with trigger="memory" in meta so
        #    analyzers can tell flush sessions apart.
        flush_logger: Optional[SessionLogger] = None
        if self.logger is not None:
            flush_logger = SessionLogger.create(
                self.workspace_root,
                state_root=self.logger.state_root,
                meta={
                    "trigger": "memory",
                    "parent_session_key": self.logger.session_key,
                    "target_path": flush_relative_path,
                },
            )

        # 4. Sub-runner. Explicit: no compaction, no nested memory-flush,
        #    small max_turns, no workspace_root plumbed to the sub-runner
        #    (prevents accidental recursion).
        sub_runner = SessionRunner(
            client=self.client,
            bootstrap=flush_bootstrap,
            tools=flush_tools,
            tool_schemas=flush_schemas,
            logger=flush_logger,
            context_window_tokens=0,       # disables nested memory-flush
            compaction_enabled=False,      # disables nested compaction
            max_turns=self.memory_flush_max_turns,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            workspace_root=None,           # explicit: no recursion
        )

        # 5. Log a parent-side event pointing at the sub-session for
        #    cross-referencing in analysis.
        if self.logger is not None and flush_logger is not None:
            self.logger.log_event(
                "memory_flush_subsession_started",
                subsession_key=flush_logger.session_key,
                target_path=flush_relative_path,
            )

        # 6. Fire the sub-session. Any error propagates to the caller,
        #    which wraps in try/except and logs `memory_flush_error`.
        sub_result = sub_runner.run(flush_prompt)

        # 7. Detect SILENT_REPLY_TOKEN — upstream convention for "nothing
        #    durable to persist" is that the sub-session's final assistant
        #    message starts with / contains SILENT_REPLY_TOKEN. We do NOT
        #    treat this as an error; we just count it so analysis can
        #    tell "gate fired but nothing was written" apart from
        #    "gate fired and new content was appended".
        silent = _subsession_replied_silently(sub_result)

        # 8. Record successful completion. Per-compaction dedup uses the
        #    compaction count at the moment the flush completes — matches
        #    upstream's `incrementCompactionCount` + persist sequence in
        #    runMemoryFlushIfNeeded (it stamps memoryFlushCompactionCount
        #    = compactionCount AFTER the flush).
        result.memory_flush_count += 1
        if silent:
            result.memory_flush_silent_count += 1
        result.memory_flush_compaction_count = result.compaction_count

        # 9. Log completion.
        if self.logger is not None:
            self.logger.log_event(
                "memory_flush_subsession_completed",
                subsession_key=(
                    flush_logger.session_key if flush_logger else None
                ),
                target_path=flush_relative_path,
                sub_turns_used=sub_result.turns_used,
                sub_stopped_reason=sub_result.stopped_reason,
                sub_hit_max_turns=sub_result.hit_max_turns,
                silent_reply=silent,
            )

    # ----- tool dispatch

    def _execute_tool_call(self, tc: ToolCall) -> ToolExecutionRecord:
        start_realtime_ns = time.time_ns()
        start_monotonic_ns = time.monotonic_ns()

        def timing() -> tuple[int, int, int]:
            end_monotonic_ns = time.monotonic_ns()
            return (
                time.time_ns(),
                end_monotonic_ns,
                int((end_monotonic_ns - start_monotonic_ns) / 1_000_000),
            )

        # Parse arguments (OpenAI ships them as a JSON string).
        parsed: Optional[dict[str, Any]]
        parse_error: Optional[str] = None
        try:
            raw = tc.function.arguments or "{}"
            parsed_obj = json.loads(raw)
            if not isinstance(parsed_obj, dict):
                parsed = None
                parse_error = "validation: tool arguments must be a JSON object"
            else:
                parsed = parsed_obj
        except json.JSONDecodeError as exc:
            parsed = None
            parse_error = f"validation: arguments JSON parse failed: {exc}"

        if parse_error is not None:
            end_realtime_ns, end_monotonic_ns, elapsed_ms = timing()
            return ToolExecutionRecord(
                tool_call_id=tc.id,
                name=tc.function.name,
                raw_arguments=tc.function.arguments,
                parsed_arguments=parsed,
                ok=False,
                elapsed_ms=elapsed_ms,
                result_json=json.dumps({"ok": False, "error": parse_error}),
                start_realtime_ns=start_realtime_ns,
                end_realtime_ns=end_realtime_ns,
                start_monotonic_ns=start_monotonic_ns,
                end_monotonic_ns=end_monotonic_ns,
                error=parse_error,
            )

        # Dispatch.
        handler = self.tools.get(tc.function.name)
        if handler is None:
            end_realtime_ns, end_monotonic_ns, elapsed_ms = timing()
            err = f"validation: unknown tool '{tc.function.name}'"
            return ToolExecutionRecord(
                tool_call_id=tc.id,
                name=tc.function.name,
                raw_arguments=tc.function.arguments,
                parsed_arguments=parsed,
                ok=False,
                elapsed_ms=elapsed_ms,
                result_json=json.dumps({"ok": False, "error": err}),
                start_realtime_ns=start_realtime_ns,
                end_realtime_ns=end_realtime_ns,
                start_monotonic_ns=start_monotonic_ns,
                end_monotonic_ns=end_monotonic_ns,
                error=err,
            )

        assert parsed is not None  # narrowed above
        try:
            result = handler(**parsed)
        except Exception as exc:  # noqa: BLE001 — intentional: one bad tool MUST NOT kill the loop
            end_realtime_ns, end_monotonic_ns, elapsed_ms = timing()
            err = f"io: tool raised: {type(exc).__name__}: {exc}"
            return ToolExecutionRecord(
                tool_call_id=tc.id,
                name=tc.function.name,
                raw_arguments=tc.function.arguments,
                parsed_arguments=parsed,
                ok=False,
                elapsed_ms=elapsed_ms,
                result_json=json.dumps({"ok": False, "error": err}),
                start_realtime_ns=start_realtime_ns,
                end_realtime_ns=end_realtime_ns,
                start_monotonic_ns=start_monotonic_ns,
                end_monotonic_ns=end_monotonic_ns,
                error=err,
            )

        end_realtime_ns, end_monotonic_ns, elapsed_ms = timing()
        result_json = _serialize_tool_result(result)

        # Extract ok/error from dataclass-style results if present.
        tool_ok = True
        tool_error: Optional[str] = None
        if is_dataclass(result):
            d = asdict(result)
            tool_ok = bool(d.get("ok", True))
            err_v = d.get("error")
            if isinstance(err_v, str):
                tool_error = err_v
        elif isinstance(result, dict):
            tool_ok = bool(result.get("ok", True))
            err_v = result.get("error")
            if isinstance(err_v, str):
                tool_error = err_v

        return ToolExecutionRecord(
            tool_call_id=tc.id,
            name=tc.function.name,
            raw_arguments=tc.function.arguments,
            parsed_arguments=parsed,
            ok=tool_ok,
            elapsed_ms=elapsed_ms,
            result_json=result_json,
            start_realtime_ns=start_realtime_ns,
            end_realtime_ns=end_realtime_ns,
            start_monotonic_ns=start_monotonic_ns,
            end_monotonic_ns=end_monotonic_ns,
            error=tool_error,
        )
