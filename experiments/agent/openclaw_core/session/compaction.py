"""Mid-session compaction — faithful port of OpenClaw `src/agents/compaction.ts`.

Triggered between turns when the assembled next prompt would exceed the
model's context budget. Unlike memory-flush (which is a separate
MINIMAL-bootstrap sub-session that appends to MEMORY.md), compaction
summarizes older transcript content *in place* so the session can
continue without hitting a hard overflow.

Design decisions (captured 2026-04-22 with user):
- Token estimate: chars/4 heuristic (no tiktoken dep).
- Routes implemented: `fits`, `compact_only`, `compact_then_truncate`.
  We do NOT implement `truncate_tool_results_only` — the harness's
  tool-result payloads are small, so that route is not load-bearing for
  the profile signatures we care about.
- `IDENTIFIER_PRESERVATION_INSTRUCTIONS` is always appended to the
  summarization prompt (policy="strict" in upstream terms).
- Compaction produces a `compactionSummary` transcript marker, not a user
  turn. In OpenClaw's precheck path, the current prompt is submitted only
  after the out-of-band compaction finishes, so the current user prompt is
  not summarized as prior history. This harness mirrors that by keeping a
  trailing user message verbatim and summarizing the history before it.
- Events (compaction_start / compaction / compaction_end / compaction_error) are
  written to the session JSONL, NOT to the inotify trace JSONL. Trace
  events come from real file activity; compaction is a metadata event.
- 3-level fallback matches OpenClaw:
  1. Full chunked summarization.
  2. Drop oversized messages (>50% context) and summarize the remainder,
     appending "[Large … omitted]" markers.
  3. If both fail, emit a literal placeholder and continue.

Constants below are byte-pinned to real OpenClaw so drift breaks loudly.
Source: openclaw/src/agents/compaction.ts.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..llm.openai_compat import ChatClient, ChatClientError, ChatMessage


# --------- constants (byte-pinned to src/agents/compaction.ts) ---------

# compaction.ts:19
BASE_CHUNK_RATIO = 0.4
# compaction.ts:20
MIN_CHUNK_RATIO = 0.15
# compaction.ts:21 — SAFETY_MARGIN is applied to the chars/4 estimate
# because estimateTokens() undercounts (multi-byte, code tokens, etc).
SAFETY_MARGIN = 1.2
# compaction.ts:22
DEFAULT_SUMMARY_FALLBACK = "No prior history."
# compaction.ts:214 — reserved for summarization prompt + system prompt +
# previous summary + serialization wrappers.
SUMMARIZATION_OVERHEAD_TOKENS = 4096

# preemptive-compaction.ts:14
ESTIMATED_CHARS_PER_TOKEN = 4

# Upstream's compaction safeguard preserves recent turns inside the summary.
# This harness keeps the constant for instruction parity/tests, but does not
# carry a raw recent-tail transcript across precheck compaction.
PRESERVE_N_RECENT = 3

# compaction.ts:24-37 — verbatim.
MERGE_SUMMARIES_INSTRUCTIONS = "\n".join(
    [
        "Merge these partial summaries into a single cohesive summary.",
        "",
        "MUST PRESERVE:",
        "- Active tasks and their current status (in-progress, blocked, pending)",
        "- Batch operation progress (e.g., '5/17 items completed')",
        "- The last thing the user requested and what was being done about it",
        "- Decisions made and their rationale",
        "- TODOs, open questions, and constraints",
        "- Any commitments or follow-ups promised",
        "",
        "PRIORITIZE recent context over older history. The agent needs to know",
        "what it was doing, not just what was discussed.",
    ]
)

# compaction.ts:38-40 — verbatim.
IDENTIFIER_PRESERVATION_INSTRUCTIONS = (
    "Preserve all opaque identifiers exactly as written (no shortening or "
    "reconstruction), including UUIDs, hashes, IDs, hostnames, IPs, ports, "
    "URLs, and file names."
)

# Summarization user-message template. Real OpenClaw builds this from
# pi-coding-agent's `generateSummary` which wraps chunks in
# <conversation>...</conversation> tags plus instructions. We mirror the
# same wrapper format so the LLM sees a familiar shape.
SUMMARIZE_CHUNK_TEMPLATE = (
    "{instructions}\n\n"
    "Summarize the following conversation chunk. Be concise but complete — "
    "the agent will rely on this summary to continue working.\n\n"
    "{previous_summary_block}"
    "<conversation>\n{chunk_text}\n</conversation>"
)

PREVIOUS_SUMMARY_BLOCK_TEMPLATE = (
    "Previous summary of earlier history:\n{summary}\n\n"
)


# ----------------------------- token estimates ---------------------------


def estimate_tokens_for_text(text: str) -> int:
    """Chars/4 heuristic. Matches `ESTIMATED_CHARS_PER_TOKEN = 4` upstream."""
    if not text:
        return 0
    return max(1, len(text) // ESTIMATED_CHARS_PER_TOKEN)


def estimate_tokens_for_message(msg: ChatMessage) -> int:
    """Approximate token count for one message.

    Includes a small per-message overhead (role + serialization) so short
    messages aren't undercounted.
    """
    n = 4  # role + wrapper overhead
    if msg.content:
        n += estimate_tokens_for_text(msg.content)
    if msg.tool_calls:
        for tc in msg.tool_calls:
            # `tc` is a ToolCall dataclass with nested `function`.
            name = getattr(getattr(tc, "function", None), "name", "") or ""
            args = getattr(getattr(tc, "function", None), "arguments", "") or ""
            n += estimate_tokens_for_text(name) + estimate_tokens_for_text(args)
    return n


def estimate_messages_tokens(messages: list[ChatMessage]) -> int:
    return sum(estimate_tokens_for_message(m) for m in messages)


# ----------------------------- route decision ----------------------------


# Routes we support. `truncate_tool_results_only` from upstream is
# intentionally omitted (see module docstring).
ROUTE_FITS = "fits"
ROUTE_COMPACT_ONLY = "compact_only"
ROUTE_COMPACT_THEN_TRUNCATE = "compact_then_truncate"


@dataclass
class PreemptiveDecision:
    """Outcome of `should_preemptively_compact`.

    Attributes:
        route: one of `fits` / `compact_only` / `compact_then_truncate`.
        should_compact: convenience flag — True unless route == "fits".
        estimated_prompt_tokens: what the next request would cost.
        prompt_budget: context_window - reserve.
        overflow_tokens: estimated_prompt_tokens - prompt_budget, floored at 0.
        reserve_tokens: reserve actually applied.
    """

    route: str
    should_compact: bool
    estimated_prompt_tokens: int
    prompt_budget: int
    overflow_tokens: int
    reserve_tokens: int


def should_preemptively_compact(
    *,
    messages: list[ChatMessage],
    next_user_prompt: str,
    system_prompt: Optional[str],
    context_window_tokens: int,
    reserve_tokens: int,
) -> PreemptiveDecision:
    """Decide whether to compact before sending the next LLM request.

    Port of `shouldPreemptivelyCompactBeforePrompt` in
    `src/agents/pi-embedded-runner/run/preemptive-compaction.ts`.

    Args:
        messages: current transcript.
        next_user_prompt: the prompt we're about to send.
        system_prompt: current system prompt (usually the bootstrap).
        context_window_tokens: the model's hard context window.
        reserve_tokens: tokens to leave for the next completion.

    Returns:
        A PreemptiveDecision with the chosen route.
    """
    if context_window_tokens <= 0:
        return PreemptiveDecision(
            route=ROUTE_FITS,
            should_compact=False,
            estimated_prompt_tokens=0,
            prompt_budget=0,
            overflow_tokens=0,
            reserve_tokens=max(0, reserve_tokens),
        )

    synthetic: list[ChatMessage] = []
    if system_prompt and system_prompt.strip():
        synthetic.append(ChatMessage(role="system", content=system_prompt))
    if next_user_prompt:
        synthetic.append(ChatMessage(role="user", content=next_user_prompt))

    est_raw = estimate_messages_tokens(messages) + estimate_messages_tokens(synthetic)
    est = max(0, int(est_raw * SAFETY_MARGIN))

    reserve = max(0, min(reserve_tokens, context_window_tokens - 1))
    prompt_budget = max(1, context_window_tokens - reserve)
    overflow = max(0, est - prompt_budget)

    if overflow == 0:
        route = ROUTE_FITS
    else:
        # We don't implement `truncate_tool_results_only`, so any overflow
        # takes the compact path. `compact_then_truncate` is selected when
        # overflow is severe enough that a subsequent tail-truncation pass
        # is likely still needed — we use a 1.5x heuristic matching the
        # upstream `truncateOnlyThresholdChars` ratio.
        if overflow * 1.5 > prompt_budget * 0.5:
            route = ROUTE_COMPACT_THEN_TRUNCATE
        else:
            route = ROUTE_COMPACT_ONLY

    return PreemptiveDecision(
        route=route,
        should_compact=route != ROUTE_FITS,
        estimated_prompt_tokens=est,
        prompt_budget=prompt_budget,
        overflow_tokens=overflow,
        reserve_tokens=reserve,
    )


# ----------------------------- chunking ----------------------------------


def compute_adaptive_chunk_ratio(
    messages: list[ChatMessage], context_window: int
) -> float:
    """Port of `computeAdaptiveChunkRatio` (compaction.ts:262-281).

    If the average message is > 10% of context, reduce chunk ratio toward
    MIN_CHUNK_RATIO so we don't overflow the summarization call itself.
    """
    if not messages:
        return BASE_CHUNK_RATIO
    total = estimate_messages_tokens(messages)
    avg = total / max(1, len(messages))
    safe_avg = avg * SAFETY_MARGIN
    avg_ratio = safe_avg / max(1, context_window)
    if avg_ratio > 0.1:
        reduction = min(avg_ratio * 2, BASE_CHUNK_RATIO - MIN_CHUNK_RATIO)
        return max(MIN_CHUNK_RATIO, BASE_CHUNK_RATIO - reduction)
    return BASE_CHUNK_RATIO


def is_oversized_for_summary(msg: ChatMessage, context_window: int) -> bool:
    """Port of `isOversizedForSummary` (compaction.ts:287-290).

    A single message bigger than 50% of the context window can't be
    summarized safely in one shot.
    """
    tokens = estimate_tokens_for_message(msg) * SAFETY_MARGIN
    return tokens > context_window * 0.5


def chunk_messages_by_max_tokens(
    messages: list[ChatMessage], max_tokens: int
) -> list[list[ChatMessage]]:
    """Port of `chunkMessagesByMaxTokens` (compaction.ts:216-256).

    Splits `messages` into contiguous chunks, each under `max_tokens`
    (after SAFETY_MARGIN). Messages larger than a chunk become their own
    chunk — they will be filtered out by the oversize check in the
    fallback path.
    """
    if not messages:
        return []
    effective_max = max(1, int(max_tokens / SAFETY_MARGIN))
    chunks: list[list[ChatMessage]] = []
    current: list[ChatMessage] = []
    current_tokens = 0
    for m in messages:
        mt = estimate_tokens_for_message(m)
        if current and current_tokens + mt > effective_max:
            chunks.append(current)
            current = []
            current_tokens = 0
        current.append(m)
        current_tokens += mt
        if mt > effective_max:
            # oversized single message — close out the chunk.
            chunks.append(current)
            current = []
            current_tokens = 0
    if current:
        chunks.append(current)
    return chunks


# ----------------------------- summarization -----------------------------


def _format_message_for_summary(m: ChatMessage) -> str:
    """Render a message into the text we pass into the summarization prompt.

    tool_results are kept — they contain information the agent relied on —
    but we trim very long content (mirrors OpenClaw's
    `stripToolResultDetails` behavior: the `details` field is never fed
    into summaries).
    """
    if m.role == "tool":
        # Keep tool name + compacted content.
        content = m.content or ""
        if len(content) > 4000:
            content = content[:4000] + f"... [truncated {len(content) - 4000} chars]"
        return f"[tool:{m.name or '?'}]\n{content}"
    if m.role == "assistant" and m.tool_calls:
        parts = [m.content or ""]
        for tc in m.tool_calls:
            fname = getattr(getattr(tc, "function", None), "name", "?")
            fargs = getattr(getattr(tc, "function", None), "arguments", "")
            parts.append(f"<tool_call name={fname}>{fargs}</tool_call>")
        return f"[assistant]\n" + "\n".join(p for p in parts if p)
    return f"[{m.role}]\n{m.content or ''}"


def build_summarization_instructions(
    *, custom_instructions: Optional[str] = None
) -> str:
    """Build the instructions block sent into the summary prompt.

    IDENTIFIER_PRESERVATION is always on (user decision). `custom_instructions`
    append in the "Additional focus:" section like upstream.
    """
    base = IDENTIFIER_PRESERVATION_INSTRUCTIONS
    custom = (custom_instructions or "").strip()
    if not custom:
        return base
    return f"{base}\n\nAdditional focus:\n{custom}"


def summarize_chunk(
    *,
    client: ChatClient,
    chunk: list[ChatMessage],
    instructions: str,
    previous_summary: Optional[str],
    temperature: Optional[float] = None,
    max_tokens: Optional[int] = None,
) -> str:
    """Call the LLM to produce a summary of one chunk.

    Returns the summary string. Raises `ChatClientError` on failure (the
    caller drives the fallback ladder).
    """
    chunk_text = "\n\n".join(_format_message_for_summary(m) for m in chunk)
    prev_block = ""
    if previous_summary:
        prev_block = PREVIOUS_SUMMARY_BLOCK_TEMPLATE.format(summary=previous_summary)
    user_text = SUMMARIZE_CHUNK_TEMPLATE.format(
        instructions=instructions,
        previous_summary_block=prev_block,
        chunk_text=chunk_text,
    )
    request_messages = [
        ChatMessage(
            role="system",
            content=(
                "You are a compaction summarizer. Produce a concise faithful "
                "summary of the provided conversation chunk."
            ),
        ),
        ChatMessage(role="user", content=user_text),
    ]
    resp = client.chat(
        messages=request_messages,
        tools=None,
        tool_choice=None,
        temperature=temperature,
        max_tokens=max_tokens,
    )
    return resp.message.content or ""


def summarize_with_fallback(
    *,
    client: ChatClient,
    messages: list[ChatMessage],
    context_window_tokens: int,
    reserve_tokens: int = SUMMARIZATION_OVERHEAD_TOKENS,
    custom_instructions: Optional[str] = None,
    previous_summary: Optional[str] = None,
    on_warn: Optional[Callable[[str], None]] = None,
    temperature: Optional[float] = None,
    max_tokens: Optional[int] = None,
) -> str:
    """3-level fallback summarization.

    1. Full chunked summarization.
    2. If (1) raises, drop oversized messages, summarize the rest, and
       append "[Large … omitted]" notes.
    3. If (2) also fails, emit a literal placeholder string.

    Matches `summarizeWithFallback` in compaction.ts:380-442.
    """
    if not messages:
        return previous_summary or DEFAULT_SUMMARY_FALLBACK

    instructions = build_summarization_instructions(
        custom_instructions=custom_instructions
    )
    chunk_ratio = compute_adaptive_chunk_ratio(messages, context_window_tokens)
    max_chunk_tokens = max(1, int(context_window_tokens * chunk_ratio) - reserve_tokens)
    if max_chunk_tokens <= 0:
        max_chunk_tokens = max(1, int(context_window_tokens * MIN_CHUNK_RATIO))

    # --- attempt 1: full summarize
    try:
        return _summarize_chunks(
            client=client,
            messages=messages,
            max_chunk_tokens=max_chunk_tokens,
            instructions=instructions,
            previous_summary=previous_summary,
            temperature=temperature,
            max_tokens=max_tokens,
        )
    except Exception as exc:  # noqa: BLE001
        if on_warn is not None:
            on_warn(f"full summarization failed: {type(exc).__name__}: {exc}")

    # --- attempt 2: drop oversized, summarize the rest
    small: list[ChatMessage] = []
    oversized_notes: list[str] = []
    for m in messages:
        if is_oversized_for_summary(m, context_window_tokens):
            tokens = estimate_tokens_for_message(m)
            oversized_notes.append(
                f"[Large {m.role} (~{max(1, round(tokens / 1000))}K tokens) "
                "omitted from summary]"
            )
        else:
            small.append(m)

    if small and len(small) != len(messages):
        try:
            partial = _summarize_chunks(
                client=client,
                messages=small,
                max_chunk_tokens=max_chunk_tokens,
                instructions=instructions,
                previous_summary=previous_summary,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            if oversized_notes:
                return partial + "\n\n" + "\n".join(oversized_notes)
            return partial
        except Exception as exc:  # noqa: BLE001
            if on_warn is not None:
                on_warn(
                    f"partial summarization also failed: "
                    f"{type(exc).__name__}: {exc}"
                )

    # --- attempt 3: literal placeholder
    return (
        f"Context contained {len(messages)} messages "
        f"({len(oversized_notes)} oversized). Summary unavailable due to "
        "size limits."
    )


def _summarize_chunks(
    *,
    client: ChatClient,
    messages: list[ChatMessage],
    max_chunk_tokens: int,
    instructions: str,
    previous_summary: Optional[str],
    temperature: Optional[float],
    max_tokens: Optional[int],
) -> str:
    """Port of `summarizeChunks` (compaction.ts:292-341).

    Walks the message list in token-bounded chunks, feeding each chunk's
    summary forward as `previous_summary` into the next chunk.
    """
    chunks = chunk_messages_by_max_tokens(messages, max_chunk_tokens)
    summary = previous_summary
    for chunk in chunks:
        summary = summarize_chunk(
            client=client,
            chunk=chunk,
            instructions=instructions,
            previous_summary=summary,
            temperature=temperature,
            max_tokens=max_tokens,
        )
    return summary or DEFAULT_SUMMARY_FALLBACK


# ----------------------------- top-level API -----------------------------


@dataclass
class CompactionResult:
    """Outcome of `compact_messages`.

    Attributes:
        messages: new transcript. Shape is [system, <compactionSummary>]
            plus a trailing current user prompt if the input ended with one.
        messages_summarized: number of messages fed into summarization.
        messages_preserved: number kept verbatim.
        summary: the generated summary string.
        estimated_tokens_before / after: rough token count for the gate.
        route: route that triggered this compaction (from PreemptiveDecision).
        elapsed_ms: wall-clock time spent compacting (including LLM call).
        warnings: any `on_warn` messages emitted during fallback.
        ok: True if LLM summarization completed on attempt 1 or 2; False
            if we had to fall back to the literal placeholder.
    """

    messages: list[ChatMessage]
    messages_summarized: int
    messages_preserved: int
    summary: str
    estimated_tokens_before: int
    estimated_tokens_after: int
    route: str
    elapsed_ms: int
    warnings: list[str] = field(default_factory=list)
    ok: bool = True


def compact_messages(
    *,
    client: ChatClient,
    messages: list[ChatMessage],
    context_window_tokens: int,
    route: str = ROUTE_COMPACT_ONLY,
    preserve_n_recent: int = PRESERVE_N_RECENT,
    custom_instructions: Optional[str] = None,
    temperature: Optional[float] = None,
    max_tokens: Optional[int] = None,
) -> CompactionResult:
    """Summarize prior history; keep system + current user prompt verbatim.

    Contract:
    - The system message (if present) at `messages[0]` is preserved.
    - If the last message is a user prompt, it is treated like upstream's
      not-yet-submitted `effectivePrompt`: it stays outside the summarized
      prior history and is appended after the compaction marker.
    - Produces a single `compactionSummary` marker, not a synthetic user
      request.

    Returns a CompactionResult with the new message list ready to hand
    back to the runner.
    """
    t0 = time.monotonic()
    warnings: list[str] = []

    if not messages:
        return CompactionResult(
            messages=[],
            messages_summarized=0,
            messages_preserved=0,
            summary=DEFAULT_SUMMARY_FALLBACK,
            estimated_tokens_before=0,
            estimated_tokens_after=0,
            route=route,
            elapsed_ms=0,
            ok=True,
        )

    est_before = estimate_messages_tokens(messages)

    # Separate out the leading system prompt.
    system_msgs: list[ChatMessage] = []
    body: list[ChatMessage] = []
    for m in messages:
        if m.role == "system" and not body:
            system_msgs.append(m)
        else:
            body.append(m)

    # OpenClaw preemptive compaction runs before the current prompt is
    # submitted: `activeSession.messages` is compacted, then the prompt is
    # retried. Our runner has already appended the current prompt to the
    # message list, so peel off a trailing user message and keep it outside
    # the history summary.
    pending_user_prompt: list[ChatMessage] = []
    history_body = body
    if body and body[-1].role == "user":
        pending_user_prompt = [body[-1]]
        history_body = body[:-1]

    to_summarize = history_body
    preserved = pending_user_prompt

    if not to_summarize:
        # Nothing to summarize — transcript is already small enough.
        return CompactionResult(
            messages=messages,
            messages_summarized=0,
            messages_preserved=len(preserved),
            summary=DEFAULT_SUMMARY_FALLBACK,
            estimated_tokens_before=est_before,
            estimated_tokens_after=est_before,
            route=route,
            elapsed_ms=int((time.monotonic() - t0) * 1000),
            ok=True,
        )

    summary = summarize_with_fallback(
        client=client,
        messages=to_summarize,
        context_window_tokens=context_window_tokens,
        custom_instructions=custom_instructions,
        on_warn=warnings.append,
        temperature=temperature,
        max_tokens=max_tokens,
    )

    # The literal-placeholder fallback string is what signals attempt 3
    # took over. Detect it so callers can log ok=False.
    ok = not summary.startswith("Context contained ") or " messages " not in summary[:100]

    summary_msg = ChatMessage(role="compactionSummary", content=summary)

    new_messages: list[ChatMessage] = list(system_msgs) + [summary_msg] + preserved
    est_after = estimate_messages_tokens(new_messages)
    return CompactionResult(
        messages=new_messages,
        messages_summarized=len(to_summarize),
        messages_preserved=len(preserved),
        summary=summary,
        estimated_tokens_before=est_before,
        estimated_tokens_after=est_after,
        route=route,
        elapsed_ms=int((time.monotonic() - t0) * 1000),
        warnings=warnings,
        ok=ok,
    )


def _adjust_cut_for_tool_pairing(
    body: list[ChatMessage], cut: int
) -> int:
    """Walk `cut` forward until it lands on a clean user/assistant boundary.

    Rule: never split an assistant-with-tool_calls from its tool-role
    replies. If `cut` points at (or just after) a `tool` message whose
    parent `assistant` lies before `cut`, move `cut` forward past all
    contiguous tool messages AND past the next assistant response
    (which will be the tool-results + next turn).

    Simpler conservative heuristic: if `body[cut-1]` is an assistant with
    tool_calls or `body[cut]` is a tool message, walk `cut` forward until
    it sits at the start of a `user` message or end of list.
    """
    if cut <= 0 or cut >= len(body):
        return cut

    def _is_assistant_with_calls(m: ChatMessage) -> bool:
        return m.role == "assistant" and bool(m.tool_calls)

    # If we're splitting inside an assistant→tool block, walk forward.
    while cut < len(body):
        left = body[cut - 1] if cut > 0 else None
        right = body[cut]
        if right.role == "tool":
            # Middle of a tool batch: move forward.
            cut += 1
            continue
        if left is not None and _is_assistant_with_calls(left):
            # tool_calls with no matching tool results in `preserved` — move
            # forward until we find a non-tool message AFTER the tool batch.
            cut += 1
            continue
        break
    return cut


# ----------------------------- logger integration ------------------------


def log_compaction_start(
    logger: Any, *, decision: PreemptiveDecision, messages_in: int
) -> None:
    """Emit a `compaction_start` session event."""
    if logger is None:
        return
    logger.log_event(
        "compaction_start",
        route=decision.route,
        estimated_prompt_tokens=decision.estimated_prompt_tokens,
        prompt_budget=decision.prompt_budget,
        overflow_tokens=decision.overflow_tokens,
        reserve_tokens=decision.reserve_tokens,
        messages_in=messages_in,
    )


def log_compaction_end(logger: Any, *, result: CompactionResult) -> None:
    """Emit a `compaction_end` session event."""
    if logger is None:
        return
    logger.log_event(
        "compaction_end",
        route=result.route,
        ok=result.ok,
        messages_summarized=result.messages_summarized,
        messages_preserved=result.messages_preserved,
        estimated_tokens_before=result.estimated_tokens_before,
        estimated_tokens_after=result.estimated_tokens_after,
        elapsed_ms=result.elapsed_ms,
        warnings=result.warnings,
    )


def log_compaction_summary(logger: Any, *, result: CompactionResult) -> None:
    """Append the compacted transcript marker to the session log."""
    if logger is None or result.messages_summarized <= 0:
        return
    if hasattr(logger, "log_compaction_summary"):
        logger.log_compaction_summary(
            summary=result.summary,
            tokens_before=result.estimated_tokens_before,
            tokens_after=result.estimated_tokens_after,
            route=result.route,
            messages_summarized=result.messages_summarized,
            messages_preserved=result.messages_preserved,
        )


def log_compaction_error(logger: Any, *, route: str, error: str) -> None:
    """Emit a `compaction_error` session event.

    Used when the LLM call itself raises and we decide NOT to fall back
    (e.g. abort). The default `summarize_with_fallback` swallows LLM
    errors into warnings, so this path is rare.
    """
    if logger is None:
        return
    logger.log_event("compaction_error", route=route, error=error)
