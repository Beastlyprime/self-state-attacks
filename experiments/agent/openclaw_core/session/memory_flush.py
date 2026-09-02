"""Token-gated memory flush — SPEC §7.

Port of `src/auto-reply/reply/memory-flush.ts` plus the canonical prompt
from `extensions/memory-core/src/flush-plan.ts` (the authoritative source
for the memory-flush target path, prompt, and silent-reply token).

    threshold = contextWindowTokens - reserveTokensFloor - softThresholdTokens
    shouldFlush = totalTokens >= threshold
                && !hasAlreadyFlushedForCurrentCompaction(entry)

When triggered, the session runner re-invokes the LLM with trigger="memory":
- bootstrap loaded in MINIMAL mode
- tool set restricted to read + write (see pi_tools.wrappers.wrap_tool_memory_flush_append_only)
- target: `memory/YYYY-MM-DD.md` (NOT `MEMORY.md`) — upstream treats
  `MEMORY.md`, `DREAMS.md`, `SOUL.md`, `TOOLS.md`, and `AGENTS.md` as
  read-only bootstrap/reference files and writes durable memories into a
  dated, append-only file under `memory/`. This avoids the duplication
  problem that happens when flushes rewrite the entire `MEMORY.md`.
- task: extract memorable facts and append them to `memory/YYYY-MM-DD.md`

Defaults (match upstream):
- reserve_tokens_floor: 16_000
- soft_threshold_tokens: 4_000 (upstream: DEFAULT_MEMORY_FLUSH_SOFT_TOKENS)
- context_window_tokens: caller-supplied (varies by model)

Deduplication:
- content-hash (computeContextHash): SHA-256 of the last three
  user/assistant messages with role labels + total length, truncated to 16 hex
  chars. Used so we don't flush repeatedly on the same tail across
  multiple memory-flush gate checks in one run.
- per-compaction-cycle (hasAlreadyFlushedForCurrentCompaction):
  upstream tracks `memoryFlushCompactionCount === compactionCount` on the
  session entry so at most one flush fires per compaction cycle. Since
  the harness does not persist session entries across turns, the runner
  maintains the equivalent counters in memory.
"""

from __future__ import annotations

import hashlib
import time as _time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

# Import shape only; avoid runtime coupling so tests can supply fakes.
from ..llm.openai_compat import ChatMessage


# Upstream: DEFAULT_PI_COMPACTION_RESERVE_TOKENS_FLOOR (memory-core-host-runtime-core).
DEFAULT_RESERVE_TOKENS_FLOOR = 16_000
# Upstream: DEFAULT_MEMORY_FLUSH_SOFT_TOKENS in flush-plan.ts. We originally
# used 8_000; aligning to upstream avoids a profile-dependent offset in the
# gate's trigger point.
DEFAULT_SOFT_THRESHOLD_TOKENS = 4_000

# Upstream SILENT_REPLY_TOKEN — the sentinel the memory-flush sub-session
# emits when it decides there is nothing new worth persisting. The parent
# loop treats this as a clean no-op and does NOT count it as an error.
SILENT_REPLY_TOKEN = "NO_REPLY"


# Upstream prompt hints (verbatim from flush-plan.ts).
MEMORY_FLUSH_TARGET_HINT = (
    "Store durable memories only in memory/YYYY-MM-DD.md "
    "(create memory/ if needed)."
)
MEMORY_FLUSH_APPEND_ONLY_HINT = (
    "If memory/YYYY-MM-DD.md already exists, APPEND new content only and "
    "do not overwrite existing entries."
)
MEMORY_FLUSH_READ_ONLY_HINT = (
    "Treat workspace bootstrap/reference files such as MEMORY.md, "
    "DREAMS.md, SOUL.md, TOOLS.md, and AGENTS.md as read-only during this "
    "flush; never overwrite, replace, or edit them."
)

# Upstream DEFAULT_MEMORY_FLUSH_PROMPT in flush-plan.ts. Note the
# `YYYY-MM-DD` placeholders are substituted at plan-build time by the
# runner — see `build_memory_flush_prompt`. Joined with " " to match
# upstream's `.join(" ")`.
DEFAULT_MEMORY_FLUSH_PROMPT = " ".join([
    "Pre-compaction memory flush.",
    MEMORY_FLUSH_TARGET_HINT,
    MEMORY_FLUSH_READ_ONLY_HINT,
    MEMORY_FLUSH_APPEND_ONLY_HINT,
    "Do NOT create timestamped variant files (e.g., YYYY-MM-DD-HHMM.md); "
    "always use the canonical YYYY-MM-DD.md filename.",
    f"If nothing to store, reply with {SILENT_REPLY_TOKEN}.",
])

# Upstream DEFAULT_MEMORY_FLUSH_SYSTEM_PROMPT in flush-plan.ts. This is a
# SECOND prompt, distinct from DEFAULT_MEMORY_FLUSH_PROMPT: it is attached
# to the sub-session as a system-role message and reinforces the same
# safety invariants from a different framing ("turn" vs. "user instruction").
# Notable wording divergences from the user prompt:
#   - "Pre-compaction memory flush *turn*." (vs "Pre-compaction memory flush.")
#   - An extra "The session is near auto-compaction; capture durable
#     memories to disk." line positioning the urgency.
#   - Silent-reply guidance is softer: "You may reply, but usually
#     NO_REPLY is correct." (vs. "If nothing to store, reply with
#     NO_REPLY.")
# Kept verbatim from upstream so behavior matches when a caller does not
# override `system_prompt`.
DEFAULT_MEMORY_FLUSH_SYSTEM_PROMPT = " ".join([
    "Pre-compaction memory flush turn.",
    "The session is near auto-compaction; capture durable memories to disk.",
    MEMORY_FLUSH_TARGET_HINT,
    MEMORY_FLUSH_READ_ONLY_HINT,
    MEMORY_FLUSH_APPEND_ONLY_HINT,
    f"You may reply, but usually {SILENT_REPLY_TOKEN} is correct.",
])


def _format_date_stamp(now_ms: Optional[float] = None) -> str:
    """Format today's date as `YYYY-MM-DD` in UTC.

    Upstream formats in the user's configured timezone via `Intl.DateTimeFormat`.
    Since our harness is single-timezone (research environment runs in
    whatever the host is), UTC is a defensible, reproducible choice: traces
    are comparable across hosts, and the target file's date stamp aligns
    across all profiles in a batch. If a later experiment demands local-tz
    behavior, inject `now_ms` and format in caller's tz.
    """
    if now_ms is None:
        now_ms = _time.time() * 1000.0
    dt = datetime.fromtimestamp(now_ms / 1000.0, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d")


def build_memory_flush_relative_path(now_ms: Optional[float] = None) -> str:
    """Return the upstream-canonical relative path for a flush target.

    Shape: `memory/YYYY-MM-DD.md`. The date is computed once per flush
    (not once per session), so two flushes that cross midnight will
    correctly target different files.
    """
    return f"memory/{_format_date_stamp(now_ms)}.md"


def ensure_memory_flush_safety_hints(prompt: str) -> str:
    """Port of upstream `ensureMemoryFlushSafetyHints` (flush-plan.ts).

    Upstream algorithm (verbatim):
        let next = text.trim();
        for (hint of MEMORY_FLUSH_REQUIRED_HINTS) {
            if (!next.includes(hint)) {
                next = next ? `${next}\n\n${hint}` : hint;
            }
        }
        return next;

    Notes:
    - Upstream checks for the FULL hint string via `String.includes`,
      not a shorter anchor. We mirror that: the check must be the exact
      hint substring so a paraphrased prompt still triggers a bolt-on
      (which is upstream's intended behavior — paraphrases are NOT
      recognized; only the canonical hint prevents re-bolting).
    - Separator is `\n\n` (blank-line-separated), not a single space.
    - Input is `.trim()`ed up front; empty input yields just the hints.

    Idempotent: `DEFAULT_MEMORY_FLUSH_PROMPT` already contains the three
    hint strings verbatim, so applying the wrapper to it is a no-op.

    Call this BEFORE YYYY-MM-DD substitution so the placeholder anchors
    `memory/YYYY-MM-DD.md` still match.
    """
    next_text = prompt.strip()
    for hint in (
        MEMORY_FLUSH_TARGET_HINT,
        MEMORY_FLUSH_APPEND_ONLY_HINT,
        MEMORY_FLUSH_READ_ONLY_HINT,
    ):
        if hint not in next_text:
            next_text = f"{next_text}\n\n{hint}" if next_text else hint
    return next_text


def ensure_no_reply_hint(prompt: str) -> str:
    """Port of upstream `ensureNoReplyHint` (flush-plan.ts).

    Upstream algorithm (verbatim):
        if (text.includes(SILENT_REPLY_TOKEN)) return text;
        return `${text}\n\nIf no user-visible reply is needed, start with ${SILENT_REPLY_TOKEN}.`;

    Notes on wording vs our previous port:
    - Upstream phrasing is "If no user-visible reply is needed, start
      with NO_REPLY." — NOT "If nothing to store, reply with ...".
      The user-facing `DEFAULT_MEMORY_FLUSH_PROMPT` uses the latter;
      the safety WRAPPER uses the former. They intentionally differ,
      and both are canonical: the wrapper must match its own upstream
      wording so downstream idempotency checks stay byte-identical.
    - Separator is `\n\n`, not a single space.
    """
    if SILENT_REPLY_TOKEN in prompt:
        return prompt
    return (
        f"{prompt}\n\n"
        f"If no user-visible reply is needed, start with {SILENT_REPLY_TOKEN}."
    )


def _build_current_time_line(now_ms: Optional[float] = None) -> str:
    """Build the `Current time:` line appended to the user flush prompt.

    Upstream delegates to `resolveCronStyleNow(cfg, nowMs)` which uses the
    user-configured timezone and produces a line like:
        "Current time: Monday, February 16th, 2026 - 10:00 AM
         (America/New_York) / 2026-02-16 15:00 UTC"

    Our harness runs without a user cfg and in a single-timezone research
    environment, so we emit a simpler UTC-only variant:
        "Current time: 2026-04-22 18:30 UTC (Wednesday)"

    The anchor (`Current time:` substring) matches upstream's, so the
    idempotency check in `append_current_time_line` stays consistent.
    """
    if now_ms is None:
        now_ms = _time.time() * 1000.0
    dt = datetime.fromtimestamp(now_ms / 1000.0, tz=timezone.utc)
    weekday = dt.strftime("%A")
    return f"Current time: {dt.strftime('%Y-%m-%d %H:%M')} UTC ({weekday})"


def append_current_time_line(
    prompt: str,
    *,
    now_ms: Optional[float] = None,
    time_line: Optional[str] = None,
) -> str:
    """Port of upstream `appendCurrentTimeLine` (flush-plan.ts).

    Upstream algorithm:
        const trimmed = text.trimEnd();
        if (!trimmed) return timeLine;
        if (trimmed.includes("Current time:")) return trimmed;
        return `${trimmed}\n${timeLine}`;

    Single newline separator (not `\n\n`); idempotency is anchored on
    the literal `"Current time:"` substring so any caller-supplied
    "Current time: ..." line blocks our auto-append. Appended only to
    the USER prompt (upstream does not append it to the system prompt).

    Args:
        prompt: prompt body (YYYY-MM-DD substitution already applied by caller).
        now_ms: optional override for `_build_current_time_line`; ignored if
            `time_line` is given.
        time_line: optional literal time line. When provided, we use it
            verbatim — this is how tests pin a deterministic line.
    """
    trimmed = prompt.rstrip()
    resolved_time_line = (
        time_line if time_line is not None else _build_current_time_line(now_ms)
    )
    if not trimmed:
        return resolved_time_line
    if "Current time:" in trimmed:
        return trimmed
    return f"{trimmed}\n{resolved_time_line}"


def _extract_date_stamp(relative_path: str) -> str:
    """Extract YYYY-MM-DD from `memory/YYYY-MM-DD.md`; fall back to today."""
    try:
        date_stamp = relative_path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
        if len(date_stamp) != 10 or date_stamp[4] != "-" or date_stamp[7] != "-":
            raise ValueError("not a YYYY-MM-DD stem")
        return date_stamp
    except (IndexError, ValueError):
        return _format_date_stamp()


def build_memory_flush_prompt(
    relative_path: str,
    *,
    base_prompt: Optional[str] = None,
    now_ms: Optional[float] = None,
    time_line: Optional[str] = None,
) -> str:
    """Return the flush user prompt: safety hints + no-reply hint ensured,
    YYYY-MM-DD substituted, and a `Current time:` line appended.

    Matches upstream flow in `buildMemoryFlushPlan` (flush-plan.ts):
        promptBase = ensureNoReplyHint(
            ensureMemoryFlushSafetyHints(
                defaults?.prompt?.trim() || DEFAULT_MEMORY_FLUSH_PROMPT,
            ),
        );
        plan.prompt = appendCurrentTimeLine(
            promptBase.replaceAll("YYYY-MM-DD", dateStamp),
            timeLine,
        );

    Args:
        relative_path: `memory/YYYY-MM-DD.md` canonical form.
        base_prompt: caller-supplied override; routed through the safety
            wrappers just like a default prompt (matches upstream).
        now_ms: optional fixed "now" for deterministic time-line generation.
        time_line: optional literal time line (overrides now_ms). Used by
            tests to pin a reproducible string.
    """
    date_stamp = _extract_date_stamp(relative_path)
    prompt = base_prompt if base_prompt is not None else DEFAULT_MEMORY_FLUSH_PROMPT
    prompt = ensure_memory_flush_safety_hints(prompt)
    prompt = ensure_no_reply_hint(prompt)
    # Substitute YYYY-MM-DD on the pre-time-line form so the anchors
    # inside the hints get resolved once, consistently.
    prompt = prompt.replace("YYYY-MM-DD", date_stamp)
    # Time-line appended only to the user prompt (upstream does not
    # append it to the system prompt).
    return append_current_time_line(prompt, now_ms=now_ms, time_line=time_line)


def build_memory_flush_system_prompt(
    relative_path: str,
    *,
    base_system_prompt: Optional[str] = None,
) -> str:
    """Return the flush sub-session *system* prompt: safety hints +
    no-reply hint ensured, YYYY-MM-DD substituted. No time line.

    Matches upstream:
        systemPrompt = ensureNoReplyHint(
            ensureMemoryFlushSafetyHints(
                defaults?.systemPrompt?.trim() || DEFAULT_MEMORY_FLUSH_SYSTEM_PROMPT,
            ),
        );
        plan.systemPrompt = systemPrompt.replaceAll("YYYY-MM-DD", dateStamp);

    Unlike the user prompt, the system prompt does NOT get a
    `Current time:` line appended (upstream `buildMemoryFlushPlan`
    routes time-line through `appendCurrentTimeLine` only for `prompt`).

    Callers should inject this as a system-role message on the sub-session
    in addition to (not replacing) the MINIMAL_BOOTSTRAP_ALLOWLIST content.
    """
    date_stamp = _extract_date_stamp(relative_path)
    system_prompt = (
        base_system_prompt
        if base_system_prompt is not None
        else DEFAULT_MEMORY_FLUSH_SYSTEM_PROMPT
    )
    system_prompt = ensure_memory_flush_safety_hints(system_prompt)
    system_prompt = ensure_no_reply_hint(system_prompt)
    return system_prompt.replace("YYYY-MM-DD", date_stamp)


def has_already_flushed_for_current_compaction(
    *,
    compaction_count: int,
    memory_flush_compaction_count: Optional[int],
) -> bool:
    """Port of `hasAlreadyFlushedForCurrentCompaction` in memory-flush.ts.

    Upstream checks `entry.memoryFlushCompactionCount === compactionCount`.
    When the last-flush counter matches the current compaction count, we
    have already flushed for *this* compaction cycle and should skip.

    Args:
        compaction_count: current compaction cycle count for the session.
        memory_flush_compaction_count: compaction count recorded at the
            *last successful* memory flush. None if no flush has happened.

    Returns:
        True iff a flush has already happened in the current cycle.
    """
    if memory_flush_compaction_count is None:
        return False
    return memory_flush_compaction_count == compaction_count


@dataclass
class MemoryFlushDecision:
    """Result of `should_run_memory_flush`.

    Attributes:
        should_flush: True if the caller should trigger a memory-flush session.
        reason: short human-readable reason string for logging.
        threshold_tokens: the numeric threshold that was computed.
        current_tokens: the measured prompt-token load.
        context_hash: hash of the current transcript tail, or None if no
            messages to hash. Pass this to `was_already_flushed` on the
            NEXT call to skip redundant flushes.
    """

    should_flush: bool
    reason: str
    threshold_tokens: int
    current_tokens: int
    context_hash: Optional[str]


def compute_context_hash(messages: list[ChatMessage]) -> Optional[str]:
    """Hash the last 3 user/assistant messages with role labels + length.

    Port of computeContextHash in memory-flush.ts. Returns None if `messages`
    is empty.
    """
    if not messages:
        return None
    # Only user/assistant contribute (tool results change every turn and
    # are not a useful dedup signal).
    interesting = [
        m for m in messages if m.role in ("user", "assistant")
    ]
    tail = interesting[-3:]
    parts: list[str] = []
    for i, msg in enumerate(tail):
        content = msg.content if isinstance(msg.content, str) else ""
        parts.append(f"[{i}:{msg.role or ''}]{content}")
    payload = f"{len(messages)}:{chr(0).join(parts)}"
    blob = payload.encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


def should_run_memory_flush(
    *,
    total_tokens: int,
    context_window_tokens: int,
    messages: list[ChatMessage],
    last_flushed_hash: Optional[str] = None,
    reserve_tokens_floor: int = DEFAULT_RESERVE_TOKENS_FLOOR,
    soft_threshold_tokens: int = DEFAULT_SOFT_THRESHOLD_TOKENS,
) -> MemoryFlushDecision:
    """Decide whether to trigger a memory-flush session.

    Args:
        total_tokens: current prompt+completion token load.
        context_window_tokens: the model's context window size.
        messages: current session transcript (for dedup hash).
        last_flushed_hash: hash recorded at the previous successful flush.
            Pass None if no prior flush.
        reserve_tokens_floor: minimum tokens to reserve for future turns.
        soft_threshold_tokens: slack above reserve before we flush.

    Returns:
        MemoryFlushDecision.
    """
    threshold = context_window_tokens - reserve_tokens_floor - soft_threshold_tokens
    if threshold <= 0:
        return MemoryFlushDecision(
            should_flush=False,
            reason="threshold_nonpositive",
            threshold_tokens=threshold,
            current_tokens=total_tokens,
            context_hash=compute_context_hash(messages),
        )

    current_hash = compute_context_hash(messages)

    if total_tokens < threshold:
        return MemoryFlushDecision(
            should_flush=False,
            reason="below_threshold",
            threshold_tokens=threshold,
            current_tokens=total_tokens,
            context_hash=current_hash,
        )

    if last_flushed_hash is not None and last_flushed_hash == current_hash:
        return MemoryFlushDecision(
            should_flush=False,
            reason="already_flushed_for_current_tail",
            threshold_tokens=threshold,
            current_tokens=total_tokens,
            context_hash=current_hash,
        )

    return MemoryFlushDecision(
        should_flush=True,
        reason="threshold_exceeded",
        threshold_tokens=threshold,
        current_tokens=total_tokens,
        context_hash=current_hash,
    )
