"""Unit tests for pure functions in `session/memory_flush.py`.

Focus:
- `ensure_memory_flush_safety_hints` / `ensure_no_reply_hint`:
  idempotent on upstream defaults; bolt missing pieces onto a bare prompt.
- `append_current_time_line`: bolts a `Current time:` line, anchors on
  the literal substring, idempotent.
- `build_memory_flush_prompt` / `build_memory_flush_system_prompt`:
  compose wrappers + YYYY-MM-DD substitution; time-line only on user prompt.

End-to-end behavior (gate/dedup/subsession wiring) is covered by the
memory-flush tests in `test_session.py`.
"""

from __future__ import annotations

import hashlib

from openclaw_core.llm.openai_compat import ChatMessage
from openclaw_core.session.memory_flush import (
    DEFAULT_MEMORY_FLUSH_PROMPT,
    DEFAULT_MEMORY_FLUSH_SYSTEM_PROMPT,
    MEMORY_FLUSH_APPEND_ONLY_HINT,
    MEMORY_FLUSH_READ_ONLY_HINT,
    MEMORY_FLUSH_TARGET_HINT,
    SILENT_REPLY_TOKEN,
    append_current_time_line,
    build_memory_flush_prompt,
    build_memory_flush_system_prompt,
    compute_context_hash,
    ensure_memory_flush_safety_hints,
    ensure_no_reply_hint,
)


class TestUpstreamConstants:
    def test_silent_reply_token_matches_openclaw(self) -> None:
        assert SILENT_REPLY_TOKEN == "NO_REPLY"


class TestComputeContextHash:
    def test_hash_payload_matches_openclaw_shape(self) -> None:
        messages = [
            ChatMessage("system", "ignored but counted"),
            ChatMessage("user", "first"),
            ChatMessage("tool", "ignored"),
            ChatMessage("assistant", "second"),
            ChatMessage("user", "third"),
            ChatMessage("assistant", "fourth"),
        ]
        payload = "6:" + "\x00".join([
            "[0:assistant]second",
            "[1:user]third",
            "[2:assistant]fourth",
        ])
        expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
        assert compute_context_hash(messages) == expected


class TestEnsureMemoryFlushSafetyHints:
    def test_default_user_prompt_is_unchanged(self) -> None:
        """DEFAULT_MEMORY_FLUSH_PROMPT already contains all three hint
        strings verbatim → wrapper must be a byte-level no-op."""
        result = ensure_memory_flush_safety_hints(DEFAULT_MEMORY_FLUSH_PROMPT)
        assert result == DEFAULT_MEMORY_FLUSH_PROMPT

    def test_default_system_prompt_is_unchanged(self) -> None:
        """DEFAULT_MEMORY_FLUSH_SYSTEM_PROMPT is constructed from the
        same three hints → wrapper must be a no-op on it too."""
        result = ensure_memory_flush_safety_hints(DEFAULT_MEMORY_FLUSH_SYSTEM_PROMPT)
        assert result == DEFAULT_MEMORY_FLUSH_SYSTEM_PROMPT

    def test_idempotent_on_repeated_calls(self) -> None:
        once = ensure_memory_flush_safety_hints(DEFAULT_MEMORY_FLUSH_PROMPT)
        twice = ensure_memory_flush_safety_hints(once)
        assert once == twice

    def test_bare_prompt_gets_all_three_hints_blank_separated(self) -> None:
        """Minimal user-supplied prompt missing all hints should have
        all three appended, with `\\n\\n` separators (matches upstream)."""
        bare = "Flush now."
        result = ensure_memory_flush_safety_hints(bare)
        assert MEMORY_FLUSH_TARGET_HINT in result
        assert MEMORY_FLUSH_READ_ONLY_HINT in result
        assert MEMORY_FLUSH_APPEND_ONLY_HINT in result
        assert result.startswith("Flush now.")
        # Upstream uses double-newline (blank-line) separator.
        assert "\n\n" in result

    def test_empty_prompt_yields_hints_only(self) -> None:
        """Upstream's guard `next ? ${next}\\n\\n${hint} : hint` means
        an empty input yields just the hints, with no leading newline."""
        result = ensure_memory_flush_safety_hints("")
        assert result.startswith(MEMORY_FLUSH_TARGET_HINT)
        assert MEMORY_FLUSH_APPEND_ONLY_HINT in result
        assert MEMORY_FLUSH_READ_ONLY_HINT in result

    def test_paraphrase_is_not_recognized(self) -> None:
        """Upstream checks the FULL canonical hint string. A paraphrase
        that mentions 'read-only' but not the exact canonical hint is
        NOT treated as already-covered — the canonical hint must be
        bolted on. This matches upstream's `.includes(hint)` check."""
        paraphrased = (
            "Flush. Please keep bootstrap files read-only. "
            "Append any new content, never overwrite."
        )
        result = ensure_memory_flush_safety_hints(paraphrased)
        # All three canonical hints must now be present verbatim.
        assert MEMORY_FLUSH_TARGET_HINT in result
        assert MEMORY_FLUSH_READ_ONLY_HINT in result
        assert MEMORY_FLUSH_APPEND_ONLY_HINT in result

    def test_prompt_with_canonical_hint_does_not_duplicate(self) -> None:
        """If the prompt already contains one canonical hint verbatim,
        that hint must NOT be re-appended (idempotency per-hint)."""
        has_target = f"Flush. {MEMORY_FLUSH_TARGET_HINT}"
        result = ensure_memory_flush_safety_hints(has_target)
        assert result.count(MEMORY_FLUSH_TARGET_HINT) == 1
        # Other two still get bolted on (they were missing).
        assert MEMORY_FLUSH_READ_ONLY_HINT in result
        assert MEMORY_FLUSH_APPEND_ONLY_HINT in result


class TestEnsureNoReplyHint:
    def test_default_user_prompt_is_unchanged(self) -> None:
        """DEFAULT_MEMORY_FLUSH_PROMPT already mentions SILENT_REPLY_TOKEN."""
        result = ensure_no_reply_hint(DEFAULT_MEMORY_FLUSH_PROMPT)
        assert result == DEFAULT_MEMORY_FLUSH_PROMPT

    def test_default_system_prompt_is_unchanged(self) -> None:
        """DEFAULT_MEMORY_FLUSH_SYSTEM_PROMPT also mentions the token."""
        result = ensure_no_reply_hint(DEFAULT_MEMORY_FLUSH_SYSTEM_PROMPT)
        assert result == DEFAULT_MEMORY_FLUSH_SYSTEM_PROMPT

    def test_idempotent_on_repeated_calls(self) -> None:
        once = ensure_no_reply_hint(DEFAULT_MEMORY_FLUSH_PROMPT)
        twice = ensure_no_reply_hint(once)
        assert once == twice

    def test_bare_prompt_gets_upstream_wording(self) -> None:
        """Upstream's bolt-on wording is 'If no user-visible reply is
        needed, start with NO_REPLY.' (NOT 'If nothing to store,
        reply with ...' — that text only appears in DEFAULT prompt)."""
        bare = "Flush now."
        result = ensure_no_reply_hint(bare)
        assert SILENT_REPLY_TOKEN in result
        assert "If no user-visible reply is needed" in result
        assert "start with" in result
        # Separator is blank-line, matching upstream.
        assert "\n\n" in result

    def test_prompt_mentioning_token_without_instruction_still_counts(self) -> None:
        """Any occurrence of SILENT_REPLY_TOKEN blocks the bolt-on."""
        already = f"If silent, say {SILENT_REPLY_TOKEN}."
        result = ensure_no_reply_hint(already)
        assert result == already
        assert result.count(SILENT_REPLY_TOKEN) == 1


class TestAppendCurrentTimeLine:
    _FAKE_LINE = "Current time: 2026-04-22 18:30 UTC (Wednesday)"

    def test_appends_to_prompt_missing_anchor(self) -> None:
        prompt = "Flush body."
        result = append_current_time_line(prompt, time_line=self._FAKE_LINE)
        assert result.endswith(self._FAKE_LINE)
        assert result.startswith("Flush body.")
        # Single-newline separator between body and time line (upstream).
        assert "Flush body.\n" + self._FAKE_LINE == result

    def test_idempotent_when_anchor_present(self) -> None:
        prompt = "Flush. Current time: 2026-01-01 00:00 UTC already here."
        result = append_current_time_line(prompt, time_line=self._FAKE_LINE)
        # Must NOT append a second `Current time:` line.
        assert result.count("Current time:") == 1
        # Returns the trimmed original (upstream `text.trimEnd()`).
        assert result == prompt.rstrip()

    def test_empty_prompt_returns_time_line_only(self) -> None:
        result = append_current_time_line("", time_line=self._FAKE_LINE)
        assert result == self._FAKE_LINE

    def test_generated_line_has_current_time_anchor(self) -> None:
        """When neither now_ms nor time_line is provided, the wrapper
        must still emit a line containing the `Current time:` anchor
        so the idempotency check works on subsequent calls."""
        result = append_current_time_line("Flush body.")
        assert "Current time:" in result


class TestBuildMemoryFlushPrompt:
    def test_default_path_substitutes_date_and_appends_time(self) -> None:
        """Default user prompt with a dated target should:
         - substitute 2026-04-22 into the target/append hints
         - preserve SILENT_REPLY_TOKEN (already present in the default)
         - have a `Current time:` line appended at the end."""
        time_line = "Current time: 2026-04-22 18:30 UTC (Wednesday)"
        prompt = build_memory_flush_prompt(
            "memory/2026-04-22.md",
            time_line=time_line,
        )
        assert "memory/2026-04-22.md" in prompt
        assert "YYYY-MM-DD" not in prompt
        assert SILENT_REPLY_TOKEN in prompt
        # Upstream wording for the silent-reply fallback in the default
        # user prompt (NOT the wrapper bolt-on text — the default prompt
        # provides the canonical user-facing phrasing).
        assert f"If nothing to store, reply with {SILENT_REPLY_TOKEN}" in prompt
        assert prompt.endswith(time_line)

    def test_custom_base_prompt_gets_safety_wrappers_and_time_line(self) -> None:
        """User override routes through ensure_* wrappers + time-line."""
        bare = "Do a memory flush."
        time_line = "Current time: 2026-04-22 18:30 UTC (Wednesday)"
        prompt = build_memory_flush_prompt(
            "memory/2026-04-22.md",
            base_prompt=bare,
            time_line=time_line,
        )
        assert "memory/2026-04-22.md" in prompt
        # All three canonical hints bolted on.
        assert MEMORY_FLUSH_TARGET_HINT.replace("YYYY-MM-DD", "2026-04-22") in prompt
        assert MEMORY_FLUSH_READ_ONLY_HINT in prompt
        assert MEMORY_FLUSH_APPEND_ONLY_HINT.replace("YYYY-MM-DD", "2026-04-22") in prompt
        # Silent-reply sentinel bolted on.
        assert SILENT_REPLY_TOKEN in prompt
        # Time line appended at tail.
        assert prompt.endswith(time_line)
        # No placeholder leakage.
        assert "YYYY-MM-DD" not in prompt

    def test_malformed_relative_path_falls_back_to_today(self) -> None:
        """If relative_path is not `memory/YYYY-MM-DD.md` shape, we fall
        back to today's UTC stamp rather than crashing."""
        prompt = build_memory_flush_prompt("memory/not-a-date.md")
        assert "YYYY-MM-DD" not in prompt


class TestBuildMemoryFlushSystemPrompt:
    def test_default_system_prompt_substitutes_date_no_time_line(self) -> None:
        """Default system prompt: safety wrappers no-op, date substituted,
        NO `Current time:` line (upstream does not append it to system)."""
        system = build_memory_flush_system_prompt("memory/2026-04-22.md")
        assert "memory/2026-04-22.md" in system
        assert "YYYY-MM-DD" not in system
        # Upstream system-prompt wording that differs from user prompt.
        assert "Pre-compaction memory flush turn." in system
        assert "The session is near auto-compaction" in system
        # Softer silent-reply phrasing (system-prompt-specific).
        assert f"usually {SILENT_REPLY_TOKEN} is correct" in system
        # Crucially — no time line on system prompt.
        assert "Current time:" not in system

    def test_custom_system_prompt_gets_wrappers(self) -> None:
        """A caller-supplied system prompt missing hints gets them
        bolted on, same contract as the user prompt wrapper."""
        bare_system = "Memory flush turn."
        system = build_memory_flush_system_prompt(
            "memory/2026-04-22.md",
            base_system_prompt=bare_system,
        )
        assert system.startswith("Memory flush turn.")
        assert "memory/2026-04-22.md" in system
        assert MEMORY_FLUSH_READ_ONLY_HINT in system
        assert MEMORY_FLUSH_APPEND_ONLY_HINT.replace("YYYY-MM-DD", "2026-04-22") in system
        assert SILENT_REPLY_TOKEN in system
        # Still no time line.
        assert "Current time:" not in system


class TestDefaultSystemPromptShape:
    """Pin upstream-verbatim properties of DEFAULT_MEMORY_FLUSH_SYSTEM_PROMPT
    so accidental drift trips a test."""

    def test_distinct_from_user_prompt(self) -> None:
        assert DEFAULT_MEMORY_FLUSH_SYSTEM_PROMPT != DEFAULT_MEMORY_FLUSH_PROMPT

    def test_contains_turn_framing(self) -> None:
        assert DEFAULT_MEMORY_FLUSH_SYSTEM_PROMPT.startswith(
            "Pre-compaction memory flush turn."
        )

    def test_contains_auto_compaction_line(self) -> None:
        assert (
            "The session is near auto-compaction; capture durable memories to disk."
            in DEFAULT_MEMORY_FLUSH_SYSTEM_PROMPT
        )

    def test_contains_softer_silent_reply_phrasing(self) -> None:
        assert (
            f"You may reply, but usually {SILENT_REPLY_TOKEN} is correct."
            in DEFAULT_MEMORY_FLUSH_SYSTEM_PROMPT
        )

    def test_contains_all_three_hints(self) -> None:
        assert MEMORY_FLUSH_TARGET_HINT in DEFAULT_MEMORY_FLUSH_SYSTEM_PROMPT
        assert MEMORY_FLUSH_READ_ONLY_HINT in DEFAULT_MEMORY_FLUSH_SYSTEM_PROMPT
        assert MEMORY_FLUSH_APPEND_ONLY_HINT in DEFAULT_MEMORY_FLUSH_SYSTEM_PROMPT
