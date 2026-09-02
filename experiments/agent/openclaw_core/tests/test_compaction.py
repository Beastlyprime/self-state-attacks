"""Unit tests for openclaw_core.session.compaction.

Offline tests only — we feed a `ScriptedClient` into `summarize_chunk` /
`compact_messages`. No real LLM calls.

Coverage:
- constants byte-pinned against real OpenClaw source strings
- token estimation (chars/4 heuristic)
- preemptive route decision (fits / compact_only / compact_then_truncate)
- adaptive chunk ratio
- oversized-for-summary check
- chunking respects the effective max (after SAFETY_MARGIN)
- `summarize_with_fallback` 3-level fallback ladder
- `compact_messages` shape: system preserved, summary marker emitted,
  current user prompt preserved outside prior-history summary
- tool messages are summarized away as prior history, avoiding orphaned
  assistant/tool pairs in the post-compaction transcript
- `SessionRunner` integration: compaction fires when gate exceeds, emits
  `compaction_start` / `compaction_end` events to the session log
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from dataclasses import dataclass
from typing import Any, Optional

from openclaw_core.llm.openai_compat import (
    ChatMessage,
    ChatResponse,
    ToolCall,
    ToolCallFunction,
    Usage,
)
from openclaw_core.session import (
    SessionLogger,
    SessionRunner,
    build_bootstrap_context,
)
from openclaw_core.session.compaction import (
    BASE_CHUNK_RATIO,
    DEFAULT_SUMMARY_FALLBACK,
    ESTIMATED_CHARS_PER_TOKEN,
    IDENTIFIER_PRESERVATION_INSTRUCTIONS,
    MERGE_SUMMARIES_INSTRUCTIONS,
    MIN_CHUNK_RATIO,
    PRESERVE_N_RECENT,
    ROUTE_COMPACT_ONLY,
    ROUTE_COMPACT_THEN_TRUNCATE,
    ROUTE_FITS,
    SAFETY_MARGIN,
    SUMMARIZATION_OVERHEAD_TOKENS,
    build_summarization_instructions,
    chunk_messages_by_max_tokens,
    compact_messages,
    compute_adaptive_chunk_ratio,
    estimate_messages_tokens,
    estimate_tokens_for_message,
    estimate_tokens_for_text,
    is_oversized_for_summary,
    should_preemptively_compact,
    summarize_with_fallback,
)
from openclaw_core.session.runner import build_default_tool_registry
from openclaw_core.workspace import ensure_agent_workspace


# --------------------------- fake client --------------------------------


@dataclass
class ScriptedTurn:
    content: str = ""
    tool_calls: Optional[list[ToolCall]] = None
    finish_reason: Optional[str] = "stop"
    prompt_tokens: int = 10
    completion_tokens: int = 5


class ScriptedClient:
    """Minimal ChatClient for compaction tests."""

    def __init__(self, script: list[ScriptedTurn]) -> None:
        self.script = list(script)
        self.calls: list[list[ChatMessage]] = []
        self.raise_on_call: Optional[Exception] = None

    def chat(
        self,
        messages: list[ChatMessage],
        *,
        tools: Any = None,
        tool_choice: Any = None,
        temperature: Any = None,
        max_tokens: Any = None,
        model: Any = None,
        extra_body: Any = None,
    ) -> ChatResponse:
        self.calls.append(list(messages))
        if self.raise_on_call is not None:
            raise self.raise_on_call
        if not self.script:
            raise AssertionError("ScriptedClient ran out of turns")
        turn = self.script.pop(0)
        return ChatResponse(
            message=ChatMessage(
                role="assistant",
                content=turn.content,
                tool_calls=turn.tool_calls,
            ),
            finish_reason=turn.finish_reason,
            model="scripted",
            usage=Usage(
                prompt_tokens=turn.prompt_tokens,
                completion_tokens=turn.completion_tokens,
                total_tokens=turn.prompt_tokens + turn.completion_tokens,
            ),
        )


class CompactionAwareClient:
    """Script main runner turns, but answer summarizer calls separately."""

    def __init__(
        self,
        main_script: list[ScriptedTurn],
        *,
        summary: str = "SUMM",
    ) -> None:
        self.main_script = list(main_script)
        self.summary = summary
        self.calls: list[list[ChatMessage]] = []
        self.summary_calls = 0

    def chat(
        self,
        messages: list[ChatMessage],
        *,
        tools: Any = None,
        tool_choice: Any = None,
        temperature: Any = None,
        max_tokens: Any = None,
        model: Any = None,
        extra_body: Any = None,
    ) -> ChatResponse:
        self.calls.append(list(messages))
        if tools is None:
            self.summary_calls += 1
            return ChatResponse(
                message=ChatMessage(role="assistant", content=self.summary),
                finish_reason="stop",
                model="scripted",
                usage=Usage(prompt_tokens=10, completion_tokens=5, total_tokens=15),
            )
        if not self.main_script:
            raise AssertionError("CompactionAwareClient ran out of main turns")
        turn = self.main_script.pop(0)
        return ChatResponse(
            message=ChatMessage(
                role="assistant",
                content=turn.content,
                tool_calls=turn.tool_calls,
            ),
            finish_reason=turn.finish_reason,
            model="scripted",
            usage=Usage(
                prompt_tokens=turn.prompt_tokens,
                completion_tokens=turn.completion_tokens,
                total_tokens=turn.prompt_tokens + turn.completion_tokens,
            ),
        )


def _tc(id: str, name: str, args: dict) -> ToolCall:
    return ToolCall(
        id=id,
        type="function",
        function=ToolCallFunction(name=name, arguments=json.dumps(args)),
    )


# -------------------- constants (byte-pinned) ----------------------------


class ConstantsPinTests(unittest.TestCase):
    def test_chunk_ratio_constants(self) -> None:
        self.assertEqual(BASE_CHUNK_RATIO, 0.4)
        self.assertEqual(MIN_CHUNK_RATIO, 0.15)
        self.assertEqual(SAFETY_MARGIN, 1.2)
        self.assertEqual(SUMMARIZATION_OVERHEAD_TOKENS, 4096)
        self.assertEqual(ESTIMATED_CHARS_PER_TOKEN, 4)
        self.assertEqual(DEFAULT_SUMMARY_FALLBACK, "No prior history.")
        self.assertEqual(PRESERVE_N_RECENT, 3)

    def test_merge_summaries_instructions_verbatim(self) -> None:
        """Pin against compaction.ts:24-37."""
        self.assertIn("Merge these partial summaries", MERGE_SUMMARIES_INSTRUCTIONS)
        self.assertIn("MUST PRESERVE:", MERGE_SUMMARIES_INSTRUCTIONS)
        self.assertIn(
            "- Active tasks and their current status (in-progress, blocked, pending)",
            MERGE_SUMMARIES_INSTRUCTIONS,
        )
        self.assertIn(
            "- Batch operation progress (e.g., '5/17 items completed')",
            MERGE_SUMMARIES_INSTRUCTIONS,
        )
        self.assertIn(
            "PRIORITIZE recent context over older history",
            MERGE_SUMMARIES_INSTRUCTIONS,
        )

    def test_identifier_preservation_instructions_verbatim(self) -> None:
        """Pin against compaction.ts:38-40."""
        self.assertIn(
            "Preserve all opaque identifiers exactly as written",
            IDENTIFIER_PRESERVATION_INSTRUCTIONS,
        )
        self.assertIn(
            "UUIDs, hashes, IDs, hostnames, IPs, ports, URLs, and file names",
            IDENTIFIER_PRESERVATION_INSTRUCTIONS,
        )


# ----------------------- token estimation --------------------------------


class TokenEstimateTests(unittest.TestCase):
    def test_text_estimate_is_chars_over_4(self) -> None:
        self.assertEqual(estimate_tokens_for_text(""), 0)
        self.assertEqual(estimate_tokens_for_text("a" * 400), 100)
        # Always >= 1 for non-empty.
        self.assertGreaterEqual(estimate_tokens_for_text("x"), 1)

    def test_message_estimate_includes_tool_calls(self) -> None:
        m = ChatMessage(
            role="assistant",
            content="hi",
            tool_calls=[_tc("c1", "read", {"path": "a" * 100})],
        )
        # Must count both content and tool-call args.
        bare = ChatMessage(role="assistant", content="hi")
        self.assertGreater(
            estimate_tokens_for_message(m),
            estimate_tokens_for_message(bare),
        )

    def test_messages_list_is_sum(self) -> None:
        a = ChatMessage(role="user", content="hello")
        b = ChatMessage(role="assistant", content="world")
        self.assertEqual(
            estimate_messages_tokens([a, b]),
            estimate_tokens_for_message(a) + estimate_tokens_for_message(b),
        )


# ----------------------- route decision ----------------------------------


class PreemptiveRouteTests(unittest.TestCase):
    def test_empty_transcript_fits(self) -> None:
        d = should_preemptively_compact(
            messages=[],
            next_user_prompt="hi",
            system_prompt=None,
            context_window_tokens=10_000,
            reserve_tokens=1_000,
        )
        self.assertEqual(d.route, ROUTE_FITS)
        self.assertFalse(d.should_compact)
        self.assertEqual(d.overflow_tokens, 0)

    def test_route_fits_when_under_budget(self) -> None:
        msgs = [ChatMessage(role="user", content="a" * 100)]
        d = should_preemptively_compact(
            messages=msgs,
            next_user_prompt="next",
            system_prompt="sys",
            context_window_tokens=100_000,
            reserve_tokens=1_000,
        )
        self.assertEqual(d.route, ROUTE_FITS)

    def test_route_compact_only_when_over_but_modest(self) -> None:
        # Make messages big enough to overflow a tiny window slightly.
        msgs = [ChatMessage(role="user", content="x" * 4000) for _ in range(4)]
        d = should_preemptively_compact(
            messages=msgs,
            next_user_prompt="",
            system_prompt=None,
            context_window_tokens=5_000,
            reserve_tokens=200,
        )
        self.assertIn(d.route, (ROUTE_COMPACT_ONLY, ROUTE_COMPACT_THEN_TRUNCATE))
        self.assertTrue(d.should_compact)

    def test_route_compact_then_truncate_when_severe(self) -> None:
        # Massive overflow ⇒ the 1.5x heuristic fires the stronger route.
        msgs = [ChatMessage(role="user", content="x" * 40_000) for _ in range(10)]
        d = should_preemptively_compact(
            messages=msgs,
            next_user_prompt="",
            system_prompt=None,
            context_window_tokens=5_000,
            reserve_tokens=200,
        )
        self.assertEqual(d.route, ROUTE_COMPACT_THEN_TRUNCATE)

    def test_zero_context_returns_fits_safely(self) -> None:
        d = should_preemptively_compact(
            messages=[ChatMessage(role="user", content="x")],
            next_user_prompt="y",
            system_prompt=None,
            context_window_tokens=0,
            reserve_tokens=0,
        )
        self.assertEqual(d.route, ROUTE_FITS)

    def test_empty_next_prompt_does_not_add_synthetic_user(self) -> None:
        msgs = [ChatMessage(role="user", content="x" * 400)]
        d = should_preemptively_compact(
            messages=msgs,
            next_user_prompt="",
            system_prompt=None,
            context_window_tokens=10_000,
            reserve_tokens=1_000,
        )
        expected = int(estimate_messages_tokens(msgs) * SAFETY_MARGIN)
        self.assertEqual(d.estimated_prompt_tokens, expected)


# ----------------------- chunking ----------------------------------------


class ChunkingTests(unittest.TestCase):
    def test_adaptive_ratio_floors_at_min(self) -> None:
        # Big messages vs small context → ratio shrinks toward MIN.
        msgs = [ChatMessage(role="user", content="x" * 20_000) for _ in range(5)]
        r = compute_adaptive_chunk_ratio(msgs, context_window=10_000)
        self.assertGreaterEqual(r, MIN_CHUNK_RATIO)
        self.assertLess(r, BASE_CHUNK_RATIO)

    def test_adaptive_ratio_returns_base_when_messages_small(self) -> None:
        msgs = [ChatMessage(role="user", content="x" * 10) for _ in range(3)]
        r = compute_adaptive_chunk_ratio(msgs, context_window=100_000)
        self.assertEqual(r, BASE_CHUNK_RATIO)

    def test_oversized_detection(self) -> None:
        tiny = ChatMessage(role="user", content="hi")
        big = ChatMessage(role="user", content="x" * 100_000)
        self.assertFalse(is_oversized_for_summary(tiny, 100_000))
        self.assertTrue(is_oversized_for_summary(big, 10_000))

    def test_chunking_respects_max(self) -> None:
        msgs = [ChatMessage(role="user", content="x" * 400) for _ in range(10)]
        # 400 chars ≈ 100 tokens per message (after /4).
        chunks = chunk_messages_by_max_tokens(msgs, max_tokens=300)
        # Every chunk's estimated tokens must be ≤ 300 (after SAFETY_MARGIN).
        effective_max = int(300 / SAFETY_MARGIN)
        for c in chunks:
            self.assertLessEqual(estimate_messages_tokens(c), effective_max * 2)
        # And we must cover all messages.
        flat = [m for c in chunks for m in c]
        self.assertEqual(len(flat), 10)

    def test_chunking_empty(self) -> None:
        self.assertEqual(chunk_messages_by_max_tokens([], 100), [])


# ----------------------- instructions building ---------------------------


class InstructionsTests(unittest.TestCase):
    def test_identifier_preservation_always_on(self) -> None:
        out = build_summarization_instructions()
        self.assertIn(IDENTIFIER_PRESERVATION_INSTRUCTIONS, out)

    def test_custom_appended_as_additional_focus(self) -> None:
        out = build_summarization_instructions(custom_instructions="focus on X")
        self.assertIn(IDENTIFIER_PRESERVATION_INSTRUCTIONS, out)
        self.assertIn("Additional focus:", out)
        self.assertIn("focus on X", out)

    def test_whitespace_only_custom_ignored(self) -> None:
        out = build_summarization_instructions(custom_instructions="   \n\t ")
        self.assertNotIn("Additional focus:", out)


# ----------------------- summarize_with_fallback -------------------------


class SummarizeFallbackTests(unittest.TestCase):
    def test_level_1_happy_path(self) -> None:
        client = ScriptedClient(
            [ScriptedTurn(content="SUMMARY-A"), ScriptedTurn(content="SUMMARY-B")]
        )
        msgs = [
            ChatMessage(role="user", content="a" * 400),
            ChatMessage(role="assistant", content="b" * 400),
        ]
        out = summarize_with_fallback(
            client=client,
            messages=msgs,
            context_window_tokens=100_000,
        )
        self.assertTrue(out.startswith("SUMMARY"))

    def test_level_2_drops_oversized(self) -> None:
        """If the LLM fails on the full set but oversized messages exist,
        attempt 2 retries with them excluded and appends [Large …] notes.

        Strategy: first call raises, subsequent calls (on smaller set)
        succeed.
        """

        class FailFirstClient:
            def __init__(self) -> None:
                self.count = 0

            def chat(self, *args: Any, **kwargs: Any) -> ChatResponse:
                self.count += 1
                if self.count == 1:
                    raise RuntimeError("simulated failure")
                return ChatResponse(
                    message=ChatMessage(role="assistant", content="PARTIAL-SUMMARY"),
                    finish_reason="stop",
                    model="scripted",
                    usage=Usage(prompt_tokens=10, completion_tokens=5, total_tokens=15),
                )

        msgs = [
            ChatMessage(role="user", content="small message"),
            ChatMessage(role="assistant", content="x" * 400_000),  # oversized
            ChatMessage(role="user", content="another small"),
        ]
        warnings: list[str] = []
        out = summarize_with_fallback(
            client=FailFirstClient(),  # type: ignore[arg-type]
            messages=msgs,
            context_window_tokens=10_000,  # small window → the 400K msg is oversized
            on_warn=warnings.append,
        )
        self.assertIn("PARTIAL-SUMMARY", out)
        self.assertIn("[Large", out)
        self.assertTrue(warnings)

    def test_level_3_literal_placeholder(self) -> None:
        """All attempts fail → emit the literal placeholder."""

        class AlwaysFailClient:
            def chat(self, *a: Any, **k: Any) -> ChatResponse:
                raise RuntimeError("always fails")

        msgs = [
            ChatMessage(role="user", content="small"),
            ChatMessage(role="assistant", content="also small"),
        ]
        out = summarize_with_fallback(
            client=AlwaysFailClient(),  # type: ignore[arg-type]
            messages=msgs,
            context_window_tokens=100_000,
        )
        self.assertIn("Context contained", out)
        self.assertIn("Summary unavailable", out)

    def test_empty_returns_previous_or_default(self) -> None:
        client = ScriptedClient([])
        out = summarize_with_fallback(
            client=client,  # type: ignore[arg-type]
            messages=[],
            context_window_tokens=10_000,
            previous_summary="PREV",
        )
        self.assertEqual(out, "PREV")
        out2 = summarize_with_fallback(
            client=client,  # type: ignore[arg-type]
            messages=[],
            context_window_tokens=10_000,
        )
        self.assertEqual(out2, DEFAULT_SUMMARY_FALLBACK)


# ----------------------- compact_messages --------------------------------


class CompactMessagesTests(unittest.TestCase):
    def test_preserves_system_and_current_user_prompt(self) -> None:
        client = ScriptedClient([ScriptedTurn(content="THE-SUMMARY")])
        messages = [
            ChatMessage(role="system", content="SYS"),
            ChatMessage(role="user", content="old-1"),
            ChatMessage(role="assistant", content="old-2"),
            ChatMessage(role="user", content="recent-ask"),
            ChatMessage(role="assistant", content="recent-answer"),
            ChatMessage(role="user", content="current-prompt"),
        ]
        result = compact_messages(
            client=client,  # type: ignore[arg-type]
            messages=messages,
            context_window_tokens=100_000,
        )
        out = result.messages
        # system kept at index 0
        self.assertEqual(out[0].role, "system")
        self.assertEqual(out[0].content, "SYS")
        # Next is the OpenClaw-style compaction marker, not a user turn.
        self.assertEqual(out[1].role, "compactionSummary")
        self.assertEqual(out[1].content, "THE-SUMMARY")
        self.assertNotIn("Continue from where", out[1].content)
        # Current user prompt is outside the prior-history summary, matching
        # upstream's precheck retry shape.
        self.assertEqual(len(out), 3)
        self.assertEqual(out[-1].role, "user")
        self.assertEqual(out[-1].content, "current-prompt")
        self.assertEqual(result.messages_preserved, 1)
        # Summarized = prior history between system and current prompt.
        self.assertEqual(result.messages_summarized, 4)

    def test_handles_no_system_prompt(self) -> None:
        client = ScriptedClient([ScriptedTurn(content="S")])
        messages = [
            ChatMessage(role="user", content="a"),
            ChatMessage(role="assistant", content="b"),
            ChatMessage(role="user", content="c"),
            ChatMessage(role="assistant", content="d"),
            ChatMessage(role="user", content="e"),
        ]
        result = compact_messages(
            client=client,  # type: ignore[arg-type]
            messages=messages,
            context_window_tokens=100_000,
        )
        out = result.messages
        self.assertEqual(out[0].role, "compactionSummary")
        self.assertEqual(out[0].content, "S")
        self.assertEqual(out[1].role, "user")
        self.assertEqual(out[1].content, "e")

    def test_no_op_when_nothing_to_summarize(self) -> None:
        client = ScriptedClient([])
        messages = [
            ChatMessage(role="system", content="S"),
            ChatMessage(role="user", content="x"),
        ]
        result = compact_messages(
            client=client,  # type: ignore[arg-type]
            messages=messages,
            context_window_tokens=100_000,
        )
        # preserve_n_recent=3 but only 1 non-system body message → nothing to summarize.
        self.assertEqual(result.messages_summarized, 0)
        self.assertEqual(result.messages, messages)

    def test_empty_input(self) -> None:
        client = ScriptedClient([])
        result = compact_messages(
            client=client,  # type: ignore[arg-type]
            messages=[],
            context_window_tokens=10_000,
        )
        self.assertEqual(result.messages, [])
        self.assertEqual(result.messages_summarized, 0)

    def test_tool_pairs_are_summarized_away_without_orphans(self) -> None:
        """Prior assistant/tool pairs are compacted into the summary marker,
        so the post-compaction transcript never keeps an orphaned tool result.
        """
        client = ScriptedClient([ScriptedTurn(content="SUMM")])
        # Craft a transcript where the default cut (len-3) falls inside
        # a tool batch.
        messages = [
            ChatMessage(role="system", content="SYS"),
            ChatMessage(role="user", content="u1"),
            ChatMessage(
                role="assistant",
                content="",
                tool_calls=[_tc("c1", "read", {"path": "a.md"})],
            ),
            ChatMessage(
                role="tool",
                content="{}",
                tool_call_id="c1",
                name="read",
            ),
            ChatMessage(role="assistant", content="a1"),
            ChatMessage(role="user", content="u2"),
            ChatMessage(role="assistant", content="a2"),
            ChatMessage(role="user", content="current prompt"),
        ]
        result = compact_messages(
            client=client,  # type: ignore[arg-type]
            messages=messages,
            context_window_tokens=100_000,
            preserve_n_recent=3,
        )
        self.assertEqual(
            [m.role for m in result.messages],
            ["system", "compactionSummary", "user"],
        )
        self.assertEqual(result.messages[-1].content, "current prompt")
        self.assertNotIn("tool", [m.role for m in result.messages])


# ----------------------- SessionRunner integration -----------------------


class RunnerCompactionTests(unittest.TestCase):
    def _make_runner(
        self, root: str, client: Any, *, ctx_tokens: int, reserve: int = 1_000
    ) -> SessionRunner:
        ensure_agent_workspace(root, mark_setup_done=True)
        bootstrap = build_bootstrap_context(root, minimal=True)
        logger = SessionLogger.create(root, meta={"trigger": "test"})
        tools = build_default_tool_registry(root)
        return SessionRunner(
            client=client,
            bootstrap=bootstrap,
            tools=tools,
            logger=logger,
            context_window_tokens=ctx_tokens,
            max_turns=6,
            compaction_reserve_tokens=reserve,
        )

    def test_compaction_fires_when_gate_exceeds(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            client = CompactionAwareClient(
                [
                    # Main turn 0: huge content + tool call keeps loop alive.
                    ScriptedTurn(
                        content="x" * 80_000,
                        finish_reason="tool_calls",
                        tool_calls=[_tc("c1", "read", {"path": "SOUL.md"})],
                    ),
                    # Main turn 1 after compaction.
                    ScriptedTurn(content="done", finish_reason="stop"),
                ]
            )
            runner = self._make_runner(root, client, ctx_tokens=5_000, reserve=500)
            result = runner.run("go")
            self.assertGreaterEqual(result.compaction_count, 1)
            self.assertGreaterEqual(client.summary_calls, 1)
            # Check session log has compaction events
            log_path = runner.logger.log_path  # type: ignore[union-attr]
            with open(log_path) as f:
                events = [json.loads(line) for line in f]
            types = [e.get("type") for e in events]
            self.assertIn("compaction_start", types)
            self.assertIn("compaction_end", types)
            # compaction_start must carry route + overflow data
            start_evt = next(e for e in events if e.get("type") == "compaction_start")
            self.assertIn(start_evt["route"], (ROUTE_COMPACT_ONLY, ROUTE_COMPACT_THEN_TRUNCATE))
            self.assertGreater(start_evt["overflow_tokens"], 0)
            end_evt = next(e for e in events if e.get("type") == "compaction_end")
            self.assertIn("messages_summarized", end_evt)
            self.assertIn("messages_preserved", end_evt)

    def test_compaction_skipped_when_context_window_zero(self) -> None:
        """context_window_tokens=0 disables the gate entirely."""
        with tempfile.TemporaryDirectory() as root:
            client = ScriptedClient(
                [
                    ScriptedTurn(content="x" * 80_000, finish_reason="stop"),
                ]
            )
            runner = self._make_runner(root, client, ctx_tokens=0)
            result = runner.run("go")
            self.assertEqual(result.compaction_count, 0)

    def test_compaction_disabled_flag(self) -> None:
        """compaction_enabled=False disables even when window > 0."""
        with tempfile.TemporaryDirectory() as root:
            client = ScriptedClient(
                [
                    ScriptedTurn(
                        content="x" * 80_000,
                        finish_reason="tool_calls",
                        tool_calls=[_tc("c1", "read", {"path": "SOUL.md"})],
                    ),
                    ScriptedTurn(content="done", finish_reason="stop"),
                ]
            )
            runner = self._make_runner(root, client, ctx_tokens=5_000, reserve=500)
            runner.compaction_enabled = False
            result = runner.run("go")
            self.assertEqual(result.compaction_count, 0)

    def test_compaction_fires_on_turn_zero_of_carry_continuation(self) -> None:
        """Regression: in chain/carry mode, the compaction gate must run on
        turn 0 of the continued task. Earlier the runner had a `turn > 0`
        guard that skipped the gate on the first turn of every run() call —
        but in carry mode `messages` already contains the full prior-task
        transcript and may be far over budget at turn 0. Skipping the gate
        meant we paid for an inflated request before any compaction
        happened, which (when the model accepted the oversized prompt) led
        to behavioral drift across long chains.

        Verify by running r1 to grow the transcript past the gate, then
        r2 with carry where the FIRST LLM call must be preceded by a
        compaction.
        """
        with tempfile.TemporaryDirectory() as root:
            # r1 ends after one big-content stop turn — transcript inflates.
            # r2 turn 0 must trigger compaction (summarize) BEFORE the first
            # LLM call.
            client = CompactionAwareClient(
                [
                    ScriptedTurn(
                        content="x" * 80_000,
                        finish_reason="stop",
                    ),
                    ScriptedTurn(
                        content="done",
                        finish_reason="stop",
                    ),
                ]
            )
            runner = self._make_runner(root, client, ctx_tokens=5_000, reserve=500)
            r1 = runner.run("first prompt", close_logger=False)
            self.assertEqual(r1.compaction_count, 0)  # no chance to compact yet

            from openclaw_core.session.runner import SessionCarryState
            carry = SessionCarryState.from_result(r1)
            r2 = runner.run("second prompt", carry=carry, close_logger=True)
            self.assertGreaterEqual(
                r2.compaction_count, 1,
                "compaction must fire on turn 0 of a carry continuation "
                "when the carried transcript is over budget",
            )
            self.assertGreaterEqual(client.summary_calls, 1)


if __name__ == "__main__":
    unittest.main()
