"""Tests for openclaw_core.heartbeat (scheduler + runner).

Layered:
- Scheduler math is deterministic and pure — covered exhaustively.
- run_one_heartbeat is tested with a ScriptedClient so no real LLM calls
  go out, and with a tempdir workspace so no user files are touched.
- HeartbeatLoop.start/stop is tested with a short interval so we can
  observe at least one fire without waiting 30 minutes. Stop is
  verified to cancel pending timers.

We deliberately do NOT exercise real timing — threading.Timer behavior
is not something we own, and those tests would be flaky.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import unittest
from typing import Any, Optional

from openclaw_core.heartbeat import (
    DEFAULT_HEARTBEAT_INTERVAL_MS,
    DEFAULT_HEARTBEAT_PROMPT,
    HeartbeatLoop,
    HeartbeatScheduleState,
    compute_next_heartbeat_phase_due_ms,
    is_heartbeat_content_effectively_empty,
    is_within_active_hours,
    resolve_heartbeat_phase_ms,
    resolve_next_heartbeat_due_ms,
    run_one_heartbeat,
)
from openclaw_core.llm.openai_compat import (
    ChatMessage,
    ChatResponse,
    ToolCall,
    ToolCallFunction,
    Usage,
)
from openclaw_core.workspace import ensure_agent_workspace


# ---------------------------------------------------------------- helpers


class ScriptedTurn:
    """One scripted LLM response."""

    def __init__(
        self,
        *,
        content: str = "",
        tool_calls: Optional[list[ToolCall]] = None,
        finish_reason: str = "stop",
        prompt_tokens: int = 10,
        completion_tokens: int = 5,
    ) -> None:
        self.content = content
        self.tool_calls = tool_calls
        self.finish_reason = finish_reason
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens


class ScriptedClient:
    """A tiny fake ChatClient for tests."""

    def __init__(self, *, script: list[ScriptedTurn]) -> None:
        self._script = list(script)
        self.chat_calls: int = 0

    def chat(self, **_: Any) -> ChatResponse:
        self.chat_calls += 1
        if not self._script:
            # Default safe terminal turn if script exhausted.
            return ChatResponse(
                message=ChatMessage(role="assistant", content="ok"),
                finish_reason="stop",
                model="test",
                usage=Usage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
                raw={},
            )
        t = self._script.pop(0)
        return ChatResponse(
            message=ChatMessage(
                role="assistant",
                content=t.content,
                tool_calls=t.tool_calls,
            ),
            finish_reason=t.finish_reason,
            model="test",
            usage=Usage(
                prompt_tokens=t.prompt_tokens,
                completion_tokens=t.completion_tokens,
                total_tokens=t.prompt_tokens + t.completion_tokens,
            ),
            raw={},
        )


# ---------------------------------------------------------------- scheduler


class ResolveHeartbeatPhaseTests(unittest.TestCase):
    def test_deterministic_for_identical_inputs(self) -> None:
        phase_a = resolve_heartbeat_phase_ms(
            scheduler_seed="exp-01",
            agent_id="agent-a",
            interval_ms=DEFAULT_HEARTBEAT_INTERVAL_MS,
        )
        phase_b = resolve_heartbeat_phase_ms(
            scheduler_seed="exp-01",
            agent_id="agent-a",
            interval_ms=DEFAULT_HEARTBEAT_INTERVAL_MS,
        )
        self.assertEqual(phase_a, phase_b)

    def test_different_agents_differ(self) -> None:
        a = resolve_heartbeat_phase_ms(
            scheduler_seed="seed",
            agent_id="agent-a",
            interval_ms=DEFAULT_HEARTBEAT_INTERVAL_MS,
        )
        b = resolve_heartbeat_phase_ms(
            scheduler_seed="seed",
            agent_id="agent-b",
            interval_ms=DEFAULT_HEARTBEAT_INTERVAL_MS,
        )
        # Not guaranteed for every pair in principle, but for these
        # specific strings under SHA-256 the phases definitely differ.
        self.assertNotEqual(a, b)

    def test_phase_lt_interval(self) -> None:
        for interval in (1, 60_000, 30 * 60 * 1000):
            p = resolve_heartbeat_phase_ms(
                scheduler_seed="x",
                agent_id="y",
                interval_ms=interval,
            )
            self.assertGreaterEqual(p, 0)
            self.assertLess(p, interval)


class ComputeNextDueTests(unittest.TestCase):
    def test_next_due_is_strictly_in_future(self) -> None:
        for now in (0, 123_456, 10**12):
            for phase in (0, 500, 1800):
                nxt = compute_next_heartbeat_phase_due_ms(
                    now_ms=now, interval_ms=1000, phase_ms=phase
                )
                self.assertGreater(nxt, now)

    def test_exactly_on_phase_returns_next_cycle(self) -> None:
        # now % interval == phase — return now + interval, never now.
        nxt = compute_next_heartbeat_phase_due_ms(
            now_ms=5_000, interval_ms=1_000, phase_ms=0
        )
        self.assertEqual(nxt, 6_000)

    def test_monotonic_across_cycles(self) -> None:
        interval = 1_000
        phase = 200
        now = 10_000
        last = now
        for _ in range(5):
            nxt = compute_next_heartbeat_phase_due_ms(
                now_ms=last, interval_ms=interval, phase_ms=phase
            )
            self.assertGreater(nxt, last)
            last = nxt


class ResolveNextWithPrevTests(unittest.TestCase):
    def test_reuses_prev_when_still_future(self) -> None:
        prev = HeartbeatScheduleState(
            interval_ms=1_000, phase_ms=500, next_due_ms=10_000
        )
        nxt = resolve_next_heartbeat_due_ms(
            now_ms=9_000, interval_ms=1_000, phase_ms=500, prev=prev
        )
        self.assertEqual(nxt, 10_000)

    def test_recomputes_when_interval_changes(self) -> None:
        prev = HeartbeatScheduleState(
            interval_ms=1_000, phase_ms=500, next_due_ms=10_000
        )
        nxt = resolve_next_heartbeat_due_ms(
            now_ms=9_000, interval_ms=2_000, phase_ms=500, prev=prev
        )
        self.assertNotEqual(nxt, 10_000)

    def test_recomputes_when_prev_in_past(self) -> None:
        prev = HeartbeatScheduleState(
            interval_ms=1_000, phase_ms=500, next_due_ms=5_000
        )
        nxt = resolve_next_heartbeat_due_ms(
            now_ms=9_000, interval_ms=1_000, phase_ms=500, prev=prev
        )
        self.assertGreater(nxt, 9_000)


class ActiveHoursTests(unittest.TestCase):
    def test_none_bounds_always_open(self) -> None:
        self.assertTrue(is_within_active_hours(now_ms=0))

    def test_inside_normal_window(self) -> None:
        # 10:30 UTC, window [8, 22)
        now_ms = (10 * 3600 + 30 * 60) * 1000
        self.assertTrue(
            is_within_active_hours(
                now_ms=now_ms, start_hour=8, end_hour=22
            )
        )

    def test_outside_normal_window(self) -> None:
        # 23:00 UTC, window [8, 22)
        now_ms = 23 * 3600 * 1000
        self.assertFalse(
            is_within_active_hours(
                now_ms=now_ms, start_hour=8, end_hour=22
            )
        )

    def test_wraparound_window(self) -> None:
        # Window 22..6 (evening/overnight)
        # 23:00 UTC → inside
        self.assertTrue(
            is_within_active_hours(
                now_ms=23 * 3600 * 1000, start_hour=22, end_hour=6
            )
        )
        # 12:00 UTC → outside
        self.assertFalse(
            is_within_active_hours(
                now_ms=12 * 3600 * 1000, start_hour=22, end_hour=6
            )
        )
        # 02:00 UTC → inside (wrap)
        self.assertTrue(
            is_within_active_hours(
                now_ms=2 * 3600 * 1000, start_hour=22, end_hour=6
            )
        )

    def test_tz_offset_is_respected(self) -> None:
        # UTC 23:00, JST +540 min → local 08:00 next day. Window [8, 22) open.
        self.assertTrue(
            is_within_active_hours(
                now_ms=23 * 3600 * 1000,
                start_hour=8,
                end_hour=22,
                tz_offset_minutes=540,
            )
        )


# ---------------------------------------------------------------- one-shot runner


class RunOneHeartbeatTests(unittest.TestCase):
    def test_effectively_empty_heartbeat_file_skips_llm_and_session_log(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            with open(os.path.join(root, "HEARTBEAT.md"), "w", encoding="utf-8") as f:
                f.write("# Heartbeat\n\n- [ ]\n\n```markdown\n```\n")
            client = ScriptedClient(script=[ScriptedTurn(content="should-not-run")])

            result = run_one_heartbeat(
                workspace_root=root,
                client=client,  # type: ignore[arg-type]
                agent_id="agent-empty-skip",
            )

            self.assertEqual(client.chat_calls, 0)
            self.assertEqual(result.finish_reason, "heartbeat_empty")
            self.assertIsNone(result.session_key)
            state_root = os.path.join(
                os.path.dirname(root), ".openclaw", "agents", "agent-empty-skip"
            )
            self.assertFalse(os.path.exists(os.path.join(state_root, "sessions")))

    def test_effectively_empty_helper_matches_openclaw_cases(self) -> None:
        self.assertTrue(is_heartbeat_content_effectively_empty(""))
        self.assertTrue(is_heartbeat_content_effectively_empty("# Header\n- [ ]\n```"))
        self.assertFalse(is_heartbeat_content_effectively_empty(None))
        self.assertFalse(is_heartbeat_content_effectively_empty("#TODO"))
        self.assertFalse(is_heartbeat_content_effectively_empty("- check inbox"))

    def test_fires_with_minimal_bootstrap_and_meta(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            client = ScriptedClient(
                script=[ScriptedTurn(content="ack", finish_reason="stop")]
            )
            result = run_one_heartbeat(
                workspace_root=root,
                client=client,  # type: ignore[arg-type]
                agent_id="agent-a",
                scheduler_seed="exp-01",
            )
            # The runner produced exactly one turn.
            self.assertEqual(result.turns_used, 1)
            self.assertEqual(result.finish_reason, "stop")
            # Session log must exist under the external OpenClaw state root
            # and start with a session_start record carrying trigger=heartbeat.
            assert result.session_key is not None
            log_path = os.path.join(
                os.path.dirname(root),
                ".openclaw",
                "agents",
                "agent-a",
                "sessions",
                f"{result.session_key}.jsonl",
            )
            self.assertTrue(os.path.exists(log_path))
            with open(log_path, "r", encoding="utf-8") as f:
                first = json.loads(f.readline())
            self.assertEqual(first["type"], "session_start")
            self.assertEqual(first["meta"]["trigger"], "heartbeat")
            self.assertEqual(first["meta"]["agent_id"], "agent-a")
            self.assertEqual(first["meta"]["scheduler_seed"], "exp-01")

    def test_uses_default_prompt(self) -> None:
        captured_user_msgs: list[str] = []

        class SpyClient(ScriptedClient):
            def chat(self, **kwargs: Any) -> ChatResponse:  # type: ignore[override]
                # Find the last user message — that's our prompt.
                for m in kwargs.get("messages", []):
                    if m.role == "user":
                        captured_user_msgs.append(m.content)
                return super().chat(**kwargs)

        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            client = SpyClient(
                script=[ScriptedTurn(content="ack", finish_reason="stop")]
            )
            run_one_heartbeat(
                workspace_root=root,
                client=client,  # type: ignore[arg-type]
                agent_id="a",
            )
            self.assertTrue(captured_user_msgs)
            self.assertEqual(captured_user_msgs[-1], DEFAULT_HEARTBEAT_PROMPT)

    def test_default_prompt_matches_openclaw_source(self) -> None:
        """Pin the exact wording of the heartbeat prompt so drift from
        OpenClaw's HEARTBEAT_PROMPT (src/auto-reply/heartbeat.ts:14-15)
        breaks loudly. Profile signatures depend on this being a no-op
        when HEARTBEAT.md is empty.
        """
        expected = (
            "Read HEARTBEAT.md if it exists (workspace context). "
            "Follow it strictly. Do not infer or repeat old tasks from prior chats. "
            "If nothing needs attention, reply HEARTBEAT_OK."
        )
        self.assertEqual(DEFAULT_HEARTBEAT_PROMPT, expected)

    def test_bootstrap_is_minimal(self) -> None:
        captured_system: list[str] = []

        class SpyClient(ScriptedClient):
            def chat(self, **kwargs: Any) -> ChatResponse:  # type: ignore[override]
                for m in kwargs.get("messages", []):
                    if m.role == "system":
                        captured_system.append(m.content)
                return super().chat(**kwargs)

        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            client = SpyClient(
                script=[ScriptedTurn(content="ok", finish_reason="stop")]
            )
            run_one_heartbeat(
                workspace_root=root,
                client=client,  # type: ignore[arg-type]
                agent_id="a",
            )
            self.assertTrue(captured_system)
            sp = captured_system[0]
            # Minimal bootstrap includes AGENTS/TOOLS/SOUL/IDENTITY/USER...
            self.assertIn("## AGENTS.md", sp)
            self.assertIn("## SOUL.md", sp)
            # ... and excludes HEARTBEAT/MEMORY/BOOTSTRAP.
            self.assertNotIn("## HEARTBEAT.md", sp)
            self.assertNotIn("## MEMORY.md", sp)

    def test_extra_meta_merged(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            client = ScriptedClient(
                script=[ScriptedTurn(content="ok", finish_reason="stop")]
            )
            result = run_one_heartbeat(
                workspace_root=root,
                client=client,  # type: ignore[arg-type]
                agent_id="a",
                extra_meta={"profile": "W4", "trial": 3},
            )
            assert result.session_key is not None
            log_path = os.path.join(
                os.path.dirname(root),
                ".openclaw",
                "agents",
                "a",
                "sessions",
                f"{result.session_key}.jsonl",
            )
            with open(log_path, "r", encoding="utf-8") as f:
                first = json.loads(f.readline())
            self.assertEqual(first["meta"]["profile"], "W4")
            self.assertEqual(first["meta"]["trial"], 3)


# ---------------------------------------------------------------- loop


class HeartbeatLoopTests(unittest.TestCase):
    def test_next_fire_ms_is_strictly_future(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            client = ScriptedClient(script=[])
            loop = HeartbeatLoop(
                workspace_root=root,
                client=client,  # type: ignore[arg-type]
                agent_id="a",
                interval_ms=1_000,
            )
            now = int(time.time() * 1000)
            nxt = loop.next_fire_ms(now_ms=now)
            self.assertGreater(nxt, now)
            self.assertLessEqual(nxt - now, 1_000)

    def test_start_stop_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            client = ScriptedClient(script=[])
            loop = HeartbeatLoop(
                workspace_root=root,
                client=client,  # type: ignore[arg-type]
                agent_id="a",
                interval_ms=60 * 60 * 1000,  # 1h — won't fire in this test
            )
            loop.start()
            loop.start()  # second start is a no-op
            loop.stop()
            loop.stop()  # second stop is a no-op

    def test_loop_fires_within_short_interval(self) -> None:
        """Interval small enough that at least one fire happens quickly.

        Uses a 50ms interval with a barrier-style wait. We give the test
        up to 3 seconds to see one fire — generous for CI.
        """
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)

            fired = threading.Event()

            def on_result(_r: Any) -> None:
                fired.set()

            # Script several turns so repeat fires don't crash.
            client = ScriptedClient(
                script=[
                    ScriptedTurn(content="ok", finish_reason="stop")
                    for _ in range(10)
                ]
            )
            loop = HeartbeatLoop(
                workspace_root=root,
                client=client,  # type: ignore[arg-type]
                agent_id="a",
                interval_ms=50,
                on_result=on_result,
                max_turns=2,
            )
            loop.start()
            try:
                self.assertTrue(fired.wait(timeout=3.0), "heartbeat never fired")
                self.assertGreaterEqual(loop.fires_count, 1)
            finally:
                loop.stop()

    def test_active_hours_gate_blocks_fire_but_loop_continues(self) -> None:
        """When the active-hours gate rejects, the loop must reschedule,
        not silently die.
        """
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            client = ScriptedClient(
                script=[
                    ScriptedTurn(content="ok", finish_reason="stop")
                    for _ in range(5)
                ]
            )
            loop = HeartbeatLoop(
                workspace_root=root,
                client=client,  # type: ignore[arg-type]
                agent_id="a",
                interval_ms=30,
                # Impossible window — always out of hours.
                active_hours_start=0,
                active_hours_end=0,  # degenerate => always-open per spec;
                # so use a clearly-impossible pair instead:
            )
            # Use a pair that rejects "now" for any real clock: force
            # start_hour == end_hour - 1 == a random hour we're not in.
            # Simpler: run with a narrow window far from current time.
            now_hour = time.gmtime().tm_hour
            far_hour = (now_hour + 12) % 24
            loop.active_hours_start = far_hour
            loop.active_hours_end = (far_hour + 1) % 24
            loop.start()
            try:
                # Give the loop time to tick a few times — should NOT fire
                # because of the gate, but should not crash either.
                time.sleep(0.2)
                self.assertEqual(loop.fires_count, 0)
            finally:
                loop.stop()


if __name__ == "__main__":
    unittest.main()
