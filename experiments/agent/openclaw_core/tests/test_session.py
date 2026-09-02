"""Unit tests for openclaw_core.session.

All tests are offline — no real LLM calls. We inject a fake ChatClient that
returns scripted ChatResponse objects so we can exercise:
- Sequential tool execution (explicit ordering guarantee)
- Every tool_call_id gets a tool-role reply even on failure
- JSON parse errors in tool arguments don't kill the loop
- Unknown tools surface as tool-role errors, loop continues
- Tool exceptions are caught, surfaced, loop continues
- Bootstrap system prompt is injected as the first message
- Session log is written in order (session_start → user → assistant → tool → ...)
- Memory-flush gate fires when threshold exceeded (and not before)
- max_turns is honored

Plus the pure units: bootstrap rendering, session key format, context hash dedup.
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
    compute_context_hash,
    new_session_key,
    render_system_prompt,
    should_run_memory_flush,
)
from openclaw_core.session.log import default_state_root
from openclaw_core.session.runner import (
    SessionCarryState,
    build_default_tool_registry,
)
from openclaw_core.workspace import (
    BootstrapEntry,
    ensure_agent_workspace,
)


# ------------------------------------------------------ fake LLM


@dataclass
class ScriptedTurn:
    """One scripted LLM reply."""

    content: str = ""
    tool_calls: Optional[list[ToolCall]] = None
    finish_reason: Optional[str] = "stop"
    prompt_tokens: int = 100
    completion_tokens: int = 20


class ScriptedClient:
    """Fake ChatClient that pops the next ScriptedTurn from a list."""

    def __init__(self, script: list[ScriptedTurn]):
        self.script = list(script)
        self.captured_messages: list[list[ChatMessage]] = []
        self.captured_tool_choice: list[Any] = []

    def chat(
        self,
        messages: list[ChatMessage],
        *,
        tools: Optional[list[Any]] = None,
        tool_choice: Optional[Any] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        model: Optional[str] = None,
        extra_body: Optional[dict[str, Any]] = None,
    ) -> ChatResponse:
        # Capture a deep-ish copy of messages for post-hoc assertions.
        self.captured_messages.append(list(messages))
        self.captured_tool_choice.append(tool_choice)
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


def _tc(id: str, name: str, args: dict) -> ToolCall:
    return ToolCall(
        id=id,
        type="function",
        function=ToolCallFunction(name=name, arguments=json.dumps(args)),
    )


# ------------------------------------------------------ bootstrap/prompt tests


class RenderSystemPromptTests(unittest.TestCase):
    def test_renders_openclaw_style_project_context(self) -> None:
        entries = [
            BootstrapEntry(filename="SOUL.md", content="soul body", identity="i1"),
            BootstrapEntry(filename="AGENTS.md", content="agents body\n", identity="i2"),
        ]
        out = render_system_prompt(entries)
        self.assertIn("You are a personal assistant running inside OpenClaw.", out)
        self.assertIn("## Tooling", out)
        self.assertIn("## Workspace Files (injected)", out)
        self.assertIn("# Project Context", out)
        self.assertIn("## SOUL.md", out)
        self.assertIn("## AGENTS.md", out)
        self.assertIn("soul body", out)
        self.assertIn("agents body", out)
        self.assertIn("## Runtime", out)

    def test_skips_missing_entries(self) -> None:
        entries = [
            BootstrapEntry(filename="SOUL.md", content=None, identity=None),
            BootstrapEntry(filename="AGENTS.md", content="agents", identity="i1"),
        ]
        out = render_system_prompt(entries)
        self.assertNotIn("## SOUL.md", out)
        self.assertIn("## AGENTS.md", out)

    def test_deterministic(self) -> None:
        entries = [
            BootstrapEntry(filename="SOUL.md", content="x", identity="i1"),
            BootstrapEntry(filename="AGENTS.md", content="y", identity="i2"),
        ]
        self.assertEqual(render_system_prompt(entries), render_system_prompt(entries))


class BuildBootstrapContextTests(unittest.TestCase):
    def test_minimal_vs_full_mode(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            full = build_bootstrap_context(root, minimal=False)
            minimal = build_bootstrap_context(root, minimal=True)
            # Full should have MORE files than minimal (MEMORY, HEARTBEAT etc.).
            self.assertGreater(
                len(full.present_filenames()), len(minimal.present_filenames())
            )
            self.assertFalse(full.minimal)
            self.assertTrue(minimal.minimal)


# ------------------------------------------------------ session log tests


class SessionLoggerTests(unittest.TestCase):
    def test_logger_writes_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            logger = SessionLogger.create(root, meta={"profile": "W1"})
            logger.log_user("hi")
            logger.log_assistant(
                content="hello",
                tool_calls=[
                    {
                        "id": "tc1",
                        "type": "function",
                        "function": {"name": "read", "arguments": "{}"},
                    }
                ],
                finish_reason="tool_calls",
                usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            )
            logger.log_tool_result(
                tool_call_id="tc1", name="read", content='{"ok":true}', ok=True
            )
            logger.close()

            with open(logger.log_path) as f:
                lines = [json.loads(line) for line in f if line.strip()]

            # session_start, user, assistant, tool, session_end.
            self.assertEqual(len(lines), 5)
            self.assertEqual(lines[0]["type"], "session_start")
            self.assertEqual(lines[0]["meta"], {"profile": "W1"})
            self.assertEqual(lines[1]["role"], "user")
            self.assertEqual(lines[2]["role"], "assistant")
            self.assertEqual(lines[2]["tool_calls"][0]["id"], "tc1")
            self.assertEqual(lines[3]["role"], "tool")
            self.assertEqual(lines[4]["type"], "session_end")
            # All records carry timestamps.
            for rec in lines:
                self.assertIn("timestamp", rec)

    def test_session_key_format(self) -> None:
        key = new_session_key()
        # session-YYYYMMDDThhmmss-<6 hex>
        parts = key.split("-")
        self.assertEqual(parts[0], "session")
        self.assertEqual(len(parts[1]), 15)  # YYYYMMDDThhmmss
        self.assertEqual(len(parts[2]), 6)

    def test_log_path_under_external_openclaw_state_root(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            logger = SessionLogger.create(root)
            expected_state_root = default_state_root(root)
            self.assertTrue(
                logger.log_path.startswith(
                    os.path.join(expected_state_root, "sessions")
                )
            )
            self.assertFalse(logger.log_path.startswith(root + os.sep))
            self.assertEqual(logger.state_root, expected_state_root)


# ------------------------------------------------------ memory-flush tests


class MemoryFlushTests(unittest.TestCase):
    def test_hash_depends_on_tail(self) -> None:
        a = [ChatMessage("user", "hi"), ChatMessage("assistant", "hello")]
        b = [ChatMessage("user", "hi"), ChatMessage("assistant", "hola")]
        self.assertNotEqual(compute_context_hash(a), compute_context_hash(b))

    def test_hash_empty_returns_none(self) -> None:
        self.assertIsNone(compute_context_hash([]))

    def test_below_threshold_no_flush(self) -> None:
        d = should_run_memory_flush(
            total_tokens=1000,
            context_window_tokens=200_000,
            messages=[ChatMessage("user", "hi")],
        )
        self.assertFalse(d.should_flush)
        self.assertEqual(d.reason, "below_threshold")

    def test_above_threshold_flushes(self) -> None:
        d = should_run_memory_flush(
            total_tokens=190_000,
            context_window_tokens=200_000,
            messages=[ChatMessage("user", "hi")],
        )
        self.assertTrue(d.should_flush)

    def test_dedup_skips_repeat_flush(self) -> None:
        msgs = [ChatMessage("user", "hi"), ChatMessage("assistant", "hello")]
        first = should_run_memory_flush(
            total_tokens=190_000,
            context_window_tokens=200_000,
            messages=msgs,
        )
        self.assertTrue(first.should_flush)
        second = should_run_memory_flush(
            total_tokens=190_000,
            context_window_tokens=200_000,
            messages=msgs,
            last_flushed_hash=first.context_hash,
        )
        self.assertFalse(second.should_flush)
        self.assertEqual(second.reason, "already_flushed_for_current_tail")


# ------------------------------------------------------ runner tests


class RunnerSequentialToolExecutionTests(unittest.TestCase):
    def test_tools_execute_in_order(self) -> None:
        # Two tool calls in a single turn, both writes. We verify BOTH executed
        # and the file state shows the SECOND as the final value — proving
        # sequential execution in the order they were returned.
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            tools = build_default_tool_registry(root)
            client = ScriptedClient(
                script=[
                    ScriptedTurn(
                        tool_calls=[
                            _tc("tc1", "write", {"path": "x.txt", "content": "first\n"}),
                            _tc("tc2", "write", {"path": "x.txt", "content": "second\n"}),
                        ],
                        finish_reason="tool_calls",
                    ),
                    ScriptedTurn(content="done", finish_reason="stop"),
                ]
            )
            bootstrap = build_bootstrap_context(root)
            runner = SessionRunner(
                client=client,  # type: ignore[arg-type]
                bootstrap=bootstrap,
                tools=tools,
            )
            result = runner.run("write x.txt twice")

            # File must have "second" (the SECOND call), not "first".
            with open(os.path.join(root, "x.txt")) as f:
                self.assertEqual(f.read(), "second\n")
            # Both executions recorded, in order.
            self.assertEqual(len(result.tool_executions), 2)
            self.assertEqual(result.tool_executions[0].tool_call_id, "tc1")
            self.assertEqual(result.tool_executions[1].tool_call_id, "tc2")
            self.assertTrue(result.tool_executions[0].ok)
            self.assertTrue(result.tool_executions[1].ok)

    def test_every_tool_call_gets_tool_role_reply(self) -> None:
        # Even when a tool fails, we must append a tool-role message for
        # that tool_call_id. Otherwise the next chat() call would 400.
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            tools = build_default_tool_registry(root)
            client = ScriptedClient(
                script=[
                    ScriptedTurn(
                        tool_calls=[
                            _tc("bad", "read", {"path": "does_not_exist.txt"}),
                            _tc("good", "write", {"path": "ok.txt", "content": "hi"}),
                        ],
                        finish_reason="tool_calls",
                    ),
                    ScriptedTurn(content="done", finish_reason="stop"),
                ]
            )
            bootstrap = build_bootstrap_context(root)
            runner = SessionRunner(
                client=client,  # type: ignore[arg-type]
                bootstrap=bootstrap,
                tools=tools,
            )
            result = runner.run("try both")

            # Second LLM call must have been made (the runner continued).
            self.assertEqual(len(client.captured_messages), 2)
            # Second turn's transcript must include BOTH tool replies.
            second_msgs = client.captured_messages[1]
            tool_reply_ids = [
                m.tool_call_id for m in second_msgs if m.role == "tool"
            ]
            self.assertEqual(set(tool_reply_ids), {"bad", "good"})

            # Bad call marked ok=False, good call ok=True.
            exec_by_id = {e.tool_call_id: e for e in result.tool_executions}
            self.assertFalse(exec_by_id["bad"].ok)
            self.assertTrue(exec_by_id["good"].ok)


class RunnerDispatchErrorTests(unittest.TestCase):
    def test_unknown_tool_surfaces_as_tool_role_error(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            tools = build_default_tool_registry(root)
            client = ScriptedClient(
                script=[
                    ScriptedTurn(
                        tool_calls=[_tc("t1", "make_coffee", {})],
                        finish_reason="tool_calls",
                    ),
                    ScriptedTurn(content="ok", finish_reason="stop"),
                ]
            )
            bootstrap = build_bootstrap_context(root)
            runner = SessionRunner(
                client=client,  # type: ignore[arg-type]
                bootstrap=bootstrap,
                tools=tools,
            )
            result = runner.run("do a thing")

            # Loop continued to second LLM call.
            self.assertEqual(len(client.captured_messages), 2)
            # One exec record, ok=False, error mentions unknown tool.
            self.assertEqual(len(result.tool_executions), 1)
            rec = result.tool_executions[0]
            self.assertFalse(rec.ok)
            assert rec.error is not None
            self.assertIn("unknown tool", rec.error)

    def test_bad_json_arguments_surfaces_as_tool_role_error(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            tools = build_default_tool_registry(root)
            # Craft a tool call with invalid JSON in arguments.
            bad_tc = ToolCall(
                id="t1",
                type="function",
                function=ToolCallFunction(
                    name="read", arguments="{bad json"
                ),
            )
            client = ScriptedClient(
                script=[
                    ScriptedTurn(
                        tool_calls=[bad_tc], finish_reason="tool_calls"
                    ),
                    ScriptedTurn(content="ok", finish_reason="stop"),
                ]
            )
            bootstrap = build_bootstrap_context(root)
            runner = SessionRunner(
                client=client,  # type: ignore[arg-type]
                bootstrap=bootstrap,
                tools=tools,
            )
            result = runner.run("x")
            self.assertEqual(len(client.captured_messages), 2)
            self.assertFalse(result.tool_executions[0].ok)
            assert result.tool_executions[0].error is not None
            self.assertIn("JSON parse failed", result.tool_executions[0].error)

    def test_tool_exception_does_not_kill_loop(self) -> None:
        def explode(**kwargs: Any) -> Any:
            raise RuntimeError("kaboom")

        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            tools = build_default_tool_registry(root)
            tools["explode"] = explode
            client = ScriptedClient(
                script=[
                    ScriptedTurn(
                        tool_calls=[_tc("t1", "explode", {})],
                        finish_reason="tool_calls",
                    ),
                    ScriptedTurn(content="recovered", finish_reason="stop"),
                ]
            )
            bootstrap = build_bootstrap_context(root)
            runner = SessionRunner(
                client=client,  # type: ignore[arg-type]
                bootstrap=bootstrap,
                tools=tools,
            )
            result = runner.run("try explode")
            self.assertEqual(len(client.captured_messages), 2)
            self.assertFalse(result.tool_executions[0].ok)
            assert result.tool_executions[0].error is not None
            self.assertIn("kaboom", result.tool_executions[0].error)


class RunnerBootstrapTests(unittest.TestCase):
    def test_system_prompt_is_first_message(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            tools = build_default_tool_registry(root)
            client = ScriptedClient(
                script=[ScriptedTurn(content="hi", finish_reason="stop")]
            )
            bootstrap = build_bootstrap_context(root)
            runner = SessionRunner(
                client=client,  # type: ignore[arg-type]
                bootstrap=bootstrap,
                tools=tools,
            )
            runner.run("hello")
            first_call_msgs = client.captured_messages[0]
            self.assertEqual(first_call_msgs[0].role, "system")
            self.assertIn(
                bootstrap.rendered_system_prompt, first_call_msgs[0].content
            )
            self.assertEqual(first_call_msgs[1].role, "user")
            self.assertEqual(first_call_msgs[1].content, "hello")


class RunnerMemoryFlushTests(unittest.TestCase):
    def test_memory_flush_triggered_when_gate_fires(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            tools = build_default_tool_registry(root)
            # Very high token usage per turn — triggers flush after turn 1.
            # threshold = 200_000 - 16_000 reserve - 4_000 soft = 180_000,
            # so current_tokens (prompt+completion) must exceed 180_000.
            client = ScriptedClient(
                script=[
                    ScriptedTurn(
                        tool_calls=[
                            _tc("t1", "read", {"path": "SOUL.md"})
                        ],
                        finish_reason="tool_calls",
                        prompt_tokens=100_000,
                        completion_tokens=85_000,
                    ),
                    ScriptedTurn(content="done", finish_reason="stop",
                                 prompt_tokens=10, completion_tokens=10),
                ]
            )
            bootstrap = build_bootstrap_context(root)
            runner = SessionRunner(
                client=client,  # type: ignore[arg-type]
                bootstrap=bootstrap,
                tools=tools,
                context_window_tokens=200_000,
            )
            result = runner.run("x")
            self.assertTrue(result.memory_flush_triggered)

    def test_memory_flush_gate_uses_cumulative_session_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            tools = build_default_tool_registry(root)
            # Each individual tool-call response is below the 180k threshold,
            # but the cumulative session usage reaches it after turn 2.
            client = ScriptedClient(
                script=[
                    ScriptedTurn(
                        tool_calls=[_tc("t1", "read", {"path": "SOUL.md"})],
                        finish_reason="tool_calls",
                        prompt_tokens=90_000,
                        completion_tokens=50_000,
                    ),
                    ScriptedTurn(
                        tool_calls=[_tc("t2", "read", {"path": "AGENTS.md"})],
                        finish_reason="tool_calls",
                        prompt_tokens=30_000,
                        completion_tokens=10_000,
                    ),
                    ScriptedTurn(content="done", finish_reason="stop"),
                ]
            )
            bootstrap = build_bootstrap_context(root)
            runner = SessionRunner(
                client=client,  # type: ignore[arg-type]
                bootstrap=bootstrap,
                tools=tools,
                context_window_tokens=200_000,
            )
            result = runner.run("x")
            self.assertTrue(result.memory_flush_triggered)

    def test_memory_flush_subsession_writes_dated_memory_file(self) -> None:
        """When workspace_root is supplied, a triggered memory-flush must
        actually execute a sub-session that writes to the upstream-canonical
        dated target `memory/YYYY-MM-DD.md` (NOT MEMORY.md).

        This test pins the target via `memory_flush_relative_path` so it
        is deterministic across runs regardless of the calendar date.
        MEMORY.md remains untouched (treated as read-only bootstrap per
        the upstream MEMORY_FLUSH_READ_ONLY_HINT).

        The sub-session's CHILD jsonl is distinct from the parent's and
        carries trigger="memory" + the target_path in its session_start
        record. The target is modified via a DIRECT write (no .tmp+rename)
        — the signature the paper's §4.2 dichotomy depends on.
        """
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            tools = build_default_tool_registry(root)

            # Pin the dated target so the test is deterministic.
            pinned_target = "memory/2026-04-22.md"

            # Snapshot MEMORY.md so we can assert it's untouched.
            memory_md_path = os.path.join(root, "MEMORY.md")
            with open(memory_md_path) as f:
                original_memory_md = f.read()

            # Main session: one high-token tool-call turn, then stop.
            # Flush-subsession: one write + one stop.
            client = ScriptedClient(
                script=[
                    # Main turn 0: forces memory-flush gate to fire.
                    ScriptedTurn(
                        tool_calls=[
                            _tc("t1", "read", {"path": "SOUL.md"})
                        ],
                        finish_reason="tool_calls",
                        prompt_tokens=100_000,
                        completion_tokens=85_000,
                    ),
                    # Flush sub-session turn 0: write the dated target.
                    ScriptedTurn(
                        tool_calls=[
                            _tc(
                                "fw1", "write",
                                {
                                    "path": pinned_target,
                                    "content": "- fact: user prefers terse output\n",
                                },
                            )
                        ],
                        finish_reason="tool_calls",
                        prompt_tokens=10, completion_tokens=10,
                    ),
                    # Flush sub-session turn 1: stop.
                    ScriptedTurn(
                        content="done", finish_reason="stop",
                        prompt_tokens=10, completion_tokens=5,
                    ),
                    # Main turn 1: stop.
                    ScriptedTurn(
                        content="main done", finish_reason="stop",
                        prompt_tokens=10, completion_tokens=10,
                    ),
                ]
            )
            bootstrap = build_bootstrap_context(root)
            parent_logger = SessionLogger.create(
                root, meta={"trigger": "task"}
            )
            runner = SessionRunner(
                client=client,  # type: ignore[arg-type]
                bootstrap=bootstrap,
                tools=tools,
                logger=parent_logger,
                context_window_tokens=200_000,
                workspace_root=root,  # enables the subsession
                memory_flush_relative_path=pinned_target,  # deterministic
            )
            result = runner.run("x")

            self.assertTrue(result.memory_flush_triggered)
            self.assertEqual(result.memory_flush_count, 1)
            self.assertEqual(result.memory_flush_silent_count, 0)

            # Dated target should exist with our content appended.
            target_path = os.path.join(root, pinned_target)
            self.assertTrue(
                os.path.exists(target_path),
                f"expected {target_path} to exist",
            )
            with open(target_path) as f:
                body = f.read()
            self.assertIn("user prefers terse output", body)

            # MEMORY.md must be untouched — it is a read-only bootstrap
            # file under the upstream memory-flush contract.
            with open(memory_md_path) as f:
                self.assertEqual(f.read(), original_memory_md)

            # Parent session log should contain the lifecycle events.
            parent_log_path = parent_logger.log_path
            with open(parent_log_path) as f:
                parent_records = [json.loads(ln) for ln in f if ln.strip()]
            parent_events = [
                r.get("type") for r in parent_records if r.get("type")
            ]
            self.assertIn("memory_flush_triggered", parent_events)
            self.assertIn("memory_flush_subsession_started", parent_events)
            self.assertIn("memory_flush_subsession_completed", parent_events)

            # The `memory_flush_subsession_started` event should carry the
            # resolved dated target as its target_path payload.
            started_evt = next(
                r for r in parent_records
                if r.get("type") == "memory_flush_subsession_started"
            )
            self.assertEqual(started_evt.get("target_path"), pinned_target)

            # Find the sub-session's own log file (co-located in the same
            # external OpenClaw state root, different key).
            sess_dir = os.path.join(parent_logger.state_root, "sessions")
            all_logs = sorted(
                os.path.join(sess_dir, f)
                for f in os.listdir(sess_dir)
                if f.endswith(".jsonl")
            )
            self.assertEqual(
                len(all_logs), 2,
                f"expected parent + sub-session log, got {all_logs}"
            )
            sub_log = next(p for p in all_logs if p != parent_log_path)
            with open(sub_log) as f:
                sub_records = [json.loads(ln) for ln in f if ln.strip()]
            sub_start = next(
                r for r in sub_records if r.get("type") == "session_start"
            )
            self.assertEqual(sub_start["meta"].get("trigger"), "memory")
            self.assertEqual(
                sub_start["meta"].get("parent_session_key"),
                parent_logger.session_key,
            )
            self.assertEqual(
                sub_start["meta"].get("target_path"), pinned_target
            )

    def test_memory_flush_subsession_refuses_write_outside_memory_target(self) -> None:
        """The sub-session's write tool is append-only to the dated
        `memory/YYYY-MM-DD.md` target — attempts to write elsewhere,
        INCLUDING to MEMORY.md (which is now treated as a read-only
        bootstrap/reference file), must fail with a validation error and
        NOT actually land on disk. This is the SPEC §6.4 boundary plus
        the upstream MEMORY_FLUSH_READ_ONLY_HINT contract."""
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            tools = build_default_tool_registry(root)

            pinned_target = "memory/2026-04-22.md"

            client = ScriptedClient(
                script=[
                    # Main turn 0: trigger flush.
                    ScriptedTurn(
                        tool_calls=[
                            _tc("t1", "read", {"path": "SOUL.md"})
                        ],
                        finish_reason="tool_calls",
                        prompt_tokens=100_000, completion_tokens=85_000,
                    ),
                    # Sub turn 0: try to write SOUL.md AND MEMORY.md
                    # (both disallowed). We issue both tool calls in the
                    # same turn so we can assert the wrapper rejects them
                    # individually without writing either.
                    ScriptedTurn(
                        tool_calls=[
                            _tc(
                                "fw1", "write",
                                {
                                    "path": "SOUL.md",
                                    "content": "corrupted\n",
                                },
                            ),
                            _tc(
                                "fw2", "write",
                                {
                                    "path": "MEMORY.md",
                                    "content": "corrupted\n",
                                },
                            ),
                        ],
                        finish_reason="tool_calls",
                        prompt_tokens=10, completion_tokens=10,
                    ),
                    # Sub turn 1: stop.
                    ScriptedTurn(
                        content="done", finish_reason="stop",
                        prompt_tokens=10, completion_tokens=5,
                    ),
                    # Main turn 1: stop.
                    ScriptedTurn(
                        content="main done", finish_reason="stop",
                        prompt_tokens=10, completion_tokens=10,
                    ),
                ]
            )
            bootstrap = build_bootstrap_context(root)
            # Snapshot SOUL.md and MEMORY.md so we can assert neither is
            # clobbered.
            soul_path = os.path.join(root, "SOUL.md")
            memory_md_path = os.path.join(root, "MEMORY.md")
            with open(soul_path) as f:
                original_soul = f.read()
            with open(memory_md_path) as f:
                original_memory_md = f.read()
            parent_logger = SessionLogger.create(
                root, meta={"trigger": "task"}
            )
            runner = SessionRunner(
                client=client,  # type: ignore[arg-type]
                bootstrap=bootstrap,
                tools=tools,
                logger=parent_logger,
                context_window_tokens=200_000,
                workspace_root=root,
                memory_flush_relative_path=pinned_target,
            )
            runner.run("x")

            # Neither SOUL.md nor MEMORY.md may have been touched by the
            # memory-flush wrapper.
            with open(soul_path) as f:
                self.assertEqual(f.read(), original_soul)
            with open(memory_md_path) as f:
                self.assertEqual(f.read(), original_memory_md)

    def test_memory_flush_subsession_silent_reply_is_clean_noop(self) -> None:
        """When the sub-session decides there is nothing durable to
        persist, upstream's convention is to reply with SILENT_REPLY_TOKEN
        (`NO_REPLY`). This must be counted as a successful no-op:
        the flush counter increments, the silent counter increments, no
        write happens on disk, and the parent loop does NOT log
        `memory_flush_error`.
        """
        from openclaw_core.session.memory_flush import SILENT_REPLY_TOKEN

        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            tools = build_default_tool_registry(root)

            pinned_target = "memory/2026-04-22.md"

            client = ScriptedClient(
                script=[
                    # Main turn 0: force flush.
                    ScriptedTurn(
                        tool_calls=[_tc("t1", "read", {"path": "SOUL.md"})],
                        finish_reason="tool_calls",
                        prompt_tokens=100_000, completion_tokens=85_000,
                    ),
                    # Sub turn 0: immediately reply with the silent token
                    # — no tool call at all.
                    ScriptedTurn(
                        content=SILENT_REPLY_TOKEN,
                        finish_reason="stop",
                        prompt_tokens=10, completion_tokens=5,
                    ),
                    # Main turn 1: stop.
                    ScriptedTurn(
                        content="main done", finish_reason="stop",
                        prompt_tokens=10, completion_tokens=10,
                    ),
                ]
            )
            bootstrap = build_bootstrap_context(root)
            parent_logger = SessionLogger.create(
                root, meta={"trigger": "task"}
            )
            runner = SessionRunner(
                client=client,  # type: ignore[arg-type]
                bootstrap=bootstrap,
                tools=tools,
                logger=parent_logger,
                context_window_tokens=200_000,
                workspace_root=root,
                memory_flush_relative_path=pinned_target,
            )
            result = runner.run("x")

            self.assertTrue(result.memory_flush_triggered)
            self.assertEqual(result.memory_flush_count, 1)
            self.assertEqual(result.memory_flush_silent_count, 1)

            # Dated target must NOT have been created — silent reply means
            # the sub-session chose not to persist anything.
            target_path = os.path.join(root, pinned_target)
            self.assertFalse(
                os.path.exists(target_path),
                f"silent-reply flush must not write {target_path}",
            )

            # No error logged.
            with open(parent_logger.log_path) as f:
                events = [
                    json.loads(ln).get("type") for ln in f if ln.strip()
                ]
            self.assertNotIn("memory_flush_error", events)

            # Completion event must record silent_reply=True for analysis.
            with open(parent_logger.log_path) as f:
                records = [json.loads(ln) for ln in f if ln.strip()]
            completed = next(
                r for r in records
                if r.get("type") == "memory_flush_subsession_completed"
            )
            self.assertTrue(completed.get("silent_reply"))

    def test_memory_flush_at_most_once_per_compaction_cycle(self) -> None:
        """Upstream's `hasAlreadyFlushedForCurrentCompaction` guarantees
        at most one flush per compaction cycle. Our port must do the same:
        after a successful flush, subsequent gate checks in the same
        compaction cycle must NOT fire another sub-session.

        We simulate this by running many high-token turns (each of which
        would independently trip the gate) without any compaction, and
        asserting the flush-count stays at 1.
        """
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            tools = build_default_tool_registry(root)

            pinned_target = "memory/2026-04-22.md"

            # Build a script with THREE high-token turns + a terminal stop.
            # After the first flush fires (turn 0), we need to verify that
            # turns 1 and 2 — which still exceed the gate threshold —
            # do NOT trigger additional flushes.
            high_tok_turn = ScriptedTurn(
                tool_calls=[_tc("tX", "read", {"path": "SOUL.md"})],
                finish_reason="tool_calls",
                prompt_tokens=100_000, completion_tokens=85_000,
            )
            # Each sub-session needs its own scripted write + stop turns.
            # Since we expect exactly ONE sub-session to fire, we script
            # only one pair.
            flush_write = ScriptedTurn(
                tool_calls=[_tc(
                    "fw", "write",
                    {"path": pinned_target, "content": "- fact\n"},
                )],
                finish_reason="tool_calls",
                prompt_tokens=10, completion_tokens=10,
            )
            flush_stop = ScriptedTurn(
                content="done", finish_reason="stop",
                prompt_tokens=10, completion_tokens=5,
            )

            client = ScriptedClient(
                script=[
                    # Main turn 0: would trigger gate.
                    high_tok_turn,
                    # Sub-session fires here.
                    flush_write,
                    flush_stop,
                    # Main turn 1: would trigger gate again, but dedup
                    # suppresses it.
                    high_tok_turn,
                    # Main turn 2: same.
                    high_tok_turn,
                    # Main turn 3: stop.
                    ScriptedTurn(
                        content="main done", finish_reason="stop",
                        prompt_tokens=10, completion_tokens=10,
                    ),
                ]
            )
            bootstrap = build_bootstrap_context(root)
            parent_logger = SessionLogger.create(
                root, meta={"trigger": "task"}
            )
            runner = SessionRunner(
                client=client,  # type: ignore[arg-type]
                bootstrap=bootstrap,
                tools=tools,
                logger=parent_logger,
                context_window_tokens=200_000,
                # Disable compaction so compaction_count stays at 0 for
                # the whole run — otherwise a new cycle would legitimately
                # allow another flush (that's the *correct* upstream
                # behavior).
                compaction_enabled=False,
                workspace_root=root,
                memory_flush_relative_path=pinned_target,
            )
            result = runner.run("x")

            self.assertTrue(result.memory_flush_triggered)
            self.assertEqual(
                result.memory_flush_count, 1,
                "per-compaction dedup must cap flushes at 1 per cycle",
            )
            self.assertEqual(result.compaction_count, 0)
            self.assertEqual(result.memory_flush_compaction_count, 0)

    def test_memory_flush_not_triggered_when_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            tools = build_default_tool_registry(root)
            client = ScriptedClient(
                script=[
                    ScriptedTurn(
                        tool_calls=[_tc("t1", "read", {"path": "SOUL.md"})],
                        finish_reason="tool_calls",
                        prompt_tokens=100_000,
                        completion_tokens=85_000,
                    ),
                    ScriptedTurn(content="done", finish_reason="stop"),
                ]
            )
            bootstrap = build_bootstrap_context(root)
            runner = SessionRunner(
                client=client,  # type: ignore[arg-type]
                bootstrap=bootstrap,
                tools=tools,
                context_window_tokens=0,  # gate disabled
            )
            result = runner.run("x")
            self.assertFalse(result.memory_flush_triggered)


class RunnerMaxTurnsTests(unittest.TestCase):
    def test_max_turns_reached(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            tools = build_default_tool_registry(root)
            # Script always returns a tool call — forces infinite loop until cap.
            always_tool_call = ScriptedTurn(
                tool_calls=[_tc("tc", "read", {"path": "SOUL.md"})],
                finish_reason="tool_calls",
            )
            client = ScriptedClient(script=[always_tool_call] * 5)
            bootstrap = build_bootstrap_context(root)
            runner = SessionRunner(
                client=client,  # type: ignore[arg-type]
                bootstrap=bootstrap,
                tools=tools,
                max_turns=3,
            )
            result = runner.run("loop")
            self.assertTrue(result.hit_max_turns)
            self.assertEqual(result.turns_used, 3)
            self.assertEqual(result.stopped_reason, "max_turns")


class RunnerBudgetGuardTests(unittest.TestCase):
    """Runaway-loop budget guard (max_total_tokens)."""

    def test_budget_guard_stops_loop_when_cumulative_tokens_exceed_cap(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            tools = build_default_tool_registry(root)
            # Each turn burns 200 prompt + 50 completion = 250 tokens.
            # Cap at 500 → loop should break at the TOP of turn 3 (after
            # turns 1 and 2 have run), because cumulative=500 >= 500.
            burner = ScriptedTurn(
                tool_calls=[_tc("tc", "read", {"path": "SOUL.md"})],
                finish_reason="tool_calls",
                prompt_tokens=200,
                completion_tokens=50,
            )
            client = ScriptedClient(script=[burner] * 10)
            bootstrap = build_bootstrap_context(root)
            runner = SessionRunner(
                client=client,  # type: ignore[arg-type]
                bootstrap=bootstrap,
                tools=tools,
                max_turns=10,
                max_total_tokens=500,
            )
            result = runner.run("burn tokens")
            self.assertEqual(result.stopped_reason, "max_tokens")
            self.assertFalse(result.hit_max_turns)
            self.assertEqual(result.turns_used, 2)
            self.assertEqual(
                result.total_prompt_tokens + result.total_completion_tokens,
                500,
            )

    def test_budget_guard_disabled_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            tools = build_default_tool_registry(root)
            client = ScriptedClient(
                script=[
                    ScriptedTurn(content="done", finish_reason="stop",
                                 prompt_tokens=10_000_000, completion_tokens=0),
                ]
            )
            bootstrap = build_bootstrap_context(root)
            runner = SessionRunner(
                client=client,  # type: ignore[arg-type]
                bootstrap=bootstrap,
                tools=tools,
                # max_total_tokens defaults to 0 → guard disabled.
            )
            result = runner.run("one shot")
            # Should reach a normal stop despite huge token report.
            self.assertEqual(result.stopped_reason, "stop")

    def test_normal_stop_sets_stopped_reason(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            tools = build_default_tool_registry(root)
            client = ScriptedClient(
                script=[ScriptedTurn(content="done", finish_reason="stop")]
            )
            bootstrap = build_bootstrap_context(root)
            runner = SessionRunner(
                client=client,  # type: ignore[arg-type]
                bootstrap=bootstrap,
                tools=tools,
            )
            result = runner.run("say done")
            self.assertEqual(result.stopped_reason, "stop")


class RunnerLoggingIntegrationTests(unittest.TestCase):
    def test_logger_captures_full_turn_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            tools = build_default_tool_registry(root)
            logger = SessionLogger.create(root, meta={"test": True})
            client = ScriptedClient(
                script=[
                    ScriptedTurn(
                        tool_calls=[_tc("t1", "write", {"path": "a.txt", "content": "hi"})],
                        finish_reason="tool_calls",
                    ),
                    ScriptedTurn(content="done", finish_reason="stop"),
                ]
            )
            bootstrap = build_bootstrap_context(root)
            runner = SessionRunner(
                client=client,  # type: ignore[arg-type]
                bootstrap=bootstrap,
                tools=tools,
                logger=logger,
            )
            runner.run("write a file")

            with open(logger.log_path) as f:
                recs = [json.loads(line) for line in f if line.strip()]

            # Expect: session_start, bootstrap event, user, assistant, tool, assistant, session_end
            types_or_roles = [
                rec.get("role") or rec.get("type") for rec in recs
            ]
            self.assertIn("session_start", types_or_roles)
            self.assertIn("bootstrap", types_or_roles)
            self.assertIn("user", types_or_roles)
            self.assertIn("assistant", types_or_roles)
            self.assertIn("tool", types_or_roles)
            self.assertIn("session_end", types_or_roles)


class RunnerCarryStateTests(unittest.TestCase):
    """Verify that run(carry=...) threads state across two user turns in
    ONE session (chain-mode primitive — upstream's external-state model,
    internalized as a carry-state arg).
    """

    def test_carry_preserves_transcript_and_does_not_restamp_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            tools = build_default_tool_registry(root)
            client = ScriptedClient(
                script=[
                    ScriptedTurn(content="first reply", finish_reason="stop"),
                    ScriptedTurn(content="second reply", finish_reason="stop"),
                ]
            )
            bootstrap = build_bootstrap_context(root)
            logger = SessionLogger.create(root, meta={"trigger": "test"})
            runner = SessionRunner(
                client=client,  # type: ignore[arg-type]
                bootstrap=bootstrap,
                tools=tools,
                logger=logger,
            )

            # Turn 1: fresh session, keep logger open.
            r1 = runner.run("first user msg", close_logger=False)
            self.assertEqual(r1.turns_used, 1)
            # Transcript contains system + user + assistant.
            roles1 = [m.role for m in r1.messages]
            self.assertEqual(roles1[0], "system")
            self.assertEqual(roles1[1], "user")
            self.assertEqual(roles1[-1], "assistant")

            # Turn 2: carry state, append new user msg.
            carry = SessionCarryState.from_result(r1)
            r2 = runner.run("second user msg", carry=carry, close_logger=True)

            # Same result object (accumulator continued).
            self.assertIs(r2, r1)
            self.assertEqual(r2.turns_used, 2)  # accumulated, not reset
            # Transcript now has: system, user1, assistant1, user2, assistant2.
            roles2 = [m.role for m in r2.messages]
            self.assertEqual(roles2, ["system", "user", "assistant", "user", "assistant"])

            # Bootstrap must be stamped ONCE across the whole session.
            log_path = logger.log_path
            with open(log_path) as f:
                recs = [json.loads(line) for line in f if line.strip()]
            bootstrap_count = sum(1 for r in recs if r.get("type") == "bootstrap")
            self.assertEqual(bootstrap_count, 1)
            # Two user records (one per turn).
            user_count = sum(1 for r in recs if r.get("role") == "user")
            self.assertEqual(user_count, 2)

    def test_carry_accumulates_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            ensure_agent_workspace(root, mark_setup_done=True)
            tools = build_default_tool_registry(root)
            client = ScriptedClient(
                script=[
                    ScriptedTurn(content="a", finish_reason="stop",
                                 prompt_tokens=500, completion_tokens=50),
                    ScriptedTurn(content="b", finish_reason="stop",
                                 prompt_tokens=700, completion_tokens=80),
                ]
            )
            bootstrap = build_bootstrap_context(root)
            runner = SessionRunner(
                client=client,  # type: ignore[arg-type]
                bootstrap=bootstrap,
                tools=tools,
            )
            r1 = runner.run("t1", close_logger=False)
            self.assertEqual(r1.total_prompt_tokens, 500)
            self.assertEqual(r1.total_completion_tokens, 50)

            carry = SessionCarryState.from_result(r1)
            r2 = runner.run("t2", carry=carry)
            # Accumulated, not reset.
            self.assertEqual(r2.total_prompt_tokens, 500 + 700)
            self.assertEqual(r2.total_completion_tokens, 50 + 80)


if __name__ == "__main__":
    unittest.main()
