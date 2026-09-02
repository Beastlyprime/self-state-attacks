"""Command-line entry point for the openclaw_core harness.

Usage:
    python3 -m openclaw_core.cli init <workspace>
    python3 -m openclaw_core.cli run <workspace> --message "..."
    python3 -m openclaw_core.cli heartbeat <workspace>

Env:
    OPENROUTER_API_KEY — required for `run` and `heartbeat`.
    OPENCLAW_MODEL     — model slug, default 'google/gemini-3-flash-preview'.
    OPENCLAW_BASE_URL  — LLM base URL, default OpenRouter
                         (https://openrouter.ai/api/v1).

`init` seeds an OpenClaw-style workspace (SOUL.md, AGENTS.md, …) under
the given directory. Safe to re-run — it will not overwrite existing
files.

`run` drives one interactive session: build bootstrap → send a user
message → loop until the LLM stops calling tools → print a summary.

`heartbeat` runs ONE heartbeat session (minimal bootstrap, short
prompt). Useful for smoke-testing the harness without a workload task.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Optional

from .heartbeat import run_one_heartbeat
from .llm.openai_compat import ChatClient, client_from_env
from .session.bootstrap import build_bootstrap_context
from .session.log import SessionLogger
from .session.runner import (
    SessionCarryState,
    SessionRunner,
    build_default_tool_registry,
)
from .trace import TraceCollector, is_supported as trace_is_supported
from .workspace import ensure_agent_workspace


DEFAULT_MODEL = "google/gemini-3-flash-preview"
DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"


# --------------------------------------------------------------- helpers


def _load_env_file(path: str) -> None:
    """Lightweight `.env` loader — no external deps.

    Reads KEY=VALUE lines, strips quotes, sets os.environ entries that
    aren't already present. Unknown formats silently ignored.
    """
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                # Don't overwrite an explicit environment setting.
                os.environ.setdefault(key, value)
    except OSError:
        return


def _build_client(*, model: str, base_url: str) -> ChatClient:
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        print(
            "error: OPENROUTER_API_KEY not set (looked in env + api_keys.env).",
            file=sys.stderr,
        )
        sys.exit(2)
    return client_from_env(
        model=model,
        base_url=base_url,
        env_var="OPENROUTER_API_KEY",
    )


def _last_nonempty_assistant_content(messages: list) -> Optional[str]:
    for message in reversed(messages):
        if message.role != "assistant":
            continue
        if not isinstance(message.content, str):
            continue
        content = message.content.strip()
        if content:
            return content
    return None


# --------------------------------------------------------------- commands


def cmd_init(args: argparse.Namespace) -> int:
    root = os.path.abspath(args.workspace)
    ensure_agent_workspace(root, mark_setup_done=args.mark_setup_done)
    print(f"initialized workspace at {root}")
    return 0


def cmd_benchmark_release(args: argparse.Namespace) -> int:
    """Run the deterministic, benchmark-only semantic bypass."""
    import json

    from .benchmark_release import execute_release, load_spec

    root = os.path.abspath(args.workspace)
    result = execute_release(root, load_spec(args.spec))
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result.get("success") else 1


def _resolve_trace_path(args: argparse.Namespace, session_key: str) -> Optional[str]:
    """Figure out where to drop the trace JSONL, or None if tracing disabled.

    Precedence:
      1. --no-trace → None
      2. Non-Linux → None (inotify unsupported)
      3. --trace-output → use as-is
      4. --trace-dir → <dir>/<session_key>.jsonl
      5. Default: <workspace>/traces/<session_key>.jsonl
    """
    if getattr(args, "no_trace", False):
        return None
    if not trace_is_supported():
        return None
    if getattr(args, "trace_output", None):
        return os.path.abspath(args.trace_output)
    if getattr(args, "trace_dir", None):
        return os.path.join(os.path.abspath(args.trace_dir), f"{session_key}.jsonl")
    # Default: workspace-local traces dir.
    root = os.path.abspath(args.workspace)
    return os.path.join(root, "traces", f"{session_key}.jsonl")


def cmd_run(args: argparse.Namespace) -> int:
    root = os.path.abspath(args.workspace)
    ensure_agent_workspace(root, mark_setup_done=True)

    client = _build_client(model=args.model, base_url=args.base_url)
    bootstrap = build_bootstrap_context(root, minimal=False)

    logger = SessionLogger.create(
        root,
        meta={
            "trigger": "user",
            "agent_id": args.agent_id,
            "model": args.model,
        },
    )
    tools = build_default_tool_registry(root)
    runner = SessionRunner(
        client=client,
        bootstrap=bootstrap,
        tools=tools,
        logger=logger,
        context_window_tokens=args.context_window,
        max_turns=args.max_turns,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
        # SPEC §7 — enable actual memory-flush sub-session execution.
        workspace_root=root,
    )

    trace_path = _resolve_trace_path(args, logger.session_key)
    collector: Optional[TraceCollector] = None
    if trace_path is not None:
        collector = TraceCollector(
            watch_root=root,
            output_path=trace_path,
            session_tag=logger.session_key,
        )
        collector.start()

    try:
        result = runner.run(args.message)
    finally:
        if collector is not None:
            collector.stop()

    print(
        f"session_key: {result.session_key}\n"
        f"turns_used: {result.turns_used}\n"
        f"finish_reason: {result.finish_reason}\n"
        f"prompt_tokens: {result.total_prompt_tokens}\n"
        f"completion_tokens: {result.total_completion_tokens}\n"
        f"tool_executions: {len(result.tool_executions)}\n"
        f"memory_flush_triggered: {result.memory_flush_triggered}\n"
        f"hit_max_turns: {result.hit_max_turns}"
    )
    if collector is not None and trace_path is not None:
        print(
            f"trace_output: {trace_path}\n"
            f"trace_events: {collector.event_count}\n"
            f"trace_overflows: {collector.overflow_count}"
        )
    assistant_content = _last_nonempty_assistant_content(result.messages)
    if assistant_content:
        print("----- assistant -----")
        print(assistant_content)
    return 0


def cmd_chat(args: argparse.Namespace) -> int:
    root = os.path.abspath(args.workspace)
    ensure_agent_workspace(root, mark_setup_done=True)

    client = _build_client(model=args.model, base_url=args.base_url)
    bootstrap = build_bootstrap_context(root, minimal=False)

    logger = SessionLogger.create(
        root,
        meta={
            "trigger": "interactive",
            "agent_id": args.agent_id,
            "model": args.model,
        },
    )
    tools = build_default_tool_registry(root)
    runner = SessionRunner(
        client=client,
        bootstrap=bootstrap,
        tools=tools,
        logger=logger,
        context_window_tokens=args.context_window,
        max_turns=args.max_turns,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
        workspace_root=root,
    )

    trace_path = _resolve_trace_path(args, logger.session_key)
    collector: Optional[TraceCollector] = None
    if trace_path is not None:
        collector = TraceCollector(
            watch_root=root,
            output_path=trace_path,
            session_tag=logger.session_key,
        )
        collector.start()

    carry: Optional[SessionCarryState] = None
    print(f"workspace: {root}")
    print(f"session_key: {logger.session_key}")
    print(f"session_log: {logger.log_path}")
    if trace_path is not None:
        print(f"trace_output: {trace_path}")
    print("Type /exit or /quit to end.\n")

    try:
        while True:
            try:
                user_message = input("you> ").strip()
            except EOFError:
                break
            if not user_message:
                continue
            if user_message in {"/exit", "/quit"}:
                break

            previous_message_count = len(carry.messages) if carry is not None else 0
            previous_tool_count = (
                len(carry.result.tool_executions) if carry is not None else 0
            )
            result = runner.run(
                user_message,
                carry=carry,
                close_logger=False,
            )
            carry = SessionCarryState.from_result(result)

            new_messages = result.messages[previous_message_count:]
            assistant_content = _last_nonempty_assistant_content(new_messages)
            tools_this_turn = len(result.tool_executions) - previous_tool_count
            if assistant_content:
                print(f"agent> {assistant_content}")
                if tools_this_turn:
                    print(f"[finish={result.finish_reason}, tools_this_turn={tools_this_turn}]")
                print()
            else:
                print(
                    "agent> "
                    f"[finish={result.finish_reason}, tools_this_turn={tools_this_turn}]\n"
                )
    except KeyboardInterrupt:
        print("\ninterrupted")
    finally:
        logger.close()
        if collector is not None:
            collector.stop()
            print(
                f"\ntrace_events: {collector.event_count}\n"
                f"trace_overflows: {collector.overflow_count}"
            )

    return 0


def cmd_heartbeat(args: argparse.Namespace) -> int:
    root = os.path.abspath(args.workspace)
    ensure_agent_workspace(root, mark_setup_done=True)

    client = _build_client(model=args.model, base_url=args.base_url)

    # run_one_heartbeat creates its own SessionLogger internally, so we don't
    # have the session_key before the call. Use a pre-session tag for the
    # trace filename; JSONL `session` field will match the logger's
    # session_key (run_one_heartbeat threads it through).  For the filename,
    # we fall back to a timestamp-based tag.
    import time as _time
    pre_tag = f"hb-{int(_time.time())}"
    trace_path: Optional[str] = None
    if getattr(args, "no_trace", False) or not trace_is_supported():
        trace_path = None
    elif getattr(args, "trace_output", None):
        trace_path = os.path.abspath(args.trace_output)
    elif getattr(args, "trace_dir", None):
        trace_path = os.path.join(os.path.abspath(args.trace_dir), f"{pre_tag}.jsonl")
    else:
        trace_path = os.path.join(root, "traces", f"{pre_tag}.jsonl")

    collector: Optional[TraceCollector] = None
    if trace_path is not None:
        collector = TraceCollector(
            watch_root=root,
            output_path=trace_path,
            session_tag=pre_tag,
        )
        collector.start()

    try:
        result = run_one_heartbeat(
            workspace_root=root,
            client=client,
            agent_id=args.agent_id,
            scheduler_seed=args.scheduler_seed,
            max_turns=args.max_turns,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
        )
    finally:
        if collector is not None:
            collector.stop()

    print(
        f"heartbeat session_key: {result.session_key}\n"
        f"turns_used: {result.turns_used}\n"
        f"tool_executions: {len(result.tool_executions)}\n"
        f"finish_reason: {result.finish_reason}"
    )
    if collector is not None and trace_path is not None:
        print(
            f"trace_output: {trace_path}\n"
            f"trace_events: {collector.event_count}\n"
            f"trace_overflows: {collector.overflow_count}"
        )
    return 0


# --------------------------------------------------------------- main


def _add_runtime_overrides(parser: argparse.ArgumentParser) -> None:
    """Allow global runtime flags after subcommands too.

    argparse only accepts top-level options before the subcommand. The test
    interface is easier to use if `openclaw_core chat <workspace> --model ...`
    works as well, so subcommands accept the same destinations without
    overriding the global defaults when omitted.
    """
    parser.add_argument(
        "--env-file",
        default=argparse.SUPPRESS,
        help="Path to .env file with OPENROUTER_API_KEY.",
    )
    parser.add_argument(
        "--model",
        default=argparse.SUPPRESS,
        help="Model slug.",
    )
    parser.add_argument(
        "--base-url",
        default=argparse.SUPPRESS,
        help="LLM API base URL.",
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="openclaw_core",
        description="Minimal OpenClaw harness CLI.",
    )
    p.add_argument(
        "--env-file",
        default="api_keys.env",
        help="Path to .env file with OPENROUTER_API_KEY (default: api_keys.env).",
    )
    p.add_argument(
        "--model",
        default=os.environ.get("OPENCLAW_MODEL", DEFAULT_MODEL),
        help=f"Model slug (default: {DEFAULT_MODEL}).",
    )
    p.add_argument(
        "--base-url",
        default=os.environ.get("OPENCLAW_BASE_URL", DEFAULT_BASE_URL),
        help="LLM API base URL.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    # init
    p_init = sub.add_parser("init", help="Seed an OpenClaw workspace.")
    p_init.add_argument("workspace")
    p_init.add_argument(
        "--mark-setup-done",
        action="store_true",
        default=True,
        help="Delete BOOTSTRAP.md after seeding (default: True).",
    )
    p_init.set_defaults(func=cmd_init)

    # Deterministic semantic bypass for dataset collection. Workspaces are
    # prepared by the external harness before the labeled segment begins.
    p_release = sub.add_parser(
        "benchmark-release",
        help="Apply one benchmark mutation through the agent tool registry.",
    )
    p_release.add_argument("workspace")
    p_release.add_argument("--spec", required=True)
    p_release.set_defaults(func=cmd_benchmark_release)

    # run
    p_run = sub.add_parser("run", help="Run one interactive session.")
    p_run.add_argument("workspace")
    _add_runtime_overrides(p_run)
    p_run.add_argument("--message", "-m", required=True, help="User message.")
    p_run.add_argument("--agent-id", default="agent-a")
    p_run.add_argument("--max-turns", type=int, default=16)
    p_run.add_argument("--context-window", type=int, default=0,
                       help="Tokens; 0 disables memory-flush gate.")
    p_run.add_argument("--temperature", type=float, default=None)
    p_run.add_argument("--max-tokens", type=int, default=None)
    p_run.add_argument("--trace-output", default=None,
                       help="Explicit JSONL path for inotify trace.")
    p_run.add_argument("--trace-dir", default=None,
                       help="Dir for trace JSONL (file auto-named by session_key).")
    p_run.add_argument("--no-trace", action="store_true",
                       help="Disable inotify trace capture.")
    p_run.set_defaults(func=cmd_run)

    # chat
    p_chat = sub.add_parser("chat", help="Run an interactive multi-turn session.")
    p_chat.add_argument("workspace")
    _add_runtime_overrides(p_chat)
    p_chat.add_argument("--agent-id", default="agent-a")
    p_chat.add_argument("--max-turns", type=int, default=16,
                        help="Max tool-loop turns per user message.")
    p_chat.add_argument("--context-window", type=int, default=0,
                        help="Tokens; 0 disables memory-flush gate.")
    p_chat.add_argument("--temperature", type=float, default=None)
    p_chat.add_argument("--max-tokens", type=int, default=None)
    p_chat.add_argument("--trace-output", default=None,
                        help="Explicit JSONL path for inotify trace.")
    p_chat.add_argument("--trace-dir", default=None,
                        help="Dir for trace JSONL (file auto-named by session_key).")
    p_chat.add_argument("--no-trace", action="store_true",
                        help="Disable inotify trace capture.")
    p_chat.set_defaults(func=cmd_chat)

    # heartbeat
    p_hb = sub.add_parser("heartbeat", help="Run one heartbeat session.")
    p_hb.add_argument("workspace")
    _add_runtime_overrides(p_hb)
    p_hb.add_argument("--agent-id", default="agent-a")
    p_hb.add_argument("--scheduler-seed", default="openclaw")
    p_hb.add_argument("--max-turns", type=int, default=4)
    p_hb.add_argument("--temperature", type=float, default=None)
    p_hb.add_argument("--max-tokens", type=int, default=None)
    p_hb.add_argument("--trace-output", default=None,
                      help="Explicit JSONL path for inotify trace.")
    p_hb.add_argument("--trace-dir", default=None,
                      help="Dir for trace JSONL (auto-named by timestamp).")
    p_hb.add_argument("--no-trace", action="store_true",
                      help="Disable inotify trace capture.")
    p_hb.set_defaults(func=cmd_heartbeat)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Best-effort: load api_keys.env BEFORE any command that needs the key.
    _load_env_file(args.env_file)

    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
