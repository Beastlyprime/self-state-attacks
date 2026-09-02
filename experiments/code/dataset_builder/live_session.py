#!/usr/bin/env python3
"""Run one real OpenRouter-backed agent turn and archive its tool decisions.

This is the semantic execution arm for the anchor-first dataset builder.  The
model sees the current workspace bootstrap, reads the delivered source through
the normal agent tools, and decides how to update self-state.  Nothing in this
module writes a benchmark target directly; all mutations go through the
``openclaw_core`` tool registry in this process.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[3]
AGENT_ROOT = PROJECT_ROOT / "experiments" / "agent"
if str(AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(AGENT_ROOT))

from openclaw_core.llm.openai_compat import client_from_env  # noqa: E402
from openclaw_core.llm.openai_compat import ChatClient  # noqa: E402
from openclaw_core.heartbeat.runner import run_one_heartbeat  # noqa: E402
from openclaw_core.session.bootstrap import build_bootstrap_context  # noqa: E402
from openclaw_core.session.log import SessionLogger  # noqa: E402
from openclaw_core.session.runner import (  # noqa: E402
    SessionRunner,
    build_default_tool_registry,
)
from openclaw_core.trace.schema import full_byte_snapshot, process_identity  # noqa: E402

try:
    from .run_safety import (  # type: ignore
        credential_variable_names,
        runtime_environment_metadata,
        validate_live_poisoned_safety,
    )
except ImportError:  # pragma: no cover - script execution
    from run_safety import (  # noqa: E402
        credential_variable_names,
        runtime_environment_metadata,
        validate_live_poisoned_safety,
    )


class RecordingClient:
    """Transparent ChatClient wrapper that archives provider requests/responses.

    The request archive intentionally stores only the model request body and
    metadata, never transport headers or credentials.  It is used by the
    user-message channel to prove that carrier text entered through the
    gateway/API path rather than through a fabricated filesystem read.
    """

    def __init__(self, delegate: Any):
        self.delegate = delegate
        self.requests = []
        self.responses = []

    def chat(self, *args: Any, **kwargs: Any) -> Any:
        messages = kwargs.get("messages")
        if messages is None and args:
            messages = args[0]
        request_record: dict[str, Any] = {
            "request_index": len(self.requests),
            "timestamp_wall_ns": time.time_ns(),
            "model": kwargs.get("model"),
            "temperature": kwargs.get("temperature"),
            "max_tokens": kwargs.get("max_tokens"),
            "tool_choice": kwargs.get("tool_choice"),
            "tools_count": len(kwargs.get("tools") or []),
        }
        if isinstance(messages, list):
            api_messages = [
                message.to_api_dict() if hasattr(message, "to_api_dict") else dict(message)
                for message in messages
            ]
            raw = json.dumps(
                {
                    "messages": api_messages,
                    "tools": kwargs.get("tools") or [],
                    "tool_choice": kwargs.get("tool_choice"),
                    "temperature": kwargs.get("temperature"),
                    "max_tokens": kwargs.get("max_tokens"),
                    "model": kwargs.get("model"),
                },
                ensure_ascii=False,
                sort_keys=True,
            ).encode("utf-8")
            request_record.update(
                {
                    "messages": api_messages,
                    "request_body_sha256": hashlib.sha256(raw).hexdigest(),
                    "request_body_bytes": len(raw),
                    "credential_value_archived": False,
                }
            )
        self.requests.append(request_record)
        response = self.delegate.chat(*args, **kwargs)
        self.responses.append(
            {
                "request_index": request_record["request_index"],
                "model_reported": response.model,
                "finish_reason": response.finish_reason,
                "usage": asdict(response.usage),
                "raw": response.raw,
            }
        )
        return response


def scrub_secret_environment() -> list[str]:
    """Remove credential-like variables before any model-selected shell runs."""
    sensitive_fragments = (
        "API_KEY",
        "ACCESS_KEY",
        "AUTH_TOKEN",
        "PASSWORD",
        "PRIVATE_KEY",
        "SECRET",
        "TOKEN",
        "CREDENTIAL",
    )
    removed = []
    for key in list(os.environ):
        upper = key.upper()
        if any(fragment in upper for fragment in sensitive_fragments):
            os.environ.pop(key, None)
            removed.append(key)
    return sorted(removed)


def _message_payload(message: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"role": message.role, "content": message.content}
    if message.tool_calls:
        payload["tool_calls"] = [
            {
                "id": call.id,
                "type": call.type,
                "function": {
                    "name": call.function.name,
                    "arguments": call.function.arguments,
                },
            }
            for call in message.tool_calls
        ]
    if message.tool_call_id is not None:
        payload["tool_call_id"] = message.tool_call_id
    if message.name is not None:
        payload["name"] = message.name
    return payload


def _bootstrap_payload(bootstrap: Any) -> dict[str, Any]:
    return {
        "minimal": bootstrap.minimal,
        "rendered_system_prompt": full_byte_snapshot(
            bootstrap.rendered_system_prompt.encode("utf-8")
        ),
        "entries": [
            {
                "filename": entry.filename,
                "content": (
                    full_byte_snapshot(entry.content.encode("utf-8"))
                    if entry.content is not None
                    else None
                ),
                "identity": entry.identity,
            }
            for entry in bootstrap.entries
        ],
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    workspace = Path(args.workspace).resolve()
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    message = Path(args.message_file).read_text(encoding="utf-8")
    initial_secret_names = credential_variable_names(os.environ)
    safety = None
    if args.variant == "poisoned":
        if initial_secret_names:
            raise RuntimeError(
                "poisoned agent process was started with credential variables: "
                + ", ".join(initial_secret_names)
            )
        if not args.safety_manifest:
            raise RuntimeError("poisoned live session requires --safety-manifest")
        safety = validate_live_poisoned_safety(
            Path(args.safety_manifest).resolve(),
            workspace=workspace,
            run_id=args.run_id,
            env=os.environ,
            model_base_url=args.base_url,
        )
        client = RecordingClient(
            ChatClient(
                api_key="assa-local-proxy-nonsecret",
                model=args.model,
                base_url=args.base_url,
            )
        )
        removed_secret_env_names: list[str] = []
    else:
        client = RecordingClient(
            client_from_env(
                model=args.model,
                base_url=args.base_url,
                env_var="OPENROUTER_API_KEY",
            )
        )
        removed_secret_env_names = scrub_secret_environment()
    bootstrap_started_ns = time.time_ns()
    bootstrap = build_bootstrap_context(str(workspace), minimal=False)
    bootstrap_ended_ns = time.time_ns()
    logger = SessionLogger.create(
        str(workspace),
        meta={
            "trigger": "anchor_first_paired_live",
            "run_id": args.run_id,
            "variant": args.variant,
            "agent_id": args.agent_id,
            "model": args.model,
        },
    )
    runner = SessionRunner(
        client=client,
        bootstrap=bootstrap,
        tools=build_default_tool_registry(str(workspace)),
        logger=logger,
        context_window_tokens=args.context_window,
        max_turns=args.max_turns,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
        seed=args.seed,
        workspace_root=str(workspace),
    )

    started_ns = time.time_ns()
    result = runner.run(message)
    ended_ns = time.time_ns()
    session_copy = output.parent / "session.jsonl"
    shutil.copy2(logger.log_path, session_copy)

    heartbeat_result = None
    if not args.skip_heartbeat_after_task:
        heartbeat_result = run_one_heartbeat(
            workspace_root=str(workspace),
            client=client,
            agent_id=args.agent_id,
            scheduler_seed=args.run_id,
            max_turns=args.heartbeat_max_turns,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
            extra_meta={
                "run_id": args.run_id,
                "variant": args.variant,
                "trigger_position": "after_main_task",
            },
        )

    payload = {
        "schema_version": "assa.semantic_session.v2",
        "run_id": args.run_id,
        "variant": args.variant,
        "model_requested": args.model,
        "secret_environment": {
            "present_at_process_start": initial_secret_names,
            "removed_before_agent_tools": removed_secret_env_names,
            "values_archived": False,
        },
        "process": process_identity(),
        "runtime_environment": runtime_environment_metadata(os.environ),
        "safety_preflight": safety,
        "timing": {
            "bootstrap_started_wall_ns": bootstrap_started_ns,
            "bootstrap_ended_wall_ns": bootstrap_ended_ns,
            "session_started_wall_ns": started_ns,
            "session_ended_wall_ns": ended_ns,
        },
        "bootstrap": _bootstrap_payload(bootstrap),
        "session_key": result.session_key,
        "session_log": session_copy.name,
        "turns_used": result.turns_used,
        "finish_reason": result.finish_reason,
        "stopped_reason": result.stopped_reason,
        "prompt_tokens": result.total_prompt_tokens,
        "completion_tokens": result.total_completion_tokens,
        "memory_flush_triggered": result.memory_flush_triggered,
        "memory_flush_count": result.memory_flush_count,
        "compaction_count": result.compaction_count,
        "heartbeat_after_task": {
            "enabled": not args.skip_heartbeat_after_task,
            "session_key": heartbeat_result.session_key if heartbeat_result else None,
            "turns_used": heartbeat_result.turns_used if heartbeat_result else 0,
            "finish_reason": heartbeat_result.finish_reason if heartbeat_result else None,
            "stopped_reason": heartbeat_result.stopped_reason if heartbeat_result else None,
            "tool_executions": (
                [asdict(item) for item in heartbeat_result.tool_executions]
                if heartbeat_result
                else []
            ),
        },
        "provider_responses": client.responses,
        "generation_parameters": {
            "provider": "local_parent_proxy" if args.variant == "poisoned" else "openrouter",
            "model": args.model,
            "temperature": args.temperature,
            "max_tokens": args.max_tokens,
            "seed": args.seed,
        },
        "tool_executions": [asdict(item) for item in result.tool_executions],
        "messages": [_message_payload(item) for item in result.messages],
    }
    output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one live semantic agent turn")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--message-file", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--variant", choices=("clean", "poisoned"), required=True)
    parser.add_argument("--agent-id", default="anchor-pilot")
    parser.add_argument("--model", default="google/gemini-3-flash-preview")
    parser.add_argument("--base-url", default="https://openrouter.ai/api/v1")
    parser.add_argument("--safety-manifest")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max-turns", type=int, default=12)
    parser.add_argument("--max-tokens", type=int, default=2048)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--context-window", type=int, default=128_000)
    parser.add_argument("--heartbeat-max-turns", type=int, default=8)
    parser.add_argument(
        "--skip-heartbeat-after-task",
        action="store_true",
        help="Disable the default one-shot native heartbeat after the main task.",
    )
    args = parser.parse_args()
    payload = run(args)
    print(
        json.dumps(
            {
                "run_id": payload["run_id"],
                "session_key": payload["session_key"],
                "turns_used": payload["turns_used"],
                "tool_executions": len(payload["tool_executions"]),
                "pid": payload["process"]["pid"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
