#!/usr/bin/env python3
"""Run and score one real task in an existing canonical agent directory."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any


CODE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = CODE_ROOT.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(CODE_ROOT))

from measurement.task_eval import evaluate_task  # noqa: E402
from openclaw_core.cli import (  # noqa: E402
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    _load_env_file,
)
from openclaw_core.llm.openai_compat import client_from_env  # noqa: E402
from openclaw_core.session.bootstrap import build_bootstrap_context  # noqa: E402
from openclaw_core.session.log import SessionLogger  # noqa: E402
from openclaw_core.session.runner import (  # noqa: E402
    SessionRunner,
    build_default_tool_registry,
)
from tasks.schema import Task  # noqa: E402


SCHEMA_VERSION = "assa.workload_evaluator.exact.v1"
EXIT_TASK_FAILED = 10
EXIT_INFRASTRUCTURE_ERROR = 2


def evaluation_is_supported(evaluation: dict[str, Any]) -> bool:
    """Return whether an evaluation represents an actual pass/fail verdict."""
    return evaluation.get("status") in {"pass", "fail"}


def _w3_prompt(task: Task) -> str:
    if task.profile != "W3":
        return task.prompt
    return (
        "[Canonical state layout] The OpenClaw workspace is the current "
        "directory. The deployment config named openclaw.json is stored one "
        "level above it at ../openclaw.json. When the task mentions "
        "openclaw.json, use that exact ../openclaw.json path; use the bash "
        "tool when access outside the guarded workspace is required.\n\n"
        + task.prompt
    )


def _w3_evaluation_view(task: Task, agent_dir: Path, artifact_dir: Path) -> Path:
    """Project canonical state paths into a read-only evaluator view."""
    view = artifact_dir / "evaluation-view"
    view.mkdir(parents=True, exist_ok=True)
    checks = task.success_criterion.get("checks", [])
    for check in checks:
        relative = check.get("path") if isinstance(check, dict) else None
        if not isinstance(relative, str) or not relative:
            continue
        source = (
            agent_dir / "openclaw.json"
            if relative == "openclaw.json"
            else agent_dir / "workspace" / relative
        )
        destination = view / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            destination.unlink()
        destination.symlink_to(source)
    return view


def evaluate_existing_task(
    task: Task,
    agent_dir: Path,
    artifact_dir: Path,
    assistant_last_message: str | None,
) -> dict[str, Any]:
    workspace = agent_dir / "workspace"
    evaluation_workspace = (
        _w3_evaluation_view(task, agent_dir, artifact_dir)
        if task.profile == "W3" and task.success_criterion.get("kind") == "file_state_check"
        else workspace
    )
    result = evaluate_task(task, evaluation_workspace, assistant_last_message)
    return result.to_dict()


def run_exact_workload(
    *,
    task: Task,
    agent_dir: Path,
    artifact_dir: Path,
    model: str,
    base_url: str,
    max_turns: int | None = None,
    max_tokens: int | None = None,
    temperature: float | None = None,
    context_window: int = 128_000,
) -> dict[str, Any]:
    agent_dir = agent_dir.resolve()
    workspace = agent_dir / "workspace"
    artifact_dir = artifact_dir.resolve()
    if not workspace.is_dir():
        raise ValueError(f"canonical workspace is missing: {workspace}")
    if not (agent_dir / "openclaw.json").is_file():
        raise ValueError(f"canonical config is missing: {agent_dir / 'openclaw.json'}")
    artifact_dir.mkdir(parents=True, exist_ok=True)

    if not os.environ.get("OPENROUTER_API_KEY"):
        raise RuntimeError("OPENROUTER_API_KEY not set")
    client = client_from_env(
        model=model,
        base_url=base_url,
        env_var="OPENROUTER_API_KEY",
    )
    logger = SessionLogger.create(
        str(workspace),
        state_root=str(artifact_dir / "state"),
        meta={
            "trigger": "prevention-workload-evaluator",
            "task_id": task.task_id,
            "profile": task.profile,
            "model": model,
            "exact_workspace": True,
        },
    )
    runner = SessionRunner(
        client=client,
        bootstrap=build_bootstrap_context(str(workspace), minimal=False),
        tools=build_default_tool_registry(str(workspace)),
        logger=logger,
        context_window_tokens=context_window,
        max_turns=max_turns or task.max_turns or 16,
        temperature=temperature,
        max_tokens=max_tokens,
        max_total_tokens=int(task.max_total_tokens or 0),
        workspace_root=str(workspace),
    )
    result = runner.run(_w3_prompt(task))
    last = result.messages[-1] if result.messages else None
    assistant_last = (
        last.content
        if last is not None and last.role == "assistant" and last.content
        else None
    )
    evaluation = evaluate_existing_task(
        task,
        agent_dir,
        artifact_dir,
        assistant_last,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "exact_workspace": True,
        "task_id": task.task_id,
        "profile": task.profile,
        "agent_dir": str(agent_dir),
        "workspace": str(workspace),
        "artifact_dir": str(artifact_dir),
        "model": model,
        "session": {
            "session_key": result.session_key,
            "session_log_path": logger.log_path,
            "turns_used": result.turns_used,
            "finish_reason": result.finish_reason,
            "stopped_reason": result.stopped_reason,
            "hit_max_turns": result.hit_max_turns,
            "prompt_tokens": result.total_prompt_tokens,
            "completion_tokens": result.total_completion_tokens,
            "tool_executions": len(result.tool_executions),
        },
        "assistant_tail": assistant_last[-500:] if assistant_last else None,
        "eval": evaluation,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task", required=True, type=Path)
    parser.add_argument("--agent-dir", required=True, type=Path)
    parser.add_argument("--artifact-dir", required=True, type=Path)
    parser.add_argument("--model", default=os.environ.get("OPENCLAW_MODEL", DEFAULT_MODEL))
    parser.add_argument("--base-url", default=os.environ.get("OPENCLAW_BASE_URL", DEFAULT_BASE_URL))
    parser.add_argument("--env-file", default="api_keys.env")
    parser.add_argument("--max-turns", type=int)
    parser.add_argument("--max-tokens", type=int)
    parser.add_argument("--temperature", type=float)
    parser.add_argument("--context-window", type=int, default=128_000)
    parser.add_argument("--evaluate-only", action="store_true")
    parser.add_argument("--assistant-message")
    args = parser.parse_args()

    try:
        task = Task.from_json_path(args.task)
        agent_dir = args.agent_dir.resolve()
        artifact_dir = args.artifact_dir.resolve()
        artifact_dir.mkdir(parents=True, exist_ok=True)
        if args.evaluate_only:
            evaluation = evaluate_existing_task(
                task,
                agent_dir,
                artifact_dir,
                args.assistant_message,
            )
            payload = {
                "schema_version": SCHEMA_VERSION,
                "status": "evaluated_only",
                "exact_workspace": True,
                "task_id": task.task_id,
                "profile": task.profile,
                "agent_dir": str(agent_dir),
                "workspace": str(agent_dir / "workspace"),
                "artifact_dir": str(artifact_dir),
                "eval": evaluation,
            }
        else:
            _load_env_file(args.env_file)
            payload = run_exact_workload(
                task=task,
                agent_dir=agent_dir,
                artifact_dir=artifact_dir,
                model=args.model,
                base_url=args.base_url,
                max_turns=args.max_turns,
                max_tokens=args.max_tokens,
                temperature=args.temperature,
                context_window=args.context_window,
            )
    except Exception as exc:  # noqa: BLE001 - emit machine-readable infra failure
        payload = {
            "schema_version": SCHEMA_VERSION,
            "status": "infrastructure_error",
            "exact_workspace": True,
            "task_id": str(args.task),
            "error": f"{type(exc).__name__}: {exc}",
        }
        print(json.dumps(payload, sort_keys=True))
        return EXIT_INFRASTRUCTURE_ERROR

    if not evaluation_is_supported(payload["eval"]):
        payload["status"] = "unsupported_evaluator"
        print(json.dumps(payload, sort_keys=True))
        return EXIT_INFRASTRUCTURE_ERROR

    print(json.dumps(payload, sort_keys=True))
    return 0 if payload["eval"]["passed"] else EXIT_TASK_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
