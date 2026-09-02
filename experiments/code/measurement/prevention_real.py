#!/usr/bin/env python3
"""Execute canonical attacks and legitimate workloads under real OS policies."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXPERIMENTS_ROOT = PROJECT_ROOT.parent
sys.path.insert(0, str(PROJECT_ROOT))

from attacks.canonical_v4 import CANONICAL_ATTACKS  # noqa: E402
from defenses.prevention.backends import (  # noqa: E402
    AgentIdentity,
    BackendContext,
    EnforcementError,
    build_backend,
    run_as_agent,
)
from defenses.runtime_manifest import runtime_manifest  # noqa: E402
from defenses.runtime_identity import audit_agent_identity  # noqa: E402
from defenses.workload_tasks import prepare_workload_task  # noqa: E402
from tasks.schema import Task  # noqa: E402


SCHEMA_VERSION = "assa.prevention.real.v1"


def _fingerprint(path: Path) -> dict:
    if not path.exists():
        return {"exists": False}
    metadata = path.stat(follow_symlinks=False)
    if not path.is_file() or path.is_symlink():
        return {
            "exists": True,
            "type": "unsupported",
            "mode": stat.S_IMODE(metadata.st_mode),
        }
    result = {
        "exists": True,
        "type": "file",
        "size": metadata.st_size,
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
    }
    try:
        result["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        result["sha256"] = None
        result["read_error"] = f"{type(exc).__name__}: {exc}"
    return result


def _parse_json_output(stdout: str) -> dict | None:
    candidates = [stdout]
    candidates.extend(line for line in reversed(stdout.splitlines()) if line.strip())
    for candidate in candidates:
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def _execute(
    context: BackendContext,
    backend,
    command: Sequence[str],
    *,
    timeout: float,
) -> dict:
    prefixed = [*backend.command_prefix(context), *command]
    complete = run_as_agent(context.identity, prefixed)
    started_ns = time.monotonic_ns()
    try:
        result = subprocess.run(
            complete,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        return {
            "command": complete,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "elapsed_ns": time.monotonic_ns() - started_ns,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": complete,
            "returncode": None,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "elapsed_ns": time.monotonic_ns() - started_ns,
            "timed_out": True,
        }


def _clone_seed(seed: Path, scenario_root: Path) -> Path:
    if scenario_root.exists():
        raise EnforcementError(f"scenario directory already exists: {scenario_root}")
    shutil.copytree(seed, scenario_root, symlinks=True)
    for path in scenario_root.rglob("*"):
        if path.is_symlink():
            raise EnforcementError(f"seed contains symlink: {path}")
    return scenario_root


def _prepare_agent_tree(root: Path, identity: AgentIdentity) -> None:
    """Make the disposable clone represent an agent-owned default install."""
    if os.geteuid() not in {0, identity.uid}:
        raise EnforcementError("runner cannot prepare files for the requested agent user")
    if os.geteuid() != 0:
        return
    for directory, dirnames, filenames in os.walk(root):
        os.chown(directory, identity.uid, identity.gid)
        for name in [*dirnames, *filenames]:
            path = Path(directory) / name
            if path.is_symlink():
                raise EnforcementError(f"seed contains symlink: {path}")
            os.chown(path, identity.uid, identity.gid)


def _attack_command(agent_dir: Path, attack_id: str) -> list[str]:
    script = PROJECT_ROOT / "attacks" / "canonical_v4.py"
    pythonpath = str(PROJECT_ROOT)
    return [
        "env",
        f"PYTHONPATH={pythonpath}",
        "PYTHONDONTWRITEBYTECODE=1",
        sys.executable,
        str(script),
        str(agent_dir),
        attack_id,
    ]


def _exact_workload_command(
    *,
    agent_dir: Path,
    artifact_dir: Path,
    task_path: Path,
    model: str | None,
    base_url: str | None,
    env_file: Path,
) -> list[str]:
    command = [
        "env",
        f"PYTHONPATH={PROJECT_ROOT}",
        "PYTHONDONTWRITEBYTECODE=1",
        sys.executable,
        str(PROJECT_ROOT / "measurement" / "workload_evaluator.py"),
        "--task",
        str(task_path),
        "--agent-dir",
        str(agent_dir),
        "--artifact-dir",
        str(artifact_dir),
        "--env-file",
        str(env_file),
    ]
    if model:
        command.extend(["--model", model])
    if base_url:
        command.extend(["--base-url", base_url])
    return command


def run_attack_scenario(
    *,
    seed: Path,
    work_root: Path,
    artifact_root: Path,
    backend_name: str,
    level: int,
    attack_id: str,
    identity: AgentIdentity,
    landlock_launcher: Path | None,
    runtime_write_paths: list[Path],
    timeout: float,
) -> dict:
    run_id = f"{backend_name}-L{level}-{attack_id}-{uuid.uuid4().hex[:8]}"
    scenario_dir = work_root / run_id
    context = BackendContext(
        agent_dir=scenario_dir,
        identity=identity,
        level=level,
        run_id=run_id,
        artifact_dir=artifact_root / run_id,
        runtime_write_paths=runtime_write_paths,
    )
    backend = build_backend(backend_name, landlock_launcher=landlock_launcher)
    row = {
        "run_id": run_id,
        "backend": backend.name,
        "level": level,
        "attack_id": attack_id,
        "paper_cell": "-".join(attack_id.split("-")[:3]),
        "target_file": CANONICAL_ATTACKS[attack_id].target_file,
        "preflight": None,
        "setup": None,
        "execution": None,
        "teardown": None,
        "blocked": None,
        "state_unchanged": None,
        "paper_admissible": False,
    }
    setup_started = False
    try:
        _clone_seed(seed, scenario_dir)
        _prepare_agent_tree(scenario_dir, identity)
        target = scenario_dir / CANONICAL_ATTACKS[attack_id].target_file
        if not target.exists():
            raise EnforcementError(f"canonical target missing from seed: {target}")
        row["preflight"] = backend.preflight(context)
        row["setup"] = backend.setup(context)
        setup_started = True
        before = _fingerprint(target)
        execution = _execute(
            context,
            backend,
            _attack_command(scenario_dir, attack_id),
            timeout=timeout,
        )
        attack_result = _parse_json_output(execution["stdout"])
        execution["attack_result"] = attack_result
        execution["stdout"] = execution["stdout"][-4000:]
        execution["stderr"] = execution["stderr"][-4000:]
        after = _fingerprint(target)
        unchanged = before == after
        valid_attack_result = bool(
            attack_result
            and attack_result.get("attack_id") == attack_id
            and attack_result.get("target_file") == str(target)
        )
        wrapper_failed = execution["returncode"] in {125, 126, 127}
        blocked = bool(
            valid_attack_result
            and not attack_result.get("success")
            and unchanged
            and not execution["timed_out"]
            and not wrapper_failed
        )
        row.update({
            "execution": execution,
            "pre_state": before,
            "post_state": after,
            "state_unchanged": unchanged,
            "blocked": blocked,
            "paper_admissible": bool(valid_attack_result and not wrapper_failed),
        })
    except (EnforcementError, OSError, ValueError) as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if setup_started:
            try:
                row["teardown"] = backend.teardown(context)
            except (EnforcementError, OSError) as exc:
                row["teardown"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
                row["paper_admissible"] = False
        shutil.rmtree(scenario_dir, ignore_errors=True)
    return row


def run_workload_scenario(
    *,
    seed: Path,
    work_root: Path,
    artifact_root: Path,
    backend_name: str,
    level: int,
    profile: str,
    command_template: str | None,
    task_path: Path | None,
    identity: AgentIdentity,
    landlock_launcher: Path | None,
    runtime_write_paths: list[Path],
    workload_model: str | None,
    workload_base_url: str | None,
    workload_env_file: Path,
    timeout: float,
) -> dict:
    run_id = f"{backend_name}-L{level}-{profile}-{uuid.uuid4().hex[:8]}"
    scenario_dir = work_root / run_id
    context = BackendContext(
        agent_dir=scenario_dir,
        identity=identity,
        level=level,
        run_id=run_id,
        artifact_dir=artifact_root / run_id,
        runtime_write_paths=list(runtime_write_paths),
    )
    runtime_dir = context.artifact_dir / "runtime"
    backend = build_backend(backend_name, landlock_launcher=landlock_launcher)
    row = {
        "run_id": run_id,
        "backend": backend.name,
        "level": level,
        "profile": profile,
        "paper_admissible": False,
    }
    setup_started = False
    try:
        _clone_seed(seed, scenario_dir)
        task = Task.from_json_path(task_path) if task_path is not None else None
        if task is not None:
            if task.profile != profile:
                raise EnforcementError(
                    f"task profile mismatch: {task.profile} != {profile}"
                )
            row["task_id"] = task.task_id
            row["task_path"] = str(task_path)
            row["task_stage"] = prepare_workload_task(task, scenario_dir)
        _prepare_agent_tree(scenario_dir, identity)
        runtime_dir.mkdir(parents=True, exist_ok=True)
        if os.geteuid() == 0:
            os.chown(runtime_dir, identity.uid, identity.gid)
        context.runtime_write_paths.append(runtime_dir)
        row["preflight"] = backend.preflight(context)
        row["setup"] = backend.setup(context)
        setup_started = True
        if task_path is not None:
            command = _exact_workload_command(
                agent_dir=scenario_dir,
                artifact_dir=runtime_dir,
                task_path=task_path,
                model=workload_model,
                base_url=workload_base_url,
                env_file=workload_env_file,
            )
        elif command_template:
            rendered = command_template.format(
                agent_dir=str(scenario_dir),
                artifact_dir=str(runtime_dir),
                profile=profile,
            )
            command = shlex.split(rendered)
        else:
            raise EnforcementError("workload has neither task nor command")
        execution = _execute(context, backend, command, timeout=timeout)
        evaluator_result = _parse_json_output(execution["stdout"])
        execution["evaluator_result"] = evaluator_result
        execution["stdout"] = execution["stdout"][-4000:]
        execution["stderr"] = execution["stderr"][-4000:]
        row["execution"] = execution
        if task_path is not None:
            eval_block = (
                evaluator_result.get("eval")
                if isinstance(evaluator_result, dict)
                else None
            )
            valid_evaluator = bool(
                evaluator_result
                and evaluator_result.get("schema_version")
                == "assa.workload_evaluator.exact.v1"
                and evaluator_result.get("task_id") == row["task_id"]
                and evaluator_result.get("exact_workspace") is True
                and evaluator_result.get("status") == "completed"
                and isinstance(eval_block, dict)
                and isinstance(eval_block.get("passed"), bool)
                and eval_block.get("status") in {"pass", "fail"}
                and execution["returncode"] in {0, 10}
            )
            row["success"] = bool(
                valid_evaluator
                and execution["returncode"] == 0
                and eval_block["passed"]
            )
            row["paper_admissible"] = bool(
                valid_evaluator and not execution["timed_out"]
            )
        else:
            row["success"] = (
                execution["returncode"] == 0 and not execution["timed_out"]
            )
            row["paper_admissible"] = execution["returncode"] not in {
                None, 125, 126, 127
            }
    except (EnforcementError, OSError, ValueError) as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if setup_started:
            try:
                row["teardown"] = backend.teardown(context)
            except (EnforcementError, OSError) as exc:
                row["teardown"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
                row["paper_admissible"] = False
        shutil.rmtree(scenario_dir, ignore_errors=True)
    return row

def _aggregate(attacks: list[dict], workloads: list[dict]) -> dict:
    groups: dict[str, dict] = {}
    for row in attacks:
        key = f"{row['backend']}:L{row['level']}"
        group = groups.setdefault(key, {
            "backend": row["backend"],
            "level": row["level"],
            "attack_scenarios": 0,
            "admissible_attacks": 0,
            "blocked_attacks": 0,
            "workload_scenarios": 0,
            "admissible_workloads": 0,
            "successful_workloads": 0,
        })
        group["attack_scenarios"] += 1
        group["admissible_attacks"] += int(row["paper_admissible"])
        group["blocked_attacks"] += int(row.get("blocked") is True)
    for row in workloads:
        key = f"{row['backend']}:L{row['level']}"
        group = groups.setdefault(key, {
            "backend": row["backend"], "level": row["level"],
            "attack_scenarios": 0, "admissible_attacks": 0, "blocked_attacks": 0,
            "workload_scenarios": 0, "admissible_workloads": 0, "successful_workloads": 0,
        })
        group["workload_scenarios"] += 1
        group["admissible_workloads"] += int(row["paper_admissible"])
        group["successful_workloads"] += int(row.get("success") is True)
    for group in groups.values():
        denominator = group["admissible_attacks"]
        group["protection_rate"] = (
            group["blocked_attacks"] / denominator if denominator else None
        )
        workload_denominator = group["admissible_workloads"]
        group["workload_success_rate"] = (
            group["successful_workloads"] / workload_denominator
            if workload_denominator else None
        )
    return {"by_backend_level": [groups[key] for key in sorted(groups)]}


def _parse_workloads(values: list[str]) -> list[tuple[str, str]]:
    result = []
    for value in values:
        if "::" not in value:
            raise SystemExit("--workload-command expects PROFILE::COMMAND")
        profile, command = value.split("::", 1)
        result.append((profile.strip().upper(), command.strip()))
    return result


def _parse_workload_tasks(values: list[str]) -> list[tuple[str, Path]]:
    result = []
    for value in values:
        task_path = Path(value).resolve()
        if not task_path.is_file():
            raise SystemExit(f"workload task is missing: {task_path}")
        try:
            task = Task.from_json_path(task_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise SystemExit(f"invalid workload task {task_path}: {exc}") from exc
        result.append((task.profile, task_path))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Run real prevention baselines")
    parser.add_argument("--seed", required=True, help="Pristine active-scaffold agent directory")
    parser.add_argument("--agent-user", required=True, help="Unprivileged OS user used by the agent")
    parser.add_argument("--backends", nargs="+", default=["dac", "immutable", "apparmor", "landlock"])
    parser.add_argument("--levels", default="0,1,2,3,4,5")
    parser.add_argument("--attacks", nargs="+", default=["all"])
    parser.add_argument("--workload-command", action="append", default=[], help="PROFILE::COMMAND; supports {agent_dir}, {artifact_dir}, and {profile}")
    parser.add_argument("--workload-task", action="append", default=[], help="Task JSON executed by the exact-workspace evaluator")
    parser.add_argument("--workload-model", default=os.environ.get("OPENCLAW_MODEL"))
    parser.add_argument("--workload-base-url", default=os.environ.get("OPENCLAW_BASE_URL"))
    parser.add_argument("--workload-env-file", default="api_keys.env")
    parser.add_argument("--runtime-write", action="append", default=[], help="Additional Landlock-writable runtime path")
    parser.add_argument("--landlock-launcher")
    parser.add_argument("--work-root", default="results/prevention_real/work")
    parser.add_argument("--output", default="results/prevention_real/result.json")
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args()

    seed = Path(args.seed).resolve()
    if not seed.is_dir():
        raise SystemExit(f"seed is not a directory: {seed}")
    identity = AgentIdentity.resolve(args.agent_user)
    try:
        identity_audit = audit_agent_identity(args.agent_user)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    levels = [int(value) for value in args.levels.split(",") if value.strip()]
    attack_ids = sorted(CANONICAL_ATTACKS) if args.attacks == ["all"] else args.attacks
    unknown = sorted(set(attack_ids) - set(CANONICAL_ATTACKS))
    if unknown:
        raise SystemExit(f"unknown attacks: {unknown}")
    missing_targets = sorted({
        CANONICAL_ATTACKS[attack_id].target_file for attack_id in attack_ids
        if not (seed / CANONICAL_ATTACKS[attack_id].target_file).is_file()
    })
    if missing_targets:
        raise SystemExit(f"seed is missing canonical targets: {missing_targets}")
    workloads = [
        (profile, command, None)
        for profile, command in _parse_workloads(args.workload_command)
    ]
    workloads.extend(
        (profile, None, task_path)
        for profile, task_path in _parse_workload_tasks(args.workload_task)
    )
    work_root = (EXPERIMENTS_ROOT / args.work_root).resolve()
    output = (EXPERIMENTS_ROOT / args.output).resolve()
    artifact_root = output.parent / "artifacts"
    for label, path in (("work root", work_root), ("output", output), ("artifact root", artifact_root)):
        if path == seed or seed in path.parents:
            raise SystemExit(f"{label} must be outside the seed: {path}")
    work_root.mkdir(parents=True, exist_ok=True)
    artifact_root.mkdir(parents=True, exist_ok=True)
    launcher = Path(args.landlock_launcher).resolve() if args.landlock_launcher else None
    runtime_write_paths = [Path(path).resolve() for path in args.runtime_write]
    workload_env_file = Path(args.workload_env_file).resolve()

    attack_rows = []
    workload_rows = []
    for backend in args.backends:
        for level in levels:
            for attack_id in attack_ids:
                row = run_attack_scenario(
                    seed=seed,
                    work_root=work_root,
                    artifact_root=artifact_root,
                    backend_name=backend,
                    level=level,
                    attack_id=attack_id,
                    identity=identity,
                    landlock_launcher=launcher,
                    runtime_write_paths=runtime_write_paths,
                    timeout=args.timeout,
                )
                attack_rows.append(row)
                print(f"{backend} L{level} {attack_id}: blocked={row.get('blocked')} admissible={row['paper_admissible']}")
            for profile, command, task_path in workloads:
                workload_rows.append(run_workload_scenario(
                    seed=seed,
                    work_root=work_root,
                    artifact_root=artifact_root,
                    backend_name=backend,
                    level=level,
                    profile=profile,
                    command_template=command,
                    task_path=task_path,
                    identity=identity,
                    landlock_launcher=launcher,
                    runtime_write_paths=runtime_write_paths,
                    workload_model=args.workload_model,
                    workload_base_url=args.workload_base_url,
                    workload_env_file=workload_env_file,
                    timeout=args.timeout,
                ))

    payload = {
        "schema_version": SCHEMA_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": runtime_manifest([launcher] if launcher else []),
        "seed": str(seed),
        "agent_identity": {"name": identity.name, "uid": identity.uid, "gid": identity.gid},
        "agent_identity_audit": identity_audit,
        "backends": args.backends,
        "levels": levels,
        "attack_results": attack_rows,
        "workload_results": workload_rows,
        "summary": _aggregate(attack_rows, workload_rows),
        "protection_admissible": bool(
            attack_rows and all(row["paper_admissible"] for row in attack_rows)
        ),
        "functionality_admissible": bool(
            workload_rows and all(row["paper_admissible"] for row in workload_rows)
        ),
    }
    payload["paper_admissible"] = bool(
        payload["protection_admissible"] and payload["functionality_admissible"]
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {output}")
    return 0 if payload["paper_admissible"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
