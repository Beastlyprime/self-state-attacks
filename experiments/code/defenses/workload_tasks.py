"""Stage benchmark tasks into a canonical active-scaffold agent directory."""

from __future__ import annotations

import hashlib
import shutil
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tasks.schema import Task  # noqa: E402
from workload.agent_packs import apply_instruction_pack  # noqa: E402


EXPERIMENTS_ROOT = Path(__file__).resolve().parents[2]
TASKS_ROOT = EXPERIMENTS_ROOT / "tasks"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def task_seed_destination(agent_dir: Path, relative: str) -> Path:
    """Map a task seed path onto the canonical state-root layout.

    The active scaffold keeps configuration at ``agent_dir/openclaw.json``
    and user-visible files under ``agent_dir/workspace``. Task specs were
    authored against a bare workspace, so the config path needs one explicit
    projection while every other seed remains workspace-relative.
    """
    if relative.startswith("/") or ".." in relative.split("/"):
        raise ValueError(f"task seed path must be relative: {relative!r}")
    if relative == "openclaw.json":
        return agent_dir / relative
    return agent_dir / "workspace" / relative


def prepare_workload_task(task: Task, agent_dir: Path) -> dict:
    """Apply the profile pack and stage task inputs before policy setup."""
    agent_dir = agent_dir.resolve()
    workspace = agent_dir / "workspace"
    if not workspace.is_dir():
        raise ValueError(f"canonical workspace is missing: {workspace}")

    pack = apply_instruction_pack(
        workspace,
        profile=task.profile,
        overwrite_defaults=True,
        strict=True,
    )
    staged = []
    for seed in task.seed_files:
        source = TASKS_ROOT / seed.content_ref
        if not source.is_file():
            raise FileNotFoundError(
                f"task seed source is missing: {source} ({task.task_id})"
            )
        destination = task_seed_destination(agent_dir, seed.path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.is_symlink():
            raise ValueError(f"refusing to replace symlink task target: {destination}")
        shutil.copy2(source, destination)
        staged.append(
            {
                "task_path": seed.path,
                "destination": str(destination),
                "source": str(source.resolve()),
                "sha256": _sha256(destination),
                "size": destination.stat().st_size,
            }
        )

    return {
        "task_id": task.task_id,
        "profile": task.profile,
        "workspace": str(workspace),
        "config_path": str(agent_dir / "openclaw.json"),
        "instruction_pack": {
            "agent_id": pack["agent_id"],
            "pack_dir": pack["pack_dir"],
            "seeded": pack["seeded"],
            "skipped": pack["skipped"],
        },
        "staged": staged,
    }


__all__ = ["prepare_workload_task", "task_seed_destination"]
