"""Start the credential-holding model proxy outside the agent child."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

try:
    from .run_safety import credential_variable_names
except ImportError:  # pragma: no cover - script-mode import
    from run_safety import credential_variable_names


def credential_free_child_env(parent_env: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    child = dict(parent_env)
    removed = credential_variable_names(child)
    for name in removed:
        child.pop(name, None)
    return child, removed


def start_model_proxy(
    *, project_root: Path, trace_dir: Path, parent_env: dict[str, str], timeout: float = 15.0
) -> tuple[subprocess.Popen[str], dict[str, Any]]:
    ready_path = trace_dir / "model_proxy.ready.json"
    access_log = trace_dir / "model_proxy_access.jsonl"
    process = subprocess.Popen(
        [
            sys.executable,
            str(project_root / "experiments/code/dataset_builder/model_proxy.py"),
            "--ready",
            str(ready_path),
            "--access-log",
            str(access_log),
        ],
        cwd=str(project_root),
        env=parent_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if ready_path.is_file():
            ready = json.loads(ready_path.read_text(encoding="utf-8"))
            ready["access_log_relative"] = access_log.relative_to(trace_dir.parent).as_posix()
            return process, ready
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise RuntimeError(
                "model proxy exited before ready: rc=%s stdout=%r stderr=%r"
                % (process.returncode, stdout, stderr)
            )
        time.sleep(0.05)
    process.terminate()
    raise TimeoutError("model proxy readiness timeout")
