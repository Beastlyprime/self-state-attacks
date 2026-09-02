"""bash tool — port of pi-coding-agent/src/core/tools/bash.ts.

SPEC §6.1 — synchronous shell exec. Returns stdout/stderr/exit_code. Working
directory defaults to the workspace root. Subject to process timeout.

Fidelity notes:
- Upstream pi-coding-agent spawns via child_process.exec with a configurable
  shell and merges stderr/stdout streams into a single structured result. We
  mirror that with subprocess.run(shell=True).
- Upstream clamps output size to prevent OOM. We apply the same cap.
- OpenClaw adds an approval flow (tools.exec.security, `allowlist`,
  `denylist`). In the harness that layer is OFF by default per user decision
  (2026-04-22) — many coding tasks need lint/test/grep and a research harness
  should not gate them.
- We still apply the process timeout.

Trace consequence: bash invocations can produce arbitrary file events. The
trace collector records them verbatim. That is the correct behavior — we
want bash-originating writes to appear as LLM actions in the anomaly
baseline, because the LLM *did* request them.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from typing import Optional


DEFAULT_BASH_TIMEOUT_S = 60
MAX_BASH_TIMEOUT_S = 600

# Upstream clamps combined output to ~200 KB. We use the same ceiling to
# avoid blowing up the LLM context with accidental cat-binary style output.
MAX_OUTPUT_BYTES = 200 * 1024
TOOL_SANDBOX_REQUIRED_ENV = "ASSA_TOOL_SANDBOX_REQUIRED"
TOOL_SANDBOX_PREFIX_ENV = "ASSA_TOOL_SANDBOX_PREFIX_JSON"


@dataclass
class ToolBashResult:
    """Return value for `bash` tool invocations.

    Attributes:
        ok: True if the process exited (regardless of exit code).
        error: Non-None if the invocation failed to run (e.g. timeout).
        exit_code: Process exit code; -1 on timeout.
        stdout: Captured stdout (clamped to MAX_OUTPUT_BYTES, UTF-8-safe).
        stderr: Captured stderr (same clamp).
        timed_out: True if the process was killed by timeout.
        truncated: True if stdout or stderr was clamped.
        elapsed_ms: Wall-clock milliseconds between start and finish.
    """

    ok: bool
    error: Optional[str] = None
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    truncated: bool = False
    elapsed_ms: int = 0


def _clamp_output(raw: bytes) -> tuple[str, bool]:
    """Clamp and UTF-8 decode. Returns (decoded_string, truncated_flag)."""
    truncated = False
    if len(raw) > MAX_OUTPUT_BYTES:
        raw = raw[:MAX_OUTPUT_BYTES]
        truncated = True
    # Replace non-UTF-8 bytes rather than failing — matches upstream.
    return raw.decode("utf-8", errors="replace"), truncated


def bash_tool(
    command: str,
    *,
    workspace_root: str,
    timeout: Optional[int] = None,
    env: Optional[dict[str, str]] = None,
) -> ToolBashResult:
    """Execute the `bash` tool.

    Args:
        command: shell command. Executed via `subprocess.run(shell=True)`.
        workspace_root: working directory for the subprocess.
        timeout: timeout in seconds. Default 60, max 600.
        env: environment. Defaults to os.environ.

    Returns:
        ToolBashResult.
    """
    if timeout is None:
        timeout = DEFAULT_BASH_TIMEOUT_S
    if timeout < 1:
        return ToolBashResult(
            ok=False,
            error="validation: timeout must be >= 1 second",
            exit_code=-1,
        )
    if timeout > MAX_BASH_TIMEOUT_S:
        timeout = MAX_BASH_TIMEOUT_S

    if not os.path.isdir(workspace_root):
        return ToolBashResult(
            ok=False,
            error=f"validation: workspace_root is not a directory: {workspace_root}",
            exit_code=-1,
        )

    import time

    start = time.monotonic()
    child_env = env if env is not None else os.environ.copy()
    required = child_env.get(TOOL_SANDBOX_REQUIRED_ENV) == "1"
    prefix_raw = child_env.get(TOOL_SANDBOX_PREFIX_ENV)
    prefix: list[str] = []
    if prefix_raw:
        try:
            parsed_prefix = json.loads(prefix_raw)
        except json.JSONDecodeError as exc:
            return ToolBashResult(
                ok=False,
                error=f"safety: invalid sandbox prefix JSON: {exc}",
                exit_code=-1,
            )
        if not isinstance(parsed_prefix, list) or not all(
            isinstance(item, str) and item for item in parsed_prefix
        ):
            return ToolBashResult(
                ok=False,
                error="safety: sandbox prefix must be a non-empty string list",
                exit_code=-1,
            )
        prefix = parsed_prefix
    if required and not prefix:
        return ToolBashResult(
            ok=False,
            error="safety: no-network sandbox is required but not configured",
            exit_code=-1,
        )

    try:
        if prefix:
            completed = subprocess.run(
                [*prefix, "/bin/sh", "-c", command],
                shell=False,
                cwd=workspace_root,
                env=child_env,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        else:
            completed = subprocess.run(
                command,
                shell=True,
                cwd=workspace_root,
                env=child_env,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
    except subprocess.TimeoutExpired as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        # `exc.stdout` / `exc.stderr` may carry partial output captured before kill.
        partial_stdout, stdout_trunc = _clamp_output(exc.stdout or b"")
        partial_stderr, stderr_trunc = _clamp_output(exc.stderr or b"")
        return ToolBashResult(
            ok=False,
            error=f"timeout after {timeout}s",
            exit_code=-1,
            stdout=partial_stdout,
            stderr=partial_stderr,
            timed_out=True,
            truncated=stdout_trunc or stderr_trunc,
            elapsed_ms=elapsed_ms,
        )
    except OSError as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return ToolBashResult(
            ok=False,
            error=f"io: spawn failed: {exc}",
            exit_code=-1,
            elapsed_ms=elapsed_ms,
        )

    elapsed_ms = int((time.monotonic() - start) * 1000)
    stdout, stdout_trunc = _clamp_output(completed.stdout)
    stderr, stderr_trunc = _clamp_output(completed.stderr)

    return ToolBashResult(
        ok=True,
        exit_code=completed.returncode,
        stdout=stdout,
        stderr=stderr,
        truncated=stdout_trunc or stderr_trunc,
        elapsed_ms=elapsed_ms,
    )
