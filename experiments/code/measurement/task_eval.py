"""Per-kind task success evaluators.

Each `Task.success_criterion["kind"]` maps to one evaluator:

- "none"              → always skipped; trace-only tasks without a scoring rule
- "unittest_exit_zero"→ W1 — run ``python -m unittest <module>_test`` in the
                         workspace and pass iff exit code == 0
- "qa_answer_match"   → W2 — fuzzy-compare the last assistant message against
                         ``gold_answer`` (lowercase + alphanumeric + whitespace
                         normalization, same shape as HotpotQA's EM)
- "bash_state_check"  → W3 v1 (archived) — run ``check_command`` in the
                         workspace root and assert stdout equals
                         ``expected_output``
- "file_state_check"  → W3 and scored W4 tasks — per-file substring / JSON-path assertions
                         against workspace-relative files (openclaw.json,
                         TOOLS.md, etc.)

Scope: this module is a pure evaluator; it doesn't run the harness or
collect traces. The pilot/experiment runner imports and calls
`evaluate_task(task, workspace_root, assistant_last_message)`.

No third-party deps — stdlib only.
"""

from __future__ import annotations

import json
import re
import subprocess
from decimal import Decimal, InvalidOperation
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from tasks.schema import Task


# --------------------------------------------------------------- result type


@dataclass
class EvalResult:
    """Outcome of one task evaluation.

    Attributes:
        kind: same value as `task.success_criterion["kind"]`.
        status: one of "pass", "fail", "skipped", "error".
        passed: True iff status == "pass". False for everything else.
        detail: freeform string for humans — gold vs actual, stderr tail, etc.
        extra: kind-specific fields (exit code, match fraction, stdout hash).
    """

    kind: str
    status: str
    passed: bool
    detail: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "status": self.status,
            "passed": self.passed,
            "detail": self.detail,
            "extra": dict(self.extra),
        }


# --------------------------------------------------------------- W1: unittest


def _find_unittest_module(workspace: Path, task: Optional[Task] = None) -> Optional[str]:
    """Pick the `<module>_test.py` file the task wants us to run.

    Single-task mode: Aider polyglot tasks stage exactly one `<module>_test.py`,
    so a bare workspace glob is unambiguous.

    Chain mode: prior tasks have left THEIR test files in the workspace too
    (we intentionally don't wipe between chained tasks). Fall back to the
    task's seed_files to pick the right one — a seed whose workspace path
    ends in `_test.py` is the test module this task is asking us to run.
    """
    # Task-seed-first path: works in both modes and is unambiguous.
    if task is not None:
        seed_tests = [
            s.path for s in task.seed_files
            if s.path.endswith("_test.py") and "/" not in s.path
        ]
        if len(seed_tests) == 1:
            return Path(seed_tests[0]).stem  # "affine_cipher_test"
    # Fallback: legacy glob heuristic (for callers that can't pass a Task).
    candidates = sorted(p for p in workspace.glob("*_test.py") if p.is_file())
    if len(candidates) != 1:
        return None
    return candidates[0].stem


def _eval_unittest_exit_zero(task: Task, workspace: Path) -> EvalResult:
    module = _find_unittest_module(workspace, task=task)
    if module is None:
        return EvalResult(
            kind="unittest_exit_zero",
            status="error",
            passed=False,
            detail="no *_test.py (or multiple) at workspace root",
        )
    try:
        proc = subprocess.run(
            ["python3", "-m", "unittest", module],
            cwd=str(workspace),
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        return EvalResult(
            kind="unittest_exit_zero",
            status="error",
            passed=False,
            detail=f"unittest timeout after {exc.timeout}s",
            extra={"module": module},
        )
    except OSError as exc:
        return EvalResult(
            kind="unittest_exit_zero",
            status="error",
            passed=False,
            detail=f"subprocess failed: {exc}",
            extra={"module": module},
        )

    passed = proc.returncode == 0
    # unittest prints its run summary on stderr.
    tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-3:]
    return EvalResult(
        kind="unittest_exit_zero",
        status="pass" if passed else "fail",
        passed=passed,
        detail=" | ".join(tail)[:400],
        extra={
            "module": module,
            "returncode": proc.returncode,
        },
    )


# --------------------------------------------------------------- W2: qa match


_QA_NORMALIZE_RE = re.compile(r"[^a-z0-9\s]")


def _normalize_answer(text: str) -> str:
    """HotpotQA-style normalization: lowercase, strip punctuation, collapse
    whitespace, remove leading articles."""
    t = text.strip().lower()
    t = _QA_NORMALIZE_RE.sub(" ", t)
    t = " ".join(t.split())
    for art in ("a ", "an ", "the "):
        if t.startswith(art):
            t = t[len(art):]
    return t


_NUMERIC_ANSWER_RE = re.compile(
    r"^\s*([+-]?\d[\d,\s]*(?:\.\d+)?)\s*([a-zA-Z%]+)?[.\s]*$"
)


def _numeric_answer(text: str) -> tuple[Decimal, str] | None:
    match = _NUMERIC_ANSWER_RE.fullmatch(text)
    if match is None:
        return None
    number_text = match.group(1).replace(",", "").replace(" ", "")
    try:
        value = Decimal(number_text)
    except InvalidOperation:
        return None
    return value, (match.group(2) or "").lower()


def _eval_qa_answer_match(
    task: Task, workspace: Path, assistant_last: Optional[str]
) -> EvalResult:
    gold = str(task.success_criterion.get("gold_answer", "")).strip()
    mode = str(task.success_criterion.get("match_mode", "fuzzy"))
    if not gold:
        return EvalResult(
            kind="qa_answer_match",
            status="error",
            passed=False,
            detail="success_criterion.gold_answer missing or empty",
        )
    if assistant_last is None:
        return EvalResult(
            kind="qa_answer_match",
            status="fail",
            passed=False,
            detail="no assistant message to evaluate",
            extra={"gold": gold, "mode": mode},
        )

    gold_n = _normalize_answer(gold)
    pred_n = _normalize_answer(assistant_last)

    if mode == "exact":
        passed = pred_n == gold_n
    else:  # fuzzy — gold appears as a substring of the normalized prediction
        passed = bool(gold_n) and gold_n in pred_n
        gold_numeric = _numeric_answer(gold)
        pred_numeric = _numeric_answer(assistant_last)
        if gold_numeric is not None and pred_numeric is not None:
            gold_value, gold_unit = gold_numeric
            pred_value, pred_unit = pred_numeric
            compatible_unit = not pred_unit or pred_unit == gold_unit
            passed = gold_value == pred_value and compatible_unit

    detail = f"gold={gold!r}; pred_tail={assistant_last.strip()[:120]!r}"
    return EvalResult(
        kind="qa_answer_match",
        status="pass" if passed else "fail",
        passed=passed,
        detail=detail,
        extra={"gold": gold, "mode": mode, "gold_n": gold_n, "pred_n": pred_n[:200]},
    )


# --------------------------------------------------------------- W3: bash state


def _eval_bash_state_check(task: Task, workspace: Path) -> EvalResult:
    sc = task.success_criterion
    cmd = sc.get("check_command")
    expected = sc.get("expected_output")
    timeout = int(sc.get("timeout_sec", 30))
    if not isinstance(cmd, str) or not cmd.strip():
        return EvalResult(
            kind="bash_state_check",
            status="error",
            passed=False,
            detail="success_criterion.check_command missing",
        )
    if expected is None:
        return EvalResult(
            kind="bash_state_check",
            status="error",
            passed=False,
            detail="success_criterion.expected_output missing",
        )

    try:
        proc = subprocess.run(
            ["bash", "-c", cmd],
            cwd=str(workspace),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return EvalResult(
            kind="bash_state_check",
            status="error",
            passed=False,
            detail=f"check_command timeout after {exc.timeout}s",
            extra={"check_command": cmd},
        )
    except OSError as exc:
        return EvalResult(
            kind="bash_state_check",
            status="error",
            passed=False,
            detail=f"check subprocess failed: {exc}",
            extra={"check_command": cmd},
        )

    stdout = proc.stdout
    passed = stdout == expected
    detail_parts = [f"returncode={proc.returncode}"]
    if not passed:
        # Show first divergence.
        for i, (a, b) in enumerate(zip(stdout, expected)):
            if a != b:
                detail_parts.append(f"diff_at={i} got={a!r} exp={b!r}")
                break
        detail_parts.append(
            f"got_len={len(stdout)} exp_len={len(expected)}"
        )
    return EvalResult(
        kind="bash_state_check",
        status="pass" if passed else "fail",
        passed=passed,
        detail=" ".join(detail_parts)[:400],
        extra={
            "check_command": cmd,
            "returncode": proc.returncode,
            "stdout_head": stdout[:200],
            "expected_head": expected[:200],
            "stderr_tail": proc.stderr[-200:] if proc.stderr else "",
        },
    )


# --------------------------------------------------------------- W3 v2: file state


# Sentinel: used to distinguish "key resolved to None" from "key absent".
_PATH_MISSING = object()


def _resolve_json_path(obj: Any, dotted: str) -> Any:
    """Resolve ``a.b.c`` on a nested dict/list structure.

    Integer path segments index into lists. Returns ``_PATH_MISSING`` if
    any segment is absent. JSON null is returned as Python None — it is
    NOT the same as missing.
    """
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict):
            if part not in cur:
                return _PATH_MISSING
            cur = cur[part]
            continue
        if isinstance(cur, list):
            try:
                idx = int(part)
            except ValueError:
                return _PATH_MISSING
            if not 0 <= idx < len(cur):
                return _PATH_MISSING
            cur = cur[idx]
            continue
        # Scalar — can't descend further.
        return _PATH_MISSING
    return cur


def _run_single_check(check: dict[str, Any], workspace: Path) -> tuple[bool, str]:
    """Run one check entry; return (passed, short_detail)."""
    ctype = check.get("type")
    rel = check.get("path")
    if not isinstance(rel, str) or not rel.strip():
        return False, f"check missing 'path': {check!r}"
    # Guard against ../ or absolute paths escaping the workspace.
    if rel.startswith("/") or ".." in rel.split("/"):
        return False, f"check 'path' must be workspace-relative: {rel!r}"

    target = workspace / rel
    if not target.exists():
        return False, f"{rel}: file not found"
    if not target.is_file():
        return False, f"{rel}: not a regular file"

    if ctype == "file_contains":
        needle = check.get("substring")
        if not isinstance(needle, str):
            return False, f"{rel}: file_contains needs 'substring' string"
        try:
            content = target.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return False, f"{rel}: read failed: {exc}"
        if needle in content:
            return True, f"{rel}: contains {needle!r}"
        return False, f"{rel}: missing substring {needle!r}"

    if ctype == "file_equals":
        expected = check.get("content")
        if not isinstance(expected, str):
            return False, f"{rel}: file_equals needs 'content' string"
        try:
            content = target.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return False, f"{rel}: read failed: {exc}"
        actual_normalized = content.replace("\r\n", "\n").removesuffix("\n")
        expected_normalized = expected.replace("\r\n", "\n").removesuffix("\n")
        if actual_normalized == expected_normalized:
            return True, f"{rel}: content matches"
        return False, (
            f"{rel}: content differs "
            f"(got {len(actual_normalized)} chars, want {len(expected_normalized)})"
        )

    if ctype in ("json_path_equals", "json_path_exists"):
        jp = check.get("json_path")
        if not isinstance(jp, str) or not jp.strip():
            return False, f"{rel}: {ctype} needs non-empty 'json_path'"
        try:
            raw = target.read_text(encoding="utf-8")
            payload = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            return False, f"{rel}: JSON parse failed: {exc}"
        resolved = _resolve_json_path(payload, jp)
        if resolved is _PATH_MISSING:
            return False, f"{rel}#{jp}: path not present"
        if ctype == "json_path_exists":
            return True, f"{rel}#{jp}: present"
        # json_path_equals
        if "equals" not in check:
            return False, f"{rel}#{jp}: json_path_equals needs 'equals'"
        expected = check["equals"]
        if resolved == expected:
            return True, f"{rel}#{jp} == {expected!r}"
        return False, f"{rel}#{jp}: got {resolved!r}, want {expected!r}"

    return False, f"unknown check type {ctype!r}"


def _eval_file_state_check(task: Task, workspace: Path) -> EvalResult:
    sc = task.success_criterion
    checks = sc.get("checks")
    if not isinstance(checks, list) or not checks:
        return EvalResult(
            kind="file_state_check",
            status="error",
            passed=False,
            detail="success_criterion.checks must be a non-empty list",
        )
    all_must_pass = bool(sc.get("all_must_pass", True))

    results: list[tuple[bool, str]] = []
    for c in checks:
        if not isinstance(c, dict):
            results.append((False, f"non-dict check entry: {c!r}"))
            continue
        results.append(_run_single_check(c, workspace))

    passed_flags = [p for p, _ in results]
    if all_must_pass:
        passed = all(passed_flags)
    else:
        passed = any(passed_flags)

    # Short detail: show which passed / failed.
    summary_parts = []
    for i, (p, detail) in enumerate(results):
        summary_parts.append(f"[{i}]{'✓' if p else '✗'} {detail}")
    detail = " | ".join(summary_parts)[:400]

    return EvalResult(
        kind="file_state_check",
        status="pass" if passed else "fail",
        passed=passed,
        detail=detail,
        extra={
            "check_count": len(checks),
            "pass_count": sum(passed_flags),
            "mode": "all" if all_must_pass else "any",
            "per_check": [
                {"passed": p, "detail": d} for p, d in results
            ],
        },
    )


# --------------------------------------------------------------- dispatcher


def evaluate_task(
    task: Task,
    workspace_root: Path | str,
    assistant_last_message: Optional[str] = None,
) -> EvalResult:
    """Dispatch on ``task.success_criterion["kind"]`` and return an EvalResult.

    ``assistant_last_message`` is only consumed by the QA evaluator; other
    kinds ignore it. The workspace should be the directory the harness ran
    in (seeds staged, agent writes applied).
    """
    kind = task.success_criterion.get("kind")
    workspace = Path(workspace_root)

    if kind == "none":
        return EvalResult(
            kind="none",
            status="skipped",
            passed=False,
            detail="trace-only task (no scoring)",
        )
    if kind == "unittest_exit_zero":
        return _eval_unittest_exit_zero(task, workspace)
    if kind == "qa_answer_match":
        return _eval_qa_answer_match(task, workspace, assistant_last_message)
    if kind == "bash_state_check":
        return _eval_bash_state_check(task, workspace)
    if kind == "file_state_check":
        return _eval_file_state_check(task, workspace)

    return EvalResult(
        kind=str(kind),
        status="error",
        passed=False,
        detail=f"unknown success_criterion.kind: {kind!r}",
    )


__all__ = ["EvalResult", "evaluate_task"]
