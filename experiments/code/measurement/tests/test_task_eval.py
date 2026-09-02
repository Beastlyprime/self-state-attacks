"""Tests for measurement.task_eval — the four per-kind evaluators.

Each test builds a synthetic Task (using tasks.schema.Task directly) + a
tempdir workspace, runs evaluate_task, and asserts the EvalResult.

Stdlib unittest, no pytest fixtures; lives under `measurement/tests/` so
it stays near the code it exercises.
"""

from __future__ import annotations

import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

# Repo-root-relative imports when running as `python -m unittest`.
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from measurement.task_eval import evaluate_task  # noqa: E402
from tasks.schema import DatasetSource, SeedFile, Task  # noqa: E402


def _mk_task(
    *,
    task_id: str = "W1_C1_V1",
    profile: str = "W1",
    cluster: int = 1,
    variant: int = 1,
    cluster_name: str = "string-encoding",
    success_criterion: dict | None = None,
    prompt: str = "do the thing",
) -> Task:
    return Task(
        task_id=task_id,
        profile=profile,
        cluster=cluster,
        variant=variant,
        cluster_name=cluster_name,
        dataset_source=DatasetSource(
            name="unit-test",
            license="CC-BY 4.0",
            citation="synthetic",
        ),
        seed_files=[],
        prompt=prompt,
        success_criterion=success_criterion or {"kind": "none"},
    )


class NoneEvalTests(unittest.TestCase):
    def test_none_kind_is_skipped(self) -> None:
        task = _mk_task(success_criterion={"kind": "none"})
        with tempfile.TemporaryDirectory() as root:
            r = evaluate_task(task, root)
        self.assertEqual(r.kind, "none")
        self.assertEqual(r.status, "skipped")
        self.assertFalse(r.passed)


class UnittestEvalTests(unittest.TestCase):
    def _make_w1_workspace(self, module_name: str, source: str, test_source: str) -> Path:
        root = Path(tempfile.mkdtemp())
        (root / f"{module_name}.py").write_text(source)
        (root / f"{module_name}_test.py").write_text(test_source)
        return root

    def test_passing_unittest_returns_pass(self) -> None:
        source = "def add(a, b):\n    return a + b\n"
        test = textwrap.dedent(
            """
            import unittest
            from add import add

            class T(unittest.TestCase):
                def test_basic(self):
                    self.assertEqual(add(1, 2), 3)
            """
        )
        root = self._make_w1_workspace("add", source, test)
        task = _mk_task(
            task_id="W1_C2_V1",
            cluster=2,
            cluster_name="data",
            success_criterion={"kind": "unittest_exit_zero"},
        )
        r = evaluate_task(task, root)
        self.assertEqual(r.status, "pass")
        self.assertTrue(r.passed)
        self.assertEqual(r.extra["returncode"], 0)

    def test_failing_unittest_returns_fail(self) -> None:
        source = "def add(a, b):\n    return a - b  # wrong\n"
        test = textwrap.dedent(
            """
            import unittest
            from add import add

            class T(unittest.TestCase):
                def test_basic(self):
                    self.assertEqual(add(1, 2), 3)
            """
        )
        root = self._make_w1_workspace("add", source, test)
        task = _mk_task(
            task_id="W1_C3_V1",
            cluster=3,
            cluster_name="algo",
            success_criterion={"kind": "unittest_exit_zero"},
        )
        r = evaluate_task(task, root)
        self.assertEqual(r.status, "fail")
        self.assertFalse(r.passed)
        self.assertNotEqual(r.extra["returncode"], 0)

    def test_missing_test_file_is_error(self) -> None:
        root = Path(tempfile.mkdtemp())
        (root / "lone.py").write_text("x = 1\n")
        task = _mk_task(success_criterion={"kind": "unittest_exit_zero"})
        r = evaluate_task(task, root)
        self.assertEqual(r.status, "error")


class QaMatchTests(unittest.TestCase):
    def test_fuzzy_substring_passes(self) -> None:
        task = _mk_task(
            profile="W2",
            task_id="W2_C1_V1",
            cluster_name="bridge-entity",
            success_criterion={
                "kind": "qa_answer_match",
                "gold_answer": "Wendell Berry",
                "match_mode": "fuzzy",
            },
        )
        with tempfile.TemporaryDirectory() as root:
            r = evaluate_task(task, root, "The author is Wendell Berry.")
        self.assertEqual(r.status, "pass")

    def test_article_prefix_ignored(self) -> None:
        task = _mk_task(
            profile="W2",
            task_id="W2_C2_V1",
            cluster=2,
            cluster_name="bridge-num",
            success_criterion={
                "kind": "qa_answer_match",
                "gold_answer": "The United Nations",
                "match_mode": "fuzzy",
            },
        )
        with tempfile.TemporaryDirectory() as root:
            # Normalization strips leading "The" from both sides.
            r = evaluate_task(task, root, "united nations, founded 1945")
        self.assertEqual(r.status, "pass")

    def test_wrong_answer_fails(self) -> None:
        task = _mk_task(
            profile="W2",
            task_id="W2_C1_V2",
            cluster_name="bridge-entity",
            variant=2,
            success_criterion={
                "kind": "qa_answer_match",
                "gold_answer": "Paris",
                "match_mode": "fuzzy",
            },
        )
        with tempfile.TemporaryDirectory() as root:
            r = evaluate_task(task, root, "The answer is Berlin.")
        self.assertEqual(r.status, "fail")

    def test_fuzzy_numeric_answer_accepts_formatting_and_omitted_unit(self) -> None:
        task = _mk_task(
            profile="W2",
            task_id="W2_C1_V1",
            cluster_name="bridge-entity",
            success_criterion={
                "kind": "qa_answer_match",
                "gold_answer": "110,000cm.",
                "match_mode": "fuzzy",
            },
        )
        with tempfile.TemporaryDirectory() as root:
            equivalent = evaluate_task(task, root, "110000")
            wrong_unit = evaluate_task(task, root, "110000km")
        self.assertEqual(equivalent.status, "pass")
        self.assertEqual(wrong_unit.status, "fail")

    def test_exact_mode(self) -> None:
        task = _mk_task(
            profile="W2",
            task_id="W2_C3_V1",
            cluster=3,
            cluster_name="cmp-entity",
            success_criterion={
                "kind": "qa_answer_match",
                "gold_answer": "yes",
                "match_mode": "exact",
            },
        )
        with tempfile.TemporaryDirectory() as root:
            r_pass = evaluate_task(task, root, "Yes.")
            r_fail = evaluate_task(task, root, "Yes it is indeed.")
        self.assertEqual(r_pass.status, "pass")
        self.assertEqual(r_fail.status, "fail")

    def test_empty_message_fails(self) -> None:
        task = _mk_task(
            profile="W2",
            task_id="W2_C1_V3",
            cluster_name="bridge-entity",
            variant=3,
            success_criterion={
                "kind": "qa_answer_match",
                "gold_answer": "Paris",
            },
        )
        with tempfile.TemporaryDirectory() as root:
            r = evaluate_task(task, root, None)
        self.assertEqual(r.status, "fail")


class BashStateCheckTests(unittest.TestCase):
    def test_matching_stdout_passes(self) -> None:
        task = _mk_task(
            profile="W3",
            task_id="W3_C1_V1",
            cluster_name="find-list",
            success_criterion={
                "kind": "bash_state_check",
                "check_command": "printf 'a\\nb\\n'",
                "expected_output": "a\nb\n",
                "timeout_sec": 5,
            },
        )
        with tempfile.TemporaryDirectory() as root:
            r = evaluate_task(task, root)
        self.assertEqual(r.status, "pass")

    def test_mismatched_stdout_fails(self) -> None:
        task = _mk_task(
            profile="W3",
            task_id="W3_C1_V2",
            cluster_name="find-list",
            variant=2,
            success_criterion={
                "kind": "bash_state_check",
                "check_command": "echo wrong",
                "expected_output": "right\n",
                "timeout_sec": 5,
            },
        )
        with tempfile.TemporaryDirectory() as root:
            r = evaluate_task(task, root)
        self.assertEqual(r.status, "fail")
        self.assertIn("diff_at", r.detail)

    def test_workspace_relative_check_command(self) -> None:
        task = _mk_task(
            profile="W3",
            task_id="W3_C2_V1",
            cluster=2,
            cluster_name="count",
            success_criterion={
                "kind": "bash_state_check",
                "check_command": "wc -l < input.txt | tr -d ' '",
                "expected_output": "3\n",
                "timeout_sec": 5,
            },
        )
        with tempfile.TemporaryDirectory() as root:
            Path(root, "input.txt").write_text("a\nb\nc\n")
            r = evaluate_task(task, root)
        self.assertEqual(r.status, "pass")


class FileStateCheckTests(unittest.TestCase):
    """W3 v2 evaluator — per-file substring + JSON-path assertions."""

    def _mk_fs_task(self, checks, all_must_pass=True):
        return _mk_task(
            profile="W3",
            task_id="W3_C1_V1",
            cluster_name="tool-skill-mgmt",
            success_criterion={
                "kind": "file_state_check",
                "checks": checks,
                "all_must_pass": all_must_pass,
            },
        )

    def test_file_contains_passes(self) -> None:
        task = self._mk_fs_task(
            [{"type": "file_contains", "path": "TOOLS.md", "substring": "browser_fetch"}]
        )
        with tempfile.TemporaryDirectory() as root:
            Path(root, "TOOLS.md").write_text(
                "# Tools\n- browser_fetch: fetch URLs\n"
            )
            r = evaluate_task(task, root)
        self.assertEqual(r.status, "pass")
        self.assertTrue(r.passed)

    def test_file_contains_missing_substring_fails(self) -> None:
        task = self._mk_fs_task(
            [{"type": "file_contains", "path": "TOOLS.md", "substring": "ghost"}]
        )
        with tempfile.TemporaryDirectory() as root:
            Path(root, "TOOLS.md").write_text("# Tools\n- real\n")
            r = evaluate_task(task, root)
        self.assertEqual(r.status, "fail")
        self.assertIn("missing substring", r.detail)

    def test_missing_file_fails(self) -> None:
        task = self._mk_fs_task(
            [{"type": "file_contains", "path": "NOPE.md", "substring": "x"}]
        )
        with tempfile.TemporaryDirectory() as root:
            r = evaluate_task(task, root)
        self.assertEqual(r.status, "fail")
        self.assertIn("not found", r.detail)

    def test_json_path_equals_passes(self) -> None:
        task = self._mk_fs_task(
            [
                {
                    "type": "json_path_equals",
                    "path": "openclaw.json",
                    "json_path": "tools.browser_fetch.enabled",
                    "equals": True,
                }
            ]
        )
        with tempfile.TemporaryDirectory() as root:
            Path(root, "openclaw.json").write_text(
                '{"tools": {"browser_fetch": {"enabled": true}}}'
            )
            r = evaluate_task(task, root)
        self.assertEqual(r.status, "pass")

    def test_json_path_equals_wrong_value_fails(self) -> None:
        task = self._mk_fs_task(
            [
                {
                    "type": "json_path_equals",
                    "path": "openclaw.json",
                    "json_path": "api.timeout",
                    "equals": 30,
                }
            ]
        )
        with tempfile.TemporaryDirectory() as root:
            Path(root, "openclaw.json").write_text('{"api": {"timeout": 60}}')
            r = evaluate_task(task, root)
        self.assertEqual(r.status, "fail")
        self.assertIn("got 60", r.detail)

    def test_json_path_exists_passes_on_null_value(self) -> None:
        # JSON null is present, so json_path_exists should pass.
        task = self._mk_fs_task(
            [
                {
                    "type": "json_path_exists",
                    "path": "openclaw.json",
                    "json_path": "schedules.cleanup",
                }
            ]
        )
        with tempfile.TemporaryDirectory() as root:
            Path(root, "openclaw.json").write_text(
                '{"schedules": {"cleanup": null}}'
            )
            r = evaluate_task(task, root)
        self.assertEqual(r.status, "pass")

    def test_json_path_exists_missing_fails(self) -> None:
        task = self._mk_fs_task(
            [
                {
                    "type": "json_path_exists",
                    "path": "openclaw.json",
                    "json_path": "schedules.cleanup",
                }
            ]
        )
        with tempfile.TemporaryDirectory() as root:
            Path(root, "openclaw.json").write_text('{"schedules": {}}')
            r = evaluate_task(task, root)
        self.assertEqual(r.status, "fail")
        self.assertIn("not present", r.detail)

    def test_multiple_checks_all_must_pass(self) -> None:
        task = self._mk_fs_task(
            [
                {
                    "type": "json_path_equals",
                    "path": "openclaw.json",
                    "json_path": "tools.browser_fetch.enabled",
                    "equals": True,
                },
                {
                    "type": "file_contains",
                    "path": "TOOLS.md",
                    "substring": "browser_fetch",
                },
            ]
        )
        with tempfile.TemporaryDirectory() as root:
            Path(root, "openclaw.json").write_text(
                '{"tools": {"browser_fetch": {"enabled": true}}}'
            )
            Path(root, "TOOLS.md").write_text("browser_fetch\n")
            r = evaluate_task(task, root)
        self.assertEqual(r.status, "pass")

    def test_multiple_checks_one_fails(self) -> None:
        task = self._mk_fs_task(
            [
                {
                    "type": "json_path_equals",
                    "path": "openclaw.json",
                    "json_path": "tools.browser_fetch.enabled",
                    "equals": True,
                },
                {
                    "type": "file_contains",
                    "path": "TOOLS.md",
                    "substring": "ghost",
                },
            ]
        )
        with tempfile.TemporaryDirectory() as root:
            Path(root, "openclaw.json").write_text(
                '{"tools": {"browser_fetch": {"enabled": true}}}'
            )
            Path(root, "TOOLS.md").write_text("browser_fetch\n")
            r = evaluate_task(task, root)
        self.assertEqual(r.status, "fail")
        # Still reports the passing check too, just the final status is fail.
        self.assertIn("✓", r.detail)
        self.assertIn("✗", r.detail)

    def test_any_mode_passes_when_one_passes(self) -> None:
        task = self._mk_fs_task(
            [
                {"type": "file_contains", "path": "TOOLS.md", "substring": "ghost"},
                {"type": "file_contains", "path": "TOOLS.md", "substring": "real"},
            ],
            all_must_pass=False,
        )
        with tempfile.TemporaryDirectory() as root:
            Path(root, "TOOLS.md").write_text("real\n")
            r = evaluate_task(task, root)
        self.assertEqual(r.status, "pass")

    def test_traversal_path_rejected(self) -> None:
        task = self._mk_fs_task(
            [{"type": "file_contains", "path": "../etc/passwd", "substring": "x"}]
        )
        with tempfile.TemporaryDirectory() as root:
            r = evaluate_task(task, root)
        self.assertEqual(r.status, "fail")
        self.assertIn("workspace-relative", r.detail)

    def test_empty_checks_is_error(self) -> None:
        task = self._mk_fs_task([])
        with tempfile.TemporaryDirectory() as root:
            r = evaluate_task(task, root)
        self.assertEqual(r.status, "error")

    def test_invalid_json_file_fails(self) -> None:
        task = self._mk_fs_task(
            [
                {
                    "type": "json_path_equals",
                    "path": "openclaw.json",
                    "json_path": "x",
                    "equals": 1,
                }
            ]
        )
        with tempfile.TemporaryDirectory() as root:
            Path(root, "openclaw.json").write_text("{not json")
            r = evaluate_task(task, root)
        self.assertEqual(r.status, "fail")
        self.assertIn("JSON parse failed", r.detail)


class DispatcherTests(unittest.TestCase):
    def test_unknown_kind_returns_error(self) -> None:
        task = _mk_task(success_criterion={"kind": "bogus"})
        # Bypass schema validation — we want to test the dispatcher's
        # defensive branch directly.
        with tempfile.TemporaryDirectory() as root:
            r = evaluate_task(task, root)
        self.assertEqual(r.status, "error")


if __name__ == "__main__":
    unittest.main()
