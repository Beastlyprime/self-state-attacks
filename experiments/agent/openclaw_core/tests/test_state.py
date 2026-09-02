"""Unit tests for openclaw_core.state.

Validates SPEC §4.2 and §5:
- Atomic write via .tmp-<pid>-<base36> + rename
- workspace-state.json schema (version=1, bootstrapSeededAt, setupCompletedAt)
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import unittest
from unittest import mock

from openclaw_core.state import (
    WORKSPACE_STATE_VERSION,
    _tmp_suffix,
    atomic_write,
    atomic_write_json,
    mark_bootstrap_seeded,
    mark_setup_completed,
    read_workspace_state,
    workspace_state_path,
    write_workspace_state,
)


class TmpSuffixTests(unittest.TestCase):
    def test_format_matches_openclaw(self) -> None:
        # Format: .tmp-<pid>-<base36_ms>
        suffix = _tmp_suffix()
        self.assertTrue(suffix.startswith(".tmp-"))
        parts = suffix[len(".tmp-"):].split("-")
        self.assertEqual(len(parts), 2)
        pid_part, b36_part = parts
        self.assertTrue(pid_part.isdigit())
        # base36: digits + a-z only
        self.assertTrue(re.fullmatch(r"[0-9a-z]+", b36_part))

    def test_suffix_changes(self) -> None:
        s1 = _tmp_suffix()
        import time
        time.sleep(0.002)  # ensure Date.now() ms tick advances
        s2 = _tmp_suffix()
        # Two calls within same process should produce different suffixes
        # (different base36 ms timestamps).
        self.assertNotEqual(s1, s2)


class AtomicWriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="openclaw-test-")

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_creates_target_atomically(self) -> None:
        target = os.path.join(self.tmp, "state.json")
        atomic_write(target, "hello\n")
        self.assertTrue(os.path.exists(target))
        with open(target) as f:
            self.assertEqual(f.read(), "hello\n")

    def test_overwrites_existing(self) -> None:
        target = os.path.join(self.tmp, "state.json")
        with open(target, "w") as f:
            f.write("old")
        atomic_write(target, "new")
        with open(target) as f:
            self.assertEqual(f.read(), "new")

    def test_tmp_cleaned_on_success(self) -> None:
        target = os.path.join(self.tmp, "state.json")
        atomic_write(target, "x")
        # No leftover .tmp-* files.
        leftovers = [f for f in os.listdir(self.tmp) if f.startswith("state.json.tmp-")]
        self.assertEqual(leftovers, [])

    def test_tmp_cleaned_on_rename_failure(self) -> None:
        target = os.path.join(self.tmp, "state.json")
        with mock.patch("os.rename", side_effect=OSError("rename failed")):
            with self.assertRaises(OSError):
                atomic_write(target, "x")
        # Best-effort cleanup should have removed tmp.
        leftovers = [f for f in os.listdir(self.tmp) if f.startswith("state.json.tmp-")]
        self.assertEqual(leftovers, [])

    def test_creates_parent_dirs(self) -> None:
        target = os.path.join(self.tmp, "deep", "nested", "state.json")
        atomic_write(target, "x")
        self.assertTrue(os.path.exists(target))

    def test_json_write_roundtrip(self) -> None:
        target = os.path.join(self.tmp, "state.json")
        data = {"version": 1, "bootstrapSeededAt": "2026-04-22T00:00:00.000Z"}
        atomic_write_json(target, data)
        with open(target) as f:
            self.assertEqual(json.load(f), data)


class WorkspaceStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="openclaw-test-")
        self.root = os.path.realpath(self.tmp)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_read_returns_none_when_missing(self) -> None:
        self.assertIsNone(read_workspace_state(self.root))

    def test_mark_bootstrap_seeded(self) -> None:
        mark_bootstrap_seeded(self.root)
        state = read_workspace_state(self.root)
        self.assertIsNotNone(state)
        self.assertEqual(state["version"], WORKSPACE_STATE_VERSION)
        self.assertIn("bootstrapSeededAt", state)
        self.assertNotIn("setupCompletedAt", state)

    def test_mark_setup_completed_preserves_seeded(self) -> None:
        mark_bootstrap_seeded(self.root)
        state1 = read_workspace_state(self.root)
        seeded_at = state1["bootstrapSeededAt"]
        mark_setup_completed(self.root)
        state2 = read_workspace_state(self.root)
        self.assertEqual(state2["bootstrapSeededAt"], seeded_at)
        self.assertIn("setupCompletedAt", state2)

    def test_state_path(self) -> None:
        self.assertEqual(
            workspace_state_path(self.root),
            os.path.join(self.root, ".openclaw", "workspace-state.json"),
        )

    def test_schema_version_is_1(self) -> None:
        write_workspace_state(self.root, bootstrap_seeded_at="2026-04-22T00:00:00.000Z")
        state = read_workspace_state(self.root)
        self.assertEqual(state["version"], 1)

    def test_iso_timestamp_format(self) -> None:
        mark_bootstrap_seeded(self.root)
        state = read_workspace_state(self.root)
        ts = state["bootstrapSeededAt"]
        # Matches OpenClaw Date.toISOString() → YYYY-MM-DDTHH:MM:SS.mmmZ
        self.assertRegex(ts, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


if __name__ == "__main__":
    unittest.main()
