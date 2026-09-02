"""Unit tests for openclaw_core.workspace.

Validates SPEC §1-2, §5:
- Bootstrap read order matches BOOTSTRAP_ORDER
- Minimal mode loads only MINIMAL_BOOTSTRAP_ALLOWLIST
- Memory fallback: MEMORY.md preferred over memory.md
- Cache identity invalidation on file change
- ensure_agent_workspace seeds templates and sets state
"""

from __future__ import annotations

import json
import os
import tempfile
import time
import unittest

from openclaw_core.workspace import (
    BOOTSTRAP_ORDER,
    DEFAULT_AGENTS_FILENAME,
    DEFAULT_BOOTSTRAP_FILENAME,
    DEFAULT_HEARTBEAT_FILENAME,
    DEFAULT_IDENTITY_FILENAME,
    DEFAULT_MEMORY_ALT_FILENAME,
    DEFAULT_MEMORY_FILENAME,
    DEFAULT_SOUL_FILENAME,
    DEFAULT_TOOLS_FILENAME,
    DEFAULT_USER_FILENAME,
    MINIMAL_BOOTSTRAP_ALLOWLIST,
    TEMPLATE_FILES,
    BootstrapEntry,
    WorkspaceFileCache,
    ensure_agent_workspace,
    load_workspace_bootstrap_files,
    resolve_memory_bootstrap_entry,
)
from openclaw_core.state import read_workspace_state, workspace_state_path


def _seed(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


class BootstrapConstantsTests(unittest.TestCase):
    def test_bootstrap_order_matches_spec(self) -> None:
        # SPEC §2: AGENTS → SOUL → TOOLS → IDENTITY → USER → HEARTBEAT → BOOTSTRAP
        # MEMORY.md is appended separately in load_workspace_bootstrap_files.
        self.assertEqual(
            BOOTSTRAP_ORDER,
            (
                DEFAULT_AGENTS_FILENAME,
                DEFAULT_SOUL_FILENAME,
                DEFAULT_TOOLS_FILENAME,
                DEFAULT_IDENTITY_FILENAME,
                DEFAULT_USER_FILENAME,
                DEFAULT_HEARTBEAT_FILENAME,
                DEFAULT_BOOTSTRAP_FILENAME,
            ),
        )

    def test_minimal_allowlist_matches_spec(self) -> None:
        # SPEC §2: subagent/heartbeat/memory-flush sessions load only these 5.
        self.assertEqual(
            MINIMAL_BOOTSTRAP_ALLOWLIST,
            (
                DEFAULT_AGENTS_FILENAME,
                DEFAULT_TOOLS_FILENAME,
                DEFAULT_SOUL_FILENAME,
                DEFAULT_IDENTITY_FILENAME,
                DEFAULT_USER_FILENAME,
            ),
        )

    def test_minimal_excludes_memory_heartbeat_bootstrap(self) -> None:
        # Memory/heartbeat/bootstrap must NOT appear in minimal path.
        self.assertNotIn(DEFAULT_MEMORY_FILENAME, MINIMAL_BOOTSTRAP_ALLOWLIST)
        self.assertNotIn(DEFAULT_HEARTBEAT_FILENAME, MINIMAL_BOOTSTRAP_ALLOWLIST)
        self.assertNotIn(DEFAULT_BOOTSTRAP_FILENAME, MINIMAL_BOOTSTRAP_ALLOWLIST)


class WorkspaceFileCacheTests(unittest.TestCase):
    def test_get_put_invalidate(self) -> None:
        cache = WorkspaceFileCache()
        self.assertIsNone(cache.get("/abs/path"))
        cache.put("/abs/path", "content", "identity-1")
        self.assertEqual(cache.get("/abs/path"), ("content", "identity-1"))
        cache.invalidate("/abs/path")
        self.assertIsNone(cache.get("/abs/path"))

    def test_clear(self) -> None:
        cache = WorkspaceFileCache()
        cache.put("/a", "x", "1")
        cache.put("/b", "y", "2")
        cache.clear()
        self.assertIsNone(cache.get("/a"))
        self.assertIsNone(cache.get("/b"))


class LoadBootstrapFilesTests(unittest.TestCase):
    def _write_all_templates(self, root: str) -> None:
        for fn in TEMPLATE_FILES:
            _seed(os.path.join(root, fn), f"# {fn}\ncontent of {fn}\n")

    def test_full_read_order(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            self._write_all_templates(root)
            entries = load_workspace_bootstrap_files(root)

            # Expected order: BOOTSTRAP_ORDER + MEMORY.md
            expected_order = list(BOOTSTRAP_ORDER) + [DEFAULT_MEMORY_FILENAME]
            actual_order = [e.filename for e in entries]
            self.assertEqual(actual_order, expected_order)

            # All files should be loaded.
            for entry in entries:
                self.assertIsNotNone(entry.content, f"{entry.filename} missing")
                self.assertIsNotNone(entry.identity)

    def test_minimal_mode_only_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            self._write_all_templates(root)
            entries = load_workspace_bootstrap_files(root, minimal=True)

            # Only the 5 minimal files — no MEMORY, HEARTBEAT, BOOTSTRAP.
            filenames = [e.filename for e in entries]
            self.assertEqual(tuple(filenames), MINIMAL_BOOTSTRAP_ALLOWLIST)

    def test_missing_files_get_none_entries(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            # Only seed SOUL.md — everything else is missing.
            _seed(os.path.join(root, DEFAULT_SOUL_FILENAME), "# soul\n")
            entries = load_workspace_bootstrap_files(root)

            # Entries are returned for every expected file, but missing files
            # have content=None/identity=None.
            by_name = {e.filename: e for e in entries}
            self.assertIsNotNone(by_name[DEFAULT_SOUL_FILENAME].content)
            self.assertIsNone(by_name[DEFAULT_AGENTS_FILENAME].content)
            self.assertIsNone(by_name[DEFAULT_AGENTS_FILENAME].identity)

    def test_memory_prefers_uppercase(self) -> None:
        # On case-sensitive FS both files can coexist. We prefer MEMORY.md.
        with tempfile.TemporaryDirectory() as root:
            _seed(os.path.join(root, DEFAULT_MEMORY_FILENAME), "UPPER\n")
            # Some FSes are case-insensitive — skip memory.md if it'd collide.
            alt_path = os.path.join(root, DEFAULT_MEMORY_ALT_FILENAME)
            if not os.path.exists(alt_path):
                _seed(alt_path, "lower\n")
            entry = resolve_memory_bootstrap_entry(root)
            self.assertIsNotNone(entry)
            assert entry is not None  # type narrow
            self.assertEqual(entry.filename, DEFAULT_MEMORY_FILENAME)
            self.assertIn("UPPER", entry.content or "")

    def test_memory_fallback_to_lowercase(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            _seed(os.path.join(root, DEFAULT_MEMORY_ALT_FILENAME), "lower\n")
            entry = resolve_memory_bootstrap_entry(root)
            self.assertIsNotNone(entry)
            assert entry is not None
            # On a case-insensitive filesystem, probing MEMORY.md resolves the
            # lowercase file. That matches upstream's "prefer MEMORY.md" rule
            # and avoids duplicate bootstrap injection. On case-sensitive
            # filesystems, the uppercase probe misses and fallback reports the
            # actual lowercase filename.
            expected_name = (
                DEFAULT_MEMORY_FILENAME
                if os.path.exists(os.path.join(root, DEFAULT_MEMORY_FILENAME))
                else DEFAULT_MEMORY_ALT_FILENAME
            )
            self.assertEqual(entry.filename, expected_name)
            self.assertEqual(entry.content, "lower\n")

    def test_memory_returns_none_when_both_missing(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            entry = resolve_memory_bootstrap_entry(root)
            self.assertIsNone(entry)


class CacheIdentityTests(unittest.TestCase):
    def test_cache_hit_returns_cached_content(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, DEFAULT_SOUL_FILENAME)
            _seed(path, "original\n")
            cache = WorkspaceFileCache()

            # First load populates cache.
            entries1 = load_workspace_bootstrap_files(root, cache=cache)
            soul1 = [e for e in entries1 if e.filename == DEFAULT_SOUL_FILENAME][0]
            self.assertEqual(soul1.content, "original\n")

            # Overwrite on disk bytes but restore mtime so identity stays same.
            st = os.stat(path)
            with open(path, "w", encoding="utf-8") as f:
                f.write("original\n")  # same length
            os.utime(path, (st.st_atime, st.st_mtime))

            # Second load: identity matches, cache hit — we should get the
            # cached content (same as before).
            entries2 = load_workspace_bootstrap_files(root, cache=cache)
            soul2 = [e for e in entries2 if e.filename == DEFAULT_SOUL_FILENAME][0]
            self.assertEqual(soul2.content, "original\n")
            self.assertEqual(soul1.identity, soul2.identity)

    def test_cache_miss_when_file_changes(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, DEFAULT_SOUL_FILENAME)
            _seed(path, "v1\n")
            cache = WorkspaceFileCache()

            entries1 = load_workspace_bootstrap_files(root, cache=cache)
            soul1 = [e for e in entries1 if e.filename == DEFAULT_SOUL_FILENAME][0]
            id1 = soul1.identity

            # Force a different mtime/size.
            time.sleep(0.02)
            _seed(path, "v2 changed content\n")

            entries2 = load_workspace_bootstrap_files(root, cache=cache)
            soul2 = [e for e in entries2 if e.filename == DEFAULT_SOUL_FILENAME][0]
            self.assertEqual(soul2.content, "v2 changed content\n")
            self.assertNotEqual(soul2.identity, id1)


class EnsureAgentWorkspaceTests(unittest.TestCase):
    def test_creates_workspace_and_seeds_templates(self) -> None:
        with tempfile.TemporaryDirectory() as base:
            root = os.path.join(base, "fresh")
            ensure_agent_workspace(root, mark_setup_done=False)

            # All template files should exist except BOOTSTRAP.md is kept
            # because mark_setup_done=False (still onboarding).
            for fn in TEMPLATE_FILES:
                self.assertTrue(
                    os.path.exists(os.path.join(root, fn)),
                    f"{fn} should be seeded",
                )
            self.assertTrue(os.path.isdir(os.path.join(root, "memory")))

    def test_mark_setup_done_deletes_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as base:
            root = os.path.join(base, "used")
            ensure_agent_workspace(root, mark_setup_done=True)

            # BOOTSTRAP.md should be gone, others should remain.
            self.assertFalse(
                os.path.exists(os.path.join(root, DEFAULT_BOOTSTRAP_FILENAME))
            )
            self.assertTrue(os.path.exists(os.path.join(root, DEFAULT_SOUL_FILENAME)))
            self.assertTrue(os.path.exists(os.path.join(root, DEFAULT_MEMORY_FILENAME)))

    def test_mark_setup_done_deletes_stale_bootstrap_on_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as base:
            root = os.path.join(base, "used")
            ensure_agent_workspace(root, mark_setup_done=True)

            bootstrap = os.path.join(root, DEFAULT_BOOTSTRAP_FILENAME)
            _seed(bootstrap, "# stale bootstrap\n")
            ensure_agent_workspace(root, mark_setup_done=True)

            self.assertFalse(os.path.exists(bootstrap))

    def test_workspace_state_json_is_written(self) -> None:
        with tempfile.TemporaryDirectory() as base:
            root = os.path.join(base, "w")
            ensure_agent_workspace(root, mark_setup_done=True)

            state = read_workspace_state(root)
            self.assertIsNotNone(state)
            assert state is not None
            self.assertIn("bootstrapSeededAt", state)
            self.assertIn("setupCompletedAt", state)

    def test_idempotent(self) -> None:
        # Calling ensure twice should not corrupt seeded files.
        with tempfile.TemporaryDirectory() as base:
            root = os.path.join(base, "w")
            ensure_agent_workspace(root, mark_setup_done=True)

            # User modifies SOUL.md.
            soul = os.path.join(root, DEFAULT_SOUL_FILENAME)
            _seed(soul, "user customized\n")

            # Re-ensure — must NOT overwrite the user's version.
            ensure_agent_workspace(root, mark_setup_done=True)
            with open(soul, encoding="utf-8") as f:
                self.assertEqual(f.read(), "user customized\n")

    def test_setup_not_marked_when_mark_setup_done_false(self) -> None:
        with tempfile.TemporaryDirectory() as base:
            root = os.path.join(base, "w")
            ensure_agent_workspace(root, mark_setup_done=False)

            state = read_workspace_state(root)
            self.assertIsNotNone(state)
            assert state is not None
            self.assertIn("bootstrapSeededAt", state)
            self.assertNotIn("setupCompletedAt", state)
            # BOOTSTRAP.md still present in onboarding state.
            self.assertTrue(
                os.path.exists(os.path.join(root, DEFAULT_BOOTSTRAP_FILENAME))
            )


if __name__ == "__main__":
    unittest.main()
