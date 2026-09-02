"""Unit tests for openclaw_core.pi_tools.

Validates SPEC §4.1 and §6:
- read: line numbering, offset/limit, boundary rejection, UTF-8 errors
- write: direct (non-atomic) write, parent mkdir, symlink rejection, boundary
- edit: exact unique match, count != 1 rejection, boundary, UTF-8 errors
- bash: stdout/stderr capture, timeout, cwd = workspace_root, exit code
- wrappers: workspace-root guard rejects escapes; memory-flush restricts
  writes to MEMORY target and coerces to append.

Trace fidelity: the LLM-facing tools MUST use direct fs.writeFile (no
.tmp+rename precursor) so that inotify traces match real OpenClaw behavior.
That is asserted in test_write_is_not_atomic.
"""

from __future__ import annotations

import os
import tempfile
import time
import unittest

from openclaw_core.pi_tools import (
    FileMutationQueue,
    MEMORY_FLUSH_ALLOWED_TOOL_NAMES,
    WorkspaceRootGuardError,
    bash_tool,
    edit_tool,
    get_default_tool_schemas,
    read_tool,
    wrap_tool_memory_flush_append_only,
    wrap_tool_workspace_root_guard,
    write_tool,
)
from openclaw_core.pi_tools.wrappers import MemoryFlushContext


def _seed(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


class ReadToolTests(unittest.TestCase):
    def test_reads_whole_file_with_line_numbers(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "x.txt")
            _seed(path, "alpha\nbeta\ngamma\n")
            result = read_tool("x.txt", workspace_root=root)
            self.assertTrue(result.ok, msg=result.error)
            assert result.content is not None
            self.assertIn("alpha", result.content)
            self.assertIn("beta", result.content)
            self.assertIn("gamma", result.content)
            # Line numbers rendered.
            self.assertIn("     1\talpha", result.content)
            self.assertIn("     2\tbeta", result.content)
            self.assertEqual(result.total_lines, 3)
            self.assertEqual(result.returned_lines, 3)

    def test_offset_and_limit(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "x.txt")
            _seed(path, "a\nb\nc\nd\ne\n")
            result = read_tool(
                "x.txt", workspace_root=root, offset=2, limit=2
            )
            self.assertTrue(result.ok, msg=result.error)
            assert result.content is not None
            self.assertIn("     2\tb", result.content)
            self.assertIn("     3\tc", result.content)
            self.assertNotIn("     4\td", result.content)
            self.assertEqual(result.returned_lines, 2)

    def test_offset_past_eof_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "x.txt")
            _seed(path, "only one line\n")
            result = read_tool("x.txt", workspace_root=root, offset=5)
            self.assertTrue(result.ok, msg=result.error)
            self.assertEqual(result.content, "")
            self.assertEqual(result.returned_lines, 0)
            self.assertEqual(result.total_lines, 1)

    def test_path_escape_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tf:
                tf.write(b"secret\n")
                outside = tf.name
            try:
                result = read_tool(outside, workspace_root=root)
                self.assertFalse(result.ok)
                assert result.error is not None
                self.assertIn("path", result.error)
            finally:
                os.unlink(outside)

    def test_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            result = read_tool("missing.txt", workspace_root=root)
            self.assertFalse(result.ok)

    def test_non_utf8_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "bin.dat")
            with open(path, "wb") as f:
                f.write(b"\xff\xfe not utf-8")
            result = read_tool("bin.dat", workspace_root=root)
            self.assertFalse(result.ok)
            assert result.error is not None
            self.assertIn("UTF-8", result.error)

    def test_invalid_offset(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "x.txt")
            _seed(path, "a\n")
            r = read_tool("x.txt", workspace_root=root, offset=0)
            self.assertFalse(r.ok)


class WriteToolTests(unittest.TestCase):
    def test_creates_new_file(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            r = write_tool("new.txt", "hello\n", workspace_root=root)
            self.assertTrue(r.ok, msg=r.error)
            self.assertTrue(r.created)
            with open(os.path.join(root, "new.txt")) as f:
                self.assertEqual(f.read(), "hello\n")

    def test_overwrites_existing(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "x.txt")
            _seed(path, "v1\n")
            r = write_tool("x.txt", "v2\n", workspace_root=root)
            self.assertTrue(r.ok)
            self.assertFalse(r.created)
            with open(path) as f:
                self.assertEqual(f.read(), "v2\n")

    def test_creates_parent_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            r = write_tool(
                "sub/deep/nested.txt", "content\n", workspace_root=root
            )
            self.assertTrue(r.ok, msg=r.error)
            self.assertTrue(
                os.path.exists(os.path.join(root, "sub/deep/nested.txt"))
            )

    def test_write_is_not_atomic_no_tmp_file(self) -> None:
        # CRITICAL FIDELITY INVARIANT: LLM-facing write must NOT use .tmp+rename.
        # This test verifies that during a write, no .tmp-* sibling is left
        # behind. (The strongest test would inspect inotify traces; here we
        # rely on the invariant that a correct direct-fs.writeFile path never
        # creates a tmp sibling in the target directory.)
        with tempfile.TemporaryDirectory() as root:
            write_tool("x.txt", "content\n", workspace_root=root)
            # No siblings matching .tmp-*
            siblings = os.listdir(root)
            self.assertEqual(siblings, ["x.txt"])
            for s in siblings:
                self.assertFalse(s.startswith(".tmp-"))

    def test_path_escape_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            with tempfile.TemporaryDirectory() as outside_root:
                outside_path = os.path.join(outside_root, "evil.txt")
                r = write_tool(outside_path, "x\n", workspace_root=root)
                self.assertFalse(r.ok)
                assert r.error is not None
                self.assertFalse(os.path.exists(outside_path))

    def test_symlink_target_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            victim = os.path.join(root, "victim.txt")
            _seed(victim, "original\n")
            link = os.path.join(root, "link.txt")
            os.symlink(victim, link)
            r = write_tool("link.txt", "pwned\n", workspace_root=root)
            self.assertFalse(r.ok)
            # Victim should NOT be modified.
            with open(victim) as f:
                self.assertEqual(f.read(), "original\n")

    def test_concurrent_writes_serialized_via_queue(self) -> None:
        # FileMutationQueue prevents interleaved content on the same path.
        import threading

        with tempfile.TemporaryDirectory() as root:
            queue = FileMutationQueue()
            path_rel = "x.txt"
            results: list[bool] = []

            def worker(content: str) -> None:
                r = write_tool(
                    path_rel, content, workspace_root=root, queue=queue
                )
                results.append(r.ok)

            # Two threads racing; queue should serialize.
            t1 = threading.Thread(target=worker, args=("a" * 1000 + "\n",))
            t2 = threading.Thread(target=worker, args=("b" * 1000 + "\n",))
            t1.start()
            t2.start()
            t1.join()
            t2.join()

            self.assertEqual(results, [True, True])
            # Final content should be ONE of the two contents, not a mix.
            with open(os.path.join(root, path_rel)) as f:
                content = f.read()
            self.assertTrue(content == "a" * 1000 + "\n" or content == "b" * 1000 + "\n")


class EditToolTests(unittest.TestCase):
    def test_unique_match_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "x.txt")
            _seed(path, "before marker after\n")
            r = edit_tool(
                "x.txt", "marker", "MARKER", workspace_root=root
            )
            self.assertTrue(r.ok, msg=r.error)
            with open(path) as f:
                self.assertEqual(f.read(), "before MARKER after\n")
            self.assertEqual(r.match_count, 1)

    def test_missing_match_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "x.txt")
            _seed(path, "hello\n")
            r = edit_tool("x.txt", "nope", "yes", workspace_root=root)
            self.assertFalse(r.ok)
            self.assertEqual(r.match_count, 0)

    def test_multiple_matches_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "x.txt")
            _seed(path, "foo bar foo\n")
            r = edit_tool("x.txt", "foo", "FOO", workspace_root=root)
            self.assertFalse(r.ok)
            self.assertEqual(r.match_count, 2)
            # File unchanged.
            with open(path) as f:
                self.assertEqual(f.read(), "foo bar foo\n")

    def test_empty_old_text_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "x.txt")
            _seed(path, "hi\n")
            r = edit_tool("x.txt", "", "nope", workspace_root=root)
            self.assertFalse(r.ok)

    def test_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            r = edit_tool(
                "missing.txt", "a", "b", workspace_root=root
            )
            self.assertFalse(r.ok)

    def test_edit_is_not_atomic_no_tmp_file(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "x.txt")
            _seed(path, "marker\n")
            edit_tool("x.txt", "marker", "MARKER", workspace_root=root)
            siblings = os.listdir(root)
            self.assertEqual(siblings, ["x.txt"])


class BashToolTests(unittest.TestCase):
    def test_runs_command_and_captures_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            r = bash_tool("echo hello", workspace_root=root)
            self.assertTrue(r.ok, msg=r.error)
            self.assertEqual(r.exit_code, 0)
            self.assertIn("hello", r.stdout)

    def test_captures_stderr_and_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            r = bash_tool(
                "echo err 1>&2 && exit 7", workspace_root=root
            )
            self.assertTrue(r.ok)
            self.assertEqual(r.exit_code, 7)
            self.assertIn("err", r.stderr)

    def test_cwd_is_workspace_root(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            r = bash_tool("pwd", workspace_root=root)
            self.assertTrue(r.ok)
            # realpath to handle macOS /private/var symlink weirdness
            self.assertEqual(
                os.path.realpath(r.stdout.strip()),
                os.path.realpath(root),
            )

    def test_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            r = bash_tool("sleep 5", workspace_root=root, timeout=1)
            self.assertFalse(r.ok)
            self.assertTrue(r.timed_out)
            self.assertEqual(r.exit_code, -1)

    def test_bad_workspace_rejected(self) -> None:
        r = bash_tool(
            "echo x", workspace_root="/no/such/dir/__bench"
        )
        self.assertFalse(r.ok)


class WorkspaceRootGuardTests(unittest.TestCase):
    def test_guard_rejects_outside_path(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            guarded = wrap_tool_workspace_root_guard(read_tool, root)
            with self.assertRaises(WorkspaceRootGuardError):
                guarded("/etc/passwd")

    def test_guard_passes_through_inside_path(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            _seed(os.path.join(root, "a.txt"), "ok\n")
            guarded = wrap_tool_workspace_root_guard(read_tool, root)
            result = guarded("a.txt")
            self.assertTrue(result.ok)


class MemoryFlushWrapperTests(unittest.TestCase):
    def test_allowlist_matches_spec(self) -> None:
        self.assertEqual(
            MEMORY_FLUSH_ALLOWED_TOOL_NAMES, frozenset({"read", "write"})
        )

    def test_non_allowed_tools_return_none(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            ctx = MemoryFlushContext(root=root, relative_path="MEMORY.md")
            self.assertIsNone(
                wrap_tool_memory_flush_append_only("edit", edit_tool, ctx)
            )
            self.assertIsNone(
                wrap_tool_memory_flush_append_only("bash", bash_tool, ctx)
            )

    def test_write_restricted_to_target(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            ctx = MemoryFlushContext(root=root, relative_path="MEMORY.md")
            wrapped = wrap_tool_memory_flush_append_only("write", write_tool, ctx)
            assert wrapped is not None

            r = wrapped("other.md", "attack payload\n")
            self.assertFalse(r.ok)
            assert r.error is not None
            self.assertIn("MEMORY.md", r.error)
            self.assertFalse(
                os.path.exists(os.path.join(root, "other.md"))
            )

    def test_write_appends_not_overwrites(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            _seed(os.path.join(root, "MEMORY.md"), "# Memory\n\nexisting\n")
            ctx = MemoryFlushContext(root=root, relative_path="MEMORY.md")
            wrapped = wrap_tool_memory_flush_append_only("write", write_tool, ctx)
            assert wrapped is not None

            r = wrapped("MEMORY.md", "new entry")
            self.assertTrue(r.ok, msg=r.error)

            with open(os.path.join(root, "MEMORY.md")) as f:
                content = f.read()
            self.assertIn("existing", content)  # preserved
            self.assertIn("new entry", content)  # appended
            self.assertEqual(content, "# Memory\n\nexisting\nnew entry")

    def test_write_append_separator_matches_upstream(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            _seed(os.path.join(root, "MEMORY.md"), "seed")
            ctx = MemoryFlushContext(root=root, relative_path="MEMORY.md")
            wrapped = wrap_tool_memory_flush_append_only("write", write_tool, ctx)
            assert wrapped is not None

            r = wrapped("MEMORY.md", "new note")
            self.assertTrue(r.ok, msg=r.error)

            with open(os.path.join(root, "MEMORY.md")) as f:
                self.assertEqual(f.read(), "seed\nnew note")

    def test_write_append_preserves_existing_trailing_whitespace(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            _seed(os.path.join(root, "MEMORY.md"), "seed  \n\n")
            ctx = MemoryFlushContext(root=root, relative_path="MEMORY.md")
            wrapped = wrap_tool_memory_flush_append_only("write", write_tool, ctx)
            assert wrapped is not None

            r = wrapped("MEMORY.md", "new note")
            self.assertTrue(r.ok, msg=r.error)

            with open(os.path.join(root, "MEMORY.md")) as f:
                self.assertEqual(f.read(), "seed  \n\nnew note")

    def test_read_passthrough(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            _seed(os.path.join(root, "MEMORY.md"), "content\n")
            ctx = MemoryFlushContext(root=root, relative_path="MEMORY.md")
            wrapped = wrap_tool_memory_flush_append_only("read", read_tool, ctx)
            assert wrapped is not None
            # read is pass-through — no path restriction in memory-flush mode.
            r = wrapped("MEMORY.md", workspace_root=root)
            self.assertTrue(r.ok)


class SchemaTests(unittest.TestCase):
    def test_default_schemas_include_four_tools(self) -> None:
        schemas = get_default_tool_schemas()
        names = [s["function"]["name"] for s in schemas]
        self.assertEqual(names, ["read", "write", "edit", "bash"])

    def test_read_schema_has_path_required(self) -> None:
        schemas = get_default_tool_schemas()
        read_schema = next(s for s in schemas if s["function"]["name"] == "read")
        self.assertEqual(
            read_schema["function"]["parameters"]["required"], ["path"]
        )


if __name__ == "__main__":
    unittest.main()
