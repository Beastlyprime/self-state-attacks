"""Unit tests for openclaw_core.boundary.

Validates the five guarantees from SPEC §3:
1. Path canonicalization (symlinks followed)
2. Root containment check
3. Hardlink rejection
4. Size cap
5. Type check (regular files only)
"""

from __future__ import annotations

import os
import tempfile
import unittest

from openclaw_core.boundary import (
    DEFAULT_MAX_BYTES,
    BoundaryError,
    file_identity,
    open_boundary_file,
    read_boundary_file,
    resolve_boundary_path,
)


class BoundaryPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="openclaw-test-")
        self.root = os.path.realpath(self.tmp)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, rel: str, content: str = "hello") -> str:
        p = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
        with open(p, "w") as f:
            f.write(content)
        return p

    def test_root_itself_resolves(self) -> None:
        result = resolve_boundary_path(self.root, self.root)
        self.assertEqual(result.canonical, self.root)

    def test_descendant_path_ok(self) -> None:
        p = self._write("SOUL.md")
        result = resolve_boundary_path(p, self.root)
        self.assertEqual(result.canonical, os.path.realpath(p))

    def test_nested_path_ok(self) -> None:
        p = self._write("memory/2026-04-22.md")
        result = resolve_boundary_path(p, self.root)
        self.assertTrue(result.canonical.startswith(self.root))

    def test_path_escape_rejected(self) -> None:
        # Path that lexically contains `..` to escape.
        escape = os.path.join(self.root, "..", "outside.md")
        with self.assertRaises(BoundaryError) as cm:
            resolve_boundary_path(escape, self.root)
        self.assertEqual(cm.exception.reason, "path")

    def test_sibling_prefix_string_attack_rejected(self) -> None:
        # "rootX" starts with "root" as a string but is NOT under root.
        # This test catches the "string-prefix-only" pitfall called out in SPEC §3.
        sibling = self.root + "-sibling"
        os.makedirs(sibling, exist_ok=True)
        try:
            evil = os.path.join(sibling, "file.md")
            with open(evil, "w") as f:
                f.write("x")
            with self.assertRaises(BoundaryError) as cm:
                resolve_boundary_path(evil, self.root)
            self.assertEqual(cm.exception.reason, "path")
        finally:
            import shutil
            shutil.rmtree(sibling, ignore_errors=True)

    def test_symlink_to_outside_rejected(self) -> None:
        # Symlink inside workspace pointing to /etc/hostname.
        link_path = os.path.join(self.root, "escape-link")
        os.symlink("/etc/hostname", link_path)
        with self.assertRaises(BoundaryError) as cm:
            resolve_boundary_path(link_path, self.root)
        self.assertEqual(cm.exception.reason, "path")

    def test_symlink_to_descendant_ok(self) -> None:
        # Symlink A -> B, both inside workspace — should resolve A to B and pass.
        target = self._write("actual.md", "x")
        link = os.path.join(self.root, "alias.md")
        os.symlink(target, link)
        result = resolve_boundary_path(link, self.root)
        self.assertEqual(result.canonical, os.path.realpath(target))


class OpenBoundaryFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="openclaw-test-")
        self.root = os.path.realpath(self.tmp)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, rel: str, content: str = "hello") -> str:
        p = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
        with open(p, "w") as f:
            f.write(content)
        return p

    def test_open_regular_file(self) -> None:
        p = self._write("SOUL.md", "soul content")
        fd, st, _ = open_boundary_file(p, self.root)
        try:
            self.assertGreater(fd, 0)
            self.assertEqual(st.st_size, len(b"soul content"))
        finally:
            os.close(fd)

    def test_open_directory_rejected_by_default(self) -> None:
        sub = os.path.join(self.root, "subdir")
        os.makedirs(sub)
        with self.assertRaises(BoundaryError) as cm:
            open_boundary_file(sub, self.root)
        self.assertEqual(cm.exception.reason, "validation")

    def test_open_directory_allowed_with_flag(self) -> None:
        sub = os.path.join(self.root, "subdir")
        os.makedirs(sub)
        fd, st, _ = open_boundary_file(sub, self.root, allow_directory=True)
        os.close(fd)
        import stat as stat_module
        self.assertTrue(stat_module.S_ISDIR(st.st_mode))

    def test_hardlink_rejected(self) -> None:
        original = self._write("original.md", "x")
        hardlink = os.path.join(self.root, "hardlink.md")
        os.link(original, hardlink)
        with self.assertRaises(BoundaryError) as cm:
            open_boundary_file(hardlink, self.root)
        self.assertEqual(cm.exception.reason, "validation")
        self.assertIn("hardlink", cm.exception.detail)

    def test_hardlink_allowed_with_flag(self) -> None:
        original = self._write("original.md", "x")
        hardlink = os.path.join(self.root, "hardlink.md")
        os.link(original, hardlink)
        fd, _st, _ = open_boundary_file(
            hardlink, self.root, reject_hardlinks=False
        )
        os.close(fd)

    def test_size_cap_rejected(self) -> None:
        p = self._write("big.md", "x" * 100)
        with self.assertRaises(BoundaryError) as cm:
            open_boundary_file(p, self.root, max_bytes=50)
        self.assertEqual(cm.exception.reason, "io")
        self.assertIn("exceeds cap", cm.exception.detail)

    def test_default_size_cap_is_2mb(self) -> None:
        # Sanity: confirm default matches SPEC §3.
        self.assertEqual(DEFAULT_MAX_BYTES, 2 * 1024 * 1024)

    def test_read_boundary_file(self) -> None:
        p = self._write("MEMORY.md", "memory content")
        contents = read_boundary_file(p, self.root)
        self.assertEqual(contents, "memory content")

    def test_read_nonexistent_file_io_error(self) -> None:
        with self.assertRaises(BoundaryError) as cm:
            # Path is fine (inside root), but the file isn't there.
            read_boundary_file(os.path.join(self.root, "missing.md"), self.root)
        self.assertEqual(cm.exception.reason, "io")


class FileIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="openclaw-test-")

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_identity_changes_on_mtime(self) -> None:
        p = os.path.join(self.tmp, "x.md")
        with open(p, "w") as f:
            f.write("a")
        id1 = file_identity(p)
        import time as _time
        _time.sleep(0.01)  # ensure mtime bumps
        with open(p, "w") as f:
            f.write("b")
        # Force mtime to advance — some filesystems have 1s resolution.
        os.utime(p, (os.stat(p).st_atime, os.stat(p).st_mtime + 1))
        id2 = file_identity(p)
        self.assertNotEqual(id1, id2)

    def test_identity_format(self) -> None:
        p = os.path.join(self.tmp, "x.md")
        with open(p, "w") as f:
            f.write("a")
        ident = file_identity(p)
        # Format: {canonical_path}|{dev}:{ino}:{size}:{mtime_ms}
        self.assertIn("|", ident)
        canonical, stat_part = ident.split("|", 1)
        self.assertEqual(canonical, os.path.realpath(p))
        parts = stat_part.split(":")
        self.assertEqual(len(parts), 4)
        dev, ino, size, mtime = parts
        self.assertTrue(dev.isdigit())
        self.assertTrue(ino.isdigit())
        self.assertEqual(int(size), 1)  # one byte
        self.assertTrue(mtime.isdigit())


if __name__ == "__main__":
    unittest.main()
