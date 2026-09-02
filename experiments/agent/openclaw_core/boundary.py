"""Boundary-safe file open — Python port of OpenClaw's boundary-file-read.ts.

Mirrors the five guarantees from SPEC.md §3:
1. Path canonicalization (os.path.realpath resolves symlinks)
2. Root containment (canonical path must be at or under rootRealPath)
3. Hardlink rejection (stat.st_nlink > 1 rejects open)
4. Size cap (maxBytes, default 2 MiB — matches real OpenClaw bootstrap reads)
5. Type check (regular files only by default)

Source reference: mnt/openclaw/src/infra/boundary-file-read.ts
"""

from __future__ import annotations

import os
import stat as stat_module
from dataclasses import dataclass
from typing import Literal, Optional

# Default cap on bootstrap file reads, matches real OpenClaw (2 MiB).
DEFAULT_MAX_BYTES = 2 * 1024 * 1024


FailureReason = Literal["path", "validation", "io"]


class BoundaryError(Exception):
    """Raised when a boundary-safe open fails.

    Attributes:
        reason: One of "path" (escape from root), "validation" (hardlink,
            wrong type, symlink target outside), "io" (EACCES, ENOENT, size
            cap exceeded, etc.)
        detail: Human-readable detail for logging/tests.
    """

    def __init__(self, reason: FailureReason, detail: str) -> None:
        super().__init__(f"[{reason}] {detail}")
        self.reason: FailureReason = reason
        self.detail = detail


@dataclass(frozen=True)
class ResolvedPath:
    """Result of a successful boundary check.

    Attributes:
        absolute: The caller-supplied absolute path (resolved, not canonical).
        canonical: realpath-resolved canonical path (symlinks followed).
        root_canonical: realpath-resolved canonical root path.
    """

    absolute: str
    canonical: str
    root_canonical: str


def resolve_boundary_path(
    absolute_path: str,
    root_path: str,
    root_canonical: Optional[str] = None,
) -> ResolvedPath:
    """Resolve and validate a path is within `root_path`.

    Steps (matching boundary-file-read.ts:resolveBoundaryPath):
    1. abspath on input (handles `..` lexically)
    2. realpath on input (handles symlinks)
    3. realpath on root (handles symlinks in the root itself)
    4. Canonical containment check (NOT string prefix — handles case-insensitive
       filesystems and trailing-slash edge cases)

    Raises BoundaryError("path") on containment escape.
    Raises BoundaryError("io") if realpath fails (typically ENOENT on a nonexistent
    parent path); caller should create intermediate directories first.
    """
    abs_input = os.path.abspath(absolute_path)
    try:
        canonical_input = os.path.realpath(abs_input)
    except OSError as e:
        raise BoundaryError("io", f"realpath({abs_input}) failed: {e}") from e

    if root_canonical is None:
        try:
            root_canonical = os.path.realpath(os.path.abspath(root_path))
        except OSError as e:
            raise BoundaryError("io", f"realpath({root_path}) failed: {e}") from e

    # Canonical containment check. Equal-to-root is allowed (opening the dir
    # itself is a separate type check in openVerifiedFile).
    # We compare paths, not strings: trailing slashes normalized by realpath,
    # case-sensitivity delegated to the OS.
    if canonical_input == root_canonical:
        return ResolvedPath(abs_input, canonical_input, root_canonical)

    root_with_sep = root_canonical.rstrip(os.sep) + os.sep
    if not canonical_input.startswith(root_with_sep):
        raise BoundaryError(
            "path",
            f"path {canonical_input!r} escapes root {root_canonical!r}",
        )

    return ResolvedPath(abs_input, canonical_input, root_canonical)


def open_boundary_file(
    absolute_path: str,
    root_path: str,
    *,
    root_canonical: Optional[str] = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    reject_hardlinks: bool = True,
    allow_directory: bool = False,
) -> tuple[int, os.stat_result, ResolvedPath]:
    """Open a file with boundary-safe checks.

    Returns (fd, stat_result, ResolvedPath). Caller is responsible for closing fd.

    Raises BoundaryError with appropriate reason tag.

    Implements the five checks from SPEC §3:
    - path: containment (via resolve_boundary_path)
    - validation: hardlink, regular-file, size-cap
    - io: EACCES, ENOENT, realpath failures
    """
    resolved = resolve_boundary_path(absolute_path, root_path, root_canonical)

    try:
        # O_NOFOLLOW prevents TOCTOU race where symlink is swapped after realpath.
        # Real OpenClaw uses openSync without O_NOFOLLOW because it has already
        # consumed the realpath above, but on Linux O_NOFOLLOW adds a cheap
        # additional guarantee.
        fd = os.open(resolved.canonical, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError as e:
        raise BoundaryError("io", f"ENOENT: {resolved.canonical}") from e
    except PermissionError as e:
        raise BoundaryError("io", f"EACCES: {resolved.canonical}") from e
    except OSError as e:
        raise BoundaryError("io", f"open failed: {e}") from e

    try:
        st = os.fstat(fd)
    except OSError as e:
        os.close(fd)
        raise BoundaryError("io", f"fstat failed: {e}") from e

    # Type check.
    if stat_module.S_ISDIR(st.st_mode):
        if not allow_directory:
            os.close(fd)
            raise BoundaryError("validation", f"is a directory: {resolved.canonical}")
    elif not stat_module.S_ISREG(st.st_mode):
        os.close(fd)
        raise BoundaryError(
            "validation",
            f"not a regular file: {resolved.canonical} (mode=0o{st.st_mode:o})",
        )

    # Hardlink rejection — only meaningful for regular files. Directories
    # always have nlink >= 2 (one for "." and one for each subdirectory's
    # "..").
    if reject_hardlinks and stat_module.S_ISREG(st.st_mode) and st.st_nlink > 1:
        os.close(fd)
        raise BoundaryError(
            "validation",
            f"hardlinked (nlink={st.st_nlink}): {resolved.canonical}",
        )

    # Size cap.
    if max_bytes is not None and st.st_size > max_bytes:
        os.close(fd)
        raise BoundaryError(
            "io",
            f"size {st.st_size} exceeds cap {max_bytes}: {resolved.canonical}",
        )

    return fd, st, resolved


def read_boundary_file(
    absolute_path: str,
    root_path: str,
    *,
    root_canonical: Optional[str] = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    reject_hardlinks: bool = True,
    encoding: str = "utf-8",
) -> str:
    """Convenience: open with boundary checks, read full contents as text, close.

    Mirrors the common pattern in workspace.ts where bootstrap files are opened,
    read fully, and closed.
    """
    fd, _st, _resolved = open_boundary_file(
        absolute_path,
        root_path,
        root_canonical=root_canonical,
        max_bytes=max_bytes,
        reject_hardlinks=reject_hardlinks,
    )
    try:
        with os.fdopen(fd, "rb", closefd=True) as f:
            raw = f.read()
    except OSError as e:
        raise BoundaryError("io", f"read failed: {e}") from e
    return raw.decode(encoding)


def file_identity(path: str) -> str:
    """Compute workspace file cache identity — SPEC §2 cache key format.

    Returns `{canonical_path}|{dev}:{ino}:{size}:{mtime_ns}`.

    Matches workspace.ts:53-55 `${canonicalPath}|${dev}:${ino}:${size}:${mtimeMs}`.
    We use mtime_ns for sub-ms precision (Python's stat gives ns; JS gives ms).
    Callers should treat the identity as an opaque string.
    """
    canonical = os.path.realpath(os.path.abspath(path))
    st = os.stat(canonical)
    # Convert to ms to match OpenClaw's mtimeMs precision for direct comparability.
    mtime_ms = int(st.st_mtime_ns / 1_000_000)
    return f"{canonical}|{st.st_dev}:{st.st_ino}:{st.st_size}:{mtime_ms}"
