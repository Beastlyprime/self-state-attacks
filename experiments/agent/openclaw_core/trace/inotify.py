"""Pure-Python ctypes wrapper around Linux inotify.

Zero third-party deps. Uses libc directly via ctypes — same path the
probe in `cli_smoke` / `tests/test_boundary` proved works.

Why not use `inotifywait` subprocess?
- The `inotify-tools` package isn't installable in our sandbox (no sudo).
- The harness wants events in-process so we can correlate them with the
  session-log `session_key` without a second JSONL merge step.
- Direct ctypes + os.read gives us syscall-level granularity, which is
  what the paper's detector algorithms actually consume.

Scope: recursive directory watches with the event mask used by the
paper's detectors (CREATE / MODIFY / DELETE / MOVED_FROM / MOVED_TO /
ATTRIB). This is NOT a general-purpose fsevents replacement — it only
runs on Linux; callers on other platforms get ImportError at usage
time, not import time (see `is_supported`).

Structure:
- `InotifyEvent` dataclass — a single parsed event.
- `InotifyWatch` class — one fd, many watch descriptors, blocking
  `read()` that returns a list of events. Callers run it on a thread.
- `recursive_watch_paths(root)` — enumerate subdirs under root so we
  can add a watch per directory (inotify isn't recursive natively).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import struct
import sys
from dataclasses import dataclass
from typing import Iterator, Optional


# ------------------------------ event masks (from <sys/inotify.h>)

IN_ACCESS = 0x00000001
IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_CLOSE_NOWRITE = 0x00000010
IN_OPEN = 0x00000020
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800

IN_UNMOUNT = 0x00002000
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000

IN_ONLYDIR = 0x01000000
IN_DONT_FOLLOW = 0x02000000
IN_MASK_ADD = 0x20000000
IN_ISDIR = 0x40000000
IN_ONESHOT = 0x80000000

# What we subscribe to by default — matches the OpenClaw detector feature
# set. We deliberately do NOT subscribe to IN_OPEN (every read OPEN would
# fire, polluting transactions). IN_CLOSE_WRITE is included because it
# brackets a write transaction: a single user-level ``open(..., "w")``
# emits ``MODIFY (truncate, size=0) → MODIFY (write, size=N) → CLOSE_WRITE``
# while ``open(..., "a")`` emits a single MODIFY before CLOSE_WRITE. The
# count of MODIFYs between consecutive CLOSE_WRITE events on the same
# path is the structural truncate-rewrite signal — see TraceCollector's
# ``_handle_event`` for the txn_id / n_modify tagging that surfaces this
# distinction to downstream detectors (paper §3 M1 vs M2).
DEFAULT_MASK = (
    IN_CREATE
    | IN_MODIFY
    | IN_DELETE
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_ATTRIB
    | IN_CLOSE_WRITE
)

# Name lookup — handy for JSONL serialization.
_MASK_NAMES: list[tuple[int, str]] = [
    (IN_ACCESS, "IN_ACCESS"),
    (IN_MODIFY, "IN_MODIFY"),
    (IN_ATTRIB, "IN_ATTRIB"),
    (IN_CLOSE_WRITE, "IN_CLOSE_WRITE"),
    (IN_CLOSE_NOWRITE, "IN_CLOSE_NOWRITE"),
    (IN_OPEN, "IN_OPEN"),
    (IN_MOVED_FROM, "IN_MOVED_FROM"),
    (IN_MOVED_TO, "IN_MOVED_TO"),
    (IN_CREATE, "IN_CREATE"),
    (IN_DELETE, "IN_DELETE"),
    (IN_DELETE_SELF, "IN_DELETE_SELF"),
    (IN_MOVE_SELF, "IN_MOVE_SELF"),
    (IN_UNMOUNT, "IN_UNMOUNT"),
    (IN_Q_OVERFLOW, "IN_Q_OVERFLOW"),
    (IN_IGNORED, "IN_IGNORED"),
    (IN_ISDIR, "IN_ISDIR"),
]


def mask_to_names(mask: int) -> list[str]:
    """Return the flag names set in `mask`. Order matches _MASK_NAMES."""
    return [name for bit, name in _MASK_NAMES if mask & bit]


def primary_event_name(mask: int) -> str:
    """Return the *primary* event name for JSONL output.

    inotify reports a bitmask (an event may carry both IN_CREATE + IN_ISDIR,
    for example). Our detectors key off the mutation kind, so we pick the
    most informative name in priority order.
    """
    # Ordered most-informative first; IN_ISDIR is a modifier, not the
    # primary name.
    for bit, name in (
        (IN_CREATE, "IN_CREATE"),
        (IN_DELETE, "IN_DELETE"),
        (IN_MOVED_FROM, "IN_MOVED_FROM"),
        (IN_MOVED_TO, "IN_MOVED_TO"),
        (IN_MODIFY, "IN_MODIFY"),
        (IN_ATTRIB, "IN_ATTRIB"),
        (IN_DELETE_SELF, "IN_DELETE_SELF"),
        (IN_MOVE_SELF, "IN_MOVE_SELF"),
        (IN_CLOSE_WRITE, "IN_CLOSE_WRITE"),
        (IN_OPEN, "IN_OPEN"),
        (IN_ACCESS, "IN_ACCESS"),
        (IN_Q_OVERFLOW, "IN_Q_OVERFLOW"),
        (IN_IGNORED, "IN_IGNORED"),
    ):
        if mask & bit:
            return name
    return f"0x{mask:x}"


# ------------------------------ platform gate


def is_supported() -> bool:
    """True on Linux (where inotify exists)."""
    return sys.platform.startswith("linux")


# ------------------------------ libc bindings


_libc = None
if is_supported():
    _libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
    _libc.inotify_init1.argtypes = [ctypes.c_int]
    _libc.inotify_init1.restype = ctypes.c_int
    _libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    _libc.inotify_add_watch.restype = ctypes.c_int
    _libc.inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
    _libc.inotify_rm_watch.restype = ctypes.c_int


IN_CLOEXEC = 0o2000000  # from <fcntl.h>
IN_NONBLOCK = 0o4000    # (value differs slightly across arches; this is x86/x86_64)


# ------------------------------ data + watch class


@dataclass
class InotifyEvent:
    """One parsed inotify event.

    Attributes:
        wd: watch descriptor (the dir the event happened in).
        mask: raw event bitmask.
        cookie: nonzero pair id for IN_MOVED_FROM / IN_MOVED_TO events.
        name: filename within the watched directory (empty for events on
            the directory itself).
        path: reconstructed absolute path (watch_dir + name). None if the
            caller hasn't registered this wd's directory — shouldn't
            happen in normal use but defensive.
    """

    wd: int
    mask: int
    cookie: int
    name: str
    path: Optional[str]


class InotifyWatch:
    """A single inotify fd with one or more watched directories.

    Thread model: this class is NOT thread-safe. Callers own the
    read/close lifecycle. Typical use:

        w = InotifyWatch()
        for d in dirs:
            w.add_watch(d)
        try:
            while keep_going:
                for evt in w.read(timeout_ms=500):
                    handle(evt)
        finally:
            w.close()

    The class is intentionally small so the `TraceCollector` wrapper can
    drive it from a background thread.
    """

    def __init__(self) -> None:
        if not is_supported():
            raise OSError(errno.ENOSYS, "inotify is Linux-only")
        # Non-blocking so we can honor a timeout in read().
        fd = _libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if fd < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err), "inotify_init1")
        self._fd = fd
        # wd -> absolute directory path
        self._wd_to_path: dict[int, str] = {}

    def fileno(self) -> int:
        return self._fd

    def add_watch(self, directory: str, mask: int = DEFAULT_MASK) -> int:
        """Attach a watch to `directory`. Returns the new wd.

        Raises OSError on failure (e.g. ENOENT, ENOSPC when
        max_user_watches is exhausted).
        """
        abspath = os.path.abspath(directory)
        wd = _libc.inotify_add_watch(self._fd, abspath.encode("utf-8"), mask)
        if wd < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err), f"inotify_add_watch({abspath})")
        self._wd_to_path[wd] = abspath
        return wd

    def rm_watch(self, wd: int) -> None:
        """Remove a previously-added watch. Silently ignores already-gone wds."""
        rc = _libc.inotify_rm_watch(self._fd, wd)
        if rc < 0:
            # EINVAL means the wd was already removed by the kernel (e.g.
            # the dir was deleted). Not an error for us.
            err = ctypes.get_errno()
            if err != errno.EINVAL:
                raise OSError(err, os.strerror(err), f"inotify_rm_watch({wd})")
        self._wd_to_path.pop(wd, None)

    def close(self) -> None:
        try:
            os.close(self._fd)
        except OSError:
            pass

    def read(self, *, timeout_ms: int = 500, max_bytes: int = 65536) -> list[InotifyEvent]:
        """Read available events. Returns empty list on timeout.

        `timeout_ms` uses select.select for cross-kernel compatibility
        (epoll would be slightly faster but not worth the complexity).
        """
        import select
        r, _, _ = select.select([self._fd], [], [], timeout_ms / 1000.0)
        if not r:
            return []
        try:
            buf = os.read(self._fd, max_bytes)
        except BlockingIOError:
            return []
        return list(self._parse_buffer(buf))

    # ---- internals

    def _parse_buffer(self, buf: bytes) -> Iterator[InotifyEvent]:
        # struct inotify_event { int wd; uint32_t mask; uint32_t cookie; uint32_t len; char name[]; }
        header_size = struct.calcsize("iIII")
        i = 0
        while i < len(buf):
            if i + header_size > len(buf):
                # Partial event — shouldn't happen because kernel
                # guarantees atomicity of events, but defensive.
                return
            wd, mask, cookie, length = struct.unpack_from("iIII", buf, i)
            i += header_size
            if length > 0:
                name = buf[i:i + length].rstrip(b"\0").decode("utf-8", "replace")
            else:
                name = ""
            i += length

            parent = self._wd_to_path.get(wd)
            if parent is not None and name:
                full_path = os.path.join(parent, name)
            elif parent is not None:
                # Event on the watched directory itself.
                full_path = parent
            else:
                full_path = None

            yield InotifyEvent(
                wd=wd, mask=mask, cookie=cookie, name=name, path=full_path
            )


# ------------------------------ recursive walk helper


# Canonical list of directory names to exclude from watches AND from runtime
# event emission. The TraceCollector reuses this so noise like Python bytecode
# caches and .git internals doesn't flood traces for code workloads (W1).
NOISE_DIR_NAMES: frozenset[str] = frozenset({
    "__pycache__", ".git", ".DS_Store", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", ".tox", ".venv", "node_modules",
})


def recursive_watch_paths(
    root: str,
    *,
    skip_names: frozenset[str] = NOISE_DIR_NAMES,
) -> list[str]:
    """Enumerate directories under `root` to install watches on.

    inotify isn't recursive — the caller must call add_watch for each
    subdirectory. We skip typical noise listed in NOISE_DIR_NAMES
    (__pycache__, .git, .venv, node_modules, …). Newly created
    subdirectories during a session are NOT auto-watched here; the
    TraceCollector adds them dynamically when it sees IN_CREATE +
    IN_ISDIR.

    IMPORTANT: we do NOT blanket-skip every dotdir. Workspace-local
    `.openclaw/` holds runtime workspace state such as
    `.openclaw/workspace-state.json`; session transcripts live in the
    external OpenClaw state root and are not part of the paper's in-matrix
    self-state targets. Use the explicit NOISE_DIR_NAMES blacklist, not a
    leading `.` rule.
    """
    root = os.path.abspath(root)
    out: list[str] = []
    if not os.path.isdir(root):
        return out
    for dirpath, dirnames, _ in os.walk(root):
        # Prune skipped subdirs in-place so os.walk doesn't descend.
        dirnames[:] = [d for d in dirnames if d not in skip_names]
        out.append(dirpath)
    return out
