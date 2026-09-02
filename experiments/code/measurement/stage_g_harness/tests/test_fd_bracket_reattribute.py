"""Unambiguous (pid, fd) bracket resolution in libsinsp reattribution.

Covers the operands the exact-key join leaves behind (audit-sourced reads whose
timestamp never matches a libsinsp event): resolve them via libsinsp's own
(pid, fd) timeline, but only when the bracketing events agree -- never bind by
temporal proximity across an fd rebind.
"""
from __future__ import annotations

import sys
from pathlib import Path

HARNESS_ROOT = Path(__file__).resolve().parents[2]
if str(HARNESS_ROOT) not in sys.path:
    sys.path.insert(0, str(HARNESS_ROOT))

from stage_g_harness.libsinsp_reattribute import _resolve_via_fd_bracket


def _lib(pid, fd, ts, inode, path):
    return {"process": {"pid": pid}, "order": {"timestamp_realtime_ns": ts},
            "syscall": {"name": "read"}, "fd": {"num": fd, "type": "file"},
            "file": {"inode": inode, "dev_major": 253, "dev_minor": 1, "path": path}}


def _read_row(pid, fd, ts, file=None):
    return {"process": {"pid": pid}, "order": {"timestamp_realtime_ns": ts},
            "syscall": {"name": "read", "success": True},
            "fd": {"input_fd": fd}, "file": file if file is not None else {}}


def test_bracket_agreement_resolves():
    lib = [_lib(997, 3, t, 5031, "/lib/libm.so.6") for t in (100, 120, 180, 200)]
    row = _read_row(997, 3, 150)
    stats = _resolve_via_fd_bracket([row], lib)
    assert stats.get("fd_bracket_resolved") == 1
    assert row["file"]["inode"] == 5031
    assert row["file"]["resolution_status"] == "libsinsp_fd_bracket"
    assert row["file"]["dev"] == "fd:01"


def test_fd_reuse_across_read_stays_unresolved():
    # fd=3 rebinds between the brackets: 5031 before, 4711 after -> must not bind.
    lib = [_lib(997, 3, 140, 5031, "/a"), _lib(997, 3, 160, 4711, "/b")]
    row = _read_row(997, 3, 150)
    stats = _resolve_via_fd_bracket([row], lib)
    assert stats.get("fd_bracket_ambiguous") == 1
    assert row["file"].get("inode") is None


def test_read_outside_libsinsp_coverage_stays_unresolved():
    # only a before-bracket exists (read after all libsinsp events on this fd).
    lib = [_lib(997, 3, 100, 5031, "/a")]
    row = _read_row(997, 3, 150)
    stats = _resolve_via_fd_bracket([row], lib)
    assert stats.get("fd_bracket_ambiguous") == 1
    assert row["file"].get("inode") is None


def test_already_resolved_row_untouched():
    lib = [_lib(997, 3, t, 5031, "/lib/libm.so.6") for t in (100, 200)]
    row = _read_row(997, 3, 150, file={"inode": 999, "dev": "fd:01"})
    _resolve_via_fd_bracket([row], lib)
    assert row["file"]["inode"] == 999


def test_socket_and_no_timeline_are_skipped():
    row_socket = {"process": {"pid": 997}, "order": {"timestamp_realtime_ns": 150},
                  "syscall": {"name": "read", "success": True},
                  "fd": {"input_fd": 3}, "socket": {"family": "AF_INET"}, "file": {}}
    row_no_tl = _read_row(997, 9, 150)  # no libsinsp timeline for (997, 9)
    stats = _resolve_via_fd_bracket([row_socket, row_no_tl], [_lib(997, 3, 100, 1, "/a")])
    assert row_socket["file"] == {}
    assert stats.get("fd_bracket_no_timeline") == 1
