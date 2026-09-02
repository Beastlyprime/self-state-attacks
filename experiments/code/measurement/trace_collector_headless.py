#!/usr/bin/env python3
"""
DEPRECATED — measurement/trace_collector_headless.py
=====================================================

This module is the old standalone CLI collector used by ``task_runner.py``
to subprocess-out a JSONL writer. It has known fidelity bugs that were
audited and documented:

  1. Module docstring + ``skip_stat`` machinery still mention ``IN_OPEN``,
     but the active Linux path does not subscribe to it. The dead code
     and stale comments are kept for git-blame friendliness, but the
     actual contract is "OPEN is never emitted on the inotify_simple
     path."
  2. ``_cache_dir()`` and the recursive walker filter every dotdir
     (``startswith(".")``). That silently skips workspace-local
     ``.openclaw/`` state under the new harness — events under it are
     not pre-cached or watched.
  3. The output JSONL has no self-event filter. If ``--output`` lands
     inside ``--watch-dirs``, every flush triggers another IN_MODIFY
     and the trace feeds back on itself. Current callers happen to put
     output outside the watch tree, but it is not enforced.
  4. ``_relative_path()`` uses raw ``startswith(d)`` rather than path
     boundary matching, so ``/tmp/abc`` would be misclassified as
     relative to a watch dir of ``/tmp/a``.

For paper-grade trace capture, use the in-process collector at
``openclaw_core.trace.TraceCollector`` instead. It:

  * uses the ``NOISE_DIR_NAMES`` blacklist (so ``.openclaw/`` is watched);
  * filters its own output realpath to break the self-feedback loop;
  * uses ``os.path.relpath`` for proper path-boundary handling;
  * subscribes to ``IN_CLOSE_WRITE`` and emits ``txn_id`` + ``n_modify``
    so downstream detectors can distinguish paper M1 (truncate-rewrite,
    ``open('w')``) from paper M2 (append, ``open('a')``);
  * runs in-process inside the harness, so no subprocess pipe overhead.

This file remains for legacy task_runner.py compatibility and may still
be invoked when the new harness is not running. New experiments should
not depend on it.

Original module documentation follows.

----------------------------------------------------------------------

Headless Trace Collector for ASSA-Bench v4 — kernel-fidelity rev.

Earlier revisions piped ``inotifywait`` and called ``os.stat`` at record
time, which lost two important kernel-level signals:

  1. **The truncate-rewrite signature.** A user-level ``open(path, "w")``
     emits ``OPEN → MODIFY (size=0) → MODIFY (size=N) → CLOSE_WRITE``.
     Stat'ing only at record time saw size=N for both MODIFY events,
     dropping the size=0 truncate marker. M1 (modify by truncate-rewrite)
     and M2 (append) became indistinguishable in our traces even though
     inotify itself can tell them apart.

  2. **Transaction boundaries.** OPEN and CLOSE_WRITE events were not
     subscribed to, so multiple MODIFY events were treated as separate
     write transactions when in reality they were a single user-level
     write.

This rewrite uses ``inotify_simple`` directly (no subprocess pipe), so:

  * We read kernel events synchronously on the same Python thread that
    runs ``os.stat``, tightening the event-time-to-stat race window.
  * We subscribe to ``OPEN``, ``CLOSE_WRITE`` in addition to MODIFY/
    ATTRIB/CREATE/DELETE/MOVED_FROM/MOVED_TO. Downstream analyzers
    receive transaction boundaries and the per-MODIFY size sequence.
  * We tag each event with a ``txn_id`` derived from the OPEN/MODIFY/
    CLOSE_WRITE sequence so trace_baseline can fold one transaction
    into a single record while preserving truncate signals.
  * Each event also records ``cookie`` (for MOVED_FROM/MOVED_TO pairs),
    ``size_at_event`` (size captured at the inotify event), and
    ``hash`` / ``mode`` for full feature recovery downstream.

The macOS path (fswatch) and the polling fallback are kept for
portability but produce a coarser event stream and emit a
``collector_warning`` marker so analyzers know to fall back to
hash-based aggregation rather than transaction-based aggregation.

Usage:
    python trace_collector_headless.py \
        --watch-dirs /path/to/dir1 /path/to/dir2 \
        --output traces/session_01.jsonl \
        --session-tag S1_fix_typo
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import platform
import signal
import stat as _stat
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple


# =============================================================================
# Filesystem helpers
# =============================================================================

def sha256_file(path: str) -> Optional[str]:
    """SHA-256 hex digest of the file at ``path``, or None if unreadable."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def file_stat(path: str) -> Tuple[Optional[int], Optional[int]]:
    """Return (size, mode_perm_bits) or (None, None) on error.

    Mode is 0o777-masked permission bits so downstream analyzers can
    detect M4 (chmod) attacks via mode-only change.
    """
    try:
        st = os.stat(path)
        return st.st_size, _stat.S_IMODE(st.st_mode)
    except OSError:
        return None, None


# =============================================================================
# Linux inotify path (fidelity-preserving)
# =============================================================================

# Mapping from inotify_simple flag enum -> our IN_* event tag.
_INOTIFY_TAG_BY_FLAG = {
    "CREATE": "IN_CREATE",
    "DELETE": "IN_DELETE",
    "MOVED_FROM": "IN_MOVED_FROM",
    "MOVED_TO": "IN_MOVED_TO",
    "MODIFY": "IN_MODIFY",
    "ATTRIB": "IN_ATTRIB",
    "OPEN": "IN_OPEN",
    "CLOSE_WRITE": "IN_CLOSE_WRITE",
    "DELETE_SELF": "IN_DELETE_SELF",
    "MOVE_SELF": "IN_MOVE_SELF",
}


class HeadlessTraceCollector:
    """Collects FS traces with per-event fidelity (Linux + Python inotify)."""

    def __init__(self, watch_dirs: list, output_path: str, session_tag: str):
        self.watch_dirs = [os.path.expanduser(d) for d in watch_dirs]
        self.output_path = output_path
        self.session_tag = session_tag
        self._cache: Dict[str, dict] = {}  # path -> last seen state
        self.event_count = 0
        self._running = False
        self._outfile = None
        # Per-(path) running write transaction id. Bumped on each OPEN
        # for the path; subsequent MODIFY events under that OPEN inherit
        # the same txn_id; CLOSE_WRITE closes the transaction. This lets
        # trace_baseline group inotify events into user-level write
        # transactions without losing intra-transaction MODIFY sequence.
        self._open_txn: Dict[str, int] = {}
        self._txn_counter = itertools.count(1)

        # Pre-cache every existing file under watch dirs so the first
        # MODIFY can produce a meaningful prev_size delta.
        for d in self.watch_dirs:
            self._cache_dir(d)

    # ----- caching ---------------------------------------------------------

    def _cache_dir(self, directory: str):
        if not os.path.isdir(directory):
            return
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                path = os.path.join(root, fname)
                size, mode = file_stat(path)
                self._cache[path] = {
                    "size": size,
                    "mode": mode,
                    "hash": sha256_file(path),
                }

    def _relative_path(self, abspath: str) -> str:
        for d in self.watch_dirs:
            if abspath.startswith(d):
                return os.path.relpath(abspath, d)
        return abspath

    # ----- record emission -------------------------------------------------

    def _emit(self, record: dict):
        if self._outfile:
            self._outfile.write(json.dumps(record) + "\n")
            self._outfile.flush()
        self.event_count += 1

    def _record_event(
        self,
        filepath: str,
        event_tag: str,
        ev_ts: float,
        cookie: Optional[int] = None,
        skip_stat: bool = False,
    ):
        """Capture a single inotify event with size/hash/mode at event time.

        ``skip_stat=True`` is used for OPEN events where we deliberately
        do NOT touch the file to keep the stat race window from
        contaminating the per-MODIFY size sequence. The OPEN event
        records only the txn_id and cookie; the prev-cache size from
        the last completed transaction is used as size_before for the
        first MODIFY in the new transaction.
        """
        prev = self._cache.get(filepath, {})
        if skip_stat:
            size = prev.get("size")
            mode = prev.get("mode")
            new_hash = prev.get("hash")
        else:
            size, mode = file_stat(filepath)
            # Hash on read events is expensive; only re-hash when content
            # could have actually changed (modify, create, close_write,
            # or attrib that strips read perms).
            if event_tag in ("IN_MODIFY", "IN_CLOSE_WRITE", "IN_CREATE"):
                new_hash = sha256_file(filepath)
            elif event_tag == "IN_ATTRIB":
                # mode change may strip read perms — preserve last known
                # hash if the new mode is unreadable.
                if size == prev.get("size") and prev.get("hash"):
                    new_hash = sha256_file(filepath) or prev.get("hash")
                else:
                    new_hash = sha256_file(filepath)
            else:
                new_hash = prev.get("hash")

        prev_size = prev.get("size")
        if size is not None and prev_size is not None:
            delta = size - prev_size
        elif size is not None:
            delta = size
        elif prev_size is not None:
            delta = -prev_size
        else:
            delta = None

        # Transaction tracking. Without OPEN events, we infer transaction
        # boundaries from CLOSE_WRITE: every MODIFY shares the txn id of
        # the next CLOSE_WRITE for the same file. We assign a new txn id
        # eagerly on the first MODIFY for a file (or the standalone
        # CREATE / ATTRIB / DELETE / MOVED_*), and the txn closes when
        # we see CLOSE_WRITE for that file. This lets trace_baseline
        # group multi-MODIFY transactions (truncate-rewrite) into one
        # logical write while keeping single-MODIFY transactions (append)
        # distinct.
        txn_id = self._open_txn.get(filepath)
        if event_tag in ("IN_MODIFY", "IN_CREATE"):
            if txn_id is None:
                txn_id = next(self._txn_counter)
                self._open_txn[filepath] = txn_id
        elif event_tag == "IN_CLOSE_WRITE":
            # Carry the txn id forward and clear it so the next MODIFY
            # starts a fresh transaction.
            txn_id = self._open_txn.pop(filepath, None)
            if txn_id is None:
                # Standalone CLOSE_WRITE without a prior MODIFY (rare —
                # e.g. close-after-truncate-only without write). Assign
                # a fresh id so it is still trackable.
                txn_id = next(self._txn_counter)
        elif event_tag in ("IN_ATTRIB", "IN_DELETE", "IN_MOVED_FROM", "IN_MOVED_TO"):
            # These are atomic events with no transaction grouping.
            txn_id = next(self._txn_counter)

        record = {
            "ts": ev_ts,
            "session": self.session_tag,
            "event": event_tag,
            "path": self._relative_path(filepath),
            "size": size,
            "size_prev": prev_size,
            "delta": delta,
            "hash": new_hash[:32] if new_hash else None,
            "hash_prev": prev.get("hash")[:32] if prev.get("hash") else None,
            "mode": mode,
            "mode_prev": prev.get("mode"),
            "txn_id": txn_id,
            "cookie": cookie,
        }
        # Update cache after emission so subsequent events see this as
        # the new "previous state" — except for OPEN where we explicitly
        # did not stat (keep prev cache untouched).
        if not skip_stat:
            self._cache[filepath] = {
                "size": size,
                "mode": mode,
                "hash": new_hash,
            }

        self._emit(record)

    # ----- main run loops --------------------------------------------------

    def run(self):
        system = platform.system()
        self._outfile = open(self.output_path, "w", encoding="utf-8")
        self._emit({
            "ts": time.time(),
            "session": self.session_tag,
            "event": "session_start",
            "path": None,
            "size": None,
            "delta": None,
            "hash": None,
            "collector_rev": "kernel_fidelity_v1",
        })

        if system == "Linux":
            try:
                self._run_inotify_python()
                return
            except ImportError:
                self._emit({
                    "ts": time.time(),
                    "session": self.session_tag,
                    "event": "collector_warning",
                    "path": None,
                    "message": "inotify_simple unavailable; falling back to inotifywait pipe",
                })
                if self._run_inotifywait_pipe():
                    return

        if system == "Darwin":
            if self._run_fswatch_pipe():
                return

        # Final fallback.
        self._emit({
            "ts": time.time(),
            "session": self.session_tag,
            "event": "collector_warning",
            "path": None,
            "message": "no native watcher; using polling (truncate signal will be coarse)",
        })
        self._run_polling()

    def _run_inotify_python(self):
        """Linux preferred path: read inotify events directly in-process.

        Subscribes to CLOSE_WRITE (writable-open close) but NOT OPEN
        (read OPENs are noisy: every os.stat / Python file read triggers
        an OPEN+CLOSE_NOWRITE pair we don't care about). The combination
        gives us:

          * Transaction boundary marker via CLOSE_WRITE.
          * Per-MODIFY size at event-time (best-effort; kernel may have
            advanced by stat-time, so the COUNT of MODIFY events between
            consecutive CLOSE_WRITE is the structural truncate signal —
            ``open('w')`` emits two MODIFY (truncate + write) while
            ``open('a')`` emits one).

        trace_baseline reads the per-file MODIFY count since the last
        CLOSE_WRITE to disambiguate M1 (truncate-rewrite) from M2
        (append) at the OS event level.
        """
        from inotify_simple import INotify, flags  # type: ignore

        ino = INotify()
        # Note: deliberately NO ``flags.OPEN`` — it fires for every read
        # OPEN as well, polluting transactions. CLOSE_WRITE is sufficient
        # to bracket write transactions (it only fires when a writable
        # open is closed).
        mask = (
            flags.CREATE | flags.DELETE
            | flags.MOVED_FROM | flags.MOVED_TO
            | flags.MODIFY | flags.ATTRIB
            | flags.CLOSE_WRITE
            | flags.DELETE_SELF | flags.MOVE_SELF
        )
        watch_descriptors: Dict[int, str] = {}
        # Recursive add — we walk the tree once and add each subdir.
        # Inotify_simple has no built-in recursive watch; the walker
        # below covers any subdir that exists at start. Subdirs created
        # mid-session are picked up by the IN_CREATE handler below.
        for d in self.watch_dirs:
            for root, dirs, _ in os.walk(d):
                dirs[:] = [x for x in dirs if not x.startswith(".") and x != "__pycache__"]
                wd = ino.add_watch(root, mask)
                watch_descriptors[wd] = root

        self._running = True

        def handle_signal(signum, frame):
            self._running = False

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        try:
            while self._running:
                events = ino.read(timeout=200)
                if not events:
                    continue
                ev_ts = time.time()  # millisecond-tight to kernel queue drain
                for ev in events:
                    parent_dir = watch_descriptors.get(ev.wd)
                    if parent_dir is None:
                        continue
                    name = ev.name or ""
                    abs_path = os.path.join(parent_dir, name) if name else parent_dir
                    # Map flags bitmask to one or more event tags, in
                    # kernel order. Note: ATTRIB+ISDIR for new subdirs
                    # is filtered by checking flags membership directly.
                    fl = list(flags.from_mask(ev.mask))
                    is_dir = flags.ISDIR in fl
                    cookie = ev.cookie if ev.cookie else None
                    for f in fl:
                        if f == flags.ISDIR:
                            continue
                        tag = _INOTIFY_TAG_BY_FLAG.get(f.name)
                        if tag is None:
                            continue
                        # If a new directory is created, recursively add
                        # it to the watch so its contents are tracked.
                        if tag == "IN_CREATE" and is_dir and os.path.isdir(abs_path):
                            try:
                                wd2 = ino.add_watch(abs_path, mask)
                                watch_descriptors[wd2] = abs_path
                            except OSError:
                                pass
                            continue
                        if is_dir and tag in ("IN_MODIFY", "IN_ATTRIB", "IN_CLOSE_WRITE"):
                            # Directory mtime / close on the directory
                            # is not a write transaction we care about
                            # for self-state.
                            continue
                        self._record_event(abs_path, tag, ev_ts, cookie=cookie)
        finally:
            self._emit({
                "ts": time.time(),
                "session": self.session_tag,
                "event": "session_end",
                "path": None,
                "size": None,
                "delta": None,
                "hash": None,
            })
            self._outfile.close()
            ino.close()
            print(f"[headless-collector] {self.event_count} events recorded", file=sys.stderr)

    # ----- legacy fallbacks ------------------------------------------------

    def _run_inotifywait_pipe(self) -> bool:
        """Kept for environments without python-inotify; coarse fidelity."""
        cmd = [
            "inotifywait", "-m", "-r",
            "--timefmt", "%s",
            "--format", "%T|%w%f|%e|%c",
            "--event", "create,modify,delete,moved_from,moved_to,attrib,open,close_write",
            "--exclude", r"(\.git|__pycache__|\.DS_Store)",
        ] + self.watch_dirs
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1,
            )
        except FileNotFoundError:
            return False

        self._running = True

        def handle_signal(signum, frame):
            self._running = False

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        try:
            for line in proc.stdout:
                if not self._running:
                    break
                line = line.strip()
                if not line:
                    continue
                parts = line.split("|", 3)
                if len(parts) < 3:
                    continue
                ts_raw = parts[0]
                filepath = parts[1].strip()
                events_field = parts[2]
                cookie_raw = parts[3] if len(parts) >= 4 else ""
                try:
                    ev_ts = float(ts_raw)
                except ValueError:
                    ev_ts = time.time()
                cookie = int(cookie_raw) if cookie_raw.strip().isdigit() else None
                for raw_ev in events_field.split(","):
                    raw_ev = raw_ev.strip().lower()
                    if "isdir" in raw_ev:
                        continue
                    if "create" in raw_ev:
                        tag = "IN_CREATE"
                    elif "delete" in raw_ev:
                        tag = "IN_DELETE"
                    elif "moved_from" in raw_ev:
                        tag = "IN_MOVED_FROM"
                    elif "moved_to" in raw_ev:
                        tag = "IN_MOVED_TO"
                    elif "modify" in raw_ev:
                        tag = "IN_MODIFY"
                    elif "attrib" in raw_ev:
                        tag = "IN_ATTRIB"
                    elif "open" in raw_ev:
                        tag = "IN_OPEN"
                    elif "close_write" in raw_ev:
                        tag = "IN_CLOSE_WRITE"
                    else:
                        continue
                    self._record_event(
                        filepath, tag, ev_ts,
                        cookie=cookie, skip_stat=(tag == "IN_OPEN"),
                    )
        finally:
            self._running = False
            self._emit({
                "ts": time.time(),
                "session": self.session_tag,
                "event": "session_end",
                "path": None,
                "size": None,
                "delta": None,
                "hash": None,
            })
            self._outfile.close()
            proc.terminate()
            proc.wait()
            print(f"[headless-collector] {self.event_count} events recorded", file=sys.stderr)
        return True

    def _run_fswatch_pipe(self) -> bool:
        """macOS path. Coarser than Linux inotify path; emits a warning."""
        self._emit({
            "ts": time.time(),
            "session": self.session_tag,
            "event": "collector_warning",
            "path": None,
            "message": "fswatch path: no OPEN/CLOSE_WRITE markers, no truncate signal preservation",
        })
        cmd = [
            "fswatch", "--event-flags", "-r",
            "--exclude", r"\.git",
            "--exclude", r"__pycache__",
            "--exclude", r"\.DS_Store",
        ] + self.watch_dirs
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1,
            )
        except FileNotFoundError:
            return False

        self._running = True

        def handle_signal(signum, frame):
            self._running = False

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        try:
            for line in proc.stdout:
                if not self._running:
                    break
                parts = line.strip().split()
                filepath = next((p for p in parts if p.startswith("/")), None)
                if not filepath:
                    continue
                events = " ".join(parts[parts.index(filepath) + 1:]).lower()
                if "created" in events or "create" in events:
                    tag = "IN_CREATE"
                elif "removed" in events or "delete" in events:
                    tag = "IN_DELETE"
                elif "renamed" in events or "moved_from" in events:
                    tag = "IN_MOVED_FROM"
                elif "moved_to" in events:
                    tag = "IN_MOVED_TO"
                elif "updated" in events or "modified" in events or "modify" in events:
                    tag = "IN_MODIFY"
                elif "attrib" in events or "ownermod" in events or "inodem" in events:
                    tag = "IN_ATTRIB"
                else:
                    continue
                self._record_event(filepath, tag, time.time())
        finally:
            self._running = False
            self._emit({
                "ts": time.time(),
                "session": self.session_tag,
                "event": "session_end",
                "path": None,
                "size": None,
                "delta": None,
                "hash": None,
            })
            self._outfile.close()
            proc.terminate()
            proc.wait()
            print(f"[headless-collector] {self.event_count} events recorded (fswatch)", file=sys.stderr)
        return True

    def _run_polling(self):
        """Last-resort polling fallback (0.5 s). Coarse fidelity."""
        self._emit({
            "ts": time.time(),
            "session": self.session_tag,
            "event": "collector_warning",
            "path": None,
            "message": "polling path: no transaction boundaries, truncate signal coarse",
        })
        self._running = True

        def handle_signal(signum, frame):
            self._running = False

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        while self._running:
            seen: set = set()
            for d in self.watch_dirs:
                if not os.path.isdir(d):
                    continue
                for root, dirs, files in os.walk(d):
                    dirs[:] = [x for x in dirs if not x.startswith(".") and x != "__pycache__"]
                    for fname in files:
                        if fname in (".DS_Store", ".gitignore", ".gitkeep"):
                            continue
                        path = os.path.join(root, fname)
                        seen.add(path)
                        size, mode = file_stat(path)
                        prev = self._cache.get(path)
                        new_hash = sha256_file(path)
                        if prev is None:
                            self._cache[path] = {"size": size, "mode": mode, "hash": new_hash}
                            self._record_event(path, "IN_CREATE", time.time())
                        else:
                            mode_changed = mode != prev.get("mode")
                            hash_changed = new_hash != prev.get("hash")
                            size_unchanged = size == prev.get("size")
                            hash_unreadable = new_hash is None
                            if mode_changed and (
                                not hash_changed or (hash_unreadable and size_unchanged)
                            ):
                                self._record_event(path, "IN_ATTRIB", time.time())
                            elif hash_changed:
                                self._record_event(path, "IN_MODIFY", time.time())
            for path in list(self._cache):
                if path in seen:
                    continue
                if any(path.startswith(d) for d in self.watch_dirs):
                    if not os.path.exists(path):
                        self._record_event(path, "IN_DELETE", time.time())
                        self._cache.pop(path, None)
            time.sleep(0.5)

        self._emit({
            "ts": time.time(),
            "session": self.session_tag,
            "event": "session_end",
            "path": None,
            "size": None,
            "delta": None,
            "hash": None,
        })
        self._outfile.close()
        print(f"[headless-collector] {self.event_count} events (polling)", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Headless trace collector (kernel-fidelity rev)")
    parser.add_argument("--watch-dirs", nargs="+", required=True)
    parser.add_argument("--output", "-o", required=True)
    parser.add_argument("--session-tag", "-t", default="session")
    args = parser.parse_args()

    for d in args.watch_dirs:
        expanded = os.path.expanduser(d)
        if not os.path.isdir(expanded):
            print(f"Warning: {expanded} does not exist", file=sys.stderr)

    collector = HeadlessTraceCollector(
        watch_dirs=args.watch_dirs,
        output_path=args.output,
        session_tag=args.session_tag,
    )
    collector.run()


if __name__ == "__main__":
    main()
