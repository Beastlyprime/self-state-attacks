"""TraceCollector — background inotify-based trace capture for one session.

Wraps `InotifyWatch` with:
- a background thread that drives the read loop
- JSONL output in the same shape as `measurement/trace_collector_headless.py`
  so the existing `trace_analyzer.py` can consume it unchanged
- per-file snapshot cache (size, sha256-prefix, mode) so each event record
  carries a size delta and a content fingerprint — required by the paper's
  anomaly detectors (content-delta, attrib-only vs modify, etc.)
- dynamic subdirectory watching: when the LLM creates a new subdir under
  the workspace, we install a watch on it so we don't miss events inside

Correlation with session log: the JSONL's `session` field is the same
`session_key` the SessionLogger uses. Downstream analysis can join
the trace and session log by that key.

Lifecycle contract:
    c = TraceCollector(
        watch_root="/abs/path/workspace",
        output_path="/abs/path/traces/session-X.jsonl",
        session_tag="session-X",
    )
    c.start()        # spawns the read thread
    # ... harness runs the LLM loop — it writes files, fires tools, etc.
    c.stop()         # signals the thread to exit, joins it, closes JSONL

start() and stop() are idempotent. stop() is safe from any thread.

This class is NOT a general-purpose file-system monitor. It's scoped to
one workspace root + one output file + one session. For cross-session
experiments, create a new instance each time.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from .inotify import (
    IN_ACCESS,
    DEFAULT_MASK,
    IN_CLOSE_WRITE,
    IN_CLOSE_NOWRITE,
    IN_CREATE,
    IN_DELETE,
    IN_ISDIR,
    IN_MODIFY,
    IN_OPEN,
    IN_Q_OVERFLOW,
    NOISE_DIR_NAMES,
    InotifyEvent,
    InotifyWatch,
    primary_event_name,
    recursive_watch_paths,
)
from .schema import boot_time_anchor, event_envelope


_HASH_PREFIX_LEN = 16  # match trace_collector_headless.py


def _safe_size(path: str) -> Optional[int]:
    try:
        return os.path.getsize(path)
    except OSError:
        return None


def _safe_mode(path: str) -> Optional[int]:
    try:
        return stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return None


def _safe_hash_prefix(path: str, *, max_bytes: int = 2 * 1024 * 1024) -> Optional[str]:
    """SHA-256 of (at most `max_bytes`) of file content, 16-hex prefix.

    Skips files >2MB for speed; detectors only need a fingerprint, not
    cryptographic integrity. Returns None on any OS error (missing file,
    perm denied, etc.).
    """
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            # Cap read to avoid hashing huge binaries — matches
            # trace_collector_headless.py behavior.
            remaining = max_bytes
            while remaining > 0:
                chunk = f.read(min(8192, remaining))
                if not chunk:
                    break
                h.update(chunk)
                remaining -= len(chunk)
        return h.hexdigest()[:_HASH_PREFIX_LEN]
    except OSError:
        return None


@dataclass
class _FileSnapshot:
    size: Optional[int] = None
    hash: Optional[str] = None
    mode: Optional[int] = None


@dataclass
class TraceCollector:
    """Background trace capture for one workspace / one session.

    Attributes:
        watch_root: absolute root directory. All subdirs will be watched
            recursively (skip dotdirs + __pycache__).
        output_path: JSONL file to append events to. Overwritten on start.
        session_tag: string stamped into each record's `session` field.
            Typically the session_key from SessionLogger.
        mask: inotify event mask. Default covers create/modify/delete/
            moved/attrib — what the paper's detectors consume.
        read_timeout_ms: how long the reader blocks in one cycle.
        queue_overflow_behavior: "log" (record a warning in JSONL) or
            "raise" (propagate). Default "log" — the collector should
            never crash the harness.
    """

    watch_root: str
    output_path: str
    session_tag: str
    mask: int = DEFAULT_MASK
    read_timeout_ms: int = 300
    queue_overflow_behavior: str = "log"
    retain_noise_events: bool = False

    # --- internal state (don't set directly) ---
    _watch: Optional[InotifyWatch] = field(default=None, init=False, repr=False)
    _thread: Optional[threading.Thread] = field(default=None, init=False, repr=False)
    _stop_event: threading.Event = field(default_factory=threading.Event, init=False, repr=False)
    _outfile: object = field(default=None, init=False, repr=False)
    _outfile_lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _cache: dict[str, _FileSnapshot] = field(default_factory=dict, init=False, repr=False)
    _event_count: int = field(default=0, init=False)
    _overflow_count: int = field(default=0, init=False)
    _started: bool = field(default=False, init=False)
    _output_realpath: Optional[str] = field(default=None, init=False, repr=False)
    _run_anchor: dict = field(default_factory=dict, init=False, repr=False)
    _collector_started_wall_ns: Optional[int] = field(default=None, init=False)
    _collector_started_monotonic_ns: Optional[int] = field(default=None, init=False)
    _collector_stopped_wall_ns: Optional[int] = field(default=None, init=False)
    _collector_stopped_monotonic_ns: Optional[int] = field(default=None, init=False)
    _queue_high_water_mark: int = field(default=0, init=False)
    _excluded_self_event_count: int = field(default=0, init=False)
    # Open write-transaction id per path. Allocated on the first MODIFY
    # (or CREATE that grew the file) and cleared on the matching
    # CLOSE_WRITE. ``txn_id`` and ``n_modify`` preserve the events the kernel
    # exposes, but are not a guaranteed M1/M2 discriminator: both Linux 6.14
    # and the benchmark's 5.4 host have coalesced truncate+rewrite to one
    # MODIFY.  The unchanged capability test remains a collection-host gate.
    _open_txn: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    # Per-path running count of MODIFY events since the last CLOSE_WRITE.
    _txn_modify_count: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _txn_counter: int = field(default=0, init=False, repr=False)

    # ---- public API

    def start(self) -> None:
        """Install watches, open output file, spawn reader thread.

        Idempotent — second call is a no-op.
        """
        if self._started:
            return
        self._started = True
        self._collector_started_wall_ns = time.time_ns()
        self._collector_started_monotonic_ns = time.monotonic_ns()
        self._run_anchor = boot_time_anchor()

        root = os.path.abspath(self.watch_root)
        os.makedirs(os.path.dirname(self.output_path) or ".", exist_ok=True)
        # Write-mode per session, matches trace_collector_headless.py.
        self._outfile = open(self.output_path, "w", encoding="utf-8")
        # Remember the resolved realpath of our own output so we can ignore
        # events on it — otherwise every flush would loop back as IN_MODIFY
        # and drown out real signal when output_path lives under watch_root.
        try:
            self._output_realpath = os.path.realpath(self.output_path)
        except OSError:
            self._output_realpath = os.path.abspath(self.output_path)

        # Pre-cache existing files so events carry delta info from turn 1.
        self._seed_cache(root)

        # Stamp session_start BEFORE arming watches so the marker always
        # precedes any event record.
        self._write_record({
            "ts": time.time(),
            "session": self.session_tag,
            "event": "session_start",
            "path": None,
            "size": None,
            "delta": None,
            "hash": None,
            "mode": None,
            "mode_prev": None,
            "cookie": None,
            "boot_time_anchor": self._run_anchor,
            "raw_stream": True,
        })

        self._watch = InotifyWatch()
        watch_paths = (
            [dirpath for dirpath, _dirs, _files in os.walk(root)]
            if self.retain_noise_events
            else recursive_watch_paths(root)
        )
        for d in watch_paths:
            try:
                self._watch.add_watch(d, self.mask)
            except OSError as exc:
                # ENOSPC = watch limit hit. Record and continue.
                self._write_record({
                    "ts": time.time(),
                    "session": self.session_tag,
                    "event": "watch_error",
                    "path": d,
                    "error": f"{exc.errno}:{exc.strerror}",
                })

        self._stop_event.clear()
        t = threading.Thread(target=self._reader_loop, name=f"trace-{self.session_tag}")
        t.daemon = True
        t.start()
        self._thread = t

    def stop(self, *, join_timeout: float = 5.0) -> None:
        """Signal the reader, drain any tail events, flush + close output.

        Safe to call from any thread, and idempotent.

        Tail-drain rationale: the reader thread exits on the next iteration
        after ``_stop_event.set()``. Events that arrived in the inotify
        kernel queue between the reader's last ``read()`` return and the
        stop-event check are left un-drained; closing the watch fd right
        after join would drop them on the floor. That matters because the
        *last* operations in a session are often the interesting ones for
        this paper — e.g., an attack's final write, or the session log's
        closing ``session_end`` record. We do a bounded final drain here
        before closing the fd so the trace doesn't lose its tail.

        The drain is bounded (``max_drain_iters`` + short per-iteration
        timeout) so a pathological event storm can't wedge ``stop()``.
        """
        if not self._started:
            return
        self._stop_event.set()
        t = self._thread
        if t is not None:
            t.join(timeout=join_timeout)
        if self._watch is not None:
            # Final drain — pull any events the kernel queued while we
            # were racing toward stop. Non-blocking short-timeout reads
            # with a hard iteration cap.
            max_drain_iters = 50
            for _ in range(max_drain_iters):
                try:
                    events = self._watch.read(timeout_ms=20)
                except OSError:
                    # fd gone (double-stop races); nothing more to drain.
                    break
                if not events:
                    break
                for evt in events:
                    try:
                        self._handle_event(evt)
                    except Exception:  # noqa: BLE001
                        # Drain must be best-effort — never block stop().
                        continue
            self._watch.close()
            self._watch = None

        self._collector_stopped_wall_ns = time.time_ns()
        self._collector_stopped_monotonic_ns = time.monotonic_ns()
        # session_end marker.
        self._write_record({
            "ts": time.time(),
            "session": self.session_tag,
            "event": "session_end",
            "path": None,
            "size": None,
            "delta": None,
            "hash": None,
            "mode": None,
            "mode_prev": None,
            "cookie": None,
            "event_count": self._event_count,
            "overflow_count": self._overflow_count,
            "drop_count": self._excluded_self_event_count,
            "queue_high_water_mark": self._queue_high_water_mark,
            "collector_started_realtime_ns": self._collector_started_wall_ns,
            "collector_started_monotonic_ns": self._collector_started_monotonic_ns,
            "collector_stopped_realtime_ns": self._collector_stopped_wall_ns,
            "collector_stopped_monotonic_ns": self._collector_stopped_monotonic_ns,
        })
        with self._outfile_lock:
            if self._outfile is not None:
                self._outfile.flush()
                self._outfile.close()
                self._outfile = None
        self._started = False

    @property
    def event_count(self) -> int:
        return self._event_count

    @property
    def overflow_count(self) -> int:
        return self._overflow_count

    @property
    def run_anchor(self) -> dict:
        return dict(self._run_anchor)

    @property
    def health(self) -> dict:
        return {
            "source": "inotify",
            "collector_started_realtime_ns": self._collector_started_wall_ns,
            "collector_started_monotonic_ns": self._collector_started_monotonic_ns,
            "collector_stopped_realtime_ns": self._collector_stopped_wall_ns,
            "collector_stopped_monotonic_ns": self._collector_stopped_monotonic_ns,
            "events_emitted": self._event_count,
            "drop_count": self._excluded_self_event_count,
            "overflow_count": self._overflow_count,
            "queue_high_water_mark": self._queue_high_water_mark,
        }

    # Context-manager convenience for tests.
    def __enter__(self) -> "TraceCollector":
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    # ---- internals

    def _seed_cache(self, root: str) -> None:
        # Match recursive_watch_paths: use the NOISE_DIR_NAMES blacklist so
        # that workspace-local `.openclaw/` state is cached and subsequent
        # events carry proper delta/hash info.
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in NOISE_DIR_NAMES]
            for fname in filenames:
                path = os.path.join(dirpath, fname)
                self._cache[path] = _FileSnapshot(
                    size=_safe_size(path),
                    hash=_safe_hash_prefix(path),
                    mode=_safe_mode(path),
                )

    def _reader_loop(self) -> None:
        """Drain the inotify fd, emit JSONL records, until stop is signaled."""
        assert self._watch is not None
        while not self._stop_event.is_set():
            try:
                events = self._watch.read(timeout_ms=self.read_timeout_ms)
            except OSError as exc:
                # EBADF means the fd was closed under us (shouldn't happen
                # since stop() closes after join, but defensive).
                self._write_record({
                    "ts": time.time(),
                    "session": self.session_tag,
                    "event": "watch_error",
                    "path": None,
                    "error": f"{exc.errno}:{exc.strerror}",
                })
                return
            for evt in events:
                self._handle_event(evt)
            self._queue_high_water_mark = max(self._queue_high_water_mark, len(events))

    def _handle_event(self, evt: InotifyEvent) -> None:
        # Overflow — tell the consumer the kernel dropped events.
        if evt.mask & IN_Q_OVERFLOW:
            self._overflow_count += 1
            self._write_record({
                "ts": time.time(),
                "session": self.session_tag,
                "event": "IN_Q_OVERFLOW",
                "path": None,
                "size": None,
                "delta": None,
                "hash": None,
                "mode": None,
                "mode_prev": None,
                "cookie": None,
            })
            if self.queue_overflow_behavior == "raise":
                raise RuntimeError("inotify queue overflow")
            return

        event_name = primary_event_name(evt.mask)
        path = evt.path

        # Noise filter: drop events on __pycache__ / .git / etc. These are
        # tool-side-effects of W1 code workloads (pyc generation from running
        # tests) and don't reflect agent behavior the paper's detectors care
        # about. Matches any path whose relative segments include a noise dir.
        if path and not self.retain_noise_events and self._is_noise_path(path):
            # For dir-create events on a noise dir, skip BOTH the dynamic
            # watch install AND the record emission.
            return

        # Dynamic subdir watching: if a new directory was created under
        # our root, install a watch on it so we don't miss events inside.
        if (evt.mask & IN_CREATE) and (evt.mask & IN_ISDIR) and path:
            try:
                assert self._watch is not None
                self._watch.add_watch(path, self.mask)
            except OSError:
                pass  # best-effort

        # Self-event filter: ignore events on our own output file. Without
        # this, writing a record → IN_MODIFY on the output → another record
        # → another IN_MODIFY → unbounded feedback loop. Drops both the
        # output file itself and anything that shares its realpath.
        if path is not None and self._output_realpath is not None:
            try:
                if os.path.realpath(path) == self._output_realpath:
                    self._excluded_self_event_count += 1
                    return
            except OSError:
                # realpath can fail if the file vanished mid-event; compare
                # abspath as a weaker fallback.
                if os.path.abspath(path) == self._output_realpath:
                    self._excluded_self_event_count += 1
                    return

        prev = self._cache.get(path) if path else None
        read_only_event = bool(
            evt.mask & (IN_OPEN | IN_ACCESS | IN_CLOSE_NOWRITE)
        ) and not bool(
            evt.mask
            & (
                IN_CREATE
                | IN_MODIFY
                | IN_DELETE
                | IN_CLOSE_WRITE
            )
        )
        if path and os.path.exists(path) and read_only_event:
            # Do not open the file to recompute its hash while handling an
            # IN_OPEN/IN_ACCESS event. Doing so would generate another read
            # event and turn the monitor into its own provenance source. A
            # read-only event cannot change the cached content fingerprint,
            # so retain it and refresh only stat-derived fields.
            curr = _FileSnapshot(
                size=_safe_size(path),
                hash=prev.hash if prev is not None else None,
                mode=_safe_mode(path),
            )
        elif path and os.path.exists(path):
            curr = _FileSnapshot(
                size=_safe_size(path),
                hash=_safe_hash_prefix(path),
                mode=_safe_mode(path),
            )
        else:
            curr = _FileSnapshot()

        # Delta calculation — matches trace_collector_headless.py.
        delta: Optional[int] = None
        if curr.size is not None and prev is not None and prev.size is not None:
            delta = curr.size - prev.size
        elif curr.size is not None:
            delta = curr.size
        elif prev is not None and prev.size is not None:
            delta = -prev.size

        # ----- Transaction tagging (candidate M1/M2 signal) ----
        # A user-level write transaction may expose a separate truncate
        # MODIFY before the write MODIFY, but kernels are allowed to coalesce
        # them.  Record exactly what arrives; never infer a missing event.
        # We allocate a txn_id on the first MODIFY/CREATE for a path,
        # increment ``n_modify`` on each subsequent MODIFY for that path,
        # then close the transaction (and stamp the same txn_id on the
        # CLOSE_WRITE record) when CLOSE_WRITE arrives. Atomic events
        # (ATTRIB / DELETE / MOVED_*) get their own txn_id and
        # ``n_modify=0``.
        txn_id: Optional[int] = None
        n_modify: int = 0
        if path is not None:
            if evt.mask & IN_MODIFY:
                txn_id = self._open_txn.get(path)
                if txn_id is None:
                    self._txn_counter += 1
                    txn_id = self._txn_counter
                    self._open_txn[path] = txn_id
                self._txn_modify_count[path] = self._txn_modify_count.get(path, 0) + 1
                n_modify = self._txn_modify_count[path]
            elif evt.mask & IN_CREATE:
                # CREATE may be followed by MODIFY+CLOSE_WRITE in the same
                # open('w', new file) transaction. Open a txn here so
                # subsequent MODIFYs inherit the id; if no MODIFY follows
                # before CLOSE_WRITE, n_modify stays 0.
                if not (evt.mask & IN_ISDIR):
                    self._txn_counter += 1
                    txn_id = self._txn_counter
                    self._open_txn[path] = txn_id
                    self._txn_modify_count[path] = 0
            elif evt.mask & IN_CLOSE_WRITE:
                txn_id = self._open_txn.pop(path, None)
                n_modify = self._txn_modify_count.pop(path, 0)
                if txn_id is None:
                    # CLOSE_WRITE without preceding MODIFY/CREATE in our
                    # buffer — still allocate so the event is trackable.
                    self._txn_counter += 1
                    txn_id = self._txn_counter
            elif read_only_event:
                # Reads are observations, not file transactions.
                txn_id = None
                n_modify = 0
            else:
                # Atomic events: ATTRIB / DELETE / MOVED_FROM / MOVED_TO.
                self._txn_counter += 1
                txn_id = self._txn_counter
                # If a delete arrives mid-transaction, drop any open
                # transaction state for the path so we don't leak it.
                self._open_txn.pop(path, None)
                self._txn_modify_count.pop(path, None)

        record = {
            "ts": time.time(),
            "session": self.session_tag,
            "event": event_name,
            "path": self._relative_path(path) if path else None,
            "size": curr.size,
            "size_prev": prev.size if prev is not None else None,
            "delta": delta,
            "hash": curr.hash,
            "hash_prev": prev.hash if prev is not None else None,
            "mode": curr.mode,
            "mode_prev": prev.mode if prev is not None else None,
            "cookie": evt.cookie if evt.cookie else None,
            "txn_id": txn_id,
            "n_modify": n_modify,
        }

        if path:
            if evt.mask & IN_DELETE:
                self._cache.pop(path, None)
            else:
                self._cache[path] = curr

        self._write_record(record)
        self._event_count += 1

    def _is_noise_path(self, abspath: str) -> bool:
        """True iff any segment of the path (relative to watch_root) is a
        well-known noise dir (__pycache__, .git, .DS_Store, cache dirs, …).

        The check runs on the abspath's relative form so that a noise dir
        anywhere in the tree — not just at the root — is filtered.
        """
        root = os.path.abspath(self.watch_root)
        try:
            rel = os.path.relpath(abspath, root)
        except ValueError:
            return False
        if rel == "." or rel.startswith(".."):
            return False
        # Split on both sep and altsep to be portable.
        segments = rel.replace(os.sep, "/").split("/")
        return any(seg in NOISE_DIR_NAMES for seg in segments)

    def _relative_path(self, abspath: Optional[str]) -> Optional[str]:
        if abspath is None:
            return None
        root = os.path.abspath(self.watch_root)
        try:
            rel = os.path.relpath(abspath, root)
            if rel.startswith(".."):
                return abspath  # outside root — shouldn't happen but safe
            return rel
        except ValueError:
            return abspath

    def _write_record(self, record: dict) -> None:
        wall_ns = time.time_ns()
        mono_ns = time.monotonic_ns()
        legacy_ts = record.pop("ts", None)
        wrapped = event_envelope(
            source="inotify",
            run_id=self.session_tag,
            event=str(record.pop("event", "unknown")),
            process=None,
            wall_ns=wall_ns,
            monotonic_ns=mono_ns,
            fields=record,
        )
        wrapped["ts"] = float(legacy_ts) if legacy_ts is not None else wall_ns / 1_000_000_000
        wrapped["process_attribution_available"] = False
        with self._outfile_lock:
            if self._outfile is None:
                return
            self._outfile.write(json.dumps(wrapped, ensure_ascii=False) + "\n")
            self._outfile.flush()
