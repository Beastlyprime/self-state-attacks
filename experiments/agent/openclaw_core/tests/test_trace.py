"""Tests for openclaw_core.trace.

Layered:
- Pure-function tests (mask_to_names, primary_event_name,
  recursive_watch_paths) — no inotify needed, portable.
- Live inotify tests — Linux-only; skipped on other platforms.
  They exercise end-to-end: write / modify / delete on a tempdir and
  assert the TraceCollector emitted matching JSONL records.

Flakiness budget:
- We give the reader thread up to ~1.5s per assertion. inotify latency
  is typically <100ms; 1.5s leaves slack for CI.
- We use tempfile.TemporaryDirectory() which lives on /tmp (ext4 on
  this host). DO NOT put tests on the FUSE-mounted workspace folder —
  see memory `project_experiment_fs_location.md`.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest

from openclaw_core.trace import (
    DEFAULT_MASK,
    TraceCollector,
    is_supported,
    mask_to_names,
    primary_event_name,
    recursive_watch_paths,
)
from openclaw_core.trace.inotify import (
    IN_ACCESS,
    IN_ATTRIB,
    IN_CLOSE_NOWRITE,
    IN_CREATE,
    IN_DELETE,
    IN_ISDIR,
    IN_MODIFY,
    IN_MOVED_FROM,
    IN_MOVED_TO,
    IN_OPEN,
)


LINUX_ONLY = unittest.skipUnless(is_supported(), "inotify is Linux-only")


# ------------------------------------------------------------------ pure


class MaskUtilsTests(unittest.TestCase):
    def test_mask_to_names_includes_isdir_modifier(self) -> None:
        mask = IN_CREATE | IN_ISDIR
        names = mask_to_names(mask)
        self.assertIn("IN_CREATE", names)
        self.assertIn("IN_ISDIR", names)

    def test_primary_event_name_prefers_mutation_over_isdir(self) -> None:
        mask = IN_CREATE | IN_ISDIR
        self.assertEqual(primary_event_name(mask), "IN_CREATE")

    def test_primary_event_name_unknown_mask_hex(self) -> None:
        # All-zero mask produces a hex fallback.
        self.assertEqual(primary_event_name(0), "0x0")


class RecursiveWatchPathsTests(unittest.TestCase):
    def test_returns_all_subdirs_and_skips_dotdirs(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "a", "b"))
            os.makedirs(os.path.join(root, ".git"))
            os.makedirs(os.path.join(root, "__pycache__"))
            os.makedirs(os.path.join(root, "c"))
            paths = recursive_watch_paths(root)
            rel = sorted(os.path.relpath(p, root) for p in paths)
            self.assertIn(".", rel)
            self.assertIn("a", rel)
            self.assertIn("a/b", rel)
            self.assertIn("c", rel)
            self.assertNotIn(".git", rel)
            self.assertNotIn("__pycache__", rel)

    def test_missing_root_returns_empty(self) -> None:
        self.assertEqual(recursive_watch_paths("/nonexistent/path/zzz"), [])


# ------------------------------------------------------------------ helpers


def _read_jsonl(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    out: list[dict] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _wait_for(predicate, *, timeout_s: float = 1.5, interval_s: float = 0.05) -> bool:
    """Poll `predicate` until it returns truthy, up to timeout_s."""
    end = time.time() + timeout_s
    while time.time() < end:
        if predicate():
            return True
        time.sleep(interval_s)
    return False


# ------------------------------------------------------------------ live


@LINUX_ONLY
class TraceCollectorLiveTests(unittest.TestCase):
    def test_read_mask_does_not_feed_back_collector_reads(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            out = os.path.join(root, "trace.jsonl")
            target = os.path.join(root, "source.txt")
            with open(target, "w") as f:
                f.write("source material\n")
            read_mask = DEFAULT_MASK | IN_OPEN | IN_ACCESS | IN_CLOSE_NOWRITE
            with TraceCollector(
                watch_root=root,
                output_path=out,
                session_tag="test-READ",
                mask=read_mask,
            ):
                with open(target, "r", encoding="utf-8") as f:
                    self.assertEqual(f.read(), "source material\n")

                def has_read() -> bool:
                    return any(
                        r.get("path") == "source.txt"
                        and r.get("event") == "IN_ACCESS"
                        for r in _read_jsonl(out)
                    )

                self.assertTrue(_wait_for(has_read))
                time.sleep(0.2)

            reads = [
                r for r in _read_jsonl(out)
                if r.get("path") == "source.txt"
                and r.get("event") in {"IN_OPEN", "IN_ACCESS", "IN_CLOSE_NOWRITE"}
            ]
            # Kernels may coalesce CLOSE_NOWRITE with the preceding access,
            # so one userspace read commonly yields two or three records.
            self.assertGreaterEqual(len(reads), 2)
            self.assertLessEqual(len(reads), 6)
            self.assertTrue(all(r.get("txn_id") is None for r in reads))

    def test_session_start_and_end_markers(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            out = os.path.join(root, "trace.jsonl")
            c = TraceCollector(
                watch_root=root, output_path=out, session_tag="test-A"
            )
            c.start()
            c.stop()
            recs = _read_jsonl(out)
            events = [r["event"] for r in recs]
            self.assertIn("session_start", events)
            self.assertIn("session_end", events)
            self.assertEqual(events[0], "session_start")
            self.assertEqual(events[-1], "session_end")
            for r in recs:
                self.assertEqual(r["session"], "test-A")

    def test_create_and_modify_captured(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            out = os.path.join(root, "trace.jsonl")
            with TraceCollector(
                watch_root=root, output_path=out, session_tag="test-B"
            ):
                target = os.path.join(root, "a.txt")
                with open(target, "w") as f:
                    f.write("v1\n")
                # Brief pause so inotify can deliver CREATE before MODIFY.
                time.sleep(0.1)
                with open(target, "a") as f:
                    f.write("v2\n")

                def has_create_and_modify() -> bool:
                    recs = _read_jsonl(out)
                    evs = [r["event"] for r in recs]
                    return "IN_CREATE" in evs and "IN_MODIFY" in evs

                self.assertTrue(_wait_for(has_create_and_modify))

            recs = _read_jsonl(out)
            create = next((r for r in recs if r["event"] == "IN_CREATE"), None)
            modify = next((r for r in recs if r["event"] == "IN_MODIFY"), None)
            assert create is not None and modify is not None
            self.assertEqual(create["path"], "a.txt")
            self.assertEqual(modify["path"], "a.txt")
            # Size should be populated after MODIFY.
            self.assertIsNotNone(modify["size"])
            # Hash should be a 16-hex prefix.
            self.assertIsNotNone(modify["hash"])
            self.assertEqual(len(modify["hash"]), 16)

    def test_delete_captured_and_cache_cleared(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            out = os.path.join(root, "trace.jsonl")
            target = os.path.join(root, "victim.txt")
            with open(target, "w") as f:
                f.write("to_delete\n")

            with TraceCollector(
                watch_root=root, output_path=out, session_tag="test-D"
            ):
                time.sleep(0.1)
                os.remove(target)

                def has_delete() -> bool:
                    recs = _read_jsonl(out)
                    return any(r["event"] == "IN_DELETE" for r in recs)

                self.assertTrue(_wait_for(has_delete))

            recs = _read_jsonl(out)
            delete = next(r for r in recs if r["event"] == "IN_DELETE")
            self.assertEqual(delete["path"], "victim.txt")
            # delta should be negative-or-zero: file now gone, prev size recorded.
            self.assertLessEqual(delete["delta"], 0)

    def test_moved_from_and_to_share_cookie(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            out = os.path.join(root, "trace.jsonl")
            src = os.path.join(root, "src.txt")
            dst = os.path.join(root, "dst.txt")
            with open(src, "w") as f:
                f.write("renameme\n")

            with TraceCollector(
                watch_root=root, output_path=out, session_tag="test-R"
            ):
                time.sleep(0.1)
                os.rename(src, dst)

                def has_pair() -> bool:
                    recs = _read_jsonl(out)
                    evs = {r["event"] for r in recs}
                    return "IN_MOVED_FROM" in evs and "IN_MOVED_TO" in evs

                self.assertTrue(_wait_for(has_pair))

            recs = _read_jsonl(out)
            mfrom = next(r for r in recs if r["event"] == "IN_MOVED_FROM")
            mto = next(r for r in recs if r["event"] == "IN_MOVED_TO")
            self.assertEqual(mfrom["path"], "src.txt")
            self.assertEqual(mto["path"], "dst.txt")
            # Cookie pairs from/to so downstream can match rename events.
            self.assertEqual(mfrom["cookie"], mto["cookie"])
            self.assertIsNotNone(mfrom["cookie"])

    def test_attrib_captured_on_chmod(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            out = os.path.join(root, "trace.jsonl")
            target = os.path.join(root, "perm.txt")
            with open(target, "w") as f:
                f.write("x\n")
            os.chmod(target, 0o644)

            with TraceCollector(
                watch_root=root, output_path=out, session_tag="test-ATTR"
            ):
                time.sleep(0.1)
                os.chmod(target, 0o600)

                def has_attrib() -> bool:
                    return any(
                        r["event"] == "IN_ATTRIB"
                        for r in _read_jsonl(out)
                    )

                self.assertTrue(_wait_for(has_attrib))

            recs = _read_jsonl(out)
            attrib = next(r for r in recs if r["event"] == "IN_ATTRIB")
            # Mode_prev should be 0o644, mode should be 0o600.
            self.assertEqual(attrib["mode_prev"], 0o644)
            self.assertEqual(attrib["mode"], 0o600)

    def test_dynamic_subdir_watching(self) -> None:
        """New subdirs created during the session are auto-watched,
        so events inside them are captured.
        """
        with tempfile.TemporaryDirectory() as root:
            out = os.path.join(root, "trace.jsonl")
            with TraceCollector(
                watch_root=root, output_path=out, session_tag="test-DYN"
            ):
                subdir = os.path.join(root, "memory")
                os.makedirs(subdir)
                time.sleep(0.2)  # let the collector install the watch
                target = os.path.join(subdir, "today.md")
                with open(target, "w") as f:
                    f.write("entry\n")

                def saw_nested_create() -> bool:
                    for r in _read_jsonl(out):
                        if (
                            r["event"] == "IN_CREATE"
                            and r["path"] == "memory/today.md"
                        ):
                            return True
                    return False

                self.assertTrue(
                    _wait_for(saw_nested_create, timeout_s=2.0)
                )

    def test_noise_dirs_not_emitted_at_runtime(self) -> None:
        """__pycache__ and .git are skipped at initial walk AND at runtime.

        Reproducer for the W1 pilot finding: running ``python -m unittest``
        inside the workspace creates ``__pycache__/*.pyc`` on the fly;
        those events should NOT land in the trace.
        """
        with tempfile.TemporaryDirectory() as root:
            out = os.path.join(root, "trace.jsonl")
            with TraceCollector(
                watch_root=root, output_path=out, session_tag="test-NOISE"
            ):
                # One legit event (real file) + noise events.
                legit = os.path.join(root, "source.py")
                with open(legit, "w") as f:
                    f.write("print('hi')\n")
                os.makedirs(os.path.join(root, "__pycache__"))
                time.sleep(0.2)
                with open(os.path.join(root, "__pycache__", "source.cpython-310.pyc"), "w") as f:
                    f.write("fake-bytecode\n")
                os.makedirs(os.path.join(root, ".git", "objects"))
                time.sleep(0.2)
                with open(os.path.join(root, ".git", "HEAD"), "w") as f:
                    f.write("ref: refs/heads/main\n")

                def saw_legit() -> bool:
                    return any(
                        r.get("event") == "IN_CREATE" and r.get("path") == "source.py"
                        for r in _read_jsonl(out)
                    )

                self.assertTrue(_wait_for(saw_legit, timeout_s=2.0))

            # After stop, no record should mention __pycache__ or .git.
            for r in _read_jsonl(out):
                path = r.get("path") or ""
                self.assertFalse(
                    path.startswith("__pycache__") or path.startswith(".git"),
                    f"noise dir leaked into trace: {r}",
                )

    def test_pre_existing_files_seed_cache_so_deltas_are_correct(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            out = os.path.join(root, "trace.jsonl")
            target = os.path.join(root, "seed.txt")
            with open(target, "w") as f:
                f.write("aaaa\n")  # 5 bytes

            with TraceCollector(
                watch_root=root, output_path=out, session_tag="test-SEED"
            ):
                time.sleep(0.1)
                # Append one byte.
                with open(target, "a") as f:
                    f.write("b")

                def saw_modify() -> bool:
                    return any(
                        r["event"] == "IN_MODIFY" and r["path"] == "seed.txt"
                        for r in _read_jsonl(out)
                    )

                self.assertTrue(_wait_for(saw_modify))

            recs = _read_jsonl(out)
            modify = next(
                r for r in recs if r["event"] == "IN_MODIFY" and r["path"] == "seed.txt"
            )
            # Pre-existing size was 5, new size is 6, delta should be 1.
            self.assertEqual(modify["size"], 6)
            self.assertEqual(modify["delta"], 1)

    def test_workspace_dot_openclaw_is_watched(self) -> None:
        """`.openclaw/workspace-state.json` must remain visible to the
        trace collector. Session transcripts live in the external OpenClaw
        state root and are intentionally outside the workspace watch root.

        Previously the collector skipped any dir beginning with `.` which
        blinded it to workspace-local runtime state.
        """
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, ".openclaw"))
            out = os.path.join(root, "trace.jsonl")
            with TraceCollector(
                watch_root=root, output_path=out, session_tag="test-DOT"
            ):
                time.sleep(0.1)
                # Simulate atomic workspace-state write: CREATE(tmp) +
                # MOVED_FROM(tmp) + MOVED_TO(workspace-state.json).
                state_path = os.path.join(root, ".openclaw", "workspace-state.json")
                tmp_path = state_path + ".tmp-123"
                with open(tmp_path, "w") as f:
                    f.write('{"k":"v"}\n')
                os.rename(tmp_path, state_path)

                def saw_state() -> bool:
                    recs = _read_jsonl(out)
                    paths_events = {(r.get("path"), r.get("event")) for r in recs}
                    has_state_moved_to = (
                        ".openclaw/workspace-state.json",
                        "IN_MOVED_TO",
                    ) in paths_events
                    return has_state_moved_to

                self.assertTrue(
                    _wait_for(saw_state, timeout_s=2.0)
                )

            recs = _read_jsonl(out)
            # The atomic-write signature must be visible in full: tmp CREATE,
            # MOVED_FROM(tmp), MOVED_TO(state).
            move_from = next(
                (
                    r for r in recs
                    if r.get("event") == "IN_MOVED_FROM"
                    and (r.get("path") or "").startswith(
                        ".openclaw/workspace-state.json.tmp"
                    )
                ),
                None,
            )
            move_to = next(
                (
                    r for r in recs
                    if r.get("event") == "IN_MOVED_TO"
                    and r.get("path") == ".openclaw/workspace-state.json"
                ),
                None,
            )
            self.assertIsNotNone(
                move_from, "expected IN_MOVED_FROM on .tmp path"
            )
            self.assertIsNotNone(
                move_to, "expected IN_MOVED_TO on workspace-state.json"
            )
            # Paired by cookie — the hallmark of atomic-rename signature.
            self.assertEqual(move_from["cookie"], move_to["cookie"])

    def test_output_file_events_filtered_when_inside_watch_root(self) -> None:
        """When output_path lives inside watch_root, every flush fires
        IN_MODIFY on the output — without self-filtering that causes an
        unbounded feedback loop. Assert the output file never appears as
        an event path in the JSONL.
        """
        with tempfile.TemporaryDirectory() as root:
            # Note: output inside watch_root — the exact footgun the
            # filter is there to avoid.
            out = os.path.join(root, "trace.jsonl")
            with TraceCollector(
                watch_root=root, output_path=out, session_tag="test-SELF"
            ):
                # Drive some real events to fill up the trace (which
                # writes → which would re-fire IN_MODIFY on `out`).
                for i in range(5):
                    with open(os.path.join(root, f"f{i}.txt"), "w") as f:
                        f.write(f"payload-{i}\n")

                def saw_real_creates() -> bool:
                    recs = _read_jsonl(out)
                    creates = [r for r in recs if r["event"] == "IN_CREATE"]
                    return len(creates) >= 5

                self.assertTrue(_wait_for(saw_real_creates, timeout_s=2.0))

            recs = _read_jsonl(out)
            # The trace output's own basename should NEVER appear as
            # an event path.
            self_hits = [r for r in recs if r.get("path") == "trace.jsonl"]
            self.assertEqual(
                self_hits, [],
                f"trace.jsonl should be filtered, got {len(self_hits)} hits"
            )
            # Sanity: the real file events should be there.
            created_paths = {
                r["path"] for r in recs
                if r["event"] == "IN_CREATE" and r.get("path")
            }
            for i in range(5):
                self.assertIn(f"f{i}.txt", created_paths)

    def test_stop_drains_tail_events(self) -> None:
        """Events that land between the reader's last read() and the
        stop signal must not be dropped. Without the final drain in
        stop(), the reader thread exits on the stop-event check, the
        watch fd is closed, and any kernel-queued events are lost —
        which would blind the paper's detectors to an attack's final
        write.

        Reproducer: create a file, then IMMEDIATELY call stop() so the
        CREATE event races with the stop signal. The drain in stop()
        should pull the event before the watch fd closes.
        """
        # Run the race 5x — intermittent failure mode that a single
        # pass might miss.
        for attempt in range(5):
            with tempfile.TemporaryDirectory() as root:
                out = os.path.join(root, "trace.jsonl")
                c = TraceCollector(
                    watch_root=root,
                    output_path=out,
                    session_tag=f"test-DRAIN-{attempt}",
                )
                c.start()
                # Write immediately before stop() — this is the race.
                target = os.path.join(root, "final.txt")
                with open(target, "w") as f:
                    f.write("last-byte\n")
                # Zero sleep: deliberately race the event vs stop().
                c.stop()

                recs = _read_jsonl(out)
                create_final = [
                    r for r in recs
                    if r.get("event") == "IN_CREATE"
                    and r.get("path") == "final.txt"
                ]
                self.assertEqual(
                    len(create_final), 1,
                    f"attempt {attempt}: CREATE on final.txt was dropped by "
                    f"stop(); recs={recs}"
                )

    def test_start_stop_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            out = os.path.join(root, "trace.jsonl")
            c = TraceCollector(
                watch_root=root, output_path=out, session_tag="test-IDEM"
            )
            c.start()
            c.start()  # no-op
            c.stop()
            c.stop()  # no-op
            # Output file exists and has exactly one session_start + one session_end.
            recs = _read_jsonl(out)
            starts = sum(1 for r in recs if r.get("event") == "session_start")
            ends = sum(1 for r in recs if r.get("event") == "session_end")
            self.assertEqual(starts, 1)
            self.assertEqual(ends, 1)


# ------------------------------------------------------------------ M1/M2 distinction


@LINUX_ONLY
class TruncateRewriteSignalTests(unittest.TestCase):
    """Verify that the txn_id + n_modify tagging surfaces the OS-visible
    distinction between paper M1 (truncate-rewrite) and M2 (append).

    A user-level ``open(path, 'a')`` emits one MODIFY before CLOSE_WRITE
    (n_modify == 1). A user-level ``open(path, 'w')`` emits two MODIFY
    (truncate, then write) before CLOSE_WRITE (n_modify >= 2). The kernel
    can coalesce identical events, so we sometimes see fewer than 2 in
    a single open('w'), but a population of repeated ops should still
    show some n_modify >= 2 cases on truncate-rewrites and exactly 1 on
    appends.
    """

    def test_close_write_emitted_in_default_mask(self) -> None:
        """CLOSE_WRITE must be in DEFAULT_MASK so transactions can close."""
        from openclaw_core.trace.inotify import IN_CLOSE_WRITE
        self.assertTrue(
            DEFAULT_MASK & IN_CLOSE_WRITE,
            "DEFAULT_MASK must include IN_CLOSE_WRITE for transaction tagging",
        )

    def test_records_carry_txn_id_and_n_modify(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            out = os.path.join(root, "trace.jsonl")
            c = TraceCollector(
                watch_root=root,
                output_path=out,
                session_tag="test-TXN",
            )
            c.start()
            try:
                target = os.path.join(root, "memo.md")
                # One append transaction.
                with open(target, "a") as f:
                    f.write("hello\n")

                self.assertTrue(
                    _wait_for(lambda: any(
                        r.get("event") == "IN_CLOSE_WRITE"
                        and r.get("path") == "memo.md"
                        for r in _read_jsonl(out)
                    )),
                    f"CLOSE_WRITE on memo.md never arrived; recs={_read_jsonl(out)}",
                )
            finally:
                c.stop()

            recs = _read_jsonl(out)
            memo_recs = [
                r for r in recs
                if r.get("path") == "memo.md"
                and r.get("event", "").startswith("IN_")
            ]
            # Every IN_* record on memo.md should carry txn_id + n_modify.
            for r in memo_recs:
                self.assertIn("txn_id", r, f"missing txn_id: {r}")
                self.assertIn("n_modify", r, f"missing n_modify: {r}")

            # All MODIFY/CREATE/CLOSE_WRITE events on the same path within
            # a single user-level write transaction must share txn_id.
            txn_ids = {
                r.get("txn_id") for r in memo_recs
                if r.get("event") in ("IN_CREATE", "IN_MODIFY", "IN_CLOSE_WRITE")
            }
            self.assertEqual(
                len(txn_ids), 1,
                f"Expected one txn_id across the write transaction, got {txn_ids}; recs={memo_recs}",
            )

    def test_truncate_rewrite_distinguishable_from_append(self) -> None:
        """``open('w')`` produces n_modify >= 2 on at least some
        invocations; ``open('a')`` always produces n_modify == 1.

        We run several of each so kernel event coalescing can't make the
        truncate-rewrite case look uniformly like append. The structural
        invariant we test:

          * every append-CLOSE_WRITE has n_modify == 1 (or 0 if the
            kernel coalesced everything into the CLOSE_WRITE itself —
            shouldn't happen, but we don't want a flake).
          * the maximum n_modify across all truncate-rewrite
            CLOSE_WRITE records is >= 2.
        """
        with tempfile.TemporaryDirectory() as root:
            out = os.path.join(root, "trace.jsonl")
            c = TraceCollector(
                watch_root=root, output_path=out, session_tag="test-M1M2"
            )
            c.start()
            try:
                target = os.path.join(root, "memo.md")
                # Seed the file so subsequent open('w')s are real
                # truncates rather than create+write.
                with open(target, "w") as f:
                    f.write("seed\n" * 20)
                time.sleep(0.1)

                # 6 append transactions
                for i in range(6):
                    with open(target, "a") as f:
                        f.write(f"appended-{i}\n")
                    time.sleep(0.05)

                # 6 truncate-rewrite transactions
                for i in range(6):
                    with open(target, "w") as f:
                        f.write(f"rewritten-{i}\n" * 5)
                    time.sleep(0.05)

                # Wait for trailing CLOSE_WRITE to land.
                self.assertTrue(
                    _wait_for(lambda: sum(
                        1 for r in _read_jsonl(out)
                        if r.get("event") == "IN_CLOSE_WRITE"
                        and r.get("path") == "memo.md"
                    ) >= 12, timeout_s=2.0),
                    f"didn't see >=12 CLOSE_WRITE records",
                )
            finally:
                c.stop()

            recs = _read_jsonl(out)
            close_writes = [
                r for r in recs
                if r.get("event") == "IN_CLOSE_WRITE"
                and r.get("path") == "memo.md"
            ]
            self.assertGreaterEqual(len(close_writes), 12)

            # First 6 CLOSE_WRITE in time order are appends, next 6 are
            # truncate-rewrites. (The seeding write produced one extra
            # CLOSE_WRITE before our 12 — drop it by sorting on ts and
            # taking the LAST 12.)
            close_writes.sort(key=lambda r: r.get("ts", 0))
            tail = close_writes[-12:]
            append_close_ns = [r.get("n_modify") for r in tail[:6]]
            truncate_close_ns = [r.get("n_modify") for r in tail[6:]]

            self.assertTrue(
                all(n == 1 for n in append_close_ns),
                f"Append transactions should have n_modify == 1, got {append_close_ns}",
            )
            self.assertGreaterEqual(
                max(truncate_close_ns), 2,
                f"At least one truncate-rewrite should have n_modify >= 2, "
                f"got {truncate_close_ns} (kernel may have aggressively coalesced)",
            )

    def test_atomic_events_get_unique_txn_ids(self) -> None:
        """ATTRIB / DELETE / MOVED_* are atomic — each gets its own
        txn_id and n_modify == 0.
        """
        with tempfile.TemporaryDirectory() as root:
            out = os.path.join(root, "trace.jsonl")
            c = TraceCollector(
                watch_root=root, output_path=out, session_tag="test-ATOMIC"
            )
            c.start()
            try:
                f1 = os.path.join(root, "a.md")
                f2 = os.path.join(root, "b.md")
                for p in (f1, f2):
                    with open(p, "w") as f:
                        f.write("seed\n")
                time.sleep(0.1)
                os.chmod(f1, 0o400)
                os.chmod(f2, 0o400)
                time.sleep(0.1)
                os.unlink(f1)
                os.unlink(f2)
                time.sleep(0.2)
            finally:
                c.stop()

            recs = _read_jsonl(out)
            atomic = [
                r for r in recs
                if r.get("event") in ("IN_ATTRIB", "IN_DELETE")
            ]
            self.assertGreaterEqual(len(atomic), 4)
            for r in atomic:
                self.assertEqual(
                    r.get("n_modify"), 0,
                    f"atomic event must carry n_modify == 0, got {r}",
                )
            txn_ids = [r.get("txn_id") for r in atomic]
            # Each atomic event gets its own txn_id.
            self.assertEqual(
                len(txn_ids), len(set(txn_ids)),
                f"atomic events must have unique txn_ids; got {txn_ids}",
            )


if __name__ == "__main__":
    unittest.main()
