#!/usr/bin/env python3
"""
Part A: Real Agent Trace Collector

Monitors file system changes in an agent's state directory using fswatch (macOS)
or inotifywait (Linux). Outputs structured JSONL records for trace analysis.

Usage (macOS):
    python3 trace_collector.py \
        --watch-dirs ~/.claude/projects ~/.claude/settings \
        --output traces_w1.jsonl \
        --session-tag S1_fix_typo

Usage (Linux):
    python3 trace_collector.py \
        --watch-dirs /path/to/agent/workspace \
        --output traces_w4.jsonl \
        --session-tag S1_what_discussed

The collector records:
  - timestamp (ISO 8601)
  - file path (relative to watch root)
  - event type (created, modified, deleted, renamed, attr_changed)
  - file size before/after (bytes)
  - size delta (bytes)
  - SHA-256 hash before/after
  - session tag (for grouping by task)

Session boundaries can be marked interactively:
  - Press Enter to mark "session end" and prompt for next session tag
  - Press Ctrl-C to stop collection
"""

import argparse
import hashlib
import json
import os
import platform
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def sha256_file(path: str) -> Optional[str]:
    """Compute SHA-256 hash of a file, or None if unreadable."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def file_size(path: str) -> Optional[int]:
    """Get file size in bytes, or None if not found."""
    try:
        return os.path.getsize(path)
    except OSError:
        return None


class FileStateCache:
    """Tracks known file sizes and hashes for delta computation."""

    def __init__(self):
        self._cache: dict[str, dict] = {}  # path -> {size, hash}

    def snapshot(self, path: str) -> dict:
        """Take a snapshot of a file's current state."""
        size = file_size(path)
        h = sha256_file(path)
        return {"size": size, "hash": h}

    def get_previous(self, path: str) -> dict:
        """Get the last known state of a file."""
        return self._cache.get(path, {"size": None, "hash": None})

    def update(self, path: str, state: dict):
        """Update cached state for a file."""
        self._cache[path] = state


class TraceCollector:
    """Collects file system traces and writes JSONL output."""

    def __init__(self, watch_dirs: list[str], output_path: str,
                 session_tag: str = "default"):
        self.watch_dirs = [os.path.expanduser(d) for d in watch_dirs]
        self.output_path = output_path
        self.session_tag = session_tag
        self.cache = FileStateCache()
        self.event_count = 0
        self.session_count = 0
        self._running = False
        self._outfile = None

        # Pre-cache initial state of all files
        for d in self.watch_dirs:
            self._cache_directory(d)

    def _cache_directory(self, directory: str):
        """Cache initial state of all files in a directory."""
        if not os.path.isdir(directory):
            return
        for root, dirs, files in os.walk(directory):
            # Skip hidden dirs like .git
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                path = os.path.join(root, fname)
                state = self.cache.snapshot(path)
                self.cache.update(path, state)

    def _normalize_event_type(self, raw_event: str) -> str:
        """Normalize platform-specific event types."""
        raw = raw_event.lower().strip()

        # fswatch (macOS) event flags
        if "created" in raw:
            return "created"
        if "removed" in raw:
            return "deleted"
        if "renamed" in raw:
            return "renamed"
        if "updated" in raw or "modified" in raw:
            return "modified"
        if "attrib" in raw or "ownermodified" in raw or "inodemet" in raw:
            return "attr_changed"

        # inotifywait (Linux) event names
        if "create" in raw:
            return "created"
        if "delete" in raw:
            return "deleted"
        if "moved_from" in raw or "moved_to" in raw:
            return "renamed"
        if "modify" in raw:
            return "modified"
        if "attrib" in raw:
            return "attr_changed"

        return raw

    def _relative_path(self, abspath: str) -> str:
        """Convert absolute path to relative (from first matching watch dir)."""
        for d in self.watch_dirs:
            if abspath.startswith(d):
                return os.path.relpath(abspath, d)
        return abspath

    def _record_event(self, filepath: str, event_type: str):
        """Record a single file system event."""
        now = datetime.now(timezone.utc).isoformat()
        prev = self.cache.get_previous(filepath)
        curr = self.cache.snapshot(filepath)

        size_delta = None
        if curr["size"] is not None and prev["size"] is not None:
            size_delta = curr["size"] - prev["size"]
        elif curr["size"] is not None and prev["size"] is None:
            size_delta = curr["size"]  # new file
        elif curr["size"] is None and prev["size"] is not None:
            size_delta = -prev["size"]  # deleted

        hash_changed = (prev["hash"] != curr["hash"])

        record = {
            "timestamp": now,
            "session_tag": self.session_tag,
            "session_index": self.session_count,
            "file": self._relative_path(filepath),
            "file_abs": filepath,
            "event": event_type,
            "size_before": prev["size"],
            "size_after": curr["size"],
            "size_delta": size_delta,
            "hash_before": prev["hash"][:16] if prev["hash"] else None,
            "hash_after": curr["hash"][:16] if curr["hash"] else None,
            "hash_changed": hash_changed,
        }

        self.cache.update(filepath, curr)

        if self._outfile:
            self._outfile.write(json.dumps(record) + "\n")
            self._outfile.flush()

        self.event_count += 1

        # Print summary
        delta_str = f" ({size_delta:+d}B)" if size_delta is not None else ""
        print(f"  [{self.session_tag}] {event_type:12s} {self._relative_path(filepath)}{delta_str}")

    def _record_session_boundary(self, boundary_type: str):
        """Record a session start/end marker."""
        now = datetime.now(timezone.utc).isoformat()
        record = {
            "timestamp": now,
            "session_tag": self.session_tag,
            "session_index": self.session_count,
            "file": None,
            "event": f"session_{boundary_type}",
            "size_before": None,
            "size_after": None,
            "size_delta": None,
            "hash_before": None,
            "hash_after": None,
            "hash_changed": False,
        }
        if self._outfile:
            self._outfile.write(json.dumps(record) + "\n")
            self._outfile.flush()

    def _start_fswatch(self) -> subprocess.Popen:
        """Start fswatch (macOS) subprocess."""
        cmd = [
            "fswatch",
            "--event-flags",
            "--timestamp",
            "-r",  # recursive
            "--exclude", r"\.git",
            "--exclude", r"__pycache__",
            "--exclude", r"\.DS_Store",
        ] + self.watch_dirs

        return subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def _start_inotifywait(self) -> subprocess.Popen:
        """Start inotifywait (Linux) subprocess."""
        cmd = [
            "inotifywait",
            "-m", "-r",
            "--timefmt", "%Y-%m-%dT%H:%M:%S",
            "--format", "%T|%w%f|%e",
            "--event", "create,modify,delete,moved_from,moved_to,attrib",
            "--exclude", r"(\.git|__pycache__|\.DS_Store)",
        ] + self.watch_dirs

        return subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def _parse_fswatch_line(self, line: str) -> Optional[tuple[str, str]]:
        """Parse a fswatch output line into (filepath, event_type)."""
        # fswatch format with --event-flags --timestamp:
        # Thu Apr  3 10:00:00 2026 /path/to/file Created Modified
        # or just: /path/to/file EventFlags...
        line = line.strip()
        if not line:
            return None

        # Try to extract path and event flags
        # fswatch outputs path followed by event flag names
        parts = line.split()
        if not parts:
            return None

        # Find the path (starts with / or ~)
        filepath = None
        event_parts = []
        for i, part in enumerate(parts):
            if part.startswith("/") or part.startswith(os.path.expanduser("~")):
                filepath = part
                event_parts = parts[i + 1:]
                break

        if filepath is None:
            # Fallback: treat entire line as filepath
            filepath = line
            event_parts = ["Modified"]

        event_type = self._normalize_event_type(" ".join(event_parts))
        return filepath, event_type

    def _parse_inotifywait_line(self, line: str) -> Optional[tuple[str, str]]:
        """Parse an inotifywait output line into (filepath, event_type)."""
        # Format: TIMESTAMP|PATH|EVENTS
        line = line.strip()
        if not line or "|" not in line:
            return None

        parts = line.split("|", 2)
        if len(parts) < 3:
            return None

        _, filepath, events = parts
        event_type = self._normalize_event_type(events)
        return filepath.strip(), event_type

    def start_session(self, tag: str):
        """Mark the start of a new session."""
        self.session_tag = tag
        self._record_session_boundary("start")
        print(f"\n{'='*60}")
        print(f"SESSION {self.session_count}: {tag}")
        print(f"{'='*60}")

    def end_session(self):
        """Mark the end of the current session."""
        self._record_session_boundary("end")
        print(f"  Session '{self.session_tag}' ended ({self.event_count} total events)")
        self.session_count += 1

    def run(self):
        """Main event loop: start file watcher and process events."""
        system = platform.system()

        self._outfile = open(self.output_path, "a", encoding="utf-8")

        if system == "Darwin":
            print(f"Starting fswatch on {self.watch_dirs}...")
            proc = self._start_fswatch()
            parse_fn = self._parse_fswatch_line
        elif system == "Linux":
            print(f"Starting inotifywait on {self.watch_dirs}...")
            proc = self._start_inotifywait()
            parse_fn = self._parse_inotifywait_line
        else:
            print(f"Unsupported platform: {system}", file=sys.stderr)
            sys.exit(1)

        self._running = True
        self.start_session(self.session_tag)

        # Session boundary input thread
        def session_input_loop():
            print("\nPress Enter to end current session (type new tag, or 'q' to quit):")
            while self._running:
                try:
                    user_input = input().strip()
                    if user_input.lower() == "q":
                        self._running = False
                        proc.terminate()
                        break
                    self.end_session()
                    tag = user_input if user_input else f"session_{self.session_count}"
                    self.start_session(tag)
                except EOFError:
                    break

        input_thread = threading.Thread(target=session_input_loop, daemon=True)
        input_thread.start()

        try:
            for line in proc.stdout:
                if not self._running:
                    break
                result = parse_fn(line)
                if result:
                    filepath, event_type = result
                    self._record_event(filepath, event_type)
        except KeyboardInterrupt:
            print("\nStopping trace collection...")
        finally:
            self._running = False
            self.end_session()
            proc.terminate()
            proc.wait()
            if self._outfile:
                self._outfile.close()

        print(f"\nTrace collection complete:")
        print(f"  Sessions: {self.session_count}")
        print(f"  Events:   {self.event_count}")
        print(f"  Output:   {self.output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Collect file system traces from agent state directories"
    )
    parser.add_argument(
        "--watch-dirs", nargs="+", required=True,
        help="Directories to monitor (e.g., ~/.claude/projects)"
    )
    parser.add_argument(
        "--output", "-o", default="traces.jsonl",
        help="Output JSONL file path (default: traces.jsonl)"
    )
    parser.add_argument(
        "--session-tag", "-t", default="session_0",
        help="Initial session tag (default: session_0)"
    )

    args = parser.parse_args()

    # Validate watch dirs exist
    for d in args.watch_dirs:
        expanded = os.path.expanduser(d)
        if not os.path.isdir(expanded):
            print(f"Warning: {expanded} does not exist, will be created if needed",
                  file=sys.stderr)

    collector = TraceCollector(
        watch_dirs=args.watch_dirs,
        output_path=args.output,
        session_tag=args.session_tag,
    )
    collector.run()


if __name__ == "__main__":
    main()
