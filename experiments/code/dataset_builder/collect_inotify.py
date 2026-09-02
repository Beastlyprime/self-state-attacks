#!/usr/bin/env python3
"""Run the existing Linux inotify collector as an external monitor process."""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
AGENT_ROOT = PROJECT_ROOT / "experiments" / "agent"
if str(AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(AGENT_ROOT))

from openclaw_core.trace import TraceCollector  # noqa: E402
from openclaw_core.trace.inotify import (  # noqa: E402
    DEFAULT_MASK,
    IN_ACCESS,
    IN_CLOSE_NOWRITE,
    IN_OPEN,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="External inotify monitor")
    parser.add_argument("--watch", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--ready", required=True)
    parser.add_argument("--session", required=True)
    parser.add_argument("--health", required=True)
    parser.add_argument("--include-reads", action="store_true")
    args = parser.parse_args()

    watch_root = Path(args.watch).resolve()
    output_path = Path(args.output).resolve()
    if output_path == watch_root or watch_root in output_path.parents:
        raise RuntimeError(
            "binding raw stream must be outside the watched workspace subtree"
        )

    stopping = False

    def _stop(_signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    mask = DEFAULT_MASK
    if args.include_reads:
        mask |= IN_ACCESS | IN_OPEN | IN_CLOSE_NOWRITE

    collector = TraceCollector(
        watch_root=str(watch_root),
        output_path=str(output_path),
        session_tag=args.session,
        mask=mask,
        read_timeout_ms=100,
        retain_noise_events=True,
    )
    collector.start()
    ready = Path(args.ready)
    ready.parent.mkdir(parents=True, exist_ok=True)
    ready.write_text(
        json.dumps(
            {
                "pid": os.getpid(),
                "ready_wall_ns": time.time_ns(),
                "ready_monotonic_ns": time.monotonic_ns(),
                "boot_time_anchor": collector.run_anchor,
                "mask": mask,
                "include_reads": args.include_reads,
                "raw_stream_unfiltered": True,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    try:
        while not stopping:
            time.sleep(0.05)
    finally:
        collector.stop()
        health = Path(args.health)
        health.parent.mkdir(parents=True, exist_ok=True)
        health.write_text(
            json.dumps(collector.health, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
