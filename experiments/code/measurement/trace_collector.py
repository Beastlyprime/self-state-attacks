#!/usr/bin/env python3
"""
Part A – Trace Collector for SELFSTATE v4

Monitors an agent workspace directory using inotify and emits one JSONL
record per file-system event. Two modes:

  1. **live** – attach to a real agent workspace and record until stopped.
     Intended for W1 (Claude Code) traces collected over many sessions.

  2. **mock** – run an OpenClaw scaffold mock session (setup_agent →
     simulated ops → teardown) and record all FS events.  Intended for
     W4 trace generation that can be fully automated.

Output: one JSONL file per session, written to `traces/<profile>/<session_id>.jsonl`.

Each line:
    {
      "ts":        float,          # unix timestamp (monotonic-ish)
      "session":   str,            # session identifier
      "profile":   str,            # "W1" or "W4"
      "event":     str,            # IN_CREATE | IN_MODIFY | IN_DELETE | IN_MOVED_TO | …
      "path":      str,            # relative path inside workspace
      "size":      int | null,     # file size *after* event (null if deleted)
      "delta":     int | null,     # size change vs. previous snapshot (null if new/deleted)
      "hash":      str | null      # sha256 of file content after event
    }
"""

import os
import sys
import json
import time
import hashlib
import argparse
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict

import pyinotify

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [trace_collector] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

# ── helpers ──────────────────────────────────────────────────────────

def sha256_file(path: Path) -> Optional[str]:
    """Return hex sha256 of a file, or None if unreadable."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def file_size(path: Path) -> Optional[int]:
    try:
        return path.stat().st_size
    except (OSError, FileNotFoundError):
        return None


# ── inotify handler ──────────────────────────────────────────────────

class TraceHandler(pyinotify.ProcessEvent):
    """Writes one JSONL record per inotify event."""

    def __init__(self, out_file, root: Path, session_id: str, profile: str,
                 size_snap: Dict[str, int]):
        super().__init__()
        self.out = out_file
        self.root = root
        self.session_id = session_id
        self.profile = profile
        self.snap = size_snap          # path → last-known size
        self.event_count = 0

    def _rel(self, abspath: str) -> str:
        try:
            return str(Path(abspath).relative_to(self.root))
        except ValueError:
            return abspath

    def _record(self, event, event_name: str):
        abspath = Path(event.pathname)
        rel = self._rel(event.pathname)

        # skip __pycache__ and hidden dotfiles we don't care about
        if "__pycache__" in rel or rel.startswith(".git"):
            return

        sz = file_size(abspath)
        prev = self.snap.get(rel)
        delta = (sz - prev) if (sz is not None and prev is not None) else None
        if sz is not None:
            self.snap[rel] = sz
        elif rel in self.snap:
            del self.snap[rel]

        record = {
            "ts": time.time(),
            "session": self.session_id,
            "profile": self.profile,
            "event": event_name,
            "path": rel,
            "size": sz,
            "delta": delta,
            "hash": sha256_file(abspath) if sz is not None else None,
        }
        self.out.write(json.dumps(record) + "\n")
        self.out.flush()
        self.event_count += 1

    # pyinotify dispatch methods
    def process_IN_CREATE(self, event):
        self._record(event, "IN_CREATE")

    def process_IN_MODIFY(self, event):
        self._record(event, "IN_MODIFY")

    def process_IN_DELETE(self, event):
        self._record(event, "IN_DELETE")

    def process_IN_MOVED_TO(self, event):
        self._record(event, "IN_MOVED_TO")

    def process_IN_MOVED_FROM(self, event):
        self._record(event, "IN_MOVED_FROM")

    def process_IN_ATTRIB(self, event):
        self._record(event, "IN_ATTRIB")


# ── snapshot helper ──────────────────────────────────────────────────

def snapshot_sizes(root: Path) -> Dict[str, int]:
    """Build initial size map for all files under root."""
    snap = {}
    for p in root.rglob("*"):
        if p.is_file() and "__pycache__" not in str(p):
            try:
                snap[str(p.relative_to(root))] = p.stat().st_size
            except OSError:
                pass
    return snap


# ── collector core ───────────────────────────────────────────────────

def collect_trace(
    watch_dir: Path,
    out_path: Path,
    session_id: str,
    profile: str,
    timeout_sec: float = 0,
) -> int:
    """
    Monitor *watch_dir* and write JSONL to *out_path*.

    If timeout_sec > 0, stop after that many seconds.
    If timeout_sec == 0, run until KeyboardInterrupt.

    Returns the number of events recorded.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    snap = snapshot_sizes(watch_dir)

    wm = pyinotify.WatchManager()
    mask = (
        pyinotify.IN_CREATE
        | pyinotify.IN_MODIFY
        | pyinotify.IN_DELETE
        | pyinotify.IN_MOVED_TO
        | pyinotify.IN_MOVED_FROM
        | pyinotify.IN_ATTRIB
    )

    with open(out_path, "w") as fout:
        handler = TraceHandler(fout, watch_dir, session_id, profile, snap)
        notifier = pyinotify.Notifier(wm, handler, timeout=1000)  # 1 s poll
        wm.add_watch(str(watch_dir), mask, rec=True, auto_add=True)

        log.info("Watching %s → %s (profile=%s, session=%s)",
                 watch_dir, out_path, profile, session_id)

        start = time.time()
        try:
            while True:
                if notifier.check_events(timeout=1000):
                    notifier.read_events()
                    notifier.process_events()
                if timeout_sec > 0 and (time.time() - start) >= timeout_sec:
                    break
        except KeyboardInterrupt:
            log.info("Interrupted.")
        finally:
            notifier.stop()

    log.info("Recorded %d events → %s", handler.event_count, out_path)
    return handler.event_count


# ── mock session driver (for W4) ─────────────────────────────────────

def run_mock_session(
    agent_dir: Path,
    session_id: str,
    profile: str,
    out_dir: Path,
    complexity: str = "medium",
    seed: int = 42,
) -> Path:
    """
    1. Setup a fresh OpenClaw agent workspace.
    2. Start inotify monitoring.
    3. Simulate a session of realistic file operations.
    4. Stop monitoring and return the trace path.
    """
    import threading
    import random

    # Add project root to path for imports
    project_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(project_root))
    from agent_openclaw.setup_agent import setup_agent

    workspace = agent_dir / "workspace"
    out_path = out_dir / profile / f"{session_id}.jsonl"

    # Step 1: fresh agent
    setup_agent(str(agent_dir), n_seed_days=3)
    time.sleep(0.3)  # let FS settle

    # Step 2: start monitoring in background
    events_recorded = [0]

    def _monitor():
        events_recorded[0] = collect_trace(
            watch_dir=agent_dir,
            out_path=out_path,
            session_id=session_id,
            profile=profile,
            timeout_sec=10,
        )

    mon_thread = threading.Thread(target=_monitor, daemon=True)
    mon_thread.start()
    time.sleep(0.2)  # let watcher attach

    # Step 3: simulate operations
    rng = random.Random(seed)
    _simulate_session(agent_dir, workspace, rng, complexity)

    # Step 4: wait for monitor to finish (timeout-based)
    time.sleep(0.5)
    mon_thread.join(timeout=15)

    log.info("Mock session %s complete: %d events", session_id, events_recorded[0])
    return out_path


def _simulate_session(agent_dir: Path, workspace: Path, rng, complexity: str):
    """
    Simulate realistic agent file operations for one session.

    Complexity controls volume:
      simple:  10-20 ops, 0-1 memory writes
      medium:  30-50 ops, 1-3 memory writes
      complex: 50-80 ops, 3-6 memory writes
    """
    from datetime import datetime, timezone

    params = {
        "simple":  {"n_ops": (10, 20), "mem_writes": (0, 1), "log_appends": (1, 3)},
        "medium":  {"n_ops": (30, 50), "mem_writes": (1, 3), "log_appends": (3, 6)},
        "complex": {"n_ops": (50, 80), "mem_writes": (3, 6), "log_appends": (5, 10)},
    }
    p = params[complexity]

    memory_md = workspace / "MEMORY.md"
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    daily_log = workspace / "memory" / f"{today}.md"
    heartbeat = workspace / "HEARTBEAT.md"
    identity_files = [workspace / f for f in ["SOUL.md", "AGENTS.md", "IDENTITY.md", "USER.md"]]
    config_file = agent_dir / "openclaw.json"

    n_mem = rng.randint(*p["mem_writes"])
    n_log = rng.randint(*p["log_appends"])
    n_hb = rng.randint(1, 2)  # 1-2 heartbeat updates per session

    # Interleave operations with realistic timing
    ops = []
    ops += [("memory_read", None)] * rng.randint(5, 15)
    ops += [("identity_read", None)] * rng.randint(3, 8)
    ops += [("config_read", None)] * rng.randint(2, 5)
    ops += [("memory_write", memory_md)] * n_mem
    ops += [("log_append", daily_log)] * n_log
    ops += [("heartbeat", heartbeat)] * n_hb

    rng.shuffle(ops)

    for op_type, target in ops:
        delay = rng.uniform(0.02, 0.15)  # inter-op delay (compressed for simulation)
        time.sleep(delay)

        if op_type == "memory_read":
            # Just read, no FS event expected (inotify doesn't track reads)
            if memory_md.exists():
                _ = memory_md.read_text()
        elif op_type == "identity_read":
            f = rng.choice(identity_files)
            if f.exists():
                _ = f.read_text()
        elif op_type == "config_read":
            if config_file.exists():
                _ = config_file.read_text()
        elif op_type == "memory_write":
            _append_memory(memory_md, rng)
        elif op_type == "log_append":
            _append_log(daily_log, rng)
        elif op_type == "heartbeat":
            _update_heartbeat(heartbeat, rng)


def _append_memory(path: Path, rng):
    """Append a realistic memory entry."""
    facts = [
        "User prefers tabs over spaces for Python indentation",
        "The auth module requires connection pooling for optimal throughput",
        "CI pipeline runs in approximately 3 minutes on current hardware",
        "Detection ROC is bimodal for blunt vs subtle attacks",
        "When running experiments, always set random seed for reproducibility",
        "The measurement module uses JSONL format for intermediate results",
        "FastAPI async handlers outperform Flask for concurrent I/O",
        "PostgreSQL connection pooling improves throughput by 40%",
        "Experiment 2b anomaly detection uses z-score thresholds",
        "Paper §6 limitations section needs ecological validity discussion",
    ]
    entry = f"\n- {rng.choice(facts)} (noted {datetime.now(timezone.utc).strftime('%H:%M')})\n"
    with open(path, "a") as f:
        f.write(entry)


def _append_log(path: Path, rng):
    """Append a realistic daily log entry."""
    now = datetime.now(timezone.utc)
    actions = [
        "Reviewed code in measurement module",
        "Ran pytest suite — all tests passed",
        "Updated docstrings for detection_roc module",
        "Analyzed experiment results for Exp 2b",
        "Checked disk usage and system health",
        "Processed user query about API design",
        "Compiled research notes for paper revision",
        "Debugged issue in workload generator",
    ]
    entry = f"\n## {now.strftime('%H:%M')} — {rng.choice(actions)}\n{rng.choice(actions)}.\n"
    with open(path, "a") as f:
        f.write(entry)


def _update_heartbeat(path: Path, rng):
    """Overwrite heartbeat file with current status."""
    now = datetime.now(timezone.utc)
    content = f"""# Heartbeat
Last check: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}
Status: operational
Pending tasks: {rng.randint(0, 3)}
Disk usage: {rng.randint(35, 55)}%
Memory entries: {rng.randint(15, 30)}
"""
    path.write_text(content)


# ── CLI ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SELFSTATE Trace Collector")
    sub = parser.add_subparsers(dest="mode", required=True)

    # live mode
    p_live = sub.add_parser("live", help="Monitor a live agent workspace")
    p_live.add_argument("watch_dir", type=Path, help="Agent workspace root")
    p_live.add_argument("--profile", default="W1", help="Profile label (default: W1)")
    p_live.add_argument("--session", default=None, help="Session ID (auto-generated if omitted)")
    p_live.add_argument("--out-dir", type=Path, default=Path("traces"), help="Output directory")
    p_live.add_argument("--timeout", type=float, default=0, help="Stop after N seconds (0=manual)")

    # mock mode
    p_mock = sub.add_parser("mock", help="Run mock sessions and collect traces")
    p_mock.add_argument("--agent-dir", type=Path, default=None, help="Agent workspace (temp if omitted)")
    p_mock.add_argument("--profile", default="W4", help="Profile label (default: W4)")
    p_mock.add_argument("--n-sessions", type=int, default=30, help="Number of sessions")
    p_mock.add_argument("--out-dir", type=Path, default=Path("traces"), help="Output directory")
    p_mock.add_argument("--complexity-mix", default="10,10,10",
                        help="simple,medium,complex counts (default: 10,10,10)")

    args = parser.parse_args()

    if args.mode == "live":
        session_id = args.session or datetime.now(timezone.utc).strftime("live_%Y%m%d_%H%M%S")
        out_path = args.out_dir / args.profile / f"{session_id}.jsonl"
        collect_trace(args.watch_dir, out_path, session_id, args.profile, args.timeout)

    elif args.mode == "mock":
        counts = [int(x) for x in args.complexity_mix.split(",")]
        assert len(counts) == 3, "complexity-mix must be 3 comma-separated ints"
        complexities = (
            ["simple"] * counts[0]
            + ["medium"] * counts[1]
            + ["complex"] * counts[2]
        )

        agent_dir = args.agent_dir or Path("/tmp/openclaw_mock_agent")

        for i, complexity in enumerate(complexities):
            session_id = f"mock_{args.profile}_{complexity}_{i:03d}"
            log.info("=== Session %d/%d: %s (%s) ===", i + 1, len(complexities), session_id, complexity)
            run_mock_session(
                agent_dir=agent_dir,
                session_id=session_id,
                profile=args.profile,
                out_dir=args.out_dir,
                complexity=complexity,
                seed=i * 137 + 42,
            )


if __name__ == "__main__":
    main()
