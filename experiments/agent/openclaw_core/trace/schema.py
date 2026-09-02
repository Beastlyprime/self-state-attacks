"""Binding event envelope for inotify, fanotify, auditd, and eBPF."""

from __future__ import annotations

import base64
import hashlib
import os
import platform
import socket
import time
from pathlib import Path
from typing import Any, Optional


TRACE_EVENT_SCHEMA_VERSION = "assa.trace_event.v1"
RUN_ANCHOR_SCHEMA_VERSION = "assa.run_time_anchor.v1"
EBPF_WRITE_BUFFER_PREFIX_BYTES = 16_384
READ_BUFFER_PREFIX_BYTES = 16_384
REQUIRED_SOURCES = ("inotify", "fanotify", "auditd", "ebpf")


def _read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None


def boot_time_anchor() -> dict[str, Any]:
    wall_ns = time.time_ns()
    monotonic_ns = time.monotonic_ns()
    clock = getattr(time, "CLOCK_BOOTTIME", time.CLOCK_MONOTONIC)
    boottime_ns = time.clock_gettime_ns(clock)
    return {
        "schema_version": RUN_ANCHOR_SCHEMA_VERSION,
        "timestamp_realtime_ns": wall_ns,
        "timestamp_monotonic_ns": monotonic_ns,
        "timestamp_boottime_ns": boottime_ns,
        "estimated_boot_realtime_ns": wall_ns - boottime_ns,
        "boot_id": _read_text(Path("/proc/sys/kernel/random/boot_id")),
        "clocksource": _read_text(
            Path("/sys/devices/system/clocksource/clocksource0/current_clocksource")
        ),
    }


def full_byte_snapshot(raw: bytes) -> dict[str, Any]:
    return {
        "encoding": "base64",
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "data": base64.b64encode(raw).decode("ascii"),
        "complete": True,
    }


def process_identity(pid: Optional[int] = None, *, tid: Optional[int] = None) -> dict[str, Any]:
    resolved_pid = int(pid if pid is not None else os.getpid())
    proc = Path("/proc") / str(resolved_pid)
    stat_raw = _read_text(proc / "stat")
    tail = stat_raw.rsplit(")", 1)[1].strip().split() if stat_raw and ")" in stat_raw else []
    status: dict[str, str] = {}
    for line in (_read_text(proc / "status") or "").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            status[key] = value.strip()
    uid = status.get("Uid", "").split()
    gid = status.get("Gid", "").split()
    try:
        cmdline_raw = (proc / "cmdline").read_bytes()
    except OSError:
        cmdline_raw = b""
    namespaces = {}
    for name in ("cgroup", "ipc", "mnt", "net", "pid", "pid_for_children", "time", "user", "uts"):
        try:
            namespaces[name] = os.readlink(proc / "ns" / name)
        except OSError:
            namespaces[name] = None
    try:
        exe = os.readlink(proc / "exe")
    except OSError:
        exe = None
    return {
        "pid": resolved_pid,
        "tid": int(tid if tid is not None else resolved_pid),
        "process_start_time_ticks": int(tail[19]) if len(tail) > 19 else None,
        "ppid": int(tail[1]) if len(tail) > 1 else None,
        "pgid": int(tail[2]) if len(tail) > 2 else None,
        "sid": int(tail[3]) if len(tail) > 3 else None,
        "exe": exe,
        "comm": _read_text(proc / "comm"),
        "cmdline": [part.decode("utf-8", errors="replace") for part in cmdline_raw.split(b"\0") if part],
        "cgroup_records": (_read_text(proc / "cgroup") or "").splitlines(),
        "uid": int(uid[0]) if uid else None,
        "euid": int(uid[1]) if len(uid) > 1 else None,
        "gid": int(gid[0]) if gid else None,
        "auid": _read_text(proc / "loginuid"),
        "ses": _read_text(proc / "sessionid"),
        "namespace_ids": namespaces,
    }


def event_envelope(
    *, source: str, run_id: str, event: str,
    process: Optional[dict[str, Any]] = None,
    wall_ns: Optional[int] = None, monotonic_ns: Optional[int] = None,
    fields: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    if source not in REQUIRED_SOURCES:
        raise ValueError("unknown binding trace source")
    if process and process.get("pid") is not None and process.get("process_start_time_ticks") is None:
        raise ValueError("pid-bearing event lacks process start time")
    row = {
        "schema_version": TRACE_EVENT_SCHEMA_VERSION,
        "source": source,
        "run_id": run_id,
        "event": event,
        "timestamp_realtime_ns": int(wall_ns if wall_ns is not None else time.time_ns()),
        "timestamp_monotonic_ns": int(monotonic_ns if monotonic_ns is not None else time.monotonic_ns()),
        "process": process,
    }
    row.update(fields or {})
    return row


def ebpf_buffer_capture(prefix: bytes, *, requested_count: int, actual_count: int) -> dict[str, Any]:
    if len(prefix) > EBPF_WRITE_BUFFER_PREFIX_BYTES:
        raise ValueError("eBPF prefix exceeds frozen capacity")
    return {
        "buffer_prefix_capacity_bytes": EBPF_WRITE_BUFFER_PREFIX_BYTES,
        "buffer_prefix_captured_bytes": len(prefix),
        "buffer_prefix_encoding": "base64",
        "buffer_prefix": base64.b64encode(prefix).decode("ascii"),
        "requested_count": int(requested_count),
        "actual_count": int(actual_count),
        "capture_truncated": int(actual_count) > len(prefix),
    }


def ingestion_read_capture(
    *, fd: int, offset: int, count: int, buffer_prefix: bytes
) -> dict[str, Any]:
    """Fields that every carrier-read adapter must emit for provenance joins."""
    if len(buffer_prefix) > READ_BUFFER_PREFIX_BYTES:
        raise ValueError("read prefix exceeds frozen capacity")
    return {
        "fd": int(fd),
        "offset": int(offset),
        "count": int(count),
        "buffer_prefix_capacity_bytes": READ_BUFFER_PREFIX_BYTES,
        "buffer_prefix_captured_bytes": len(buffer_prefix),
        "buffer_prefix_encoding": "base64",
        "buffer_prefix": base64.b64encode(buffer_prefix).decode("ascii"),
        "capture_truncated": int(count) > len(buffer_prefix),
    }


def write_mutation_capture(
    *,
    preimage: bytes,
    postimage: bytes,
    buffer_prefix: bytes,
    requested_count: int,
    actual_count: int,
) -> dict[str, Any]:
    """Bind complete file images to the frozen syscall-level eBPF prefix."""
    return {
        "preimage": full_byte_snapshot(preimage),
        "postimage": full_byte_snapshot(postimage),
        "write_buffer": ebpf_buffer_capture(
            buffer_prefix,
            requested_count=requested_count,
            actual_count=actual_count,
        ),
    }


def validate_raw_trace_bundle(bundle: dict[str, Any]) -> None:
    """Reject a release bundle that discarded a source or lacks health counters."""
    anchor = bundle.get("run_time_anchor")
    if not isinstance(anchor, dict) or not anchor.get("boot_id"):
        raise ValueError("run trace bundle lacks boot-time anchor")
    sources = bundle.get("sources")
    if not isinstance(sources, dict):
        raise ValueError("run trace bundle lacks source records")
    for source in REQUIRED_SOURCES:
        record = sources.get(source)
        if not isinstance(record, dict):
            raise ValueError("run trace bundle lacks %s" % source)
        if record.get("raw_stream_retained") is not True:
            raise ValueError("%s raw stream was not retained" % source)
        if not isinstance(record.get("raw_stream_path"), str):
            raise ValueError("%s raw stream path is absent" % source)
        health = record.get("health")
        if not isinstance(health, dict):
            raise ValueError("%s health is absent" % source)
        for field in (
            "collector_started_realtime_ns",
            "collector_started_monotonic_ns",
            "collector_stopped_realtime_ns",
            "collector_stopped_monotonic_ns",
            "events_emitted",
            "drop_count",
            "overflow_count",
            "queue_high_water_mark",
        ):
            if not isinstance(health.get(field), int):
                raise ValueError("%s health lacks %s" % (source, field))


def run_host_identity() -> dict[str, Any]:
    return {
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "distribution": platform.platform(),
        "out_of_tree_modules": _read_text(Path("/proc/modules")),
    }


def empty_source_health(source: str) -> dict[str, Any]:
    if source not in REQUIRED_SOURCES:
        raise ValueError(source)
    return {
        "source": source,
        "collector_started_realtime_ns": None,
        "collector_started_monotonic_ns": None,
        "collector_stopped_realtime_ns": None,
        "collector_stopped_monotonic_ns": None,
        "events_emitted": 0,
        "drop_count": 0,
        "overflow_count": 0,
        "queue_high_water_mark": 0,
    }
