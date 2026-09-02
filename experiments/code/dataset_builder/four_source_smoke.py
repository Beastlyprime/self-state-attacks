#!/usr/bin/env python3
"""Privileged, no-LLM S1 smoke for the binding four-source trace contract.

The supervisor creates one disposable workspace and one cgroup/network
namespace, starts all collectors, verifies their live controls, and only then
releases a small worker that performs two reads and one O_TRUNC + write.  It
never imports or invokes an agent/model runtime.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import multiprocessing
import os
import platform
import pwd
import re
import select
import signal
import struct
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[3]
AGENT_ROOT = PROJECT_ROOT / "experiments" / "agent"
CODE_ROOT = PROJECT_ROOT / "experiments" / "code"
for _path in (AGENT_ROOT, CODE_ROOT):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from dataset_builder.finalize_trace_bundle import finalize  # noqa: E402
from dataset_builder.injection_routes import ingestion_join_key  # noqa: E402
from dataset_builder.run_safety import credential_variable_names  # noqa: E402
from openclaw_core.trace.schema import (  # noqa: E402
    EBPF_WRITE_BUFFER_PREFIX_BYTES,
    boot_time_anchor,
    event_envelope,
    full_byte_snapshot,
    ingestion_read_capture,
    process_identity,
    run_host_identity,
    validate_raw_trace_bundle,
    write_mutation_capture,
)


SMOKE_SCHEMA_VERSION = "assa.s1_smoke.v1"
SAFETY_SCHEMA_VERSION = "assa.s1_smoke_safety.v1"
PREFIX_BYTES = 16_384
FANOTIFY_RESPONSE_TIMEOUT_MS = 1000
INITIAL_BYTES = b"assa four-source smoke: pre-image\n"
WRITTEN_BYTES = b"assa four-source smoke: post-image\n"
CARRIER_BYTES = b"carrier-positive-6fc74742\n"
NEGATIVE_BYTES = b"carrier-negative-no-write-2d94412a\n"

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
IN_Q_OVERFLOW = 0x00004000
IN_MASK = (
    IN_ACCESS
    | IN_MODIFY
    | IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_CLOSE_NOWRITE
    | IN_OPEN
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE
)

FAN_ACCESS = 0x00000001
FAN_MODIFY = 0x00000002
FAN_CLOSE_WRITE = 0x00000008
FAN_OPEN = 0x00000020
FAN_OPEN_PERM = 0x00010000
FAN_ACCESS_PERM = 0x00020000
FAN_Q_OVERFLOW = 0x00004000
FAN_EVENT_ON_CHILD = 0x08000000
FAN_MARK_ADD = 0x00000001
FAN_CLASS_CONTENT = 0x00000004
FAN_CLOEXEC = 0x00000001
FAN_NONBLOCK = 0x00000002
FAN_ALLOW = 0x01
FAN_NOFD = -1
AT_FDCWD = -100
FAN_MASK = (
    FAN_ACCESS
    | FAN_MODIFY
    | FAN_CLOSE_WRITE
    | FAN_OPEN
    | FAN_OPEN_PERM
    | FAN_ACCESS_PERM
    | FAN_EVENT_ON_CHILD
)


def _json_write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _jsonl_write(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _command(args: list[str], *, input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
    )


def _wait_file(path: Path, processes: Iterable[Any], timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file() and path.stat().st_size:
            return
        for process in processes:
            alive = process.poll() is None if isinstance(process, subprocess.Popen) else process.is_alive()
            if not alive:
                raise RuntimeError("collector exited before ready: %s" % process)
        time.sleep(0.03)
    raise TimeoutError("collector ready file timed out: %s" % path)


def _health(source: str, started_wall: int, started_mono: int, events: int, drops: int, overflows: int, high_water: int) -> dict[str, Any]:
    return {
        "source": source,
        "collector_started_realtime_ns": started_wall,
        "collector_started_monotonic_ns": started_mono,
        "collector_stopped_realtime_ns": time.time_ns(),
        "collector_stopped_monotonic_ns": time.monotonic_ns(),
        "events_emitted": events,
        "drop_count": drops,
        "overflow_count": overflows,
        "queue_high_water_mark": high_water,
    }


def _inotify_collector(workspace: str, raw_path: str, health_path: str, ready_path: str, stop_path: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    if fd < 0:
        raise OSError(ctypes.get_errno(), "inotify_init1")
    watch_roots: dict[int, str] = {}
    for directory in [Path(workspace), *sorted(Path(workspace).rglob("*"))]:
        if not directory.is_dir():
            continue
        wd = libc.inotify_add_watch(
            fd, os.fsencode(directory), ctypes.c_uint32(IN_MASK)
        )
        if wd < 0:
            raise OSError(ctypes.get_errno(), "inotify_add_watch")
        watch_roots[int(wd)] = str(directory)
    started_wall, started_mono = time.time_ns(), time.monotonic_ns()
    events = overflows = high_water = 0
    raw = Path(raw_path)
    Path(ready_path).write_text(json.dumps({"pid": os.getpid(), "watch_descriptors": watch_roots, "mark_root": workspace, "mark_scope": "workspace_subtree"}), encoding="utf-8")
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    try:
        with raw.open("w", encoding="utf-8") as output:
            quiet_since = None
            while True:
                stop = Path(stop_path).exists()
                available = poller.poll(50)
                batch = 0
                if available:
                    try:
                        data = os.read(fd, 256 * 1024)
                    except BlockingIOError:
                        data = b""
                    offset = 0
                    while offset + 16 <= len(data):
                        event_wd, mask, cookie, name_len = struct.unpack_from("iIII", data, offset)
                        offset += 16
                        name_raw = data[offset : offset + name_len]
                        offset += name_len
                        name = name_raw.split(b"\0", 1)[0].decode("utf-8", errors="replace")
                        wall, mono = time.time_ns(), time.monotonic_ns()
                        row = {
                            "record_type": "inotify_event",
                            "source": "inotify",
                            "timestamp_realtime_ns": wall,
                            "timestamp_monotonic_ns": mono,
                            "watch_descriptor": event_wd,
                            "mask": mask,
                            "cookie": cookie,
                            "name": name,
                            "path": str(Path(watch_roots.get(event_wd, workspace)) / name) if name else watch_roots.get(event_wd, workspace),
                        }
                        output.write(json.dumps(row, sort_keys=True) + "\n")
                        output.flush()
                        batch += 1
                        events += 1
                        if mask & IN_Q_OVERFLOW:
                            overflows += 1
                high_water = max(high_water, batch)
                if stop:
                    quiet_since = quiet_since or time.monotonic()
                    if not available and time.monotonic() - quiet_since > 0.25:
                        break
                else:
                    quiet_since = None
    finally:
        os.close(fd)
        _json_write(Path(health_path), _health("inotify", started_wall, started_mono, events, overflows, overflows, high_water))


class _FanotifyMetadata(ctypes.Structure):
    _fields_ = [
        ("event_len", ctypes.c_uint32),
        ("vers", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8),
        ("metadata_len", ctypes.c_uint16),
        ("mask", ctypes.c_uint64),
        ("fd", ctypes.c_int32),
        ("pid", ctypes.c_int32),
    ]


def _fd_snapshot(fd: int) -> dict[str, Any] | None:
    try:
        size = os.fstat(fd).st_size
        raw = bytearray()
        offset = 0
        while offset < size:
            block = os.pread(fd, min(1024 * 1024, size - offset), offset)
            if not block:
                break
            raw.extend(block)
            offset += len(block)
        return full_byte_snapshot(bytes(raw))
    except OSError:
        return None


def _write_heartbeat(path: str) -> None:
    heartbeat = Path(path)
    tmp = heartbeat.with_name("%s.%d.tmp" % (heartbeat.name, os.getpid()))
    tmp.write_text(str(time.monotonic_ns()), encoding="ascii")
    os.replace(tmp, heartbeat)


def _fanotify_collector(workspace: str, raw_path: str, health_path: str, ready_path: str, heartbeat_path: str, stop_path: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    fan_fd = libc.fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK, os.O_RDONLY | os.O_LARGEFILE)
    if fan_fd < 0:
        raise OSError(ctypes.get_errno(), "fanotify_init")
    marked_paths = []
    for directory in [Path(workspace), *sorted(Path(workspace).rglob("*"))]:
        if not directory.is_dir():
            continue
        result = libc.fanotify_mark(
            fan_fd,
            FAN_MARK_ADD,
            ctypes.c_uint64(FAN_MASK),
            AT_FDCWD,
            os.fsencode(directory),
        )
        if result < 0:
            raise OSError(ctypes.get_errno(), "fanotify_mark")
        marked_paths.append(str(directory))
    started_wall, started_mono = time.time_ns(), time.monotonic_ns()
    events = overflows = high_water = 0
    _write_heartbeat(heartbeat_path)
    _json_write(
        Path(ready_path),
        {
            "pid": os.getpid(),
            "fanotify_fd": fan_fd,
            "metadata_version": 3,
            "mark_root": workspace,
            "mark_scope": "workspace_subtree",
            "marked_paths": marked_paths,
            "event_on_child": True,
            "response_timeout_ms": FANOTIFY_RESPONSE_TIMEOUT_MS,
            "mask": FAN_MASK,
        },
    )
    poller = select.poll()
    poller.register(fan_fd, select.POLLIN)
    try:
        with Path(raw_path).open("w", encoding="utf-8") as output:
            quiet_since = None
            while True:
                _write_heartbeat(heartbeat_path)
                stop = Path(stop_path).exists()
                available = poller.poll(50)
                batch = 0
                if available:
                    try:
                        data = os.read(fan_fd, 256 * 1024)
                    except BlockingIOError:
                        data = b""
                    offset = 0
                    while offset + ctypes.sizeof(_FanotifyMetadata) <= len(data):
                        metadata = _FanotifyMetadata.from_buffer_copy(data, offset)
                        if metadata.event_len < ctypes.sizeof(_FanotifyMetadata):
                            raise RuntimeError("invalid fanotify metadata length")
                        offset += metadata.event_len
                        wall, mono = time.time_ns(), time.monotonic_ns()
                        _write_heartbeat(heartbeat_path)
                        if metadata.mask & FAN_Q_OVERFLOW:
                            overflows += 1
                        path = None
                        snapshot = None
                        identity = None
                        if metadata.fd >= 0:
                            try:
                                path = os.readlink("/proc/self/fd/%d" % metadata.fd)
                            except OSError:
                                path = None
                            snapshot = _fd_snapshot(metadata.fd)
                            try:
                                identity = process_identity(metadata.pid)
                            except Exception:
                                identity = {"pid": metadata.pid, "process_start_time_ticks": None}
                        _write_heartbeat(heartbeat_path)
                        row = {
                            "record_type": "fanotify_event",
                            "source": "fanotify",
                            "timestamp_realtime_ns": wall,
                            "timestamp_monotonic_ns": mono,
                            "mask": int(metadata.mask),
                            "event_fd": int(metadata.fd),
                            "pid": int(metadata.pid),
                            "path": path,
                            "process": identity,
                            "pre_response_snapshot": snapshot,
                        }
                        output.write(json.dumps(row, sort_keys=True) + "\n")
                        output.flush()
                        events += 1
                        batch += 1
                        if metadata.fd >= 0 and metadata.mask & (FAN_OPEN_PERM | FAN_ACCESS_PERM):
                            os.write(fan_fd, struct.pack("iI", metadata.fd, FAN_ALLOW))
                        if metadata.fd >= 0:
                            os.close(metadata.fd)
                        _write_heartbeat(heartbeat_path)
                high_water = max(high_water, batch)
                if stop:
                    quiet_since = quiet_since or time.monotonic()
                    if not available and time.monotonic() - quiet_since > 0.25:
                        break
                else:
                    quiet_since = None
    finally:
        os.close(fan_fd)
        _json_write(Path(health_path), _health("fanotify", started_wall, started_mono, events, overflows, overflows, high_water))


def _fanotify_watchdog(collector_pid: int, heartbeat_path: str, stop_path: str, status_path: str) -> None:
    threshold_ns = FANOTIFY_RESPONSE_TIMEOUT_MS * 1_000_000
    status = {"pid": os.getpid(), "collector_pid": collector_pid, "triggered": False, "threshold_ns": threshold_ns}
    while not Path(stop_path).exists():
        heartbeat = None
        try:
            heartbeat = int(Path(heartbeat_path).read_text(encoding="ascii"))
            stale = time.monotonic_ns() - heartbeat > threshold_ns
        except (OSError, ValueError):
            stale = True
        try:
            os.kill(collector_pid, 0)
            alive = True
        except OSError:
            alive = False
        if stale or not alive:
            time.sleep(0.05)
            confirmed_heartbeat = heartbeat
            try:
                confirmed_heartbeat = int(Path(heartbeat_path).read_text(encoding="ascii"))
                stale = time.monotonic_ns() - confirmed_heartbeat > threshold_ns
            except (OSError, ValueError):
                stale = True
            try:
                os.kill(collector_pid, 0)
                alive = True
            except OSError:
                alive = False
            if not stale and alive:
                continue
            status.update({
                "triggered": True,
                "stale": stale,
                "collector_alive": alive,
                "last_heartbeat_monotonic_ns": confirmed_heartbeat,
                "triggered_monotonic_ns": time.monotonic_ns(),
            })
            if alive:
                os.kill(collector_pid, signal.SIGKILL)
            break
        time.sleep(0.05)
    _json_write(Path(status_path), status)


def _set_no_new_privs() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS)")


def _spawn_worker(workspace: Path, cgroup: Path, uid: int, gid: int) -> tuple[int, dict[str, int], dict[str, Any]]:
    start_read, start_write = os.pipe()
    result_read, result_write = os.pipe()
    stop_read, stop_write = os.pipe()
    ready_read, ready_write = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(start_write)
            os.close(result_read)
            os.close(stop_write)
            os.close(ready_read)
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.unshare(0x40000000) != 0:
                raise OSError(ctypes.get_errno(), "unshare(CLONE_NEWNET)")
            _command(["/usr/sbin/ip", "link", "set", "lo", "up"])
            nft_rules = """table inet assa_smoke {
 chain output { type filter hook output priority 0; policy drop; }
 chain input { type filter hook input priority 0; policy drop; }
}
"""
            _command(["/usr/sbin/nft", "-f", "-"], input_text=nft_rules)
            (cgroup / "cgroup.procs").write_text(str(os.getpid()), encoding="ascii")
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            _set_no_new_privs()
            ready = {
                "pid": os.getpid(),
                "network_namespace_id": os.readlink("/proc/self/ns/net"),
                "cgroup_records": Path("/proc/self/cgroup").read_text(encoding="utf-8").splitlines(),
                "uid": os.getuid(),
                "gid": os.getgid(),
            }
            os.write(ready_write, (json.dumps(ready) + "\n").encode())
            os.close(ready_write)
            if os.read(start_read, 1) != b"S":
                raise RuntimeError("worker start token missing")
            observations = []
            for name in ("carrier.txt", "negative_carrier.txt"):
                fd = os.open(workspace / name, os.O_RDONLY)
                data = os.read(fd, PREFIX_BYTES)
                observations.append({"path": name, "fd": fd, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
                os.close(fd)
            target_fd = os.open(workspace / "target.txt", os.O_WRONLY | os.O_TRUNC)
            actual = os.write(target_fd, WRITTEN_BYTES)
            os.fsync(target_fd)
            os.close(target_fd)
            result = {"observations": observations, "target_fd": target_fd, "requested": len(WRITTEN_BYTES), "actual": actual}
            os.write(result_write, (json.dumps(result) + "\n").encode())
            os.close(result_write)
            os.read(stop_read, 1)
            os._exit(0)
        except BaseException as exc:
            try:
                os.write(result_write, (json.dumps({"worker_error": repr(exc)}) + "\n").encode())
            except OSError:
                pass
            os._exit(111)
    for fd in (start_read, result_write, stop_read, ready_write):
        os.close(fd)
    ready_raw = b""
    deadline = time.monotonic() + 10
    while b"\n" not in ready_raw and time.monotonic() < deadline:
        readable, _, _ = select.select([ready_read], [], [], 0.1)
        if readable:
            block = os.read(ready_read, 65536)
            if not block:
                break
            ready_raw += block
    os.close(ready_read)
    if not ready_raw:
        _, status = os.waitpid(pid, 0)
        raise RuntimeError("worker failed before readiness: status=%d" % status)
    ready = json.loads(ready_raw.splitlines()[0])
    return pid, {"start": start_write, "result": result_read, "stop": stop_write}, ready


def _read_pipe_json(fd: int, timeout: float = 10.0) -> dict[str, Any]:
    data = b""
    deadline = time.monotonic() + timeout
    while b"\n" not in data and time.monotonic() < deadline:
        readable, _, _ = select.select([fd], [], [], 0.1)
        if readable:
            block = os.read(fd, 65536)
            if not block:
                break
            data += block
    os.close(fd)
    if not data:
        raise TimeoutError("worker result timed out")
    return json.loads(data.splitlines()[0])


def _compile_ebpf(source_dir: Path, binary_dir: Path) -> dict[str, Any]:
    binary_dir.mkdir(parents=True, exist_ok=True)
    bpf_object = binary_dir / "smoke_ebpf.bpf.o"
    loader = binary_dir / "smoke_ebpf"
    _command([
        "/usr/bin/clang", "-O2", "-g", "-target", "bpf", "-D__TARGET_ARCH_x86",
        "-I/usr/include/x86_64-linux-gnu", "-c", str(source_dir / "smoke_ebpf.bpf.c"), "-o", str(bpf_object),
    ])
    _command([
        "/usr/bin/cc", "-O2", "-Wall", "-Wextra", str(source_dir / "smoke_ebpf.c"),
        "-o", str(loader), "-lbpf", "-lelf", "-lz",
    ])
    return {
        "object": bpf_object,
        "loader": loader,
        "object_sha256": _sha_file(bpf_object),
        "loader_sha256": _sha_file(loader),
        "source_sha256": {
            "bpf": _sha_file(source_dir / "smoke_ebpf.bpf.c"),
            "loader": _sha_file(source_dir / "smoke_ebpf.c"),
        },
    }


def _landlock_abi() -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(444, 0, 0, 1)
    if result < 0:
        raise OSError(ctypes.get_errno(), "landlock_create_ruleset(VERSION)")
    return int(result)


def _version(command: list[str]) -> str:
    result = _command(command, check=False)
    return (result.stdout or result.stderr).strip().splitlines()[0]


def _environment_fingerprint(compiled: dict[str, Any]) -> dict[str, Any]:
    os_release = {}
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            os_release[key] = value.strip('"')
    ntp = _command(["/usr/bin/timedatectl", "show", "--property=NTPSynchronized", "--property=NTP", "--property=Timezone"], check=False)
    libbpf = _command(
        ["/usr/bin/dpkg-query", "-W", "-f=${Version}", "libbpf0"], check=False
    )
    return {
        "schema_version": "assa.environment_fingerprint.v1",
        "host": run_host_identity(),
        "uname": " ".join(platform.uname()),
        "os_release": os_release,
        "root_filesystem": _command(["/usr/bin/findmnt", "-no", "SOURCE,FSTYPE", "/"]).stdout.strip(),
        "landlock_abi": _landlock_abi(),
        "monitor_versions": {
            "inotify": "linux-inotify-uapi/%s" % platform.release(),
            "fanotify": "fanotify-metadata-v3/%s" % platform.release(),
            "auditd": _version(["/usr/sbin/auditctl", "-v"]),
            "ebpf": "assa-libbpf-smoke-v1 object=%s" % compiled["object_sha256"],
        },
        "tool_versions": {
            "bpftool": _version(["/usr/sbin/bpftool", "version"]),
            "bpftrace": _version(["/usr/bin/bpftrace", "--version"]),
            "libbpf_runtime": libbpf.stdout.strip() or libbpf.stderr.strip(),
            "clang": _version(["/usr/bin/clang", "--version"]),
            "nft": _version(["/usr/sbin/nft", "--version"]),
            "python": platform.python_version(),
        },
        "ebpf_build": {key: value for key, value in compiled.items() if key not in {"object", "loader"}},
        "ntp_state": ntp.stdout.strip().splitlines(),
        "btf_vmlinux_present": Path("/sys/kernel/btf/vmlinux").is_file(),
    }


def _audit_status() -> dict[str, int]:
    output = _command(["/usr/sbin/auditctl", "-s"]).stdout
    values = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("-").isdigit():
            values[parts[0]] = int(parts[1])
    return values


def _audit_groups(raw: str, anchor: dict[str, Any]) -> list[dict[str, Any]]:
    groups: dict[str, list[str]] = {}
    order = []
    for line in raw.splitlines():
        match = re.search(r"msg=audit\((\d+(?:\.\d+)?):(\d+)\)", line)
        key = match.group(2) if match else "unkeyed-%d" % len(order)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(line)
    rows = []
    for key in order:
        records = groups[key]
        joined = "\n".join(records)
        match = re.search(r"msg=audit\((\d+(?:\.\d+)?):", joined)
        event_wall = int(float(match.group(1)) * 1_000_000_000) if match else time.time_ns()
        event_mono = event_wall - int(anchor["estimated_boot_realtime_ns"])
        rows.append({
            "record_type": "audit_event_group",
            "source": "auditd",
            "timestamp_realtime_ns": event_wall,
            "timestamp_monotonic_ns": event_mono,
            "audit_serial": key,
            "raw_records": records,
        })
    return rows


def _parse_audit_value(joined: str, field: str) -> int | None:
    match = re.search(r"(?:^| )%s=(-?\d+)(?: |$)" % re.escape(field), joined)
    return int(match.group(1)) if match else None


def _parse_audit_argument(joined: str, field: str) -> int | None:
    match = re.search(r"(?:^| )%s=([0-9a-fA-F]+)(?: |$)" % re.escape(field), joined)
    return int(match.group(1), 16) if match else None


def _normalize(
    *, run_id: str, run_dir: Path, workspace: Path, anchor: dict[str, Any], worker_identity: dict[str, Any],
    worker_result: dict[str, Any], audit_raw: str, audit_before: dict[str, int], audit_after: dict[str, int],
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    raw_dir, normalized_dir, health_dir = run_dir / "raw", run_dir / "normalized", run_dir / "health"
    target = workspace / "target.txt"
    correlation_id = "%s:ordinary-write:1" % run_id
    mutation = write_mutation_capture(
        preimage=INITIAL_BYTES,
        postimage=WRITTEN_BYTES,
        buffer_prefix=WRITTEN_BYTES[:PREFIX_BYTES],
        requested_count=len(WRITTEN_BYTES),
        actual_count=int(worker_result["actual"]),
    )

    normalized: dict[str, list[dict[str, Any]]] = {name: [] for name in ("inotify", "fanotify", "auditd", "ebpf")}
    inotify_rows = _read_jsonl(raw_dir / "inotify.jsonl")
    candidates = [row for row in inotify_rows if row.get("path") == str(target) and row.get("mask", 0) & (IN_MODIFY | IN_CLOSE_WRITE)]
    if not candidates:
        raise RuntimeError("inotify did not observe target mutation")
    chosen = candidates[-1]
    normalized["inotify"].append(event_envelope(
        source="inotify", run_id=run_id, event="write", process=None,
        wall_ns=chosen["timestamp_realtime_ns"], monotonic_ns=chosen["timestamp_monotonic_ns"],
        fields={"path": str(target), "inode": target.stat().st_ino, "raw_mask": chosen["mask"], "correlation_id": correlation_id, "mutation": mutation},
    ))

    fanotify_rows = _read_jsonl(raw_dir / "fanotify.jsonl")
    fan_candidates = [row for row in fanotify_rows if row.get("path") == str(target) and row.get("pid") == worker_identity["pid"]]
    if not fan_candidates:
        raise RuntimeError("fanotify did not observe target open")
    fan = fan_candidates[0]
    normalized["fanotify"].append(event_envelope(
        source="fanotify", run_id=run_id, event="write", process=worker_identity,
        wall_ns=fan["timestamp_realtime_ns"], monotonic_ns=fan["timestamp_monotonic_ns"],
        fields={"path": str(target), "inode": target.stat().st_ino, "raw_mask": fan["mask"], "permission_intercepted": bool(fan["mask"] & FAN_OPEN_PERM), "correlation_id": correlation_id, "mutation": mutation},
    ))

    audit_groups = _audit_groups(audit_raw, anchor)
    _jsonl_write(raw_dir / "auditd.jsonl", audit_groups)
    target_groups = []
    worker_groups = []
    for row in audit_groups:
        joined = "\n".join(row["raw_records"])
        if _parse_audit_value(joined, "pid") == worker_identity["pid"]:
            worker_groups.append((row, joined))
            if str(target) in joined or 'name="target.txt"' in joined:
                target_groups.append((row, joined))
    open_groups = [
        (row, joined)
        for row, joined in target_groups
        if _parse_audit_value(joined, "syscall") == 257
    ]
    write_groups = [
        (row, joined)
        for row, joined in worker_groups
        if _parse_audit_value(joined, "syscall") == 1
        and _parse_audit_argument(joined, "a0") == int(worker_result["target_fd"])
        and _parse_audit_argument(joined, "a2") == len(WRITTEN_BYTES)
    ]
    if not write_groups:
        raise RuntimeError("auditd did not observe worker write syscall on target")
    if not open_groups:
        raise RuntimeError("auditd did not observe worker O_TRUNC openat on target")
    audit, audit_joined = write_groups[0]
    audit_open, _audit_open_joined = open_groups[0]
    normalized["auditd"].append(event_envelope(
        source="auditd", run_id=run_id, event="write", process=worker_identity,
        wall_ns=audit["timestamp_realtime_ns"], monotonic_ns=audit["timestamp_monotonic_ns"],
        fields={
            "path": str(target),
            "inode": target.stat().st_ino,
            "syscall_number": 1,
            "syscall_name": "write",
            "syscall_arguments": {
                name: _parse_audit_argument(audit_joined, name)
                for name in ("a0", "a1", "a2", "a3")
            },
            "syscall_arguments_raw": audit["raw_records"],
            "openat_syscall_arguments_raw": audit_open["raw_records"],
            "audit_serial": audit["audit_serial"],
            "openat_audit_serial": audit_open["audit_serial"],
            "auid": _parse_audit_value(audit_joined, "auid"),
            "ses": _parse_audit_value(audit_joined, "ses"),
            "correlation_id": correlation_id,
            "mutation": mutation,
        },
    ))

    ebpf_rows = _read_jsonl(raw_dir / "ebpf.jsonl")
    payload_hex = WRITTEN_BYTES.hex()
    ebpf_writes = [row for row in ebpf_rows if row.get("kind") == "write" and row.get("pid") == worker_identity["pid"] and row.get("buffer_prefix_hex") == payload_hex]
    if len(ebpf_writes) != 1:
        raise RuntimeError("eBPF target buffer capture count is %d, expected one" % len(ebpf_writes))
    ebpf_write = ebpf_writes[0]
    if ebpf_write.get("buffer_prefix_capacity_bytes") != EBPF_WRITE_BUFFER_PREFIX_BYTES:
        raise RuntimeError("eBPF collector is not configured for frozen prefix capacity")
    if ebpf_write.get("capture_error") or ebpf_write.get("actual_count") != len(WRITTEN_BYTES):
        raise RuntimeError("eBPF target capture is incomplete")
    normalized["ebpf"].append(event_envelope(
        source="ebpf", run_id=run_id, event="write", process=worker_identity,
        wall_ns=ebpf_write["timestamp_realtime_ns"], monotonic_ns=ebpf_write["timestamp_monotonic_ns"],
        fields={"path": str(target), "inode": target.stat().st_ino, "fd": ebpf_write["fd"], "kernel_monotonic_ns": ebpf_write["kernel_monotonic_ns"], "correlation_id": correlation_id, "mutation": mutation},
    ))

    negative_outcomes = []
    for name, expected, outcome in (
        ("carrier.txt", CARRIER_BYTES, "read_then_smoke_write_not_semantically_attributed"),
        ("negative_carrier.txt", NEGATIVE_BYTES, "read_without_attributable_write"),
    ):
        path = workspace / name
        matches = [row for row in ebpf_rows if row.get("kind") == "read" and row.get("pid") == worker_identity["pid"] and row.get("buffer_prefix_hex") == expected.hex()]
        if len(matches) != 1:
            raise RuntimeError("eBPF read capture for %s has count %d" % (name, len(matches)))
        read = matches[0]
        join = ingestion_join_key(
            run_id=run_id,
            source="ebpf",
            boot_id=anchor["boot_id"],
            pid=worker_identity["pid"],
            process_start_time_ticks=worker_identity["process_start_time_ticks"],
            fd=read["fd"],
            path=str(path),
            inode=path.stat().st_ino,
            timestamp_monotonic_ns=read["timestamp_monotonic_ns"],
        )
        read_site_id = "%s:%s" % (run_id, name)
        normalized["ebpf"].append(event_envelope(
            source="ebpf", run_id=run_id, event="read", process=worker_identity,
            wall_ns=read["timestamp_realtime_ns"], monotonic_ns=read["timestamp_monotonic_ns"],
            fields={
                "path": str(path), "inode": path.stat().st_ino, "carrier_read": True,
                "read_site_id": read_site_id,
                "kernel_monotonic_ns": read["kernel_monotonic_ns"],
                "read_observation": ingestion_read_capture(fd=read["fd"], offset=0, count=read["actual_count"], buffer_prefix=bytes.fromhex(read["buffer_prefix_hex"])),
                "ingestion_join_key": join,
            },
        ))
        negative_outcomes.append({
            "read_site_id": read_site_id,
            "path": str(path),
            "outcome": outcome,
            "retained": True,
            "ingestion_join_key": join,
        })

    for source, rows in normalized.items():
        _jsonl_write(normalized_dir / (source + ".jsonl"), rows)

    audit_health = _health(
        "auditd",
        min(row["timestamp_realtime_ns"] for row in audit_groups),
        min(row["timestamp_monotonic_ns"] for row in audit_groups),
        len(audit_groups),
        max(0, audit_after.get("lost", 0) - audit_before.get("lost", 0)),
        max(0, audit_after.get("lost", 0) - audit_before.get("lost", 0)),
        max(audit_before.get("backlog", 0), audit_after.get("backlog", 0)),
    )
    _json_write(health_dir / "auditd.json", audit_health)
    source_paths = {
        source: {
            "raw_stream_path": str((raw_dir / (source + ".jsonl")).resolve()),
            "normalized_stream_path": str((normalized_dir / (source + ".jsonl")).resolve()),
            "health_path": str((health_dir / (source + ".json")).resolve()),
        }
        for source in normalized
    }
    return source_paths, negative_outcomes


def _validate_smoke_bundle(bundle: dict[str, Any], *, run_dir: Path, written: bytes) -> dict[str, Any]:
    validate_raw_trace_bundle(bundle)
    checks: dict[str, bool] = {}
    canonical = []
    raw_dual = True
    health_zero_loss = True
    for source, record in bundle["sources"].items():
        raw_rows = _read_jsonl(Path(record["raw_stream_path"]))
        raw_dual = raw_dual and bool(raw_rows) and all(isinstance(row.get("timestamp_realtime_ns"), int) and isinstance(row.get("timestamp_monotonic_ns"), int) for row in raw_rows)
        rows = _read_jsonl(Path(record["normalized_stream_path"]))
        writes = [row for row in rows if row.get("event") == "write"]
        checks["%s_one_canonical_write" % source] = len(writes) == 1
        canonical.extend(writes)
        health = record["health"]
        health_zero_loss = health_zero_loss and health["drop_count"] == 0 and health["overflow_count"] == 0
    checks["all_raw_events_dual_timestamped"] = raw_dual
    checks["all_sources_zero_drop_and_overflow"] = health_zero_loss
    checks["write_alignment_key_identical"] = len({row.get("correlation_id") for row in canonical}) == 1
    checks["pid_events_have_process_start_time"] = all(
        row.get("process") is None or isinstance(row["process"].get("process_start_time_ticks"), int)
        for row in canonical
    )
    ebpf_writes = [row for row in canonical if row["source"] == "ebpf"]
    checks["ebpf_has_frozen_prefix_capacity"] = len(ebpf_writes) == 1 and ebpf_writes[0]["mutation"]["write_buffer"]["buffer_prefix_capacity_bytes"] == EBPF_WRITE_BUFFER_PREFIX_BYTES
    checks["pre_and_post_images_are_complete"] = all(
        row["mutation"][name]["complete"] is True and isinstance(row["mutation"][name]["data"], str)
        for row in canonical for name in ("preimage", "postimage")
    )
    checks["postimage_matches_disk"] = (run_dir / "workspace" / "target.txt").read_bytes() == written
    ebpf_rows = _read_jsonl(Path(bundle["sources"]["ebpf"]["normalized_stream_path"]))
    carrier_reads = [row for row in ebpf_rows if row.get("carrier_read") is True]
    checks["ingestion_join_keys_retained"] = len(carrier_reads) == 2 and all(row.get("ingestion_join_key") for row in carrier_reads)
    checks["read_without_write_negative_retained"] = any(row.get("outcome") == "read_without_attributable_write" for row in bundle.get("negative_outcomes_retained", []))
    failed = sorted(key for key, value in checks.items() if not value)
    if failed:
        raise RuntimeError("smoke bundle self-check failed: " + ", ".join(failed))
    return {"schema_version": "assa.s1_smoke_self_check.v1", "passed": True, "checks": checks, "validated_with": "openclaw_core.trace.schema.validate_raw_trace_bundle"}


def run(output_root: Path) -> Path:
    if os.geteuid() != 0:
        raise PermissionError("four-source smoke supervisor must run as root")
    if PREFIX_BYTES != EBPF_WRITE_BUFFER_PREFIX_BYTES:
        raise RuntimeError("collector prefix differs from frozen trace schema")
    run_id = "s1-smoke-%s-%s" % (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()), uuid.uuid4().hex[:8])
    run_dir = (output_root / run_id).resolve()
    if run_dir.exists():
        raise FileExistsError(run_dir)
    raw_dir, health_dir, control_dir, workspace = run_dir / "raw", run_dir / "health", run_dir / "control", run_dir / "workspace"
    for path in (raw_dir, health_dir, control_dir, workspace):
        path.mkdir(parents=True, exist_ok=False)
    account = pwd.getpwnam("assa")
    os.chown(workspace, account.pw_uid, account.pw_gid)
    os.chmod(workspace, 0o700)
    for name, content in (("target.txt", INITIAL_BYTES), ("carrier.txt", CARRIER_BYTES), ("negative_carrier.txt", NEGATIVE_BYTES)):
        path = workspace / name
        path.write_bytes(content)
        os.chown(path, account.pw_uid, account.pw_gid)
        os.chmod(path, 0o600)

    source_dir = Path(__file__).with_name("s1_smoke")
    compiled = _compile_ebpf(source_dir, run_dir / "bin")
    anchor = boot_time_anchor()
    _json_write(run_dir / "run_time_anchor.json", anchor)
    fingerprint = _environment_fingerprint(compiled)
    _json_write(run_dir / "environment_fingerprint.json", fingerprint)

    cgroup_parent = Path("/sys/fs/cgroup/assa-bench")
    cgroup = cgroup_parent / run_id
    cgroup_parent.mkdir(exist_ok=True)
    available_controllers = set(
        (cgroup_parent / "cgroup.controllers").read_text(encoding="ascii").split()
    )
    required_controllers = {"cpu", "memory", "pids"}
    if not required_controllers.issubset(available_controllers):
        raise RuntimeError("cgroup v2 lacks required cpu/memory/pids controllers")
    (cgroup_parent / "cgroup.subtree_control").write_text(
        "+cpu +memory +pids", encoding="ascii"
    )
    cgroup.mkdir()
    (cgroup / "pids.max").write_text("32", encoding="ascii")
    (cgroup / "memory.max").write_text(str(256 * 1024 * 1024), encoding="ascii")
    (cgroup / "cpu.max").write_text("50000 100000", encoding="ascii")

    worker_pid = None
    pipes: dict[str, int] = {}
    worker_stopped = False
    processes: list[multiprocessing.Process] = []
    ebpf_process: subprocess.Popen[str] | None = None
    audit_key = ("oc_" + uuid.uuid4().hex[:20])
    audit_watch_installed = False
    audit_syscall_installed = False
    collector_stop = control_dir / "collectors.stop"
    watchdog_stop = control_dir / "watchdog.stop"
    try:
        worker_pid, pipes, worker_ready = _spawn_worker(workspace, cgroup, account.pw_uid, account.pw_gid)
        inotify_ready = control_dir / "inotify.ready.json"
        fanotify_ready = control_dir / "fanotify.ready.json"
        heartbeat = control_dir / "fanotify.heartbeat"
        inotify = multiprocessing.Process(
            target=_inotify_collector,
            args=(str(workspace), str(raw_dir / "inotify.jsonl"), str(health_dir / "inotify.json"), str(inotify_ready), str(collector_stop)),
            name="assa-inotify-smoke",
        )
        fanotify = multiprocessing.Process(
            target=_fanotify_collector,
            args=(str(workspace), str(raw_dir / "fanotify.jsonl"), str(health_dir / "fanotify.json"), str(fanotify_ready), str(heartbeat), str(collector_stop)),
            name="assa-fanotify-smoke",
        )
        inotify.start()
        fanotify.start()
        processes.extend([inotify, fanotify])
        _wait_file(inotify_ready, [inotify])
        _wait_file(fanotify_ready, [fanotify])
        watchdog_status = control_dir / "fanotify_watchdog.json"
        watchdog = multiprocessing.Process(
            target=_fanotify_watchdog,
            args=(fanotify.pid, str(heartbeat), str(watchdog_stop), str(watchdog_status)),
            name="assa-fanotify-watchdog",
        )
        watchdog.start()
        processes.append(watchdog)

        ebpf_ready = control_dir / "ebpf.ready"
        ebpf_stderr = (raw_dir / "ebpf.stderr.log").open("w", encoding="utf-8")
        ebpf_process = subprocess.Popen(
            [str(compiled["loader"]), str(compiled["object"]), str(worker_pid), str(raw_dir / "ebpf.jsonl"), str(health_dir / "ebpf.json"), str(ebpf_ready)],
            stdout=subprocess.DEVNULL,
            stderr=ebpf_stderr,
            text=True,
        )
        _wait_file(ebpf_ready, [ebpf_process])

        audit_before = _audit_status()
        audit_watch_add = ["/usr/sbin/auditctl", "-w", str(workspace), "-p", "rwxa", "-k", audit_key]
        audit_watch_remove = ["/usr/sbin/auditctl", "-W", str(workspace), "-p", "rwxa", "-k", audit_key]
        audit_syscall_add = [
            "/usr/sbin/auditctl", "-a", "always,exit", "-F", "arch=b64",
            "-S", "read,write", "-F", "pid=%d" % worker_pid, "-k", audit_key,
        ]
        audit_syscall_remove = [
            "/usr/sbin/auditctl", "-d", "always,exit", "-F", "arch=b64",
            "-S", "read,write", "-F", "pid=%d" % worker_pid, "-k", audit_key,
        ]
        _command(audit_watch_add)
        audit_watch_installed = True
        _command(audit_syscall_add)
        audit_syscall_installed = True
        audit_rules = _command(["/usr/sbin/auditctl", "-l"]).stdout
        nft_rules = _command(["/usr/bin/nsenter", "-t", str(worker_pid), "-n", "/usr/sbin/nft", "list", "ruleset"]).stdout
        routes = _command(["/usr/bin/nsenter", "-t", str(worker_pid), "-n", "/usr/sbin/ip", "route", "show"]).stdout
        supervisor_netns = os.readlink("/proc/self/ns/net")
        collector_records = {
            "inotify": {"pid": inotify.pid, "ready": json.loads(inotify_ready.read_text(encoding="utf-8"))},
            "fanotify": {"pid": fanotify.pid, "ready": json.loads(fanotify_ready.read_text(encoding="utf-8"))},
            "auditd": {"pid": _audit_status().get("pid"), "rule_key": audit_key},
            "ebpf": {"pid": ebpf_process.pid, "ready": ebpf_ready.read_text(encoding="utf-8").strip()},
        }
        checks = {
            "no_llm_or_agent_runtime_invoked": True,
            "credential_shaped_environment_absent": not credential_variable_names(os.environ),
            "unique_worker_cgroup_active": any(str(cgroup.relative_to(Path('/sys/fs/cgroup'))) in row for row in worker_ready["cgroup_records"]),
            "worker_network_namespace_isolated": worker_ready["network_namespace_id"] != supervisor_netns,
            "egress_default_deny_installed": "policy drop" in nft_rules and not routes.strip(),
            "fanotify_mark_is_workspace_only": json.loads(fanotify_ready.read_text(encoding="utf-8"))["mark_root"] == str(workspace),
            "fanotify_response_timeout_bounded": json.loads(fanotify_ready.read_text(encoding="utf-8"))["response_timeout_ms"] <= 1000,
            "fanotify_watchdog_active": watchdog.is_alive(),
            "audit_watch_and_pid_syscall_rules_active": (
                str(workspace) in audit_rules
                and audit_key in audit_rules
                and "pid=%d" % worker_pid in audit_rules
                and "write" in audit_rules
            ),
            "four_collectors_active": inotify.is_alive() and fanotify.is_alive() and watchdog.is_alive() and ebpf_process.poll() is None,
            "frozen_ebpf_prefix_compiled": PREFIX_BYTES == 16384,
        }
        failed = sorted(key for key, value in checks.items() if not value)
        attestation = {
            "schema_version": SAFETY_SCHEMA_VERSION,
            "run_id": run_id,
            "workspace": str(workspace),
            "created_realtime_ns": time.time_ns(),
            "created_monotonic_ns": time.monotonic_ns(),
            "llm_used": False,
            "live_poisoned_collection_started": False,
            "environment_variable_names": sorted(os.environ),
            "credential_shaped_environment_names": credential_variable_names(os.environ),
            "cgroup": {
                "path": str(cgroup), "unique_per_run": True, "worker_records": worker_ready["cgroup_records"],
                "limits": {name: (cgroup / name).read_text(encoding="ascii").strip() for name in ("pids.max", "memory.max", "cpu.max")},
            },
            "network": {
                "supervisor_namespace_id": supervisor_netns,
                "worker_namespace_id": worker_ready["network_namespace_id"],
                "egress_default_deny": True,
                "nft_ruleset": nft_rules,
                "routes": routes.splitlines(),
            },
            "fanotify": {
                **json.loads(fanotify_ready.read_text(encoding="utf-8")),
                "watchdog_pid": watchdog.pid,
                "watchdog_status_path": str(watchdog_status),
            },
            "auditd": {"rule": audit_rules.strip(), "key": audit_key, "backlog_limit": audit_before.get("backlog_limit")},
            "monitors": collector_records,
            "preflight_checks": checks,
            "preflight_passed": not failed,
        }
        _json_write(run_dir / "run_safety_attestation.json", attestation)
        if failed:
            raise RuntimeError("S1 smoke safety preflight failed: " + ", ".join(failed))

        os.write(pipes["start"], b"S")
        os.close(pipes["start"])
        worker_result = _read_pipe_json(pipes["result"])
        if worker_result.get("worker_error"):
            raise RuntimeError(worker_result["worker_error"])
        if worker_result.get("actual") != len(WRITTEN_BYTES):
            raise RuntimeError("ordinary write was incomplete")
        time.sleep(0.8)
        worker_identity = process_identity(worker_pid)

        ebpf_process.send_signal(signal.SIGINT)
        if ebpf_process.wait(timeout=10) != 0:
            raise RuntimeError("eBPF collector failed; see raw/ebpf.stderr.log")
        ebpf_stderr.close()
        os.write(pipes["stop"], b"X")
        os.close(pipes["stop"])
        _, worker_status = os.waitpid(worker_pid, 0)
        worker_stopped = True
        if worker_status != 0:
            raise RuntimeError("worker exited with status %d" % worker_status)
        collector_stop.write_text("stop\n", encoding="ascii")
        for process in (inotify, fanotify):
            process.join(timeout=10)
            if process.exitcode != 0:
                raise RuntimeError("%s collector failed with %s" % (process.name, process.exitcode))
        watchdog_stop.write_text("stop\n", encoding="ascii")
        watchdog.join(timeout=5)
        if watchdog.exitcode != 0:
            raise RuntimeError("fanotify watchdog failed")
        watchdog_record = json.loads(watchdog_status.read_text(encoding="utf-8"))
        if watchdog_record.get("triggered") is True:
            raise RuntimeError("fanotify watchdog triggered")
        time.sleep(0.5)
        audit_after = _audit_status()
        audit_raw = _command(
            ["/usr/sbin/ausearch", "--input-logs", "-k", audit_key, "--raw"]
        ).stdout
        (raw_dir / "auditd_ausearch.log").write_text(audit_raw, encoding="utf-8")
        _command(audit_syscall_remove)
        audit_syscall_installed = False
        _command(audit_watch_remove)
        audit_watch_installed = False

        source_paths, negative_outcomes = _normalize(
            run_id=run_id,
            run_dir=run_dir,
            workspace=workspace,
            anchor=anchor,
            worker_identity=worker_identity,
            worker_result=worker_result,
            audit_raw=audit_raw,
            audit_before=audit_before,
            audit_after=audit_after,
        )
        versions = fingerprint["monitor_versions"]
        spec = {
            "run_id": run_id,
            "run_time_anchor": anchor,
            "negative_outcomes_retained": negative_outcomes,
            "fixture_http_access_log": None,
            "sources": {
                source: {**paths, "version": versions[source]}
                for source, paths in source_paths.items()
            },
        }
        _json_write(run_dir / "bundle_spec.json", spec)
        bundle_path = run_dir / "raw_trace_bundle.json"
        bundle = finalize(run_dir / "bundle_spec.json", bundle_path)
        self_check = _validate_smoke_bundle(bundle, run_dir=run_dir, written=WRITTEN_BYTES)
        _json_write(run_dir / "bundle_self_check.json", self_check)
        completion = {
            "schema_version": SMOKE_SCHEMA_VERSION,
            "run_id": run_id,
            "passed": True,
            "llm_used": False,
            "live_poisoned_collection_started": False,
            "run_safety_attestation": str((run_dir / "run_safety_attestation.json").resolve()),
            "raw_trace_bundle": str(bundle_path.resolve()),
            "self_check": str((run_dir / "bundle_self_check.json").resolve()),
            "environment_fingerprint": str((run_dir / "environment_fingerprint.json").resolve()),
        }
        _json_write(run_dir / "smoke_result.json", completion)
        for path in sorted(run_dir.rglob("*"), reverse=True):
            if path.is_file():
                os.chown(path, account.pw_uid, account.pw_gid)
                os.chmod(path, 0o640)
            elif path.is_dir():
                os.chown(path, account.pw_uid, account.pw_gid)
                os.chmod(path, 0o750)
        os.chown(run_dir, account.pw_uid, account.pw_gid)
        os.chmod(run_dir, 0o750)
        return run_dir
    finally:
        if audit_syscall_installed and worker_pid is not None:
            _command(
                [
                    "/usr/sbin/auditctl", "-d", "always,exit", "-F", "arch=b64",
                    "-S", "read,write", "-F", "pid=%d" % worker_pid, "-k", audit_key,
                ],
                check=False,
            )
        if audit_watch_installed:
            _command(
                ["/usr/sbin/auditctl", "-W", str(workspace), "-p", "rwxa", "-k", audit_key],
                check=False,
            )
        if ebpf_process is not None and ebpf_process.poll() is None:
            ebpf_process.terminate()
            try:
                ebpf_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                ebpf_process.kill()
        if worker_pid is not None and not worker_stopped:
            try:
                if pipes.get("stop") is not None:
                    os.write(pipes["stop"], b"X")
            except OSError:
                pass
            try:
                os.kill(worker_pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                os.waitpid(worker_pid, 0)
            except ChildProcessError:
                pass
        collector_stop.parent.mkdir(parents=True, exist_ok=True)
        collector_stop.write_text("stop\n", encoding="ascii")
        watchdog_stop.write_text("stop\n", encoding="ascii")
        for process in processes:
            if process.is_alive():
                process.join(timeout=2)
            if process.is_alive():
                process.kill()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one no-LLM binding four-source smoke")
    parser.add_argument(
        "--output-root",
        default=str(PROJECT_ROOT / "experiments" / "results" / "s1_smoke"),
    )
    args = parser.parse_args()
    run_dir = run(Path(args.output_root))
    print(run_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
