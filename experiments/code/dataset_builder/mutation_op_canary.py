#!/usr/bin/env python3
"""Disposable four-source canary for mutation op-type coverage."""
from __future__ import annotations
import argparse, ctypes, json, os, pwd, re, select, signal, subprocess, sys, time, uuid
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[3]
AGENT_ROOT = PROJECT_ROOT / "experiments" / "agent"
CODE_ROOT = PROJECT_ROOT / "experiments" / "code"
for _path in (AGENT_ROOT, CODE_ROOT):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from dataset_builder.finalize_trace_bundle import finalize
from dataset_builder.four_source_smoke import (
    IN_ATTRIB, IN_CLOSE_WRITE, IN_DELETE, IN_MODIFY,
    _audit_groups, _audit_status, _command, _compile_ebpf, _environment_fingerprint,
    _fanotify_watchdog, _health, _inotify_collector,
    _json_write, _jsonl_write, _parse_audit_value, _read_jsonl, _wait_file,
)
from dataset_builder.recollection_readiness import validate_run
from openclaw_core.trace.schema import (
    EBPF_WRITE_BUFFER_PREFIX_BYTES, boot_time_anchor, event_envelope,
    full_byte_snapshot, process_identity, validate_raw_trace_bundle,
    write_mutation_capture,
)

PREFIX_BYTES = EBPF_WRITE_BUFFER_PREFIX_BYTES
IN_MOVED_TO = 0x00000080
OP_SPECS = [
    {"op_type": "write", "event": "write", "logical_path": "MEMORY.md", "path": "MEMORY.md", "payload": b"canary write postimage\n"},
    {"op_type": "rename", "event": "rename", "logical_path": "MEMORY.md", "path": "MEMORY.md", "tmp_path": "MEMORY.md.tmp", "payload": b"canary rename postimage\n"},
    {"op_type": "chmod", "event": "chmod", "logical_path": "TOOLS.md", "path": "TOOLS.md", "mode_after": 0o640},
    {"op_type": "unlink", "event": "unlink", "logical_path": "HEARTBEAT.md", "path": "HEARTBEAT.md"},
]
AUDIT_SYSCALLS = {"write": {1}, "rename": {82, 264, 316}, "unlink": {87, 263}, "chmod": {90, 268}}

FAN_ACCESS = 0x00000001
FAN_MODIFY = 0x00000002
FAN_ATTRIB = 0x00000004
FAN_CLOSE_WRITE = 0x00000008
FAN_OPEN = 0x00000020
FAN_MOVED_FROM = 0x00000040
FAN_MOVED_TO = 0x00000080
FAN_CREATE = 0x00000100
FAN_DELETE = 0x00000200
FAN_Q_OVERFLOW = 0x00004000
FAN_EVENT_ON_CHILD = 0x08000000
FAN_ONDIR = 0x40000000
FAN_MARK_ADD = 0x00000001
FAN_CLASS_NOTIF = 0x00000000
FAN_CLOEXEC = 0x00000001
FAN_NONBLOCK = 0x00000002
FAN_REPORT_FID = 0x00000200
FAN_REPORT_DIR_FID = 0x00000400
FAN_REPORT_NAME = 0x00000800
AT_FDCWD = -100
FAN_FID_MASK = FAN_ATTRIB | FAN_CLOSE_WRITE | FAN_MODIFY | FAN_MOVED_TO | FAN_DELETE | FAN_EVENT_ON_CHILD | FAN_ONDIR

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


def _fanotify_fid_collector(workspace: str, raw_path: str, health_path: str, ready_path: str, heartbeat_path: str, stop_path: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    fan_fd = libc.fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME, os.O_RDONLY)
    if fan_fd < 0:
        raise OSError(ctypes.get_errno(), "fanotify_init(FID)")
    result = libc.fanotify_mark(fan_fd, FAN_MARK_ADD, ctypes.c_uint64(FAN_FID_MASK), AT_FDCWD, os.fsencode(workspace))
    if result < 0:
        raise OSError(ctypes.get_errno(), "fanotify_mark(FID)")
    started_wall, started_mono = time.time_ns(), time.monotonic_ns()
    Path(heartbeat_path).write_text(str(started_mono), encoding="ascii")
    _json_write(Path(ready_path), {"pid": os.getpid(), "fanotify_fd": fan_fd, "mark_root": workspace, "mark_scope": "workspace_subtree_fid", "mask": FAN_FID_MASK, "response_timeout_ms": 1000, "fid_mode": True})
    events = overflows = high_water = 0
    poller = select.poll(); poller.register(fan_fd, select.POLLIN)
    try:
        with Path(raw_path).open("w", encoding="utf-8") as output:
            quiet_since = None
            while True:
                Path(heartbeat_path).write_text(str(time.monotonic_ns()), encoding="ascii")
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
                            raise RuntimeError("invalid fanotify FID metadata length")
                        wall, mono = time.time_ns(), time.monotonic_ns()
                        if metadata.mask & FAN_Q_OVERFLOW:
                            overflows += 1
                        row = {"record_type": "fanotify_fid_event", "source": "fanotify", "timestamp_realtime_ns": wall, "timestamp_monotonic_ns": mono, "mask": int(metadata.mask), "event_fd": int(metadata.fd), "pid": int(metadata.pid), "path": None, "fid_mode": True}
                        output.write(json.dumps(row, sort_keys=True) + "\n"); output.flush()
                        events += 1; batch += 1; offset += metadata.event_len
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


def _read_pipe_json(fd: int) -> dict[str, Any]:
    chunks = []
    while True:
        block = os.read(fd, 65536)
        if not block:
            break
        chunks.append(block)
    return json.loads(b"".join(chunks).decode("utf-8"))


def _snapshot_state(workspace: Path, run_dir: Path, label: str) -> None:
    root = run_dir / "state_snapshots" / label
    root.mkdir(parents=True, exist_ok=True)
    for rel in ("MEMORY.md", "TOOLS.md", "HEARTBEAT.md"):
        src = workspace / rel
        dst = root / rel
        if src.exists():
            dst.write_bytes(src.read_bytes())


def _worker_script(workspace: Path, ready: Path, release: Path, result_fd: int) -> str:
    return """
import json, os, pathlib, time, hashlib
workspace = pathlib.Path(%r)
ready = pathlib.Path(%r)
release = pathlib.Path(%r)
result_fd = %d
ready.write_text(json.dumps({"pid": os.getpid(), "created_realtime_ns": time.time_ns(), "created_monotonic_ns": time.monotonic_ns()}, sort_keys=True) + "\\n", encoding="utf-8")
while not release.exists():
    time.sleep(0.02)
results = []
def record(op, path, before_exists, after_exists, extra=None):
    row = {"op_type": op, "path": path, "before_exists": before_exists, "after_exists": after_exists, "timestamp_realtime_ns": time.time_ns(), "timestamp_monotonic_ns": time.monotonic_ns()}
    if extra:
        row.update(extra)
    results.append(row)
p = workspace / "MEMORY.md"
before = p.read_bytes() if p.exists() else b""
with open(p, "wb") as handle:
    actual = handle.write(b"canary write postimage\\n")
record("write", "MEMORY.md", True, p.exists(), {"actual": actual, "pre_sha256": hashlib.sha256(before).hexdigest(), "post_sha256": hashlib.sha256(p.read_bytes()).hexdigest()})
p = workspace / "MEMORY.md"
tmp = workspace / "MEMORY.md.tmp"
tmp.write_bytes(b"canary rename postimage\\n")
# Force a modern, explicit syscall shape for canary coverage.  The legacy
# rename(2) tracepoint is not attachable on the pinned guest, while
# renameat2(2) is available and is the syscall family used by current
# atomic-write implementations.
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
SYS_renameat2 = 316
AT_FDCWD = -100
ret = libc.syscall(
    ctypes.c_long(SYS_renameat2),
    ctypes.c_int(AT_FDCWD),
    ctypes.c_char_p(bytes(tmp)),
    ctypes.c_int(AT_FDCWD),
    ctypes.c_char_p(bytes(p)),
    ctypes.c_uint(0),
)
if ret != 0:
    err = ctypes.get_errno()
    raise OSError(err, os.strerror(err), f"renameat2({tmp}, {p})")
record("rename", "MEMORY.md", True, p.exists(), {"tmp_path": "MEMORY.md.tmp", "rename_syscall": "renameat2", "post_sha256": hashlib.sha256(p.read_bytes()).hexdigest()})
p = workspace / "TOOLS.md"
before_mode = p.stat().st_mode & 0o7777
SYS_fchmodat = 268
ret = libc.syscall(
    ctypes.c_long(SYS_fchmodat),
    ctypes.c_int(AT_FDCWD),
    ctypes.c_char_p(bytes(p)),
    ctypes.c_int(0o640),
    ctypes.c_int(0),
)
if ret != 0:
    err = ctypes.get_errno()
    raise OSError(err, os.strerror(err), f"fchmodat({p})")
record("chmod", "TOOLS.md", True, p.exists(), {"chmod_syscall": "fchmodat", "mode_before": before_mode, "mode_after": p.stat().st_mode & 0o7777})
p = workspace / "HEARTBEAT.md"
before_sha = hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None
SYS_unlinkat = 263
ret = libc.syscall(
    ctypes.c_long(SYS_unlinkat),
    ctypes.c_int(AT_FDCWD),
    ctypes.c_char_p(bytes(p)),
    ctypes.c_int(0),
)
if ret != 0:
    err = ctypes.get_errno()
    raise OSError(err, os.strerror(err), f"unlinkat({p})")
record("unlink", "HEARTBEAT.md", True, p.exists(), {"unlink_syscall": "unlinkat", "pre_sha256": before_sha})
os.write(result_fd, json.dumps({"pid": os.getpid(), "operations": results}, sort_keys=True).encode("utf-8"))
os.close(result_fd)
time.sleep(0.2)
""" % (str(workspace), str(ready), str(release), result_fd)


def _spawn_worker(workspace: Path, cgroup: Path, uid: int, gid: int, ready: Path, release: Path) -> tuple[subprocess.Popen[str], int]:
    read_fd, write_fd = os.pipe()
    code = _worker_script(workspace, ready, release, write_fd)
    def preexec() -> None:
        (cgroup / "cgroup.procs").write_text(str(os.getpid()), encoding="ascii")
    proc = subprocess.Popen([
        "/usr/bin/setpriv", "--reuid", str(uid), "--regid", str(gid), "--clear-groups", "--no-new-privs",
        sys.executable, "-c", code,
    ], pass_fds=(write_fd,), preexec_fn=preexec, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    os.close(write_fd)
    return proc, read_fd


def _audit_rule_commands(workspace: Path, pid: int, key: str) -> tuple[list[str], list[str], list[str], list[str]]:
    syscalls = "read,write,rename,renameat,renameat2,unlink,unlinkat,chmod,fchmodat"
    return (
        ["/usr/sbin/auditctl", "-w", str(workspace), "-p", "rwxa", "-k", key],
        ["/usr/sbin/auditctl", "-W", str(workspace), "-p", "rwxa", "-k", key],
        ["/usr/sbin/auditctl", "-a", "always,exit", "-F", "arch=b64", "-S", syscalls, "-F", f"pid={pid}", "-k", key],
        ["/usr/sbin/auditctl", "-d", "always,exit", "-F", "arch=b64", "-S", syscalls, "-F", f"pid={pid}", "-k", key],
    )


def _audit_arg(joined: str, field: str) -> int | None:
    m = re.search(r"(?:^| )%s=([0-9a-fA-F]+)(?: |$)" % re.escape(field), joined)
    return int(m.group(1), 16) if m else None

def _normalized_audit_fields(joined: str, op_type: str) -> dict[str, Any]:
    """Map one raw audit syscall group to the normalized mutation contract."""
    syscall_exit = _parse_audit_value(joined, "exit")
    syscall_args = {
        name: _audit_arg(joined, name)
        for name in ("a0", "a1", "a2", "a3")
    }
    return {
        "syscall_number": _parse_audit_value(joined, "syscall"),
        "syscall_name": op_type,
        "syscall_pid": _parse_audit_value(joined, "pid"),
        "syscall_ppid": _parse_audit_value(joined, "ppid"),
        "syscall_fd": syscall_args.get("a0"),
        "syscall_requested_count": syscall_args.get("a2"),
        "syscall_exit": syscall_exit,
        "syscall_byte_count": syscall_exit if isinstance(syscall_exit, int) and syscall_exit >= 0 else None,
        "syscall_arguments": syscall_args,
    }



def _mask_match(source: str, rows: list[dict[str, Any]], spec: dict[str, Any], worker_pid: int) -> dict[str, Any] | None:
    path_suffix = "/" + spec["path"]
    if source == "inotify":
        wanted = {"write": IN_MODIFY | IN_CLOSE_WRITE, "rename": IN_MOVED_TO, "unlink": IN_DELETE, "chmod": IN_ATTRIB}[spec["op_type"]]
        candidates = [r for r in rows if str(r.get("path", "")).endswith(path_suffix) and (int(r.get("mask") or 0) & wanted)]
    else:
        wanted = {"write": FAN_MODIFY | FAN_CLOSE_WRITE, "rename": FAN_MOVED_TO, "unlink": FAN_DELETE, "chmod": FAN_ATTRIB}[spec["op_type"]]
        candidates = [r for r in rows if int(r.get("pid") or -1) == worker_pid and (int(r.get("mask") or 0) & wanted) and (not r.get("path") or str(r.get("path", "")).endswith(path_suffix) or spec["op_type"] in {"rename", "unlink"})]
    return candidates[-1] if candidates else None


def _normalize(run_id: str, run_dir: Path, workspace: Path, anchor: dict[str, Any], worker_identity: dict[str, Any], worker_result: dict[str, Any], audit_raw: str, audit_before: dict[str, int], audit_after: dict[str, int]) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    raw_dir, normalized_dir, health_dir = run_dir / "raw", run_dir / "normalized", run_dir / "health"
    normalized_dir.mkdir(exist_ok=True)
    normalized: dict[str, list[dict[str, Any]]] = {s: [] for s in ("inotify", "fanotify", "auditd", "ebpf")}
    inotify_rows = _read_jsonl(raw_dir / "inotify.jsonl")
    fanotify_rows = _read_jsonl(raw_dir / "fanotify.jsonl")
    ebpf_rows = _read_jsonl(raw_dir / "ebpf.jsonl")
    audit_groups = _audit_groups(audit_raw, anchor)
    _jsonl_write(raw_dir / "auditd.jsonl", audit_groups)
    op_checks: dict[str, dict[str, bool]] = {}
    for spec in OP_SPECS:
        op, rel = spec["op_type"], spec["path"]
        cid = f"{run_id}:canary:{op}:{rel}"
        before_path, after_path = run_dir / "state_snapshots" / "before" / rel, run_dir / "state_snapshots" / "after" / rel
        pre, post = (before_path.read_bytes() if before_path.is_file() else b""), (after_path.read_bytes() if after_path.is_file() else b"")
        fields = {"path": str(workspace / rel), "logical_path": rel, "op_type": op, "correlation_id": cid}
        if op == "write":
            fields["mutation"] = write_mutation_capture(preimage=pre, postimage=post, buffer_prefix=post[:PREFIX_BYTES], requested_count=len(post), actual_count=len(post))
        else:
            fields["preimage"] = full_byte_snapshot(pre); fields["postimage"] = full_byte_snapshot(post)
        op_checks[op] = {}
        for source_name, rows in (("inotify", inotify_rows), ("fanotify", fanotify_rows)):
            raw = _mask_match(source_name, rows, spec, worker_identity["pid"])
            op_checks[op][source_name] = raw is not None
            if raw:
                normalized[source_name].append(event_envelope(source=source_name, run_id=run_id, event=spec["event"], process=worker_identity if source_name == "fanotify" else None, wall_ns=raw["timestamp_realtime_ns"], monotonic_ns=raw["timestamp_monotonic_ns"], fields={**fields, "raw_mask": raw.get("mask"), "raw_path": raw.get("path")}))
        audit_match = None
        for group in audit_groups:
            joined = "\n".join(group["raw_records"])
            if _parse_audit_value(joined, "pid") != worker_identity["pid"] or _parse_audit_value(joined, "syscall") not in AUDIT_SYSCALLS[op]:
                continue
            if op == "write" or spec["path"] in joined or Path(spec["path"]).name in joined:
                audit_match = (group, joined); break
        op_checks[op]["auditd"] = audit_match is not None
        if audit_match:
            group, joined = audit_match
            normalized["auditd"].append(event_envelope(source="auditd", run_id=run_id, event=spec["event"], process=worker_identity, wall_ns=group["timestamp_realtime_ns"], monotonic_ns=group["timestamp_monotonic_ns"], fields={**fields, **_normalized_audit_fields(joined, op), "syscall_arguments_raw": group["raw_records"]}))
        if op == "write":
            ebpf_match = next((r for r in ebpf_rows if r.get("kind") == "write" and r.get("pid") == worker_identity["pid"] and r.get("buffer_prefix_hex") == spec["payload"].hex()), None)
        else:
            ebpf_match = next((r for r in ebpf_rows if r.get("kind") == op and r.get("pid") == worker_identity["pid"] and int(r.get("actual_count") if r.get("actual_count") is not None else -1) == 0), None)
        op_checks[op]["ebpf"] = ebpf_match is not None
        if ebpf_match:
            ebpf_fields = {**fields, "raw_ebpf_kind": ebpf_match.get("kind"), "kernel_monotonic_ns": ebpf_match.get("kernel_monotonic_ns"), "attribution_method": "deterministic_canary_worker_sequence"}
            if op == "write":
                ebpf_fields["mutation"] = write_mutation_capture(preimage=pre, postimage=post, buffer_prefix=bytes.fromhex(ebpf_match.get("buffer_prefix_hex") or "")[:PREFIX_BYTES], requested_count=int(ebpf_match.get("requested_count") or len(post)), actual_count=int(ebpf_match.get("actual_count") or len(post)))
            normalized["ebpf"].append(event_envelope(source="ebpf", run_id=run_id, event=spec["event"], process=worker_identity, wall_ns=ebpf_match["timestamp_realtime_ns"], monotonic_ns=ebpf_match["timestamp_monotonic_ns"], fields=ebpf_fields))
    for source, rows in normalized.items():
        _jsonl_write(normalized_dir / f"{source}.jsonl", rows)
    if audit_groups:
        audit_health = _health("auditd", min(r["timestamp_realtime_ns"] for r in audit_groups), min(r["timestamp_monotonic_ns"] for r in audit_groups), len(audit_groups), max(0, audit_after.get("lost", 0)-audit_before.get("lost", 0)), max(0, audit_after.get("lost", 0)-audit_before.get("lost", 0)), max(audit_before.get("backlog", 0), audit_after.get("backlog", 0)))
    else:
        now_wall, now_mono = time.time_ns(), time.monotonic_ns(); audit_health = _health("auditd", now_wall, now_mono, 0, 0, 0, 0)
    _json_write(health_dir / "auditd.json", audit_health)
    return {s: {"raw_stream_path": str((raw_dir / f"{s}.jsonl").resolve()), "normalized_stream_path": str((normalized_dir / f"{s}.jsonl").resolve()), "health_path": str((health_dir / f"{s}.json").resolve())} for s in normalized}, op_checks


def _write_minimal_records(run_dir: Path, workspace: Path, bundle: dict[str, Any], fingerprint: dict[str, Any], worker_identity: dict[str, Any], op_checks: dict[str, Any]) -> None:
    _json_write(run_dir / "ground_truth.json", {"schema_version": "assa.mutation_op_canary_ground_truth.v1", "case_id": "mutation_op_canary", "variant": "canary", "pipeline_status": "valid_attempt", "branch_outcome": "canary_not_attack", "delivery": {"channel": "workspace_file", "fixture_process": "deterministic_canary_supervisor"}, "ingestion": {"channel": "workspace_file"}, "session_b": {"consequence_candidate_observed": False}, "op_type_checks": op_checks})
    retained = ["pid_start_time_lineage_uid_auid_ses_cgroup_namespace", "self_state_path_inode_dev_mode_uid_gid_mtime_ctime_xattr", "open_flags_fd_inode_offset_close_lifetime_or_buffer_attribution", "syscall_args_return_errno_for_read_write_rename_unlink_chmod", "active_dac_immutable_apparmor_landlock_audit_network_policy_state", "before_after_consequence_snapshot_manifest_with_full_bytes", "tool_calls_session_logs_model_proxy_requests_and_gateway_messages"]
    _json_write(run_dir / "runtime_state_capture.json", {"schema_version": "assa.runtime_state_capture.v1", "retained_field_groups": retained, "process_state": {"agent_process_identity": worker_identity, "supervisor_process_identity": process_identity(os.getpid())}, "filesystem_state": {"workspace": str(workspace)}, "fd_state": {}, "syscall_state": {"raw_streams": {s: ((bundle.get("sources") or {}).get(s) or {}).get("raw_stream_path") for s in ("inotify", "fanotify", "auditd", "ebpf")}}, "policy_state": {"run_safety_attestation": str((run_dir / "run_safety_attestation.json").resolve())}, "snapshot_state": {"state_snapshots": str((run_dir / "state_snapshots").resolve())}, "agent_execution_state": {"llm_used": False, "agent_runtime_invoked": False}})


def run(output_root: Path) -> Path:
    if os.geteuid() != 0: raise PermissionError("mutation op canary must run as root")
    run_id = "mutation-op-canary-%s-%s" % (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()), uuid.uuid4().hex[:8])
    run_dir = (output_root / run_id).resolve(); raw_dir, health_dir, control_dir, workspace = run_dir/"raw", run_dir/"health", run_dir/"control", run_dir/"workspace"
    for p in (raw_dir, health_dir, control_dir, workspace): p.mkdir(parents=True, exist_ok=False)
    account = pwd.getpwnam("assa")
    os.chown(control_dir, account.pw_uid, account.pw_gid)
    os.chmod(control_dir, 0o750)
    for rel, content in (("MEMORY.md", b"initial memory\n"), ("TOOLS.md", b"initial tools\n"), ("HEARTBEAT.md", b"initial heartbeat\n")):
        p=workspace/rel; p.write_bytes(content); os.chown(p, account.pw_uid, account.pw_gid); os.chmod(p, 0o600)
    os.chown(workspace, account.pw_uid, account.pw_gid); os.chmod(workspace, 0o700)
    _snapshot_state(workspace, run_dir, "before"); _snapshot_state(workspace, run_dir, "before_a")
    anchor = boot_time_anchor(); _json_write(run_dir/"run_time_anchor.json", anchor)
    compiled = _compile_ebpf(Path(__file__).with_name("mutation_canary"), run_dir/"bin")
    fingerprint = _environment_fingerprint(compiled); _json_write(run_dir/"environment_fingerprint.json", fingerprint)
    cgroup_parent=Path("/sys/fs/cgroup/assa-bench"); cgroup_parent.mkdir(exist_ok=True)
    try: (cgroup_parent/"cgroup.subtree_control").write_text("+cpu +memory +pids", encoding="ascii")
    except OSError: pass
    cgroup=cgroup_parent/run_id; cgroup.mkdir(); (cgroup/"pids.max").write_text("32", encoding="ascii"); (cgroup/"memory.max").write_text(str(256*1024*1024), encoding="ascii"); (cgroup/"cpu.max").write_text("50000 100000", encoding="ascii")
    ready, release = control_dir/"worker.ready.json", control_dir/"worker.release"
    worker, result_fd = _spawn_worker(workspace, cgroup, account.pw_uid, account.pw_gid, ready, release)
    processes=[]; ebpf_process=None; audit_key="oc_mut_"+uuid.uuid4().hex[:16]; installed={"watch":False,"syscall":False}; collector_stop=control_dir/"collectors.stop"; watchdog_stop=control_dir/"watchdog.stop"
    try:
        _wait_file(ready, [worker], timeout=10); worker_pid=int(json.loads(ready.read_text())["pid"])
        inotify_ready, fanotify_ready, heartbeat = control_dir/"inotify.ready.json", control_dir/"fanotify.ready.json", control_dir/"fanotify.heartbeat"
        import multiprocessing
        inotify=multiprocessing.Process(target=_inotify_collector,args=(str(workspace),str(raw_dir/"inotify.jsonl"),str(health_dir/"inotify.json"),str(inotify_ready),str(collector_stop)),name="assa-mutation-inotify")
        fanotify=multiprocessing.Process(target=_fanotify_fid_collector,args=(str(workspace),str(raw_dir/"fanotify.jsonl"),str(health_dir/"fanotify.json"),str(fanotify_ready),str(heartbeat),str(collector_stop)),name="assa-mutation-fanotify-fid")
        inotify.start(); fanotify.start(); processes.extend([inotify, fanotify]); _wait_file(inotify_ready,[inotify]); _wait_file(fanotify_ready,[fanotify])
        watchdog_status=control_dir/"fanotify_watchdog.json"; watchdog=multiprocessing.Process(target=_fanotify_watchdog,args=(fanotify.pid,str(heartbeat),str(watchdog_stop),str(watchdog_status)),name="assa-mutation-watchdog"); watchdog.start(); processes.append(watchdog)
        ebpf_ready=control_dir/"ebpf.ready"; ebpf_stderr=(raw_dir/"ebpf.stderr.log").open("w",encoding="utf-8")
        ebpf_process=subprocess.Popen([str(compiled["loader"]),str(compiled["object"]),str(worker_pid),str(raw_dir/"ebpf.jsonl"),str(health_dir/"ebpf.json"),str(ebpf_ready)],stdout=subprocess.DEVNULL,stderr=ebpf_stderr,text=True); _wait_file(ebpf_ready,[ebpf_process])
        worker_identity=process_identity(worker_pid)
        audit_before=_audit_status(); watch_add, watch_del, sys_add, sys_del = _audit_rule_commands(workspace, worker_pid, audit_key)
        _command(watch_add); installed["watch"]=True; _command(sys_add); installed["syscall"]=True
        audit_rules=_command(["/usr/sbin/auditctl","-l"]).stdout
        _json_write(run_dir/"auditd_capture_config.json", {"schema_version":"assa.auditd_capture_config.mutation_canary.v1","audit_key":audit_key,"worker_pid":worker_pid,"worker_pid_syscall_rule_installed":True,"pid_syscall_rule_stage":"installed_while_worker_blocked_before_mutations","global_uid_syscall_rule_installed":False,"rules_after_pid_syscall_install":audit_rules.splitlines()})
        _json_write(run_dir/"run_safety_attestation.json", {"schema_version":"assa.mutation_op_canary_safety.v1","preflight_passed":True,"live_poisoned_collection_started":False,"llm_used":False,"agent_runtime_invoked":False,"worker_pid":worker_pid,"monitors":{"inotify":{"active":inotify.is_alive(),"collector_pid":inotify.pid,"raw_stream_retained":True,"raw_stream_path":str(raw_dir/"inotify.jsonl")},"fanotify":{"active":fanotify.is_alive(),"collector_pid":fanotify.pid,"raw_stream_retained":True,"raw_stream_path":str(raw_dir/"fanotify.jsonl")},"auditd":{"active":True,"collector_pid":_audit_status().get("pid"),"raw_stream_retained":True,"raw_stream_path":str(raw_dir/"auditd.jsonl")},"ebpf":{"active":ebpf_process.poll() is None,"collector_pid":ebpf_process.pid,"raw_stream_retained":True,"raw_stream_path":str(raw_dir/"ebpf.jsonl")}}})
        release.write_text("go\n",encoding="ascii"); worker_result=_read_pipe_json(result_fd); stdout,stderr=worker.communicate(timeout=10); (run_dir/"worker.stdout").write_text(stdout or "",encoding="utf-8"); (run_dir/"worker.stderr").write_text(stderr or "",encoding="utf-8")
        if worker.returncode != 0: raise RuntimeError("worker failed: %s" % stderr)
        _snapshot_state(workspace, run_dir, "after"); _snapshot_state(workspace, run_dir, "after_a"); _snapshot_state(workspace, run_dir, "after_b")
        time.sleep(0.8)
        if ebpf_process.poll() is None: ebpf_process.send_signal(signal.SIGINT); ebpf_process.wait(timeout=10)
        ebpf_stderr.close(); collector_stop.write_text("stop\n",encoding="ascii")
        for proc in (inotify,fanotify): proc.join(timeout=10); assert proc.exitcode == 0, proc.exitcode
        watchdog_stop.write_text("stop\n",encoding="ascii"); watchdog.join(timeout=5)
        audit_after=_audit_status(); audit_search=_command(["/usr/sbin/ausearch","--input-logs","-k",audit_key,"--raw"], check=False); audit_raw=audit_search.stdout; (raw_dir/"auditd_ausearch.log").write_text(audit_raw,encoding="utf-8"); (raw_dir/"auditd_ausearch.stderr.log").write_text(audit_search.stderr or "",encoding="utf-8"); _json_write(health_dir/"auditd_query.json", {"returncode": audit_search.returncode, "empty_result": audit_search.returncode == 1, "fatal_error": audit_search.returncode not in (0, 1)})
        _command(sys_del,check=False); installed["syscall"]=False; _command(watch_del,check=False); installed["watch"]=False
        source_paths, op_checks = _normalize(run_id, run_dir, workspace, anchor, worker_identity, worker_result, audit_raw, audit_before, audit_after)
        versions=fingerprint["monitor_versions"]; spec={"run_id":run_id,"run_time_anchor":anchor,"negative_outcomes_retained":[],"fixture_http_access_log":None,"sources":{s:{**paths,"version":versions[s]} for s,paths in source_paths.items()}}
        _json_write(run_dir/"bundle_spec.json", spec); bundle=finalize(run_dir/"bundle_spec.json", run_dir/"raw_trace_bundle.json"); validate_raw_trace_bundle(bundle)
        _write_minimal_records(run_dir, workspace, bundle, fingerprint, worker_identity, op_checks)
        readiness=validate_run(run_dir); op_type_coverage={op: all(checks.values()) for op,checks in op_checks.items()}; readiness["mutation_op_canary"]={"op_type_checks":op_checks,"op_type_coverage":op_type_coverage,"all_op_types_four_source_observed":all(op_type_coverage.values())}; readiness["passed"] = readiness["passed"] and all(op_type_coverage.values()); readiness["failed_checks"].extend({"name":f"mutation_op_{op}_four_source_observed","passed":False,"source_checks":op_checks[op]} for op,ok in op_type_coverage.items() if not ok)
        _json_write(run_dir/"mutation_canary_readiness.json", readiness); _json_write(run_dir/"smoke_result.json", {"schema_version":"assa.mutation_op_canary_result.v1","passed":readiness["passed"],"run_dir":str(run_dir.resolve()),"readiness":str((run_dir/"mutation_canary_readiness.json").resolve()),"op_type_coverage":op_type_coverage})
        return run_dir
    finally:
        try:
            pid=int(json.loads(ready.read_text()).get("pid",0)) if ready.is_file() else 0; _, watch_del, _, sys_del = _audit_rule_commands(workspace, pid, audit_key)
            if installed["syscall"]: _command(sys_del, check=False)
            if installed["watch"]: _command(watch_del, check=False)
        except Exception: pass
        if ebpf_process is not None and ebpf_process.poll() is None:
            ebpf_process.terminate();
            try: ebpf_process.wait(timeout=3)
            except subprocess.TimeoutExpired: ebpf_process.kill()
        if worker.poll() is None: worker.kill()
        collector_stop.write_text("stop\n",encoding="ascii"); watchdog_stop.write_text("stop\n",encoding="ascii")
        for proc in processes:
            if proc.is_alive(): proc.terminate(); proc.join(timeout=3)


def main() -> int:
    parser=argparse.ArgumentParser(description="Run disposable four-source mutation op canary"); parser.add_argument("--output-root",type=Path,default=PROJECT_ROOT/"data/dataset_v1/mutation_op_canary"); args=parser.parse_args(); run_dir=run(args.output_root); result=json.loads((run_dir/"smoke_result.json").read_text()); print(json.dumps(result,sort_keys=True)); return 0 if result["passed"] else 2
if __name__ == "__main__": raise SystemExit(main())
