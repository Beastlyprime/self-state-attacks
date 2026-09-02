from __future__ import annotations

import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any, Callable

from . import SYSCALL_SCHEMA_VERSION
from .io import file_record, sha256_file


Run = Callable[..., subprocess.CompletedProcess[str]]


# ``-j`` emits named JSON fields; leading ``*`` retains events when an optional
# field is unavailable. Keep the format explicit because Sysdig's default
# display format omits most fields required by normalization.
SCAP_OUTPUT_FORMAT = " ".join([
    "*%evt.num", "%evt.rawtime", "%evt.dir", "%syscall.type",
    "%proc.pid", "%thread.tid", "%proc.ppid", "%proc.exepath", "%proc.name",
    "%user.uid", "%user.loginuid", "%group.gid", "%thread.cgroups",
    "%evt.failed", "%evt.rawres", "%evt.res",
    "%fd.num", "%fd.type", "%fd.name", "%fd.lip", "%fd.rip",
    "%fd.lport", "%fd.rport", "%fd.l4proto",
])


def _value(payload: dict[str, Any], name: str) -> Any:
    if name in payload:
        return payload[name]
    fields = payload.get("output_fields")
    if isinstance(fields, dict):
        return fields.get(name)
    return None


def _integer(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _boolean(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.lower()
        if lowered in {"true", "1", "yes"}:
            return True
        if lowered in {"false", "0", "no"}:
            return False
    return None


def _process(
    payload: dict[str, Any],
    boot_id: str,
    process_catalog: dict[str, dict[str, Any]],
    observed_starts: dict[int, str],
    incomplete_tokens: dict[int, str],
    exec_epochs: dict[int, int],
    event_number: int,
) -> dict[str, Any]:
    pid = _integer(_value(payload, "proc.pid"))
    tid = _integer(_value(payload, "thread.tid"))
    catalog = process_catalog.get(str(pid), {}) if pid is not None else {}
    start = catalog.get("process_start_time_ticks")
    start_evidence = f"proc_stat_ticks:{start}" if start is not None else None
    if start_evidence is None and pid is not None:
        start_evidence = observed_starts.get(pid)
    identity_status = "complete" if start_evidence is not None else "identity_incomplete"
    if pid is not None and start_evidence is None:
        start_evidence = incomplete_tokens.setdefault(pid, f"scap_first:{event_number}")
    epoch = exec_epochs.get(pid, 0) if pid is not None else 0
    identity_key = f"{boot_id}:{pid}:{start_evidence or f'event:{event_number}'}:{epoch}"
    return {
        "boot_id": boot_id,
        "pid": pid,
        "tid": tid,
        "ppid": _integer(_value(payload, "proc.ppid")),
        "process_start_time_ticks": start,
        "process_start_evidence": (
            start_evidence if identity_status == "complete" else None
        ),
        "exec_epoch": epoch,
        "identity_status": identity_status,
        "identity_key": identity_key,
        "exe": _value(payload, "proc.exepath") or catalog.get("exe"),
        "comm": _value(payload, "proc.name") or catalog.get("comm"),
        "uid": _integer(_value(payload, "user.uid")),
        "euid": None,
        "auid": _integer(_value(payload, "user.loginuid")),
        "gid": _integer(_value(payload, "group.gid")),
        "cgroup_records": _value(payload, "thread.cgroups"),
    }


def _resource(payload: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    fd_number = _integer(_value(payload, "fd.num"))
    fd_type = _value(payload, "fd.type")
    fd_name = _value(payload, "fd.name")
    if fd_type in {"ipv4", "ipv6", "unix"}:
        socket = {
            "fd": fd_number,
            "socket_type": fd_type,
            "name": fd_name,
            "local_address": _value(payload, "fd.lip"),
            "remote_address": _value(payload, "fd.rip"),
            "local_port": _integer(_value(payload, "fd.lport")),
            "remote_port": _integer(_value(payload, "fd.rport")),
            "protocol": _value(payload, "fd.l4proto"),
            "tuple_status": "address_observed" if fd_name else "identity_incomplete",
        }
        return None, socket
    if fd_type in {"file", "directory"} and fd_name:
        return {
            "raw_path": fd_name,
            "resolved_path": fd_name,
            "resolution_method": "scap_fd_state",
            "resolution_status": "scap_fd_state",
            "inode": None,
            "dev": None,
        }, None
    if fd_type == "pipe":
        return {
            "node_type": "pipe",
            "fd": fd_number,
            "raw_path": fd_name or None,
            "resolution_method": "scap_fd_state",
            "resolution_status": "non_file_pipe",
        }, None
    return None, None


def parse_scap_events(
    path: Path,
    *,
    run_id: str,
    boot_id: str,
    runner_uid: int | None = None,
    runner_cgroup_path: str | None = None,
    allowed_pids: set[int] | None = None,
    process_catalog: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    source_hash = sha256_file(path)
    catalog = process_catalog or {}
    rows: list[dict[str, Any]] = []
    dispositions: Counter[str] = Counter()
    malformed: list[dict[str, Any]] = []
    observed_starts: dict[int, str] = {}
    incomplete_tokens: dict[int, str] = {}
    exec_epochs: dict[int, int] = {}
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
    ):
        if not line.strip():
            dispositions["blank"] += 1
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            dispositions["malformed"] += 1
            malformed.append({"line": line_number, "error": str(exc)})
            continue
        if not isinstance(payload, dict):
            dispositions["malformed"] += 1
            malformed.append({"line": line_number, "error": "JSON event is not an object"})
            continue
        if _value(payload, "evt.dir") != "<":
            dispositions["non_exit"] += 1
            continue
        name = _value(payload, "syscall.type") or _value(payload, "evt.type")
        if not isinstance(name, str) or not name:
            dispositions["unsupported_non_syscall"] += 1
            continue
        timestamp = _integer(_value(payload, "evt.rawtime"))
        event_number = _integer(_value(payload, "evt.num"))
        if timestamp is None or event_number is None:
            dispositions["malformed"] += 1
            malformed.append({
                "line": line_number,
                "error": "completed event lacks evt.rawtime or evt.num",
            })
            continue
        process = _process(
            payload, boot_id, catalog, observed_starts, incomplete_tokens,
            exec_epochs, event_number,
        )
        if runner_uid is not None and process["uid"] != runner_uid:
            dispositions["out_of_scope_uid"] += 1
            continue
        if allowed_pids is not None and process["pid"] not in allowed_pids:
            dispositions["out_of_scope_pid"] += 1
            continue
        if runner_cgroup_path is not None:
            cgroups = process.get("cgroup_records")
            tokens = cgroups.split() if isinstance(cgroups, str) else (cgroups or [])
            if not any(
                isinstance(token, str)
                and token.split("=", 1)[-1] == runner_cgroup_path
                for token in tokens
            ):
                dispositions["out_of_scope_cgroup"] += 1
                continue
        failed = _boolean(_value(payload, "evt.failed"))
        result = _integer(_value(payload, "evt.rawres"))
        if result is None:
            result = _integer(_value(payload, "evt.res"))
        rendered_result = _value(payload, "evt.res")
        if failed is not None:
            success: bool | None = not failed
        elif result is not None:
            success = result >= 0
        elif isinstance(rendered_result, str) and rendered_result.startswith("E"):
            success = False
        else:
            success = None
        file_obj, socket_obj = _resource(payload)
        if file_obj is None and name in {"execve", "execveat"} and process.get("exe"):
            file_obj = {
                "raw_path": process["exe"],
                "resolved_path": process["exe"],
                "resolution_method": "scap_exec_path",
                "resolution_status": "scap_exec_path",
                "inode": None,
                "dev": None,
            }
        fd_number = _integer(_value(payload, "fd.num"))
        fd = None
        if fd_number is not None:
            fd = {
                "input_fd": fd_number,
                "output_fd": None,
                "dirfd": None,
                "resolution_status": (
                    file_obj["resolution_status"] if file_obj else
                    "socket_observed" if socket_obj else "unresolved"
                ),
            }
        row = {
            "schema_version": SYSCALL_SCHEMA_VERSION,
            "run_id": run_id,
            "event_id": f"{run_id}:scap:{event_number}",
            "order": {
                "merged": len(rows) + 1,
                "timestamp_realtime_ns": timestamp,
                "scap_event_number": event_number,
            },
            "scope": {
                "runner_uid": runner_uid,
                "target_cgroup_id": None,
                "scap_uid_match": runner_uid is None or process["uid"] == runner_uid,
            },
            "process": process,
            "syscall": {
                "architecture": None,
                "number": None,
                "name": name,
                "success": success,
                "return_value": result,
                "errno": -result if result is not None and result < 0 else None,
                "arguments": {},
                "arguments_raw": {"evt.args": _value(payload, "evt.args")},
            },
            "fd": fd,
            "file": file_obj,
            "paths": [],
            "socket": socket_obj,
            "transfer": None,
            "sequence_eligible": True,
            "evidence": [{
                "source": "scap",
                "raw_path": str(path.resolve()),
                "scap_event_number": event_number,
                "line": line_number,
                "raw_sha256": source_hash,
            }],
            "completeness": {
                "process_identity": process["identity_status"],
                "parent": "observed_pid_only" if process["ppid"] is not None else "missing",
                "fd": fd["resolution_status"] if fd else "not_applicable",
                "path": file_obj["resolution_status"] if file_obj else "missing",
                "socket": socket_obj["tuple_status"] if socket_obj else "not_applicable",
                "enter": "paired_by_libsinsp",
                "exit": "complete" if result is not None else "completed_result_unavailable",
            },
        }
        rows.append(row)
        dispositions["normalized_exit"] += 1
        pid = process.get("pid")
        if success and name in {"clone", "clone3", "fork", "vfork"} and result and result > 0:
            observed_starts[result] = f"scap_fork:{event_number}"
            incomplete_tokens.pop(result, None)
            exec_epochs[result] = 0
        if success and name in {"execve", "execveat"} and pid is not None:
            exec_epochs[pid] = exec_epochs.get(pid, 0) + 1
        if name in {"exit", "exit_group", "procexit"} and pid is not None:
            observed_starts.pop(pid, None)
            incomplete_tokens.pop(pid, None)
            exec_epochs.pop(pid, None)
    input_lines = sum(dispositions.values())
    accounting = {
        "schema_version": "assa.scap_decode_conservation.v1",
        "raw_lines": input_lines,
        "normalized_exit_events": len(rows),
        "dispositions": dict(dispositions),
        "malformed": malformed,
        "accounted_lines": input_lines,
        "passed": not malformed,
    }
    return rows, accounting


def decode_capture(
    capture_path: Path,
    output_path: Path,
    *,
    runner_uid: int,
    runner_cgroup_path: str | None = None,
    allowed_pids: set[int] | None = None,
    sysdig: str = "sysdig",
    runner: Run = subprocess.run,
) -> dict[str, Any]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path = output_path.with_suffix(output_path.suffix + ".stderr.log")
    scope_filter = f"evt.dir=< and user.uid={runner_uid}"
    if runner_cgroup_path is not None:
        scope_filter += f" and thread.cgroups contains \"{runner_cgroup_path}\""
    command = [
        sysdig,
        "-r",
        str(capture_path),
        "-j",
        "-p",
        SCAP_OUTPUT_FORMAT,
        scope_filter,
    ]
    result = runner(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    output_path.write_text(result.stdout, encoding="utf-8")
    stderr_path.write_text(result.stderr, encoding="utf-8")
    _, accounting = parse_scap_events(
        output_path,
        run_id="scap-decoder-validation",
        boot_id="identity-unavailable-during-decode",
        runner_uid=runner_uid,
        runner_cgroup_path=runner_cgroup_path,
        allowed_pids=allowed_pids,
    )
    invalid_reasons: list[str] = []
    if result.returncode != 0:
        invalid_reasons.append(f"decoder_exit={result.returncode}")
    if not accounting["passed"]:
        invalid_reasons.append("decoder_output_malformed")
    if accounting["normalized_exit_events"] == 0:
        invalid_reasons.append("decoder_output_has_no_completed_in_scope_syscalls")
    return {
        "schema_version": "assa.scap_decoder.v1",
        "command": command,
        "exit_status": result.returncode,
        "capture": file_record(capture_path),
        "events": file_record(output_path),
        "stderr": file_record(stderr_path),
        "conservation": accounting,
        "allowed_pids": sorted(allowed_pids) if allowed_pids is not None else None,
        "valid": not invalid_reasons,
        "invalid_reasons": invalid_reasons,
    }
