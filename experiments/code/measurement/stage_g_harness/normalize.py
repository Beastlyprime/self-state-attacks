from __future__ import annotations

import argparse
import copy
import hashlib
import ipaddress
import json
import posixpath
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import (
    HARNESS_SCHEMA_VERSION,
    PROVENANCE_EDGE_SCHEMA_VERSION,
    PROVENANCE_NODE_SCHEMA_VERSION,
    SYSCALL_SCHEMA_VERSION,
)
from .external import git_head
from .io import read_jsonl, sha256_file, write_json, write_jsonl
from .scap import parse_scap_events


# Linux x86_64 numbers used by the frozen collector. The audit manifest records
# the architecture; unknown architectures keep the number and mark the name
# unsupported rather than guessing.
X86_64_SYSCALLS = {
    0: "read", 1: "write", 2: "open", 3: "close", 8: "lseek", 9: "mmap", 11: "munmap", 26: "msync",
    17: "pread64", 18: "pwrite64", 19: "readv", 20: "writev", 22: "pipe", 32: "dup",
    33: "dup2", 40: "sendfile", 41: "socket", 42: "connect", 43: "accept", 44: "sendto",
    45: "recvfrom", 46: "sendmsg", 47: "recvmsg", 48: "shutdown", 49: "bind", 50: "listen",
    53: "socketpair", 56: "clone", 57: "fork", 58: "vfork", 59: "execve", 60: "exit",
    72: "fcntl", 76: "truncate", 77: "ftruncate", 80: "chdir", 81: "fchdir", 82: "rename",
    83: "mkdir", 85: "creat", 86: "link", 87: "unlink", 88: "symlink", 89: "readlink",
    90: "chmod", 91: "fchmod", 231: "exit_group", 257: "openat",
    258: "mkdirat", 263: "unlinkat", 264: "renameat", 265: "linkat", 266: "symlinkat",
    267: "readlinkat", 268: "fchmodat", 275: "splice", 276: "tee", 278: "vmsplice",
    288: "accept4", 292: "dup3", 293: "pipe2", 295: "preadv", 296: "pwritev",
    299: "recvmmsg", 307: "sendmmsg", 316: "renameat2", 322: "execveat", 326: "copy_file_range",
    327: "preadv2", 328: "pwritev2", 435: "clone3", 436: "close_range", 437: "openat2", 452: "fchmodat2",
}

AARCH64_SYSCALLS = {
    23: "dup", 24: "dup3", 25: "fcntl", 35: "unlinkat", 36: "symlinkat",
    37: "linkat", 38: "renameat", 45: "truncate", 46: "ftruncate", 49: "chdir",
    50: "fchdir", 52: "fchmod", 53: "fchmodat", 56: "openat", 57: "close",
    59: "pipe2", 63: "read", 64: "write", 65: "readv", 66: "writev",
    67: "pread64", 68: "pwrite64", 69: "preadv", 70: "pwritev", 71: "sendfile",
    75: "vmsplice", 76: "splice", 77: "tee", 78: "readlinkat", 93: "exit",
    94: "exit_group", 198: "socket", 199: "socketpair", 200: "bind", 201: "listen",
    202: "accept", 203: "connect", 206: "sendto", 207: "recvfrom", 210: "shutdown",
    211: "sendmsg", 212: "recvmsg", 215: "munmap", 220: "clone", 221: "execve",
    222: "mmap", 227: "msync", 242: "accept4", 243: "recvmmsg", 269: "sendmmsg",
    276: "renameat2", 281: "execveat", 285: "copy_file_range", 286: "preadv2",
    287: "pwritev2", 435: "clone3", 436: "close_range", 437: "openat2",
    452: "fchmodat2",
}
AUDIT_ARCH_SYSCALLS = {"c000003e": X86_64_SYSCALLS, "c00000b7": AARCH64_SYSCALLS}
PROJECT_ROOT = Path(__file__).resolve().parents[4]
OBSERVATION_GENERATION_SCHEMA_VERSION = "assa.observation_generation.v1"


def build_observation_generation(contract: dict[str, Any]) -> dict[str, Any]:
    """Return a content-addressed observation-generation manifest."""
    if not isinstance(contract, dict) or not contract:
        raise ValueError("observation generation contract must be a nonempty object")
    canonical = json.dumps(
        contract, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return {
        "schema_version": OBSERVATION_GENERATION_SCHEMA_VERSION,
        "status": "frozen",
        "generation_id": f"sha256:{hashlib.sha256(canonical).hexdigest()}",
        "contract": copy.deepcopy(contract),
    }


def legacy_unspecified_generation() -> dict[str, Any]:
    """Return an explicit, deliberately non-comparable legacy stamp."""
    return {
        "schema_version": OBSERVATION_GENERATION_SCHEMA_VERSION,
        "status": "legacy_unspecified",
        "generation_id": None,
        "contract": None,
    }


def validate_observation_generation(manifest: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise ValueError("observation generation manifest must be an object")
    if manifest.get("schema_version") != OBSERVATION_GENERATION_SCHEMA_VERSION:
        raise ValueError("unsupported observation generation schema")
    if manifest.get("status") == "legacy_unspecified":
        return legacy_unspecified_generation()
    if manifest.get("status") != "frozen":
        raise ValueError("observation generation is not frozen")
    expected = build_observation_generation(manifest.get("contract"))
    if manifest.get("generation_id") != expected["generation_id"]:
        raise ValueError("observation generation id does not match its contract")
    return expected


def require_same_observation_generation(*manifests: dict[str, Any]) -> str:
    """Return the shared ID or reject legacy/mixed-generation comparison."""
    validated = [validate_observation_generation(item) for item in manifests]
    generation_ids = [item["generation_id"] for item in validated]
    if not generation_ids or any(value is None for value in generation_ids):
        raise ValueError("comparison requires frozen observation generations")
    if len(set(generation_ids)) != 1:
        raise ValueError("cross-generation comparison is forbidden")
    return generation_ids[0]



OPEN_CALLS = {"open", "openat", "openat2", "creat"}
READ_CALLS = {"read", "pread64", "readv", "preadv", "preadv2"}
WRITE_CALLS = {"write", "pwrite64", "writev", "pwritev", "pwritev2", "truncate", "ftruncate"}
DUP_CALLS = {"dup", "dup2", "dup3"}
FORK_CALLS = {"clone", "clone3", "fork", "vfork"}
EXEC_CALLS = {"execve", "execveat"}
SEND_CALLS = {"connect", "sendto", "sendmsg", "sendmmsg"}
RECV_CALLS = {"accept", "accept4", "recvfrom", "recvmsg", "recvmmsg"}
IDENTITY_RENAME_CALLS = {"rename", "renameat", "renameat2"}
RENAME_CALLS = {"rename", "renameat", "renameat2", "link", "linkat", "symlink", "symlinkat"}
REMOVE_CALLS = {"unlink", "unlinkat"}
CHMOD_CALLS = {"chmod", "fchmod", "fchmodat", "fchmodat2"}
TRANSFER_CALLS = {"sendfile", "copy_file_range", "splice", "tee", "vmsplice"}
FD_ARG0_CALLS = (
    READ_CALLS | (WRITE_CALLS - {"truncate"}) | DUP_CALLS | SEND_CALLS | RECV_CALLS
    | {"close", "close_range", "fcntl", "fchmod", "ftruncate", "fchdir", "shutdown", "bind", "listen"}
)
FD_LIFECYCLE_MUTATION_SYSCALLS = (
    OPEN_CALLS | {"close", "close_range"} | DUP_CALLS | {"fcntl"}
)


def normalization_tool_identity() -> dict[str, Any]:
    sources = [
        Path(__file__),
        Path(__file__).with_name("sidecars.py"),
    ]
    return {
        "name": "assa-stage-g-normalizer",
        "version": HARNESS_SCHEMA_VERSION,
        "commit_sha": git_head(PROJECT_ROOT),
        "python": sys.version.split()[0],
        "schemas": {
            "syscall": SYSCALL_SCHEMA_VERSION,
            "provenance_node": PROVENANCE_NODE_SCHEMA_VERSION,
            "provenance_edge": PROVENANCE_EDGE_SCHEMA_VERSION,
            "supersedes": "assa.provenance_supersedes.v1",
        },
        "source_files": [
            {"path": str(path.resolve()), "sha256": sha256_file(path)}
            for path in sources
        ],
    }


def audit_union_normalization_stamp(
    accounting: dict[str, Any],
    *,
    audit_path: Path,
    tool: dict[str, Any] | None = None,
    audit_syscall_coverage: dict[str, set[str]] | None = None,
) -> dict[str, Any]:
    if accounting.get("conservation_passed") is not True:
        raise ValueError("audit partition union is not conserved")
    declared = accounting.get("declared_keys")
    counts = accounting.get("partition_group_counts")
    if (
        not isinstance(declared, list)
        or not declared
        or not isinstance(counts, dict)
        or any(key not in counts for key in declared)
    ):
        raise ValueError("audit partition accounting omits declared keys or group counts")
    syscall_coverage = audit_syscall_coverage or {}
    undeclared_coverage = sorted(set(syscall_coverage) - set(declared))
    if undeclared_coverage:
        raise ValueError(
            f"audit syscall coverage names undeclared keys: {undeclared_coverage}"
        )
    return {
        "schema_version": "assa.normalization_input.v1",
        "audit_input_mode": "declared_key_union",
        "completeness_status": "complete_declared_union",
        "may_underestimate": False,
        "included_audit_keys": declared,
        "partition_group_counts": {key: counts[key] for key in declared},
        "audit_fd_lifecycle_coverage": {
            key: {
                "covered_syscalls": sorted(syscall_coverage.get(key, set())),
                "required_mutation_syscalls": sorted(
                    FD_LIFECYCLE_MUTATION_SYSCALLS
                ),
                "mutation_signals_observable": (
                    FD_LIFECYCLE_MUTATION_SYSCALLS
                    <= syscall_coverage.get(key, set())
                ),
                "missing_mutation_syscalls": sorted(
                    FD_LIFECYCLE_MUTATION_SYSCALLS
                    - syscall_coverage.get(key, set())
                ),
            }
            for key in declared
        },
        "union_conservation": {
            "partition_group_sum": accounting.get("partition_group_sum"),
            "union_group_count": accounting.get("union_group_count"),
            "duplicate_group_occurrences": accounting.get("duplicate_group_occurrences"),
            "identical_overlap_group_occurrences": accounting.get(
                "identical_overlap_group_occurrences", 0
            ),
            "conflicting_duplicate_groups": accounting.get(
                "conflicting_duplicate_groups", []
            ),
            "conservation_passed": True,
        },
        "audit_raw": {
            "path": str(audit_path.resolve()),
            "sha256": sha256_file(audit_path),
        },
        "tool": tool or normalization_tool_identity(),
    }


def _single_partition_normalization_stamp(
    audit_path: Path, group_count: int
) -> dict[str, Any]:
    return {
        "schema_version": "assa.normalization_input.v1",
        "audit_input_mode": "single_partition",
        "completeness_status": "single_partition_may_underestimate",
        "may_underestimate": True,
        "included_audit_keys": [],
        "partition_group_counts": {"unattributed_single_partition": group_count},
        "audit_fd_lifecycle_coverage": {},
        "union_conservation": {
            "partition_group_sum": group_count,
            "union_group_count": group_count,
            "duplicate_group_occurrences": 0,
            "identical_overlap_group_occurrences": 0,
            "conflicting_duplicate_groups": [],
            "conservation_passed": None,
        },
        "audit_raw": {
            "path": str(audit_path.resolve()),
            "sha256": sha256_file(audit_path),
        },
        "tool": normalization_tool_identity(),
    }


def _field(text: str, name: str) -> str | None:
    match = re.search(rf"(?:^|\s){re.escape(name)}=(\"(?:[^\"\\]|\\.)*\"|'[^']*'|[^\s]+)", text)
    if not match:
        return None
    value = match.group(1)
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _integer(text: str, name: str, *, base: int = 10) -> int | None:
    value = _field(text, name)
    if value is None:
        return None
    try:
        return int(value, base)
    except ValueError:
        return None


def _hex_argument(text: str, name: str) -> int | None:
    value = _field(text, name)
    if value is None:
        return None
    try:
        unsigned = int(value, 16)
    except ValueError:
        return None
    bits = max(64, len(value) * 4)
    if unsigned & (1 << (bits - 1)):
        return unsigned - (1 << bits)
    return unsigned


def _decode_audit_name(value: str | None) -> str | None:
    if value is None or value in {"(null)", "?"}:
        return None
    if re.fullmatch(r"[0-9A-Fa-f]+", value) and len(value) % 2 == 0:
        try:
            return bytes.fromhex(value).decode("utf-8", errors="surrogateescape")
        except ValueError:
            pass
    return value


@dataclass
class AuditGroup:
    serial: str
    realtime_ns: int
    lines: list[tuple[int, str]] = field(default_factory=list)

    @property
    def records(self) -> list[str]:
        return [line for _, line in self.lines]

    def records_of_type(self, record_type: str) -> list[str]:
        return [line for _, line in self.lines if _field(line, "type") == record_type or line.startswith(f"type={record_type} ")]


def parse_audit_groups(path: Path) -> tuple[list[AuditGroup], list[dict[str, Any]]]:
    groups: dict[str, AuditGroup] = {}
    order: list[str] = []
    malformed: list[dict[str, Any]] = []
    pattern = re.compile(r"msg=audit\((\d+(?:\.\d+)?):(\d+)\)")
    for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        match = pattern.search(line)
        if not match:
            if line.strip() and not line.startswith("----"):
                malformed.append({"line": line_number, "reason": "missing_audit_serial"})
            continue
        serial = match.group(2)
        if serial not in groups:
            groups[serial] = AuditGroup(serial, int(float(match.group(1)) * 1_000_000_000))
            order.append(serial)
        groups[serial].lines.append((line_number, line))
    return [groups[serial] for serial in order], malformed


def _audit_paths(group: AuditGroup) -> list[dict[str, Any]]:
    cwd = None
    for line in group.records:
        if line.startswith("type=CWD "):
            cwd = _decode_audit_name(_field(line, "cwd"))
            break
    paths = []
    for line in group.records:
        if not line.startswith("type=PATH "):
            continue
        raw_name = _decode_audit_name(_field(line, "name"))
        resolved = raw_name
        status = "audit_absolute" if raw_name and raw_name.startswith("/") else "audit_relative"
        if raw_name and cwd and not raw_name.startswith("/"):
            resolved = str(Path(cwd) / raw_name)
            status = "cwd_lexical_join"
        paths.append({
            "item": _integer(line, "item"), "nametype": _field(line, "nametype"),
            "raw_path": raw_name, "resolved_path": resolved, "cwd": cwd,
            "dev": _field(line, "dev"), "inode": _integer(line, "inode"),
            "mode": _field(line, "mode"), "resolution_status": status,
        })
    return sorted(paths, key=lambda row: row["item"] if row["item"] is not None else 10**9)


def _socket_record(group: AuditGroup) -> dict[str, Any] | None:
    for line in group.records:
        if line.startswith("type=SOCKADDR "):
            raw = _field(line, "saddr")
            record: dict[str, Any] = {"saddr_raw": raw, "tuple_status": "raw_sockaddr_only"}
            try:
                data = bytes.fromhex(raw or "")
                family = int.from_bytes(data[:2], "little")
                record["family"] = family
                if family == 2 and len(data) >= 8:
                    record.update({"address": str(ipaddress.ip_address(data[4:8])),
                                   "port": int.from_bytes(data[2:4], "big"),
                                   "tuple_status": "address_observed"})
                elif family == 10 and len(data) >= 24:
                    record.update({"address": str(ipaddress.ip_address(data[8:24])),
                                   "port": int.from_bytes(data[2:4], "big"),
                                   "scope_id": int.from_bytes(data[24:28], "little") if len(data) >= 28 else None,
                                   "tuple_status": "address_observed"})
                elif family == 1 and len(data) > 2:
                    record.update({"unix_path": data[2:].rstrip(b"\0").decode("utf-8", errors="replace"),
                                   "tuple_status": "address_observed"})
            except (ValueError, TypeError):
                pass
            return record
    return None


class Normalizer:
    def __init__(self, *, run_id: str, boot_id: str, runner_uid: int | None = None, cgroup_id: int | None = None,
                 process_catalog: dict[str, dict[str, Any]] | None = None,
                 runner_cgroup_path: str | None = None):
        self.run_id = run_id
        self.boot_id = boot_id
        self.runner_uid = runner_uid
        self.cgroup_id = cgroup_id
        self.process_catalog = process_catalog or {}
        self.runner_cgroup_path = runner_cgroup_path
        self.fd_tables: dict[str, dict[int, dict[str, Any]]] = defaultdict(dict)
        self.exec_epochs: dict[str, int] = defaultdict(int)
        self.observed_process_starts: dict[int, str] = {}

    def _process(self, pid: int | None, syscall_line: str, ppid: int | None) -> dict[str, Any]:
        catalog = self.process_catalog.get(str(pid), {}) if pid is not None else {}
        start = catalog.get("process_start_time_ticks")
        start_evidence = f"proc_stat_ticks:{start}" if start is not None else self.observed_process_starts.get(pid)
        base = f"{self.boot_id}:{pid}:{start_evidence or 'unknown'}"
        epoch = self.exec_epochs[base]
        return {
            "boot_id": self.boot_id, "pid": pid, "tid": _integer(syscall_line, "tid"), "ppid": ppid,
            "process_start_time_ticks": start, "exec_epoch": epoch,
            "process_start_evidence": start_evidence,
            "identity_status": "complete" if start_evidence is not None else "identity_incomplete",
            "identity_key": f"{base}:{epoch}",
            "exe": _decode_audit_name(_field(syscall_line, "exe")) or catalog.get("exe"),
            "comm": _decode_audit_name(_field(syscall_line, "comm")) or catalog.get("comm"),
            "uid": _integer(syscall_line, "uid"), "euid": _integer(syscall_line, "euid"),
            "auid": _integer(syscall_line, "auid"), "gid": _integer(syscall_line, "gid"),
            "cgroup_records": catalog.get("cgroup_records"),
        }

    def normalize_group(self, group: AuditGroup, raw_path: Path, source_hash: str, order: int) -> tuple[dict[str, Any] | None, str]:
        syscall_lines = [line for line in group.records if line.startswith("type=SYSCALL ")]
        if not syscall_lines:
            return None, "unsupported_non_syscall"
        if len(syscall_lines) != 1:
            return None, "malformed_multiple_syscall_records"
        line = syscall_lines[0]
        arch = _field(line, "arch")
        number = _integer(line, "syscall")
        name = AUDIT_ARCH_SYSCALLS.get(arch, {}).get(number)
        if name is None:
            name = f"syscall_{number}" if number is not None else "unknown"
        pid, ppid = _integer(line, "pid"), _integer(line, "ppid")
        process = self._process(pid, line, ppid)
        args = {f"a{i}": _hex_argument(line, f"a{i}") for i in range(6)}
        result = _integer(line, "exit")
        success_field = _field(line, "success")
        success = success_field in {"yes", "1"} if success_field is not None else (result is not None and result >= 0)
        paths = _audit_paths(group)
        fd: dict[str, Any] | None = None
        target_paths = [path for path in paths if path.get("nametype") != "PARENT"]
        file_obj: dict[str, Any] | None = (
            copy.deepcopy(target_paths[-1] if target_paths else paths[-1])
            if paths else None
        )
        if name in RENAME_CALLS and len(paths) >= 2:
            file_obj = {
                **copy.deepcopy(paths[0]),
                "before": copy.deepcopy(paths[0]),
                "after": copy.deepcopy(paths[-1]),
            }
        socket_obj = _socket_record(group)
        table = self.fd_tables[process["identity_key"]]
        transfer: dict[str, Any] | None = None
        input_fd = args["a0"] if name in FD_ARG0_CALLS else None

        if name in OPEN_CALLS:
            dirfd = args["a0"] if name in {"openat", "openat2"} else None
            flags = args["a1"] if name == "open" else args["a2"] if name == "openat" else None
            close_on_exec = bool(flags & 0x80000) if flags is not None else None
            fd = {"input_fd": None, "output_fd": result if success else None, "dirfd": dirfd,
                  "resolution_status": file_obj.get("resolution_status") if file_obj else "unresolved",
                  "close_on_exec": close_on_exec}
            if success and result is not None:
                opened = dict(file_obj or {"node_type": "file_unknown", "resolution_status": "unresolved"})
                opened["close_on_exec"] = close_on_exec
                table[result] = opened
        elif input_fd is not None:
            resolved = table.get(input_fd)
            fd = {"input_fd": input_fd, "output_fd": None, "dirfd": None,
                  "resolution_status": "fd_table" if resolved else "unresolved"}
            if file_obj is None and resolved:
                if resolved.get("node_type") == "socket":
                    socket_obj = {**resolved, **(socket_obj or {})}
                else:
                    file_obj = dict(resolved)
            if name == "close" and success:
                table.pop(input_fd, None)
            elif name == "close_range" and success and args["a1"] is not None:
                for current in list(table):
                    if input_fd <= current <= args["a1"]:
                        if args["a2"] is not None and args["a2"] & 0x4:
                            table[current] = {**table[current], "close_on_exec": True}
                        else:
                            table.pop(current, None)
            elif name in DUP_CALLS and success and result is not None:
                if resolved:
                    duplicated = dict(resolved)
                    duplicated["close_on_exec"] = bool(name == "dup3" and args["a2"] and args["a2"] & 0x80000)
                    table[result] = duplicated
                fd["output_fd"] = result
            elif name == "fcntl" and success and args["a1"] in {0, 1030} and result is not None:
                if resolved:
                    duplicated = dict(resolved)
                    duplicated["close_on_exec"] = args["a1"] == 1030
                    table[result] = duplicated
                fd["output_fd"] = result

        if name == "socket" and success and result is not None:
            close_on_exec = bool(args["a1"] is not None and args["a1"] & 0x80000)
            socket_obj = {"fd": result, "family": args["a0"], "socket_type": args["a1"],
                          "protocol": args["a2"], "socket_key": f"{process['identity_key']}:fd:{result}",
                          "tuple_status": "identity_incomplete", "close_on_exec": close_on_exec}
            table[result] = {"node_type": "socket", **socket_obj}
            fd = {"input_fd": None, "output_fd": result, "dirfd": None,
                  "resolution_status": "socket_created", "close_on_exec": close_on_exec}
        elif name in SEND_CALLS | RECV_CALLS and input_fd is not None:
            known = table.get(input_fd)
            if known and known.get("node_type") == "socket":
                socket_obj = {**known, **(socket_obj or {})}
                if name.startswith("accept") and success and result is not None:
                    accepted = {**socket_obj, "fd": result,
                                "socket_key": f"{process['identity_key']}:fd:{result}",
                                "close_on_exec": bool(name == "accept4" and args["a3"] and args["a3"] & 0x80000)}
                    table[result] = {"node_type": "socket", **accepted}
                    fd["output_fd"] = result
                    socket_obj = accepted

        if name in TRANSFER_CALLS:
            if name == "sendfile":
                source_fd, destination_fd = args["a1"], args["a0"]
            elif name in {"copy_file_range", "splice"}:
                source_fd, destination_fd = args["a0"], args["a2"]
            elif name == "tee":
                source_fd, destination_fd = args["a0"], args["a1"]
            else:
                source_fd, destination_fd = None, args["a0"]
            transfer = {
                "source_fd": source_fd,
                "source": dict(table.get(source_fd) or {"node_type": "file_unknown", "endpoint": "source"}) if source_fd is not None else None,
                "destination_fd": destination_fd,
                "destination": dict(table.get(destination_fd) or {"node_type": "file_unknown", "endpoint": "destination"}),
            }

        if name in EXEC_CALLS and success:
            base = process["identity_key"].rsplit(":", 1)[0]
            next_epoch = self.exec_epochs[base] + 1
            next_key = f"{base}:{next_epoch}"
            self.fd_tables[next_key] = {
                fd_number: dict(value) for fd_number, value in table.items() if not value.get("close_on_exec")
            }
            if file_obj and file_obj.get("resolved_path"):
                process["exe"] = file_obj["resolved_path"]
            self.exec_epochs[base] = next_epoch
            process["exec_epoch"], process["identity_key"] = next_epoch, next_key

        event_id = f"{self.run_id}:audit:{group.serial}"
        first_line, last_line = group.lines[0][0], group.lines[-1][0]
        row = {
            "schema_version": SYSCALL_SCHEMA_VERSION, "run_id": self.run_id, "event_id": event_id,
            "order": {"merged": order, "timestamp_realtime_ns": group.realtime_ns, "audit_serial": group.serial},
            "scope": {"runner_uid": self.runner_uid, "target_cgroup_id": self.cgroup_id,
                      "audit_uid_match": self.runner_uid is None or process["uid"] == self.runner_uid},
            "process": process,
            "syscall": {"architecture": arch, "number": number, "name": name, "success": success,
                        "return_value": result, "errno": -result if result is not None and result < 0 else None,
                        "arguments": args, "arguments_raw": {f"a{i}": _field(line, f"a{i}") for i in range(6)}},
            "fd": fd, "file": file_obj, "paths": paths, "socket": socket_obj, "transfer": transfer,
            "sequence_eligible": False,
            "evidence": [{"source": "auditd", "raw_path": str(raw_path.resolve()),
                          "audit_serial": group.serial, "line_start": first_line, "line_end": last_line,
                          "raw_sha256": source_hash, "audit_key": _field(line, "key")}],
            "completeness": {
                "process_identity": process["identity_status"],
                "parent": "observed_pid_only" if ppid is not None else "missing",
                "fd": fd["resolution_status"] if fd else "not_applicable",
                "path": file_obj.get("resolution_status", "unresolved") if file_obj else "missing",
                "socket": socket_obj.get("tuple_status", "incomplete") if socket_obj else "not_applicable",
                "enter": "arguments_from_audit_context", "exit": "complete" if result is not None else "missing",
            },
        }

        if name in FORK_CALLS and success and result and result > 0:
            start_evidence = f"audit_fork:{group.serial}"
            self.observed_process_starts[result] = start_evidence
            child_base = f"{self.boot_id}:{result}:{start_evidence}"
            child_key = f"{child_base}:0"
            shares_files = name == "clone" and args["a0"] is not None and bool(args["a0"] & 0x400)
            self.fd_tables[child_key] = table if shares_files else {
                fd_number: dict(value) for fd_number, value in table.items()
            }
        return row, "normalized"

    def normalize(
        self,
        audit_path: Path,
        output_dir: Path,
        ebpf_path: Path | None = None,
        scap_events_path: Path | None = None,
        audit_input_stamp: dict[str, Any] | None = None,
        fanotify_events_path: Path | None = None,
        observation_generation: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        groups, malformed = parse_audit_groups(audit_path)
        source_hash = sha256_file(audit_path)
        input_stamp = copy.deepcopy(audit_input_stamp) if audit_input_stamp else (
            _single_partition_normalization_stamp(audit_path, len(groups))
        )
        if input_stamp.get("schema_version") != "assa.normalization_input.v1":
            raise ValueError("unsupported normalization input stamp")
        if input_stamp.get("audit_raw", {}).get("sha256") != source_hash:
            raise ValueError("normalization input stamp does not match audit raw")
        if (
            input_stamp.get("audit_input_mode") == "declared_key_union"
            and input_stamp.get("union_conservation", {}).get("conservation_passed") is not True
        ):
            raise ValueError("normalization refuses an unconserved audit union")
        existing_generation = input_stamp.get("observation_generation")
        if existing_generation is not None and observation_generation is not None:
            require_same_observation_generation(existing_generation, observation_generation)
            generation = validate_observation_generation(observation_generation)
        elif existing_generation is not None:
            generation = validate_observation_generation(existing_generation)
        elif observation_generation is not None:
            generation = validate_observation_generation(observation_generation)
        else:
            generation = legacy_unspecified_generation()
        input_stamp["observation_generation"] = generation

        audit_rows: list[dict[str, Any]] = []
        dispositions = Counter()
        for order, group in enumerate(groups, 1):
            row, disposition = self.normalize_group(group, audit_path, source_hash, order)
            dispositions[disposition] += 1
            if row is not None:
                audit_rows.append(row)

        scap_accounting = None
        correlation_accounting = None
        rows = audit_rows
        if scap_events_path is not None:
            scap_rows, scap_accounting = parse_scap_events(
                scap_events_path,
                run_id=self.run_id,
                boot_id=self.boot_id,
                runner_uid=self.runner_uid,
                runner_cgroup_path=self.runner_cgroup_path,
                process_catalog=self.process_catalog,
            )
            rows, correlation_accounting = self._merge_scap_audit(scap_rows, audit_rows)

        ebpf_accounting = self._correlate_ebpf(rows, ebpf_path) if ebpf_path else None
        # After eBPF so sched_fork evidence wins; fanotify only fills what is still
        # unknown. Before fd-lifecycle enrichment so process identity is settled first.
        fanotify_accounting = (
            self._correlate_fanotify(rows, fanotify_events_path)
            if fanotify_events_path else None
        )
        input_stamp["evidence_sources"] = sorted(
            {"auditd"}
            | ({"scap"} if scap_events_path else set())
            | ({"ebpf"} if ebpf_path else set())
            | ({"fanotify"} if fanotify_events_path else set())
        )
        input_stamp["fanotify_correlation"] = fanotify_accounting
        fd_lifecycle_identity = _enrich_fd_lifecycle_file_identities(
            rows, input_stamp.get("audit_fd_lifecycle_coverage") or {}
        )
        input_stamp["fd_lifecycle_identity_outcome"] = fd_lifecycle_identity
        _enrich_file_identities(rows)
        output_dir.mkdir(parents=True, exist_ok=True)
        write_jsonl(output_dir / "syscalls.jsonl", rows)
        graph = ProvenanceBuilder(self.run_id).build(rows)
        write_jsonl(output_dir / "provenance.nodes.jsonl", graph["nodes"])
        write_jsonl(output_dir / "provenance.edges.jsonl", graph["edges"])
        write_json(output_dir / "provenance.supersedes.json", graph["supersedes"])
        coverage = build_coverage(rows, graph, malformed)
        coverage["normalization_input"] = input_stamp
        coverage["fd_lifecycle_identity"] = fd_lifecycle_identity
        coverage["fanotify_correlation"] = fanotify_accounting
        audit_conserved = len(groups) == sum(dispositions.values())
        scap_conserved = scap_accounting is None or scap_accounting["passed"]
        ebpf_conserved = (
            ebpf_accounting is None
            or ebpf_accounting["accounted_events"] == ebpf_accounting["raw_events"]
        )
        conservation = {
            "schema_version": "assa.trace_conservation.v2",
            "raw_audit_groups": len(groups),
            "dispositions": dict(dispositions),
            "malformed_unserialed_lines": malformed,
            "accounted_groups": sum(dispositions.values()),
            "scap": scap_accounting,
            "audit_scap_correlation": correlation_accounting,
            "ebpf_lifecycle": ebpf_accounting,
            "fanotify": fanotify_accounting,
            "normalization_input": input_stamp,
            "provenance_schema": coverage["provenance_schema"],
            "passed": (
                audit_conserved and scap_conserved and ebpf_conserved
                and (fanotify_accounting is None or fanotify_accounting["passed"])
            ),
        }
        write_json(output_dir / "normalization_input.json", input_stamp)
        write_json(output_dir / "coverage.json", coverage)
        write_json(output_dir / "conservation.json", conservation)
        return {"syscalls": rows, "graph": graph, "coverage": coverage, "conservation": conservation}

    @staticmethod
    def _merge_syscall_name(name: str | None) -> str | None:
        aliases = {
            "pread": "pread64",
            "pwrite": "pwrite64",
        }
        return aliases.get(name or "", name)

    @staticmethod
    def _merge_scap_audit(
        scap_rows: list[dict[str, Any]], audit_rows: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        used_audit: set[int] = set()
        merged_rows: list[dict[str, Any]] = []
        ambiguous_scap: list[str] = []
        for scap in scap_rows:
            scap_thread = scap["process"].get("tid") or scap["process"].get("pid")
            candidates: list[tuple[int, int, dict[str, Any]]] = []
            for index, audit in enumerate(audit_rows):
                if index in used_audit:
                    continue
                audit_thread = audit["process"].get("tid") or audit["process"].get("pid")
                if scap_thread != audit_thread:
                    continue
                if (
                    Normalizer._merge_syscall_name(scap["syscall"]["name"])
                    != Normalizer._merge_syscall_name(audit["syscall"]["name"])
                ):
                    continue
                scap_result = scap["syscall"].get("return_value")
                audit_result = audit["syscall"].get("return_value")
                if (
                    scap_result is not None
                    and audit_result is not None
                    and scap_result != audit_result
                ):
                    continue
                scap_fd = (scap.get("fd") or {}).get("input_fd")
                audit_fd = (audit.get("fd") or {}).get("input_fd")
                if scap_fd is not None and audit_fd is not None and scap_fd != audit_fd:
                    continue
                if scap["syscall"]["name"] in OPEN_CALLS:
                    scap_paths = _observed_absolute_paths(scap)
                    audit_paths = _observed_absolute_paths(audit)
                    if scap_paths and audit_paths and scap_paths.isdisjoint(audit_paths):
                        continue
                delta = abs(
                    int(scap["order"]["timestamp_realtime_ns"])
                    - int(audit["order"]["timestamp_realtime_ns"])
                )
                if delta <= 100_000_000:
                    candidates.append((delta, index, audit))
            candidates.sort(key=lambda item: (item[0], item[1]))
            if not candidates:
                merged_rows.append(scap)
                continue
            if len(candidates) > 1 and candidates[0][0] == candidates[1][0]:
                scap["candidate_correlation_id"] = [
                    candidate[2]["event_id"] for candidate in candidates
                ]
                ambiguous_scap.append(scap["event_id"])
                merged_rows.append(scap)
                continue

            delta, index, audit = candidates[0]
            used_audit.add(index)
            merged = copy.deepcopy(audit)
            merged["event_id"] = scap["event_id"]
            merged["order"] = {
                **scap["order"],
                "audit_serial": audit["order"].get("audit_serial"),
            }
            merged["scope"] = {**audit["scope"], **scap["scope"]}
            merged["process"] = copy.deepcopy(audit["process"])
            for key, value in scap["process"].items():
                if merged["process"].get(key) is None and value is not None:
                    merged["process"][key] = value
            if scap["process"].get("tid") is not None:
                merged["process"]["tid"] = scap["process"]["tid"]
            if merged.get("file") is None and scap.get("file") is not None:
                merged["file"] = copy.deepcopy(scap["file"])
                merged["completeness"]["path"] = scap["completeness"].get("path", "scap_fd_state")
            if merged.get("socket") is None and scap.get("socket") is not None:
                merged["socket"] = copy.deepcopy(scap["socket"])
                merged["completeness"]["socket"] = scap["completeness"].get("socket", "scap_fd_state")
            if merged.get("fd") is not None and scap.get("fd") is not None:
                merged["fd"] = {**copy.deepcopy(merged["fd"]), **{k: v for k, v in scap["fd"].items() if v is not None}}
            merged["sequence_eligible"] = True
            merged["evidence"] = [*scap["evidence"], *audit["evidence"]]
            merged["correlation"] = {
                "status": "matched",
                "method": "thread_syscall_result_nearest_time_100ms",
                "delta_ns": delta,
                "audit_event_id": audit["event_id"],
            }
            merged_rows.append(merged)

        for index, audit in enumerate(audit_rows):
            if index not in used_audit:
                merged_rows.append(audit)
        merged_rows.sort(key=lambda row: (
            row["order"]["timestamp_realtime_ns"],
            0 if row.get("sequence_eligible") else 1,
            row["event_id"],
        ))
        for order, row in enumerate(merged_rows, 1):
            row["order"]["merged"] = order
        return merged_rows, {
            "scap_events": len(scap_rows),
            "audit_events": len(audit_rows),
            "matched_audit_events": len(used_audit),
            "unmatched_audit_events": len(audit_rows) - len(used_audit),
            "ambiguous_scap_events": ambiguous_scap,
            "sequence_eligible_events": sum(
                bool(row.get("sequence_eligible")) for row in merged_rows
            ),
        }

    @staticmethod
    def _correlate_fanotify(rows: list[dict[str, Any]], fanotify_path: Path) -> dict[str, Any]:
        """Attach fanotify event-bound evidence to already-normalized rows.

        fanotify content is obtained by the collector reading the file through the
        event fd at event time: a file pre-image bound to an access event and a
        pid. Stronger than a post-hoc snapshot that binds to no event, weaker than
        intercepting the buffer at the syscall boundary, hence ``event_bound_read``.

        Binding requires same pid, a byte-exact absolute path, and a mask
        compatible with the row's syscall. Time is both a hard admission filter
        (100 ms) and a tie-break, as the method name says.

        Allocation is global, not row-ordered. Candidate pairs are ranked by mask
        affinity first, so the syscall that produced a content-bearing event wins
        it over one that merely shares the burst -- otherwise an ``openat`` claims,
        via the OPEN bit, the MODIFY event belonging to the ``write`` beside it,
        and the write that matters ends up with no evidence at all.

        Only the pre-image fingerprint enters normalized output; bytes stay in the
        raw stream, referenced by index.
        """
        fan_rows = read_jsonl(fanotify_path)
        source_hash = sha256_file(fanotify_path)
        raw_path = str(fanotify_path.resolve())

        # Start ticks belong to the process, not the event. Keying evidence on the
        # event index mints one identity per row and fragments the process graph.
        ticks_by_pid: dict[Any, set[Any]] = defaultdict(set)
        for event in fan_rows:
            mask = event.get("mask")
            if isinstance(mask, int) and mask & 0x4000:
                continue  # overflow marker: not an observation of any process
            if event.get("timestamp_realtime_ns") is None:
                continue  # cannot be placed in time, so cannot bound anything
            pid = event.get("pid")
            ticks = (event.get("process") or {}).get("process_start_time_ticks")
            if pid is not None and ticks is not None:
                ticks_by_pid[pid].add(ticks)
        stable_ticks = {
            pid: next(iter(values))
            for pid, values in ticks_by_pid.items() if len(values) == 1
        }

        by_key: dict[tuple[Any, bytes], list[int]] = defaultdict(list)
        unusable = 0
        overflow_events = 0
        missing_timestamp = 0
        for index, event in enumerate(fan_rows):
            mask = event.get("mask")
            if isinstance(mask, int) and mask & 0x4000:
                overflow_events += 1
                continue
            pid, path = event.get("pid"), event.get("path")
            if pid is None or not isinstance(path, str) or not path.startswith("/"):
                unusable += 1
                continue
            if event.get("timestamp_realtime_ns") is None:
                missing_timestamp += 1
                continue
            by_key[(pid, path.encode("utf-8", errors="surrogateescape"))].append(index)

        # Phase 1: enumerate every admissible (row, event) pair.
        candidates: list[tuple[int, int, int, int]] = []  # rank, delta, row_index, event
        rejected_pairs: set[int] = set()
        alias_ambiguous_rows = 0
        for row_index, row in enumerate(rows):
            pid = row["process"].get("pid")
            timestamp = row["order"].get("timestamp_realtime_ns")
            if pid is None or timestamp is None:
                continue
            # Only the row's own target file may lend its path. Folding in
            # ``paths[]`` lets a pre-image of a different file be presented on
            # this row, and the emitted block could not say which file it was.
            target = row.get("file")
            if not isinstance(target, dict) or target.get("nametype") == "PARENT":
                continue
            row_paths = _byte_exact_absolute_paths(target)
            if len(row_paths) > 1:
                # Two distinct *absolute* candidates means a genuine alias, and
                # which one the event names cannot be decided here, so bind
                # neither. A relative raw_path beside an absolute resolved_path is
                # not an alias -- it is a cwd join, and only one absolute
                # candidate survives, so there is nothing to disambiguate.
                alias_ambiguous_rows += 1
                continue
            if not row_paths:
                continue
            name = row["syscall"]["name"]
            for encoded in row_paths:
                for index in by_key.get((pid, encoded), ()):
                    rank = _fanotify_binding_rank(fan_rows[index].get("mask"), name)
                    if rank is None:
                        rejected_pairs.add(index)
                        continue
                    delta = abs(
                        int(fan_rows[index]["timestamp_realtime_ns"]) - int(timestamp)
                    )
                    if delta <= 100_000_000:
                        candidates.append((rank, delta, row_index, index))

        # Phase 2. Nearest-time cannot arbitrate here: 21.6% of adjacent rows in
        # this corpus have their timestamp decreasing as the audit serial
        # increases, worst inversion 94.8 ms against a 100 ms window. A tie-break
        # resolving 0.3-3 ms differences would be operating an order of magnitude
        # below the noise floor of its own input, and it demonstrably crossed two
        # openat bindings on this data.
        #
        # So bind only where the answer does not depend on time: a row and an
        # event are joined when the row's best-ranked admissible event is unique
        # AND no other row claims that event at the same rank. Anything else is
        # recorded as ambiguous and left unbound. This trades recall for a
        # statement that survives the input's ordering being wrong.
        by_row: dict[int, list[tuple[int, int, int]]] = defaultdict(list)
        by_event: dict[int, list[tuple[int, int]]] = defaultdict(list)
        for rank, delta, row_index, index in candidates:
            by_row[row_index].append((rank, delta, index))
            by_event[index].append((rank, row_index))

        matched = 0
        preimages_linked = 0
        postimages_linked = 0
        indeterminate_relations = 0
        ambiguous_rows = 0
        rows_event_contested = 0
        for row_index in sorted(by_row):
            entries = by_row[row_index]
            best_rank = min(rank for rank, _, _ in entries)
            best = [index for rank, _, index in entries if rank == best_rank]
            if len(set(best)) != 1:
                ambiguous_rows += 1
                continue
            index = best[0]
            claimants = {r for rank, r in by_event[index] if rank == best_rank}
            if len(claimants) != 1:
                rows_event_contested += 1
                continue
            matched += 1
            row, event = rows[row_index], fan_rows[index]
            snapshot = event.get("pre_response_snapshot") or {}
            row_ts = row["order"].get("timestamp_realtime_ns")
            event_ts = event.get("timestamp_realtime_ns")
            signed_delta = (
                int(event_ts) - int(row_ts)
                if row_ts is not None and event_ts is not None else None
            )
            bound_path = (row.get("file") or {}).get("resolved_path") or (
                row.get("file") or {}).get("raw_path")

            row["evidence"].append({
                "source": "fanotify",
                "evidence_class": "event_bound_read",
                "raw_path": raw_path,
                "raw_event_index": index,
                "raw_sha256": source_hash,
                "correlation": FANOTIFY_CORRELATION_METHOD,
            })
            content = None
            if snapshot:
                # The collector snapshots at dequeue. Permission classes still
                # block the syscall, so their bytes precede it; notification
                # classes do not. But the mask alone must not decide: if the
                # event was stamped after the row's syscall already returned, the
                # "before" story is causally impossible and the relation is
                # unknown rather than asserted.
                blocking = isinstance(event.get("mask"), int) and event["mask"] & 0x30000
                if signed_delta is None:
                    relation = "indeterminate_no_timestamp"
                elif blocking and signed_delta > 0:
                    relation = "indeterminate_event_after_syscall_return"
                elif blocking:
                    relation = "before_syscall"
                else:
                    relation = "after_syscall"
                content = {
                    "sha256": snapshot.get("sha256"),
                    "bytes": snapshot.get("bytes"),
                    "complete": snapshot.get("complete"),
                    "relation_to_syscall": relation,
                    "snapshot_taken": "at_event_dequeue",
                    "content_location": {
                        "raw_path": raw_path,
                        "raw_event_index": index,
                        "field": "pre_response_snapshot.data",
                        "encoding": snapshot.get("encoding"),
                    },
                    "note": "fingerprint only; bytes remain in the raw stream by design",
                }
                if relation == "before_syscall":
                    preimages_linked += 1
                elif relation == "after_syscall":
                    postimages_linked += 1
                else:
                    indeterminate_relations += 1
            row.setdefault("correlation", {})["fanotify"] = {
                "status": "matched",
                "evidence_class": "event_bound_read",
                "raw_event_index": index,
                "path": bound_path,
                "binding_rank": best_rank,
                "signed_delta_ns": signed_delta,
                "mask": event.get("mask"),
                "mask_names": _decode_fanotify_mask(event.get("mask")),
                "timestamp_realtime_ns": event_ts,
                "content": content,
            }

        # Phase 3: process identity. Start ticks are a property of the *process*,
        # not of the event that revealed them, so they apply to every row of that
        # pid -- the same treatment proc_stat_ticks and ebpf_sched_fork already
        # get. Scoping this to rows that happened to bind an event would split one
        # process into two identities, which is the fragmentation this is meant to
        # avoid. The risk that makes pid-wide application unsafe is pid reuse, and
        # that is handled by the conflict and disagreement checks below.
        start_ticks_filled = 0
        catalog_disagreements: list[dict[str, Any]] = []
        # A pid observed once tells us nothing about rows that precede the
        # incarnation we saw, and neither guard below can see that case: the
        # conflict check needs two tick values from fanotify, the disagreement
        # check needs an existing value on rows that by construction have none.
        # So bound the fill in time -- but by the process's *start*, not by when
        # we first happened to observe it, which is much later and would reject
        # almost everything.
        #
        # start_realtime = boot_realtime + ticks/USER_HZ, where boot_realtime comes
        # from each event carrying both a monotonic and a realtime stamp. USER_HZ
        # is not assumed: candidates are tested and the tightest one that keeps
        # every derived start at or before that pid's earliest observation wins.
        # If none does, the conversion is not established and the fill is skipped
        # rather than guessed.
        boot_offsets = [
            int(event["timestamp_realtime_ns"]) - int(event["timestamp_monotonic_ns"])
            for event in fan_rows
            if event.get("timestamp_realtime_ns") is not None
            and event.get("timestamp_monotonic_ns") is not None
        ]
        earliest_observation: dict[Any, int] = {}
        for event in fan_rows:
            pid = event.get("pid")
            ts = event.get("timestamp_realtime_ns")
            ticks = (event.get("process") or {}).get("process_start_time_ticks")
            if pid is None or ts is None or ticks is None:
                continue
            if pid not in earliest_observation or int(ts) < earliest_observation[pid]:
                earliest_observation[pid] = int(ts)

        # USER_HZ is not derived: on Linux it is a fixed ABI constant of 100 for
        # /proc/pid/stat field 22, independent of CONFIG_HZ. An earlier version
        # "derived" it by taking the first of 100/250/300/1000 satisfying a
        # monotone one-sided predicate -- which every candidate satisfies, so the
        # answer came from list order, and a 10 ms error in boot_realtime silently
        # reported 250. Assert the constant and validate it instead.
        USER_HZ = 100
        implied_start: dict[Any, int] = {}
        user_hz_validated = False
        if boot_offsets and stable_ticks:
            boot_realtime = sorted(boot_offsets)[len(boot_offsets) // 2]
            derived = {
                pid: boot_realtime + (ticks * 1_000_000_000) // USER_HZ
                for pid, ticks in stable_ticks.items()
            }
            if all(
                derived[pid] <= earliest_observation.get(pid, derived[pid])
                for pid in derived
            ):
                implied_start, user_hz_validated = derived, True

        rows_before_observation = 0
        for row in rows:
            process = row["process"]
            pid = process.get("pid")
            if pid not in stable_ticks:
                continue
            ticks = stable_ticks[pid]
            existing = process.get("process_start_time_ticks")
            if existing is not None and existing != ticks:
                catalog_disagreements.append(
                    {"pid": pid, "existing_ticks": existing, "fanotify_ticks": ticks}
                )
                continue
            row_ts = row["order"].get("timestamp_realtime_ns")
            if (
                row_ts is not None and pid in implied_start
                and int(row_ts) < implied_start[pid]
            ):
                rows_before_observation += 1
                continue
            if process.get("process_start_evidence") is not None:
                continue
            evidence = f"fanotify_process_start_ticks:{ticks}"
            process["process_start_time_ticks"] = ticks
            process["process_start_evidence"] = evidence
            process["identity_status"] = "complete"
            process["identity_key"] = (
                f"{process['boot_id']}:{pid}:{evidence}:{process.get('exec_epoch', 0)}"
            )
            row["completeness"]["process_identity"] = "complete"
            start_ticks_filled += 1

        row_pids = {row["process"].get("pid") for row in rows}
        conflicting_pids = sorted(
            str(pid) for pid, values in ticks_by_pid.items()
            if len(values) > 1 and pid in row_pids
        )
        return {
            "schema_version": "assa.fanotify_correlation.v3",
            "raw_path": raw_path,
            "raw_sha256": source_hash,
            "raw_events": len(fan_rows),
            "indexable_events": sum(len(v) for v in by_key.values()),
            "unusable_events_missing_pid_or_path": unusable,
            "events_missing_timestamp": missing_timestamp,
            "matched_events": matched,
            "unmatched_events": len(fan_rows) - matched,
            "mask_incompatible_events": len(rejected_pairs - set(by_event)),
            "alias_ambiguous_rows_skipped": alias_ambiguous_rows,
            "preimages_linked": preimages_linked,
            "postimages_linked": postimages_linked,
            "indeterminate_relations": indeterminate_relations,
            "ambiguous_rows_unbound": ambiguous_rows,
            "rows_unbound_event_contested": rows_event_contested,
            "process_start_ticks_filled": start_ticks_filled,
            "process_start_ticks_conflicting_pids": conflicting_pids,
            "rows_predating_process_start": rows_before_observation,
            "user_hz": USER_HZ,
            "user_hz_validated": user_hz_validated,
            "process_start_ticks_catalog_disagreements": catalog_disagreements,
            "queue_overflow_events": overflow_events,
            "allocation": "global_rank_then_delta",
            "correlation_method": FANOTIFY_CORRELATION_METHOD,
            "evidence_class": "event_bound_read",
            # fanotify emits a burst per syscall while a row binds at most one
            # event, and watches paths the audit rules never cover, so unmatched
            # events are expected. What is NOT acceptable: the kernel reporting
            # dropped events, records we cannot index or time, a pid whose start
            # time two sources disagree on, or fanotify contradicting the catalog.
            "unmatched_reason": "per-syscall bursts exceed one event per row, plus paths outside audit rule scope",
            "accounted_events": len(fan_rows),
            "passed": (
                overflow_events == 0
                and missing_timestamp == 0
                and not conflicting_pids
                and not catalog_disagreements
                and rows_before_observation == 0
            ),
        }

    @staticmethod
    def _correlate_ebpf(rows: list[dict[str, Any]], ebpf_path: Path) -> dict[str, Any]:
        ebpf_rows = read_jsonl(ebpf_path)
        source_hash = sha256_file(ebpf_path)
        used: set[int] = set()
        kind_names = {
            "open": OPEN_CALLS, "close": {"close", "close_range"}, "dup": DUP_CALLS | {"fcntl"},
            "exec": EXEC_CALLS, "fork": FORK_CALLS, "exit": {"exit", "exit_group"},
        }
        primary_file_identities: set[tuple[Any, Any]] = set()
        observed_host_children: dict[int, str] = {}

        def lifecycle_fields_match(row: dict[str, Any], ebpf: dict[str, Any]) -> bool:
            name = row["syscall"]["name"]
            arguments = row["syscall"]["arguments"]
            ebpf_arguments = ebpf.get("args") or []
            result = row["syscall"].get("return_value")
            ebpf_result = ebpf.get("result")
            tid = row["process"].get("tid")
            if tid is not None and ebpf.get("tid") != tid:
                return False
            if name in OPEN_CALLS | {"close", "close_range"} | DUP_CALLS | {"fcntl"}:
                if ebpf_result is None or result != ebpf_result:
                    return False
            if name in OPEN_CALLS:
                ebpf_paths = {
                    normalized
                    for value in (ebpf.get("resolved_path"), ebpf.get("path"))
                    if (normalized := _normalize_absolute_path(value)) is not None
                }
                row_paths = _observed_absolute_paths(row)
                if ebpf_paths and row_paths and ebpf_paths.isdisjoint(row_paths):
                    return False
                for offset, value in enumerate(ebpf_arguments):
                    row_value = arguments.get(f"a{offset}")
                    if row_value is not None and value is not None and row_value != value:
                        return False
            if name in {"close", "close_range"}:
                row_fd = (row.get("fd") or {}).get("input_fd")
                if row_fd is not None and (not ebpf_arguments or row_fd != ebpf_arguments[0]):
                    return False
            if name in FORK_CALLS and not ebpf.get("related_pid"):
                return False
            return True

        for row in rows:
            name = row["syscall"]["name"]
            pid = row["process"].get("pid")
            timestamp = row["order"]["timestamp_realtime_ns"]
            candidates = []
            for index, ebpf in enumerate(ebpf_rows):
                if index in used or ebpf.get("pid") != pid:
                    continue
                accepted = kind_names.get(ebpf.get("kind"), set())
                ebpf_number = ebpf.get("syscall_number")
                row_number = row["syscall"].get("number")
                if name not in accepted and (row_number is None or ebpf_number != row_number):
                    continue
                if (
                    ebpf_number is not None and ebpf_number >= 0
                    and row_number is not None and ebpf_number != row_number
                ):
                    continue
                if not lifecycle_fields_match(row, ebpf):
                    continue
                delta = abs(int(ebpf.get("timestamp_realtime_ns", 0)) - int(timestamp))
                if delta <= 100_000_000:
                    candidates.append((delta, index, ebpf))
            if not candidates:
                continue
            _, index, ebpf = min(candidates)
            used.add(index)
            row["evidence"].append({
                "source": "ebpf", "raw_path": str(ebpf_path.resolve()), "raw_event_index": index,
                "raw_sha256": source_hash,
                "correlation": "pid_syscall_time_100ms_with_available_tid_fd_result",
            })
            row["scope"]["ebpf_cgroup_match"] = True
            row.setdefault("correlation", {})["ebpf_lifecycle"] = {
                "status": "matched",
                "raw_event_index": index,
                "kind": ebpf.get("kind"),
                "syscall_number": ebpf.get("syscall_number"),
                "result": ebpf.get("result"),
                "timestamp_realtime_ns": ebpf.get("timestamp_realtime_ns"),
                "args": ebpf.get("args"),
                "related_pid": ebpf.get("related_pid"),
                "pid_namespace_return_value": (
                    row["syscall"].get("return_value") if name in FORK_CALLS else None
                ),
            }
            if name in FORK_CALLS and ebpf.get("related_pid"):
                observed_host_children[int(ebpf["related_pid"])] = f"ebpf_sched_fork:{index}"
            resolved_path = ebpf.get("resolved_path")
            resolution_method = ebpf.get("resolution_method")
            if row.get("file") is None and (resolved_path or ebpf.get("path")):
                row["file"] = {
                    "raw_path": ebpf.get("path"),
                    "resolved_path": resolved_path,
                    "resolution_method": resolution_method,
                    "resolution_status": resolution_method or "ebpf_raw_path_only",
                    "inode": None,
                    "dev": None,
                }
                row["completeness"]["path"] = resolution_method or "ebpf_raw_path_only"
            elif row.get("file") is not None and name in OPEN_CALLS:
                if resolved_path:
                    row["file"]["resolved_path"] = resolved_path
                if resolution_method:
                    row["file"]["resolution_method"] = resolution_method
                    row["file"]["resolution_status"] = resolution_method
                elif row["file"].get("dev") is not None and row["file"].get("inode") is not None:
                    row["file"]["resolution_method"] = "ebpf_open_exit_audit_identity"
                if row["file"].get("dev") is not None and row["file"].get("inode") is not None:
                    primary_file_identities.add((row["file"]["dev"], row["file"]["inode"]))
        for row in rows:
            pid = row["process"].get("pid")
            if pid not in observed_host_children:
                continue
            evidence = observed_host_children[pid]
            process = row["process"]
            process["process_start_evidence"] = evidence
            process["identity_status"] = "complete"
            process["identity_key"] = (
                f"{process['boot_id']}:{pid}:{evidence}:{process.get('exec_epoch', 0)}"
            )
            row["completeness"]["process_identity"] = "complete"

        fd_tables: dict[int, dict[int, dict[str, Any]]] = defaultdict(dict)
        for row in rows:
            if not row["syscall"].get("success"):
                continue
            pid = row["process"].get("pid")
            if pid is None:
                continue
            name = row["syscall"]["name"]
            lifecycle = (row.get("correlation") or {}).get("ebpf_lifecycle") or {}
            args = lifecycle.get("args") or []
            input_fd = args[0] if args else (row.get("fd") or {}).get("input_fd")
            result = row["syscall"].get("return_value")
            table = fd_tables[pid]
            if name in OPEN_CALLS and result is not None and result >= 0:
                resource = copy.deepcopy(row.get("file") or {})
                resolved, _method = _resolved_file_operand(resource)
                if resolved:
                    table[result] = resource
            elif name in READ_CALLS | (WRITE_CALLS - {"truncate"}):
                resource = table.get(input_fd)
                if resource:
                    row["file"] = {**copy.deepcopy(resource), "resolution_method": "ebpf_fd_table",
                                   "resolution_status": "ebpf_fd_table"}
                    row["completeness"]["path"] = "ebpf_fd_table"
                    if row.get("fd") is not None:
                        row["fd"]["resolution_status"] = "ebpf_fd_table"
            elif name in DUP_CALLS | {"fcntl"} and result is not None and result >= 0:
                if input_fd in table:
                    table[result] = copy.deepcopy(table[input_fd])
            elif name == "close" and input_fd is not None:
                table.pop(input_fd, None)
            elif name in FORK_CALLS:
                child = lifecycle.get("related_pid")
                if child:
                    fd_tables[child] = {fd: copy.deepcopy(value) for fd, value in table.items()}

        for row in rows:
            file_obj = row.get("file") or {}
            identity = (file_obj.get("dev"), file_obj.get("inode"))
            if identity in primary_file_identities:
                file_obj["resolution_method"] = "ebpf_open_exit_audit_identity"
        return {
            "raw_events": len(ebpf_rows), "matched_events": len(used),
            "unmatched_retained_raw": len(ebpf_rows) - len(used), "accounted_events": len(ebpf_rows),
        }


FANOTIFY_MASKS: dict[int, str] = {
    0x1: "ACCESS", 0x2: "MODIFY", 0x4: "ATTRIB", 0x8: "CLOSE_WRITE",
    0x10: "CLOSE_NOWRITE", 0x20: "OPEN", 0x40: "MOVED_FROM", 0x80: "MOVED_TO",
    0x100: "CREATE", 0x200: "DELETE", 0x400: "DELETE_SELF", 0x800: "MOVE_SELF",
    0x1000: "OPEN_EXEC", 0x4000: "Q_OVERFLOW", 0x10000: "OPEN_PERM",
    0x20000: "ACCESS_PERM", 0x40000: "OPEN_EXEC_PERM",
}

FANOTIFY_CORRELATION_METHOD = "pid_byte_exact_path_unique_best_rank_within_100ms"

# A content pre-image may only be attached to a syscall that could plausibly have
# touched the file the way the mask reports. Ordered by affinity: a lower rank is
# a stronger claim on the event, so a `write` row outbids an `openat` row for the
# MODIFY event that the write itself produced.
FANOTIFY_MASK_SYSCALL_COMPATIBILITY: tuple[tuple[int, frozenset[str], int], ...] = (
    # Rank encodes bit specificity, not preference. A collector may merge a whole
    # burst into one record (MODIFY|CLOSE_WRITE|OPEN), and then both the opener
    # and the writer can claim it. The content-bearing bits say the file's bytes
    # changed or were read, so the syscall they name has the stronger claim;
    # OPEN/CLOSE_NOWRITE only say the file was reached.
    # Ranks are per BIT, not per semantic group, and strictly ordered. A collector
    # may merge a whole burst into one record (MODIFY|CLOSE_WRITE|OPEN); with
    # group-level ranks the write claimed it via MODIFY and the close via
    # CLOSE_WRITE at equal rank, so both were dropped as contested and the single
    # most important binding in the corpus was lost. Ordering the bits by how much
    # they say about the file's bytes settles it without consulting timestamps.
    (0x2, frozenset(WRITE_CALLS), 0),                             # MODIFY: bytes changed
    (0x1 | 0x20000, frozenset(READ_CALLS), 1),                    # ACCESS: bytes read
    (0x8, frozenset({"close", "close_range"}), 2),                # CLOSE_WRITE: close(), not write()
    (0x20 | 0x10000, frozenset(OPEN_CALLS), 3),                   # OPEN: file merely reached
    (0x10, frozenset({"close", "close_range"}), 4),               # CLOSE_NOWRITE: weakest
)
# Deliberately absent: ATTRIB, CREATE, DELETE, DELETE_SELF, MOVED_FROM, MOVED_TO,
# MOVE_SELF. Those require a FAN_REPORT_FID group, and fanotify_init(2) rejects
# FAN_REPORT_FID together with FAN_CLASS_CONTENT (EINVAL) -- which is the class
# this collector uses, because FID groups carry no event fd and so no content
# snapshot. They are impossible here, not merely unconfigured, and listing them
# would imply a coverage we cannot have. OPEN_EXEC/OPEN_EXEC_PERM are omitted for
# the weaker reason that the collector does not request them.


def _fanotify_binding_rank(mask: Any, syscall_name: str | None) -> int | None:
    """Lowest compatible rank, or None when no mask bit fits this syscall.

    Rank exists so allocation is not decided by row order: the syscall that
    actually produced a content-bearing event outbids one that merely appears
    in the same burst.
    """
    if not isinstance(mask, int) or syscall_name is None:
        return None
    ranks = [
        rank for bits, names, rank in FANOTIFY_MASK_SYSCALL_COMPATIBILITY
        if mask & bits and syscall_name in names
    ]
    return min(ranks) if ranks else None


def _fanotify_mask_matches_syscall(mask: Any, syscall_name: str | None) -> bool:
    return _fanotify_binding_rank(mask, syscall_name) is not None


def _decode_fanotify_mask(mask: Any) -> list[str]:
    """Names for the bits actually set; unknown bits are surfaced, not dropped."""
    if not isinstance(mask, int):
        return []
    names = [name for bit, name in sorted(FANOTIFY_MASKS.items()) if mask & bit]
    residual = mask & ~sum(FANOTIFY_MASKS)
    if residual:
        names.append(f"unknown_bits:{hex(residual)}")
    return names


def _normalize_absolute_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value.startswith("/"):
        return None
    return posixpath.normpath(value)


def _resource_identity_paths(resource: dict[str, Any] | None) -> set[str]:
    resource = resource or {}
    raw = _normalize_absolute_path(resource.get("raw_path"))
    resolved = _normalize_absolute_path(resource.get("resolved_path"))
    if raw is not None and resolved is not None and raw != resolved:
        return set()
    return {path for path in (resolved, raw) if path is not None}


def _observed_absolute_paths(event: dict[str, Any]) -> set[str]:
    paths: set[str] = set()
    resources = [event.get("file"), *(event.get("paths") or [])]
    for resource in resources:
        if not isinstance(resource, dict) or resource.get("nametype") == "PARENT":
            continue
        raw = _normalize_absolute_path(resource.get("raw_path"))
        resolved = _normalize_absolute_path(resource.get("resolved_path"))
        paths.update(path for path in (raw, resolved) if path is not None)
    return paths


def _byte_exact_absolute_paths(resource: dict[str, Any] | None) -> dict[bytes, str]:
    """Return absolute paths without lexical normalization or alias folding."""
    paths: dict[bytes, str] = {}
    for field_name in ("raw_path", "resolved_path"):
        value = (resource or {}).get(field_name)
        if not isinstance(value, str) or not value.startswith("/"):
            continue
        encoded = value.encode("utf-8", errors="surrogateescape")
        paths[encoded] = value
    return paths


def _audit_open_fd_binding(event: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    audit_evidence = [
        copy.deepcopy(item) for item in event.get("evidence", [])
        if item.get("source") == "auditd"
        and item.get("audit_serial") is not None
        and item.get("line_start") is not None
        and item.get("line_end") is not None
        and item.get("raw_sha256")
    ]
    if not audit_evidence:
        return None, "missing_audit_evidence"

    target_paths = _byte_exact_absolute_paths(event.get("file"))
    if len(target_paths) != 1:
        return None, "ambiguous_open_target_path"
    target_bytes, target_path = next(iter(target_paths.items()))
    candidates: dict[tuple[Any, Any], dict[str, Any]] = {}
    for resource in event.get("paths") or []:
        if not isinstance(resource, dict) or resource.get("nametype") == "PARENT":
            continue
        raw_path = resource.get("raw_path")
        dev, inode = resource.get("dev"), resource.get("inode")
        if (
            not isinstance(raw_path, str)
            or not raw_path.startswith("/")
            or dev is None
            or inode is None
        ):
            continue
        raw_bytes = raw_path.encode("utf-8", errors="surrogateescape")
        if raw_bytes != target_bytes:
            continue
        candidates[(dev, inode)] = {
            "path": target_path,
            "path_bytes_sha256": hashlib.sha256(target_bytes).hexdigest(),
            "dev": dev,
            "inode": inode,
        }
    if len(candidates) != 1:
        return None, "missing_or_conflicting_audit_path_identity"

    binding = next(iter(candidates.values()))
    binding.update({
        "open_event_id": event["event_id"],
        "open_order": event["order"].get("merged"),
        "audit_serial": event["order"].get("audit_serial"),
        "audit_evidence": audit_evidence,
    })
    return binding, "bound"


def _enrich_fd_lifecycle_file_identities(
    rows: list[dict[str, Any]],
    audit_fd_lifecycle_coverage: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Carry an audit open PATH identity across one observed FD lifetime."""
    coverage_by_key = audit_fd_lifecycle_coverage or {}
    bindings: dict[tuple[Any, Any, int], dict[str, Any]] = {}
    blocked: set[tuple[Any, Any, int]] = set()
    outcome = Counter()
    degraded_by_key = Counter()
    scap_sequence_present = any(
        item.get("source") == "scap"
        for event in rows for item in event.get("evidence", [])
    )

    def key_for(event: dict[str, Any], fd_number: Any) -> tuple[Any, Any, int] | None:
        process = event.get("process") or {}
        boot_id, pid = process.get("boot_id"), process.get("pid")
        if boot_id is None or pid is None or not isinstance(fd_number, int) or fd_number < 0:
            return None
        return boot_id, pid, fd_number

    def audit_backed(event: dict[str, Any]) -> bool:
        return any(item.get("source") == "auditd" for item in event.get("evidence", []))

    def scap_backed(event: dict[str, Any]) -> bool:
        return any(item.get("source") == "scap" for item in event.get("evidence", []))

    def audit_keys(evidence: list[dict[str, Any]]) -> set[str]:
        return {
            item["audit_key"]
            for item in evidence
            if item.get("source") == "auditd"
            and isinstance(item.get("audit_key"), str)
            and item["audit_key"]
        }

    def mutation_signals_observable(
        event: dict[str, Any], binding: dict[str, Any]
    ) -> tuple[bool, list[str], dict[str, list[str]]]:
        keys = audit_keys(binding.get("audit_evidence") or [])
        keys.update(audit_keys(event.get("evidence") or []))
        if not keys:
            return False, ["unattributed_audit_partition"], {
                "unattributed_audit_partition": sorted(FD_LIFECYCLE_MUTATION_SYSCALLS)
            }
        missing = {
            key: list(
                coverage_by_key.get(key, {}).get(
                    "missing_mutation_syscalls",
                    sorted(FD_LIFECYCLE_MUTATION_SYSCALLS),
                )
            )
            for key in sorted(keys)
        }
        missing = {key: values for key, values in missing.items() if values}
        return not missing, sorted(keys), missing

    audit_open_bindings: dict[str, tuple[dict[str, Any] | None, str]] = {}
    audit_open_candidates: dict[tuple[Any, Any, int, bytes], list[dict[str, Any]]] = defaultdict(list)
    for event in rows:
        syscall = event.get("syscall") or {}
        if (
            syscall.get("success")
            and syscall.get("name") in OPEN_CALLS
            and audit_backed(event)
        ):
            binding, status = _audit_open_fd_binding(event)
            audit_open_bindings[event["event_id"]] = (binding, status)
            output_fd = (event.get("fd") or {}).get("output_fd")
            if output_fd is None:
                output_fd = syscall.get("return_value")
            key = key_for(event, output_fd)
            if key is None or binding is None:
                continue
            lifecycle = (event.get("correlation") or {}).get("ebpf_lifecycle") or {}
            binding["lifecycle_timestamp_realtime_ns"] = (
                lifecycle.get("timestamp_realtime_ns")
                or event["order"].get("timestamp_realtime_ns")
            )
            path_bytes = binding["path"].encode("utf-8", errors="surrogateescape")
            audit_open_candidates[(*key, path_bytes)].append(binding)

    for event in rows:
        syscall = event.get("syscall") or {}
        if not syscall.get("success"):
            continue
        name = syscall.get("name")
        fd_info = event.get("fd") or {}
        arguments = syscall.get("arguments") or {}
        input_fd = fd_info.get("input_fd")
        if input_fd is None:
            input_fd = arguments.get("a0")

        if name in OPEN_CALLS:
            output_fd = fd_info.get("output_fd")
            if output_fd is None:
                output_fd = syscall.get("return_value")
            key = key_for(event, output_fd)
            if key is None:
                continue
            if key in bindings or key in blocked:
                outcome["rebound_on_successful_open"] += 1
            bindings.pop(key, None)
            blocked.discard(key)

            if audit_backed(event):
                binding, status = audit_open_bindings[event["event_id"]]
            else:
                binding, status = None, "scap_open_without_unique_audit_path_binding"
                target_paths = _byte_exact_absolute_paths(event.get("file"))
                event_timestamp = event["order"].get("timestamp_realtime_ns")
                if len(target_paths) == 1 and isinstance(event_timestamp, int):
                    target_bytes = next(iter(target_paths))
                    eligible = []
                    for candidate in audit_open_candidates.get((*key, target_bytes), []):
                        candidate_timestamp = candidate.get("lifecycle_timestamp_realtime_ns")
                        if not isinstance(candidate_timestamp, int):
                            continue
                        delta = abs(event_timestamp - candidate_timestamp)
                        if delta <= 100_000_000:
                            eligible.append((delta, candidate))
                    eligible.sort(key=lambda item: item[0])
                    if eligible and (
                        len(eligible) == 1 or eligible[0][0] < eligible[1][0]
                    ):
                        delta, selected = eligible[0]
                        binding = copy.deepcopy(selected)
                        binding["activation"] = {
                            "event_id": event["event_id"],
                            "delta_ns": delta,
                            "method": "pid_fd_exact_path_nearest_time_100ms",
                            "scap_evidence": [
                                copy.deepcopy(item) for item in event.get("evidence", [])
                                if item.get("source") == "scap"
                            ],
                        }
                        status = "bound"
                    elif eligible:
                        status = "ambiguous_scap_to_audit_open_binding"

            if binding is None:
                blocked.add(key)
                file_obj = event.get("file")
                if isinstance(file_obj, dict):
                    file_obj["fd_identity_resolution_status"] = status
            else:
                bindings[key] = copy.deepcopy(binding)
            continue

        if name == "close" and input_fd is not None:
            # SCAP is the frozen sequence spine. Audit timestamps can collapse
            # within one millisecond and otherwise move a close before its write.
            if scap_sequence_present and not scap_backed(event):
                continue
            key = key_for(event, input_fd)
            if key is not None:
                bindings.pop(key, None)
                blocked.discard(key)
            continue

        if name == "close_range" and input_fd is not None:
            if scap_sequence_present and not scap_backed(event):
                continue
            last_fd = arguments.get("a1")
            if isinstance(last_fd, int):
                process = event.get("process") or {}
                prefix = (process.get("boot_id"), process.get("pid"))
                for key in list(set(bindings) | blocked):
                    if key[:2] == prefix and input_fd <= key[2] <= last_fd:
                        bindings.pop(key, None)
                        blocked.discard(key)
            continue

        result = syscall.get("return_value")
        if name in DUP_CALLS | {"fcntl"} and input_fd is not None and isinstance(result, int) and result >= 0:
            if name == "fcntl" and arguments.get("a1") not in {0, 1030}:
                continue
            source_key = key_for(event, input_fd)
            destination_key = key_for(event, result)
            if destination_key is None:
                continue
            bindings.pop(destination_key, None)
            blocked.discard(destination_key)
            if source_key in bindings:
                bindings[destination_key] = copy.deepcopy(bindings[source_key])
            elif source_key in blocked:
                blocked.add(destination_key)
            continue

        if name not in WRITE_CALLS - {"truncate"} or input_fd is None:
            continue
        file_obj = event.get("file")
        if not isinstance(file_obj, dict):
            continue
        inherited_fd_table_identity = (
            (event.get("fd") or {}).get("resolution_status") == "fd_table"
            and not event.get("paths")
            and file_obj.get("dev") is not None
            and file_obj.get("inode") is not None
        )
        if (
            file_obj.get("dev") is not None
            and file_obj.get("inode") is not None
            and not inherited_fd_table_identity
        ):
            continue
        if inherited_fd_table_identity:
            file_obj["dev"] = None
            file_obj["inode"] = None
        key = key_for(event, input_fd)
        if key is None or key in blocked or key not in bindings:
            file_obj["fd_identity_resolution_status"] = "fd_lifecycle_no_audit_path_binding"
            continue

        binding = bindings[key]
        if not scap_backed(event):
            observable, relevant_keys, missing = mutation_signals_observable(
                event, binding
            )
            if not observable:
                outcome["degraded_missing_mutation_coverage"] += 1
                for partition_key in relevant_keys:
                    degraded_by_key[partition_key] += 1
                file_obj["fd_identity_resolution_status"] = (
                    "fd_lifecycle_missing_mutation_coverage"
                )
                file_obj["fd_identity_lifecycle_degradation"] = {
                    "reason": "audit_only_without_complete_fd_mutation_coverage",
                    "audit_partition_keys": relevant_keys,
                    "required_mutation_syscalls": sorted(
                        FD_LIFECYCLE_MUTATION_SYSCALLS
                    ),
                    "missing_mutation_syscalls_by_key": missing,
                }
                continue
        target_paths = _byte_exact_absolute_paths(file_obj)
        binding_bytes = binding["path"].encode("utf-8", errors="surrogateescape")
        if len(target_paths) != 1 or binding_bytes not in target_paths:
            bindings.pop(key, None)
            blocked.add(key)
            file_obj["fd_identity_resolution_status"] = "fd_lifecycle_path_conflict"
            continue
        if (
            file_obj.get("dev") not in {None, binding["dev"]}
            or file_obj.get("inode") not in {None, binding["inode"]}
        ):
            bindings.pop(key, None)
            blocked.add(key)
            file_obj["fd_identity_resolution_status"] = "fd_lifecycle_identity_conflict"
            continue

        write_evidence = [
            copy.deepcopy(item) for item in event.get("evidence", [])
            if item.get("source") == "scap"
        ]
        file_obj["dev"] = binding["dev"]
        file_obj["inode"] = binding["inode"]
        file_obj["identity_resolution_method"] = "fd_lifecycle_openat_path_inode"
        file_obj["fd_identity_resolution_status"] = "resolved"
        file_obj["identity_evidence"] = {
            "open_event_id": binding["open_event_id"],
            "open_order": binding["open_order"],
            "path": binding["path"],
            "path_bytes_sha256": binding["path_bytes_sha256"],
            "audit_serial": binding["audit_serial"],
            "open_audit_evidence": copy.deepcopy(binding["audit_evidence"]),
            "open_activation": copy.deepcopy(binding.get("activation")),
            "write_event_id": event["event_id"],
            "write_scap_evidence": write_evidence,
        }
        outcome["resolved"] += 1

    return {
        "schema_version": "assa.fd_lifecycle_identity_outcome.v1",
        "required_mutation_syscalls": sorted(FD_LIFECYCLE_MUTATION_SYSCALLS),
        "resolved": outcome["resolved"],
        "degraded_missing_mutation_coverage": outcome[
            "degraded_missing_mutation_coverage"
        ],
        "degraded_missing_mutation_coverage_by_key": dict(degraded_by_key),
        "rebound_on_successful_open": outcome["rebound_on_successful_open"],
    }


def _enrich_file_identities(rows: list[dict[str, Any]]) -> None:
    """Carry prior exact-path dev/inode evidence into later FD operations."""
    known: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in rows:
        resources = event.get("paths") or []
        for resource in resources:
            if not isinstance(resource, dict) or resource.get("nametype") == "PARENT":
                continue
            dev, inode = resource.get("dev"), resource.get("inode")
            if dev is None or inode is None:
                continue
            for path in _resource_identity_paths(resource):
                known[path].append({
                    "dev": dev,
                    "inode": inode,
                    "event_id": event["event_id"],
                    "order": event["order"].get("merged"),
                    "audit_serial": event["order"].get("audit_serial"),
                    "path": path,
                })

        file_obj = event.get("file")
        if not isinstance(file_obj, dict):
            continue
        if file_obj.get("dev") is not None and file_obj.get("inode") is not None:
            continue
        if file_obj.get("fd_identity_resolution_status"):
            continue
        event_serial_raw = event["order"].get("audit_serial")
        try:
            event_serial = int(event_serial_raw) if event_serial_raw is not None else None
        except (TypeError, ValueError):
            event_serial = None
        candidates: dict[tuple[Any, Any], dict[str, Any]] = {}
        for path in _resource_identity_paths(file_obj):
            eligible = []
            for observation in known.get(path, []):
                serial_raw = observation.get("audit_serial")
                try:
                    serial = int(serial_raw) if serial_raw is not None else None
                except (TypeError, ValueError):
                    serial = None
                if event_serial is not None and serial is not None and serial > event_serial:
                    continue
                eligible.append((
                    serial if serial is not None else -1,
                    observation["order"] or -1,
                    observation,
                ))
            if eligible:
                observation = max(eligible, key=lambda candidate: candidate[:2])[2]
                candidates[(observation["dev"], observation["inode"])] = observation
        if len(candidates) != 1:
            continue
        observation = next(iter(candidates.values()))
        file_obj["dev"] = observation["dev"]
        file_obj["inode"] = observation["inode"]
        file_obj["identity_resolution_method"] = "prior_exact_path_dev_inode"
        file_obj["identity_evidence"] = {
            "event_id": observation["event_id"],
            "order": observation["order"],
            "path": observation["path"],
            "audit_serial": observation["audit_serial"],
        }


def _audit_absolute_path_bytes(resource: dict[str, Any] | None) -> bytes | None:
    """Return literal decoded audit PATH bytes without lexical folding."""
    resource = resource or {}
    value = resource.get("raw_path")
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or resource.get("resolution_status") != "audit_absolute"
    ):
        return None
    return value.encode("utf-8", errors="surrogateescape")


def _stable_audit_path(
    resource: dict[str, Any], *, nametype: str
) -> tuple[bytes, dict[str, Any]] | None:
    path = _audit_absolute_path_bytes(resource)
    if (
        path is None
        or resource.get("nametype") != nametype
        or not isinstance(resource.get("dev"), str)
        or not isinstance(resource.get("inode"), int)
        or not isinstance(resource.get("item"), int)
    ):
        return None
    return path, resource


def _path_identity(resource: dict[str, Any]) -> tuple[str, int]:
    return str(resource["dev"]), int(resource["inode"])


def _path_evidence(resource: dict[str, Any]) -> dict[str, Any]:
    return {
        "item": resource.get("item"),
        "nametype": resource.get("nametype"),
        "raw_path": resource.get("raw_path"),
        "dev": resource.get("dev"),
        "inode": resource.get("inode"),
    }


def _audit_evidence(event: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        copy.deepcopy(item) for item in event.get("evidence", [])
        if item.get("source") == "auditd"
    ]


def _rename_supersede_pair(
    event: dict[str, Any]
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, bytes | None, str]:
    if not _audit_evidence(event) or event["order"].get("audit_serial") is None:
        return None, None, None, "rename_missing_audit_event_evidence"
    deletes = [
        result for path in event.get("paths") or []
        if (result := _stable_audit_path(path, nametype="DELETE")) is not None
    ]
    creates = [
        result for path in event.get("paths") or []
        if (result := _stable_audit_path(path, nametype="CREATE")) is not None
    ]
    if not deletes or not creates:
        return None, None, None, "rename_path_evidence_incomplete"
    pairs = [
        (old, new, old_path)
        for old_path, old in deletes
        for new_path, new in creates
        if old_path == new_path and _path_identity(old) != _path_identity(new)
    ]
    if len(pairs) == 1:
        old, new, path = pairs[0]
        return old, new, path, "resolved_rename_overwrite"
    if len(pairs) > 1:
        return None, None, None, "rename_ambiguous_overwrite_pairs"
    same_identity = any(
        old_path == new_path and _path_identity(old) == _path_identity(new)
        for old_path, old in deletes
        for new_path, new in creates
    )
    if same_identity:
        return None, None, None, "rename_same_identity_no_supersede"
    return None, None, None, "rename_no_byte_exact_overwrite_pair"


def _unlink_target(
    event: dict[str, Any]
) -> tuple[dict[str, Any] | None, bytes | None, str]:
    if not _audit_evidence(event) or event["order"].get("audit_serial") is None:
        return None, None, "unlink_missing_audit_event_evidence"
    targets = [
        result for path in event.get("paths") or []
        if (result := _stable_audit_path(path, nametype="DELETE")) is not None
    ]
    if len(targets) != 1:
        status = (
            "unlink_path_evidence_incomplete"
            if not targets else "unlink_ambiguous_delete_paths"
        )
        return None, None, status
    path, target = targets[0]
    return target, path, "pending_exact_path_recreate"


class ProvenanceBuilder:
    def __init__(self, run_id: str, *, enable_supersedes: bool = True):
        self.run_id = run_id
        self.enable_supersedes = enable_supersedes
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: list[dict[str, Any]] = []
        self.file_versions: Counter[str] = Counter()
        self.supersede_outcomes: list[dict[str, Any]] = []

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()[:24]

    def _node(self, node_id: str, node_type: str, identity_status: str, attributes: dict[str, Any], event: dict[str, Any]) -> str:
        existing = self.nodes.get(node_id)
        order = event["order"]["merged"]
        if existing:
            existing["last_observed_order"] = order
            return node_id
        self.nodes[node_id] = {
            "schema_version": PROVENANCE_NODE_SCHEMA_VERSION, "run_id": self.run_id,
            "node_id": node_id, "node_type": node_type, "identity_status": identity_status,
            "attributes": attributes, "first_observed_order": order, "last_observed_order": order,
            "evidence": event["evidence"],
        }
        return node_id

    def _process_node(self, event: dict[str, Any], *, child_pid: int | None = None) -> str:
        process = event["process"]
        if child_pid is not None:
            audit_serial = event["order"].get("audit_serial")
            start_evidence = (
                f"audit_fork:{audit_serial}" if audit_serial is not None
                else f"scap_fork:{event['event_id']}"
            )
            key = f"{process['boot_id']}:{child_pid}:{start_evidence}:0"
            status = "complete"
            attrs = {"boot_id": process["boot_id"], "pid": child_pid, "process_start_time_ticks": None,
                     "process_start_evidence": start_evidence, "exec_epoch": 0}
        else:
            key, status, attrs = process["identity_key"], process["identity_status"], process
        return self._node(f"process:{self._hash(key)}", "process", status, attrs, event)

    def _file_node(self, event: dict[str, Any], *, mutate: bool = False, file_obj: dict[str, Any] | None = None) -> str:
        file_obj = file_obj or event.get("file") or {}
        if file_obj.get("inode") is not None:
            boot_id = event["process"].get("boot_id")
            identity = f"{boot_id}:{file_obj.get('dev')}:{file_obj['inode']}"
            status = "complete" if file_obj.get("dev") else "identity_incomplete"
            if mutate:
                self.file_versions[identity] += 1
            version = self.file_versions[identity]
            return self._node(f"file:{self._hash(identity)}:v{version}", "file", status,
                              {**file_obj, "version": version}, event)
        unknown_identity = f"{event['event_id']}:{file_obj.get('endpoint', 'resource')}"
        return self._node(f"file_unknown:{self._hash(unknown_identity)}", "file_unknown", "identity_incomplete",
                          {**file_obj, "reason": "unresolved_fd_or_path"}, event)

    def _socket_node(self, event: dict[str, Any], socket: dict[str, Any] | None = None) -> str:
        socket = socket or event.get("socket") or {}
        identity = socket.get("cookie") or socket.get("inode") or socket.get("socket_key") or event["event_id"]
        status = "complete" if socket.get("cookie") or socket.get("inode") or socket.get("socket_key") else "identity_incomplete"
        node_type = "socket" if status == "complete" else "socket_unknown"
        return self._node(f"{node_type}:{self._hash(str(identity))}", node_type, status, socket, event)

    def _resource_node(self, event: dict[str, Any], resource: dict[str, Any] | None, *, mutate: bool = False) -> str:
        resource = resource or {"node_type": "file_unknown"}
        if resource.get("node_type") == "socket":
            return self._socket_node(event, resource)
        return self._file_node(event, mutate=mutate, file_obj=resource)

    def _edge(
        self, source: str, target: str, relation: str, event: dict[str, Any], *,
        evidence: list[dict[str, Any]] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> str:
        edge = {
            "schema_version": PROVENANCE_EDGE_SCHEMA_VERSION, "run_id": self.run_id,
            "edge_id": f"{event['event_id']}:{relation}:{len(self.edges)}", "source_node_id": source,
            "destination_node_id": target, "relation": relation, "order": event["order"],
            "success": True, "byte_count": event["syscall"]["return_value"] if relation in {"read", "write", "send", "recv", "transfer"} else None,
            "evidence": evidence if evidence is not None else event["evidence"],
            "completeness": event["completeness"],
        }
        edge.update(extra or {})
        self.edges.append(edge)
        return edge["edge_id"]

    @staticmethod
    def _touched_exact_paths(event: dict[str, Any]) -> set[bytes]:
        """Collect observed absolute path bytes for conservative interference."""
        touched: set[bytes] = set()
        resources = [event.get("file"), *(event.get("paths") or [])]
        for resource in resources:
            if not isinstance(resource, dict) or resource.get("nametype") == "PARENT":
                continue
            touched.update(_byte_exact_absolute_paths(resource))
        return touched

    @staticmethod
    def _create_for_path(event: dict[str, Any], expected: bytes) -> dict[str, Any] | None:
        name = event["syscall"]["name"]
        args = event["syscall"].get("arguments") or {}
        flags = (
            args.get("a1") if name == "open"
            else args.get("a2") if name == "openat"
            else None
        )
        has_create_flag = name == "creat" or (
            name in {"open", "openat"}
            and isinstance(flags, int)
            and bool(flags & 0x40)
        )
        if not event["syscall"].get("success") or not has_create_flag or not _audit_evidence(event):
            return None
        matches = [
            resource for resource in event.get("paths") or []
            if (stable := _stable_audit_path(resource, nametype="CREATE")) is not None
            and stable[0] == expected
        ]
        return matches[0] if len(matches) == 1 else None

    def build(self, rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
        pending_unlinks: dict[bytes, dict[str, Any]] = {}
        for event in rows:
            syscall = event["syscall"]
            touched_paths = (
                self._touched_exact_paths(event)
                if self.enable_supersedes else set()
            )
            resolved_recreates: list[tuple[dict[str, Any], dict[str, Any], bytes]] = []
            for path in sorted(touched_paths & pending_unlinks.keys()):
                pending = pending_unlinks.pop(path)
                created = self._create_for_path(event, path)
                if created is not None:
                    resolved_recreates.append((pending, created, path))
                else:
                    pending["outcome"]["supersede_resolution_status"] = (
                        "unlink_recreate_interrupted_by_same_path_event"
                    )
                    pending["outcome"]["interfering_event_id"] = event["event_id"]
                    pending["outcome"]["interfering_syscall"] = syscall["name"]
            if not syscall["success"]:
                continue
            name = syscall["name"]
            process = self._process_node(event)
            unlink_node: str | None = None
            if name in READ_CALLS:
                if event.get("socket"):
                    self._edge(self._socket_node(event), process, "recv", event)
                else:
                    self._edge(self._file_node(event), process, "read", event)
            elif name in WRITE_CALLS:
                if event.get("socket"):
                    self._edge(process, self._socket_node(event), "send", event)
                else:
                    self._edge(process, self._file_node(event, mutate=True), "write", event)
            elif name in EXEC_CALLS:
                self._edge(self._file_node(event), process, "exec", event)
            elif name in TRANSFER_CALLS:
                transfer = event.get("transfer") or {}
                self._edge(self._resource_node(event, transfer.get("source")),
                           self._resource_node(event, transfer.get("destination"), mutate=True), "transfer", event)
            elif name in FORK_CALLS and syscall["return_value"] and syscall["return_value"] > 0:
                lifecycle = (event.get("correlation") or {}).get("ebpf_lifecycle") or {}
                child_pid = lifecycle.get("related_pid") or syscall["return_value"]
                self._edge(process, self._process_node(event, child_pid=child_pid), "fork", event)
            elif name in SEND_CALLS:
                self._edge(process, self._socket_node(event), "connect" if name == "connect" else "send", event)
            elif name in RECV_CALLS:
                self._edge(self._socket_node(event), process, "accept" if name.startswith("accept") else "recv", event)
            elif name in RENAME_CALLS:
                file_obj = event.get("file") or {}
                before = file_obj.get("before") or file_obj
                after = file_obj.get("after") or file_obj
                self._edge(self._file_node(event, file_obj=before),
                           self._file_node(event, mutate=True, file_obj=after), "rename", event)
                if self.enable_supersedes and name in IDENTITY_RENAME_CALLS:
                    old, new, path, status = _rename_supersede_pair(event)
                    outcome = {
                        "event_id": event["event_id"],
                        "syscall": name,
                        "audit_serial": event["order"].get("audit_serial"),
                        "supersede_resolution_status": status,
                    }
                    self.supersede_outcomes.append(outcome)
                    if old is not None and new is not None and path is not None:
                        old_node = self._file_node(event, file_obj=old)
                        new_node = self._file_node(event, file_obj=new)
                        resolution = {
                            "method": "same_audit_event_delete_create_byte_exact_path",
                            "audit_serial": event["order"].get("audit_serial"),
                            "path_bytes_hex": path.hex(),
                            "old_path_record": _path_evidence(old),
                            "new_path_record": _path_evidence(new),
                        }
                        edge_id = self._edge(
                            old_node, new_node, "supersedes", event,
                            extra={
                                "supersede_resolution_status": status,
                                "supersede_evidence": resolution,
                            },
                        )
                        outcome.update({
                            "edge_id": edge_id,
                            "path": old["raw_path"],
                            "old_node_id": old_node,
                            "new_node_id": new_node,
                            "evidence": resolution,
                        })
            elif name in REMOVE_CALLS | CHMOD_CALLS:
                relation = "unlink" if name in REMOVE_CALLS else "chmod"
                unlink_node = self._file_node(event, mutate=True)
                self._edge(process, unlink_node, relation, event)

            for pending, created, path in resolved_recreates:
                new_node = self._file_node(event, mutate=True, file_obj=created)
                resolution = {
                    "method": "unlink_then_open_create_byte_exact_path_no_intervening_path_event",
                    "path_bytes_hex": path.hex(),
                    "unlink_event_id": pending["event"]["event_id"],
                    "unlink_audit_serial": pending["event"]["order"].get("audit_serial"),
                    "unlink_path_record": _path_evidence(pending["resource"]),
                    "create_event_id": event["event_id"],
                    "create_audit_serial": event["order"].get("audit_serial"),
                    "create_path_record": _path_evidence(created),
                }
                combined_evidence = [
                    *_audit_evidence(pending["event"]),
                    *_audit_evidence(event),
                ]
                edge_id = self._edge(
                    pending["old_node_id"], new_node, "supersedes", event,
                    evidence=combined_evidence,
                    extra={
                        "supersede_resolution_status": "resolved_unlink_recreate",
                        "supersede_evidence": resolution,
                    },
                )
                pending["outcome"].update({
                    "supersede_resolution_status": "resolved_unlink_recreate",
                    "edge_id": edge_id,
                    "recreate_event_id": event["event_id"],
                    "new_node_id": new_node,
                    "evidence": resolution,
                })

            if self.enable_supersedes and name in REMOVE_CALLS:
                target, path, status = _unlink_target(event)
                outcome = {
                    "event_id": event["event_id"],
                    "syscall": name,
                    "audit_serial": event["order"].get("audit_serial"),
                    "supersede_resolution_status": status,
                }
                self.supersede_outcomes.append(outcome)
                if target is not None and path is not None and unlink_node is not None:
                    target_node = self._file_node(event, file_obj=target)
                    if target_node != unlink_node:
                        outcome["supersede_resolution_status"] = "unlink_target_identity_mismatch"
                    else:
                        outcome.update({
                            "path": target["raw_path"],
                            "old_node_id": target_node,
                            "unlink_path_record": _path_evidence(target),
                        })
                        pending_unlinks[path] = {
                            "event": event,
                            "resource": target,
                            "old_node_id": target_node,
                            "outcome": outcome,
                        }

        for pending in pending_unlinks.values():
            pending["outcome"]["supersede_resolution_status"] = (
                "unlink_without_subsequent_exact_path_recreate"
            )
        status_counts = Counter(
            outcome["supersede_resolution_status"]
            for outcome in self.supersede_outcomes
        )
        supersedes = {
            "schema_version": "assa.provenance_supersedes.v1",
            "run_id": self.run_id,
            "supported": True,
            "enabled": self.enable_supersedes,
            "edge_schema_version": PROVENANCE_EDGE_SCHEMA_VERSION,
            "relation": "supersedes",
            "temporal_proximity_inference": False,
            "resolution_methods": [
                "same_audit_event_delete_create_byte_exact_path",
                "unlink_then_open_create_byte_exact_path_no_intervening_path_event",
            ],
            "edge_count": sum(edge["relation"] == "supersedes" for edge in self.edges),
            "status_counts": dict(status_counts),
            "outcomes": self.supersede_outcomes,
        }
        return {"nodes": list(self.nodes.values()), "edges": self.edges, "supersedes": supersedes}


FD_PATH_RESOLVED_THRESHOLD = 0.95
_PRIMARY_RESOLUTION_METHODS = {
    "ebpf_open_exit",
    "ebpf_open_exit_audit_identity",
    "ebpf_fd_table",
    "audit_path",
    "proc_fd",
    "scap_fd_state",
}


def _resolved_file_operand(resource: dict[str, Any] | None) -> tuple[bool, str]:
    resource = resource or {}
    if resource.get("node_type") in {"socket", "pipe"}:
        return False, "excluded_non_file"
    method = resource.get("resolution_method")
    status = resource.get("resolution_status")
    if resource.get("dev") is not None and resource.get("inode") is not None:
        return True, method or "stable_dev_inode"
    if method in _PRIMARY_RESOLUTION_METHODS:
        return True, str(method)
    if status == "cwd_dirfd_join" or status == "cwd_lexical_join":
        return False, "lexical_only"
    return False, str(method or status or "unresolved")


def _fd_path_operands(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    operands: list[dict[str, Any]] = []
    for row in rows:
        syscall = row["syscall"]
        if not syscall.get("success"):
            continue
        name = syscall["name"]
        if name in READ_CALLS | (WRITE_CALLS - {"truncate"}):
            fd = row.get("fd") or {}
            if fd.get("input_fd") is None or row.get("socket"):
                continue
            resolved, method = _resolved_file_operand(row.get("file"))
            if method == "excluded_non_file":
                continue
            operands.append({
                "event_id": row["event_id"],
                "syscall": name,
                "operand": "input_fd",
                "fd": fd.get("input_fd"),
                "resolved": resolved,
                "resolution_method": method,
            })
        elif name in TRANSFER_CALLS:
            transfer = row.get("transfer") or {}
            for endpoint in ("source", "destination"):
                resource = transfer.get(endpoint)
                fd_number = transfer.get(f"{endpoint}_fd")
                if fd_number is None or (resource or {}).get("node_type") in {"socket", "pipe"}:
                    continue
                resolved, method = _resolved_file_operand(resource)
                operands.append({
                    "event_id": row["event_id"],
                    "syscall": name,
                    "operand": endpoint,
                    "fd": fd_number,
                    "resolved": resolved,
                    "resolution_method": method,
                })
    return operands


def build_coverage(rows: list[dict[str, Any]], graph: dict[str, Any], malformed: list[dict[str, Any]]) -> dict[str, Any]:
    by_name = Counter(row["syscall"]["name"] for row in rows)
    process_complete = sum(row["completeness"]["process_identity"] == "complete" for row in rows)
    paths_applicable = [row for row in rows if row.get("file") or row.get("paths") or (row.get("fd") and not row.get("socket"))]
    paths_complete = sum(row["completeness"]["path"] not in {"missing", "unresolved"} for row in paths_applicable)
    sockets = [row for row in rows if row.get("socket") or row["syscall"]["name"] in SEND_CALLS | RECV_CALLS | {"socket"}]
    sockets_complete = sum(row["completeness"]["socket"] not in {"not_applicable", "incomplete", "identity_incomplete", "raw_sockaddr_only"} for row in sockets)
    unknown_nodes = sum(node["node_type"].endswith("unknown") for node in graph["nodes"])
    fd_operands = _fd_path_operands(rows)
    resolved_operands = sum(operand["resolved"] for operand in fd_operands)
    fd_rate = resolved_operands / len(fd_operands) if fd_operands else None
    provenance_evaluable = fd_rate is not None and fd_rate >= FD_PATH_RESOLVED_THRESHOLD
    resolution_methods = Counter(operand["resolution_method"] for operand in fd_operands)
    supersedes = graph.get("supersedes") or {}
    provenance_schema = {
        "node_schema_version": PROVENANCE_NODE_SCHEMA_VERSION,
        "edge_schema_version": PROVENANCE_EDGE_SCHEMA_VERSION,
        "supersedes_supported": supersedes.get("supported") is True,
        "supersedes_enabled": supersedes.get("enabled") is True,
        "supersedes_artifact": "provenance.supersedes.json",
        "supersedes_schema_version": supersedes.get("schema_version"),
        "supersedes_edge_count": supersedes.get("edge_count", 0),
        "supersedes_status_counts": supersedes.get("status_counts", {}),
    }
    return {
        "schema_version": "assa.provenance_coverage.v3", "syscall_events": len(rows),
        "provenance_schema": provenance_schema,
        "sequence_eligible_events": sum(bool(row.get("sequence_eligible")) for row in rows),
        "syscalls_by_name": dict(by_name), "malformed_lines": len(malformed),
        "process_identity_complete": process_complete,
        "process_identity_complete_fraction": process_complete / len(rows) if rows else None,
        "path_applicable": len(paths_applicable), "path_complete": paths_complete,
        "path_complete_fraction": paths_complete / len(paths_applicable) if paths_applicable else None,
        "socket_applicable": len(sockets), "socket_complete": sockets_complete,
        "socket_complete_fraction": sockets_complete / len(sockets) if sockets else None,
        "fd_path_resolved_threshold": FD_PATH_RESOLVED_THRESHOLD,
        "fd_path_operand_denominator": len(fd_operands),
        "fd_path_resolved_numerator": resolved_operands,
        "fd_path_resolved_rate": fd_rate,
        "fd_path_resolution_methods": dict(resolution_methods),
        "fd_path_unresolved_operands": [
            operand for operand in fd_operands if not operand["resolved"]
        ],
        "provenance_evaluable": provenance_evaluable,
        "provenance_status": "passed" if provenance_evaluable else "data_insufficient",
        "graph_nodes": len(graph["nodes"]), "graph_edges": len(graph["edges"]),
        "unknown_nodes": unknown_nodes,
        "unknown_node_fraction": unknown_nodes / len(graph["nodes"]) if graph["nodes"] else None,
        "status": "complete" if rows and provenance_evaluable
        and process_complete == len(rows) and unknown_nodes == 0
        and paths_complete == len(paths_applicable) and sockets_complete == len(sockets)
        else "data_insufficient",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-raw", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--scap-events", type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--boot-id", required=True)
    parser.add_argument("--runner-uid", type=int)
    parser.add_argument("--cgroup-id", type=int)
    parser.add_argument("--cgroup-path")
    parser.add_argument("--process-catalog", type=Path)
    parser.add_argument("--ebpf-lifecycle", type=Path)
    parser.add_argument("--generation-manifest", type=Path)
    parser.add_argument("--fanotify-events", type=Path)
    args = parser.parse_args()
    generation = json.loads(args.generation_manifest.read_text()) if args.generation_manifest else None
    catalog = json.loads(args.process_catalog.read_text()) if args.process_catalog else None
    result = Normalizer(run_id=args.run_id, boot_id=args.boot_id, runner_uid=args.runner_uid,
                        cgroup_id=args.cgroup_id, process_catalog=catalog,
                        runner_cgroup_path=args.cgroup_path).normalize(
                            args.audit_raw, args.output_dir, args.ebpf_lifecycle,
                            args.scap_events,
                            fanotify_events_path=args.fanotify_events,
                            observation_generation=generation)
    print(json.dumps({"syscalls": len(result["syscalls"]), "coverage": result["coverage"],
                      "conservation": result["conservation"]["passed"]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
