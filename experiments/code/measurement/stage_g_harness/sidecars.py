from __future__ import annotations

import fcntl
import hashlib
import json
import platform
import re
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from io import TextIOBase
from pathlib import Path
from typing import Any, Callable

from . import HARNESS_SCHEMA_VERSION
from .audit import AuditRulePlan, removal_rule
from .io import file_record, write_json
from .scap import decode_capture


def capture_process_identity(pid: int) -> dict[str, Any]:
    proc = Path("/proc") / str(pid)
    stat_text = (proc / "stat").read_text(encoding="utf-8")
    close_paren = stat_text.rfind(")")
    if close_paren < 0:
        raise RuntimeError(f"malformed /proc/{pid}/stat")
    fields_after_comm = stat_text[close_paren + 2:].split()
    if len(fields_after_comm) <= 19:
        raise RuntimeError(f"short /proc/{pid}/stat")
    status: dict[str, str] = {}
    for line in (proc / "status").read_text(encoding="utf-8").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            status[key] = value.strip()
    cgroup_records = (proc / "cgroup").read_text(encoding="utf-8").splitlines()
    try:
        exe = str((proc / "exe").resolve(strict=True))
    except (FileNotFoundError, PermissionError):
        exe = None
    return {
        "pid": pid,
        "process_start_time_ticks": int(fields_after_comm[19]),
        "comm": status.get("Name"),
        "exe": exe,
        "real_uid": int(status["Uid"].split()[0]),
        "real_gid": int(status["Gid"].split()[0]),
        "cgroup_records": cgroup_records,
    }


def validate_runner_scope(pid: int, runner_uid: int, cgroup_path: str) -> dict[str, Any]:
    identity = capture_process_identity(pid)
    if identity["real_uid"] != runner_uid:
        raise RuntimeError(f"runner PID {pid} UID {identity['real_uid']} != {runner_uid}")
    if not any(
        len(parts := record.split(":", 2)) == 3 and parts[2] == cgroup_path
        for record in identity["cgroup_records"]
    ):
        raise RuntimeError(f"runner PID {pid} is not in cgroup {cgroup_path}")
    return identity


Run = Callable[..., subprocess.CompletedProcess[str]]

AUDIT_FROZEN_SETTINGS = {
    "rate_limit": 0,
    "backlog_limit": 65536,
    "backlog_wait_time": 60000,
    "failure": 1,
}

_AUDIT_KEY_RE = re.compile(r"[A-Za-z0-9_.-]{1,31}")
_AUDIT_SERIAL_RE = re.compile(r"msg=audit\([^:()]+:(\d+)\)")
_AUDIT_EVENT_KEY_RE = re.compile(r'(?:^|\s)key=(?:"([^"]*)"|(\S+))')
_AUSEARCH_NO_MATCH_RE = re.compile(r"^(?:<?no matches(?: found)?>?)$", re.IGNORECASE)


def _audit_rule_key(rule: str) -> str | None:
    match = re.search(r'(?:-k\s+|-F\s+key=)(?:"([^"]+)"|(\S+))', rule)
    return (match.group(1) or match.group(2)) if match else None


def _paths_overlap(first: Path, second: Path) -> bool:
    first = first.resolve(strict=False)
    second = second.resolve(strict=False)
    return first == second or first in second.parents or second in first.parents


def _merge_audit_partitions(
    partitions: dict[str, str],
    *,
    declared_keys: tuple[str, ...] | None = None,
    require_nonempty_partitions: bool = False,
) -> tuple[str, dict[str, Any]]:
    declared = tuple(dict.fromkeys(declared_keys or tuple(partitions)))
    declared_set = set(declared)
    groups: dict[int, tuple[str, ...]] = {}
    group_owners: dict[int, str] = {}
    partition_group_counts: dict[str, int] = {}
    duplicate_serials: set[int] = set()
    identical_overlap_serials: set[int] = set()
    conflicting_duplicates: list[dict[str, Any]] = []
    duplicate_group_occurrences = 0
    unparsed_lines: dict[str, list[str]] = {}
    interpretation_line_counts: dict[str, int] = {}
    interpretation_line_samples: dict[str, list[str]] = {}
    observed_keys_by_partition: dict[str, list[str]] = {}
    for key, raw in partitions.items():
        partition_groups: dict[int, list[str]] = {}
        observed_keys: set[str] = set()
        for line in raw.splitlines():
            if not line or line == "----":
                continue
            match = _AUDIT_SERIAL_RE.search(line)
            if match is None:
                if re.match(r"^[A-Z][A-Z0-9_]*=", line):
                    interpretation_line_counts[key] = interpretation_line_counts.get(key, 0) + 1
                    samples = interpretation_line_samples.setdefault(key, [])
                    if len(samples) < 10:
                        samples.append(line)
                    continue
                unparsed_lines.setdefault(key, []).append(line)
                continue
            serial = int(match.group(1))
            partition_groups.setdefault(serial, []).append(line)
            for key_match in _AUDIT_EVENT_KEY_RE.finditer(line):
                observed = key_match.group(1) or key_match.group(2)
                if observed and observed != "(null)":
                    observed_keys.add(observed)
        observed_keys_by_partition[key] = sorted(observed_keys)
        partition_group_counts[key] = len(partition_groups)
        for serial, lines in partition_groups.items():
            group = tuple(lines)
            if serial not in groups:
                groups[serial] = group
                group_owners[serial] = key
                continue
            duplicate_serials.add(serial)
            duplicate_group_occurrences += 1
            if groups[serial] == group:
                identical_overlap_serials.add(serial)
                continue
            conflicting_duplicates.append({
                "serial": serial,
                "first_partition": group_owners[serial],
                "conflicting_partition": key,
                "first_sha256": hashlib.sha256(
                    ("\n".join(groups[serial]) + "\n").encode("utf-8")
                ).hexdigest(),
                "conflicting_sha256": hashlib.sha256(
                    ("\n".join(group) + "\n").encode("utf-8")
                ).hexdigest(),
            })
    merged_lines = [line for serial in sorted(groups) for line in groups[serial]]
    merged = "\n".join(merged_lines) + ("\n" if merged_lines else "")
    partition_group_sum = sum(partition_group_counts.values())
    undeclared_observed_keys = sorted({
        observed
        for observed_keys in observed_keys_by_partition.values()
        for observed in observed_keys
        if observed not in declared_set
    })
    empty_partitions = sorted(
        key for key, count in partition_group_counts.items() if count == 0
    )
    accounting = {
        "declared_keys": list(declared),
        "partition_group_counts": partition_group_counts,
        "partition_group_sum": partition_group_sum,
        "union_group_count": len(groups),
        "duplicate_group_occurrences": duplicate_group_occurrences,
        "duplicate_serials": sorted(duplicate_serials),
        "identical_overlap_group_occurrences": (
            duplicate_group_occurrences - len(conflicting_duplicates)
        ),
        "identical_overlap_serials": sorted(identical_overlap_serials),
        "conflicting_duplicate_groups": conflicting_duplicates,
        "observed_keys_by_partition": observed_keys_by_partition,
        "undeclared_observed_keys": undeclared_observed_keys,
        "empty_partitions": empty_partitions,
        "require_nonempty_partitions": require_nonempty_partitions,
        "unparsed_lines": unparsed_lines,
        "interpretation_line_counts": interpretation_line_counts,
        "interpretation_line_samples": interpretation_line_samples,
        "conservation_passed": (
            partition_group_sum == len(groups) + duplicate_group_occurrences
            and not conflicting_duplicates
            and not undeclared_observed_keys
            and (not require_nonempty_partitions or not empty_partitions)
            and not unparsed_lines
        ),
    }
    return merged, accounting


def _ausearch_query_status(
    returncode: int, stdout: str | None, stderr: str | None
) -> str:
    """Classify ausearch's exit 1 no-match without forgiving real failures."""
    stdout = (stdout or "").strip()
    stderr = (stderr or "").strip()
    if returncode == 0:
        if _AUDIT_SERIAL_RE.search(stdout):
            return "matched"
        messages = [value for value in (stdout, stderr) if value]
        return "no_match" if not messages or all(
            _AUSEARCH_NO_MATCH_RE.fullmatch(value) for value in messages
        ) else "error"
    if returncode == 1:
        messages = [value for value in (stdout, stderr) if value]
        if not messages or all(_AUSEARCH_NO_MATCH_RE.fullmatch(value) for value in messages):
            return "no_match"
    return "error"


def parse_audit_status(text: str) -> dict[str, int]:
    status: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        try:
            status[parts[0]] = int(parts[1])
        except ValueError:
            continue
    return status


def _run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check
    )


@dataclass
class AuditSidecar:
    plan: AuditRulePlan
    config_path: Path
    raw_log: Path
    additional_keys: tuple[str, ...] = ()
    workspace_path: Path | None = None
    runner: Run = _run
    lock_path: Path = Path("/run/lock/assa-stage-g-audit.lock")
    sample_interval_seconds: float = 0.1
    drain_timeout_seconds: float = 15.0
    installed: list[list[str]] = field(default_factory=list)
    status_before: str = ""
    status_samples: list[dict[str, Any]] = field(default_factory=list)
    partition_checks: list[dict[str, Any]] = field(default_factory=list)
    scope_pids: set[int] = field(default_factory=set)
    _lock_handle: TextIOBase | None = field(default=None, init=False, repr=False)
    _prior_settings: dict[str, int] | None = field(default=None, init=False, repr=False)
    _sample_stop: threading.Event = field(default_factory=threading.Event, init=False, repr=False)
    _sample_thread: threading.Thread | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        keys = tuple(dict.fromkeys(self.additional_keys))
        if self.plan.key in keys:
            raise ValueError("the Stage G audit key must not be repeated as an additional key")
        invalid = [key for key in keys if _AUDIT_KEY_RE.fullmatch(key) is None]
        if invalid:
            raise ValueError(f"invalid additional audit keys: {invalid}")
        if self.workspace_path is not None and not self.workspace_path.is_absolute():
            raise ValueError("audit workspace scope must be absolute")
        self.additional_keys = keys

    @property
    def declared_keys(self) -> tuple[str, ...]:
        return (self.plan.key, *self.additional_keys)

    def _rule_may_partition(self, rule: str) -> bool:
        watch_match = re.search(r'(?:^|\s)-w\s+(?:"([^"]+)"|(\S+))', rule)
        if watch_match:
            if self.workspace_path is None:
                return False
            return _paths_overlap(
                Path(watch_match.group(1) or watch_match.group(2)),
                self.workspace_path,
            )
        if re.search(r'(?:^|\s)-(?:a|A)\s+always,exit(?:\s|$)', rule) is None:
            return False
        uid_filters = {
            int(value) for value in re.findall(r'(?:^|\s)(?:-F\s+)?uid=(\d+)', rule)
        }
        if uid_filters and self.plan.runner_uid not in uid_filters:
            return False
        pid_filters = {
            int(value) for value in re.findall(r'(?:^|\s)(?:-F\s+)?pid=(\d+)', rule)
        }
        if pid_filters and self.scope_pids and pid_filters.isdisjoint(self.scope_pids):
            return False
        return True

    def _partition_observation(self, phase: str) -> dict[str, Any]:
        result = self.runner(["auditctl", "-l"], check=False)
        if result.returncode != 0:
            raise RuntimeError(f"auditctl -l failed during {phase}: {result.stderr}")
        declared = set(self.declared_keys)
        observed_declared: set[str] = set()
        unincorporated: list[dict[str, str]] = []
        keyed_rules: list[dict[str, str]] = []
        for rule in result.stdout.splitlines():
            key = _audit_rule_key(rule)
            if key is None:
                continue
            keyed_rules.append({"key": key, "rule": rule})
            if key in declared:
                observed_declared.add(key)
            elif self._rule_may_partition(rule):
                unincorporated.append({"key": key, "rule": rule})
        observation = {
            "phase": phase,
            "realtime_ns": time.time_ns(),
            "declared_keys": list(self.declared_keys),
            "observed_declared_keys": sorted(observed_declared),
            "missing_declared_keys": sorted(declared - observed_declared),
            "unincorporated_overlapping_rules": unincorporated,
            "keyed_rules": keyed_rules,
            "scope_pids": sorted(self.scope_pids),
            "workspace_path": str(self.workspace_path) if self.workspace_path else None,
            "passed": not unincorporated and declared <= observed_declared,
        }
        self.partition_checks.append(observation)
        return observation

    def attest_declared_partitions(
        self, *, phase: str, scope_pids: set[int] | None = None
    ) -> dict[str, Any]:
        if scope_pids:
            self.scope_pids.update(scope_pids)
        observation = self._partition_observation(phase)
        if not observation["passed"]:
            raise RuntimeError(
                "audit partition attestation failed: "
                f"missing={observation['missing_declared_keys']} "
                f"unincorporated={observation['unincorporated_overlapping_rules']}"
            )
        return observation

    def _status(self) -> tuple[str, dict[str, int]]:
        result = self.runner(["auditctl", "-s"], check=False)
        if result.returncode != 0:
            raise RuntimeError(f"auditctl -s failed: {result.stderr}")
        return result.stdout, parse_audit_status(result.stdout)

    def _record_status(self, phase: str) -> dict[str, int]:
        _, status = self._status()
        self.status_samples.append({
            "phase": phase,
            "realtime_ns": time.time_ns(),
            "monotonic_ns": time.monotonic_ns(),
            "status": status,
        })
        return status

    def _run_setting(self, command: list[str]) -> None:
        result = self.runner(command, check=False)
        if result.returncode != 0:
            raise RuntimeError(f"audit setting failed {command!r}: {result.stderr}")

    def _acquire_lock(self) -> None:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_handle = self.lock_path.open("a+", encoding="ascii")
        try:
            fcntl.flock(self._lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            self._lock_handle.close()
            self._lock_handle = None
            raise RuntimeError("another Stage G audit collection is active") from exc

    def _release_lock(self) -> None:
        if self._lock_handle is None:
            return
        fcntl.flock(self._lock_handle.fileno(), fcntl.LOCK_UN)
        self._lock_handle.close()
        self._lock_handle = None

    def _configure(self) -> dict[str, int]:
        self.status_before, before = self._status()
        required = set(AUDIT_FROZEN_SETTINGS)
        missing = sorted(required - before.keys())
        if missing:
            raise RuntimeError(f"audit status omits restorable settings: {missing}")
        self._prior_settings = {name: before[name] for name in required}
        commands = [
            ["auditctl", "-r", "0"],
            ["auditctl", "-b", "65536"],
            ["auditctl", "--backlog_wait_time", "60000"],
            ["auditctl", "-f", "1"],
            ["auditctl", "--reset-lost"],
            ["auditctl", "--reset_backlog_wait_time_actual"],
        ]
        for command in commands:
            self._run_setting(command)
        ready = self._record_status("pre_release")
        mismatches = {
            name: {"expected": expected, "actual": ready.get(name)}
            for name, expected in AUDIT_FROZEN_SETTINGS.items()
            if ready.get(name) != expected
        }
        if mismatches:
            raise RuntimeError(f"frozen audit settings did not apply: {mismatches}")
        if ready.get("lost") != 0 or ready.get("backlog") != 0:
            raise RuntimeError(
                f"audit is not release-ready: lost={ready.get('lost')} backlog={ready.get('backlog')}"
            )
        return ready

    def _restore(self) -> None:
        if self._prior_settings is None:
            return
        prior = self._prior_settings
        commands = [
            ["auditctl", "-r", str(prior["rate_limit"])],
            ["auditctl", "-b", str(prior["backlog_limit"])],
            ["auditctl", "--backlog_wait_time", str(prior["backlog_wait_time"])],
            ["auditctl", "-f", str(prior["failure"])],
        ]
        try:
            for command in commands:
                self._run_setting(command)
            restored = self._record_status("restored")
            mismatches = {
                name: {"expected": expected, "actual": restored.get(name)}
                for name, expected in prior.items()
                if restored.get(name) != expected
            }
            if mismatches:
                raise RuntimeError(f"audit settings restoration mismatch: {mismatches}")
        finally:
            self._prior_settings = None

    def _sample_loop(self) -> None:
        while not self._sample_stop.wait(self.sample_interval_seconds):
            try:
                self._record_status("running")
            except BaseException as exc:
                self.status_samples.append({
                    "phase": "sampling_error", "realtime_ns": time.time_ns(),
                    "error": repr(exc),
                })
                return

    def _start_sampler(self) -> None:
        if self.sample_interval_seconds <= 0:
            return
        self._sample_stop.clear()
        self._sample_thread = threading.Thread(
            target=self._sample_loop, name="stage-g-audit-health", daemon=True
        )
        self._sample_thread.start()

    def _stop_sampler(self) -> None:
        self._sample_stop.set()
        if self._sample_thread is not None:
            self._sample_thread.join(timeout=max(1.0, self.sample_interval_seconds * 4))
            self._sample_thread = None

    def _drain(self) -> dict[str, int]:
        deadline = time.monotonic() + self.drain_timeout_seconds
        while True:
            status = self._record_status("drain")
            if status.get("backlog") == 0:
                return status
            if time.monotonic() >= deadline:
                return status
            time.sleep(min(0.05, max(self.sample_interval_seconds, 0.01)))

    def _health_summary(self) -> dict[str, Any]:
        statuses = [
            sample["status"] for sample in self.status_samples if "status" in sample
        ]
        backlogs = [status.get("backlog") for status in statuses if status.get("backlog") is not None]
        actuals = [
            status.get("backlog_wait_time_actual")
            for status in statuses
            if status.get("backlog_wait_time_actual") is not None
        ]
        activation_intervals = sum(
            current > previous for previous, current in zip(actuals, actuals[1:])
        )
        wait_delta = actuals[-1] - actuals[0] if len(actuals) >= 2 else None
        return {
            "samples": self.status_samples,
            "peak_backlog": max(backlogs) if backlogs else None,
            "backlog_limit": AUDIT_FROZEN_SETTINGS["backlog_limit"],
            "backlog_headroom_fraction": (
                1 - max(backlogs) / AUDIT_FROZEN_SETTINGS["backlog_limit"]
                if backlogs else None
            ),
            "backlog_wait_trigger_count_observed": (
                activation_intervals if len(actuals) >= 2 else None
            ),
            "backlog_wait_trigger_count_status": (
                "lower_bound_from_sampling" if len(actuals) >= 2 else "data_insufficient"
            ),
            "backlog_wait_cumulative_ms": wait_delta,
            "backlog_wait_measurement_status": (
                "kernel_counter_delta" if wait_delta is not None else "data_insufficient"
            ),
            "timing_caveat": "audit backlog waiting can throttle audited syscalls",
        }

    def start(self) -> dict[str, Any]:
        if self.plan.unsupported_syscalls:
            raise RuntimeError(
                f"required native audit syscalls unavailable: {self.plan.unsupported_syscalls}"
            )
        self.plan.write(self.config_path)
        self._acquire_lock()
        try:
            ready_status = self._configure()
            for command_tuple in self.plan.rules:
                command = list(command_tuple)
                result = self.runner(command, check=False)
                if result.returncode != 0:
                    raise RuntimeError(result.stderr)
                self.installed.append(command)
            listed = self.runner(["auditctl", "-l"]).stdout
            if self.plan.key not in listed or f"uid={self.plan.runner_uid}" not in listed:
                raise RuntimeError("UID-scoped audit rules did not appear in auditctl -l")
            partition_check = self.attest_declared_partitions(phase="collector_start")
            self._start_sampler()
        except BaseException:
            self.abort()
            raise
        return {
            "ready": True,
            "ready_realtime_ns": time.time_ns(),
            "scope": "runner_uid",
            "runner_uid": self.plan.runner_uid,
            "key": self.plan.key,
            "declared_keys": list(self.declared_keys),
            "partition_check": partition_check,
            "config": file_record(self.config_path),
            "rules": [list(rule) for rule in self.plan.rules],
            "frozen_settings": AUDIT_FROZEN_SETTINGS,
            "pre_release_status": ready_status,
            "single_flight_lock": str(self.lock_path),
            "native_arch": self.plan.native_arch,
            "supported_syscalls": list(self.plan.supported_syscalls),
            "unsupported_syscalls": list(self.plan.unsupported_syscalls),
            "compat_arch": self.plan.compat_arch,
            "compat_supported_syscalls": list(self.plan.compat_supported_syscalls),
            "compat_unsupported_syscalls": list(self.plan.compat_unsupported_syscalls),
        }

    def _remove(self) -> None:
        errors: list[str] = []
        for command in reversed(self.installed):
            result = self.runner(removal_rule(command), check=False)
            if result.returncode != 0:
                errors.append(f"{command!r}: {result.stderr.strip()}")
        self.installed.clear()
        if errors:
            raise RuntimeError("audit rule removal failed: " + "; ".join(errors))

    def abort(self) -> None:
        self._stop_sampler()
        errors: list[str] = []
        try:
            self._remove()
        except BaseException as exc:
            errors.append(f"remove rules: {exc!r}")
        try:
            self._restore()
        except BaseException as exc:
            errors.append(f"restore settings: {exc!r}")
        self._release_lock()
        if errors:
            raise RuntimeError("; ".join(errors))

    def stop(self) -> dict[str, Any]:
        self._stop_sampler()
        errors: list[str] = []
        final_status: dict[str, int] = {}
        try:
            final_status = self._drain()
            self.raw_log.parent.mkdir(parents=True, exist_ok=True)
            try:
                partition_check = self._partition_observation("collector_stop")
                if not partition_check["passed"]:
                    errors.append(
                        "audit_partition_attestation_failed:"
                        f"missing={partition_check['missing_declared_keys']}:"
                        "unincorporated="
                        f"{partition_check['unincorporated_overlapping_rules']}"
                    )
            except BaseException as exc:
                partition_check = {"phase": "collector_stop", "passed": False, "error": repr(exc)}
                errors.append(f"audit_partition_attestation_error={exc!r}")
            partition_dir = self.raw_log.parent / "auditd.partitions"
            partition_dir.mkdir(parents=True, exist_ok=True)
            partition_raw: dict[str, str] = {}
            partition_results: dict[str, dict[str, Any]] = {}
            for key in self.declared_keys:
                result = self.runner(
                    ["ausearch", "--input-logs", "-k", key, "--raw"],
                    check=False,
                )
                raw_path = partition_dir / f"{key}.log"
                stderr_path = partition_dir / f"{key}.stderr.log"
                raw_path.write_text(result.stdout or "", encoding="utf-8")
                stderr_path.write_text(result.stderr or "", encoding="utf-8")
                partition_raw[key] = result.stdout or ""
                query_status = _ausearch_query_status(
                    result.returncode, result.stdout, result.stderr
                )
                partition_results[key] = {
                    "command": ["ausearch", "--input-logs", "-k", key, "--raw"],
                    "exit_status": result.returncode,
                    "effective_exit_status": 0 if query_status != "error" else result.returncode,
                    "query_status": query_status,
                    "raw": file_record(raw_path),
                    "stderr": file_record(stderr_path),
                }
                if query_status == "error":
                    errors.append(f"ausearch_key={key}:exit={result.returncode}")
                if re.search(
                    r"backlog(?: limit)? (?:exceeded|overflow)", result.stderr or "", re.I
                ):
                    errors.append(f"audit_backlog_overflow_reported:key={key}")
            merged, accounting = _merge_audit_partitions(
                partition_raw, declared_keys=self.declared_keys
            )
            self.raw_log.write_text(merged, encoding="utf-8")
            accounting.update({
                "schema_version": f"{HARNESS_SCHEMA_VERSION}.audit_partition_union",
                "declared_keys": list(self.declared_keys),
                "partitions": partition_results,
                "rule_partition_checks": self.partition_checks,
            })
            accounting_path = self.raw_log.parent / "auditd.partitions.json"
            write_json(accounting_path, accounting)
            if not accounting["conservation_passed"]:
                errors.append("audit_partition_union_conservation_failed")
            if final_status.get("lost") != 0:
                errors.append(f"audit_lost={final_status.get('lost')}")
            if final_status.get("backlog") != 0:
                errors.append(f"audit_backlog_after_drain={final_status.get('backlog')}")
            if any(sample.get("phase") == "sampling_error" for sample in self.status_samples):
                errors.append("audit_health_sampling_failed")
            health = self._health_summary()
            return {
                "exit_status": max(
                    (item["effective_exit_status"] for item in partition_results.values()),
                    default=1,
                ),
                "partition_check": partition_check,
                "partition_union": file_record(accounting_path),
                "status_before": self.status_before,
                "status_after": final_status,
                "health": health,
                "valid": not errors,
                "invalid_reasons": errors,
                "raw": file_record(self.raw_log),
            }
        finally:
            self.abort()


@dataclass
class ScapSidecar:
    capture_path: Path
    stdout_path: Path
    stderr_path: Path
    command: list[str]
    decoder: str | None = None
    scope_mode: str = "unspecified"
    process: subprocess.Popen[str] | None = None
    stdout_handle: TextIOBase | None = field(default=None, init=False, repr=False)
    stderr_handle: TextIOBase | None = field(default=None, init=False, repr=False)
    started_realtime_ns: int | None = None
    started_monotonic_ns: int | None = None

    @classmethod
    def sysdig(
        cls, output_dir: Path, *, sysdig: str = "sysdig", snaplen: int = 0,
        engine: str = "modern-bpf", capture_filter: str | None = None,
        scope_mode: str = "unspecified",
    ) -> "ScapSidecar":
        capture = output_dir / "raw" / "capture.scap"
        if engine not in {"modern-bpf", "kernel-module"}:
            raise ValueError(f"unsupported SCAP engine: {engine}")
        command = [sysdig]
        if engine == "modern-bpf":
            command.append("--modern-bpf")
        command.extend(["-v", "-w", str(capture)])
        if snaplen > 0:
            command.extend(["-s", str(snaplen)])
        if capture_filter:
            command.append(capture_filter)
        return cls(
            capture,
            output_dir / "raw" / "scap.stdout.log",
            output_dir / "raw" / "scap.stderr.log",
            command,
            decoder=sysdig,
            scope_mode=scope_mode,
        )

    def _capture_fd(self) -> int | None:
        if self.process is None:
            return None
        expected = self.capture_path.resolve()
        fd_root = Path("/proc") / str(self.process.pid) / "fd"
        try:
            entries = list(fd_root.iterdir())
        except (FileNotFoundError, PermissionError):
            return None
        for entry in entries:
            try:
                if entry.resolve(strict=True) == expected:
                    return int(entry.name)
            except (FileNotFoundError, PermissionError, ValueError):
                continue
        return None

    def start(self, timeout: float = 15.0) -> dict[str, Any]:
        self.capture_path.parent.mkdir(parents=True, exist_ok=True)
        self.stdout_handle = self.stdout_path.open("w", encoding="utf-8")
        self.stderr_handle = self.stderr_path.open("w", encoding="utf-8")
        self.started_realtime_ns = time.time_ns()
        self.started_monotonic_ns = time.monotonic_ns()
        self.process = subprocess.Popen(
            self.command, stdout=self.stdout_handle, stderr=self.stderr_handle, text=True
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self._close_logs()
                raise RuntimeError(f"SCAP capture exited before ready: {self.process.returncode}")
            capture_fd = self._capture_fd()
            if capture_fd is not None and self.capture_path.is_file():
                self.stderr_handle.flush()
                startup_stderr = self.stderr_path.read_text(
                    encoding="utf-8", errors="replace"
                )
                if re.search(
                    r"(?:^|\b)(?:error|fatal|failed)(?:\b|:)", startup_stderr, re.I
                ):
                    raise RuntimeError(f"SCAP startup error: {startup_stderr.strip()}")
                return {
                    "ready": True,
                    "pid": self.process.pid,
                    "command": self.command,
                    "format": "libscap",
                    "capture_fd": capture_fd,
                    "capture_path": str(self.capture_path.resolve()),
                    "scope_mode": self.scope_mode,
                    "ready_realtime_ns": time.time_ns(),
                    "ready_monotonic_ns": time.monotonic_ns(),
                    "startup_stderr_bytes": len(startup_stderr.encode()),
                }
            time.sleep(0.05)
        raise TimeoutError(
            "SCAP capture never opened its output file before the readiness deadline"
        )

    @staticmethod
    def _health_counter(text: str, label: str) -> int | None:
        patterns = {
            "captured": (
                r"Captured Events\s*:\s*(\d+)",
                r"events? captured\s*[:=]\s*(\d+)",
            ),
            "driver": (r"Driver Events\s*:\s*(\d+)",),
            "dropped": (
                r"Driver Drops\s*:\s*(\d+)",
                r"events? dropped\s*[:=]\s*(\d+)",
            ),
        }
        for pattern in patterns.get(label, ()):
            match = re.search(pattern, text, re.I)
            if match:
                return int(match.group(1))
        return None

    def stop(self, timeout: float = 15.0) -> dict[str, Any]:
        if self.process is None:
            raise RuntimeError("SCAP capture was not started")
        self.process.send_signal(signal.SIGINT)
        try:
            status = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            status = self.process.wait(timeout=5)
        self._close_logs()
        if status != 0:
            raise RuntimeError(f"SCAP capture exited with status {status}")
        if not self.capture_path.is_file() or self.capture_path.stat().st_size == 0:
            raise RuntimeError("SCAP capture is missing or empty")
        stderr_text = self.stderr_path.read_text(encoding="utf-8", errors="replace")
        event_count = self._health_counter(stderr_text, "captured")
        driver_event_count = self._health_counter(stderr_text, "driver")
        drop_count = self._health_counter(stderr_text, "dropped")
        invalid_reasons = []
        if event_count is None:
            invalid_reasons.append("scap_event_count_missing")
        if drop_count is None:
            invalid_reasons.append("scap_drop_count_missing")
        elif drop_count != 0:
            invalid_reasons.append(f"scap_dropped={drop_count}")
        return {
            "exit_status": status,
            "started_realtime_ns": self.started_realtime_ns,
            "started_monotonic_ns": self.started_monotonic_ns,
            "stopped_realtime_ns": time.time_ns(),
            "stopped_monotonic_ns": time.monotonic_ns(),
            "command": self.command,
            "capture": file_record(self.capture_path),
            "stdout": file_record(self.stdout_path),
            "stderr": file_record(self.stderr_path),
            "event_count": event_count,
            "driver_event_count": driver_event_count,
            "drop_count": drop_count,
            "valid": not invalid_reasons,
            "invalid_reasons": invalid_reasons,
            "health_status": "complete" if not invalid_reasons else "invalid",
        }

    def _close_logs(self) -> None:
        for stream in (self.stdout_handle, self.stderr_handle):
            if stream is not None and not stream.closed:
                stream.close()


@dataclass
class LifecycleEbpfSidecar:
    run_dir: Path
    target_cgroup_id: int
    clang: str = "/usr/bin/clang"
    cc: str = "/usr/bin/cc"
    process: subprocess.Popen[str] | None = None
    stderr_handle: TextIOBase | None = field(default=None, init=False, repr=False)

    @property
    def source_dir(self) -> Path:
        return Path(__file__).with_name("ebpf")

    def compile(self) -> dict[str, Any]:
        binary_dir = self.run_dir / "bin"
        binary_dir.mkdir(parents=True, exist_ok=True)
        bpf_object = binary_dir / "lifecycle_ebpf.bpf.o"
        loader = binary_dir / "lifecycle_ebpf"
        machine = platform.machine().lower()
        targets = {
            "x86_64": ("x86", "x86_64-linux-gnu"),
            "amd64": ("x86", "x86_64-linux-gnu"),
            "aarch64": ("arm64", "aarch64-linux-gnu"),
            "arm64": ("arm64", "aarch64-linux-gnu"),
            "ppc64le": ("powerpc", "powerpc64le-linux-gnu"),
            "s390x": ("s390", "s390x-linux-gnu"),
        }
        if machine not in targets:
            raise RuntimeError(f"unsupported eBPF build architecture: {machine}")
        target_arch, multiarch = targets[machine]
        bpf_command = [
            self.clang, "-O2", "-g", "-target", "bpf",
            f"-D__TARGET_ARCH_{target_arch}",
        ]
        multiarch_include = Path("/usr/include") / multiarch
        if multiarch_include.is_dir():
            bpf_command.append(f"-I{multiarch_include}")
        bpf_command.extend([
            "-c", str(self.source_dir / "lifecycle_ebpf.bpf.c"),
            "-o", str(bpf_object),
        ])
        commands = [
            bpf_command,
            [self.cc, "-O2", "-Wall", "-Wextra", str(self.source_dir / "lifecycle_ebpf.c"),
             "-o", str(loader), "-lbpf", "-lelf", "-lz"],
        ]
        for command in commands:
            result = _run(command, check=False)
            if result.returncode != 0:
                raise RuntimeError(f"eBPF compile failed: {command!r}: {result.stderr}")
        return {"object": bpf_object, "loader": loader, "commands": commands,
                "host_machine": machine, "bpf_target_arch": target_arch,
                "object_record": file_record(bpf_object), "loader_record": file_record(loader)}

    def start(self, timeout: float = 15.0) -> dict[str, Any]:
        built = self.compile()
        raw = self.run_dir / "raw" / "ebpf_lifecycle.jsonl"
        health = self.run_dir / "health" / "ebpf_lifecycle.json"
        ready = self.run_dir / "control" / "ebpf_lifecycle.ready.json"
        stderr_path = self.run_dir / "raw" / "ebpf_lifecycle.stderr.log"
        for path in (raw.parent, health.parent, ready.parent):
            path.mkdir(parents=True, exist_ok=True)
        self.stderr_handle = stderr_path.open("w", encoding="utf-8")
        command = [str(built["loader"]), str(built["object"]), str(self.target_cgroup_id),
                   str(raw), str(health), str(ready)]
        self.process = subprocess.Popen(
            command, stdout=subprocess.DEVNULL, stderr=self.stderr_handle, text=True
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if ready.is_file() and ready.stat().st_size:
                payload = json.loads(ready.read_text(encoding="utf-8"))
                if payload.get("cgroup_id") != self.target_cgroup_id:
                    raise RuntimeError("eBPF ready cgroup ID mismatch")
                return {**payload, "pid": self.process.pid, "command": command,
                        "build": {key: value for key, value in built.items() if key not in {"object", "loader"}}}
            if self.process.poll() is not None:
                raise RuntimeError(f"eBPF lifecycle collector exited before ready: {self.process.returncode}")
            time.sleep(0.05)
        raise TimeoutError("eBPF lifecycle ready file timed out")

    def stop(self, timeout: float = 15.0) -> dict[str, Any]:
        if self.process is None:
            raise RuntimeError("eBPF lifecycle collector was not started")
        self.process.send_signal(signal.SIGINT)
        try:
            status = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            status = self.process.wait(timeout=5)
        if self.stderr_handle is not None and not self.stderr_handle.closed:
            self.stderr_handle.close()
        raw = self.run_dir / "raw" / "ebpf_lifecycle.jsonl"
        health = self.run_dir / "health" / "ebpf_lifecycle.json"
        stderr = self.run_dir / "raw" / "ebpf_lifecycle.stderr.log"
        if status != 0 or not raw.is_file() or not health.is_file():
            raise RuntimeError(f"eBPF lifecycle collector failed with status {status}")
        return {"exit_status": status, "raw": file_record(raw), "health": file_record(health),
                "stderr": file_record(stderr), "scope": "cgroup_id", "cgroup_id": self.target_cgroup_id}


class CollectionHarness:
    """Composable sidecars for an existing blocked-runner recollection flow."""

    def __init__(self, run_dir: Path, audit: AuditSidecar, scap: ScapSidecar,
                 lifecycle_ebpf: LifecycleEbpfSidecar | None = None, *,
                 runner_pid: int | None = None, runner_cgroup_path: str | None = None):
        self.run_dir = run_dir
        self.audit = audit
        self.scap = scap
        self.lifecycle_ebpf = lifecycle_ebpf
        self.ready: dict[str, Any] = {}
        self.runner_pid = runner_pid
        self.runner_cgroup_path = runner_cgroup_path

    def start_before_release(self) -> dict[str, Any]:
        try:
            if (self.runner_pid is None) != (self.runner_cgroup_path is None):
                raise ValueError("runner_pid and runner_cgroup_path must be supplied together")
            if self.runner_pid is not None and self.runner_cgroup_path is not None:
                identity = validate_runner_scope(
                    self.runner_pid, self.audit.plan.runner_uid, self.runner_cgroup_path
                )
                write_json(self.run_dir / "process_catalog.json", {str(self.runner_pid): identity})
                self.ready["runner_scope"] = identity
            if self.lifecycle_ebpf is not None:
                self.ready["ebpf_lifecycle"] = self.lifecycle_ebpf.start()
            self.ready["auditd"] = self.audit.start()
            self.ready["scap"] = self.scap.start()
        except BaseException:
            if self.audit.installed or self.audit._prior_settings is not None:
                self.audit.abort()
            if self.lifecycle_ebpf is not None and self.lifecycle_ebpf.process is not None:
                if self.lifecycle_ebpf.process.poll() is None:
                    self.lifecycle_ebpf.process.terminate()
                    self.lifecycle_ebpf.process.wait(timeout=5)
                if self.lifecycle_ebpf.stderr_handle is not None and not self.lifecycle_ebpf.stderr_handle.closed:
                    self.lifecycle_ebpf.stderr_handle.close()
            if self.scap.process is not None:
                if self.scap.process.poll() is None:
                    self.scap.process.terminate()
                    self.scap.process.wait(timeout=5)
                self.scap._close_logs()
            raise
        manifest = {
            "schema_version": f"{HARNESS_SCHEMA_VERSION}.collection_ready",
            "created_realtime_ns": time.time_ns(),
            "ready": self.ready,
        }
        write_json(self.run_dir / "collector_ready.json", manifest)
        return manifest

    def stop_after_descendants(self) -> dict[str, Any]:
        results: dict[str, Any] = {}
        errors: list[str] = []
        sidecars: list[tuple[str, Any]] = [("scap", self.scap)]
        if self.lifecycle_ebpf is not None:
            sidecars.append(("ebpf_lifecycle", self.lifecycle_ebpf))
        sidecars.append(("auditd", self.audit))
        for name, sidecar in sidecars:
            try:
                result = sidecar.stop()
                results[name] = result
                if result.get("valid") is False:
                    errors.append(f"{name}: invalid: {result.get('invalid_reasons')}")
            except BaseException as exc:
                errors.append(f"{name}: {exc!r}")
        if results.get("scap", {}).get("valid") and self.scap.decoder:
            try:
                allowed_pids: set[int] | None = None
                if self.scap.scope_mode == "dedicated_uid_with_ebpf_cgroup_attestation":
                    allowed_pids = {self.runner_pid} if self.runner_pid is not None else set()
                    lifecycle_path = self.run_dir / "raw" / "ebpf_lifecycle.jsonl"
                    for line in lifecycle_path.read_text(
                        encoding="utf-8", errors="replace"
                    ).splitlines():
                        event = json.loads(line)
                        for field_name in ("pid", "related_pid"):
                            value = event.get(field_name)
                            if isinstance(value, int) and value > 0:
                                allowed_pids.add(value)
                    if not allowed_pids:
                        raise RuntimeError("SCAP replay has no cgroup-attested PIDs")
                decoder = decode_capture(
                    self.scap.capture_path,
                    self.run_dir / "raw" / "scap.events.jsonl",
                    runner_uid=self.audit.plan.runner_uid,
                    runner_cgroup_path=(
                        self.runner_cgroup_path
                        if self.scap.scope_mode == "uid_and_cgroup_field"
                        else None
                    ),
                    allowed_pids=allowed_pids,
                    sysdig=self.scap.decoder,
                )
                decoder["scope_mode"] = self.scap.scope_mode
                results["scap_decoder"] = decoder
                if not decoder["valid"]:
                    errors.append(
                        f"scap_decoder: invalid: {decoder.get('invalid_reasons')}"
                    )
            except BaseException as exc:
                errors.append(f"scap_decoder: {exc!r}")
        manifest = {
            "schema_version": f"{HARNESS_SCHEMA_VERSION}.collection_stop",
            "stopped_realtime_ns": time.time_ns(),
            "results": results,
            "errors": errors,
            "passed": not errors,
        }
        write_json(self.run_dir / "collector_stop.json", manifest)
        if errors:
            raise RuntimeError("; ".join(errors))
        return manifest
