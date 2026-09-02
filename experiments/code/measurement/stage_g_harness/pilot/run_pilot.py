#!/usr/bin/env python3
"""Run one Stage G collection around an arbitrary already-approved workload command."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import signal
import sys
import time
from pathlib import Path
from typing import Any, Callable, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[5]
CODE_ROOT = PROJECT_ROOT / "experiments/code"
sys.path.insert(0, str(PROJECT_ROOT / "experiments/code/measurement"))
sys.path.insert(0, str(CODE_ROOT))

from stage_g_harness import HARNESS_SCHEMA_VERSION  # noqa: E402
from stage_g_harness.audit import AuditRulePlan  # noqa: E402
from stage_g_harness.io import file_record, write_json  # noqa: E402
from stage_g_harness.normalize import (  # noqa: E402
    Normalizer,
    audit_union_normalization_stamp,
)
from stage_g_harness.sidecars import (  # noqa: E402
    AuditSidecar,
    CollectionHarness,
    LifecycleEbpfSidecar,
    ScapSidecar,
    validate_runner_scope,
)
from dataset_builder.run_safety import validate_stage_g_safety_bridge  # noqa: E402


def _load_config(path: Path) -> dict[str, Any]:
    config = json.loads(path.read_text(encoding="utf-8"))
    if config.get("schema_version") != f"{HARNESS_SCHEMA_VERSION}.pilot_config":
        raise ValueError("pilot config schema does not match the harness")
    frozen = config["audit"]
    expected = {
        "rate_limit": 0,
        "backlog_limit": 65536,
        "backlog_wait_time": 60000,
        "failure": 1,
    }
    actual = {key: frozen.get(key) for key in expected}
    if actual != expected:
        raise ValueError(f"audit parameters are not frozen: {actual}")
    if platform.machine().lower() not in {config.get("required_machine"), "amd64"}:
        raise RuntimeError(
            f"pilot requires {config.get('required_machine')}; machine is {platform.machine()}"
        )
    if platform.node() != config.get("required_guest_hostname"):
        raise RuntimeError(
            f"pilot requires guest {config.get('required_guest_hostname')}; node is {platform.node()}"
        )
    if config["provenance"].get("fd_path_resolved_rate_min") != 0.95:
        raise ValueError("provenance gate must remain 0.95")
    if config["scap"].get("scope_mode") != "dedicated_uid_with_ebpf_cgroup_attestation":
        raise ValueError("SCAP scope mode is not the frozen cgroup-v2-compatible mode")
    return config


def _bridge_audit_scope(safety: Mapping[str, Any]) -> tuple[str, Path]:
    attestation = safety.get("attestation")
    if not isinstance(attestation, Mapping):
        raise RuntimeError("safety bridge omits the validated attestation")
    monitors = attestation.get("monitors")
    audit = monitors.get("auditd") if isinstance(monitors, Mapping) else None
    if not isinstance(audit, Mapping):
        raise RuntimeError("safety bridge omits the legacy audit monitor")
    key = audit.get("audit_key")
    scope = audit.get("scope")
    if (
        not isinstance(key, str)
        or re.fullmatch(r"[A-Za-z0-9_.-]{1,31}", key) is None
        or audit.get("active") is not True
        or audit.get("raw_stream_retained") is not True
        or scope != "workspace_path_watch_plus_worker_pid_scoped_read_write"
        or audit.get("global_uid_syscall_rule_installed") is not False
    ):
        raise RuntimeError("safety bridge legacy audit declaration is incomplete")
    workspace = Path(str(safety.get("workspace", "")))
    attested_workspace = Path(str(attestation.get("workspace", "")))
    if (
        not workspace.is_absolute()
        or not attested_workspace.is_absolute()
        or workspace.resolve() != attested_workspace.resolve()
    ):
        raise RuntimeError("safety bridge audit workspace does not match the attestation")
    return key, workspace.resolve()


def _uid_processes(uid: int, exclude: set[int]) -> list[int]:
    matches: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) in exclude:
            continue
        try:
            if entry.stat().st_uid == uid:
                matches.append(int(entry.name))
        except (FileNotFoundError, PermissionError):
            continue
    return sorted(matches)


def _spawn_blocked(command: list[str], uid: int | None, gid: int | None,
                   stdout: Path, stderr: Path, env: Mapping[str, str] | None = None) -> int:
    out_fd = os.open(stdout, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    err_fd = os.open(stderr, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    pid = os.fork()
    if pid == 0:
        try:
            os.dup2(out_fd, 1)
            os.dup2(err_fd, 2)
            os.close(out_fd)
            os.close(err_fd)
            if uid is not None:
                if gid is None:
                    raise ValueError("gid is required when dropping runner privileges")
                os.setgroups([])
                os.setgid(gid)
                os.setuid(uid)
            os.kill(os.getpid(), signal.SIGSTOP)
            os.execvpe(command[0], command, dict(env) if env is not None else os.environ)
        except BaseException as exc:
            os.write(2, f"blocked runner exec failed: {exc!r}\n".encode())
            os._exit(127)
    os.close(out_fd)
    os.close(err_fd)
    waited, status = os.waitpid(pid, os.WUNTRACED)
    if waited != pid or not os.WIFSTOPPED(status):
        raise RuntimeError("runner did not enter the blocked state")
    return pid


def _wait_cgroup_empty(cgroup: Path, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    events = cgroup / "cgroup.events"
    while time.monotonic() < deadline:
        values = dict(
            line.split(None, 1) for line in events.read_text(encoding="ascii").splitlines()
        )
        if values.get("populated") == "0":
            return
        time.sleep(0.05)
    raise TimeoutError(f"descendants remain in {cgroup}")


def _wait_path(path: Path, pid: int, timeout: float = 15.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            raise RuntimeError(
                f"safety launch wrapper exited before ready: {os.waitstatus_to_exitcode(status)}"
            )
        time.sleep(0.02)
    raise TimeoutError(f"safety launch wrapper did not create {path}")


def _pid_has_cgroup(pid: int, relative_cgroup: str) -> bool:
    try:
        rows = (Path("/proc") / str(pid) / "cgroup").read_text(
            encoding="ascii"
        ).splitlines()
    except OSError:
        return False
    return any(row.endswith(relative_cgroup) for row in rows)


def _wait_controlled_pid(cgroup: Path, uid: int, timeout: float = 15.0) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            pids = [int(value) for value in (cgroup / "cgroup.procs").read_text(
                encoding="ascii"
            ).split()]
        except (OSError, ValueError):
            pids = []
        for pid in pids:
            try:
                if (Path("/proc") / str(pid)).stat().st_uid == uid:
                    return pid
            except (FileNotFoundError, PermissionError):
                continue
        time.sleep(0.02)
    raise TimeoutError("controlled agent did not enter the attested UID/cgroup")


def run(
    *, config_path: Path, run_dir: Path, run_id: str, input_class: str,
    command: list[str], descendant_timeout: float,
    safety_manifest: Path | None = None,
    before_safety_release: Callable[[int], None] | None = None,
    workload_env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise PermissionError("Stage G pilot collection must run as root")
    if not command:
        raise ValueError("a workload command is required after --")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", run_id):
        raise ValueError("run_id must be 1-80 safe characters")
    curated = PROJECT_ROOT / "experiments/code/dataset_builder/curated_live_session.py"
    is_curated = len(command) > 1 and Path(command[1]).resolve() == curated.resolve()
    variant_index = command.index("--variant") if "--variant" in command else -1
    if (
        safety_manifest is None and is_curated and variant_index >= 0
        and variant_index + 1 < len(command) and command[variant_index + 1] == "poisoned"
    ):
        raise RuntimeError("poisoned Stage G curated session requires --safety-manifest")
    config = _load_config(config_path)
    uid, gid = int(config["runner_uid"]), int(config["runner_gid"])
    safety: dict[str, Any] | None = None
    bridge_audit_keys: tuple[str, ...] = ()
    bridge_audit_workspace: Path | None = None
    effective_env = dict(workload_env) if workload_env is not None else dict(os.environ)
    if safety_manifest is not None:
        safety = validate_stage_g_safety_bridge(
            safety_manifest.resolve(), run_id=run_id, command=command,
            planned_worker_env=effective_env,
        )
        if (safety["runner_uid"], safety["runner_gid"]) != (uid, gid):
            raise RuntimeError(
                "safety attestation UID/GID do not match frozen Stage G runner identity"
            )
        legacy_key, bridge_audit_workspace = _bridge_audit_scope(safety)
        bridge_audit_keys = (legacy_key,)

    run_dir.mkdir(parents=True, exist_ok=False)
    write_json(run_dir / "pilot_config.resolved.json", config)
    stdout, stderr = run_dir / "workload.stdout.log", run_dir / "workload.stderr.log"
    owns_cgroup = safety is None
    if safety is None:
        cgroup_root = Path(config["cgroup_root"])
        cgroup_root.mkdir(parents=True, exist_ok=True)
        cgroup = cgroup_root / run_id
        cgroup.mkdir()
    else:
        cgroup = Path(safety["cgroup_path"])
    relative_cgroup = "/" + cgroup.relative_to("/sys/fs/cgroup").as_posix()
    cgroup_id = cgroup.stat().st_ino
    release_path = Path(safety["launch_release_path"]) if safety is not None else None

    child: int | None = None
    controlled_pid: int | None = None
    child_reaped = resumed = safety_released = False
    harness: CollectionHarness | None = None
    harness_started = stop_attempted = False
    workload_exit: int | None = None
    started_ns = time.time_ns()
    try:
        effective_command = [*safety["launch_prefix"], *command] if safety else command
        child = _spawn_blocked(
            effective_command, None if safety else uid, None if safety else gid,
            stdout, stderr,
            effective_env,
        )

        if safety is None:
            (cgroup / "cgroup.procs").write_text(f"{child}\n", encoding="ascii")
        conflicts = _uid_processes(uid, {child})
        if conflicts:
            raise RuntimeError(f"runner UID {uid} is not dedicated; other PIDs: {conflicts}")

        key = "ocg" + __import__("hashlib").sha256(run_id.encode()).hexdigest()[:20]
        audit = AuditSidecar(
            AuditRulePlan.create(uid, key),
            run_dir / "collector_config/audit.rules",
            run_dir / "raw/auditd.log",
            additional_keys=bridge_audit_keys,
            workspace_path=bridge_audit_workspace,
            sample_interval_seconds=float(config["audit"]["sample_interval_seconds"]),
            drain_timeout_seconds=float(config["audit"]["drain_timeout_seconds"]),
        )
        scap = ScapSidecar.sysdig(
            run_dir, sysdig=config["scap"]["binary"],
            snaplen=int(config["scap"]["snaplen"]), engine=config["scap"]["engine"],
            capture_filter=f"user.uid={uid}", scope_mode=config["scap"]["scope_mode"],
        )
        harness = CollectionHarness(
            run_dir, audit, scap, LifecycleEbpfSidecar(run_dir, cgroup_id),
            runner_pid=child if safety is None else None,
            runner_cgroup_path=relative_cgroup if safety is None else None,
        )
        harness.start_before_release()
        harness_started = True
        os.kill(child, signal.SIGCONT)
        resumed = True

        if safety is not None:
            ready = _wait_path(Path(safety["launch_ready_path"]), child)
            if ready.get("pid") != child or not _pid_has_cgroup(child, relative_cgroup):
                raise RuntimeError(
                    "trusted launch wrapper did not attest the expected PID/cgroup"
                )
            if before_safety_release is not None:
                before_safety_release(child)
            safety = validate_stage_g_safety_bridge(
                safety_manifest.resolve(), run_id=run_id, command=command,
                planned_worker_env=effective_env,
            )
            refreshed_key, refreshed_workspace = _bridge_audit_scope(safety)
            if (
                (refreshed_key,) != bridge_audit_keys
                or refreshed_workspace != bridge_audit_workspace
            ):
                raise RuntimeError("safety bridge audit declaration changed before release")
            audit.attest_declared_partitions(
                phase="pre_safety_release", scope_pids={child}
            )
            write_json(
                run_dir / "safety_bridge_preflight.json",
                {key: value for key, value in safety.items() if key != "attestation"},
            )
            if release_path is None:
                raise RuntimeError("safety release path disappeared after validation")
            release_path.write_text("go\n", encoding="ascii")
            safety_released = True
            controlled_pid = _wait_controlled_pid(cgroup, uid)
            identity = validate_runner_scope(controlled_pid, uid, relative_cgroup)
            write_json(run_dir / "process_catalog.json", {str(controlled_pid): identity})
            harness.runner_pid = controlled_pid
            harness.runner_cgroup_path = relative_cgroup
            audit.scope_pids.add(controlled_pid)
        else:
            controlled_pid = child

        _, status = os.waitpid(child, 0)
        child_reaped = True
        workload_exit = os.waitstatus_to_exitcode(status)
        _wait_cgroup_empty(cgroup, descendant_timeout)
        stop_attempted = True
        stopped = harness.stop_after_descendants()
        catalog_path = run_dir / "process_catalog.json"
        if not catalog_path.is_file():
            write_json(catalog_path, {})
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="ascii"
        ).strip()
        audit_raw_path = run_dir / "raw/auditd.log"
        audit_accounting = json.loads(
            (run_dir / "raw/auditd.partitions.json").read_text(encoding="utf-8")
        )
        audit_input_stamp = audit_union_normalization_stamp(
            audit_accounting,
            audit_path=audit_raw_path,
            audit_syscall_coverage={
                key: (
                    set(audit.plan.supported_syscalls)
                    | set(audit.plan.compat_supported_syscalls)
                    if key == audit.plan.key
                    else set()
                )
                for key in audit.declared_keys
            },
        )
        normalized = Normalizer(
            run_id=run_id, boot_id=boot_id, runner_uid=uid, cgroup_id=cgroup_id,
            process_catalog=catalog, runner_cgroup_path=relative_cgroup,
        ).normalize(
            audit_raw_path, run_dir / "normalized",
            run_dir / "raw/ebpf_lifecycle.jsonl", run_dir / "raw/scap.events.jsonl",
            audit_input_stamp=audit_input_stamp,
        )
        result = {
            "schema_version": f"{HARNESS_SCHEMA_VERSION}.pilot_run",
            "run_id": run_id, "input_class": input_class, "command": command,
            "effective_command_prefix": safety["launch_prefix"] if safety else [],
            "runner_uid": uid, "runner_gid": gid, "runner_pid": controlled_pid,
            "launch_wrapper_pid": child if safety else None,
            "runner_cgroup_path": relative_cgroup, "runner_cgroup_id": cgroup_id,
            "dedicated_uid_conflicts_before_release": conflicts,
            "scap_scope_mode": config["scap"]["scope_mode"],
            "safety_bridge": {
                "enabled": safety is not None,
                "manifest": file_record(safety_manifest) if safety_manifest else None,
                "preflight": (
                    file_record(run_dir / "safety_bridge_preflight.json") if safety else None
                ),
                "local_parent_proxy": (
                    safety["model_proxy_base_url"] if safety else None
                ),
                "audit_keys_normalized": list(audit.declared_keys),
                "release_completed": safety_released,
            },
            "execution_environment": {
                "machine": platform.machine(), "node": platform.node(),
                "platform": platform.platform(), "boot_id": boot_id,
                "guest_attested": (
                    platform.machine().lower() in {config["required_machine"], "amd64"}
                    and platform.node() == config["required_guest_hostname"]
                ),
            },
            "started_realtime_ns": started_ns,
            "stopped_realtime_ns": time.time_ns(),
            "workload_exit_status": workload_exit,
            "collector_ready": file_record(run_dir / "collector_ready.json"),
            "collector_stop": file_record(run_dir / "collector_stop.json"),
            "coverage": normalized["coverage"],
            "conservation_passed": normalized["conservation"]["passed"],
            "passed": (
                workload_exit == 0 and stopped["passed"]
                and normalized["conservation"]["passed"]
            ),
        }
        write_json(run_dir / "pilot_run_manifest.json", result)
        return result
    finally:
        if (
            safety is not None and release_path is not None
            and not safety_released and not release_path.exists()
        ):
            try:
                release_path.write_text("abort\n", encoding="ascii")
            except OSError:
                pass
        if child is not None and not child_reaped:
            try:
                if not resumed:
                    os.kill(child, signal.SIGCONT)
                os.kill(child, signal.SIGKILL)
                os.waitpid(child, 0)
            except (ChildProcessError, ProcessLookupError):
                pass
        if harness is not None and harness_started and not stop_attempted:
            try:
                harness.stop_after_descendants()
            except BaseException as exc:
                write_json(run_dir / "cleanup_error.json", {"error": repr(exc)})
        if owns_cgroup:
            try:
                events = cgroup / "cgroup.events"
                if events.is_file() and "populated 1" in events.read_text(encoding="ascii"):
                    kill_file = cgroup / "cgroup.kill"
                    if kill_file.is_file():
                        kill_file.write_text("1\n", encoding="ascii")
                        _wait_cgroup_empty(cgroup, 10.0)
                cgroup.rmdir()
            except OSError as exc:
                write_json(run_dir / "cgroup_cleanup_error.json", {"error": repr(exc)})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("pilot_config.json"))
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument(
        "--input-class", choices=("clean_training", "held_out_clean", "evaluation"), required=True
    )
    parser.add_argument("--descendant-timeout", type=float, default=60.0)
    parser.add_argument("--safety-manifest", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    result = run(
        config_path=args.config.resolve(), run_dir=args.run_dir.resolve(), run_id=args.run_id,
        input_class=args.input_class, command=command,
        descendant_timeout=args.descendant_timeout,
        safety_manifest=args.safety_manifest.resolve() if args.safety_manifest else None,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
