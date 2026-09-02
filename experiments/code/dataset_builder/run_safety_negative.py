#!/usr/bin/env python3
"""Exercise four fail-closed pre-launch controls without starting a worker.

Each scenario first passes the complete baseline gate, then degrades exactly
one live control and requires ``require_prelaunch_controls`` to reject.  The
collector and namespace processes are safety infrastructure, not workload or
agent processes; no mutation is released and no LLM code is imported.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing
import os
import platform
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[3]
CODE_ROOT = PROJECT_ROOT / "experiments" / "code"
if str(CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(CODE_ROOT))

from dataset_builder.four_source_smoke import (  # noqa: E402
    FANOTIFY_RESPONSE_TIMEOUT_MS,
    _audit_status,
    _command,
    _compile_ebpf,
    _fanotify_collector,
    _fanotify_watchdog,
    _inotify_collector,
    _json_write,
    _wait_file,
)
from dataset_builder.run_safety import (  # noqa: E402
    PrelaunchSafetyError,
    evaluate_prelaunch_controls,
    require_prelaunch_controls,
)


SCENARIOS = {
    "monitor_absent": "monitor_inotify_active",
    "egress_allow": "egress_default_deny_installed",
    "fanotify_root": "fanotify_mark_workspace_only",
    "credential_present": "credential_shaped_worker_environment_absent",
}


def _wait_exists(path: Path, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    raise TimeoutError(path)


def _audit_pid() -> int:
    pid = _audit_status().get("pid")
    if not isinstance(pid, int) or not Path("/proc", str(pid)).exists():
        raise RuntimeError("auditd is not active")
    return pid


def _prepare_cgroup(run_id: str) -> tuple[Path, dict[str, str]]:
    parent = Path("/sys/fs/cgroup/assa-bench-negative")
    parent.mkdir(exist_ok=True)
    required = {"cpu", "memory", "pids"}
    available = set((parent / "cgroup.controllers").read_text(encoding="ascii").split())
    if not required.issubset(available):
        raise RuntimeError("negative preflight cgroup lacks required controllers")
    (parent / "cgroup.subtree_control").write_text(
        "+cpu +memory +pids", encoding="ascii"
    )
    path = parent / run_id
    path.mkdir()
    limits = {"pids.max": "32", "memory.max": str(256 * 1024 * 1024), "cpu.max": "50000 100000"}
    for name, value in limits.items():
        (path / name).write_text(value, encoding="ascii")
    return path, limits


def _prepare_netns(name: str) -> None:
    _command(["/usr/sbin/ip", "netns", "add", name])
    _command(["/usr/sbin/ip", "netns", "exec", name, "/usr/sbin/ip", "link", "set", "lo", "up"])
    rules = """table inet assa_negative {
 chain output { type filter hook output priority 0; policy drop; }
 chain input { type filter hook input priority 0; policy drop; }
}
"""
    _command(["/usr/sbin/ip", "netns", "exec", name, "/usr/sbin/nft", "-f", "-"], input_text=rules)


def _network_facts(name: str, *, expected_deny: bool) -> dict[str, Any]:
    namespace_id = _command(
        ["/usr/sbin/ip", "netns", "exec", name, "/usr/bin/readlink", "/proc/self/ns/net"]
    ).stdout.strip()
    rules = _command(
        ["/usr/sbin/ip", "netns", "exec", name, "/usr/sbin/nft", "list", "ruleset"]
    ).stdout
    routes = _command(
        ["/usr/sbin/ip", "netns", "exec", name, "/usr/sbin/ip", "route", "show"]
    ).stdout.splitlines()
    return {
        "isolated_namespace": True,
        "namespace_name": name,
        "namespace_id": namespace_id,
        "supervisor_namespace_id": os.readlink("/proc/self/ns/net"),
        "egress_default_deny": expected_deny,
        "nft_ruleset": rules,
        "routes": routes,
    }


def _start_fanotify(
    *, mark_root: Path, run_dir: Path, suffix: str
) -> tuple[multiprocessing.Process, multiprocessing.Process, dict[str, Path], dict[str, Any]]:
    paths = {
        "raw": run_dir / "raw" / ("fanotify_%s.jsonl" % suffix),
        "health": run_dir / "health" / ("fanotify_%s.json" % suffix),
        "ready": run_dir / "control" / ("fanotify_%s.ready.json" % suffix),
        "heartbeat": run_dir / "control" / ("fanotify_%s.heartbeat" % suffix),
        "stop": run_dir / "control" / ("fanotify_%s.stop" % suffix),
        "watchdog_stop": run_dir / "control" / ("fanotify_%s.watchdog.stop" % suffix),
        "watchdog_status": run_dir / "control" / ("fanotify_%s.watchdog.json" % suffix),
    }
    collector = multiprocessing.Process(
        target=_fanotify_collector,
        args=(
            str(mark_root),
            str(paths["raw"]),
            str(paths["health"]),
            str(paths["ready"]),
            str(paths["heartbeat"]),
            str(paths["stop"]),
        ),
        name="assa-negative-fanotify-%s" % suffix,
    )
    collector.start()
    _wait_file(paths["ready"], [collector])
    _wait_exists(paths["raw"])
    watchdog = multiprocessing.Process(
        target=_fanotify_watchdog,
        args=(
            collector.pid,
            str(paths["heartbeat"]),
            str(paths["watchdog_stop"]),
            str(paths["watchdog_status"]),
        ),
        name="assa-negative-fanotify-watchdog-%s" % suffix,
    )
    watchdog.start()
    ready = json.loads(paths["ready"].read_text(encoding="utf-8"))
    return collector, watchdog, paths, ready


def _stop_fanotify(
    collector: multiprocessing.Process,
    watchdog: multiprocessing.Process,
    paths: dict[str, Path],
) -> None:
    paths["stop"].write_text("stop\n", encoding="ascii")
    collector.join(timeout=5)
    paths["watchdog_stop"].write_text("stop\n", encoding="ascii")
    watchdog.join(timeout=5)
    if collector.is_alive():
        collector.kill()
    if watchdog.is_alive():
        watchdog.kill()


def _payload(
    *,
    run_id: str,
    workspace: Path,
    cgroup: Path,
    limits: dict[str, str],
    network: dict[str, Any],
    inotify: multiprocessing.Process,
    inotify_raw: Path,
    fanotify: multiprocessing.Process,
    fanotify_raw: Path,
    fanotify_ready: dict[str, Any],
    watchdog: multiprocessing.Process,
    ebpf: subprocess.Popen[str],
    ebpf_raw: Path,
) -> dict[str, Any]:
    return {
        "schema_version": "assa.negative_preflight_input.v1",
        "run_id": run_id,
        "workspace": str(workspace),
        "worker_started": False,
        "agent_started": False,
        "live_poisoned_collection_started": False,
        "cgroup": {
            "path": str(cgroup),
            "unique_per_run": True,
            "limits": limits,
            "processes": [],
        },
        "network": network,
        "fanotify": {
            "mark_root": fanotify_ready["mark_root"],
            "mark_scope": (
                "workspace_subtree"
                if Path(fanotify_ready["mark_root"]).resolve() == workspace.resolve()
                else "root_directory"
            ),
            "response_timeout_ms": FANOTIFY_RESPONSE_TIMEOUT_MS,
            "watchdog_pid": watchdog.pid,
            "watchdog_active": watchdog.is_alive(),
        },
        "monitors": {
            "inotify": {
                "collector_pid": inotify.pid,
                "active": inotify.is_alive(),
                "raw_stream_retained": True,
                "raw_stream_path": str(inotify_raw),
            },
            "fanotify": {
                "collector_pid": fanotify.pid,
                "active": fanotify.is_alive(),
                "raw_stream_retained": True,
                "raw_stream_path": str(fanotify_raw),
            },
            "auditd": {
                "collector_pid": _audit_pid(),
                "active": True,
                "raw_stream_retained": True,
                "raw_stream_path": "/var/log/audit/audit.log",
            },
            "ebpf": {
                "collector_pid": ebpf.pid,
                "active": ebpf.poll() is None,
                "raw_stream_retained": True,
                "raw_stream_path": str(ebpf_raw),
            },
        },
    }


def run_scenario(output_root: Path, scenario: str) -> Path:
    if scenario not in SCENARIOS:
        raise ValueError(scenario)
    run_id = "negative-%s-%s-%s" % (
        scenario,
        time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()),
        uuid.uuid4().hex[:8],
    )
    run_dir = (output_root / run_id).resolve()
    for path in (run_dir / "raw", run_dir / "health", run_dir / "control", run_dir / "workspace", run_dir / "bin"):
        path.mkdir(parents=True, exist_ok=False)
    workspace = run_dir / "workspace"
    cgroup, limits = _prepare_cgroup(run_id)
    netns = ("ocn-" + uuid.uuid4().hex[:12])
    _prepare_netns(netns)
    network = _network_facts(netns, expected_deny=True)
    planned_env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}

    inotify_stop = run_dir / "control" / "inotify.stop"
    inotify_ready = run_dir / "control" / "inotify.ready.json"
    inotify_raw = run_dir / "raw" / "inotify.jsonl"
    inotify = multiprocessing.Process(
        target=_inotify_collector,
        args=(
            str(workspace),
            str(inotify_raw),
            str(run_dir / "health" / "inotify.json"),
            str(inotify_ready),
            str(inotify_stop),
        ),
        name="assa-negative-inotify",
    )
    fanotify = watchdog = None
    fan_paths: dict[str, Path] = {}
    ebpf: subprocess.Popen[str] | None = None
    ebpf_stderr = None
    try:
        inotify.start()
        _wait_file(inotify_ready, [inotify])
        _wait_exists(inotify_raw)
        fanotify, watchdog, fan_paths, fan_ready = _start_fanotify(
            mark_root=workspace, run_dir=run_dir, suffix="baseline"
        )
        compiled = _compile_ebpf(
            Path(__file__).with_name("s1_smoke"), run_dir / "bin"
        )
        ebpf_raw = run_dir / "raw" / "ebpf.jsonl"
        ebpf_ready = run_dir / "control" / "ebpf.ready"
        ebpf_stderr = (run_dir / "raw" / "ebpf.stderr.log").open(
            "w", encoding="utf-8"
        )
        ebpf = subprocess.Popen(
            [
                str(compiled["loader"]),
                str(compiled["object"]),
                str(os.getpid()),
                str(ebpf_raw),
                str(run_dir / "health" / "ebpf.json"),
                str(ebpf_ready),
            ],
            stdout=subprocess.DEVNULL,
            stderr=ebpf_stderr,
            text=True,
        )
        _wait_file(ebpf_ready, [ebpf])
        payload = _payload(
            run_id=run_id,
            workspace=workspace,
            cgroup=cgroup,
            limits=limits,
            network=network,
            inotify=inotify,
            inotify_raw=inotify_raw,
            fanotify=fanotify,
            fanotify_raw=fan_paths["raw"],
            fanotify_ready=fan_ready,
            watchdog=watchdog,
            ebpf=ebpf,
            ebpf_raw=ebpf_raw,
        )
        baseline = require_prelaunch_controls(payload, planned_worker_env=planned_env)
        if not baseline["preflight_passed"]:
            raise RuntimeError("complete baseline unexpectedly rejected")

        if scenario == "monitor_absent":
            inotify.terminate()
            inotify.join(timeout=5)
        elif scenario == "egress_allow":
            _command(
                [
                    "/usr/sbin/ip", "netns", "exec", netns, "/usr/sbin/nft",
                    "delete", "table", "inet", "assa_negative",
                ]
            )
            network = _network_facts(netns, expected_deny=False)
        elif scenario == "fanotify_root":
            _stop_fanotify(fanotify, watchdog, fan_paths)
            fanotify, watchdog, fan_paths, fan_ready = _start_fanotify(
                mark_root=Path("/"), run_dir=run_dir, suffix="degraded_root"
            )
        elif scenario == "credential_present":
            planned_env["FOO_API_KEY"] = "x"

        degraded_payload = _payload(
            run_id=run_id,
            workspace=workspace,
            cgroup=cgroup,
            limits=limits,
            network=network,
            inotify=inotify,
            inotify_raw=inotify_raw,
            fanotify=fanotify,
            fanotify_raw=fan_paths["raw"],
            fanotify_ready=fan_ready,
            watchdog=watchdog,
            ebpf=ebpf,
            ebpf_raw=ebpf_raw,
        )
        evaluated = evaluate_prelaunch_controls(
            degraded_payload, planned_worker_env=planned_env
        )
        rejection_exception = None
        try:
            require_prelaunch_controls(
                degraded_payload, planned_worker_env=planned_env
            )
        except PrelaunchSafetyError as exc:
            rejection_exception = {
                "type": type(exc).__name__,
                "message": str(exc),
                "failed_checks": exc.result["failed_checks"],
            }
        expected = SCENARIOS[scenario]
        if evaluated["preflight_passed"] is not False:
            raise RuntimeError("degraded preflight unexpectedly passed")
        if evaluated["failed_checks"] != [expected]:
            raise RuntimeError(
                "scenario %s failed %r, expected only %s"
                % (scenario, evaluated["failed_checks"], expected)
            )
        if rejection_exception is None:
            raise RuntimeError("require_prelaunch_controls did not reject")
        attestation = {
            "schema_version": "assa.prelaunch_rejection_attestation.v1",
            "run_id": run_id,
            "scenario": scenario,
            "degraded_control": expected,
            "created_realtime_ns": time.time_ns(),
            "created_monotonic_ns": time.monotonic_ns(),
            "baseline_preflight": baseline,
            "preflight_passed": False,
            "checks": evaluated["checks"],
            "rejection_reasons": evaluated["failed_checks"],
            "unexpected_failed_checks": [],
            "gate_exception": rejection_exception,
            "live_poisoned_collection_started": False,
            "worker_started": False,
            "agent_started": False,
            "llm_used": False,
            "planned_worker_environment_variable_names": sorted(planned_env),
            "planned_worker_environment_values_archived": False,
            "credential_shaped_worker_environment_names": evaluated[
                "credential_shaped_worker_environment_names"
            ],
            "control_evidence": degraded_payload,
            "process_launch_log": [],
            "collector_process_roles": {
                source: record["collector_pid"]
                for source, record in degraded_payload["monitors"].items()
            },
            "guest": {
                "hostname": platform.node(),
                "kernel": platform.release(),
                "architecture": platform.machine(),
            },
        }
        path = run_dir / "rejection_attestation.json"
        _json_write(path, attestation)
        return path
    finally:
        if ebpf is not None and ebpf.poll() is None:
            ebpf.send_signal(signal.SIGINT)
            try:
                ebpf.wait(timeout=5)
            except subprocess.TimeoutExpired:
                ebpf.kill()
        if ebpf_stderr is not None:
            ebpf_stderr.close()
        if fanotify is not None and watchdog is not None:
            _stop_fanotify(fanotify, watchdog, fan_paths)
        if inotify.is_alive():
            inotify_stop.write_text("stop\n", encoding="ascii")
            inotify.join(timeout=5)
        if inotify.is_alive():
            inotify.kill()
        _command(["/usr/sbin/ip", "netns", "del", netns], check=False)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run fail-closed pre-launch degradation scenarios"
    )
    parser.add_argument(
        "--output-root",
        default=str(
            PROJECT_ROOT / "experiments" / "results" / "run_safety_negative"
        ),
    )
    parser.add_argument(
        "--scenario", choices=sorted(SCENARIOS), action="append"
    )
    args = parser.parse_args()
    scenarios = args.scenario or list(SCENARIOS)
    paths = [
        run_scenario(Path(args.output_root), scenario) for scenario in scenarios
    ]
    for path in paths:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
