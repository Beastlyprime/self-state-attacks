"""Fail-closed validation for live poisoned collection.

The privileged supervisor creates the attestation after installing the cgroup,
network, egress, and fanotify controls.  The agent validates observable kernel
state and refuses to start a poisoned turn when any prerequisite is absent.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import resource
import shutil
import stat
import tarfile
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse


SAFETY_SCHEMA_VERSION = "assa.live_safety.v1"
PRELAUNCH_SCHEMA_VERSION = "assa.prelaunch_safety.v1"
REQUIRED_MONITORS = ("inotify", "fanotify", "auditd", "ebpf")
TOOL_SANDBOX_PREFIX_ENV = "ASSA_TOOL_SANDBOX_PREFIX_JSON"
TOOL_SANDBOX_REQUIRED_ENV = "ASSA_TOOL_SANDBOX_REQUIRED"
SENSITIVE_NAME_FRAGMENTS = (
    "API_KEY",
    "ACCESS_KEY",
    "AUTH_TOKEN",
    "PASSWORD",
    "PRIVATE_KEY",
    "SECRET",
    "TOKEN",
    "CREDENTIAL",
)


class PrelaunchSafetyError(RuntimeError):
    """Raised before process creation when a required control is absent."""

    def __init__(self, result: dict[str, Any]):
        self.result = result
        super().__init__(
            "pre-launch safety gate rejected: "
            + ", ".join(result["failed_checks"])
        )


def _proxy_egress_policy_is_exact(network: Mapping[str, Any]) -> bool:
    allowlist = network.get("proxy_egress_allowlist")
    ruleset = str(network.get("nft_ruleset", ""))
    if allowlist == ["dns", "tcp:443"]:
        return "udp dport 53" in ruleset and "tcp dport" in ruleset and "443" in ruleset
    if not isinstance(allowlist, list) or len(allowlist) != 1:
        return False
    match = re.fullmatch(r"tcp:([^:]+):(\d+)", str(allowlist[0]))
    if match is None:
        return False
    try:
        address = ipaddress.ip_address(match.group(1))
        port = int(match.group(2))
    except ValueError:
        return False
    return (
        address.version == 4
        and address.is_private
        and 1024 <= port <= 65535
        and f"ip daddr {address}" in ruleset
        and f"tcp dport {port}" in ruleset
    )

class StageGSafetyBridgeError(RuntimeError):
    """Raised before release when Stage G cannot prove the legacy sandbox contract."""


def _command_option(command: Sequence[str], name: str) -> str | None:
    try:
        index = command.index(name)
    except ValueError:
        return None
    if index + 1 >= len(command):
        return None
    return command[index + 1]


def evaluate_prelaunch_controls(
    payload: Mapping[str, Any], *, planned_worker_env: Mapping[str, str]
) -> dict[str, Any]:
    """Evaluate controls that must exist before a worker/agent is created.

    The privileged supervisor supplies kernel-observed facts.  Checks remain
    separate so a rejection identifies the missing control instead of merely
    failing an aggregate boolean.
    """
    cgroup = payload.get("cgroup") or {}
    network = payload.get("network") or {}
    fanotify = payload.get("fanotify") or {}
    monitors = payload.get("monitors") or {}
    workspace = Path(str(payload.get("workspace", "")))
    cgroup_path = Path(str(cgroup.get("path", "")))
    limits = cgroup.get("limits") or {}
    checks: dict[str, bool] = {
        "worker_and_agent_not_started": (
            payload.get("worker_started") is False
            and payload.get("agent_started") is False
        ),
        "credential_shaped_worker_environment_absent": not credential_variable_names(
            planned_worker_env
        ),
        "unique_run_cgroup_prepared": (
            cgroup.get("unique_per_run") is True
            and isinstance(payload.get("run_id"), str)
            and payload["run_id"] in str(cgroup_path)
            and cgroup_path.is_absolute()
            and cgroup_path.is_dir()
            and all(isinstance(limits.get(name), str) and limits[name] for name in (
                "pids.max",
                "memory.max",
                "cpu.max",
            ))
        ),
        "worker_network_namespace_prepared": (
            network.get("isolated_namespace") is True
            and isinstance(network.get("namespace_id"), str)
            and network.get("namespace_id") != network.get("supervisor_namespace_id")
        ),
        "egress_default_deny_installed": (
            network.get("egress_default_deny") is True
            and "policy drop" in str(network.get("nft_ruleset", ""))
            and (
                network.get("routes") == []
                or (
                    network.get("routes_restricted_by_default_deny") is True
                    and network.get("worker_egress_allowlist")
                    in (["loopback:model_proxy"], ["loopback:model_proxy", "loopback:local_http_fixture"])
                    and _proxy_egress_policy_is_exact(network)
                )
            )
        ),
        "fanotify_mark_workspace_only": (
            workspace.is_absolute()
            and workspace.is_dir()
            and fanotify.get("mark_scope") == "workspace_subtree"
            and Path(str(fanotify.get("mark_root", ""))).resolve()
            == workspace.resolve()
        ),
        "fanotify_response_timeout_bounded": (
            isinstance(fanotify.get("response_timeout_ms"), int)
            and 0 < fanotify["response_timeout_ms"] <= 1000
        ),
        "fanotify_watchdog_active": (
            fanotify.get("watchdog_active") is True
            and isinstance(fanotify.get("watchdog_pid"), int)
            and Path("/proc", str(fanotify["watchdog_pid"])).exists()
        ),
    }
    for source in REQUIRED_MONITORS:
        monitor = monitors.get(source) or {}
        pid = monitor.get("collector_pid")
        checks["monitor_%s_active" % source] = (
            monitor.get("active") is True
            and isinstance(pid, int)
            and Path("/proc", str(pid)).exists()
            and monitor.get("raw_stream_retained") is True
            and isinstance(monitor.get("raw_stream_path"), str)
            and Path(monitor["raw_stream_path"]).is_file()
        )
    failed = sorted(name for name, passed in checks.items() if not passed)
    return {
        "schema_version": PRELAUNCH_SCHEMA_VERSION,
        "preflight_passed": not failed,
        "checks": checks,
        "failed_checks": failed,
        "credential_shaped_worker_environment_names": credential_variable_names(
            planned_worker_env
        ),
    }


def require_prelaunch_controls(
    payload: Mapping[str, Any], *, planned_worker_env: Mapping[str, str]
) -> dict[str, Any]:
    """Return the passing result or reject before process creation."""
    result = evaluate_prelaunch_controls(
        payload, planned_worker_env=planned_worker_env
    )
    if not result["preflight_passed"]:
        raise PrelaunchSafetyError(result)
    return result


def credential_variable_names(env: Mapping[str, str]) -> list[str]:
    return sorted(
        key
        for key in env
        if any(fragment in key.upper() for fragment in SENSITIVE_NAME_FRAGMENTS)
    )


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _workspace_manifest_sha256(
    workspace: Path, *, exclude_paths: set[str] | None = None
) -> str:
    excluded = exclude_paths or set()
    rows = []
    for path in sorted(workspace.rglob("*")):
        if not path.is_file() or ".openclaw" in path.parts or "traces" in path.parts:
            continue
        relative = path.relative_to(workspace).as_posix()
        if relative in excluded:
            continue
        raw = path.read_bytes()
        rows.append(
            {
                "path": relative,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "mode": stat.S_IMODE(path.stat().st_mode),
            }
        )
    canonical = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def _namespace_id(name: str) -> str:
    return os.readlink(Path("/proc/self/ns") / name)


def _current_cgroups() -> list[str]:
    return Path("/proc/self/cgroup").read_text(encoding="utf-8").splitlines()


def _process_is_in_cgroup(cgroup_path: str, records: list[str]) -> bool:
    if any(cgroup_path in line for line in records):
        return True
    try:
        relative = "/" + Path(cgroup_path).resolve().relative_to("/sys/fs/cgroup").as_posix()
    except (OSError, ValueError):
        return False
    return any(line.endswith(relative) for line in records)


def _root_owned_not_writable(path: Path) -> bool:
    st = path.stat()
    return st.st_uid == 0 and not bool(stat.S_IMODE(st.st_mode) & 0o022)


def agent_launch_prefix(manifest_path: Path) -> list[str]:
    """Return the trusted supervisor wrapper that enters this run's cgroup."""
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    prefix = (payload.get("agent_process") or {}).get("command_prefix")
    if not isinstance(prefix, list) or not prefix or not all(
        isinstance(item, str) and item for item in prefix
    ):
        raise RuntimeError("safety attestation lacks agent-process command prefix")
    executable = Path(prefix[0])
    if not executable.is_absolute() or not executable.is_file() or not _root_owned_not_writable(executable):
        raise RuntimeError("agent-process command prefix is not a trusted executable")
    return prefix


def wall_time_budget(manifest_path: Path) -> int:
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    value = (payload.get("budgets") or {}).get("wall_seconds")
    if not isinstance(value, int) or value <= 0:
        raise RuntimeError("safety attestation lacks a positive wall budget")
    return value


def validate_live_poisoned_safety(
    manifest_path: Path,
    *,
    workspace: Path,
    run_id: str,
    env: Mapping[str, str],
    model_base_url: str,
) -> dict[str, Any]:
    """Validate real controls; schema assertions alone are insufficient."""
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != SAFETY_SCHEMA_VERSION:
        raise RuntimeError("live poisoned safety attestation has wrong schema")
    checks: dict[str, bool] = {}
    checks["run_id_matches"] = payload.get("run_id") == run_id
    checks["workspace_matches"] = Path(payload.get("workspace", "")).resolve() == workspace.resolve()
    checks["credential_names_absent_before_agent_turn"] = not credential_variable_names(env)

    checkpoint = payload.get("checkpoint") or {}
    source_manifest = Path(checkpoint.get("source_manifest", ""))
    delivered = checkpoint.get("delivered_fixtures") or []
    delivered_valid = isinstance(delivered, list)
    delivered_paths: set[str] = set()
    if delivered_valid:
        for fixture in delivered:
            if not isinstance(fixture, dict) or not isinstance(fixture.get("path"), str):
                delivered_valid = False
                break
            relative = fixture["path"]
            fixture_path = workspace / relative
            delivered_paths.add(relative)
            if not fixture_path.is_file() or _sha_file(fixture_path) != fixture.get("sha256"):
                delivered_valid = False
                break
    checks["pristine_checkpoint_manifest_verified"] = (
        checkpoint.get("fresh_copy") is True
        and checkpoint.get("workspace_reusable") is False
        and checkpoint.get("destroy_after_run") is True
        and source_manifest.is_file()
        and _sha_file(source_manifest) == checkpoint.get("source_manifest_sha256")
        and delivered_valid
        and _workspace_manifest_sha256(workspace, exclude_paths=delivered_paths)
        == checkpoint.get("pristine_workspace_manifest_sha256")
    )

    cgroup = payload.get("cgroup") or {}
    cgroup_path = str(cgroup.get("path", ""))
    checks["unique_run_cgroup_active"] = (
        cgroup.get("unique_per_run") is True
        and run_id in cgroup_path
        and _process_is_in_cgroup(cgroup_path, _current_cgroups())
    )

    network = payload.get("network") or {}
    checks["agent_network_namespace_matches"] = (
        network.get("agent_namespace_id") == _namespace_id("net")
    )
    checks["egress_default_deny_attested"] = (
        network.get("egress_default_deny") is True
        and network.get("tool_children_have_no_network") is True
        and network.get("model_api_parent_only") is True
        and network.get("loopback_fixture_only") is True
    )
    parsed = urlparse(model_base_url)
    checks["model_uses_local_parent_proxy"] = parsed.hostname in {"127.0.0.1", "::1", "localhost"}

    sandbox = payload.get("tool_sandbox") or {}
    prefix = sandbox.get("command_prefix")
    executable = Path(prefix[0]) if isinstance(prefix, list) and prefix else Path("")
    checks["tool_sandbox_wrapper_trusted"] = (
        isinstance(prefix, list)
        and all(isinstance(item, str) and item for item in prefix)
        and executable.is_absolute()
        and executable.is_file()
        and _root_owned_not_writable(executable)
        and sandbox.get("child_network_namespace_id") != network.get("agent_namespace_id")
    )

    fanotify = payload.get("fanotify") or {}
    watchdog_pid = fanotify.get("watchdog_pid")
    checks["fanotify_scoped_and_watched"] = (
        fanotify.get("mark_scope") == "workspace_subtree"
        and Path(fanotify.get("mark_root", "")).resolve() == workspace.resolve()
        and isinstance(fanotify.get("response_timeout_ms"), int)
        and 0 < fanotify["response_timeout_ms"] <= 1000
        and isinstance(watchdog_pid, int)
        and Path("/proc", str(watchdog_pid)).exists()
    )

    budgets = payload.get("budgets") or {}
    syscall_enforcer_pid = budgets.get("syscall_enforcer_pid")
    checks["wall_and_syscall_budgets_set"] = (
        isinstance(budgets.get("wall_seconds"), int)
        and budgets["wall_seconds"] > 0
        and isinstance(budgets.get("max_syscalls"), int)
        and budgets["max_syscalls"] > 0
        and isinstance(syscall_enforcer_pid, int)
        and Path("/proc", str(syscall_enforcer_pid)).exists()
    )
    monitors = payload.get("monitors") or {}
    monitor_checks = []
    for source in REQUIRED_MONITORS:
        monitor = monitors.get(source) or {}
        pid = monitor.get("collector_pid")
        monitor_checks.append(
            monitor.get("active") is True
            and isinstance(monitor.get("version"), str)
            and bool(monitor["version"])
            and monitor.get("raw_stream_retained") is True
            and isinstance(monitor.get("raw_stream_path"), str)
            and isinstance(pid, int)
            and Path("/proc", str(pid)).exists()
        )
    checks["four_source_collectors_active_with_raw_streams"] = all(monitor_checks)
    try:
        launch_prefix = agent_launch_prefix(manifest_path)
    except RuntimeError:
        launch_prefix = []
    checks["per_run_cgroup_launch_wrapper_trusted"] = bool(launch_prefix)
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise RuntimeError("live poisoned safety preflight failed: " + ", ".join(failed))
    os.environ[TOOL_SANDBOX_REQUIRED_ENV] = "1"
    os.environ[TOOL_SANDBOX_PREFIX_ENV] = json.dumps(prefix)
    return {"checks": checks, "passed": True, "attestation": payload}


def assert_workspace_is_fresh_copy(
    *, workspace: Path, checkpoint_manifest_sha256: str, observed_manifest_sha256: str
) -> None:
    if workspace.exists() and any(workspace.iterdir()):
        if checkpoint_manifest_sha256 != observed_manifest_sha256:
            raise RuntimeError("workspace does not match pristine checkpoint manifest")


def archive_and_destroy_poisoned_workspace(
    *, workspace: Path, run_dir: Path
) -> dict[str, Any]:
    """Preserve one forensic archive, then make the poisoned tree non-reusable."""
    workspace = workspace.resolve()
    run_dir = run_dir.resolve()
    if workspace.parent != run_dir or workspace.name != "workspace":
        raise RuntimeError("refusing to destroy a workspace outside its dedicated run directory")
    if not workspace.is_dir():
        raise RuntimeError("poisoned workspace is absent before disposal")
    archive = run_dir / "contaminated_workspace.tar"
    if archive.exists():
        raise FileExistsError("refusing to overwrite contaminated workspace archive")
    with tarfile.open(archive, "w") as handle:
        handle.add(workspace, arcname="workspace", recursive=True)
    archive_sha256 = _sha_file(archive)
    shutil.rmtree(workspace)
    if workspace.exists():
        raise RuntimeError("poisoned workspace destruction did not complete")
    return {
        "archive": archive.name,
        "archive_sha256": archive_sha256,
        "workspace_destroyed": True,
        "workspace_reusable": False,
    }


def runtime_environment_metadata(env: Mapping[str, str]) -> dict[str, Any]:
    status = Path("/proc/self/status").read_text(encoding="utf-8", errors="replace")
    seccomp = None
    no_new_privs = None
    for line in status.splitlines():
        if line.startswith("Seccomp:"):
            seccomp = int(line.split(":", 1)[1].strip())
        if line.startswith("NoNewPrivs:"):
            no_new_privs = int(line.split(":", 1)[1].strip())
    limits = {}
    for name in (
        "RLIMIT_AS",
        "RLIMIT_CPU",
        "RLIMIT_FSIZE",
        "RLIMIT_NOFILE",
        "RLIMIT_NPROC",
    ):
        key = getattr(resource, name, None)
        if key is not None:
            limits[name] = list(resource.getrlimit(key))
    namespaces = {}
    for name in ("cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts"):
        try:
            namespaces[name] = _namespace_id(name)
        except OSError:
            namespaces[name] = None
    return {
        "environment_variable_names": sorted(env),
        "environment_values_archived": False,
        "credential_shaped_variable_names": credential_variable_names(env),
        "rlimits": limits,
        "cgroup_records": _current_cgroups(),
        "namespace_ids": namespaces,
        "seccomp_mode": seccomp,
        "no_new_privs": no_new_privs,
    }


def validate_stage_g_safety_bridge(
    manifest_path: Path,
    *,
    run_id: str,
    command: Sequence[str],
    planned_worker_env: Mapping[str, str],
) -> dict[str, Any]:
    """Validate the reviewed sandbox before Stage G releases its agent wrapper."""
    manifest_path = manifest_path.resolve()
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    checks: dict[str, bool] = {
        "schema_matches": payload.get("schema_version") == SAFETY_SCHEMA_VERSION,
        "run_id_matches": payload.get("run_id") == run_id,
        "not_previously_released": payload.get("live_poisoned_collection_started") is False,
        "credential_names_absent": not credential_variable_names(planned_worker_env),
    }
    workspace = Path(str(payload.get("workspace", "")))
    checks["workspace_exists"] = workspace.is_absolute() and workspace.is_dir()

    checkpoint = payload.get("checkpoint") or {}
    source_manifest = Path(str(checkpoint.get("source_manifest", "")))
    delivered = checkpoint.get("delivered_fixtures")
    delivered_paths: set[str] = set()
    delivered_valid = isinstance(delivered, list)
    if delivered_valid:
        for fixture in delivered:
            if not isinstance(fixture, dict) or not isinstance(fixture.get("path"), str):
                delivered_valid = False
                break
            relative = fixture["path"]
            fixture_path = workspace / relative
            delivered_paths.add(relative)
            if not fixture_path.is_file() or _sha_file(fixture_path) != fixture.get("sha256"):
                delivered_valid = False
                break
    checks["pristine_checkpoint_manifest_verified"] = (
        checks["workspace_exists"]
        and checkpoint.get("fresh_copy") is True
        and checkpoint.get("workspace_reusable") is False
        and checkpoint.get("destroy_after_run") is True
        and source_manifest.is_file()
        and _sha_file(source_manifest) == checkpoint.get("source_manifest_sha256")
        and delivered_valid
        and _workspace_manifest_sha256(workspace, exclude_paths=delivered_paths)
        == checkpoint.get("pristine_workspace_manifest_sha256")
    )

    cgroup = payload.get("cgroup") or {}
    cgroup_path = Path(str(cgroup.get("path", "")))
    limits = cgroup.get("limits") or {}
    checks["safety_cgroup_ready"] = (
        cgroup_path.is_absolute() and cgroup_path.is_dir()
        and cgroup.get("unique_per_run") is True and run_id in str(cgroup_path)
        and all(isinstance(limits.get(name), str) and limits[name]
                for name in ("pids.max", "memory.max", "cpu.max"))
    )
    network = payload.get("network") or {}
    proxy = network.get("model_proxy") or {}
    proxy_url = str(proxy.get("base_url") or "")
    parsed_proxy = urlparse(proxy_url)
    proxy_pid = proxy.get("pid")
    checks["local_parent_proxy_active"] = (
        parsed_proxy.scheme == "http"
        and parsed_proxy.hostname in {"127.0.0.1", "::1", "localhost"}
        and isinstance(proxy_pid, int) and Path("/proc", str(proxy_pid)).exists()
        and network.get("model_api_parent_only") is True
    )

    agent = payload.get("agent_process") or {}
    uid, gid = agent.get("uid"), agent.get("gid")
    ready = Path(str(agent.get("launch_ready_path", "")))
    release = Path(str(agent.get("launch_release_path", "")))
    try:
        launch_prefix = agent_launch_prefix(manifest_path)
    except RuntimeError:
        launch_prefix = []
    checks["trusted_agent_launch_wrapper"] = bool(launch_prefix)
    checks["launch_gate_paths_present"] = (
        ready.is_absolute() and release.is_absolute()
        and ready.parent == release.parent and ready.parent.is_dir()
        and not release.exists()
    )
    checks["agent_identity_declared"] = (
        isinstance(uid, int) and uid > 0 and isinstance(gid, int) and gid > 0
    )

    tool_sandbox = payload.get("tool_sandbox") or {}
    tool_prefix = tool_sandbox.get("command_prefix")
    tool_executable = Path(tool_prefix[0]) if isinstance(tool_prefix, list) and tool_prefix else Path("")
    checks["tool_netns_wrapper_trusted"] = (
        isinstance(tool_prefix, list)
        and all(isinstance(item, str) and item for item in tool_prefix)
        and tool_executable.is_absolute() and tool_executable.is_file()
        and _root_owned_not_writable(tool_executable)
        and tool_sandbox.get("child_network_namespace_id") != network.get("agent_namespace_id")
    )

    prelaunch_payload = {
        "run_id": run_id, "workspace": str(workspace),
        "worker_started": False, "agent_started": False,
        "cgroup": cgroup, "network": network,
        "fanotify": payload.get("fanotify") or {},
        "monitors": payload.get("monitors") or {},
    }
    prelaunch = evaluate_prelaunch_controls(
        prelaunch_payload, planned_worker_env=planned_worker_env
    )
    checks["reviewed_prelaunch_controls_live"] = prelaunch["preflight_passed"]
    monitors = payload.get("monitors") or {}
    checks["monitor_versions_declared"] = all(
        isinstance((monitors.get(source) or {}).get("version"), str)
        and bool((monitors.get(source) or {})["version"])
        for source in REQUIRED_MONITORS
    )
    budgets = payload.get("budgets") or {}
    enforcer_pid = budgets.get("syscall_enforcer_pid")
    checks["runtime_budget_enforcer_active"] = (
        isinstance(budgets.get("wall_seconds"), int)
        and budgets["wall_seconds"] > 0
        and isinstance(budgets.get("max_syscalls"), int)
        and budgets["max_syscalls"] > 0
        and isinstance(enforcer_pid, int)
        and Path("/proc", str(enforcer_pid)).exists()
    )
    recorded_prelaunch = payload.get("prelaunch_gate") or {}
    checks["recorded_prelaunch_gate_passed"] = (
        payload.get("preflight_passed") is True
        and recorded_prelaunch.get("preflight_passed") is True
        and recorded_prelaunch.get("failed_checks") == []
    )

    curated_entrypoint = Path(__file__).with_name("curated_live_session.py").resolve()
    command_entrypoint = Path(command[1]).resolve() if len(command) > 1 else Path("")
    checks["curated_entrypoint_locked"] = (
        len(command) > 1 and Path(command[0]).name.startswith("python")
        and command_entrypoint == curated_entrypoint
    )
    command_manifest = _command_option(command, "--safety-manifest")
    command_workspace = _command_option(command, "--workspace")
    checks["command_manifest_matches"] = (
        command_manifest is not None and Path(command_manifest).resolve() == manifest_path
    )
    checks["command_run_id_matches"] = _command_option(command, "--run-id") == run_id
    checks["command_workspace_matches"] = (
        command_workspace is not None
        and Path(command_workspace).resolve() == workspace.resolve()
    )
    checks["command_uses_attested_proxy"] = (
        _command_option(command, "--base-url") == proxy_url
        and parsed_proxy.hostname in {"127.0.0.1", "::1", "localhost"}
    )
    checks["command_variant_explicit"] = _command_option(command, "--variant") in {"clean", "poisoned"}

    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise StageGSafetyBridgeError(
            "Stage G safety bridge rejected before release: " + ", ".join(failed)
        )
    return {
        "schema_version": "assa.stage_g_safety_bridge.v1",
        "passed": True, "checks": checks, "prelaunch": prelaunch,
        "attestation": payload, "workspace": str(workspace.resolve()),
        "cgroup_path": str(cgroup_path.resolve()),
        "cgroup_id": cgroup_path.stat().st_ino,
        "runner_uid": uid, "runner_gid": gid,
        "launch_prefix": launch_prefix,
        "launch_ready_path": str(ready),
        "launch_release_path": str(release),
        "model_proxy_base_url": proxy_url,
    }
