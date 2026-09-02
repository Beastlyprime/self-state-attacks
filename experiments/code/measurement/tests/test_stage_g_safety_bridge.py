from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from dataset_builder.run_safety import (
    SAFETY_SCHEMA_VERSION,
    StageGSafetyBridgeError,
    _sha_file,
    _workspace_manifest_sha256,
    require_prelaunch_controls,
    validate_stage_g_safety_bridge,
)
from measurement.stage_g_harness.pilot import run_pilot


def _manifest(tmp_path: Path) -> tuple[Path, list[str]]:
    run_id = "clean-safety-unit"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "MEMORY.md").write_text("benign\n", encoding="utf-8")
    source_manifest = tmp_path / "source_manifest.json"
    source_manifest.write_text("{}\n", encoding="utf-8")
    cgroup = tmp_path / run_id
    cgroup.mkdir()
    control = tmp_path / "control"
    control.mkdir()
    raw = tmp_path / "raw"
    raw.mkdir()
    monitors = {}
    for source in ("inotify", "fanotify", "auditd", "ebpf"):
        stream = raw / f"{source}.jsonl"
        stream.write_text("", encoding="utf-8")
        monitors[source] = {
            "active": True,
            "collector_pid": os.getpid(),
            "version": f"{source}-test",
            "raw_stream_retained": True,
            "raw_stream_path": str(stream),
        }
    monitors["auditd"].update({
        "audit_key": "oclive_clean_unit",
        "scope": "workspace_path_watch_plus_worker_pid_scoped_read_write",
        "global_uid_syscall_rule_installed": False,
        "worker_pid_syscall_rule_installed": False,
    })
    network = {
        "isolated_namespace": True,
        "namespace_id": "net:[2]",
        "supervisor_namespace_id": "net:[1]",
        "agent_namespace_id": "net:[2]",
        "egress_default_deny": True,
        "routes": [],
        "nft_ruleset": "chain output { policy drop; }",
        "tool_children_have_no_network": True,
        "model_api_parent_only": True,
        "loopback_fixture_only": True,
        "model_proxy": {
            "pid": os.getpid(),
            "base_url": "http://127.0.0.1:43123",
        },
    }
    fanotify = {
        "mark_scope": "workspace_subtree",
        "mark_root": str(workspace),
        "response_timeout_ms": 750,
        "watchdog_active": True,
        "watchdog_pid": os.getpid(),
    }
    prelaunch_payload = {
        "run_id": run_id,
        "workspace": str(workspace),
        "worker_started": False,
        "agent_started": False,
        "cgroup": {
            "path": str(cgroup),
            "unique_per_run": True,
            "limits": {
                "pids.max": "96",
                "memory.max": "805306368",
                "cpu.max": "80000 100000",
            },
        },
        "network": network,
        "fanotify": fanotify,
        "monitors": monitors,
    }
    prelaunch = require_prelaunch_controls(
        prelaunch_payload, planned_worker_env={"PATH": "/usr/bin"}
    )
    payload = {
        "schema_version": SAFETY_SCHEMA_VERSION,
        "run_id": run_id,
        "workspace": str(workspace),
        "checkpoint": {
            "fresh_copy": True,
            "workspace_reusable": False,
            "destroy_after_run": True,
            "source_manifest": str(source_manifest),
            "source_manifest_sha256": _sha_file(source_manifest),
            "pristine_workspace_manifest_sha256": _workspace_manifest_sha256(workspace),
            "delivered_fixtures": [],
        },
        "cgroup": prelaunch_payload["cgroup"],
        "network": network,
        "tool_sandbox": {
            "command_prefix": ["/usr/bin/unshare", "--map-root-user", "-n", "--"],
            "child_network_namespace_id": "net:[3]",
        },
        "fanotify": fanotify,
        "budgets": {
            "wall_seconds": 360,
            "max_syscalls": 200000,
            "syscall_enforcer_pid": os.getpid(),
        },
        "monitors": monitors,
        "agent_process": {
            "command_prefix": ["/bin/true"],
            "launch_ready_path": str(control / "agent_launch.ready.json"),
            "launch_release_path": str(control / "agent_launch.release"),
            "uid": os.getuid() or 2001,
            "gid": os.getgid() or 2001,
        },
        "prelaunch_gate": prelaunch,
        "preflight_passed": True,
        "live_poisoned_collection_started": False,
    }
    manifest = tmp_path / "run_safety_attestation.json"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    curated = Path(run_pilot.PROJECT_ROOT) / (
        "experiments/code/dataset_builder/curated_live_session.py"
    )
    command = [
        sys.executable, str(curated),
        "--workspace", str(workspace),
        "--run-id", run_id,
        "--variant", "clean",
        "--base-url", "http://127.0.0.1:43123",
        "--safety-manifest", str(manifest),
    ]
    return manifest, command


def test_stage_g_bridge_accepts_reviewed_contract(tmp_path: Path) -> None:
    manifest, command = _manifest(tmp_path)
    result = validate_stage_g_safety_bridge(
        manifest, run_id="clean-safety-unit", command=command,
        planned_worker_env={"PATH": "/usr/bin"},
    )
    assert result["passed"] is True
    key, workspace = run_pilot._bridge_audit_scope(result)
    assert key == "oclive_clean_unit"
    assert workspace == (tmp_path / "workspace").resolve()
    assert all(result["checks"].values())


@pytest.mark.parametrize(
    "mutation",
    ["proxy", "tool_netns", "watchdog", "monitor_version", "budget", "agent_uid"],
)
def test_stage_g_bridge_rejects_missing_control(
    tmp_path: Path, mutation: str
) -> None:
    manifest, command = _manifest(tmp_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    if mutation == "proxy":
        payload["network"].pop("model_proxy")
    elif mutation == "tool_netns":
        payload["tool_sandbox"].pop("command_prefix")
    elif mutation == "watchdog":
        payload["fanotify"]["watchdog_active"] = False
    elif mutation == "monitor_version":
        payload["monitors"]["scap" if "scap" in payload["monitors"] else "ebpf"].pop(
            "version"
        )
    elif mutation == "budget":
        payload["budgets"].pop("max_syscalls")
    else:
        payload["agent_process"].pop("uid")
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(StageGSafetyBridgeError, match="rejected before release"):
        validate_stage_g_safety_bridge(
            manifest, run_id="clean-safety-unit", command=command,
            planned_worker_env={"PATH": "/usr/bin"},
        )


def test_stage_g_runner_rejects_missing_legacy_audit_partition(
    tmp_path: Path,
) -> None:
    manifest, command = _manifest(tmp_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["monitors"]["auditd"].pop("audit_key")
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    validated = validate_stage_g_safety_bridge(
        manifest,
        run_id="clean-safety-unit",
        command=command,
        planned_worker_env={"PATH": "/usr/bin"},
    )
    with pytest.raises(RuntimeError, match="legacy audit declaration is incomplete"):
        run_pilot._bridge_audit_scope(validated)


def test_stage_g_bridge_rejects_direct_proxy_fallback(tmp_path: Path) -> None:
    manifest, command = _manifest(tmp_path)
    command[command.index("--base-url") + 1] = "https://openrouter.ai/api/v1"
    with pytest.raises(StageGSafetyBridgeError, match="command_uses_attested_proxy"):
        validate_stage_g_safety_bridge(
            manifest, run_id="clean-safety-unit", command=command,
            planned_worker_env={"PATH": "/usr/bin"},
        )


def test_stage_g_runner_rejects_poisoned_curated_without_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    curated = Path(run_pilot.PROJECT_ROOT) / (
        "experiments/code/dataset_builder/curated_live_session.py"
    )
    monkeypatch.setattr(run_pilot.os, "geteuid", lambda: 0)
    with pytest.raises(RuntimeError, match="requires --safety-manifest"):
        run_pilot.run(
            config_path=Path("unused"),
            run_dir=tmp_path / "must-not-exist",
            run_id="poisoned-contract-only",
            input_class="evaluation",
            command=[sys.executable, str(curated), "--variant", "poisoned"],
            descendant_timeout=1,
        )
    assert not (tmp_path / "must-not-exist").exists()
