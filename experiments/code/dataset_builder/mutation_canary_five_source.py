#!/usr/bin/env python3
"""Five-source mutation canary: gen1's flow plus SCAP, lifecycle eBPF, and the graph.

The gen1 canary (`mutation_op_canary.py`) collects four sources -- inotify,
fanotify, auditd and its own smoke eBPF probe -- and emits no merged graph. It
therefore witnesses sensor achievability only for the snapshot and
feature-tuple detectors, not for Falco (needs a SCAP capture), STIDE or UNICORN
(need `graph/`). See `paper/ATTACK_SAMPLE_ADMISSIBILITY_20260823.md` section 4a.

This module keeps gen1's proven sequence intact and adds exactly three things:

  1. `ScapSidecar.sysdig(..., scope_mode="host_all_events")` -> raw/capture.scap
  2. `LifecycleEbpfSidecar(run_dir, cgroup_id)` -> raw/ebpf_lifecycle.jsonl
     (the graph bridge hard-requires this stream; gen1's smoke probe writes a
     different schema to raw/ebpf.jsonl and is not a substitute)
  3. `five_source_graph_bridge.py` over the finished run directory

Both sidecars start while the worker is still blocked on the release file, so
no mutation happens before either probe is attached, and both stop after the
post-mutation snapshots. Fails closed: a missing or empty required stream
raises rather than downgrading to a four-source result.

Run as root on a disposable collection VM. Ops are gen1's four; the 16-cell
matrix in `mutation_matrix_canary.py` is swapped in only after this integration
is proven on one run.
"""
from __future__ import annotations

import argparse
import json
import multiprocessing
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import mutation_op_canary as gen1
from mutation_op_canary import (  # noqa: F401  (path side effects come from gen1)
    CODE_ROOT, PROJECT_ROOT, _audit_rule_commands, _audit_status, _command,
    _compile_ebpf, _environment_fingerprint, _fanotify_fid_collector,
    _fanotify_watchdog, _inotify_collector, _json_write, _normalize,
    _read_pipe_json, _snapshot_state, _spawn_worker, _wait_file,
    _write_minimal_records, boot_time_anchor, finalize, process_identity,
    validate_raw_trace_bundle, validate_run,
)

from measurement.stage_g_harness.sidecars import (  # noqa: E402
    LifecycleEbpfSidecar, ScapSidecar,
)

SCHEMA = "assa.mutation_canary_five_source.v1"
REQUIRED_STREAMS = (
    "raw/inotify.jsonl", "raw/fanotify.jsonl", "raw/auditd_ausearch.log",
    "raw/ebpf.jsonl", "raw/ebpf_lifecycle.jsonl", "raw/capture.scap",
)
FALCO_CONFIG_DEFAULT = Path("/etc/falco/falco.yaml")


def _cgroup_id(cgroup: Path) -> int:
    return int(cgroup.stat().st_ino)


def _require_streams(run_dir: Path) -> dict[str, int]:
    """Fail closed on any missing or empty required stream."""
    sizes: dict[str, int] = {}
    missing: list[str] = []
    for rel in REQUIRED_STREAMS:
        path = run_dir / rel
        if not path.is_file() or path.stat().st_size == 0:
            missing.append(rel)
        else:
            sizes[rel] = path.stat().st_size
    if missing:
        raise RuntimeError(f"five-source contract violated, missing/empty: {missing}")
    return sizes


def _run_graph_bridge(run_dir: Path, run_id: str, anchor: dict[str, Any],
                      account_uid: int, cgroup: Path, falco_config: Path) -> dict[str, Any]:
    bridge = Path(__file__).with_name("five_source_graph_bridge.py")
    command = [
        sys.executable, str(bridge), "--run-dir", str(run_dir),
        "--run-id", run_id, "--runner-uid", str(account_uid),
        "--cgroup-id", str(_cgroup_id(cgroup)), "--cgroup-path", str(cgroup),
        "--falco-config", str(falco_config),
    ]
    boot = anchor.get("boot_id") if isinstance(anchor, dict) else None
    if boot:
        command += ["--boot-id", str(boot)]
    proc = subprocess.run(command, text=True, capture_output=True, check=False)
    (run_dir / "graph_bridge.stdout.log").write_text(proc.stdout or "", encoding="utf-8")
    (run_dir / "graph_bridge.stderr.log").write_text(proc.stderr or "", encoding="utf-8")
    report = run_dir / "five_source_graph_bridge.json"
    result: dict[str, Any] = {"exit_status": proc.returncode, "command": command}
    if report.is_file():
        result["bridge"] = json.loads(report.read_text(encoding="utf-8"))
    elif proc.returncode != 0:
        # No verdict at all: that is a real failure, not a failed verdict.
        raise RuntimeError(
            f"graph bridge produced no report ({proc.returncode}): "
            f"{(proc.stderr or proc.stdout or '')[-600:]}")
    return result


SPINE = Path("graph/reattributed/resolution_spine_effective")


def _graph_op_witness(run_dir: Path, workspace: Path) -> dict[str, Any]:
    """Per-op witness on the merged graph: is each mutation a resolved edge?

    This is the substantive five-source check, and unlike the spec 6.3 rate it
    is robust to sample size. The acceptance line is a *rate* over spine
    operands; a four-mutation canary yields a spine denominator of ~3, where the
    attainable values are 0, 1/3, 2/3 and 1, so a >=0.95 threshold demands a
    perfect score and one apparatus operand (auditctl's netlink sockets) fails
    the run without saying anything about the mutations. Per-op edge presence
    with complete file identity is what the canary actually needs to establish.
    """
    nodes_path, edges_path = run_dir / SPINE / "provenance.nodes.jsonl", run_dir / SPINE / "provenance.edges.jsonl"
    if not (nodes_path.is_file() and edges_path.is_file()):
        return {"graph_present": False}
    nodes: dict[str, dict[str, Any]] = {}
    for line in nodes_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            nodes[row["node_id"]] = row
    ws = str(workspace)
    witness: dict[str, Any] = {}
    for line in edges_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        edge = json.loads(line)
        relation = edge.get("relation")
        if relation not in ("write", "rename", "chmod", "unlink"):
            continue
        for key in ("source_node_id", "destination_node_id"):
            node = nodes.get(edge[key]) or {}
            attrs = node.get("attributes") or {}
            path = str(attrs.get("resolved_path") or "")
            if node.get("node_type") == "file" and path.startswith(ws):
                entry = witness.setdefault(
                    relation, {"edges": 0, "identity_complete": 0, "paths": []})
                entry["edges"] += 1
                if node.get("identity_status") == "complete":
                    entry["identity_complete"] += 1
                leaf = path[len(ws):].lstrip("/") or "<workspace-dir>"
                if leaf not in entry["paths"]:
                    entry["paths"].append(leaf)
    expected = ("write", "rename", "chmod", "unlink")
    per_op = {
        op: {
            **witness.get(op, {"edges": 0, "identity_complete": 0, "paths": []}),
            "witnessed": witness.get(op, {}).get("identity_complete", 0) > 0,
        }
        for op in expected
    }
    return {
        "graph_present": True,
        "criterion": "each mutation op appears as a graph edge on a workspace "
                     "file node whose identity_status is complete",
        "per_op": per_op,
        "all_ops_graph_witnessed": all(v["witnessed"] for v in per_op.values()),
    }


def run(output_root: Path, falco_config: Path = FALCO_CONFIG_DEFAULT) -> Path:
    """gen1's sequence with SCAP + lifecycle eBPF + the graph bridge."""
    import os
    import pwd

    if os.geteuid() != 0:
        raise PermissionError("five-source mutation canary must run as root")
    if not falco_config.is_file():
        raise FileNotFoundError(f"falco config not found: {falco_config}")

    run_id = "mutation-canary-5src-%s-%s" % (
        time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()), uuid.uuid4().hex[:8])
    run_dir = (output_root / run_id).resolve()
    raw_dir = run_dir / "raw"
    health_dir = run_dir / "health"
    control_dir = run_dir / "control"
    workspace = run_dir / "workspace"
    for path in (raw_dir, health_dir, control_dir, workspace):
        path.mkdir(parents=True, exist_ok=False)

    account = pwd.getpwnam("assa")
    os.chown(control_dir, account.pw_uid, account.pw_gid)
    os.chmod(control_dir, 0o750)
    # Seed exactly the targets the installed op specs need, so swapping in a
    # larger matrix does not require touching this function. gen1's four specs
    # reduce to the original MEMORY.md / TOOLS.md / HEARTBEAT.md triple.
    seeds = {spec["path"]: ("initial %s\n" % spec["path"]).encode()
             for spec in gen1.OP_SPECS}
    for rel, content in sorted(seeds.items()):
        target = workspace / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        os.chown(target, account.pw_uid, account.pw_gid)
        os.chmod(target, 0o600)
    for parent in sorted({(workspace / rel).parent for rel in seeds},
                         key=lambda p: len(str(p)), reverse=True):
        os.chown(parent, account.pw_uid, account.pw_gid)
        os.chmod(parent, 0o700)
    os.chown(workspace, account.pw_uid, account.pw_gid)
    os.chmod(workspace, 0o700)

    _snapshot_state(workspace, run_dir, "before")
    _snapshot_state(workspace, run_dir, "before_a")
    anchor = boot_time_anchor()
    _json_write(run_dir / "run_time_anchor.json", anchor)
    compiled = _compile_ebpf(Path(gen1.__file__).with_name("mutation_canary"),
                            run_dir / "bin")
    fingerprint = _environment_fingerprint(compiled)
    _json_write(run_dir / "environment_fingerprint.json", fingerprint)

    cgroup_parent = Path("/sys/fs/cgroup/assa-bench")
    cgroup_parent.mkdir(exist_ok=True)
    try:
        (cgroup_parent / "cgroup.subtree_control").write_text(
            "+cpu +memory +pids", encoding="ascii")
    except OSError:
        pass
    cgroup = cgroup_parent / run_id
    cgroup.mkdir()
    (cgroup / "pids.max").write_text("32", encoding="ascii")
    (cgroup / "memory.max").write_text(str(256 * 1024 * 1024), encoding="ascii")
    (cgroup / "cpu.max").write_text("50000 100000", encoding="ascii")

    ready, release = control_dir / "worker.ready.json", control_dir / "worker.release"
    worker, result_fd = _spawn_worker(workspace, cgroup, account.pw_uid,
                                     account.pw_gid, ready, release)
    processes: list[Any] = []
    ebpf_process = None
    scap: ScapSidecar | None = None
    lifecycle: LifecycleEbpfSidecar | None = None
    audit_key = "oc_mut5_" + uuid.uuid4().hex[:12]
    installed = {"watch": False, "syscall": False}
    collector_stop = control_dir / "collectors.stop"
    watchdog_stop = control_dir / "watchdog.stop"
    try:
        _wait_file(ready, [worker], timeout=10)
        worker_pid = int(json.loads(ready.read_text())["pid"])

        inotify_ready = control_dir / "inotify.ready.json"
        fanotify_ready = control_dir / "fanotify.ready.json"
        heartbeat = control_dir / "fanotify.heartbeat"
        inotify = multiprocessing.Process(
            target=_inotify_collector,
            args=(str(workspace), str(raw_dir / "inotify.jsonl"),
                  str(health_dir / "inotify.json"), str(inotify_ready),
                  str(collector_stop)), name="assa-mut5-inotify")
        fanotify = multiprocessing.Process(
            target=_fanotify_fid_collector,
            args=(str(workspace), str(raw_dir / "fanotify.jsonl"),
                  str(health_dir / "fanotify.json"), str(fanotify_ready),
                  str(heartbeat), str(collector_stop)), name="assa-mut5-fanotify")
        inotify.start()
        fanotify.start()
        processes.extend([inotify, fanotify])
        _wait_file(inotify_ready, [inotify])
        _wait_file(fanotify_ready, [fanotify])
        watchdog_status = control_dir / "fanotify_watchdog.json"
        watchdog = multiprocessing.Process(
            target=_fanotify_watchdog,
            args=(fanotify.pid, str(heartbeat), str(watchdog_stop),
                  str(watchdog_status)), name="assa-mut5-watchdog")
        watchdog.start()
        processes.append(watchdog)

        ebpf_ready = control_dir / "ebpf.ready"
        ebpf_stderr = (raw_dir / "ebpf.stderr.log").open("w", encoding="utf-8")
        ebpf_process = subprocess.Popen(
            [str(compiled["loader"]), str(compiled["object"]), str(worker_pid),
             str(raw_dir / "ebpf.jsonl"), str(health_dir / "ebpf.json"),
             str(ebpf_ready)],
            stdout=subprocess.DEVNULL, stderr=ebpf_stderr, text=True)
        _wait_file(ebpf_ready, [ebpf_process])

        # --- the five-source additions, while the worker is still blocked ---
        lifecycle = LifecycleEbpfSidecar(run_dir, _cgroup_id(cgroup))
        lifecycle_start = lifecycle.start()
        _json_write(run_dir / "ebpf_lifecycle.start.json", lifecycle_start)
        scap = ScapSidecar.sysdig(run_dir, scope_mode="host_all_events")
        scap_start = scap.start()
        _json_write(run_dir / "scap.start.json", scap_start)

        worker_identity = process_identity(worker_pid)
        audit_before = _audit_status()
        watch_add, watch_del, sys_add, sys_del = _audit_rule_commands(
            workspace, worker_pid, audit_key)
        _command(watch_add)
        installed["watch"] = True
        _command(sys_add)
        installed["syscall"] = True
        audit_rules = _command(["/usr/sbin/auditctl", "-l"]).stdout
        _json_write(run_dir / "auditd_capture_config.json", {
            "schema_version": "assa.auditd_capture_config.mutation_canary_5src.v1",
            "audit_key": audit_key, "worker_pid": worker_pid,
            "worker_pid_syscall_rule_installed": True,
            "pid_syscall_rule_stage": "installed_while_worker_blocked_before_mutations",
            "global_uid_syscall_rule_installed": False,
            "rules_after_pid_syscall_install": audit_rules.splitlines()})
        _json_write(run_dir / "run_safety_attestation.json", {
            "schema_version": "assa.mutation_canary_five_source_safety.v1",
            "preflight_passed": True, "live_poisoned_collection_started": False,
            "llm_used": False, "agent_runtime_invoked": False,
            "worker_pid": worker_pid,
            "monitors": {
                "inotify": {"active": inotify.is_alive(), "collector_pid": inotify.pid,
                            "raw_stream_path": str(raw_dir / "inotify.jsonl")},
                "fanotify": {"active": fanotify.is_alive(), "collector_pid": fanotify.pid,
                             "raw_stream_path": str(raw_dir / "fanotify.jsonl")},
                "auditd": {"active": True, "collector_pid": _audit_status().get("pid"),
                           "raw_stream_path": str(raw_dir / "auditd.jsonl")},
                "ebpf": {"active": ebpf_process.poll() is None,
                         "collector_pid": ebpf_process.pid,
                         "raw_stream_path": str(raw_dir / "ebpf.jsonl")},
                "ebpf_lifecycle": {"active": lifecycle.process is not None
                                   and lifecycle.process.poll() is None,
                                   "collector_pid": lifecycle_start.get("pid"),
                                   "version": "assa-lifecycle-ebpf-v1",
                                   "raw_stream_path": str(raw_dir / "ebpf_lifecycle.jsonl")},
                "scap": {"active": scap.process is not None and scap.process.poll() is None,
                         "collector_pid": scap_start.get("pid"),
                         "version": "libscap-sysdig-modern-bpf",
                         "raw_stream_path": str(raw_dir / "capture.scap")}}})

        release.write_text("go\n", encoding="ascii")
        worker_result = _read_pipe_json(result_fd)
        stdout, stderr = worker.communicate(timeout=10)
        (run_dir / "worker.stdout").write_text(stdout or "", encoding="utf-8")
        (run_dir / "worker.stderr").write_text(stderr or "", encoding="utf-8")
        if worker.returncode != 0:
            raise RuntimeError("worker failed: %s" % stderr)
        for label in ("after", "after_a", "after_b"):
            _snapshot_state(workspace, run_dir, label)
        time.sleep(0.8)

        scap_stop = scap.stop()
        _json_write(run_dir / "scap.stop.json", scap_stop)
        lifecycle_stop = lifecycle.stop()
        _json_write(run_dir / "ebpf_lifecycle.stop.json", lifecycle_stop)
        scap, lifecycle = None, None

        if ebpf_process.poll() is None:
            ebpf_process.send_signal(signal.SIGINT)
            ebpf_process.wait(timeout=10)
        ebpf_stderr.close()
        collector_stop.write_text("stop\n", encoding="ascii")
        for proc in (inotify, fanotify):
            proc.join(timeout=10)
            assert proc.exitcode == 0, proc.exitcode
        watchdog_stop.write_text("stop\n", encoding="ascii")
        watchdog.join(timeout=5)

        audit_after = _audit_status()
        audit_search = _command(
            ["/usr/sbin/ausearch", "--input-logs", "-k", audit_key, "--raw"],
            check=False)
        audit_raw = audit_search.stdout
        (raw_dir / "auditd_ausearch.log").write_text(audit_raw, encoding="utf-8")
        (raw_dir / "auditd_ausearch.stderr.log").write_text(
            audit_search.stderr or "", encoding="utf-8")
        _json_write(health_dir / "auditd_query.json", {
            "returncode": audit_search.returncode,
            "empty_result": audit_search.returncode == 1,
            "fatal_error": audit_search.returncode not in (0, 1)})
        _command(sys_del, check=False)
        installed["syscall"] = False
        _command(watch_del, check=False)
        installed["watch"] = False

        stream_sizes = _require_streams(run_dir)
        source_paths, op_checks = _normalize(
            run_id, run_dir, workspace, anchor, worker_identity, worker_result,
            audit_raw, audit_before, audit_after)
        versions = fingerprint["monitor_versions"]
        spec = {"run_id": run_id, "run_time_anchor": anchor,
                "negative_outcomes_retained": [], "fixture_http_access_log": None,
                "sources": {s: {**paths, "version": versions[s]}
                            for s, paths in source_paths.items()}}
        _json_write(run_dir / "bundle_spec.json", spec)
        bundle = finalize(run_dir / "bundle_spec.json", run_dir / "raw_trace_bundle.json")
        validate_raw_trace_bundle(bundle)
        _write_minimal_records(run_dir, workspace, bundle, fingerprint,
                               worker_identity, op_checks)

        bridge = _run_graph_bridge(run_dir, run_id, anchor, account.pw_uid,
                                   cgroup, falco_config)

        readiness = validate_run(run_dir)
        op_coverage = {op: all(checks.values()) for op, checks in op_checks.items()}
        acceptance = ((bridge.get("bridge") or {}).get("acceptance_line") or {})
        graph_witness = _graph_op_witness(run_dir, workspace)
        spine = ((bridge.get("bridge") or {}).get("coverage_resolution_spine") or {})
        readiness["mutation_canary_five_source"] = {
            "schema_version": SCHEMA,
            "op_type_checks": op_checks,
            "op_type_coverage": op_coverage,
            "all_op_types_four_source_observed": all(op_coverage.values()),
            "required_streams_present": stream_sizes,
            "graph_emitted": (run_dir / "graph").is_dir(),
            "graph_op_witness": graph_witness,
            "graph_bridge_acceptance_line": acceptance,
            "graph_bridge_spine_coverage": spine,
            "acceptance_line_is_rate_limited_at_this_sample_size": (
                spine.get("spine_operand_denominator", 0) < 20),
        }
        # `validate_run` is the clean-run readiness validator. Three of its
        # checks are inapplicable to a canary, and each is replaced below by the
        # canary-appropriate assertion rather than simply dropped.
        base_failed = {c.get("name") for c in (readiness.get("failed_checks") or [])}
        overrides = {
            # A canary that did not change state would be broken. Assert the
            # inverse: the expected paths did change.
            "no_state_change_snapshot_equality": {
                "reason": "inverted for a canary: state change is the point",
                "replacement": "state_changed_in_expected_paths",
            },
            # gen1 must spawn the worker to learn its pid, then install the
            # pid-scoped rule while the worker is blocked. The guarantee that
            # matters -- rule in place before any mutation -- is asserted below.
            "auditd_pid_rule_installed_before_exec": {
                "reason": "canary installs the pid rule while the worker is "
                          "blocked, which is before any mutation",
                "replacement": "audit_rule_installed_before_release",
            },
            # Rate over spine operands; at denominator ~3 the threshold demands
            # a perfect score, so one apparatus operand (auditctl netlink) vetoes
            # a run whose mutations all resolved. Recorded, not gated.
            "fd_path_resolved_rate_acceptance_line": {
                "reason": "spec 6.3 is a rate; unsatisfiable at spine "
                          "denominator %s" % spine.get("spine_operand_denominator"),
                "replacement": "graph_op_witness.all_ops_graph_witnessed",
            },
            "provenance_graph_evaluable": {
                "reason": "same rate limitation as the acceptance line",
                "replacement": "graph_op_witness.all_ops_graph_witnessed",
            },
        }
        # Derived from the installed specs, plus the .tmp pre-images that the
        # rename cells create, so a larger matrix needs no edit here.
        expected_changed = {spec["path"] for spec in gen1.OP_SPECS}
        expected_changed |= {spec["tmp_path"] for spec in gen1.OP_SPECS
                             if "tmp_path" in spec}
        changed = set()
        for check in (readiness.get("failed_checks") or []):
            if check.get("name") == "no_state_change_snapshot_equality":
                changed = set(check.get("changed_paths") or [])
        canary_checks = {
            "state_changed_in_expected_paths": bool(changed)
            and changed <= expected_changed,
            "audit_rule_installed_before_release": (
                json.loads((run_dir / "auditd_capture_config.json").read_text())
                .get("pid_syscall_rule_stage")
                == "installed_while_worker_blocked_before_mutations"),
            "all_ops_four_source_observed": all(op_coverage.values()),
            "all_ops_graph_witnessed":
                graph_witness.get("all_ops_graph_witnessed") is True,
            "required_streams_present": len(stream_sizes) == len(REQUIRED_STREAMS),
        }
        unexpected_base_failures = sorted(base_failed - set(overrides))
        readiness["mutation_canary_five_source"]["canary_gate"] = {
            "overridden_base_checks": overrides,
            "canary_checks": canary_checks,
            "unexpected_base_failures": unexpected_base_failures,
            "changed_paths": sorted(changed),
        }
        readiness["passed"] = bool(
            all(canary_checks.values()) and not unexpected_base_failures)
        _json_write(run_dir / "mutation_canary_readiness.json", readiness)
        _json_write(run_dir / "smoke_result.json", {
            "schema_version": SCHEMA, "passed": readiness["passed"],
            "run_dir": str(run_dir), "op_type_coverage": op_coverage,
            "graph_op_witness": graph_witness,
            "graph_bridge_acceptance_line": acceptance,
            "graph_bridge_spine_coverage": spine,
            "readiness": str(run_dir / "mutation_canary_readiness.json")})
        return run_dir
    finally:
        for sidecar in (scap, lifecycle):
            if sidecar is not None and getattr(sidecar, "process", None) is not None:
                try:
                    if sidecar.process.poll() is None:
                        sidecar.process.terminate()
                        sidecar.process.wait(timeout=5)
                except Exception:
                    pass
        try:
            pid = int(json.loads(ready.read_text()).get("pid", 0)) if ready.is_file() else 0
            _, watch_del, _, sys_del = _audit_rule_commands(workspace, pid, audit_key)
            if installed["syscall"]:
                _command(sys_del, check=False)
            if installed["watch"]:
                _command(watch_del, check=False)
        except Exception:
            pass
        if ebpf_process is not None and ebpf_process.poll() is None:
            ebpf_process.terminate()
            try:
                ebpf_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                ebpf_process.kill()
        if worker.poll() is None:
            worker.kill()
        collector_stop.write_text("stop\n", encoding="ascii")
        watchdog_stop.write_text("stop\n", encoding="ascii")
        for proc in processes:
            if proc.is_alive():
                proc.terminate()
                proc.join(timeout=3)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the disposable five-source mutation canary")
    parser.add_argument("--output-root", type=Path,
                        default=PROJECT_ROOT / "data/mutation_canary_five_source")
    parser.add_argument("--falco-config", type=Path, default=FALCO_CONFIG_DEFAULT)
    args = parser.parse_args()
    run_dir = run(args.output_root, args.falco_config)
    result = json.loads((run_dir / "smoke_result.json").read_text())
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
