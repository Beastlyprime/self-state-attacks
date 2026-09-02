from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import pytest

from measurement.stage_g_harness import audit as audit_module
from measurement.stage_g_harness import external as external_module
from measurement.stage_g_harness.audit import (
    AuditRulePlan, SYSCALL_FAMILIES, audit_rule_token, build_uid_rules, removal_rule,
)

from measurement.stage_g_harness.sidecars import (
    AUDIT_FROZEN_SETTINGS, AuditSidecar, ScapSidecar, capture_process_identity,
    validate_runner_scope,
)
from measurement.stage_g_harness.falco_rules import write_self_state_rules
from measurement.stage_g_harness.external import run_tool
from measurement.stage_g_harness.io import file_record, write_jsonl
from measurement.stage_g_harness.normalize import (
    Normalizer,
    build_observation_generation,
    require_same_observation_generation,
    _enrich_fd_lifecycle_file_identities,
    _enrich_file_identities,
    build_coverage,
)
from measurement.stage_g_harness.scap import (
    SCAP_OUTPUT_FORMAT, decode_capture, parse_scap_events,
)
from measurement.stage_g_harness.stide_bridge import run as run_stide_bridge
from measurement.stage_g_harness.unicorn_adapter import adapt_graph


def test_pilot_config_requires_frozen_guest(monkeypatch: pytest.MonkeyPatch) -> None:
    script = Path(__file__).parents[1] / "stage_g_harness/pilot/run_pilot.py"
    spec = importlib.util.spec_from_file_location("stage_g_run_pilot_test", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    config = script.with_name("pilot_config.json")

    monkeypatch.setattr(module.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(module.platform, "node", lambda: "development-host")
    with pytest.raises(RuntimeError, match="pilot requires x86_64"):
        module._load_config(config)

    monkeypatch.setattr(module.platform, "machine", lambda: "x86_64")
    with pytest.raises(RuntimeError, match="pilot requires guest assa-stageg"):
        module._load_config(config)

    monkeypatch.setattr(module.platform, "node", lambda: "assa-stageg")
    loaded = module._load_config(config)
    assert loaded["required_guest_hostname"] == "assa-stageg"
    assert loaded["scap"]["scope_mode"] == "dedicated_uid_with_ebpf_cgroup_attestation"


def _event(serial: int, syscall: int, *, pid: int = 100, ppid: int = 1, exit_value: int = 0,
           args: tuple[str, ...] = ("0", "0", "0", "0"),
           records: list[str] | None = None) -> str:
    timestamp = f"1700000000.{serial:03d}"
    padded = (*args, "0", "0")[:6]
    lines = [
        f'type=SYSCALL msg=audit({timestamp}:{serial}): arch=c000003e syscall={syscall} '
        f'success=yes exit={exit_value} a0={padded[0]} a1={padded[1]} a2={padded[2]} a3={padded[3]} a4={padded[4]} a5={padded[5]} '
        f'ppid={ppid} pid={pid} auid=1000 uid=2001 euid=2001 gid=2001 comm="benign" exe="/usr/bin/benign"'
    ]
    lines.extend(records or [])
    lines.append(f"type=EOE msg=audit({timestamp}:{serial}):")
    return "\n".join(lines)


def test_runner_scope_uses_proc_start_time_uid_and_cgroup() -> None:
    identity = capture_process_identity(__import__("os").getpid())
    cgroup_path = identity["cgroup_records"][0].split(":", 2)[2]
    validated = validate_runner_scope(identity["pid"], identity["real_uid"], cgroup_path)
    assert validated["process_start_time_ticks"] > 0
    assert validated["cgroup_records"] == identity["cgroup_records"]


def test_directory_manifest_and_missing_tool_are_retained(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    root.mkdir()
    (root / "clean.txt").write_text("clean\n", encoding="utf-8")
    record = file_record(root)
    assert record["kind"] == "directory"
    assert record["file_count"] == 1
    run = run_tool(["assa-command-that-does-not-exist"], tmp_path / "tool", "missing")
    assert run.exit_status == 127
    assert "command not found" in run.stderr.read_text(encoding="utf-8")


def _benign_audit_log() -> str:
    return "\n".join([
        _event(10, 257, exit_value=3, args=("ffffff9c", "7fff", "0", "0"), records=[
            'type=CWD msg=audit(1700000000.010:10): cwd="/tmp/clean"',
            'type=PATH msg=audit(1700000000.010:10): item=0 name="note.txt" inode=42 dev=08:01 mode=0100644 nametype=NORMAL',
        ]),
        _event(11, 0, exit_value=5, args=("3", "7fff", "5", "0")),
        _event(12, 32, exit_value=4, args=("3", "0", "0", "0")),
        _event(13, 56, exit_value=101, args=("0", "0", "0", "0")),
        _event(14, 59, pid=101, ppid=100, exit_value=0, records=[
            'type=PATH msg=audit(1700000000.014:14): item=0 name="/usr/bin/benign" inode=99 dev=08:01 mode=0100755 nametype=NORMAL',
        ]),
        _event(15, 41, pid=101, ppid=100, exit_value=5, args=("2", "1", "6", "0")),
        _event(16, 42, pid=101, ppid=100, exit_value=0, args=("5", "7fff", "10", "0"), records=[
            'type=SOCKADDR msg=audit(1700000000.016:16): saddr=020001BB7F0000010000000000000000',
        ]),
        _event(17, 1, pid=101, ppid=100, exit_value=5, args=("3", "7fff", "5", "0")),
        _event(18, 40, pid=101, ppid=100, exit_value=5, args=("5", "3", "0", "5")),
        _event(19, 3, pid=101, ppid=100, exit_value=0, args=("3", "0", "0", "0")),
    ]) + "\n"


def test_audit_rules_cover_frozen_families_and_scope_by_uid() -> None:
    names = [name for family in SYSCALL_FAMILIES.values() for name in family]
    assert audit_rule_token("pread64") == "pread"
    assert audit_rule_token("pwrite64") == "pwrite"
    rules = build_uid_rules(runner_uid=2001, key="oc_clean_test", arch="b64", supported=names, chunk_size=12)
    joined = " ".join(part for rule in rules for part in rule)
    assert "uid=2001" in joined
    assert "pid=" not in joined
    for required in ("openat", "close", "dup3", "clone", "execve", "connect", "recvmsg", "renameat2", "fchmodat"):
        assert required in joined
    assert removal_rule(rules[0])[1] == "-d"


def test_normalizer_tracks_fd_process_network_and_conservation(tmp_path: Path) -> None:
    audit = tmp_path / "audit.log"
    audit.write_text(_benign_audit_log(), encoding="utf-8")
    ebpf = tmp_path / "ebpf.jsonl"
    write_jsonl(ebpf, [{
        "record_type": "syscall_lifecycle", "source": "ebpf", "kind": "open", "pid": 100,
        "syscall_number": 257, "timestamp_realtime_ns": 1_700_000_000_010_000_000,
        "path": "note.txt", "result": 3,
    }])
    result = Normalizer(
        run_id="clean-unit", boot_id="boot-clean", runner_uid=2001, cgroup_id=77,
        process_catalog={"100": {"process_start_time_ticks": 500, "exe": "/usr/bin/benign"}},
    ).normalize(audit, tmp_path / "normalized", ebpf)
    rows = result["syscalls"]
    assert result["conservation"]["passed"] is True
    assert result["conservation"]["ebpf_lifecycle"]["matched_events"] == 1
    assert [row["syscall"]["name"] for row in rows] == [
        "openat", "read", "dup", "clone", "execve", "socket", "connect", "write", "sendfile", "close"
    ]
    assert rows[1]["file"]["resolved_path"] == "/tmp/clean/note.txt"
    assert rows[2]["fd"]["output_fd"] == 4
    assert rows[4]["process"]["identity_status"] == "complete"
    assert rows[4]["process"]["exec_epoch"] == 1
    assert rows[6]["socket"]["address"] == "127.0.0.1"
    assert rows[6]["socket"]["port"] == 443
    assert rows[7]["file"]["resolved_path"] == "/tmp/clean/note.txt"
    assert rows[7]["file"]["inode"] is None
    assert (
        rows[7]["file"]["fd_identity_resolution_status"]
        == "fd_lifecycle_no_audit_path_binding"
    )
    relations = {edge["relation"] for edge in result["graph"]["edges"]}
    assert {"read", "fork", "exec", "connect", "write", "transfer"} <= relations


def test_unresolved_fd_creates_event_unique_unknown_node(tmp_path: Path) -> None:
    audit = tmp_path / "audit.log"
    audit.write_text(_event(20, 0, exit_value=4, args=("9", "7fff", "4", "0")) + "\n", encoding="utf-8")
    result = Normalizer(run_id="clean-unknown", boot_id="boot", runner_uid=2001).normalize(
        audit, tmp_path / "normalized"
    )
    unknown = [node for node in result["graph"]["nodes"] if node["node_type"] == "file_unknown"]
    assert len(unknown) == 1
    assert unknown[0]["identity_status"] == "identity_incomplete"
    assert result["coverage"]["status"] == "data_insufficient"


def test_clean_held_fd_workload_reuses_one_fd(tmp_path: Path) -> None:
    script = (
        Path(__file__).parents[1]
        / "stage_g_harness/pilot/clean_held_fd_workload.py"
    )
    output = tmp_path / "held-fd.txt"
    completed = subprocess.run(
        [sys.executable, str(script), "--output", str(output)],
        check=True,
        capture_output=True,
        text=True,
    )
    report = json.loads(completed.stdout)
    assert report["input_class"] == "clean"
    assert report["same_fd_for_all_writes"] is True
    assert report["write_syscall_count"] == 3
    assert report["inode"] == output.stat().st_ino


def test_held_fd_writes_use_audit_open_path_inode_evidence(tmp_path: Path) -> None:
    state_path = "/tmp/clean-state/openclaw.json"
    audit = tmp_path / "audit.log"
    audit.write_text(_event(10, 257, exit_value=3, records=[
        'type=PATH msg=audit(1700000000.010:10): item=0 '
        'name="/tmp/clean-state/" inode=40 dev=08:01 mode=040755 nametype=PARENT',
        f'type=PATH msg=audit(1700000000.010:10): item=1 name="{state_path}" '
        'inode=42 dev=08:01 mode=0100644 nametype=NORMAL',
    ]) + "\n", encoding="utf-8")
    scap = tmp_path / "scap.events.jsonl"
    write_jsonl(scap, [
        {
            "evt.num": 100, "evt.rawtime": 1_700_000_000_050_000_000,
            "evt.dir": "<", "syscall.type": "openat", "evt.rawres": 3,
            "evt.failed": False, "thread.tid": 101, "proc.pid": 100,
            "proc.ppid": 1, "proc.exepath": "/usr/bin/benign",
            "proc.name": "benign", "user.uid": 2001, "fd.num": 3,
            "fd.type": "file", "fd.name": state_path,
        },
        {
            "evt.num": 102, "evt.rawtime": 1_700_000_000_051_000_000,
            "evt.dir": "<", "syscall.type": "write", "evt.rawres": 7,
            "evt.failed": False, "thread.tid": 101, "proc.pid": 100,
            "proc.ppid": 1, "proc.exepath": "/usr/bin/benign",
            "proc.name": "benign", "user.uid": 2001, "fd.num": 3,
            "fd.type": "file", "fd.name": state_path,
        },
        {
            "evt.num": 104, "evt.rawtime": 1_700_000_000_052_000_000,
            "evt.dir": "<", "syscall.type": "pwrite64", "evt.rawres": 5,
            "evt.failed": False, "thread.tid": 101, "proc.pid": 100,
            "proc.ppid": 1, "proc.exepath": "/usr/bin/benign",
            "proc.name": "benign", "user.uid": 2001, "fd.num": 3,
            "fd.type": "file", "fd.name": state_path,
        },
    ])
    ebpf = tmp_path / "ebpf.jsonl"
    write_jsonl(ebpf, [
        {
            "record_type": "syscall_lifecycle", "source": "ebpf", "kind": "open",
            "pid": 100, "syscall_number": 257,
            "timestamp_realtime_ns": 1_700_000_000_010_000_000,
            "path": state_path, "resolved_path": state_path,
            "resolution_method": "ebpf_open_exit", "result": 3,
        },
    ])
    result = Normalizer(
        run_id="clean-self-state", boot_id="boot-clean", runner_uid=2001,
        process_catalog={"100": {"process_start_time_ticks": 5}},
    ).normalize(audit, tmp_path / "normalized", ebpf, scap_events_path=scap)

    audit_open = next(row for row in result["syscalls"] if row["event_id"].endswith("audit:10"))
    assert audit_open["file"]["nametype"] == "NORMAL"
    assert audit_open["file"]["resolved_path"] == state_path
    assert audit_open["file"]["inode"] == 42
    assert audit_open["paths"][0]["nametype"] == "PARENT"

    writes = [
        row for row in result["syscalls"]
        if row["event_id"].endswith(("scap:102", "scap:104"))
    ]
    assert len(writes) == 2
    for write in writes:
        assert write["file"]["resolution_method"] == "ebpf_fd_table"
        assert write["file"]["dev"] == "08:01"
        assert write["file"]["inode"] == 42
        assert write["file"]["identity_resolution_method"] == "fd_lifecycle_openat_path_inode"
        identity = write["file"]["identity_evidence"]
        assert identity["open_event_id"].endswith("audit:10")
        assert identity["audit_serial"] == "10"
        assert identity["open_audit_evidence"][0]["line_start"] == 1
        assert identity["open_audit_evidence"][0]["raw_sha256"]
        assert identity["open_activation"]["event_id"].endswith("scap:100")
        assert identity["open_activation"]["delta_ns"] == 40_000_000
        assert identity["open_activation"]["method"] == "pid_fd_exact_path_nearest_time_100ms"
        assert identity["open_activation"]["scap_evidence"][0]["scap_event_number"] == 100
        assert identity["write_event_id"] == write["event_id"]
        assert identity["write_scap_evidence"][0]["scap_event_number"] in {102, 104}

    edges = [
        edge for edge in result["graph"]["edges"]
        if edge["relation"] == "write"
    ]
    assert len(edges) == 2
    nodes = {node["node_id"]: node for node in result["graph"]["nodes"]}
    for edge in edges:
        source = nodes[edge["source_node_id"]]
        destination = nodes[edge["destination_node_id"]]
        assert source["node_type"] == "process"
        assert source["attributes"]["pid"] == 100
        assert destination["node_type"] == "file"
        assert destination["identity_status"] == "complete"
        assert destination["attributes"]["resolved_path"] == state_path
        assert destination["attributes"]["dev"] == "08:01"
        assert destination["attributes"]["inode"] == 42
        assert edge["evidence"][0]["source"] == "scap"
    assert result["coverage"]["fd_path_resolved_rate"] == 1.0
    assert result["conservation"]["passed"] is True


def _fd_lifecycle_event(
    order: int,
    name: str,
    fd_number: int,
    *,
    path: str | None = None,
    inode: int | None = None,
    include_audit_path: bool = False,
) -> dict:
    is_open = name in {"open", "openat", "openat2"}
    audit = is_open or name == "close"
    file_obj = None
    if path is not None:
        file_obj = {
            "raw_path": path,
            "resolved_path": path,
            "dev": "08:01" if include_audit_path else None,
            "inode": inode if include_audit_path else None,
            "resolution_method": "audit_path" if include_audit_path else "ebpf_fd_table",
            "resolution_status": "audit_absolute" if include_audit_path else "ebpf_fd_table",
        }
    paths = []
    if include_audit_path and path is not None:
        paths.append({
            "raw_path": path,
            "resolved_path": path,
            "dev": "08:01",
            "inode": inode,
            "nametype": "NORMAL",
        })
    evidence = [{
        "source": "auditd",
        "raw_path": "/clean/raw/auditd.log",
        "audit_serial": str(order),
        "line_start": order * 3 - 2,
        "line_end": order * 3,
        "raw_sha256": "a" * 64,
    }] if audit else [{
        "source": "scap",
        "raw_path": "/clean/raw/scap.events.jsonl",
        "scap_event_number": order,
        "line": order,
        "raw_sha256": "b" * 64,
    }]
    return {
        "event_id": f"clean:fd:{order}",
        "order": {
            "merged": order,
            "timestamp_realtime_ns": order,
            "audit_serial": str(order) if audit else None,
        },
        "process": {"boot_id": "boot-clean", "pid": 100},
        "syscall": {
            "name": name,
            "success": True,
            "return_value": fd_number if is_open else 4 if name != "close" else 0,
            "arguments": {"a0": fd_number},
        },
        "fd": {
            "input_fd": None if is_open else fd_number,
            "output_fd": fd_number if is_open else None,
        },
        "file": file_obj,
        "paths": paths,
        "evidence": evidence,
    }


def test_fd_lifecycle_close_reopen_does_not_carry_stale_inode() -> None:
    first = "/state/first.txt"
    second = "/state/second.txt"
    rows = [
        _fd_lifecycle_event(1, "openat", 3, path=first, inode=42, include_audit_path=True),
        _fd_lifecycle_event(2, "close", 3),
        _fd_lifecycle_event(3, "openat", 3, path=second, inode=99, include_audit_path=True),
        _fd_lifecycle_event(4, "write", 3, path=first),
    ]
    _enrich_fd_lifecycle_file_identities(rows)
    _enrich_file_identities(rows)
    write = rows[-1]["file"]
    assert write["dev"] is None
    assert write["inode"] is None
    assert write["fd_identity_resolution_status"] == "fd_lifecycle_path_conflict"
    assert "identity_evidence" not in write


def test_fd_lifecycle_requires_byte_exact_path() -> None:
    rows = [
        _fd_lifecycle_event(
            1, "openat", 3, path="/state/held.txt", inode=42, include_audit_path=True
        ),
        _fd_lifecycle_event(2, "write", 3, path="/state/./held.txt"),
    ]
    _enrich_fd_lifecycle_file_identities(rows)
    _enrich_file_identities(rows)
    write = rows[-1]["file"]
    assert write["dev"] is None
    assert write["inode"] is None
    assert write["fd_identity_resolution_status"] == "fd_lifecycle_path_conflict"
    assert "identity_evidence" not in write


def test_fd_lifecycle_without_audit_path_evidence_stays_unknown() -> None:
    rows = [
        _fd_lifecycle_event(1, "openat", 3, path="/state/held.txt"),
        _fd_lifecycle_event(2, "write", 3, path="/state/held.txt"),
    ]
    _enrich_fd_lifecycle_file_identities(rows)
    _enrich_file_identities(rows)
    write = rows[-1]["file"]
    assert write["dev"] is None
    assert write["inode"] is None
    assert write["fd_identity_resolution_status"] == "fd_lifecycle_no_audit_path_binding"
    assert "identity_evidence" not in write


def test_prior_exact_path_identity_applies_without_fd_operand() -> None:
    path = "/state/openclaw.json"
    rows = [
        {
            "event_id": "clean:audit-path:10",
            "order": {"merged": 1, "audit_serial": "10"},
            "process": {"boot_id": "boot-clean", "pid": 100},
            "syscall": {
                "name": "chmod", "success": True, "return_value": 0,
                "arguments": {},
            },
            "fd": None,
            "paths": [{
                "raw_path": path, "resolved_path": path,
                "dev": "08:01", "inode": 42, "nametype": "NORMAL",
            }],
            "file": None,
            "evidence": [{
                "source": "auditd", "audit_serial": "10",
                "raw_path": "/clean/raw/auditd.log", "raw_sha256": "a" * 64,
                "line_start": 1, "line_end": 3,
            }],
        },
        {
            "event_id": "clean:path-write:20",
            "order": {"merged": 2, "audit_serial": "20"},
            "process": {"boot_id": "boot-clean", "pid": 100},
            "syscall": {
                "name": "truncate", "success": True, "return_value": 0,
                "arguments": {},
            },
            "fd": None,
            "paths": [],
            "file": {
                "raw_path": path, "resolved_path": path,
                "dev": None, "inode": None,
            },
            "evidence": [],
        },
    ]

    _enrich_fd_lifecycle_file_identities(rows)
    assert "fd_identity_resolution_status" not in rows[1]["file"]
    _enrich_file_identities(rows)

    write = rows[1]["file"]
    assert write["dev"] == "08:01"
    assert write["inode"] == 42
    assert write["identity_resolution_method"] == "prior_exact_path_dev_inode"
    assert write["identity_evidence"]["event_id"] == "clean:audit-path:10"
    assert write["identity_evidence"]["audit_serial"] == "10"


def test_path_identity_join_rejects_conflicting_absolute_paths() -> None:
    rows = [
        {
            "event_id": "clean:open", "order": {"merged": 1},
            "paths": [{"raw_path": "/state/openclaw.json", "resolved_path": "/state/openclaw.json",
                       "dev": "08:01", "inode": 42, "nametype": "NORMAL"}],
            "file": None,
        },
        {
            "event_id": "clean:write", "order": {"merged": 2}, "paths": [],
            "file": {"raw_path": "/other/file", "resolved_path": "/state/openclaw.json",
                     "dev": None, "inode": None},
        },
    ]
    _enrich_file_identities(rows)
    assert rows[1]["file"]["dev"] is None
    assert rows[1]["file"]["inode"] is None
    assert "identity_evidence" not in rows[1]["file"]


def test_path_identity_join_excludes_future_audit_serial() -> None:
    path = "/state/openclaw.json"
    rows = [
        {
            "event_id": "clean:open", "order": {"merged": 1, "audit_serial": "10"},
            "paths": [{"raw_path": path, "resolved_path": path,
                       "dev": "08:01", "inode": 42, "nametype": "NORMAL"}],
            "file": None,
        },
        {
            "event_id": "clean:future-open", "order": {"merged": 2, "audit_serial": "30"},
            "paths": [{"raw_path": path, "resolved_path": path,
                       "dev": "08:01", "inode": 99, "nametype": "NORMAL"}],
            "file": None,
        },
        {
            "event_id": "clean:write", "order": {"merged": 3, "audit_serial": "20"},
            "paths": [], "file": {"raw_path": path, "resolved_path": path,
                                     "dev": None, "inode": None},
        },
    ]
    _enrich_file_identities(rows)
    assert rows[2]["file"]["inode"] == 42
    assert rows[2]["file"]["identity_evidence"]["event_id"] == "clean:open"
    assert rows[2]["file"]["identity_evidence"]["audit_serial"] == "10"


def test_unicorn_adapter_conserves_edges(tmp_path: Path) -> None:
    audit = tmp_path / "audit.log"
    audit.write_text(_benign_audit_log(), encoding="utf-8")
    Normalizer(run_id="clean-unicorn", boot_id="boot", runner_uid=2001,
               process_catalog={"100": {"process_start_time_ticks": 1}}).normalize(audit, tmp_path / "normalized")
    report = adapt_graph(tmp_path / "normalized/provenance.nodes.jsonl",
                         tmp_path / "normalized/provenance.edges.jsonl", tmp_path / "unicorn")
    assert report["input_edges"] == report["output_edges"]
    assert report["dropped_edges"] == 0
    assert len((tmp_path / "unicorn/assa.edgelist").read_text().splitlines()) == report["input_edges"]


def test_falco_rules_include_all_frozen_self_state_families(tmp_path: Path) -> None:
    rules = tmp_path / "rules.yaml"
    write_self_state_rules(rules, monitored_root=tmp_path / "state", runner_uid=2001)
    text = rules.read_text(encoding="utf-8")
    assert text.startswith("- required_engine_version:")
    for token in ("open-write", "rename", "remove", "chmod", "exec", "outbound connect"):
        assert token in text
    assert "user.uid = 2001" in text


def test_real_lidds_stide_classes_on_benign_sequences(tmp_path: Path) -> None:
    repository = Path("/tmp/assa-stage-g-lid-ds")
    if not repository.is_dir():
        pytest.skip("pinned LID-DS checkout is not available")
    base = {
        "schema_version": "assa.syscall_event.v2", "run_id": "clean-train", "event_id": "",
        "order": {"timestamp_realtime_ns": 1}, "process": {"pid": 10, "tid": 10,
        "uid": 2001, "exe": "/usr/bin/benign", "identity_key": "boot:10:1:0"},
        "syscall": {"success": True, "name": ""},
        "sequence_eligible": True,
    }
    train_rows = []
    motif = ["openat", "read", "close", "openat", "write", "close", "exit_group"]
    sequence = (motif * 16)[:112]
    for index, name in enumerate(sequence):
        row = json.loads(json.dumps(base)); row["event_id"] = f"train:{index}"; row["syscall"]["name"] = name
        train_rows.append(row)
    test_rows = []
    for index, name in enumerate(sequence):
        row = json.loads(json.dumps(base)); row["run_id"] = "clean-test"; row["event_id"] = f"test:{index}"
        row["process"]["identity_key"] = "boot:11:2:0"; row["syscall"]["name"] = name; test_rows.append(row)
    train, test = tmp_path / "train.jsonl", tmp_path / "test.jsonl"
    write_jsonl(train, train_rows); write_jsonl(test, test_rows)
    result = run_stide_bridge(repository, [train], [test], 6)
    executable = result["results"]["/usr/bin/benign"]
    assert executable["normal_database_ngrams"] > 0
    assert executable["evaluated_ngrams"] > 0
    assert executable["max_training_instance_syscalls"] == 112
    assert executable["max_test_instance_syscalls"] == 112
    assert executable["scoring_gate_passed"] is True
    assert executable["unknown_ngrams"] == 0
    assert result["scoring_gate_passed"] is True

def test_stide_adapter_does_not_pass_an_empty_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run_tool(command, output_dir, name):
        output = Path(command[command.index("--output") + 1])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps({"results": {}}), encoding="utf-8")
        stdout, stderr = output_dir / f"{name}.stdout.log", output_dir / f"{name}.stderr.log"
        stdout.write_text("", encoding="utf-8")
        stderr.write_text("", encoding="utf-8")
        return external_module.ToolRun(command, 0, stdout, stderr, 1, 2)

    monkeypatch.setattr(external_module, "run_tool", fake_run_tool)
    monkeypatch.setattr(
        external_module, "record_tool_manifest",
        lambda _output_dir, **kwargs: kwargs,
    )
    manifest = external_module.run_stide(
        tmp_path / "repo", [tmp_path / "train"], [tmp_path / "test"], tmp_path / "out"
    )
    assert manifest["status"] == "data_insufficient"
    assert manifest["extra"]["result_count"] == 0
    assert manifest["extra"]["normal_database_ngrams"] == 0
    assert manifest["extra"]["evaluated_ngrams"] == 0
    assert manifest["extra"]["scoring_gate_passed"] is False



def test_normalizer_keeps_rename_accept_and_strict_ebpf_identity(tmp_path: Path) -> None:
    audit = tmp_path / "audit.log"
    audit.write_text("\n".join([
        _event(30, 82, records=[
            'type=PATH msg=audit(1700000000.030:30): item=0 name="/tmp/clean/old" inode=1 dev=08:01 mode=0100644 nametype=DELETE',
            'type=PATH msg=audit(1700000000.030:30): item=1 name="/tmp/clean/new" inode=1 dev=08:01 mode=0100644 nametype=CREATE',
        ]),
        _event(31, 41, exit_value=5, args=("2", "1", "6", "0")),
        _event(32, 43, exit_value=6, args=("5", "7fff", "10", "0"), records=[
            'type=SOCKADDR msg=audit(1700000000.032:32): saddr=02001F907F0000010000000000000000',
        ]),
        _event(33, 3, exit_value=0, args=("6", "0", "0", "0")),
    ]) + "\n", encoding="utf-8")
    ebpf = tmp_path / "ebpf.jsonl"
    write_jsonl(ebpf, [{
        "record_type": "syscall_lifecycle", "source": "ebpf", "kind": "close", "pid": 100,
        "tid": 999, "syscall_number": 3, "timestamp_realtime_ns": 1_700_000_000_033_000_000,
        "args": [7, 0, 0, 0], "result": 0, "path": "",
    }])
    result = Normalizer(run_id="clean-strict", boot_id="boot", runner_uid=2001).normalize(
        audit, tmp_path / "normalized", ebpf
    )
    rename, _, accepted, closed = result["syscalls"]
    assert rename["file"]["before"]["resolved_path"] == "/tmp/clean/old"
    assert rename["file"]["after"]["resolved_path"] == "/tmp/clean/new"
    assert accepted["socket"]["fd"] == 6
    assert accepted["socket"]["socket_key"].endswith(":fd:6")
    assert closed["evidence"] == [closed["evidence"][0]]
    assert result["conservation"]["ebpf_lifecycle"]["matched_events"] == 0


def test_audit_plan_adds_compat_rules_without_making_compat_gaps_fatal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(audit_module.platform, "machine", lambda: "x86_64")

    def supported(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "1\n", "")

    plan = AuditRulePlan.create(2001, "oc_clean_compat", runner=supported)
    rendered = [" ".join(rule) for rule in plan.rules]
    assert plan.native_arch == "b64"
    assert plan.compat_arch == "b32"
    assert plan.unsupported_syscalls == ()
    assert any("arch=b64" in rule for rule in rendered)
    assert any("arch=b32" in rule for rule in rendered)


def test_scap_readiness_requires_open_capture_fd_and_records_health(tmp_path: Path) -> None:
    capture = tmp_path / "capture.scap"
    stdout = tmp_path / "capture.stdout.log"
    stderr = tmp_path / "capture.stderr.log"
    script = """
import signal
import sys
import time
capture = open(sys.argv[1], "wb")
capture.write(b"clean-scap-canary")
capture.flush()
def stop(*_):
    sys.stderr.write("events captured: 3\\nevents dropped: 0\\n")
    sys.stderr.flush()
    capture.close()
    raise SystemExit(0)
signal.signal(signal.SIGINT, stop)
while True:
    time.sleep(0.05)
"""
    sidecar = ScapSidecar(
        capture, stdout, stderr, [sys.executable, "-c", script, str(capture)]
    )
    ready = sidecar.start(timeout=5)
    assert ready["ready"] is True
    assert ready["capture_fd"] >= 0
    result = sidecar.stop(timeout=5)
    assert result["exit_status"] == 0
    assert result["event_count"] == 3
    assert result["drop_count"] == 0
    assert result["health_status"] == "complete"


class _FakeAuditRunner:
    def __init__(self) -> None:
        self.state = {
            "enabled": 1,
            "failure": 1,
            "pid": 123,
            "rate_limit": 50,
            "backlog_limit": 256,
            "lost": 0,
            "backlog": 0,
            "backlog_wait_time": 500,
            "backlog_wait_time_actual": 0,
        }
        self.rules: list[str] = []
        self.ausearch_by_key: dict[str, str] = {}
        self.ausearch_results: dict[
            str, tuple[int, str, str]
        ] = {}

    def __call__(self, command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        if command == ["auditctl", "-s"]:
            stdout = "\n".join(f"{key} {value}" for key, value in self.state.items()) + "\n"
            return subprocess.CompletedProcess(command, 0, stdout, "")
        if command == ["auditctl", "-l"]:
            return subprocess.CompletedProcess(command, 0, "\n".join(self.rules), "")
        if command[:2] == ["auditctl", "-r"]:
            self.state["rate_limit"] = int(command[2])
        elif command[:2] == ["auditctl", "-b"]:
            self.state["backlog_limit"] = int(command[2])
        elif command[:2] == ["auditctl", "--backlog_wait_time"]:
            self.state["backlog_wait_time"] = int(command[2])
        elif command[:2] == ["auditctl", "-f"]:
            self.state["failure"] = int(command[2])
        elif command == ["auditctl", "--reset-lost"]:
            self.state["lost"] = 0
        elif command == ["auditctl", "--reset_backlog_wait_time_actual"]:
            self.state["backlog_wait_time_actual"] = 0
        elif command[0] == "auditctl" and "-a" in command:
            self.rules.append(" ".join(command))
        elif command[0] == "auditctl" and "-d" in command:
            self.rules = []
        elif command[0] == "ausearch":
            key = command[command.index("-k") + 1]
            if key in self.ausearch_results:
                return subprocess.CompletedProcess(
                    command, *self.ausearch_results[key]
                )
            return subprocess.CompletedProcess(
                command, 0, self.ausearch_by_key.get(key, ""), ""
            )
        return subprocess.CompletedProcess(command, 0, "", "")


def _audit_sidecar(
    tmp_path: Path,
    runner: _FakeAuditRunner,
    *,
    additional_keys: tuple[str, ...] = (),
    workspace_path: Path | None = None,
) -> AuditSidecar:
    rule = build_uid_rules(
        runner_uid=2001, key="oc_clean_v2", arch="b64", supported=["openat"]
    )[0]
    plan = AuditRulePlan(
        runner_uid=2001,
        key="oc_clean_v2",
        native_arch="b64",
        rules=(tuple(rule),),
        supported_syscalls=("openat",),
        unsupported_syscalls=(),
        compat_arch=None,
        compat_supported_syscalls=(),
        compat_unsupported_syscalls=(),
    )
    return AuditSidecar(
        plan,
        tmp_path / "audit.rules",
        tmp_path / "audit.raw",
        additional_keys=additional_keys,
        workspace_path=workspace_path,
        runner=runner,
        lock_path=tmp_path / "audit.lock",
        sample_interval_seconds=0,
        drain_timeout_seconds=0,
    )


def test_audit_sidecar_applies_fail_closed_settings_and_restores(tmp_path: Path) -> None:
    runner = _FakeAuditRunner()
    prior = dict(runner.state)
    sidecar = _audit_sidecar(tmp_path, runner)
    ready = sidecar.start()
    assert ready["frozen_settings"] == AUDIT_FROZEN_SETTINGS
    assert {key: runner.state[key] for key in AUDIT_FROZEN_SETTINGS} == AUDIT_FROZEN_SETTINGS
    result = sidecar.stop()
    assert result["valid"] is True
    assert result["health"]["peak_backlog"] == 0
    assert {key: runner.state[key] for key in AUDIT_FROZEN_SETTINGS} == {
        key: prior[key] for key in AUDIT_FROZEN_SETTINGS
    }
    assert sidecar._lock_handle is None


def test_audit_sidecar_marks_lost_run_invalid_and_still_restores(tmp_path: Path) -> None:
    runner = _FakeAuditRunner()
    prior = dict(runner.state)
    sidecar = _audit_sidecar(tmp_path, runner)
    sidecar.start()
    runner.state["lost"] = 2
    result = sidecar.stop()
    assert result["valid"] is False
    assert "audit_lost=2" in result["invalid_reasons"]
    assert {key: runner.state[key] for key in AUDIT_FROZEN_SETTINGS} == {
        key: prior[key] for key in AUDIT_FROZEN_SETTINGS
    }


def _keyed_audit_event(
    serial: int, key: str, *, path: str | None = None
) -> str:
    records = (
        [
            f'type=PATH msg=audit(1700000000.{serial:03d}:{serial}): '
            f'item=0 name="{path}" inode={serial + 1000} dev=08:01 '
            'mode=0100644 nametype=NORMAL'
        ]
        if path is not None
        else []
    )
    event = _event(serial, 1, exit_value=8, args=("3", "7fff", "8", "0"), records=records)
    return event.replace(
        'exe="/usr/bin/benign"',
        f'exe="/usr/bin/benign" key="{key}"',
        1,
    ) + chr(0x1D) + 'AUID="benign"\n'


def test_audit_sidecar_unions_declared_double_key_partitions(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "openclaw.json"
    legacy_key = "oclive_clean_fixture"
    runner = _FakeAuditRunner()
    runner.rules.append(f"-w {workspace} -p rwxa -k {legacy_key}")
    runner.ausearch_by_key = {
        "oc_clean_v2": _keyed_audit_event(101, "oc_clean_v2"),
        legacy_key: (
            _keyed_audit_event(102, legacy_key, path=str(target))
            + _keyed_audit_event(103, legacy_key)
        ),
    }
    old_single_key_input = runner.ausearch_by_key["oc_clean_v2"]
    assert old_single_key_input.count("type=SYSCALL") == 1
    assert str(target) not in old_single_key_input
    old_input_path = tmp_path / "old-single-key.raw"
    old_input_path.write_text(old_single_key_input, encoding="utf-8")
    old_normalized = Normalizer(
        run_id="clean-double-key-before", boot_id="boot", runner_uid=2001
    ).normalize(old_input_path, tmp_path / "normalized-before")
    assert len(old_normalized["syscalls"]) == 1
    assert all((row.get("file") or {}).get("resolved_path") != str(target)
               for row in old_normalized["syscalls"])

    sidecar = _audit_sidecar(
        tmp_path,
        runner,
        additional_keys=(legacy_key,),
        workspace_path=workspace,
    )
    ready = sidecar.start()
    assert ready["declared_keys"] == ["oc_clean_v2", legacy_key]
    result = sidecar.stop()

    merged = (tmp_path / "audit.raw").read_text(encoding="utf-8")
    accounting = json.loads(
        (tmp_path / "auditd.partitions.json").read_text(encoding="utf-8")
    )
    new_normalized = Normalizer(
        run_id="clean-double-key-after", boot_id="boot", runner_uid=2001
    ).normalize(tmp_path / "audit.raw", tmp_path / "normalized-after")
    assert result["valid"] is True
    assert merged.count("type=SYSCALL") == 3
    assert merged.count(str(target)) == 1
    assert len(new_normalized["syscalls"]) == 3
    assert any((row.get("file") or {}).get("resolved_path") == str(target)
               for row in new_normalized["syscalls"])
    assert accounting["partition_group_counts"] == {
        "oc_clean_v2": 1,
        legacy_key: 2,
    }
    assert accounting["partition_group_sum"] == 3
    assert accounting["union_group_count"] == 3
    assert accounting["interpretation_line_counts"] == {
        "oc_clean_v2": 1,
        legacy_key: 2,
    }
    assert accounting["unparsed_lines"] == {}
    assert accounting["conservation_passed"] is True


def test_audit_sidecar_accepts_declared_partition_with_no_matches(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    legacy_key = "oclive_clean_empty"
    runner = _FakeAuditRunner()
    runner.rules.append(f"-w {workspace} -p rwxa -k {legacy_key}")
    runner.ausearch_by_key["oc_clean_v2"] = _keyed_audit_event(
        111, "oc_clean_v2"
    )
    runner.ausearch_results[legacy_key] = (1, "", "<no matches>\n")
    sidecar = _audit_sidecar(
        tmp_path,
        runner,
        additional_keys=(legacy_key,),
        workspace_path=workspace,
    )
    sidecar.start()
    result = sidecar.stop()
    accounting = json.loads(
        (tmp_path / "auditd.partitions.json").read_text(encoding="utf-8")
    )
    assert result["valid"] is True
    assert result["exit_status"] == 0
    assert accounting["partition_group_counts"][legacy_key] == 0
    assert accounting["partitions"][legacy_key]["exit_status"] == 1
    assert accounting["partitions"][legacy_key]["effective_exit_status"] == 0
    assert accounting["partitions"][legacy_key]["query_status"] == "no_match"


def test_audit_sidecar_rejects_real_ausearch_error(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    legacy_key = "oclive_clean_error"
    runner = _FakeAuditRunner()
    runner.rules.append(f"-w {workspace} -p rwxa -k {legacy_key}")
    runner.ausearch_results[legacy_key] = (2, "", "cannot read audit logs\n")
    sidecar = _audit_sidecar(
        tmp_path,
        runner,
        additional_keys=(legacy_key,),
        workspace_path=workspace,
    )
    sidecar.start()
    result = sidecar.stop()
    assert result["valid"] is False
    assert result["exit_status"] == 2
    assert f"ausearch_key={legacy_key}:exit=2" in result["invalid_reasons"]


def test_audit_sidecar_rejects_unincorporated_overlapping_key(tmp_path: Path) -> None:
    runner = _FakeAuditRunner()
    runner.rules.append(
        "-a always,exit -F arch=b64 -S write -F uid=2001 -F key=benign_other_key"
    )
    sidecar = _audit_sidecar(tmp_path, runner)
    with pytest.raises(RuntimeError, match="audit partition attestation failed"):
        sidecar.start()
    assert sidecar._lock_handle is None


def test_scap_sequence_spine_enriches_from_audit_without_duplicate(tmp_path: Path) -> None:
    audit = tmp_path / "audit.log"
    audit.write_text(_event(10, 257, exit_value=3, records=[
        'type=PATH msg=audit(1700000000.010:10): item=0 name="/tmp/clean.txt" inode=42 dev=08:01 mode=0100644 nametype=NORMAL',
    ]) + "\n", encoding="utf-8")
    scap = tmp_path / "scap.events.jsonl"
    write_jsonl(scap, [
        {
            "evt.num": 1, "evt.rawtime": 1_700_000_000_010_000_000,
            "evt.dir": "<", "evt.type": "openat", "evt.rawres": 3,
            "evt.failed": False, "thread.tid": 100, "proc.pid": 100,
            "proc.ppid": 1, "proc.exepath": "/usr/bin/benign",
            "proc.name": "benign", "user.uid": 2001,
        },
        {
            "evt.num": 2, "evt.rawtime": 1_700_000_000_011_000_000,
            "evt.dir": "<", "evt.type": "getpid", "evt.rawres": 100,
            "evt.failed": False, "thread.tid": 100, "proc.pid": 100,
            "proc.ppid": 1, "proc.exepath": "/usr/bin/benign",
            "proc.name": "benign", "user.uid": 2001,
        },
    ])
    result = Normalizer(
        run_id="clean-scap", boot_id="boot", runner_uid=2001,
        process_catalog={"100": {"process_start_time_ticks": 9, "exe": "/usr/bin/benign"}},
    ).normalize(audit, tmp_path / "normalized", scap_events_path=scap)
    rows = result["syscalls"]
    assert [row["syscall"]["name"] for row in rows] == ["openat", "getpid"]
    assert all(row["sequence_eligible"] for row in rows)
    assert [evidence["source"] for evidence in rows[0]["evidence"]] == ["scap", "auditd"]
    assert rows[0]["process"]["identity_status"] == "complete"
    assert result["conservation"]["audit_scap_correlation"]["matched_audit_events"] == 1
    assert result["coverage"]["sequence_eligible_events"] == 2


def _coverage_row(index: int, resolved: bool) -> dict[str, object]:
    file_obj = (
        {"dev": "08:01", "inode": index + 1, "resolved_path": f"/tmp/{index}",
         "resolution_status": "audit_absolute", "resolution_method": "audit_path"}
        if resolved else
        {"node_type": "file_unknown", "resolution_status": "unresolved"}
    )
    return {
        "event_id": f"coverage:{index}",
        "sequence_eligible": True,
        "syscall": {"name": "read", "success": True, "return_value": 1},
        "fd": {"input_fd": index + 3},
        "file": file_obj,
        "paths": [],
        "socket": None,
        "completeness": {
            "process_identity": "complete", "path": (
                "audit_absolute" if resolved else "unresolved"
            ), "socket": "not_applicable",
        },
    }


def test_scap_fd_state_counts_as_resolved_nonlexical_path() -> None:
    row = _coverage_row(0, False)
    row["file"] = {
        "resolved_path": "/tmp/clean",
        "resolution_status": "scap_fd_state",
        "resolution_method": "scap_fd_state",
    }
    coverage = build_coverage([row], {"nodes": [], "edges": []}, [])
    assert coverage["fd_path_resolved_numerator"] == 1
    assert coverage["fd_path_operand_denominator"] == 1
    assert coverage["fd_path_resolved_rate"] == 1.0


def test_fd_path_gate_is_inclusive_at_preregistered_95_percent() -> None:
    at_threshold = [_coverage_row(index, index < 19) for index in range(20)]
    below_threshold = [_coverage_row(index, index < 18) for index in range(20)]
    graph = {"nodes": [], "edges": []}
    accepted = build_coverage(at_threshold, graph, [])
    rejected = build_coverage(below_threshold, graph, [])
    assert accepted["fd_path_resolved_numerator"] == 19
    assert accepted["fd_path_operand_denominator"] == 20
    assert accepted["fd_path_resolved_rate"] == 0.95
    assert accepted["provenance_status"] == "passed"
    assert rejected["fd_path_resolved_rate"] == 0.9
    assert rejected["provenance_status"] == "data_insufficient"


def test_scap_missing_drop_counter_is_invalid(tmp_path: Path) -> None:
    capture = tmp_path / "missing-drop.scap"
    stdout = tmp_path / "missing-drop.stdout.log"
    stderr = tmp_path / "missing-drop.stderr.log"
    script = """
import signal
import sys
import time
capture = open(sys.argv[1], "wb")
capture.write(b"clean-scap-canary")
capture.flush()
def stop(*_):
    sys.stderr.write("events captured: 1\\n")
    sys.stderr.flush()
    capture.close()
    raise SystemExit(0)
signal.signal(signal.SIGINT, stop)
while True:
    time.sleep(0.05)
"""
    sidecar = ScapSidecar(
        capture, stdout, stderr, [sys.executable, "-c", script, str(capture)]
    )
    sidecar.start(timeout=5)
    result = sidecar.stop(timeout=5)
    assert result["valid"] is False
    assert result["invalid_reasons"] == ["scap_drop_count_missing"]


def test_scap_sysdig_command_and_official_health_counters(tmp_path: Path) -> None:
    sidecar = ScapSidecar.sysdig(tmp_path, sysdig="/opt/sysdig")
    assert sidecar.command[:3] == ["/opt/sysdig", "--modern-bpf", "-v"]
    filtered = ScapSidecar.sysdig(
        tmp_path, sysdig="/opt/sysdig", capture_filter="user.uid=2001 and thread.cgroups contains \"/assa\"",
    )
    assert filtered.command[-1] == "user.uid=2001 and thread.cgroups contains \"/assa\""
    module_sidecar = ScapSidecar.sysdig(
        tmp_path, sysdig="/opt/sysdig", engine="kernel-module")
    assert module_sidecar.command[:2] == ["/opt/sysdig", "-v"]
    stderr = (
        "Driver Events:123\nDriver Drops:0\n"
        "Suppressed by Comm:0\nCaptured Events: 120, 10.0 eps\n"
    )
    assert sidecar._health_counter(stderr, "captured") == 120
    assert sidecar._health_counter(stderr, "driver") == 123
    assert sidecar._health_counter(stderr, "dropped") == 0


def test_unicorn_gate_rejects_below_threshold_coverage(tmp_path: Path) -> None:
    nodes = tmp_path / "provenance.nodes.jsonl"
    edges = tmp_path / "provenance.edges.jsonl"
    coverage = tmp_path / "coverage.json"
    write_jsonl(nodes, [
        {
            "node_id": "process:1", "node_type": "process", "identity_status": "complete",
            "attributes": {"exe": "/usr/bin/benign"},
        },
        {
            "node_id": "file:1", "node_type": "file", "identity_status": "complete",
            "attributes": {"resolved_path": "/tmp/clean"},
        },
    ])
    write_jsonl(edges, [{
        "edge_id": "edge:1", "source_node_id": "process:1",
        "destination_node_id": "file:1", "relation": "write", "order": {"merged": 1},
    }])
    coverage.write_text(json.dumps({
        "fd_path_resolved_rate": 0.94,
        "fd_path_resolved_threshold": 0.95,
        "provenance_evaluable": False,
    }), encoding="utf-8")
    report = adapt_graph(nodes, edges, tmp_path / "unicorn-gated", coverage)
    assert report["status"] == "data_insufficient"
    assert report["fd_path_resolved_rate"] == 0.94


def test_unicorn_gate_retains_unknown_nodes_after_registered_gate_passes(tmp_path: Path) -> None:
    nodes = tmp_path / "provenance.nodes.jsonl"
    edges = tmp_path / "provenance.edges.jsonl"
    coverage = tmp_path / "coverage.json"
    write_jsonl(nodes, [
        {
            "node_id": "process:1", "node_type": "process", "identity_status": "complete",
            "attributes": {"exe": "/usr/bin/benign"},
        },
        {
            "node_id": "socket_unknown:1", "node_type": "socket_unknown",
            "identity_status": "incomplete", "attributes": {},
        },
    ])
    write_jsonl(edges, [{
        "edge_id": "edge:1", "source_node_id": "process:1",
        "destination_node_id": "socket_unknown:1", "relation": "connect",
        "order": {"merged": 1},
    }])
    coverage.write_text(json.dumps({
        "fd_path_resolved_rate": 1.0,
        "fd_path_resolved_threshold": 0.95,
        "provenance_evaluable": True,
    }), encoding="utf-8")
    report = adapt_graph(nodes, edges, tmp_path / "unicorn-gated", coverage)
    assert report["status"] == "passed"
    assert report["incomplete_node_count"] == 1
    assert report["incomplete_nodes_retained"] is True
    assert report["input_edges"] == report["output_edges"] == 1


def test_scap_process_instances_track_fork_and_exec_epoch(tmp_path: Path) -> None:
    events = tmp_path / "process.events.jsonl"
    write_jsonl(events, [
        {
            "evt.num": 1, "evt.rawtime": 1, "evt.dir": "<", "evt.type": "clone",
            "evt.rawres": 101, "evt.failed": False, "thread.tid": 100,
            "proc.pid": 100, "proc.ppid": 1, "user.uid": 2001,
        },
        {
            "evt.num": 2, "evt.rawtime": 2, "evt.dir": "<", "evt.type": "execve",
            "evt.rawres": 0, "evt.failed": False, "thread.tid": 101,
            "proc.pid": 101, "proc.ppid": 100, "user.uid": 2001,
            "proc.exepath": "/usr/bin/child",
        },
        {
            "evt.num": 3, "evt.rawtime": 3, "evt.dir": "<", "evt.type": "read",
            "evt.rawres": 1, "evt.failed": False, "thread.tid": 101,
            "proc.pid": 101, "proc.ppid": 100, "user.uid": 2001,
            "proc.exepath": "/usr/bin/child",
        },
    ])
    rows, accounting = parse_scap_events(
        events, run_id="clean-process", boot_id="boot", runner_uid=2001,
        process_catalog={"100": {"process_start_time_ticks": 7}},
    )
    assert accounting["passed"] is True
    assert rows[1]["process"]["identity_status"] == "complete"
    assert rows[1]["process"]["exec_epoch"] == 0
    assert rows[2]["process"]["exec_epoch"] == 1
    assert rows[1]["process"]["identity_key"] != rows[2]["process"]["identity_key"]


def test_scap_decoder_requests_complete_named_fields_and_validates_output(
    tmp_path: Path,
) -> None:
    capture = tmp_path / "clean.scap"
    capture.write_bytes(b"clean-scap")
    observed: dict[str, object] = {}
    event = {
        "evt.num": 1,
        "evt.rawtime": 1_700_000_000_000_000_000,
        "evt.dir": "<",
        "syscall.type": "read",
        "evt.rawres": 1,
        "evt.failed": False,
        "thread.tid": 100,
        "proc.pid": 100,
        "proc.ppid": 1,
        "proc.exepath": "/usr/bin/benign",
        "proc.name": "benign",
        "user.uid": 2001,
    }

    def fake_runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        return subprocess.CompletedProcess(command, 0, json.dumps(event) + "\n", "")

    report = decode_capture(
        capture, tmp_path / "scap.events.jsonl", runner_uid=2001,
        runner=fake_runner,
    )
    command = observed["command"]
    assert isinstance(command, list)
    assert command[command.index("-p") + 1] == SCAP_OUTPUT_FORMAT
    assert {"%evt.rawtime", "%syscall.type", "%fd.name"} <= set(
        SCAP_OUTPUT_FORMAT.split()
    )
    assert report["valid"] is True
    assert report["conservation"]["normalized_exit_events"] == 1


def test_scap_unknown_result_is_not_marked_successful(tmp_path: Path) -> None:
    events = tmp_path / "unknown-result.events.jsonl"
    write_jsonl(events, [{
        "evt.num": 1,
        "evt.rawtime": 1_700_000_000_000_000_000,
        "evt.dir": "<",
        "syscall.type": "clock_nanosleep",
        "evt.rawres": None,
        "evt.res": None,
        "evt.failed": None,
        "thread.tid": 100,
        "proc.pid": 100,
        "proc.ppid": 1,
        "proc.exepath": "/usr/bin/benign",
        "proc.name": "benign",
        "user.uid": 2001,
    }])
    rows, accounting = parse_scap_events(
        events,
        run_id="clean-unknown-result",
        boot_id="boot",
        runner_uid=2001,
    )
    assert accounting["passed"] is True
    assert len(rows) == 1
    assert rows[0]["sequence_eligible"] is True
    assert rows[0]["syscall"]["success"] is None



def test_scap_ebpf_merge_accepts_missing_number_and_pid_namespace_child(tmp_path: Path) -> None:
    audit = tmp_path / "audit.empty.log"
    audit.write_text("", encoding="utf-8")
    scap = tmp_path / "scap.events.jsonl"
    write_jsonl(scap, [
        {
            "evt.num": 1, "evt.rawtime": 1_000_000_000, "evt.dir": "<",
            "syscall.type": "openat", "evt.rawres": 3, "evt.failed": False,
            "thread.tid": 100, "proc.pid": 100, "proc.ppid": 1,
            "user.uid": 2001, "fd.num": 3, "fd.type": "file",
            "fd.name": "/tmp/clean.txt",
        },
        {
            "evt.num": 2, "evt.rawtime": 1_001_000_000, "evt.dir": "<",
            "syscall.type": "write", "evt.rawres": 5, "evt.failed": False,
            "thread.tid": 100, "proc.pid": 100, "proc.ppid": 1,
            "user.uid": 2001, "fd.num": 3, "fd.type": "file",
            "fd.name": "/tmp/clean.txt",
        },
        {
            "evt.num": 3, "evt.rawtime": 1_002_000_000, "evt.dir": "<",
            "syscall.type": "clone", "evt.rawres": 13, "evt.failed": False,
            "thread.tid": 100, "proc.pid": 100, "proc.ppid": 1,
            "user.uid": 2001,
        },
        {
            "evt.num": 4, "evt.rawtime": 1_003_000_000, "evt.dir": "<",
            "syscall.type": "execve", "evt.rawres": 0, "evt.failed": False,
            "thread.tid": 101, "proc.pid": 101, "proc.ppid": 100,
            "user.uid": 2001, "proc.exepath": "/usr/bin/true",
        },
    ])
    ebpf = tmp_path / "ebpf.jsonl"
    write_jsonl(ebpf, [
        {
            "kind": "open", "pid": 100, "tid": 100, "syscall_number": 56,
            "timestamp_realtime_ns": 1_000_000_000, "result": 3,
            "args": [-100, 1, 2, 3], "path": "/tmp/clean.txt",
            "resolved_path": "/tmp/clean.txt", "resolution_method": "ebpf_open_exit",
        },
        {
            "kind": "fork", "pid": 100, "tid": 100, "syscall_number": -1,
            "timestamp_realtime_ns": 1_002_000_000, "result": 0,
            "related_pid": 101, "args": [0, 0, 0, 0],
        },
    ])
    result = Normalizer(
        run_id="clean-namespace", boot_id="boot", runner_uid=2001,
        process_catalog={"100": {"process_start_time_ticks": 9}},
    ).normalize(audit, tmp_path / "normalized", ebpf, scap)
    rows = result["syscalls"]
    assert result["conservation"]["ebpf_lifecycle"]["matched_events"] == 2
    assert rows[1]["file"]["resolution_method"] == "ebpf_fd_table"
    assert result["coverage"]["fd_path_resolved_rate"] == 1.0
    assert rows[2]["correlation"]["ebpf_lifecycle"]["pid_namespace_return_value"] == 13
    assert rows[2]["correlation"]["ebpf_lifecycle"]["related_pid"] == 101
    assert rows[3]["process"]["identity_status"] == "complete"
    assert rows[3]["process"]["process_start_evidence"].startswith("ebpf_sched_fork:")
    assert rows[3]["file"]["resolved_path"] == "/usr/bin/true"
    fork_edges = [edge for edge in result["graph"]["edges"] if edge["relation"] == "fork"]
    assert len(fork_edges) == 1
    child = next(
        node for node in result["graph"]["nodes"]
        if node["node_id"] == fork_edges[0]["destination_node_id"]
    )
    assert child["attributes"]["pid"] == 101


def test_audit_rule_removal_failure_is_fail_closed_and_restores(tmp_path: Path) -> None:
    class RemovalFailureRunner(_FakeAuditRunner):
        def __call__(self, command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            if command[0] == "auditctl" and "-d" in command:
                return subprocess.CompletedProcess(command, 1, "", "removal denied")
            return super().__call__(command, **kwargs)

    runner = RemovalFailureRunner()
    prior = dict(runner.state)
    sidecar = _audit_sidecar(tmp_path, runner)
    sidecar.start()
    with pytest.raises(RuntimeError, match="audit rule removal failed"):
        sidecar.stop()
    assert {key: runner.state[key] for key in AUDIT_FROZEN_SETTINGS} == {
        key: prior[key] for key in AUDIT_FROZEN_SETTINGS
    }
    assert sidecar._lock_handle is None



def test_scap_scope_requires_uid_and_exact_cgroup_path(tmp_path: Path) -> None:
    events = tmp_path / "scope.events.jsonl"
    base = {
        "evt.rawtime": 1, "evt.dir": "<", "syscall.type": "read",
        "evt.rawres": 1, "evt.failed": False, "thread.tid": 10,
        "proc.pid": 10, "proc.ppid": 1, "user.uid": 2001,
    }
    write_jsonl(events, [
        {**base, "evt.num": 1, "thread.cgroups": "cpu=/assa/target memory=/assa/target"},
        {**base, "evt.num": 2, "thread.cgroups": "cpu=/assa/outside memory=/assa/outside"},
    ])
    rows, accounting = parse_scap_events(
        events, run_id="clean-scope", boot_id="boot", runner_uid=2001,
        runner_cgroup_path="/assa/target",
    )
    assert [row["event_id"] for row in rows] == ["clean-scope:scap:1"]
    assert accounting["dispositions"]["out_of_scope_cgroup"] == 1
    assert accounting["passed"] is True


def test_scap_scope_can_use_cgroup_attested_pid_set(tmp_path: Path) -> None:
    events = tmp_path / "scope-pids.events.jsonl"
    base = {
        "evt.rawtime": 1, "evt.dir": "<", "syscall.type": "read",
        "evt.rawres": 1, "evt.failed": False, "thread.tid": 10,
        "proc.ppid": 1, "user.uid": 2001,
    }
    write_jsonl(events, [
        {**base, "evt.num": 1, "proc.pid": 10},
        {**base, "evt.num": 2, "proc.pid": 99},
    ])
    rows, accounting = parse_scap_events(
        events, run_id="clean-pid-scope", boot_id="boot", runner_uid=2001,
        allowed_pids={10},
    )
    assert [row["event_id"] for row in rows] == ["clean-pid-scope:scap:1"]
    assert accounting["dispositions"]["out_of_scope_pid"] == 1
    assert accounting["passed"] is True


def test_scap_fcntl_output_fd_correlates_with_ebpf_input_fd(tmp_path: Path) -> None:
    audit = tmp_path / "audit.empty.log"
    audit.write_text("", encoding="utf-8")
    scap = tmp_path / "scap.events.jsonl"
    write_jsonl(scap, [{
        "evt.num": 1, "evt.rawtime": 1_000_000_000, "evt.dir": "<",
        "syscall.type": "fcntl", "evt.rawres": 4, "evt.failed": False,
        "thread.tid": 100, "proc.pid": 100, "proc.ppid": 1,
        "user.uid": 2001, "fd.num": 4, "fd.type": "file",
        "fd.name": "/tmp/clean.txt",
    }])
    ebpf = tmp_path / "ebpf.jsonl"
    write_jsonl(ebpf, [{
        "kind": "dup", "pid": 100, "tid": 100, "syscall_number": 25,
        "timestamp_realtime_ns": 1_000_000_000, "result": 4,
        "args": [3, 1030, 0, 0],
    }])
    result = Normalizer(run_id="clean-fcntl", boot_id="boot", runner_uid=2001).normalize(
        audit, tmp_path / "normalized", ebpf, scap
    )
    row = result["syscalls"][0]
    assert result["conservation"]["ebpf_lifecycle"]["matched_events"] == 1
    assert row["correlation"]["ebpf_lifecycle"]["args"][:2] == [3, 1030]


def test_observation_generation_stamp_and_cross_generation_guard(tmp_path: Path) -> None:
    contract = {
        "harness_schema": "assa.stage_g_harness.v6",
        "collector": {"scap": "modern-bpf", "audit": "declared-key-union"},
        "file_identity": "libsinsp",
    }
    generation = build_observation_generation(contract)
    audit = tmp_path / "audit.empty.log"
    audit.write_text("", encoding="utf-8")
    result = Normalizer(
        run_id="clean-generation", boot_id="boot", runner_uid=2001
    ).normalize(
        audit, tmp_path / "normalized-generation",
        observation_generation=generation,
    )
    stamped = result["coverage"]["normalization_input"]["observation_generation"]
    assert stamped == generation
    persisted = json.loads(
        (tmp_path / "normalized-generation/normalization_input.json").read_text(encoding="utf-8")
    )
    assert persisted["observation_generation"] == generation
    replay = Normalizer(
        run_id="clean-generation-replay", boot_id="boot", runner_uid=2001
    ).normalize(
        audit, tmp_path / "normalized-generation-replay",
        audit_input_stamp=persisted,
    )
    assert replay["coverage"]["normalization_input"]["observation_generation"] == generation

    assert require_same_observation_generation(generation, generation) == (
        generation["generation_id"]
    )

    other = build_observation_generation({**contract, "file_identity": "other"})
    with pytest.raises(ValueError, match="cross-generation"):
        require_same_observation_generation(generation, other)
    with pytest.raises(ValueError, match="cross-generation"):
        Normalizer(run_id="mixed", boot_id="boot", runner_uid=2001).normalize(
            audit, tmp_path / "normalized-mixed",
            audit_input_stamp=persisted, observation_generation=other,
        )


    legacy = Normalizer(
        run_id="legacy-generation", boot_id="boot", runner_uid=2001
    ).normalize(audit, tmp_path / "normalized-legacy")
    with pytest.raises(ValueError, match="requires frozen"):
        require_same_observation_generation(
            generation, legacy["coverage"]["normalization_input"]["observation_generation"]
        )

    tampered = dict(generation)
    tampered["generation_id"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="does not match"):
        Normalizer(run_id="tampered", boot_id="boot", runner_uid=2001).normalize(
            audit, tmp_path / "normalized-tampered",
            observation_generation=tampered,
        )
