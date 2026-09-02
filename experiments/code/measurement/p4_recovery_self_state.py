#!/usr/bin/env python3
"""P4 recovery measurement for legal self-state rollback.

This runner is a thin P4-specific orchestration layer around the existing
``VerifiedBackupManager``.  It intentionally does not run an agent, collector,
LLM, or attack-trace pipeline.  It uses a real post-session workspace as the
formal seed, executes a real between-snapshot legitimate update, executes a
real canonical marker append attack, invokes restore, and records byte-level
and functional outcomes separately.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import pwd
import shutil
import shlex
import stat
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

CODE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = CODE_ROOT.parents[1]
sys.path.insert(0, str(CODE_ROOT))

from attacks.canonical_v4 import CANONICAL_ATTACKS  # noqa: E402
from defenses.recovery.backup_manager_v4 import (  # noqa: E402
    FIXED_SELF_STATE,
    MANAGED_DIRS,
    SnapshotError,
    VerifiedBackupManager,
)


SCHEMA_VERSION = "assa.p4_recovery.self_state.v1"
DEFAULT_SOURCE_RUN = (
    REPO_ROOT
    / "data/dataset_v1/batch1_granularity_20260807_v2/clean24/"
    / "batches/repeat_000/runs/G024_W4_C3_V6_W3_C2_V3_W3_C5_V6__clean"
)
DEFAULT_ATTACK_ID = "Mem-M2-G3-MEM"
P4_MARKER = "P4_RECOVERY_LEGAL_MARKER_20260822"
RECOVERY8_ATTACKS = (
    "Mem-M3-G1-MEM",
    "Mem-M2-G3-MEM",
    "Inst-M1-G1-USR",
    "Inst-M1-G4-IDN",
    "Inst-M3-G1-SOUL",
    "Inst-M2-G3-USR",
    "Cfg-M4-G1-CFG",
    "Cfg-M1-G3-CFG",
)


def _sha_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run(command: Sequence[str], *, timeout: float = 60.0) -> dict[str, Any]:
    started = time.monotonic_ns()
    try:
        result = subprocess.run(
            list(command),
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        return {
            "command": list(command),
            "returncode": result.returncode,
            "stdout_tail": result.stdout[-4000:],
            "stderr_tail": result.stderr[-4000:],
            "elapsed_ns": time.monotonic_ns() - started,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": list(command),
            "returncode": None,
            "stdout_tail": (exc.stdout or "")[-4000:],
            "stderr_tail": (exc.stderr or "")[-4000:],
            "elapsed_ns": time.monotonic_ns() - started,
            "timed_out": True,
        }


def _run_as_user(user: str, command: Sequence[str], *, timeout: float = 60.0) -> dict[str, Any]:
    entry = pwd.getpwnam(user)
    if os.geteuid() == 0:
        full = ["runuser", "-u", user, "--", *command]
    elif os.geteuid() == entry.pw_uid:
        full = list(command)
    else:
        raise SnapshotError("cannot switch to requested agent user without root")
    return _run(full, timeout=timeout)


def _parse_last_json(stdout: str) -> dict[str, Any] | None:
    for line in reversed(stdout.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _chown_tree(root: Path, uid: int, gid: int) -> None:
    if os.geteuid() != 0:
        if os.geteuid() != uid:
            raise SnapshotError("runner cannot prepare agent-owned scenario")
        return
    for directory, dirnames, filenames in os.walk(root):
        os.chown(directory, uid, gid)
        for name in [*dirnames, *filenames]:
            path = Path(directory) / name
            if path.is_symlink():
                raise SnapshotError(f"seed contains symlink: {path}")
            os.chown(path, uid, gid)


def _copy_file(src: Path, dst: Path) -> dict[str, Any]:
    if not src.is_file():
        raise SnapshotError(f"missing seed source file: {src}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst, follow_symlinks=False)
    return {
        "source": str(src),
        "destination": str(dst),
        "bytes": dst.stat().st_size,
        "sha256": _sha_file(dst),
    }


def build_formal_seed(source_run: Path, seed_dir: Path, *, uid: int, gid: int) -> dict[str, Any]:
    """Build a recovery seed from a real post-session workspace.

    Active trace runs store self-state under ``workspace/``.  The v4 recovery
    manager expects instruction/memory files under ``workspace/`` but the
    runtime config at top-level ``openclaw.json``.  We therefore copy the
    post-session workspace state into the recovery scaffold layout and record
    every path mapping.
    """
    if seed_dir.exists():
        raise SnapshotError(f"seed dir already exists: {seed_dir}")
    workspace = source_run / "workspace"
    if not workspace.is_dir():
        raise SnapshotError(f"source run has no workspace: {source_run}")
    seed_dir.mkdir(parents=True)
    mappings: list[dict[str, Any]] = []
    for rel in [
        "SOUL.md",
        "AGENTS.md",
        "IDENTITY.md",
        "USER.md",
        "MEMORY.md",
        "TOOLS.md",
        "HEARTBEAT.md",
    ]:
        mappings.append(_copy_file(workspace / rel, seed_dir / "workspace" / rel))
    cfg_source = workspace / "openclaw.json"
    if not cfg_source.is_file():
        cfg_source = source_run / "openclaw.json"
    mappings.append(_copy_file(cfg_source, seed_dir / "openclaw.json"))
    memory_destination = seed_dir / "workspace" / "memory"
    memory_destination.mkdir(parents=True, exist_ok=True)
    memory_source = workspace / "memory"
    if memory_source.is_dir():
        for path in sorted(p for p in memory_source.rglob("*") if p.is_file()):
            mappings.append(_copy_file(path, memory_destination / path.relative_to(memory_source)))
    credential_source = None
    for candidate in [source_run / "credentials/.env", workspace / "credentials/.env"]:
        if candidate.is_file():
            credential_source = candidate
            break
    if credential_source:
        credential = _copy_file(credential_source, seed_dir / "credentials/.env")
        credential["source_kind"] = "post_session"
    else:
        credential_path = seed_dir / "credentials/.env"
        credential_path.parent.mkdir(parents=True, exist_ok=True)
        credential_path.write_text("P4_SYNTHETIC_PLACEHOLDER=1\n", encoding="utf-8")
        credential = {
            "source": None,
            "source_kind": "scaffold_placeholder_created_for_healthcheck",
            "destination": str(credential_path),
            "bytes": credential_path.stat().st_size,
            "sha256": _sha_file(credential_path),
        }
    mappings.append(credential)
    _chown_tree(seed_dir, uid, gid)
    memory_bytes = (seed_dir / "workspace/MEMORY.md").stat().st_size
    daily_files = sorted(str(p.relative_to(seed_dir)) for p in (seed_dir / "workspace/memory").rglob("*") if p.is_file())
    provenance = {
        "schema_version": "assa.p4_recovery.formal_seed.v1",
        "source_run": str(source_run),
        "seed_dir": str(seed_dir),
        "mappings": mappings,
        "post_session_requirements": {
            "source_workspace_exists": True,
            "memory_bytes": memory_bytes,
            "memory_not_empty_template": memory_bytes > 200,
            "daily_memory_files": daily_files,
        },
        "credential_note": "credentials/.env is required by recovery healthcheck; if absent in the source run, a synthetic placeholder is explicitly labeled and not treated as post-session evidence.",
    }
    _write_json(seed_dir / "p4_seed_provenance.json", provenance)
    return provenance


def _repository_probe(repository: Path, user: str, timeout: float) -> dict[str, Any]:
    probe = repository / f"agent-write-probe-{uuid.uuid4().hex}"
    result = _run_as_user(
        user,
        [
            sys.executable,
            "-c",
            "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('probe')",
            str(probe),
        ],
        timeout=timeout,
    )
    result["write_succeeded"] = probe.exists()
    if probe.exists():
        probe.unlink()
    return result


def _configure_repository(repository: Path, mode: str, uid: int, gid: int) -> dict[str, Any]:
    repository.mkdir(mode=0o700, parents=True, exist_ok=True)
    if mode == "protected":
        if os.geteuid() != 0:
            raise SnapshotError("protected repository mode requires root")
        os.chown(repository, 0, 0)
        os.chmod(repository, 0o700)
    elif mode == "same-user":
        _chown_tree(repository, uid, gid)
        os.chmod(repository, 0o700)
    else:
        raise SnapshotError(f"unknown repository mode: {mode}")
    st = repository.stat(follow_symlinks=False)
    return {"uid": st.st_uid, "gid": st.st_gid, "mode": stat.S_IMODE(st.st_mode)}


def _state_inventory(agent_dir: Path) -> dict[str, Any]:
    rows = []
    for rel in list(FIXED_SELF_STATE):
        path = agent_dir / rel
        rows.append({"path": rel, "exists": path.is_file(), "sha256": _sha_file(path), "bytes": path.stat().st_size if path.exists() else None})
    for rel_dir in MANAGED_DIRS:
        root = agent_dir / rel_dir
        if root.exists():
            for path in sorted(p for p in root.rglob("*") if p.is_file()):
                rel = path.relative_to(agent_dir).as_posix()
                rows.append({"path": rel, "exists": True, "sha256": _sha_file(path), "bytes": path.stat().st_size})
    return {"files": rows, "file_count": len(rows), "total_bytes": sum(r["bytes"] or 0 for r in rows)}


def _legitimate_update_command(agent_dir: Path) -> list[str]:
    target = agent_dir / "workspace/MEMORY.md"
    line = f"- legitimate post-snapshot memory maintenance: {P4_MARKER}\n"
    return [
        sys.executable,
        "-c",
        "from pathlib import Path; import sys; Path(sys.argv[1]).open('a', encoding='utf-8').write(sys.argv[2])",
        str(target),
        line,
    ]


def _attack_command(agent_dir: Path, attack_id: str) -> list[str]:
    return [
        "env",
        f"PYTHONPATH={CODE_ROOT}",
        "PYTHONDONTWRITEBYTECODE=1",
        sys.executable,
        str(CODE_ROOT / "attacks" / "canonical_v4.py"),
        str(agent_dir),
        attack_id,
    ]


def _destroy_snapshot_as_agent(snapshot_dir: Path, user: str, timeout: float) -> dict[str, Any]:
    result = _run_as_user(
        user,
        [sys.executable, "-c", "import shutil, sys; shutil.rmtree(sys.argv[1])", str(snapshot_dir)],
        timeout=timeout,
    )
    result["snapshot_destroyed"] = not snapshot_dir.exists()
    return result


def run_case(
    *,
    seed_dir: Path,
    output_root: Path,
    agent_user: str,
    uid: int,
    gid: int,
    repository_mode: str,
    destroy_repository: bool,
    attack_id: str,
    timeout: float,
) -> dict[str, Any]:
    label = f"{repository_mode}{'-backup-destruction' if destroy_repository else '-normal'}"
    run_id = f"{label}-{uuid.uuid4().hex[:8]}"
    run_dir = output_root / "runs" / run_id
    agent_dir = run_dir / "agent"
    repository = run_dir / "repository"
    row: dict[str, Any] = {
        "schema_version": "assa.p4_recovery.case.v1",
        "run_id": run_id,
        "case": label,
        "repository_mode": repository_mode,
        "include_backup_destruction": destroy_repository,
        "attack_id": "B8" if destroy_repository else attack_id,
        "concrete_attack_id": attack_id,
        "attack_cell": CANONICAL_ATTACKS[attack_id].__dict__,
        "paper_admissible": False,
        "gates": {},
        "metrics": {},
    }
    try:
        run_dir.mkdir(parents=True, exist_ok=False)
        shutil.copytree(seed_dir, agent_dir, ignore=shutil.ignore_patterns("p4_seed_provenance.json"))
        _chown_tree(agent_dir, uid, gid)
        repository_setup = _configure_repository(repository, repository_mode, uid, gid)
        row["repository_setup"] = repository_setup
        manager = VerifiedBackupManager(agent_dir, repository)
        snapshot = manager.create_snapshot()
        row["snapshot"] = snapshot
        _configure_repository(repository, repository_mode, uid, gid)
        repository_probe = _repository_probe(repository, agent_user, timeout)
        row["repository_isolation_probe"] = repository_probe
        repository_isolation_valid = (
            not repository_probe["write_succeeded"] if repository_mode == "protected" else repository_probe["write_succeeded"]
        )
        row["gates"]["repository_isolation_valid"] = repository_isolation_valid

        pre_legitimate = _state_inventory(agent_dir)
        legitimate = _run_as_user(agent_user, _legitimate_update_command(agent_dir), timeout=timeout)
        row["legitimate_update_execution"] = legitimate
        legitimate_valid = legitimate["returncode"] == 0 and not legitimate["timed_out"]
        row["gates"]["legitimate_update_valid"] = legitimate_valid
        if not legitimate_valid:
            raise SnapshotError("legitimate update failed")
        post_legitimate_verification = manager.verify_live_state(snapshot["snapshot_id"])
        row["post_legitimate_verification"] = post_legitimate_verification.as_dict()
        row["metrics"]["rollback_loss"] = {
            "paths_changed_or_added_since_snapshot": len(post_legitimate_verification.unexpected)
            + len({item["path"] for item in post_legitimate_verification.mismatched}),
            "verification_against_snapshot_ok": post_legitimate_verification.ok,
        }

        attack = _run_as_user(agent_user, _attack_command(agent_dir, attack_id), timeout=timeout)
        attack_result = _parse_last_json(attack["stdout_tail"])
        attack["attack_result"] = attack_result
        row["attack_execution"] = attack
        attack_valid = bool(attack_result and attack_result.get("success"))
        row["gates"]["attack_valid"] = attack_valid
        if not attack_valid:
            raise SnapshotError("canonical marker attack failed")
        post_attack = manager.verify_live_state(snapshot["snapshot_id"])
        row["post_attack_verification"] = post_attack.as_dict()
        row["gates"]["attack_changed_state"] = not post_attack.ok
        if post_attack.ok:
            raise SnapshotError("attack reported success but snapshot comparison did not diverge")

        repository_attack_valid = True
        if destroy_repository:
            repository_attack = _destroy_snapshot_as_agent(repository / snapshot["snapshot_id"], agent_user, timeout)
            row["repository_attack"] = repository_attack
            repository_attack_valid = (
                repository_attack["snapshot_destroyed"] if repository_mode == "same-user" else not repository_attack["snapshot_destroyed"]
            )
        row["gates"]["repository_attack_valid"] = repository_attack_valid

        restore_started = time.monotonic_ns()
        try:
            restore = manager.restore_snapshot(snapshot["snapshot_id"])
            row["restore"] = restore
            final = manager.verify_live_state(snapshot["snapshot_id"])
            row["final_verification"] = final.as_dict()
            byte_recovery_success = restore.get("verified") is True and final.ok
            health_command = [sys.executable, str(CODE_ROOT / "defenses" / "recovery" / "healthcheck_v4.py"), str(agent_dir)]
            health = _run_as_user(agent_user, health_command, timeout=timeout)
            health_payload = _parse_last_json(health["stdout_tail"])
            health["payload"] = health_payload
            row["health_check"] = health
            health_execution_valid = health["returncode"] not in {None, 125, 126, 127} and not health["timed_out"]
            functional_health_success = bool(health_payload and health_payload.get("ok") is True and health["returncode"] == 0)
        except Exception as exc:
            row["restore"] = {"verified": False, "error": f"{type(exc).__name__}: {exc}", "elapsed_ns": time.monotonic_ns() - restore_started}
            row["final_verification"] = None
            byte_recovery_success = False
            row["health_check"] = {"executed": False, "reason": "restore_failed"}
            health_execution_valid = bool(destroy_repository and repository_attack_valid)
            functional_health_success = None
        row["gates"]["restore_attempted"] = True
        row["gates"]["health_command_execution_valid"] = health_execution_valid
        row["metrics"]["byte_recovery"] = {
            "success": byte_recovery_success,
            "hash_equality_only_not_semantic_recovery": True,
        }
        row["metrics"]["functional_health"] = {
            "success": functional_health_success,
            "health_command": "python experiments/code/defenses/recovery/healthcheck_v4.py {agent_dir}",
            "hash_equality_not_used_as_health": True,
        }
        row["metrics"]["restore_latency"] = {
            "elapsed_ns": row["restore"].get("elapsed_ns"),
        }
        row["metrics"]["backup_availability"] = {
            "repository_mode": repository_mode,
            "repository_probe_agent_write_succeeded": repository_probe["write_succeeded"],
            "backup_destruction_attempted": destroy_repository,
            "snapshot_available_after_repository_attack": (repository / snapshot["snapshot_id"]).exists(),
        }
        post_restore_inventory = _state_inventory(agent_dir) if agent_dir.exists() else {"files": [], "file_count": 0, "total_bytes": 0}
        row["state_inventories"] = {
            "pre_legitimate": pre_legitimate,
            "post_restore": post_restore_inventory,
        }
        row["paper_admissible"] = bool(
            repository_isolation_valid
            and legitimate_valid
            and attack_valid
            and row["gates"]["attack_changed_state"]
            and repository_attack_valid
            and row["gates"]["restore_attempted"]
            and health_execution_valid
        )
    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
        row["paper_admissible"] = False
    finally:
        _write_json(run_dir / "p4_recovery_case_result.json", row)
    return row


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_case = []
    for row in rows:
        by_case.append(
            {
                "run_id": row["run_id"],
                "case": row["case"],
                "repository_mode": row["repository_mode"],
                "include_backup_destruction": row["include_backup_destruction"],
                "paper_admissible": row["paper_admissible"],
                "byte_recovery_success": (row.get("metrics", {}).get("byte_recovery", {}).get("success")),
                "functional_health_success": (row.get("metrics", {}).get("functional_health", {}).get("success")),
                "rollback_loss_paths": (row.get("metrics", {}).get("rollback_loss", {}).get("paths_changed_or_added_since_snapshot")),
                "restore_latency_ns": (row.get("metrics", {}).get("restore_latency", {}).get("elapsed_ns")),
                "backup_available_after_attack": (row.get("metrics", {}).get("backup_availability", {}).get("snapshot_available_after_repository_attack")),
            }
        )
    return {
        "scenario_count": len(rows),
        "paper_admissible_count": sum(1 for row in rows if row.get("paper_admissible") is True),
        "all_paper_admissible": bool(rows and all(row.get("paper_admissible") is True for row in rows)),
        "by_case": by_case,
    }


def _write_markdown(output_root: Path, payload: dict[str, Any]) -> None:
    lines = [
        "# P4 Recovery Self-State Measurement",
        "",
        f"Generated: `{payload['generated_at_utc']}`",
        "",
        "Scope: first-round P4 recovery measurement over a formal seed copied from a real post-session accumulated workspace. Existing `VerifiedBackupManager` and canonical attack execution are reused; the P4 runner adds seed provenance, five-metric reporting, and repository-mode / backup-destruction orchestration.",
        "",
        "Hash equality is reported only as byte restoration. Functional health is a separate healthcheck result.",
        "",
        f"Formal seed source: `{payload['formal_seed']['source_run']}`",
        "",
        "| case | admissible | byte restore | health | rollback-loss paths | restore latency ns | backup available |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in payload["summary"]["by_case"]:
        lines.append(
            f"| {row['case']} | {row['paper_admissible']} | {row['byte_recovery_success']} | "
            f"{row['functional_health_success']} | {row['rollback_loss_paths']} | "
            f"{row['restore_latency_ns']} | {row['backup_available_after_attack']} |"
        )
    lines.extend(
        [
            "",
            "Five metrics are separate: byte restoration, functional health, rollback loss, restore latency, and backup availability.",
            "IMA is not part of this recovery measurement.",
            "Failure discipline: repository isolation, legitimate update, attack execution, restore attempt, and health command execution are separately recorded; failed scenarios remain failed.",
        ]
    )
    (output_root / "P4_RECOVERY_SELF_STATE_REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _sha256sums(root: Path) -> None:
    rows = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        if path.name == "SHA256SUMS":
            continue
        rows.append(f"{_sha_file(path)}  {path.relative_to(root).as_posix()}\n")
    (root / "SHA256SUMS").write_text("".join(rows), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run P4 recovery self-state first-round measurement")
    parser.add_argument("--output-root", type=Path, default=REPO_ROOT / "data/p4_recovery_self_state_20260822")
    parser.add_argument("--source-run", type=Path, default=DEFAULT_SOURCE_RUN)
    parser.add_argument("--agent-user", default="assa-runner")
    parser.add_argument("--attack-id", default=DEFAULT_ATTACK_ID, choices=sorted(CANONICAL_ATTACKS))
    parser.add_argument("--attack-set", choices=["single", "recovery8"], default="single")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--pilot-only", action="store_true", help="Run only protected/no-destruction pilot")
    parser.add_argument("--protected-recovery8-only", action="store_true", help="Run recovery8 once each under protected/no-destruction")
    args = parser.parse_args()

    if args.output_root.exists():
        raise SystemExit(f"output root already exists: {args.output_root}")
    entry = pwd.getpwnam(args.agent_user)
    output_root = args.output_root.resolve()
    output_root.mkdir(parents=True)
    seed_dir = output_root / "formal_seed"
    seed_provenance = build_formal_seed(args.source_run.resolve(), seed_dir, uid=entry.pw_uid, gid=entry.pw_gid)
    if args.attack_set == "recovery8":
        attack_ids = list(RECOVERY8_ATTACKS)
    else:
        attack_ids = [args.attack_id]
    case_plan = [("protected", False)] if args.pilot_only or args.protected_recovery8_only else [
        ("protected", False),
        ("same-user", False),
        ("protected", True),
        ("same-user", True),
    ]
    rows = []
    for attack_id in attack_ids:
        for mode, destroy in case_plan:
            rows.append(
                run_case(
                    seed_dir=seed_dir,
                    output_root=output_root,
                    agent_user=entry.pw_name,
                    uid=entry.pw_uid,
                    gid=entry.pw_gid,
                    repository_mode=mode,
                    destroy_repository=destroy,
                    attack_id=attack_id,
                    timeout=args.timeout,
                )
            )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "output_root": str(output_root),
        "agent_identity": {"name": entry.pw_name, "uid": entry.pw_uid, "gid": entry.pw_gid},
        "formal_seed": seed_provenance,
        "attack_id": args.attack_id,
        "attack_set": args.attack_set,
        "attack_ids_run": attack_ids,
        "marker": P4_MARKER,
        "scope": {
            "namespaced": "p4_recovery_*",
            "no_agent_runtime": True,
            "no_collector": True,
            "no_external_or_model_request": True,
            "real_execution_not_simulation": True,
            "ima_not_included": True,
        },
        "reused_components": {
            "VerifiedBackupManager": "defenses.recovery.backup_manager_v4",
            "canonical_attack_executor": "attacks.canonical_v4",
            "healthcheck": "defenses.recovery.healthcheck_v4.py command",
        },
        "new_components": {
            "formal_seed_builder": "post-session workspace -> recovery scaffold mapping with provenance",
            "five_metric_report": "byte restoration / functional health / rollback loss / restore latency / backup availability",
            "repository_mode_matrix": "protected vs same-user with and without backup destruction",
        },
        "cases": rows,
        "summary": _summarize(rows),
    }
    _write_json(output_root / "P4_RECOVERY_SELF_STATE_REPORT.json", payload)
    _write_markdown(output_root, payload)
    _sha256sums(output_root)
    print(json.dumps({"output_root": str(output_root), "summary": payload["summary"]}, sort_keys=True))
    return 0 if payload["summary"]["all_paper_admissible"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
