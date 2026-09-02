#!/usr/bin/env python3
"""Real file-level recovery experiment for the active OpenClaw scaffold."""

from __future__ import annotations

import argparse
import json
import os
import pwd
import shlex
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXPERIMENTS_ROOT = PROJECT_ROOT.parent
sys.path.insert(0, str(PROJECT_ROOT))

from attacks.canonical_v4 import CANONICAL_ATTACKS  # noqa: E402
from defenses.recovery.backup_manager_v4 import (  # noqa: E402
    SnapshotError,
    VerifiedBackupManager,
)
from defenses.runtime_manifest import runtime_manifest  # noqa: E402
from defenses.runtime_identity import audit_agent_identity  # noqa: E402


SCHEMA_VERSION = "assa.recovery.real.v1"
RECOVERY9_ATTACKS = (
    "Mem-M3-G1-MEM",
    "Mem-M2-G3-MEM",
    "Inst-M1-G1-USR",
    "Inst-M1-G4-IDN",
    "Inst-M3-G1-SOUL",
    "Inst-M2-G3-USR",
    "Cfg-M4-G1-CFG",
    "Cfg-M1-G3-CFG",
)


def _run_as_user(
    user: str,
    command: Sequence[str],
    *,
    timeout: float,
) -> dict:
    entry = pwd.getpwnam(user)
    if os.geteuid() == 0:
        complete = ["runuser", "-u", user, "--", *command]
    elif os.geteuid() == entry.pw_uid:
        complete = list(command)
    else:
        raise SnapshotError("cannot switch to requested agent user without root")
    started_ns = time.monotonic_ns()
    try:
        result = subprocess.run(
            complete,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        return {
            "command": complete,
            "returncode": result.returncode,
            "stdout": result.stdout[-4000:],
            "stderr": result.stderr[-4000:],
            "elapsed_ns": time.monotonic_ns() - started_ns,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": complete,
            "returncode": None,
            "stdout": (exc.stdout or "")[-4000:],
            "stderr": (exc.stderr or "")[-4000:],
            "elapsed_ns": time.monotonic_ns() - started_ns,
            "timed_out": True,
        }


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


def _attack_command(agent_dir: Path, attack_id: str) -> list[str]:
    return [
        "env",
        f"PYTHONPATH={PROJECT_ROOT}",
        "PYTHONDONTWRITEBYTECODE=1",
        sys.executable,
        str(PROJECT_ROOT / "attacks" / "canonical_v4.py"),
        str(agent_dir),
        attack_id,
    ]


def _parse_json(stdout: str) -> dict | None:
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _repository_probe(repository: Path, user: str, timeout: float) -> dict:
    probe = repository / f"agent-write-probe-{uuid.uuid4().hex}"
    command = [
        sys.executable,
        "-c",
        "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('probe')",
        str(probe),
    ]
    result = _run_as_user(user, command, timeout=timeout)
    result["write_succeeded"] = probe.exists()
    probe.unlink(missing_ok=True)
    return result


def _destroy_snapshot_as_agent(snapshot_dir: Path, user: str, timeout: float) -> dict:
    command = [
        sys.executable,
        "-c",
        "import shutil, sys; shutil.rmtree(sys.argv[1])",
        str(snapshot_dir),
    ]
    result = _run_as_user(user, command, timeout=timeout)
    result["snapshot_destroyed"] = not snapshot_dir.exists()
    return result


def _configure_repository(repository: Path, mode: str, uid: int, gid: int) -> None:
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


def run_scenario(
    *,
    seed: Path,
    work_root: Path,
    attack_id: str,
    agent_user: str,
    repository_mode: str,
    profile: str,
    legitimate_command: str | None,
    health_command: str | None,
    timeout: float,
    destroy_repository: bool = False,
) -> dict:
    entry = pwd.getpwnam(agent_user)
    reported_attack_id = "B8" if destroy_repository else attack_id
    run_id = f"{profile}-{reported_attack_id}-{uuid.uuid4().hex[:8]}"
    scenario_root = work_root / run_id
    agent_dir = scenario_root / "agent"
    repository = scenario_root / "repository"
    row = {
        "run_id": run_id,
        "profile": profile,
        "attack_id": reported_attack_id,
        "concrete_attack_id": attack_id,
        "paper_cell": "backup-destruction-sentinel" if destroy_repository else "-".join(attack_id.split("-")[:3]),
        "destroys_repository": destroy_repository,
        "repository_mode": repository_mode,
        "paper_admissible": False,
    }
    try:
        scenario_root.mkdir(parents=True)
        shutil.copytree(seed, agent_dir, symlinks=True)
        _chown_tree(agent_dir, entry.pw_uid, entry.pw_gid)
        target = agent_dir / CANONICAL_ATTACKS[attack_id].target_file
        if not target.exists():
            raise SnapshotError(f"canonical target missing from seed: {target}")

        repository.mkdir(mode=0o700)
        _configure_repository(repository, repository_mode, entry.pw_uid, entry.pw_gid)
        manager = VerifiedBackupManager(agent_dir, repository)
        snapshot = manager.create_snapshot()
        row["snapshot"] = snapshot
        # Snapshot creation may add root-owned children. Apply the requested
        # threat model only after publication.
        _configure_repository(repository, repository_mode, entry.pw_uid, entry.pw_gid)
        probe = _repository_probe(repository, agent_user, timeout)
        row["repository_isolation_probe"] = probe
        isolation_valid = (
            not probe["write_succeeded"]
            if repository_mode == "protected"
            else probe["write_succeeded"]
        )

        if legitimate_command:
            rendered = legitimate_command.format(agent_dir=str(agent_dir), profile=profile)
            legitimate = _run_as_user(agent_user, shlex.split(rendered), timeout=timeout)
            row["legitimate_execution"] = legitimate
            if legitimate["returncode"] != 0 or legitimate["timed_out"]:
                raise SnapshotError("legitimate between-snapshot workload failed")
        else:
            row["legitimate_execution"] = {"status": "not_configured"}

        rollback_delta = manager.verify_live_state(snapshot["snapshot_id"])
        row["pre_attack_rollback_delta"] = rollback_delta.as_dict()
        row["rollback_loss_paths"] = len(rollback_delta.unexpected) + len({
            item["path"] for item in rollback_delta.mismatched
        })

        attack = _run_as_user(
            agent_user,
            _attack_command(agent_dir, attack_id),
            timeout=timeout,
        )
        attack_result = _parse_json(attack["stdout"])
        attack["attack_result"] = attack_result
        row["attack_execution"] = attack
        if not attack_result or not attack_result.get("success"):
            raise SnapshotError("canonical attack did not execute successfully")
        corrupted = manager.verify_live_state(snapshot["snapshot_id"])
        row["post_attack_verification"] = corrupted.as_dict()
        if corrupted.ok:
            raise SnapshotError("attack reported success but state did not diverge")

        repository_attack_valid = True
        repository_destroyed = False
        if destroy_repository:
            repository_attack = _destroy_snapshot_as_agent(
                repository / snapshot["snapshot_id"], agent_user, timeout
            )
            row["repository_attack"] = repository_attack
            repository_destroyed = repository_attack["snapshot_destroyed"]
            repository_attack_valid = (
                repository_destroyed if repository_mode == "same-user"
                else not repository_destroyed
            )

        try:
            restore = manager.restore_snapshot(snapshot["snapshot_id"])
            row["restore"] = restore
            final_verification = manager.verify_live_state(snapshot["snapshot_id"])
            row["final_verification"] = final_verification.as_dict()
            row["file_recovery_success"] = restore["verified"] and final_verification.ok
            if health_command:
                rendered = health_command.format(agent_dir=str(agent_dir), profile=profile)
                health = _run_as_user(agent_user, shlex.split(rendered), timeout=timeout)
                row["health_check"] = health
                health_execution_valid = (
                    health["returncode"] not in {None, 125, 126, 127}
                    and not health["timed_out"]
                )
                health_ok = health["returncode"] == 0 and not health["timed_out"]
            else:
                row["health_check"] = {"status": "not_configured"}
                health_execution_valid = False
                health_ok = None
        except SnapshotError as exc:
            row["restore"] = {"verified": False, "error": f"{type(exc).__name__}: {exc}"}
            row["file_recovery_success"] = False
            row["final_verification"] = None
            row["health_check"] = {"status": "not_applicable_restore_failed"}
            health_ok = None
            health_execution_valid = bool(destroy_repository and repository_destroyed)
            if not health_execution_valid:
                raise

        row["semantic_health_success"] = health_ok
        row["paper_admissible"] = bool(
            isolation_valid
            and repository_attack_valid
            and health_execution_valid
        )
    except (SnapshotError, OSError, KeyError, ValueError) as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
        row.setdefault("file_recovery_success", False)
    finally:
        shutil.rmtree(scenario_root, ignore_errors=True)
    return row


def _parse_commands(values: list[str]) -> list[tuple[str, str]]:
    parsed = []
    for value in values:
        if "::" not in value:
            raise SystemExit("command arguments expect PROFILE::COMMAND")
        profile, command = value.split("::", 1)
        parsed.append((profile.strip().upper(), command.strip()))
    return parsed


def _summary(rows: list[dict]) -> dict:
    admissible = [row for row in rows if row["paper_admissible"]]
    recovered = [row for row in rows if row.get("file_recovery_success")]
    healthy = [row for row in rows if row.get("semantic_health_success") is True]
    restore_elapsed = [
        row["restore"]["elapsed_ns"]
        for row in rows
        if isinstance(row.get("restore", {}).get("elapsed_ns"), (int, float))
    ]
    return {
        "scenarios": len(rows),
        "paper_admissible_scenarios": len(admissible),
        "file_recovery_successes": len(recovered),
        "semantic_health_successes": len(healthy),
        "file_recovery_rate": len(recovered) / len(rows) if rows else None,
        "mean_snapshot_elapsed_ns": (
            sum(row["snapshot"]["elapsed_ns"] for row in rows if "snapshot" in row)
            / sum("snapshot" in row for row in rows)
            if any("snapshot" in row for row in rows) else None
        ),
        "mean_restore_elapsed_ns": (
            sum(restore_elapsed) / len(restore_elapsed) if restore_elapsed else None
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run real recovery baselines")
    parser.add_argument("--seed", required=True)
    parser.add_argument("--agent-user", required=True)
    parser.add_argument("--repository-mode", choices=["protected", "same-user"], default="protected")
    parser.add_argument("--attack-set", choices=["recovery8", "canonical43"], default="recovery8")
    parser.add_argument("--attacks", nargs="+")
    parser.add_argument("--include-backup-destruction", action="store_true")
    parser.add_argument("--legitimate-command", action="append", default=[], help="PROFILE::COMMAND between snapshot and attack")
    parser.add_argument("--health-command", help="Post-restore command; supports {agent_dir} and {profile}")
    parser.add_argument("--work-root", default="results/recovery_real/work")
    parser.add_argument("--output", default="results/recovery_real/result.json")
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args()

    seed = Path(args.seed).resolve()
    if not seed.is_dir():
        raise SystemExit(f"seed is not a directory: {seed}")
    try:
        identity_audit = audit_agent_identity(args.agent_user)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    if args.attacks:
        attack_ids = args.attacks
    elif args.attack_set == "canonical43":
        attack_ids = sorted(CANONICAL_ATTACKS)
    else:
        attack_ids = list(RECOVERY9_ATTACKS)
    unknown = sorted(set(attack_ids) - set(CANONICAL_ATTACKS))
    if unknown:
        raise SystemExit(f"unknown attacks: {unknown}")
    target_attack_ids = list(attack_ids)
    if args.include_backup_destruction:
        target_attack_ids.append("Mem-M3-G1-MEM")
    missing_targets = sorted({
        CANONICAL_ATTACKS[attack_id].target_file for attack_id in target_attack_ids
        if not (seed / CANONICAL_ATTACKS[attack_id].target_file).is_file()
    })
    if missing_targets:
        raise SystemExit(f"seed is missing canonical targets: {missing_targets}")
    legitimate = _parse_commands(args.legitimate_command)
    if not legitimate:
        legitimate = [("NONE", "")]
    work_root = (EXPERIMENTS_ROOT / args.work_root).resolve()
    output = (EXPERIMENTS_ROOT / args.output).resolve()
    for label, path in (("work root", work_root), ("output", output)):
        if path == seed or seed in path.parents:
            raise SystemExit(f"{label} must be outside the seed: {path}")
    work_root.mkdir(parents=True, exist_ok=True)

    rows = []
    for profile, command in legitimate:
        for attack_id in attack_ids:
            row = run_scenario(
                seed=seed,
                work_root=work_root,
                attack_id=attack_id,
                agent_user=args.agent_user,
                repository_mode=args.repository_mode,
                profile=profile,
                legitimate_command=command or None,
                health_command=args.health_command,
                timeout=args.timeout,
                destroy_repository=False,
            )
            rows.append(row)
            print(
                f"{profile} {attack_id}: recovered={row.get('file_recovery_success')} "
                f"admissible={row['paper_admissible']}"
            )
        if args.include_backup_destruction:
            row = run_scenario(
                seed=seed,
                work_root=work_root,
                attack_id="Mem-M3-G1-MEM",
                agent_user=args.agent_user,
                repository_mode=args.repository_mode,
                profile=profile,
                legitimate_command=command or None,
                health_command=args.health_command,
                timeout=args.timeout,
                destroy_repository=True,
            )
            rows.append(row)
            print(
                f"{profile} B8: recovered={row.get('file_recovery_success')} "
                f"admissible={row['paper_admissible']}"
            )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": runtime_manifest(),
        "seed": str(seed),
        "agent_user": args.agent_user,
        "agent_identity_audit": identity_audit,
        "repository_mode": args.repository_mode,
        "health_command_configured": bool(args.health_command),
        "scenarios": rows,
        "summary": _summary(rows),
        "paper_admissible": bool(rows and all(row["paper_admissible"] for row in rows)),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {output}")
    return 0 if payload["paper_admissible"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
