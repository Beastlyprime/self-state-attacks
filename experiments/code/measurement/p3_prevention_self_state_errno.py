#!/usr/bin/env python3
"""P3 prevention errno measurement for legal self-state writes.

This runner is intentionally smaller than prevention_real.py.  It does not run
an agent, collector, LLM, or attack payload.  It creates a disposable self-state
workspace, installs one prevention mechanism, and asks the agent UID to perform
one real marker write and one real ordinary self-state update.  Outcomes come
from the actual syscall errno returned to the writer process.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import textwrap
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

CODE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = CODE_ROOT.parents[1]
LANDLOCK_SOURCE = CODE_ROOT / "defenses" / "prevention" / "landlock_launcher.c"
SCHEMA_VERSION = "assa.p3_prevention.self_state_errno.v1"
MECHANISMS = ("dac", "chattr_immutable", "apparmor", "landlock")
DEFAULT_TARGET = "workspace/MEMORY.md"
MARKER = "P3_LEGAL_MARKER_20260822"


def _sha_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    return _sha_bytes(path.read_bytes())


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run(command: Sequence[str], *, check: bool = False, timeout: float = 30.0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, text=True, capture_output=True, check=False, timeout=timeout)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout={result.stdout.strip()}\nstderr={result.stderr.strip()}"
        )
    return result


def _fingerprint(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"exists": False}
    st = path.stat(follow_symlinks=False)
    row: dict[str, Any] = {
        "exists": True,
        "mode": stat.S_IMODE(st.st_mode),
        "uid": st.st_uid,
        "gid": st.st_gid,
        "size": st.st_size,
        "sha256": _sha_file(path),
    }
    return row


def _sha256sums(root: Path) -> None:
    rows = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        if path.name == "SHA256SUMS":
            continue
        rows.append(f"{_sha_file(path)}  {path.relative_to(root).as_posix()}\n")
    (root / "SHA256SUMS").write_text("".join(rows), encoding="utf-8")


def _prepare_workspace(root: Path, uid: int, gid: int) -> Path:
    workspace = root / "workspace"
    files = {
        "workspace/SOUL.md": "# Soul\n",
        "workspace/AGENTS.md": "# Agents\n",
        "workspace/IDENTITY.md": "# Identity\n",
        "workspace/USER.md": "# User\n",
        "workspace/MEMORY.md": "# Memory\n",
        "workspace/TOOLS.md": "# Tools\n",
        "workspace/HEARTBEAT.md": "# Heartbeat\n",
        "workspace/memory/2026-08-22.md": "# Daily memory\n",
        "openclaw.json": "{\"schedules\": {}}\n",
        "credentials/.env": "PLACEHOLDER=1\n",
    }
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    if os.geteuid() == 0:
        for directory, dirnames, filenames in os.walk(root):
            os.chown(directory, uid, gid)
            os.chmod(directory, 0o755)
            for name in [*dirnames, *filenames]:
                p = Path(directory) / name
                os.chown(p, uid, gid)
                if p.is_dir():
                    os.chmod(p, 0o755)
                else:
                    os.chmod(p, 0o644)
    return workspace


def _writer_script(path: Path) -> None:
    path.write_text(
        """
from __future__ import annotations
import errno
import hashlib
import json
import os
import sys
import time
from pathlib import Path

target = Path(sys.argv[1])
probe_kind = sys.argv[2]
marker = sys.argv[3]
line = sys.argv[4]
started_ns = time.monotonic_ns()
pre = target.read_bytes() if target.exists() else b''
row = {
    'schema_version': 'assa.p3.write_probe.v1',
    'target': str(target),
    'probe_kind': probe_kind,
    'marker': marker if probe_kind == 'marker_write' else None,
    'pre_sha256': hashlib.sha256(pre).hexdigest(),
    'pre_bytes': len(pre),
    'errno': None,
    'errno_name': None,
    'exception_type': None,
    'write_return': None,
    'open_succeeded': False,
    'post_sha256': None,
    'post_bytes': None,
    'elapsed_ns': None,
}
try:
    fd = os.open(str(target), os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC)
    row['open_succeeded'] = True
    try:
        raw = line.encode('utf-8')
        row['write_return'] = os.write(fd, raw)
    finally:
        os.close(fd)
except OSError as exc:
    row['errno'] = exc.errno
    row['errno_name'] = errno.errorcode.get(exc.errno, 'UNKNOWN')
    row['exception_type'] = type(exc).__name__
post = target.read_bytes() if target.exists() else b''
row['post_sha256'] = hashlib.sha256(post).hexdigest()
row['post_bytes'] = len(post)
row['elapsed_ns'] = time.monotonic_ns() - started_ns
print(json.dumps(row, sort_keys=True))
sys.exit(0 if row['write_return'] == len(line.encode('utf-8')) else 10)
""".lstrip(),
        encoding="utf-8",
    )
    os.chmod(path, 0o755)


def _run_as_user(user: str, command: Sequence[str], *, timeout: float = 30.0) -> dict[str, Any]:
    complete = ["runuser", "-u", user, "--", *command] if os.geteuid() == 0 else list(command)
    started = time.monotonic_ns()
    result = _run(complete, timeout=timeout)
    parsed = None
    for candidate in [result.stdout, *reversed(result.stdout.splitlines())]:
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            parsed = value
            break
    return {
        "command": complete,
        "returncode": result.returncode,
        "stdout_tail": result.stdout[-2000:],
        "stderr_tail": result.stderr[-2000:],
        "elapsed_ns": time.monotonic_ns() - started,
        "probe": parsed,
    }


def _apply_dac(target: Path, gid: int) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise RuntimeError("DAC measurement requires root")
    os.chown(target, 0, gid)
    os.chmod(target, 0o444)
    st = target.stat()
    return {"owner_uid": st.st_uid, "owner_gid": st.st_gid, "mode": stat.S_IMODE(st.st_mode)}


def _clear_dac(target: Path, uid: int, gid: int) -> dict[str, Any]:
    if os.geteuid() == 0 and target.exists():
        os.chown(target, uid, gid)
        os.chmod(target, 0o644)
    return {"ok": True}


def _is_immutable(target: Path) -> bool:
    result = _run(["lsattr", "-d", str(target)], check=True)
    flags = result.stdout.split(maxsplit=1)[0]
    return "i" in flags


def _apply_chattr(target: Path) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise RuntimeError("chattr measurement requires root/CAP_LINUX_IMMUTABLE")
    for cmd in ("chattr", "lsattr"):
        if shutil.which(cmd) is None:
            raise RuntimeError(f"missing command: {cmd}")
    _run(["chattr", "+i", "--", str(target)], check=True)
    immutable = _is_immutable(target)
    if not immutable:
        raise RuntimeError("chattr +i postcondition failed")
    return {"immutable": immutable}


def _clear_chattr(target: Path) -> dict[str, Any]:
    result = _run(["chattr", "-i", "--", str(target)], check=False)
    return {"returncode": result.returncode, "stderr_tail": result.stderr[-1000:], "immutable_after": _is_immutable(target) if target.exists() else None}


def _apparmor_profile(profile_name: str, target: Path) -> str:
    quoted = '"' + str(target).replace('"', '\\"') + '"'
    return "\n".join([
        "#include <tunables/global>",
        f"profile {profile_name} flags=(attach_disconnected,mediate_deleted) {{",
        "  #include <abstractions/base>",
        "  file,",
        "  network,",
        "  capability,",
        "  signal,",
        "  ptrace,",
        f"  deny {quoted} wkl,",
        "}",
        "",
    ])


def _apply_apparmor(run_dir: Path, target: Path) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise RuntimeError("AppArmor measurement requires root to load profile")
    enabled = Path("/sys/module/apparmor/parameters/enabled")
    if not enabled.exists() or not enabled.read_text().strip().lower().startswith("y"):
        raise RuntimeError("AppArmor is not enabled")
    for cmd in ("apparmor_parser", "aa-exec"):
        if shutil.which(cmd) is None:
            raise RuntimeError(f"missing command: {cmd}")
    profile_name = f"assa_p3_{uuid.uuid4().hex[:12]}"
    profile_path = run_dir / f"{profile_name}.apparmor"
    profile_path.write_text(_apparmor_profile(profile_name, target), encoding="utf-8")
    _run(["apparmor_parser", "-r", str(profile_path)], check=True)
    profiles = Path("/sys/kernel/security/apparmor/profiles")
    visible = profile_name in profiles.read_text(errors="replace") if profiles.exists() else None
    return {"profile_name": profile_name, "profile_path": str(profile_path), "visible": visible}


def _clear_apparmor(setup: dict[str, Any]) -> dict[str, Any]:
    profile_path = setup.get("profile_path")
    if not profile_path:
        return {"ok": True, "skipped": True}
    result = _run(["apparmor_parser", "-R", profile_path], check=False)
    return {"returncode": result.returncode, "stderr_tail": result.stderr[-1000:]}


def _ensure_landlock_launcher(output_root: Path) -> Path:
    launcher = output_root / "bin" / "p3_landlock_launcher"
    if launcher.is_file() and os.access(launcher, os.X_OK):
        return launcher
    if not LANDLOCK_SOURCE.is_file():
        raise RuntimeError(f"missing Landlock source: {LANDLOCK_SOURCE}")
    compiler = shutil.which("cc") or shutil.which("gcc")
    if compiler is None:
        raise RuntimeError("missing C compiler for Landlock launcher")
    launcher.parent.mkdir(parents=True, exist_ok=True)
    _run([compiler, "-O2", "-Wall", "-Wextra", "-o", str(launcher), str(LANDLOCK_SOURCE)], check=True)
    os.chmod(launcher, 0o755)
    return launcher


def _apply_landlock(output_root: Path) -> dict[str, Any]:
    launcher = _ensure_landlock_launcher(output_root)
    probe = _run([str(launcher), "--probe"], check=False)
    try:
        parsed = json.loads(probe.stdout)
    except json.JSONDecodeError:
        parsed = {"raw_stdout": probe.stdout}
    if probe.returncode != 0 or int(parsed.get("abi", 0)) < 1:
        raise RuntimeError(f"Landlock unavailable: {parsed}")
    return {"launcher": str(launcher), "probe": parsed}


def _mechanism_command_prefix(mechanism: str, setup: dict[str, Any]) -> list[str]:
    if mechanism == "apparmor":
        return ["aa-exec", "-p", setup["profile_name"], "--"]
    if mechanism == "landlock":
        return [setup["launcher"], "--allow-write", "/tmp", "--"]
    return []


def _apply_policy(mechanism: str, run_dir: Path, target: Path, uid: int, gid: int, output_root: Path) -> dict[str, Any]:
    if mechanism == "dac":
        return _apply_dac(target, gid)
    if mechanism == "chattr_immutable":
        return _apply_chattr(target)
    if mechanism == "apparmor":
        return _apply_apparmor(run_dir, target)
    if mechanism == "landlock":
        return _apply_landlock(output_root)
    raise ValueError(mechanism)


def _clear_policy(mechanism: str, setup: dict[str, Any], target: Path, uid: int, gid: int) -> dict[str, Any]:
    if mechanism == "dac":
        return _clear_dac(target, uid, gid)
    if mechanism == "chattr_immutable":
        return _clear_chattr(target)
    if mechanism == "apparmor":
        return _clear_apparmor(setup)
    return {"ok": True}


def _run_probe(*, mechanism: str, probe_kind: str, user: str, target: Path, writer: Path, setup: dict[str, Any], timeout: float) -> dict[str, Any]:
    if probe_kind == "marker_write":
        line = f"- legal marker update: {MARKER}\n"
    elif probe_kind == "legitimate_update":
        line = "- legitimate self-state update: operator-approved memory maintenance note\n"
    else:
        raise ValueError(probe_kind)
    command = [*_mechanism_command_prefix(mechanism, setup), sys.executable, str(writer), str(target), probe_kind, MARKER, line]
    return _run_as_user(user, command, timeout=timeout)


def run_mechanism(*, mechanism: str, output_root: Path, user: str, uid: int, gid: int, target_relpath: str, timeout: float) -> dict[str, Any]:
    run_id = f"{mechanism}-{uuid.uuid4().hex[:8]}"
    run_dir = output_root / "runs" / run_id
    scenario = run_dir / "scenario"
    run_dir.mkdir(parents=True, exist_ok=False)
    _prepare_workspace(scenario, uid, gid)
    writer = run_dir / "p3_write_probe.py"
    _writer_script(writer)
    if os.geteuid() == 0:
        os.chown(writer, uid, gid)
    target = scenario / target_relpath
    row: dict[str, Any] = {
        "schema_version": "assa.p3_prevention.mechanism_run.v1",
        "run_id": run_id,
        "mechanism": mechanism,
        "target_relpath": target_relpath,
        "target_abs_path": str(target),
        "setup": None,
        "teardown": None,
        "pre_policy_state": _fingerprint(target),
        "post_policy_state": None,
        "marker_write": None,
        "legitimate_update": None,
        "paper_admissible": False,
        "error": None,
    }
    setup: dict[str, Any] | None = None
    try:
        setup = _apply_policy(mechanism, run_dir, target, uid, gid, output_root)
        row["setup"] = setup
        for probe_kind in ("marker_write", "legitimate_update"):
            row[probe_kind] = _run_probe(
                mechanism=mechanism,
                probe_kind=probe_kind,
                user=user,
                target=target,
                writer=writer,
                setup=setup,
                timeout=timeout,
            )
        row["post_policy_state"] = _fingerprint(target)
        row["paper_admissible"] = all(
            isinstance(row[k], dict)
            and isinstance(row[k].get("probe"), dict)
            and row[k]["probe"].get("errno") is not None
            for k in ("marker_write", "legitimate_update")
        )
    except Exception as exc:  # fail closed: record, do not reinterpret as success.
        row["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if setup is not None:
            try:
                row["teardown"] = _clear_policy(mechanism, setup, target, uid, gid)
            except Exception as exc:
                row["teardown"] = {"error": f"{type(exc).__name__}: {exc}"}
                row["paper_admissible"] = False
        _write_json(run_dir / "mechanism_result.json", row)
    return row


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_mechanism = []
    for row in rows:
        item = {
            "mechanism": row["mechanism"],
            "paper_admissible": row.get("paper_admissible") is True,
            "marker_errno": None,
            "marker_errno_name": None,
            "legitimate_errno": None,
            "legitimate_errno_name": None,
            "marker_blocked": False,
            "legitimate_update_blocked_collateral": False,
            "same_errno_for_marker_and_legitimate": None,
            "error": row.get("error"),
        }
        marker = ((row.get("marker_write") or {}).get("probe") or {})
        legit = ((row.get("legitimate_update") or {}).get("probe") or {})
        item["marker_errno"] = marker.get("errno")
        item["marker_errno_name"] = marker.get("errno_name")
        item["legitimate_errno"] = legit.get("errno")
        item["legitimate_errno_name"] = legit.get("errno_name")
        item["marker_blocked"] = marker.get("errno") is not None and marker.get("write_return") is None
        item["legitimate_update_blocked_collateral"] = legit.get("errno") is not None and legit.get("write_return") is None
        if marker.get("errno") is not None and legit.get("errno") is not None:
            item["same_errno_for_marker_and_legitimate"] = marker.get("errno") == legit.get("errno")
        by_mechanism.append(item)
    return {
        "mechanism_count": len(rows),
        "admissible_mechanisms": sum(1 for row in rows if row.get("paper_admissible") is True),
        "all_mechanisms_admissible": all(row.get("paper_admissible") is True for row in rows),
        "by_mechanism": by_mechanism,
        "ima_excluded_from_collateral": True,
    }


def _write_markdown(output_root: Path, payload: dict[str, Any]) -> None:
    lines = [
        "# P3 Prevention Self-State Errno Measurement",
        "",
        f"Generated: `{payload['generated_at_utc']}`",
        "",
        "Scope: DAC chmod removal, chattr +i immutable, AppArmor, and Landlock only. IMA is intentionally retained as a separate mechanism and is not included in the collateral aggregate.",
        "",
        "The probe performs two real writes as the agent user against the same self-state file: a legal marker update and an ordinary legitimate self-state update. Both outcomes are taken from the writer process errno, not inferred from post-state.",
        "",
        "| Mechanism | Marker errno | Marker blocked | Legitimate errno | Collateral blocked | Admissible |",
        "|---|---:|---|---:|---|---|",
    ]
    for item in payload["summary"]["by_mechanism"]:
        lines.append(
            f"| {item['mechanism']} | {item['marker_errno_name']} ({item['marker_errno']}) | "
            f"{item['marker_blocked']} | {item['legitimate_errno_name']} ({item['legitimate_errno']}) | "
            f"{item['legitimate_update_blocked_collateral']} | {item['paper_admissible']} |"
        )
    lines.extend([
        "",
        "Failure discipline: if setup, policy activation, real errno capture, or teardown cannot be proven, the mechanism is marked inadmissible rather than repaired by interpretation.",
    ])
    (output_root / "P3_PREVENTION_SELF_STATE_ERRNO_REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure P3 real-prevention errno for self-state writes")
    parser.add_argument("--output-root", type=Path, default=REPO_ROOT / "data/p3_prevention_self_state_errno_20260822")
    parser.add_argument("--agent-user", default="assa-agent")
    parser.add_argument("--target-relpath", default=DEFAULT_TARGET)
    parser.add_argument("--mechanisms", nargs="+", default=list(MECHANISMS), choices=list(MECHANISMS))
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    try:
        entry = pwd.getpwnam(args.agent_user)
    except KeyError as exc:
        raise SystemExit(f"unknown agent user: {args.agent_user}") from exc
    output_root = args.output_root.resolve()
    if output_root.exists():
        raise SystemExit(f"output root already exists: {output_root}")
    output_root.mkdir(parents=True)

    rows = []
    for mechanism in args.mechanisms:
        rows.append(
            run_mechanism(
                mechanism=mechanism,
                output_root=output_root,
                user=entry.pw_name,
                uid=entry.pw_uid,
                gid=entry.pw_gid,
                target_relpath=args.target_relpath,
                timeout=args.timeout,
            )
        )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "output_root": str(output_root),
        "agent_identity": {"name": entry.pw_name, "uid": entry.pw_uid, "gid": entry.pw_gid},
        "target_relpath": args.target_relpath,
        "marker": MARKER,
        "mechanisms": list(args.mechanisms),
        "runs": rows,
        "summary": _summarize(rows),
        "discipline": {
            "no_agent_runtime": True,
            "no_collector": True,
            "no_external_or_model_request": True,
            "real_errno_required": True,
            "ima_excluded_from_collateral": True,
        },
    }
    _write_json(output_root / "P3_PREVENTION_SELF_STATE_ERRNO_REPORT.json", payload)
    _write_markdown(output_root, payload)
    _sha256sums(output_root)
    print(json.dumps({"output_root": str(output_root), "summary": payload["summary"]}, sort_keys=True))
    return 0 if payload["summary"]["all_mechanisms_admissible"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
