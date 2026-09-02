#!/usr/bin/env python3
"""Real enforcement backends for the prevention experiment.

Backends never simulate success.  Missing privileges, kernel support, tools, or
post-condition failures raise :class:`EnforcementError` and make the scenario
inadmissible.
"""

from __future__ import annotations

import json
import os
import pwd
import shutil
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from defenses.prevention.permission_policies_v4 import PERMISSION_POLICIES_V4


class EnforcementError(RuntimeError):
    """The requested kernel policy could not be proven active."""


@dataclass(frozen=True)
class AgentIdentity:
    name: str
    uid: int
    gid: int

    @classmethod
    def resolve(cls, name: str) -> "AgentIdentity":
        try:
            entry = pwd.getpwnam(name)
        except KeyError as exc:
            raise EnforcementError(f"unknown agent user: {name}") from exc
        return cls(name=entry.pw_name, uid=entry.pw_uid, gid=entry.pw_gid)


@dataclass
class BackendContext:
    agent_dir: Path
    identity: AgentIdentity
    level: int
    run_id: str
    artifact_dir: Path
    runtime_write_paths: list[Path] = field(default_factory=list)


def _run(command: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if check and result.returncode != 0:
        raise EnforcementError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout={result.stdout.strip()}\nstderr={result.stderr.strip()}"
        )
    return result


def _locked_relpaths(level: int) -> list[str]:
    try:
        permissions = PERMISSION_POLICIES_V4[level]["permissions"]
    except KeyError as exc:
        raise EnforcementError(f"unknown policy level: {level}") from exc
    return sorted(rel for rel, mode in permissions.items() if not (mode & stat.S_IWUSR))


def _unlocked_relpaths(level: int) -> list[str]:
    permissions = PERMISSION_POLICIES_V4[level]["permissions"]
    return sorted(rel for rel, mode in permissions.items() if mode & stat.S_IWUSR)


def _expand_existing(agent_dir: Path, relpaths: Iterable[str]) -> list[Path]:
    expanded: list[Path] = []
    for rel in relpaths:
        path = agent_dir / rel.rstrip("/")
        if not path.exists():
            raise EnforcementError(f"policy target is missing: {path}")
        expanded.append(path)
        if rel.endswith("/"):
            expanded.extend(sorted(p for p in path.rglob("*") if not p.is_symlink()))
    return expanded


def _chown_tree(root: Path, uid: int, gid: int) -> None:
    for directory, dirnames, filenames in os.walk(root):
        os.chown(directory, uid, gid)
        for name in [*dirnames, *filenames]:
            path = Path(directory) / name
            if path.is_symlink():
                raise EnforcementError(f"symlink in scenario workspace: {path}")
            os.chown(path, uid, gid)


class EnforcementBackend:
    name = "base"

    def preflight(self, context: BackendContext) -> dict:
        raise NotImplementedError

    def setup(self, context: BackendContext) -> dict:
        raise NotImplementedError

    def command_prefix(self, context: BackendContext) -> list[str]:
        return []

    def teardown(self, context: BackendContext) -> dict:
        return {"ok": True}


class DACBackend(EnforcementBackend):
    """Cross-principal DAC with root-owned locked files and sticky parents."""

    name = "dac"

    def preflight(self, context: BackendContext) -> dict:
        if os.geteuid() != 0:
            raise EnforcementError("DAC backend requires root to assign ownership")
        if context.identity.uid == 0:
            raise EnforcementError("agent user must not be root")
        return {"ok": True, "operator_uid": os.geteuid(), "agent_uid": context.identity.uid}

    def setup(self, context: BackendContext) -> dict:
        self.preflight(context)
        _chown_tree(context.agent_dir, context.identity.uid, context.identity.gid)

        # Root owns policy boundaries. Sticky workspace preserves legitimate
        # create/delete for agent-owned files while protecting root-owned files.
        os.chown(context.agent_dir, 0, context.identity.gid)
        os.chmod(context.agent_dir, 0o1777)
        workspace = context.agent_dir / "workspace"
        os.chown(workspace, 0, context.identity.gid)
        os.chmod(workspace, 0o1777)
        credentials = context.agent_dir / "credentials"
        if credentials.exists():
            os.chown(credentials, 0, context.identity.gid)
            os.chmod(credentials, 0o755)

        applied = []
        for path in _expand_existing(context.agent_dir, _locked_relpaths(context.level)):
            os.chown(path, 0, context.identity.gid)
            mode = 0o555 if path.is_dir() else 0o444
            if path.name == ".env":
                mode = 0o440
            os.chmod(path, mode)
            metadata = path.stat()
            if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != mode:
                raise EnforcementError(f"DAC post-condition failed: {path}")
            applied.append(str(path))
        return {"ok": True, "locked": applied}


class ImmutableBackend(EnforcementBackend):
    name = "immutable"

    def __init__(self) -> None:
        self._locked: dict[str, list[Path]] = {}

    def preflight(self, context: BackendContext) -> dict:
        if os.geteuid() != 0:
            raise EnforcementError("immutable backend requires root/CAP_LINUX_IMMUTABLE")
        for command in ("chattr", "lsattr"):
            if shutil.which(command) is None:
                raise EnforcementError(f"missing command: {command}")
        return {"ok": True}

    @staticmethod
    def _is_immutable(path: Path) -> bool:
        result = _run(["lsattr", "-d", str(path)])
        flags = result.stdout.split(maxsplit=1)[0] if result.stdout.strip() else ""
        return "i" in flags

    def setup(self, context: BackendContext) -> dict:
        self.preflight(context)
        paths = _expand_existing(context.agent_dir, _locked_relpaths(context.level))
        # Lock children before directories, then verify every inode.
        paths = sorted(set(paths), key=lambda p: len(p.parts), reverse=True)
        applied: list[Path] = []
        try:
            for path in paths:
                _run(["chattr", "+i", "--", str(path)])
                if not self._is_immutable(path):
                    raise EnforcementError(f"immutable post-condition failed: {path}")
                applied.append(path)
        except Exception:
            for path in reversed(applied):
                _run(["chattr", "-i", "--", str(path)], check=False)
            raise
        self._locked[context.run_id] = applied
        return {"ok": True, "locked": [str(path) for path in applied]}

    def teardown(self, context: BackendContext) -> dict:
        failed = []
        for path in reversed(self._locked.pop(context.run_id, [])):
            result = _run(["chattr", "-i", "--", str(path)], check=False)
            if result.returncode != 0 or self._is_immutable(path):
                failed.append(str(path))
        if failed:
            raise EnforcementError(f"failed to remove immutable flag: {failed}")
        return {"ok": True}


class AppArmorBackend(EnforcementBackend):
    name = "apparmor"

    def __init__(self) -> None:
        self._profiles: dict[str, tuple[str, Path]] = {}

    def preflight(self, context: BackendContext) -> dict:
        enabled = Path("/sys/module/apparmor/parameters/enabled")
        if not enabled.exists() or not enabled.read_text().strip().lower().startswith("y"):
            raise EnforcementError("AppArmor is not enabled")
        for command in ("apparmor_parser", "aa-exec"):
            if shutil.which(command) is None:
                raise EnforcementError(f"missing command: {command}")
        if os.geteuid() != 0:
            raise EnforcementError("AppArmor profile loading requires root")
        return {"ok": True}

    @staticmethod
    def _quote(path: Path) -> str:
        return '"' + str(path).replace('"', '\\"') + '"'

    def setup(self, context: BackendContext) -> dict:
        self.preflight(context)
        profile_name = f"assa_exp1_{context.run_id.replace('-', '_')}"
        rules = [
            "#include <tunables/global>",
            f"profile {profile_name} flags=(attach_disconnected,mediate_deleted) {{",
            "  #include <abstractions/base>",
            "  file,",
            "  network,",
            "  capability,",
            "  signal,",
            "  ptrace,",
        ]
        locked = _expand_existing(context.agent_dir, _locked_relpaths(context.level))
        for path in sorted(set(locked)):
            quoted = self._quote(path)
            rules.append(f"  deny {quoted} wkl,")
            if path.is_dir():
                rules.append(f"  deny {self._quote(path / '**')} wkl,")
        rules.append("}")
        context.artifact_dir.mkdir(parents=True, exist_ok=True)
        profile_path = context.artifact_dir / f"{profile_name}.apparmor"
        profile_path.write_text("\n".join(rules) + "\n", encoding="utf-8")
        _run(["apparmor_parser", "-r", str(profile_path)])
        profiles = Path("/sys/kernel/security/apparmor/profiles")
        if profiles.exists() and profile_name not in profiles.read_text(errors="replace"):
            _run(["apparmor_parser", "-R", str(profile_path)], check=False)
            raise EnforcementError("AppArmor profile was not visible after load")
        self._profiles[context.run_id] = (profile_name, profile_path)
        return {"ok": True, "profile": profile_name, "profile_path": str(profile_path)}

    def command_prefix(self, context: BackendContext) -> list[str]:
        try:
            profile_name, _ = self._profiles[context.run_id]
        except KeyError as exc:
            raise EnforcementError("AppArmor backend is not set up") from exc
        return ["aa-exec", "-p", profile_name, "--"]

    def teardown(self, context: BackendContext) -> dict:
        profile = self._profiles.pop(context.run_id, None)
        if profile is None:
            return {"ok": True}
        _, profile_path = profile
        _run(["apparmor_parser", "-R", str(profile_path)])
        return {"ok": True}


class LandlockBackend(EnforcementBackend):
    name = "landlock"

    def __init__(self, launcher: str | Path):
        self.launcher = Path(launcher).resolve()

    def preflight(self, context: BackendContext) -> dict:
        if not self.launcher.is_file() or not os.access(self.launcher, os.X_OK):
            raise EnforcementError(f"Landlock launcher is not executable: {self.launcher}")
        result = _run([str(self.launcher), "--probe"])
        try:
            probe = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise EnforcementError("invalid Landlock probe output") from exc
        if int(probe.get("abi", 0)) < 1:
            raise EnforcementError("Landlock is unavailable")
        return {"ok": True, **probe}

    def setup(self, context: BackendContext) -> dict:
        return self.preflight(context)

    def command_prefix(self, context: BackendContext) -> list[str]:
        if context.level == 0:
            return []
        allowed: list[Path] = []
        for rel in _unlocked_relpaths(context.level):
            path = context.agent_dir / rel.rstrip("/")
            if path.exists():
                allowed.append(path)
        allowed.extend(context.runtime_write_paths)
        for path in (Path("/tmp"), Path("/dev/null")):
            if path.exists():
                allowed.append(path)
        prefix = [str(self.launcher)]
        for path in sorted(set(path.resolve() for path in allowed)):
            prefix.extend(["--allow-write", str(path)])
        prefix.append("--")
        return prefix


def build_backend(name: str, *, landlock_launcher: str | Path | None = None) -> EnforcementBackend:
    if name == "dac":
        return DACBackend()
    if name in {"immutable", "chattr"}:
        return ImmutableBackend()
    if name == "apparmor":
        return AppArmorBackend()
    if name == "landlock":
        if landlock_launcher is None:
            raise EnforcementError("Landlock backend requires --landlock-launcher")
        return LandlockBackend(landlock_launcher)
    raise EnforcementError(f"unknown prevention backend: {name}")


def run_as_agent(identity: AgentIdentity, command: Sequence[str]) -> list[str]:
    if os.geteuid() == 0:
        return ["runuser", "-u", identity.name, "--", *command]
    if os.geteuid() != identity.uid:
        raise EnforcementError("cannot switch to requested agent user without root")
    return list(command)


__all__ = [
    "AgentIdentity",
    "AppArmorBackend",
    "BackendContext",
    "DACBackend",
    "EnforcementBackend",
    "EnforcementError",
    "ImmutableBackend",
    "LandlockBackend",
    "build_backend",
    "run_as_agent",
]
