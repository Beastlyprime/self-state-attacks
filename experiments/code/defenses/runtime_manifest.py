"""Reproducibility metadata shared by real defense runners."""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable


VERSION_COMMANDS = {
    "apparmor_parser": ["apparmor_parser", "--version"],
    "aa-exec": ["aa-exec", "--help"],
    "chattr": ["chattr", "-V"],
    "lsattr": ["lsattr", "-V"],
    "runuser": ["runuser", "--version"],
    "cc": ["cc", "--version"],
}


def _version(command: list[str]) -> dict:
    executable = shutil.which(command[0])
    if executable is None:
        return {"available": False}
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    output = (result.stdout or result.stderr).strip().splitlines()
    return {
        "available": True,
        "path": executable,
        "returncode": result.returncode,
        "version": output[0][:500] if output else None,
    }


def _file_record(path: Path) -> dict:
    if not path.is_file():
        return {"path": str(path), "exists": False}
    return {
        "path": str(path),
        "exists": True,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "size": path.stat().st_size,
    }


def runtime_manifest(extra_files: Iterable[str | Path] = ()) -> dict:
    os_release = {}
    release_path = Path("/etc/os-release")
    if release_path.exists():
        for line in release_path.read_text(errors="replace").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                os_release[key] = value.strip().strip('"')
    apparmor_enabled = Path("/sys/module/apparmor/parameters/enabled")
    return {
        "platform": platform.uname()._asdict(),
        "os_release": os_release,
        "python": {
            "version": sys.version,
            "executable": sys.executable,
        },
        "process": {
            "uid": os.getuid(),
            "euid": os.geteuid(),
            "gid": os.getgid(),
            "egid": os.getegid(),
        },
        "apparmor_enabled": (
            apparmor_enabled.read_text(errors="replace").strip()
            if apparmor_enabled.exists() else None
        ),
        "tools": {name: _version(command) for name, command in VERSION_COMMANDS.items()},
        "extra_files": [_file_record(Path(path).resolve()) for path in extra_files],
    }


__all__ = ["runtime_manifest"]
