"""Validate the OS identity used to execute an untrusted agent."""

from __future__ import annotations

import grp
import os
import pwd
import shutil
import subprocess


PRIVILEGED_GROUPS = frozenset({"admin", "sudo", "wheel"})


def audit_agent_identity(name: str) -> dict:
    """Return an identity audit and reject accounts with privilege escalation."""
    try:
        entry = pwd.getpwnam(name)
    except KeyError as exc:
        raise ValueError(f"unknown agent user: {name}") from exc

    group_ids = os.getgrouplist(entry.pw_name, entry.pw_gid)
    group_names = sorted(
        {
            grp.getgrgid(group_id).gr_name
            for group_id in group_ids
        }
    )
    privileged_groups = sorted(PRIVILEGED_GROUPS.intersection(group_names))

    passwordless_sudo = False
    sudo = shutil.which("sudo")
    if sudo:
        if os.geteuid() == 0:
            command = ["runuser", "-u", entry.pw_name, "--", sudo, "-n", "true"]
        elif os.geteuid() == entry.pw_uid:
            command = [sudo, "-n", "true"]
        else:
            command = []
        if command:
            probe = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=10,
            )
            passwordless_sudo = probe.returncode == 0

    audit = {
        "name": entry.pw_name,
        "uid": entry.pw_uid,
        "gid": entry.pw_gid,
        "groups": group_names,
        "privileged_groups": privileged_groups,
        "passwordless_sudo": passwordless_sudo,
    }
    violations = []
    if entry.pw_uid == 0:
        violations.append("agent UID is 0")
    if privileged_groups:
        violations.append(f"privileged groups: {privileged_groups}")
    if passwordless_sudo:
        violations.append("passwordless sudo succeeds")
    if violations:
        raise ValueError(
            f"agent user {entry.pw_name!r} is not unprivileged: "
            + "; ".join(violations)
        )
    return audit


__all__ = ["PRIVILEGED_GROUPS", "audit_agent_identity"]
