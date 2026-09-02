from __future__ import annotations

import platform
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable


SYSCALL_FAMILIES: dict[str, tuple[str, ...]] = {
    "open_create": ("open", "openat", "openat2", "creat"),
    "fd_lifecycle": ("close", "close_range", "dup", "dup2", "dup3", "fcntl"),
    "read": ("read", "pread64", "readv", "preadv", "preadv2"),
    "write": ("write", "pwrite64", "writev", "pwritev", "pwritev2", "truncate", "ftruncate"),
    "process": ("clone", "clone3", "fork", "vfork", "execve", "execveat", "exit", "exit_group"),
    "socket": ("socket", "socketpair", "bind", "listen", "accept", "accept4", "connect", "shutdown"),
    "network": ("sendto", "sendmsg", "sendmmsg", "recvfrom", "recvmsg", "recvmmsg"),
    "rename": ("rename", "renameat", "renameat2"),
    "link_alias": ("link", "linkat", "symlink", "symlinkat", "readlink", "readlinkat"),
    "remove": ("unlink", "unlinkat"),
    "mode": ("chmod", "fchmod", "fchmodat", "fchmodat2"),
    "direct_transfer": ("sendfile", "copy_file_range", "splice", "tee", "vmsplice"),
    "pipe_path": ("pipe", "pipe2", "chdir", "fchdir"),
    "mapped_io": ("mmap", "msync", "munmap"),
}


AUDIT_NAME_ALIASES = {
    ("b64", "pread64"): "pread",
    ("b64", "pwrite64"): "pwrite",
}
AUDIT_NUMERIC_FALLBACKS = {
    ("x86_64", "fchmodat2"): "452",
    ("amd64", "fchmodat2"): "452",
    ("aarch64", "fchmodat2"): "452",
    ("arm64", "fchmodat2"): "452",
}


def audit_rule_token(name: str, arch: str | None = None) -> str:
    selected_arch = arch or _native_arch()
    return AUDIT_NUMERIC_FALLBACKS.get(
        (platform.machine().lower(), name), AUDIT_NAME_ALIASES.get((selected_arch, name), name)
    )


def _native_arch() -> str:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64", "aarch64", "s390x", "ppc64le"}:
        return "b64"
    return "b32"


def _compat_arch() -> str | None:
    return "b32" if platform.machine().lower() in {"x86_64", "amd64"} else None


def all_syscalls() -> tuple[str, ...]:
    return tuple(dict.fromkeys(name for family in SYSCALL_FAMILIES.values() for name in family))


def probe_syscalls(
    arch: str,
    names: Iterable[str] = all_syscalls(),
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[list[str], list[str]]:
    supported: list[str] = []
    unsupported: list[str] = []
    for name in names:
        numeric_fallback = AUDIT_NUMERIC_FALLBACKS.get((platform.machine().lower(), name))
        if numeric_fallback is not None:
            supported.append(name)
            continue
        result = runner(
            ["ausyscall", arch, audit_rule_token(name, arch)], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        (supported if result.returncode == 0 else unsupported).append(name)
    return supported, unsupported


def build_uid_rules(
    *, runner_uid: int, key: str, arch: str, supported: Iterable[str], chunk_size: int = 28,
) -> list[list[str]]:
    if runner_uid < 0:
        raise ValueError("runner UID must be non-negative")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,31}", key):
        raise ValueError("audit key must be 1-31 safe characters")
    names = list(dict.fromkeys(supported))
    if not names:
        raise ValueError("no supported syscalls")
    rules: list[list[str]] = []
    for offset in range(0, len(names), chunk_size):
        chunk = [audit_rule_token(name, arch) for name in names[offset : offset + chunk_size]]
        rules.append([
            "auditctl", "-a", "always,exit", "-F", f"arch={arch}",
            "-S", ",".join(chunk), "-F", f"uid={runner_uid}", "-k", key,
        ])
    return rules


def removal_rule(add_rule: list[str]) -> list[str]:
    rule = list(add_rule)
    index = rule.index("-a")
    rule[index] = "-d"
    return rule


def probe_installable_syscalls(
    *, runner_uid: int, key: str, arch: str, names: Iterable[str],
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[list[str], list[str]]:
    supported: list[str] = []
    unsupported: list[str] = []
    probe_key = key
    for name in names:
        command = build_uid_rules(
            runner_uid=runner_uid, key=probe_key, arch=arch,
            supported=[name], chunk_size=1,
        )[0]
        result = runner(
            command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
        )
        if result.returncode != 0:
            unsupported.append(name)
            continue
        removal = runner(
            removal_rule(command), text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False,
        )
        if removal.returncode != 0:
            raise RuntimeError(
                f"failed to remove audit capability probe for {arch}/{name}: {removal.stderr}"
            )
        supported.append(name)
    return supported, unsupported


def render_rules(rules: Iterable[list[str]]) -> str:
    return "\n".join(" ".join(rule[1:]) for rule in rules) + "\n"


@dataclass(frozen=True)
class AuditRulePlan:
    runner_uid: int
    key: str
    native_arch: str
    rules: tuple[tuple[str, ...], ...]
    supported_syscalls: tuple[str, ...]
    unsupported_syscalls: tuple[str, ...]
    compat_arch: str | None
    compat_supported_syscalls: tuple[str, ...]
    compat_unsupported_syscalls: tuple[str, ...]

    @classmethod
    def create(
        cls, runner_uid: int, key: str, *,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> "AuditRulePlan":
        native_arch = _native_arch()
        named_supported, name_unsupported = probe_syscalls(native_arch, runner=runner)
        supported, install_unsupported = probe_installable_syscalls(
            runner_uid=runner_uid, key=key, arch=native_arch,
            names=named_supported, runner=runner,
        )
        unsupported = list(dict.fromkeys([*name_unsupported, *install_unsupported]))
        rules = build_uid_rules(
            runner_uid=runner_uid, key=key, arch=native_arch, supported=supported
        )
        compat_arch = _compat_arch()
        compat_supported: list[str] = []
        compat_unsupported: list[str] = []
        if compat_arch is not None:
            compat_named, compat_name_unsupported = probe_syscalls(compat_arch, runner=runner)
            compat_supported, compat_install_unsupported = probe_installable_syscalls(
                runner_uid=runner_uid, key=key, arch=compat_arch,
                names=compat_named, runner=runner,
            )
            compat_unsupported = list(dict.fromkeys([
                *compat_name_unsupported, *compat_install_unsupported,
            ]))
            if compat_supported:
                rules.extend(build_uid_rules(
                    runner_uid=runner_uid, key=key, arch=compat_arch,
                    supported=compat_supported,
                ))
        return cls(
            runner_uid, key, native_arch, tuple(tuple(rule) for rule in rules),
            tuple(supported), tuple(unsupported), compat_arch,
            tuple(compat_supported), tuple(compat_unsupported),
        )

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_rules([list(rule) for rule in self.rules]), encoding="ascii")
