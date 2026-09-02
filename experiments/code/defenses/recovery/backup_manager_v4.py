#!/usr/bin/env python3
"""Verified snapshots for the active OpenClaw self-state layout.

The repository must live outside the agent directory.  Snapshots are written
to a temporary directory, verified, fsynced, and atomically published.  A
restore is manifest-driven: files created after the snapshot are removed and
every restored file is verified byte-for-byte.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import stat
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SCHEMA_VERSION = "assa.recovery.snapshot.v1"
FIXED_SELF_STATE = (
    "workspace/SOUL.md",
    "workspace/AGENTS.md",
    "workspace/IDENTITY.md",
    "workspace/USER.md",
    "workspace/MEMORY.md",
    "workspace/TOOLS.md",
    "workspace/HEARTBEAT.md",
    "openclaw.json",
    "credentials/.env",
)
MANAGED_DIRS = ("workspace/memory",)


class SnapshotError(RuntimeError):
    """Raised when a snapshot or restore cannot be proven complete."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _xattrs(path: Path) -> dict[str, str]:
    if not hasattr(os, "listxattr"):
        return {}
    result: dict[str, str] = {}
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError:
        return result
    for name in sorted(names):
        try:
            value = os.getxattr(path, name, follow_symlinks=False)
        except OSError:
            continue
        result[name] = base64.b64encode(value).decode("ascii")
    return result


def _apply_xattrs(path: Path, values: dict[str, str]) -> None:
    if not hasattr(os, "setxattr"):
        if values:
            raise SnapshotError("platform cannot restore extended attributes")
        return
    current = set(os.listxattr(path, follow_symlinks=False))
    expected = set(values)
    for name in current - expected:
        os.removexattr(path, name, follow_symlinks=False)
    for name, encoded in values.items():
        os.setxattr(
            path,
            name,
            base64.b64decode(encoded.encode("ascii")),
            follow_symlinks=False,
        )


def _relative_files(agent_dir: Path) -> list[str]:
    paths = {rel for rel in FIXED_SELF_STATE if (agent_dir / rel).exists()}
    for rel_dir in MANAGED_DIRS:
        root = agent_dir / rel_dir
        if not root.exists():
            continue
        if root.is_symlink() or not root.is_dir():
            raise SnapshotError(f"managed directory is not a real directory: {root}")
        for path in root.rglob("*"):
            if path.is_symlink():
                raise SnapshotError(f"symlink is not permitted in self-state: {path}")
            if path.is_file():
                paths.add(path.relative_to(agent_dir).as_posix())
    return sorted(paths)


def _entry(path: Path, rel: str) -> dict:
    if path.is_symlink() or not path.is_file():
        raise SnapshotError(f"self-state entry is not a regular file: {path}")
    metadata = path.stat(follow_symlinks=False)
    return {
        "path": rel,
        "sha256": _sha256(path),
        "size": metadata.st_size,
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mtime_ns": metadata.st_mtime_ns,
        "xattrs": _xattrs(path),
    }


def _manifest_path(snapshot_dir: Path) -> Path:
    return snapshot_dir / "manifest.json"


def _load_manifest(snapshot_dir: Path) -> dict:
    try:
        manifest = json.loads(_manifest_path(snapshot_dir).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"cannot read snapshot manifest: {exc}") from exc
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise SnapshotError("unsupported snapshot manifest schema")
    return manifest


@dataclass(frozen=True)
class Verification:
    ok: bool
    missing: list[str]
    unexpected: list[str]
    mismatched: list[dict]

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "missing": self.missing,
            "unexpected": self.unexpected,
            "mismatched": self.mismatched,
        }


class VerifiedBackupManager:
    def __init__(self, agent_dir: str | Path, repository: str | Path):
        self.agent_dir = Path(agent_dir).resolve()
        self.repository = Path(repository).resolve()
        if not self.agent_dir.is_dir():
            raise SnapshotError(f"agent directory does not exist: {self.agent_dir}")
        if self.repository == self.agent_dir or self.agent_dir in self.repository.parents:
            raise SnapshotError("backup repository must be outside the agent directory")
        self.repository.mkdir(parents=True, exist_ok=True, mode=0o700)

    def create_snapshot(self) -> dict:
        started_ns = time.monotonic_ns()
        snapshot_id = f"{time.time_ns()}-{uuid.uuid4().hex[:12]}"
        temporary = self.repository / f".{snapshot_id}.tmp"
        final = self.repository / snapshot_id
        data_dir = temporary / "data"
        data_dir.mkdir(parents=True)
        entries: list[dict] = []
        try:
            for rel in _relative_files(self.agent_dir):
                source = self.agent_dir / rel
                destination = data_dir / rel
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination, follow_symlinks=False)
                with destination.open("rb") as handle:
                    os.fsync(handle.fileno())
                source_entry = _entry(source, rel)
                copied_entry = _entry(destination, rel)
                if copied_entry["sha256"] != source_entry["sha256"]:
                    raise SnapshotError(f"copy verification failed: {rel}")
                entries.append(source_entry)

            manifest = {
                "schema_version": SCHEMA_VERSION,
                "snapshot_id": snapshot_id,
                "created_time_ns": time.time_ns(),
                "agent_dir": str(self.agent_dir),
                "fixed_self_state": list(FIXED_SELF_STATE),
                "managed_dirs": list(MANAGED_DIRS),
                "entries": entries,
            }
            manifest_path = _manifest_path(temporary)
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with manifest_path.open("rb") as handle:
                os.fsync(handle.fileno())
            _fsync_dir(temporary)
            os.replace(temporary, final)
            _fsync_dir(self.repository)
            verification = self.verify_snapshot(snapshot_id)
            if not verification.ok:
                raise SnapshotError(f"published snapshot failed verification: {verification.as_dict()}")
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            raise

        return {
            "snapshot_id": snapshot_id,
            "files": len(entries),
            "bytes": sum(entry["size"] for entry in entries),
            "elapsed_ns": time.monotonic_ns() - started_ns,
            "verified": True,
        }

    def verify_snapshot(self, snapshot_id: str) -> Verification:
        snapshot_dir = self.repository / snapshot_id
        manifest = _load_manifest(snapshot_dir)
        expected = {entry["path"]: entry for entry in manifest["entries"]}
        data_dir = snapshot_dir / "data"
        actual = {
            path.relative_to(data_dir).as_posix()
            for path in data_dir.rglob("*")
            if path.is_file()
        }
        missing = sorted(set(expected) - actual)
        unexpected = sorted(actual - set(expected))
        mismatched = []
        for rel in sorted(set(expected) & actual):
            path = data_dir / rel
            entry = expected[rel]
            if path.is_symlink():
                mismatched.append({"path": rel, "field": "type"})
                continue
            observed_hash = _sha256(path)
            if observed_hash != entry["sha256"]:
                mismatched.append({
                    "path": rel,
                    "field": "sha256",
                    "expected": entry["sha256"],
                    "observed": observed_hash,
                })
            if path.stat().st_size != entry["size"]:
                mismatched.append({"path": rel, "field": "size"})
        return Verification(not (missing or unexpected or mismatched), missing, unexpected, mismatched)

    def verify_live_state(self, snapshot_id: str) -> Verification:
        manifest = _load_manifest(self.repository / snapshot_id)
        expected = {entry["path"]: entry for entry in manifest["entries"]}
        actual = set(_relative_files(self.agent_dir))
        missing = sorted(set(expected) - actual)
        unexpected = sorted(actual - set(expected))
        mismatched = []
        for rel in sorted(set(expected) & actual):
            try:
                observed = _entry(self.agent_dir / rel, rel)
            except (OSError, SnapshotError) as exc:
                mismatched.append({
                    "path": rel,
                    "field": "readable",
                    "expected": True,
                    "observed": False,
                    "error": f"{type(exc).__name__}: {exc}",
                })
                continue
            wanted = expected[rel]
            for field in ("sha256", "size", "mode", "uid", "gid", "xattrs"):
                if observed[field] != wanted[field]:
                    mismatched.append({
                        "path": rel,
                        "field": field,
                        "expected": wanted[field],
                        "observed": observed[field],
                    })
        return Verification(not (missing or unexpected or mismatched), missing, unexpected, mismatched)

    def restore_snapshot(self, snapshot_id: str) -> dict:
        started_ns = time.monotonic_ns()
        snapshot_dir = self.repository / snapshot_id
        verification = self.verify_snapshot(snapshot_id)
        if not verification.ok:
            raise SnapshotError(f"refusing corrupt snapshot: {verification.as_dict()}")
        manifest = _load_manifest(snapshot_dir)
        expected = {entry["path"]: entry for entry in manifest["entries"]}

        restored = []
        for rel, entry in expected.items():
            source = snapshot_dir / "data" / rel
            destination = self.agent_dir / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(f".{destination.name}.restore-{uuid.uuid4().hex}")
            shutil.copyfile(source, temporary, follow_symlinks=False)
            os.chmod(temporary, entry["mode"], follow_symlinks=False)
            try:
                os.chown(temporary, entry["uid"], entry["gid"], follow_symlinks=False)
            except PermissionError as exc:
                current = temporary.stat(follow_symlinks=False)
                if (current.st_uid, current.st_gid) != (entry["uid"], entry["gid"]):
                    temporary.unlink(missing_ok=True)
                    raise SnapshotError(f"cannot restore ownership for {rel}") from exc
            _apply_xattrs(temporary, entry.get("xattrs", {}))
            os.utime(
                temporary,
                ns=(entry["mtime_ns"], entry["mtime_ns"]),
                follow_symlinks=False,
            )
            with temporary.open("rb") as handle:
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            _fsync_dir(destination.parent)
            restored.append(rel)

        removed = []
        for rel in sorted(set(_relative_files(self.agent_dir)) - set(expected), reverse=True):
            path = self.agent_dir / rel
            path.unlink()
            removed.append(rel)
        for rel_dir in MANAGED_DIRS:
            root = self.agent_dir / rel_dir
            if root.exists():
                for directory in sorted(
                    (p for p in root.rglob("*") if p.is_dir()),
                    key=lambda p: len(p.parts),
                    reverse=True,
                ):
                    try:
                        directory.rmdir()
                    except OSError:
                        pass

        live_verification = self.verify_live_state(snapshot_id)
        if not live_verification.ok:
            raise SnapshotError(f"restore verification failed: {live_verification.as_dict()}")
        return {
            "snapshot_id": snapshot_id,
            "restored": restored,
            "removed": removed,
            "elapsed_ns": time.monotonic_ns() - started_ns,
            "verified": True,
        }

    def list_snapshots(self) -> Iterable[str]:
        for path in sorted(self.repository.iterdir()):
            if path.is_dir() and not path.name.startswith("."):
                yield path.name


def main() -> int:
    parser = argparse.ArgumentParser(description="Verified OpenClaw v4 backup manager")
    parser.add_argument("agent_dir")
    parser.add_argument("--repository", required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--create", action="store_true")
    action.add_argument("--restore")
    action.add_argument("--verify")
    action.add_argument("--list", action="store_true")
    args = parser.parse_args()

    manager = VerifiedBackupManager(args.agent_dir, args.repository)
    if args.create:
        result: object = manager.create_snapshot()
    elif args.restore:
        result = manager.restore_snapshot(args.restore)
    elif args.verify:
        result = manager.verify_snapshot(args.verify).as_dict()
    else:
        result = list(manager.list_snapshots())
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
