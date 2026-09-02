#!/usr/bin/env python3
"""Build a minimal, credential-free Stage G runtime bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_VERSION = "assa.stage_g.runtime_bundle.v1"
CODE_PACKAGES = ("attacks", "defenses", "measurement", "workload")
COPY_IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", "tests")
SECRET_MARKERS = (
    b"sk-or-" + b"v1-",
    b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----",
    b"-----BEGIN " + b"RSA PRIVATE KEY-----",
    b"-----BEGIN " + b"EC PRIVATE KEY-----",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _copy_tree(source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise ValueError(f"bundle source directory is missing: {source}")
    shutil.copytree(source, destination, ignore=COPY_IGNORE)


def _copy_file(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise ValueError(f"bundle source file is missing: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def _task_payload(task_path: Path) -> dict:
    try:
        payload = json.loads(task_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid task JSON {task_path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"task JSON must be an object: {task_path}")
    if payload.get("profile") not in {"W1", "W2", "W3", "W4"}:
        raise ValueError(f"task has invalid profile: {task_path}")
    if not isinstance(payload.get("seed_files"), list):
        raise ValueError(f"task has no seed_files list: {task_path}")
    return payload


def _set_read_only(root: Path) -> None:
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if path.is_symlink():
            continue
        if path.is_dir():
            path.chmod(0o555)
        else:
            executable = bool(path.stat().st_mode & 0o100)
            path.chmod(0o555 if executable else 0o444)
    root.chmod(0o555)


def build_runtime_bundle(
    output: Path,
    *,
    tasks: list[Path],
    landlock_launcher: Path | None = None,
    repo_root: Path = REPO_ROOT,
    read_only: bool = True,
) -> dict:
    """Copy exact runner dependencies and selected task inputs into a bundle."""
    output = output.resolve()
    repo_root = repo_root.resolve()
    if output.exists():
        raise FileExistsError(f"refusing to overwrite existing bundle: {output}")
    if not tasks:
        raise ValueError("at least one task JSON is required")

    task_root = repo_root / "experiments" / "tasks"
    parsed: list[tuple[Path, dict]] = []
    for task in tasks:
        task = task.resolve()
        try:
            task.relative_to(task_root)
        except ValueError as exc:
            raise ValueError(f"task must be inside {task_root}: {task}") from exc
        parsed.append((task, _task_payload(task)))

    output.mkdir(parents=True)
    code_root = repo_root / "experiments" / "code"
    for package in CODE_PACKAGES:
        _copy_tree(code_root / package, output / "experiments" / "code" / package)

    openclaw_source = (repo_root / "experiments" / "agent" / "openclaw_core").resolve()
    _copy_tree(
        openclaw_source,
        output / "experiments" / "agent" / "openclaw_core",
    )
    (output / "openclaw_core").symlink_to("experiments/agent/openclaw_core")

    schema = task_root / "schema.py"
    _copy_file(schema, output / "experiments" / "tasks" / "schema.py")
    init = task_root / "__init__.py"
    if init.is_file():
        _copy_file(init, output / "experiments" / "tasks" / "__init__.py")
    (output / "tasks").symlink_to("experiments/tasks")

    profiles = sorted({payload["profile"] for _, payload in parsed})
    pack_names = {
        "W1": "w1_coding",
        "W2": "w2_knowledge",
        "W3": "w3_devops",
        "W4": "w4_general",
    }
    for profile in profiles:
        pack_name = pack_names[profile]
        _copy_tree(
            repo_root / "experiments" / "agent_packs" / pack_name,
            output / "experiments" / "agent_packs" / pack_name,
        )

    task_records = []
    for source, payload in parsed:
        relative = source.relative_to(task_root)
        destination = output / "experiments" / "tasks" / relative
        _copy_file(source, destination)
        copied_seeds = []
        for seed in payload["seed_files"]:
            content_ref = seed.get("content_ref") if isinstance(seed, dict) else None
            if (
                not isinstance(content_ref, str)
                or content_ref.startswith("/")
                or ".." in content_ref.split("/")
            ):
                raise ValueError(
                    f"invalid seed content_ref in {source}: {content_ref!r}"
                )
            seed_source = task_root / content_ref
            _copy_file(seed_source, output / "experiments" / "tasks" / content_ref)
            copied_seeds.append(content_ref)
        task_records.append(
            {
                "task_id": payload.get("task_id"),
                "profile": payload["profile"],
                "path": str(relative),
                "seed_files": sorted(copied_seeds),
            }
        )

    launcher_record = None
    if landlock_launcher is not None:
        launcher = landlock_launcher.resolve()
        destination = output / "bin" / "assa-landlock"
        _copy_file(launcher, destination)
        destination.chmod(destination.stat().st_mode | 0o100)
        launcher_record = {
            "path": "bin/assa-landlock",
            "sha256": _sha256(destination),
        }

    credential_files = [
        path for path in output.rglob("*")
        if path.is_file() and path.name == ".env"
    ]
    if credential_files:
        raise ValueError(f"bundle contains credential files: {credential_files}")
    for path in output.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        content = path.read_bytes()
        if any(marker in content for marker in SECRET_MARKERS):
            raise ValueError(f"bundle contains a secret marker: {path}")

    file_records = []
    for path in sorted(output.rglob("*")):
        if path.is_file() and not path.is_symlink():
            file_records.append(
                {
                    "path": str(path.relative_to(output)),
                    "sha256": _sha256(path),
                    "size": path.stat().st_size,
                }
            )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_repo": str(repo_root),
        "builder_uid": os.geteuid(),
        "credential_free": True,
        "read_only": read_only,
        "profiles": profiles,
        "tasks": task_records,
        "landlock_launcher": launcher_record,
        "files": file_records,
    }
    manifest_path = output / "bundle-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if read_only:
        _set_read_only(output)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--task", action="append", required=True, type=Path)
    parser.add_argument("--landlock-launcher", type=Path)
    parser.add_argument("--writable", action="store_true")
    args = parser.parse_args()
    manifest = build_runtime_bundle(
        args.output,
        tasks=args.task,
        landlock_launcher=args.landlock_launcher,
        read_only=not args.writable,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
