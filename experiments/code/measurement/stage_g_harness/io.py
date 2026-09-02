from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at {path}:{line_number}: {exc}") from exc
    return rows


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
            count += 1
    return count


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def directory_record(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    total_bytes = 0
    file_count = 0
    for child in sorted(path.rglob("*"), key=lambda item: item.relative_to(path).as_posix()):
        relative = child.relative_to(path).as_posix()
        if child.is_symlink():
            digest.update(f"L\0{relative}\0{child.readlink()}\n".encode())
        elif child.is_file():
            size = child.stat().st_size
            digest.update(f"F\0{relative}\0{size}\0{sha256_file(child)}\n".encode())
            total_bytes += size
            file_count += 1
        elif child.is_dir():
            digest.update(f"D\0{relative}\n".encode())
    return {
        "path": str(path.resolve()),
        "kind": "directory",
        "bytes": total_bytes,
        "file_count": file_count,
        "sha256": digest.hexdigest(),
    }


def file_record(path: Path) -> dict[str, Any]:
    if path.is_dir():
        return directory_record(path)
    return {
        "path": str(path.resolve()),
        "kind": "file",
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }
