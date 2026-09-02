#!/usr/bin/env python3
"""Benign same-FD write workload for Stage-G lifecycle preflight."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def run(output: Path) -> dict:
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        output,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC,
        0o600,
    )
    try:
        writes = [
            os.write(fd, b"clean-one\n"),
            os.write(fd, b"clean-two\n"),
            os.pwrite(fd, b"clean-three\n", 20),
        ]
        os.fsync(fd)
        stat_result = os.fstat(fd)
    finally:
        os.close(fd)
    return {
        "input_class": "clean",
        "path": str(output),
        "same_fd_for_all_writes": True,
        "write_syscall_count": len(writes),
        "bytes_written": writes,
        "dev": stat_result.st_dev,
        "inode": stat_result.st_ino,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.output), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
