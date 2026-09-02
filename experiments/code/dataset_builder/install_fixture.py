#!/usr/bin/env python3
"""Install one source artifact through a process separate from the agent."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Install a paired source fixture")
    parser.add_argument("--source", required=True)
    parser.add_argument("--destination", required=True)
    args = parser.parse_args()

    source = Path(args.source).resolve()
    destination = Path(args.destination).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    raw = source.read_bytes()
    with destination.open("wb") as handle:
        handle.write(raw)
    print(
        json.dumps(
            {
                "pid": os.getpid(),
                "ppid": os.getppid(),
                "exe": os.readlink("/proc/self/exe"),
                "source": str(source),
                "destination": str(destination),
                "bytes": len(raw),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
