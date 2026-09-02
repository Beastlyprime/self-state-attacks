#!/usr/bin/env python3
"""Post-restore load check for the active OpenClaw self-state layout."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from defenses.recovery.backup_manager_v4 import FIXED_SELF_STATE  # noqa: E402


def check_state(agent_dir: str | Path) -> dict:
    root = Path(agent_dir).resolve()
    checks = []
    for rel in FIXED_SELF_STATE:
        path = root / rel
        try:
            raw = path.read_bytes()
            checks.append({"path": rel, "ok": path.is_file(), "size": len(raw)})
        except OSError as exc:
            checks.append({"path": rel, "ok": False, "error": f"{type(exc).__name__}: {exc}"})

    config_path = root / "openclaw.json"
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config_ok = isinstance(config, dict)
        checks.append({"path": "openclaw.json", "check": "json_object", "ok": config_ok})
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        checks.append({"path": "openclaw.json", "check": "json_object", "ok": False, "error": str(exc)})

    memory_dir = root / "workspace" / "memory"
    memory_ok = memory_dir.is_dir() and not memory_dir.is_symlink()
    checks.append({"path": "workspace/memory", "check": "real_directory", "ok": memory_ok})
    return {
        "schema_version": "assa.recovery.health.v1",
        "agent_dir": str(root),
        "ok": bool(checks and all(check["ok"] for check in checks)),
        "checks": checks,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate restored OpenClaw v4 self-state")
    parser.add_argument("agent_dir")
    args = parser.parse_args()
    result = check_state(args.agent_dir)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
