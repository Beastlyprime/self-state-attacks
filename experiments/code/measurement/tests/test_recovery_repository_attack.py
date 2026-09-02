from __future__ import annotations

import os
import pwd
from pathlib import Path

from measurement.recovery_real import run_scenario


def _seed(root: Path) -> Path:
    seed = root / "seed"
    files = {
        "workspace/SOUL.md": "soul\n",
        "workspace/AGENTS.md": "agents\n",
        "workspace/IDENTITY.md": "identity\n",
        "workspace/USER.md": "user\n",
        "workspace/MEMORY.md": "memory\n",
        "workspace/TOOLS.md": "tools\n",
        "workspace/HEARTBEAT.md": "heartbeat\n",
        "workspace/memory/2026-04-26.md": "daily\n",
        "openclaw.json": "{}\n",
        "credentials/.env": "KEY=value\n",
    }
    for rel, content in files.items():
        path = seed / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return seed


def test_same_user_backup_destruction_is_valid_failed_recovery(tmp_path: Path) -> None:
    user = pwd.getpwuid(os.geteuid()).pw_name
    row = run_scenario(
        seed=_seed(tmp_path),
        work_root=tmp_path / "work",
        attack_id="Mem-M3-G1-MEM",
        agent_user=user,
        repository_mode="same-user",
        profile="TEST",
        legitimate_command=None,
        health_command=None,
        timeout=20,
        destroy_repository=True,
    )
    assert row["attack_id"] == "B8"
    assert row["repository_attack"]["snapshot_destroyed"] is True
    assert row["file_recovery_success"] is False
    assert row["paper_admissible"] is True
