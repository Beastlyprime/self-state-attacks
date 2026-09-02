from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from defenses.recovery.backup_manager_v4 import SnapshotError, VerifiedBackupManager


def _agent_fixture(root: Path) -> Path:
    agent = root / "agent"
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
        path = agent / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    os.chmod(agent / "credentials/.env", 0o600)
    return agent


def test_snapshot_restore_removes_new_state_and_restores_metadata(tmp_path: Path) -> None:
    agent = _agent_fixture(tmp_path)
    original_mode = (agent / "openclaw.json").stat().st_mode & 0o777
    manager = VerifiedBackupManager(agent, tmp_path / "repository")
    snapshot = manager.create_snapshot()

    (agent / "workspace/MEMORY.md").write_text("poison\n", encoding="utf-8")
    (agent / "workspace/SOUL.md").unlink()
    (agent / "workspace/memory/injected.md").write_text("poison\n", encoding="utf-8")
    os.chmod(agent / "openclaw.json", 0)

    assert not manager.verify_live_state(snapshot["snapshot_id"]).ok
    restored = manager.restore_snapshot(snapshot["snapshot_id"])

    assert restored["verified"] is True
    assert manager.verify_live_state(snapshot["snapshot_id"]).ok
    assert not (agent / "workspace/memory/injected.md").exists()
    assert (agent / "workspace/SOUL.md").read_text(encoding="utf-8") == "soul\n"
    assert (agent / "workspace/MEMORY.md").read_text(encoding="utf-8") == "memory\n"
    assert (agent / "openclaw.json").stat().st_mode & 0o777 == original_mode


def test_corrupt_snapshot_is_rejected_before_restore(tmp_path: Path) -> None:
    agent = _agent_fixture(tmp_path)
    manager = VerifiedBackupManager(agent, tmp_path / "repository")
    snapshot = manager.create_snapshot()
    snapshot_dir = manager.repository / snapshot["snapshot_id"]
    (snapshot_dir / "data/workspace/MEMORY.md").write_text("corrupt", encoding="utf-8")

    with pytest.raises(SnapshotError, match="refusing corrupt snapshot"):
        manager.restore_snapshot(snapshot["snapshot_id"])


def test_repository_must_be_outside_agent_tree(tmp_path: Path) -> None:
    agent = _agent_fixture(tmp_path)
    with pytest.raises(SnapshotError, match="outside"):
        VerifiedBackupManager(agent, agent / "backups")


def test_manifest_uses_full_sha256_and_unique_ids(tmp_path: Path) -> None:
    agent = _agent_fixture(tmp_path)
    manager = VerifiedBackupManager(agent, tmp_path / "repository")
    first = manager.create_snapshot()
    second = manager.create_snapshot()
    assert first["snapshot_id"] != second["snapshot_id"]
    manifest = json.loads(
        (manager.repository / first["snapshot_id"] / "manifest.json").read_text()
    )
    assert manifest["entries"]
    assert all(len(entry["sha256"]) == 64 for entry in manifest["entries"])
