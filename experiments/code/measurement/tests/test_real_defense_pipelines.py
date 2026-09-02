from __future__ import annotations

import os
import pwd
import sys
from pathlib import Path

from defenses.prevention.backends import (
    AgentIdentity,
    BackendContext,
    LandlockBackend,
    _locked_relpaths,
)
from measurement.prevention_real import _aggregate, _fingerprint
from measurement.recovery_real import run_scenario


def _seed(root: Path) -> Path:
    agent = root / "seed"
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
    return agent


def test_policy_levels_are_cumulative() -> None:
    previous: set[str] = set()
    for level in range(6):
        current = set(_locked_relpaths(level))
        assert previous <= current
        previous = current


def test_landlock_prefix_contains_only_unlocked_and_runtime_paths(tmp_path: Path) -> None:
    seed = _seed(tmp_path)
    launcher = tmp_path / "landlock"
    launcher.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    launcher.chmod(0o755)
    identity_entry = pwd.getpwuid(os.geteuid())
    context = BackendContext(
        agent_dir=seed,
        identity=AgentIdentity(identity_entry.pw_name, identity_entry.pw_uid, identity_entry.pw_gid),
        level=4,
        run_id="test",
        artifact_dir=tmp_path / "artifacts",
        runtime_write_paths=[tmp_path / "runtime"],
    )
    (tmp_path / "runtime").mkdir()
    prefix = LandlockBackend(launcher).command_prefix(context)
    joined = " ".join(prefix)
    assert str(seed / "workspace/memory") in joined
    assert str(seed / "workspace/MEMORY.md") not in joined
    assert str(tmp_path / "runtime") in joined


def test_prevention_aggregate_uses_only_admissible_denominator() -> None:
    attacks = [
        {"backend": "dac", "level": 1, "paper_admissible": True, "blocked": True},
        {"backend": "dac", "level": 1, "paper_admissible": True, "blocked": False},
        {"backend": "dac", "level": 1, "paper_admissible": False, "blocked": None},
    ]
    summary = _aggregate(attacks, [])
    row = summary["by_backend_level"][0]
    assert row["admissible_attacks"] == 2
    assert row["protection_rate"] == 0.5


def test_fingerprint_detects_content_and_mode_changes(tmp_path: Path) -> None:
    path = tmp_path / "state"
    path.write_text("clean", encoding="utf-8")
    before = _fingerprint(path)
    path.write_text("poison", encoding="utf-8")
    assert _fingerprint(path) != before
    path.write_text("clean", encoding="utf-8")
    path.chmod(0)
    assert _fingerprint(path) != before


def test_real_recovery_scenario_same_user(tmp_path: Path) -> None:
    seed = _seed(tmp_path)
    user = pwd.getpwuid(os.geteuid()).pw_name
    health = (
        f"{sys.executable} -c 'from pathlib import Path; import sys; "
        "assert Path(sys.argv[1]).read_text() == \"memory\\n\"' "
        "{agent_dir}/workspace/MEMORY.md"
    )
    row = run_scenario(
        seed=seed,
        work_root=tmp_path / "work",
        attack_id="Mem-M2-G3-MEM",
        agent_user=user,
        repository_mode="same-user",
        profile="TEST",
        legitimate_command=None,
        health_command=health,
        timeout=20,
    )
    assert row.get("file_recovery_success") is True, row
    assert row.get("semantic_health_success") is True, row
    assert row["paper_admissible"] is True, row
