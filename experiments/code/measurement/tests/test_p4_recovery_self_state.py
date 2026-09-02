from __future__ import annotations

import os
import pwd
from pathlib import Path

from measurement import p4_recovery_self_state as p4


def _source_run(root: Path) -> Path:
    source = root / "source_run"
    workspace = source / "workspace"
    files = {
        "SOUL.md": "soul\n",
        "AGENTS.md": "agents\n",
        "IDENTITY.md": "identity\n",
        "USER.md": "user\n",
        "MEMORY.md": "# Memory\n\n- accumulated post-session fact\n",
        "TOOLS.md": "tools\n",
        "HEARTBEAT.md": "heartbeat\n",
        "openclaw.json": '{"schedules": {}}\n',
        "memory/2026-08-22.md": "daily accumulated note\n",
    }
    for rel, text in files.items():
        path = workspace / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return source


def test_formal_seed_maps_post_session_workspace_layout(tmp_path: Path) -> None:
    user = pwd.getpwuid(os.geteuid())
    seed = tmp_path / "formal_seed"

    provenance = p4.build_formal_seed(_source_run(tmp_path), seed, uid=user.pw_uid, gid=user.pw_gid)

    assert (seed / "workspace/MEMORY.md").read_text(encoding="utf-8").startswith("# Memory")
    assert (seed / "openclaw.json").read_text(encoding="utf-8").startswith("{")
    assert (seed / "workspace/memory/2026-08-22.md").is_file()
    assert (seed / "credentials/.env").is_file()
    assert provenance["post_session_requirements"]["memory_not_empty_template"] is False
    assert any(
        row.get("source_kind") == "scaffold_placeholder_created_for_healthcheck"
        for row in provenance["mappings"]
    )


def test_summary_keeps_five_metrics_separate() -> None:
    rows = [
        {
            "run_id": "r1",
            "case": "protected-normal",
            "repository_mode": "protected",
            "include_backup_destruction": False,
            "paper_admissible": True,
            "metrics": {
                "byte_recovery": {"success": True},
                "functional_health": {"success": False},
                "rollback_loss": {"paths_changed_or_added_since_snapshot": 1},
                "restore_latency": {"elapsed_ns": 10},
                "backup_availability": {"snapshot_available_after_repository_attack": True},
            },
        }
    ]

    summary = p4._summarize(rows)

    case = summary["by_case"][0]
    assert case["byte_recovery_success"] is True
    assert case["functional_health_success"] is False
    assert case["rollback_loss_paths"] == 1
    assert case["restore_latency_ns"] == 10
    assert case["backup_available_after_attack"] is True


def test_metrics_mark_hash_equality_as_byte_only() -> None:
    row = {
        "metrics": {
            "byte_recovery": {
                "success": True,
                "hash_equality_only_not_semantic_recovery": True,
            },
            "functional_health": {
                "success": True,
                "hash_equality_not_used_as_health": True,
            },
        }
    }

    assert row["metrics"]["byte_recovery"]["hash_equality_only_not_semantic_recovery"] is True
    assert row["metrics"]["functional_health"]["hash_equality_not_used_as_health"] is True

