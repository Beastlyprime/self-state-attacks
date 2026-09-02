from pathlib import Path

from defenses.recovery.backup_manager_v4 import FIXED_SELF_STATE
from defenses.recovery.healthcheck_v4 import check_state


def _complete_state(root: Path) -> None:
    for rel in FIXED_SELF_STATE:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n" if rel == "openclaw.json" else "state\n", encoding="utf-8")
    (root / "workspace/memory").mkdir(parents=True, exist_ok=True)


def test_healthcheck_accepts_complete_readable_state(tmp_path: Path) -> None:
    _complete_state(tmp_path)
    assert check_state(tmp_path)["ok"] is True


def test_healthcheck_rejects_invalid_config_and_missing_file(tmp_path: Path) -> None:
    _complete_state(tmp_path)
    (tmp_path / "openclaw.json").write_text("not json", encoding="utf-8")
    (tmp_path / "workspace/SOUL.md").unlink()
    result = check_state(tmp_path)
    assert result["ok"] is False
    assert any(not check["ok"] for check in result["checks"])
