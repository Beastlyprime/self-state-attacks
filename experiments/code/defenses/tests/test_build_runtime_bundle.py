import json
import stat
from pathlib import Path

import pytest

from defenses.build_runtime_bundle import build_runtime_bundle


REPO_ROOT = Path(__file__).resolve().parents[4]


def test_build_runtime_bundle_contains_only_selected_task_inputs(
    tmp_path: Path,
) -> None:
    output = tmp_path / "bundle"
    task = REPO_ROOT / "experiments/tasks/W4/W4_C5_V1.json"

    manifest = build_runtime_bundle(output, tasks=[task])

    assert manifest["credential_free"] is True
    assert manifest["profiles"] == ["W4"]
    assert [row["task_id"] for row in manifest["tasks"]] == ["W4_C5_V1"]
    assert (output / "experiments/tasks/W4/W4_C5_V1.json").is_file()
    assert (output / "experiments/tasks/seeds/W4_C5_V1/people.csv").is_file()
    assert not list(output.rglob(".env"))
    assert (output / "openclaw_core").resolve().is_dir()
    assert (output / "tasks/schema.py").is_file()
    assert stat.S_IMODE(output.stat().st_mode) == 0o555
    payload = json.loads((output / "bundle-manifest.json").read_text())
    assert payload["schema_version"] == "assa.stage_g.runtime_bundle.v1"


def test_build_runtime_bundle_refuses_external_task(tmp_path: Path) -> None:
    task = tmp_path / "task.json"
    task.write_text(
        json.dumps({"profile": "W4", "seed_files": []}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="task must be inside"):
        build_runtime_bundle(tmp_path / "bundle", tasks=[task])


def test_build_runtime_bundle_rejects_secret_marker(tmp_path: Path) -> None:
    task = REPO_ROOT / "experiments/tasks/W4/W4_C5_V1.json"
    launcher = tmp_path / "launcher"
    launcher.write_bytes(b"sk-or-" + b"v1-test-secret")

    with pytest.raises(ValueError, match="secret marker"):
        build_runtime_bundle(
            tmp_path / "bundle",
            tasks=[task],
            landlock_launcher=launcher,
        )
