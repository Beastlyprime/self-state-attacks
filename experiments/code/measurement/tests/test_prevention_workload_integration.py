import json
import os
import pwd
from pathlib import Path

import measurement.prevention_real as prevention_real
from defenses.prevention.backends import AgentIdentity


REPO_ROOT = Path(__file__).resolve().parents[4]
TASK_PATH = REPO_ROOT / "experiments/tasks/W3/W3_C1_V1.json"


class _FakeBackend:
    name = "fake"

    def preflight(self, context):
        assert (context.agent_dir / "openclaw.json").is_file()
        assert (context.agent_dir / "workspace/TOOLS.md").is_file()
        return {"ok": True}

    def setup(self, context):
        return {"ok": True}

    def command_prefix(self, context):
        return []

    def teardown(self, context):
        return {"ok": True}


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
    for relative, content in files.items():
        path = agent / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return agent


def _identity() -> AgentIdentity:
    entry = pwd.getpwuid(os.geteuid())
    return AgentIdentity(entry.pw_name, entry.pw_uid, entry.pw_gid)


def _run(tmp_path: Path, monkeypatch, *, returncode: int, payload: dict) -> dict:
    seed = _seed(tmp_path)
    monkeypatch.setattr(
        prevention_real,
        "build_backend",
        lambda *_args, **_kwargs: _FakeBackend(),
    )
    monkeypatch.setattr(
        prevention_real,
        "_execute",
        lambda *_args, **_kwargs: {
            "command": ["fake"],
            "returncode": returncode,
            "stdout": json.dumps(payload),
            "stderr": "",
            "elapsed_ns": 1,
            "timed_out": False,
        },
    )
    return prevention_real.run_workload_scenario(
        seed=seed,
        work_root=tmp_path / "work",
        artifact_root=tmp_path / "artifacts",
        backend_name="fake",
        level=5,
        profile="W3",
        command_template=None,
        task_path=TASK_PATH,
        identity=_identity(),
        landlock_launcher=None,
        runtime_write_paths=[],
        workload_model=None,
        workload_base_url=None,
        workload_env_file=tmp_path / "api_keys.env",
        timeout=10,
    )


def test_task_failure_is_an_admissible_functionality_observation(
    tmp_path: Path, monkeypatch
) -> None:
    row = _run(
        tmp_path,
        monkeypatch,
        returncode=10,
        payload={
            "schema_version": "assa.workload_evaluator.exact.v1",
            "status": "completed",
            "exact_workspace": True,
            "task_id": "W3_C1_V1",
            "eval": {"passed": False, "status": "fail"},
        },
    )

    assert row["paper_admissible"] is True
    assert row["success"] is False
    assert row["task_stage"]["task_id"] == "W3_C1_V1"
    assert row["teardown"]["ok"] is True


def test_evaluator_infrastructure_error_is_inadmissible(
    tmp_path: Path, monkeypatch
) -> None:
    row = _run(
        tmp_path,
        monkeypatch,
        returncode=2,
        payload={
            "schema_version": "assa.workload_evaluator.exact.v1",
            "status": "infrastructure_error",
            "exact_workspace": True,
            "task_id": "W3_C1_V1",
            "error": "provider unavailable",
        },
    )

    assert row["paper_admissible"] is False
    assert row["success"] is False


def test_unsupported_evaluator_is_inadmissible(tmp_path: Path, monkeypatch) -> None:
    row = _run(
        tmp_path,
        monkeypatch,
        returncode=10,
        payload={
            "schema_version": "assa.workload_evaluator.exact.v1",
            "status": "completed",
            "exact_workspace": True,
            "task_id": "W3_C1_V1",
            "eval": {"passed": False, "status": "skipped"},
        },
    )

    assert row["paper_admissible"] is False
    assert row["success"] is False
