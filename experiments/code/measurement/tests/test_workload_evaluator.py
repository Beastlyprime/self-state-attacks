from pathlib import Path

from defenses.workload_tasks import prepare_workload_task, task_seed_destination
from measurement.workload_evaluator import (
    evaluate_existing_task,
    evaluation_is_supported,
)
from tasks.schema import Task


REPO_ROOT = Path(__file__).resolve().parents[4]
TASKS_ROOT = REPO_ROOT / "experiments" / "tasks"


def _agent_seed(root: Path) -> Path:
    agent = root / "agent"
    workspace = agent / "workspace"
    workspace.mkdir(parents=True)
    for name in (
        "SOUL.md",
        "AGENTS.md",
        "IDENTITY.md",
        "USER.md",
        "MEMORY.md",
        "TOOLS.md",
        "HEARTBEAT.md",
    ):
        (workspace / name).write_text(f"seed {name}\n", encoding="utf-8")
    (workspace / "memory").mkdir()
    (agent / "openclaw.json").write_text("{}\n", encoding="utf-8")
    return agent


def test_task_seed_destination_projects_config_to_state_root(tmp_path: Path) -> None:
    agent = tmp_path / "agent"
    assert task_seed_destination(agent, "openclaw.json") == agent / "openclaw.json"
    assert task_seed_destination(agent, "TOOLS.md") == agent / "workspace/TOOLS.md"


def test_prepare_w3_task_stages_before_policy(tmp_path: Path) -> None:
    agent = _agent_seed(tmp_path)
    task = Task.from_json_path(TASKS_ROOT / "W3/W3_C1_V1.json")

    manifest = prepare_workload_task(task, agent)

    assert manifest["profile"] == "W3"
    assert "browser_fetch" not in (agent / "workspace/TOOLS.md").read_text()
    assert "tools" in (agent / "openclaw.json").read_text()
    destinations = {row["task_path"]: row["destination"] for row in manifest["staged"]}
    assert destinations["openclaw.json"] == str(agent / "openclaw.json")
    assert destinations["TOOLS.md"] == str(agent / "workspace/TOOLS.md")


def test_w3_evaluator_reads_config_from_state_root(tmp_path: Path) -> None:
    agent = _agent_seed(tmp_path)
    task = Task.from_json_path(TASKS_ROOT / "W3/W3_C1_V1.json")
    (agent / "openclaw.json").write_text(
        '{"tools":{"browser_fetch":{"enabled":true,"description":"fetch"}}}',
        encoding="utf-8",
    )
    (agent / "workspace/TOOLS.md").write_text("browser_fetch\n", encoding="utf-8")

    result = evaluate_existing_task(task, agent, tmp_path / "artifacts", "done")

    assert result["passed"] is True


def test_only_real_pass_fail_verdicts_are_supported() -> None:
    assert evaluation_is_supported({"status": "pass", "passed": True}) is True
    assert evaluation_is_supported({"status": "fail", "passed": False}) is True
    assert evaluation_is_supported({"status": "skipped", "passed": False}) is False
