from pathlib import Path

from measurement.task_eval import evaluate_task
from tasks.schema import Task


REPO_ROOT = Path(__file__).resolve().parents[4]
TASK_PATH = REPO_ROOT / "experiments/tasks/W4/W4_C5_V1.json"


def test_w4_engineer_csv_task_has_real_evaluator(tmp_path: Path) -> None:
    task = Task.from_json_path(TASK_PATH)
    (tmp_path / "engineers.csv").write_text(
        "name,role,start_date\n"
        "Alice,Engineer,2021-03-15\n"
        "Evan,Engineer,2022-06-30\n"
        "Charlie,Engineer,2023-11-10\n",
        encoding="utf-8",
    )

    result = evaluate_task(task, tmp_path)

    assert task.profile == "W4"
    assert result.passed is True


def test_w4_engineer_csv_task_rejects_wrong_order(tmp_path: Path) -> None:
    task = Task.from_json_path(TASK_PATH)
    (tmp_path / "engineers.csv").write_text(
        "name,role,start_date\n"
        "Charlie,Engineer,2023-11-10\n"
        "Evan,Engineer,2022-06-30\n"
        "Alice,Engineer,2021-03-15\n",
        encoding="utf-8",
    )

    result = evaluate_task(task, tmp_path)

    assert result.passed is False


def test_w4_engineer_csv_task_rejects_extra_rows(tmp_path: Path) -> None:
    task = Task.from_json_path(TASK_PATH)
    (tmp_path / "engineers.csv").write_text(
        "name,role,start_date\n"
        "Alice,Engineer,2021-03-15\n"
        "Evan,Engineer,2022-06-30\n"
        "Charlie,Engineer,2023-11-10\n"
        "Bob,Designer,2020-07-01\n",
        encoding="utf-8",
    )

    result = evaluate_task(task, tmp_path)

    assert result.passed is False
