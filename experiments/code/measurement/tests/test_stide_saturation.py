import json
from pathlib import Path

from experiments.code.measurement.stage_g_harness.stide_saturation import measure


def _write(path: Path, run_id: str, identity: str, names: list[str]) -> None:
    rows = []
    for index, name in enumerate(names):
        rows.append({
            "run_id": run_id,
            "event_id": f"{run_id}:{index}",
            "sequence_eligible": True,
            "process": {"exe": "/bin/tool", "pid": 7, "identity_key": identity},
            "syscall": {"name": name, "success": True},
        })
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_reports_batch_unique_rate_without_cross_run_concatenation(tmp_path: Path) -> None:
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    _write(first, "r1", "same", ["a", "b", "c", "d"])
    _write(second, "r2", "same", ["c", "d", "e", "f"])

    report = measure([("b1", [first]), ("b2", [second])], ngram_length=2)

    first_row = report["batches"][0]["executables"]["/bin/tool"]
    second_row = report["batches"][1]["executables"]["/bin/tool"]
    assert first_row["batch_unique_ngrams"] == 3
    assert first_row["new_unique_rate_primary_batch_denominator"] == 1.0
    assert first_row["initialization_batch"] is True
    assert second_row["batch_unique_ngrams"] == 3
    assert second_row["new_unique_ngrams"] == 2
    assert second_row["new_unique_rate_primary_batch_denominator"] == 2 / 3
    assert ["d", "c"] not in second_row["new_unique_ngrams_values"]


def test_failed_and_noneligible_rows_do_not_enter_sequences(tmp_path: Path) -> None:
    path = tmp_path / "rows.jsonl"
    rows = [
        {"run_id": "r", "event_id": "0", "sequence_eligible": True,
         "process": {"exe": "x", "pid": 1, "identity_key": "i"},
         "syscall": {"name": "a", "success": True}},
        {"run_id": "r", "event_id": "1", "sequence_eligible": True,
         "process": {"exe": "x", "pid": 1, "identity_key": "i"},
         "syscall": {"name": "ignored_failed", "success": False}},
        {"run_id": "r", "event_id": "2", "sequence_eligible": False,
         "process": {"exe": "x", "pid": 1, "identity_key": "i"},
         "syscall": {"name": "ignored_source", "success": True}},
        {"run_id": "r", "event_id": "3", "sequence_eligible": True,
         "process": {"exe": "x", "pid": 1, "identity_key": "i"},
         "syscall": {"name": "b", "success": True}},
    ]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    report = measure([("b1", [path])], ngram_length=2)
    row = report["batches"][0]["executables"]["x"]
    assert row["eligible_syscalls"] == 2
    assert row["new_unique_ngrams_values"] == [["a", "b"]]


def test_short_observed_executable_is_reported_but_not_modeled(tmp_path: Path) -> None:
    path = tmp_path / "short.jsonl"
    _write(path, "r", "i", ["a", "b"])

    report = measure([("b1", [path])], ngram_length=6)

    assert report["batches"][0]["executables"]["/bin/tool"]["batch_unique_ngrams"] == 0
    assert report["final_by_executable"] == {}
    assert report["unmodeled_insufficient_sequence_executables"] == ["/bin/tool"]
    assert report["all_modeled_executables_converged"] is False
