import json
from pathlib import Path

from experiments.code.measurement.stage_g_harness.stide_core_tail import measure


def _row(run_id: str, exe: str, syscall: str) -> dict:
    return {
        "run_id": run_id,
        "sequence_eligible": True,
        "syscall": {"name": syscall, "success": True},
        "process": {"exe": exe, "pid": 7, "identity_key": f"boot:7:{run_id}"},
    }


def _stream(path: Path, run_id: str, sequences: dict[str, list[str]]) -> Path:
    rows = []
    for exe, sequence in sequences.items():
        rows.extend(_row(run_id, exe, name) for name in sequence)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return path


def test_core_counter_and_tail_are_separate(tmp_path: Path):
    discovery_path = _stream(
        tmp_path / "discovery.jsonl", "d",
        {"/core": ["a", "b", "c", "d", "e", "f"],
         "/old-tail": ["x", "x", "x", "x", "x", "x"]})
    batch_path = _stream(
        tmp_path / "batch.jsonl", "b",
        {"/core": ["a", "b", "c", "d", "e", "f"],
         "/new-tail": ["y", "y", "y", "y", "y", "y"]})
    discovery = {"batches": [{"inputs": [{"path": str(discovery_path)}]}]}
    prereg = {
        "decision": "B",
        "stopping_rule": {"ngram_length": 6, "threshold_strictly_below": 0.01,
                          "required_consecutive_observed_batches": 2},
        "batch_admissibility": {"minimum_readiness_admitted_runs_for_convergence_batch": 4},
        "profile_freeze": {"W": {"core_executables": ["/core"],
                                   "discovery_sha256": "bound"}},
    }
    result = measure(preregistration=prereg, profile="W",
                     discovery_artifact=discovery, batch_paths=[batch_path],
                     batch_label="post1", attempted_runs=5, admitted_runs=4)
    assert result["core_executables"]["/core"]["new_unique_rate"] == 0.0
    assert result["core_executables"]["/core"]["consecutive_below_threshold"] == 1
    assert result["open_world_tail"]["new_executable_identities"] == ["/new-tail"]
    assert result["all_frozen_core_executables_converged"] is False


def test_unobserved_core_does_not_fabricate_zero(tmp_path: Path):
    discovery_path = _stream(tmp_path / "discovery.jsonl", "d",
                             {"/core": ["a", "b", "c", "d", "e", "f"]})
    batch_path = _stream(tmp_path / "batch.jsonl", "b",
                         {"/tail": ["x", "x", "x", "x", "x", "x"]})
    discovery = {"batches": [{"inputs": [{"path": str(discovery_path)}]}]}
    prereg = {
        "decision": "B",
        "stopping_rule": {"ngram_length": 6, "threshold_strictly_below": 0.01,
                          "required_consecutive_observed_batches": 2},
        "batch_admissibility": {"minimum_readiness_admitted_runs_for_convergence_batch": 4},
        "profile_freeze": {"W": {"core_executables": ["/core"],
                                   "discovery_sha256": "bound"}},
    }
    result = measure(preregistration=prereg, profile="W",
                     discovery_artifact=discovery, batch_paths=[batch_path],
                     batch_label="post1", attempted_runs=5, admitted_runs=4)
    row = result["core_executables"]["/core"]
    assert row["status"] == "not_observed"
    assert row["new_unique_rate"] is None
    assert row["consecutive_below_threshold"] == 0


def test_second_batch_uses_cumulative_postfreeze_baseline(tmp_path: Path):
    discovery_path = _stream(tmp_path / "discovery.jsonl", "d",
                             {"/core": ["a", "b", "c", "d", "e", "f"]})
    batch1_path = _stream(tmp_path / "batch1.jsonl", "b1",
                         {"/core": ["g", "h", "i", "j", "k", "l"],
                          "/tail": ["x", "x", "x", "x", "x", "x"]})
    batch2_path = _stream(tmp_path / "batch2.jsonl", "b2",
                         {"/core": ["g", "h", "i", "j", "k", "l"],
                          "/tail": ["x", "x", "x", "x", "x", "x"]})
    discovery = {"batches": [{"inputs": [{"path": str(discovery_path)}]}]}
    prereg = {
        "decision": "B",
        "stopping_rule": {"ngram_length": 6, "threshold_strictly_below": 0.01,
                          "required_consecutive_observed_batches": 2},
        "batch_admissibility": {"minimum_readiness_admitted_runs_for_convergence_batch": 4},
        "profile_freeze": {"W": {"core_executables": ["/core"],
                                   "discovery_sha256": "bound"}},
    }
    first = measure(preregistration=prereg, profile="W",
                    discovery_artifact=discovery, batch_paths=[batch1_path],
                    batch_label="post1", attempted_runs=5, admitted_runs=4)
    assert first["core_executables"]["/core"]["new_unique_rate"] == 1.0
    assert first["open_world_tail"]["new_executable_identities"] == ["/tail"]

    second = measure(preregistration=prereg, profile="W",
                     discovery_artifact=discovery, batch_paths=[batch2_path],
                     batch_label="post2", attempted_runs=5, admitted_runs=4,
                     previous=first)
    assert second["core_executables"]["/core"]["new_unique_rate"] == 0.0
    assert second["core_executables"]["/core"]["consecutive_below_threshold"] == 1
    assert second["open_world_tail"]["new_executable_identities"] == []
    assert second["open_world_tail"]["tail_new_unique_ngrams"] == 0
    assert len(second["cumulative_postfreeze_inputs_after_batch"]) == 2
