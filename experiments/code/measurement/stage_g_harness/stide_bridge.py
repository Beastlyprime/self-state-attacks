from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


EXPECTED_COMMIT = "587d15870843961acb78fbb4b8fcd0ede28eabcc"
DEFAULT_MIN_SCORING_SEQUENCE_LENGTH = 106


class ASSASyscall:
    def __init__(self, row: dict[str, Any]):
        self.row = row
        self.recording_path = row["run_id"]
        self.line_id = row["event_id"]

    def timestamp_unix_in_ns(self) -> int: return int(self.row["order"]["timestamp_realtime_ns"])
    def user_id(self) -> int: return int(self.row["process"].get("uid") or -1)
    def process_id(self) -> int: return int(self.row["process"].get("pid") or -1)
    def process_name(self) -> str: return self.row["process"].get("exe") or self.row["process"].get("comm") or "<unknown>"
    def thread_id(self) -> int: return int(self.row["process"].get("tid") or self.process_id())
    def name(self) -> str: return self.row["syscall"]["name"]
    def params(self) -> dict[str, Any]: return self.row["syscall"].get("arguments") or {}
    def param(self, param_name: str, b64decode: bool = False): return self.params().get(param_name)


def _load(paths: list[Path]) -> dict[str, dict[str, list[ASSASyscall]]]:
    grouped: dict[str, dict[str, list[ASSASyscall]]] = defaultdict(lambda: defaultdict(list))
    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if not row.get("sequence_eligible", False):
                continue
            if not row.get("syscall", {}).get("success"):
                continue
            process = row.get("process") or {}
            executable = process.get("exe") or process.get("comm") or "<unknown>"
            instance = process.get("identity_key") or f"{row['run_id']}:{process.get('pid')}:identity_incomplete"
            grouped[executable][instance].append(ASSASyscall(row))
    return grouped


def run(repository: Path, train_paths: list[Path], test_paths: list[Path], ngram_length: int = 6,
        minimum_scoring_sequence_length: int = DEFAULT_MIN_SCORING_SEQUENCE_LENGTH) -> dict[str, Any]:
    sys.path.insert(0, str(repository.resolve()))
    from algorithms.decision_engines.stide import Stide
    from algorithms.features.impl.int_embedding import IntEmbedding
    from algorithms.features.impl.ngram import Ngram
    from algorithms.building_block import BuildingBlock

    compatibility_shims: list[dict[str, str]] = []
    if sys.version_info >= (3, 13):
        BuildingBlock._BuildingBlock__arguments = staticmethod(lambda: {})
        compatibility_shims.append({"name": "python_3_13_frame_locals",
                                    "scope": "configuration introspection only; scoring code unchanged"})

    train, test = _load(train_paths), _load(test_paths)
    results: dict[str, Any] = {}
    for executable in sorted(set(train) | set(test)):
        train_recordings = list(train.get(executable, {}).values())
        test_recordings = list(test.get(executable, {}).values())
        train_lengths = [len(recording) for recording in train_recordings]
        test_lengths = [len(recording) for recording in test_recordings]
        embedding = IntEmbedding()
        ngram = Ngram([embedding], False, ngram_length)
        stide = Stide(ngram)
        for recording in train_recordings:
            for syscall in recording:
                embedding.train_on(syscall)
            embedding.new_recording()
        embedding.fit()
        train_syscalls = 0
        for recording in train_recordings:
            for syscall in recording:
                stide.train_on(syscall)
                train_syscalls += 1
            ngram.new_recording()
        stide.fit()
        evaluated = anomalies = 0
        by_instance: dict[str, Any] = {}
        for instance, recording in test.get(executable, {}).items():
            instance_evaluated = instance_anomalies = 0
            for syscall in recording:
                score = stide.get_result(syscall)
                if score is not None:
                    evaluated += 1
                    instance_evaluated += 1
                    anomalies += int(score)
                    instance_anomalies += int(score)
            ngram.new_recording()
            by_instance[instance] = {"evaluated_ngrams": instance_evaluated, "unknown_ngrams": instance_anomalies}
        normal_database_ngrams = len(stide._normal_database)
        long_training_instances = sum(length >= minimum_scoring_sequence_length for length in train_lengths)
        long_test_instances = sum(length >= minimum_scoring_sequence_length for length in test_lengths)
        scoring_gate_passed = bool(
            normal_database_ngrams
            and evaluated
            and long_training_instances
            and long_test_instances
        )
        reasons = []
        if not normal_database_ngrams:
            reasons.append("no trainable n-gram baseline")
        if not evaluated:
            reasons.append("held-out data produced no repository-native score")
        if not long_training_instances:
            reasons.append(f"no training process instance has >= {minimum_scoring_sequence_length} syscalls")
        if not long_test_instances:
            reasons.append(f"no held-out process instance has >= {minimum_scoring_sequence_length} syscalls")
        results[executable] = {
            "training_process_instances": len(train.get(executable, {})), "training_syscalls": train_syscalls,
            "max_training_instance_syscalls": max(train_lengths, default=0),
            "long_training_process_instances": long_training_instances,
            "status": "passed" if scoring_gate_passed else "data_insufficient",
            "reason": None if scoring_gate_passed else "; ".join(reasons),
            "normal_database_ngrams": normal_database_ngrams,
            "test_process_instances": len(test.get(executable, {})), "evaluated_ngrams": evaluated,
            "max_test_instance_syscalls": max(test_lengths, default=0),
            "long_test_process_instances": long_test_instances,
            "minimum_scoring_sequence_length": minimum_scoring_sequence_length,
            "scoring_gate_passed": scoring_gate_passed,
            "unknown_ngrams": anomalies, "unknown_ngram_fraction": anomalies / evaluated if evaluated else None,
            "instances": by_instance,
        }
    return {"implementation": "LID-DS Stide+Ngram", "commit": EXPECTED_COMMIT,
            "ngram_length": ngram_length, "thread_aware": False,
            "minimum_scoring_sequence_length": minimum_scoring_sequence_length,
            "scoring_gate_passed": bool(results) and all(
                result["scoring_gate_passed"] for result in results.values()
            ),
            "compatibility_shims": compatibility_shims, "results": results}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--train", required=True, action="append", type=Path)
    parser.add_argument("--test", required=True, action="append", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--ngram-length", type=int, default=6)
    parser.add_argument("--minimum-scoring-sequence-length", type=int,
                        default=DEFAULT_MIN_SCORING_SEQUENCE_LENGTH)
    args = parser.parse_args()
    result = run(args.repository, args.train, args.test, args.ngram_length,
                 args.minimum_scoring_sequence_length)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
