from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "assa.stide_saturation.v1"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_sequences(paths: Iterable[Path]) -> tuple[dict[str, dict[str, list[str]]], list[dict[str, Any]]]:
    grouped: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    inputs: list[dict[str, Any]] = []
    for path in paths:
        eligible = 0
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
            identity = process.get("identity_key")
            if not identity:
                identity = f"{row['run_id']}:{process.get('pid')}:identity_incomplete"
            # run_id is included even when identity_key is present. This makes the
            # no-cross-run boundary explicit rather than relying on boot/PID entropy.
            instance = f"{row['run_id']}::{identity}"
            grouped[executable][instance].append(row["syscall"]["name"])
            eligible += 1
        inputs.append({"path": str(path), "sha256": _sha256(path), "eligible_syscalls": eligible})
    return grouped, inputs


def _ngrams(sequence: list[str], n: int) -> set[tuple[str, ...]]:
    if len(sequence) < n:
        return set()
    return {tuple(sequence[index:index + n]) for index in range(len(sequence) - n + 1)}


def _digest_ngrams(values: set[tuple[str, ...]]) -> str:
    encoded = "\n".join("\x1f".join(value) for value in sorted(values)).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def measure(batches: list[tuple[str, list[Path]]], ngram_length: int = 6,
            threshold: float = 0.01, required_consecutive: int = 2) -> dict[str, Any]:
    seen: dict[str, set[tuple[str, ...]]] = defaultdict(set)
    consecutive: dict[str, int] = defaultdict(int)
    reports: list[dict[str, Any]] = []
    observed_executables: set[str] = set()

    for batch_index, (label, paths) in enumerate(batches, start=1):
        grouped, input_rows = _load_sequences(paths)
        observed_executables.update(grouped)
        executable_rows: dict[str, Any] = {}
        for executable in sorted(grouped):
            batch_unique: set[tuple[str, ...]] = set()
            sequence_lengths: list[int] = []
            for sequence in grouped[executable].values():
                sequence_lengths.append(len(sequence))
                batch_unique.update(_ngrams(sequence, ngram_length))
            new_unique = batch_unique - seen[executable]
            seen[executable].update(batch_unique)
            primary_rate = len(new_unique) / len(batch_unique) if batch_unique else None
            cumulative_rate = len(new_unique) / len(seen[executable]) if seen[executable] else None
            initialization_batch = batch_index == 1 or len(seen[executable]) == len(new_unique)
            below = bool(not initialization_batch and primary_rate is not None and primary_rate < threshold)
            consecutive[executable] = consecutive[executable] + 1 if below else 0
            executable_rows[executable] = {
                "process_instances": len(grouped[executable]),
                "eligible_syscalls": sum(sequence_lengths),
                "sequence_lengths": sorted(sequence_lengths),
                "batch_unique_ngrams": len(batch_unique),
                "new_unique_ngrams": len(new_unique),
                "cumulative_unique_ngrams": len(seen[executable]),
                "new_unique_rate_primary_batch_denominator": primary_rate,
                "new_unique_rate_secondary_cumulative_denominator": cumulative_rate,
                "initialization_batch": initialization_batch,
                "below_threshold": below,
                "consecutive_below_threshold": consecutive[executable],
                "converged": consecutive[executable] >= required_consecutive,
                "batch_unique_ngrams_sha256": _digest_ngrams(batch_unique),
                "new_unique_ngrams_sha256": _digest_ngrams(new_unique),
                "cumulative_unique_ngrams_sha256": _digest_ngrams(seen[executable]),
                "new_unique_ngrams_values": [list(value) for value in sorted(new_unique)],
            }
        reports.append({
            "batch_index": batch_index,
            "label": label,
            "inputs": input_rows,
            "executables": executable_rows,
        })

    final_status = {
        executable: {
            "cumulative_unique_ngrams": len(seen[executable]),
            "consecutive_below_threshold": consecutive[executable],
            "converged": consecutive[executable] >= required_consecutive,
        }
        for executable in sorted(observed_executables)
        if seen[executable]
    }
    unmodeled = sorted(executable for executable in observed_executables if not seen[executable])
    return {
        "schema_version": SCHEMA_VERSION,
        "implementation_alignment": {
            "adapter": "stage_g_harness/stide_bridge.py",
            "input": "successful sequence_eligible SCAP-spine syscalls",
            "grouping": "per executable and per run-qualified process identity",
            "ngram_representation": "syscall-name tuples; count-equivalent to injective IntEmbedding tuples",
            "cross_process_concatenation": False,
            "cross_run_concatenation": False,
        },
        "ngram_length": ngram_length,
        "threshold": threshold,
        "required_consecutive_batches": required_consecutive,
        "primary_rate_definition": "new unique n-grams in batch / all unique n-grams in batch",
        "secondary_rate_definition": "new unique n-grams in batch / cumulative unique n-grams after batch",
        "initialization_batches_count_toward_convergence": False,
        "batches": reports,
        "final_by_executable": final_status,
        "unmodeled_insufficient_sequence_executables": unmodeled,
        "unmodeled_note": "Observed executable identities with no within-instance n-gram are retained but do not enter the per-modeled-executable convergence predicate.",
        "all_modeled_executables_converged": bool(final_status) and all(
            row["converged"] for row in final_status.values()
        ),
    }


def _parse_batch(value: str) -> tuple[str, list[Path]]:
    label, separator, raw_paths = value.partition("::")
    if not separator or not label or not raw_paths:
        raise argparse.ArgumentTypeError("batch must be LABEL::PATH[,PATH...]")
    paths = [Path(item) for item in raw_paths.split(",") if item]
    if not paths:
        raise argparse.ArgumentTypeError("batch must contain at least one path")
    return label, paths


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch", action="append", required=True, type=_parse_batch)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--ngram-length", type=int, default=6)
    parser.add_argument("--threshold", type=float, default=0.01)
    parser.add_argument("--required-consecutive", type=int, default=2)
    args = parser.parse_args()
    result = measure(args.batch, args.ngram_length, args.threshold, args.required_consecutive)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
