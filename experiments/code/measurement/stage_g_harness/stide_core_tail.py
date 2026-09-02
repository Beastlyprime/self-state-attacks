from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "assa.stide_core_tail.v2"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ngrams(sequence: list[str], n: int) -> set[tuple[str, ...]]:
    if len(sequence) < n:
        return set()
    return {tuple(sequence[index:index + n]) for index in range(len(sequence) - n + 1)}


def _load_sequences(paths: Iterable[Path]) -> tuple[
        dict[str, dict[str, list[str]]], list[dict[str, Any]]]:
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
            instance = f"{row['run_id']}::{identity}"
            grouped[executable][instance].append(row["syscall"]["name"])
            eligible += 1
        inputs.append({"path": str(path), "sha256": _sha256(path),
                       "eligible_syscalls": eligible})
    return grouped, inputs


def _unique_by_executable(grouped: dict[str, dict[str, list[str]]], n: int
                          ) -> dict[str, set[tuple[str, ...]]]:
    result: dict[str, set[tuple[str, ...]]] = {}
    for executable, instances in grouped.items():
        values: set[tuple[str, ...]] = set()
        for sequence in instances.values():
            values.update(_ngrams(sequence, n))
        result[executable] = values
    return result


def _discovery_paths(artifact: dict[str, Any]) -> list[Path]:
    return [Path(row["path"]) for batch in artifact["batches"]
            for row in batch["inputs"]]


def _validated_previous_inputs(previous: dict[str, Any] | None, *,
                               profile: str, discovery_sha256: str,
                               ngram_length: int) -> list[Path]:
    if previous is None:
        return []
    if previous.get("profile") != profile:
        raise ValueError("previous post-freeze artifact has a different profile")
    if previous.get("discovery_artifact_sha256") != discovery_sha256:
        raise ValueError("previous post-freeze artifact has a different discovery baseline")
    if previous.get("ngram_length") != ngram_length:
        raise ValueError("previous post-freeze artifact has a different n-gram length")
    rows = previous.get("cumulative_postfreeze_inputs_after_batch")
    if not isinstance(rows, list):
        raise ValueError("previous artifact lacks cumulative post-freeze inputs")
    paths: list[Path] = []
    for row in rows:
        path = Path(row["path"])
        if not path.is_file():
            raise ValueError(f"previous post-freeze input is unavailable: {path}")
        if _sha256(path) != row.get("sha256"):
            raise ValueError(f"previous post-freeze input hash changed: {path}")
        paths.append(path)
    if len(paths) != len(set(paths)):
        raise ValueError("previous post-freeze inputs are not unique")
    return paths


def measure(*, preregistration: dict[str, Any], profile: str,
            discovery_artifact: dict[str, Any], batch_paths: list[Path],
            batch_label: str, attempted_runs: int, admitted_runs: int,
            previous: dict[str, Any] | None = None) -> dict[str, Any]:
    freeze = preregistration["profile_freeze"][profile]
    core = set(freeze["core_executables"])
    n = int(preregistration["stopping_rule"]["ngram_length"])
    threshold = float(preregistration["stopping_rule"]["threshold_strictly_below"])
    required = int(preregistration["stopping_rule"]["required_consecutive_observed_batches"])

    discovery_grouped, discovery_inputs = _load_sequences(
        _discovery_paths(discovery_artifact))
    prior_paths = _validated_previous_inputs(
        previous, profile=profile, discovery_sha256=freeze["discovery_sha256"],
        ngram_length=n)
    if set(prior_paths) & set(batch_paths):
        raise ValueError("current batch overlaps previous post-freeze inputs")
    prior_grouped, prior_inputs = _load_sequences(prior_paths)
    batch_grouped, batch_inputs = _load_sequences(batch_paths)
    discovery_unique = _unique_by_executable(discovery_grouped, n)
    prior_unique = _unique_by_executable(prior_grouped, n)
    baseline_unique = {
        executable: discovery_unique.get(executable, set()) |
        prior_unique.get(executable, set())
        for executable in set(discovery_unique) | set(prior_unique)
    }
    batch_unique = _unique_by_executable(batch_grouped, n)
    baseline_identities = set(discovery_grouped) | set(prior_grouped)
    prior_rows = (previous or {}).get("core_executables", {})

    core_rows: dict[str, Any] = {}
    resets: list[dict[str, Any]] = []
    for executable in sorted(core):
        values = batch_unique.get(executable, set())
        prior = int((prior_rows.get(executable) or {}).get(
            "consecutive_below_threshold", 0))
        if not values:
            core_rows[executable] = {
                "status": "not_observed",
                "batch_unique_ngrams": 0,
                "new_unique_ngrams": 0,
                "new_unique_rate": None,
                "prior_consecutive_below_threshold": prior,
                "consecutive_below_threshold": prior,
                "converged": prior >= required,
            }
            continue
        new_values = values - baseline_unique.get(executable, set())
        rate = len(new_values) / len(values)
        below = rate < threshold
        current = prior + 1 if below else 0
        if prior > 0 and not below:
            resets.append({
                "executable": executable,
                "prior_consecutive_below_threshold": prior,
                "batch_rate": rate,
                "new_consecutive_below_threshold": current,
            })
        core_rows[executable] = {
            "status": "observed",
            "batch_unique_ngrams": len(values),
            "new_unique_ngrams": len(new_values),
            "new_unique_rate": rate,
            "below_threshold": below,
            "prior_consecutive_below_threshold": prior,
            "consecutive_below_threshold": current,
            "converged": current >= required,
        }

    batch_executables = set(batch_grouped)
    tail_executables = batch_executables - core
    eligible_by_executable = {
        executable: sum(len(sequence) for sequence in instances.values())
        for executable, instances in batch_grouped.items()
    }
    process_instances_by_executable = {
        executable: len(instances) for executable, instances in batch_grouped.items()
    }
    total_eligible = sum(eligible_by_executable.values())
    tail_eligible = sum(eligible_by_executable.get(executable, 0)
                        for executable in tail_executables)
    total_instances = sum(process_instances_by_executable.values())
    tail_instances = sum(process_instances_by_executable.get(executable, 0)
                         for executable in tail_executables)

    tail_rows: dict[str, Any] = {}
    tail_new_total = 0
    tail_batch_total = 0
    for executable in sorted(tail_executables):
        values = batch_unique.get(executable, set())
        new_values = values - baseline_unique.get(executable, set())
        tail_new_total += len(new_values)
        tail_batch_total += len(values)
        tail_rows[executable] = {
            "first_observed_in_this_postfreeze_batch": executable not in baseline_identities,
            "eligible_syscalls": eligible_by_executable[executable],
            "process_executable_instances": process_instances_by_executable[executable],
            "batch_unique_ngrams": len(values),
            "new_unique_ngrams": len(new_values),
        }

    all_new_total = 0
    all_batch_total = 0
    for executable, values in batch_unique.items():
        all_new_total += len(values - baseline_unique.get(executable, set()))
        all_batch_total += len(values)

    minimum_admitted = int(preregistration["batch_admissibility"][
        "minimum_readiness_admitted_runs_for_convergence_batch"])
    admissible = admitted_runs >= minimum_admitted
    all_core_converged = admissible and all(
        row["converged"] for row in core_rows.values())
    return {
        "schema_version": SCHEMA_VERSION,
        "profile": profile,
        "batch_label": batch_label,
        "preregistration_decision": preregistration["decision"],
        "discovery_artifact_sha256": freeze["discovery_sha256"],
        "ngram_length": n,
        "threshold": threshold,
        "required_consecutive_observed_batches": required,
        "batch_admissibility": {
            "attempted_runs": attempted_runs,
            "readiness_admitted_runs": admitted_runs,
            "minimum_required": minimum_admitted,
            "eligible_for_convergence": admissible,
        },
        "inputs": batch_inputs,
        "discovery_inputs": discovery_inputs,
        "postfreeze_seen_inputs_before_batch": prior_inputs,
        "cumulative_postfreeze_inputs_after_batch": prior_inputs + batch_inputs,
        "novelty_baseline": "discovery_plus_all_prior_registered_postfreeze_batches",
        "core_executables": core_rows,
        "core_counter_resets": resets,
        "all_frozen_core_executables_converged": all_core_converged,
        "open_world_tail": {
            "observed_noncore_executables": tail_rows,
            "new_executable_identities": sorted(
                executable for executable, row in tail_rows.items()
                if row["first_observed_in_this_postfreeze_batch"]),
            "outside_core_eligible_syscalls": tail_eligible,
            "all_eligible_syscalls": total_eligible,
            "outside_core_eligible_syscall_fraction": (
                tail_eligible / total_eligible if total_eligible else None),
            "outside_core_process_executable_instances": tail_instances,
            "all_process_executable_instances": total_instances,
            "outside_core_process_instance_fraction": (
                tail_instances / total_instances if total_instances else None),
            "tail_batch_unique_ngrams": tail_batch_total,
            "tail_new_unique_ngrams": tail_new_total,
            "tail_new_unique_ngram_rate": (
                tail_new_total / tail_batch_total if tail_batch_total else None),
        },
        "aggregate_auxiliary_curve": {
            "role": "secondary_only_not_a_stopping_rule",
            "batch_unique_ngrams": all_batch_total,
            "new_unique_ngrams": all_new_total,
            "new_unique_rate": all_new_total / all_batch_total if all_batch_total else None,
        },
        "metric_note": "Process-instance fractions use executable-qualified run/process identities; mixed executable identities are not pooled.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preregistration", required=True, type=Path)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--discovery-artifact", required=True, type=Path)
    parser.add_argument("--batch-input", action="append", required=True, type=Path)
    parser.add_argument("--batch-label", required=True)
    parser.add_argument("--attempted-runs", required=True, type=int)
    parser.add_argument("--admitted-runs", required=True, type=int)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    preregistration = json.loads(args.preregistration.read_text(encoding="utf-8"))
    discovery = json.loads(args.discovery_artifact.read_text(encoding="utf-8"))
    if args.profile not in preregistration["profile_freeze"]:
        raise ValueError(f"unregistered profile: {args.profile}")
    expected_discovery = preregistration["profile_freeze"][args.profile][
        "discovery_sha256"]
    actual_discovery = _sha256(args.discovery_artifact)
    if actual_discovery != expected_discovery:
        raise ValueError("discovery artifact hash does not match preregistration")
    if len(args.batch_input) != len(set(args.batch_input)):
        raise ValueError("batch inputs must be unique")
    if len(args.batch_input) != args.admitted_runs:
        raise ValueError("one syscall stream is required per readiness-admitted run")
    registered_attempts = int(preregistration["batch_admissibility"][
        "registered_attempts_per_batch"])
    if args.attempted_runs != registered_attempts:
        raise ValueError("attempted run count does not match preregistered batch size")
    previous = (json.loads(args.previous.read_text(encoding="utf-8"))
                if args.previous else None)
    result = measure(
        preregistration=preregistration,
        profile=args.profile,
        discovery_artifact=discovery,
        batch_paths=args.batch_input,
        batch_label=args.batch_label,
        attempted_runs=args.attempted_runs,
        admitted_runs=args.admitted_runs,
        previous=previous,
    )
    result["preregistration_sha256"] = _sha256(args.preregistration)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
