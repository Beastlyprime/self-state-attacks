from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .io import file_record, sha256_file, write_json


@dataclass(frozen=True)
class ToolRun:
    command: list[str]
    exit_status: int
    stdout: Path
    stderr: Path
    started_realtime_ns: int
    stopped_realtime_ns: int


def run_tool(command: list[str], output_dir: Path, name: str, *, cwd: Path | None = None,
             env: dict[str, str] | None = None, timeout: float | None = None) -> ToolRun:
    output_dir.mkdir(parents=True, exist_ok=True)
    stdout_path, stderr_path = output_dir / f"{name}.stdout.log", output_dir / f"{name}.stderr.log"
    started = time.time_ns()
    with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open("w", encoding="utf-8") as stderr:
        try:
            result = subprocess.run(command, cwd=cwd, env=env, text=True, stdout=stdout, stderr=stderr,
                                    check=False, timeout=timeout)
            exit_status = result.returncode
        except FileNotFoundError as exc:
            stderr.write(f"command not found: {exc}\n")
            exit_status = 127
        except subprocess.TimeoutExpired as exc:
            stderr.write(f"command timed out after {exc.timeout} seconds\n")
            exit_status = 124
    return ToolRun(command, exit_status, stdout_path, stderr_path, started, time.time_ns())


def tool_version(command: list[str]) -> str:
    try:
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except OSError as exc:
        return f"unavailable: {exc}"
    return (result.stdout or result.stderr).strip().splitlines()[0] if (result.stdout or result.stderr).strip() else "unknown"


def git_head(repository: Path) -> str | None:
    result = subprocess.run(["git", "-C", str(repository), "rev-parse", "HEAD"], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return result.stdout.strip() if result.returncode == 0 else None


def record_tool_manifest(output_dir: Path, *, tool: str, version: str, status: str,
                         runs: list[ToolRun], inputs: list[Path], configs: list[Path],
                         repository: Path | None = None, expected_commit: str | None = None,
                         extra: dict[str, Any] | None = None) -> dict[str, Any]:
    head = git_head(repository) if repository else None
    if expected_commit and head != expected_commit:
        raise RuntimeError(f"{tool} commit mismatch: expected {expected_commit}, got {head}")
    manifest = {
        "schema_version": "assa.tool_run.v1", "tool": tool, "version": version,
        "repository": str(repository.resolve()) if repository else None, "commit_sha": head,
        "expected_commit_sha": expected_commit, "status": status,
        "runs": [{
            "command": run.command, "exit_status": run.exit_status,
            "started_realtime_ns": run.started_realtime_ns, "stopped_realtime_ns": run.stopped_realtime_ns,
            "stdout": file_record(run.stdout), "stderr": file_record(run.stderr),
        } for run in runs],
        "inputs": [file_record(path) for path in inputs], "configs": [file_record(path) for path in configs],
        "environment": {"python": os.sys.version, "platform": dict(zip(
            ("sysname", "nodename", "release", "version", "machine"), os.uname()))},
        **(extra or {}),
    }
    write_json(output_dir / "tool_manifest.json", manifest)
    return manifest


def _replace_tree(source: Path, destination: Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination, symlinks=True)


def _parse_aide_report(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    patterns = {
        "added": r"Added (?:entries|files):\s*(\d+)",
        "removed": r"Removed (?:entries|files):\s*(\d+)",
        "changed": r"Changed (?:entries|files):\s*(\d+)",
    }
    result = {name: int(match.group(1)) if (match := re.search(pattern, text, re.I)) else None
              for name, pattern in patterns.items()}
    result["no_differences"] = bool(re.search(r"(?:NO differences found|looks okay)", text, re.I))
    result["parse_status"] = (
        "parsed" if result["no_differences"] or any(result[name] is not None for name in patterns) else "unparsed"
    )
    return result


def _parse_falco_json(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            events.append(value)
    return events


def run_aide(snapshot_root: Path, output_dir: Path, *, aide: str = "aide",
             source_repository: Path | None = None,
             expected_commit: str | None = None,
             source_archive: Path | None = None) -> dict[str, Any]:
    snapshots = [snapshot_root / name for name in ("before_a", "after_a", "after_b")]
    if not all(path.is_dir() for path in snapshots):
        raise ValueError("snapshot root must contain before_a, after_a, and after_b")
    work_root = output_dir / "materialized_state"
    database = output_dir / "aide.db"
    database_new = output_dir / "aide.db.new"
    config = output_dir / "aide.conf"
    output_dir.mkdir(parents=True, exist_ok=True)
    escaped_root = str(work_root.resolve()).replace(".", r"\.").replace("+", r"\+")
    config.write_text(
        f"database_in=file:{database.resolve()}\n"
        f"database_out=file:{database_new.resolve()}\n"
        "report_url=stdout\n"
        "Checks = p+i+n+u+g+s+m+c+sha256\n"
        f"{escaped_root} Checks\n",
        encoding="utf-8",
    )
    _replace_tree(snapshots[0], work_root)
    runs = [run_tool([aide, "--config", str(config), "--init"], output_dir, "init")]
    if runs[0].exit_status != 0 or not database_new.is_file():
        status = "failed"
    else:
        database_new.replace(database)
        status = "passed"
        runs.append(run_tool([aide, "--config", str(config), "--check"], output_dir, "before_control"))
        if runs[-1].exit_status != 0:
            status = "failed"
        for name, snapshot in (("after_a", snapshots[1]), ("after_b", snapshots[2])):
            _replace_tree(snapshot, work_root)
            # AIDE returns nonzero when differences are found; execution and a
            # parseable report, not a no-change result, is the adapter criterion.
            runs.append(run_tool([aide, "--config", str(config), "--check"], output_dir, name))
    reports = {run.stdout.stem.replace(".stdout", ""): _parse_aide_report(run.stdout) for run in runs[1:]}
    if status == "passed" and any(report["parse_status"] != "parsed" for report in reports.values()):
        status = "failed"
    write_json(output_dir / "parsed_reports.json", reports)
    binary = Path(aide)
    provenance_inputs = [*snapshots]
    if source_archive is not None:
        provenance_inputs.append(source_archive)
    return record_tool_manifest(
        output_dir, tool="AIDE", version=tool_version([aide, "--version"]), status=status,
        runs=runs, inputs=provenance_inputs, configs=[config], repository=source_repository,
        expected_commit=expected_commit,
        extra={"database": file_record(database) if database.is_file() else None,
               "binary": file_record(binary) if binary.is_file() else None,
               "source_archive": file_record(source_archive) if source_archive is not None else None,
               "parsed_reports": file_record(output_dir / "parsed_reports.json"), "clean_snapshot_contract": True},
    )


def run_falco_replay(capture: Path, rules: Path, output_dir: Path, *, falco: str = "falco",
                     default_rules: bool = False, source_repository: Path | None = None,
                     expected_commit: str | None = None,
                     distribution_archive: Path | None = None,
                     config: Path | None = None) -> dict[str, Any]:
    if not capture.is_file() or capture.stat().st_size == 0:
        raise ValueError("native SCAP is missing or empty")
    command = [falco]
    if config is not None:
        command.extend(["-c", str(config)])
    command.extend(["-o", "engine.kind=replay", "-o", f"engine.replay.capture_file={capture}",
               "-o", "json_output=true"])
    if not default_rules:
        command.extend(["-r", str(rules)])
    run = run_tool(command, output_dir, "replay_default" if default_rules else "replay_self_state")
    status = "passed" if run.exit_status == 0 else "failed"
    events = _parse_falco_json(run.stdout)
    write_json(output_dir / "parsed_events.json", events)
    binary = Path(falco)
    provenance_inputs = [capture]
    if distribution_archive is not None:
        provenance_inputs.append(distribution_archive)
    return record_tool_manifest(
        output_dir, tool="Falco", version=tool_version([falco, "--version"]), status=status,
        runs=[run], inputs=provenance_inputs, configs=([config] if config is not None else []) + ([] if default_rules else [rules]),
        repository=source_repository, expected_commit=expected_commit,
        extra={"input_transport": "native_libscap", "ruleset": "default" if default_rules else "self_state",
               "binary": file_record(binary) if binary.is_file() else None,
               "distribution_archive": file_record(distribution_archive) if distribution_archive is not None else None,
               "parsed_event_count": len(events), "parsed_events": file_record(output_dir / "parsed_events.json")},
    )


def run_stide(repository: Path, train: list[Path], test: list[Path], output_dir: Path,
              *, ngram_length: int = 6, minimum_scoring_sequence_length: int = 106) -> dict[str, Any]:
    output = output_dir / "stide_results.json"
    bridge = Path(__file__).with_name("stide_bridge.py")
    command = [sys.executable, str(bridge), "--repository", str(repository), "--output", str(output),
               "--ngram-length", str(ngram_length), "--minimum-scoring-sequence-length",
               str(minimum_scoring_sequence_length)]
    for path in train:
        command.extend(["--train", str(path)])
    for path in test:
        command.extend(["--test", str(path)])
    run = run_tool(command, output_dir, "stide")
    status = "passed" if run.exit_status == 0 and output.is_file() else "failed"
    detector_statuses: list[str] = []
    result_count = 0
    evaluated_ngrams = 0
    normal_database_ngrams = 0
    scoring_gate_passed = False
    if status == "passed":
        payload = json.loads(output.read_text(encoding="utf-8"))
        results = payload.get("results") or {}
        result_count = len(results)
        detector_statuses = [value["status"] for value in results.values()]
        evaluated_ngrams = sum(int(value.get("evaluated_ngrams") or 0) for value in results.values())
        normal_database_ngrams = sum(int(value.get("normal_database_ngrams") or 0) for value in results.values())
        scoring_gate_passed = bool(results) and payload.get("scoring_gate_passed") is True and all(
            value.get("scoring_gate_passed") is True for value in results.values()
        )
        if not scoring_gate_passed or any(value != "passed" for value in detector_statuses):
            status = "data_insufficient"
    return record_tool_manifest(
        output_dir, tool="LID-DS STIDE", version="587d15870843961acb78fbb4b8fcd0ede28eabcc",
        status=status, runs=[run], inputs=[*train, *test], configs=[], repository=repository,
        expected_commit="587d15870843961acb78fbb4b8fcd0ede28eabcc",
        extra={"ngram_length": ngram_length, "thread_aware": False,
               "minimum_scoring_sequence_length": minimum_scoring_sequence_length,
               "result": file_record(output) if output.is_file() else None,
               "result_count": result_count, "executable_statuses": detector_statuses,
               "normal_database_ngrams": normal_database_ngrams,
               "evaluated_ngrams": evaluated_ngrams,
               "scoring_gate_passed": scoring_gate_passed},
    )
