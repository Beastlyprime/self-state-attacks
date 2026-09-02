"""Extract an enriched syscall stream from a SCAP capture using libsinsp.

libsinsp maintains its own thread and fd tables, so it can name the file behind
a ``write(fd, ...)`` that the syscall itself never names. This module takes that
resolution from a pinned Falco build rather than reimplementing it: Falco
statically links libsinsp, and the binary is already pinned in the tool
manifest, so no new artifact is introduced.

Falco is used here as an extractor, not as a detector. The rule matches on scope
alone and every field of interest is placed in the output template; no detection
semantics are involved.

Rationale and the alternatives considered are in
``experiments/code/measurement/LIBSINSP_REPLACEMENT_EVALUATION.md``.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
from pathlib import Path
from typing import Any, Iterator

from .io import file_record, write_json


SCHEMA_VERSION = "assa.libsinsp_events.v1"

# Ordered so the emitted template is stable and diffable.
EXTRACT_FIELDS: tuple[str, ...] = (
    "evt.num", "evt.rawtime", "evt.type", "evt.dir", "evt.res",
    "proc.pid", "thread.tid", "proc.ppid", "proc.name", "proc.exepath",
    "proc.pid.ts", "proc.ppid.ts", "proc.exe_ino", "proc.vpid",
    "user.uid",
    "fd.num", "fd.type", "fd.name",
    "fd.ino", "fd.dev.major", "fd.dev.minor",
)

RULE_NAME = "ASSA libsinsp extraction"


def build_rule(*, uid: int | None) -> str:
    """A scope-only rule whose output template carries every extracted field."""
    condition = f"user.uid = {uid}" if uid is not None else "evt.num >= 0"
    template = " ".join(f"{name}=%{name}" for name in EXTRACT_FIELDS)
    return (
        "- required_engine_version: 47\n"
        "\n"
        f"- rule: {RULE_NAME}\n"
        "  desc: extraction only - carries identity fields, asserts nothing\n"
        f"  condition: {condition}\n"
        f'  output: "{template}"\n'
        "  priority: NOTICE\n"
        "  tags: [assa, extraction]\n"
    )


def _int_or_none(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _str_or_none(value: Any) -> str | None:
    if value is None or value == "" or value == "<NA>":
        return None
    return str(value)


def to_record(fields: dict[str, Any], *, run_id: str) -> dict[str, Any]:
    """Map one Falco output_fields object onto the extraction schema.

    Absent values stay absent. Nothing is inferred, defaulted or back-filled --
    an unresolved fd must remain visibly unresolved so that coverage reporting
    counts it.
    """
    evt_num = _int_or_none(fields.get("evt.num"))
    ino = _int_or_none(fields.get("fd.ino"))
    major = _int_or_none(fields.get("fd.dev.major"))
    minor = _int_or_none(fields.get("fd.dev.minor"))
    path = _str_or_none(fields.get("fd.name"))

    file_block: dict[str, Any] | None = None
    if path is not None or ino is not None:
        file_block = {
            "path": path,
            "inode": ino,
            "dev_major": major,
            "dev_minor": minor,
        }

    fd_num = _int_or_none(fields.get("fd.num"))
    fd_block: dict[str, Any] | None = None
    if fd_num is not None or fields.get("fd.type"):
        fd_block = {"num": fd_num, "type": _str_or_none(fields.get("fd.type"))}

    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "event_id": f"{run_id}:libsinsp:{evt_num}" if evt_num is not None else None,
        "source": "libsinsp",
        "order": {
            "event_number": evt_num,
            "timestamp_realtime_ns": _int_or_none(fields.get("evt.rawtime")),
        },
        "syscall": {
            "name": _str_or_none(fields.get("evt.type")),
            "direction": _str_or_none(fields.get("evt.dir")),
            "result": _str_or_none(fields.get("evt.res")),
        },
        "process": {
            "pid": _int_or_none(fields.get("proc.pid")),
            "tid": _int_or_none(fields.get("thread.tid")),
            "ppid": _int_or_none(fields.get("proc.ppid")),
            "vpid": _int_or_none(fields.get("proc.vpid")),
            "comm": _str_or_none(fields.get("proc.name")),
            "exe": _str_or_none(fields.get("proc.exepath")),
            "exe_inode": _int_or_none(fields.get("proc.exe_ino")),
            "uid": _int_or_none(fields.get("user.uid")),
            # Absolute nanosecond process start, reported by libsinsp. This
            # replaces the tick-based start estimate, which required deriving
            # USER_HZ -- a derivation that turned out to be a tautology.
            "start_realtime_ns": _int_or_none(fields.get("proc.pid.ts")),
            "parent_start_realtime_ns": _int_or_none(fields.get("proc.ppid.ts")),
        },
        "fd": fd_block,
        "file": file_block,
    }


def parse_stream(lines: Iterator[str], *, run_id: str) -> Iterator[dict[str, Any]]:
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if payload.get("rule") != RULE_NAME:
            continue
        fields = payload.get("output_fields")
        if not isinstance(fields, dict):
            continue
        yield to_record(fields, run_id=run_id)


def extract(
    capture: Path,
    output_dir: Path,
    *,
    falco_command: list[str],
    config: Path,
    run_id: str,
    uid: int | None = 2001,
) -> dict[str, Any]:
    """Replay ``capture`` through libsinsp and write the extracted stream.

    Fails closed: a non-zero Falco exit, a capture Falco never opened, or any
    reported event drop invalidates the extraction rather than yielding a
    partial stream that later stages would treat as complete.
    """
    if not capture.is_file() or capture.stat().st_size == 0:
        raise ValueError(f"capture missing or empty: {capture}")
    output_dir.mkdir(parents=True, exist_ok=True)

    rules_path = output_dir / "extraction_rules.yaml"
    rules_path.write_text(build_rule(uid=uid), encoding="utf-8")

    command = [
        *falco_command, "-c", str(config), "-r", str(rules_path),
        "-o", "engine.kind=replay",
        "-o", f"engine.replay.capture_file={capture}",
        "-o", "json_output=true",
        "-o", "syslog_output.enabled=false",
    ]
    completed = subprocess.run(command, capture_output=True, text=True)
    (output_dir / "extract.stderr.log").write_text(completed.stderr, encoding="utf-8")

    events_path = output_dir / "libsinsp_events.jsonl"
    count = 0
    with events_path.open("w", encoding="utf-8") as handle:
        for record in parse_stream(iter(completed.stdout.splitlines()), run_id=run_id):
            handle.write(json.dumps(record, sort_keys=True) + "\n")
            count += 1

    engine_opened = "Replaying events from the capture file:" in completed.stderr
    zero_drops = "event drop detected: 0 occurrences" in completed.stderr
    valid = completed.returncode == 0 and engine_opened and zero_drops and count > 0

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "status": "passed" if valid else "failed",
        "valid": valid,
        "run_id": run_id,
        "uid_scope": uid,
        "exit_status": completed.returncode,
        "engine_opened": engine_opened,
        "zero_drop_evidence": zero_drops,
        "event_count": count,
        "command": command,
        "extract_fields": list(EXTRACT_FIELDS),
        "capture": file_record(capture),
        "rules": file_record(rules_path),
        "config": file_record(config),
        "events": file_record(events_path),
    }
    write_json(output_dir / "extraction_manifest.json", manifest)
    return manifest


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--capture", type=Path, required=True)
    ap.add_argument("--output-dir", type=Path, required=True)
    ap.add_argument("--config", type=Path, required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--uid", type=int, default=2001)
    ap.add_argument("--falco", required=True,
                    help="Falco invocation as one shell-quoted string; may include "
                         "a qemu prefix, e.g. 'qemu-x86_64-static -L /prefix /path/falco'")
    args = ap.parse_args()
    manifest = extract(args.capture, args.output_dir, falco_command=shlex.split(args.falco),
                       config=args.config, run_id=args.run_id, uid=args.uid)
    print(json.dumps({k: manifest[k] for k in
                      ("status", "event_count", "exit_status", "engine_opened",
                       "zero_drop_evidence")}, indent=2))
    return 0 if manifest["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
