#!/usr/bin/env python3
"""Fail closed unless four retained raw streams yield binding-complete events."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[3]
AGENT_ROOT = PROJECT_ROOT / "experiments" / "agent"
if str(AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(AGENT_ROOT))

from openclaw_core.trace.schema import (  # noqa: E402
    EBPF_WRITE_BUFFER_PREFIX_BYTES,
    REQUIRED_SOURCES,
    validate_raw_trace_bundle,
)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8", errors="strict").splitlines(), start=1
    ):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError("%s:%d is not an event object" % (path, line_number))
        rows.append(value)
    return rows


def _validate_event(row: dict[str, Any], *, source: str) -> None:
    if row.get("source") != source:
        raise ValueError("normalized event source mismatch")
    for field in ("timestamp_realtime_ns", "timestamp_monotonic_ns"):
        if not isinstance(row.get(field), int):
            raise ValueError("%s event lacks %s" % (source, field))
    process = row.get("process")
    if isinstance(process, dict) and process.get("pid") is not None:
        if not isinstance(process.get("process_start_time_ticks"), int):
            raise ValueError("%s pid-bearing event lacks process start time" % source)
    if source == "ebpf" and row.get("event") in {"write", "writev", "pwrite64"}:
        mutation = row.get("mutation") or {}
        for image in ("preimage", "postimage"):
            snapshot = mutation.get(image) or {}
            if snapshot.get("complete") is not True or not isinstance(snapshot.get("data"), str):
                raise ValueError("eBPF write lacks complete %s" % image)
        write_buffer = mutation.get("write_buffer") or {}
        if write_buffer.get("buffer_prefix_capacity_bytes") != EBPF_WRITE_BUFFER_PREFIX_BYTES:
            raise ValueError("eBPF write-buffer capacity differs from frozen schema")
    if row.get("carrier_read") is True:
        read = row.get("read_observation") or {}
        for field in ("fd", "offset", "count", "buffer_prefix", "buffer_prefix_capacity_bytes"):
            if field not in read:
                raise ValueError("carrier read lacks %s" % field)
        join = row.get("ingestion_join_key") or {}
        for field in (
            "run_id",
            "boot_id",
            "pid",
            "process_start_time_ticks",
            "fd",
            "path",
            "inode",
            "timestamp_monotonic_ns",
        ):
            if join.get(field) is None:
                raise ValueError("carrier read join key lacks %s" % field)


def finalize(spec_path: Path, output_path: Path) -> dict[str, Any]:
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    bundle = {
        "schema_version": "assa.four_source_bundle.v1",
        "run_id": spec["run_id"],
        "run_time_anchor": spec["run_time_anchor"],
        "sources": {},
        "negative_outcomes_retained": spec.get("negative_outcomes_retained", []),
        "fixture_http_access_log": spec.get("fixture_http_access_log"),
    }
    for source in REQUIRED_SOURCES:
        source_spec = spec["sources"][source]
        raw = Path(source_spec["raw_stream_path"]).resolve()
        normalized = Path(source_spec["normalized_stream_path"]).resolve()
        health_path = Path(source_spec["health_path"]).resolve()
        if not raw.is_file() or not normalized.is_file() or not health_path.is_file():
            raise FileNotFoundError("%s source artifact is missing" % source)
        events = _read_jsonl(normalized)
        for event in events:
            _validate_event(event, source=source)
        bundle["sources"][source] = {
            "version": source_spec["version"],
            "raw_stream_retained": True,
            "raw_stream_path": str(raw),
            "normalized_stream_path": str(normalized),
            "events_validated": len(events),
            "health": json.loads(health_path.read_text(encoding="utf-8")),
        }
    validate_raw_trace_bundle(bundle)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return bundle


def main() -> int:
    parser = argparse.ArgumentParser(description="Finalize one binding four-source trace")
    parser.add_argument("--spec", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    finalize(Path(args.spec), Path(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
