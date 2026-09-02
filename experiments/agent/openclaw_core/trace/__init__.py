"""Trace capture layer — pairs with openclaw_core.session for per-session
inotify JSONL traces.

Public API:
    InotifyWatch, InotifyEvent — low-level ctypes wrapper
    TraceCollector — background thread, one-session JSONL writer
    is_supported() — False on non-Linux
"""

from __future__ import annotations

from .collector import TraceCollector
from .inotify import (
    DEFAULT_MASK,
    InotifyEvent,
    InotifyWatch,
    is_supported,
    mask_to_names,
    primary_event_name,
    recursive_watch_paths,
)
from .schema import (
    EBPF_WRITE_BUFFER_PREFIX_BYTES,
    READ_BUFFER_PREFIX_BYTES,
    boot_time_anchor,
    ebpf_buffer_capture,
    event_envelope,
    full_byte_snapshot,
    ingestion_read_capture,
    process_identity,
    validate_raw_trace_bundle,
    write_mutation_capture,
)


__all__ = [
    "DEFAULT_MASK",
    "InotifyEvent",
    "InotifyWatch",
    "TraceCollector",
    "is_supported",
    "mask_to_names",
    "primary_event_name",
    "recursive_watch_paths",
    "EBPF_WRITE_BUFFER_PREFIX_BYTES",
    "READ_BUFFER_PREFIX_BYTES",
    "boot_time_anchor",
    "ebpf_buffer_capture",
    "event_envelope",
    "full_byte_snapshot",
    "ingestion_read_capture",
    "process_identity",
    "validate_raw_trace_bundle",
    "write_mutation_capture",
]
