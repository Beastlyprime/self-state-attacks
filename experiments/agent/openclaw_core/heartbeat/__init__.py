"""Heartbeat layer — SPEC §8.

Exports:
    scheduler: phase / next-due math
    runner: one-shot run_one_heartbeat + background HeartbeatLoop
"""

from __future__ import annotations

from .runner import (
    DEFAULT_HEARTBEAT_PROMPT,
    HeartbeatLoop,
    is_heartbeat_content_effectively_empty,
    run_one_heartbeat,
)
from .scheduler import (
    DEFAULT_HEARTBEAT_INTERVAL_MS,
    HeartbeatScheduleState,
    compute_next_heartbeat_phase_due_ms,
    is_within_active_hours,
    resolve_heartbeat_phase_ms,
    resolve_next_heartbeat_due_ms,
)


__all__ = [
    "DEFAULT_HEARTBEAT_INTERVAL_MS",
    "DEFAULT_HEARTBEAT_PROMPT",
    "HeartbeatLoop",
    "HeartbeatScheduleState",
    "compute_next_heartbeat_phase_due_ms",
    "is_heartbeat_content_effectively_empty",
    "is_within_active_hours",
    "resolve_heartbeat_phase_ms",
    "resolve_next_heartbeat_due_ms",
    "run_one_heartbeat",
]
