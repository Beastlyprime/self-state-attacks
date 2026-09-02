"""Heartbeat scheduling math — SPEC §8.1.

Port of `src/infra/heartbeat-schedule.ts`:

    resolveHeartbeatPhaseMs({ schedulerSeed, agentId, intervalMs })
    computeNextHeartbeatPhaseDueMs({ nowMs, intervalMs, phaseMs })
    resolveNextHeartbeatDueMs({ nowMs, intervalMs, phaseMs, prev? })

Rationale:
- The phase offset is seeded from SHA-256(schedulerSeed + agentId) so that
  multiple machines / agents don't fire heartbeats at the exact same wall
  clock minute. Two runs with identical (seed, agentId) produce identical
  phase — which matters for reproducible experiment traces.
- computeNextHeartbeatPhaseDueMs wraps the phase calculation around the
  interval. The important invariant: the returned value is strictly >
  nowMs. If now falls exactly on phase, we return now + interval (not now)
  so the caller can't accidentally fire-immediately.

Default interval: 30 minutes. Active-hour gating (§8.1) is left to the
caller — see `is_within_active_hours`.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional


DEFAULT_HEARTBEAT_INTERVAL_MS = 30 * 60 * 1000  # 30 minutes


def _normalize_modulo(value: int, divisor: int) -> int:
    """TS-compat modulo: always returns a non-negative result."""
    return ((value % divisor) + divisor) % divisor


def resolve_heartbeat_phase_ms(
    *,
    scheduler_seed: str,
    agent_id: str,
    interval_ms: int = DEFAULT_HEARTBEAT_INTERVAL_MS,
) -> int:
    """Derive a deterministic phase offset within the interval.

    The phase is the first 32-bit big-endian chunk of
    SHA-256(f"{seed}:{agent_id}") modulo interval_ms. Identical inputs
    always produce identical phase, so experiments can be replayed.
    """
    interval = max(1, int(interval_ms))
    digest = hashlib.sha256(f"{scheduler_seed}:{agent_id}".encode("utf-8")).digest()
    first_u32 = int.from_bytes(digest[:4], byteorder="big", signed=False)
    return first_u32 % interval


def compute_next_heartbeat_phase_due_ms(
    *,
    now_ms: int,
    interval_ms: int,
    phase_ms: int,
) -> int:
    """Next fire time strictly greater than now_ms.

    If now falls exactly on the phase boundary we return now + interval so
    we never fire twice at the same instant.
    """
    interval = max(1, int(interval_ms))
    now = int(now_ms)
    phase = _normalize_modulo(int(phase_ms), interval)
    cycle_position = _normalize_modulo(now, interval)
    delta = _normalize_modulo(phase - cycle_position, interval)
    if delta == 0:
        delta = interval
    return now + delta


@dataclass
class HeartbeatScheduleState:
    """Persistent scheduling hint.

    Stored in the session state (§4) so a process restart keeps the same
    cadence. If interval or phase changes between calls, we recompute.

    Attributes:
        interval_ms: last-used interval.
        phase_ms: last-used phase.
        next_due_ms: last-computed fire time (epoch ms).
    """

    interval_ms: int
    phase_ms: int
    next_due_ms: int


def resolve_next_heartbeat_due_ms(
    *,
    now_ms: int,
    interval_ms: int,
    phase_ms: int,
    prev: Optional[HeartbeatScheduleState] = None,
) -> int:
    """Return the next fire time, reusing prev if still valid.

    prev is honored only if the (interval, phase) pair is unchanged AND
    prev.next_due_ms is still in the future. Otherwise we recompute.
    """
    interval = max(1, int(interval_ms))
    phase = _normalize_modulo(int(phase_ms), interval)

    if (
        prev is not None
        and prev.interval_ms == interval
        and prev.phase_ms == phase
        and prev.next_due_ms > now_ms
    ):
        return prev.next_due_ms

    return compute_next_heartbeat_phase_due_ms(
        now_ms=now_ms, interval_ms=interval, phase_ms=phase
    )


def is_within_active_hours(
    *,
    now_ms: int,
    start_hour: Optional[int] = None,
    end_hour: Optional[int] = None,
    tz_offset_minutes: int = 0,
) -> bool:
    """Return True if now falls inside [start_hour, end_hour) local time.

    If either bound is None, the window is considered always-open.

    Args:
        now_ms: epoch milliseconds.
        start_hour: inclusive start hour (0-23).
        end_hour: exclusive end hour (1-24). end_hour > start_hour required
            for a normal window; end_hour <= start_hour means wrap-around
            (e.g. 22 -> 6 is evening/overnight).
        tz_offset_minutes: offset in minutes from UTC (+540 for JST, -480
            for PST). Caller supplies — we don't read the host tz.
    """
    if start_hour is None or end_hour is None:
        return True
    if start_hour == end_hour:
        # Degenerate: window covers everything.
        return True
    local_minutes = ((now_ms // 1000) // 60) + tz_offset_minutes
    local_hour = (local_minutes // 60) % 24
    if start_hour < end_hour:
        return start_hour <= local_hour < end_hour
    # Wrap-around window (e.g. 22..6).
    return local_hour >= start_hour or local_hour < end_hour
