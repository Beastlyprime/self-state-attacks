"""fanotify is an event-bound read, not a syscall-boundary capture and not a
post-hoc snapshot. These tests pin the binding rules and the evidence class."""
from __future__ import annotations

import json
from pathlib import Path

from measurement.stage_g_harness.normalize import (
    Normalizer,
    _decode_fanotify_mask,
)


def _row(*, pid: int, path: str, ts: int, start_evidence=None) -> dict:
    return {
        "syscall": {"name": "write", "number": 1, "arguments": {}, "return_value": 7},
        "process": {
            "boot_id": "boot", "pid": pid, "tid": pid, "ppid": 1,
            "process_start_time_ticks": None if start_evidence is None else 42,
            "process_start_evidence": start_evidence,
            "identity_status": "identity_incomplete" if start_evidence is None else "complete",
            "identity_key": f"boot:{pid}:{start_evidence or 'unknown'}:0",
            "exec_epoch": 0,
        },
        "file": {"raw_path": path, "resolved_path": path},
        "order": {"timestamp_realtime_ns": ts},
        "evidence": [],
        "completeness": {"process_identity": "identity_incomplete"},
        "scope": {},
    }


def _event(*, pid: int, path: str, ts: int, mask: int = 0x2A, ticks=None, content=b"x") -> dict:
    event = {"pid": pid, "path": path, "mask": mask, "timestamp_realtime_ns": ts,
             "pre_response_snapshot": {"bytes": len(content), "complete": True,
                                       "sha256": "a" * 64, "encoding": "base64",
                                       "data": "eA=="}}
    if ticks is not None:
        event["process"] = {"process_start_time_ticks": ticks}
    return event


def _write(tmp_path: Path, events: list[dict]) -> Path:
    p = tmp_path / "fanotify.jsonl"
    p.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    return p


def test_binding_requires_matching_pid(tmp_path: Path) -> None:
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    path = _write(tmp_path, [_event(pid=999, path="/w/openclaw.json", ts=1_000)])
    accounting = Normalizer._correlate_fanotify(rows, path)
    assert accounting["matched_events"] == 0
    assert "fanotify" not in (rows[0].get("correlation") or {})


def test_binding_requires_byte_exact_path(tmp_path: Path) -> None:
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    path = _write(tmp_path, [_event(pid=100, path="/w/other.json", ts=1_000)])
    assert Normalizer._correlate_fanotify(rows, path)["matched_events"] == 0


def test_time_alone_does_not_bind(tmp_path: Path) -> None:
    """Same instant, different pid and path: proximity must not be sufficient."""
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    path = _write(tmp_path, [_event(pid=101, path="/w/elsewhere.json", ts=1_000)])
    assert Normalizer._correlate_fanotify(rows, path)["matched_events"] == 0


def test_outside_time_window_does_not_bind(tmp_path: Path) -> None:
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    path = _write(tmp_path, [_event(pid=100, path="/w/openclaw.json", ts=1_000 + 200_000_000)])
    assert Normalizer._correlate_fanotify(rows, path)["matched_events"] == 0


def test_matched_event_attaches_event_bound_read_evidence(tmp_path: Path) -> None:
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    path = _write(tmp_path, [_event(pid=100, path="/w/openclaw.json", ts=1_000)])
    accounting = Normalizer._correlate_fanotify(rows, path)
    assert accounting["matched_events"] == 1
    evidence = [e for e in rows[0]["evidence"] if e["source"] == "fanotify"]
    assert len(evidence) == 1
    assert evidence[0]["evidence_class"] == "event_bound_read"
    assert evidence[0]["correlation"] == "pid_byte_exact_path_unique_best_rank_within_100ms"


def test_content_is_fingerprint_only_and_never_inlines_bytes(tmp_path: Path) -> None:
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    path = _write(tmp_path, [_event(pid=100, path="/w/openclaw.json", ts=1_000)])
    Normalizer._correlate_fanotify(rows, path)
    content = rows[0]["correlation"]["fanotify"]["content"]
    assert content["sha256"] == "a" * 64 and content["bytes"] == 1
    assert "data" not in content
    assert "eA==" not in json.dumps(rows[0])
    assert content["content_location"]["field"] == "pre_response_snapshot.data"


def test_modify_content_is_labelled_after_the_syscall(tmp_path: Path) -> None:
    """MODIFY is non-blocking: the write already happened, so the snapshot holds
    the state AFTER the change. Calling that a pre-image inverts its meaning."""
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    path = _write(tmp_path, [_event(pid=100, path="/w/openclaw.json", ts=1_000, mask=0x2)])
    accounting = Normalizer._correlate_fanotify(rows, path)
    assert rows[0]["correlation"]["fanotify"]["content"]["relation_to_syscall"] == "after_syscall"
    assert accounting["postimages_linked"] == 1 and accounting["preimages_linked"] == 0


def test_permission_event_content_is_labelled_before_the_syscall(tmp_path: Path) -> None:
    """OPEN_PERM blocks the syscall, so the snapshot genuinely precedes it."""
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    rows[0]["syscall"]["name"] = "openat"
    path = _write(tmp_path, [_event(pid=100, path="/w/openclaw.json", ts=1_000, mask=0x10000)])
    accounting = Normalizer._correlate_fanotify(rows, path)
    assert rows[0]["correlation"]["fanotify"]["content"]["relation_to_syscall"] == "before_syscall"
    assert accounting["preimages_linked"] == 1 and accounting["postimages_linked"] == 0


def test_cwd_joined_relative_raw_path_is_not_an_alias(tmp_path: Path) -> None:
    """audit rows routinely carry a relative raw_path beside an absolute resolved
    one. Only one absolute candidate exists, so there is nothing to disambiguate
    and the row must still bind."""
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    rows[0]["file"]["raw_path"] = "openclaw.json"
    path = _write(tmp_path, [_event(pid=100, path="/w/openclaw.json", ts=1_000)])
    accounting = Normalizer._correlate_fanotify(rows, path)
    assert accounting["matched_events"] == 1
    assert accounting["alias_ambiguous_rows_skipped"] == 0


def test_rows_predating_the_observed_incarnation_are_not_stamped(tmp_path: Path) -> None:
    """A pid seen once says nothing about rows that precede that incarnation.
    Neither the conflict nor the disagreement guard can see this case."""
    early = _row(pid=100, path="/w/openclaw.json", ts=1)
    late = _row(pid=100, path="/w/openclaw.json", ts=9_000_000_000)
    rows = [early, late]
    # boot_realtime = realtime - monotonic = 0, so with USER_HZ=100 the derived
    # start is 777/100 s = 7.77e9 ns: after the early row, before the late one.
    event = _event(pid=100, path="/w/openclaw.json", ts=9_000_000_000, ticks=777)
    event["timestamp_monotonic_ns"] = 9_000_000_000
    path = _write(tmp_path, [event])
    accounting = Normalizer._correlate_fanotify(rows, path)
    assert accounting["rows_predating_process_start"] == 1
    assert early["process"]["process_start_evidence"] is None
    assert accounting["passed"] is False


def test_write_does_not_claim_a_close_write_event(tmp_path: Path) -> None:
    """write(2) never generates FAN_CLOSE_WRITE; closing the last writable fd does."""
    write_row = _row(pid=100, path="/w/openclaw.json", ts=1_000)
    close_row = _row(pid=100, path="/w/openclaw.json", ts=1_200)
    close_row["syscall"]["name"] = "close"
    rows = [write_row, close_row]
    path = _write(tmp_path, [_event(pid=100, path="/w/openclaw.json", ts=1_050, mask=0x8)])
    Normalizer._correlate_fanotify(rows, path)
    assert (write_row.get("correlation") or {}).get("fanotify") is None
    assert close_row["correlation"]["fanotify"]["raw_event_index"] == 0


def test_rank_beats_proximity_when_they_disagree(tmp_path: Path) -> None:
    """The earlier test let nearest-time alone give the right answer, so it never
    exercised ranking. Here proximity favours the openat and only rank is decisive."""
    open_row = _row(pid=100, path="/w/openclaw.json", ts=0)
    open_row["syscall"]["name"] = "openat"
    write_row = _row(pid=100, path="/w/openclaw.json", ts=20_000_000)
    rows = [open_row, write_row]
    path = _write(tmp_path, [
        _event(pid=100, path="/w/openclaw.json", ts=5_000_000, mask=0x2A),
        _event(pid=100, path="/w/openclaw.json", ts=30_000_000, mask=0x20),
    ])
    accounting = Normalizer._correlate_fanotify(rows, path)
    assert write_row["correlation"]["fanotify"]["raw_event_index"] == 0
    assert (open_row.get("correlation") or {}).get("fanotify") is None
    assert accounting["ambiguous_rows_unbound"] == 1


def test_impossible_mask_families_are_not_claimed(tmp_path: Path) -> None:
    """ATTRIB/CREATE/DELETE/MOVE need FAN_REPORT_FID, which fanotify_init rejects
    alongside FAN_CLASS_CONTENT. Listing them would imply coverage we cannot have."""
    for mask in (0x4, 0x100, 0x200, 0x40, 0x80):
        rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
        rows[0]["syscall"]["name"] = "unlink"
        path = _write(tmp_path, [_event(pid=100, path="/w/openclaw.json", ts=1_000, mask=mask)])
        assert Normalizer._correlate_fanotify(rows, path)["matched_events"] == 0


def test_process_start_ticks_fill_only_when_unknown(tmp_path: Path) -> None:
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    path = _write(tmp_path, [_event(pid=100, path="/w/openclaw.json", ts=1_000, ticks=777)])
    accounting = Normalizer._correlate_fanotify(rows, path)
    assert accounting["process_start_ticks_filled"] == 1
    assert rows[0]["process"]["process_start_time_ticks"] == 777
    assert rows[0]["process"]["identity_status"] == "complete"


def test_existing_start_evidence_is_not_overwritten(tmp_path: Path) -> None:
    """eBPF sched_fork evidence must win; fanotify only fills genuine gaps."""
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000,
                 start_evidence="ebpf_sched_fork:5")]
    path = _write(tmp_path, [_event(pid=100, path="/w/openclaw.json", ts=1_000, ticks=777)])
    accounting = Normalizer._correlate_fanotify(rows, path)
    assert accounting["process_start_ticks_filled"] == 0
    assert rows[0]["process"]["process_start_evidence"] == "ebpf_sched_fork:5"
    assert rows[0]["process"]["process_start_time_ticks"] == 42


def test_unmatched_events_are_accounted_not_a_conservation_failure(tmp_path: Path) -> None:
    """fanotify watches paths, so it sees files no audit rule covers."""
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    path = _write(tmp_path, [
        _event(pid=100, path="/w/openclaw.json", ts=1_000),
        _event(pid=555, path="/elsewhere/unrelated.txt", ts=2_000),
    ])
    accounting = Normalizer._correlate_fanotify(rows, path)
    assert accounting["matched_events"] == 1
    assert accounting["unmatched_events"] == 1
    assert accounting["accounted_events"] == accounting["raw_events"] == 2
    assert accounting["passed"] is True


def test_events_without_pid_or_path_are_counted_not_dropped(tmp_path: Path) -> None:
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    path = _write(tmp_path, [{"mask": 2, "timestamp_realtime_ns": 1_000}])
    accounting = Normalizer._correlate_fanotify(rows, path)
    assert accounting["unusable_events_missing_pid_or_path"] == 1
    assert accounting["accounted_events"] == 1
    # Out of scope, not malformed: fanotify legitimately reports records for
    # paths outside our namespace. Visible in the counter, not a run failure.
    assert accounting["passed"] is True


def test_two_rows_contending_for_one_event_bind_nothing(tmp_path: Path) -> None:
    """Time cannot arbitrate: this corpus has 21.6% of adjacent rows with their
    timestamp decreasing as the audit serial increases, worst inversion 94.8 ms
    against a 100 ms window. Picking the nearer row would resolve milliseconds
    inside data whose own ordering is wrong by tens of them."""
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000),
            _row(pid=100, path="/w/openclaw.json", ts=1_010)]
    path = _write(tmp_path, [_event(pid=100, path="/w/openclaw.json", ts=1_000)])
    accounting = Normalizer._correlate_fanotify(rows, path)
    assert accounting["matched_events"] == 0
    assert accounting["rows_unbound_event_contested"] == 2
    assert all((r.get("correlation") or {}).get("fanotify") is None for r in rows)


def test_mask_decoder_surfaces_unknown_bits(tmp_path: Path) -> None:
    assert _decode_fanotify_mask(0x2A) == ["MODIFY", "CLOSE_WRITE", "OPEN"]
    assert _decode_fanotify_mask(0x4) == ["ATTRIB"]
    assert any(n.startswith("unknown_bits:") for n in _decode_fanotify_mask(0x80000000))


def test_identity_key_is_stable_across_rows_of_one_process(tmp_path: Path) -> None:
    """The bug this pins: keying evidence on the event index minted one identity
    per row and fragmented the process graph while claiming completeness."""
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000),
            _row(pid=100, path="/w/openclaw.json", ts=1_010),
            _row(pid=100, path="/w/openclaw.json", ts=1_020)]
    path = _write(tmp_path, [
        _event(pid=100, path="/w/openclaw.json", ts=1_000, ticks=777),
        _event(pid=100, path="/w/openclaw.json", ts=1_010, ticks=777),
        _event(pid=100, path="/w/openclaw.json", ts=1_020, ticks=777),
    ])
    Normalizer._correlate_fanotify(rows, path)
    keys = {r["process"]["identity_key"] for r in rows}
    assert len(keys) == 1, f"process identity fragmented into {len(keys)} keys"
    assert {r["process"]["process_start_evidence"] for r in rows} == {
        "fanotify_process_start_ticks:777"}


def test_conflicting_start_ticks_for_one_pid_fail_closed(tmp_path: Path) -> None:
    """Two different start times for one pid is pid reuse, not a value to pick from."""
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    path = _write(tmp_path, [
        _event(pid=100, path="/w/openclaw.json", ts=1_000, ticks=777),
        _event(pid=100, path="/w/openclaw.json", ts=1_010, ticks=888),
    ])
    accounting = Normalizer._correlate_fanotify(rows, path)
    assert accounting["process_start_ticks_conflicting_pids"] == ["100"]
    assert accounting["process_start_ticks_filled"] == 0
    assert accounting["passed"] is False
    assert rows[0]["process"]["process_start_evidence"] is None


def test_dotdot_path_does_not_collide(tmp_path: Path) -> None:
    """Lexical `..` folding is unsound across symlinked directories."""
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    path = _write(tmp_path, [_event(pid=100, path="/w/sub/../openclaw.json", ts=1_000)])
    assert Normalizer._correlate_fanotify(rows, path)["matched_events"] == 0


def test_double_slash_path_does_not_collide(tmp_path: Path) -> None:
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    path = _write(tmp_path, [_event(pid=100, path="/w//openclaw.json", ts=1_000)])
    assert Normalizer._correlate_fanotify(rows, path)["matched_events"] == 0


def test_mask_incompatible_with_syscall_does_not_bind(tmp_path: Path) -> None:
    """An OPEN-family event must not staple a content pre-image onto a close row."""
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    rows[0]["syscall"]["name"] = "close"
    path = _write(tmp_path, [_event(pid=100, path="/w/openclaw.json", ts=1_000, mask=0x10000)])
    accounting = Normalizer._correlate_fanotify(rows, path)
    assert accounting["matched_events"] == 0
    assert accounting["mask_incompatible_events"] == 1


def test_stat_row_never_receives_a_content_preimage(tmp_path: Path) -> None:
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    rows[0]["syscall"]["name"] = "newfstatat"
    path = _write(tmp_path, [_event(pid=100, path="/w/openclaw.json", ts=1_000, mask=0x1)])
    Normalizer._correlate_fanotify(rows, path)
    assert (rows[0].get("correlation") or {}).get("fanotify") is None


def test_queue_overflow_fails_closed(tmp_path: Path) -> None:
    """FAN_Q_OVERFLOW is the kernel stating the evidence stream is incomplete."""
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    path = _write(tmp_path, [
        _event(pid=100, path="/w/openclaw.json", ts=1_000),
        {"mask": 0x4000, "pid": 100, "path": "/w/openclaw.json",
         "timestamp_realtime_ns": 1_001},
    ])
    accounting = Normalizer._correlate_fanotify(rows, path)
    assert accounting["queue_overflow_events"] == 1
    assert accounting["passed"] is False


def test_missing_timestamp_fails_closed(tmp_path: Path) -> None:
    """A record we cannot place in time is malformed, unlike one that is merely
    outside our path scope. Binding needs a timestamp as much as a pid."""
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    path = _write(tmp_path, [{"mask": 2, "pid": 100, "path": "/w/openclaw.json"}])
    accounting = Normalizer._correlate_fanotify(rows, path)
    assert accounting["events_missing_timestamp"] == 1
    assert accounting["passed"] is False


def test_write_row_outbids_openat_for_the_modify_event(tmp_path: Path) -> None:
    """The defect this pins: greedy row-order allocation let an earlier openat
    claim, via the OPEN bit, the MODIFY event produced by the write beside it --
    leaving the write that actually changed the file with no evidence at all."""
    open_row = _row(pid=100, path="/w/openclaw.json", ts=1_000)
    open_row["syscall"]["name"] = "openat"
    write_row = _row(pid=100, path="/w/openclaw.json", ts=1_050)
    rows = [open_row, write_row]
    path = _write(tmp_path, [
        _event(pid=100, path="/w/openclaw.json", ts=1_000, mask=0x10000),   # OPEN_PERM
        _event(pid=100, path="/w/openclaw.json", ts=1_050, mask=0x2A),      # MODIFY|CLOSE_WRITE|OPEN
    ])
    accounting = Normalizer._correlate_fanotify(rows, path)
    # The write has a unique rank-0 claim on the MODIFY event and takes it.
    assert write_row["correlation"]["fanotify"]["raw_event_index"] == 1
    assert "MODIFY" in write_row["correlation"]["fanotify"]["mask_names"]
    # The openat sees both events at rank 1 and cannot choose without trusting
    # timestamps, so it binds nothing rather than guessing.
    assert (open_row.get("correlation") or {}).get("fanotify") is None
    assert accounting["ambiguous_rows_unbound"] == 1


def test_preimage_records_which_path_it_belongs_to(tmp_path: Path) -> None:
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    path = _write(tmp_path, [_event(pid=100, path="/w/openclaw.json", ts=1_000)])
    Normalizer._correlate_fanotify(rows, path)
    assert rows[0]["correlation"]["fanotify"]["path"] == "/w/openclaw.json"


def test_raw_resolved_alias_row_binds_nothing(tmp_path: Path) -> None:
    """raw != resolved is an alias; which file the event names cannot be decided."""
    rows = [_row(pid=100, path="/w/link.json", ts=1_000)]
    rows[0]["file"]["resolved_path"] = "/w/real.json"
    path = _write(tmp_path, [_event(pid=100, path="/w/real.json", ts=1_000)])
    accounting = Normalizer._correlate_fanotify(rows, path)
    assert accounting["matched_events"] == 0
    assert accounting["alias_ambiguous_rows_skipped"] == 1


def test_secondary_path_cannot_lend_a_preimage(tmp_path: Path) -> None:
    """A pre-image of a different file must never be presented on this row."""
    rows = [_row(pid=100, path="/w/a.json", ts=1_000)]
    rows[0]["paths"] = [{"raw_path": "/w/secret.key", "resolved_path": "/w/secret.key"}]
    path = _write(tmp_path, [_event(pid=100, path="/w/secret.key", ts=1_000)])
    assert Normalizer._correlate_fanotify(rows, path)["matched_events"] == 0


def test_identity_does_not_split_between_bound_and_unbound_rows(tmp_path: Path) -> None:
    """Start ticks are a property of the process, not of the event that revealed
    them, so they apply pid-wide. Scoping the fill to rows that happened to bind
    an event would split one process into two identities -- the very
    fragmentation this whole mechanism exists to avoid. Pid reuse, the reason
    pid-wide application could be unsafe, is guarded separately."""
    bound = _row(pid=100, path="/w/openclaw.json", ts=1_000)
    unbound = _row(pid=100, path="/w/openclaw.json", ts=9_000_000_000)
    rows = [bound, unbound]
    path = _write(tmp_path, [_event(pid=100, path="/w/openclaw.json", ts=1_000, ticks=777)])
    accounting = Normalizer._correlate_fanotify(rows, path)
    assert accounting["process_start_ticks_filled"] == 2
    assert len({r["process"]["identity_key"] for r in rows}) == 1


def test_catalog_disagreement_is_recorded_and_fails_closed(tmp_path: Path) -> None:
    """Two sources disagreeing on a process start time must not vanish silently."""
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    rows[0]["process"]["process_start_time_ticks"] = 999
    path = _write(tmp_path, [_event(pid=100, path="/w/openclaw.json", ts=1_000, ticks=777)])
    accounting = Normalizer._correlate_fanotify(rows, path)
    assert accounting["process_start_ticks_catalog_disagreements"] == [
        {"pid": 100, "existing_ticks": 999, "fanotify_ticks": 777}]
    assert accounting["passed"] is False


def test_close_write_can_bind_its_own_close(tmp_path: Path) -> None:
    """close() is the syscall that generates FAN_CLOSE_WRITE."""
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    rows[0]["syscall"]["name"] = "close"
    path = _write(tmp_path, [_event(pid=100, path="/w/openclaw.json", ts=1_000, mask=0x8)])
    assert Normalizer._correlate_fanotify(rows, path)["matched_events"] == 1


def test_modify_never_binds_a_stat_row(tmp_path: Path) -> None:
    """The content-bearing bits need a negative test of their own."""
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    rows[0]["syscall"]["name"] = "newfstatat"
    path = _write(tmp_path, [_event(pid=100, path="/w/openclaw.json", ts=1_000, mask=0x2)])
    assert Normalizer._correlate_fanotify(rows, path)["matched_events"] == 0


def test_impossible_before_label_becomes_indeterminate(tmp_path: Path) -> None:
    """A permission event stamped after the syscall already returned cannot be a
    pre-image. The mask says "blocking"; the timestamps say otherwise; asserting
    the mask's story would be the same inversion this field was split to avoid."""
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    rows[0]["syscall"]["name"] = "openat"
    path = _write(tmp_path, [
        _event(pid=100, path="/w/openclaw.json", ts=6_000_000, mask=0x10000)])
    accounting = Normalizer._correlate_fanotify(rows, path)
    relation = rows[0]["correlation"]["fanotify"]["content"]["relation_to_syscall"]
    assert relation == "indeterminate_event_after_syscall_return"
    assert accounting["indeterminate_relations"] == 1
    assert accounting["preimages_linked"] == 0


def test_signed_delta_is_preserved(tmp_path: Path) -> None:
    """abs() destroyed the only field a consumer could use to check the label."""
    rows = [_row(pid=100, path="/w/openclaw.json", ts=1_000)]
    path = _write(tmp_path, [_event(pid=100, path="/w/openclaw.json", ts=900)])
    Normalizer._correlate_fanotify(rows, path)
    assert rows[0]["correlation"]["fanotify"]["signed_delta_ns"] == -100


def test_user_hz_is_asserted_not_derived(tmp_path: Path) -> None:
    """USER_HZ is a fixed Linux ABI constant for /proc/pid/stat field 22. An
    earlier version "derived" it from a monotone predicate every candidate
    satisfies, so the answer came from list order."""
    rows = [_row(pid=100, path="/w/openclaw.json", ts=9_000_000_000)]
    event = _event(pid=100, path="/w/openclaw.json", ts=9_000_000_000, ticks=777)
    event["timestamp_monotonic_ns"] = 9_000_000_000
    accounting = Normalizer._correlate_fanotify(rows, _write(tmp_path, [event]))
    assert accounting["user_hz"] == 100
    assert accounting["user_hz_validated"] is True
