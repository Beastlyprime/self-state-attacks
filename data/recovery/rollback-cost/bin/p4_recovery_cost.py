#!/usr/bin/env python3
"""P4 recovery-cost quantification: replace the frozen 'rollback_loss = 1' design
constant with the empirical legitimate self-state write process from the clean
corpus (176 gen2 training + 60 held-out natural runs).

rollback loss = legitimate self-state updates committed after the recovery point
that a restore discards. Under a per-session backup (the frozen P4 design:
snapshot at session start, restore at end), the loss equals the number of
self-state objects the session modified -- which the frozen runner forced to
exactly 1, but the real corpus measures directly.

Self-state write definition is identical to the head-to-head substrate
(syscall in WRITE, result SUCCESS, path canonicalizing to a self-state layer,
grouped by bucket). No agent runtime, no model request; offline read of frozen
libsinsp events.
"""
import os, sys, json, math, statistics
from pathlib import Path
from collections import defaultdict

# repo-relative: this file lives at data/<artifact>/bin/p4_recovery_cost.py
ROOT = Path(os.environ.get("ASSA_ROOT", str(Path(__file__).resolve().parents[4])))
OUTDIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments/code"))
from workload.taxonomy import canonical_path, bucket_key, layer_of  # noqa
import importlib.util
HH = ROOT / "data/superseded"
_spec = importlib.util.spec_from_file_location("score_ours", HH / "score_ours.py")
so = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(so)
WRITE = so.WRITE

CLEAN = {
    "clean_train_gen2_176": ROOT / "data/corpus-manifests/tier_b/clean_train",
    "clean_heldout_gen2_60": ROOT / "data/corpus-manifests/tier_b/clean_heldout",
}


EXPECTED_RUNS = 236  # 176 gen2 training + 60 held-out natural


def fail_closed(message):
    """Refuse to estimate rather than overwrite a frozen output with an empty result.

    This estimator reads the durable-archive clean-run tiers, which the anonymous
    release does not ship. Without them no session is scanned and the resulting
    all-zero distribution would otherwise be written out as legitimate and
    destroy the published evidence.
    """
    sys.exit(f"fail-closed: {message}\n"
             "  Nothing was written. See ANON_EXPORT_README.md, section\n"
             "  'What can be reproduced here, and what cannot'.")


def profile_of(rid):
    for w in ("W1", "W2", "W3", "W4"):
        if f"_{w}_" in rid or rid.startswith(w + "_") or f"_{w}__" in rid:
            return w
    return "??"


def run_stats(rundir):
    f = Path(rundir) / "graph/libsinsp/libsinsp_events.jsonl"
    if not f.is_file():
        return None
    rid = Path(rundir).name
    bk = defaultdict(list)          # bucket -> [ts_sec,...]
    all_ts = []
    for line in f.open():
        e = json.loads(line); sc = e.get("syscall", {})
        ts = (e.get("order") or {}).get("timestamp_realtime_ns")
        if ts is not None:
            all_ts.append(ts / 1e9)
        if sc.get("name") not in WRITE or sc.get("result") != "SUCCESS":
            continue
        p = (e.get("file") or {}).get("path"); k = f"/{rid}/"; i = p.find(k) if p else -1
        if i < 0:
            continue
        cp = canonical_path(p[i + len(k):])
        if cp is None:
            continue
        bk[bucket_key(cp)].append(ts / 1e9 if ts is not None else 0.0)
    n_objects = len(bk)                                   # distinct self-state objects modified
    n_write_events = sum(len(v) for v in bk.values())
    flat = sorted(t for v in bk.values() for t in v)
    write_span = (flat[-1] - flat[0]) if len(flat) >= 2 else 0.0
    session_span = (max(all_ts) - min(all_ts)) if len(all_ts) >= 2 else 0.0
    return {"run_id": rid, "profile": profile_of(rid),
            "n_objects": n_objects, "n_write_events": n_write_events,
            "write_span_sec": write_span, "session_span_sec": session_span,
            "layers": sorted({layer_of(next(iter([c for c in [b] ]))) if False else "" for b in bk})}


def summ(xs):
    xs = list(xs)
    if not xs:
        return {}
    xs_s = sorted(xs)
    def q(p):
        i = min(len(xs_s) - 1, int(round(p * (len(xs_s) - 1))))
        return xs_s[i]
    return {"n": len(xs), "mean": round(statistics.mean(xs), 4),
            "median": q(0.5), "p90": q(0.9), "max": max(xs), "min": min(xs)}


def main():
    rows = []
    absent = [str(d) for d in CLEAN.values() if not d.is_dir()]
    if absent:
        fail_closed("required clean-run tiers are absent: " + ", ".join(absent))
    for pool, d in CLEAN.items():
        for rd in sorted(d.iterdir()):
            if not rd.is_dir():
                continue
            s = run_stats(rd)
            if s is None:
                continue
            s["pool"] = pool
            rows.append(s)

    if not rows:
        fail_closed("the clean-run tiers are present but yielded 0 scannable sessions "
                    f"(expected {EXPECTED_RUNS})")

    writers = [r for r in rows if r["n_objects"] > 0]      # sessions that actually wrote self-state
    # per-session loss (= objects modified per session; the per-session-backup operating point)
    per_session_objects = summ(r["n_objects"] for r in rows)
    per_session_objects_writers = summ(r["n_objects"] for r in writers)
    per_session_events = summ(r["n_write_events"] for r in rows)

    # within-session rate (objects/sec, events/sec) over the self-state write span, writers with span>0
    rate_rows = [r for r in writers if r["write_span_sec"] > 0]
    obj_rate = [r["n_objects"] / r["write_span_sec"] for r in rate_rows]
    evt_rate = [r["n_write_events"] / r["write_span_sec"] for r in rate_rows]

    # WITHIN-SESSION burst rate (descriptive only): self-state writes cluster in
    # short bursts, so this rate must NOT be extrapolated across idle gaps to long T.
    pooled_evt_rate = (sum(r["n_write_events"] for r in rate_rows) /
                       sum(r["write_span_sec"] for r in rate_rows)) if rate_rows else 0.0
    pooled_obj_rate = (sum(r["n_objects"] for r in rate_rows) /
                       sum(r["write_span_sec"] for r in rate_rows)) if rate_rows else 0.0

    # A naive `N sessions * mean-per-session` curve is intentionally NOT emitted:
    # the rollback-loss metric counts DISTINCT changed paths, but summing per-session
    # means across sessions double-counts a path modified in more than one session
    # (that is cumulative object-update incidence, not distinct paths). Only a
    # directional statement is supported without the cross-session revisit model.
    backup_interval_note = ("Multi-session loss as DISTINCT rollback paths is not "
                            "quantified here: N*mean double-counts paths revisited "
                            "across sessions. Directional only -- cost can grow with "
                            "the recovery-point interval; per-session backup is the "
                            "minimum-loss operating point.")

    by_profile = {}
    for w in ("W1", "W2", "W3", "W4"):
        wr = [r for r in rows if r["profile"] == w]
        by_profile[w] = {"n_runs": len(wr),
                         "objects_per_session": summ(r["n_objects"] for r in wr),
                         "write_events_per_session": summ(r["n_write_events"] for r in wr),
                         "median_write_span_sec": (statistics.median([r["write_span_sec"] for r in wr]) if wr else None)}

    out = {
        "schema": "assa.p4.recovery_cost.v1",
        "discipline": {"no_agent_runtime": True, "no_model_request": True,
                       "offline_read_of_frozen_libsinsp": True,
                       "self_state_write_def": "identical to head-to-head substrate (WRITE syscall, SUCCESS, canonical self-state path, bucketed)"},
        "population": {"total_runs_scanned": len(rows),
                       "sessions_writing_self_state": len(writers),
                       "sessions_zero_self_state_write": len(rows) - len(writers)},
        "frozen_p4_design_constant": {"rollback_loss_paths": 1,
                                      "note": "each frozen P4 case injects exactly one post-snapshot legitimate update"},
        "per_session_backup_operating_point": {
            "objects_lost_all_sessions": per_session_objects,
            "objects_lost_writing_sessions_only": per_session_objects_writers,
            "write_events_lost_all_sessions": per_session_events},
        "within_session_burst_rate_descriptive_only": {
            "caveat": "self-state writes cluster in short bursts; do NOT extrapolate across idle gaps to long wall-clock intervals",
            "objects_per_sec": summ(obj_rate),
            "write_events_per_sec": summ(evt_rate),
            "pooled_objects_per_sec": round(pooled_obj_rate, 6),
            "pooled_write_events_per_sec": round(pooled_evt_rate, 6)},
        "backup_interval_note": backup_interval_note,
        "by_profile": by_profile,
        "runs": rows,
    }
    outp = str(OUTDIR / "p4_recovery_cost_result.json")
    with open(outp, "w") as f:
        json.dump(out, f, indent=2)
    print("WROTE", outp)
    print(f"\nPopulation: {len(rows)} runs, {len(writers)} wrote self-state, "
          f"{len(rows)-len(writers)} zero-write")
    print(f"\nFrozen P4 rollback_loss = 1 (design constant)\n")
    print("Per-session rollback loss (objects modified per session):")
    print("  all sessions:", per_session_objects)
    print("  writing-only:", per_session_objects_writers)
    print("Write events per session:", per_session_events)
    print(f"\n[within-session burst rate, descriptive only] {pooled_obj_rate:.4f} objects/s "
          f"-- NOT for long-T extrapolation (bursty)")
    print("Backup interval: directional only (N*mean double-counts distinct paths) -- "
          "per-session is minimum-loss operating point.")
    print("\nBy profile (objects/session):")
    for w, v in by_profile.items():
        print(f"  {w}: n={v['n_runs']:>3} {v['objects_per_session']}")


if __name__ == "__main__":
    main()
