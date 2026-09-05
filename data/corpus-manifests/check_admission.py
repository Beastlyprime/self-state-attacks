#!/usr/bin/env python3
"""Recompute the section 4.4 admission figures for the 236 clean executions.

The paper states that all 176 training and 60 held-out clean executions have
non-empty five-source inputs, zero recorded drop/overflow, no excluded writes,
and an effective path-resolution rate of 1.0. Three of those four were only
readable here as pass/fail booleans in the freeze records, and drop/overflow was
not in the release at all -- the numbers lived in per-run collector health
records that the reproduction corpus did not carry. It carries them now, under
``tier_a/clean_admission/``, and this script adds them up.

What the evidence covers, exactly:

* ``health/{inotify,fanotify,auditd,ebpf,ebpf_lifecycle}.json`` for **236/236**
  runs -- ``drop_count``, ``overflow_count``, ``events_emitted`` and
  ``queue_high_water_mark`` per collector. SCAP is the fifth source named in
  Table 6 and has no health record of its own; its capture is in ``tier_c``.
* ``recollection_readiness.json`` for **100/236** runs, which is where the
  fd-to-path resolution rate is recorded. Eighty of those hash-match the
  ``readiness_sha256`` in the freeze, so they are provably the records the
  freeze blessed; twenty survive only in the older wave trees, which recorded no
  hash. The remaining 136 runs predate that schema and have no readiness record
  anywhere -- for them the resolution rate is attested only by the freeze's
  ``bridge_acceptance_passed`` gate, which is >= 0.95 rather than == 1.0.

So the drop/overflow and non-emptiness claims are now checkable for every run,
and the ``= 1.0`` resolution rate for 100 of 236. The script prints both and
does not pretend the coverage is uniform.

    python3 data/corpus-manifests/check_admission.py
"""
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(os.environ.get("ASSA_ROOT", str(Path(__file__).resolve().parents[2])))
ADM = ROOT / "data/corpus-manifests/tier_a/clean_admission"
FREEZES = ROOT / "data/corpus-manifests/tier_a/job_reports"
RATE_KEYS = ("fd_path_resolved_rate", "effective_fd_path_resolution_rate", "spine_rate")
EXPECTED_RUNS = 236
EXPECTED_SOURCES = ("auditd", "ebpf", "ebpf_lifecycle", "fanotify", "inotify")


def main():
    if not ADM.is_dir():
        sys.exit(f"{ADM} is absent -- unpack selfstate-corpus-tier_a.tar.zst into "
                 "data/corpus-manifests/")

    freeze_sha = {}
    for name in ("P2_CLEAN_TRAINING_FREEZE_GEN2.json", "P2_HELDOUT_CLEAN_FREEZE_GEN2.json"):
        path = FREEZES / name
        if path.is_file():
            for rec in json.loads(path.read_text())["records"]:
                if rec.get("readiness_sha256"):
                    freeze_sha[rec["run_id"]] = rec["readiness_sha256"]

    runs = sorted(p for p in ADM.iterdir() if p.is_dir())
    drops = overflows = 0
    empty, missing_source, rates, readiness, verified, mismatched = [], [], [], 0, 0, []
    for run in runs:
        health = run / "health"
        seen = set()
        for record in sorted(health.glob("*.json")) if health.is_dir() else []:
            j = json.loads(record.read_text())
            seen.add(j.get("source", record.stem))
            drops += int(j.get("drop_count") or 0)
            overflows += int(j.get("overflow_count") or 0)
            if not int(j.get("events_emitted") or 0) > 0:
                empty.append(f"{run.name}/{record.stem}")
        for src in EXPECTED_SOURCES:
            if src not in seen:
                missing_source.append(f"{run.name}/{src}")
        rp = run / "recollection_readiness.json"
        if rp.is_file():
            readiness += 1
            raw = rp.read_text()
            rates += [float(x) for k in RATE_KEYS
                      for x in re.findall(rf'"{k}"\s*:\s*([0-9.]+)', raw)]
            want = freeze_sha.get(run.name)
            if want:
                import hashlib
                got = hashlib.sha256(rp.read_bytes()).hexdigest()
                if got == want:
                    verified += 1
                else:
                    mismatched.append(run.name)

    print(f"runs with collector health records : {len(runs)}/{EXPECTED_RUNS}")
    print(f"five collectors present per run    : {len(runs) - len({m.split('/')[0] for m in missing_source})}/{len(runs)}")
    print(f"total drop_count                   : {drops}")
    print(f"total overflow_count               : {overflows}")
    print(f"collector streams with no events   : {len(empty)}")
    print(f"readiness records present          : {readiness}/{EXPECTED_RUNS}"
          f"  ({verified} hash-verified against the freeze)")
    if rates:
        print(f"fd-to-path resolution rates        : {len(rates)} values, "
              f"min {min(rates)}, max {max(rates)}")

    problems = []
    if len(runs) != EXPECTED_RUNS:
        problems.append(f"{len(runs)} run directories, expected {EXPECTED_RUNS}")
    if missing_source:
        problems.append(f"{len(missing_source)} missing collector records, e.g. {missing_source[:3]}")
    if drops or overflows:
        problems.append(f"drop_count={drops}, overflow_count={overflows}: the paper reports zero")
    if empty:
        problems.append(f"{len(empty)} collector streams emitted nothing, e.g. {empty[:3]}")
    if mismatched:
        problems.append(f"readiness records not matching the freeze: {mismatched[:3]}")
    if rates and max(rates) != 1.0:
        problems.append(f"a resolution rate below 1.0 is recorded: min {min(rates)}")
    if problems:
        print("\nFAIL")
        for p in problems:
            print(f"  {p}")
        sys.exit(1)
    print("\nOK -- matches what section 4.4 reports, at the coverage stated in this "
          "script's docstring.")


if __name__ == "__main__":
    main()
