#!/usr/bin/env python3
"""Recompute what the release can actually show about section 4.4's admission gates.

The paper states that all 176 training and 60 held-out clean executions have
non-empty five-source inputs, zero recorded drop/overflow, no excluded writes,
and an effective path-resolution rate of 1.0. An earlier version of
``docs/results.md`` pointed at ``FINAL_3POOL_SPLIT_MANIFEST.json``'s
``anti_leakage_asserts`` for that; those fourteen asserts are population counts,
disjointness and substrate presence, and carry none of the four quantities. The
numbers lived in per-run collector health records that the reproduction corpus
did not carry. It carries them now, under ``tier_a/clean_admission/``.

What that evidence does and does not cover, stated once so the output below can
be read correctly:

* ``health/{inotify,fanotify,auditd,ebpf,ebpf_lifecycle}.json`` for **236/236**
  runs. Note that these are five *collectors*, not Table 6's five *sources*:
  ``ebpf_lifecycle`` is a second eBPF probe, and SCAP -- Table 6's fifth source
  -- has no health record of its own.
* Raw SCAP captures ship in ``tier_c`` for the 60 held-out clean runs only;
  there are none for the 176 training runs. Every one of the 236 does have a
  non-empty SCAP-derived libsinsp stream in ``tier_b``, and the readiness
  records that survive carry a passing ``scap_capture_present_and_valid``, but
  neither is the published raw input. So "non-empty five-source inputs" is
  directly checkable here for four collectors across 236 runs, and for SCAP
  only indirectly.
* ``recollection_readiness.json`` for **100/236** runs, which is where the
  fd-to-path resolution rate is recorded. Eighty hash-match the freeze's
  ``readiness_sha256`` and are provably the records it blessed; twenty survive
  only in older wave trees that recorded no hash. The other **136** runs predate
  that schema and have no readiness record anywhere: for them the rate is
  attested only by the freeze's ``>= 0.95`` gate, never as ``== 1.0``.

So the drop/overflow and collector non-emptiness claims are checkable for every
run; the ``= 1.0`` resolution rate is checkable for 100 of 236. This script
refuses to report anything weaker as a pass.

    python3 data/corpus-manifests/check_admission.py
"""
import hashlib
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import corpus_index

ROOT = Path(os.environ.get("ASSA_ROOT", str(Path(__file__).resolve().parents[2])))
ADM = ROOT / "data/corpus-manifests/tier_a/clean_admission"
FREEZES = ROOT / "data/corpus-manifests/tier_a/job_reports"
TIER_C = ROOT / "data/corpus-manifests/tier_c"

FREEZE_FILES = ("P2_CLEAN_TRAINING_FREEZE_GEN2.json", "P2_HELDOUT_CLEAN_FREEZE_GEN2.json")
COLLECTORS = ("auditd", "ebpf", "ebpf_lifecycle", "fanotify", "inotify")
RATE_KEYS = ("fd_path_resolved_rate", "effective_fd_path_resolution_rate", "spine_rate")
COUNTERS = ("drop_count", "overflow_count", "events_emitted")

# The published population, fixed. A short or long count is an incomplete or
# contaminated input, not a weaker finding, so these are asserted rather than
# reported.
EXPECTED_RUNS = 236
EXPECTED_READINESS = 100
EXPECTED_HASH_VERIFIED = 80
EXCLUDED_GATES = ("bridge_writes_excluded_zero", "writes_excluded_zero")
PIPELINE_GATES = ("pipeline_status_valid_attempt", "pipeline_valid_attempt")


def load_freezes():
    runs = {}
    for name in FREEZE_FILES:
        path = FREEZES / name
        if not path.is_file():
            sys.exit(f"{path} is absent -- unpack selfstate-corpus-tier_a.tar.zst into "
                     "data/corpus-manifests/")
        for rec in json.loads(path.read_text())["records"]:
            runs[rec["run_id"]] = rec
    return runs


def gate(rec, names):
    """The first of `names` the record's checks carry, or None if it carries none."""
    for n in names:
        if n in rec["checks"]:
            return bool(rec["checks"][n])
    return None


def main():
    if not ADM.is_dir():
        sys.exit(f"{ADM} is absent -- unpack selfstate-corpus-tier_a.tar.zst into "
                 "data/corpus-manifests/")
    freeze = load_freezes()
    present = {p.name for p in ADM.iterdir() if p.is_dir()}
    problems = []

    # 1. the admission set must be exactly the frozen population
    missing = sorted(set(freeze) - present)
    foreign = sorted(present - set(freeze))
    if missing:
        problems.append(f"{len(missing)} frozen runs have no admission evidence, "
                        f"e.g. {missing[:3]}")
    if foreign:
        problems.append(f"{len(foreign)} admission directories name runs that are not in "
                        f"the freeze, e.g. {foreign[:3]}")

    # 2. collector health, every counter present rather than defaulted
    drops = overflows = 0
    empty, absent_record, absent_field = [], [], []
    for rid in sorted(present & set(freeze)):
        health = ADM / rid / "health"
        for src in COLLECTORS:
            record = health / f"{src}.json"
            if not record.is_file():
                absent_record.append(f"{rid}/{src}")
                continue
            j = json.loads(record.read_text())
            for key in COUNTERS:
                if not isinstance(j.get(key), int):
                    absent_field.append(f"{rid}/{src}.{key}")
            drops += int(j.get("drop_count") or 0)
            overflows += int(j.get("overflow_count") or 0)
            if not int(j.get("events_emitted") or 0) > 0:
                empty.append(f"{rid}/{src}")

    # 3. readiness records, their coverage and their binding to the freeze
    rates, readiness, verified, mismatched, rateless = [], 0, 0, [], []
    for rid in sorted(present & set(freeze)):
        rp = ADM / rid / "recollection_readiness.json"
        if not rp.is_file():
            continue
        readiness += 1
        raw = rp.read_text()
        found = [float(x) for k in RATE_KEYS for x in re.findall(rf'"{k}"\s*:\s*([0-9.]+)', raw)]
        if not found:
            rateless.append(rid)
        rates += found
        want = freeze[rid].get("readiness_sha256")
        if want:
            if hashlib.sha256(rp.read_bytes()).hexdigest() == want:
                verified += 1
            else:
                mismatched.append(rid)

    # 4. the two gates the freeze does carry for the whole population
    no_excluded = [r for r in sorted(freeze) if gate(freeze[r], EXCLUDED_GATES) is not True]
    not_valid = [r for r in sorted(freeze) if gate(freeze[r], PIPELINE_GATES) is not True]

    # 5. every admission file must be the published bytes. The freeze's
    # readiness_sha256 binds 80 of the 100 readiness records to the generation
    # that blessed them; the other 20 have no such hash, so tampering with one
    # of those is invisible to the check above. The release checksum index
    # covers all 1,281 files and closes that gap.
    unpublished = corpus_index.check_tree(ADM, ROOT, limit=6)

    scap = sum(1 for r in freeze
               if any((TIER_C / d / r).is_dir() for d in ("attacks", "twins", "clean_heldout")))

    print(f"frozen clean population              : {len(freeze)}")
    print(f"runs with admission evidence         : {len(present & set(freeze))}"
          f"  (foreign dirs: {len(foreign)})")
    print(f"collector records present            : "
          f"{len(present & set(freeze)) * len(COLLECTORS) - len(absent_record)}"
          f"/{len(present & set(freeze)) * len(COLLECTORS)}"
          f"  ({', '.join(COLLECTORS)})")
    print(f"total drop_count                     : {drops}")
    print(f"total overflow_count                 : {overflows}")
    print(f"collector streams with no events     : {len(empty)}")
    print(f"freeze gate: no excluded writes      : {len(freeze) - len(no_excluded)}/{len(freeze)}")
    print(f"freeze gate: pipeline valid attempt  : {len(freeze) - len(not_valid)}/{len(freeze)}")
    print(f"readiness records                    : {readiness}/{len(freeze)}"
          f"  ({verified} hash-verified against the freeze)")
    if rates:
        print(f"fd-to-path resolution rate           : {min(rates)}-{max(rates)}, from "
              f"{readiness} run-level readiness records")
    print(f"raw SCAP captures published          : {scap}/{len(freeze)}"
          f"  (held-out clean only; none for the 176 training runs)")
    print(f"admission files matching the index   : "
          f"{'all' if not unpublished else 'NO -- ' + str(len(unpublished)) + '+ differ'}")

    if absent_record:
        problems.append(f"{len(absent_record)} collector records absent, e.g. {absent_record[:3]}")
    if absent_field:
        problems.append(f"{len(absent_field)} collector counters missing or non-integer -- "
                        f"absent is not zero -- e.g. {absent_field[:3]}")
    if drops or overflows:
        problems.append(f"drop_count={drops}, overflow_count={overflows}; the paper reports zero")
    if empty:
        problems.append(f"{len(empty)} collector streams emitted nothing, e.g. {empty[:3]}")
    if readiness != EXPECTED_READINESS:
        problems.append(f"{readiness} readiness records, expected {EXPECTED_READINESS}")
    if verified != EXPECTED_HASH_VERIFIED:
        problems.append(f"{verified} readiness records hash-verified, "
                        f"expected {EXPECTED_HASH_VERIFIED}")
    if mismatched:
        problems.append(f"readiness records not matching the freeze: {mismatched[:3]}")
    if rateless:
        problems.append(f"{len(rateless)} readiness records record no resolution rate, "
                        f"e.g. {rateless[:3]}")
    if rates and (min(rates) != 1.0 or max(rates) != 1.0):
        problems.append(f"a recorded resolution rate is not 1.0: range {min(rates)}-{max(rates)}")
    if not rates:
        problems.append("no resolution rate was recovered from any readiness record")
    if no_excluded:
        problems.append(f"{len(no_excluded)} runs without a passing excluded-writes gate, "
                        f"e.g. {no_excluded[:3]}")
    if not_valid:
        problems.append(f"{len(not_valid)} runs without a passing pipeline-valid gate, "
                        f"e.g. {not_valid[:3]}")
    if len(freeze) != EXPECTED_RUNS:
        problems.append(f"{len(freeze)} frozen runs, expected {EXPECTED_RUNS}")
    if unpublished:
        problems.append("admission files that are not the published bytes: "
                        + "; ".join(unpublished))

    if problems:
        print("\nFAIL")
        for p in problems:
            print(f"  {p}")
        sys.exit(1)

    print(f"\nOK. Zero drops and zero overflows across {len(freeze) * len(COLLECTORS)} collector "
          f"streams, every stream non-empty, and both freeze gates hold for all {len(freeze)} "
          f"runs.\nThe = 1.0 resolution rate is shown for the {readiness} runs whose readiness "
          f"record survives,\nnot for the other {len(freeze) - readiness}, which carry only the "
          ">= 0.95 gate. SCAP is evidenced\nindirectly for the 176 training runs -- see this "
          "script's docstring.")


if __name__ == "__main__":
    main()
