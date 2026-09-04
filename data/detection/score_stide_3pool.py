#!/usr/bin/env python3
"""STIDE on 3-pool: train per-profile on gen2-176, test 55 attacks + gen2-60 heldout.
Batched per profile (test instances scored independently -> identical to per-run calls, faster).
Reuses stide_bridge.run verbatim; frozen preregistration core executables."""
import json, sys, os
from pathlib import Path
from collections import defaultdict

ROOT = Path(os.environ.get("ASSA_ROOT", str(Path(__file__).resolve().parents[2])))
HH = ROOT / "data/superseded"
OUT = ROOT / "data/detection"
SCR = Path(os.environ.get("ASSA_SCRATCH", str(ROOT / ".scratch")))
POOLS = ROOT / "data/corpus-manifests/tier_b"       # unpacked corpus
POOL_DIR = {"train": "clean_train", "heldout": "clean_heldout"}
STAGE = HH / "staging"
sys.path.insert(0, str(ROOT))
from experiments.code.measurement.stage_g_harness.stide_bridge import run as stide_run

STIDE_REPO = Path("/tmp/assa-stage-g-lid-ds")
CORE = json.loads((ROOT / "data/aux/P2_STIDE_STOPPING_RULE_PREREGISTRATION.json").read_text())
PF = CORE["profile_freeze"]
MAN = json.load(open(OUT / "FINAL_3POOL_SPLIT_MANIFEST.json"))
REATTR_REL = "graph/reattributed/resolution_spine_effective/syscalls.jsonl"
STREAM_REL = {
    "resolution_spine_effective": REATTR_REL,
    "normalized": "graph/normalized/syscalls.jsonl",
}


def idkeys(path, expect_rid=None):
    """Identity keys in a stream, and -- if asked -- proof it is the right stream.

    Presence of a file is not evidence that it is the right file. A blanked
    stream and another run's stream both parse cleanly and both move the
    numbers, so bind the stream to the run it is supposed to describe. Each
    record names its own run; STREAM_AUDIT collects what was seen and the gate
    in main() acts on it.
    """
    ks = set()
    seen = 0
    foreign = set()
    for line in open(path):
        r = json.loads(line)
        seen += 1
        if expect_rid is not None and r.get("run_id") != expect_rid:
            foreign.add(r.get("run_id"))
        if not r.get("sequence_eligible"):
            continue
        pr = r.get("process") or {}
        ks.add(pr.get("identity_key") or f"{r['run_id']}:{pr.get('pid')}:identity_incomplete")
    if expect_rid is not None:
        STREAM_AUDIT[expect_rid] = {"path": str(path), "records": seen, "foreign_run_ids": foreign}
    return ks


STREAM_AUDIT: dict = {}


def stream_head_identity(path, expect_rid):
    """Cheap identity check for a stream this scorer hands to the backend unread.

    The 176 training streams are consumed by STIDE, not by this process, so
    reading them in full only to validate would cost several gigabytes. Check
    the first record instead: that catches a blanked file and a whole-stream
    substitution, which are the ways an input gets silently swapped. It does not
    catch a stream spliced record by record, and the fit is only as trustworthy
    as the published checksums for those files.
    """
    with open(path) as fh:
        first = fh.readline()
    if not first.strip():
        return "empty"
    rid = json.loads(first).get("run_id")
    return None if rid == expect_rid else f"first record names {rid}"


def fail_closed(message: str):
    """Refuse to score rather than overwrite the frozen rows with a partial result.

    Two things collapse this scorer to a uniform data_insufficient without any
    error: a missing per-run substrate, and a STIDE backend that returns no
    normal database (a bad STIDE_REPO checkout, or the pinned analyzer absent).
    Both look exactly like a detector that simply never fired, so gate on the
    population instead of trusting exit status.
    """
    sys.exit(f"fail-closed: {message}\n"
             "  Nothing was written. See REPRODUCE.md, 'Level 3 -- what needs\n"
             "  the corpus', for what this scorer needs beyond this repository.")


# The eleven W3 C-series attacks were resolved out of the detector staging tree
# when these rows were frozen; the staging volume no longer carries its own copy,
# and the same trees are published under tier_b/attacks_lockedpop_cseries with
# byte-identical streams. Try staging first, then the attack pools.
ATTACK_POOL_DIRS = ("attacks", "attacks_lockedpop_cseries")


def attack_substrate(rid, rel):
    for cand in (STAGE / rid, *(POOLS / sub / rid for sub in ATTACK_POOL_DIRS)):
        if (cand / rel).is_file():
            return cand / rel
    return STAGE / rid / rel    # keep the historical path in the error message


def main():
    pool1 = MAN["pools"]["pool1_clean_training_gen2_176"]["records"]
    pool2 = MAN["pools"]["pool2_clean_heldout_test_gen2_60"]["records"]
    pool3 = MAN["pools"]["pool3_attack_test_55"]["records"]

    train_by_prof = defaultdict(list)
    for r in pool1:
        train_by_prof[r["profile"]].append(POOLS / POOL_DIR["train"] / r["run_id"] / REATTR_REL)

    # test runs per profile with their substrate path + side
    test_runs = []
    for a in pool3:
        stream = a["stide_stream"]
        test_runs.append((a["run_id"], a["profile"], "attack",
                          attack_substrate(a["run_id"], STREAM_REL[stream]), a))
    for c in pool2:
        test_runs.append((c["run_id"], c["profile"], "clean",
                          POOLS / POOL_DIR["heldout"] / c["run_id"] / REATTR_REL, c))

    missing_train = [str(p) for paths in train_by_prof.values() for p in paths if not p.is_file()]
    missing_test = [f"{rid} ({path})" for rid, _, _, path, _ in test_runs if not path.is_file()]
    if missing_train or missing_test:
        fail_closed(f"{len(missing_train)} of {len(pool1)} training streams and "
                    f"{len(missing_test)} of {len(test_runs)} test substrates are absent. "
                    + "; ".join((missing_train + missing_test)[:6])
                    + (" ..." if len(missing_train) + len(missing_test) > 6 else ""))

    # Bind the training streams to their runs before handing them to the backend.
    wrong_train = []
    for r in pool1:
        p = POOLS / POOL_DIR["train"] / r["run_id"] / REATTR_REL
        why = stream_head_identity(p, r["run_id"])
        if why:
            wrong_train.append(f"{r['run_id']} ({why})")
    if wrong_train:
        fail_closed(f"{len(wrong_train)} of {len(pool1)} training streams do not belong to "
                    f"their run: " + "; ".join(wrong_train[:6])
                    + (" ..." if len(wrong_train) > 6 else ""))

    rows = []
    for prof in ("W1", "W2", "W3", "W4"):
        cores = PF[prof]["core_executables"]
        train_paths = train_by_prof[prof]
        prof_tests = [t for t in test_runs if t[1] == prof]
        test_paths = [t[3] for t in prof_tests if t[3].is_file()]
        # map identity_key -> run_id
        key2run = {}
        for rid, _, _, path, _ in prof_tests:
            if path.is_file():
                for k in idkeys(path, expect_rid=rid):
                    key2run[k] = rid
        res = stide_run(STIDE_REPO, train_paths, test_paths, 6, 106)
        exres = res["results"]
        # per run: collect core-exec instances belonging to it
        for rid, p, side, path, meta in prof_tests:
            if not path.is_file():
                rows.append({"run_id": rid, "profile": p, "side": side, "status": "data_insufficient",
                             "reasons": ["missing_substrate"], "binary_decision": None,
                             "stide_stream": meta.get("stide_stream", "resolution_spine_effective")}); continue
            evaluable_instances = 0; unknown_hit = False; total_unknown = 0
            for exe in cores:
                er = exres.get(exe)
                if not er or not er.get("normal_database_ngrams"):
                    continue
                for ik, inst in (er.get("instances") or {}).items():
                    if key2run.get(ik) != rid:
                        continue
                    if inst.get("evaluated_ngrams", 0) > 0:
                        evaluable_instances += 1
                        total_unknown += int(inst.get("unknown_ngrams") or 0)
                        if int(inst.get("unknown_ngrams") or 0) > 0:
                            unknown_hit = True
            if evaluable_instances == 0:
                rows.append({"run_id": rid, "profile": p, "side": side, "status": "data_insufficient",
                             "reasons": ["no_evaluable_frozen_core_executable"], "binary_decision": None,
                             "op_signature": meta.get("op_signature", "clean"),
                             "stide_stream": meta.get("stide_stream", "resolution_spine_effective")})
            else:
                rows.append({"run_id": rid, "profile": p, "side": side, "status": "passed",
                             "binary_decision": bool(unknown_hit),
                             "core_evaluable_instances": evaluable_instances, "core_unknown_ngrams": total_unknown,
                             "op_signature": meta.get("op_signature", "clean"),
                             "stide_stream": meta.get("stide_stream", "resolution_spine_effective"),
                             "performs_write": meta.get("performs_self_state_write"),
                             "scenario_id": meta.get("scenario_id"), "tier": meta.get("tier")})
        print(f"{prof}: trained {len(train_paths)} tested {len(test_paths)}")

    atk = [r for r in rows if r["side"] == "attack"]
    cl = [r for r in rows if r["side"] == "clean"]
    ae = [r for r in atk if r["status"] == "passed"]; ce = [r for r in cl if r["status"] == "passed"]

    # Every test stream must have belonged to its own run. An emptied or
    # substituted stream parses fine and quietly shifts TPR or FPR.
    bad = [f"{rid} ({'empty' if a['records'] == 0 else 'carries ' + str(sorted(x for x in a['foreign_run_ids'] if x)[:2])})"
           for rid, a in STREAM_AUDIT.items() if a["records"] == 0 or a["foreign_run_ids"]]
    if bad:
        fail_closed(f"{len(bad)} test substrates do not belong to their run: "
                    + "; ".join(bad[:6]) + (" ..." if len(bad) > 6 else ""))
    if len(STREAM_AUDIT) != len(test_runs):
        fail_closed(f"only {len(STREAM_AUDIT)} of {len(test_runs)} test substrates were read")

    # The frozen generation evaluated every run on both sides -- 55/55 and 60/60,
    # zero data_insufficient. Anything short of that means an input or the STIDE
    # backend is missing, which reads identically to a detector that never fired.
    EXPECTED_ATTACK, EXPECTED_CLEAN = 55, 60
    if len(ae) != EXPECTED_ATTACK or len(ce) != EXPECTED_CLEAN:
        bad = sorted(r["run_id"] for r in rows if r["status"] != "passed")
        fail_closed(f"evaluable population is short: attack {len(ae)}/{EXPECTED_ATTACK}, "
                    f"clean {len(ce)}/{EXPECTED_CLEAN}. Not evaluated: "
                    + ", ".join(bad[:8]) + (" ..." if len(bad) > 8 else "")
                    + ".\n  A uniform data_insufficient is also what an absent STIDE backend produces --"
                    " check that STIDE_REPO points at the pinned checkout.")

    (OUT / "scored_stide_3pool.json").write_text(json.dumps(
        {"detector": "STIDE", "design": "3pool: train gen2-176 per-profile / test 55+gen2-60; frozen core; n=6 minseq=106",
         "rows": rows}, indent=2) + "\n")
    # summary
    cw = [r for r in ce if r.get("performs_write")]; cnw = [r for r in ce if not r.get("performs_write")]
    print(f"STIDE TPR {sum(bool(r['binary_decision']) for r in ae)}/{len(ae)} evaluable (of {len(atk)})")
    print(f"STIDE FPR-all {sum(bool(r['binary_decision']) for r in ce)}/{len(ce)} evaluable (of 60)"
          f" | FPR-write {sum(bool(r['binary_decision']) for r in cw)}/{len(cw)}"
          f" | FPR-nowrite {sum(bool(r['binary_decision']) for r in cnw)}/{len(cnw)}")


if __name__ == "__main__":
    main()
