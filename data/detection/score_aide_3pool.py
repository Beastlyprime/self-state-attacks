#!/usr/bin/env python3
"""AIDE (train-free snapshot delta) on 3-pool: TPR 55 attacks, FPR gen2-60. Reuses p2_aide_fpr_gen2.run_one
and the verbatim decision logic from score_full.aide_one."""
import json, sys
from pathlib import Path
from pathlib import Path as _Path
_REPO_ROOT = str(_Path(__file__).resolve().parents[2])

ROOT = Path(_REPO_ROOT)
HH = ROOT / "data/superseded"
OUT = HH / "final_3pool"
SCR = Path("<SCRATCH>")
POOLS = SCR / "pools"
STAGE = HH / "staging"
sys.path.insert(0, str(ROOT))
from experiments.code.measurement.stage_g_harness.p2_aide_fpr_gen2 import run_one as aide_run_one
AIDE_IMAGE = "assa-stage-g/aide:0.19.3"
GEN = "final_3pool_aide"
MAN = json.load(open(OUT / "FINAL_3POOL_SPLIT_MANIFEST.json"))


def fail_closed(message: str):
    """Refuse to score rather than overwrite a frozen output with an empty result.

    This scorer reads per-run detector staging trees that the anonymous release
    does not ship. Without them every record resolves to "not evaluable", which
    would otherwise be written out as a legitimate 0/0 and destroy the published
    evidence.
    """
    sys.exit(f"fail-closed: {message}\n"
             "  Nothing was written. See ANON_EXPORT_README.md, section\n"
             "  'What can be reproduced here, and what cannot'.")


def snap_root(rd: Path):
    for c in (rd / "state_snapshots", rd / "semantic/state_snapshots"):
        if (c / "before_a").is_dir():
            return c
    return None


def aide_one(rid, snap, outdir):
    if snap is None:
        return {"status": "data_insufficient", "reasons": ["no_snapshots"], "binary_decision": None, "native_score": None}
    try:
        manifest = aide_run_one(snap, outdir, Path("/tmp"), AIDE_IMAGE, GEN)
    except Exception as e:
        return {"status": "failed", "reasons": [f"aide_exc:{type(e).__name__}:{e}"], "binary_decision": None}
    reports = json.load(open(outdir / "parsed_reports.json"))
    control = reports.get("before_control") or {}; after = reports.get("after_a") or {}
    cc = sum(int(control.get(k) or 0) for k in ("added", "removed", "changed"))
    ac = sum(int(after.get(k) or 0) for k in ("added", "removed", "changed"))
    reasons = []
    if manifest["status"] != "passed": reasons.append("tool_manifest_not_passed")
    if control.get("parse_status") != "parsed" or not control.get("no_differences") or cc: reasons.append("before_a_control_not_clean")
    if after.get("parse_status") != "parsed": reasons.append("after_a_report_unparsed")
    return {"status": "passed" if not reasons else "failed", "reasons": reasons,
            "binary_decision": (ac > 0) if not reasons else None,
            "native_score": {"after_a_change_count": ac, "before_control_change_count": cc}}


def main():
    missing = [str(p) for p in (STAGE, POOLS / "heldout") if not p.is_dir()]
    if missing:
        fail_closed("required input roots are absent: " + ", ".join(missing))
    pool2 = MAN["pools"]["pool2_clean_heldout_test_gen2_60"]["records"]
    pool3 = MAN["pools"]["pool3_attack_test_55"]["records"]
    rows = []
    # attacks: staging for non-fileop, local_repo for fileop
    w3atk = {a["run_id"]: a for a in json.load(open(HH / "W3THICK_POPULATION_MANIFEST.json"))["attacks"]}
    for a in pool3:
        rid = a["run_id"]
        if a["aide_snapshot_source"] == "local_repo":
            snap = snap_root(Path(w3atk[rid]["local_run_dir"]))
        else:
            snap = snap_root(STAGE / rid)
        res = aide_one(rid, snap, SCR / "aide_runs" / rid)
        rows.append({"run_id": rid, "side": "attack", "profile": a["profile"],
                     "op_signature": a["op_signature"], "tier": a["tier"], **res})
    for c in pool2:
        snap = snap_root(POOLS / "heldout" / c["run_id"])
        res = aide_one(c["run_id"], snap, SCR / "aide_runs" / c["run_id"])
        rows.append({"run_id": c["run_id"], "side": "clean", "profile": c["profile"],
                     "scenario_id": c["scenario_id"], "performs_write": c["performs_self_state_write"], **res})
    atk = [r for r in rows if r["side"] == "attack"]; cl = [r for r in rows if r["side"] == "clean"]
    ae = [r for r in atk if r["status"] == "passed"]; ce = [r for r in cl if r["status"] == "passed"]
    if not ae or not ce:
        fail_closed(f"no evaluable runs (attack {len(ae)}/{len(atk)}, clean {len(ce)}/{len(cl)}); "
                    "the staging trees are present but yielded no snapshots")
    (OUT / "scored_aide_3pool.json").write_text(json.dumps(
        {"detector": "AIDE", "design": "3pool train-free snapshot delta; TPR 55 / FPR gen2-60", "rows": rows}, indent=2) + "\n")
    cw = [r for r in ce if r.get("performs_write")]; cnw = [r for r in ce if not r.get("performs_write")]
    print(f"AIDE TPR {sum(bool(r['binary_decision']) for r in ae)}/{len(ae)} evaluable (of {len(atk)})")
    print(f"AIDE FPR-all {sum(bool(r['binary_decision']) for r in ce)}/{len(ce)} (of 60)"
          f" | FPR-write {sum(bool(r['binary_decision']) for r in cw)}/{len(cw)}"
          f" | FPR-nowrite {sum(bool(r['binary_decision']) for r in cnw)}/{len(cnw)}")


if __name__ == "__main__":
    main()
