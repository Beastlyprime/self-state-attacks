#!/usr/bin/env python3
"""Read-only two-hop gzip pull of the 3 detector substrates for a clean pool.
Pulls: graph/libsinsp/libsinsp_events.jsonl, graph/reattributed/resolution_spine_effective/syscalls.jsonl,
       state_snapshots/  (also graph/normalized/syscalls.jsonl as fallback).
Never writes to the VMs. Resumable: skips a run whose 3 rels already exist locally.
Usage: python3 pull_pool.py {train|heldout}
"""
import json, os, subprocess, sys
from pathlib import Path

SCR = Path("<SCRATCH>")
POOLS = SCR / "pools"
JUMP = "<COLLECTOR_HOST>"
VM = "<GUEST_HOST_A>"
KEY = "<HOME>/.ssh/assa_guest"
os.environ["SSH_AUTH_SOCK"] = "<HOME>/.ssh/codex-agent.sock"

RELS = [
    "graph/libsinsp/libsinsp_events.jsonl",
    "graph/reattributed/resolution_spine_effective/syscalls.jsonl",
    "state_snapshots",
]
CHECK = [
    "graph/libsinsp/libsinsp_events.jsonl",
    "graph/reattributed/resolution_spine_effective/syscalls.jsonl",
]


def pull_one(pool, r):
    rid = r["run_id"]; rundir = r["run_dir"]
    dest = POOLS / pool / rid
    if all((dest / c).exists() and (dest / c).stat().st_size > 0 for c in CHECK):
        return {"run_id": rid, "status": "cached"}
    dest.mkdir(parents=True, exist_ok=True)
    inner = f"cd {rundir} && tar czf - " + " ".join(RELS) + " 2>/dev/null"
    remote = f"ssh -o BatchMode=yes -o StrictHostKeyChecking=no -i {KEY} -o ConnectTimeout=25 assa@{VM} \"{inner}\""
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=25", JUMP, remote]
    tgz = dest / "_p.tgz"
    with tgz.open("wb") as fh:
        p = subprocess.run(cmd, stdout=fh, stderr=subprocess.PIPE)
    if p.returncode != 0 or tgz.stat().st_size == 0:
        return {"run_id": rid, "status": "failed", "rc": p.returncode, "stderr": p.stderr.decode()[-200:]}
    x = subprocess.run(["tar", "xzf", str(tgz), "-C", str(dest)], stderr=subprocess.PIPE)
    tgz.unlink(missing_ok=True)
    if x.returncode != 0:
        return {"run_id": rid, "status": "untar_failed", "stderr": x.stderr.decode()[-200:]}
    got = {c: (dest / c).exists() for c in CHECK}
    return {"run_id": rid, "status": "ok" if all(got.values()) else "partial", "got": got}


def main():
    pool = sys.argv[1]
    runs = json.loads((SCR / "pool_runs.json").read_text())[pool]
    results = []
    for i, r in enumerate(runs, 1):
        res = pull_one(pool, r)
        results.append(res)
        print(f"[{pool} {i}/{len(runs)}] {res['status']:10} {r['run_id']}", flush=True)
    ok = sum(r["status"] in ("ok", "cached") for r in results)
    (SCR / f"PULL_{pool}_REPORT.json").write_text(json.dumps(
        {"pool": pool, "n": len(results), "ok": ok,
         "failed": [r for r in results if r["status"] not in ("ok", "cached")],
         "results": results}, indent=2) + "\n")
    print(f"PULL {pool} done: {ok}/{len(results)}")


if __name__ == "__main__":
    main()
