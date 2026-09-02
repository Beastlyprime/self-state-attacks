#!/usr/bin/env python3
"""Read-only two-hop sync of detector inputs into staging/<run_id>/.
Pulls only the needed files (STIDE syscalls ~18MB, libsinsp ~4MB, snapshots ~130KB).
Never writes to the VMs. One tar-over-ssh per run; a failed run is recorded, not fatal.
"""
from __future__ import annotations
import json, os, subprocess, sys
from pathlib import Path

OUT = Path(__file__).resolve().parent
STAGE = OUT / "staging"
JUMP = "<COLLECTOR_HOST>"
SSH_BASE = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=20"]
NEED_REL = {
    "stide_syscalls": "graph/reattributed/resolution_spine_effective/syscalls.jsonl",
    "libsinsp": "graph/libsinsp/libsinsp_events.jsonl",
    "snapshots": "state_snapshots",
}
BENCH = "assa-bench/data"


def rows(pop):
    for grp in ("attacks_graph_present", "ours_baseline_twins", "clean_heldout_40"):
        for r in pop[grp]:
            if r.get("sync"):
                yield r


def remote_abs(remote_run: str) -> str:
    if remote_run.startswith("/"):
        return remote_run
    return f"~/{BENCH}/{remote_run}"


def sync_one(r) -> dict:
    rid = r["run_id"]; s = r["sync"]; vm = s["vm"]
    dest = STAGE / rid
    rels = [NEED_REL[n] for n in s["need"]]
    # skip if all present
    present = all((dest / rel).exists() for rel in rels)
    if present:
        return {"run_id": rid, "status": "cached"}
    dest.mkdir(parents=True, exist_ok=True)
    rbase = remote_abs(s["remote_run"])
    # build remote tar of only-existing rels
    exist_check = " ".join(f'[ -e {rbase}/{rel} ] && echo {rel};' for rel in rels)
    inner = f'cd {rbase} && tar cf - ' + " ".join(rels) + " 2>/dev/null"
    remote = f'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ~/.ssh/assa_guest assa@{vm} "{inner}"'
    cmd = SSH_BASE + [JUMP, remote]
    with (dest / "_sync.tar").open("wb") as fh:
        p = subprocess.run(cmd, stdout=fh, stderr=subprocess.PIPE)
    tarpath = dest / "_sync.tar"
    if p.returncode != 0 or tarpath.stat().st_size == 0:
        return {"run_id": rid, "status": "failed", "rc": p.returncode, "stderr": p.stderr.decode()[-300:]}
    x = subprocess.run(["tar", "xf", str(tarpath), "-C", str(dest)], stderr=subprocess.PIPE)
    tarpath.unlink(missing_ok=True)
    if x.returncode != 0:
        return {"run_id": rid, "status": "untar_failed", "stderr": x.stderr.decode()[-300:]}
    got = {rel: (dest / rel).exists() for rel in rels}
    return {"run_id": rid, "status": "ok" if all(got.values()) else "partial", "got": got}


def main():
    os.environ["SSH_AUTH_SOCK"] = "<HOME>/.ssh/codex-agent.sock"
    pop = json.loads((OUT / "PARTIAL_LOCKED_POPULATION.json").read_text())
    todo = list(rows(pop))
    results = []
    for i, r in enumerate(todo, 1):
        res = sync_one(r)
        results.append(res)
        print(f"[{i}/{len(todo)}] {res['status']:10} {r['run_id']}", flush=True)
    (OUT / "SYNC_REPORT.json").write_text(json.dumps(
        {"n": len(results), "ok": sum(r["status"] in ("ok", "cached") for r in results),
         "failed": [r for r in results if r["status"] not in ("ok", "cached")],
         "results": results}, indent=2) + "\n")
    print("SYNC done:", sum(r["status"] in ("ok", "cached") for r in results), "/", len(results))


if __name__ == "__main__":
    main()
