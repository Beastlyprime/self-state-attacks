#!/usr/bin/env python3
"""Read-only two-hop tar pull of graph/snapshot feature subpaths for the 44 D-A pairs.
Pulls per run dir: graph/, state_snapshots/, runtime_state_capture.json, ground_truth.json.
Never writes to the VMs. Resumable: skips a run whose graph dir already has files locally.
Usage: python3 pull_graphs.py            (pulls TIER B graphs, both roles)
"""
import json, os, subprocess, sys
from pathlib import Path
from pathlib import Path as _Path
_REPO_ROOT = str(_Path(__file__).resolve().parents[3])

ARCH = Path(_REPO_ROOT + "/data/corpus-manifests")
JUMP = "<COLLECTOR_HOST>"
KEY = "<HOME>/.ssh/assa_guest"
os.environ["SSH_AUTH_SOCK"] = "<HOME>/.ssh/codex-agent.sock"

SUBPATHS = ["graph", "state_snapshots", "runtime_state_capture.json", "ground_truth.json"]

def pull(run_id, vm_ip, rundir, dest):
    marker = dest / "graph"
    if marker.exists() and any(marker.rglob("*.jsonl")):
        return {"run_id": run_id, "status": "cached"}
    dest.mkdir(parents=True, exist_ok=True)
    inner = f"cd {rundir} && tar czf - " + " ".join(SUBPATHS) + " 2>/dev/null"
    remote = f"ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i {KEY} -o ConnectTimeout=30 assa@{vm_ip} \"{inner}\""
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=30", JUMP, remote]
    tgz = dest / "_g.tgz"
    with tgz.open("wb") as fh:
        p = subprocess.run(cmd, stdout=fh, stderr=subprocess.PIPE)
    if p.returncode != 0 or tgz.stat().st_size == 0:
        tgz.unlink(missing_ok=True)
        return {"run_id": run_id, "status": "failed", "rc": p.returncode, "stderr": p.stderr.decode()[-200:]}
    x = subprocess.run(["tar", "xzf", str(tgz), "-C", str(dest)], stderr=subprocess.PIPE)
    tgz.unlink(missing_ok=True)
    if x.returncode != 0:
        return {"run_id": run_id, "status": "untar_failed", "stderr": x.stderr.decode()[-200:]}
    has_graph = (dest / "graph").exists()
    return {"run_id": run_id, "status": "ok" if has_graph else "no_graph"}

def main():
    pairs = json.loads((ARCH / "manifests" / "da44_source_paths.json").read_text())
    results = {"attacks": [], "twins": []}
    for i, p in enumerate(pairs, 1):
        ra = pull(p["attack_run_id"], p["vm_ip"], p["attack_dir"], ARCH / "tier_b" / "attacks" / p["attack_run_id"])
        results["attacks"].append(ra)
        rt = pull(p["twin_run_id"], p["vm_ip"], p["twin_dir"], ARCH / "tier_b" / "twins" / p["twin_run_id"])
        results["twins"].append(rt)
        print(f"[{i}/{len(pairs)}] vm{p['vm']} A:{ra['status']:8} T:{rt['status']:8} {p['pair_id']}", flush=True)
    okA = sum(r["status"] in ("ok", "cached") for r in results["attacks"])
    okT = sum(r["status"] in ("ok", "cached") for r in results["twins"])
    (ARCH / "manifests" / "PULL_TIERB_GRAPHS_REPORT.json").write_text(json.dumps(
        {"okA": okA, "okT": okT, "n": len(pairs),
         "failed": [r for role in results.values() for r in role if r["status"] not in ("ok", "cached")],
         "results": results}, indent=2) + "\n")
    print(f"TIER B graphs done: attacks {okA}/{len(pairs)}, twins {okT}/{len(pairs)}")

if __name__ == "__main__":
    main()
