#!/usr/bin/env python3
"""Read-only two-hop pull of raw/capture.scap for the 55 attacks + 55 twins + gen2-60 heldout.
Streams each scap gzip-over-ssh into tier_c/<role>/<run_id>/capture.scap.gz. Resumable.
Never writes to the VMs.
"""
import json, os, subprocess
from pathlib import Path
from pathlib import Path as _Path
_REPO_ROOT = str(_Path(__file__).resolve().parents[3])

ARCH = Path(_REPO_ROOT + "/data/corpus-manifests")
JUMP = "<COLLECTOR_HOST>"
KEY = "<HOME>/.ssh/assa_guest"
os.environ["SSH_AUTH_SOCK"] = "<HOME>/.ssh/codex-agent.sock"

def remote_size(ip, path):
    inner = f"stat -c%s {path} 2>/dev/null || echo 0"
    remote = f"ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i {KEY} -o ConnectTimeout=25 assa@{ip} \"{inner}\""
    out = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=25", JUMP, remote],
                         capture_output=True).stdout.decode().strip()
    try: return int(out.splitlines()[-1])
    except: return 0

def pull(t):
    ip = t["vm_ip"]; scap = t["scap"]
    dest = ARCH / t["dest"]; dest.mkdir(parents=True, exist_ok=True)
    out = dest / "capture.scap.gz"
    rsz = remote_size(ip, scap)
    if rsz == 0:
        return {"run_id": t["run_id"], "role": t["role"], "vm": t["vm"], "status": "remote_missing", "remote_bytes": 0}
    meta = dest / ".remote_size"
    if out.exists() and meta.exists() and meta.read_text().strip() == str(rsz) and out.stat().st_size > 0:
        return {"run_id": t["run_id"], "role": t["role"], "vm": t["vm"], "status": "cached", "remote_bytes": rsz, "local_gz_bytes": out.stat().st_size}
    inner = f"gzip -c {scap} 2>/dev/null"
    remote = f"ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i {KEY} -o ConnectTimeout=30 assa@{ip} \"{inner}\""
    with out.open("wb") as fh:
        p = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=30", JUMP, remote],
                           stdout=fh, stderr=subprocess.PIPE)
    if p.returncode != 0 or out.stat().st_size == 0:
        return {"run_id": t["run_id"], "role": t["role"], "vm": t["vm"], "status": "failed", "remote_bytes": rsz, "stderr": p.stderr.decode()[-150:]}
    meta.write_text(str(rsz) + "\n")
    return {"run_id": t["run_id"], "role": t["role"], "vm": t["vm"], "status": "ok", "remote_bytes": rsz, "local_gz_bytes": out.stat().st_size}

def main():
    targets = json.loads((ARCH / "manifests" / "scap_targets.json").read_text())
    res = []
    for i, t in enumerate(targets, 1):
        r = pull(t); res.append(r)
        print(f"[{i}/{len(targets)}] {r['status']:14} {r.get('remote_bytes',0):>12} {t['role']:13} {t['run_id']}", flush=True)
    ok = sum(r["status"] in ("ok", "cached") for r in res)
    miss = [r for r in res if r["status"] == "remote_missing"]
    fail = [r for r in res if r["status"] not in ("ok", "cached", "remote_missing")]
    tot_remote = sum(r.get("remote_bytes", 0) for r in res)
    tot_gz = sum(r.get("local_gz_bytes", 0) for r in res if "local_gz_bytes" in r)
    (ARCH / "manifests" / "PULL_TIERC_SCAP_REPORT.json").write_text(json.dumps(
        {"n": len(res), "ok": ok, "remote_missing": miss, "failed": fail,
         "total_remote_bytes": tot_remote, "total_local_gz_bytes": tot_gz, "results": res}, indent=2) + "\n")
    print(f"TIER C scap done: {ok}/{len(res)} ok; remote_missing={len(miss)}; failed={len(fail)}; remote_total={tot_remote} gz_total={tot_gz}")

if __name__ == "__main__":
    main()
