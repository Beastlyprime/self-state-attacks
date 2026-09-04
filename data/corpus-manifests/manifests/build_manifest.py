#!/usr/bin/env python3
"""Build ARCHIVE_MANIFEST.json + ARCHIVE_SHA256SUMS.txt for the durable archive.
Run AFTER all tiers are pulled. Computes sha256 for every file under the archive.
"""
import json, hashlib, os, datetime
from pathlib import Path
from pathlib import Path as _Path
_REPO_ROOT = str(_Path(__file__).resolve().parents[3])

ARCH = Path(_REPO_ROOT + "/data/corpus-manifests")

def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()

def tree_stats(root):
    n = 0; sz = 0
    for dp, _, fs in os.walk(root):
        for f in fs:
            fp = Path(dp) / f
            if fp.is_file():
                n += 1; sz += fp.stat().st_size
    return n, sz

def main():
    sums_path = ARCH / "ARCHIVE_SHA256SUMS.txt"
    lines = []
    total_files = 0; total_bytes = 0
    for dp, _, fs in os.walk(ARCH):
        for f in sorted(fs):
            fp = Path(dp) / f
            if fp == sums_path or fp.name == "ARCHIVE_MANIFEST.json":
                continue
            if not fp.is_file():
                continue
            rel = fp.relative_to(ARCH)
            lines.append(f"{sha256(fp)}  {rel}")
            total_files += 1; total_bytes += fp.stat().st_size
    sums_path.write_text("\n".join(lines) + "\n")

    tiers = {}
    for sub in ["tier_a", "tier_b", "tier_c"]:
        n, sz = tree_stats(ARCH / sub)
        tiers[sub] = {"files": n, "bytes": sz, "gb": round(sz / 1e9, 3)}
    # per-subdir counts
    def cnt(p):
        d = ARCH / p
        return len([x for x in d.iterdir()]) if d.exists() else 0

    da = json.loads((ARCH / "manifests" / "da44_source_paths.json").read_text())
    cs = json.loads((ARCH / "manifests" / "cseries11_source_paths.json").read_text())
    scap_rep = json.loads((ARCH / "manifests" / "PULL_TIERC_SCAP_REPORT.json").read_text()) if (ARCH / "manifests" / "PULL_TIERC_SCAP_REPORT.json").exists() else {}

    manifest = {
        "archive": str(ARCH),
        "created": datetime.datetime.utcnow().isoformat() + "Z",
        "purpose": "Durable <ANALYSIS_HOST>-local persistence of irreplaceable P2 measurement data (VM/job-tmp were ephemeral).",
        "two_hop_source": "<COLLECTOR_HOST> -> assa@<GUEST_HOSTS> (read-only)",
        "totals": {"files": total_files, "bytes": total_bytes, "gb": round(total_bytes / 1e9, 3)},
        "tiers": tiers,
        "tier_a": {
            "freezes": {"src_host": "<GUEST_HOST_A>", "src_path": "<GUEST_HOME>/derived_results/p2_gen2_clean_20260822/freezes/",
                        "files": cnt("tier_a/freezes")},
            "job_reports": {"src": "<SCRATCH>", "files": cnt("tier_a/job_reports")},
            "drivers": {"src": "<SCRATCH>", "files": cnt("tier_a/drivers")},
            "local_result_refs": {"note": "snapshot of top-level manifests/tables from p2_headtohead_detectors_20260825 + p2_supervised_arm_expanded_20260825 (excludes FINAL_3POOL_* live files)",
                                  "headtohead_files": cnt("tier_a/local_result_refs/p2_headtohead_detectors_20260825"),
                                  "supervised_files": cnt("tier_a/local_result_refs/p2_supervised_arm_expanded_20260825")},
        },
        "tier_b": {
            "attacks_44_DA": {"runs": cnt("tier_b/attacks"), "src_hosts": ".91 (38) + .69 (6)",
                              "subpaths": "graph/{normalized,reattributed,libsinsp}, state_snapshots, runtime_state_capture.json, ground_truth.json",
                              "source_manifest": "manifests/da44_source_paths.json"},
            "twins_44_DA": {"runs": cnt("tier_b/twins"), "source_manifest": "manifests/da44_source_paths.json"},
            "attacks_lockedpop_cseries_11": {"runs": cnt("tier_b/attacks_lockedpop_cseries"),
                              "provenance": "best_effort: pulled from underlying source generation on .91; exact match to b1b2 locked-pop derivation input NOT verified",
                              "source_manifest": "manifests/cseries11_source_paths.json"},
            "twins_lockedpop_cseries_11": {"runs": cnt("tier_b/twins_lockedpop_cseries")},
            "clean_train_gen2_176": {"runs": cnt("tier_b/clean_train"), "src_host": "<GUEST_HOST_A>",
                              "note": "gen2 clean training feature files (graph + state_snapshots); already pulled by exec agent into job-tmp/pools, copied here for durability",
                              "source_manifest": "manifests/../../ (pool_runs.json in tier_a/job_reports)"},
            "clean_heldout_gen2_60": {"runs": cnt("tier_b/clean_heldout"), "src_host": "<GUEST_HOST_A>"},
        },
        "tier_c": {
            "scap_format": "each capture.scap streamed gzip-over-ssh -> capture.scap.gz (+ .remote_size sidecar = uncompressed remote size)",
            "attacks": {"runs": cnt("tier_c/attacks")},
            "twins": {"runs": cnt("tier_c/twins")},
            "clean_heldout": {"runs": cnt("tier_c/clean_heldout")},
            "pull_report": "manifests/PULL_TIERC_SCAP_REPORT.json",
            "scap_ok": scap_rep.get("ok"), "scap_remote_missing": len(scap_rep.get("remote_missing", [])),
            "scap_failed": len(scap_rep.get("failed", [])),
            "total_remote_uncompressed_bytes": scap_rep.get("total_remote_bytes"),
            "total_local_gz_bytes": scap_rep.get("total_local_gz_bytes"),
        },
        "sha256sums": "ARCHIVE_SHA256SUMS.txt (covers every file in this archive)",
    }
    (ARCH / "ARCHIVE_MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest["totals"], indent=2))
    print("tiers:", json.dumps(tiers))
    print("wrote ARCHIVE_MANIFEST.json and ARCHIVE_SHA256SUMS.txt (", total_files, "files )")

if __name__ == "__main__":
    main()
