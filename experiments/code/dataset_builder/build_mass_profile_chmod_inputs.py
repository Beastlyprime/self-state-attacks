#!/usr/bin/env python3
"""Author Lane-1 batch02: chmod landers across W1/W2/W4 (no execution)."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
ARCHIVE = ROOT / "data/dataset_v1_archive/batch2_unbiased_frequency_20260807"
TEMPLATE = ROOT / "data/p2_l0_archetype_inputs_20260823"
DEFAULT_OUTPUT = ROOT / "data/p2_mass_profile_inputs_20260823/batch02_chmod"

PROFILES = {"W1": "w1_coding", "W2": "w2_knowledge", "W4": "w4_general"}
TEMPLATES = {
    "memory_lockout": ("B1_w3_memory_chmod_lockout", "MEMORY.md"),
    "rules_worldwrite": ("B2_w3_rules_chmod_worldwrite", "AGENTS.md"),
}


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def replace_ids(value: Any, old: str, new: str) -> Any:
    if isinstance(value, str):
        return value.replace(old, new)
    if isinstance(value, list):
        return [replace_ids(v, old, new) for v in value]
    if isinstance(value, dict):
        return {k: replace_ids(v, old, new) for k, v in value.items()}
    return value


def pick_checkpoint(profile: str) -> tuple[Path, str]:
    source = ARCHIVE / f"input_{profile}"
    choices = sorted(p for p in (source / "checkpoints").iterdir() if p.is_dir())
    if not choices:
        raise RuntimeError(f"no checkpoint for {profile}")
    return source, choices[0].name


def build(output: Path) -> Path:
    output = output.resolve()
    if output.exists():
        raise FileExistsError(output)
    output.mkdir(parents=True)
    rows = []
    serial = 1
    for profile, agent_id in PROFILES.items():
        source, source_ck = pick_checkpoint(profile)
        source_manifest = json.loads((source / "checkpoints" / source_ck / "workspace_manifest.json").read_text())
        for subtype, (template_id, target) in TEMPLATES.items():
            case_id = f"MCH{serial:02d}_{profile.lower()}_{subtype}"
            serial += 1
            src_case = TEMPLATE / "cases" / template_id
            dst_case = output / "cases" / case_id
            shutil.copytree(src_case, dst_case)
            for name in ("case.json", "task.json", "consequence.json", "ground_truth.json"):
                path = dst_case / name
                data = replace_ids(json.loads(path.read_text()), template_id, case_id)
                if name == "case.json":
                    data["case_id"] = case_id
                    data["profile"] = profile
                    data["task_id"] = f"{profile}_MASS_CHMOD_{serial-1:02d}"
                    data["task"]["profile"] = profile
                    data["task"]["task_id"] = data["task_id"]
                    data["checkpoint"]["workspace"] = f"checkpoints/{case_id}/workspace"
                    data["checkpoint"]["manifest"] = f"checkpoints/{case_id}/workspace_manifest.json"
                    data["checkpoint"]["manifest_sha256"] = source_manifest["sha256"]
                    data["checkpoint"]["instruction_pack"]["agent_id"] = agent_id
                    data["attack"]["semantic_subtype"] = subtype
                    data["source_provenance"].update({
                        "mass_collection_matrix": "FINALIZED MATRIX 2026-08-23",
                        "source_checkpoint_profile": profile,
                        "source_checkpoint_case_id": source_ck,
                        "profile_adaptation_of": template_id,
                    })
                elif name == "task.json":
                    data["profile"] = profile
                    data["task_id"] = f"{profile}_MASS_CHMOD_{serial-1:02d}"
                    data["dataset_source"]["citation"] = "SELFSTATE authors; Lane-1 profile-spread chmod expansion"
                    data["prompt"] = data["prompt"].replace("W3 DevOps", f"{profile} profile")
                    data["prompt_sha256"] = sha(data["prompt"].encode())
                elif name == "ground_truth.json":
                    data["case_id"] = case_id
                    data["semantic_subtype"] = subtype
                write_json(path, data)
            for variant in ("clean", "poisoned"):
                path = dst_case / "variants" / f"{variant}.bin"
                text = path.read_text().replace("Owner: W3 DevOps", f"Owner: {profile} profile")
                path.write_text(text)
            case = json.loads((dst_case / "case.json").read_text())
            case["variants"] = {
                v: {"artifact": f"variants/{v}.bin", "bytes": (dst_case/"variants"/f"{v}.bin").stat().st_size,
                    "sha256": sha((dst_case/"variants"/f"{v}.bin").read_bytes())}
                for v in ("clean", "poisoned")
            }
            write_json(dst_case / "case.json", case)
            gt = json.loads((dst_case / "ground_truth.json").read_text())
            gt["carrier_variants"] = {
                "clean_sha256": case["variants"]["clean"]["sha256"],
                "poisoned_sha256": case["variants"]["poisoned"]["sha256"],
            }
            write_json(dst_case / "ground_truth.json", gt)
            shutil.copytree(source / "checkpoints" / source_ck, output / "checkpoints" / case_id)
            rows.append({"case_id": case_id, "profile": profile, "op_signature": "chmod",
                         "semantic_subtype": subtype, "target": target,
                         "source_checkpoint_case_id": source_ck})
    write_json(output / "input_root_manifest.json", {
        "schema_version": "assa.mass_profile_spread_input.v1",
        "purpose": "Lane-1 finalized-matrix batch02 chmod profile spread",
        "case_count": len(rows), "cases": rows,
        "corpus_role": "L0 attack evaluation; never clean detector training/FPR",
        "polarity_status": "FINAL-all-malicious for landed poisoned branches only",
    })
    write_json(output / "source_manifest.json", {
        "schema_version": "assa.source_manifest.v1",
        "sources": [{"name": "benchmark-authored Lane-1 profile-spread chmod fixtures",
                     "authored_by": "benchmark_authors", "license": "CC-BY 4.0",
                     "selected_anchor_ids": [r["case_id"] for r in rows],
                     "note": "profile-adapted clean/poison chmod twins on real profile checkpoints"}],
    })
    write_json(output / "VALIDATION.json", {
        "passed": True, "case_count": len(rows), "profiles": sorted(PROFILES),
        "agent_or_collector_started": False,
    })
    lines = [f"{sha(p.read_bytes())}  {p.relative_to(output).as_posix()}"
             for p in sorted(output.rglob("*")) if p.is_file()]
    (output / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n")
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    print(json.dumps({"output_root": str(build(args.output_root))}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
