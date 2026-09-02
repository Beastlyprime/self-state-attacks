#!/usr/bin/env python3
"""Build P2 gen2 clean input roots without mutating gen1 artifacts.

The gen2 held-out expansion intentionally repeats the already preregistered
held-out clean tasks rather than promoting training/reserve tasks into held-out.
That preserves the gen1 train/held-out task boundary while increasing the
run-level held-out sample size.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any


PROFILES = ("W1", "W2", "W3", "W4")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def tree_sha(root: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        rel = path.relative_to(root).as_posix()
        size = path.stat().st_size
        h = sha256_file(path)
        digest.update(f"{rel}\0{size}\0{h}\n".encode())
        rows.append({"path": rel, "bytes": size, "sha256": h})
    return {"tree_sha256": digest.hexdigest(), "file_count": len(rows), "files": rows}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def rewrite_case_ids(value: Any, *, old: str, new: str) -> Any:
    if isinstance(value, dict):
        out = {}
        for key, child in value.items():
            if key == "case_id" and child == old:
                out[key] = new
            elif isinstance(child, str):
                out[key] = child.replace(old, new)
            else:
                out[key] = rewrite_case_ids(child, old=old, new=new)
        return out
    if isinstance(value, list):
        return [rewrite_case_ids(child, old=old, new=new) for child in value]
    if isinstance(value, str):
        return value.replace(old, new)
    return value


def copy_case(source_root: Path, output_root: Path, old_case_id: str, new_case_id: str,
              *, role: str, repeat_index: int, source_note: str) -> dict[str, Any]:
    source_case_dir = source_root / "cases" / old_case_id
    source_checkpoint_dir = source_root / "checkpoints" / old_case_id
    if not source_case_dir.is_dir():
        raise FileNotFoundError(source_case_dir)
    if not source_checkpoint_dir.is_dir():
        raise FileNotFoundError(source_checkpoint_dir)
    dest_case_dir = output_root / "cases" / new_case_id
    dest_checkpoint_dir = output_root / "checkpoints" / new_case_id
    shutil.copytree(source_case_dir, dest_case_dir)
    shutil.copytree(source_checkpoint_dir, dest_checkpoint_dir)

    case = rewrite_case_ids(load_json(dest_case_dir / "case.json"), old=old_case_id, new=new_case_id)
    case["case_id"] = new_case_id
    case["split_role"] = role
    case["gen2_repeat"] = {
        "enabled": True,
        "repeat_index": repeat_index,
        "source_case_id": old_case_id,
        "source_root": str(source_root),
        "selection": source_note,
        "independence_boundary": (
            "The runtime copies the pristine checkpoint into a fresh run workspace; "
            "repeat identity is a run-level replicate, not a reused run artifact."
        ),
    }
    case.setdefault("source_provenance", {})["gen2_source_case_id"] = old_case_id
    case["source_provenance"]["gen2_selection"] = source_note
    write_json(dest_case_dir / "case.json", case)

    for name in ("task.json", "consequence.json"):
        path = dest_case_dir / name
        if path.is_file():
            write_json(path, rewrite_case_ids(load_json(path), old=old_case_id, new=new_case_id))

    checkpoint_manifest = dest_checkpoint_dir / "workspace_manifest.json"
    row = {
        "case_id": new_case_id,
        "source_case_id": old_case_id,
        "task_id": case["task_id"],
        "profile": case["profile"],
        "split_role": role,
        "repeat_index": repeat_index,
        "carrier_path": case.get("carrier_path"),
        "delivery_channel": (case.get("delivery") or {}).get("channel"),
        "checkpoint_manifest_sha256": sha256_file(checkpoint_manifest),
        "source_root": str(source_root),
    }
    return row


def heldout_repeats(args: argparse.Namespace) -> int:
    output = args.output_root
    if output.exists():
        raise FileExistsError(output)
    output.mkdir(parents=True)
    split = load_json(args.split_root / "split_manifest.json")
    user_message_by_task: dict[str, tuple[Path, str]] = {}
    if args.w4_user_message_root:
        for case_file in sorted((args.w4_user_message_root / "cases").glob("*/case.json")):
            case = load_json(case_file)
            user_message_by_task[case["task_id"]] = (args.w4_user_message_root, case["case_id"])

    rows: list[dict[str, Any]] = []
    for source in split["heldout_clean"]:
        task_id = source["task_id"]
        source_root = args.split_root
        old_case_id = source["case_id"]
        if source["profile"] == "W4" and task_id in user_message_by_task:
            source_root, old_case_id = user_message_by_task[task_id]
        for repeat_index in args.repeat_indexes:
            new_case_id = f"{old_case_id}_gen2_holdout_r{repeat_index:02d}"
            rows.append(copy_case(
                source_root, output, old_case_id, new_case_id,
                role="heldout_clean_gen2_repeat",
                repeat_index=repeat_index,
                source_note="locked gen1 heldout task repeated for gen2 FPR sample size; no train/reserve task promoted",
            ))

    counts = {profile: sum(1 for row in rows if row["profile"] == profile) for profile in PROFILES}
    manifest = {
        "schema_version": "assa.p2_gen2_heldout_repeat_input.v1",
        "role": "gen2_heldout_clean_expansion_inputs",
        "source_split_root": str(args.split_root),
        "source_split_sha256": sha256_file(args.split_root / "split_manifest.json"),
        "w4_user_message_root": str(args.w4_user_message_root) if args.w4_user_message_root else None,
        "repeat_indexes": args.repeat_indexes,
        "selection": "repeat locked gen1 heldout task IDs only; training/reserve task IDs remain excluded from held-out",
        "counts": {"total": len(rows), "by_profile": counts},
        "cases": rows,
    }
    write_json(output / "input_root_manifest.json", manifest)
    write_json(output / "regeneration_provenance.json", manifest)
    write_json(output / "source_manifest.json", {
        "schema_version": "assa.p2_gen2_heldout_repeat_source_manifest.v1",
        "role": manifest["role"],
        "source_split_root": manifest["source_split_root"],
        "source_split_sha256": manifest["source_split_sha256"],
        "w4_user_message_root": manifest["w4_user_message_root"],
        "selection": manifest["selection"],
        "case_count": len(rows),
        "case_source": {
            row["case_id"]: {
                "source_case_id": row["source_case_id"],
                "source_root": row["source_root"],
                "task_id": row["task_id"],
                "profile": row["profile"],
                "repeat_index": row["repeat_index"],
            }
            for row in rows
        },
    })
    validation = {
        "schema_version": "assa.p2_gen2_input_validation.v1",
        "checks": {
            "expected_total_40": len(rows) == 40,
            "expected_10_per_profile": counts == {profile: 10 for profile in PROFILES},
            "unique_case_ids": len({row["case_id"] for row in rows}) == len(rows),
            "no_source_case_id_equals_new_case_id": all(row["case_id"] != row["source_case_id"] for row in rows),
        },
    }
    validation["passed"] = all(validation["checks"].values())
    write_json(output / "VALIDATION.json", validation)
    sums = tree_sha(output)
    (output / "SHA256SUMS").write_text(
        "".join(f"{row['sha256']}  {row['path']}\n" for row in sums["files"] if row["path"] != "SHA256SUMS"),
        encoding="utf-8",
    )
    print(json.dumps({"output_root": str(output.resolve()), "validation_passed": validation["passed"], "counts": manifest["counts"]}, sort_keys=True))
    return 0 if validation["passed"] else 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    heldout = sub.add_parser("heldout-repeats")
    heldout.add_argument("--split-root", required=True, type=Path)
    heldout.add_argument("--w4-user-message-root", type=Path)
    heldout.add_argument("--output-root", required=True, type=Path)
    heldout.add_argument("--repeat-indexes", type=int, nargs="+", default=[2, 3])
    args = parser.parse_args()
    if args.command == "heldout-repeats":
        return heldout_repeats(args)
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
