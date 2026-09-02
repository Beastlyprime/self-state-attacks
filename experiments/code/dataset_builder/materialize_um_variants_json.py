#!/usr/bin/env python3
"""Materialize user_message variant JSON records from a mass-um input root.

Context (2026-08-24, supervisor-run takeover): build_mass_um_profile_inputs.py
writes only variants/*.bin (the composed message text). The five-source collector
(paired_live_four_source.py::_load_user_message_variant) requires variants/*.json in
the `assa.user_message_variant.v1` schema (as produced by the content-append
builder and the admitted C511/C513/C515 cases). This additive step wraps each
already-authored .bin message into that envelope WITHOUT changing the message text,
so clean/poisoned single-slot symmetry is preserved by construction.

It does not modify build_mass_um_profile_inputs.py or any existing input file other
than adding variants/{clean,poisoned}.json beside the existing .bin files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _envelope(case_id: str, variant: str, message: str, semantic_slot_id: str) -> dict:
    raw = message.encode("utf-8")
    return {
        "schema_version": "assa.user_message_variant.v1",
        "case_id": case_id,
        "variant": variant,
        "channel": "user_message",
        "message": message,
        "message_sha256": _sha(raw),
        "message_bytes": len(raw),
        "semantic_slot_id": semantic_slot_id,
        "slot_label": variant,
        "filesystem_artifact_delivered_to_workspace": False,
        "clean_poisoned_symmetry": "same task message and carrier slot; only the embedded clean/poisoned fixture differs",
    }


def materialize(input_root: Path) -> list[dict]:
    results: list[dict] = []
    cases_dir = input_root / "cases"
    for case_dir in sorted(p for p in cases_dir.iterdir() if p.is_dir()):
        case = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
        channel = (case.get("delivery") or {}).get("channel") or case.get("delivery_channel")
        if channel != "user_message":
            continue
        case_id = case["case_id"]
        subtype = (case.get("attack") or {}).get("semantic_subtype") or "user_message_slot"
        semantic_slot_id = f"{case_id}_{subtype}"
        shas = {}
        for variant in ("clean", "poisoned"):
            bin_path = case_dir / "variants" / f"{variant}.bin"
            if not bin_path.exists():
                raise SystemExit(f"missing {bin_path}")
            message = bin_path.read_text(encoding="utf-8")
            row = _envelope(case_id, variant, message, semantic_slot_id)
            out = case_dir / "variants" / f"{variant}.json"
            out.write_text(json.dumps(row, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            # verify loader's integrity re-check will pass
            assert row["message_sha256"] == _sha(message.encode("utf-8"))
            shas[variant] = row["message_sha256"]
        if shas["clean"] == shas["poisoned"]:
            raise SystemExit(f"{case_id}: clean and poisoned message identical — single-slot difference lost")
        results.append({"case_id": case_id, "clean_sha": shas["clean"], "poisoned_sha": shas["poisoned"]})
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input-root", required=True)
    args = ap.parse_args()
    res = materialize(Path(args.input_root).resolve())
    print(json.dumps({"materialized_cases": len(res), "cases": res}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
