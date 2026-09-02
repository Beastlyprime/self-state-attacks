from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[4]
AGENT_ROOT = PROJECT_ROOT / "experiments" / "agent"
CODE_ROOT = PROJECT_ROOT / "experiments" / "code"
for path in (AGENT_ROOT, CODE_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from openclaw_core.workspace import ensure_agent_workspace
from dataset_builder.build_p2_clean_split import PROFILES, build


def test_builds_disjoint_warm_clean_split(tmp_path: Path) -> None:
    warm = tmp_path / "warm"
    ensure_agent_workspace(str(warm), mark_setup_done=True)
    (warm / "memory").mkdir(exist_ok=True)
    (warm / "memory" / "2026-08-19.md").write_text("prior clean state\n", encoding="utf-8")
    source_hash = hashlib.sha256((warm / "memory" / "2026-08-19.md").read_bytes()).hexdigest()

    output = tmp_path / "out"
    build(
        output_root=output,
        warm_workspaces={profile: warm for profile in PROFILES},
        seed=202608201,
        train_count=1,
        heldout_count=1,
        reserve_count=1,
        excluded_task_ids={"W1_C1_V1", "W3_C3_V3"},
    )

    split = json.loads((output / "split_manifest.json").read_text())
    manifest = json.loads((output / "input_root_manifest.json").read_text())
    source = json.loads((output / "source_manifest.json").read_text())
    assert source["case_count"] == 12
    assert len(source["case_source_sha256"]) == 12
    assert split["role_disjoint_task_ids"] is True
    assert len(split["train"]) == 4
    assert len(split["heldout_clean"]) == 4
    assert len(split["reserve_train"]) == 4
    assert len({row["task_id"] for rows in (split["train"], split["heldout_clean"], split["reserve_train"]) for row in rows}) == 12
    assert not ({"W1_C1_V1", "W3_C3_V3"} & {row["task_id"] for row in manifest["cases"]})

    for row in manifest["cases"]:
        case = json.loads((output / "cases" / row["case_id"] / "case.json").read_text())
        checkpoint = output / case["checkpoint"]["workspace"]
        assert (checkpoint / "memory" / "2026-08-19.md").is_file()
        assert hashlib.sha256((checkpoint / "memory" / "2026-08-19.md").read_bytes()).hexdigest() == source_hash
        assert case["source_provenance"]["warm_checkpoint_is_clean"] is True
        assert case["delivery"].get("task_seeds_preseeded_in_checkpoint") is not True
        assert case["delivery"]["fixture_process"] == "workspace seeder"
        assert case["split_role"] in {"train", "heldout_clean", "reserve_train"}
        assert case["attack"]["marker"] == "P2-CLEAN-NO-ATTACK"

