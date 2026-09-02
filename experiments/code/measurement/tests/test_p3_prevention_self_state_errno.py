from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[4] / "experiments" / "code"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from measurement import p3_prevention_self_state_errno as p3


def _row(mechanism: str, marker_errno: int | None, legit_errno: int | None) -> dict:
    return {
        "mechanism": mechanism,
        "paper_admissible": marker_errno is not None and legit_errno is not None,
        "error": None,
        "marker_write": {
            "probe": {
                "errno": marker_errno,
                "errno_name": "EACCES" if marker_errno == 13 else ("EPERM" if marker_errno == 1 else None),
                "write_return": None if marker_errno is not None else 4,
            }
        },
        "legitimate_update": {
            "probe": {
                "errno": legit_errno,
                "errno_name": "EACCES" if legit_errno == 13 else ("EPERM" if legit_errno == 1 else None),
                "write_return": None if legit_errno is not None else 4,
            }
        },
    }


def test_summary_tracks_collateral_separately_from_marker_block() -> None:
    summary = p3._summarize([_row("dac", 13, 13), _row("landlock", 13, None)])

    dac = next(row for row in summary["by_mechanism"] if row["mechanism"] == "dac")
    landlock = next(row for row in summary["by_mechanism"] if row["mechanism"] == "landlock")

    assert dac["marker_blocked"] is True
    assert dac["legitimate_update_blocked_collateral"] is True
    assert dac["same_errno_for_marker_and_legitimate"] is True
    assert landlock["paper_admissible"] is False
    assert summary["all_mechanisms_admissible"] is False


def test_ima_is_not_counted_in_collateral_aggregate() -> None:
    summary = p3._summarize([_row("dac", 13, 13)])

    assert summary["ima_excluded_from_collateral"] is True
    assert [row["mechanism"] for row in summary["by_mechanism"]] == ["dac"]


def test_writer_script_reports_errno_from_real_open(tmp_path: Path) -> None:
    writer = tmp_path / "writer.py"
    target = tmp_path / "state.md"
    target.write_text("base\n", encoding="utf-8")
    p3._writer_script(writer)

    import subprocess

    result = subprocess.run(
        [sys.executable, str(writer), str(target), "marker_write", p3.MARKER, "x\n"],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert p3.MARKER in result.stdout
    assert target.read_text(encoding="utf-8").endswith("x\n")
