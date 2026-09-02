from pathlib import Path

from experiments.code.measurement.stage_g_harness.p2_aide_fpr_gen2 import (
    apply_content_delta,
)


def test_apply_content_delta_leaves_identical_files_untouched(tmp_path: Path) -> None:
    snapshot, materialized = tmp_path / "snapshot", tmp_path / "materialized"
    snapshot.mkdir(); materialized.mkdir()
    (snapshot / "same").write_bytes(b"same")
    (materialized / "same").write_bytes(b"same")
    (snapshot / "changed").write_bytes(b"after")
    (materialized / "changed").write_bytes(b"before")
    (snapshot / "added").write_bytes(b"new")
    (materialized / "removed").write_bytes(b"old")
    same_before = (materialized / "same").stat().st_mtime_ns
    delta = apply_content_delta(snapshot, materialized)
    assert (materialized / "same").stat().st_mtime_ns == same_before
    assert (materialized / "changed").read_bytes() == b"after"
    assert not (materialized / "removed").exists()
    assert delta["untouched_byte_identical"] == ["same"]
    assert delta["content_changed"] == ["changed"]
    assert delta["added"] == ["added"]
    assert delta["removed"] == ["removed"]
