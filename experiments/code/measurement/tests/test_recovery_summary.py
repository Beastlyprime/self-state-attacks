from measurement.recovery_real import _summary


def test_summary_ignores_failed_restore_without_elapsed_time() -> None:
    rows = [
        {
            "paper_admissible": True,
            "file_recovery_success": True,
            "semantic_health_success": True,
            "snapshot": {"elapsed_ns": 10},
            "restore": {"verified": True, "elapsed_ns": 20},
        },
        {
            "paper_admissible": True,
            "file_recovery_success": False,
            "semantic_health_success": None,
            "snapshot": {"elapsed_ns": 30},
            "restore": {"verified": False, "error": "snapshot unavailable"},
        },
    ]

    result = _summary(rows)

    assert result["paper_admissible_scenarios"] == 2
    assert result["file_recovery_rate"] == 0.5
    assert result["mean_snapshot_elapsed_ns"] == 20
    assert result["mean_restore_elapsed_ns"] == 20
