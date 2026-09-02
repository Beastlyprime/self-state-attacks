import pytest

from experiments.code.dataset_builder.extend_p2_clean_split import continuation_order


def test_continuation_preserves_frozen_draw_and_exhausts_unassigned_first() -> None:
    eligible = [f"T{i}" for i in range(12)]
    import random
    rng = random.Random(17)
    selected = rng.sample(eligible, 8)

    rows = continuation_order(
        eligible_task_ids=eligible,
        originally_selected=selected,
        seed=17,
        requested=5,
    )

    assert len(rows) == 5
    assert len({task for task, repeated in rows if not repeated}) == 4
    assert sum(repeated for _, repeated in rows) == 1
    assert not ({task for task, repeated in rows if not repeated} & set(selected))
    assert len({task for task, _ in rows}) == 5


def test_continuation_fails_if_parent_split_does_not_replay() -> None:
    with pytest.raises(ValueError, match="does not match"):
        continuation_order(
            eligible_task_ids=["a", "b", "c"],
            originally_selected=["a", "b"],
            seed=1,
            requested=1,
        )
