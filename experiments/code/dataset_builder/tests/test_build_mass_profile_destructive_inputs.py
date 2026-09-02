import pytest

from experiments.code.dataset_builder.build_mass_profile_destructive_inputs import (
    logical_class,
)


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("MEMORY.md", "Memory"),
        ("memory/2026-08-24.md", "Memory"),
        ("TOOLS.md", "Instruction"),
        ("HEARTBEAT.md", "Configuration"),
        ("openclaw.json", "Configuration"),
    ],
)
def test_logical_class_uses_canonical_state_schema(path, expected):
    assert logical_class(path) == expected


def test_logical_class_rejects_unbound_paths():
    with pytest.raises(ValueError, match="not bound"):
        logical_class("README.md")
