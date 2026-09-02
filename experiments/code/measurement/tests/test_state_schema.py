import pytest

from attacks.canonical_v4 import CANONICAL_ATTACKS
from workload import taxonomy as tax
from workload.state_schema import DEFAULT_STATE_SCHEMA, StateSchema


def test_default_schema_resolves_logical_roles_and_legacy_paths():
    assert DEFAULT_STATE_SCHEMA.adapter == "openclaw-compatible"
    assert tax.canonical_path("MEMORY.md") == "workspace/MEMORY.md"
    assert tax.role_of("MEMORY.md") == "durable global memory"
    assert tax.role_of("memory/2026-08-23.md") == "episodic memory"
    assert tax.role_of("memory/project.md") == "topic-scoped memory"
    assert tax.role_of("SOUL.md") == "identity/persona"
    assert tax.role_of("openclaw.json") == "runtime parameters"
    assert (
        tax.bucket_key("workspace/memory/2026-08-23.md")
        == "workspace/memory/*.md"
    )


def test_canonical_attacks_retain_logical_object_metadata():
    durable = CANONICAL_ATTACKS["Mem-M1-G4-MEM"]
    episodic = CANONICAL_ATTACKS["Mem-M1-G4-MSUB"]
    assert durable.state_object_id == "memory.durable_global"
    assert durable.target_role == "durable global memory"
    assert episodic.state_object_id == "memory.episodic"
    assert episodic.target_role == "episodic memory"

def test_schema_can_bind_the_same_roles_to_an_alternate_agent_layout():
    schema = StateSchema.from_mapping(
        {
            "schema_version": 1,
            "schema_id": "test.alternate.v1",
            "adapter": "alternate-agent",
            "objects": [
                {
                    "id": "instruction.behavioral_policy",
                    "layer": "instruction",
                    "role": "behavioral policy",
                    "scope": "workspace",
                    "consumption": "prompt bootstrap",
                    "paths": ["state/policy.txt"],
                },
                {
                    "id": "memory.durable_global",
                    "layer": "memory",
                    "role": "durable global memory",
                    "scope": "agent",
                    "consumption": "runtime retrieval",
                    "paths": ["state/profile_memory.json"],
                },
                {
                    "id": "memory.episodic",
                    "layer": "memory",
                    "role": "episodic memory",
                    "scope": "session sequence",
                    "consumption": "runtime retrieval",
                    "paths": [],
                    "globs": ["state/sessions/*.jsonl"],
                    "bucket": "state/sessions/*.jsonl",
                },
                {
                    "id": "config.runtime",
                    "layer": "config",
                    "role": "runtime parameters",
                    "scope": "deployment",
                    "consumption": "runtime parser",
                    "paths": ["state/settings.toml"],
                },
            ],
        }
    )

    assert schema.layer_of("state/profile_memory.json") == "memory"
    assert schema.role_of("state/sessions/run-7.jsonl") == "episodic memory"
    assert schema.canonical_path("state/settings.toml") == "state/settings.toml"
    assert (
        schema.bucket_key("state/sessions/run-7.jsonl")
        == "state/sessions/*.jsonl"
    )
    assert schema.canonical_path("workspace/MEMORY.md") is None


def test_schema_rejects_duplicate_exact_bindings():
    duplicate = {
        "schema_version": 1,
        "schema_id": "test.duplicate.v1",
        "adapter": "bad-adapter",
        "objects": [
            {
                "id": "memory.a",
                "layer": "memory",
                "role": "a",
                "scope": "agent",
                "consumption": "read",
                "paths": ["state/memory"],
            },
            {
                "id": "memory.b",
                "layer": "memory",
                "role": "b",
                "scope": "agent",
                "consumption": "read",
                "paths": ["state/memory"],
            },
        ],
    }
    with pytest.raises(ValueError, match="unique"):
        StateSchema.from_mapping(duplicate)
