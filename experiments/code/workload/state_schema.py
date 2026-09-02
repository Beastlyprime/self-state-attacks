"""Logical self-state schema for file-backed agent adapters.

The benchmark operates on logical state objects. A schema maps those objects
to the concrete paths used by one agent implementation. The shipped default
schema describes the OpenClaw-compatible adapter, but callers can load another
mapping without changing code that relies on workload.taxonomy.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Mapping, Optional


SUPPORTED_LAYERS = frozenset({"instruction", "memory", "config"})


def _strings(value: Any, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise ValueError(f"{field} must be a list of non-empty strings")
    return tuple(value)


def _path_candidates(path: str) -> tuple[str, ...]:
    """Return normalized path forms that a platform manifest may bind."""
    if not path:
        return ()
    normalized = path.replace("\\", "/")
    if normalized.startswith("./"):
        normalized = normalized[2:]

    candidates: list[str] = []
    marker = "/workspace/"
    if marker in normalized:
        candidates.append("workspace/" + normalized.split(marker, 1)[1])

    relative = normalized.lstrip("/")
    candidates.append(relative)
    if not relative.startswith("workspace/"):
        candidates.append(f"workspace/{relative}")

    return tuple(dict.fromkeys(candidates))


@dataclass(frozen=True)
class StateObjectSpec:
    """One logical state role and its concrete bindings in an adapter."""

    object_id: str
    layer: str
    role: str
    scope: str
    consumption: str
    paths: tuple[str, ...]
    globs: tuple[str, ...]
    bucket: Optional[str] = None

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "StateObjectSpec":
        required = ("id", "layer", "role", "scope", "consumption")
        missing = [
            key
            for key in required
            if not isinstance(raw.get(key), str) or not raw[key]
        ]
        if missing:
            raise ValueError(
                f"state object has missing string fields: {', '.join(missing)}"
            )
        layer = str(raw["layer"])
        if layer not in SUPPORTED_LAYERS:
            raise ValueError(f"unsupported self-state layer: {layer}")
        paths = _strings(raw.get("paths"), "paths")
        globs = _strings(raw.get("globs"), "globs")
        if not paths and not globs:
            raise ValueError(f"state object {raw['id']} has no path bindings")
        bucket = raw.get("bucket")
        if bucket is not None and (not isinstance(bucket, str) or not bucket):
            raise ValueError("bucket must be a non-empty string when present")
        return cls(
            object_id=str(raw["id"]),
            layer=layer,
            role=str(raw["role"]),
            scope=str(raw["scope"]),
            consumption=str(raw["consumption"]),
            paths=paths,
            globs=globs,
            bucket=bucket,
        )


@dataclass(frozen=True)
class StateMatch:
    spec: StateObjectSpec
    canonical_path: str


@dataclass(frozen=True)
class StateSchema:
    """Validated mapping from logical self-state roles to concrete paths."""

    schema_id: str
    adapter: str
    objects: tuple[StateObjectSpec, ...]

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "StateSchema":
        if raw.get("schema_version") != 1:
            raise ValueError("unsupported self-state schema version")
        schema_id = raw.get("schema_id")
        adapter = raw.get("adapter")
        if not isinstance(schema_id, str) or not schema_id:
            raise ValueError("schema_id must be a non-empty string")
        if not isinstance(adapter, str) or not adapter:
            raise ValueError("adapter must be a non-empty string")
        raw_objects = raw.get("objects")
        if not isinstance(raw_objects, list) or not raw_objects:
            raise ValueError("self-state schema must contain objects")
        objects = tuple(StateObjectSpec.from_mapping(item) for item in raw_objects)

        object_ids = [obj.object_id for obj in objects]
        if len(object_ids) != len(set(object_ids)):
            raise ValueError("self-state object IDs must be unique")
        exact_paths = [path for obj in objects for path in obj.paths]
        if len(exact_paths) != len(set(exact_paths)):
            raise ValueError("exact path bindings must be unique")
        return cls(schema_id=schema_id, adapter=adapter, objects=objects)

    def object(self, object_id: str) -> StateObjectSpec:
        for spec in self.objects:
            if spec.object_id == object_id:
                return spec
        raise KeyError(object_id)

    def exact_paths(self, layer: Optional[str] = None) -> tuple[str, ...]:
        return tuple(
            path
            for spec in self.objects
            if layer is None or spec.layer == layer
            for path in spec.paths
        )

    def match(self, path: str) -> Optional[StateMatch]:
        candidates = _path_candidates(path)
        for candidate in candidates:
            for spec in self.objects:
                if candidate in spec.paths:
                    return StateMatch(spec=spec, canonical_path=candidate)
        for candidate in candidates:
            for spec in self.objects:
                if any(fnmatchcase(candidate, pattern) for pattern in spec.globs):
                    return StateMatch(spec=spec, canonical_path=candidate)
        return None

    def canonical_path(self, path: str) -> Optional[str]:
        match = self.match(path)
        return match.canonical_path if match else None

    def object_for(self, path: str) -> Optional[StateObjectSpec]:
        match = self.match(path)
        return match.spec if match else None

    def layer_of(self, path: str) -> Optional[str]:
        spec = self.object_for(path)
        return spec.layer if spec else None

    def role_of(self, path: str) -> Optional[str]:
        spec = self.object_for(path)
        return spec.role if spec else None

    def bucket_key(self, path: str) -> str:
        match = self.match(path)
        if match is None:
            return path
        return match.spec.bucket or match.canonical_path


def load_state_schema(path: Path | str) -> StateSchema:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("self-state schema root must be an object")
    return StateSchema.from_mapping(payload)


BUILTIN_SCHEMA_PATH = Path(__file__).with_name("self_state_openclaw.json")
STATE_SCHEMA_ENV = "ASSA_STATE_SCHEMA"
SELECTED_SCHEMA_PATH = Path(
    os.environ.get(STATE_SCHEMA_ENV, str(BUILTIN_SCHEMA_PATH))
)
DEFAULT_SCHEMA_PATH = SELECTED_SCHEMA_PATH  # Backward-compatible export.
DEFAULT_STATE_SCHEMA = load_state_schema(SELECTED_SCHEMA_PATH)
