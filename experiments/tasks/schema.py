"""Task JSON schema — dataclass + loader/validator.

See `tasks/README.md` for the field-level documentation. This module is the
single source of truth: every curator script and every experiment runner
loads tasks through `Task.from_json_path()`.

Design intent:
- Plain stdlib (dataclasses + json), no pydantic/jsonschema deps.
- Validate on load; fail fast with a clear message.
- `success_criterion` is a discriminated union on `kind` — keep it a dict
  here and let per-kind evaluators in `measurement/task_eval.py` pick it
  apart. This keeps the schema layer small.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


# Allowed values are kept as module-level frozensets so callers can import and
# assert on them without stringly-typed drift.
ALLOWED_PROFILES = frozenset({"W1", "W2", "W3", "W4"})

# Four success-criterion kinds only. Experiment measures workload traces, not
# agent answer quality — success rates on the three evaluable kinds are a
# sanity-check, not the primary result. Open-ended tasks (W3 self-authored
# diagnosis + W4 general) use "none" to say "collect the trace, don't score."
ALLOWED_SUCCESS_KINDS = frozenset(
    {
        "none",                 # trace-only; success not evaluated
        "unittest_exit_zero",   # W1 — unittest exit code == 0
        "qa_answer_match",      # W2 — fuzzy match against gold answer
        "bash_state_check",     # W3 v1 (archived) — stdout of check cmd == expected
        "file_state_check",     # W3 v2 — per-file substring / JSON-path assertions
    }
)


@dataclass(frozen=True)
class DatasetSource:
    """Where a task came from.

    Attributes:
        name: short id, e.g. "aider-polyglot", "hotpotqa", "intercode-bash",
            or "authored".
        upstream_id: stable id in the upstream dataset. None for authored tasks.
        license: license string for attribution.
        citation: short citation line (commit sha, paper reference, etc.).
        url: canonical URL for the upstream item (None for authored).
    """

    name: str
    license: str
    citation: str
    upstream_id: Optional[str] = None
    url: Optional[str] = None


@dataclass(frozen=True)
class SeedFile:
    """A file to stage into the workspace root before a task run.

    Attributes:
        path: workspace-relative path (no leading slash).
        content_ref: path relative to `tasks/` pointing at the seed content.
            The runner copies this file's bytes into `<workspace>/<path>`.
    """

    path: str
    content_ref: str


@dataclass
class Task:
    """One benchmark task.

    See tasks/README.md for field-level docs.
    """

    task_id: str
    profile: str
    cluster: int
    variant: int
    cluster_name: str
    dataset_source: DatasetSource
    seed_files: list[SeedFile]
    prompt: str
    # Discriminated on `kind` — leave as a dict and let task_eval.py dispatch.
    success_criterion: dict[str, Any]
    max_turns: Optional[int] = None
    max_total_tokens: Optional[int] = None
    # Free-form metadata (trial seeds, original question id, etc.).
    meta: dict[str, Any] = field(default_factory=dict)

    # ----- load / validate

    @classmethod
    def from_dict(cls, payload: dict[str, Any], *, source_path: Optional[Path] = None) -> "Task":
        """Construct + validate from a parsed JSON dict.

        `source_path` is used only for error messages.
        """
        ctx = f" (in {source_path})" if source_path else ""

        def require(key: str) -> Any:
            if key not in payload:
                raise ValueError(f"missing field '{key}'{ctx}")
            return payload[key]

        task_id = str(require("task_id"))
        profile = str(require("profile"))
        if profile not in ALLOWED_PROFILES:
            raise ValueError(
                f"profile must be one of {sorted(ALLOWED_PROFILES)}, got {profile!r}{ctx}"
            )
        cluster = int(require("cluster"))
        if not 1 <= cluster <= 5:
            raise ValueError(f"cluster must be in 1..5, got {cluster}{ctx}")
        variant = int(require("variant"))
        # V5, V6 added 2026-04-25 to extend chains to 30 unique tasks.
        if not 1 <= variant <= 6:
            raise ValueError(f"variant must be in 1..6, got {variant}{ctx}")
        cluster_name = str(require("cluster_name"))

        expected_id = f"{profile}_C{cluster}_V{variant}"
        if task_id != expected_id:
            raise ValueError(
                f"task_id {task_id!r} must match profile/cluster/variant "
                f"(expected {expected_id!r}){ctx}"
            )

        ds_raw = require("dataset_source")
        if not isinstance(ds_raw, dict):
            raise ValueError(f"dataset_source must be an object{ctx}")
        dataset_source = DatasetSource(
            name=str(ds_raw.get("name") or ""),
            license=str(ds_raw.get("license") or ""),
            citation=str(ds_raw.get("citation") or ""),
            upstream_id=(
                str(ds_raw["upstream_id"]) if ds_raw.get("upstream_id") is not None else None
            ),
            url=str(ds_raw["url"]) if ds_raw.get("url") is not None else None,
        )
        if not dataset_source.name or not dataset_source.license:
            raise ValueError(f"dataset_source.name and .license are required{ctx}")

        seeds_raw = payload.get("seed_files", [])
        if not isinstance(seeds_raw, list):
            raise ValueError(f"seed_files must be a list{ctx}")
        seed_files = []
        for i, s in enumerate(seeds_raw):
            if not isinstance(s, dict):
                raise ValueError(f"seed_files[{i}] must be an object{ctx}")
            p = s.get("path")
            c = s.get("content_ref")
            if not isinstance(p, str) or not p:
                raise ValueError(f"seed_files[{i}].path must be a non-empty string{ctx}")
            if not isinstance(c, str) or not c:
                raise ValueError(
                    f"seed_files[{i}].content_ref must be a non-empty string{ctx}"
                )
            if p.startswith("/") or ".." in p.split("/"):
                raise ValueError(f"seed_files[{i}].path must be workspace-relative{ctx}")
            seed_files.append(SeedFile(path=p, content_ref=c))

        prompt = str(require("prompt"))
        if not prompt.strip():
            raise ValueError(f"prompt must not be empty{ctx}")

        sc = require("success_criterion")
        if not isinstance(sc, dict):
            raise ValueError(f"success_criterion must be an object{ctx}")
        kind = sc.get("kind")
        if kind not in ALLOWED_SUCCESS_KINDS:
            raise ValueError(
                f"success_criterion.kind must be one of "
                f"{sorted(ALLOWED_SUCCESS_KINDS)}, got {kind!r}{ctx}"
            )

        mt = payload.get("max_turns")
        if mt is not None and (not isinstance(mt, int) or mt <= 0):
            raise ValueError(f"max_turns must be a positive int{ctx}")
        mtt = payload.get("max_total_tokens")
        if mtt is not None and (not isinstance(mtt, int) or mtt <= 0):
            raise ValueError(f"max_total_tokens must be a positive int{ctx}")

        meta = payload.get("meta") or {}
        if not isinstance(meta, dict):
            raise ValueError(f"meta must be an object{ctx}")

        return cls(
            task_id=task_id,
            profile=profile,
            cluster=cluster,
            variant=variant,
            cluster_name=cluster_name,
            dataset_source=dataset_source,
            seed_files=seed_files,
            prompt=prompt,
            success_criterion=sc,
            max_turns=mt,
            max_total_tokens=mtt,
            meta=meta,
        )

    @classmethod
    def from_json_path(cls, path: Path | str) -> "Task":
        p = Path(path)
        with p.open("r", encoding="utf-8") as f:
            payload = json.load(f)
        return cls.from_dict(payload, source_path=p)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "task_id": self.task_id,
            "profile": self.profile,
            "cluster": self.cluster,
            "variant": self.variant,
            "cluster_name": self.cluster_name,
            "dataset_source": {
                "name": self.dataset_source.name,
                "license": self.dataset_source.license,
                "citation": self.dataset_source.citation,
            },
            "seed_files": [
                {"path": s.path, "content_ref": s.content_ref} for s in self.seed_files
            ],
            "prompt": self.prompt,
            "success_criterion": dict(self.success_criterion),
        }
        if self.dataset_source.upstream_id is not None:
            out["dataset_source"]["upstream_id"] = self.dataset_source.upstream_id
        if self.dataset_source.url is not None:
            out["dataset_source"]["url"] = self.dataset_source.url
        if self.max_turns is not None:
            out["max_turns"] = self.max_turns
        if self.max_total_tokens is not None:
            out["max_total_tokens"] = self.max_total_tokens
        if self.meta:
            out["meta"] = self.meta
        return out

    def to_json_path(self, path: Path | str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2, sort_keys=False)
            f.write("\n")


def load_all(tasks_root: Path | str) -> list[Task]:
    """Load every `W*_C*_V*.json` file under `tasks_root/{W1,W2,W3,W4}/`."""
    root = Path(tasks_root)
    out: list[Task] = []
    for profile in ("W1", "W2", "W3", "W4"):
        pdir = root / profile
        if not pdir.is_dir():
            continue
        for fp in sorted(pdir.glob(f"{profile}_C*_V*.json")):
            out.append(Task.from_json_path(fp))
    return out
