"""Curator for W1 (Coding) — Aider polyglot Python tasks.

Downloads 30 tasks from Aider-AI/polyglot-benchmark (Python subset),
organized as 5 clusters × 6 variants. Writes:

- 30 task JSONs under tasks/W1/W1_C<cluster>_V<variant>.json
- 60 seed files under tasks/seeds/W1_C<cluster>_V<variant>/

The task JSONs conform to tasks/schema.py. Success criterion is
"unittest_exit_zero" — the agent must make `python -m unittest
<module>_test` exit 0.

Re-running this script is idempotent:
- It always pins to the commit SHA in AIDER_COMMIT below (reproducible
  sample; rerunning the curator without bumping the SHA yields identical
  output bytes).
- It overwrites existing seeds/JSONs.

Usage:
    python -m tasks.curate_w1

Dependencies: Python 3.10 stdlib only (urllib).
"""

from __future__ import annotations

import sys
import urllib.error
import urllib.request
from pathlib import Path

# Make tasks.schema importable when run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tasks.schema import DatasetSource, SeedFile, Task  # noqa: E402


# ------------------------------------------------------------------- constants

# Pin to a specific commit SHA for reproducibility. Update this + rerun
# the curator when we want to refresh the task set.
#
# We intentionally do NOT pin to "main" — the paper must be reproducible
# from what's in the repo.
#
# This SHA is the most recent commit on main as of curation time (looked
# up via `git ls-remote https://github.com/Aider-AI/polyglot-benchmark main`).
AIDER_COMMIT = "7e0611e77b54e2dea774cdc0aa00cf9f7ed6144f"
AIDER_RAW_BASE = (
    f"https://raw.githubusercontent.com/Aider-AI/polyglot-benchmark/{AIDER_COMMIT}"
)
AIDER_TREE_URL = (
    f"https://github.com/Aider-AI/polyglot-benchmark/tree/{AIDER_COMMIT}"
)

# Exercise → Python module name mapping. Exercism's convention: a kebab-case
# exercise "affine-cipher" has starter file "affine_cipher.py" and test file
# "affine_cipher_test.py". Most tasks just need kebab→snake_case transform,
# but a few have irregular names (listed explicitly).
EXERCISE_MODULE_OVERRIDES = {
    # None currently — Exercism Python is consistent.
}

# Cluster definition. Order matters: variant index is position in list.
# V1-V4 are the original sample (paper round 6); V5, V6 added 2026-04-25 to
# extend each chain to 30 unique tasks without repetition. All exercises
# are from the same pinned polyglot commit.
W1_CLUSTERS: list[tuple[int, str, list[str]]] = [
    (
        1,
        "string/encoding",
        ["affine-cipher", "pig-latin", "phone-number", "proverb",
         "transpose", "bottle-song"],
    ),
    (
        2,
        "data-structures",
        ["simple-linked-list", "zipper", "tree-building", "grade-school",
         "list-ops", "pov"],
    ),
    (
        3,
        "algorithms/rules",
        ["poker", "go-counting", "zebra-puzzle", "two-bucket",
         "bowling", "dominoes"],
    ),
    (
        4,
        "parsing/DSL",
        ["forth", "wordy", "sgf-parsing", "dot-dsl",
         "scale-generator", "variable-length-quantity"],
    ),
    (
        5,
        "io/system",
        ["paasio", "grep", "rest-api", "react",
         "connect", "robot-name"],
    ),
]


LICENSE_STRING = "Exercism Open Source (content © Exercism)"


# --------------------------------------------------------------- helper fetch


def _module_name(exercise: str) -> str:
    if exercise in EXERCISE_MODULE_OVERRIDES:
        return EXERCISE_MODULE_OVERRIDES[exercise]
    return exercise.replace("-", "_")


def _fetch(url: str) -> bytes:
    """Fetch a URL as bytes. Raises on HTTP error."""
    req = urllib.request.Request(url, headers={"User-Agent": "assa-curator/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code} fetching {url}: {e.reason}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"network error fetching {url}: {e.reason}") from e


def _fetch_exercise_files(exercise: str) -> tuple[bytes, bytes]:
    """Fetch (starter_bytes, test_bytes) for one Exercism exercise."""
    mod = _module_name(exercise)
    base = f"{AIDER_RAW_BASE}/python/exercises/practice/{exercise}"
    starter = _fetch(f"{base}/{mod}.py")
    tests = _fetch(f"{base}/{mod}_test.py")
    return starter, tests


# --------------------------------------------------------------- task builder


def _build_task(
    cluster: int,
    cluster_name: str,
    variant: int,
    exercise: str,
    seeds_dir: Path,
) -> Task:
    """Build a Task for one exercise. Seeds are already staged in seeds_dir."""
    mod = _module_name(exercise)
    task_id = f"W1_C{cluster}_V{variant}"
    seeds_rel = f"seeds/{task_id}"

    prompt = (
        f"Your task is to implement the exercise `{exercise}`. "
        f"Open `{mod}.py` to see the function stubs you need to fill in. "
        f"The tests are in `{mod}_test.py`. When you're done, run "
        f"`python -m unittest {mod}_test` in the workspace. "
        f"The task is complete when all tests pass (exit code 0). "
        f"Do NOT modify `{mod}_test.py`."
    )

    return Task(
        task_id=task_id,
        profile="W1",
        cluster=cluster,
        variant=variant,
        cluster_name=cluster_name,
        dataset_source=DatasetSource(
            name="aider-polyglot",
            upstream_id=exercise,
            license=LICENSE_STRING,
            citation=f"Aider-AI/polyglot-benchmark@{AIDER_COMMIT[:8]}",
            url=(
                f"{AIDER_TREE_URL}/python/exercises/practice/{exercise}"
            ),
        ),
        seed_files=[
            SeedFile(path=f"{mod}.py", content_ref=f"{seeds_rel}/{mod}.py"),
            SeedFile(
                path=f"{mod}_test.py",
                content_ref=f"{seeds_rel}/{mod}_test.py",
            ),
        ],
        prompt=prompt,
        success_criterion={
            "kind": "unittest_exit_zero",
            "command": f"python -m unittest {mod}_test",
            "timeout_sec": 60,
        },
        # Coding tasks can take a while; give them headroom.
        max_turns=48,
        max_total_tokens=150_000,
        meta={"exercise": exercise, "aider_commit": AIDER_COMMIT},
    )


# --------------------------------------------------------------- main


def main() -> int:
    tasks_root = Path(__file__).resolve().parent
    w1_dir = tasks_root / "W1"
    seeds_root = tasks_root / "seeds"
    w1_dir.mkdir(parents=True, exist_ok=True)
    seeds_root.mkdir(parents=True, exist_ok=True)

    print(f"Curating W1 tasks from Aider polyglot @ {AIDER_COMMIT[:8]}")

    all_tasks: list[Task] = []
    for cluster, cluster_name, exercises in W1_CLUSTERS:
        if len(exercises) < 1:
            raise ValueError(
                f"cluster {cluster} must have at least 1 exercise, got 0"
            )
        print(f"  C{cluster} {cluster_name}:")
        for variant_idx, exercise in enumerate(exercises, start=1):
            task_id = f"W1_C{cluster}_V{variant_idx}"
            mod = _module_name(exercise)
            seeds_dir = seeds_root / task_id
            seeds_dir.mkdir(parents=True, exist_ok=True)

            print(f"    V{variant_idx} {exercise:<22} → {task_id}", end="")
            starter, tests = _fetch_exercise_files(exercise)
            (seeds_dir / f"{mod}.py").write_bytes(starter)
            (seeds_dir / f"{mod}_test.py").write_bytes(tests)

            task = _build_task(
                cluster=cluster,
                cluster_name=cluster_name,
                variant=variant_idx,
                exercise=exercise,
                seeds_dir=seeds_dir,
            )
            task.to_json_path(w1_dir / f"{task_id}.json")
            all_tasks.append(task)
            print(f"  [{len(starter)}B + {len(tests)}B]")

    print(f"\nWrote {len(all_tasks)} tasks to {w1_dir}")
    print(f"Wrote {2 * len(all_tasks)} seed files to {seeds_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
