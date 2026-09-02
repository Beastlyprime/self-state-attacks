"""Tests for `tasks.schema` — task JSON loader + validator."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tasks.schema import DatasetSource, SeedFile, Task, load_all


def _valid_payload() -> dict:
    return {
        "task_id": "W1_C1_V2",
        "profile": "W1",
        "cluster": 1,
        "variant": 2,
        "cluster_name": "string/encoding",
        "dataset_source": {
            "name": "aider-polyglot",
            "upstream_id": "affine-cipher",
            "license": "Exercism Open Source",
            "citation": "Aider-AI/polyglot-benchmark@abc123",
            "url": "https://example.com/affine-cipher",
        },
        "seed_files": [
            {"path": "affine_cipher.py", "content_ref": "seeds/W1_C1_V2/affine_cipher.py"},
            {"path": "affine_cipher_test.py", "content_ref": "seeds/W1_C1_V2/affine_cipher_test.py"},
        ],
        "prompt": "Implement encode/decode.",
        "success_criterion": {
            "kind": "unittest_exit_zero",
            "command": "python -m unittest affine_cipher_test",
            "timeout_sec": 60,
        },
        "max_turns": 32,
        "max_total_tokens": 100000,
    }


class LoadValidTaskTests(unittest.TestCase):
    def test_parses_valid_payload(self) -> None:
        t = Task.from_dict(_valid_payload())
        self.assertEqual(t.task_id, "W1_C1_V2")
        self.assertEqual(t.profile, "W1")
        self.assertEqual(t.cluster, 1)
        self.assertEqual(t.variant, 2)
        self.assertEqual(t.dataset_source.name, "aider-polyglot")
        self.assertEqual(t.dataset_source.upstream_id, "affine-cipher")
        self.assertEqual(len(t.seed_files), 2)
        self.assertEqual(t.success_criterion["kind"], "unittest_exit_zero")
        self.assertEqual(t.max_turns, 32)

    def test_roundtrip_json_path(self) -> None:
        t = Task.from_dict(_valid_payload())
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "task.json"
            t.to_json_path(p)
            t2 = Task.from_json_path(p)
            self.assertEqual(t.to_dict(), t2.to_dict())


class ValidationTests(unittest.TestCase):
    def test_rejects_bad_profile(self) -> None:
        bad = _valid_payload()
        bad["profile"] = "W5"
        bad["task_id"] = "W5_C1_V2"
        with self.assertRaisesRegex(ValueError, "profile must be one of"):
            Task.from_dict(bad)

    def test_rejects_bad_cluster(self) -> None:
        bad = _valid_payload()
        bad["cluster"] = 9
        bad["task_id"] = "W1_C9_V2"
        with self.assertRaisesRegex(ValueError, "cluster must be in 1..5"):
            Task.from_dict(bad)

    def test_rejects_bad_variant(self) -> None:
        bad = _valid_payload()
        bad["variant"] = 0
        bad["task_id"] = "W1_C1_V0"
        with self.assertRaisesRegex(ValueError, "variant must be in 1..6"):
            Task.from_dict(bad)

    def test_rejects_mismatched_task_id(self) -> None:
        bad = _valid_payload()
        bad["task_id"] = "W1_C1_V3"  # variant is 2
        with self.assertRaisesRegex(ValueError, "task_id .* must match"):
            Task.from_dict(bad)

    def test_rejects_absolute_seed_path(self) -> None:
        bad = _valid_payload()
        bad["seed_files"][0]["path"] = "/etc/passwd"
        with self.assertRaisesRegex(ValueError, "workspace-relative"):
            Task.from_dict(bad)

    def test_rejects_parent_traversal_seed_path(self) -> None:
        bad = _valid_payload()
        bad["seed_files"][0]["path"] = "../../escape.txt"
        with self.assertRaisesRegex(ValueError, "workspace-relative"):
            Task.from_dict(bad)

    def test_rejects_unknown_success_kind(self) -> None:
        bad = _valid_payload()
        bad["success_criterion"]["kind"] = "magical_judge"
        with self.assertRaisesRegex(ValueError, "success_criterion.kind"):
            Task.from_dict(bad)

    def test_accepts_none_kind_for_trace_only_tasks(self) -> None:
        p = _valid_payload()
        p["success_criterion"] = {"kind": "none"}
        t = Task.from_dict(p)
        self.assertEqual(t.success_criterion["kind"], "none")

    def test_rejects_removed_kinds(self) -> None:
        """llm_judge / bash_diagnosis_match / file_content_check were removed
        on purpose (trace is the measurement, success is a sanity check).
        Make sure nobody silently reintroduces them."""
        for dead_kind in ("llm_judge", "bash_diagnosis_match", "file_content_check"):
            bad = _valid_payload()
            bad["success_criterion"] = {"kind": dead_kind}
            with self.assertRaisesRegex(
                ValueError, "success_criterion.kind",
                msg=f"expected {dead_kind!r} to be rejected",
            ):
                Task.from_dict(bad)

    def test_rejects_empty_prompt(self) -> None:
        bad = _valid_payload()
        bad["prompt"] = "   "
        with self.assertRaisesRegex(ValueError, "prompt must not be empty"):
            Task.from_dict(bad)

    def test_rejects_missing_required(self) -> None:
        bad = _valid_payload()
        del bad["dataset_source"]
        with self.assertRaisesRegex(ValueError, "missing field 'dataset_source'"):
            Task.from_dict(bad)


class LoadAllTests(unittest.TestCase):
    def test_load_all_empty_dirs_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            for p in ("W1", "W2", "W3", "W4"):
                (Path(d) / p).mkdir()
            self.assertEqual(load_all(d), [])

    def test_load_all_picks_up_correctly_named_files(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "W1").mkdir()
            (root / "W2").mkdir()
            t1 = Task.from_dict(_valid_payload())
            t1.to_json_path(root / "W1" / "W1_C1_V2.json")
            p2 = _valid_payload()
            p2["task_id"] = "W2_C3_V1"
            p2["profile"] = "W2"
            p2["cluster"] = 3
            p2["variant"] = 1
            p2["dataset_source"]["name"] = "hotpotqa"
            p2["success_criterion"] = {"kind": "qa_answer_match", "gold_answer": "yes"}
            t2 = Task.from_dict(p2)
            t2.to_json_path(root / "W2" / "W2_C3_V1.json")
            loaded = load_all(root)
            ids = [t.task_id for t in loaded]
            self.assertEqual(sorted(ids), ["W1_C1_V2", "W2_C3_V1"])

    def test_load_all_skips_noise_files(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "W1").mkdir()
            t1 = Task.from_dict(_valid_payload())
            t1.to_json_path(root / "W1" / "W1_C1_V2.json")
            # readme and non-matching json should be ignored
            (root / "W1" / "README.md").write_text("# w1")
            (root / "W1" / "extras.json").write_text("{}")
            loaded = load_all(root)
            self.assertEqual([t.task_id for t in loaded], ["W1_C1_V2"])


if __name__ == "__main__":
    unittest.main()
