from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from fidb_poc.fid_compact import (
    INDEX_SCHEMA,
    _relation_smash,
    build_compact_candidate_index,
    compact_index_status,
    load_fid_matching_performance,
    match_compact,
    match_compact_population,
    selected_backend_id,
    validate_compact_candidate_index,
)
from fidb_poc.fid_matching import load_matching_authority


class CompactFidTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[1]
        cls.authority = load_matching_authority(cls.root)

    def fixture(self, root: Path):
        fidb = root / "sample.fidb"
        fidb.write_bytes(b"packed-fidb")
        digest = hashlib.sha256(fidb.read_bytes()).hexdigest()
        entries = [
            {
                "route_id": "linux-x86",
                "treatment_id": "o2",
                "owner": "sample@1",
                "fidb_path": str(fidb),
                "fidb_sha256": digest,
            }
        ]
        child_smash = _relation_smash("0000000000000001", "cc")

        def inspect(_path: Path):
            return {
                "schema_version": "fidb-compact-candidate-source/v1",
                "fidb_sha256": digest,
                "candidates": [
                    {
                        "candidate_id": "relation",
                        "record_key": "0000000000000001",
                        "owner": "sample@1",
                        "name": "relation",
                        "full_hash": "aa",
                        "specific_hash": "cc",
                        "specific_hash_additional_size": 0,
                        "code_unit_size": 14,
                        "auto_pass": False,
                        "auto_fail": False,
                        "force_specific": False,
                        "force_relation": False,
                    },
                    {
                        "candidate_id": "specific",
                        "record_key": "0000000000000002",
                        "owner": "sample@1",
                        "name": "specific",
                        "full_hash": "aa",
                        "specific_hash": "bb",
                        "specific_hash_additional_size": 8,
                        "code_unit_size": 10,
                        "auto_pass": False,
                        "auto_fail": False,
                        "force_specific": False,
                        "force_relation": False,
                    },
                ],
                "relations": {"superior": [child_smash], "inferior": []},
            }

        return entries, inspect

    def query(self):
        return [
            {
                "address": "1000",
                "function_name": "query",
                "full_hash": "aa",
                "specific_hash": "bb",
                "specific_hash_additional_size": 8,
                "code_unit_size": 10,
                "children": [{"full_hash": "cc", "code_unit_size": 2}],
                "parents": [],
            }
        ]

    def test_index_stores_each_candidate_and_relation_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            entries, inspect = self.fixture(root)
            destination = root / "compact.sqlite3"

            report = build_compact_candidate_index(entries, destination, inspect)
            reused = build_compact_candidate_index(
                entries, destination, lambda _path: self.fail("index was rebuilt")
            )

            self.assertEqual(report["schema_version"], INDEX_SCHEMA)
            self.assertEqual(report["sources"], 1)
            self.assertEqual(report["candidates"], 2)
            self.assertEqual(report["relations"], 1)
            self.assertEqual(reused, compact_index_status(destination))
            self.assertEqual(
                validate_compact_candidate_index(entries, destination), report
            )

            changed = [{**entries[0], "owner": "another@1"}]
            with self.assertRaisesRegex(ValueError, "does not match"):
                validate_compact_candidate_index(changed, destination)

    def test_shared_source_is_inspected_once_without_a_global_row_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            entries, inspect = self.fixture(root)
            entries.append({**entries[0], "route_id": "linux-x86-v2"})
            inspector = Mock(side_effect=inspect)

            report = build_compact_candidate_index(
                entries, root / "compact.sqlite3", inspector
            )

            inspector.assert_called_once()
            self.assertEqual(report["sources"], 1)
            self.assertEqual(report["candidates"], 4)
            self.assertEqual(report["relations"], 1)

    def test_performance_toml_selects_gpu_with_cpu_fallback(self) -> None:
        performance = load_fid_matching_performance(self.root)

        self.assertEqual(performance["mode"], "gpu")
        self.assertTrue(performance["fallback_to_cpu"])
        self.assertEqual(
            selected_backend_id(performance, self.authority),
            "gpu-portable-fid-v1",
        )

    def test_cpu_stream_retains_only_equal_highest_winners(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            entries, inspect = self.fixture(root)
            destination = root / "compact.sqlite3"
            build_compact_candidate_index(entries, destination, inspect)

            result = match_compact(
                destination,
                self.query(),
                "linux-x86",
                "o2",
                self.authority,
                backend_id="cpu-portable-fid-v1",
                chunk_rows=1,
            )

            self.assertEqual(result["candidate_count"], 2)
            self.assertEqual(result["matched_functions"], 1)
            self.assertEqual(
                [row["candidate_id"] for row in result["functions"][0]["matches"]],
                ["relation"],
            )
            self.assertEqual(result["functions"][0]["matches"][0]["score"], 16.0)

    def test_population_selects_global_winners_without_rebuilding_union(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            entries, inspect = self.fixture(root)
            first = root / "archive.sqlite3"
            build_compact_candidate_index(entries, first, inspect)

            linked_fidb = root / "linked.fidb"
            linked_fidb.write_bytes(b"linked-fidb")
            linked_digest = hashlib.sha256(linked_fidb.read_bytes()).hexdigest()
            linked_entries = [
                {
                    **entries[0],
                    "fidb_path": str(linked_fidb),
                    "fidb_sha256": linked_digest,
                }
            ]

            def inspect_linked(_path: Path):
                source = inspect(_path)
                source["fidb_sha256"] = linked_digest
                source["candidates"][0]["code_unit_size"] = 30
                return source

            second = root / "linked.sqlite3"
            build_compact_candidate_index(linked_entries, second, inspect_linked)

            result = match_compact_population(
                [first, second],
                self.query(),
                "linux-x86",
                "o2",
                self.authority,
                backend_id="cpu-portable-fid-v1",
                chunk_rows=1,
            )

            self.assertEqual(result["candidate_count"], 4)
            self.assertEqual(len(result["component_indexes"]), 2)
            self.assertEqual(
                [row["candidate_id"] for row in result["functions"][0]["matches"]],
                ["relation"],
            )
            self.assertEqual(result["functions"][0]["matches"][0]["score"], 32.0)

    def test_gpu_startup_failure_uses_explicit_cpu_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            entries, inspect = self.fixture(root)
            destination = root / "compact.sqlite3"
            build_compact_candidate_index(entries, destination, inspect)

            with patch(
                "fidb_poc.fid_compact.score_rows_gpu",
                side_effect=RuntimeError("adapter unavailable"),
            ):
                result = match_compact(
                    destination,
                    self.query(),
                    "linux-x86",
                    "o2",
                    self.authority,
                    backend_id="gpu-portable-fid-v1",
                    fallback_to_cpu=True,
                )

            self.assertEqual(result["requested_backend"], "gpu-portable-fid-v1")
            self.assertEqual(result["backend"], "cpu-portable-fid-v1")
            self.assertIn("adapter unavailable", result["fallback_reason"])


if __name__ == "__main__":
    unittest.main()
