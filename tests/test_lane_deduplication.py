from contextlib import closing
import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from fidb_poc.lane_database import build_lane_database
from fidb_poc.lane_registry import load_lane_registry
from scripts.deduplicate_lane_db import compact_lane_database, preview_compaction


class LaneDeduplicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.registry = load_lane_registry(
            cls.root / "lanes/registry.toml",
            cls.root / "targets/registry.toml",
        )

    @staticmethod
    def occurrence(**updates):
        row = {
            "sublane_id": "linux-x86-elf64",
            "library": "example",
            "library_version": "1.0",
            "source_language": "c",
            "source_url": "https://example.invalid/example.tar.gz",
            "source_sha256": "1" * 64,
            "build_id": "example:gcc:o2",
            "route_id": "linux-x86-64-gcc",
            "compiler_family": "gcc",
            "compiler_version": "14.3.0",
            "compiler_sha256": "2" * 64,
            "treatment_id": "baseline_o2",
            "build_manifest_sha256": "3" * 64,
            "ghidra_language_id": "x86:LE:64:default",
            "ghidra_compiler_spec_id": "gcc",
            "domain_path": "/example.o",
            "function_name": "one",
            "full_hash": "0000000000000001",
            "specific_hash": "1000000000000001",
            "specific_hash_additional_size": 1,
            "code_unit_size": 12,
        }
        row.update(updates)
        return row

    def raw_database(self, path: Path):
        build_lane_database(
            path,
            registry=self.registry,
            lane_id="linux-x86",
            generation_id="raw-v1",
            registry_sha256="a" * 64,
            source_run_id="synthetic",
            source_run_sha256="b" * 64,
            occurrences=[
                self.occurrence(),
                self.occurrence(function_name="two", domain_path="/two.o"),
                self.occurrence(
                    build_id="example:gcc:o3",
                    treatment_id="optimization_o3",
                    build_manifest_sha256="4" * 64,
                ),
            ],
            created_at="2026-09-02T20:00:00+00:00",
        )

    def test_preview_is_read_only_and_reports_exact_key(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / "raw.sqlite3"
            self.raw_database(raw)
            before = hashlib.sha256(raw.read_bytes()).hexdigest()

            result = preview_compaction(raw)

            self.assertEqual(result["raw_observations"], 3)
            self.assertEqual(result["unique_signatures"], 1)
            self.assertEqual(result["repeated_observations"], 2)
            self.assertFalse(result["would_modify_source"])
            self.assertIn("sublane_id", result["deduplication_key"])
            self.assertEqual(hashlib.sha256(raw.read_bytes()).hexdigest(), before)

    def test_explicit_compaction_preserves_occurrences_and_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "raw.sqlite3"
            compact = root / "compact.sqlite3"
            self.raw_database(raw)
            before = hashlib.sha256(raw.read_bytes()).hexdigest()

            result = compact_lane_database(
                raw,
                compact,
                generation_id="compact-v1",
                created_at="2026-09-02T20:01:00+00:00",
            )

            self.assertEqual(result["counts"]["compact_signature"], 1)
            self.assertEqual(result["counts"]["signature_occurrence"], 3)
            self.assertEqual(result["counts"]["admission_decision"], 1)
            self.assertEqual(hashlib.sha256(raw.read_bytes()).hexdigest(), before)
            with closing(sqlite3.connect(compact)) as connection:
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    connection.execute(
                        "UPDATE compact_generation SET state = 'changed'"
                    )

    def test_compaction_refuses_in_place_and_existing_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "raw.sqlite3"
            output = root / "compact.sqlite3"
            self.raw_database(raw)

            with self.assertRaisesRegex(ValueError, "must differ"):
                compact_lane_database(raw, raw, generation_id="compact-v1")
            output.write_text("keep", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                compact_lane_database(raw, output, generation_id="compact-v1")
            self.assertEqual(output.read_text(encoding="utf-8"), "keep")


if __name__ == "__main__":
    unittest.main()
