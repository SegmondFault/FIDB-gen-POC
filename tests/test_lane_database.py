import sqlite3
import tempfile
import unittest
from pathlib import Path

from fidb_poc.lane_database import build_lane_database, inspect_lane_database
from fidb_poc.lane_registry import load_lane_registry


class LaneDatabaseTests(unittest.TestCase):
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
            "source_url": "https://example.invalid/example-1.0.tar.gz",
            "source_sha256": "1" * 64,
            "build_id": "example-1-linux-x86-64-gcc-o2",
            "route_id": "linux-x86-64-gcc",
            "compiler_family": "gcc",
            "compiler_version": "14.3.0",
            "compiler_sha256": "2" * 64,
            "treatment_id": "baseline_o2",
            "build_manifest_sha256": "3" * 64,
            "ghidra_language_id": "x86:LE:64:default",
            "ghidra_compiler_spec_id": "gcc",
            "domain_path": "/example.o",
            "function_name": "example_one",
            "full_hash": "0000000000000001",
            "specific_hash": "0000000000000002",
            "specific_hash_additional_size": 1,
            "code_unit_size": 12,
        }
        row.update(updates)
        return row

    def build(self, path: Path, occurrences):
        return build_lane_database(
            path,
            registry=self.registry,
            lane_id="linux-x86",
            generation_id="linux-x86-test-v1",
            registry_sha256="a" * 64,
            source_run_id="test-run",
            source_run_sha256="b" * 64,
            occurrences=occurrences,
            created_at="2026-09-02T20:00:00+00:00",
        )

    def test_equal_signatures_remain_separate_raw_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "linux-x86.sqlite3"
            result = self.build(
                path,
                [
                    self.occurrence(),
                    self.occurrence(
                        function_name="example_two",
                        domain_path="/other.o",
                    ),
                    self.occurrence(
                        build_id="example-1-linux-x86-64-gcc-o3",
                        treatment_id="optimization_o3",
                        build_manifest_sha256="4" * 64,
                    ),
                ],
            )

            self.assertEqual(result["counts"]["raw_signature_observation"], 3)
            self.assertEqual(result["counts"]["build_variant"], 2)
            self.assertEqual(result["generation"]["signature_records"], 3)
            self.assertEqual(
                result["generation"]["native_projection_state"],
                "blocked-missing-relationships",
            )

    def test_cross_bitness_observations_retain_their_sublanes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "linux-x86.sqlite3"
            result = self.build(
                path,
                [
                    self.occurrence(),
                    self.occurrence(
                        sublane_id="linux-x86-elf32",
                        build_id="example-1-linux-x86-32-gcc-o2",
                        route_id="linux-x86-32-gcc",
                        build_manifest_sha256="4" * 64,
                        ghidra_language_id="x86:LE:32:default",
                    ),
                ],
            )

            self.assertEqual(result["counts"]["raw_signature_observation"], 2)
            with sqlite3.connect(path) as connection:
                sublanes = {
                    row[0]
                    for row in connection.execute(
                        "SELECT sublane_id FROM raw_signature_observation"
                    )
                }
            self.assertEqual(sublanes, {"linux-x86-elf32", "linux-x86-elf64"})

    def test_published_database_is_immutable_and_cannot_be_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "linux-x86.sqlite3"
            self.build(path, [self.occurrence()])

            with sqlite3.connect(path) as connection:
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    connection.execute(
                        "UPDATE lane_generation SET lane_label = 'changed'"
                    )
            with self.assertRaises(FileExistsError):
                self.build(path, [self.occurrence()])
            self.assertEqual(
                inspect_lane_database(path)["counts"]["raw_signature_observation"],
                1,
            )

    def test_identical_input_rows_are_not_silently_deduplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "linux-x86.sqlite3"
            row = self.occurrence()

            result = self.build(path, [row, dict(row)])

            self.assertEqual(result["counts"]["raw_signature_observation"], 2)

    def test_incompatible_language_and_unknown_fields_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.sqlite3"
            with self.assertRaisesRegex(ValueError, "language is not admitted"):
                self.build(
                    path,
                    [self.occurrence(ghidra_language_id="ARM:LE:32:v7")],
                )
            self.assertFalse(path.exists())

            with self.assertRaisesRegex(ValueError, r"unknown=\['extra'\]"):
                self.build(path, [self.occurrence(extra="not allowed")])
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
