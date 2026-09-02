import json
import tempfile
import unittest
from pathlib import Path

from fidb_poc.lane_database import build_lane_database
from fidb_poc.lane_inventory import detect_lane_inventory
from fidb_poc.lane_registry import load_lane_registry
from scripts.deduplicate_lane_db import compact_lane_database


class LaneInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_root = Path(__file__).resolve().parents[1]
        cls.registry = load_lane_registry(
            cls.source_root / "lanes/registry.toml",
            cls.source_root / "targets/registry.toml",
        )

    @staticmethod
    def occurrence() -> dict[str, object]:
        return {
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
            "function_name": "example",
            "full_hash": "0000000000000001",
            "specific_hash": "0000000000000002",
            "specific_hash_additional_size": 1,
            "code_unit_size": 12,
        }

    def make_root(self, directory: str) -> Path:
        root = Path(directory)
        (root / "lanes").mkdir()
        (root / "targets").mkdir()
        (root / "lanes/registry.toml").write_bytes(
            (self.source_root / "lanes/registry.toml").read_bytes()
        )
        (root / "targets/registry.toml").write_bytes(
            (self.source_root / "targets/registry.toml").read_bytes()
        )
        return root

    def test_inventory_projects_completed_width_run_and_real_databases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            run = root / "artifacts/width-runs/c-width-v1/run-one"
            run.mkdir(parents=True)
            (run / "width-run.json").write_text(
                json.dumps(
                    {
                        "schema_version": "fidb-width-run/v1",
                        "state": "measured-complete",
                        "mode": "full",
                        "fixed_recipe": "example@1.0",
                        "finished_at_utc": "2026-09-02T15:00:00Z",
                        "scheduled_executions": 6,
                        "completed_executions": 6,
                        "retained_bytes": 1000,
                        "coverage": {"successful_route_profile_pairs": 6},
                        "hash_coverage": {
                            "totals": {
                                "signature_records": 12,
                                "unique_signatures": 8,
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            lane_root = root / "var/fidb-lanes/linux-x86"
            raw = lane_root / "raw.sqlite3"
            compact = lane_root / "compact.sqlite3"
            build_lane_database(
                raw,
                registry=self.registry,
                lane_id="linux-x86",
                generation_id="raw-v1",
                registry_sha256="a" * 64,
                source_run_id="run-one",
                source_run_sha256="b" * 64,
                occurrences=[self.occurrence()],
                created_at="2026-09-02T16:00:00Z",
            )
            compact_lane_database(
                raw,
                compact,
                generation_id="compact-v1",
                created_at="2026-09-02T17:00:00Z",
            )

            result = detect_lane_inventory(root)

            self.assertEqual(result["detection_mode"], "read-only-metadata")
            self.assertEqual(result["summary"]["complete_width_runs"], 1)
            self.assertEqual(result["summary"]["raw_generations"], 1)
            self.assertEqual(result["summary"]["compact_generations"], 1)
            self.assertEqual(result["summary"]["active_packs"], 0)
            self.assertEqual(
                result["latest_complete_width_run"]["unique_signatures"], 8
            )
            compact_row = next(
                row for row in result["databases"] if row["kind"] == "compact"
            )
            self.assertEqual(compact_row["lane_id"], "linux-x86")
            self.assertEqual(compact_row["ecological_validation_state"], "unreviewed")

    def test_inventory_reports_invalid_managed_database_without_failing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            invalid = root / "var/fidb-lanes/linux-x86/not-a-lane.sqlite3"
            invalid.parent.mkdir(parents=True)
            invalid.write_text("not sqlite", encoding="utf-8")

            result = detect_lane_inventory(root)

            self.assertEqual(result["summary"]["materialized_generations"], 0)
            self.assertEqual(result["summary"]["issues"], 1)
            self.assertEqual(
                result["issues"][0]["path"], str(invalid.relative_to(root))
            )


if __name__ == "__main__":
    unittest.main()
