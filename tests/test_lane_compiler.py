import csv
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from fidb_poc.lane_compiler import (
    build_lane_from_plan,
    compile_lane_plan,
    iter_lane_occurrences,
)


class LaneCompilerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_root = Path(__file__).resolve().parents[1]

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for name in ("coverage", "lanes", "targets", "toolchains"):
            shutil.copytree(self.source_root / name, self.root / name)
        self.run = self.root / "artifacts/width-runs/test-width/test-run"
        group = self.run / "replay-01/group-001"
        ledger = group / "artifacts/libs/fid-signatures/example.jsonl"
        ledger.parent.mkdir(parents=True)
        rows = [
            {
                "language": "x86:LE:64:default",
                "full_hash": "0000000000000001",
                "specific_hash": "1000000000000001",
                "specific_hash_additional_size": 1,
                "code_unit_size": 12,
                "domain_path": "/example.o",
                "name": name,
            }
            for name in ("example_one", "example_two")
        ]
        ledger.write_text(
            "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
        )
        manifest = group / "artifacts/libs/fidb_manifest.csv"
        with manifest.open("w", newline="", encoding="utf-8") as stream:
            fieldnames = (
                "status",
                "route",
                "treatment",
                "target_os",
                "architecture",
                "binary_format",
                "library",
                "version",
                "source_url",
                "source_sha256",
                "compiler_version",
                "compiler_sha256",
                "ghidra_language",
                "ghidra_compiler_spec",
                "ghidra_version",
                "ghidra_release",
                "ghidra_build",
                "fid_signatures_path",
                "fid_signatures_sha256",
                "fid_signature_records",
            )
            writer = csv.DictWriter(stream, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerow(
                {
                    "status": "complete",
                    "route": "linux-x86-64-gcc",
                    "treatment": "baseline_o2",
                    "target_os": "linux",
                    "architecture": "x86_64",
                    "binary_format": "ELF",
                    "library": "example",
                    "version": "1.0",
                    "source_url": "https://example.invalid/example.tar.gz",
                    "source_sha256": "1" * 64,
                    "compiler_version": "gcc 14.3.0",
                    "compiler_sha256": "2" * 64,
                    "ghidra_language": "x86:LE:64:default",
                    "ghidra_compiler_spec": "gcc",
                    "ghidra_version": "12.1.2",
                    "ghidra_release": "DEV",
                    "ghidra_build": "2026-Jun-29 1514 GMT",
                    "fid_signatures_path": (
                        "artifacts/libs/fid-signatures/example.jsonl"
                    ),
                    "fid_signatures_sha256": hashlib.sha256(
                        ledger.read_bytes()
                    ).hexdigest(),
                    "fid_signature_records": 2,
                }
            )
        (self.run / "width-run.json").write_text(
            json.dumps(
                {
                    "schema_version": "fidb-width-run/v1",
                    "state": "measured-complete",
                    "fixed_recipe": "example@1.0",
                    "finished_at_utc": "2026-09-02T20:00:00+00:00",
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self):
        self.temporary.cleanup()

    def test_preview_selects_lane_without_reading_or_deduplicating_records(self):
        plan = compile_lane_plan(self.root, self.run, "linux-x86")

        self.assertEqual(plan["deduplication"], "not-performed")
        self.assertEqual(plan["lane"]["id"], "linux-x86")
        self.assertEqual(plan["lane"]["selected_sublane_ids"], ["linux-x86-elf64"])
        self.assertEqual(plan["summary"]["raw_signature_records"], 2)
        self.assertIsNone(plan["summary"]["deduplicated_signatures"])

    def test_build_preserves_every_ledger_row_in_raw_database(self):
        plan = compile_lane_plan(self.root, self.run, "linux-x86")
        output = self.root / "var/fidb-lanes/linux-x86/test.raw.sqlite3"

        result = build_lane_from_plan(self.root, plan, output, "linux-x86-test-v1")

        self.assertEqual(result["counts"]["raw_signature_observation"], 2)
        self.assertEqual(result["generation"]["signature_records"], 2)

    def test_changed_signature_ledger_fails_before_publication(self):
        plan = compile_lane_plan(self.root, self.run, "linux-x86")
        ledger = self.root / plan["cells"][0]["signature_ledger_path"]
        ledger.write_text("{}\n", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "digest differs"):
            list(iter_lane_occurrences(self.root, plan))


if __name__ == "__main__":
    unittest.main()
