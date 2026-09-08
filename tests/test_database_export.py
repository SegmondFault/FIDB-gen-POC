import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from fidb_poc.database_export import (
    EXPORT_SAFEGUARD_SCHEMA,
    _Artifact,
    _population_digest,
    _safeguard_status,
    build_export,
    inspect_export,
    safeguard_export,
)


class DatabaseExportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for directory in ("artifacts", "evidence", "validation", "lanes"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        self.fidbf = self.root / "evidence/library.fidbf"
        self.fidbf.write_bytes(b"raw fidbf test payload")
        self.quality = self.root / "evidence/hash-quality.sqlite3"
        connection = sqlite3.connect(self.quality)
        connection.execute("CREATE TABLE evidence(value TEXT NOT NULL)")
        connection.execute("INSERT INTO evidence VALUES ('generation-1')")
        connection.commit()
        connection.close()
        (self.root / "validation/report.json").write_text(
            json.dumps({"schema_version": "test-report/v1"}), encoding="utf-8"
        )
        (self.root / "lanes/registry.toml").write_text(
            'schema_version = "test-lanes/v1"\n', encoding="utf-8"
        )
        (self.root / "evidence/seal.json").write_text("{}\n", encoding="utf-8")
        self.ledger = self.root / "evidence/ledger.sqlite3"
        connection = sqlite3.connect(self.ledger)
        connection.execute("CREATE TABLE jobs(active INTEGER, state TEXT)")
        connection.commit()
        connection.close()
        self.retention = self.root / "evidence/retention.toml"
        self.retention.write_text(
            'schema_version = "test-retention/v1"\n', encoding="utf-8"
        )
        digest = hashlib.sha256(self.fidbf.read_bytes()).hexdigest()
        self.identity = "library@1.0:linux-x86-64-gcc:baseline_o2"
        self.artifact = _Artifact(
            identity=self.identity,
            library_id="library",
            library_version="1.0",
            rank=1,
            route_id="linux-x86-64-gcc",
            treatment_id="baseline_o2",
            job_id="job-1",
            batch_id="batch-1",
            cell_id="cell-1",
            source_sha256="a" * 64,
            toolchain_identity="gcc-test",
            ghidra_language_id="x86:LE:64:default",
            ghidra_compiler_spec_id="gcc",
            artifact_path=self.fidbf,
            artifact_sha256=digest,
            artifact_bytes=self.fidbf.stat().st_size,
            seal_path="evidence/seal.json",
            seal_sha256="b" * 64,
            completed_at="2026-09-08T08:00:00+00:00",
        )
        self.authority = {
            "schema_version": "fidb-export/v1",
            "id": "test-export",
            "label": "Test export",
            "release_id": "test-release",
            "language_id": "c",
            "package_format": "tar.zst",
            "compression_level": 1,
            "output_root": "artifacts/exports",
            "authority_path": "export/test.toml",
            "authority_sha256": "c" * 64,
            "safeguard": {
                "required": True,
                "require_idle_ledger": True,
                "receipt": "evidence/source-receipt.json",
                "ledger_snapshot": "evidence/ledger-snapshot.sqlite3",
                "retention_authority": "evidence/retention.toml",
                "package_path": "evidence/source-safeguard.json",
            },
            "population": {
                "ledger": "evidence/ledger.sqlite3",
                "expected_identities_per_library": 1,
                "require_ledger_sha256": True,
            },
            "catalogue": {"path": "index/catalogue.sqlite3"},
            "hash_quality": {
                "database": "evidence/hash-quality.sqlite3",
                "package_path": "index/hash-quality.sqlite3",
            },
            "validation": {
                "report": "validation/report.json",
                "package_path": "validation/report.json",
            },
            "compatibility": {
                "lane_registry": "lanes/registry.toml",
                "package_path": "authority/lanes.toml",
            },
            "verification": {"reopen_archive": True},
        }
        self.status = {
            "schema_version": "fidb-export-status/v1",
            "ready": True,
            "blockers": [],
            "population": {"present": 1, "raw_bytes": self.fidbf.stat().st_size},
            "libraries": [
                {
                    "id": "library",
                    "label": "Library",
                    "version": "1.0",
                    "rank": 1,
                    "present": 1,
                    "bytes": self.fidbf.stat().st_size,
                }
            ],
            "hash_quality": {
                "state": "ready",
                "generation": {
                    "ordinal": 1,
                    "digest": "d" * 64,
                    "owners": 1,
                    "signatures": 1,
                },
            },
        }
        snapshot = self.root / "evidence/ledger-snapshot.sqlite3"
        snapshot.write_bytes(self.ledger.read_bytes())
        receipt = self.root / "evidence/source-receipt.json"
        receipt.write_text(
            json.dumps(
                {
                    "schema_version": EXPORT_SAFEGUARD_SCHEMA,
                    "authority_sha256": self.authority["authority_sha256"],
                    "population_sha256": _population_digest([self.artifact]),
                    "artifact_count": 1,
                    "raw_artifact_bytes": self.fidbf.stat().st_size,
                    "retention_authority_sha256": hashlib.sha256(
                        self.retention.read_bytes()
                    ).hexdigest(),
                    "created_at": "2026-09-08T08:01:00+00:00",
                    "ledger_snapshot": {
                        "path": "evidence/ledger-snapshot.sqlite3",
                        "bytes": snapshot.stat().st_size,
                        "sha256": hashlib.sha256(snapshot.read_bytes()).hexdigest(),
                    },
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self.status["safeguard"] = {
            "state": "current",
            "population_sha256": _population_digest([self.artifact]),
            "receipt_sha256": hashlib.sha256(receipt.read_bytes()).hexdigest(),
        }

    def tearDown(self):
        self.temporary.cleanup()

    def test_build_is_reproducible_and_contains_catalogue_quality_and_raw_fidbf(self):
        sources = {"library": {"id": "library", "version": "1.0", "rank": 1}}
        artifacts = {self.identity: self.artifact}

        with (
            patch(
                "fidb_poc.database_export._load_authority", return_value=self.authority
            ),
            patch(
                "fidb_poc.database_export._expected_identities",
                return_value=(sources, {self.identity}, {"linux-x86-64-gcc"}),
            ),
            patch(
                "fidb_poc.database_export._read_artifacts",
                return_value=(artifacts, []),
            ),
            patch(
                "fidb_poc.database_export.inspect_export",
                return_value=self.status,
            ),
        ):
            first = build_export(self.root)
            first_digest = first["build"]["sha256"]
            second = build_export(self.root)

        self.assertEqual(second["build"]["sha256"], first_digest)
        package = self.root / second["build"]["path"]
        members = subprocess.run(
            ["tar", "--use-compress-program=zstd", "-tf", str(package)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        self.assertIn(self.artifact.package_path, members)
        self.assertIn("index/catalogue.sqlite3", members)
        self.assertIn("index/hash-quality.sqlite3", members)
        self.assertIn("evidence/source-safeguard.json", members)
        self.assertIn("manifest.md", members)
        self.assertIn("checksums.sha256", members)
        self.assertEqual(len(members), len(set(members)))

        manifest = subprocess.run(
            [
                "tar",
                "--use-compress-program=zstd",
                "-xOf",
                str(package),
                "manifest.md",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        self.assertIn("## Libraries and versions covered", manifest)
        self.assertIn("| `library` | `1.0` |", manifest)
        self.assertIn("## Execution variants covered", manifest)
        self.assertIn("`linux-x86-64-gcc`", manifest)
        self.assertIn("## Database files", manifest)
        self.assertIn("#### `fidbf_artifact`", manifest)
        self.assertIn("#### `evidence`", manifest)
        self.assertIn("| Native Ghidra `.fidb` files | 0 |", manifest)
        self.assertIn("| Raw Ghidra `.fidbf` files | 1 |", manifest)

    def test_safeguard_snapshots_idle_ledger_and_receipts_exact_artifacts(self):
        sources = {"library": {"id": "library", "version": "1.0", "rank": 1}}
        artifacts = {self.identity: self.artifact}
        (self.root / self.authority["safeguard"]["receipt"]).unlink()
        (self.root / self.authority["safeguard"]["ledger_snapshot"]).unlink()

        def status(*_args, require_safeguard=True, **_kwargs):
            document = dict(self.status)
            safeguard = _safeguard_status(
                self.root,
                self.authority,
                population_digest=_population_digest([self.artifact]),
                artifact_count=1,
                raw_bytes=self.fidbf.stat().st_size,
                live_jobs=0,
            )
            document["safeguard"] = safeguard
            blocked = require_safeguard and safeguard["state"] != "current"
            document["blockers"] = (
                ["export source safeguard is missing, stale or invalid"]
                if blocked
                else []
            )
            document["ready"] = not blocked
            return document

        with (
            patch(
                "fidb_poc.database_export._load_authority",
                return_value=self.authority,
            ),
            patch(
                "fidb_poc.database_export._expected_identities",
                return_value=(sources, {self.identity}, {"linux-x86-64-gcc"}),
            ),
            patch(
                "fidb_poc.database_export._read_artifacts",
                return_value=(artifacts, []),
            ),
            patch("fidb_poc.database_export.inspect_export", side_effect=status),
        ):
            result = safeguard_export(self.root)

        receipt = json.loads(
            (self.root / self.authority["safeguard"]["receipt"]).read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(result["safeguard"]["state"], "current")
        self.assertEqual(receipt["artifact_count"], 1)
        self.assertEqual(receipt["artifacts"][0]["identity"], self.identity)
        self.assertEqual(
            receipt["artifacts"][0]["sha256"], self.artifact.artifact_sha256
        )
        self.assertTrue(
            (self.root / self.authority["safeguard"]["ledger_snapshot"]).is_file()
        )

    def test_current_authority_preview_finds_the_exact_openssl_gap(self):
        project = Path(__file__).resolve().parents[1]
        if not (project / "var/fidb-coordinator/ledger.sqlite3").is_file():
            self.skipTest("local C10 ledger is not present")
        status = inspect_export(project)
        openssl = next(row for row in status["libraries"] if row["id"] == "openssl")
        self.assertEqual(status["population"]["expected"], 2_220)
        self.assertEqual(openssl["expected"], 222)
        self.assertEqual(status["population"]["missing"], openssl["missing"])


if __name__ == "__main__":
    unittest.main()
