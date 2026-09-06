import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

from fidb_poc.noisy_hashes import compile_noisy_hashes, save_noisy_hash_decision


class NoisyHashTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path(__file__).resolve().parents[1]

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for name in ("lanes", "targets", "toolchains", "validation"):
            shutil.copytree(self.source / name, self.root / name)
        for index, owner in enumerate(("wrong-a@1", "wrong-b@2"), start=1):
            case = self.root / f"var/fidb-ecological-validation/cases/eco-run-{index}"
            case.mkdir(parents=True)
            failures = [
                {
                    "failure_type": "collision",
                    "owner": owner,
                    "signature": "0123456789abcdef:fedcba9876543210:4:40",
                    "route_id": "linux-x86-64-gcc",
                    "compiler_id": "gcc-14.3.0",
                    "treatment_id": "baseline_o2",
                    "target_function": f"FUN_{index}_{repeat}",
                    "evidence_path": f"evidence-{index}-{repeat}",
                }
                for repeat in range(2)
            ]
            (case / "report.json").write_text(
                json.dumps(
                    {
                        "schema_version": "fidb-ecological-validation-report/v1",
                        "case_id": f"eco-run-{index}",
                        "probe": {"sublane_id": "linux-x86-elf64"},
                        "failures": failures,
                    }
                ),
                encoding="utf-8",
            )

    def tearDown(self):
        self.temporary.cleanup()

    def test_recurring_cross_run_collision_is_confirmed_and_manageable(self):
        status = compile_noisy_hashes(self.root)
        self.assertEqual(status["summary"]["confirmed_noisy"], 1)
        self.assertEqual(status["summary"]["returned_hashes"], 1)
        self.assertEqual(status["summary"]["hash_rows_truncated"], 0)
        row = status["hashes"][0]
        self.assertEqual(row["scope"], "linux-x86-elf64")
        self.assertEqual(row["collisions"], 4)
        self.assertEqual(row["distinct_runs"], 2)
        self.assertEqual(row["distinct_owners"], 2)
        self.assertEqual(row["risk"], "high")

        updated = save_noisy_hash_decision(
            self.root,
            row["signature_id"],
            "quarantine",
            "Repeated false attribution in two held-out binaries.",
        )
        self.assertEqual(updated["summary"]["quarantined"], 1)
        self.assertEqual(updated["hashes"][0]["disposition"], "quarantine")
        decision = (
            self.root / f'validation/noisy-hash-decisions/{row["signature_id"]}.toml'
        )
        self.assertTrue(decision.is_file())

    def test_transport_limit_preserves_full_population_digest_and_counts(self):
        full = compile_noisy_hashes(self.root)
        summary_only = compile_noisy_hashes(self.root, max_hash_rows=0)

        self.assertEqual(summary_only["hashes"], [])
        self.assertEqual(summary_only["summary"]["observed_hashes"], 1)
        self.assertEqual(summary_only["summary"]["returned_hashes"], 0)
        self.assertEqual(summary_only["summary"]["hash_rows_truncated"], 1)
        self.assertEqual(summary_only["status_digest"], full["status_digest"])

    def test_machine_hash_evidence_reads_every_fp_observation(self):
        evidence = (
            self.root / "artifacts/validation-runs/cohort/run/hash-evidence.sqlite3"
        )
        evidence.parent.mkdir(parents=True)
        connection = sqlite3.connect(evidence)
        connection.executescript("""
            CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE hash_observation(
                scope TEXT, language TEXT, full_hash TEXT, specific_hash TEXT,
                additional_size INTEGER, code_size INTEGER, outcome TEXT,
                owner TEXT, route_id TEXT, treatment_id TEXT, fold TEXT,
                query_address TEXT, query_function TEXT,
                corpus_function TEXT, evidence_path TEXT
            );
            """)
        connection.executemany(
            "INSERT INTO metadata VALUES (?,?)",
            [
                ("schema_version", "fidb-machine-validation-hash-evidence/v1"),
                ("state", "complete"),
                ("source_run_id", "machine-run"),
            ],
        )
        connection.executemany(
            "INSERT INTO hash_observation VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    "linux|ELF|lang",
                    "lang",
                    "aa",
                    "bb",
                    1,
                    20,
                    "fp",
                    owner,
                    "route",
                    "treatment",
                    "A",
                    "1000",
                    "query",
                    "corpus",
                    "reference.jsonl",
                )
                for owner in ("wrong-a@1", "wrong-b@2")
            ],
        )
        connection.commit()
        connection.close()

        status = compile_noisy_hashes(self.root)
        machine = next(
            row for row in status["hashes"] if row["scope"] == "linux|ELF|lang"
        )

        self.assertEqual(status["summary"]["evidence_databases_scanned"], 1)
        self.assertEqual(machine["collisions"], 2)
        self.assertEqual(machine["distinct_owners"], 2)
        self.assertEqual(machine["sources"], ["machine"])
