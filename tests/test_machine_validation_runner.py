import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from fidb_poc.machine_validation_runner import _query_index, load_runtime


class MachineValidationRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]

    def test_runtime_is_toml_controlled_and_never_executes_targets(self):
        runtime = load_runtime(self.root)

        self.assertEqual(runtime["validation_id"], "c-top10-cohort-001")
        self.assertEqual(runtime["execution"]["workers"], 4)
        self.assertFalse(runtime["safety"]["execute_target_binaries"])
        self.assertEqual(runtime["canary"]["positions"], [1, 145, 175])

    def test_reference_query_can_include_or_withhold_exact_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            index = root / "reference.sqlite3"
            connection = sqlite3.connect(index)
            connection.execute(
                """
                CREATE TABLE reference_signature(
                    language TEXT, full_hash TEXT, specific_hash TEXT,
                    additional_size INTEGER, code_size INTEGER, owner TEXT,
                    route_id TEXT, treatment_id TEXT, function_name TEXT,
                    evidence_path TEXT
                )
                """
            )
            connection.executemany(
                "INSERT INTO reference_signature VALUES (?,?,?,?,?,?,?,?,?,?)",
                [
                    ("x86:LE:64:default", "01", "02", 3, 4, "one@1", "r1", "t1", "one", "one.jsonl"),
                    ("x86:LE:64:default", "01", "02", 3, 4, "one@1", "r2", "t2", "one", "two.jsonl"),
                ],
            )
            connection.commit()
            connection.close()
            query = root / "query.jsonl"
            query.write_text(
                json.dumps(
                    {
                        "address": "1000",
                        "function_name": "anonymous",
                        "ghidra_language_id": "x86:LE:64:default",
                        "full_hash": "01",
                        "specific_hash": "02",
                        "specific_hash_additional_size": 3,
                        "code_unit_size": 4,
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            included, _ = _query_index(index, query, "r1", "t1", True)
            withheld, _ = _query_index(index, query, "r1", "t1", False)

            self.assertEqual(len(included["one@1"]), 1)
            self.assertEqual(len(withheld["one@1"]), 1)
            connection = sqlite3.connect(index)
            connection.execute("DELETE FROM reference_signature WHERE route_id='r2'")
            connection.commit()
            connection.close()
            withheld, _ = _query_index(index, query, "r1", "t1", False)
            self.assertNotIn("one@1", withheld)


if __name__ == "__main__":
    unittest.main()
