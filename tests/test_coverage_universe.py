import tempfile
import unittest
from pathlib import Path

from fidb_poc.coverage_universe import load_coverage_universe


class CoverageUniverseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]

    def test_repository_universe_separates_dimensions_profiles_and_scale(self):
        document = load_coverage_universe(self.root / "coverage/universe.toml")

        self.assertEqual(document["schema_version"], "fidb-coverage-universe/v2")
        self.assertEqual(len(document["dimensions"]), 7)
        self.assertEqual(
            {row["id"] for row in document["languages"]},
            {"c", "cpp", "rust", "go", "swift", "other"},
        )
        self.assertEqual(len(document["compiler_families"]), 8)
        self.assertEqual(len(document["profiles"]), 16)
        self.assertTrue(all(row["language_id"] == "c" for row in document["profiles"]))
        self.assertEqual(
            {row["matrix_role"] for row in document["dimensions"]},
            {
                "multiplier",
                "applicability",
                "bounded-profile",
                "analysis-reuse",
                "policy-control",
            },
        )
        self.assertEqual(
            {row["id"]: row["unique_executions"] for row in document["scenarios"]}[
                "c-stress-envelope"
            ],
            339_600,
        )
        self.assertEqual(
            document["population"]["nine_source_shared_frontier_keys"],
            7_801,
        )
        self.assertEqual(
            document["population"]["nine_source_n80_candidate_rank"],
            1_005,
        )

    def test_incorrect_scenario_product_fails_closed(self):
        source = (self.root / "coverage/universe.toml").read_text(encoding="utf-8")
        source = source.replace("unique_executions = 5094", "unique_executions = 5095")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "universe.toml"
            path.write_text(source, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must equal its multipliers"):
                load_coverage_universe(path)

    def test_unknown_language_scope_fails_closed(self):
        source = (self.root / "coverage/universe.toml").read_text(encoding="utf-8")
        source = source.replace('language_id = "c"', 'language_id = "unknown"', 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "universe.toml"
            path.write_text(source, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unknown language"):
                load_coverage_universe(path)


if __name__ == "__main__":
    unittest.main()
