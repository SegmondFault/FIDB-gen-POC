from pathlib import Path
import shutil
import tempfile
import unittest

from fidb_poc.hash_discrimination import (
    compile_hash_discrimination,
    load_hash_discrimination_authority,
)


class HashDiscriminationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path(__file__).resolve().parents[1]

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "validation").mkdir()
        shutil.copy2(
            self.source / "validation/hash-discrimination.toml",
            self.root / "validation/hash-discrimination.toml",
        )

    def tearDown(self):
        self.temporary.cleanup()

    def compile(self, *, complete_libraries=0, corpus=False, measured=False):
        return compile_hash_discrimination(
            self.root,
            _machine_validation={
                "summary": {"complete_libraries": complete_libraries},
                "results": {"state": "measured-complete" if measured else "not-run"},
            },
            _ecological_validation={"aggregate": {"measured_cases": 0}},
            _noisy_hashes={
                "state": "active-observation",
                "status_digest": "a" * 64,
                "summary": {
                    "observed_hashes": 0,
                    "candidate_noisy": 0,
                    "confirmed_noisy": 0,
                    "quarantined": 0,
                    "reviewed_shared": 0,
                    "cleared": 0,
                    "reports_scanned": 0,
                },
            },
            _lane_inventory={
                "summary": {
                    "materialized_generations": 1 if corpus else 0,
                    "raw_observations": 100 if corpus else 0,
                    "compact_unique_signatures": 80 if corpus else 0,
                }
            },
            _corpus_hash_index={
                "schema_version": "fidb-corpus-hash-index/v1",
                "state": "not-built",
                "database_path": "artifacts/hash-discrimination/corpus-index-v1.sqlite3",
                "authority_sha256": "b" * 64,
            },
        )

    def test_dormant_status_exposes_formula_and_never_invents_scores(self):
        status = self.compile()

        self.assertEqual(status["schema_version"], "fidb-hash-discrimination-status/v1")
        self.assertEqual(status["index"]["abbreviation"], "HDI")
        self.assertEqual(status["state"], "awaiting-c10-evidence")
        self.assertIsNone(status["summary"]["scored_signatures"])
        self.assertEqual(status["scores"], [])
        self.assertFalse(status["readiness"]["ready_for_first_fit"])
        self.assertEqual(
            sum(row["weight_percent"] for row in status["hdi_components"]), 100
        )
        self.assertEqual(
            sum(row["weight_percent"] for row in status["noise_components"]), 100
        )
        self.assertEqual(status["reproducibility"]["randomness"], "none")
        self.assertEqual(
            status["safety"]["missing_measurements"], "unavailable-not-zero"
        )

    def test_even_complete_inputs_remain_blocked_without_contribution_evidence(self):
        status = self.compile(complete_libraries=10, corpus=True, measured=True)

        self.assertFalse(status["readiness"]["ready_for_first_fit"])
        self.assertEqual(
            status["readiness"]["blockers"],
            [
                "candidate-level per-hash attribution contributions are not yet published"
            ],
        )
        self.assertEqual(status["generations"][0]["state"], "waiting-for-evidence")

    def test_authority_rejects_automatic_filtering(self):
        path = self.root / "validation/hash-discrimination.toml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "automatic_filtering = false", "automatic_filtering = true"
            ),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ValueError, "safety or scoring contract"):
            load_hash_discrimination_authority(self.root)
