import unittest
from pathlib import Path

from fidb_poc.authority_catalog import authority_catalog
from fidb_poc.cohort_validation import load_cohort_validation_lifecycle


class CohortValidationLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]

    def test_authority_freezes_scientific_and_scheduler_boundaries(self):
        authority = load_cohort_validation_lifecycle(self.root)

        self.assertEqual(authority["scientific_cohort_size"], 10)
        self.assertEqual(
            authority["execution"]["scientific_boundary"],
            "completed-library-cohort",
        )
        self.assertEqual(
            authority["execution"]["scheduler_boundary"],
            "time-bounded-resumable-block",
        )
        self.assertTrue(authority["fusion"]["enabled_for_new_runs"])
        self.assertEqual(authority["fusion"]["routine_backfill"], "forbidden")
        self.assertFalse(authority["admission"]["automatic_corpus_admission"])

    def test_projection_adds_validation_and_admission_to_every_cohort(self):
        status = authority_catalog(self.root)["cohort_validation"]
        cohorts = status["programmes"][0]["cohorts"]

        self.assertEqual(len(cohorts), 28)
        self.assertEqual(cohorts[0]["work"]["validation_composites"], 444)
        self.assertEqual(cohorts[-1]["capacity"], 6)
        self.assertEqual(cohorts[-1]["work"]["validation_composites"], 444)
        self.assertEqual(
            [stage["id"] for stage in cohorts[0]["stages"]],
            [
                "source-recipe-preparation",
                "recipe-qualification",
                "width-build",
                "validation-composites",
                "query-evidence-export",
                "incremental-corpus-query",
                "hash-discrimination",
                "retention",
                "corpus-admission",
            ],
        )


if __name__ == "__main__":
    unittest.main()
