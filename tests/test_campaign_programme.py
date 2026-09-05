import unittest
from pathlib import Path

from fidb_poc.campaign_programme import compile_campaign_programme


class CampaignProgrammeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.programme = compile_campaign_programme(cls.root)

    def test_published_c80_frontier_is_exact_and_disarmed(self):
        programme = self.programme

        self.assertEqual(
            programme["schema_version"], "fidb-campaign-programme-status/v1"
        )
        self.assertEqual(programme["state"], "planned-disarmed")
        self.assertEqual(programme["summary"]["candidate_population"], 276)
        self.assertEqual(programme["summary"]["research_source_pinned_candidates"], 275)
        self.assertEqual(programme["source_acquisition"]["unresolved"], 1)
        self.assertEqual(programme["summary"]["cohorts"], 28)
        self.assertEqual(programme["summary"]["full_cohorts"], 27)
        self.assertEqual(programme["summary"]["final_cohort_size"], 6)
        self.assertEqual(programme["summary"]["planned_qualification_cells"], 4_416)
        self.assertEqual(programme["summary"]["planned_campaign_executions"], 61_272)
        self.assertAlmostEqual(programme["candidate_cumulative_proxy_pct"], 80.044856)

    def test_candidate_rows_and_cohorts_preserve_research_order(self):
        cohorts = self.programme["cohorts"]
        candidates = [row for cohort in cohorts for row in cohort["candidates"]]

        self.assertEqual([row["rank"] for row in candidates], list(range(1, 277)))
        self.assertEqual(
            [row["canonical_key"] for row in cohorts[0]["candidates"][:3]],
            ["openssl", "cmake", "zlib"],
        )
        self.assertEqual(cohorts[-1]["candidates"][-1]["canonical_key"], "openal-soft")
        self.assertEqual(cohorts[-1]["candidate_rank_start"], 271)
        self.assertEqual(cohorts[-1]["candidate_rank_end"], 276)

    def test_readiness_is_an_overlay_not_candidate_promotion(self):
        candidates = [
            row for cohort in self.programme["cohorts"] for row in cohort["candidates"]
        ]
        openssl = next(row for row in candidates if row["canonical_key"] == "openssl")
        cmake = next(row for row in candidates if row["canonical_key"] == "cmake")
        sqlite = next(row for row in candidates if row["canonical_key"] == "sqlite3")

        self.assertTrue(openssl["screened"])
        self.assertTrue(openssl["research_source_pinned"])
        self.assertTrue(openssl["recipe_ready"])
        self.assertFalse(cmake["screened"])
        self.assertTrue(cmake["research_source_pinned"])
        self.assertEqual(cmake["stage"], "candidate-screen")
        self.assertEqual(sqlite["subject_id"], "sqlite")
        self.assertTrue(sqlite["source_pinned"])
        opengl = next(row for row in candidates if row["canonical_key"] == "opengl")
        self.assertFalse(opengl["research_source_pinned"])
        self.assertIn("virtual-system-interface", opengl["research_source_reason"])


if __name__ == "__main__":
    unittest.main()
