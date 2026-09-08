import unittest
from pathlib import Path

from fidb_poc.campaign_programme import compile_campaign_programme
from fidb_poc.priority_schedule import compile_priority_schedule
from fidb_poc.runtime_libraries import runtime_library_status


class PriorityScheduleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        programme = compile_campaign_programme(cls.root)
        recipes = [
            {
                "id": path.stem,
                "name": (
                    path.stem.split("-")[0] if path.stem == "zlib-1.3.2" else path.stem
                ),
                "kind": "native",
            }
            for path in sorted((cls.root / "recipes").glob("*.toml"))
        ]
        recipes.append(
            {"id": "uclibc@0.9.30.1", "name": "uclibc", "kind": "source-library"}
        )
        cls.schedule = compile_priority_schedule(
            cls.root,
            "coverage/c-malware-priority-v1.toml",
            programme=programme,
            recipes=recipes,
            runtime_libraries=runtime_library_status(cls.root),
        )

    def test_exact_operator_order_is_frozen_into_three_disarmed_cohorts(self):
        subjects = [
            row for cohort in self.schedule["cohorts"] for row in cohort["subjects"]
        ]

        self.assertEqual(self.schedule["state"], "planned-disarmed")
        self.assertEqual(self.schedule["summary"]["subjects"], 25)
        self.assertEqual(self.schedule["summary"]["source_families"], 23)
        self.assertEqual(
            [row["capacity"] for row in self.schedule["cohorts"]], [10, 10, 5]
        )
        self.assertEqual(
            [row["id"] for row in subjects[:6]],
            ["boringssl", "glibc", "uclibc", "libgcc", "libstdcxx", "zlib"],
        )
        self.assertEqual(subjects[-2]["id"], "libssh2")
        self.assertEqual(subjects[-1]["id"], "libpcap")

    def test_c80_overlap_reorders_without_duplicating_research_candidates(self):
        subjects = [
            row for cohort in self.schedule["cohorts"] for row in cohort["subjects"]
        ]
        libgcc = next(row for row in subjects if row["id"] == "libgcc")
        libstdcxx = next(row for row in subjects if row["id"] == "libstdcxx")
        ncurses = next(row for row in subjects if row["id"] == "ncurses")
        libtinfo = next(row for row in subjects if row["id"] == "libtinfo")

        self.assertEqual(self.schedule["summary"]["research_overlap_subjects"], 14)
        self.assertEqual(self.schedule["summary"]["research_overlap_candidates"], 12)
        self.assertEqual(self.schedule["summary"]["priority_additions"], 11)
        self.assertEqual(libgcc["research_key"], libstdcxx["research_key"])
        self.assertEqual(ncurses["research_key"], libtinfo["research_key"])

    def test_maximum_workload_preserves_detection_subjects_but_qualifies_sources_once(
        self,
    ):
        summary = self.schedule["summary"]

        self.assertEqual(summary["maximum_subject_executions"], 25 * 222)
        self.assertEqual(summary["maximum_source_qualification_cells"], 23 * 16)
        self.assertEqual(len(self.schedule["schedule_digest"]), 64)

    def test_runtime_owned_subjects_are_explicit_execution_providers(self):
        subjects = {
            row["id"]: row
            for cohort in self.schedule["cohorts"]
            for row in cohort["subjects"]
        }

        self.assertEqual(self.schedule["summary"]["runtime_provider_ready"], 4)
        self.assertEqual(subjects["glibc"]["runtime_provider_cells"], 24)
        self.assertEqual(subjects["uclibc"]["runtime_provider_cells"], 23)
        self.assertTrue(subjects["libgcc"]["runtime_plan_bound"])
        self.assertEqual(subjects["libgcc"]["stage"], "queue-candidate")


if __name__ == "__main__":
    unittest.main()
