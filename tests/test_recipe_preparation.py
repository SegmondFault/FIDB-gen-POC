from __future__ import annotations

from pathlib import Path
import unittest

from fidb_poc.recipe_preparation import load_recipe_preparation


class RecipePreparationTests(unittest.TestCase):
    def test_priority_plan_covers_sources_and_detection_subjects(self):
        root = Path(__file__).resolve().parents[1]

        plan = load_recipe_preparation(root)

        self.assertEqual(plan["schema_version"], "fidb-recipe-preparation-status/v1")
        self.assertEqual(plan["summary"]["source_families"], 23)
        self.assertEqual(plan["summary"]["detection_subjects"], 25)
        self.assertEqual(plan["summary"]["recipe_ready"], 2)
        by_id = {row["source_family"]: row for row in plan["families"]}
        self.assertEqual(by_id["gcc"]["detection_subjects"], ["libgcc", "libstdcxx"])
        self.assertEqual(
            by_id["ncurses"]["detection_subjects"], ["ncurses", "libtinfo"]
        )
        self.assertEqual(
            by_id["opencl-loader"]["state"], "dependency-contract-required"
        )
        self.assertEqual(by_id["libpcap"]["source_version"], "1.10.7")


if __name__ == "__main__":
    unittest.main()
