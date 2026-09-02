import unittest
from pathlib import Path

from fidb_poc.c_width import compile_c_width, load_c_width_authority


class CWidthCompilerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]

    def test_compiler_preserves_declared_and_feasible_width(self):
        compiled = compile_c_width(self.root)

        self.assertEqual(compiled["schema_version"], "fidb-width-compilation/v1")
        self.assertEqual(compiled["fixed_recipe"], "zlib@1.3.1")
        self.assertEqual(len(compiled["routes"]), 9)
        self.assertEqual(len(compiled["build_profiles"]), 16)
        self.assertEqual(len(compiled["artifact_profiles"]), 4)
        self.assertEqual(len(compiled["analysis_profiles"]), 6)
        self.assertEqual(len(compiled["admission_profiles"]), 3)
        self.assertEqual(len(compiled["factors"]), 41)
        self.assertEqual(compiled["summary"]["qualified_routes"], 9)
        self.assertEqual(compiled["summary"]["executable_route_profile_pairs"], 54)
        self.assertEqual(compiled["summary"]["feasible_build_cells"], 54)
        self.assertEqual(compiled["summary"]["feasible_full_path_executions"], 108)
        self.assertGreater(compiled["summary"]["inapplicable_pairs"], 0)
        self.assertGreater(compiled["summary"]["unimplemented_applicable_pairs"], 0)
        self.assertEqual(len(compiled["compilation_digest"]), 64)

    def test_every_applicability_cell_has_an_explicit_state(self):
        compiled = compile_c_width(self.root)
        cells = compiled["applicability"]

        self.assertEqual(len(cells), 9 * 16)
        self.assertEqual(
            {row["state"] for row in cells},
            {"executable", "inapplicable", "unimplemented"},
        )
        self.assertTrue(
            all(row["reasons"] for row in cells if row["state"] != "executable")
        )

    def test_layer_authority_is_bounded_and_disarmed(self):
        authority = load_c_width_authority(self.root / "coverage/c-width-v1.toml")

        self.assertEqual(authority["state"], "candidate-disarmed")
        self.assertEqual(authority["selected_replay"], 2)
        self.assertEqual(
            [row["state"] for row in authority["artifact_profiles"]],
            ["registered", "desired", "guarded", "desired"],
        )


if __name__ == "__main__":
    unittest.main()
