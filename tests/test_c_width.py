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
        self.assertEqual(compiled["id"], "c-width-v1")
        self.assertEqual(compiled["fixed_recipe"], "openssl@3.5.8")
        self.assertEqual(len(compiled["routes"]), 29)
        self.assertTrue(all(row["compiler_id"] for row in compiled["routes"]))
        self.assertEqual(len({row["compiler_id"] for row in compiled["routes"]}), 8)
        self.assertEqual(len(compiled["build_profiles"]), 16)
        self.assertEqual(len(compiled["artifact_profiles"]), 4)
        self.assertEqual(len(compiled["analysis_profiles"]), 6)
        self.assertEqual(len(compiled["admission_profiles"]), 3)
        self.assertEqual(len(compiled["factors"]), 41)
        self.assertEqual(
            compiled["summary"]["executable_route_profile_pairs"],
            compiled["summary"]["qualified_routes"] * 6,
        )
        self.assertEqual(
            compiled["summary"]["feasible_build_cells"],
            compiled["summary"]["executable_route_profile_pairs"],
        )
        self.assertEqual(
            compiled["summary"]["feasible_full_path_executions"],
            compiled["summary"]["feasible_build_cells"],
        )
        self.assertGreater(compiled["summary"]["inapplicable_pairs"], 0)
        self.assertGreater(compiled["summary"]["unimplemented_applicable_pairs"], 0)
        self.assertEqual(len(compiled["compilation_digest"]), 64)

    def test_every_applicability_cell_has_an_explicit_state(self):
        compiled = compile_c_width(self.root)
        cells = compiled["applicability"]

        self.assertEqual(len(cells), 29 * 16)
        states = {row["state"] for row in cells}
        self.assertTrue(
            states <= {"executable", "unavailable", "inapplicable", "unimplemented"}
        )
        self.assertTrue({"inapplicable", "unimplemented"} < states)
        self.assertTrue(
            all(row["reasons"] for row in cells if row["state"] != "executable")
        )

    def test_layer_authority_is_bounded_and_bound_to_measured_freeze(self):
        authority = load_c_width_authority(
            self.root / "coverage/c-route-toolchain-canary-v1.toml"
        )

        self.assertEqual(authority["state"], "frozen-measured")
        self.assertEqual(authority["selected_replay"], 2)
        self.assertEqual(authority["freeze"]["completed_executions"], 108)
        self.assertEqual(authority["freeze"]["artifact_byte_identical_cells"], 48)
        self.assertEqual(authority["freeze"]["fid_semantic_identical_cells"], 53)
        self.assertEqual(
            [row["state"] for row in authority["artifact_profiles"]],
            ["registered", "desired", "guarded", "desired"],
        )

    def test_substantive_authority_is_disarmed_and_uses_rank_one_subject(self):
        authority = load_c_width_authority(
            self.root / "coverage/c-width-v1.toml"
        )

        self.assertEqual(authority["state"], "candidate-disarmed")
        self.assertEqual(authority["fixed_recipe"], "openssl@3.5.8")
        self.assertEqual(authority["toolchain_profile"], "c-compiler-width-v1")
        self.assertEqual(authority["selected_replay"], 1)
        self.assertIsNone(authority["freeze"])


if __name__ == "__main__":
    unittest.main()
