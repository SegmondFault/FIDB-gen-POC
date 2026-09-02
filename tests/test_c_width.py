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
        authority = load_c_width_authority(self.root / "coverage/c-width-v1.toml")

        self.assertEqual(authority["state"], "candidate-disarmed")
        self.assertEqual(authority["fixed_recipe"], "openssl@3.5.8")
        self.assertEqual(authority["toolchain_profile"], "c-compiler-width-v1")
        self.assertEqual(authority["selected_replay"], 1)
        self.assertIsNone(authority["freeze"])

    def test_android_width_extends_v1_without_changing_its_frozen_membership(self):
        original = compile_c_width(self.root, "c-width-v1")
        extended = compile_c_width(self.root, "c-width-v2")
        gap = compile_c_width(self.root, "c-android-gap-v1")

        original_routes = {row["id"] for row in original["routes"]}
        extended_routes = {row["id"] for row in extended["routes"]}
        gap_routes = {row["id"] for row in gap["routes"]}
        self.assertEqual(len(original_routes), 29)
        self.assertEqual(len(gap_routes), 8)
        self.assertEqual(extended_routes, original_routes | gap_routes)
        self.assertTrue(original_routes.isdisjoint(gap_routes))
        self.assertEqual(extended["summary"]["feasible_full_path_executions"], 222)
        self.assertEqual(gap["summary"]["feasible_full_path_executions"], 48)
        self.assertEqual(len({row["compiler_id"] for row in extended["routes"]}), 10)
        self.assertEqual(len({row["compiler_id"] for row in gap["routes"]}), 2)
        self.assertEqual(extended["state"], "candidate-disarmed")
        self.assertEqual(gap["state"], "candidate-disarmed")


if __name__ == "__main__":
    unittest.main()
