import unittest
from pathlib import Path

from fidb_poc.compiler_width_assets import load_compiler_width_assets
from fidb_poc.toolchain_packs import resolve_toolchain_profile


class CompilerWidthAssetsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]

    def test_compact_authority_expands_selected_downloadable_width(self):
        width = load_compiler_width_assets(self.root / "toolchains/compiler-width.toml")

        self.assertEqual(len(width["gcc_targets"]), 8)
        self.assertEqual(len(width["gcc_generations"]), 2)
        self.assertEqual(len(width["packs"]), 20)
        self.assertEqual(len(width["routes"]), 20)
        self.assertEqual(len(width["qualifications"]), 20)
        self.assertEqual(
            {row["compiler_id"] for row in width["routes"]},
            {
                "gcc-12.3.0",
                "gcc-13.3.0",
                "llvm-clang-15.0.0",
                "llvm-clang-17.0.6",
                "llvm-clang-19.1.6",
                "llvm-clang-20.1.7",
            },
        )

    def test_profile_preserves_target_and_compiler_multiplicity(self):
        plan = resolve_toolchain_profile(self.root, "c-compiler-width-v1")

        self.assertEqual(plan["summary"]["routes"], 29)
        self.assertEqual(plan["summary"]["coverage_requirements"], 9)
        self.assertEqual(plan["summary"]["packs"], 29)
        self.assertEqual(len({row["target_id"] for row in plan["routes"]}), 9)
        self.assertEqual(len({row["compiler_id"] for row in plan["routes"]}), 8)


if __name__ == "__main__":
    unittest.main()
