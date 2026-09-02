import unittest
from pathlib import Path

from fidb_poc.compiler_identities import load_compiler_identities


class CompilerIdentityTests(unittest.TestCase):
    def test_target_independent_compiler_generations_are_explicit(self):
        root = Path(__file__).resolve().parents[1]
        rows = load_compiler_identities(root / "toolchains/compilers.toml")
        by_id = {row["id"]: row for row in rows}

        self.assertEqual(by_id["gcc-12.3.0"]["family"], "gcc")
        self.assertEqual(by_id["gcc-14.3.0"]["generation"], "14")
        self.assertEqual(by_id["llvm-clang-15.0.0"]["family"], "llvm-clang")
        self.assertEqual(by_id["llvm-clang-23.1.0"]["generation"], "23")


if __name__ == "__main__":
    unittest.main()
