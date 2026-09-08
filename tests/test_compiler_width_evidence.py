import tomllib
import unittest
from pathlib import Path


class CompilerWidthEvidenceTests(unittest.TestCase):
    def test_snapshot_preserves_all_compiler_and_route_identities(self):
        root = Path(__file__).resolve().parents[1]
        path = (
            root / "toolchains/evidence/c-compiler-width-v1-reference-host-2026-09-02.toml"
        )
        document = tomllib.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(document["profile_state"], "qualified")
        self.assertEqual(document["qualified_routes"], 29)
        self.assertEqual(document["missing_qualifications"], 0)
        self.assertEqual(document["broken_routes"], 0)
        self.assertEqual(len(document["compiler"]), 8)
        self.assertEqual(sum(row["route_count"] for row in document["compiler"]), 29)
        self.assertEqual(sum(len(row["route_ids"]) for row in document["compiler"]), 29)
        self.assertEqual(
            document["storage"]["selected_extracted_file_bytes"], 12_890_591_603
        )


if __name__ == "__main__":
    unittest.main()
