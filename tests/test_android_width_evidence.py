from pathlib import Path
import tomllib
import unittest


class AndroidWidthEvidenceTests(unittest.TestCase):
    def test_snapshot_preserves_two_generations_and_four_abis(self):
        root = Path(__file__).resolve().parents[1]
        path = (
            root
            / "toolchains/evidence/c-android-width-v1-reference-host-2026-09-02.toml"
        )
        document = tomllib.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(document["profile_id"], "c-android-width-v1")
        self.assertEqual(document["profile_state"], "qualified")
        self.assertEqual(document["qualified_routes"], 8)
        self.assertEqual(document["coverage_requirements"], 4)
        self.assertEqual(document["missing_qualifications"], 0)
        self.assertEqual(document["broken_routes"], 0)
        self.assertEqual(len(document["compiler"]), 2)
        self.assertEqual(
            {row["ndk_release"] for row in document["compiler"]}, {"r27d", "r29"}
        )
        self.assertTrue(all(row["route_count"] == 4 for row in document["compiler"]))
        self.assertEqual(
            document["storage"]["selected_archive_bytes"], 1_447_505_517
        )
        self.assertEqual(
            document["storage"]["selected_extracted_file_bytes"], 4_548_615_143
        )


if __name__ == "__main__":
    unittest.main()
