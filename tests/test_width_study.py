import tempfile
import unittest
from pathlib import Path

from fidb_poc.width_study import load_width_study


class WidthStudyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.path = cls.root / "coverage/c-top10-width-study.toml"

    def test_repository_study_freezes_subjects_and_exposes_reuse_layers(self):
        document = load_width_study(self.path)

        self.assertEqual(document["schema_version"], "fidb-width-study/v1")
        self.assertEqual(document["id"], "batch-010")
        self.assertEqual(document["family_count"], 10)
        self.assertEqual(
            document["scaling"]["comparison_family_counts"], [10, 20, 40, 80]
        )
        self.assertEqual(document["calibration"]["sample_count"], 2)
        self.assertEqual(
            document["calibration"]["retained_bundle_bytes_p50"], 31_265_942
        )
        self.assertEqual(len(document["toolchain_requirements"]), 22)
        self.assertEqual(
            [
                (row["order"], row["target_id"], row["compiler_family"])
                for row in document["toolchain_requirements"][:3]
            ],
            [
                (1, "linux-x86-64-elf", "gcc"),
                (2, "macos-arm64-macho", "apple-clang"),
                (3, "windows-x86-64-pecoff", "msvc"),
            ],
        )
        self.assertEqual(
            [row["id"] for row in document["families"]],
            [
                "openssl",
                "sqlite",
                "xz",
                "zstd",
                "pcre2",
                "lz4",
                "gettext",
                "nghttp2",
                "readline",
                "gmp",
            ],
        )
        campaign_b = next(
            row for row in document["presets"] if row["id"] == "campaign-b-18"
        )
        self.assertEqual(campaign_b["metrics"]["build_width_per_family"], 18)
        self.assertEqual(campaign_b["metrics"]["build_cells"], 180)
        self.assertEqual(campaign_b["metrics"]["replayed_executions"], 360)
        wild = next(
            row for row in document["presets"] if row["id"] == "wild-full-stack"
        )
        self.assertEqual(wild["metrics"]["build_cells"], 48_000)
        self.assertEqual(wild["metrics"]["analysis_runs"], 288_000)
        self.assertEqual(wild["metrics"]["replayed_executions"], 576_000)
        self.assertEqual(wild["metrics"]["policy_evaluations"], 864_000)

    def test_top_twenty_study_preserves_ranked_continuation(self):
        document = load_width_study(self.root / "coverage/c-top20-width-study.toml")

        self.assertEqual(document["id"], "study-c20")
        self.assertEqual(document["family_count"], 20)
        self.assertEqual(
            [row["id"] for row in document["families"][10:]],
            [
                "harfbuzz",
                "freetype",
                "glib",
                "expat",
                "brotli",
                "libjpeg-turbo",
                "libunistring",
                "bzip2",
                "libtiff",
                "libpng",
            ],
        )
        self.assertEqual(
            [row["rank"] for row in document["families"][10:]],
            list(range(11, 21)),
        )

    def test_invalid_preset_outside_axis_bounds_fails_closed(self):
        source = self.path.read_text(encoding="utf-8")
        source = source.replace("routes = 20", "routes = 21", 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "study.toml"
            path.write_text(source, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "outside declared bounds"):
                load_width_study(path)

    def test_family_count_mismatch_fails_closed(self):
        source = self.path.read_text(encoding="utf-8")
        source = source.replace("family_count = 10", "family_count = 11", 1)
        source = source.replace(
            "comparison_family_counts = [10, 20, 40, 80]",
            "comparison_family_counts = [11, 20, 40, 80]",
            1,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "study.toml"
            path.write_text(source, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must match family rows"):
                load_width_study(path)

    def test_toolchain_requirement_order_gap_fails_closed(self):
        source = self.path.read_text(encoding="utf-8")
        source = source.replace(
            'order = 20\nid = "windows-x86-32-msvc"',
            'order = 21\nid = "windows-x86-32-msvc"',
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "study.toml"
            path.write_text(source, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "contiguous from one"):
                load_width_study(path)


if __name__ == "__main__":
    unittest.main()
