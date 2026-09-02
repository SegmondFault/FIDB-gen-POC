import tempfile
import unittest
from pathlib import Path

from fidb_poc.authority_catalog import authority_catalog
from fidb_poc.width_batch import load_width_batch, project_width_batch_readiness


class WidthBatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.path = cls.root / "batches/c-next-nine-mega-width.toml"

    def test_next_nine_are_bound_to_expanded_nonapple_width(self):
        batch = load_width_batch(self.root, self.path)

        self.assertEqual(batch["state"], "defined-disarmed")
        self.assertEqual(
            [row["id"] for row in batch["libraries"]],
            [
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
        self.assertEqual(batch["summary"]["route_profiles"], 37)
        self.assertEqual(batch["summary"]["compiler_identities"], 10)
        self.assertEqual(batch["summary"]["executable_treatments"], 6)
        self.assertEqual(batch["summary"]["executions_per_library"], 222)
        self.assertEqual(batch["summary"]["total_executions"], 1_998)
        self.assertEqual(batch["summary"]["locally_qualified_routes"], 37)
        self.assertEqual(batch["summary"]["locally_executable_per_library"], 222)
        self.assertEqual(len(batch["batch_digest"]), 64)

    def test_openssl_gap_contains_only_new_android_width(self):
        batch = load_width_batch(
            self.root, self.root / "batches/c-openssl-android-gap.toml"
        )

        self.assertEqual([row["id"] for row in batch["libraries"]], ["openssl"])
        self.assertEqual(batch["summary"]["route_profiles"], 8)
        self.assertEqual(batch["summary"]["compiler_identities"], 2)
        self.assertEqual(batch["summary"]["executions_per_library"], 48)
        self.assertEqual(batch["summary"]["total_executions"], 48)
        self.assertEqual(batch["summary"]["locally_executable_per_library"], 48)

    def test_recipe_gates_keep_unimplemented_libraries_out_of_queue(self):
        catalog = authority_catalog(self.root)
        batch = project_width_batch_readiness(
            load_width_batch(self.root, self.path), catalog["recipes"]
        )

        self.assertEqual(batch["readiness"]["source_pins"], 9)
        self.assertEqual(batch["readiness"]["recipe_ready_libraries"], 0)
        self.assertEqual(batch["readiness"]["blocked_executions"], 1_998)
        self.assertEqual(batch["readiness"]["queue_state"], "not-materialized-disarmed")
        self.assertEqual(len(batch["readiness"]["blockers"]), 9)

    def test_changed_dependency_digest_is_rejected(self):
        text = self.path.read_text(encoding="utf-8").replace(
            "97544e2c51d791be6ecfadbe5c493915914651a8db967070736333652be05c57",
            "0" * 64,
        )
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            path = Path(temporary) / "batch.toml"
            path.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError, "source_pack_sha256 no longer matches"
            ):
                load_width_batch(self.root, path)


if __name__ == "__main__":
    unittest.main()
