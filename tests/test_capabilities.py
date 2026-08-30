import hashlib
import shutil
import tempfile
import unittest
from pathlib import Path

from fidb_poc import capabilities


class CapabilityDetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_root = Path(__file__).resolve().parents[1]

    def test_detection_never_mutates_toolchain_cache(self):
        with tempfile.TemporaryDirectory() as temporary:
            project_root = Path(temporary)
            shutil.copy2(self.source_root / "worker.json", project_root / "worker.json")
            shutil.copytree(self.source_root / "recipes", project_root / "recipes")
            shutil.copytree(
                self.source_root / "toolchains", project_root / "toolchains"
            )
            cache = project_root / capabilities.TOOLCHAIN_CACHE

            result = capabilities.detect_capabilities(
                project_root,
                environment={"PATH": ""},
            )

            self.assertFalse(cache.exists())
            self.assertEqual(result["detection_mode"], "read-only")
            self.assertTrue(result["toolchains"]["entries"])
            self.assertTrue(
                all(
                    row["state"] == "missing" for row in result["toolchains"]["entries"]
                )
            )

    def test_verified_cache_is_distinct_from_prepared_toolchain(self):
        payload = b"reviewed pinned archive"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            (cache / digest).write_bytes(payload)

            entry = capabilities._cache_entry(cache, digest)

            self.assertEqual(entry["state"], "verified-cached")
            self.assertEqual(entry["observed_sha256"], digest)


if __name__ == "__main__":
    unittest.main()
