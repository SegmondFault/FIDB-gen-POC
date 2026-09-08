import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fidb_poc.runtime_libraries import (
    load_runtime_library_catalog,
    runtime_library_status,
)


class RuntimeLibraryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]

    def test_catalog_separates_route_queries_from_archive_registry(self):
        catalog = load_runtime_library_catalog(self.root)

        self.assertEqual(catalog["schema_version"], "fidb-runtime-library-catalog/v1")
        self.assertEqual(
            [row["subject_id"] for row in catalog["provider"]],
            ["glibc", "uclibc", "libgcc", "libstdcxx"],
        )
        self.assertEqual(catalog["provider"][0]["query"], "-print-file-name=libc.a")
        self.assertEqual(catalog["provider"][1]["registry_family"], "uclibc")

    def test_status_projects_exact_route_and_registry_cells_without_probing(self):
        document = runtime_library_status(self.root)

        self.assertEqual(document["schema_version"], "fidb-runtime-library-status/v1")
        self.assertEqual(document["summary"]["subjects"], 4)
        self.assertEqual(document["summary"]["qualified_route_cells"], 72)
        self.assertEqual(document["summary"]["archive_registry_cells"], 23)
        self.assertEqual(document["summary"]["cells"], 95)
        self.assertEqual(len(document["provider_digest"]), 64)
        self.assertFalse(document["probe"])

    def test_route_probe_rejects_compiler_outside_managed_toolchains(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "libc.a"
            archive.write_bytes(b"not trusted")
            route = type(
                "Route",
                (),
                {"compiler": ("/usr/bin/cc",), "archiver": ("/usr/bin/ar",)},
            )()
            completed = type(
                "Completed",
                (),
                {"returncode": 0, "stdout": str(archive), "stderr": ""},
            )()
            with patch(
                "fidb_poc.runtime_libraries.subprocess.run", return_value=completed
            ):
                from fidb_poc.runtime_libraries import _probe_route_archive

                result = _probe_route_archive(
                    self.root, route, "-print-file-name=libc.a"
                )

        self.assertEqual(result["state"], "compiler-outside-managed-toolchains")
