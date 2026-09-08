from contextlib import redirect_stdout
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fidb_poc.runtime_libraries import (
    RuntimeLibraryResolver,
    load_runtime_library_catalog,
    runtime_library_status,
)
from fidb_poc.toolchain_cli import main as toolchain_main


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
        self.assertEqual(
            catalog["provider"][1]["plan"],
            "plans/c-malware-priority-uclibc-v1.toml",
        )

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

    def test_cached_resolver_reuses_compiled_route_authority(self):
        resolver = RuntimeLibraryResolver(self.root)

        provider, route = resolver.resolve("glibc", "linux-x86-64-gcc-12", probe=False)

        self.assertEqual(provider["state"], "qualified-unprobed")
        self.assertEqual(provider["route_id"], route.id)
        self.assertEqual(provider["toolchain_identity"], route.toolchain_identity)

    def test_runtime_status_cli_is_read_only_by_default(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = toolchain_main(
                ["runtime", "status", "--project-root", str(self.root)]
            )

        document = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertFalse(document["probe"])
        self.assertEqual(document["summary"]["cells"], 95)
