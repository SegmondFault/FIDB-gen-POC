from __future__ import annotations

import csv
import os
import platform
import shutil
import tempfile
import unittest
from pathlib import Path

from fidb_poc.config import load_configuration, select_configuration
from fidb_poc.pipeline import execute, sha256


def native_route() -> str | None:
    requested = os.environ.get("FIDB_SMOKE_ROUTE")
    if requested:
        return requested
    machine = platform.machine().lower()
    if platform.system() == "Linux" and machine in {"x86_64", "amd64"}:
        return "linux-x86_64-gnu-gcc"
    return None


@unittest.skipUnless(
    os.environ.get("FIDB_RUN_LIVE_SMOKE") == "1",
    "set FIDB_RUN_LIVE_SMOKE=1 to run the compiler/Ghidra integration smoke test",
)
class LivePipelineSmokeTests(unittest.TestCase):
    def test_native_zlib_pipeline_produces_verified_fidb(self) -> None:
        route = native_route()
        if route is None:
            self.skipTest("set FIDB_SMOKE_ROUTE for this host")

        repository = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            project_root = Path(temporary)
            shutil.copy(repository / "worker.json", project_root / "worker.json")
            shutil.copytree(repository / "recipes", project_root / "recipes")
            shutil.copytree(
                repository / "ghidra_scripts", project_root / "ghidra_scripts"
            )
            configuration = load_configuration(
                project_root / "worker.json", request_override=("zlib",)
            )
            configuration = select_configuration(
                configuration,
                route_ids=(route,),
                treatment_ids=None,
                profile="smoke",
            )

            manifest = execute(configuration, project_root)

            with manifest.open(newline="", encoding="utf-8") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row["status"], "complete", row["error"])
            self.assertEqual(row["source_sha256"], configuration.libraries[0].sha256)
            self.assertGreater(int(row["object_count"]), 0)
            self.assertGreater(int(row["fid_programs"]), 0)
            self.assertGreater(int(row["fid_attempted"]), 0)
            self.assertGreater(int(row["fid_added"]), 0)
            self.assertEqual(
                int(row["fid_attempted"]),
                int(row["fid_added"]) + int(row["fid_excluded"]),
            )
            fidb = project_root / row["fidb_path"]
            self.assertTrue(fidb.is_file())
            self.assertGreater(fidb.stat().st_size, 0)
            self.assertEqual(sha256(fidb), row["fidb_sha256"])
