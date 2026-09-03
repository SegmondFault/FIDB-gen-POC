import tempfile
import unittest
import contextlib
import io
import json
from pathlib import Path

from fidb_poc.cli import main
from fidb_poc.performance_profiles import load_performance_profiles


class PerformanceProfilesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]

    def test_project_profiles_are_valid_and_default_preserves_policy(self):
        catalog = load_performance_profiles(self.root)
        selected = catalog.select()

        self.assertEqual(catalog.default_profile, "auto")
        self.assertEqual(catalog.authority_path, "performance/profiles.toml")
        self.assertEqual(len(catalog.profiles), 8)
        self.assertEqual(selected.settings.worker_mode, "automatic")
        self.assertIsNone(selected.settings.workers)
        self.assertEqual(selected.settings.build_jobs_per_cell, 4)
        self.assertEqual(selected.settings.ghidra_heap_mib, 4096)

    def test_profiles_cover_requested_host_classes(self):
        catalog = load_performance_profiles(self.root)
        profiles = {profile.id: profile for profile in catalog.profiles}

        self.assertEqual(profiles["laptop-4c-8g"].settings.workers, 1)
        self.assertEqual(profiles["laptop-8c-32g"].settings.workers, 6)
        self.assertEqual(profiles["reference-host-94g-balanced"].settings.workers, 20)
        self.assertEqual(profiles["reference-host-112g-throughput"].settings.workers, 29)
        self.assertEqual(
            profiles["m1-max-64g-balanced"].host["memory_model"], "unified"
        )

    def test_unknown_profile_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown performance profile"):
            load_performance_profiles(self.root).select("not-real")

    def test_cli_exposes_one_profile_without_running_work(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = main(
                [
                    "performance",
                    "m1-max-64g-balanced",
                    "--project-root",
                    str(self.root),
                ]
            )

        document = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(document["profile"]["host"]["memory_model"], "unified")
        self.assertEqual(document["profile"]["settings"]["workers"], 8)

    def test_cli_resolves_auto_against_detected_host_without_running_work(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = main(
                [
                    "performance",
                    "auto",
                    "--resolve-auto",
                    "--project-root",
                    str(self.root),
                ]
            )

        document = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        resolution = document["automatic_resolution"]
        self.assertEqual(resolution["profile_id"], "auto")
        self.assertGreaterEqual(resolution["host"]["physical_cores"], 1)
        self.assertGreaterEqual(resolution["host"]["logical_cpus"], 1)
        self.assertGreaterEqual(resolution["effective_settings"]["workers"], 1)

    def test_invalid_profile_cannot_escape_resource_bounds(self):
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            path = Path(temporary) / "bad.toml"
            path.write_text(
                """schema_version = "fidb-performance-profiles/v1"
default_profile = "bad"
[[profiles]]
id = "bad"
label = "Bad"
description = "Bad profile"
qualification = "portable-starting-point"
guidance = "Do not use"
[profiles.host]
system = "any"
architecture = "any"
memory_model = "dedicated-system-memory"
[profiles.settings]
worker_mode = "fixed"
workers = 33
build_jobs_per_cell = 1
ghidra_heap_mib = 4096
""",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "must not exceed 32"):
                load_performance_profiles(self.root, path)


if __name__ == "__main__":
    unittest.main()
