import contextlib
import gzip
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from fidb_poc.cli import main
from fidb_poc.c_width import compile_c_width
from fidb_poc.width_run import (
    _execute_cell,
    _groups,
    _process_tree_pids,
    _read_csv_rows,
    _release_cell_scratch,
    _release_jvm_scratch,
    _replay_comparison,
    _terminate_executor,
    compile_width_run_plan,
    default_width_workers,
    width_run_preview,
)


class WidthRunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]

    def test_full_preview_is_exactly_the_compiled_feasible_width(self):
        plan = compile_width_run_plan(self.root, canary=False)
        preview = width_run_preview(plan)
        compilation = compile_c_width(self.root)
        qualified = compilation["summary"]["qualified_routes"]

        self.assertEqual(preview["state"], "disarmed-preview")
        self.assertEqual(preview["mode"], "full")
        self.assertEqual(preview["performance_profile"], "auto")
        self.assertEqual(preview["build_jobs_per_cell"], 4)
        self.assertEqual(preview["ghidra_heap_mib"], 4096)
        self.assertEqual(preview["java_tool_options"], "-Xmx4096m")
        self.assertEqual(preview["build_cells_per_replay"], qualified * 6)
        self.assertEqual(preview["replays"], 1)
        self.assertEqual(preview["scheduled_executions"], qualified * 6)
        self.assertEqual(len(preview["cells"]), qualified * 6)
        self.assertEqual(len({row["route_id"] for row in preview["cells"]}), qualified)
        self.assertTrue(all(row["profile_id"] for row in preview["cells"]))
        groups = _groups(plan)
        self.assertEqual(len(groups), preview["scheduled_executions"])
        self.assertTrue(
            all(len(group.routes) == len(group.treatments) == 1 for group in groups)
        )

    def test_canary_selects_one_baseline_cell_per_route(self):
        preview = width_run_preview(compile_width_run_plan(self.root, canary=True))

        self.assertEqual(preview["mode"], "canary")
        self.assertEqual(preview["replays"], 1)
        self.assertEqual(
            preview["scheduled_executions"],
            compile_c_width(self.root)["summary"]["qualified_routes"],
        )
        self.assertEqual(
            {row["treatment_id"] for row in preview["cells"]}, {"baseline_o2"}
        )

    def test_android_gap_authority_is_independently_previewable(self):
        preview = width_run_preview(
            compile_width_run_plan(
                self.root, canary=False, authority_id="c-android-gap-v1"
            )
        )

        self.assertEqual(preview["width_id"], "c-android-gap-v1")
        self.assertEqual(preview["scheduled_executions"], 48)
        self.assertEqual(len({row["route_id"] for row in preview["cells"]}), 8)

    def test_command_is_disarmed_without_execute_flag(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = main(["run-width", "--project-root", str(self.root), "--canary"])

        document = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(document["state"], "disarmed-preview")
        self.assertEqual(
            document["scheduled_executions"],
            compile_c_width(self.root)["summary"]["qualified_routes"],
        )

    def test_unbounded_width_heap_remains_an_explicit_preview_choice(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = main(
                [
                    "run-width",
                    "--project-root",
                    str(self.root),
                    "--canary",
                    "--unbounded-ghidra-heap",
                ]
            )

        document = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertIsNone(document["ghidra_heap_mib"])
        self.assertEqual(document["java_tool_options"], "")
        self.assertEqual(document["performance_profile"], "manual")

    def test_named_performance_profile_is_an_exact_disarmed_choice(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = main(
                [
                    "run-width",
                    "--project-root",
                    str(self.root),
                    "--canary",
                    "--performance-profile",
                    "laptop-4c-8g",
                ]
            )

        document = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(document["performance_profile"], "laptop-4c-8g")
        self.assertEqual(document["parallel_workers"], 1)
        self.assertEqual(document["build_jobs_per_cell"], 2)
        self.assertEqual(document["ghidra_heap_mib"], 2048)
        self.assertEqual(document["java_tool_options"], "-Xmx2048m")

    def test_named_profile_rejects_ambiguous_manual_overrides(self):
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            status = main(
                [
                    "run-width",
                    "--project-root",
                    str(self.root),
                    "--canary",
                    "--performance-profile",
                    "laptop-4c-8g",
                    "--workers",
                    "2",
                ]
            )

        self.assertEqual(status, 1)
        self.assertIn("cannot be combined", errors.getvalue())

    def test_default_workers_select_measured_knee_with_memory_headroom(self):
        visible = int(93.93 * 1024**3)

        self.assertEqual(
            default_width_workers(
                logical_cpus=32, available_memory_bytes=visible, heap_mib=4096
            ),
            20,
        )
        self.assertEqual(
            default_width_workers(
                logical_cpus=32, available_memory_bytes=visible, heap_mib=8192
            ),
            10,
        )
        self.assertEqual(
            default_width_workers(
                logical_cpus=32, available_memory_bytes=6 * 1024**3, heap_mib=4096
            ),
            1,
        )

    def test_process_tree_finds_children_started_by_non_main_threads(self):
        ready = threading.Event()
        release = threading.Event()
        child: dict[str, subprocess.Popen] = {}

        def launch() -> None:
            process = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"]
            )
            child["process"] = process
            ready.set()
            release.wait(timeout=10)
            process.terminate()
            process.wait(timeout=10)

        thread = threading.Thread(target=launch)
        thread.start()
        try:
            self.assertTrue(ready.wait(timeout=10))
            self.assertIn(child["process"].pid, _process_tree_pids(os.getpid()))
        finally:
            release.set()
            thread.join(timeout=15)

    def test_replay_comparison_separates_artifact_fidb_and_semantics(self):
        baseline = {
            "cells": [
                {
                    "route_id": "route-a",
                    "treatment_id": "treatment-a",
                    "status": "complete",
                    "analysis_artifact_sha256": "a" * 64,
                    "fidb_sha256": "b" * 64,
                    "fid_signatures_sha256": "d" * 64,
                    "fid_signature_records": "8",
                    "fid_unique_full_hashes": "7",
                    "fid_unique_signatures": "6",
                    "fid_programs": "1",
                    "fid_attempted": "10",
                    "fid_added": "8",
                    "fid_excluded": "2",
                }
            ]
        }
        changed = {
            "cells": [
                {
                    "route_id": "route-a",
                    "treatment_id": "treatment-a",
                    "status": "complete",
                    "analysis_artifact_sha256": "a" * 64,
                    "fidb_sha256": "c" * 64,
                    "fid_signatures_sha256": "d" * 64,
                    "fid_signature_records": "8",
                    "fid_unique_full_hashes": "7",
                    "fid_unique_signatures": "6",
                    "fid_programs": "1",
                    "fid_attempted": "11",
                    "fid_added": "8",
                    "fid_excluded": "3",
                }
            ]
        }

        comparison = _replay_comparison([baseline, changed])

        self.assertTrue(comparison["comparable"])
        self.assertEqual(comparison["compared_cells"], 1)
        self.assertEqual(comparison["artifact_bytes"]["matching_cells"], 1)
        self.assertEqual(comparison["fidb_container_bytes"]["matching_cells"], 0)
        self.assertEqual(comparison["fid_semantics"]["matching_cells"], 0)
        self.assertEqual(len(comparison["fid_semantics"]["mismatches"]), 1)

    def test_replay_comparison_detects_signature_drift_with_equal_counts(self):
        def cell(digest: str) -> dict[str, str]:
            return {
                "route_id": "route-a",
                "treatment_id": "treatment-a",
                "status": "complete",
                "analysis_artifact_sha256": "a" * 64,
                "fidb_sha256": "b" * 64,
                "fid_signatures_sha256": digest,
                "fid_signature_records": "8",
                "fid_unique_full_hashes": "7",
                "fid_unique_signatures": "6",
                "fid_programs": "1",
                "fid_attempted": "10",
                "fid_added": "8",
                "fid_excluded": "2",
            }

        comparison = _replay_comparison(
            [{"cells": [cell("c" * 64)]}, {"cells": [cell("d" * 64)]}]
        )

        self.assertEqual(comparison["fid_semantics"]["matching_cells"], 0)
        mismatch = comparison["fid_semantics"]["mismatches"][0]
        self.assertEqual(mismatch["baseline"]["fid_signatures_sha256"], "c" * 64)
        self.assertEqual(mismatch["observed"]["fid_signatures_sha256"], "d" * 64)

    def test_scratch_release_keeps_logs_and_ghidra_user_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            group = Path(temporary) / "group-001"
            removable = (
                "work/sources",
                "work/builds",
                "work/ghidra/projects",
                "work/ghidra/references",
                "work/ghidra/candidates",
            )
            retained = ("work/logs", "work/downloads", "work/ghidra/user")
            for relative in removable + retained:
                path = group / relative
                path.mkdir(parents=True)
                (path / "evidence").write_text("x", encoding="utf-8")

            _release_cell_scratch(group)

            self.assertTrue(all(not (group / path).exists() for path in removable))
            self.assertTrue(all((group / path).is_dir() for path in retained))

    def test_large_openssl_manifest_fields_are_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = Path(temporary) / "manifest.csv"
            manifest.write_text(
                "status,analysis_artifact_path\ncomplete,"
                + ("object.o;" * 20_000)
                + "\n",
                encoding="utf-8",
            )

            rows = _read_csv_rows(manifest)

            self.assertEqual(rows[0]["status"], "complete")
            self.assertGreater(len(rows[0]["analysis_artifact_path"]), 131_072)

    def test_jvm_scratch_release_archives_logs_and_drops_cache(self):
        with tempfile.TemporaryDirectory() as temporary:
            group = Path(temporary) / "group-001"
            user = group / "work/ghidra/user"
            application = user / ".config/ghidra/version/application.log"
            cache = user / ".cache/ghidra/packed-db-cache/cache.gbf"
            application.parent.mkdir(parents=True)
            cache.parent.mkdir(parents=True)
            application.write_text("diagnostic\n" * 100, encoding="utf-8")
            cache.write_bytes(b"cache" * 100)

            result = _release_jvm_scratch(group)

            archives = list((group / "work/logs/ghidra-jvm").glob("*.gz"))
            self.assertFalse(user.exists())
            self.assertEqual(len(archives), 1)
            with gzip.open(archives[0], "rt", encoding="utf-8") as stream:
                self.assertEqual(stream.read(), "diagnostic\n" * 100)
            self.assertGreater(result["reclaimed_bytes"], 0)

    def test_width_cell_retains_pipeline_stage_timing(self):
        configuration = _groups(compile_width_run_plan(self.root, canary=True))[0]
        with tempfile.TemporaryDirectory() as temporary:
            group = Path(temporary) / "group-001"
            group.mkdir()

            def fake_execute(_configuration, project_root, **kwargs):
                self.assertEqual(kwargs["build_jobs_per_cell"], 3)
                with kwargs["timing"]("compile", "benchmark compile stage"):
                    pass
                kwargs["skipped"]("patch", "no patch required")
                manifest = project_root / "artifacts/libs/fidb_manifest.csv"
                manifest.parent.mkdir(parents=True)
                manifest.write_text("status\ncomplete\n", encoding="utf-8")
                return manifest

            with patch("fidb_poc.width_run.execute", side_effect=fake_execute):
                measurement = _execute_cell(
                    configuration, str(group), False, build_jobs_per_cell=3
                )

            timing = measurement["stage_timing"]
            self.assertEqual(timing["schema_version"], "fidb-execution-timing/v1")
            self.assertIn("compile", timing["summary"]["stage_duration_ns"])
            self.assertEqual(timing["summary"]["terminal_event_counts"]["skipped"], 1)

    def test_pool_termination_uses_supported_executor_api(self):
        class Executor:
            def __init__(self):
                self.terminated = False

            def terminate_workers(self):
                self.terminated = True

        executor = Executor()

        _terminate_executor(executor)

        self.assertTrue(executor.terminated)


if __name__ == "__main__":
    unittest.main()
