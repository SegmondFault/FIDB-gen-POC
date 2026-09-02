import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from fidb_poc.cli import main
from fidb_poc.c_width import compile_c_width
from fidb_poc.width_run import (
    _groups,
    _release_cell_scratch,
    _replay_comparison,
    compile_width_run_plan,
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

    def test_replay_comparison_separates_artifact_fidb_and_semantics(self):
        baseline = {
            "cells": [
                {
                    "route_id": "route-a",
                    "treatment_id": "treatment-a",
                    "status": "complete",
                    "analysis_artifact_sha256": "a" * 64,
                    "fidb_sha256": "b" * 64,
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


if __name__ == "__main__":
    unittest.main()
