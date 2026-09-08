from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fidb_poc.recipe_qualification import (
    compile_recipe_qualification,
    recipe_qualification_status,
    run_recipe_qualification,
)


class RecipeQualificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1]
        self.authority = self.root / "qualification/c11-c20.toml"

    def test_c11_c20_plan_is_exact_target_and_generation_boundary(self) -> None:
        plan = compile_recipe_qualification(self.root, self.authority)
        self.assertEqual(plan["summary"]["libraries"], 10)
        self.assertEqual(plan["summary"]["routes"], 16)
        self.assertEqual(plan["summary"]["cells"], 160)
        self.assertEqual(len({row["id"] for row in plan["cells"]}), 160)
        self.assertEqual(
            {row["treatment_id"] for row in plan["cells"]}, {"baseline_o2"}
        )

    def test_priority_plan_omits_unreviewed_recipe_route_edges(self) -> None:
        authority = self.root / "qualification/c-malware-priority-native-v1.toml"
        plan = compile_recipe_qualification(self.root, authority)

        self.assertEqual(plan["summary"]["libraries"], 21)
        self.assertEqual(plan["summary"]["routes"], 16)
        self.assertEqual(plan["summary"]["cells"], 268)
        perl_routes = {
            row["route_id"]
            for row in plan["cells"]
            if row["recipe_id"] == "libperl@5.44.0"
        }
        self.assertEqual(
            perl_routes, {"linux-x86-64-gcc", "linux-x86-64-gcc-12"}
        )

    def test_execution_checkpoints_concise_results_and_resumes(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            authority = Path(temporary) / "qualification.toml"
            text = (
                self.authority.read_text(encoding="utf-8")
                .replace(
                    'evidence_path = "qualification/evidence/c11-c20-target-edges-v1.json"',
                    f'evidence_path = "{Path(temporary).name}/evidence.json"',
                )
                .replace("workers = 4", "workers = 1")
            )
            authority.write_text(text, encoding="utf-8")
            plan = compile_recipe_qualification(self.root, authority)
            plan["cells"] = plan["cells"][:1]

            fake_state = {
                "record": {
                    "status": "built",
                    "error": "",
                    "compiler_sha256": "a" * 64,
                    "compiler_version": "compiler 1",
                    "static_archive_sha256": "b" * 64,
                    "analysis_artifact_sha256": ";".join(("c" * 64, "d" * 64)),
                    "object_count": 2,
                }
            }

            def fake_execute(_configuration, group_root, **_kwargs):
                state = group_root / "work/staged-build.json"
                state.write_text(json.dumps(fake_state), encoding="utf-8")
                return {
                    "state_path": str(state),
                    "started_at_utc": "2026-01-01T00:00:00Z",
                    "finished_at_utc": "2026-01-01T00:00:01Z",
                    "wall_time_ns": 1,
                    "peak_process_rss_bytes": 2,
                    "peak_scratch_bytes": 3,
                    "pipeline_error": "",
                }

            with (
                patch(
                    "fidb_poc.recipe_qualification.compile_recipe_qualification",
                    return_value=plan,
                ),
                patch("fidb_poc.recipe_qualification._configuration"),
                patch(
                    "fidb_poc.recipe_qualification.execute_build_stage",
                    side_effect=fake_execute,
                ) as execute,
            ):
                first = run_recipe_qualification(self.root, authority)
                second = run_recipe_qualification(self.root, authority)
                status = recipe_qualification_status(self.root, authority, _plan=plan)
            self.assertEqual(
                first["summary"], {"total": 1, "built": 1, "failed": 0, "remaining": 0}
            )
            self.assertEqual(second["summary"], first["summary"])
            self.assertEqual(execute.call_count, 1)
            self.assertEqual(first["results"][0]["artifact_validation"], "passed")
            self.assertNotIn("analysis_artifact_sha256", first["results"][0])
            self.assertEqual(
                first["seal"]["schema_version"], "fidb-recipe-qualification-seal/v1"
            )
            self.assertEqual(status["state"], "qualified")
            self.assertTrue(status["satisfied"])
            self.assertEqual(
                status["qualification_digest"], first["seal"]["qualification_digest"]
            )

            stale_plan = {**plan, "input_digest": "f" * 64}
            stale = recipe_qualification_status(self.root, authority, _plan=stale_plan)
            self.assertEqual(stale["state"], "stale")
            self.assertFalse(stale["satisfied"])

    def test_failed_cells_remain_pending_without_losing_the_attempt(self) -> None:
        report = {
            "results": [
                {"id": "cell-a", "status": "build_failed"},
                {"id": "cell-b", "status": "built"},
            ]
        }
        from fidb_poc.recipe_qualification import _summarize

        _summarize(report, 3)
        self.assertEqual(
            report["summary"],
            {"total": 3, "built": 1, "failed": 1, "remaining": 1},
        )
        self.assertIsNone(report["finished_at_utc"])


if __name__ == "__main__":
    unittest.main()
