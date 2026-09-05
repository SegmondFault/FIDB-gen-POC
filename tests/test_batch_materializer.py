import contextlib
import copy
import io
import json
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from fidb_poc.batch_materializer import (
    check_materialization,
    compile_materialization,
    write_materialization,
)
from fidb_poc.cli import main


class BatchMaterializerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.document = compile_materialization(cls.root)

    def test_campaign_materializes_exact_disarmed_width(self):
        document = self.document

        self.assertEqual(document["schema_version"], "fidb-materialized-campaign/v1")
        self.assertEqual(document["state"], "materialized-disarmed")
        self.assertEqual(document["summary"]["blocks"], 5)
        self.assertEqual(document["summary"]["libraries"], 10)
        self.assertEqual(document["summary"]["executions"], 2_046)
        self.assertEqual(
            [row["executions"] for row in document["blocks"]],
            [444, 444, 270, 444, 444],
        )
        self.assertTrue(
            all(row["state"] == "materialized-disarmed" for row in document["blocks"])
        )

    def test_generated_plan_keeps_all_compiler_generation_routes(self):
        path = "plans/materialized/c-top10-nonapple-width-v2/block-01.toml"
        plan = tomllib.loads(self.document["rendered_plans"][path])

        self.assertEqual(plan["matrix"][0]["kind"], "width-native")
        self.assertEqual(len(plan["matrix"][0]["routes"]), 37)
        self.assertIn("linux-x86-64-gcc-12", plan["matrix"][0]["routes"])
        self.assertIn("linux-x86-64-gcc-13", plan["matrix"][0]["routes"])
        self.assertIn("linux-x86-64-gcc", plan["matrix"][0]["routes"])
        self.assertEqual(len(plan["matrix"][0]["treatments"]), 6)

    def test_checked_in_materialization_matches_current_authorities(self):
        check = check_materialization(self.document, self.root)

        self.assertEqual(
            check, {"state": "current", "checked_files": 6, "mismatches": []}
        )

    def test_write_and_check_are_exact_and_do_not_arm_anything(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_materialization(self.document, root)

            check = check_materialization(self.document, root)

            self.assertEqual(check["state"], "current")
            self.assertEqual(check["checked_files"], 6)
            manifest = tomllib.loads(
                (root / self.document["manifest_path"]).read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["state"], "materialized-disarmed")
            self.assertNotIn("armed", manifest)

    def test_cli_preview_does_not_write_rendered_payloads(self):
        output = io.StringIO()
        with (
            patch(
                "fidb_poc.batch_materializer.compile_materialization",
                return_value=copy.deepcopy(self.document),
            ),
            contextlib.redirect_stdout(output),
        ):
            status = main(["materialize-batches", "--project-root", str(self.root)])

        result = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(result["state"], "materialized-disarmed")
        self.assertNotIn("rendered_plans", result)

    def test_materialization_fails_closed_when_qualification_is_not_satisfied(self):
        with patch(
            "fidb_poc.batch_materializer.require_qualification_gates",
            side_effect=ValueError(
                "campaign materialization blocked by qualification: batch-next=stale"
            ),
        ):
            with self.assertRaisesRegex(ValueError, "blocked by qualification"):
                compile_materialization(self.root)


if __name__ == "__main__":
    unittest.main()
