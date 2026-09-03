import contextlib
import io
import json
from pathlib import Path
import unittest

from fidb_poc.batch_time_model import compile_time_block_plan
from fidb_poc.cli import main


class BatchTimeModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]

    def test_top_ten_campaign_is_packed_into_bounded_disarmed_blocks(self):
        document = compile_time_block_plan(self.root)

        self.assertEqual(document["schema_version"], "fidb-time-block-plan/v1")
        self.assertEqual(document["state"], "draft-disarmed")
        self.assertEqual(document["summary"]["executions"], 2_046)
        self.assertEqual(document["summary"]["android_executions"], 480)
        self.assertEqual(document["summary"]["blocks"], 5)
        self.assertEqual(document["performance_profile"]["settings"]["workers"], 20)
        self.assertTrue(
            all(block["estimated_hours"] <= 5.0 for block in document["blocks"])
        )
        self.assertTrue(
            all(block["expected_start_local"] == "00:00" for block in document["blocks"])
        )
        self.assertEqual(
            {item["source_id"] for block in document["blocks"] for item in block["items"]},
            {"openssl", "sqlite", "xz", "zstd", "pcre2", "lz4", "gettext", "nghttp2", "readline", "gmp"},
        )

    def test_profile_width_changes_estimated_rate_and_duration(self):
        balanced = compile_time_block_plan(self.root)
        burst = compile_time_block_plan(
            self.root, performance_profile="reference-host-112g-throughput"
        )

        self.assertGreater(
            burst["reference"]["estimated_cells_per_wall_hour"],
            balanced["reference"]["estimated_cells_per_wall_hour"],
        )
        self.assertLess(
            burst["summary"]["estimated_hours"],
            balanced["summary"]["estimated_hours"],
        )

    def test_cli_is_read_only_and_prints_plan(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = main(["plan-time-blocks", "--project-root", str(self.root)])

        document = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(document["summary"]["blocks"], 5)
        self.assertEqual(document["policy"]["max_block_hours"], 5.0)


if __name__ == "__main__":
    unittest.main()
