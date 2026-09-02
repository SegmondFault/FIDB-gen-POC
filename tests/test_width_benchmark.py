import contextlib
import io
import json
import unittest
from pathlib import Path

from fidb_poc.cli import main
from fidb_poc.width_benchmark import _java_options, width_benchmark_preview


class WidthBenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]

    def test_preview_is_disarmed_and_exact(self):
        preview = width_benchmark_preview(
            self.root,
            route_ids=("linux-x86-64-gcc-13",),
            treatment_ids=("baseline_o2", "optimization_o3"),
            workers=2,
            heap_mib=4096,
            core_limit=2,
        )

        self.assertEqual(preview["state"], "disarmed-preview")
        self.assertEqual(preview["scheduled_cells"], 2)
        self.assertEqual(preview["parallel_workers"], 2)
        self.assertEqual(preview["java_tool_options"], "-Xmx4096m -Dcpu.core.limit=2")

    def test_cli_does_not_execute_without_flag(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = main(
                [
                    "benchmark-width",
                    "--project-root",
                    str(self.root),
                    "--route",
                    "linux-x86-64-gcc-13",
                    "--treatment",
                    "baseline_o2",
                    "--workers",
                    "1",
                ]
            )

        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue())["state"], "disarmed-preview")

    def test_heap_and_core_bounds_are_validated(self):
        with self.assertRaisesRegex(ValueError, "heap"):
            _java_options(512, 2)
        with self.assertRaisesRegex(ValueError, "core"):
            _java_options(4096, 0)


if __name__ == "__main__":
    unittest.main()
