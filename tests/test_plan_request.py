import json
import hashlib
import shutil
import tempfile
import unittest
from pathlib import Path

from fidb_poc.cli import main
from fidb_poc.plan_request import load_plan_request, resolve_plan


class PlanRequestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.request = cls.root / "plans/coverage-baseline.toml"

    def test_repository_plan_resolves_desired_and_blocked_coverage(self):
        plan = resolve_plan(self.request, self.root)

        self.assertEqual(plan["schema_version"], "fidb-resolved-plan/v1")
        self.assertEqual(plan["summary"]["desired_cells"], 6)
        self.assertEqual(plan["summary"]["planned_cells"], 4)
        self.assertEqual(plan["summary"]["blocked_cells"], 2)
        self.assertEqual(plan["summary"]["sensitivity_factors"], 41)
        self.assertEqual(len(plan["queue_preview"]), 6)
        self.assertTrue(
            plan["queue_preview"][0]["base_cell"].startswith("native-libraries:zlib")
        )
        self.assertTrue(
            plan["queue_preview"][1]["base_cell"].startswith("native-libraries:bzip2")
        )
        blocked = [cell for cell in plan["cells"] if cell["status"] == "blocked"]
        self.assertEqual(len(blocked), 2)
        self.assertTrue(all(cell["readiness"] == "unmet" for cell in blocked))
        self.assertTrue(
            all("archive-only" in " ".join(cell["blockers"]) for cell in blocked)
        )
        self.assertEqual(plan["inventory"]["summary"]["artifact_only"], 1)

    def test_resolution_is_deterministic_and_records_sensitivity(self):
        first = resolve_plan(self.request, self.root)
        second = resolve_plan(self.request, self.root)

        self.assertEqual(first["plan_digest"], second["plan_digest"])
        self.assertEqual(len(first["plan_digest"]), 64)
        source = next(
            cell for cell in first["cells"] if cell["kind"] == "source-library"
        )
        self.assertIn("compiler-version", source["sensitivity"])
        self.assertIn("analysis-configuration", source["sensitivity"])
        self.assertIn("debug-symbol-availability", source["sensitivity"])
        self.assertIn("fid-database-set", source["sensitivity"])
        self.assertEqual(source["routing"]["executor"], "qemu")
        self.assertNotIn("executor", source["sensitivity"])
        factors = {row["id"]: row for row in first["sensitivity_catalog"]["factors"]}
        self.assertEqual(factors["ghidra-language"]["confidence"], "observed-sensitive")

    def test_native_routes_resolve_to_platform_specific_worker_pools(self):
        linux = resolve_plan(self.root / "plans/bzip2-native.toml", self.root)["cells"][
            0
        ]
        macos = resolve_plan(self.root / "plans/macos-arm64-canary.toml", self.root)[
            "cells"
        ][0]
        self.assertEqual(linux["routing"]["worker_pool"], "library-local")
        self.assertEqual(macos["routing"]["worker_pool"], "macos-native")
        self.assertEqual(macos["target"]["binary_format"], "Mach-O")

    def test_width_native_routes_preserve_compiler_generation_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "width-native.toml"
            path.write_text(
                """schema_version = "fidb-plan/v1"
name = "width-native"
[policy]
max_cells = 1
[[matrix]]
id = "sqlite-gcc12"
kind = "width-native"
width_batch = "batches/c-next-nine-mega-width.toml"
recipes = ["sqlite@3.53.4"]
routes = ["linux-x86-64-gcc-12"]
treatments = ["baseline_o2"]
""",
                encoding="utf-8",
            )

            plan = resolve_plan(path, self.root)

        self.assertEqual(plan["summary"]["planned_cells"], 1)
        cell = plan["cells"][0]
        self.assertEqual(cell["kind"], "native")
        self.assertEqual(cell["toolchain"]["route"], "linux-x86-64-gcc-12")
        self.assertEqual(cell["toolchain"]["compiler_id"], "gcc-12.3.0")
        self.assertEqual(cell["width"]["batch_id"], "batch-020")
        self.assertEqual(cell["width"]["profile_id"], "gcc-current-o2")
        self.assertEqual(cell["sensitivity"]["compiler-version"]["value"], "gcc-12.3.0")

    def test_request_cannot_supply_a_raw_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.toml"
            path.write_text(
                """schema_version = "fidb-plan/v1"
name = "bad"
[policy]
max_cells = 1
priority = "normal"
[[matrix]]
id = "bad"
kind = "native"
recipes = ["zlib@1.3.1"]
routes = ["linux-x86_64-gnu-gcc"]
treatments = ["baseline_o2"]
command = "cc anything.c"
""",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unsupported fields"):
                load_plan_request(path)

    def test_unknown_toolchain_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "unknown.toml"
            path.write_text(
                """schema_version = "fidb-plan/v1"
name = "unknown"
[[matrix]]
id = "cross"
kind = "source-library"
recipes = ["uclibc@0.9.30.1"]
toolchains = ["uclibc@9:unreviewed"]
executor = "qemu"
""",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unknown toolchain variants"):
                resolve_plan(path, self.root)

    def test_archive_library_resolves_as_runnable_without_executor_choice(self):
        plan = resolve_plan(self.root / "plans/archive-uclibc-powerpc.toml", self.root)

        self.assertEqual(plan["summary"]["planned_cells"], 1)
        cell = plan["cells"][0]
        self.assertEqual(cell["kind"], "archive-library")
        self.assertEqual(cell["routing"], {"executor": "archive-local"})
        self.assertEqual(cell["toolchain"]["capability"], "archive")
        self.assertEqual(cell["build"]["adapter"], "archive-extract")
        self.assertEqual(plan["queue_preview"][0]["state"], "planned")

    def test_archive_library_rejects_source_executor_selection(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad-archive.toml"
            path.write_text(
                """schema_version = "fidb-plan/v1"
name = "bad-archive"
[[matrix]]
id = "archive"
kind = "archive-library"
recipes = ["uclibc@0.9.30.1"]
toolchains = ["uclibc@0.9.30.1:powerpc-default-core"]
executor = "local"
""",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "cannot set.*executor"):
                load_plan_request(path)

    def test_unknown_factor_variant_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "unknown-factor.toml"
            path.write_text(
                """schema_version = "fidb-plan/v1"
name = "unknown-factor"
[coverage]
factor_variants = ["optimization:invented"]
[[matrix]]
id = "native"
kind = "native"
recipes = ["zlib@1.3.1"]
routes = ["linux-x86_64-gnu-gcc"]
treatments = ["baseline_o2"]
""",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unknown factor variants"):
                resolve_plan(path, self.root)

    def test_max_cells_counts_factor_cross_product(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "too-wide.toml"
            path.write_text(
                """schema_version = "fidb-plan/v1"
name = "too-wide"
[policy]
max_cells = 1
[coverage]
factor_variants = ["optimization:o2", "optimization:o0"]
[[matrix]]
id = "native"
kind = "native"
recipes = ["zlib@1.3.1"]
routes = ["linux-x86_64-gnu-gcc"]
treatments = ["baseline_o2"]
""",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "after factor expansion"):
                resolve_plan(path, self.root)

    def test_matrix_factor_variants_override_coverage_without_leaking(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "matrix-variants.toml"
            path.write_text(
                """schema_version = "fidb-plan/v1"
name = "matrix-variants"
[policy]
max_cells = 3
[coverage]
factor_variants = ["optimization:o2"]
[[matrix]]
id = "zlib"
kind = "native"
recipes = ["zlib@1.3.1"]
routes = ["linux-x86_64-gnu-gcc"]
treatments = ["baseline_o2"]
factor_variants = ["optimization:o2", "optimization:o0"]
[[matrix]]
id = "bzip2"
kind = "native"
recipes = ["bzip2@1.0.7"]
routes = ["linux-x86_64-gnu-gcc"]
treatments = ["baseline_o2"]
""",
                encoding="utf-8",
            )

            plan = resolve_plan(path, self.root)

            self.assertEqual(plan["summary"]["base_cells"], 2)
            self.assertEqual(plan["summary"]["desired_cells"], 3)
            self.assertEqual(plan["summary"]["planned_cells"], 2)
            self.assertEqual(plan["summary"]["blocked_cells"], 1)
            self.assertEqual(
                [row["factor_variants"] for row in plan["queue_preview"]],
                [
                    ["optimization:o2"],
                    ["optimization:o0"],
                    ["optimization:o2"],
                ],
            )
            override = plan["coverage"]["matrix_overrides"]["zlib"]
            self.assertEqual(override["summary"]["combinations"], 2)
            self.assertNotIn("bzip2", plan["coverage"]["matrix_overrides"])

    def test_matrix_factor_variants_can_explicitly_select_no_variance(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "empty-matrix-variants.toml"
            path.write_text(
                """schema_version = "fidb-plan/v1"
name = "empty-matrix-variants"
[policy]
max_cells = 1
[coverage]
factor_variants = ["optimization:o2", "optimization:o0"]
[[matrix]]
id = "native"
kind = "native"
recipes = ["zlib@1.3.1"]
routes = ["linux-x86_64-gnu-gcc"]
treatments = ["baseline_o2"]
factor_variants = []
""",
                encoding="utf-8",
            )

            plan = resolve_plan(path, self.root)

            self.assertEqual(plan["summary"]["desired_cells"], 1)
            self.assertEqual(plan["queue_preview"][0]["factor_variants"], [])
            self.assertEqual(
                plan["coverage"]["matrix_overrides"]["native"]["summary"][
                    "combinations"
                ],
                1,
            )

    def test_matrix_factor_variants_count_toward_max_cells(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "too-many-matrix-variants.toml"
            path.write_text(
                """schema_version = "fidb-plan/v1"
name = "too-many-matrix-variants"
[policy]
max_cells = 2
[coverage]
factor_variants = ["optimization:o2"]
[[matrix]]
id = "zlib"
kind = "native"
recipes = ["zlib@1.3.1"]
routes = ["linux-x86_64-gnu-gcc"]
treatments = ["baseline_o2"]
factor_variants = ["optimization:o2", "optimization:o0"]
[[matrix]]
id = "bzip2"
kind = "native"
recipes = ["bzip2@1.0.7"]
routes = ["linux-x86_64-gnu-gcc"]
treatments = ["baseline_o2"]
""",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "3 desired cells"):
                resolve_plan(path, self.root)

    def test_unknown_matrix_factor_variant_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "unknown-matrix-factor.toml"
            path.write_text(
                """schema_version = "fidb-plan/v1"
name = "unknown-matrix-factor"
[[matrix]]
id = "native"
kind = "native"
recipes = ["zlib@1.3.1"]
routes = ["linux-x86_64-gnu-gcc"]
treatments = ["baseline_o2"]
factor_variants = ["optimization:invented"]
""",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "unknown factor variants"):
                resolve_plan(path, self.root)

    def test_cli_writes_canonical_resolved_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "resolved.json"
            status = main(
                [
                    "resolve-plan",
                    str(self.request),
                    "--project-root",
                    str(self.root),
                    "--output",
                    str(output),
                ]
            )

            self.assertEqual(status, 0)
            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(document["summary"]["desired_cells"], 6)
            self.assertIn("plan_digest", document)

    def test_built_inventory_requires_a_valid_seal_and_both_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("worker.toml", "pyproject.toml"):
                shutil.copy2(self.root / name, root / name)
            for name in ("plans", "recipes", "sensitivity", "toolchains"):
                shutil.copytree(self.root / name, root / name)
            attempt = root / "artifacts/runs/job-test/attempt-1"
            artifacts = attempt / "artifacts"
            artifacts.mkdir(parents=True)
            fidb = artifacts / "library.fidb"
            fidbf = artifacts / "library.fidbf"
            fidb.write_bytes(b"packed-fidb")
            fidbf.write_bytes(b"raw-fidbf")
            cell_id = "bzip2-native:bzip2-1.0.7:" "linux-x86_64-gnu-gcc:baseline_o2"
            seal = {
                "schema_version": "fidb-cell-seal/v1",
                "cell": {"id": cell_id},
                "artifacts": {
                    "fidb": {
                        "path": "artifacts/library.fidb",
                        "sha256": hashlib.sha256(fidb.read_bytes()).hexdigest(),
                        "bytes": fidb.stat().st_size,
                    },
                    "fidbf": {
                        "path": "artifacts/library.fidbf",
                        "sha256": hashlib.sha256(fidbf.read_bytes()).hexdigest(),
                        "bytes": fidbf.stat().st_size,
                    },
                },
            }
            seal_path = artifacts / "cell-seal.json"
            seal_path.write_text(json.dumps(seal), encoding="utf-8")

            built = resolve_plan(root / "plans/bzip2-native.toml", root)
            self.assertEqual(built["inventory"]["cells"][cell_id]["state"], "built")

            fidb.write_bytes(b"changed-after-seal")
            invalid = resolve_plan(root / "plans/bzip2-native.toml", root)
            self.assertEqual(
                invalid["inventory"]["cells"][cell_id]["state"], "not-built"
            )


if __name__ == "__main__":
    unittest.main()
