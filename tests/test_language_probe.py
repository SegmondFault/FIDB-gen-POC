from __future__ import annotations

import argparse
from contextlib import redirect_stderr
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fidb_poc.language_probe import (
    ProbeCase,
    compare_rows,
    ghidra_version,
    main,
    parse_case,
    resolve_probe_directories,
    run_probe,
    validate_cases,
)


class LanguageProbeTests(unittest.TestCase):
    CASES = (
        ProbeCase("default", "x86:LE:64:default"),
        ProbeCase("compat32", "x86:LE:64:compat32"),
    )

    def test_parse_case_preserves_language_colons(self) -> None:
        self.assertEqual(
            parse_case("e500=PowerPC:BE:32:e500"),
            ProbeCase("e500", "PowerPC:BE:32:e500"),
        )

    def test_parse_case_rejects_missing_label(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_case("PowerPC:BE:32:e500")

    def test_parse_case_rejects_path_like_label(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_case("../escape=PowerPC:BE:32:e500")

    def test_cases_require_two_unique_labels(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least two"):
            validate_cases([ProbeCase("only", "x86:LE:64:default")])
        with self.assertRaisesRegex(ValueError, "unique"):
            validate_cases(
                [
                    ProbeCase("same", "x86:LE:64:default"),
                    ProbeCase("same", "x86:LE:64:default"),
                ]
            )

    def test_matrix_counts_missing_and_changed_functions(self) -> None:
        reference = [
            {"entry_point": "1000", "full_hash": "aa", "specific_hash": "11"},
            {"entry_point": "2000", "full_hash": "bb", "specific_hash": "22"},
            {"entry_point": "3000", "full_hash": "cc", "specific_hash": "33"},
        ]
        comparison = [
            {"entry_point": "1000", "full_hash": "aa", "specific_hash": "11"},
            {"entry_point": "2000", "full_hash": "changed", "specific_hash": "22"},
            {"entry_point": "4000", "full_hash": "dd", "specific_hash": "44"},
        ]
        row = compare_rows("default", "e500", reference, comparison)
        self.assertEqual(row["reference_hashable"], 3)
        self.assertEqual(row["comparison_hashable"], 3)
        self.assertEqual(row["shared_entrypoints"], 2)
        self.assertEqual(row["full_hash_equal"], 1)
        self.assertEqual(row["specific_hash_equal"], 2)
        self.assertEqual(row["dual_hash_equal"], 1)
        self.assertEqual(row["reference_retained_pct"], "33.333333")

    def test_ghidra_version_reads_application_properties(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ghidra_home = Path(temporary)
            properties = ghidra_home / "Ghidra/application.properties"
            properties.parent.mkdir(parents=True)
            properties.write_text(
                "application.name=Ghidra\napplication.version=12.1\n",
                encoding="utf-8",
            )

            version, observed_path = ghidra_version(ghidra_home)

        self.assertEqual(version, "12.1")
        self.assertEqual(observed_path, properties)

    def test_programmatic_fresh_rejects_unsafe_output_paths_before_deletion(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            project_root = base / "project"
            project_root.mkdir()
            binary = project_root / "sample.o"
            binary.write_bytes(b"fixed input")
            unrelated = base / "unrelated"
            unrelated.mkdir()

            unsafe_paths = {
                "project root": project_root,
                "project ancestor": project_root.parent,
                "unrelated directory": unrelated,
            }
            with patch("fidb_poc.language_probe.shutil.rmtree") as remove:
                for label, unsafe_path in unsafe_paths.items():
                    with self.subTest(label=label):
                        with self.assertRaisesRegex(
                            ValueError, "output directory must stay below"
                        ):
                            run_probe(
                                project_root=project_root,
                                binary=binary,
                                cases=self.CASES,
                                output_directory=unsafe_path,
                                fresh=True,
                            )

            remove.assert_not_called()
            self.assertTrue(project_root.is_dir())
            self.assertTrue(unrelated.is_dir())

    def test_cli_fresh_rejects_project_root_before_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project_root = Path(temporary) / "project"
            project_root.mkdir()
            binary = project_root / "sample.o"
            binary.write_bytes(b"fixed input")
            stderr = io.StringIO()

            with (
                patch("fidb_poc.language_probe.shutil.rmtree") as remove,
                redirect_stderr(stderr),
            ):
                result = main(
                    [
                        "--project-root",
                        str(project_root),
                        "--binary",
                        str(binary),
                        "--case",
                        "default=x86:LE:64:default",
                        "--case",
                        "compat32=x86:LE:64:compat32",
                        "--output-directory",
                        str(project_root),
                        "--fresh",
                    ]
                )

            self.assertEqual(result, 1)
            self.assertIn("output directory must stay below", stderr.getvalue())
            remove.assert_not_called()
            self.assertTrue(project_root.is_dir())

    def test_probe_output_and_work_roots_must_not_overlap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project_root = Path(temporary) / "project"
            work_root = project_root / "work/language_probe"
            work_root.mkdir(parents=True)
            output_parent = project_root / "output"
            output_parent.mkdir()
            (output_parent / "language_probe").symlink_to(
                work_root, target_is_directory=True
            )

            with self.assertRaisesRegex(ValueError, "symlink aliases"):
                resolve_probe_directories(project_root, None, "sample-123")

    def test_probe_target_symlink_cannot_alias_a_sibling(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project_root = Path(temporary) / "project"
            sibling = project_root / "output/language_probe/sibling"
            sibling.mkdir(parents=True)
            alias = project_root / "output/language_probe/alias"
            alias.symlink_to(sibling, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "symlink aliases"):
                resolve_probe_directories(project_root, alias, "sample-123")

            self.assertTrue(sibling.is_dir())

    def test_safe_explicit_output_stays_in_separate_probe_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project_root = Path(temporary) / "project"
            project_root.mkdir()
            output = project_root / "output/language_probe/custom"

            resolved_output, resolved_work = resolve_probe_directories(
                project_root, output, "sample-123"
            )

            self.assertEqual(resolved_output, output)
            self.assertEqual(
                resolved_work, project_root / "work/language_probe/sample-123"
            )


if __name__ == "__main__":
    unittest.main()
