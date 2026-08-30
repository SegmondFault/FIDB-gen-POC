from __future__ import annotations

import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fidb_poc.hunt import load_cells
from fidb_poc.hunt_cli import build_parser
from fidb_poc.malware_build import build_malware_binary
from fidb_poc.recipe_generator import generate_cells, load_recipes
from fidb_poc.source_build import (
    AdapterInputs,
    adapter_inputs,
    executor_for,
    run_local_source_build,
)
from fidb_poc.toolchain_registry import load_toolchains


class SourceExecutorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[1]
        cls.recipes = load_recipes(cls.root / "recipes" / "libs")
        cls.toolchains = load_toolchains(cls.root / "toolchains" / "registry.toml")

    def test_qemu_is_the_default_cli_and_cell_executor(self) -> None:
        parser = build_parser()
        self.assertEqual(parser.parse_args(["hunt", "target"]).executor, "qemu")
        self.assertEqual(parser.parse_args(["build-malware"]).executor, "qemu")
        self.assertEqual(
            generate_cells(self.recipes, self.toolchains)[0]["executor"], "qemu"
        )
        self.assertEqual(executor_for({}), "qemu")

    def test_local_and_qemu_cells_use_the_same_reviewed_adapter_inputs(self) -> None:
        qemu = generate_cells(self.recipes, self.toolchains, executor="qemu")[0]
        local = generate_cells(self.recipes, self.toolchains, executor="local")[0]

        self.assertEqual(
            adapter_inputs(qemu, "uclibc_defconfig"),
            adapter_inputs(local, "uclibc_defconfig"),
        )
        self.assertEqual(
            {key: value for key, value in qemu.items() if key != "executor"},
            {key: value for key, value in local.items() if key != "executor"},
        )

    def test_local_cell_reaches_local_build_and_records_provenance(self) -> None:
        cell = {
            "family": "fixture",
            "version": "1",
            "variant": "powerpc-source",
            "mode": "source",
            "executor": "local",
            "source_url": "https://example.invalid/source.tar.gz",
            "source_sha256": "a" * 64,
            "toolchain_url": "https://example.invalid/toolchain.tar.gz",
            "toolchain_sha256": "b" * 64,
            "vm_iso_url": "https://example.invalid/alpine.iso",
            "vm_iso_sha256": "c" * 64,
            "source_kind": "tar",
            "arch": "powerpc",
            "cross_bin_prefix": "bin/powerpc-linux-",
            "library_path": "release/bot",
            "build_adapter": "plain_make",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archives = iter((root / "source.tar.gz", root / "toolchain.tar.gz"))

            def extract(_archive: Path, destination: Path) -> str:
                name = (
                    "source" if not (destination / "source").exists() else "toolchain"
                )
                (destination / name).mkdir(parents=True)
                return name

            def local_build(inputs, _source, _toolchain, out_dir):
                built = out_dir / Path(inputs.output_relpath).name
                out_dir.mkdir(parents=True, exist_ok=True)
                built.write_bytes(b"cross-built")
                return built

            with (
                patch(
                    "fidb_poc.malware_build._download_url",
                    side_effect=lambda *_: next(archives),
                ),
                patch("fidb_poc.malware_build._extract_verified", side_effect=extract),
                patch(
                    "fidb_poc.malware_build.run_local_source_build",
                    side_effect=local_build,
                ) as local,
                patch("fidb_poc.malware_build.run_qemu_source_build") as qemu,
            ):
                result = build_malware_binary(cell, root / "work", root / "downloads")

        local.assert_called_once()
        qemu.assert_not_called()
        self.assertEqual(result["executor"], "local")
        self.assertEqual(result["build_adapter"], "plain_make")

    def test_local_executor_runs_the_fixed_cross_build_invocation(self) -> None:
        inputs = AdapterInputs(
            build_adapter="plain_make",
            arch="powerpc",
            cross_bin_prefix="bin/powerpc-linux-",
            output_relpath="release/bot",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            toolchain = root / "toolchain"
            output = source / "release/bot"
            output.parent.mkdir(parents=True)
            toolchain.mkdir()
            output.write_bytes(b"cross-built")
            with patch("fidb_poc.source_build.subprocess.run") as run:
                destination = run_local_source_build(
                    inputs, source, toolchain, root / "out"
                )
            self.assertEqual(destination.read_bytes(), b"cross-built")
            timing_log = root / "out/reviewed-build-command.log"
            self.assertTrue(timing_log.is_file())
            logged = timing_log.read_text(encoding="utf-8")
            self.assertIn("started_at_utc=", logged)
            self.assertIn("finished_at_utc=", logged)
            self.assertIn("duration_ns=", logged)
            self.assertIn("outcome=completed", logged)

        run.assert_called_once_with(
            [
                "make",
                f"CC={toolchain / 'bin/powerpc-linux-'}gcc",
                "-j4",
            ],
            cwd=source,
            check=True,
            timeout=2400,
        )

    def test_archive_cells_are_unchanged_by_executor_selection(self) -> None:
        qemu = load_cells(
            self.root / "toolchains" / "registry.toml",
            self.root / "recipes" / "libs",
            executor="qemu",
        )
        local = load_cells(
            self.root / "toolchains" / "registry.toml",
            self.root / "recipes" / "libs",
            executor="local",
        )
        qemu_archives = [cell for cell in qemu if cell["mode"] == "archive"]
        local_archives = [cell for cell in local if cell["mode"] == "archive"]

        self.assertEqual(qemu_archives, local_archives)
        self.assertTrue(qemu_archives)
        self.assertTrue(all("executor" not in cell for cell in qemu_archives))

    def test_invalid_executor_fails_cleanly(self) -> None:
        errors = io.StringIO()
        with (
            contextlib.redirect_stderr(errors),
            self.assertRaises(SystemExit) as raised,
        ):
            build_parser().parse_args(["hunt", "target", "--executor", "container"])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("invalid choice", errors.getvalue())
        with self.assertRaisesRegex(ValueError, "unsupported source-build executor"):
            generate_cells(self.recipes, self.toolchains, executor="container")


if __name__ == "__main__":
    unittest.main()
