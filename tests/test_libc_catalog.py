from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from fidb_poc.libc_catalog import _acquisition_stage, _digest, prepare_recipe
from fidb_poc.timing import ProgressStatus, TimingRecorder


class CandidatePreparationTests(unittest.TestCase):
    def test_executor_image_has_distinct_timing_stage(self):
        self.assertEqual(_acquisition_stage("source"), "source-acquire")
        self.assertEqual(_acquisition_stage("toolchain"), "toolchain-acquire")
        self.assertEqual(_acquisition_stage("vm-iso"), "executor-image-acquire")

    def test_cached_qemu_source_recipe_records_executor_image_skip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recipe = {
                "family": "testlib",
                "version": "1",
                "variant": "fixture",
                "machine": "ARM",
                "endianness": "little",
                "elf_class": 32,
                "mode": "source",
                "executor": "qemu",
                "source_url": "https://example.invalid/source.tar.gz",
                "source_sha256": "a" * 64,
            }
            prepared = root / "work/prepared" / _digest(recipe)[:16]
            objects = prepared / "objects"
            objects.mkdir(parents=True)
            (objects / "fixture.o").write_bytes(b"object")
            (prepared / "recipe.json").write_text("{}\n", encoding="utf-8")
            events = []
            timing = TimingRecorder(events.append)

            with patch("fidb_poc.libc_catalog.adapter_inputs", return_value=object()):
                prepare_recipe(
                    recipe,
                    root / "work",
                    root / "downloads",
                    timing=timing.span,
                    skipped=timing.skip,
                )

            image_events = [
                event
                for event in events
                if event.stage.value == "executor-image-acquire"
            ]
            self.assertEqual(len(image_events), 1)
            self.assertEqual(image_events[0].status, ProgressStatus.SKIPPED)
            self.assertIn("QEMU", image_events[0].message)

    def test_downloads_verifies_and_extracts_selected_archive_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / "inputs"
            inputs.mkdir()
            (inputs / "keep.o").write_bytes(b"keep")
            (inputs / "skip.o").write_bytes(b"skip")
            library = root / "libtest.a"
            subprocess.run(
                ["ar", "rcs", str(library), "keep.o", "skip.o"], cwd=inputs, check=True
            )
            archive = root / "candidate.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                output.add(library, arcname="toolchain/lib/libtest.a")
            members = root / "members.txt"
            members.write_text("keep.o\n", encoding="utf-8")
            recipe = {
                "family": "testlib",
                "version": "1",
                "variant": "fixture",
                "machine": "ARM",
                "endianness": "little",
                "elf_class": 32,
                "mode": "archive",
                "url": archive.as_uri(),
                "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "library_member": "toolchain/lib/libtest.a",
                "members_file": str(members),
                "members_sha256": hashlib.sha256(members.read_bytes()).hexdigest(),
            }

            events = []
            timing = TimingRecorder(events.append)
            guess = prepare_recipe(
                recipe,
                root / "work",
                root / "downloads",
                timing=timing.span,
                skipped=timing.skip,
            )
            objects = Path(str(guess["objects"]))

            self.assertEqual((objects / "keep.o").read_bytes(), b"keep")
            self.assertFalse((objects / "skip.o").exists())
            self.assertEqual(guess["source_sha256"], recipe["sha256"])
            terminal = [
                event for event in events if event.status is not ProgressStatus.STARTED
            ]
            self.assertEqual(
                [event.stage.value for event in terminal],
                [
                    "source-acquire",
                    "input-verification",
                    "toolchain-acquire",
                    "toolchain-extract",
                    "patch",
                    "configure",
                    "compile",
                    "source-extract",
                    "archive-object-selection",
                    "artifact-validation",
                ],
            )
            self.assertEqual(terminal[0].metrics["cache_hit"], False)
            self.assertEqual(terminal[-2].metrics["object_count"], 1)

            cached_events = []
            cached_timing = TimingRecorder(cached_events.append)
            prepare_recipe(
                recipe,
                root / "work",
                root / "downloads",
                timing=cached_timing.span,
                skipped=cached_timing.skip,
            )
            cached_terminal = [
                event
                for event in cached_events
                if event.status is not ProgressStatus.STARTED
            ]
            self.assertTrue(
                all(event.status is ProgressStatus.SKIPPED for event in cached_terminal)
            )
            self.assertTrue(
                {
                    "toolchain-acquire",
                    "toolchain-extract",
                    "patch",
                    "configure",
                    "compile",
                }.issubset({event.stage.value for event in cached_terminal})
            )
