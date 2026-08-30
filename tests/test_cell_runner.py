from __future__ import annotations

import copy
import csv
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from fidb_poc import libc_catalog
from fidb_poc.cell_runner import (
    CellResolutionError,
    CellRunnerError,
    CellStage,
    GhidraRuntime,
    _write_seal,
    run_cell,
)
from fidb_poc.elf import ghidra_language
from fidb_poc.plan_request import resolve_plan
from fidb_poc.timing import ProgressStatus, TimingRecorder


class CellRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.project_root = Path(__file__).resolve().parents[1]
        plan = resolve_plan(
            cls.project_root / "plans/coverage-baseline.toml", cls.project_root
        )
        cls.native_cell = next(
            cell
            for cell in plan["cells"]
            if cell["kind"] == "native" and cell["recipe"]["name"] == "zlib"
        )
        cls.source_cell = next(
            cell
            for cell in plan["cells"]
            if cell["kind"] == "source-library" and cell["status"] == "planned"
        )
        cls.malware_cell = next(
            cell
            for cell in plan["cells"]
            if cell["kind"] == "malware" and cell["status"] == "planned"
        )

    @staticmethod
    def _fake_export(packed: Path, output: Path) -> Path:
        if not packed.read_bytes():
            raise AssertionError("packed FIDB should be non-empty before export")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(b"raw-fidbf")
        return output

    @staticmethod
    def _fake_runtime() -> GhidraRuntime:
        return GhidraRuntime(
            install_dir=Path("/opt/ghidra"),
            identity={
                "ghidra": {"version": "12.1"},
                "java": {"version": "21"},
                "pyghidra": {"version": "3.1.0"},
            },
        )

    @staticmethod
    def _fake_fidb(*, output: Path, **_kwargs: object) -> dict[str, int]:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(b"packed-fidb")
        return {"programs": 1, "attempted": 3, "added": 2, "excluded": 1}

    @staticmethod
    def _fake_prepare(
        cell,
        work: Path,
        _downloads: Path,
        *,
        timing=None,
        skipped=None,
    ):
        objects = work / "prepared/objects"
        objects.mkdir(parents=True, exist_ok=True)
        (objects / "one.o").write_bytes(b"object")
        return {
            "family": cell["family"],
            "version": str(cell["version"]),
            "variant": cell["variant"],
            "language": ghidra_language(
                str(cell["machine"]),
                str(cell["endianness"]),
                int(cell["elf_class"]),
            ),
            "objects": str(objects),
            "pattern": ".*",
            "limit": None,
            "recipe_digest": libc_catalog._digest(cell),
            "source_url": cell["source_url"],
            "source_sha256": cell["source_sha256"],
            "executor": cell["executor"],
        }

    @staticmethod
    def _fake_malware_build(cell, work: Path, _downloads: Path):
        binary = work / "prepared/vm/out/mirai.bot"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(b"fake-elf")
        binary.chmod(0o755)
        return {
            "family": cell["family"],
            "version": cell["version"],
            "variant": cell["variant"],
            "arch": cell["arch"],
            "binary_path": str(binary.resolve()),
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "source_url": cell["source_url"],
            "source_sha256": cell["source_sha256"],
            "toolchain_url": cell["toolchain_url"],
            "toolchain_sha256": cell["toolchain_sha256"],
            "build_adapter": cell["build_adapter"],
            "executor": cell["executor"],
            "cell_digest": libc_catalog._digest(cell),
        }

    @staticmethod
    def _fake_facts(cell) -> SimpleNamespace:
        values = {
            "machine": cell["target"]["machine"],
            "endianness": cell["target"]["endianness"],
            "elf_class": cell["target"]["elf_class"],
            "sha256": "f" * 64,
            "size": 8,
        }
        return SimpleNamespace(**values, to_dict=lambda: values)

    def _run_direct(self, cell: dict, attempt: Path):
        events = []
        with (
            patch(
                "fidb_poc.cell_runner._initialize_ghidra",
                return_value=self._fake_runtime(),
            ),
            patch(
                "fidb_poc.cell_runner.ghidra_fid.build_library_fidb",
                side_effect=self._fake_fidb,
            ) as build_fidb,
            patch(
                "fidb_poc.cell_runner.ghidra_fid.export_raw_fidbf",
                side_effect=self._fake_export,
            ),
            patch(
                "fidb_poc.cell_runner.libc_catalog.prepare_recipe",
                side_effect=self._fake_prepare,
            ) as prepare,
            patch(
                "fidb_poc.cell_runner.malware_build.build_malware_binary",
                side_effect=self._fake_malware_build,
            ) as build_malware,
            patch(
                "fidb_poc.cell_runner.inspect_elf",
                return_value=self._fake_facts(cell),
            ),
        ):
            result = run_cell(
                cell,
                [],
                self.project_root,
                attempt,
                progress=events.append,
            )
        return result, events, prepare, build_malware, build_fidb

    def test_source_and_malware_dispatch_through_complete_paths(self):
        for cell, expected_prepare, expected_malware in (
            (self.source_cell, 1, 0),
            (self.malware_cell, 0, 1),
        ):
            with self.subTest(kind=cell["kind"]), tempfile.TemporaryDirectory() as tmp:
                attempt = Path(tmp) / "attempt"
                result, events, prepare, malware, fidb = self._run_direct(
                    copy.deepcopy(cell), attempt
                )

                self.assertEqual(result.kind, cell["kind"])
                self.assertEqual(prepare.call_count, expected_prepare)
                self.assertEqual(malware.call_count, expected_malware)
                self.assertEqual(fidb.call_count, 1)
                self.assertTrue(result.fidb_path.is_file())
                self.assertTrue(result.fidbf_path.is_file())
                self.assertTrue(result.manifest_path.is_file())
                self.assertEqual(result.seal_path, result.manifest_path)
                self.assertEqual(events[-1].stage, CellStage.PROVENANCE_SEAL)
                self.assertEqual(events[-1].status, ProgressStatus.COMPLETED)

    def test_local_source_execution_requires_resolved_local_route(self):
        cell = copy.deepcopy(self.source_cell)
        cell["routing"]["executor"] = "local"
        with tempfile.TemporaryDirectory() as temporary:
            result, _events, prepare, _malware, _fidb = self._run_direct(
                cell, Path(temporary) / "attempt"
            )

        self.assertEqual(result.executor, "local")
        self.assertEqual(prepare.call_args.args[0]["executor"], "local")

    def test_native_dispatch_uses_isolated_pipeline_and_seals_both_formats(self):
        def fake_execute(
            configuration,
            root,
            progress,
            verbose=False,
            *,
            timing=None,
            skipped=None,
        ):
            self.assertEqual(configuration.libraries[0].name, "zlib")
            self.assertFalse(verbose)
            if progress is not None:
                progress("native fake")
            fidb = root / "artifacts/libs/fidb/native.fidb"
            fidb.parent.mkdir(parents=True, exist_ok=True)
            fidb.write_bytes(b"native-fidb")
            manifest = root / "artifacts/libs/fidb_manifest.csv"
            fields = {
                "status": "complete",
                "fidb_path": str(fidb.relative_to(root)),
                "fidb_sha256": hashlib.sha256(fidb.read_bytes()).hexdigest(),
                "fid_programs": "2",
                "fid_attempted": "5",
                "fid_added": "4",
                "fid_excluded": "1",
                "ghidra_version": "12.1",
                "ghidra_release": "PUBLIC",
                "ghidra_build": "2026-01-01",
                "ghidra_application_properties_sha256": "a" * 64,
                "ghidra_headless_path": "/opt/ghidra/support/analyzeHeadless",
                "java_path": "/usr/bin/java",
                "java_version": "21",
                "pyghidra_version": "3.1.0",
                "source_url": "https://example.invalid/source",
                "source_sha256": "b" * 64,
                "static_archive_path": "work/libz.a",
                "static_archive_sha256": "c" * 64,
                "analysis_artifact_kind": "objects",
                "analysis_artifact_path": "work/objects",
                "analysis_artifact_sha256": "d" * 64,
                "object_count": "2",
            }
            manifest.parent.mkdir(parents=True, exist_ok=True)
            with manifest.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=list(fields))
                writer.writeheader()
                writer.writerow(fields)
            return manifest

        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary) / "attempt"
            with (
                patch(
                    "fidb_poc.cell_runner.pipeline.execute",
                    side_effect=fake_execute,
                ) as execute,
                patch(
                    "fidb_poc.cell_runner.ghidra_fid.export_raw_fidbf",
                    side_effect=self._fake_export,
                ),
            ):
                result = run_cell(
                    copy.deepcopy(self.native_cell),
                    ["optimization:o2"],
                    self.project_root,
                    attempt,
                )

            self.assertEqual(execute.call_args.args[1], attempt.resolve())
            self.assertEqual(result.executor, "native-local")
            seal = json.loads(result.manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(seal["counts"]["added"], 4)
            self.assertEqual(
                seal["cell"]["factor_variants"][0]["id"], "optimization:o2"
            )
            self.assertEqual(seal["artifacts"]["fidb"]["bytes"], 11)
            self.assertEqual(seal["artifacts"]["fidbf"]["bytes"], 9)

    def test_raw_commands_and_unsupported_kinds_fail_before_dispatch(self):
        raw = copy.deepcopy(self.native_cell)
        raw["build"]["command"] = "cc injected.c"
        unsupported = copy.deepcopy(self.native_cell)
        unsupported["kind"] = "archive"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(CellResolutionError, "raw command"):
                run_cell(raw, [], self.project_root, root / "raw")
            with self.assertRaisesRegex(CellResolutionError, "unsupported.*kind"):
                run_cell(unsupported, [], self.project_root, root / "kind")

    def test_unregistered_factor_variant_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                CellResolutionError, "unsupported factor variants"
            ):
                run_cell(
                    self.native_cell,
                    ["optimization:o0"],
                    self.project_root,
                    Path(temporary) / "attempt",
                )

    def test_catalog_reresolution_rejects_changed_pin_and_executor(self):
        changed_pin = copy.deepcopy(self.source_cell)
        changed_pin["recipe"]["sha256"] = "0" * 64
        changed_adapter = copy.deepcopy(self.source_cell)
        changed_adapter["build"]["adapter"] = "plain_make"
        changed_target = copy.deepcopy(self.source_cell)
        changed_target["target"]["endianness"] = "little"
        changed_executor = copy.deepcopy(self.source_cell)
        changed_executor["routing"]["executor"] = "container"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(CellResolutionError, "recipe pins"):
                run_cell(changed_pin, [], self.project_root, root / "pin")
            with self.assertRaisesRegex(CellResolutionError, "build adapter"):
                run_cell(changed_adapter, [], self.project_root, root / "adapter")
            with self.assertRaisesRegex(CellResolutionError, "target ABI"):
                run_cell(changed_target, [], self.project_root, root / "target")
            with self.assertRaisesRegex(CellResolutionError, "source executor"):
                run_cell(changed_executor, [], self.project_root, root / "executor")

    def test_malware_is_never_executable_and_elf_target_is_checked(self):
        cell = copy.deepcopy(self.malware_cell)
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary) / "attempt"
            result, _events, _prepare, build_malware, build_fidb = self._run_direct(
                cell, attempt
            )
            binary = Path(build_malware.call_args.args[1]) / "prepared/vm/out/mirai.bot"
            self.assertEqual(binary.stat().st_mode & 0o777, 0o644)
            self.assertEqual(build_fidb.call_args.kwargs["objects"], [binary.resolve()])
            seal = json.loads(result.manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(
                seal["evidence"]["binary"]["sha256"],
                hashlib.sha256(b"fake-elf").hexdigest(),
            )

    def test_fidb_and_fidbf_must_both_be_nonempty(self):
        def empty_fidb(*, output: Path, **_kwargs: object) -> dict[str, int]:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.touch()
            return {"programs": 1, "attempted": 1, "added": 1, "excluded": 0}

        def empty_export(_packed: Path, output: Path) -> Path:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.touch()
            return output

        cases = (
            ("fidb", empty_fidb, self._fake_export, "FIDB is empty"),
            ("fidbf", self._fake_fidb, empty_export, "FIDBF is empty"),
        )
        for label, build, export, message in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                attempt = Path(temporary) / "attempt"
                with (
                    patch(
                        "fidb_poc.cell_runner._initialize_ghidra",
                        return_value=self._fake_runtime(),
                    ),
                    patch(
                        "fidb_poc.cell_runner.libc_catalog.prepare_recipe",
                        side_effect=self._fake_prepare,
                    ),
                    patch(
                        "fidb_poc.cell_runner.ghidra_fid.build_library_fidb",
                        side_effect=build,
                    ),
                    patch(
                        "fidb_poc.cell_runner.ghidra_fid.export_raw_fidbf",
                        side_effect=export,
                    ),
                    patch(
                        "fidb_poc.cell_runner.inspect_elf",
                        return_value=self._fake_facts(self.source_cell),
                    ),
                ):
                    with self.assertRaisesRegex(CellRunnerError, message):
                        run_cell(self.source_cell, [], self.project_root, attempt)

    def test_manifest_is_atomic_and_records_hashes_counts_and_pins(self):
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary) / "attempt"
            result, _events, _prepare, _malware, _fidb = self._run_direct(
                copy.deepcopy(self.source_cell), attempt
            )
            seal = json.loads(result.manifest_path.read_text(encoding="utf-8"))

            self.assertEqual(seal["schema_version"], "fidb-cell-seal/v1")
            self.assertEqual(len(seal["cell"]["resolved_cell_sha256"]), 64)
            self.assertEqual(seal["cell"]["executor"], "qemu")
            self.assertEqual(seal["pins"]["recipe"], self.source_cell["recipe"])
            self.assertEqual(seal["counts"]["programs"], 1)
            self.assertEqual(len(seal["artifacts"]["fidb"]["sha256"]), 64)
            self.assertEqual(len(seal["artifacts"]["fidbf"]["sha256"]), 64)
            self.assertEqual(
                seal["timing"]["schema_version"], "fidb-execution-timing/v1"
            )
            self.assertTrue(seal["timing"]["spans"])
            self.assertNotIn(
                "provenance-seal",
                {span["stage"] for span in seal["timing"]["spans"]},
            )
            self.assertIn(
                "provenance-seal",
                {span["stage"] for span in result.timing["spans"]},
            )
            for span in seal["timing"]["spans"]:
                self.assertIn(span["status"], {"completed", "skipped"})
                self.assertIsInstance(span["duration_ns"], int)
                self.assertGreaterEqual(span["duration_ns"], 0)
                self.assertTrue(span["started_at"].endswith("Z"))
                self.assertTrue(span["finished_at"].endswith("Z"))
            self.assertEqual(
                result.manifest_sha256,
                hashlib.sha256(result.manifest_path.read_bytes()).hexdigest(),
            )
            self.assertEqual(list(result.manifest_path.parent.glob(".*.tmp")), [])

    def test_atomic_seal_fsyncs_its_parent_after_rename(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "artifacts/cell-seal.json"
            with patch("fidb_poc.cell_runner._fsync_directory") as sync_directory:
                seal_path, digest = _write_seal(
                    path,
                    {"schema_version": "fidb-cell-seal/v1", "cell": {"id": "test"}},
                )

            self.assertEqual(seal_path, path)
            self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            sync_directory.assert_called_once_with(path.parent)
            self.assertEqual(list(path.parent.glob(".*.tmp")), [])

    def test_timing_recorder_emits_typed_resource_metrics_and_failed_span(self):
        events = []
        recorder = TimingRecorder(events.append)
        with self.assertRaisesRegex(RuntimeError, "timed failure"):
            with recorder.span(
                CellStage.COMPILE,
                "failing compile",
                {"object_count": 3},
            ):
                raise RuntimeError("timed failure")

        self.assertEqual(
            [event.status for event in events],
            [ProgressStatus.STARTED, ProgressStatus.FAILED],
        )
        terminal = events[-1]
        self.assertIsInstance(terminal.duration_ns, int)
        self.assertGreaterEqual(terminal.duration_ns, 0)
        self.assertEqual(terminal.metrics["object_count"], 3)
        for name in (
            "process_cpu_duration_ns",
            "self_user_cpu_duration_ns",
            "self_system_cpu_duration_ns",
            "child_user_cpu_duration_ns",
            "child_system_cpu_duration_ns",
            "self_max_rss_bytes_peak",
            "child_max_rss_bytes_peak",
        ):
            self.assertIn(name, terminal.metrics)


if __name__ == "__main__":
    unittest.main()
