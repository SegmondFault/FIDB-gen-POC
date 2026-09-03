from __future__ import annotations

import copy
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fidb_poc.cell_runner import CellRunResult
from fidb_poc.coordinator import Coordinator
from fidb_poc.queue_cli import (
    QueueCliError,
    _durably_publish,
    _staging_root,
    _validate_cell_timing,
    main,
)
from fidb_poc.timing import (
    CellStage,
    ProgressEvent,
    ProgressStatus,
    TimingRecorder,
)


class QueueCommandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.project_root = Path(__file__).resolve().parents[1]

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".queue-cli-test-", dir=self.project_root
        )
        self.directory = Path(self.temporary.name)
        self.database = self.directory / "ledger.sqlite3"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _write_fake_seal(
        attempt: Path,
        seal: Path,
        fidb: Path,
        fidbf: Path,
        cell: dict[str, object],
        timing: dict[str, object],
    ) -> None:
        seal.write_text(
            json.dumps(
                {
                    "schema_version": "fidb-cell-seal/v1",
                    "cell": {
                        "id": cell["id"],
                        "kind": cell["kind"],
                        "executor": cell["routing"]["executor"],
                    },
                    "artifacts": {
                        "fidb": {
                            "path": str(fidb.relative_to(attempt)),
                            "sha256": hashlib.sha256(fidb.read_bytes()).hexdigest(),
                            "bytes": fidb.stat().st_size,
                        },
                        "fidbf": {
                            "path": str(fidbf.relative_to(attempt)),
                            "sha256": hashlib.sha256(fidbf.read_bytes()).hexdigest(),
                            "bytes": fidbf.stat().st_size,
                        },
                    },
                    "timing": timing,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    def _queue(self, *, armed: bool) -> Path:
        path = self.directory / "priority.toml"
        path.write_text(
            "\n".join(
                (
                    'schema_version = "fidb-queue/v1"',
                    'name = "queue-cli-test"',
                    "",
                    "[queue]",
                    f"armed = {str(armed).lower()}",
                    "max_workers = 4",
                    'batch_order = ["batch-mirai"]',
                    "poll_seconds = 1",
                    "lease_seconds = 60",
                    "max_attempts = 2",
                    "",
                    "[[batch]]",
                    'id = "batch-mirai"',
                    'name = "mirai baseline"',
                    'plan = "plans/mirai-baseline.toml"',
                    "",
                )
            ),
            encoding="utf-8",
        )
        return path

    def _arguments(self, command: str, queue: Path | None = None) -> list[str]:
        result = [
            command,
            "--project-root",
            str(self.project_root),
            "--state",
            str(self.database),
        ]
        if queue is not None:
            result.extend(("--queue", str(queue)))
        return result

    def _mixed_pool_queue(self) -> Path:
        path = self.directory / "mixed-pools.toml"
        path.write_text(
            """schema_version = "fidb-queue/v1"
name = "mixed-pool-cli"

[queue]
armed = true
max_workers = 4
batch_order = ["batch-qemu", "batch-malware", "batch-local"]
poll_seconds = 1
lease_seconds = 60
max_attempts = 2

[[batch]]
id = "batch-qemu"
name = "qemu source library"
plan = "plans/coverage-baseline.toml"
matrices = ["uclibc-cross"]

[[batch]]
id = "batch-malware"
name = "malware"
plan = "plans/coverage-baseline.toml"
matrices = ["mirai-ground-truth"]

[[batch]]
id = "batch-local"
name = "local native libraries"
plan = "plans/coverage-baseline.toml"
matrices = ["native-libraries"]
""",
            encoding="utf-8",
        )
        return path

    def test_sync_materializes_disarmed_queue_without_execution(self) -> None:
        output = io.StringIO()
        with (
            patch("fidb_poc.queue_cli.run_cell") as run_cell,
            contextlib.redirect_stdout(output),
        ):
            status = main(self._arguments("sync", self._queue(armed=False)))

        self.assertEqual(status, 0)
        run_cell.assert_not_called()
        self.assertIn('"status": "disarmed"', output.getvalue())
        with Coordinator(self.database, self.project_root) as coordinator:
            snapshot = coordinator.snapshot()
        self.assertEqual(snapshot["counts"]["queued"], 1)
        self.assertEqual(snapshot["counts"]["complete"], 0)

    def test_run_refuses_disarmed_toml_before_claim_or_execution(self) -> None:
        errors = io.StringIO()
        arguments = self._arguments("run", self._queue(armed=False))
        arguments.extend(("--worker-id", "test-worker", "--once"))
        with (
            patch("fidb_poc.queue_cli.run_cell") as run_cell,
            contextlib.redirect_stderr(errors),
        ):
            status = main(arguments)

        self.assertEqual(status, 1)
        run_cell.assert_not_called()
        self.assertFalse(self.database.exists())
        self.assertIn("queue is disarmed", errors.getvalue())
        self.assertIn("no build was started", errors.getvalue())

    def test_start_block_manually_admits_one_batch_without_execution(self) -> None:
        output = io.StringIO()
        arguments = self._arguments("start-block", self._queue(armed=True))
        with (
            patch("fidb_poc.queue_cli.run_cell") as run_cell,
            contextlib.redirect_stdout(output),
        ):
            status = main(arguments)

        document = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertTrue(document["active"])
        self.assertEqual(document["batch_id"], "batch-mirai")
        self.assertTrue(document["admission_id"].startswith("manual:"))
        run_cell.assert_not_called()
        with Coordinator(self.database, self.project_root) as coordinator:
            self.assertEqual(
                coordinator.status()["execution_block"]["batch_id"],
                "batch-mirai",
            )

    def test_started_block_claims_after_window_without_cutoff_timer(self) -> None:
        queue = self._queue(armed=True)
        queue.write_text(
            queue.read_text(encoding="utf-8") + """
[schedule]
enabled = true
timezone = "Europe/Luxembourg"
days = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
start = "01:00"
stop_claiming = "05:30"
finish_started_batch = true
""",
            encoding="utf-8",
        )
        with Coordinator(self.database, self.project_root) as coordinator:
            coordinator.sync_queue(queue, now=10)
            coordinator.start_next_block("manual:test", scheduled=False, now=11)
        operations = {
            "schedule": {
                "claims_allowed": False,
                "window_started_at": None,
                "hard_cutoff_at": None,
            },
            "resources": {"passed": True, "reasons": [], "metrics": {}},
        }
        arguments = self._arguments("run", queue)
        arguments.extend(("--worker-id", "draining-worker", "--once"))
        with (
            patch("fidb_poc.queue_cli.evaluate_operations", return_value=operations),
            patch("fidb_poc.queue_cli._execute_claim", return_value=True) as execute,
            patch("fidb_poc.queue_cli.threading.Timer") as timer,
        ):
            status = main(arguments)

        self.assertEqual(status, 0)
        execute.assert_called_once()
        timer.assert_not_called()

    def test_preflight_reports_schedule_and_resources_without_state_mutation(
        self,
    ) -> None:
        output = io.StringIO()
        arguments = self._arguments(
            "preflight", self.project_root / "plans/priority-queue.toml"
        )
        with contextlib.redirect_stdout(output):
            status = main(arguments)

        document = json.loads(output.getvalue())
        self.assertEqual(status, 1)
        self.assertEqual(document["schema_version"], "fidb-operations-preflight/v1")
        self.assertFalse(document["queue_armed"])
        self.assertIn("claims_allowed", document["schedule"])
        self.assertIn("available_memory_gib", document["resources"]["metrics"])
        self.assertFalse(self.database.exists())

    def test_hard_cutoff_requeues_once_worker_without_becoming_operator_interrupt(
        self,
    ) -> None:
        class ImmediateTimer:
            daemon = False

            def __init__(self, _delay, callback):
                self.callback = callback

            def start(self):
                self.callback()

            def cancel(self):
                return None

        arguments = self._arguments("run", self._queue(armed=True))
        arguments.extend(("--worker-id", "cutoff-worker", "--once"))
        preflight = {
            "schedule": {
                "claims_allowed": True,
                "hard_cutoff_at": "2099-01-01T00:00:00+00:00",
            },
            "resources": {"passed": True, "reasons": [], "metrics": {}},
        }
        with (
            patch("fidb_poc.queue_cli.evaluate_operations", return_value=preflight),
            patch("fidb_poc.queue_cli.threading.Timer", ImmediateTimer),
            patch("fidb_poc.queue_cli.os.kill"),
            patch("fidb_poc.queue_cli._execute_claim", side_effect=KeyboardInterrupt),
        ):
            status = main(arguments)

        self.assertEqual(status, 1)

    def test_staging_root_has_no_hidden_components_for_ghidra(self) -> None:
        staging, final = _staging_root(
            self.directory,
            {"job_id": f"job-{'a' * 64}", "lease_generation": 1},
        )

        relative = staging.relative_to(self.directory / "artifacts/runs")
        self.assertTrue(relative.parts)
        self.assertTrue(all(not part.startswith(".") for part in relative.parts))
        self.assertEqual(final.name, "attempt-1")

    def test_armed_run_publishes_sealed_fidb_and_completes_job(self) -> None:
        queue = self._queue(armed=True)

        def fake_run_cell(cell, variants, root, attempt, **kwargs):
            self.assertEqual(cell["kind"], "malware")
            self.assertEqual(variants, [])
            self.assertEqual(root, self.project_root)
            artifacts = attempt / "artifacts/fidbs"
            artifacts.mkdir(parents=True)
            fidb = artifacts / "result.fidb"
            fidbf = artifacts / "result.fidbf"
            seal = attempt / "artifacts/cell-seal.json"
            fidb.write_bytes(b"packed")
            fidbf.write_bytes(b"raw")
            timing = TimingRecorder(kwargs["progress"])
            with timing.span(
                CellStage.COMPILE,
                "fake reviewed compile",
                {"cache_hit": False},
            ) as metrics:
                metrics["object_count"] = 7
            self._write_fake_seal(
                attempt,
                seal,
                fidb,
                fidbf,
                cell,
                timing.document(),
            )
            with timing.span(
                CellStage.PROVENANCE_SEAL,
                "fake completed provenance seal",
            ):
                pass
            return CellRunResult(
                cell_id=cell["id"],
                kind=cell["kind"],
                executor=cell["routing"]["executor"],
                manifest_path=seal,
                manifest_sha256=hashlib.sha256(seal.read_bytes()).hexdigest(),
                fidb_path=fidb,
                fidbf_path=fidbf,
                timing=timing.document(),
            )

        arguments = self._arguments("run", queue)
        arguments.extend(("--worker-id", "test-worker", "--once"))
        staging = self.directory / "staging"
        final = self.directory / "published"
        staging.mkdir()
        with (
            patch("fidb_poc.queue_cli.run_cell", side_effect=fake_run_cell),
            patch(
                "fidb_poc.queue_cli._staging_root",
                return_value=(staging, final),
            ),
        ):
            status = main(arguments)

        self.assertEqual(status, 0)
        with Coordinator(self.database, self.project_root) as coordinator:
            snapshot = coordinator.snapshot()
        self.assertEqual(snapshot["counts"]["complete"], 1)
        job = snapshot["jobs"][0]
        self.assertEqual(job["state"], "complete")
        self.assertEqual(job["result"]["executor"], "qemu")
        self.assertEqual(
            job["result"]["timing"]["schema_version"],
            "fidb-job-timing/v1",
        )
        publication = job["result"]["timing"]["publication"]
        self.assertEqual(publication["spans"][0]["stage"], "publication")
        self.assertEqual(publication["spans"][0]["status"], "completed")
        self.assertGreaterEqual(publication["spans"][0]["duration_ns"], 0)
        spans = {span["stage"]: span for span in snapshot["stage_attempts"]}
        self.assertEqual(set(spans), {"compile", "provenance-seal", "publication"})
        compile_span = spans["compile"]
        self.assertEqual(compile_span["state"], "completed")
        self.assertEqual(compile_span["duration_source"], "worker-monotonic")
        self.assertIsInstance(compile_span["duration_ns"], int)
        self.assertTrue(compile_span["started_at"].endswith("+00:00"))
        self.assertTrue(compile_span["ended_at"].endswith("+00:00"))
        self.assertEqual(compile_span["metrics"]["cache_hit"], False)
        self.assertEqual(compile_span["metrics"]["object_count"], 7)
        self.assertEqual(spans["publication"]["state"], "completed")
        for artifact in ("seal", "fidb", "fidbf"):
            path = self.project_root / job["result"][artifact]["path"]
            self.assertTrue(path.is_file())
            self.assertEqual(
                hashlib.sha256(path.read_bytes()).hexdigest(),
                job["result"][artifact]["sha256"],
            )

    def test_durable_publication_flushes_materials_on_both_sides_of_rename(
        self,
    ) -> None:
        staging = self.directory / "staging"
        final = self.directory / "published/attempt-1"
        final.parent.mkdir(parents=True)
        artifacts = staging / "artifacts"
        artifacts.mkdir(parents=True)
        seal = artifacts / "seal.json"
        fidb = artifacts / "output.fidb"
        fidbf = artifacts / "output.fidbf"
        fidb.write_bytes(b"fidb")
        fidbf.write_bytes(b"fidbf")
        cell = {
            "id": "cell",
            "kind": "native",
            "routing": {"executor": "native-local"},
        }
        timing = TimingRecorder()
        with timing.span(CellStage.COMPILE, "compile"):
            pass
        self._write_fake_seal(staging, seal, fidb, fidbf, cell, timing.document())
        with timing.span(CellStage.PROVENANCE_SEAL, "seal"):
            pass
        result = CellRunResult(
            cell_id="cell",
            kind="native",
            executor="native-local",
            manifest_path=seal,
            manifest_sha256=hashlib.sha256(seal.read_bytes()).hexdigest(),
            fidb_path=fidb,
            fidbf_path=fidbf,
            timing=timing.document(),
        )
        operations: list[tuple[str, object]] = []
        real_replace = os.replace

        def record_file(path):
            operations.append(("file", Path(path)))

        def record_directories(paths, boundary):
            operations.append(("directories", (tuple(paths), Path(boundary))))

        def record_replace(source, destination):
            operations.append(("replace", (Path(source), Path(destination))))
            real_replace(source, destination)

        with (
            patch("fidb_poc.queue_cli._fsync_regular_file", side_effect=record_file),
            patch(
                "fidb_poc.queue_cli._fsync_directory_chains",
                side_effect=record_directories,
            ),
            patch("fidb_poc.queue_cli.os.replace", side_effect=record_replace),
        ):
            published = _durably_publish(result, staging, final, self.directory)

        self.assertEqual(
            [operation for operation, _details in operations],
            [
                "file",
                "file",
                "file",
                "directories",
                "replace",
                "file",
                "file",
                "file",
                "directories",
            ],
        )
        self.assertEqual(published["seal"], final / "artifacts/seal.json")
        self.assertTrue(published["FIDB"].is_file())
        self.assertTrue(published["FIDBF"].is_file())

    def test_post_seal_artifact_mutation_is_rejected_before_rename(self) -> None:
        staging = self.directory / "mutated-staging"
        final = self.directory / "mutated-published"
        artifacts = staging / "artifacts"
        artifacts.mkdir(parents=True)
        seal = artifacts / "seal.json"
        fidb = artifacts / "output.fidb"
        fidbf = artifacts / "output.fidbf"
        fidb.write_bytes(b"sealed-fidb")
        fidbf.write_bytes(b"sealed-fidbf")
        cell = {
            "id": "cell",
            "kind": "native",
            "routing": {"executor": "native-local"},
        }
        timing = TimingRecorder()
        with timing.span(CellStage.COMPILE, "compile"):
            pass
        self._write_fake_seal(staging, seal, fidb, fidbf, cell, timing.document())
        with timing.span(CellStage.PROVENANCE_SEAL, "seal"):
            pass
        result = CellRunResult(
            cell_id="cell",
            kind="native",
            executor="native-local",
            manifest_path=seal,
            manifest_sha256=hashlib.sha256(seal.read_bytes()).hexdigest(),
            fidb_path=fidb,
            fidbf_path=fidbf,
            timing=timing.document(),
        )

        fidb.write_bytes(b"mutated-after-seal")
        with self.assertRaisesRegex(QueueCliError, "authoritative seal"):
            _durably_publish(result, staging, final, self.directory)

        self.assertTrue(staging.is_dir())
        self.assertFalse(final.exists())

    def test_sealed_timing_must_match_completed_timing_prefix(self) -> None:
        staging = self.directory / "timing-binding-staging"
        final = self.directory / "timing-binding-published"
        artifacts = staging / "artifacts"
        artifacts.mkdir(parents=True)
        seal = artifacts / "seal.json"
        fidb = artifacts / "output.fidb"
        fidbf = artifacts / "output.fidbf"
        fidb.write_bytes(b"fidb")
        fidbf.write_bytes(b"fidbf")
        cell = {
            "id": "cell",
            "kind": "native",
            "routing": {"executor": "native-local"},
        }
        timing = TimingRecorder()
        with timing.span(CellStage.COMPILE, "compile"):
            pass
        self._write_fake_seal(staging, seal, fidb, fidbf, cell, timing.document())
        sealed = json.loads(seal.read_text(encoding="utf-8"))
        sealed["timing"]["spans"][0]["message"] = "unrelated timing"
        seal.write_text(json.dumps(sealed) + "\n", encoding="utf-8")
        with timing.span(CellStage.PROVENANCE_SEAL, "seal"):
            pass
        result = CellRunResult(
            cell_id="cell",
            kind="native",
            executor="native-local",
            manifest_path=seal,
            manifest_sha256=hashlib.sha256(seal.read_bytes()).hexdigest(),
            fidb_path=fidb,
            fidbf_path=fidbf,
            timing=timing.document(),
        )

        with self.assertRaisesRegex(QueueCliError, "seal timing"):
            _durably_publish(result, staging, final, self.directory)

        self.assertTrue(staging.is_dir())
        self.assertFalse(final.exists())

    def test_cell_timing_validation_rejects_malformed_or_incomplete_spans(self) -> None:
        timing = TimingRecorder()
        with timing.span(CellStage.COMPILE, "compile"):
            pass
        with timing.span(CellStage.PROVENANCE_SEAL, "seal"):
            pass
        valid = timing.document()
        _validate_cell_timing(valid)

        malformed = []
        wrong_schema = copy.deepcopy(valid)
        wrong_schema["schema_version"] = "fidb-execution-timing/v0"
        malformed.append(wrong_schema)
        non_object = copy.deepcopy(valid)
        non_object["spans"] = [None]
        malformed.append(non_object)
        open_span = copy.deepcopy(valid)
        open_span["spans"][-1]["status"] = "started"
        malformed.append(open_span)
        missing_seal = copy.deepcopy(valid)
        missing_seal["spans"] = missing_seal["spans"][:-1]
        missing_seal["summary"]["terminal_event_counts"]["completed"] -= 1
        missing_seal["summary"]["stage_duration_ns"].pop("provenance-seal")
        malformed.append(missing_seal)
        invalid_duration = copy.deepcopy(valid)
        invalid_duration["spans"][-1]["duration_ns"] = -1
        malformed.append(invalid_duration)
        invalid_metrics = copy.deepcopy(valid)
        invalid_metrics["spans"][-1]["metrics"] = []
        malformed.append(invalid_metrics)

        for document in malformed:
            with self.subTest(document=document), self.assertRaises(QueueCliError):
                _validate_cell_timing(document)

    def test_incomplete_timing_fails_before_attempt_publication(self) -> None:
        queue = self._queue(armed=True)
        staging = self.directory / "invalid-timing-staging"
        final = self.directory / "invalid-timing-published"
        staging.mkdir()

        def fake_run_cell(cell, _variants, _root, attempt, **kwargs):
            artifacts = attempt / "artifacts"
            artifacts.mkdir(parents=True)
            seal = artifacts / "seal.json"
            fidb = artifacts / "output.fidb"
            fidbf = artifacts / "output.fidbf"
            seal.write_bytes(b"seal")
            fidb.write_bytes(b"fidb")
            fidbf.write_bytes(b"fidbf")
            timing = TimingRecorder(kwargs["progress"])
            with timing.span(CellStage.COMPILE, "compile without final seal"):
                pass
            return CellRunResult(
                cell_id=cell["id"],
                kind=cell["kind"],
                executor=cell["routing"]["executor"],
                manifest_path=seal,
                manifest_sha256=hashlib.sha256(seal.read_bytes()).hexdigest(),
                fidb_path=fidb,
                fidbf_path=fidbf,
                timing=timing.document(),
            )

        arguments = self._arguments("run", queue)
        arguments.extend(("--worker-id", "test-worker", "--once"))
        errors = io.StringIO()
        with (
            patch("fidb_poc.queue_cli.run_cell", side_effect=fake_run_cell),
            patch("fidb_poc.queue_cli._staging_root", return_value=(staging, final)),
            patch("fidb_poc.queue_cli._durably_publish") as publish,
            contextlib.redirect_stderr(errors),
        ):
            status = main(arguments)

        self.assertEqual(status, 1)
        publish.assert_not_called()
        self.assertFalse(final.exists())
        with Coordinator(self.database, self.project_root) as coordinator:
            snapshot = coordinator.snapshot()
        self.assertEqual(snapshot["counts"]["complete"], 0)
        self.assertIn("completed provenance-seal", errors.getvalue())

    def test_fsync_failure_prevents_ledger_completion_and_rename(self) -> None:
        queue = self._queue(armed=True)
        staging = self.directory / "fsync-failure-staging"
        final = self.directory / "fsync-failure-published"
        staging.mkdir()

        def fake_run_cell(cell, _variants, _root, attempt, **kwargs):
            artifacts = attempt / "artifacts"
            artifacts.mkdir(parents=True)
            seal = artifacts / "seal.json"
            fidb = artifacts / "output.fidb"
            fidbf = artifacts / "output.fidbf"
            fidb.write_bytes(b"fidb")
            fidbf.write_bytes(b"fidbf")
            timing = TimingRecorder(kwargs["progress"])
            with timing.span(CellStage.COMPILE, "completed compile"):
                pass
            self._write_fake_seal(
                attempt,
                seal,
                fidb,
                fidbf,
                cell,
                timing.document(),
            )
            with timing.span(CellStage.PROVENANCE_SEAL, "completed seal"):
                pass
            return CellRunResult(
                cell_id=cell["id"],
                kind=cell["kind"],
                executor=cell["routing"]["executor"],
                manifest_path=seal,
                manifest_sha256=hashlib.sha256(seal.read_bytes()).hexdigest(),
                fidb_path=fidb,
                fidbf_path=fidbf,
                timing=timing.document(),
            )

        arguments = self._arguments("run", queue)
        arguments.extend(("--worker-id", "test-worker", "--once"))
        errors = io.StringIO()
        with (
            patch("fidb_poc.queue_cli.run_cell", side_effect=fake_run_cell),
            patch("fidb_poc.queue_cli._staging_root", return_value=(staging, final)),
            patch(
                "fidb_poc.queue_cli._fsync_regular_file",
                side_effect=OSError("forced fsync failure"),
            ),
            contextlib.redirect_stderr(errors),
        ):
            status = main(arguments)

        self.assertEqual(status, 1)
        self.assertTrue(staging.is_dir())
        self.assertFalse(final.exists())
        with Coordinator(self.database, self.project_root) as coordinator:
            snapshot = coordinator.snapshot()
        self.assertEqual(snapshot["counts"]["complete"], 0)
        self.assertIn("forced fsync failure", errors.getvalue())

    def test_state_path_outside_project_fails_cleanly(self) -> None:
        outside = Path(tempfile.gettempdir()) / "fidb-outside-ledger.sqlite3"
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            status = main(
                [
                    "sync",
                    "--project-root",
                    str(self.project_root),
                    "--state",
                    str(outside),
                    "--queue",
                    str(self._queue(armed=False)),
                ]
            )

        self.assertEqual(status, 1)
        self.assertFalse(outside.exists())
        self.assertIn("must remain inside the project root", errors.getvalue())

    def test_worker_requeues_when_result_returns_with_open_stage(self) -> None:
        queue = self._queue(armed=True)

        def fake_run_cell(cell, _variants, _root, attempt, **kwargs):
            artifacts = attempt / "artifacts/fidbs"
            artifacts.mkdir(parents=True)
            fidb = artifacts / "result.fidb"
            fidbf = artifacts / "result.fidbf"
            seal = attempt / "artifacts/cell-seal.json"
            fidb.write_bytes(b"packed")
            fidbf.write_bytes(b"raw")
            seal.write_text('{"schema_version":"fidb-cell-seal/v1"}\n')
            kwargs["progress"](
                ProgressEvent(
                    stage=CellStage.PUBLICATION,
                    status=ProgressStatus.STARTED,
                    message="incorrectly left publication open",
                    duration_ns=None,
                    metrics={},
                    started_at="2026-08-26T20:00:00Z",
                    finished_at=None,
                )
            )
            timing = TimingRecorder()
            with timing.span(CellStage.COMPILE, "completed compile"):
                pass
            with timing.span(CellStage.PROVENANCE_SEAL, "completed seal"):
                pass
            return CellRunResult(
                cell_id=cell["id"],
                kind=cell["kind"],
                executor=cell["routing"]["executor"],
                manifest_path=seal,
                manifest_sha256=hashlib.sha256(seal.read_bytes()).hexdigest(),
                fidb_path=fidb,
                fidbf_path=fidbf,
                timing=timing.document(),
            )

        arguments = self._arguments("run", queue)
        arguments.extend(("--worker-id", "test-worker", "--once"))
        errors = io.StringIO()
        with (
            patch("fidb_poc.queue_cli.run_cell", side_effect=fake_run_cell),
            contextlib.redirect_stderr(errors),
        ):
            status = main(arguments)

        self.assertEqual(status, 1)
        self.assertIn("already running", errors.getvalue())
        with Coordinator(self.database, self.project_root) as coordinator:
            snapshot = coordinator.snapshot()
            timings = coordinator.timings()
        self.assertEqual(snapshot["jobs"][0]["state"], "queued")
        self.assertEqual(snapshot["attempts"][0]["state"], "failed")
        self.assertEqual(snapshot["stage_attempts"][0]["state"], "interrupted")
        self.assertEqual(timings["sample_counts"]["completed_workflows"], 0)
        self.assertIsNone(timings["throughput"])

    def test_library_local_pool_is_passed_to_atomic_claim(self) -> None:
        queue = self._mixed_pool_queue()
        arguments = self._arguments("run", queue)
        arguments.extend(
            (
                "--worker-id",
                "library-worker",
                "--pool",
                "library-local",
                "--once",
            )
        )

        def inspect_claim(_coordinator, _database, _root, lease, _seconds, **_kwargs):
            self.assertEqual(lease["batch_id"], "batch-local")
            self.assertEqual(lease["cell"]["kind"], "native")
            self.assertEqual(lease["cell"]["routing"]["executor"], "native-local")
            return True

        with patch("fidb_poc.queue_cli._execute_claim", side_effect=inspect_claim):
            status = main(arguments)

        self.assertEqual(status, 0)

    def test_queue_performance_profile_reaches_worker_execution(self) -> None:
        queue = self._mixed_pool_queue()
        queue.write_text(
            queue.read_text(encoding="utf-8").replace(
                "max_workers = 4",
                'max_workers = 20\nperformance_profile = "reference-host-94g-balanced"',
            ),
            encoding="utf-8",
        )
        arguments = self._arguments("run", queue)
        arguments.extend(
            ("--worker-id", "profile-worker", "--pool", "library-local", "--once")
        )
        operations = {
            "schedule": {"claims_allowed": True, "hard_cutoff_at": None},
            "resources": {"passed": True, "reasons": [], "metrics": {}},
        }

        with (
            patch.dict(os.environ, {"JAVA_TOOL_OPTIONS": "-Xmx4g"}),
            patch("fidb_poc.queue_cli.evaluate_operations", return_value=operations),
            patch("fidb_poc.queue_cli._execute_claim", return_value=True) as execute,
        ):
            status = main(arguments)
            self.assertEqual(os.environ["JAVA_TOOL_OPTIONS"], "-Xmx4g")

        self.assertEqual(status, 0)
        self.assertEqual(execute.call_args.kwargs["build_jobs_per_cell"], 4)

    def test_invalid_worker_pool_fails_cleanly(self) -> None:
        errors = io.StringIO()
        arguments = self._arguments("run", self._mixed_pool_queue())
        arguments.extend(("--worker-id", "worker", "--pool", "malware", "--once"))

        with (
            contextlib.redirect_stderr(errors),
            self.assertRaises(SystemExit) as raised,
        ):
            main(arguments)

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("invalid choice", errors.getvalue())
        self.assertFalse(self.database.exists())


if __name__ == "__main__":
    unittest.main()
