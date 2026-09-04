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

from fidb_poc.cell_runner import CellResolutionError, CellRunResult
from fidb_poc.coordinator import Coordinator
from fidb_poc.queue_cli import (
    QueueCliError,
    _RETENTION_PRE_RECYCLE_JVM,
    _RETENTION_PRE_RECYCLE_RSS,
    _RETENTION_RECYCLED_SESSION,
    _RETENTION_RECYCLED_WORKER,
    _durably_publish,
    _maybe_post_drain_maintenance,
    _park_recycled_terminal_worker,
    _post_drain_maintenance,
    _post_recycle_memory_audit,
    _recycle_worker_process,
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

    def test_post_drain_retention_recycles_worker_even_when_collection_is_deferred(
        self,
    ) -> None:
        policy = type("Policy", (), {"worker_action": "recycle"})()
        with (
            patch("fidb_poc.retention.load_retention_policy", return_value=policy),
            patch(
                "fidb_poc.retention.automatic_retention",
                return_value={
                    "state": "manual-review-required",
                    "plan_digest": "a" * 64,
                    "summary": {"actions": 2},
                },
            ),
            patch("fidb_poc.queue_cli._recycle_worker_process") as recycle,
            patch.dict(os.environ, {}, clear=True),
        ):
            _post_drain_maintenance(
                self.project_root, self.database, "batch-drained-42", "worker-1"
            )

        recycle.assert_called_once_with("batch-drained-42", "worker-1")

    def test_post_drain_retention_is_once_per_worker_and_session(self) -> None:
        with (
            patch("fidb_poc.retention.load_retention_policy") as load_policy,
            patch("fidb_poc.retention.automatic_retention") as collect,
            patch("fidb_poc.queue_cli._recycle_worker_process") as recycle,
            patch.dict(
                os.environ,
                {_RETENTION_RECYCLED_SESSION: "batch-drained-42"},
                clear=True,
            ),
        ):
            _post_drain_maintenance(
                self.project_root, self.database, "batch-drained-42", "worker-1"
            )

        load_policy.assert_not_called()
        collect.assert_not_called()
        recycle.assert_not_called()

    def test_post_drain_worker_recycles_after_safe_retention_failure(self) -> None:
        policy = type("Policy", (), {"worker_action": "recycle"})()
        with (
            patch("fidb_poc.retention.load_retention_policy", return_value=policy),
            patch(
                "fidb_poc.retention.automatic_retention",
                side_effect=ValueError("invalid evidence"),
            ),
            patch("fidb_poc.queue_cli._recycle_worker_process") as recycle,
            patch.dict(os.environ, {}, clear=True),
        ):
            _post_drain_maintenance(
                self.project_root, self.database, "batch-drained-42", "worker-1"
            )

        recycle.assert_called_once_with("batch-drained-42", "worker-1")

    def test_worker_recycle_hands_memory_evidence_to_fresh_process(self) -> None:
        with (
            patch("fidb_poc.queue_cli._self_rss_bytes", return_value=734003200),
            patch("fidb_poc.queue_cli._embedded_jvm_started", return_value=True),
            patch("fidb_poc.queue_cli.os.execve") as execute,
            patch.dict(os.environ, {}, clear=True),
        ):
            _recycle_worker_process("batch-drained-42", "worker-1")

        environment = execute.call_args.args[2]
        self.assertEqual(
            environment[_RETENTION_RECYCLED_SESSION], "batch-drained-42"
        )
        self.assertEqual(environment[_RETENTION_RECYCLED_WORKER], "worker-1")
        self.assertEqual(environment[_RETENTION_PRE_RECYCLE_RSS], "734003200")
        self.assertEqual(environment[_RETENTION_PRE_RECYCLE_JVM], "true")

    def test_fresh_worker_records_secondary_memory_audit(self) -> None:
        environment = {
            _RETENTION_RECYCLED_SESSION: "batch-drained-42",
            _RETENTION_RECYCLED_WORKER: "worker-1",
            _RETENTION_PRE_RECYCLE_RSS: "734003200",
            _RETENTION_PRE_RECYCLE_JVM: "true",
        }
        with (
            patch.dict(os.environ, environment, clear=True),
            patch("fidb_poc.queue_cli._self_rss_bytes", return_value=67108864),
            patch("fidb_poc.queue_cli._embedded_jvm_started", return_value=False),
            patch(
                "fidb_poc.retention.write_memory_cleanup_audit",
                return_value={"state": "passed", "reclaimed_rss_bytes": 666894336},
            ) as write_audit,
        ):
            _post_recycle_memory_audit(self.project_root, "worker-1")

        write_audit.assert_called_once_with(
            self.project_root,
            worker_id="worker-1",
            session_id="batch-drained-42",
            before_rss_bytes=734003200,
            after_rss_bytes=67108864,
            before_jvm_started=True,
            after_jvm_started=False,
        )

    def test_recycled_terminal_worker_parks_until_work_is_queued(self) -> None:
        policy = type(
            "Policy",
            (),
            {
                "memory_cleanup_enabled": True,
                "park_terminal_workers": True,
                "park_poll_seconds": 10,
            },
        )()
        with (
            patch("fidb_poc.retention.load_retention_policy", return_value=policy),
            patch(
                "fidb_poc.queue_cli._terminal_queue_has_pending_work",
                side_effect=(False, True),
            ) as pending,
            patch("fidb_poc.queue_cli.time.sleep") as sleep,
        ):
            _park_recycled_terminal_worker(self.project_root, self.database)

        self.assertEqual(pending.call_count, 2)
        sleep.assert_called_once_with(10)

    def test_terminal_maintenance_is_independent_of_claim_window(self) -> None:
        coordinator = type(
            "TerminalCoordinator",
            (),
            {
                "status": lambda _self: {
                    "counts": {"queued": 0, "leased": 0, "running": 0}
                }
            },
        )()
        notifications = type("Notifications", (), {})()
        with (
            patch(
                "fidb_poc.retention.current_retention_session",
                return_value="batch-drained-42",
            ),
            patch("fidb_poc.queue_cli._notify") as notify,
            patch("fidb_poc.queue_cli._post_drain_maintenance") as maintain,
            patch.dict(os.environ, {}, clear=True),
        ):
            handled = _maybe_post_drain_maintenance(
                coordinator,
                self.project_root,
                self.database,
                "worker-1",
                notifications,
                already_notified=False,
            )

        self.assertTrue(handled)
        notify.assert_called_once()
        maintain.assert_called_once_with(
            self.project_root, self.database, "batch-drained-42", "worker-1"
        )

    def test_terminal_maintenance_skips_status_after_notification(self) -> None:
        coordinator = type("UnexpectedCoordinator", (), {})()

        handled = _maybe_post_drain_maintenance(
            coordinator,
            self.project_root,
            self.database,
            "worker-1",
            type("Notifications", (), {})(),
            already_notified=True,
        )

        self.assertTrue(handled)

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
        arguments = self._arguments("preflight", self._queue(armed=False))
        with contextlib.redirect_stdout(output):
            status = main(arguments)

        document = json.loads(output.getvalue())
        self.assertEqual(status, 1)
        self.assertEqual(document["schema_version"], "fidb-operations-preflight/v1")
        self.assertFalse(document["queue_armed"])
        self.assertIn("claims_allowed", document["schedule"])
        self.assertIn("available_memory_gib", document["resources"]["metrics"])
        self.assertFalse(self.database.exists())

    def test_resolution_preflight_checks_exact_active_jobs_without_execution(self):
        queue = self._queue(armed=False)
        with Coordinator(self.database, self.project_root) as coordinator:
            coordinator.sync_queue(queue, now=10)
        output = io.StringIO()
        resolved = {
            "cell_id": "resolved-cell",
            "kind": "malware",
            "executor": "qemu",
            "route_id": None,
            "treatment_id": None,
            "toolchain_identity": None,
            "factor_variants_catalog_sha256": "a" * 64,
            "factor_variant_count": 0,
            "pins_sha256": "b" * 64,
        }
        with (
            patch(
                "fidb_poc.queue_cli.preflight_cell_authority",
                return_value=resolved,
            ) as preflight,
            patch("fidb_poc.queue_cli.run_cell") as run_cell,
            contextlib.redirect_stdout(output),
        ):
            status = main(self._arguments("resolve-preflight"))

        document = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(
            document["schema_version"],
            "fidb-execution-resolution-preflight/v1",
        )
        self.assertEqual(document["summary"]["active_jobs"], 1)
        self.assertEqual(document["summary"]["passed"], 1)
        self.assertTrue(document["summary"]["ready"])
        preflight.assert_called_once()
        run_cell.assert_not_called()

    def test_doctor_reports_guarded_recovery_without_mutating_ledger(self) -> None:
        queue = self._queue(armed=True)
        with Coordinator(self.database, self.project_root) as coordinator:
            coordinator.sync(queue, now=10)
            lease = coordinator.claim("test-worker", now=20)
            coordinator.fail(
                lease["job_id"],
                lease["lease_token"],
                lease["lease_generation"],
                "java.lang.OutOfMemoryError: unable to create native thread",
                retryable=False,
                failure_class="ghidra-analysis:RuntimeError",
                now=21,
            )
            queue = self._queue(armed=False)
            coordinator.sync(queue, now=22)
            coordinator.pause("reviewing evidence", now=23)
            before_event = coordinator.status()["last_event_id"]

        output = io.StringIO()
        arguments = self._arguments("doctor")
        arguments.extend(("--batch", "batch-mirai"))
        with contextlib.redirect_stdout(output):
            status = main(arguments)

        self.assertEqual(status, 0)
        document = json.loads(output.getvalue())
        self.assertEqual(document["schema_version"], "fidb-queue-incident-report/v1")
        self.assertTrue(document["read_only"])
        self.assertEqual(document["failures"]["current"], 1)
        self.assertEqual(document["queue"]["global_live_work"], 0)
        self.assertEqual(
            document["worker_unit"]["repository_limits"]["TasksMax"], "2048"
        )
        rule_ids = {row["id"] for row in document["matched_diagnostic_rules"]}
        self.assertIn("native-thread-task-ceiling", rule_ids)
        candidate = document["recovery"]["candidates"][0]
        self.assertTrue(candidate["ready"])
        self.assertEqual(candidate["failed_jobs"], 1)
        self.assertIn("--expected-count 1", candidate["command"])
        self.assertEqual(len(candidate["job_ids_sha256"]), 64)

        with Coordinator(self.database, self.project_root) as coordinator:
            after = coordinator.status()
        self.assertEqual(after["last_event_id"], before_event)
        self.assertEqual(after["counts"]["failed"], 1)

    def test_doctor_refuses_to_describe_live_armed_queue_as_recoverable(self) -> None:
        queue = self._queue(armed=True)
        with Coordinator(self.database, self.project_root) as coordinator:
            coordinator.sync(queue, now=10)
            coordinator.claim("test-worker", now=20)

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = main(self._arguments("doctor"))

        self.assertEqual(status, 0)
        document = json.loads(output.getvalue())
        self.assertTrue(document["queue"]["armed"])
        self.assertEqual(document["queue"]["global_live_work"], 1)
        self.assertIn(
            "the durable queue is armed",
            document["recovery"]["global_blockers"],
        )
        self.assertIn(
            "the durable queue is not paused",
            document["recovery"]["global_blockers"],
        )

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

    def test_worker_classifies_authority_resolution_failures_for_breaker(self) -> None:
        queue = self._queue(armed=True)

        def reject_authority(_cell, _variants, _root, _attempt, **kwargs):
            kwargs["progress"](
                ProgressEvent(
                    stage=CellStage.AUTHORITY_RESOLUTION,
                    status=ProgressStatus.STARTED,
                    message="resolving queued identity",
                    duration_ns=None,
                    metrics={},
                    started_at="2026-09-03T12:00:00Z",
                    finished_at=None,
                )
            )
            kwargs["progress"](
                ProgressEvent(
                    stage=CellStage.AUTHORITY_RESOLUTION,
                    status=ProgressStatus.FAILED,
                    message="queued identity differs from reviewed authority",
                    duration_ns=1,
                    metrics={},
                    started_at="2026-09-03T12:00:00Z",
                    finished_at="2026-09-03T12:00:00.000001Z",
                )
            )
            raise CellResolutionError("queued identity differs from authority")

        arguments = self._arguments("run", queue)
        arguments.extend(("--worker-id", "test-worker", "--once"))
        with patch("fidb_poc.queue_cli.run_cell", side_effect=reject_authority):
            status = main(arguments)

        self.assertEqual(status, 1)
        with Coordinator(self.database, self.project_root) as coordinator:
            failed = coordinator.snapshot()["jobs"][0]
        self.assertEqual(failed["state"], "failed")
        self.assertEqual(
            failed["failure_class"],
            "authority-resolution:CellResolutionError",
        )

    def test_requeue_failed_command_requires_exact_reviewed_count(self) -> None:
        queue = self._queue(armed=True)
        with Coordinator(self.database, self.project_root) as coordinator:
            coordinator.sync(queue, now=10)
            lease = coordinator.claim("test-worker", now=20)
            coordinator.fail(
                lease["job_id"],
                lease["lease_token"],
                lease["lease_generation"],
                "terminal canary failure",
                retryable=False,
                now=21,
            )
            queue = self._queue(armed=False)
            coordinator.sync(queue, now=22)
            coordinator.pause("reviewing evidence", now=23)

        output = io.StringIO()
        arguments = self._arguments("requeue-failed")
        arguments.extend(
            (
                "--batch",
                "batch-mirai",
                "--expected-count",
                "1",
                "--reason",
                "canary repair verified",
            )
        )
        with contextlib.redirect_stdout(output):
            status = main(arguments)

        self.assertEqual(status, 0)
        document = json.loads(output.getvalue())
        self.assertEqual(document["requeued"], 1)
        self.assertEqual(document["queue"]["counts"]["failed"], 0)
        self.assertEqual(document["queue"]["counts"]["queued"], 1)

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
