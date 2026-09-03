import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from fidb_poc.coordinator import (
    Coordinator,
    CoordinatorError,
    LeaseConflictError,
    QueueConfig,
    load_queue_config,
    worker_pool_accepts_cell,
)


class CoordinatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project_root = Path(__file__).resolve().parents[1]

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.database = self.directory / "coordinator.sqlite3"

    def tearDown(self):
        self.temporary.cleanup()

    def write_queue(
        self,
        *,
        filename: str = "priority.toml",
        batches: tuple[tuple[str, str, str], ...] = (
            ("batch-baseline", "coverage baseline", "plans/coverage-baseline.toml"),
        ),
        order: tuple[str, ...] | None = None,
        armed: bool = True,
        max_workers: int = 4,
        lease_seconds: int = 10,
        max_attempts: int = 2,
        batch_extra: str = "",
        queue_extra: str = "",
    ) -> Path:
        path = self.directory / filename
        effective_order = order or tuple(row[0] for row in batches)
        order_toml = ", ".join(f'"{batch_id}"' for batch_id in effective_order)
        tables = []
        for batch_id, name, plan in batches:
            tables.append(
                "\n".join(
                    (
                        "[[batch]]",
                        f'id = "{batch_id}"',
                        f'name = "{name}"',
                        f'plan = "{plan}"',
                        batch_extra,
                    )
                )
            )
        path.write_text(
            "\n".join(
                (
                    'schema_version = "fidb-queue/v1"',
                    'name = "test-priority"',
                    "",
                    "[queue]",
                    f"armed = {str(armed).lower()}",
                    f"max_workers = {max_workers}",
                    f"batch_order = [{order_toml}]",
                    "poll_seconds = 1",
                    f"lease_seconds = {lease_seconds}",
                    f"max_attempts = {max_attempts}",
                    queue_extra,
                    "",
                    *tables,
                )
            ),
            encoding="utf-8",
        )
        return path

    def config(self, path: Path | None = None) -> QueueConfig:
        return load_queue_config(
            path or self.write_queue(),
            self.project_root,
        )

    def write_mixed_pool_queue(self) -> Path:
        path = self.directory / "mixed-pools.toml"
        path.write_text(
            """schema_version = "fidb-queue/v1"
name = "mixed-pool-routing"

[queue]
armed = true
max_workers = 4
batch_order = ["batch-qemu", "batch-malware", "batch-local", "batch-local-source"]
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

[[batch]]
id = "batch-local-source"
name = "local source library"
plan = "plans/tier0-runtime-foundations.toml"
matrices = ["tier0-uclibc-powerpc"]
""",
            encoding="utf-8",
        )
        return path

    def test_sync_persists_immutable_plans_jobs_events_and_batch_order(self):
        queue_path = self.write_queue(
            batches=(
                (
                    "batch-mirai",
                    "mirai baseline",
                    "plans/mirai-baseline.toml",
                ),
                (
                    "batch-runtime",
                    "runtime foundations",
                    "plans/tier0-runtime-foundations.toml",
                ),
            ),
            order=("batch-runtime", "batch-mirai"),
        )
        with Coordinator(self.database) as coordinator:
            snapshot = coordinator.sync(self.config(queue_path), now=10)
            self.assertEqual(
                [batch["id"] for batch in snapshot["batches"]],
                ["batch-runtime", "batch-mirai"],
            )
            self.assertEqual(len(snapshot["jobs"]), 3)
            self.assertEqual(snapshot["counts"]["queued"], 3)
            self.assertEqual(
                coordinator.connection.execute("SELECT COUNT(*) FROM plans").fetchone()[
                    0
                ],
                2,
            )
            self.assertEqual(
                coordinator.connection.execute(
                    "SELECT COUNT(*) FROM resolved_cells"
                ).fetchone()[0],
                3,
            )
            first_job_id = snapshot["jobs"][0]["job_id"]
            plan_json = coordinator.connection.execute(
                "SELECT plan_json FROM plans ORDER BY plan_digest LIMIT 1"
            ).fetchone()[0]
            self.assertNotIn('"inventory"', plan_json)

        with Coordinator(self.database) as reopened:
            snapshot = reopened.snapshot()
            self.assertEqual(snapshot["jobs"][0]["job_id"], first_job_id)
            self.assertGreater(snapshot["last_event_id"], 0)
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                reopened.connection.execute(
                    "UPDATE events SET actor = 'changed' WHERE event_id = 1"
                )

    def test_queue_rejects_materialized_plan_file_drift(self):
        path = self.write_queue(batch_extra='plan_sha256 = "' + "0" * 64 + '"')

        with self.assertRaisesRegex(ValueError, "plan_sha256 mismatch"):
            self.config(path)

    def test_sync_rejects_materialized_queue_identity_drift(self):
        plan = self.project_root / "plans/coverage-baseline.toml"
        digest = hashlib.sha256(plan.read_bytes()).hexdigest()
        path = self.write_queue(
            batch_extra="\n".join(
                (
                    f'plan_sha256 = "{digest}"',
                    'queue_digest = "' + "0" * 64 + '"',
                    "executions = 6",
                )
            )
        )

        with Coordinator(self.database) as coordinator:
            with self.assertRaisesRegex(ValueError, "queue_digest mismatch"):
                coordinator.sync(self.config(path), now=10)

    def test_claim_follows_batch_then_job_order_and_skips_blocked_rows(self):
        with Coordinator(self.database) as coordinator:
            coordinator.sync(self.config(), now=10)
            leases = [
                coordinator.claim(f"worker-{index}", now=20) for index in range(4)
            ]
            self.assertEqual(
                [lease["job_position"] for lease in leases],
                [1, 2, 3, 5],
            )
            self.assertTrue(all(lease is not None for lease in leases))
            self.assertIsNone(coordinator.claim("worker-extra", now=20))
            snapshot = coordinator.snapshot()
            blocked = [job for job in snapshot["jobs"] if job["state"] == "blocked"]
            self.assertEqual([job["position"] for job in blocked], [4, 6])
            self.assertTrue(all(job["attempt_count"] == 0 for job in blocked))

    def test_durable_block_admission_drains_one_batch_per_schedule_window(self):
        path = self.write_queue(
            batches=(
                ("batch-mirai", "mirai", "plans/mirai-baseline.toml"),
                ("batch-bzip2", "bzip2", "plans/bzip2-native.toml"),
            )
        )
        with Coordinator(self.database) as coordinator:
            coordinator.sync(self.config(path), now=10)
            block = coordinator.start_next_block(
                "2026-09-04T01:00:00+02:00", scheduled=True, now=20
            )
            self.assertEqual(block["batch_id"], "batch-mirai")
            self.assertEqual(
                coordinator.start_next_block(
                    "2026-09-04T01:00:00+02:00", scheduled=True, now=21
                )["batch_id"],
                "batch-mirai",
            )

            lease = coordinator.claim("worker", batch_id=block["batch_id"], now=22)
            self.assertEqual(lease["batch_id"], "batch-mirai")
            coordinator.complete(
                lease["job_id"],
                lease["lease_token"],
                lease["lease_generation"],
                now=23,
            )
            self.assertTrue(coordinator.finish_active_block_if_drained(now=24))
            self.assertFalse(coordinator.execution_block()["active"])
            self.assertIsNone(
                coordinator.start_next_block(
                    "2026-09-04T01:00:00+02:00", scheduled=True, now=25
                )
            )

            manual = coordinator.start_next_block(
                "manual-2026-09-04T12:00:00+02:00", scheduled=False, now=26
            )
            self.assertEqual(manual["batch_id"], "batch-bzip2")
            events = coordinator.events()
            self.assertEqual(
                [
                    event["event_type"]
                    for event in events
                    if event["event_type"].startswith("batch.")
                ],
                ["batch.admitted", "batch.drained", "batch.admitted"],
            )

    def test_max_workers_caps_concurrent_leases(self):
        path = self.write_queue(max_workers=2)
        with Coordinator(self.database) as coordinator:
            coordinator.sync(self.config(path), now=10)
            first = coordinator.claim("worker-one", now=20)
            second = coordinator.claim("worker-two", now=20)

            self.assertIsNotNone(first)
            self.assertIsNotNone(second)
            self.assertIsNone(coordinator.claim("worker-three", now=20))
            status = coordinator.status()
            self.assertEqual(status["max_workers"], 2)
            self.assertEqual(status["active_workers"], 2)
            self.assertEqual(status["available_worker_slots"], 0)

            coordinator.complete(
                first["job_id"],
                first["lease_token"],
                first["lease_generation"],
                now=21,
            )
            self.assertIsNotNone(coordinator.claim("worker-three", now=22))

    def test_two_connections_cannot_lease_the_same_job(self):
        path = self.write_queue(
            batches=(("batch-mirai", "mirai baseline", "plans/mirai-baseline.toml"),)
        )
        first = Coordinator(self.database)
        second = Coordinator(self.database)
        self.addCleanup(first.close)
        self.addCleanup(second.close)
        first.sync(self.config(path), now=10)

        lease = first.claim("worker-one", now=20)

        self.assertIsNotNone(lease)
        self.assertIsNone(second.claim("worker-two", now=20))
        self.assertEqual(second.get_job(lease["job_id"])["leased_by"], "worker-one")

    def test_library_local_pool_skips_earlier_qemu_and_malware_jobs_atomically(self):
        path = self.write_mixed_pool_queue()
        config = self.config(path)
        with Coordinator(self.database) as coordinator:
            coordinator.sync(config, now=10)

            lease = coordinator.claim("library-worker", pool="library-local", now=20)

            self.assertIsNotNone(lease)
            self.assertEqual(lease["batch_id"], "batch-local")
            self.assertEqual(lease["cell"]["kind"], "native")
            self.assertEqual(lease["cell"]["routing"]["executor"], "native-local")
            snapshot = coordinator.snapshot()
            earlier = [
                job
                for job in snapshot["jobs"]
                if job["batch_id"] in {"batch-qemu", "batch-malware"}
                and job["state"] != "blocked"
            ]
            self.assertEqual(
                [
                    (job["batch_id"], job["state"], job["attempt_count"])
                    for job in earlier
                ],
                [
                    ("batch-qemu", "queued", 0),
                    ("batch-malware", "queued", 0),
                ],
            )
            claimed_event = [
                event
                for event in snapshot["events"]
                if event["event_type"] == "job.claimed"
            ][-1]
            self.assertEqual(claimed_event["payload"]["worker_pool"], "library-local")

            coordinator.claim("library-worker-2", pool="library-local", now=20)
            source_lease = coordinator.claim(
                "library-worker-3", pool="library-local", now=20
            )
            self.assertEqual(source_lease["batch_id"], "batch-local-source")
            self.assertEqual(source_lease["cell"]["kind"], "source-library")
            self.assertEqual(source_lease["cell"]["routing"]["executor"], "local")

        default_database = self.directory / "default-claim.sqlite3"
        with Coordinator(default_database) as coordinator:
            coordinator.sync(config, now=10)
            lease = coordinator.claim("general-worker", now=20)
            self.assertEqual(lease["batch_id"], "batch-qemu")
            self.assertEqual(lease["cell"]["routing"]["executor"], "qemu")

    def test_library_local_pool_accepts_typed_archive_extraction(self):
        self.assertTrue(
            worker_pool_accepts_cell(
                "library-local",
                {
                    "kind": "archive-library",
                    "routing": {"executor": "archive-local"},
                },
            )
        )

    def test_native_pools_are_separated_by_reviewed_routing(self):
        linux = {
            "kind": "native",
            "routing": {
                "executor": "native-local",
                "worker_pool": "library-local",
            },
        }
        macos = {
            "kind": "native",
            "routing": {
                "executor": "native-local",
                "worker_pool": "macos-native",
            },
        }
        self.assertTrue(worker_pool_accepts_cell("library-local", linux))
        self.assertFalse(worker_pool_accepts_cell("library-local", macos))
        self.assertTrue(worker_pool_accepts_cell("macos-native", macos))
        self.assertFalse(worker_pool_accepts_cell("macos-native", linux))
        self.assertFalse(
            worker_pool_accepts_cell(
                "library-local",
                {"kind": "archive-library", "routing": {"executor": "local"}},
            )
        )

    def test_unknown_worker_pool_fails_without_mutating_jobs(self):
        path = self.write_mixed_pool_queue()
        with Coordinator(self.database) as coordinator:
            coordinator.sync(self.config(path), now=10)
            before = coordinator.snapshot()

            with self.assertRaisesRegex(ValueError, "unsupported worker pool"):
                coordinator.claim("worker", pool="anything", now=20)

            after = coordinator.snapshot()
        self.assertEqual(before["counts"], after["counts"])
        self.assertEqual(before["attempts"], after["attempts"])

    def test_worker_registration_and_heartbeat_are_persistent_and_credential_free(self):
        with Coordinator(self.database) as coordinator:
            registered = coordinator.touch_worker(
                "remote-linux-1",
                transport="remote-http",
                pools=("library-local",),
                metadata={"last_operation": "claim"},
                now=10,
            )
            heartbeat = coordinator.touch_worker(
                "remote-linux-1",
                transport="remote-http",
                pools=("library-local",),
                metadata={"last_operation": "renew"},
                now=20,
            )

        with Coordinator(self.database) as reopened:
            snapshot = reopened.snapshot()

        self.assertEqual(registered["registered_at"], "1970-01-01T00:00:10+00:00")
        self.assertEqual(heartbeat["last_seen_at"], "1970-01-01T00:00:20+00:00")
        self.assertEqual(heartbeat["metadata"]["last_operation"], "renew")
        self.assertEqual(len(snapshot["workers"]), 1)
        self.assertNotIn("token", json.dumps(snapshot["workers"]))
        self.assertEqual(
            len(
                [
                    event
                    for event in snapshot["events"]
                    if event["event_type"] == "worker.registered"
                ]
            ),
            1,
        )

    def test_expired_lease_requeues_then_stops_at_retry_cap(self):
        path = self.write_queue(
            batches=(("batch-mirai", "mirai baseline", "plans/mirai-baseline.toml"),),
            lease_seconds=10,
            max_attempts=2,
        )
        with Coordinator(self.database) as coordinator:
            coordinator.sync(self.config(path), now=10)
            first = coordinator.claim("worker-one", now=100)
            self.assertEqual(coordinator.recover_expired(now=111), 1)
            self.assertEqual(coordinator.get_job(first["job_id"])["state"], "queued")

            second = coordinator.claim("worker-two", now=111)
            self.assertEqual(second["job_id"], first["job_id"])
            self.assertEqual(second["lease_generation"], 2)
            self.assertNotEqual(second["lease_token"], first["lease_token"])
            self.assertEqual(coordinator.recover_expired(now=122), 1)
            self.assertEqual(coordinator.get_job(first["job_id"])["state"], "failed")
            self.assertIsNone(coordinator.claim("worker-three", now=123))
            attempts = coordinator.snapshot()["attempts"]
            self.assertEqual([row["state"] for row in attempts], ["expired", "expired"])

    def test_retry_backoff_is_durable_exponential_and_capped(self):
        path = self.write_queue(
            batches=(("batch-mirai", "mirai baseline", "plans/mirai-baseline.toml"),),
            lease_seconds=10,
            max_attempts=4,
            queue_extra="retry_backoff_seconds = 30\nretry_backoff_max_seconds = 60",
        )
        with Coordinator(self.database) as coordinator:
            coordinator.sync(self.config(path), now=10)
            first = coordinator.claim("worker-one", now=20)
            coordinator.fail(
                first["job_id"],
                first["lease_token"],
                first["lease_generation"],
                "transient one",
                now=21,
            )
            waiting = coordinator.get_job(first["job_id"])
            self.assertEqual(waiting["eligible_at"], 51)
            self.assertIsNone(coordinator.claim("worker-two", now=50.999))

        with Coordinator(self.database) as reopened:
            second = reopened.claim("worker-two", now=51)
            self.assertEqual(second["job_id"], first["job_id"])
            reopened.fail(
                second["job_id"],
                second["lease_token"],
                second["lease_generation"],
                "transient two",
                now=52,
            )
            self.assertEqual(reopened.get_job(first["job_id"])["eligible_at"], 112)
            self.assertIsNone(reopened.claim("worker-three", now=111.999))
            third = reopened.claim("worker-three", now=112)
            reopened.fail(
                third["job_id"],
                third["lease_token"],
                third["lease_generation"],
                "transient three",
                now=113,
            )
            self.assertEqual(reopened.get_job(first["job_id"])["eligible_at"], 173)
            event = reopened.events()[-1]
            self.assertEqual(event["payload"]["retry_delay_seconds"], 60)
            self.assertEqual(event["payload"]["eligible_at"], 173)

    def test_retry_backoff_configuration_fails_closed(self):
        valid_batch = (("batch-mirai", "mirai baseline", "plans/mirai-baseline.toml"),)
        cases = (
            ("negative", "retry_backoff_seconds = -1", "non-negative integer"),
            (
                "max below base",
                "retry_backoff_seconds = 30\nretry_backoff_max_seconds = 10",
                "must be at least",
            ),
        )
        for label, extra, message in cases:
            with self.subTest(label=label):
                path = self.write_queue(
                    filename=f"retry-{label}.toml",
                    batches=valid_batch,
                    queue_extra=extra,
                )
                with self.assertRaisesRegex(ValueError, message):
                    QueueConfig.load(path, self.project_root)

    def test_stale_worker_is_fenced_after_requeue(self):
        path = self.write_queue(
            batches=(("batch-mirai", "mirai baseline", "plans/mirai-baseline.toml"),),
            lease_seconds=10,
            max_attempts=3,
        )
        with Coordinator(self.database) as coordinator:
            coordinator.sync(self.config(path), now=10)
            stale = coordinator.claim("stale-worker", now=100)
            current = coordinator.claim("current-worker", now=111)

            with self.assertRaises(LeaseConflictError):
                coordinator.complete(
                    stale["job_id"],
                    stale["lease_token"],
                    stale["lease_generation"],
                    now=112,
                )
            coordinator.record_stage(
                current["job_id"],
                current["lease_token"],
                current["lease_generation"],
                "ghidra-ingest",
                details={"files": 1},
                now=112,
            )
            renewed = coordinator.renew(
                current["job_id"],
                current["lease_token"],
                current["lease_generation"],
                now=113,
            )
            coordinator.record_stage(
                current["job_id"],
                renewed["lease_token"],
                renewed["lease_generation"],
                "ghidra-ingest",
                status="completed",
                duration_ns=1_000_000_000,
                now=113.5,
            )
            completed = coordinator.complete(
                current["job_id"],
                renewed["lease_token"],
                renewed["lease_generation"],
                result={"fidb": "sealed"},
                now=114,
            )
            self.assertEqual(completed["state"], "complete")
            self.assertEqual(completed["result"], {"fidb": "sealed"})
            self.assertIn(
                "stage.started",
                [event["event_type"] for event in coordinator.events()],
            )

    def test_stage_attempt_schema_migrates_existing_ledger_and_adds_indexes(self):
        with Coordinator(self.database) as coordinator:
            coordinator.connection.execute("DROP TABLE stage_attempts")

        with Coordinator(self.database) as migrated:
            columns = {
                row["name"]
                for row in migrated.connection.execute(
                    "PRAGMA table_info(stage_attempts)"
                ).fetchall()
            }
            indexes = {
                row["name"]: bool(row["unique"])
                for row in migrated.connection.execute(
                    "PRAGMA index_list(stage_attempts)"
                ).fetchall()
            }
            state_columns = {
                row["name"]
                for row in migrated.connection.execute(
                    "PRAGMA table_info(coordinator_state)"
                ).fetchall()
            }
            job_columns = {
                row["name"]
                for row in migrated.connection.execute(
                    "PRAGMA table_info(jobs)"
                ).fetchall()
            }
            job_indexes = {
                row["name"]
                for row in migrated.connection.execute(
                    "PRAGMA index_list(jobs)"
                ).fetchall()
            }

        self.assertTrue(
            {
                "attempt_id",
                "job_id",
                "lease_generation",
                "sequence",
                "stage_attempt",
                "duration_ns",
                "duration_source",
                "wall_clock_regressed",
                "details_json",
                "metrics_json",
            }.issubset(columns)
        )
        self.assertIn("stage_attempts_attempt_history", indexes)
        self.assertIn("stage_attempts_one_open_per_attempt", indexes)
        self.assertTrue(indexes["stage_attempts_one_open_per_attempt"])
        self.assertIn("stage_attempts_stage_history", indexes)
        self.assertTrue(
            {
                "retry_backoff_seconds",
                "retry_backoff_max_seconds",
                "operations_json",
            }.issubset(state_columns)
        )
        self.assertIn("eligible_at", job_columns)
        self.assertIn("jobs_claim_eligibility", job_indexes)

    def test_retry_eligibility_migrates_a_pre_backoff_job_table(self):
        with Coordinator(self.database):
            pass
        connection = sqlite3.connect(self.database)
        try:
            connection.execute("DROP INDEX jobs_claim_eligibility")
            connection.execute("ALTER TABLE jobs DROP COLUMN eligible_at")
            connection.commit()
        finally:
            connection.close()

        with Coordinator(self.database) as migrated:
            columns = {
                row["name"]
                for row in migrated.connection.execute(
                    "PRAGMA table_info(jobs)"
                ).fetchall()
            }
            indexes = {
                row["name"]
                for row in migrated.connection.execute(
                    "PRAGMA index_list(jobs)"
                ).fetchall()
            }

        self.assertIn("eligible_at", columns)
        self.assertIn("jobs_claim_eligibility", indexes)

    def test_stage_spans_persist_monotonic_duration_details_and_metrics(self):
        path = self.write_queue(
            batches=(("batch-mirai", "mirai", "plans/mirai-baseline.toml"),),
            lease_seconds=30,
        )
        with Coordinator(self.database) as coordinator:
            coordinator.sync(self.config(path), now=10)
            lease = coordinator.claim("worker-one", now=20)
            started_event = coordinator.record_stage(
                lease["job_id"],
                lease["lease_token"],
                lease["lease_generation"],
                "compile",
                details={
                    "message": "compiling",
                    "started_at": "1970-01-01T00:00:21Z",
                    "finished_at": None,
                },
                now=21,
            )
            completed_event = coordinator.record_stage(
                lease["job_id"],
                lease["lease_token"],
                lease["lease_generation"],
                "compile",
                status="completed",
                duration_ns=2_500_000_123,
                details={
                    "message": "compiled",
                    "metrics": {"object_count": 42, "cache_hit": False},
                    "started_at": "1970-01-01T00:00:21Z",
                    "finished_at": "1970-01-01T00:00:24Z",
                },
                now=24,
            )
            coordinator.record_stage(
                lease["job_id"],
                lease["lease_token"],
                lease["lease_generation"],
                "clock-check",
                details={"started_at": "1970-01-01T00:00:30Z"},
                now=25,
            )
            coordinator.record_stage(
                lease["job_id"],
                lease["lease_token"],
                lease["lease_generation"],
                "clock-check",
                status="completed",
                duration_ns=77,
                details={
                    "started_at": "1970-01-01T00:00:30Z",
                    "finished_at": "1970-01-01T00:00:29Z",
                },
                now=26,
            )

            snapshot = coordinator.snapshot()
            span = snapshot["stage_attempts"][0]
            regressed = snapshot["stage_attempts"][1]
            attempt = snapshot["attempts"][0]

        self.assertLess(started_event, completed_event)
        self.assertEqual(span["state"], "completed")
        self.assertEqual(span["stage_attempt"], 1)
        self.assertEqual(span["started_at"], "1970-01-01T00:00:21+00:00")
        self.assertEqual(span["ended_at"], "1970-01-01T00:00:24+00:00")
        self.assertEqual(span["duration_ns"], 2_500_000_123)
        self.assertEqual(span["duration_source"], "worker-monotonic")
        self.assertFalse(span["wall_clock_regressed"])
        self.assertEqual(span["metrics"]["object_count"], 42)
        self.assertEqual(regressed["duration_ns"], 77)
        self.assertTrue(regressed["wall_clock_regressed"])
        self.assertEqual(attempt["queue_wait_duration_ns"], 10_000_000_000)
        self.assertEqual(
            attempt["queue_wait_basis"],
            "wall-clock-includes-disarmed-paused-readiness",
        )

    def test_stage_retry_is_ordered_and_invalid_transitions_are_atomic(self):
        path = self.write_queue(
            batches=(("batch-mirai", "mirai", "plans/mirai-baseline.toml"),),
            lease_seconds=60,
        )
        with Coordinator(self.database) as coordinator:
            coordinator.sync(self.config(path), now=10)
            lease = coordinator.claim("worker-one", now=20)
            arguments = (
                lease["job_id"],
                lease["lease_token"],
                lease["lease_generation"],
            )

            with self.assertRaisesRegex(CoordinatorError, "running stage"):
                coordinator.record_stage(
                    *arguments,
                    "compile",
                    status="completed",
                    duration_ns=1,
                    now=21,
                )
            coordinator.record_stage(*arguments, "compile", now=21)
            with self.assertRaisesRegex(CoordinatorError, "already running"):
                coordinator.record_stage(*arguments, "ghidra", now=22)
            with self.assertRaisesRegex(ValueError, "duration_ns"):
                coordinator.record_stage(
                    *arguments,
                    "compile",
                    status="failed",
                    now=22,
                )
            coordinator.record_stage(
                *arguments,
                "compile",
                status="failed",
                duration_ns=10,
                details={"message": "compiler exited"},
                now=22,
            )
            coordinator.record_stage(*arguments, "compile", now=23)
            coordinator.record_stage(
                *arguments,
                "compile",
                status="completed",
                duration_ns=20,
                now=24,
            )
            with self.assertRaisesRegex(ValueError, "stage status"):
                coordinator.record_stage(
                    *arguments,
                    "compile",
                    status="progress",
                    duration_ns=1,
                    now=25,
                )
            with self.assertRaisesRegex(ValueError, "zero for a skipped stage"):
                coordinator.record_stage(
                    *arguments,
                    "patch",
                    status="skipped",
                    duration_ns=1,
                    now=25,
                )
            with self.assertRaisesRegex(ValueError, "identical start and finish"):
                coordinator.record_stage(
                    *arguments,
                    "patch",
                    status="skipped",
                    duration_ns=0,
                    details={
                        "started_at": "1970-01-01T00:00:25Z",
                        "finished_at": "1970-01-01T00:00:26Z",
                    },
                    now=25,
                )
            spans = coordinator.snapshot()["stage_attempts"]
            terminal_event = [
                event
                for event in coordinator.events()
                if event["event_type"] == "stage.completed"
            ][-1]

        self.assertEqual(
            [(row["sequence"], row["stage_attempt"], row["state"]) for row in spans],
            [(1, 1, "failed"), (2, 2, "completed")],
        )
        self.assertEqual(spans[0]["error"], "compiler exited")
        self.assertEqual(
            terminal_event["payload"]["started_at"], spans[1]["started_at"]
        )
        self.assertFalse(terminal_event["payload"]["wall_clock_regressed"])

    def test_attempt_failure_and_expiry_interrupt_open_spans_with_provenance(self):
        path = self.write_queue(
            batches=(("batch-mirai", "mirai", "plans/mirai-baseline.toml"),),
            lease_seconds=10,
            max_attempts=2,
        )
        with Coordinator(self.database) as coordinator:
            coordinator.sync(self.config(path), now=10)
            first = coordinator.claim("worker-one", now=100)
            coordinator.record_stage(
                first["job_id"],
                first["lease_token"],
                first["lease_generation"],
                "ghidra-analysis",
                now=101,
            )
            coordinator.recover_expired(now=115)

            second = coordinator.claim("worker-two", now=116)
            coordinator.record_stage(
                second["job_id"],
                second["lease_token"],
                second["lease_generation"],
                "compile",
                now=117,
            )
            coordinator.fail(
                second["job_id"],
                second["lease_token"],
                second["lease_generation"],
                "worker crashed",
                retryable=False,
                now=119,
            )
            snapshot = coordinator.snapshot()

        expired, failed = snapshot["stage_attempts"]
        self.assertEqual(expired["state"], "interrupted")
        self.assertEqual(expired["ended_at"], "1970-01-01T00:01:50+00:00")
        self.assertEqual(expired["duration_ns"], 9_000_000_000)
        self.assertEqual(expired["duration_source"], "coordinator-wall-clock")
        self.assertEqual(failed["state"], "interrupted")
        self.assertEqual(failed["error"], "worker crashed")
        self.assertEqual(
            [row["state"] for row in snapshot["attempts"]],
            ["expired", "failed"],
        )
        self.assertEqual(
            snapshot["attempts"][0]["ended_at"],
            "1970-01-01T00:01:50+00:00",
        )

    def test_timing_aggregates_exclude_failed_and_interrupted_stage_spans(self):
        path = self.write_queue(
            batches=(("batch-mirai", "mirai", "plans/mirai-baseline.toml"),),
            lease_seconds=60,
        )
        with Coordinator(self.database) as coordinator:
            coordinator.sync(self.config(path), now=10)
            lease = coordinator.claim("worker-one", now=20)
            arguments = (
                lease["job_id"],
                lease["lease_token"],
                lease["lease_generation"],
            )
            coordinator.record_stage(*arguments, "compile", now=21)
            coordinator.record_stage(
                *arguments,
                "compile",
                status="failed",
                duration_ns=999,
                details={"message": "retry"},
                now=22,
            )
            coordinator.record_stage(*arguments, "compile", now=23)
            coordinator.record_stage(
                *arguments,
                "compile",
                status="completed",
                duration_ns=100,
                now=24,
            )
            coordinator.record_stage(*arguments, "publish", now=25)
            coordinator.record_stage(
                *arguments,
                "publish",
                status="completed",
                duration_ns=10,
                now=26,
            )
            coordinator.complete(*arguments, now=27)
            timings = coordinator.timings(limit=2)

        compile_timing = next(
            row for row in timings["stages"] if row["stage"] == "compile"
        )
        self.assertEqual(compile_timing["sample_count"], 1)
        self.assertEqual(compile_timing["duration_ns"]["p50"], 100)
        self.assertEqual(compile_timing["state_counts"]["failed"], 1)
        self.assertEqual(timings["sample_counts"]["completed_workflows"], 1)
        self.assertIsNotNone(timings["throughput"])
        self.assertIsNone(timings["eta"])
        self.assertLessEqual(len(timings["recent"]), 2)

    def test_complete_rejects_open_stage_then_worker_failure_requeues(self):
        path = self.write_queue(
            batches=(("batch-mirai", "mirai", "plans/mirai-baseline.toml"),),
            lease_seconds=60,
            max_attempts=2,
        )
        with Coordinator(self.database) as coordinator:
            coordinator.sync(self.config(path), now=10)
            lease = coordinator.claim("worker-one", now=20)
            arguments = (
                lease["job_id"],
                lease["lease_token"],
                lease["lease_generation"],
            )
            coordinator.record_stage(*arguments, "publication", now=21)
            last_event_before_complete = coordinator.status()["last_event_id"]

            with self.assertRaisesRegex(CoordinatorError, "still running"):
                coordinator.complete(*arguments, result={"sealed": True}, now=22)

            unchanged = coordinator.snapshot()
            self.assertEqual(unchanged["jobs"][0]["state"], "running")
            self.assertEqual(unchanged["attempts"][0]["state"], "running")
            self.assertEqual(unchanged["stage_attempts"][0]["state"], "started")
            self.assertIsNone(unchanged["jobs"][0]["result"])
            self.assertEqual(unchanged["last_event_id"], last_event_before_complete)
            before_failure = coordinator.timings()
            self.assertEqual(before_failure["sample_counts"]["completed_workflows"], 0)
            self.assertIsNone(before_failure["throughput"])

            # This is the normal queue worker error path after complete()
            # fails: record an attempt failure, close the span and retry.
            coordinator.fail(
                *arguments,
                "CoordinatorError: publication stage remained open",
                retryable=True,
                now=23,
            )
            failed = coordinator.snapshot()
            after_failure = coordinator.timings()

        self.assertEqual(failed["jobs"][0]["state"], "queued")
        self.assertEqual(failed["attempts"][0]["state"], "failed")
        self.assertEqual(failed["stage_attempts"][0]["state"], "interrupted")
        self.assertEqual(after_failure["sample_counts"]["completed_workflows"], 0)
        self.assertIsNone(after_failure["throughput"])

    def test_pause_blocks_new_claims_until_resumed(self):
        path = self.write_queue(
            batches=(("batch-mirai", "mirai baseline", "plans/mirai-baseline.toml"),)
        )
        with Coordinator(self.database) as coordinator:
            coordinator.sync(self.config(path), now=10)
            paused = coordinator.pause("maintenance", now=20)
            self.assertEqual(paused["status"], "paused")
            self.assertIsNone(coordinator.claim("worker", now=21))
            resumed = coordinator.resume(now=22)
            self.assertEqual(resumed["status"], "ready")
            self.assertIsNotNone(coordinator.claim("worker", now=23))

    def test_optional_matrix_filter_materializes_only_selected_cells(self):
        path = self.write_queue(batch_extra='matrices = ["native-libraries"]')
        with Coordinator(self.database) as coordinator:
            snapshot = coordinator.sync(self.config(path), now=10)
            self.assertEqual(len(snapshot["jobs"]), 2)
            self.assertEqual(snapshot["counts"]["blocked"], 0)
            matrices = {
                row[0]
                for row in coordinator.connection.execute(
                    "SELECT matrix_id FROM resolved_cells"
                ).fetchall()
            }
            self.assertEqual(matrices, {"native-libraries"})

    def test_disarmed_configuration_is_persisted_and_not_claimable(self):
        path = self.write_queue(
            batches=(("batch-mirai", "mirai baseline", "plans/mirai-baseline.toml"),),
            armed=False,
        )
        with Coordinator(self.database) as coordinator:
            snapshot = coordinator.sync(self.config(path), now=10)
            self.assertEqual(snapshot["status"], "disarmed")
            self.assertEqual(snapshot["claimable"], 0)
            self.assertIsNone(coordinator.claim("worker", now=20))

    def test_queue_toml_validation_fails_closed(self):
        valid_batch = (("batch-mirai", "mirai baseline", "plans/mirai-baseline.toml"),)
        cases = (
            (
                "unknown queue field",
                self.write_queue(
                    filename="unknown-queue-field.toml",
                    batches=valid_batch,
                    queue_extra='command = "run whatever"',
                ),
                "unsupported fields",
            ),
            (
                "raw batch command",
                self.write_queue(
                    filename="raw-batch-command.toml",
                    batches=valid_batch,
                    batch_extra='command = "run whatever"',
                ),
                "unsupported fields",
            ),
            (
                "inexact order",
                self.write_queue(
                    filename="inexact-order.toml",
                    batches=valid_batch,
                    order=("invented",),
                ),
                "exactly once",
            ),
        )
        for label, path, message in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, message):
                    QueueConfig.load(path, self.project_root)

        escaped = self.directory / "escape.toml"
        escaped.write_text(
            """schema_version = "fidb-queue/v1"
name = "unsafe"
[queue]
armed = true
max_workers = 1
batch_order = ["escape"]
poll_seconds = 1
lease_seconds = 10
max_attempts = 1
[[batch]]
id = "escape"
name = "escape"
plan = "../outside.toml"
""",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "outside project root"):
            QueueConfig.load(escaped, self.project_root)


if __name__ == "__main__":
    unittest.main()
