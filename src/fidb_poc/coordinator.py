"""Durable, execution-free coordination for resolved FIDB build plans.

The coordinator is deliberately a state machine, not a job runner.  Queue TOML
selects reviewed plan requests, :func:`resolve_plan` freezes those requests, and
SQLite records queue, lease and stage transitions.  A separate worker may use a
claimed cell, but no command is accepted or executed by this module.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator, Mapping

from .coordinator_config import (
    QUEUE_SCHEMA,
    BatchConfig,
    QueueConfig,
    _identifier,
    _positive_integer,
    _text,
    load_queue_config,
)
from .plan_request import RESOLVED_SCHEMA, queue_identity_digest, resolve_plan

SNAPSHOT_SCHEMA = "fidb-coordinator-snapshot/v1"
JOB_SCHEMA = "fidb-job/v1"
TIMINGS_SCHEMA = "fidb-timings/v1"

_JOB_STATES = {
    "queued",
    "blocked",
    "leased",
    "running",
    "complete",
    "failed",
}
_LEASED_STATES = {"leased", "running"}
WORKER_POOLS = ("library-local", "macos-native")
STAGE_STATUSES = ("started", "completed", "failed", "skipped")
STAGE_TERMINAL_STATES = ("completed", "failed", "skipped", "interrupted")
DEFAULT_TIMING_LIMIT = 100
MAX_TIMING_LIMIT = 500
MAX_TIMING_SAMPLES = 10_000
MAX_DURATION_NS = 9_223_372_036_854_775_807


class CoordinatorError(RuntimeError):
    """Base class for coordinator state errors."""


class LeaseConflictError(CoordinatorError):
    """Raised when a worker presents an expired or stale lease fence."""


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ValueError("coordinator metadata must be JSON serializable") from error


def _stage_duration_ns(value: object, status: str) -> int | None:
    """Validate worker-reported monotonic stage duration semantics."""

    if status == "started":
        if value is not None:
            raise ValueError("duration_ns must be omitted for a started stage")
        return None
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > MAX_DURATION_NS
    ):
        raise ValueError(
            "duration_ns must be a non-negative signed 64-bit integer "
            "for a terminal stage"
        )
    if status == "skipped" and value != 0:
        raise ValueError("duration_ns must be zero for a skipped stage")
    return value


def _elapsed_ns(started_at: str, ended_at: str) -> int:
    """Return a non-negative wall-clock elapsed duration for coordinator closure."""

    started = datetime.fromisoformat(started_at)
    ended = datetime.fromisoformat(ended_at)
    delta = ended - started
    return min(
        MAX_DURATION_NS,
        max(
            0,
            delta.days * 86_400_000_000_000
            + delta.seconds * 1_000_000_000
            + delta.microseconds * 1_000,
        ),
    )


def _utc_timestamp(value: object, context: str) -> str:
    """Validate and normalize one worker wall-clock timestamp to UTC."""

    if not isinstance(value, str) or not value:
        raise ValueError(f"{context} must be a non-empty UTC timestamp")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as error:
        raise ValueError(f"{context} must be a valid UTC timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"{context} must use UTC")
    return parsed.astimezone(timezone.utc).isoformat()


def _percentiles(values: list[int]) -> dict[str, int | float] | None:
    """Summarise a bounded integer duration sample without external dependencies."""

    if not values:
        return None
    ordered = sorted(values)

    def percentile(percent: int) -> int:
        if len(ordered) == 1:
            return ordered[0]
        numerator = (len(ordered) - 1) * percent
        lower, remainder = divmod(numerator, 100)
        upper = min(lower + 1, len(ordered) - 1)
        return (
            ordered[lower] * (100 - remainder) + ordered[upper] * remainder + 50
        ) // 100

    return {
        "min": ordered[0],
        "p50": percentile(50),
        "p90": percentile(90),
        "p95": percentile(95),
        "max": ordered[-1],
        "mean": (sum(ordered) + len(ordered) // 2) // len(ordered),
    }


def _stable_job_id(
    batch_id: str,
    plan_digest: str,
    base_cell: str,
    factor_variants: list[object],
) -> str:
    identity = {
        "schema_version": JOB_SCHEMA,
        "batch_id": batch_id,
        "plan_digest": plan_digest,
        "base_cell": base_cell,
        "factor_variants": factor_variants,
    }
    digest = hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest()
    return f"job-{digest}"


def stable_job_id(
    batch_id: str,
    plan_digest: str,
    base_cell: str,
    factor_variants: list[object],
) -> str:
    """Return the content-derived execution identity used by the database."""

    return _stable_job_id(batch_id, plan_digest, base_cell, factor_variants)


def worker_pool_accepts_cell(pool: str, cell: object) -> bool:
    """Fail-closed routing predicate for a named worker pool."""

    if not isinstance(cell, dict):
        return False
    routing = cell.get("routing")
    if not isinstance(routing, dict):
        return False
    kind = cell.get("kind")
    executor = routing.get("executor")
    if pool == "library-local":
        return (
            (
                kind == "native"
                and executor == "native-local"
                and routing.get("worker_pool", "library-local") == "library-local"
            )
            or (kind == "source-library" and executor == "local")
            or (kind == "archive-library" and executor == "archive-local")
            or (kind == "runtime-library" and executor == "runtime-archive-local")
        )
    if pool == "macos-native":
        return (
            kind == "native"
            and executor == "native-local"
            and routing.get("worker_pool") == "macos-native"
        )
    return False


class Coordinator:
    """SQLite-backed coordinator which never executes a job itself."""

    def __init__(
        self,
        database_path: str | Path,
        project_root: str | Path | None = None,
        *,
        busy_timeout_ms: int = 5_000,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(busy_timeout_ms, int) or busy_timeout_ms < 1:
            raise ValueError("busy_timeout_ms must be a positive integer")
        self.database_path = database_path
        self.project_root = (
            Path(project_root).resolve() if project_root is not None else None
        )
        self._clock = clock
        if str(database_path) != ":memory:":
            Path(database_path).resolve().parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(
            str(database_path),
            timeout=busy_timeout_ms / 1_000,
            isolation_level=None,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._create_schema()

    @property
    def connection(self) -> sqlite3.Connection:
        """Expose the connection for read-only diagnostics and SQLite backups."""

        return self._connection

    def __enter__(self) -> "Coordinator":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._connection.close()

    def _create_schema(self) -> None:
        self._connection.executescript("""
            CREATE TABLE IF NOT EXISTS coordinator_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                config_name TEXT,
                config_path TEXT,
                armed INTEGER NOT NULL CHECK (armed IN (0, 1)),
                paused INTEGER NOT NULL CHECK (paused IN (0, 1)),
                max_workers INTEGER NOT NULL CHECK (max_workers > 0),
                performance_json TEXT,
                poll_seconds INTEGER NOT NULL CHECK (poll_seconds > 0),
                lease_seconds INTEGER NOT NULL CHECK (lease_seconds > 0),
                max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
                retry_backoff_seconds INTEGER NOT NULL DEFAULT 0
                    CHECK (retry_backoff_seconds >= 0),
                retry_backoff_max_seconds INTEGER NOT NULL DEFAULT 0
                    CHECK (retry_backoff_max_seconds >= retry_backoff_seconds),
                authority_failure_threshold INTEGER NOT NULL DEFAULT 0
                    CHECK (authority_failure_threshold >= 0),
                operations_json TEXT NOT NULL DEFAULT '{}',
                active_batch_id TEXT,
                active_admission_id TEXT,
                lookahead_batch_id TEXT,
                lookahead_admission_id TEXT,
                last_schedule_admission_id TEXT,
                sync_generation INTEGER NOT NULL CHECK (sync_generation >= 0),
                synced_at TEXT
            );

            CREATE TABLE IF NOT EXISTS plans (
                plan_digest TEXT PRIMARY KEY,
                schema_version TEXT NOT NULL,
                name TEXT NOT NULL,
                plan_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS batches (
                batch_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                plan_digest TEXT NOT NULL REFERENCES plans(plan_digest),
                plan_path TEXT NOT NULL,
                matrices_json TEXT,
                position INTEGER NOT NULL CHECK (position > 0),
                active INTEGER NOT NULL CHECK (active IN (0, 1)),
                sync_generation INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS resolved_cells (
                plan_digest TEXT NOT NULL REFERENCES plans(plan_digest),
                cell_id TEXT NOT NULL,
                matrix_id TEXT NOT NULL,
                cell_state TEXT NOT NULL CHECK (cell_state IN ('planned', 'blocked')),
                cell_json TEXT NOT NULL,
                PRIMARY KEY (plan_digest, cell_id)
            );

            CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY,
                batch_id TEXT NOT NULL REFERENCES batches(batch_id),
                plan_digest TEXT NOT NULL,
                base_cell_id TEXT NOT NULL,
                position INTEGER NOT NULL CHECK (position > 0),
                state TEXT NOT NULL CHECK (
                    state IN ('queued', 'blocked', 'leased', 'running',
                              'complete', 'failed')
                ),
                blockers_json TEXT NOT NULL,
                factor_variants_json TEXT NOT NULL,
                queue_row_json TEXT NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
                eligible_at REAL NOT NULL DEFAULT 0,
                lease_token TEXT,
                lease_generation INTEGER NOT NULL DEFAULT 0
                    CHECK (lease_generation >= 0),
                leased_by TEXT,
                lease_expires_at REAL,
                current_stage TEXT,
                result_json TEXT,
                error TEXT,
                failure_class TEXT,
                active INTEGER NOT NULL CHECK (active IN (0, 1)),
                sync_generation INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (plan_digest, base_cell_id)
                    REFERENCES resolved_cells(plan_digest, cell_id),
                CHECK (
                    (state IN ('leased', 'running')
                     AND lease_token IS NOT NULL
                     AND leased_by IS NOT NULL
                     AND lease_expires_at IS NOT NULL)
                    OR
                    (state NOT IN ('leased', 'running')
                     AND lease_token IS NULL
                     AND leased_by IS NULL
                     AND lease_expires_at IS NULL)
                )
            );

            CREATE INDEX IF NOT EXISTS jobs_claim_order
                ON jobs(state, active, batch_id, position, job_id);
            CREATE INDEX IF NOT EXISTS jobs_lease_expiry
                ON jobs(state, lease_expires_at);

            CREATE TABLE IF NOT EXISTS pathological_cell_quarantines (
                quarantine_id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL REFERENCES jobs(job_id),
                batch_id TEXT NOT NULL REFERENCES batches(batch_id),
                state TEXT NOT NULL CHECK (state IN ('active', 'released')),
                reason TEXT NOT NULL,
                failure_class TEXT NOT NULL,
                attempt_count INTEGER NOT NULL CHECK (attempt_count >= 0),
                created_at TEXT NOT NULL,
                released_at TEXT,
                release_reason TEXT,
                CHECK (
                    (state = 'active' AND released_at IS NULL AND release_reason IS NULL)
                    OR
                    (state = 'released' AND released_at IS NOT NULL
                     AND release_reason IS NOT NULL)
                )
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_active_pathological_quarantine
                ON pathological_cell_quarantines(job_id) WHERE state = 'active';
            CREATE INDEX IF NOT EXISTS pathological_quarantine_batch
                ON pathological_cell_quarantines(batch_id, state, quarantine_id);

            CREATE TABLE IF NOT EXISTS attempts (
                attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL REFERENCES jobs(job_id),
                attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
                lease_token TEXT NOT NULL UNIQUE,
                lease_generation INTEGER NOT NULL CHECK (lease_generation > 0),
                worker_id TEXT NOT NULL,
                state TEXT NOT NULL CHECK (
                    state IN ('leased', 'running', 'complete', 'failed', 'expired')
                ),
                started_at TEXT NOT NULL,
                lease_expires_at REAL NOT NULL,
                ended_at TEXT,
                error TEXT,
                UNIQUE (job_id, attempt_number),
                UNIQUE (job_id, lease_generation)
            );

            CREATE TABLE IF NOT EXISTS workers (
                worker_id TEXT PRIMARY KEY,
                transport TEXT NOT NULL CHECK (transport IN ('local', 'remote-http')),
                pools_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('online', 'offline')),
                metadata_json TEXT NOT NULL,
                registered_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS stage_attempts (
                stage_attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                attempt_id INTEGER NOT NULL REFERENCES attempts(attempt_id),
                job_id TEXT NOT NULL REFERENCES jobs(job_id),
                attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
                lease_generation INTEGER NOT NULL CHECK (lease_generation > 0),
                worker_id TEXT NOT NULL,
                sequence INTEGER NOT NULL CHECK (sequence > 0),
                stage TEXT NOT NULL,
                stage_attempt INTEGER NOT NULL CHECK (stage_attempt > 0),
                state TEXT NOT NULL CHECK (
                    state IN ('started', 'completed', 'failed', 'skipped',
                              'interrupted')
                ),
                started_at TEXT NOT NULL,
                ended_at TEXT,
                duration_ns INTEGER CHECK (duration_ns IS NULL OR duration_ns >= 0),
                duration_source TEXT CHECK (
                    duration_source IS NULL OR duration_source IN (
                        'worker-monotonic', 'coordinator-wall-clock'
                    )
                ),
                wall_clock_regressed INTEGER NOT NULL DEFAULT 0
                    CHECK (wall_clock_regressed IN (0, 1)),
                details_json TEXT NOT NULL,
                metrics_json TEXT NOT NULL,
                error TEXT,
                UNIQUE (attempt_id, sequence),
                UNIQUE (attempt_id, stage, stage_attempt),
                CHECK (
                    (state = 'started' AND ended_at IS NULL
                     AND duration_ns IS NULL AND duration_source IS NULL)
                    OR
                    (state != 'started' AND ended_at IS NOT NULL
                     AND duration_ns IS NOT NULL AND duration_source IS NOT NULL)
                )
            );

            CREATE INDEX IF NOT EXISTS stage_attempts_attempt_history
                ON stage_attempts(attempt_id, sequence);
            CREATE UNIQUE INDEX IF NOT EXISTS stage_attempts_one_open_per_attempt
                ON stage_attempts(attempt_id) WHERE state = 'started';
            CREATE INDEX IF NOT EXISTS stage_attempts_job_generation
                ON stage_attempts(job_id, lease_generation, sequence);
            CREATE INDEX IF NOT EXISTS stage_attempts_stage_history
                ON stage_attempts(stage, state, ended_at, stage_attempt_id);

            CREATE TABLE IF NOT EXISTS events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                batch_id TEXT,
                job_id TEXT,
                plan_digest TEXT,
                payload_json TEXT NOT NULL
            );

            CREATE TRIGGER IF NOT EXISTS events_are_append_only_update
            BEFORE UPDATE ON events
            BEGIN
                SELECT RAISE(ABORT, 'coordinator events are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS events_are_append_only_delete
            BEFORE DELETE ON events
            BEGIN
                SELECT RAISE(ABORT, 'coordinator events are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS plans_are_immutable_update
            BEFORE UPDATE ON plans
            BEGIN
                SELECT RAISE(ABORT, 'resolved plans are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS plans_are_immutable_delete
            BEFORE DELETE ON plans
            BEGIN
                SELECT RAISE(ABORT, 'resolved plans are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS resolved_cells_are_immutable_update
            BEFORE UPDATE ON resolved_cells
            BEGIN
                SELECT RAISE(ABORT, 'resolved cells are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS resolved_cells_are_immutable_delete
            BEFORE DELETE ON resolved_cells
            BEGIN
                SELECT RAISE(ABORT, 'resolved cells are immutable');
            END;
            """)
        state_columns = {
            str(row["name"])
            for row in self._connection.execute(
                "PRAGMA table_info(coordinator_state)"
            ).fetchall()
        }
        if "max_workers" not in state_columns:
            self._connection.execute(
                "ALTER TABLE coordinator_state "
                "ADD COLUMN max_workers INTEGER NOT NULL DEFAULT 4 "
                "CHECK (max_workers > 0)"
            )
        if "performance_json" not in state_columns:
            self._connection.execute(
                "ALTER TABLE coordinator_state ADD COLUMN performance_json TEXT"
            )
        if "retry_backoff_seconds" not in state_columns:
            self._connection.execute(
                "ALTER TABLE coordinator_state ADD COLUMN retry_backoff_seconds "
                "INTEGER NOT NULL DEFAULT 0 CHECK (retry_backoff_seconds >= 0)"
            )
        if "retry_backoff_max_seconds" not in state_columns:
            self._connection.execute(
                "ALTER TABLE coordinator_state ADD COLUMN retry_backoff_max_seconds "
                "INTEGER NOT NULL DEFAULT 0 CHECK (retry_backoff_max_seconds >= 0)"
            )
        if "authority_failure_threshold" not in state_columns:
            self._connection.execute(
                "ALTER TABLE coordinator_state "
                "ADD COLUMN authority_failure_threshold INTEGER NOT NULL DEFAULT 0 "
                "CHECK (authority_failure_threshold >= 0)"
            )
        if "operations_json" not in state_columns:
            self._connection.execute(
                "ALTER TABLE coordinator_state ADD COLUMN operations_json "
                "TEXT NOT NULL DEFAULT '{}'"
            )
        if "active_batch_id" not in state_columns:
            self._connection.execute(
                "ALTER TABLE coordinator_state ADD COLUMN active_batch_id TEXT"
            )
        if "active_admission_id" not in state_columns:
            self._connection.execute(
                "ALTER TABLE coordinator_state ADD COLUMN active_admission_id TEXT"
            )
        if "lookahead_batch_id" not in state_columns:
            self._connection.execute(
                "ALTER TABLE coordinator_state ADD COLUMN lookahead_batch_id TEXT"
            )
        if "lookahead_admission_id" not in state_columns:
            self._connection.execute(
                "ALTER TABLE coordinator_state ADD COLUMN lookahead_admission_id TEXT"
            )
        if "last_schedule_admission_id" not in state_columns:
            self._connection.execute(
                "ALTER TABLE coordinator_state ADD COLUMN last_schedule_admission_id TEXT"
            )
        job_columns = {
            str(row["name"])
            for row in self._connection.execute("PRAGMA table_info(jobs)").fetchall()
        }
        if "eligible_at" not in job_columns:
            self._connection.execute(
                "ALTER TABLE jobs ADD COLUMN eligible_at REAL NOT NULL DEFAULT 0"
            )
        if "failure_class" not in job_columns:
            self._connection.execute("ALTER TABLE jobs ADD COLUMN failure_class TEXT")
        # Create this only after migrating older ledgers which predate the
        # eligibility column; placing it in the initial script would make the
        # migration fail before ALTER TABLE can run.
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS jobs_claim_eligibility "
            "ON jobs(state, active, eligible_at, batch_id, position, job_id)"
        )
        stage_columns = {
            str(row["name"])
            for row in self._connection.execute(
                "PRAGMA table_info(stage_attempts)"
            ).fetchall()
        }
        if "wall_clock_regressed" not in stage_columns:
            self._connection.execute(
                "ALTER TABLE stage_attempts ADD COLUMN wall_clock_regressed "
                "INTEGER NOT NULL DEFAULT 0 "
                "CHECK (wall_clock_regressed IN (0, 1))"
            )
        self._connection.execute("""
            INSERT OR IGNORE INTO coordinator_state (
                singleton, config_name, config_path, armed, paused,
                max_workers, performance_json, poll_seconds, lease_seconds, max_attempts,
                retry_backoff_seconds, retry_backoff_max_seconds,
                authority_failure_threshold,
                operations_json, active_batch_id, active_admission_id,
                lookahead_batch_id, lookahead_admission_id,
                last_schedule_admission_id,
                sync_generation, synced_at
            ) VALUES (
                1, NULL, NULL, 0, 0, 4, NULL, 5, 3600, 3, 0, 0, 0, '{}',
                NULL, NULL, NULL, NULL, NULL, 0, NULL
            )
            """)
        # Keep the query planner's statistics current after migrations add the
        # timing-history indexes above.  This is safe on both new and old ledgers.
        self._connection.execute("PRAGMA optimize")

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self._connection.rollback()
            raise
        else:
            self._connection.commit()

    def _timestamp(self, now: float) -> str:
        return datetime.fromtimestamp(now, timezone.utc).isoformat()

    def _now(self, value: float | datetime | None = None) -> float:
        if value is None:
            return float(self._clock())
        if isinstance(value, bool):
            raise ValueError("now must be a Unix timestamp or datetime")
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, datetime):
            if value.tzinfo is None:
                raise ValueError("now datetime must include a timezone")
            return value.timestamp()
        raise ValueError("now must be a Unix timestamp or datetime")

    def _event_locked(
        self,
        event_type: str,
        *,
        now: float,
        actor: str,
        batch_id: str | None = None,
        job_id: str | None = None,
        plan_digest: str | None = None,
        payload: object | None = None,
    ) -> int:
        cursor = self._connection.execute(
            """
            INSERT INTO events (
                occurred_at, event_type, actor, batch_id, job_id,
                plan_digest, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self._timestamp(now),
                event_type,
                _text(actor, "event actor"),
                batch_id,
                job_id,
                plan_digest,
                _canonical_json({} if payload is None else payload),
            ),
        )
        return int(cursor.lastrowid)

    def _coerce_config(self, config: QueueConfig | str | Path) -> QueueConfig:
        if isinstance(config, QueueConfig):
            if self.project_root is not None and (
                config.project_root != self.project_root
            ):
                raise ValueError("queue config project root differs from coordinator")
            if self.project_root is None:
                self.project_root = config.project_root
            return config
        if self.project_root is None:
            raise ValueError(
                "project_root is required when sync_queue receives a TOML path"
            )
        return QueueConfig.load(config, self.project_root)

    def sync_queue(
        self,
        config: QueueConfig | str | Path,
        *,
        now: float | datetime | None = None,
        actor: str = "coordinator",
    ) -> dict[str, object]:
        """Resolve and durably synchronize every selected queue row.

        Resolution happens before the database transaction, so an invalid plan
        cannot partially replace the active queue.  Existing jobs retain their
        terminal or in-flight state when the same immutable identity is synced
        again.
        """

        queue_config = self._coerce_config(config)
        timestamp = self._now(now)
        resolved_batches: list[
            tuple[
                BatchConfig,
                dict[str, object],
                list[dict[str, object]],
                list[dict[str, object]],
            ]
        ] = []
        for batch in queue_config.batches:
            plan = resolve_plan(batch.plan, queue_config.project_root)
            if plan.get("schema_version") != RESOLVED_SCHEMA:
                raise ValueError(f"batch {batch.id} did not resolve a supported plan")
            matrices = {
                str(matrix["id"])
                for matrix in plan["matrices"]
                if isinstance(matrix, dict) and "id" in matrix
            }
            selected_matrices = matrices
            if batch.matrices is not None:
                missing = set(batch.matrices) - matrices
                if missing:
                    raise ValueError(
                        f"batch {batch.id} selects unknown matrices: {sorted(missing)}"
                    )
                selected_matrices = set(batch.matrices)
            selected_cells = [
                cell
                for cell in plan["cells"]
                if isinstance(cell, dict)
                and str(cell.get("matrix")) in selected_matrices
            ]
            cells_by_id = {str(cell["id"]): cell for cell in selected_cells}
            selected_rows = [
                row
                for row in plan["queue_preview"]
                if isinstance(row, dict) and str(row.get("base_cell")) in cells_by_id
            ]
            if len(cells_by_id) != len(selected_cells):
                raise ValueError(f"batch {batch.id} resolved duplicate cell ids")
            for row in selected_rows:
                if row.get("state") not in {"planned", "blocked"}:
                    raise ValueError(
                        f"batch {batch.id} has unsupported queue row state: "
                        f"{row.get('state')!r}"
                    )
            if batch.executions is not None and len(selected_rows) != batch.executions:
                raise ValueError(
                    f"batch {batch.id} resolved {len(selected_rows)} queue rows; "
                    f"expected {batch.executions}"
                )
            if batch.queue_digest is not None:
                actual_queue_digest = queue_identity_digest(selected_rows)
                if actual_queue_digest != batch.queue_digest:
                    raise ValueError(
                        f"batch {batch.id} queue_digest mismatch: expected "
                        f"{batch.queue_digest}, got {actual_queue_digest}"
                    )
            resolved_batches.append((batch, plan, selected_cells, selected_rows))

        submitted = 0
        blocked = 0
        created_jobs = 0
        with self._transaction():
            state = self._connection.execute(
                "SELECT sync_generation FROM coordinator_state WHERE singleton = 1"
            ).fetchone()
            generation = int(state["sync_generation"]) + 1
            self._connection.execute("UPDATE batches SET active = 0")
            self._connection.execute("UPDATE jobs SET active = 0")
            self._connection.execute(
                """
                UPDATE coordinator_state
                SET config_name = ?, config_path = ?, armed = ?,
                    max_workers = ?, performance_json = ?, poll_seconds = ?,
                    lease_seconds = ?, max_attempts = ?,
                    retry_backoff_seconds = ?, retry_backoff_max_seconds = ?,
                    authority_failure_threshold = ?,
                    operations_json = ?,
                    sync_generation = ?, synced_at = ?
                WHERE singleton = 1
                """,
                (
                    queue_config.name,
                    str(queue_config.source_path),
                    int(queue_config.armed),
                    queue_config.max_workers,
                    (
                        _canonical_json(queue_config.performance_profile.document())
                        if queue_config.performance_profile is not None
                        else None
                    ),
                    queue_config.poll_seconds,
                    queue_config.lease_seconds,
                    queue_config.max_attempts,
                    queue_config.retry_backoff_seconds,
                    queue_config.retry_backoff_max_seconds,
                    queue_config.authority_failure_threshold,
                    _canonical_json(queue_config.operations.document()),
                    generation,
                    self._timestamp(timestamp),
                ),
            )

            for batch_position, (
                batch,
                plan,
                cells,
                queue_rows,
            ) in enumerate(resolved_batches, start=1):
                plan_digest = str(plan["plan_digest"])
                immutable_plan = {
                    key: value for key, value in plan.items() if key != "inventory"
                }
                plan_json = _canonical_json(immutable_plan)
                existing_plan = self._connection.execute(
                    "SELECT plan_json FROM plans WHERE plan_digest = ?",
                    (plan_digest,),
                ).fetchone()
                if existing_plan is None:
                    self._connection.execute(
                        """
                        INSERT INTO plans (
                            plan_digest, schema_version, name, plan_json, created_at
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            plan_digest,
                            str(plan["schema_version"]),
                            str(plan["name"]),
                            plan_json,
                            self._timestamp(timestamp),
                        ),
                    )
                    self._event_locked(
                        "plan.resolved",
                        now=timestamp,
                        actor=actor,
                        batch_id=batch.id,
                        plan_digest=plan_digest,
                        payload={"plan": batch.plan_path},
                    )
                elif existing_plan["plan_json"] != plan_json:
                    raise CoordinatorError(
                        f"immutable plan digest collision: {plan_digest}"
                    )

                existing_batch = self._connection.execute(
                    "SELECT created_at FROM batches WHERE batch_id = ?", (batch.id,)
                ).fetchone()
                created_at = (
                    existing_batch["created_at"]
                    if existing_batch is not None
                    else self._timestamp(timestamp)
                )
                self._connection.execute(
                    """
                    INSERT INTO batches (
                        batch_id, name, plan_digest, plan_path, matrices_json,
                        position, active, sync_generation, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                    ON CONFLICT(batch_id) DO UPDATE SET
                        name = excluded.name,
                        plan_digest = excluded.plan_digest,
                        plan_path = excluded.plan_path,
                        matrices_json = excluded.matrices_json,
                        position = excluded.position,
                        active = 1,
                        sync_generation = excluded.sync_generation,
                        updated_at = excluded.updated_at
                    """,
                    (
                        batch.id,
                        batch.name,
                        plan_digest,
                        batch.plan_path,
                        (
                            _canonical_json(list(batch.matrices))
                            if batch.matrices is not None
                            else None
                        ),
                        batch_position,
                        generation,
                        created_at,
                        self._timestamp(timestamp),
                    ),
                )

                for cell in cells:
                    cell_id = str(cell["id"])
                    cell_json = _canonical_json(cell)
                    existing_cell = self._connection.execute(
                        """
                        SELECT cell_json FROM resolved_cells
                        WHERE plan_digest = ? AND cell_id = ?
                        """,
                        (plan_digest, cell_id),
                    ).fetchone()
                    if existing_cell is None:
                        self._connection.execute(
                            """
                            INSERT INTO resolved_cells (
                                plan_digest, cell_id, matrix_id, cell_state,
                                cell_json
                            ) VALUES (?, ?, ?, ?, ?)
                            """,
                            (
                                plan_digest,
                                cell_id,
                                str(cell["matrix"]),
                                str(cell["status"]),
                                cell_json,
                            ),
                        )
                    elif existing_cell["cell_json"] != cell_json:
                        raise CoordinatorError(
                            "immutable resolved cell collision: "
                            f"{plan_digest}:{cell_id}"
                        )

                for row in queue_rows:
                    base_cell = str(row["base_cell"])
                    factor_variants = row.get("factor_variants", [])
                    if not isinstance(factor_variants, list):
                        raise ValueError(
                            f"queue row {base_cell} factor_variants must be an array"
                        )
                    job_id = _stable_job_id(
                        batch.id, plan_digest, base_cell, factor_variants
                    )
                    row_json = _canonical_json(row)
                    blockers_json = _canonical_json(row.get("blockers", []))
                    factor_json = _canonical_json(factor_variants)
                    state_value = "queued" if row["state"] == "planned" else "blocked"
                    existing_job = self._connection.execute(
                        """
                        SELECT batch_id, plan_digest, base_cell_id,
                               factor_variants_json, queue_row_json
                        FROM jobs WHERE job_id = ?
                        """,
                        (job_id,),
                    ).fetchone()
                    if existing_job is None:
                        self._connection.execute(
                            """
                            INSERT INTO jobs (
                                job_id, batch_id, plan_digest, base_cell_id,
                                position, state, blockers_json,
                                factor_variants_json, queue_row_json,
                                active, sync_generation, created_at, updated_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                            """,
                            (
                                job_id,
                                batch.id,
                                plan_digest,
                                base_cell,
                                int(row["position"]),
                                state_value,
                                blockers_json,
                                factor_json,
                                row_json,
                                generation,
                                self._timestamp(timestamp),
                                self._timestamp(timestamp),
                            ),
                        )
                        created_jobs += 1
                        self._event_locked(
                            (
                                "job.queued"
                                if state_value == "queued"
                                else "job.blocked"
                            ),
                            now=timestamp,
                            actor=actor,
                            batch_id=batch.id,
                            job_id=job_id,
                            plan_digest=plan_digest,
                            payload={
                                "position": int(row["position"]),
                                "base_cell": base_cell,
                                "blockers": row.get("blockers", []),
                            },
                        )
                    else:
                        immutable_values = (
                            existing_job["batch_id"],
                            existing_job["plan_digest"],
                            existing_job["base_cell_id"],
                            existing_job["factor_variants_json"],
                            existing_job["queue_row_json"],
                        )
                        requested_values = (
                            batch.id,
                            plan_digest,
                            base_cell,
                            factor_json,
                            row_json,
                        )
                        if immutable_values != requested_values:
                            raise CoordinatorError(f"stable job id collision: {job_id}")
                        self._connection.execute(
                            """
                            UPDATE jobs
                            SET position = ?, active = 1, sync_generation = ?,
                                updated_at = ?
                            WHERE job_id = ?
                            """,
                            (
                                int(row["position"]),
                                generation,
                                self._timestamp(timestamp),
                                job_id,
                            ),
                        )
                    if state_value == "blocked":
                        blocked += 1
                    else:
                        submitted += 1

            admission_state = self._state_locked()
            for batch_field, admission_field in (
                ("active_batch_id", "active_admission_id"),
                ("lookahead_batch_id", "lookahead_admission_id"),
            ):
                batch_id = admission_state[batch_field]
                if batch_id is None:
                    continue
                still_active = self._connection.execute(
                    "SELECT 1 FROM batches WHERE batch_id = ? AND active = 1",
                    (batch_id,),
                ).fetchone()
                if still_active is None:
                    self._connection.execute(
                        f"UPDATE coordinator_state SET {batch_field} = NULL, "
                        f"{admission_field} = NULL WHERE singleton = 1"
                    )

            self._event_locked(
                "queue.synced",
                now=timestamp,
                actor=actor,
                payload={
                    "config": queue_config.name,
                    "generation": generation,
                    "batches": len(resolved_batches),
                    "submitted": submitted,
                    "blocked": blocked,
                    "created_jobs": created_jobs,
                    "armed": queue_config.armed,
                },
            )
        return self.snapshot()

    def sync(
        self,
        config: QueueConfig | str | Path,
        *,
        now: float | datetime | None = None,
        actor: str = "coordinator",
    ) -> dict[str, object]:
        """Alias for :meth:`sync_queue`, suitable for service integration."""

        return self.sync_queue(config, now=now, actor=actor)

    def reconfigure_runtime(
        self,
        config: QueueConfig | str | Path,
        *,
        expected_sync_generation: int,
        expected_active_jobs: int,
        reason: str,
        actor: str = "operator",
        now: float | datetime | None = None,
    ) -> dict[str, object]:
        """Rebind runtime policy without replacing immutable execution work.

        This transition is intentionally narrower than :meth:`sync_queue`.
        It accepts only the queue already synchronized into the ledger, proves
        that its ordered batch references and active-job population are
        unchanged, and updates only coordinator runtime policy.
        """

        queue_config = self._coerce_config(config)
        generation = _positive_integer(
            expected_sync_generation, "expected sync generation"
        )
        expected_jobs = _positive_integer(expected_active_jobs, "expected active jobs")
        reason_text = _text(reason, "runtime reconfiguration reason")
        timestamp = self._now(now)
        with self._transaction():
            state = self._state_locked()
            if not bool(state["paused"]):
                raise CoordinatorError(
                    "runtime reconfiguration requires a paused queue"
                )
            if int(state["sync_generation"]) != generation:
                raise CoordinatorError(
                    "runtime reconfiguration sync generation changed: "
                    f"{state['sync_generation']} != {generation}"
                )
            if str(state["config_name"]) != queue_config.name:
                raise CoordinatorError("runtime reconfiguration queue name changed")
            if Path(str(state["config_path"])).resolve() != queue_config.source_path:
                raise CoordinatorError("runtime reconfiguration queue path changed")

            live = self._connection.execute("""
                SELECT COUNT(*) AS count FROM jobs
                WHERE active = 1 AND state IN ('leased', 'running')
                """).fetchone()
            if int(live["count"]) != 0:
                raise CoordinatorError(
                    "runtime reconfiguration requires zero live active jobs"
                )
            active_jobs = self._connection.execute(
                "SELECT COUNT(*) AS count FROM jobs WHERE active = 1"
            ).fetchone()
            if int(active_jobs["count"]) != expected_jobs:
                raise CoordinatorError(
                    "runtime reconfiguration active-job count changed: "
                    f"{active_jobs['count']} != {expected_jobs}"
                )
            if any(batch.executions is None for batch in queue_config.batches):
                raise CoordinatorError(
                    "runtime reconfiguration requires executions on every batch"
                )
            configured_jobs = sum(
                int(batch.executions or 0) for batch in queue_config.batches
            )
            if configured_jobs != expected_jobs:
                raise CoordinatorError(
                    "runtime reconfiguration queue job count changed: "
                    f"{configured_jobs} != {expected_jobs}"
                )

            current_batches = self._connection.execute("""
                SELECT batch_id, plan_path, matrices_json, position
                FROM batches WHERE active = 1 ORDER BY position, batch_id
                """).fetchall()
            configured_batches = [
                (
                    batch.id,
                    batch.plan_path,
                    (
                        _canonical_json(list(batch.matrices))
                        if batch.matrices is not None
                        else None
                    ),
                    position,
                )
                for position, batch in enumerate(queue_config.batches, start=1)
            ]
            durable_batches = [
                (
                    str(row["batch_id"]),
                    str(row["plan_path"]),
                    row["matrices_json"],
                    int(row["position"]),
                )
                for row in current_batches
            ]
            if durable_batches != configured_batches:
                raise CoordinatorError(
                    "runtime reconfiguration cannot change ordered batch references"
                )

            previous_profile = (
                json.loads(state["performance_json"])
                if state["performance_json"] is not None
                else None
            )
            next_profile = (
                queue_config.performance_profile.document()
                if queue_config.performance_profile is not None
                else None
            )
            self._connection.execute(
                """
                UPDATE coordinator_state
                SET armed = ?, max_workers = ?, performance_json = ?,
                    poll_seconds = ?, lease_seconds = ?, max_attempts = ?,
                    retry_backoff_seconds = ?, retry_backoff_max_seconds = ?,
                    authority_failure_threshold = ?, operations_json = ?
                WHERE singleton = 1
                """,
                (
                    int(queue_config.armed),
                    queue_config.max_workers,
                    _canonical_json(next_profile) if next_profile is not None else None,
                    queue_config.poll_seconds,
                    queue_config.lease_seconds,
                    queue_config.max_attempts,
                    queue_config.retry_backoff_seconds,
                    queue_config.retry_backoff_max_seconds,
                    queue_config.authority_failure_threshold,
                    _canonical_json(queue_config.operations.document()),
                ),
            )
            self._event_locked(
                "queue.runtime-reconfigured",
                now=timestamp,
                actor=actor,
                payload={
                    "reason": reason_text,
                    "sync_generation": generation,
                    "active_jobs": expected_jobs,
                    "previous": {
                        "armed": bool(state["armed"]),
                        "max_workers": int(state["max_workers"]),
                        "performance_profile": previous_profile,
                    },
                    "current": {
                        "armed": queue_config.armed,
                        "max_workers": queue_config.max_workers,
                        "performance_profile": next_profile,
                    },
                    "execution_generation_preserved": True,
                },
            )
        return self.status()

    def disarm_for_recovery(
        self,
        config: QueueConfig | str | Path,
        *,
        expected_sync_generation: int,
        expected_active_jobs: int,
        expected_live_jobs: int,
        reason: str,
        actor: str = "operator",
        now: float | datetime | None = None,
    ) -> dict[str, object]:
        """Disarm a paused queue without disturbing live recovery evidence.

        This transition exists for service-manager stops: workers can be gone
        while their fenced leases remain live in the ledger.  Normal runtime
        reconfiguration correctly refuses that state, but interrupted-job
        recovery must first prove that reviewed TOML is disarmed.  Exact
        generation and population assertions prevent this narrow transition
        from becoming an unguarded runtime edit.
        """

        queue_config = self._coerce_config(config)
        generation = _positive_integer(
            expected_sync_generation, "expected sync generation"
        )
        expected_jobs = _positive_integer(expected_active_jobs, "expected active jobs")
        expected_live = _positive_integer(expected_live_jobs, "expected live jobs")
        reason_text = _text(reason, "recovery disarm reason")
        if queue_config.armed:
            raise CoordinatorError("recovery disarm requires disarmed queue TOML")
        timestamp = self._now(now)
        with self._transaction():
            state = self._state_locked()
            if not bool(state["paused"]):
                raise CoordinatorError("recovery disarm requires a paused queue")
            if int(state["sync_generation"]) != generation:
                raise CoordinatorError(
                    "recovery disarm sync generation changed: "
                    f"{state['sync_generation']} != {generation}"
                )
            if str(state["config_name"]) != queue_config.name:
                raise CoordinatorError("recovery disarm queue name changed")
            if Path(str(state["config_path"])).resolve() != queue_config.source_path:
                raise CoordinatorError("recovery disarm queue path changed")

            populations = self._connection.execute("""
                SELECT COUNT(*) AS active_jobs,
                       SUM(CASE WHEN state IN ('leased', 'running') THEN 1 ELSE 0 END)
                           AS live_jobs
                FROM jobs WHERE active = 1
                """).fetchone()
            if int(populations["active_jobs"]) != expected_jobs:
                raise CoordinatorError(
                    "recovery disarm active-job count changed: "
                    f"{populations['active_jobs']} != {expected_jobs}"
                )
            if int(populations["live_jobs"] or 0) != expected_live:
                raise CoordinatorError(
                    "recovery disarm live-job count changed: "
                    f"{populations['live_jobs']} != {expected_live}"
                )
            if any(batch.executions is None for batch in queue_config.batches):
                raise CoordinatorError(
                    "recovery disarm requires executions on every batch"
                )
            configured_jobs = sum(
                int(batch.executions or 0) for batch in queue_config.batches
            )
            if configured_jobs != expected_jobs:
                raise CoordinatorError(
                    "recovery disarm queue job count changed: "
                    f"{configured_jobs} != {expected_jobs}"
                )
            current_batches = self._connection.execute("""
                SELECT batch_id, plan_path, matrices_json, position
                FROM batches WHERE active = 1 ORDER BY position, batch_id
                """).fetchall()
            durable_batches = [
                (
                    str(row["batch_id"]),
                    str(row["plan_path"]),
                    row["matrices_json"],
                    int(row["position"]),
                )
                for row in current_batches
            ]
            configured_batches = [
                (
                    batch.id,
                    batch.plan_path,
                    (
                        _canonical_json(list(batch.matrices))
                        if batch.matrices is not None
                        else None
                    ),
                    position,
                )
                for position, batch in enumerate(queue_config.batches, start=1)
            ]
            if durable_batches != configured_batches:
                raise CoordinatorError(
                    "recovery disarm cannot change ordered batch references"
                )

            self._connection.execute(
                "UPDATE coordinator_state SET armed = 0 WHERE singleton = 1"
            )
            self._event_locked(
                "queue.recovery-disarmed",
                now=timestamp,
                actor=actor,
                payload={
                    "reason": reason_text,
                    "sync_generation": generation,
                    "active_jobs": expected_jobs,
                    "live_jobs": expected_live,
                    "live_evidence_preserved": True,
                },
            )
        return self.status()

    def _state_locked(self) -> sqlite3.Row:
        state = self._connection.execute(
            "SELECT * FROM coordinator_state WHERE singleton = 1"
        ).fetchone()
        if state is None:  # pragma: no cover - protected by schema initialization
            raise CoordinatorError("coordinator state is missing")
        return state

    def _block_document(
        self, batch_id: object, admission_id: object
    ) -> dict[str, object]:
        if batch_id is None:
            return {"active": False, "batch_id": None, "admission_id": None}
        rows = self._connection.execute(
            """
            SELECT jobs.state, COUNT(*) AS count
            FROM jobs JOIN batches ON batches.batch_id = jobs.batch_id
            WHERE jobs.batch_id = ? AND jobs.active = 1 AND batches.active = 1
            GROUP BY jobs.state
            """,
            (batch_id,),
        ).fetchall()
        counts = {job_state: 0 for job_state in sorted(_JOB_STATES)}
        counts.update({str(row["state"]): int(row["count"]) for row in rows})
        return {
            "active": True,
            "batch_id": str(batch_id),
            "admission_id": str(admission_id),
            "counts": counts,
            "remaining": counts["queued"] + counts["leased"] + counts["running"],
        }

    def execution_block(self) -> dict[str, object]:
        """Return the primary and bounded look-ahead admissions workers may drain."""

        state = self._state_locked()
        primary = self._block_document(
            state["active_batch_id"], state["active_admission_id"]
        )
        primary["last_schedule_admission_id"] = state["last_schedule_admission_id"]
        primary["lookahead"] = self._block_document(
            state["lookahead_batch_id"], state["lookahead_admission_id"]
        )
        return primary

    def start_next_block(
        self,
        admission_id: str,
        *,
        scheduled: bool,
        allow_scheduled_reentry: bool = False,
        now: float | datetime | None = None,
        actor: str = "operator",
    ) -> dict[str, object] | None:
        """Admit one ordered queue batch, without claiming or executing a cell.

        Re-entry is explicit and only used by a chaining schedule after the
        previous batch has durably drained.  The active-batch guard still
        serializes concurrent workers at the admission boundary.
        """

        admission = _text(admission_id, "block admission id")
        timestamp = self._now(now)
        with self._transaction():
            state = self._state_locked()
            if not bool(state["armed"]) or bool(state["paused"]):
                return None
            if state["active_batch_id"] is not None:
                return self.execution_block()
            if state["lookahead_batch_id"] is not None:
                raise CoordinatorError(
                    "look-ahead admission exists without a primary block"
                )
            if (
                scheduled
                and not allow_scheduled_reentry
                and state["last_schedule_admission_id"] == admission
            ):
                return None
            batch = self._connection.execute("""
                SELECT batches.* FROM batches
                WHERE batches.active = 1 AND EXISTS (
                    SELECT 1 FROM jobs
                    WHERE jobs.batch_id = batches.batch_id AND jobs.active = 1
                      AND jobs.state IN ('queued', 'leased', 'running')
                )
                ORDER BY batches.position, batches.batch_id LIMIT 1
                """).fetchone()
            if batch is None:
                return None
            self._connection.execute(
                """
                UPDATE coordinator_state
                SET active_batch_id = ?, active_admission_id = ?,
                    last_schedule_admission_id = CASE WHEN ? THEN ?
                        ELSE last_schedule_admission_id END
                WHERE singleton = 1
                """,
                (batch["batch_id"], admission, int(scheduled), admission),
            )
            self._event_locked(
                "batch.admitted",
                now=timestamp,
                actor=actor,
                batch_id=str(batch["batch_id"]),
                plan_digest=str(batch["plan_digest"]),
                payload={"admission_id": admission, "scheduled": scheduled},
            )
            return self.execution_block()

    def admit_lookahead_block(
        self,
        admission_id: str,
        *,
        minimum_idle_slots: int,
        actor: str = "coordinator",
        now: float | datetime | None = None,
    ) -> dict[str, object] | None:
        """Admit only the immediate successor when the primary has no queued work."""

        admission = _text(admission_id, "look-ahead admission id")
        idle_threshold = _positive_integer(minimum_idle_slots, "minimum idle slots")
        timestamp = self._now(now)
        with self._transaction():
            state = self._state_locked()
            primary_id = state["active_batch_id"]
            if not bool(state["armed"]) or bool(state["paused"]):
                return None
            if primary_id is None:
                return None
            if state["lookahead_batch_id"] is not None:
                return self.execution_block()
            primary_queued = self._connection.execute(
                "SELECT COUNT(*) AS count FROM jobs WHERE batch_id = ? "
                "AND active = 1 AND state = 'queued'",
                (primary_id,),
            ).fetchone()
            if int(primary_queued["count"]):
                return None
            live = self._connection.execute(
                "SELECT COUNT(*) AS count FROM jobs WHERE active = 1 "
                "AND state IN ('leased', 'running')"
            ).fetchone()
            idle_slots = int(state["max_workers"]) - int(live["count"])
            if idle_slots < idle_threshold:
                return None
            primary = self._connection.execute(
                "SELECT position FROM batches WHERE batch_id = ? AND active = 1",
                (primary_id,),
            ).fetchone()
            if primary is None:
                raise CoordinatorError("primary admission is not an active batch")
            successor = self._connection.execute(
                """
                SELECT batches.* FROM batches
                WHERE batches.active = 1 AND batches.position > ?
                  AND EXISTS (
                    SELECT 1 FROM jobs WHERE jobs.batch_id = batches.batch_id
                      AND jobs.active = 1
                      AND jobs.state IN ('queued', 'leased', 'running')
                  )
                ORDER BY batches.position, batches.batch_id LIMIT 1
                """,
                (primary["position"],),
            ).fetchone()
            if successor is None:
                return None
            self._connection.execute(
                "UPDATE coordinator_state SET lookahead_batch_id = ?, "
                "lookahead_admission_id = ? WHERE singleton = 1",
                (successor["batch_id"], admission),
            )
            self._event_locked(
                "batch.lookahead-admitted",
                now=timestamp,
                actor=actor,
                batch_id=str(successor["batch_id"]),
                plan_digest=str(successor["plan_digest"]),
                payload={
                    "admission_id": admission,
                    "primary_batch_id": primary_id,
                    "idle_slots": idle_slots,
                    "minimum_idle_slots": idle_threshold,
                },
            )
            return self.execution_block()

    def finish_active_block_if_drained(
        self,
        *,
        now: float | datetime | None = None,
        actor: str = "coordinator",
    ) -> bool:
        """Close an active admission only after queued and live jobs drain."""

        timestamp = self._now(now)
        with self._transaction():
            state = self._state_locked()
            batch_id = state["active_batch_id"]
            if batch_id is None:
                return False
            remaining = self._connection.execute(
                """
                SELECT COUNT(*) AS count FROM jobs
                JOIN batches ON batches.batch_id = jobs.batch_id
                WHERE jobs.batch_id = ? AND jobs.active = 1 AND batches.active = 1
                  AND jobs.state IN ('queued', 'leased', 'running')
                """,
                (batch_id,),
            ).fetchone()
            if int(remaining["count"]):
                return False
            admission_id = str(state["active_admission_id"])
            batch = self._connection.execute(
                "SELECT plan_digest FROM batches WHERE batch_id = ?", (batch_id,)
            ).fetchone()
            lookahead_id = state["lookahead_batch_id"]
            lookahead_admission = state["lookahead_admission_id"]
            self._connection.execute("""
                UPDATE coordinator_state
                SET active_batch_id = lookahead_batch_id,
                    active_admission_id = lookahead_admission_id,
                    lookahead_batch_id = NULL,
                    lookahead_admission_id = NULL
                WHERE singleton = 1
                """)
            self._event_locked(
                "batch.drained",
                now=timestamp,
                actor=actor,
                batch_id=str(batch_id),
                plan_digest=str(batch["plan_digest"]) if batch is not None else None,
                payload={"admission_id": admission_id},
            )
            if lookahead_id is not None:
                promoted = self._connection.execute(
                    "SELECT plan_digest FROM batches WHERE batch_id = ?",
                    (lookahead_id,),
                ).fetchone()
                self._event_locked(
                    "batch.lookahead-promoted",
                    now=timestamp,
                    actor=actor,
                    batch_id=str(lookahead_id),
                    plan_digest=str(promoted["plan_digest"]),
                    payload={
                        "admission_id": str(lookahead_admission),
                        "drained_primary_batch_id": str(batch_id),
                    },
                )
            return True

    def _close_open_stage_attempts_locked(
        self,
        row: sqlite3.Row,
        *,
        now: float,
        reason: str,
        actor: str,
    ) -> int:
        """Interrupt open spans when their fenced attempt cannot continue.

        Worker terminal durations use a monotonic clock.  A coordinator can
        only estimate a lost worker's elapsed span from persisted UTC values,
        so that distinct provenance is stored and exposed explicitly.
        """

        ended_at = self._timestamp(now)
        spans = self._connection.execute(
            """
            SELECT * FROM stage_attempts
            WHERE job_id = ? AND lease_generation = ? AND state = 'started'
            ORDER BY sequence
            """,
            (row["job_id"], row["lease_generation"]),
        ).fetchall()
        for span in spans:
            original_details = json.loads(span["details_json"])
            details = {
                "started": original_details,
                "interruption": {
                    "reason": reason,
                    "measurement": "coordinator-wall-clock",
                },
            }
            duration_ns = _elapsed_ns(str(span["started_at"]), ended_at)
            wall_clock_regressed = datetime.fromisoformat(
                ended_at
            ) < datetime.fromisoformat(str(span["started_at"]))
            self._connection.execute(
                """
                UPDATE stage_attempts
                SET state = 'interrupted', ended_at = ?, duration_ns = ?,
                    duration_source = 'coordinator-wall-clock',
                    wall_clock_regressed = ?, details_json = ?, error = ?
                WHERE stage_attempt_id = ? AND state = 'started'
                """,
                (
                    ended_at,
                    duration_ns,
                    int(wall_clock_regressed),
                    _canonical_json(details),
                    reason,
                    span["stage_attempt_id"],
                ),
            )
            self._event_locked(
                "stage.interrupted",
                now=now,
                actor=actor,
                batch_id=str(row["batch_id"]),
                job_id=str(row["job_id"]),
                plan_digest=str(row["plan_digest"]),
                payload={
                    "stage": str(span["stage"]),
                    "stage_attempt_id": int(span["stage_attempt_id"]),
                    "stage_attempt": int(span["stage_attempt"]),
                    "lease_generation": int(row["lease_generation"]),
                    "duration_ns": duration_ns,
                    "duration_source": "coordinator-wall-clock",
                    "wall_clock_regressed": wall_clock_regressed,
                    "reason": reason,
                },
            )
        return len(spans)

    def _recover_expired_locked(self, now: float, *, actor: str = "coordinator") -> int:
        state = self._state_locked()
        rows = self._connection.execute(
            """
            SELECT * FROM jobs
            WHERE state IN ('leased', 'running')
              AND lease_expires_at <= ?
            ORDER BY lease_expires_at, job_id
            """,
            (now,),
        ).fetchall()
        recovered = 0
        for row in rows:
            retry = int(row["attempt_count"]) < int(state["max_attempts"])
            next_state = "queued" if retry else "failed"
            retry_delay = (
                self._retry_delay(state, int(row["attempt_count"])) if retry else 0
            )
            eligible_at = now + retry_delay if retry else 0
            error = "lease expired"
            # End a span at the lease fence, not at a potentially much later
            # recovery sweep, so coordinator delay is not counted as work.
            span_end = min(now, float(row["lease_expires_at"]))
            self._close_open_stage_attempts_locked(
                row,
                now=span_end,
                reason=error,
                actor=actor,
            )
            self._connection.execute(
                """
                UPDATE attempts
                SET state = 'expired', ended_at = ?, error = ?
                WHERE job_id = ? AND lease_generation = ?
                  AND state IN ('leased', 'running')
                """,
                (
                    self._timestamp(span_end),
                    error,
                    row["job_id"],
                    row["lease_generation"],
                ),
            )
            self._connection.execute(
                """
                UPDATE jobs
                SET state = ?, lease_token = NULL, leased_by = NULL,
                    lease_expires_at = NULL, current_stage = NULL,
                    error = ?, eligible_at = ?, updated_at = ?
                WHERE job_id = ? AND lease_generation = ?
                """,
                (
                    next_state,
                    error,
                    eligible_at,
                    self._timestamp(now),
                    row["job_id"],
                    row["lease_generation"],
                ),
            )
            self._event_locked(
                "job.requeued" if retry else "job.failed",
                now=now,
                actor=actor,
                batch_id=str(row["batch_id"]),
                job_id=str(row["job_id"]),
                plan_digest=str(row["plan_digest"]),
                payload={
                    "reason": error,
                    "expired_generation": int(row["lease_generation"]),
                    "attempt_count": int(row["attempt_count"]),
                    "retry_cap_reached": not retry,
                    "retry_delay_seconds": retry_delay,
                    "eligible_at": eligible_at if retry else None,
                },
            )
            recovered += 1
        return recovered

    @staticmethod
    def _retry_delay(state: sqlite3.Row, attempt_count: int) -> int:
        base = int(state["retry_backoff_seconds"])
        maximum = int(state["retry_backoff_max_seconds"])
        if base == 0 or maximum == 0:
            return 0
        exponent = max(0, attempt_count - 1)
        return min(maximum, base * (2**exponent))

    def recover_expired(
        self,
        *,
        now: float | datetime | None = None,
        actor: str = "coordinator",
    ) -> int:
        """Requeue expired leases, or fail jobs which reached the retry cap."""

        timestamp = self._now(now)
        with self._transaction():
            return self._recover_expired_locked(timestamp, actor=actor)

    def claim(
        self,
        worker_id: str,
        *,
        now: float | datetime | None = None,
        pool: str | None = None,
        batch_id: str | None = None,
        batch_ids: tuple[str, ...] | None = None,
    ) -> dict[str, object] | None:
        """Atomically claim the first eligible job in batch and job order."""

        worker = _text(worker_id, "worker id")
        if pool is not None and pool not in WORKER_POOLS:
            raise ValueError(f"unsupported worker pool: {pool}")
        if batch_id is not None and batch_ids is not None:
            raise ValueError("claim accepts either batch_id or batch_ids")
        selected_batch = (
            _identifier(batch_id, "claim batch id") if batch_id is not None else None
        )
        selected_batches = (
            tuple(_identifier(value, "claim batch id") for value in batch_ids)
            if batch_ids is not None
            else None
        )
        if selected_batches is not None and (
            not selected_batches or len(set(selected_batches)) != len(selected_batches)
        ):
            raise ValueError("claim batch_ids must be non-empty and unique")
        timestamp = self._now(now)
        with self._transaction():
            self._recover_expired_locked(timestamp)
            state = self._state_locked()
            if not bool(state["armed"]) or bool(state["paused"]):
                return None
            active_workers = self._connection.execute("""
                SELECT COUNT(*) AS count FROM jobs
                JOIN batches ON batches.batch_id = jobs.batch_id
                WHERE jobs.active = 1 AND batches.active = 1
                  AND jobs.state IN ('leased', 'running')
                """).fetchone()
            if int(active_workers["count"]) >= int(state["max_workers"]):
                return None
            claim_query = """
                SELECT jobs.*, batches.position AS batch_position,
                       cells.cell_json AS resolved_cell_json
                FROM jobs
                JOIN batches ON batches.batch_id = jobs.batch_id
                JOIN resolved_cells AS cells
                  ON cells.plan_digest = jobs.plan_digest
                 AND cells.cell_id = jobs.base_cell_id
                WHERE jobs.active = 1 AND batches.active = 1
                  AND jobs.state = 'queued'
                  AND jobs.eligible_at <= ?
                """
            # ``fail`` enforces the automatic retry ceiling before it places a
            # job back in ``queued``. An operator recovery transition also
            # deliberately creates a queued job while preserving its exhausted
            # attempt count. The durable state is therefore the claim authority;
            # filtering it by the historical count would make reviewed recovery
            # jobs impossible to execute.
            parameters: list[object] = [timestamp]
            if selected_batch is not None:
                claim_query += " AND jobs.batch_id = ?"
                parameters.append(selected_batch)
            elif selected_batches is not None:
                placeholders = ",".join("?" for _ in selected_batches)
                claim_query += f" AND jobs.batch_id IN ({placeholders})"
                parameters.extend(selected_batches)
            claim_query += " ORDER BY batches.position, jobs.position, jobs.job_id"
            if pool is None:
                claim_query += " LIMIT 1"
            candidates = self._connection.execute(
                claim_query,
                parameters,
            ).fetchall()
            row = next(
                (
                    candidate
                    for candidate in candidates
                    if pool is None
                    or worker_pool_accepts_cell(
                        pool, json.loads(candidate["resolved_cell_json"])
                    )
                ),
                None,
            )
            if row is None:
                return None
            token = secrets.token_urlsafe(32)
            generation = int(row["lease_generation"]) + 1
            attempt = int(row["attempt_count"]) + 1
            expires_at = timestamp + int(state["lease_seconds"])
            cursor = self._connection.execute(
                """
                UPDATE jobs
                SET state = 'leased', attempt_count = ?, lease_token = ?,
                    lease_generation = ?, leased_by = ?, lease_expires_at = ?,
                    current_stage = NULL, error = NULL, failure_class = NULL,
                    eligible_at = 0, updated_at = ?
                WHERE job_id = ? AND state = 'queued' AND active = 1
                """,
                (
                    attempt,
                    token,
                    generation,
                    worker,
                    expires_at,
                    self._timestamp(timestamp),
                    row["job_id"],
                ),
            )
            if cursor.rowcount != 1:  # pragma: no cover - BEGIN IMMEDIATE fences this
                raise CoordinatorError("eligible job changed during atomic claim")
            self._connection.execute(
                """
                INSERT INTO attempts (
                    job_id, attempt_number, lease_token, lease_generation,
                    worker_id, state, started_at, lease_expires_at
                ) VALUES (?, ?, ?, ?, ?, 'leased', ?, ?)
                """,
                (
                    row["job_id"],
                    attempt,
                    token,
                    generation,
                    worker,
                    self._timestamp(timestamp),
                    expires_at,
                ),
            )
            event_payload: dict[str, object] = {
                "attempt": attempt,
                "lease_generation": generation,
                "lease_expires_at": expires_at,
            }
            if pool is not None:
                event_payload["worker_pool"] = pool
            self._event_locked(
                "job.claimed",
                now=timestamp,
                actor=worker,
                batch_id=str(row["batch_id"]),
                job_id=str(row["job_id"]),
                plan_digest=str(row["plan_digest"]),
                payload=event_payload,
            )
            claimed = self._connection.execute(
                """
                SELECT jobs.*, batches.position AS batch_position
                FROM jobs JOIN batches ON batches.batch_id = jobs.batch_id
                WHERE jobs.job_id = ?
                """,
                (row["job_id"],),
            ).fetchone()
            return self._lease_payload(claimed)

    def claim_job(
        self,
        worker_id: str,
        *,
        now: float | datetime | None = None,
        pool: str | None = None,
    ) -> dict[str, object] | None:
        """Alias for :meth:`claim`."""

        return self.claim(worker_id, now=now, pool=pool)

    def _lease_payload(self, row: sqlite3.Row) -> dict[str, object]:
        cell = self._connection.execute(
            """
            SELECT cell_json FROM resolved_cells
            WHERE plan_digest = ? AND cell_id = ?
            """,
            (row["plan_digest"], row["base_cell_id"]),
        ).fetchone()
        return {
            "job_id": str(row["job_id"]),
            "batch_id": str(row["batch_id"]),
            "batch_position": int(row["batch_position"]),
            "job_position": int(row["position"]),
            "plan_digest": str(row["plan_digest"]),
            "base_cell": str(row["base_cell_id"]),
            "factor_variants": json.loads(row["factor_variants_json"]),
            "attempt_number": int(row["attempt_count"]),
            "lease_token": str(row["lease_token"]),
            "lease_generation": int(row["lease_generation"]),
            "leased_by": str(row["leased_by"]),
            "lease_expires_at": float(row["lease_expires_at"]),
            "queue_row": json.loads(row["queue_row_json"]),
            "cell": json.loads(cell["cell_json"]),
        }

    def _require_lease_locked(
        self,
        job_id: str,
        lease_token: str,
        lease_generation: int,
        now: float,
    ) -> sqlite3.Row:
        self._recover_expired_locked(now)
        row = self._connection.execute(
            "SELECT * FROM jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
        if row is None:
            raise LeaseConflictError(f"unknown job: {job_id}")
        if (
            row["state"] not in _LEASED_STATES
            or row["lease_token"] != lease_token
            or int(row["lease_generation"]) != lease_generation
            or float(row["lease_expires_at"]) <= now
        ):
            raise LeaseConflictError(
                f"stale or inactive lease for job {job_id} generation "
                f"{lease_generation}"
            )
        return row

    def renew(
        self,
        job_id: str,
        lease_token: str,
        lease_generation: int,
        *,
        now: float | datetime | None = None,
        lease_seconds: int | None = None,
    ) -> dict[str, object]:
        """Renew a live lease after validating its token and generation."""

        if lease_seconds is not None:
            lease_seconds = _positive_integer(lease_seconds, "lease_seconds")
        timestamp = self._now(now)
        with self._transaction():
            row = self._require_lease_locked(
                job_id, lease_token, lease_generation, timestamp
            )
            state = self._state_locked()
            duration = lease_seconds or int(state["lease_seconds"])
            expires_at = timestamp + duration
            self._connection.execute(
                """
                UPDATE jobs SET lease_expires_at = ?, updated_at = ?
                WHERE job_id = ? AND lease_token = ? AND lease_generation = ?
                """,
                (
                    expires_at,
                    self._timestamp(timestamp),
                    job_id,
                    lease_token,
                    lease_generation,
                ),
            )
            self._connection.execute(
                """
                UPDATE attempts SET lease_expires_at = ?
                WHERE job_id = ? AND lease_generation = ?
                  AND state IN ('leased', 'running')
                """,
                (expires_at, job_id, lease_generation),
            )
            self._event_locked(
                "lease.renewed",
                now=timestamp,
                actor=str(row["leased_by"]),
                batch_id=str(row["batch_id"]),
                job_id=job_id,
                plan_digest=str(row["plan_digest"]),
                payload={
                    "lease_generation": lease_generation,
                    "lease_expires_at": expires_at,
                },
            )
            renewed = self._connection.execute(
                """
                SELECT jobs.*, batches.position AS batch_position
                FROM jobs JOIN batches ON batches.batch_id = jobs.batch_id
                WHERE jobs.job_id = ?
                """,
                (job_id,),
            ).fetchone()
            return self._lease_payload(renewed)

    def renew_lease(
        self,
        job_id: str,
        lease_token: str,
        lease_generation: int,
        *,
        now: float | datetime | None = None,
        lease_seconds: int | None = None,
    ) -> dict[str, object]:
        """Alias for :meth:`renew`."""

        return self.renew(
            job_id,
            lease_token,
            lease_generation,
            now=now,
            lease_seconds=lease_seconds,
        )

    def record_stage(
        self,
        job_id: str,
        lease_token: str,
        lease_generation: int,
        stage: str,
        *,
        status: str = "started",
        duration_ns: int | None = None,
        details: object | None = None,
        now: float | datetime | None = None,
    ) -> int:
        """Persist one strict, fenced stage-span transition.

        A ``started`` transition creates an open span.  ``completed`` and
        ``failed`` close the matching open span; ``skipped`` records a terminal
        zero-work span without a start event.  Repeating a terminal stage after
        it has closed creates a new ``stage_attempt`` when it is started again.
        Worker terminal durations must be monotonic nanoseconds.
        """

        stage_name = _identifier(stage, "stage")
        stage_status = _identifier(status, "stage status")
        if stage_status not in STAGE_STATUSES:
            raise ValueError(
                f"stage status must be one of: {', '.join(STAGE_STATUSES)}"
            )
        measured_duration = _stage_duration_ns(duration_ns, stage_status)
        if details is None:
            stage_details: Mapping[str, object] = {}
        elif isinstance(details, Mapping):
            stage_details = details
        else:
            raise ValueError("stage details must be a JSON object")
        details_json = _canonical_json(stage_details)
        raw_metrics = stage_details.get("metrics", {})
        if not isinstance(raw_metrics, Mapping):
            raise ValueError("stage details metrics must be a JSON object")
        metrics_json = _canonical_json(raw_metrics)
        timestamp = self._now(now)
        recorded_at = self._timestamp(timestamp)
        supplied_started_at = stage_details.get("started_at")
        supplied_finished_at = stage_details.get("finished_at")
        stage_started_at = (
            _utc_timestamp(supplied_started_at, "stage started_at")
            if supplied_started_at is not None
            else recorded_at
        )
        if stage_status == "started":
            if supplied_finished_at is not None:
                raise ValueError("a started stage cannot have finished_at")
            stage_ended_at = None
        else:
            stage_ended_at = (
                _utc_timestamp(supplied_finished_at, "stage finished_at")
                if supplied_finished_at is not None
                else recorded_at
            )
            if stage_status == "skipped" and stage_started_at != stage_ended_at:
                raise ValueError(
                    "a skipped stage must have identical start and finish timestamps"
                )
        with self._transaction():
            row = self._require_lease_locked(
                job_id, lease_token, lease_generation, timestamp
            )
            attempt = self._connection.execute(
                """
                SELECT * FROM attempts
                WHERE job_id = ? AND lease_generation = ?
                  AND state IN ('leased', 'running')
                """,
                (job_id, lease_generation),
            ).fetchone()
            if attempt is None:  # pragma: no cover - lease invariant guard
                raise CoordinatorError("live lease has no active attempt")
            open_span = self._connection.execute(
                """
                SELECT * FROM stage_attempts
                WHERE attempt_id = ? AND state = 'started'
                ORDER BY sequence DESC LIMIT 1
                """,
                (attempt["attempt_id"],),
            ).fetchone()
            if stage_status == "started":
                if open_span is not None:
                    raise CoordinatorError(
                        f"stage {open_span['stage']} is already running for this attempt"
                    )
                counters = self._connection.execute(
                    """
                    SELECT COALESCE(MAX(sequence), 0) + 1 AS next_sequence,
                           COALESCE(MAX(CASE WHEN stage = ? THEN stage_attempt END), 0)
                               + 1 AS next_stage_attempt
                    FROM stage_attempts WHERE attempt_id = ?
                    """,
                    (stage_name, attempt["attempt_id"]),
                ).fetchone()
                cursor = self._connection.execute(
                    """
                    INSERT INTO stage_attempts (
                        attempt_id, job_id, attempt_number, lease_generation,
                        worker_id, sequence, stage, stage_attempt, state,
                        started_at, ended_at, duration_ns, duration_source,
                        wall_clock_regressed, details_json, metrics_json, error
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'started', ?, NULL, NULL,
                              NULL, 0, ?, ?, NULL)
                    """,
                    (
                        attempt["attempt_id"],
                        job_id,
                        attempt["attempt_number"],
                        lease_generation,
                        attempt["worker_id"],
                        counters["next_sequence"],
                        stage_name,
                        counters["next_stage_attempt"],
                        stage_started_at,
                        details_json,
                        metrics_json,
                    ),
                )
                stage_attempt_id = int(cursor.lastrowid)
                stage_attempt = int(counters["next_stage_attempt"])
            elif stage_status == "skipped":
                if open_span is not None:
                    raise CoordinatorError(
                        f"cannot skip {stage_name} while stage {open_span['stage']} is running"
                    )
                counters = self._connection.execute(
                    """
                    SELECT COALESCE(MAX(sequence), 0) + 1 AS next_sequence,
                           COALESCE(MAX(CASE WHEN stage = ? THEN stage_attempt END), 0)
                               + 1 AS next_stage_attempt
                    FROM stage_attempts WHERE attempt_id = ?
                    """,
                    (stage_name, attempt["attempt_id"]),
                ).fetchone()
                cursor = self._connection.execute(
                    """
                    INSERT INTO stage_attempts (
                        attempt_id, job_id, attempt_number, lease_generation,
                        worker_id, sequence, stage, stage_attempt, state,
                        started_at, ended_at, duration_ns, duration_source,
                        wall_clock_regressed, details_json, metrics_json, error
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'skipped', ?, ?, ?,
                              'worker-monotonic', ?, ?, ?, NULL)
                    """,
                    (
                        attempt["attempt_id"],
                        job_id,
                        attempt["attempt_number"],
                        lease_generation,
                        attempt["worker_id"],
                        counters["next_sequence"],
                        stage_name,
                        counters["next_stage_attempt"],
                        stage_started_at,
                        stage_ended_at,
                        measured_duration,
                        int(
                            datetime.fromisoformat(str(stage_ended_at))
                            < datetime.fromisoformat(stage_started_at)
                        ),
                        details_json,
                        metrics_json,
                    ),
                )
                stage_attempt_id = int(cursor.lastrowid)
                stage_attempt = int(counters["next_stage_attempt"])
            else:
                if open_span is None or str(open_span["stage"]) != stage_name:
                    running = str(open_span["stage"]) if open_span is not None else None
                    raise CoordinatorError(
                        f"cannot mark stage {stage_name} {stage_status}; "
                        f"running stage is {running!r}"
                    )
                if supplied_started_at is None:
                    stage_started_at = str(open_span["started_at"])
                elif stage_started_at != str(open_span["started_at"]):
                    raise CoordinatorError(
                        "terminal stage started_at does not match its open span"
                    )
                wall_clock_regressed = datetime.fromisoformat(
                    str(stage_ended_at)
                ) < datetime.fromisoformat(str(open_span["started_at"]))
                error = None
                if stage_status == "failed":
                    message = stage_details.get("message")
                    error = (
                        message
                        if isinstance(message, str) and message
                        else "stage failed"
                    )
                self._connection.execute(
                    """
                    UPDATE stage_attempts
                    SET state = ?, ended_at = ?, duration_ns = ?,
                        duration_source = 'worker-monotonic', details_json = ?,
                        metrics_json = ?, wall_clock_regressed = ?, error = ?
                    WHERE stage_attempt_id = ? AND state = 'started'
                    """,
                    (
                        stage_status,
                        stage_ended_at,
                        measured_duration,
                        details_json,
                        metrics_json,
                        int(wall_clock_regressed),
                        error,
                        open_span["stage_attempt_id"],
                    ),
                )
                stage_attempt_id = int(open_span["stage_attempt_id"])
                stage_attempt = int(open_span["stage_attempt"])
            self._connection.execute(
                """
                UPDATE jobs SET state = 'running', current_stage = ?, updated_at = ?
                WHERE job_id = ? AND lease_token = ? AND lease_generation = ?
                """,
                (
                    stage_name if stage_status == "started" else None,
                    recorded_at,
                    job_id,
                    lease_token,
                    lease_generation,
                ),
            )
            self._connection.execute(
                """
                UPDATE attempts SET state = 'running'
                WHERE job_id = ? AND lease_generation = ?
                  AND state IN ('leased', 'running')
                """,
                (job_id, lease_generation),
            )
            return self._event_locked(
                f"stage.{stage_status}",
                now=timestamp,
                actor=str(row["leased_by"]),
                batch_id=str(row["batch_id"]),
                job_id=job_id,
                plan_digest=str(row["plan_digest"]),
                payload={
                    "stage": stage_name,
                    "stage_attempt_id": stage_attempt_id,
                    "stage_attempt": stage_attempt,
                    "lease_generation": lease_generation,
                    "duration_ns": measured_duration,
                    "duration_source": (
                        None if stage_status == "started" else "worker-monotonic"
                    ),
                    "wall_clock_regressed": (
                        False
                        if stage_status == "started"
                        else (
                            datetime.fromisoformat(str(stage_ended_at))
                            < datetime.fromisoformat(stage_started_at)
                        )
                    ),
                    "started_at": stage_started_at,
                    "ended_at": stage_ended_at,
                    "details": stage_details,
                },
            )

    def complete(
        self,
        job_id: str,
        lease_token: str,
        lease_generation: int,
        *,
        result: object | None = None,
        now: float | datetime | None = None,
    ) -> dict[str, object]:
        """Commit success only after every worker stage reached a terminal state."""

        timestamp = self._now(now)
        result_json = _canonical_json({} if result is None else result)
        with self._transaction():
            row = self._require_lease_locked(
                job_id, lease_token, lease_generation, timestamp
            )
            open_span = self._connection.execute(
                """
                SELECT stage FROM stage_attempts
                WHERE job_id = ? AND lease_generation = ? AND state = 'started'
                ORDER BY sequence LIMIT 1
                """,
                (job_id, lease_generation),
            ).fetchone()
            if open_span is not None:
                raise CoordinatorError(
                    "cannot complete job while stage "
                    f"{open_span['stage']} is still running"
                )
            self._connection.execute(
                """
                UPDATE jobs
                SET state = 'complete', lease_token = NULL, leased_by = NULL,
                    lease_expires_at = NULL, result_json = ?, error = NULL,
                    current_stage = NULL, updated_at = ?
                WHERE job_id = ? AND lease_token = ? AND lease_generation = ?
                """,
                (
                    result_json,
                    self._timestamp(timestamp),
                    job_id,
                    lease_token,
                    lease_generation,
                ),
            )
            self._connection.execute(
                """
                UPDATE attempts SET state = 'complete', ended_at = ?
                WHERE job_id = ? AND lease_generation = ?
                  AND state IN ('leased', 'running')
                """,
                (self._timestamp(timestamp), job_id, lease_generation),
            )
            self._event_locked(
                "job.completed",
                now=timestamp,
                actor=str(row["leased_by"]),
                batch_id=str(row["batch_id"]),
                job_id=job_id,
                plan_digest=str(row["plan_digest"]),
                payload={
                    "lease_generation": lease_generation,
                    "result": {} if result is None else result,
                },
            )
        return self.get_job(job_id)

    def complete_job(
        self,
        job_id: str,
        lease_token: str,
        lease_generation: int,
        *,
        result: object | None = None,
        now: float | datetime | None = None,
    ) -> dict[str, object]:
        """Alias for :meth:`complete`."""

        return self.complete(
            job_id,
            lease_token,
            lease_generation,
            result=result,
            now=now,
        )

    def fail(
        self,
        job_id: str,
        lease_token: str,
        lease_generation: int,
        error: str,
        *,
        retryable: bool = True,
        failure_class: str | None = None,
        pathological: bool = False,
        now: float | datetime | None = None,
    ) -> dict[str, object]:
        """Record a fenced failure and requeue while attempts remain."""

        failure = _text(error, "failure error")
        if not isinstance(retryable, bool):
            raise ValueError("retryable must be a boolean")
        if not isinstance(pathological, bool):
            raise ValueError("pathological must be a boolean")
        classified = (
            _text(failure_class, "failure class") if failure_class is not None else None
        )
        timestamp = self._now(now)
        with self._transaction():
            row = self._require_lease_locked(
                job_id, lease_token, lease_generation, timestamp
            )
            state = self._state_locked()
            should_retry = (
                not pathological
                and retryable
                and int(row["attempt_count"]) < int(state["max_attempts"])
            )
            next_state = "queued" if should_retry else "failed"
            retry_delay = (
                self._retry_delay(state, int(row["attempt_count"]))
                if should_retry
                else 0
            )
            eligible_at = timestamp + retry_delay if should_retry else 0
            self._close_open_stage_attempts_locked(
                row,
                now=timestamp,
                reason=failure,
                actor=str(row["leased_by"]),
            )
            self._connection.execute(
                """
                UPDATE jobs
                SET state = ?, lease_token = NULL, leased_by = NULL,
                    lease_expires_at = NULL, current_stage = NULL,
                    error = ?, failure_class = ?, eligible_at = ?, updated_at = ?
                WHERE job_id = ? AND lease_token = ? AND lease_generation = ?
                """,
                (
                    next_state,
                    failure,
                    classified,
                    eligible_at,
                    self._timestamp(timestamp),
                    job_id,
                    lease_token,
                    lease_generation,
                ),
            )
            self._connection.execute(
                """
                UPDATE attempts SET state = 'failed', ended_at = ?, error = ?
                WHERE job_id = ? AND lease_generation = ?
                  AND state IN ('leased', 'running')
                """,
                (
                    self._timestamp(timestamp),
                    failure,
                    job_id,
                    lease_generation,
                ),
            )
            self._event_locked(
                "job.requeued" if should_retry else "job.failed",
                now=timestamp,
                actor=str(row["leased_by"]),
                batch_id=str(row["batch_id"]),
                job_id=job_id,
                plan_digest=str(row["plan_digest"]),
                payload={
                    "reason": failure,
                    "lease_generation": lease_generation,
                    "attempt_count": int(row["attempt_count"]),
                    "retryable": retryable,
                    "failure_class": classified,
                    "retry_cap_reached": (
                        retryable and not pathological and not should_retry
                    ),
                    "pathological": pathological,
                    "retry_delay_seconds": retry_delay,
                    "eligible_at": eligible_at if should_retry else None,
                },
            )
            if pathological:
                pathology_class = classified or "pathological:analysis-timeout"
                self._connection.execute(
                    """
                    INSERT INTO pathological_cell_quarantines (
                        job_id, batch_id, state, reason, failure_class,
                        attempt_count, created_at
                    ) VALUES (?, ?, 'active', ?, ?, ?, ?)
                    """,
                    (
                        job_id,
                        row["batch_id"],
                        failure,
                        pathology_class,
                        int(row["attempt_count"]),
                        self._timestamp(timestamp),
                    ),
                )
                self._event_locked(
                    "job.pathological-quarantined",
                    now=timestamp,
                    actor=str(row["leased_by"]),
                    batch_id=str(row["batch_id"]),
                    job_id=job_id,
                    plan_digest=str(row["plan_digest"]),
                    payload={
                        "reason": failure,
                        "failure_class": pathology_class,
                        "attempt_count": int(row["attempt_count"]),
                        "attempt_evidence_preserved": True,
                    },
                )
            if (
                next_state == "failed"
                and classified is not None
                and classified.startswith("authority-resolution:")
                and int(state["authority_failure_threshold"]) > 0
            ):
                repeated = self._connection.execute(
                    """
                    SELECT COUNT(*) AS count FROM jobs
                    JOIN batches ON batches.batch_id = jobs.batch_id
                    WHERE jobs.active = 1 AND batches.active = 1
                      AND jobs.batch_id = ? AND jobs.state = 'failed'
                      AND jobs.failure_class = ?
                    """,
                    (row["batch_id"], classified),
                ).fetchone()
                failure_count = int(repeated["count"])
                threshold = int(state["authority_failure_threshold"])
                if failure_count >= threshold and not bool(state["paused"]):
                    self._connection.execute(
                        "UPDATE coordinator_state SET paused = 1 WHERE singleton = 1"
                    )
                    self._event_locked(
                        "queue.circuit-opened",
                        now=timestamp,
                        actor="coordinator",
                        batch_id=str(row["batch_id"]),
                        plan_digest=str(row["plan_digest"]),
                        payload={
                            "reason": "repeated authority-resolution failure",
                            "failure_class": classified,
                            "failure_count": failure_count,
                            "threshold": threshold,
                        },
                    )
        return self.get_job(job_id)

    def quarantine_pathological_jobs(
        self,
        batch_id: str,
        job_ids: tuple[str, ...],
        expected_count: int,
        reason: str,
        *,
        actor: str = "operator",
        now: float | datetime | None = None,
    ) -> dict[str, object]:
        """Quarantine an exact reviewed queued/failed set without erasing evidence."""

        selected_batch = _identifier(batch_id, "quarantine batch id")
        count = _positive_integer(expected_count, "quarantine expected count")
        reason_text = _text(reason, "quarantine reason")
        selected_jobs = tuple(
            _identifier(value, "quarantine job id") for value in job_ids
        )
        if len(selected_jobs) != count or len(set(selected_jobs)) != count:
            raise CoordinatorError(
                "quarantine job ids must be unique and match expected count"
            )
        timestamp = self._now(now)
        with self._transaction():
            state = self._state_locked()
            if bool(state["armed"]) or not bool(state["paused"]):
                raise CoordinatorError(
                    "pathological quarantine requires a paused, disarmed queue"
                )
            if state["active_batch_id"] not in (None, selected_batch):
                raise CoordinatorError(
                    "pathological quarantine cannot cross an active admission"
                )
            live = self._connection.execute(
                "SELECT COUNT(*) AS count FROM jobs WHERE state IN ('leased', 'running')"
            ).fetchone()
            if int(live["count"]):
                raise CoordinatorError(
                    "pathological quarantine requires no live leases"
                )
            placeholders = ",".join("?" for _ in selected_jobs)
            rows = self._connection.execute(
                f"SELECT * FROM jobs WHERE batch_id = ? AND active = 1 "
                f"AND job_id IN ({placeholders}) ORDER BY position, job_id",
                (selected_batch, *selected_jobs),
            ).fetchall()
            if len(rows) != count or any(
                row["state"] not in {"queued", "failed"} for row in rows
            ):
                raise CoordinatorError(
                    "quarantine selection changed or contains a live/complete job"
                )
            digest = hashlib.sha256()
            for row in rows:
                job_id = str(row["job_id"])
                existing = self._connection.execute(
                    "SELECT 1 FROM pathological_cell_quarantines "
                    "WHERE job_id = ? AND state = 'active'",
                    (job_id,),
                ).fetchone()
                if existing is not None:
                    raise CoordinatorError(f"job is already quarantined: {job_id}")
                digest.update(job_id.encode("ascii"))
                digest.update(b"\n")
                previous_error = row["error"]
                if row["state"] == "queued":
                    self._connection.execute(
                        "UPDATE jobs SET state = 'failed', error = ?, "
                        "failure_class = 'pathological:operator-quarantine', updated_at = ? "
                        "WHERE job_id = ? AND state = 'queued'",
                        (reason_text, self._timestamp(timestamp), job_id),
                    )
                self._connection.execute(
                    "INSERT INTO pathological_cell_quarantines "
                    "(job_id, batch_id, state, reason, failure_class, attempt_count, created_at) "
                    "VALUES (?, ?, 'active', ?, 'pathological:operator-quarantine', ?, ?)",
                    (
                        job_id,
                        selected_batch,
                        reason_text,
                        int(row["attempt_count"]),
                        self._timestamp(timestamp),
                    ),
                )
                self._event_locked(
                    "job.pathological-quarantined",
                    now=timestamp,
                    actor=actor,
                    batch_id=selected_batch,
                    job_id=job_id,
                    plan_digest=str(row["plan_digest"]),
                    payload={
                        "reason": reason_text,
                        "previous_state": row["state"],
                        "previous_error": previous_error,
                        "attempt_evidence_preserved": True,
                    },
                )
            summary = {
                "batch_id": selected_batch,
                "quarantined": count,
                "job_ids_sha256": digest.hexdigest(),
                "reason": reason_text,
                "attempt_evidence_preserved": True,
            }
            self._event_locked(
                "batch.pathological-jobs-quarantined",
                now=timestamp,
                actor=actor,
                batch_id=selected_batch,
                plan_digest=str(rows[0]["plan_digest"]),
                payload=summary,
            )
            return summary

    def release_pathological_quarantine(
        self,
        batch_id: str,
        expected_count: int,
        reason: str,
        *,
        actor: str = "operator",
        now: float | datetime | None = None,
    ) -> dict[str, object]:
        """Release exactly one reviewed quarantine set back to queued state."""

        selected_batch = _identifier(batch_id, "quarantine batch id")
        count = _positive_integer(expected_count, "quarantine expected count")
        reason_text = _text(reason, "quarantine release reason")
        timestamp = self._now(now)
        with self._transaction():
            state = self._state_locked()
            if bool(state["armed"]) or not bool(state["paused"]):
                raise CoordinatorError(
                    "quarantine release requires a paused, disarmed queue"
                )
            live = self._connection.execute(
                "SELECT COUNT(*) AS count FROM jobs WHERE state IN ('leased', 'running')"
            ).fetchone()
            if int(live["count"]):
                raise CoordinatorError("quarantine release requires no live leases")
            rows = self._connection.execute(
                "SELECT q.*, j.plan_digest FROM pathological_cell_quarantines q "
                "JOIN jobs j ON j.job_id = q.job_id "
                "WHERE q.batch_id = ? AND q.state = 'active' ORDER BY q.quarantine_id",
                (selected_batch,),
            ).fetchall()
            if len(rows) != count:
                raise CoordinatorError(
                    f"quarantine release count mismatch: expected {count}, found {len(rows)}"
                )
            digest = hashlib.sha256()
            for row in rows:
                job_id = str(row["job_id"])
                digest.update(job_id.encode("ascii"))
                digest.update(b"\n")
                self._connection.execute(
                    "UPDATE pathological_cell_quarantines SET state = 'released', "
                    "released_at = ?, release_reason = ? WHERE quarantine_id = ? AND state = 'active'",
                    (self._timestamp(timestamp), reason_text, row["quarantine_id"]),
                )
                self._connection.execute(
                    "UPDATE jobs SET state = 'queued', eligible_at = 0, error = NULL, "
                    "failure_class = NULL, updated_at = ? WHERE job_id = ? AND state = 'failed'",
                    (self._timestamp(timestamp), job_id),
                )
                self._event_locked(
                    "job.pathological-quarantine-released",
                    now=timestamp,
                    actor=actor,
                    batch_id=selected_batch,
                    job_id=job_id,
                    plan_digest=str(row["plan_digest"]),
                    payload={"reason": reason_text, "attempt_evidence_preserved": True},
                )
            return {
                "batch_id": selected_batch,
                "released": count,
                "job_ids_sha256": digest.hexdigest(),
                "reason": reason_text,
                "attempt_evidence_preserved": True,
            }

    def fail_job(
        self,
        job_id: str,
        lease_token: str,
        lease_generation: int,
        error: str,
        *,
        retryable: bool = True,
        failure_class: str | None = None,
        now: float | datetime | None = None,
    ) -> dict[str, object]:
        """Alias for :meth:`fail`."""

        return self.fail(
            job_id,
            lease_token,
            lease_generation,
            error,
            retryable=retryable,
            failure_class=failure_class,
            now=now,
        )

    def requeue_failed_batch(
        self,
        batch_id: str,
        expected_count: int,
        reason: str,
        *,
        actor: str = "operator",
        now: float | datetime | None = None,
    ) -> dict[str, object]:
        """Requeue an exact failed batch without erasing attempt evidence.

        This is deliberately an operator recovery transition rather than a
        ledger edit. It is available only while the queue is both disarmed and
        paused, with no live leases and no admission for a different batch. The
        explicit expected count prevents an operator from broadening a reviewed
        recovery set by accident.
        """

        selected_batch = _identifier(batch_id, "requeue batch id")
        count = _positive_integer(expected_count, "requeue expected count")
        reason_text = _text(reason, "requeue reason")
        timestamp = self._now(now)
        with self._transaction():
            state = self._state_locked()
            if bool(state["armed"]):
                raise CoordinatorError("failed-job recovery requires a disarmed queue")
            if not bool(state["paused"]):
                raise CoordinatorError("failed-job recovery requires a paused queue")
            if state["active_batch_id"] not in (None, selected_batch):
                raise CoordinatorError(
                    "failed-job recovery cannot cross an active batch admission"
                )
            live = self._connection.execute(
                "SELECT COUNT(*) AS count FROM jobs "
                "WHERE state IN ('leased', 'running')"
            ).fetchone()
            if int(live["count"]):
                raise CoordinatorError(
                    "failed-job recovery requires all leases to be terminal"
                )
            batch = self._connection.execute(
                "SELECT * FROM batches WHERE batch_id = ? AND active = 1",
                (selected_batch,),
            ).fetchone()
            if batch is None:
                raise CoordinatorError(f"unknown active batch: {selected_batch}")
            rows = self._connection.execute(
                """
                SELECT * FROM jobs
                WHERE batch_id = ? AND active = 1 AND state = 'failed'
                ORDER BY position, job_id
                """,
                (selected_batch,),
            ).fetchall()
            if len(rows) != count:
                raise CoordinatorError(
                    f"failed-job recovery count mismatch for {selected_batch}: "
                    f"expected {count}, found {len(rows)}"
                )
            digest = hashlib.sha256()
            for row in rows:
                job_id = str(row["job_id"])
                digest.update(job_id.encode("ascii"))
                digest.update(b"\n")
                self._connection.execute(
                    """
                    UPDATE jobs
                    SET state = 'queued', eligible_at = 0,
                        error = NULL, failure_class = NULL, updated_at = ?
                    WHERE job_id = ? AND state = 'failed' AND active = 1
                    """,
                    (self._timestamp(timestamp), job_id),
                )
                self._event_locked(
                    "job.operator-requeued",
                    now=timestamp,
                    actor=actor,
                    batch_id=selected_batch,
                    job_id=job_id,
                    plan_digest=str(row["plan_digest"]),
                    payload={
                        "reason": reason_text,
                        "attempt_count": int(row["attempt_count"]),
                        "previous_error": row["error"],
                        "previous_failure_class": row["failure_class"],
                    },
                )
            summary = {
                "batch_id": selected_batch,
                "requeued": len(rows),
                "job_ids_sha256": digest.hexdigest(),
                "reason": reason_text,
                "attempt_evidence_preserved": True,
            }
            self._event_locked(
                "batch.failed-jobs-requeued",
                now=timestamp,
                actor=actor,
                batch_id=selected_batch,
                plan_digest=str(batch["plan_digest"]),
                payload=summary,
            )
        return summary

    def requeue_interrupted_batch(
        self,
        batch_id: str,
        expected_count: int,
        reason: str,
        *,
        actor: str = "operator",
        now: float | datetime | None = None,
    ) -> dict[str, object]:
        """Fence and requeue an exact stopped-worker set without losing evidence.

        A service-manager stop can terminate workers before they return a
        fenced result, leaving otherwise healthy leases live until their
        expiry. This guarded transition closes open stage spans, terminalises
        their attempts, and preserves every attempt and event before requeueing.
        """

        selected_batch = _identifier(batch_id, "interrupted batch id")
        count = _positive_integer(expected_count, "interrupted expected count")
        reason_text = _text(reason, "interrupted reason")
        timestamp = self._now(now)
        interruption = f"operator interrupted: {reason_text}"
        with self._transaction():
            state = self._state_locked()
            if bool(state["armed"]):
                raise CoordinatorError(
                    "interrupted-job recovery requires a disarmed queue"
                )
            if not bool(state["paused"]):
                raise CoordinatorError(
                    "interrupted-job recovery requires a paused queue"
                )
            if state["active_batch_id"] not in (None, selected_batch):
                raise CoordinatorError(
                    "interrupted-job recovery cannot cross an active batch admission"
                )
            all_live = self._connection.execute(
                "SELECT * FROM jobs WHERE state IN ('leased', 'running') "
                "ORDER BY batch_id, position, job_id"
            ).fetchall()
            rows = [row for row in all_live if row["batch_id"] == selected_batch]
            if len(rows) != count or len(all_live) != count:
                raise CoordinatorError(
                    f"interrupted-job recovery count mismatch for {selected_batch}: "
                    f"expected {count}, found {len(rows)} in batch and "
                    f"{len(all_live)} globally"
                )
            batch = self._connection.execute(
                "SELECT * FROM batches WHERE batch_id = ? AND active = 1",
                (selected_batch,),
            ).fetchone()
            if batch is None:
                raise CoordinatorError(f"unknown active batch: {selected_batch}")
            digest = hashlib.sha256()
            for row in rows:
                job_id = str(row["job_id"])
                digest.update(job_id.encode("ascii"))
                digest.update(b"\n")
                self._close_open_stage_attempts_locked(
                    row,
                    now=timestamp,
                    reason=interruption,
                    actor=actor,
                )
                self._connection.execute(
                    """
                    UPDATE attempts
                    SET state = 'failed', ended_at = ?, error = ?
                    WHERE job_id = ? AND lease_generation = ?
                      AND state IN ('leased', 'running')
                    """,
                    (
                        self._timestamp(timestamp),
                        interruption,
                        job_id,
                        row["lease_generation"],
                    ),
                )
                self._connection.execute(
                    """
                    UPDATE jobs
                    SET state = 'queued', lease_token = NULL, leased_by = NULL,
                        lease_expires_at = NULL, current_stage = NULL,
                        error = NULL, failure_class = NULL, eligible_at = 0,
                        updated_at = ?
                    WHERE job_id = ? AND lease_generation = ?
                      AND state IN ('leased', 'running')
                    """,
                    (
                        self._timestamp(timestamp),
                        job_id,
                        row["lease_generation"],
                    ),
                )
                self._event_locked(
                    "job.operator-interrupted-requeued",
                    now=timestamp,
                    actor=actor,
                    batch_id=selected_batch,
                    job_id=job_id,
                    plan_digest=str(row["plan_digest"]),
                    payload={
                        "reason": reason_text,
                        "attempt_count": int(row["attempt_count"]),
                        "interrupted_generation": int(row["lease_generation"]),
                        "interrupted_worker": str(row["leased_by"]),
                    },
                )
            summary = {
                "batch_id": selected_batch,
                "requeued": len(rows),
                "job_ids_sha256": digest.hexdigest(),
                "reason": reason_text,
                "attempt_evidence_preserved": True,
                "stale_workers_fenced": True,
            }
            self._event_locked(
                "batch.interrupted-jobs-requeued",
                now=timestamp,
                actor=actor,
                batch_id=selected_batch,
                plan_digest=str(batch["plan_digest"]),
                payload=summary,
            )
        return summary

    def pause(
        self,
        reason: str = "operator request",
        *,
        actor: str = "operator",
        now: float | datetime | None = None,
    ) -> dict[str, object]:
        """Stop new claims while leaving existing leases fenced and renewable."""

        reason_text = _text(reason, "pause reason")
        timestamp = self._now(now)
        with self._transaction():
            state = self._state_locked()
            if not bool(state["paused"]):
                self._connection.execute(
                    "UPDATE coordinator_state SET paused = 1 WHERE singleton = 1"
                )
                self._event_locked(
                    "queue.paused",
                    now=timestamp,
                    actor=actor,
                    payload={"reason": reason_text},
                )
        return self.status()

    def resume(
        self,
        *,
        actor: str = "operator",
        now: float | datetime | None = None,
    ) -> dict[str, object]:
        """Allow claims again if the declarative queue is armed."""

        timestamp = self._now(now)
        with self._transaction():
            state = self._state_locked()
            if bool(state["paused"]):
                self._connection.execute(
                    "UPDATE coordinator_state SET paused = 0 WHERE singleton = 1"
                )
                self._event_locked(
                    "queue.resumed", now=timestamp, actor=actor, payload={}
                )
        return self.status()

    def _job_payload(self, row: sqlite3.Row) -> dict[str, object]:
        return {
            "job_id": str(row["job_id"]),
            "batch_id": str(row["batch_id"]),
            "plan_digest": str(row["plan_digest"]),
            "base_cell": str(row["base_cell_id"]),
            "position": int(row["position"]),
            "state": str(row["state"]),
            "blockers": json.loads(row["blockers_json"]),
            "factor_variants": json.loads(row["factor_variants_json"]),
            "attempt_count": int(row["attempt_count"]),
            "eligible_at": float(row["eligible_at"]),
            "lease_generation": int(row["lease_generation"]),
            "lease_token": row["lease_token"],
            "leased_by": row["leased_by"],
            "lease_expires_at": row["lease_expires_at"],
            "current_stage": row["current_stage"],
            "result": (
                json.loads(row["result_json"])
                if row["result_json"] is not None
                else None
            ),
            "error": row["error"],
            "failure_class": row["failure_class"],
            "active": bool(row["active"]),
            "queue_row": json.loads(row["queue_row_json"]),
        }

    @staticmethod
    def _stage_attempt_payload(row: sqlite3.Row) -> dict[str, object]:
        """Return the public, credential-free representation of one span."""

        return {
            "stage_attempt_id": int(row["stage_attempt_id"]),
            "attempt_id": int(row["attempt_id"]),
            "job_id": str(row["job_id"]),
            "attempt_number": int(row["attempt_number"]),
            "lease_generation": int(row["lease_generation"]),
            "worker_id": str(row["worker_id"]),
            "sequence": int(row["sequence"]),
            "stage": str(row["stage"]),
            "stage_attempt": int(row["stage_attempt"]),
            "state": str(row["state"]),
            "started_at": str(row["started_at"]),
            "ended_at": row["ended_at"],
            "duration_ns": (
                int(row["duration_ns"]) if row["duration_ns"] is not None else None
            ),
            "duration_source": row["duration_source"],
            "wall_clock_regressed": bool(row["wall_clock_regressed"]),
            "details": json.loads(row["details_json"]),
            "metrics": json.loads(row["metrics_json"]),
            "error": row["error"],
        }

    def resolution_inputs(
        self, batch_ids: tuple[str, ...] | None = None
    ) -> list[dict[str, object]]:
        """Return exact active job inputs for execution-free authority checks."""

        selected = None
        if batch_ids is not None:
            selected = tuple(
                _identifier(value, "preflight batch id") for value in batch_ids
            )
            if not selected:
                raise ValueError("preflight batch selection cannot be empty")
        query = """
            SELECT jobs.job_id, jobs.batch_id, jobs.state,
                   jobs.factor_variants_json, cells.cell_json,
                   batches.position AS batch_position, jobs.position AS job_position
            FROM jobs
            JOIN batches ON batches.batch_id = jobs.batch_id
            JOIN resolved_cells AS cells
              ON cells.plan_digest = jobs.plan_digest
             AND cells.cell_id = jobs.base_cell_id
            WHERE jobs.active = 1 AND batches.active = 1
        """
        parameters: list[object] = []
        if selected is not None:
            placeholders = ",".join("?" for _value in selected)
            query += f" AND jobs.batch_id IN ({placeholders})"
            parameters.extend(selected)
        query += " ORDER BY batches.position, jobs.position, jobs.job_id"
        rows = self._connection.execute(query, parameters).fetchall()
        return [
            {
                "job_id": str(row["job_id"]),
                "batch_id": str(row["batch_id"]),
                "state": str(row["state"]),
                "batch_position": int(row["batch_position"]),
                "job_position": int(row["job_position"]),
                "factor_variants": json.loads(row["factor_variants_json"]),
                "cell": json.loads(row["cell_json"]),
            }
            for row in rows
        ]

    @staticmethod
    def _attempt_payload(row: sqlite3.Row) -> dict[str, object]:
        ended_at = str(row["ended_at"]) if row["ended_at"] is not None else None
        duration_ns = (
            _elapsed_ns(str(row["started_at"]), ended_at)
            if ended_at is not None
            else None
        )
        wait_from = row["previous_ended_at"] or row["job_created_at"]
        queue_wait_duration_ns = (
            _elapsed_ns(str(wait_from), str(row["started_at"]))
            if wait_from is not None
            else None
        )
        return {
            "attempt_id": int(row["attempt_id"]),
            "job_id": str(row["job_id"]),
            "attempt_number": int(row["attempt_number"]),
            "lease_generation": int(row["lease_generation"]),
            "worker_id": str(row["worker_id"]),
            "state": str(row["state"]),
            "started_at": str(row["started_at"]),
            "lease_expires_at": float(row["lease_expires_at"]),
            "ended_at": ended_at,
            "duration_ns": duration_ns,
            "duration_source": (
                "coordinator-wall-clock" if duration_ns is not None else None
            ),
            "queue_wait_duration_ns": queue_wait_duration_ns,
            "queue_wait_source": (
                "coordinator-wall-clock" if queue_wait_duration_ns is not None else None
            ),
            "queue_wait_basis": "wall-clock-includes-disarmed-paused-readiness",
            "error": row["error"],
        }

    def get_job(self, job_id: str) -> dict[str, object]:
        """Return one durable job record."""

        row = self._connection.execute(
            "SELECT * FROM jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
        if row is None:
            raise KeyError(job_id)
        return self._job_payload(row)

    def touch_worker(
        self,
        worker_id: str,
        *,
        transport: str,
        pools: tuple[str, ...],
        metadata: Mapping[str, object] | None = None,
        now: float | datetime | None = None,
    ) -> dict[str, object]:
        """Register or heartbeat one authenticated, typed worker identity."""

        worker = _text(worker_id, "worker id")
        if transport not in {"local", "remote-http"}:
            raise ValueError(f"unsupported worker transport: {transport}")
        if not pools or any(pool not in WORKER_POOLS for pool in pools):
            raise ValueError("worker pools contain an unsupported pool")
        if len(set(pools)) != len(pools):
            raise ValueError("worker pools contain duplicates")
        timestamp = self._now(now)
        occurred_at = self._timestamp(timestamp)
        with self._transaction():
            existing = self._connection.execute(
                "SELECT * FROM workers WHERE worker_id = ?", (worker,)
            ).fetchone()
            metadata_document = (
                json.loads(existing["metadata_json"]) if existing is not None else {}
            )
            metadata_document.update(dict(metadata or {}))
            metadata_json = _canonical_json(metadata_document)
            self._connection.execute(
                """
                INSERT INTO workers (
                    worker_id, transport, pools_json, state, metadata_json,
                    registered_at, last_seen_at
                ) VALUES (?, ?, ?, 'online', ?, ?, ?)
                ON CONFLICT(worker_id) DO UPDATE SET
                    transport = excluded.transport,
                    pools_json = excluded.pools_json,
                    state = 'online',
                    metadata_json = excluded.metadata_json,
                    last_seen_at = excluded.last_seen_at
                """,
                (
                    worker,
                    transport,
                    _canonical_json(list(pools)),
                    metadata_json,
                    occurred_at,
                    occurred_at,
                ),
            )
            if existing is None:
                self._event_locked(
                    "worker.registered",
                    now=timestamp,
                    actor=worker,
                    payload={"transport": transport, "pools": list(pools)},
                )
        row = self._connection.execute(
            "SELECT * FROM workers WHERE worker_id = ?", (worker,)
        ).fetchone()
        return self._worker_payload(row)

    def pool_status(self, pool: str) -> dict[str, object]:
        """Return actionable job counts for one fail-closed worker pool."""

        if pool not in WORKER_POOLS:
            raise ValueError(f"unsupported worker pool: {pool}")
        state = self._state_locked()
        rows = self._connection.execute("""
            SELECT jobs.state, jobs.eligible_at, cells.cell_json
            FROM jobs
            JOIN batches ON batches.batch_id = jobs.batch_id
            JOIN resolved_cells AS cells
              ON cells.plan_digest = jobs.plan_digest
             AND cells.cell_id = jobs.base_cell_id
            WHERE jobs.active = 1 AND batches.active = 1
            """).fetchall()
        accepted = [
            row
            for row in rows
            if worker_pool_accepts_cell(pool, json.loads(row["cell_json"]))
        ]
        counts = {job_state: 0 for job_state in sorted(_JOB_STATES)}
        for row in accepted:
            counts[str(row["state"])] += 1
        now = self._now()
        eligible = sum(
            1
            for row in accepted
            if row["state"] == "queued" and float(row["eligible_at"]) <= now
        )
        remaining = counts["queued"] + counts["leased"] + counts["running"]
        return {
            "pool": pool,
            "armed": bool(state["armed"]),
            "paused": bool(state["paused"]),
            "counts": counts,
            "eligible": eligible,
            "remaining": remaining,
            "drained": remaining == 0,
        }

    @staticmethod
    def _worker_payload(row: sqlite3.Row) -> dict[str, object]:
        last_seen = datetime.fromisoformat(str(row["last_seen_at"]))
        age = (datetime.now(timezone.utc) - last_seen).total_seconds()
        return {
            "worker_id": str(row["worker_id"]),
            "transport": str(row["transport"]),
            "pools": json.loads(row["pools_json"]),
            "state": "online" if age <= 180 else "offline",
            "metadata": json.loads(row["metadata_json"]),
            "registered_at": str(row["registered_at"]),
            "last_seen_at": str(row["last_seen_at"]),
        }

    def status(self) -> dict[str, object]:
        """Return compact queue status and active-state counts."""

        state = self._state_locked()
        rows = self._connection.execute("""
            SELECT jobs.state, COUNT(*) AS count
            FROM jobs JOIN batches ON batches.batch_id = jobs.batch_id
            WHERE jobs.active = 1 AND batches.active = 1
            GROUP BY jobs.state
            """).fetchall()
        counts = {job_state: 0 for job_state in sorted(_JOB_STATES)}
        counts.update({str(row["state"]): int(row["count"]) for row in rows})
        queued = counts["queued"]
        now = self._now()
        eligible = self._connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM jobs JOIN batches ON batches.batch_id = jobs.batch_id
            WHERE jobs.active = 1 AND batches.active = 1
              AND jobs.state = 'queued' AND jobs.eligible_at <= ?
            """,
            (now,),
        ).fetchone()
        claimable_jobs = int(eligible["count"])
        active_workers = counts["leased"] + counts["running"]
        max_workers = int(state["max_workers"])
        armed = bool(state["armed"])
        paused = bool(state["paused"])
        if not armed:
            runtime_status = "disarmed"
        elif paused:
            runtime_status = "paused"
        elif queued:
            runtime_status = "ready"
        elif counts["leased"] or counts["running"]:
            runtime_status = "active"
        else:
            runtime_status = "idle"
        last_event = self._connection.execute(
            "SELECT MAX(event_id) AS event_id FROM events"
        ).fetchone()
        active_pathologies = self._connection.execute(
            "SELECT COUNT(*) AS count FROM pathological_cell_quarantines "
            "WHERE state = 'active'"
        ).fetchone()
        return {
            "schema_version": SNAPSHOT_SCHEMA,
            "status": runtime_status,
            "config_name": state["config_name"],
            "config_path": state["config_path"],
            "armed": armed,
            "paused": paused,
            "max_workers": max_workers,
            "performance_profile": (
                json.loads(state["performance_json"])
                if state["performance_json"] is not None
                else None
            ),
            "active_workers": active_workers,
            "available_worker_slots": max(0, max_workers - active_workers),
            "poll_seconds": int(state["poll_seconds"]),
            "lease_seconds": int(state["lease_seconds"]),
            "max_attempts": int(state["max_attempts"]),
            "retry_backoff_seconds": int(state["retry_backoff_seconds"]),
            "retry_backoff_max_seconds": int(state["retry_backoff_max_seconds"]),
            "authority_failure_threshold": int(state["authority_failure_threshold"]),
            "operations": json.loads(state["operations_json"]),
            "execution_block": self.execution_block(),
            "sync_generation": int(state["sync_generation"]),
            "synced_at": state["synced_at"],
            "counts": counts,
            "claimable": claimable_jobs if armed and not paused else 0,
            "retry_wait": queued - claimable_jobs,
            "pathological_quarantines": int(active_pathologies["count"]),
            "last_event_id": int(last_event["event_id"] or 0),
        }

    def events(self, *, after_event_id: int = 0) -> list[dict[str, object]]:
        """Return append-only events after an event cursor."""

        rows = self._connection.execute(
            "SELECT * FROM events WHERE event_id > ? ORDER BY event_id",
            (after_event_id,),
        ).fetchall()
        return [
            {
                "event_id": int(row["event_id"]),
                "occurred_at": str(row["occurred_at"]),
                "event_type": str(row["event_type"]),
                "actor": str(row["actor"]),
                "batch_id": row["batch_id"],
                "job_id": row["job_id"],
                "plan_digest": row["plan_digest"],
                "payload": json.loads(row["payload_json"]),
            }
            for row in rows
        ]

    def timings(self, *, limit: int = DEFAULT_TIMING_LIMIT) -> dict[str, object]:
        """Return bounded timing history and explicitly sourced aggregates.

        Stage percentiles use only successful worker-monotonic spans.  Failed,
        skipped, open and coordinator-interrupted spans remain visible in state
        counts and recent history but cannot contaminate performance estimates.
        Workflow and queue-wait durations are labelled wall-clock observations.
        """

        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or limit < 1
            or limit > MAX_TIMING_LIMIT
        ):
            raise ValueError(f"timing limit must be 1-{MAX_TIMING_LIMIT}")

        stage_state_rows = self._connection.execute("""
            SELECT stage, state, COUNT(*) AS count
            FROM stage_attempts
            GROUP BY stage, state
            ORDER BY stage, state
            """).fetchall()
        stage_states: dict[str, dict[str, int]] = {}
        for row in stage_state_rows:
            stage_states.setdefault(str(row["stage"]), {})[str(row["state"])] = int(
                row["count"]
            )

        stage_sample_rows = self._connection.execute(
            """
            SELECT stage, duration_ns FROM stage_attempts
            WHERE state = 'completed'
              AND duration_source = 'worker-monotonic'
            ORDER BY stage_attempt_id DESC
            LIMIT ?
            """,
            (MAX_TIMING_SAMPLES + 1,),
        ).fetchall()
        stage_samples_truncated = len(stage_sample_rows) > MAX_TIMING_SAMPLES
        stage_durations: dict[str, list[int]] = {}
        for row in stage_sample_rows[:MAX_TIMING_SAMPLES]:
            stage_durations.setdefault(str(row["stage"]), []).append(
                int(row["duration_ns"])
            )
        stage_names = sorted(set(stage_states) | set(stage_durations))
        stages = [
            {
                "stage": stage,
                "sample_count": len(stage_durations.get(stage, [])),
                "state_counts": {
                    state: stage_states.get(stage, {}).get(state, 0)
                    for state in ("started", *STAGE_TERMINAL_STATES)
                },
                "duration_source": "worker-monotonic",
                "duration_ns": _percentiles(stage_durations.get(stage, [])),
            }
            for stage in stage_names
        ]

        workflow_state_rows = self._connection.execute("""
            SELECT resolved_cells.matrix_id AS workflow, attempts.state,
                   COUNT(*) AS count
            FROM attempts
            JOIN jobs ON jobs.job_id = attempts.job_id
            JOIN resolved_cells
              ON resolved_cells.plan_digest = jobs.plan_digest
             AND resolved_cells.cell_id = jobs.base_cell_id
            GROUP BY resolved_cells.matrix_id, attempts.state
            ORDER BY resolved_cells.matrix_id, attempts.state
            """).fetchall()
        workflow_states: dict[str, dict[str, int]] = {}
        for row in workflow_state_rows:
            workflow_states.setdefault(str(row["workflow"]), {})[str(row["state"])] = (
                int(row["count"])
            )

        workflow_sample_rows = self._connection.execute(
            """
            SELECT attempts.*, jobs.created_at AS job_created_at,
                   resolved_cells.matrix_id AS workflow,
                   (
                       SELECT previous.ended_at FROM attempts AS previous
                       WHERE previous.job_id = attempts.job_id
                         AND previous.attempt_number = attempts.attempt_number - 1
                   ) AS previous_ended_at
            FROM attempts
            JOIN jobs ON jobs.job_id = attempts.job_id
            JOIN resolved_cells
              ON resolved_cells.plan_digest = jobs.plan_digest
             AND resolved_cells.cell_id = jobs.base_cell_id
            WHERE attempts.state = 'complete' AND attempts.ended_at IS NOT NULL
            ORDER BY attempts.attempt_id DESC
            LIMIT ?
            """,
            (MAX_TIMING_SAMPLES + 1,),
        ).fetchall()
        workflow_samples_truncated = len(workflow_sample_rows) > MAX_TIMING_SAMPLES
        workflow_durations: dict[str, list[int]] = {}
        workflow_waits: dict[str, list[int]] = {}
        completed_durations: list[int] = []
        for row in workflow_sample_rows[:MAX_TIMING_SAMPLES]:
            payload = self._attempt_payload(row)
            workflow = str(row["workflow"])
            duration_ns = payload["duration_ns"]
            if isinstance(duration_ns, int):
                workflow_durations.setdefault(workflow, []).append(duration_ns)
                completed_durations.append(duration_ns)
            queue_wait_ns = payload["queue_wait_duration_ns"]
            if isinstance(queue_wait_ns, int):
                workflow_waits.setdefault(workflow, []).append(queue_wait_ns)
        workflow_names = sorted(set(workflow_states) | set(workflow_durations))
        workflows = [
            {
                "workflow": workflow,
                "sample_count": len(workflow_durations.get(workflow, [])),
                "state_counts": {
                    state: workflow_states.get(workflow, {}).get(state, 0)
                    for state in ("leased", "running", "complete", "failed", "expired")
                },
                "duration_source": "coordinator-wall-clock",
                "duration_ns": _percentiles(workflow_durations.get(workflow, [])),
                "queue_wait_source": "coordinator-wall-clock",
                "queue_wait_basis": "wall-clock-includes-disarmed-paused-readiness",
                "queue_wait_duration_ns": _percentiles(
                    workflow_waits.get(workflow, [])
                ),
            }
            for workflow in workflow_names
        ]

        counts = self._connection.execute("""
            SELECT
                (SELECT COUNT(*) FROM stage_attempts) AS stage_spans,
                (SELECT COUNT(*) FROM stage_attempts
                 WHERE state = 'completed'
                   AND duration_source = 'worker-monotonic') AS completed_stages,
                (SELECT COUNT(*) FROM attempts
                 WHERE state = 'complete' AND ended_at IS NOT NULL) AS workflows
            """).fetchone()
        recent_rows = self._connection.execute(
            """
            SELECT * FROM stage_attempts
            ORDER BY stage_attempt_id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        positive_workflow_durations = [
            duration for duration in completed_durations if duration > 0
        ]
        throughput = None
        if positive_workflow_durations:
            mean_ns = sum(positive_workflow_durations) / len(
                positive_workflow_durations
            )
            throughput = {
                "kind": "successful-attempt-service-rate-proxy",
                "sample_count": len(positive_workflow_durations),
                "basis": "completed-successful-final-attempt-wall-clock",
                "scope": "excludes-retries-queue-idle-and-worker-concurrency",
                "service_jobs_per_hour": 3_600_000_000_000 / mean_ns,
            }
        return {
            "schema_version": TIMINGS_SCHEMA,
            "generated_at": self._timestamp(self._now()),
            "limit": limit,
            "aggregate_sample_limit": MAX_TIMING_SAMPLES,
            "aggregates_truncated": (
                stage_samples_truncated or workflow_samples_truncated
            ),
            "sample_policy": {
                "stage_percentiles": "completed-worker-monotonic-only",
                "workflow_percentiles": "completed-attempt-wall-clock-only",
                "interrupted_spans": "visible-but-excluded-from-percentiles",
                "aggregate_selection": "most-recent-global-sample-window",
                "queue_wait_basis": ("wall-clock-includes-disarmed-paused-readiness"),
                "service_rate": (
                    "successful-final-attempts-only; excludes retries, queue, idle, "
                    "and concurrency"
                ),
            },
            "sample_counts": {
                "stage_spans": int(counts["stage_spans"]),
                "completed_stage_spans": int(counts["completed_stages"]),
                "completed_workflows": int(counts["workflows"]),
            },
            "throughput": throughput,
            # No heterogeneous queue ETA is inferred from sparse history.  A
            # later estimator can populate this using matching workflow data.
            "eta": None,
            "stages": stages,
            "workflows": workflows,
            "recent": [self._stage_attempt_payload(row) for row in recent_rows],
        }

    def snapshot(
        self,
        *,
        include_inactive: bool = False,
        include_events: bool = True,
        attempt_limit: int | None = None,
        stage_attempt_limit: int | None = None,
    ) -> dict[str, object]:
        """Return an inspectable snapshot of queue, jobs, attempts and events."""

        for limit_name, limit in (
            ("attempt_limit", attempt_limit),
            ("stage_attempt_limit", stage_attempt_limit),
        ):
            if limit is not None and (
                not isinstance(limit, int)
                or isinstance(limit, bool)
                or limit < 1
                or limit > MAX_TIMING_LIMIT
            ):
                raise ValueError(f"{limit_name} must be 1-{MAX_TIMING_LIMIT}")

        status = self.status()
        active_clause = "" if include_inactive else "WHERE active = 1"
        batches = self._connection.execute(f"""
            SELECT * FROM batches {active_clause}
            ORDER BY active DESC, position, batch_id
            """).fetchall()
        job_active_clause = (
            "" if include_inactive else "WHERE jobs.active = 1 AND batches.active = 1"
        )
        jobs = self._connection.execute(f"""
            SELECT jobs.*, batches.position AS batch_position
            FROM jobs JOIN batches ON batches.batch_id = jobs.batch_id
            {job_active_clause}
            ORDER BY batches.active DESC, batches.position, jobs.position, jobs.job_id
            """).fetchall()
        attempt_count = int(
            self._connection.execute(
                """
                SELECT COUNT(*) FROM attempts
                JOIN jobs ON jobs.job_id = attempts.job_id
                WHERE ? OR jobs.active = 1
                """,
                (int(include_inactive),),
            ).fetchone()[0]
        )
        attempt_sql = """
            SELECT attempts.*, jobs.created_at AS job_created_at,
                   (
                       SELECT previous.ended_at FROM attempts AS previous
                       WHERE previous.job_id = attempts.job_id
                         AND previous.attempt_number = attempts.attempt_number - 1
                   ) AS previous_ended_at
            FROM attempts
            JOIN jobs ON jobs.job_id = attempts.job_id
            WHERE ? OR jobs.active = 1
            ORDER BY attempts.attempt_id DESC
        """
        attempt_parameters: tuple[object, ...] = (int(include_inactive),)
        if attempt_limit is not None:
            attempt_sql += " LIMIT ?"
            attempt_parameters += (attempt_limit,)
        attempts = list(
            reversed(
                self._connection.execute(attempt_sql, attempt_parameters).fetchall()
            )
        )
        workers = self._connection.execute(
            "SELECT * FROM workers ORDER BY worker_id"
        ).fetchall()
        stage_count = int(
            self._connection.execute(
                """
                SELECT COUNT(*) FROM stage_attempts
                JOIN jobs ON jobs.job_id = stage_attempts.job_id
                WHERE ? OR jobs.active = 1
                """,
                (int(include_inactive),),
            ).fetchone()[0]
        )
        stage_sql = """
            SELECT stage_attempts.* FROM stage_attempts
            JOIN jobs ON jobs.job_id = stage_attempts.job_id
            WHERE ? OR jobs.active = 1
            ORDER BY stage_attempts.stage_attempt_id DESC
        """
        stage_parameters: tuple[object, ...] = (int(include_inactive),)
        if stage_attempt_limit is not None:
            stage_sql += " LIMIT ?"
            stage_parameters += (stage_attempt_limit,)
        stage_attempts = list(
            reversed(self._connection.execute(stage_sql, stage_parameters).fetchall())
        )
        result = {
            **status,
            "batches": [
                {
                    "id": str(row["batch_id"]),
                    "name": str(row["name"]),
                    "position": int(row["position"]),
                    "plan_digest": str(row["plan_digest"]),
                    "plan_path": str(row["plan_path"]),
                    "matrices": (
                        json.loads(row["matrices_json"])
                        if row["matrices_json"] is not None
                        else None
                    ),
                    "active": bool(row["active"]),
                }
                for row in batches
            ],
            "jobs": [
                {**self._job_payload(row), "batch_position": int(row["batch_position"])}
                for row in jobs
            ],
            "attempts": [self._attempt_payload(row) for row in attempts],
            "attempts_total": attempt_count,
            "attempts_truncated": attempt_count > len(attempts),
            "workers": [self._worker_payload(row) for row in workers],
            "stage_attempts": [
                self._stage_attempt_payload(row) for row in stage_attempts
            ],
            "stage_attempts_total": stage_count,
            "stage_attempts_truncated": stage_count > len(stage_attempts),
        }
        if include_events:
            result["events"] = self.events()
        return result


def sync_queue(
    database_path: str | Path,
    queue_path: str | Path,
    project_root: str | Path,
) -> dict[str, object]:
    """One-shot convenience helper for resolving and synchronizing a queue."""

    with Coordinator(database_path, project_root) as coordinator:
        return coordinator.sync_queue(queue_path)
