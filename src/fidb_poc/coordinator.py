"""Durable, execution-free coordination for resolved FIDB build plans.

The coordinator is deliberately a state machine, not a job runner.  Queue TOML
selects reviewed plan requests, :func:`resolve_plan` freezes those requests, and
SQLite records queue, lease and stage transitions.  A separate worker may use a
claimed cell, but no command is accepted or executed by this module.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
import time
import tomllib
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator, Mapping

from .operations_policy import OperationsPolicy, load_operations_policy
from .plan_request import RESOLVED_SCHEMA, resolve_plan

QUEUE_SCHEMA = "fidb-queue/v1"
SNAPSHOT_SCHEMA = "fidb-coordinator-snapshot/v1"
JOB_SCHEMA = "fidb-job/v1"
TIMINGS_SCHEMA = "fidb-timings/v1"

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_JOB_STATES = {
    "queued",
    "blocked",
    "leased",
    "running",
    "complete",
    "failed",
}
_LEASED_STATES = {"leased", "running"}
WORKER_POOLS = ("library-local",)
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


@dataclass(frozen=True)
class BatchConfig:
    """One ordered batch from a queue configuration."""

    id: str
    name: str
    plan: Path
    plan_path: str
    matrices: tuple[str, ...] | None = None


@dataclass(frozen=True)
class QueueConfig:
    """Validated ``fidb-queue/v1`` configuration."""

    schema_version: str
    name: str
    batch_order: tuple[str, ...]
    armed: bool
    max_workers: int
    poll_seconds: int
    lease_seconds: int
    max_attempts: int
    retry_backoff_seconds: int
    retry_backoff_max_seconds: int
    operations: OperationsPolicy
    batches: tuple[BatchConfig, ...]
    project_root: Path
    source_path: Path

    @classmethod
    def load(cls, path: str | Path, project_root: str | Path) -> "QueueConfig":
        """Load and fail-closed validate queue TOML.

        Plan paths must be relative paths which resolve to regular files below
        ``project_root``.  The optional ``matrices`` field on a batch limits the
        resolved matrices materialized by that batch.
        """

        source_path = Path(path).resolve()
        root = Path(project_root).resolve()
        document = tomllib.loads(source_path.read_text(encoding="utf-8"))
        _only_keys(
            document,
            {
                "schema_version",
                "name",
                "queue",
                "batch",
                "schedule",
                "resources",
                "notifications",
            },
            "queue document",
        )
        if document.get("schema_version") != QUEUE_SCHEMA:
            raise ValueError(
                f"unsupported or missing queue schema_version in {source_path}"
            )
        name = _text(document.get("name"), "queue name")

        queue = document.get("queue")
        if not isinstance(queue, dict):
            raise ValueError("queue document must contain a [queue] table")
        required_queue_fields = {
            "batch_order",
            "armed",
            "max_workers",
            "poll_seconds",
            "lease_seconds",
            "max_attempts",
        }
        _only_keys(
            queue,
            required_queue_fields
            | {"retry_backoff_seconds", "retry_backoff_max_seconds"},
            "queue table",
        )
        missing_queue_fields = required_queue_fields - set(queue)
        if missing_queue_fields:
            raise ValueError(
                "queue table is missing required fields: "
                f"{sorted(missing_queue_fields)}"
            )
        batch_order = _identifiers(queue["batch_order"], "queue batch_order")
        armed = queue["armed"]
        if not isinstance(armed, bool):
            raise ValueError("queue armed must be a boolean")
        max_workers = _positive_integer(queue["max_workers"], "queue max_workers")
        poll_seconds = _positive_integer(queue["poll_seconds"], "queue poll_seconds")
        lease_seconds = _positive_integer(queue["lease_seconds"], "queue lease_seconds")
        max_attempts = _positive_integer(queue["max_attempts"], "queue max_attempts")
        retry_backoff_seconds = _nonnegative_integer(
            queue.get("retry_backoff_seconds", 0), "queue retry_backoff_seconds"
        )
        retry_backoff_max_seconds = _nonnegative_integer(
            queue.get("retry_backoff_max_seconds", retry_backoff_seconds),
            "queue retry_backoff_max_seconds",
        )
        if retry_backoff_max_seconds < retry_backoff_seconds:
            raise ValueError(
                "queue retry_backoff_max_seconds must be at least "
                "retry_backoff_seconds"
            )
        operations = load_operations_policy(document, root)

        raw_batches = document.get("batch")
        if not isinstance(raw_batches, list) or not raw_batches:
            raise ValueError("queue document must contain at least one [[batch]] table")
        batches: list[BatchConfig] = []
        seen_batch_ids: set[str] = set()
        for position, row in enumerate(raw_batches, start=1):
            if not isinstance(row, dict):
                raise ValueError(f"batch {position} must be a table")
            _only_keys(row, {"id", "name", "plan", "matrices"}, f"batch {position}")
            batch_id = _identifier(row.get("id"), f"batch {position} id")
            if batch_id in seen_batch_ids:
                raise ValueError(f"duplicate batch id: {batch_id}")
            seen_batch_ids.add(batch_id)
            batch_name = _text(row.get("name"), f"batch {batch_id} name")
            relative_plan = _text(row.get("plan"), f"batch {batch_id} plan")
            plan_fragment = Path(relative_plan)
            if plan_fragment.is_absolute():
                raise ValueError(f"batch {batch_id} plan must be a relative path")
            plan_path = (root / plan_fragment).resolve()
            try:
                normalized_plan = str(plan_path.relative_to(root))
            except ValueError as error:
                raise ValueError(
                    f"batch {batch_id} plan is outside project root: {relative_plan}"
                ) from error
            if not plan_path.is_file():
                raise ValueError(
                    f"batch {batch_id} plan is not an in-project file: {relative_plan}"
                )
            matrices = None
            if "matrices" in row:
                matrices = _identifiers(row["matrices"], f"batch {batch_id} matrices")
            batches.append(
                BatchConfig(
                    id=batch_id,
                    name=batch_name,
                    plan=plan_path,
                    plan_path=normalized_plan,
                    matrices=matrices,
                )
            )

        if set(batch_order) != seen_batch_ids or len(batch_order) != len(batches):
            missing = seen_batch_ids - set(batch_order)
            extra = set(batch_order) - seen_batch_ids
            raise ValueError(
                "queue batch_order must contain each batch id exactly once; "
                f"missing={sorted(missing)}, extra={sorted(extra)}"
            )
        by_id = {batch.id: batch for batch in batches}
        ordered_batches = tuple(by_id[batch_id] for batch_id in batch_order)
        return cls(
            schema_version=QUEUE_SCHEMA,
            name=name,
            batch_order=batch_order,
            armed=armed,
            max_workers=max_workers,
            poll_seconds=poll_seconds,
            lease_seconds=lease_seconds,
            max_attempts=max_attempts,
            retry_backoff_seconds=retry_backoff_seconds,
            retry_backoff_max_seconds=retry_backoff_max_seconds,
            operations=operations,
            batches=ordered_batches,
            project_root=root,
            source_path=source_path,
        )


def load_queue_config(path: str | Path, project_root: str | Path) -> QueueConfig:
    """Functional alias for :meth:`QueueConfig.load`."""

    return QueueConfig.load(path, project_root)


def _only_keys(row: Mapping[str, object], allowed: set[str], context: str) -> None:
    unknown = set(row) - allowed
    if unknown:
        raise ValueError(f"{context} contains unsupported fields: {sorted(unknown)}")


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(
            f"{context} must be a non-empty string without outer whitespace"
        )
    return value


def _identifier(value: object, context: str) -> str:
    result = _text(value, context)
    if not _IDENTIFIER.fullmatch(result):
        raise ValueError(
            f"{context} must contain only letters, digits, '.', '_' or '-'"
        )
    return result


def _identifiers(value: object, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{context} must be a non-empty array")
    result = tuple(_identifier(item, context) for item in value)
    if len(set(result)) != len(result):
        raise ValueError(f"{context} contains duplicates")
    return result


def _positive_integer(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{context} must be a positive integer")
    return value


def _nonnegative_integer(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{context} must be a non-negative integer")
    return value


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
            (kind == "native" and executor == "native-local")
            or (kind == "source-library" and executor == "local")
            or (kind == "archive-library" and executor == "archive-local")
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
                poll_seconds INTEGER NOT NULL CHECK (poll_seconds > 0),
                lease_seconds INTEGER NOT NULL CHECK (lease_seconds > 0),
                max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
                retry_backoff_seconds INTEGER NOT NULL DEFAULT 0
                    CHECK (retry_backoff_seconds >= 0),
                retry_backoff_max_seconds INTEGER NOT NULL DEFAULT 0
                    CHECK (retry_backoff_max_seconds >= retry_backoff_seconds),
                operations_json TEXT NOT NULL DEFAULT '{}',
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
        if "operations_json" not in state_columns:
            self._connection.execute(
                "ALTER TABLE coordinator_state ADD COLUMN operations_json "
                "TEXT NOT NULL DEFAULT '{}'"
            )
        job_columns = {
            str(row["name"])
            for row in self._connection.execute("PRAGMA table_info(jobs)").fetchall()
        }
        if "eligible_at" not in job_columns:
            self._connection.execute(
                "ALTER TABLE jobs ADD COLUMN eligible_at REAL NOT NULL DEFAULT 0"
            )
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
                max_workers, poll_seconds, lease_seconds, max_attempts,
                retry_backoff_seconds, retry_backoff_max_seconds,
                operations_json,
                sync_generation, synced_at
            ) VALUES (1, NULL, NULL, 0, 0, 4, 5, 3600, 3, 0, 0, '{}', 0, NULL)
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
                    max_workers = ?, poll_seconds = ?, lease_seconds = ?, max_attempts = ?,
                    retry_backoff_seconds = ?, retry_backoff_max_seconds = ?,
                    operations_json = ?,
                    sync_generation = ?, synced_at = ?
                WHERE singleton = 1
                """,
                (
                    queue_config.name,
                    str(queue_config.source_path),
                    int(queue_config.armed),
                    queue_config.max_workers,
                    queue_config.poll_seconds,
                    queue_config.lease_seconds,
                    queue_config.max_attempts,
                    queue_config.retry_backoff_seconds,
                    queue_config.retry_backoff_max_seconds,
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

    def _state_locked(self) -> sqlite3.Row:
        state = self._connection.execute(
            "SELECT * FROM coordinator_state WHERE singleton = 1"
        ).fetchone()
        if state is None:  # pragma: no cover - protected by schema initialization
            raise CoordinatorError("coordinator state is missing")
        return state

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
    ) -> dict[str, object] | None:
        """Atomically claim the first eligible job in batch and job order."""

        worker = _text(worker_id, "worker id")
        if pool is not None and pool not in WORKER_POOLS:
            raise ValueError(f"unsupported worker pool: {pool}")
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
                  AND jobs.attempt_count < ?
                ORDER BY batches.position, jobs.position, jobs.job_id
                """
            if pool is None:
                claim_query += " LIMIT 1"
            candidates = self._connection.execute(
                claim_query,
                (timestamp, int(state["max_attempts"])),
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
                    current_stage = NULL, error = NULL, eligible_at = 0, updated_at = ?
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
        now: float | datetime | None = None,
    ) -> dict[str, object]:
        """Record a fenced failure and requeue while attempts remain."""

        failure = _text(error, "failure error")
        if not isinstance(retryable, bool):
            raise ValueError("retryable must be a boolean")
        timestamp = self._now(now)
        with self._transaction():
            row = self._require_lease_locked(
                job_id, lease_token, lease_generation, timestamp
            )
            state = self._state_locked()
            should_retry = retryable and int(row["attempt_count"]) < int(
                state["max_attempts"]
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
                    error = ?, eligible_at = ?, updated_at = ?
                WHERE job_id = ? AND lease_token = ? AND lease_generation = ?
                """,
                (
                    next_state,
                    failure,
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
                    "retry_cap_reached": retryable and not should_retry,
                    "retry_delay_seconds": retry_delay,
                    "eligible_at": eligible_at if should_retry else None,
                },
            )
        return self.get_job(job_id)

    def fail_job(
        self,
        job_id: str,
        lease_token: str,
        lease_generation: int,
        error: str,
        *,
        retryable: bool = True,
        now: float | datetime | None = None,
    ) -> dict[str, object]:
        """Alias for :meth:`fail`."""

        return self.fail(
            job_id,
            lease_token,
            lease_generation,
            error,
            retryable=retryable,
            now=now,
        )

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
        metadata_document = dict(metadata or {})
        metadata_json = _canonical_json(metadata_document)
        timestamp = self._now(now)
        occurred_at = self._timestamp(timestamp)
        with self._transaction():
            existing = self._connection.execute(
                "SELECT * FROM workers WHERE worker_id = ?", (worker,)
            ).fetchone()
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
        return {
            "schema_version": SNAPSHOT_SCHEMA,
            "status": runtime_status,
            "config_name": state["config_name"],
            "config_path": state["config_path"],
            "armed": armed,
            "paused": paused,
            "max_workers": max_workers,
            "active_workers": active_workers,
            "available_worker_slots": max(0, max_workers - active_workers),
            "poll_seconds": int(state["poll_seconds"]),
            "lease_seconds": int(state["lease_seconds"]),
            "max_attempts": int(state["max_attempts"]),
            "retry_backoff_seconds": int(state["retry_backoff_seconds"]),
            "retry_backoff_max_seconds": int(state["retry_backoff_max_seconds"]),
            "operations": json.loads(state["operations_json"]),
            "sync_generation": int(state["sync_generation"]),
            "synced_at": state["synced_at"],
            "counts": counts,
            "claimable": claimable_jobs if armed and not paused else 0,
            "retry_wait": queued - claimable_jobs,
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
        stage_attempt_limit: int | None = None,
    ) -> dict[str, object]:
        """Return an inspectable snapshot of queue, jobs, attempts and events."""

        if stage_attempt_limit is not None:
            if (
                not isinstance(stage_attempt_limit, int)
                or isinstance(stage_attempt_limit, bool)
                or stage_attempt_limit < 1
                or stage_attempt_limit > MAX_TIMING_LIMIT
            ):
                raise ValueError(f"stage_attempt_limit must be 1-{MAX_TIMING_LIMIT}")

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
        attempts = self._connection.execute(
            """
            SELECT attempts.*, jobs.created_at AS job_created_at,
                   (
                       SELECT previous.ended_at FROM attempts AS previous
                       WHERE previous.job_id = attempts.job_id
                         AND previous.attempt_number = attempts.attempt_number - 1
                   ) AS previous_ended_at
            FROM attempts
            JOIN jobs ON jobs.job_id = attempts.job_id
            WHERE ? OR jobs.active = 1
            ORDER BY attempts.attempt_id
            """,
            (int(include_inactive),),
        ).fetchall()
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
