"""Reviewed TOML authority for durable coordinator queues."""

from __future__ import annotations

import hashlib
import re
import tomllib
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping

from .operations_policy import OperationsPolicy, load_operations_policy
from .performance_profiles import PerformanceProfile, load_performance_profiles

QUEUE_SCHEMA = "fidb-queue/v1"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")


@dataclass(frozen=True)
class BatchConfig:
    """One ordered batch from a queue configuration."""

    id: str
    name: str
    plan: Path
    plan_path: str
    matrices: tuple[str, ...] | None = None
    plan_sha256: str | None = None
    queue_digest: str | None = None
    executions: int | None = None


@dataclass(frozen=True)
class QueueConfig:
    """Validated ``fidb-queue/v1`` configuration."""

    schema_version: str
    name: str
    batch_order: tuple[str, ...]
    armed: bool
    max_workers: int
    performance_profile: PerformanceProfile | None
    poll_seconds: int
    lease_seconds: int
    max_attempts: int
    retry_backoff_seconds: int
    retry_backoff_max_seconds: int
    authority_failure_threshold: int
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
            | {
                "performance_profile",
                "retry_backoff_seconds",
                "retry_backoff_max_seconds",
                "authority_failure_threshold",
            },
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
        performance_profile = None
        if "performance_profile" in queue:
            profile_id = _identifier(
                queue["performance_profile"], "queue performance_profile"
            )
            performance_profiles = load_performance_profiles(root)
            performance_profile = performance_profiles.select(profile_id)
            if performance_profile.settings.worker_mode == "automatic":
                from .host_capacity import (
                    detect_host_capacity,
                    resolve_automatic_performance,
                )

                automatic = resolve_automatic_performance(
                    detect_host_capacity(), performance_profiles.automatic_policy
                )
                performance_profile = replace(
                    performance_profile,
                    settings=automatic.settings,
                    resolution=automatic.document(),
                )
            profile_workers = performance_profile.settings.workers
            if (
                performance_profile.settings.worker_mode != "fixed"
                or profile_workers is None
            ):
                raise ValueError(
                    "queue performance_profile must select a fixed worker count"
                )
            if max_workers != profile_workers:
                raise ValueError(
                    "queue max_workers does not match performance profile: "
                    f"{max_workers} != {profile_workers} ({profile_id})"
                )
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
        authority_failure_threshold = _nonnegative_integer(
            queue.get("authority_failure_threshold", 0),
            "queue authority_failure_threshold",
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
            _only_keys(
                row,
                {
                    "id",
                    "name",
                    "plan",
                    "matrices",
                    "plan_sha256",
                    "queue_digest",
                    "executions",
                },
                f"batch {position}",
            )
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
            plan_sha256 = None
            if "plan_sha256" in row:
                plan_sha256 = _sha256_text(
                    row["plan_sha256"], f"batch {batch_id} plan_sha256"
                )
                actual_plan_sha256 = hashlib.sha256(plan_path.read_bytes()).hexdigest()
                if actual_plan_sha256 != plan_sha256:
                    raise ValueError(
                        f"batch {batch_id} plan_sha256 mismatch: expected "
                        f"{plan_sha256}, got {actual_plan_sha256}"
                    )
            queue_digest = None
            if "queue_digest" in row:
                queue_digest = _sha256_text(
                    row["queue_digest"], f"batch {batch_id} queue_digest"
                )
            executions = None
            if "executions" in row:
                executions = _positive_integer(
                    row["executions"], f"batch {batch_id} executions"
                )
            batches.append(
                BatchConfig(
                    id=batch_id,
                    name=batch_name,
                    plan=plan_path,
                    plan_path=normalized_plan,
                    matrices=matrices,
                    plan_sha256=plan_sha256,
                    queue_digest=queue_digest,
                    executions=executions,
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
            performance_profile=performance_profile,
            poll_seconds=poll_seconds,
            lease_seconds=lease_seconds,
            max_attempts=max_attempts,
            retry_backoff_seconds=retry_backoff_seconds,
            retry_backoff_max_seconds=retry_backoff_max_seconds,
            authority_failure_threshold=authority_failure_threshold,
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


def _sha256_text(value: object, context: str) -> str:
    result = _text(value, context)
    if len(result) != 64 or any(
        character not in "0123456789abcdef" for character in result
    ):
        raise ValueError(f"{context} must be a lowercase SHA-256")
    return result


def _positive_integer(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{context} must be a positive integer")
    return value


def _nonnegative_integer(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{context} must be a non-negative integer")
    return value
