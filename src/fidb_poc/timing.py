"""Typed, provenance-ready timing spans for build execution.

Wall-clock timestamps make spans comparable across workers.  Durations always
come from ``monotonic_ns`` so clock corrections cannot produce negative or
inflated elapsed times.  Resource readings are deliberately process-level:
they are useful for worker-capacity decisions, but they are not presented as
per-command cgroup accounting.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import resource
import sys
import time
from typing import Callable, Iterator, Mapping

TIMING_SCHEMA = "fidb-execution-timing/v1"


class CellStage(str, Enum):
    REQUEST_VALIDATION = "request-validation"
    AUTHORITY_RESOLUTION = "authority-resolution"
    SOURCE_ACQUIRE = "source-acquire"
    TOOLCHAIN_ACQUIRE = "toolchain-acquire"
    EXECUTOR_IMAGE_ACQUIRE = "executor-image-acquire"
    INPUT_VERIFICATION = "input-verification"
    SOURCE_EXTRACT = "source-extract"
    TOOLCHAIN_EXTRACT = "toolchain-extract"
    PATCH = "patch"
    CONFIGURE = "configure"
    COMPILE = "compile"
    ARCHIVE_OBJECT_SELECTION = "archive-object-selection"
    ARTIFACT_VALIDATION = "artifact-validation"
    GHIDRA_STARTUP = "ghidra-startup"
    GHIDRA_DIAGNOSTIC_POLICY = "ghidra-diagnostic-policy"
    GHIDRA_IMPORT_ANALYSIS = "ghidra-import-analysis"
    FID_POPULATION = "fid-population"
    FID_VALIDATION = "fid-validation"
    FIDB_EXPORT = "fidb-export"
    FIDBF_EXPORT = "fidbf-export"
    PROVENANCE_SEAL = "provenance-seal"
    PUBLICATION = "publication"

    # Compatibility aliases for callers which used the original coarse stages.
    VALIDATING = REQUEST_VALIDATION
    RESOLVING = AUTHORITY_RESOLUTION
    PREPARING = SOURCE_ACQUIRE
    BUILDING = COMPILE
    VALIDATING_BINARY = ARTIFACT_VALIDATION
    INITIALIZING_GHIDRA = GHIDRA_STARTUP
    BUILDING_FIDB = FID_POPULATION
    EXPORTING = FIDBF_EXPORT
    SEALING = PROVENANCE_SEAL


class ProgressStatus(str, Enum):
    STARTED = "started"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class ProgressEvent:
    stage: CellStage
    status: ProgressStatus
    message: str
    duration_ns: int | None
    metrics: dict[str, object]
    started_at: str
    finished_at: str | None


ProgressCallback = Callable[[ProgressEvent], None]
SpanFactory = Callable[
    [CellStage | str, str, Mapping[str, object] | None],
    object,
]


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _rss_bytes(value: int | float) -> int:
    # Linux reports KiB, while macOS and the BSDs report bytes.  This project
    # executes on Linux, but keeping the conversion explicit prevents wildly
    # wrong readings if the code is inspected elsewhere.
    return int(value if sys.platform == "darwin" else value * 1024)


def _usage() -> dict[str, int | None]:
    try:
        own = resource.getrusage(resource.RUSAGE_SELF)
        children = resource.getrusage(resource.RUSAGE_CHILDREN)
    except (OSError, ValueError):
        return {
            "self_user_cpu_ns": None,
            "self_system_cpu_ns": None,
            "child_user_cpu_ns": None,
            "child_system_cpu_ns": None,
            "self_max_rss_bytes_peak": None,
            "child_max_rss_bytes_peak": None,
        }
    return {
        "self_user_cpu_ns": int(own.ru_utime * 1_000_000_000),
        "self_system_cpu_ns": int(own.ru_stime * 1_000_000_000),
        "child_user_cpu_ns": int(children.ru_utime * 1_000_000_000),
        "child_system_cpu_ns": int(children.ru_stime * 1_000_000_000),
        "self_max_rss_bytes_peak": _rss_bytes(own.ru_maxrss),
        "child_max_rss_bytes_peak": _rss_bytes(children.ru_maxrss),
    }


def _resource_metrics(
    before: Mapping[str, int | None],
    after: Mapping[str, int | None],
    process_cpu_before: int,
    process_cpu_after: int,
) -> dict[str, int | None]:
    result: dict[str, int | None] = {
        "process_cpu_duration_ns": max(0, process_cpu_after - process_cpu_before),
        "self_max_rss_bytes_peak": after["self_max_rss_bytes_peak"],
        "child_max_rss_bytes_peak": after["child_max_rss_bytes_peak"],
    }
    for name in (
        "self_user_cpu_ns",
        "self_system_cpu_ns",
        "child_user_cpu_ns",
        "child_system_cpu_ns",
    ):
        start = before[name]
        finish = after[name]
        result[f"{name.removesuffix('_ns')}_duration_ns"] = (
            max(0, finish - start)
            if isinstance(start, int) and isinstance(finish, int)
            else None
        )
    return result


class TimingRecorder:
    """Emit typed lifecycle events and retain terminal spans for provenance."""

    def __init__(self, callback: ProgressCallback | None = None) -> None:
        self.callback = callback
        self._terminal: list[ProgressEvent] = []
        self._started_ns = time.monotonic_ns()
        self._started_at = utc_now()
        self._open_stage: CellStage | None = None

    def _emit(self, event: ProgressEvent) -> None:
        if event.status is not ProgressStatus.STARTED:
            self._terminal.append(event)
        if self.callback is not None:
            self.callback(event)

    @contextmanager
    def span(
        self,
        stage: CellStage | str,
        message: str,
        metrics: Mapping[str, object] | None = None,
    ) -> Iterator[dict[str, object]]:
        stage = stage if isinstance(stage, CellStage) else CellStage(stage)
        if self._open_stage is not None:
            raise RuntimeError(
                f"timing spans must be sequential; {self._open_stage.value!r} is open"
            )
        self._open_stage = stage
        operation_metrics = dict(metrics or {})
        started_at = utc_now()
        started_ns = time.monotonic_ns()
        process_cpu_started = time.process_time_ns()
        usage_started = _usage()
        try:
            self._emit(
                ProgressEvent(
                    stage=stage,
                    status=ProgressStatus.STARTED,
                    message=message,
                    duration_ns=None,
                    metrics=dict(operation_metrics),
                    started_at=started_at,
                    finished_at=None,
                )
            )
        except BaseException:
            self._open_stage = None
            raise
        try:
            yield operation_metrics
        except BaseException as error:
            finished_ns = time.monotonic_ns()
            terminal_metrics = {
                **operation_metrics,
                **_resource_metrics(
                    usage_started,
                    _usage(),
                    process_cpu_started,
                    time.process_time_ns(),
                ),
                "error_type": type(error).__name__,
            }
            self._open_stage = None
            self._emit(
                ProgressEvent(
                    stage=stage,
                    status=ProgressStatus.FAILED,
                    message=f"{message}: {type(error).__name__}: {error}",
                    duration_ns=max(0, finished_ns - started_ns),
                    metrics=terminal_metrics,
                    started_at=started_at,
                    finished_at=utc_now(),
                )
            )
            raise
        else:
            finished_ns = time.monotonic_ns()
            terminal_metrics = {
                **operation_metrics,
                **_resource_metrics(
                    usage_started,
                    _usage(),
                    process_cpu_started,
                    time.process_time_ns(),
                ),
            }
            self._open_stage = None
            self._emit(
                ProgressEvent(
                    stage=stage,
                    status=ProgressStatus.COMPLETED,
                    message=message,
                    duration_ns=max(0, finished_ns - started_ns),
                    metrics=terminal_metrics,
                    started_at=started_at,
                    finished_at=utc_now(),
                )
            )

    def skip(
        self,
        stage: CellStage | str,
        message: str,
        metrics: Mapping[str, object] | None = None,
    ) -> None:
        stage = stage if isinstance(stage, CellStage) else CellStage(stage)
        if self._open_stage is not None:
            raise RuntimeError(
                f"cannot record skipped stage while {self._open_stage.value!r} is open"
            )
        now = utc_now()
        self._emit(
            ProgressEvent(
                stage=stage,
                status=ProgressStatus.SKIPPED,
                message=message,
                duration_ns=0,
                metrics=dict(metrics or {}),
                started_at=now,
                finished_at=now,
            )
        )

    @staticmethod
    def event_document(event: ProgressEvent) -> dict[str, object]:
        return {
            "stage": event.stage.value,
            "status": event.status.value,
            "message": event.message,
            "started_at": event.started_at,
            "finished_at": event.finished_at,
            "duration_ns": event.duration_ns,
            "metrics": dict(event.metrics),
        }

    def terminal_events(self) -> tuple[ProgressEvent, ...]:
        return tuple(self._terminal)

    def document(self) -> dict[str, object]:
        finished_ns = time.monotonic_ns()
        counts = {status.value: 0 for status in ProgressStatus}
        stage_duration_ns: dict[str, int] = {}
        for event in self._terminal:
            counts[event.status.value] += 1
            if event.duration_ns is not None:
                stage_duration_ns[event.stage.value] = (
                    stage_duration_ns.get(event.stage.value, 0) + event.duration_ns
                )
        return {
            "schema_version": TIMING_SCHEMA,
            "policy": {
                "wall_clock": "UTC RFC3339 timestamps",
                "duration_clock": "monotonic_ns",
                "resource_scope": "worker process and waited-for child processes",
                "rss_semantics": "peak reading, not a span delta",
                "span_order": "strictly sequential; one open stage per attempt",
            },
            "summary": {
                "measurement_started_at": self._started_at,
                "elapsed_before_snapshot_ns": max(0, finished_ns - self._started_ns),
                "terminal_event_counts": counts,
                "stage_duration_ns": stage_duration_ns,
            },
            "spans": [self.event_document(event) for event in self._terminal],
        }
