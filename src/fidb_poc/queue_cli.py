"""CLI surface for the durable, TOML-authoritative build queue.

The queue document defines immutable intent and priority.  SQLite contains only
runtime coordination state: leases, attempts, stages and terminal results.  A
worker can execute only resolved cells through :func:`cell_runner.run_cell`;
there is no command string or recipe-provided shell escape in this interface.
"""

from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import stat
import sys
import tempfile
import threading
import time
from typing import Sequence

from .cell_runner import (
    SEAL_SCHEMA,
    CellAuthorityResolver,
    CellResolutionError,
    CellRunResult,
    ProgressEvent,
    preflight_cell_authority,
    run_cell,
)
from .coordinator import (
    MAX_DURATION_NS,
    Coordinator,
    LeaseConflictError,
    QueueConfig,
    WORKER_POOLS,
)
from .jvm_policy import java_options
from .operations_policy import (
    NotificationPolicy,
    emit_notification,
    evaluate_operations,
)
from .timing import CellStage, ProgressStatus, TIMING_SCHEMA, TimingRecorder

DEFAULT_QUEUE = Path("plans/priority-queue.toml")
DEFAULT_STATE = Path("var/fidb-coordinator/ledger.sqlite3")
RESULT_SCHEMA = "fidb-job-result/v1"
JOB_TIMING_SCHEMA = "fidb-job-timing/v1"
_JOB_ID = re.compile(r"job-[0-9a-f]{64}\Z")
_RETENTION_RECYCLED_SESSION = "FIDB_RETENTION_RECYCLED_SESSION"
_RETENTION_RECYCLED_WORKER = "FIDB_RETENTION_RECYCLED_WORKER"
_RETENTION_PRE_RECYCLE_RSS = "FIDB_RETENTION_PRE_RECYCLE_RSS_BYTES"
_RETENTION_PRE_RECYCLE_JVM = "FIDB_RETENTION_PRE_RECYCLE_JVM_STARTED"


class QueueCliError(RuntimeError):
    """An operator-facing queue command could not be completed safely."""


def _self_rss_bytes() -> int:
    """Read current resident memory without confusing it with peak RSS."""

    try:
        for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
            if line.startswith("VmRSS:"):
                fields = line.split()
                if len(fields) == 3 and fields[2] == "kB":
                    return int(fields[1]) * 1024
    except (OSError, ValueError):
        pass
    return 0


def _embedded_jvm_started() -> bool | None:
    """Inspect already-imported pyghidra without importing or starting it."""

    module = sys.modules.get("pyghidra")
    if module is None:
        return False
    started = getattr(module, "started", None)
    if not callable(started):
        return None
    try:
        return bool(started())
    except Exception:
        return None


def _recycle_worker_process(session_id: str, worker_id: str) -> None:
    """Replace this process once so imported JVM state is returned to the OS."""

    environment = os.environ.copy()
    environment[_RETENTION_RECYCLED_SESSION] = session_id
    environment[_RETENTION_RECYCLED_WORKER] = worker_id
    environment[_RETENTION_PRE_RECYCLE_RSS] = str(_self_rss_bytes())
    jvm_started = _embedded_jvm_started()
    environment[_RETENTION_PRE_RECYCLE_JVM] = (
        "unknown" if jvm_started is None else str(jvm_started).lower()
    )
    os.execve(sys.executable, [sys.executable, *sys.argv], environment)


def _post_recycle_memory_audit(root: Path, worker_id: str) -> bool:
    """Verify memory release from the fresh side of an exec-based recycle."""

    session_id = os.environ.get(_RETENTION_RECYCLED_SESSION)
    if session_id is None:
        return False
    handed_off_worker = os.environ.get(_RETENTION_RECYCLED_WORKER)
    if handed_off_worker != worker_id:
        print(
            "warning: post-recycle memory audit worker identity mismatch",
            file=sys.stderr,
        )
        return True
    before_text = os.environ.get(_RETENTION_PRE_RECYCLE_RSS, "")
    if not before_text.isdigit():
        print("warning: post-recycle memory audit lacks prior RSS", file=sys.stderr)
        return True
    jvm_text = os.environ.get(_RETENTION_PRE_RECYCLE_JVM, "unknown")
    before_jvm = {"true": True, "false": False}.get(jvm_text)
    try:
        from .retention import write_memory_cleanup_audit

        report = write_memory_cleanup_audit(
            root,
            worker_id=worker_id,
            session_id=session_id,
            before_rss_bytes=int(before_text),
            after_rss_bytes=_self_rss_bytes(),
            before_jvm_started=before_jvm,
            after_jvm_started=_embedded_jvm_started(),
        )
        print(
            json.dumps(
                {
                    "event": "retention.memory-cleanup-audit",
                    "session_id": session_id,
                    "worker_id": worker_id,
                    "state": report.get("state"),
                    "reclaimed_rss_bytes": report.get("reclaimed_rss_bytes"),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
    except (OSError, ValueError) as error:
        print(f"warning: post-recycle memory audit failed: {error}", file=sys.stderr)
    return True


def _terminal_queue_has_pending_work(state: Path) -> bool:
    """Check the durable queue cheaply without rebuilding its resolved plans."""

    uri = f"{state.resolve().as_uri()}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=5)) as connection:
        row = connection.execute("""
            SELECT 1 FROM jobs
            WHERE active = 1 AND state IN ('queued', 'leased', 'running')
            LIMIT 1
            """).fetchone()
    return row is not None


def _park_recycled_terminal_worker(root: Path, state: Path) -> None:
    """Keep a clean worker cheap until durable work is queued again."""

    try:
        from .retention import load_retention_policy

        policy = load_retention_policy(root)
    except (OSError, ValueError) as error:
        print(
            f"warning: terminal worker park policy unavailable: {error}",
            file=sys.stderr,
        )
        return
    if not policy.memory_cleanup_enabled or not policy.park_terminal_workers:
        return
    while True:
        try:
            if _terminal_queue_has_pending_work(state):
                return
        except (OSError, sqlite3.Error) as error:
            print(
                f"warning: terminal worker park check failed: {error}", file=sys.stderr
            )
            return
        time.sleep(policy.park_poll_seconds)


def _post_drain_maintenance(
    root: Path, state: Path, session_id: str, worker_id: str
) -> None:
    """Run configured retention, then recycle a long-lived worker if requested."""

    from .retention import (
        RetentionError,
        automatic_retention,
        load_retention_policy,
    )

    if os.environ.get(_RETENTION_RECYCLED_SESSION) == session_id:
        return
    try:
        policy = load_retention_policy(root)
    except (OSError, ValueError) as error:
        print(
            f"warning: retention policy unavailable after queue drain: {error}",
            file=sys.stderr,
        )
        return
    try:
        result = automatic_retention(root, state)
        summary = result.get("summary")
        print(
            json.dumps(
                {
                    "event": "retention.post-drain",
                    "session_id": session_id,
                    "state": result.get("state"),
                    "plan_digest": result.get("plan_digest"),
                    "summary": summary,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
    except (OSError, RetentionError, ValueError) as error:
        print(f"warning: post-drain retention failed safely: {error}", file=sys.stderr)
    finally:
        if policy.worker_action == "recycle":
            _recycle_worker_process(session_id, worker_id)


def _maybe_post_drain_maintenance(
    coordinator: Coordinator,
    root: Path,
    state: Path,
    worker_id: str,
    notifications: NotificationPolicy,
    *,
    already_notified: bool,
) -> bool:
    """Run terminal maintenance once, including outside the claim window."""

    if already_notified:
        return True
    status = coordinator.status()
    counts = status["counts"]
    if not (
        isinstance(counts, dict)
        and counts.get("queued") == 0
        and counts.get("leased") == 0
        and counts.get("running") == 0
    ):
        return False
    from .retention import current_retention_session

    retention_session = current_retention_session(root, state)
    if os.environ.get(_RETENTION_RECYCLED_SESSION) != retention_session:
        _notify(
            notifications,
            "queue-drained",
            {
                "worker_id": worker_id,
                "counts": counts,
                "retention_session": retention_session,
            },
        )
        _post_drain_maintenance(root, state, retention_session, worker_id)
    return True


def _common_parser(*, queue: bool) -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(add_help=False)
    result.add_argument(
        "--project-root",
        type=Path,
        default=Path.cwd(),
        help="FIDB project directory (default: current directory)",
    )
    result.add_argument(
        "--state",
        type=Path,
        default=DEFAULT_STATE,
        help=f"coordinator SQLite path (default: {DEFAULT_STATE})",
    )
    result.add_argument(
        "--campaign-registry",
        type=Path,
        help=(
            "resolve queue and ledger from the active operational campaign; "
            "when supplied it takes precedence over --queue and --state"
        ),
    )
    if queue:
        result.add_argument(
            "--queue",
            type=Path,
            default=DEFAULT_QUEUE,
            help=f"priority queue TOML (default: {DEFAULT_QUEUE})",
        )
    return result


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="fidb-poc queue",
        description=(
            "Synchronize and run the TOML-authoritative FIDB priority queue. "
            "Synchronizing and inspecting never execute a build."
        ),
    )
    commands = result.add_subparsers(dest="command", required=True)

    sync = commands.add_parser(
        "sync",
        parents=[_common_parser(queue=True)],
        help="resolve queue plans into the ledger without executing them",
    )
    sync.add_argument(
        "--full", action="store_true", help="include batches, jobs and events"
    )

    reconfigure = commands.add_parser(
        "reconfigure-runtime",
        parents=[_common_parser(queue=True)],
        help="rebind runtime policy without replacing synchronized jobs",
    )
    reconfigure.add_argument("--expected-sync-generation", required=True, type=int)
    reconfigure.add_argument("--expected-active-jobs", required=True, type=int)
    reconfigure.add_argument(
        "--reason", required=True, help="durable operator rationale"
    )

    status = commands.add_parser(
        "status",
        parents=[_common_parser(queue=False)],
        help="show durable coordinator state",
    )
    status.add_argument(
        "--full", action="store_true", help="include batches, jobs and events"
    )

    events = commands.add_parser(
        "events",
        parents=[_common_parser(queue=False)],
        help="show append-only queue events",
    )
    events.add_argument("--after", type=int, default=0, help="event cursor")

    pause = commands.add_parser(
        "pause",
        parents=[_common_parser(queue=False)],
        help="stop new claims while current leases finish",
    )
    pause.add_argument("--reason", default="operator request")

    commands.add_parser(
        "resume",
        parents=[_common_parser(queue=False)],
        help="resume claims when the TOML queue is armed",
    )

    requeue = commands.add_parser(
        "requeue-failed",
        parents=[_common_parser(queue=False)],
        help="requeue an exact failed batch while preserving attempts and events",
    )
    requeue.add_argument("--batch", required=True, help="exact active batch id")
    requeue.add_argument(
        "--expected-count",
        required=True,
        type=int,
        help="fail closed unless exactly this many failed jobs are selected",
    )
    requeue.add_argument("--reason", required=True, help="durable operator rationale")

    interrupted = commands.add_parser(
        "requeue-interrupted",
        parents=[_common_parser(queue=False)],
        help="fence and requeue an exact stopped-worker set while preserving evidence",
    )
    interrupted.add_argument("--batch", required=True, help="exact active batch id")
    interrupted.add_argument(
        "--expected-count",
        required=True,
        type=int,
        help="fail closed unless exactly this many live jobs are selected",
    )
    interrupted.add_argument(
        "--reason", required=True, help="durable operator rationale"
    )

    commands.add_parser(
        "preflight",
        parents=[_common_parser(queue=True)],
        help="evaluate schedule and host resource gates without claiming work",
    )

    resolution = commands.add_parser(
        "resolve-preflight",
        parents=[_common_parser(queue=False)],
        help="re-resolve exact active jobs without building or starting Java",
    )
    resolution.add_argument(
        "--batch",
        action="append",
        dest="batches",
        help="limit validation to an exact active batch id; repeat as needed",
    )

    doctor = commands.add_parser(
        "doctor",
        parents=[_common_parser(queue=False)],
        help=(
            "compile a read-only incident report and guarded recovery plan; "
            "never pause, requeue or execute work"
        ),
    )
    doctor.add_argument(
        "--batch",
        action="append",
        dest="batches",
        help="limit the report to an exact batch id; repeat as needed",
    )
    doctor.add_argument(
        "--include-inactive",
        action="store_true",
        help="include superseded job generations in counts and failure history",
    )
    doctor.add_argument(
        "--history-limit",
        type=int,
        default=20,
        help="maximum recent failed attempts, stages and incident events (1-200)",
    )
    doctor.add_argument(
        "--services",
        action="store_true",
        help="also inspect live worker limits using read-only systemctl show",
    )

    start_block = commands.add_parser(
        "start-block",
        parents=[_common_parser(queue=True)],
        help=(
            "manually admit the next batch outside the schedule window; "
            "workers still enforce queue arming and resource gates"
        ),
    )
    start_block.add_argument(
        "--expected-sync-generation",
        type=int,
        help=(
            "admit an already-synchronized ledger without resolving every plan "
            "again; requires --expected-active-jobs"
        ),
    )
    start_block.add_argument(
        "--expected-active-jobs",
        type=int,
        help="fail closed unless the synchronized active-job count matches exactly",
    )

    worker = commands.add_parser(
        "run",
        parents=[_common_parser(queue=True)],
        help="continuously execute the highest-priority runnable cells",
    )
    worker.add_argument("--worker-id", required=True)
    worker.add_argument(
        "--pool",
        choices=WORKER_POOLS,
        help=(
            "restrict atomic claims to a typed worker pool; library-local accepts "
            "only native-local native cells and local source-library cells"
        ),
    )
    worker.add_argument(
        "--once",
        action="store_true",
        help="claim at most one cell, then exit (useful for service tests)",
    )
    worker.add_argument(
        "--use-synced-queue",
        action="store_true",
        help=(
            "require the ledger to match the configured queue summary instead of "
            "resolving every plan again at worker startup"
        ),
    )
    worker.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="stream underlying build output where supported",
    )
    return result


def _project_root(path: Path) -> Path:
    root = path.expanduser().resolve()
    required = (
        root / "pyproject.toml",
        root / "worker.toml",
        root / "recipes",
        root / "toolchains/registry.toml",
    )
    if not root.is_dir() or any(not item.exists() for item in required):
        raise QueueCliError(f"not an FIDB project root: {root}")
    return root


def _inside_project(path: Path, root: Path, label: str) -> Path:
    candidate = path if path.is_absolute() else root / path
    resolved = candidate.expanduser().resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise QueueCliError(
            f"{label} must remain inside the project root: {path}"
        ) from error
    if candidate.is_symlink():
        raise QueueCliError(f"{label} cannot be a symlink: {candidate}")
    return resolved


def _paths(
    arguments: argparse.Namespace, *, require_queue: bool
) -> tuple[Path, Path, Path | None]:
    root = _project_root(arguments.project_root)
    registry_path = getattr(arguments, "campaign_registry", None)
    if registry_path is not None:
        from .campaign_registry import resolve_campaign_paths

        state, queue, _binding = resolve_campaign_paths(root, registry_path)
        return root, state, queue if require_queue else None
    state = _inside_project(arguments.state, root, "coordinator state")
    queue = None
    if require_queue:
        queue = _inside_project(arguments.queue, root, "queue configuration")
        if not queue.is_file():
            raise QueueCliError(f"queue configuration is not a file: {queue}")
    return root, state, queue


def _existing_state(state: Path) -> None:
    if not state.is_file():
        raise QueueCliError(
            f"coordinator state does not exist: {state}; run 'fidb-poc queue sync' first"
        )


def _print_json(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _notify(
    policy: NotificationPolicy,
    event: str,
    payload: dict[str, object],
) -> None:
    try:
        delivery = emit_notification(policy, event, payload)
        if delivery and delivery.get("webhook_error"):
            print(
                f"warning: notification delivery failed: {delivery['webhook_error']}",
                file=sys.stderr,
                flush=True,
            )
    except (OSError, ValueError) as error:
        print(
            f"warning: notification outbox failed: {error}", file=sys.stderr, flush=True
        )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _fsync_regular_file(path: Path) -> None:
    """Flush one generated file without following a final-component symlink."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise QueueCliError(f"artifact is not a regular file: {path}")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    """Flush a directory entry set without following a symlink."""

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise QueueCliError(f"artifact publication path is not a directory: {path}")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory_chains(directories: Sequence[Path], boundary: Path) -> None:
    """Flush relevant directory trees from their leaves through ``boundary``."""

    root = boundary.resolve()
    pending: dict[Path, None] = {}
    for directory in directories:
        resolved = directory.resolve()
        try:
            resolved.relative_to(root)
        except ValueError as error:
            raise QueueCliError(
                f"artifact publication directory escaped the project root: {directory}"
            ) from error
        current = resolved
        while True:
            pending[current] = None
            if current == root:
                break
            current = current.parent
    for directory in sorted(pending, key=lambda item: len(item.parts), reverse=True):
        _fsync_directory(directory)


class _Heartbeat:
    """Renew one fenced lease using a connection owned by its thread."""

    def __init__(
        self,
        database: Path,
        project_root: Path,
        lease: dict[str, object],
        lease_seconds: int,
    ) -> None:
        self.database = database
        self.project_root = project_root
        self.lease = lease
        self.interval = max(0.25, min(float(lease_seconds) / 3.0, 60.0))
        # A heartbeat is deliberately much more patient than an ordinary
        # coordinator write.  SQLite WAL still permits only one writer at a
        # time, so a large simultaneous stage flush can outlive the
        # connection's busy timeout without invalidating a 60-minute lease.
        # Keep retrying only lock contention, and bound the retry window well
        # inside the remaining lease lifetime so real fencing failures still
        # surface promptly.
        self.lock_retry_seconds = max(
            1.0,
            min(30.0, float(lease_seconds) / 6.0),
        )
        self.lock_retry_delay = max(0.1, min(1.0, self.interval / 10.0))
        self.lock_retries = 0
        self.stop_event = threading.Event()
        self.error: BaseException | None = None
        self.thread = threading.Thread(
            target=self._run,
            name=f"lease-{lease['job_id']}",
            daemon=True,
        )

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=max(2.0, self.interval + 1.0))

    def check(self) -> None:
        if self.error is not None:
            raise LeaseConflictError(f"lease heartbeat failed: {self.error}")

    def _run(self) -> None:
        try:
            with Coordinator(self.database, self.project_root) as coordinator:
                while not self.stop_event.wait(self.interval):
                    retry_deadline = time.monotonic() + self.lock_retry_seconds
                    while True:
                        try:
                            coordinator.renew(
                                str(self.lease["job_id"]),
                                str(self.lease["lease_token"]),
                                int(self.lease["lease_generation"]),
                            )
                            break
                        except sqlite3.OperationalError as error:
                            if not _is_sqlite_lock_contention(error):
                                raise
                            remaining = retry_deadline - time.monotonic()
                            if remaining <= 0:
                                raise
                            self.lock_retries += 1
                            if self.stop_event.wait(
                                min(self.lock_retry_delay, remaining)
                            ):
                                return
        except BaseException as error:  # surfaced synchronously by check()
            self.error = error
            self.stop_event.set()


def _is_sqlite_lock_contention(error: sqlite3.OperationalError) -> bool:
    """Recognise only SQLite's transient writer-contention result classes."""

    code = getattr(error, "sqlite_errorcode", None)
    if isinstance(code, int) and code & 0xFF in (
        sqlite3.SQLITE_BUSY,
        sqlite3.SQLITE_LOCKED,
    ):
        return True
    message = str(error).lower()
    return "database is locked" in message or "database table is locked" in message


def _staging_root(root: Path, lease: dict[str, object]) -> tuple[Path, Path]:
    job_id = str(lease["job_id"])
    generation = int(lease["lease_generation"])
    if not _JOB_ID.fullmatch(job_id) or generation < 1:
        raise QueueCliError("coordinator returned an invalid job identity")
    runs = root / "artifacts/runs"
    # Ghidra rejects project paths containing any component which starts with
    # a dot.  Runs are already ignored as a whole, so the attempt staging tree
    # does not need hidden path components.
    staging_parent = runs / "staging"
    final_parent = runs / job_id
    for directory in (runs, staging_parent, final_parent):
        if directory.is_symlink():
            raise QueueCliError(
                f"artifact publication path cannot be a symlink: {directory}"
            )
        directory.mkdir(parents=True, exist_ok=True)
    final = final_parent / f"attempt-{generation}"
    if final.exists() or final.is_symlink():
        raise QueueCliError(f"attempt publication already exists: {final}")
    staging = Path(
        tempfile.mkdtemp(prefix=f"{job_id}-g{generation}-", dir=staging_parent)
    ).resolve()
    return staging, final


def _nonnegative_integer(value: object, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > MAX_DURATION_NS
    ):
        raise QueueCliError(
            f"{label} must be an integer between 0 and {MAX_DURATION_NS}"
        )
    return value


def _utc_timing_timestamp(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise QueueCliError(f"{label} must be a UTC RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(f"{value[:-1]}+00:00")
    except ValueError as error:
        raise QueueCliError(f"{label} must be a UTC RFC3339 timestamp") from error
    if parsed.utcoffset() != timedelta(0):
        raise QueueCliError(f"{label} must be a UTC RFC3339 timestamp")
    return value


def _validate_cell_timing(timing: object) -> None:
    """Require a complete, JSON-safe execution record before publication."""

    if not isinstance(timing, dict) or timing.get("schema_version") != TIMING_SCHEMA:
        raise QueueCliError("cell result is missing valid execution timing provenance")
    try:
        json.dumps(timing, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise QueueCliError(
            "cell execution timing provenance is not valid JSON"
        ) from error

    policy = timing.get("policy")
    summary = timing.get("summary")
    spans = timing.get("spans")
    if not isinstance(policy, dict) or policy.get("duration_clock") != "monotonic_ns":
        raise QueueCliError("cell execution timing has an invalid duration policy")
    if not isinstance(summary, dict):
        raise QueueCliError("cell execution timing is missing its summary")
    _utc_timing_timestamp(
        summary.get("measurement_started_at"),
        "cell timing measurement_started_at",
    )
    _nonnegative_integer(
        summary.get("elapsed_before_snapshot_ns"),
        "cell timing elapsed_before_snapshot_ns",
    )
    if not isinstance(spans, list) or not spans:
        raise QueueCliError("cell result is missing terminal execution timing spans")

    status_counts = {status.value: 0 for status in ProgressStatus}
    stage_durations: dict[str, int] = {}
    terminal_statuses = {
        ProgressStatus.COMPLETED.value,
        ProgressStatus.FAILED.value,
        ProgressStatus.SKIPPED.value,
    }
    for index, span in enumerate(spans):
        label = f"cell timing span {index}"
        if not isinstance(span, dict):
            raise QueueCliError(f"{label} must be an object")
        stage_value = span.get("stage")
        try:
            stage = CellStage(stage_value)
        except (TypeError, ValueError) as error:
            raise QueueCliError(f"{label} has an invalid stage") from error
        if stage is CellStage.PUBLICATION:
            raise QueueCliError(f"{label} cannot contain the publication stage")
        status = span.get("status")
        if status not in terminal_statuses:
            raise QueueCliError(f"{label} does not have a terminal status")
        if status == ProgressStatus.FAILED.value:
            raise QueueCliError("a successful cell result cannot contain a failed span")
        message = span.get("message")
        if not isinstance(message, str) or not message:
            raise QueueCliError(f"{label} must contain a message")
        started_at = _utc_timing_timestamp(
            span.get("started_at"), f"{label} started_at"
        )
        finished_at = _utc_timing_timestamp(
            span.get("finished_at"), f"{label} finished_at"
        )
        duration = _nonnegative_integer(span.get("duration_ns"), f"{label} duration_ns")
        if status == ProgressStatus.SKIPPED.value and duration != 0:
            raise QueueCliError(f"{label} has a non-zero skipped duration")
        if status == ProgressStatus.SKIPPED.value and started_at != finished_at:
            raise QueueCliError(f"{label} has unequal skipped timestamps")
        if not isinstance(span.get("metrics"), dict):
            raise QueueCliError(f"{label} metrics must be an object")
        status_counts[status] += 1
        stage_durations[stage.value] = stage_durations.get(stage.value, 0) + duration

    final = spans[-1]
    if (
        final["stage"] != CellStage.PROVENANCE_SEAL.value
        or final["status"] != ProgressStatus.COMPLETED.value
    ):
        raise QueueCliError(
            "cell execution timing must end with a completed provenance-seal span"
        )

    recorded_counts = summary.get("terminal_event_counts")
    if recorded_counts != status_counts:
        raise QueueCliError(
            "cell execution timing summary counts do not match its spans"
        )
    recorded_durations = summary.get("stage_duration_ns")
    if recorded_durations != stage_durations:
        raise QueueCliError(
            "cell execution timing summary durations do not match its spans"
        )


def _material_relatives(result: CellRunResult, staging: Path) -> dict[str, Path]:
    """Validate material artifact paths and return stable staging-relative names."""

    root = staging.resolve()
    relatives: dict[str, Path] = {}
    materials = {
        "seal": result.seal_path,
        "FIDB": result.fidb_path,
        "FIDBF": result.fidbf_path,
    }
    for label, raw_path in materials.items():
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = staging / candidate
        try:
            resolved = candidate.resolve(strict=True)
            relative = resolved.relative_to(root)
        except (FileNotFoundError, ValueError) as error:
            raise QueueCliError(
                f"generated {label} escaped or is missing from the staging root: {raw_path}"
            ) from error
        current = root
        for component in relative.parts:
            current /= component
            if current.is_symlink():
                raise QueueCliError(f"generated {label} cannot be a symlink: {current}")
        if not resolved.is_file():
            raise QueueCliError(f"generated {label} is not a regular file: {resolved}")
        relatives[label] = relative
    if _sha256(root / relatives["seal"]) != result.seal_sha256:
        raise QueueCliError("generated cell seal digest does not match its result")
    return relatives


def _validate_seal_binding(
    result: CellRunResult,
    staging: Path,
    relatives: dict[str, Path],
) -> None:
    """Bind the published artifacts and timing prefix to the immutable seal."""

    seal_path = staging / relatives["seal"]
    try:
        seal = json.loads(seal_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise QueueCliError(
            f"generated cell seal is not valid JSON: {seal_path}"
        ) from error
    if not isinstance(seal, dict) or seal.get("schema_version") != SEAL_SCHEMA:
        raise QueueCliError("generated cell seal has an invalid schema")

    cell = seal.get("cell")
    if not isinstance(cell, dict):
        raise QueueCliError("generated cell seal is missing its resolved cell identity")
    expected_identity = {
        "id": result.cell_id,
        "kind": result.kind,
        "executor": result.executor,
    }
    observed_identity = {field: cell.get(field) for field in expected_identity}
    if observed_identity != expected_identity:
        raise QueueCliError(
            "generated cell seal does not match the completed cell identity"
        )

    artifacts = seal.get("artifacts")
    if not isinstance(artifacts, dict):
        raise QueueCliError("generated cell seal is missing artifact provenance")
    for label, field in (("FIDB", "fidb"), ("FIDBF", "fidbf")):
        record = artifacts.get(field)
        if not isinstance(record, dict):
            raise QueueCliError(f"generated cell seal is missing its {label} record")
        recorded_path = record.get("path")
        if (
            not isinstance(recorded_path, str)
            or not recorded_path
            or recorded_path.startswith("/")
            or "\\" in recorded_path
            or any(part in {"", ".", ".."} for part in recorded_path.split("/"))
        ):
            raise QueueCliError(f"generated cell seal has an invalid {label} path")
        if Path(recorded_path) != relatives[label]:
            raise QueueCliError(
                f"generated {label} path does not match the authoritative seal"
            )
        artifact_path = staging / relatives[label]
        digest = _sha256(artifact_path)
        size = artifact_path.stat().st_size
        recorded_size = _nonnegative_integer(
            record.get("bytes"), f"sealed {label} byte count"
        )
        if record.get("sha256") != digest or recorded_size != size:
            raise QueueCliError(
                f"generated {label} content does not match the authoritative seal"
            )

    sealed_timing = seal.get("timing")
    if not isinstance(sealed_timing, dict):
        raise QueueCliError("generated cell seal is missing its timing provenance")
    result_summary = result.timing["summary"]
    sealed_summary = sealed_timing.get("summary")
    prefix = result.timing["spans"][:-1]
    if (
        sealed_timing.get("schema_version") != TIMING_SCHEMA
        or sealed_timing.get("policy") != result.timing["policy"]
        or sealed_timing.get("spans") != prefix
        or not isinstance(sealed_summary, dict)
        or sealed_summary.get("measurement_started_at")
        != result_summary["measurement_started_at"]
    ):
        raise QueueCliError(
            "generated cell seal timing does not match completed execution timing"
        )
    sealed_elapsed = _nonnegative_integer(
        sealed_summary.get("elapsed_before_snapshot_ns"),
        "sealed timing elapsed_before_snapshot_ns",
    )
    if sealed_elapsed > result_summary["elapsed_before_snapshot_ns"]:
        raise QueueCliError(
            "sealed timing elapsed duration exceeds completed execution"
        )
    prefix_counts = {status.value: 0 for status in ProgressStatus}
    prefix_durations: dict[str, int] = {}
    for span in prefix:
        prefix_counts[span["status"]] += 1
        prefix_durations[span["stage"]] = (
            prefix_durations.get(span["stage"], 0) + span["duration_ns"]
        )
    if (
        sealed_summary.get("terminal_event_counts") != prefix_counts
        or sealed_summary.get("stage_duration_ns") != prefix_durations
    ):
        raise QueueCliError(
            "generated cell seal timing summary does not match its prefix"
        )


def _durably_publish(
    result: CellRunResult,
    staging: Path,
    final: Path,
    root: Path,
) -> dict[str, Path]:
    """Sync material artifacts, rename the attempt, and sync the new names."""

    _validate_cell_timing(result.timing)
    if final.exists() or final.is_symlink():
        raise QueueCliError(f"attempt publication already exists: {final}")
    relatives = _material_relatives(result, staging)
    _validate_seal_binding(result, staging, relatives)
    staged = {label: staging / relative for label, relative in relatives.items()}
    for path in staged.values():
        _fsync_regular_file(path)
    _fsync_directory_chains(
        [
            staging,
            staging.parent,
            final.parent,
            *(path.parent for path in staged.values()),
        ],
        root,
    )

    os.replace(staging, final)

    published = {label: final / relative for label, relative in relatives.items()}
    for path in published.values():
        _fsync_regular_file(path)
    _fsync_directory_chains(
        [
            final,
            staging.parent,
            final.parent,
            *(path.parent for path in published.values()),
        ],
        root,
    )
    return published


def _result_document(
    result: CellRunResult,
    published: dict[str, Path],
    final: Path,
    root: Path,
) -> dict[str, object]:
    seal = published["seal"]
    fidb = published["FIDB"]
    fidbf = published["FIDBF"]
    for label, path in (("seal", seal), ("FIDB", fidb), ("FIDBF", fidbf)):
        if not path.is_file() or path.is_symlink():
            raise QueueCliError(f"published {label} is not a regular file: {path}")
    if _sha256(seal) != result.seal_sha256:
        raise QueueCliError("published cell seal digest changed during publication")
    return {
        "schema_version": RESULT_SCHEMA,
        "cell_id": result.cell_id,
        "kind": result.kind,
        "executor": result.executor,
        "attempt_root": str(final.relative_to(root)),
        "seal": {
            "path": str(seal.relative_to(root)),
            "sha256": result.seal_sha256,
        },
        "fidb": {"path": str(fidb.relative_to(root)), "sha256": _sha256(fidb)},
        "fidbf": {"path": str(fidbf.relative_to(root)), "sha256": _sha256(fidbf)},
    }


def _execute_claim(
    coordinator: Coordinator,
    database: Path,
    root: Path,
    lease: dict[str, object],
    lease_seconds: int,
    *,
    verbose: bool,
    build_jobs_per_cell: int = 4,
    authority_resolver: CellAuthorityResolver | None = None,
    notifications: NotificationPolicy = NotificationPolicy(),
) -> bool:
    staging, final = _staging_root(root, lease)
    token = str(lease["lease_token"])
    generation = int(lease["lease_generation"])
    job_id = str(lease["job_id"])
    heartbeat = _Heartbeat(database, root, lease, lease_seconds)
    failed_stage: str | None = None

    def progress(event: ProgressEvent) -> None:
        nonlocal failed_stage
        if event.status == ProgressStatus.FAILED:
            failed_stage = event.stage.value
        heartbeat.check()
        coordinator.record_stage(
            job_id,
            token,
            generation,
            event.stage.value,
            status=event.status.value,
            duration_ns=event.duration_ns,
            details={
                "message": event.message,
                "metrics": event.metrics,
                "started_at": event.started_at,
                "finished_at": event.finished_at,
            },
        )
        duration = (
            f" ({event.duration_ns / 1_000_000_000:.3f}s)"
            if event.duration_ns is not None
            else ""
        )
        print(
            f"{job_id}: {event.stage.value}: {event.status.value}{duration}: "
            f"{event.message}",
            flush=True,
        )

    heartbeat.start()
    try:
        result = run_cell(
            lease["cell"],
            lease["factor_variants"],
            root,
            staging,
            progress=progress,
            verbose=verbose,
            build_jobs_per_cell=build_jobs_per_cell,
            authority_resolver=authority_resolver,
        )
        heartbeat.check()
        _validate_cell_timing(result.timing)
        publication_timing = TimingRecorder(progress)
        with publication_timing.span(
            CellStage.PUBLICATION,
            "atomically publishing sealed cell artifacts",
            {"job_id": job_id, "lease_generation": generation},
        ) as publication_metrics:
            coordinator.renew(job_id, token, generation)
            final.parent.mkdir(parents=True, exist_ok=True)
            published = _durably_publish(result, staging, final, root)
            document = _result_document(result, published, final, root)
            publication_metrics.update(
                {
                    "seal_bytes": (root / str(document["seal"]["path"])).stat().st_size,
                    "fidb_bytes": (root / str(document["fidb"]["path"])).stat().st_size,
                    "fidbf_bytes": (root / str(document["fidbf"]["path"]))
                    .stat()
                    .st_size,
                }
            )
        document["timing"] = {
            "schema_version": JOB_TIMING_SCHEMA,
            "cell": result.timing,
            "publication": publication_timing.document(),
        }
        coordinator.complete(job_id, token, generation, result=document)
        print(f"{job_id}: complete: {document['seal']['path']}", flush=True)
        return True
    except KeyboardInterrupt:
        try:
            failed = coordinator.fail(
                job_id,
                token,
                generation,
                "worker interrupted",
                retryable=True,
            )
            _notify(
                notifications,
                "job-requeued" if failed["state"] == "queued" else "job-failed",
                {
                    "job_id": job_id,
                    "reason": "worker interrupted",
                    "state": failed["state"],
                },
            )
        except LeaseConflictError:
            pass
        raise
    except Exception as error:
        retryable = not isinstance(error, (CellResolutionError, ValueError))
        failure_class = (
            f"{failed_stage}:{type(error).__name__}"
            if failed_stage is not None
            else f"worker:{type(error).__name__}"
        )
        try:
            failed = coordinator.fail(
                job_id,
                token,
                generation,
                f"{type(error).__name__}: {error}",
                retryable=retryable,
                failure_class=failure_class,
            )
            _notify(
                notifications,
                "job-requeued" if failed["state"] == "queued" else "job-failed",
                {
                    "job_id": job_id,
                    "reason": f"{type(error).__name__}: {error}",
                    "state": failed["state"],
                },
            )
        except LeaseConflictError:
            pass
        print(f"error: {job_id}: {error}", file=sys.stderr, flush=True)
        return False
    finally:
        heartbeat.stop()


def _sync(arguments: argparse.Namespace) -> int:
    root, state, queue = _paths(arguments, require_queue=True)
    assert queue is not None
    with Coordinator(state, root) as coordinator:
        snapshot = coordinator.sync_queue(queue, actor="operator")
        _print_json(snapshot if arguments.full else coordinator.status())
    return 0


def _status(arguments: argparse.Namespace) -> int:
    root, state, _ = _paths(arguments, require_queue=False)
    _existing_state(state)
    with Coordinator(state, root) as coordinator:
        _print_json(coordinator.snapshot() if arguments.full else coordinator.status())
    return 0


def _reconfigure_runtime(arguments: argparse.Namespace) -> int:
    root, state, queue = _paths(arguments, require_queue=True)
    assert queue is not None
    _existing_state(state)
    config = QueueConfig.load(queue, root)
    with Coordinator(state, root) as coordinator:
        document = coordinator.reconfigure_runtime(
            config,
            expected_sync_generation=arguments.expected_sync_generation,
            expected_active_jobs=arguments.expected_active_jobs,
            reason=arguments.reason,
            actor="operator",
        )
        _print_json(document)
    return 0


def _events(arguments: argparse.Namespace) -> int:
    root, state, _ = _paths(arguments, require_queue=False)
    _existing_state(state)
    if arguments.after < 0:
        raise QueueCliError("event cursor cannot be negative")
    with Coordinator(state, root) as coordinator:
        _print_json(coordinator.events(after_event_id=arguments.after))
    return 0


def _pause(arguments: argparse.Namespace) -> int:
    root, state, _ = _paths(arguments, require_queue=False)
    _existing_state(state)
    with Coordinator(state, root) as coordinator:
        _print_json(coordinator.pause(arguments.reason))
    return 0


def _resume(arguments: argparse.Namespace) -> int:
    root, state, _ = _paths(arguments, require_queue=False)
    _existing_state(state)
    with Coordinator(state, root) as coordinator:
        _print_json(coordinator.resume())
    return 0


def _requeue_failed(arguments: argparse.Namespace) -> int:
    root, state, _ = _paths(arguments, require_queue=False)
    _existing_state(state)
    with Coordinator(state, root) as coordinator:
        result = coordinator.requeue_failed_batch(
            arguments.batch,
            arguments.expected_count,
            arguments.reason,
            actor="operator",
        )
        result["queue"] = coordinator.status()
        _print_json(result)
    return 0


def _requeue_interrupted(arguments: argparse.Namespace) -> int:
    root, state, _ = _paths(arguments, require_queue=False)
    _existing_state(state)
    with Coordinator(state, root) as coordinator:
        result = coordinator.requeue_interrupted_batch(
            arguments.batch,
            arguments.expected_count,
            arguments.reason,
            actor="operator",
        )
        result["queue"] = coordinator.status()
        _print_json(result)
    return 0


def _preflight(arguments: argparse.Namespace) -> int:
    root, _, queue_path = _paths(arguments, require_queue=True)
    assert queue_path is not None
    config = QueueConfig.load(queue_path, root)
    document = evaluate_operations(config.operations, root)
    document["queue_armed"] = config.armed
    document["ready"] = bool(document["ready"]) and config.armed
    _print_json(document)
    return 0 if document["ready"] else 1


def _resolution_preflight(arguments: argparse.Namespace) -> int:
    root, state, _ = _paths(arguments, require_queue=False)
    _existing_state(state)
    selected = tuple(arguments.batches) if arguments.batches else None
    with Coordinator(state, root) as coordinator:
        rows = coordinator.resolution_inputs(selected)
    if not rows:
        raise QueueCliError("resolution preflight selected no active jobs")

    resolver = CellAuthorityResolver(root)
    by_batch: dict[str, dict[str, object]] = {}
    failure_classes: dict[str, int] = {}
    route_ids: set[str] = set()
    treatment_ids: set[str] = set()
    passed = 0
    failures = []
    for row in rows:
        batch_id = str(row["batch_id"])
        batch = by_batch.setdefault(
            batch_id,
            {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "states": {},
            },
        )
        batch["total"] = int(batch["total"]) + 1
        states = batch["states"]
        assert isinstance(states, dict)
        state_name = str(row["state"])
        states[state_name] = int(states.get(state_name, 0)) + 1
        try:
            result = preflight_cell_authority(
                row["cell"],
                row["factor_variants"],
                root,
                authority_resolver=resolver,
            )
        except Exception as error:
            failure_class = f"{type(error).__name__}: {error}"
            failure_classes[failure_class] = failure_classes.get(failure_class, 0) + 1
            batch["failed"] = int(batch["failed"]) + 1
            if len(failures) < 20:
                failures.append(
                    {
                        "job_id": row["job_id"],
                        "batch_id": batch_id,
                        "cell_id": row["cell"].get("id"),
                        "error": failure_class,
                    }
                )
            continue
        passed += 1
        batch["passed"] = int(batch["passed"]) + 1
        if result["route_id"] is not None:
            route_ids.add(str(result["route_id"]))
        if result["treatment_id"] is not None:
            treatment_ids.add(str(result["treatment_id"]))

    document = {
        "schema_version": "fidb-execution-resolution-preflight/v1",
        "project_root": str(root),
        "selected_batches": list(selected) if selected is not None else None,
        "summary": {
            "active_jobs": len(rows),
            "passed": passed,
            "failed": len(rows) - passed,
            "routes": len(route_ids),
            "treatments": len(treatment_ids),
            "ready": passed == len(rows),
        },
        "batches": by_batch,
        "failure_classes": [
            {"error": error, "count": count}
            for error, count in sorted(
                failure_classes.items(), key=lambda item: (-item[1], item[0])
            )
        ],
        "failure_examples": failures,
    }
    _print_json(document)
    return 0 if document["summary"]["ready"] else 1


def _doctor(arguments: argparse.Namespace) -> int:
    root, state, _ = _paths(arguments, require_queue=False)
    _existing_state(state)
    from .incident_report import compile_incident_report

    document = compile_incident_report(
        root,
        state,
        batches=tuple(arguments.batches) if arguments.batches else None,
        include_inactive=arguments.include_inactive,
        history_limit=arguments.history_limit,
        services=arguments.services,
    )
    _print_json(document)
    return 0


def _start_block(arguments: argparse.Namespace) -> int:
    root, state, queue_path = _paths(arguments, require_queue=True)
    assert queue_path is not None
    config = QueueConfig.load(queue_path, root)
    if not config.armed:
        raise QueueCliError(f"queue is disarmed in {queue_path}; no block was admitted")
    with Coordinator(state, root) as coordinator:
        expected_generation = arguments.expected_sync_generation
        expected_jobs = arguments.expected_active_jobs
        if (expected_generation is None) != (expected_jobs is None):
            raise QueueCliError(
                "--expected-sync-generation and --expected-active-jobs must be used together"
            )
        if expected_generation is None:
            coordinator.sync_queue(config, actor="operator")
        else:
            if expected_generation < 1 or expected_jobs < 1:
                raise QueueCliError(
                    "synchronized admission expectations must be positive"
                )
            status = coordinator.status()
            actual_jobs = sum(int(value) for value in status["counts"].values())
            mismatches = []
            if int(status["sync_generation"]) != expected_generation:
                mismatches.append(
                    f"generation {status['sync_generation']} != {expected_generation}"
                )
            if actual_jobs != expected_jobs:
                mismatches.append(f"active jobs {actual_jobs} != {expected_jobs}")
            if status["config_name"] != config.name:
                mismatches.append(
                    f"config {status['config_name']!r} != {config.name!r}"
                )
            if Path(str(status["config_path"])).resolve() != config.source_path:
                mismatches.append("config path differs from synchronized authority")
            if not bool(status["armed"]):
                mismatches.append("synchronized queue is disarmed")
            if mismatches:
                raise QueueCliError(
                    "already-synchronized admission rejected: " + "; ".join(mismatches)
                )
        admission_id = f"manual:{datetime.now().astimezone().isoformat()}"
        block = coordinator.start_next_block(
            admission_id, scheduled=False, actor="operator"
        )
        _print_json(block or coordinator.status())
    return 0 if block is not None else 1


def _run_worker(arguments: argparse.Namespace) -> int:
    root, state, queue_path = _paths(arguments, require_queue=True)
    assert queue_path is not None
    recycled = _post_recycle_memory_audit(root, arguments.worker_id)
    if recycled and not arguments.once:
        _park_recycled_terminal_worker(root, state)
    config = QueueConfig.load(queue_path, root)
    if not config.armed:
        raise QueueCliError(f"queue is disarmed in {queue_path}; no build was started")
    build_jobs_per_cell = 4
    if config.performance_profile is not None:
        settings = config.performance_profile.settings
        try:
            os.environ["JAVA_TOOL_OPTIONS"] = java_options(
                settings.ghidra_heap_mib,
                settings.ghidra_core_limit,
            )
        except ValueError as error:
            raise QueueCliError(
                "queue worker JVM policy conflicts with performance profile "
                f"{config.performance_profile.id}: {error}"
            ) from error
        build_jobs_per_cell = settings.build_jobs_per_cell

    authority_resolver = CellAuthorityResolver(root)
    previous_sigterm = signal.getsignal(signal.SIGTERM)

    def interrupt_worker(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupt_worker)
    try:
        with Coordinator(state, root) as coordinator:
            if arguments.use_synced_queue:
                if any(batch.executions is None for batch in config.batches):
                    raise QueueCliError(
                        "synced worker startup requires executions on every batch"
                    )
                expected_jobs = sum(int(batch.executions) for batch in config.batches)
                status = coordinator.status()
                actual_jobs = sum(int(value) for value in status["counts"].values())
                mismatches = []
                if status["config_name"] != config.name:
                    mismatches.append(
                        f"config {status['config_name']!r} != {config.name!r}"
                    )
                if Path(str(status["config_path"])).resolve() != config.source_path:
                    mismatches.append("config path differs from synchronized authority")
                if actual_jobs != expected_jobs:
                    mismatches.append(f"active jobs {actual_jobs} != {expected_jobs}")
                if not bool(status["armed"]):
                    mismatches.append("synchronized queue is disarmed")
                if mismatches:
                    raise QueueCliError(
                        "synced worker startup rejected: " + "; ".join(mismatches)
                    )
            else:
                coordinator.sync_queue(config, actor=arguments.worker_id)
            last_resource_block: tuple[str, ...] | None = None
            drained_notified = False
            while True:
                operations = evaluate_operations(config.operations, root)
                schedule = operations["schedule"]
                resources = operations["resources"]
                assert isinstance(schedule, dict) and isinstance(resources, dict)
                finish_started = config.operations.schedule.finish_started_batch
                block = coordinator.execution_block() if finish_started else None
                if (
                    finish_started
                    and config.operations.schedule.enabled
                    and not bool(block["active"])
                    and bool(schedule["claims_allowed"])
                    and bool(resources["passed"])
                ):
                    window_id = schedule.get("window_started_at")
                    if not isinstance(window_id, str):
                        raise QueueCliError(
                            "open schedule did not provide a durable window identity"
                        )
                    block = coordinator.start_next_block(
                        window_id,
                        scheduled=True,
                        allow_scheduled_reentry=(
                            config.operations.schedule.chain_batches
                        ),
                        actor=arguments.worker_id,
                    )
                claims_authorized = (
                    bool(block and block["active"])
                    if finish_started
                    else bool(schedule["claims_allowed"])
                )
                if not claims_authorized:
                    drained_notified = _maybe_post_drain_maintenance(
                        coordinator,
                        root,
                        state,
                        arguments.worker_id,
                        config.operations.notifications,
                        already_notified=drained_notified,
                    )
                    if arguments.once:
                        _print_json(operations)
                        return 0
                    time.sleep(config.poll_seconds)
                    continue
                if not bool(resources["passed"]):
                    drained_notified = _maybe_post_drain_maintenance(
                        coordinator,
                        root,
                        state,
                        arguments.worker_id,
                        config.operations.notifications,
                        already_notified=drained_notified,
                    )
                    reasons = tuple(str(value) for value in resources["reasons"])
                    if reasons != last_resource_block:
                        _notify(
                            config.operations.notifications,
                            "resource-blocked",
                            {
                                "worker_id": arguments.worker_id,
                                "reasons": list(reasons),
                                "metrics": resources["metrics"],
                            },
                        )
                    last_resource_block = reasons
                    if arguments.once:
                        _print_json(operations)
                        return 0
                    time.sleep(config.poll_seconds)
                    continue
                last_resource_block = None
                lease = coordinator.claim(
                    arguments.worker_id,
                    pool=arguments.pool,
                    batch_id=(
                        str(block["batch_id"])
                        if finish_started and block is not None
                        else None
                    ),
                )
                if lease is not None:
                    drained_notified = False
                    cutoff_triggered = threading.Event()
                    timer = None
                    cutoff_value = (
                        None if finish_started else schedule.get("hard_cutoff_at")
                    )
                    if isinstance(cutoff_value, str):
                        cutoff = datetime.fromisoformat(cutoff_value)
                        delay = max(0.0, cutoff.timestamp() - time.time())

                        def interrupt_at_cutoff() -> None:
                            cutoff_triggered.set()
                            os.kill(os.getpid(), signal.SIGTERM)

                        timer = threading.Timer(delay, interrupt_at_cutoff)
                        timer.daemon = True
                        timer.start()
                    cutoff_interrupted = False
                    try:
                        succeeded = _execute_claim(
                            coordinator,
                            state,
                            root,
                            lease,
                            config.lease_seconds,
                            verbose=arguments.verbose,
                            build_jobs_per_cell=build_jobs_per_cell,
                            authority_resolver=authority_resolver,
                            notifications=config.operations.notifications,
                        )
                    except KeyboardInterrupt:
                        if cutoff_triggered.is_set():
                            _notify(
                                config.operations.notifications,
                                "schedule-cutoff",
                                {
                                    "worker_id": arguments.worker_id,
                                    "job_id": lease["job_id"],
                                    "hard_cutoff_at": cutoff_value,
                                },
                            )
                            cutoff_interrupted = True
                            succeeded = False
                        else:
                            raise
                    finally:
                        if timer is not None:
                            timer.cancel()
                    if cutoff_interrupted:
                        if arguments.once:
                            return 1
                        continue
                    if finish_started:
                        drained = coordinator.finish_active_block_if_drained(
                            actor=arguments.worker_id
                        )
                        if drained:
                            try:
                                from .machine_validation import (
                                    reconcile_all_machine_validations,
                                )

                                reconcile_all_machine_validations(root)
                            except (OSError, ValueError) as error:
                                print(
                                    f"warning: machine-validation reconcile failed: {error}",
                                    file=sys.stderr,
                                )
                    if arguments.once:
                        return 0 if succeeded else 1
                    continue

                if finish_started:
                    coordinator.finish_active_block_if_drained(
                        actor=arguments.worker_id
                    )
                if arguments.once:
                    _print_json(coordinator.status())
                    return 0
                drained_notified = _maybe_post_drain_maintenance(
                    coordinator,
                    root,
                    state,
                    arguments.worker_id,
                    config.operations.notifications,
                    already_notified=drained_notified,
                )
                time.sleep(config.poll_seconds)
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    handlers = {
        "sync": _sync,
        "reconfigure-runtime": _reconfigure_runtime,
        "status": _status,
        "events": _events,
        "pause": _pause,
        "resume": _resume,
        "requeue-failed": _requeue_failed,
        "requeue-interrupted": _requeue_interrupted,
        "preflight": _preflight,
        "resolve-preflight": _resolution_preflight,
        "doctor": _doctor,
        "start-block": _start_block,
        "run": _run_worker,
    }
    try:
        return handlers[arguments.command](arguments)
    except KeyboardInterrupt:
        print("worker interrupted", file=sys.stderr)
        return 130
    except (OSError, QueueCliError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
