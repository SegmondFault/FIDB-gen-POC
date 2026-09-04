"""Read-only incident and recovery diagnostics for the durable build queue.

The report intentionally opens SQLite in read-only mode and never calls the
coordinator's migration or transition paths.  It is safe to collect while a
campaign is running: one SQLite read transaction supplies a coherent snapshot,
and optional systemd inspection uses only ``systemctl show``.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import sqlite3
import subprocess
from typing import Iterable

INCIDENT_REPORT_SCHEMA = "fidb-queue-incident-report/v1"
DEFAULT_WORKER_UNIT = Path("operations/fidb-library-local-worker@.service")
_COUNT_STATES = ("blocked", "complete", "failed", "leased", "queued", "running")
_SERVICE_PROPERTIES = (
    "Id",
    "ActiveState",
    "SubState",
    "TasksCurrent",
    "TasksMax",
    "MemoryCurrent",
    "MemoryPeak",
)


def _inside(root: Path, path: str | Path, label: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = candidate.expanduser().resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError(f"{label} must be inside the project root")
    return candidate


def _open_read_only(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise ValueError(f"coordinator ledger is unavailable: {path}")
    connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    required = {
        "attempts",
        "batches",
        "coordinator_state",
        "events",
        "jobs",
        "stage_attempts",
    }
    present = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    missing = required - present
    if missing:
        connection.close()
        raise ValueError(f"coordinator ledger lacks required tables: {sorted(missing)}")
    return connection


def _digest_job_ids(rows: Iterable[sqlite3.Row]) -> str:
    digest = hashlib.sha256()
    for row in rows:
        digest.update(str(row["job_id"]).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _counts(rows: Iterable[sqlite3.Row]) -> dict[str, int]:
    result = {state: 0 for state in _COUNT_STATES}
    for row in rows:
        result[str(row["state"])] = int(row["count"])
    return result


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _unit_limits(path: Path) -> dict[str, str]:
    wanted = {"CPUQuota", "MemoryHigh", "MemoryMax", "TasksMax"}
    result: dict[str, str] = {}
    if not path.is_file():
        return result
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")) or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in wanted:
            result[key] = value
    return result


def inspect_worker_unit(root: Path) -> dict[str, object]:
    """Compare checked-in and installed worker service authority."""

    repository = root / DEFAULT_WORKER_UNIT
    installed = Path.home() / ".config/systemd/user" / DEFAULT_WORKER_UNIT.name
    repository_exists = repository.is_file()
    installed_exists = installed.is_file()
    repository_sha256 = _sha256(repository) if repository_exists else None
    installed_sha256 = _sha256(installed) if installed_exists else None
    return {
        "repository_path": str(repository),
        "repository_exists": repository_exists,
        "repository_sha256": repository_sha256,
        "repository_limits": _unit_limits(repository),
        "installed_path": str(installed),
        "installed_exists": installed_exists,
        "installed_sha256": installed_sha256,
        "installed_limits": _unit_limits(installed),
        "matches_repository": bool(
            repository_exists
            and installed_exists
            and repository_sha256 == installed_sha256
        ),
    }


def inspect_worker_services(max_workers: int) -> dict[str, object]:
    """Read live worker cgroup counters through ``systemctl show``."""

    units = [
        f"fidb-library-local-worker@{index}.service"
        for index in range(1, max_workers + 1)
    ]
    command = ["systemctl", "--user", "show", *units, "--no-pager"]
    for property_name in _SERVICE_PROPERTIES:
        command.append(f"--property={property_name}")
    try:
        process = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {
            "state": "unavailable",
            "reason": str(error),
            "units_requested": len(units),
        }
    if process.returncode != 0:
        return {
            "state": "unavailable",
            "reason": process.stderr.strip()[:1000] or "systemctl show failed",
            "units_requested": len(units),
        }

    records: list[dict[str, object]] = []
    for block in process.stdout.strip().split("\n\n"):
        record: dict[str, object] = {}
        for line in block.splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key in {"TasksCurrent", "TasksMax", "MemoryCurrent", "MemoryPeak"}:
                record[key] = int(value) if value.isdigit() else value
            elif key in _SERVICE_PROPERTIES:
                record[key] = value
        if record.get("Id"):
            records.append(record)
    active = sum(record.get("ActiveState") == "active" for record in records)
    return {
        "state": "available",
        "units_requested": len(units),
        "units_reported": len(records),
        "active": active,
        "inactive": len(records) - active,
        "units": records,
    }


def _failure_rules(errors: list[str], classes: list[str]) -> list[dict[str, object]]:
    evidence = "\n".join([*errors, *classes]).lower()
    rules = []
    definitions = (
        (
            "canonical-authority-resolution",
            (
                "authority-resolution",
                "unknown route",
                "queued toolchain",
                "identity differs",
            ),
            "Run resolve-preflight across the exact active generation; repair authority and prove it with an isolated canary before requeueing.",
        ),
        (
            "native-thread-task-ceiling",
            (
                "unable to create native thread",
                "pthread_create",
                "resource temporarily unavailable",
            ),
            "Compare TasksCurrent with TasksMax; do not treat this signature as Java-heap exhaustion without memory evidence.",
        ),
        (
            "source-cache-or-network",
            ("download", "connection", "network", "checksum", "source cache"),
            "Verify the content-addressed source cache and checksum pin; do not make every attempt fetch upstream.",
        ),
        (
            "sqlite-write-contention",
            ("database is locked", "database table is locked", "sqlite_busy"),
            "Preserve the failed attempt, inspect concurrent coordinator writes and heartbeat timeout evidence, and do not requeue while other leases are live.",
        ),
        (
            "archive-boundary",
            ("symlink", "archive", "tarfile", "outside extraction"),
            "Inspect archive extraction and retained-object handling; accept only safe relative links and pinned archives.",
        ),
        (
            "object-format-validation",
            ("coff", "elf", "mach-o", "object format", "file output"),
            "Inspect binary headers and the target validator before weakening an exact object-format assertion.",
        ),
        (
            "recipe-adapter-build",
            ("configure", "cmake", "make", "build failed", "compiler"),
            "Reproduce through the fixed adapter, add a regression test, and run the smallest route-family canary.",
        ),
    )
    for rule_id, needles, action in definitions:
        matched = sorted(needle for needle in needles if needle in evidence)
        if matched:
            rules.append({"id": rule_id, "matched": matched, "action": action})
    return rules


def compile_incident_report(
    project_root: str | Path,
    ledger: str | Path,
    *,
    batches: tuple[str, ...] | None = None,
    include_inactive: bool = False,
    history_limit: int = 20,
    services: bool = False,
) -> dict[str, object]:
    """Compile one bounded, mutation-free queue incident report."""

    if history_limit < 1 or history_limit > 200:
        raise ValueError("incident history limit must be 1-200")
    root = Path(project_root).expanduser().resolve()
    state_path = _inside(root, ledger, "coordinator ledger")
    selected = tuple(dict.fromkeys(batches or ()))
    if any(not value or value != value.strip() for value in selected):
        raise ValueError("incident batch ids must be non-empty strings")

    connection = _open_read_only(state_path)
    try:
        connection.execute("BEGIN")
        state = connection.execute(
            "SELECT * FROM coordinator_state WHERE singleton = 1"
        ).fetchone()
        if state is None:
            raise ValueError("coordinator state is missing")

        global_counts = _counts(
            connection.execute(
                """
                SELECT jobs.state, COUNT(*) AS count
                FROM jobs JOIN batches ON batches.batch_id = jobs.batch_id
                WHERE jobs.active = 1 AND batches.active = 1
                GROUP BY jobs.state
                """
            ).fetchall()
        )
        if selected:
            placeholders = ",".join("?" for _value in selected)
            known = {
                str(row["batch_id"])
                for row in connection.execute(
                    f"SELECT batch_id FROM batches WHERE batch_id IN ({placeholders})",
                    selected,
                ).fetchall()
            }
            unknown = set(selected) - known
            if unknown:
                raise ValueError(f"incident report selected unknown batches: {sorted(unknown)}")

        scope = ["jobs.active = 1", "batches.active = 1"]
        parameters: list[object] = []
        if include_inactive:
            scope = ["1 = 1"]
        if selected:
            placeholders = ",".join("?" for _value in selected)
            scope.append(f"jobs.batch_id IN ({placeholders})")
            parameters.extend(selected)
        where = " AND ".join(scope)

        counts = _counts(
            connection.execute(
                f"""
                SELECT jobs.state, COUNT(*) AS count
                FROM jobs JOIN batches ON batches.batch_id = jobs.batch_id
                WHERE {where}
                GROUP BY jobs.state
                """,
                parameters,
            ).fetchall()
        )
        batch_rows = connection.execute(
            f"""
            SELECT batches.position, batches.batch_id, batches.name,
                   batches.active, jobs.state, COUNT(*) AS count
            FROM jobs JOIN batches ON batches.batch_id = jobs.batch_id
            WHERE {where}
            GROUP BY batches.batch_id, jobs.state
            ORDER BY batches.active DESC, batches.position, batches.batch_id
            """,
            parameters,
        ).fetchall()
        batch_documents: dict[str, dict[str, object]] = {}
        for row in batch_rows:
            batch_id = str(row["batch_id"])
            document = batch_documents.setdefault(
                batch_id,
                {
                    "position": int(row["position"]),
                    "batch_id": batch_id,
                    "name": str(row["name"]),
                    "active": bool(row["active"]),
                    "counts": {state_name: 0 for state_name in _COUNT_STATES},
                },
            )
            document["counts"][str(row["state"])] = int(row["count"])

        failed_rows = connection.execute(
            f"""
            SELECT jobs.job_id, jobs.batch_id, jobs.position,
                   jobs.attempt_count, jobs.failure_class, jobs.error,
                   jobs.active AS job_active, batches.active AS batch_active
            FROM jobs JOIN batches ON batches.batch_id = jobs.batch_id
            WHERE {where} AND jobs.state = 'failed'
            ORDER BY batches.position, jobs.position, jobs.job_id
            """,
            parameters,
        ).fetchall()
        failures_by_batch: dict[str, list[sqlite3.Row]] = {}
        classes: dict[str, int] = {}
        fingerprints: dict[tuple[str, str], int] = {}
        for row in failed_rows:
            failures_by_batch.setdefault(str(row["batch_id"]), []).append(row)
            failure_class = str(row["failure_class"] or "unclassified")
            error = str(row["error"] or "")
            classes[failure_class] = classes.get(failure_class, 0) + 1
            digest = hashlib.sha256(error.encode("utf-8")).hexdigest()
            fingerprints[(digest, error)] = fingerprints.get((digest, error), 0) + 1

        attempt_scope = ["1 = 1"] if include_inactive else ["jobs.active = 1"]
        attempt_parameters: list[object] = []
        if selected:
            placeholders = ",".join("?" for _value in selected)
            attempt_scope.append(f"jobs.batch_id IN ({placeholders})")
            attempt_parameters.extend(selected)
        recent_attempts = connection.execute(
            f"""
            SELECT attempts.attempt_id, attempts.job_id, jobs.batch_id,
                   attempts.attempt_number, attempts.worker_id,
                   attempts.started_at, attempts.ended_at, attempts.error
            FROM attempts JOIN jobs ON jobs.job_id = attempts.job_id
            WHERE {' AND '.join(attempt_scope)} AND attempts.state = 'failed'
            ORDER BY attempts.attempt_id DESC LIMIT ?
            """,
            [*attempt_parameters, history_limit],
        ).fetchall()
        recent_stages = connection.execute(
            f"""
            SELECT stage_attempts.stage_attempt_id, stage_attempts.job_id,
                   jobs.batch_id, stage_attempts.attempt_number,
                   stage_attempts.stage, stage_attempts.ended_at,
                   stage_attempts.error
            FROM stage_attempts JOIN jobs ON jobs.job_id = stage_attempts.job_id
            WHERE {' AND '.join(attempt_scope)} AND stage_attempts.state = 'failed'
            ORDER BY stage_attempts.stage_attempt_id DESC LIMIT ?
            """,
            [*attempt_parameters, history_limit],
        ).fetchall()
        incident_events = connection.execute(
            """
            SELECT event_id, occurred_at, event_type, actor, batch_id, job_id,
                   payload_json
            FROM events
            WHERE event_type IN (
                'queue.circuit-opened', 'queue.paused', 'job.failed',
                'job.operator-requeued', 'batch.failed-jobs-requeued'
            )
            ORDER BY event_id DESC LIMIT ?
            """,
            (history_limit,),
        ).fetchall()
        connection.execute("COMMIT")
    finally:
        connection.close()

    live = global_counts["leased"] + global_counts["running"]
    armed = bool(state["armed"])
    paused = bool(state["paused"])
    active_batch = state["active_batch_id"]
    global_blockers = []
    if armed:
        global_blockers.append("the durable queue is armed")
    if not paused:
        global_blockers.append("the durable queue is not paused")
    if live:
        global_blockers.append(f"{live} active jobs still hold live work")

    recovery_candidates = []
    active_failures_by_batch = {
        batch_id: [
            row
            for row in rows
            if bool(row["job_active"]) and bool(row["batch_active"])
        ]
        for batch_id, rows in failures_by_batch.items()
    }
    active_failures_by_batch = {
        batch_id: rows for batch_id, rows in active_failures_by_batch.items() if rows
    }
    for batch_id, rows in active_failures_by_batch.items():
        blockers = list(global_blockers)
        if active_batch not in (None, batch_id):
            blockers.append(
                f"active admission belongs to different batch {active_batch}"
            )
        expected = len(rows)
        recovery_candidates.append(
            {
                "batch_id": batch_id,
                "failed_jobs": expected,
                "job_ids_sha256": _digest_job_ids(rows),
                "attempt_evidence_preserved_by_transition": True,
                "ready": not blockers,
                "blockers": blockers,
                "command": (
                    "uv run fidb-poc queue requeue-failed --project-root . "
                    "--state var/fidb-coordinator/ledger.sqlite3 "
                    f"--batch {batch_id} --expected-count {expected} "
                    '--reason "REVIEWED_REPAIR_AND_CANARY"'
                ),
            }
        )

    current_job_ids = {str(row["job_id"]) for row in failed_rows}
    current_errors = [str(row["error"] or "") for row in failed_rows]
    current_errors.extend(
        str(row["error"] or "")
        for row in recent_stages
        if str(row["job_id"]) in current_job_ids
    )
    historical_errors = [str(row["error"] or "") for row in recent_attempts]
    historical_errors.extend(str(row["error"] or "") for row in recent_stages)
    class_names = list(classes)
    unit = inspect_worker_unit(root)
    report: dict[str, object] = {
        "schema_version": INCIDENT_REPORT_SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "project_root": str(root),
        "ledger": str(state_path),
        "selection": {
            "batches": list(selected) if selected else None,
            "include_inactive": include_inactive,
            "history_limit": history_limit,
        },
        "queue": {
            "config_name": state["config_name"],
            "config_path": state["config_path"],
            "armed": armed,
            "paused": paused,
            "active_batch_id": active_batch,
            "active_admission_id": state["active_admission_id"],
            "max_workers": int(state["max_workers"]),
            "authority_failure_threshold": int(state["authority_failure_threshold"]),
            "sync_generation": int(state["sync_generation"]),
            "synced_at": state["synced_at"],
            "selection_counts": counts,
            "global_counts": global_counts,
            "global_live_work": live,
        },
        "batches": list(batch_documents.values()),
        "failures": {
            "in_selection": len(failed_rows),
            "current": sum(len(rows) for rows in active_failures_by_batch.values()),
            "classes": [
                {"failure_class": name, "count": count}
                for name, count in sorted(
                    classes.items(), key=lambda item: (-item[1], item[0])
                )
            ],
            "fingerprints": [
                {
                    "sha256": digest,
                    "count": count,
                    "error_excerpt": error[:1000],
                }
                for (digest, error), count in sorted(
                    fingerprints.items(), key=lambda item: (-item[1], item[0][0])
                )[:history_limit]
            ],
            "recent_attempts": [dict(row) for row in recent_attempts],
            "recent_stage_failures": [dict(row) for row in recent_stages],
        },
        "recent_incident_events": [dict(row) for row in incident_events],
        "diagnostic_rules": {
            "current": _failure_rules(current_errors, class_names),
            "recent_history": _failure_rules(historical_errors, class_names),
        },
        "worker_unit": unit,
        "recovery": {
            "mutation_performed": False,
            "global_blockers": global_blockers,
            "candidates": recovery_candidates,
            "commands": {
                "status": "uv run fidb-poc queue status --full",
                "authority": "uv run fidb-poc queue resolve-preflight",
                "operations": "uv run fidb-poc queue preflight",
                "pause": 'uv run fidb-poc queue pause --reason "incident review"',
                "events": "uv run fidb-poc queue events",
            },
        },
    }
    if services:
        report["worker_services"] = inspect_worker_services(int(state["max_workers"]))
    return report
