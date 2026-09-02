"""Read-only inventory of measured width evidence and lane DB generations."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from urllib.parse import quote

from .lane_database import (
    LANE_DATABASE_APPLICATION_ID,
    LANE_DATABASE_USER_VERSION,
)
from .lane_registry import load_lane_registry

LANE_INVENTORY_SCHEMA = "fidb-lane-inventory/v1"
COMPACT_APPLICATION_ID = 0x46494443  # FIDC
COMPACT_USER_VERSION = 1
MAX_WIDTH_RESULT_BYTES = 64 * 1024 * 1024


def _relative(root: Path, path: Path) -> str:
    return str(path.resolve().relative_to(root))


def _regular_managed_file(root: Path, path: Path) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(root)
    except ValueError:
        return False
    cursor = root
    for part in relative.parts[:-1]:
        cursor /= part
        if cursor.is_symlink():
            return False
    return True


def _modified_at(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()


def _read_width_run(root: Path, path: Path) -> dict[str, object]:
    size = path.stat().st_size
    if size > MAX_WIDTH_RESULT_BYTES:
        raise ValueError(
            f"width result exceeds {MAX_WIDTH_RESULT_BYTES} byte inventory limit"
        )
    document = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != "fidb-width-run/v1"
    ):
        raise ValueError("unsupported width-run result")
    relative = path.parent.relative_to(root / "artifacts/width-runs")
    width_id, run_id = relative.parts
    state = str(document.get("state", "unknown"))
    coverage = document.get("coverage")
    coverage = coverage if isinstance(coverage, dict) else {}
    hashes = document.get("hash_coverage")
    hashes = hashes if isinstance(hashes, dict) else {}
    totals = hashes.get("totals")
    totals = totals if isinstance(totals, dict) else {}
    return {
        "width_id": width_id,
        "run_id": run_id,
        "path": _relative(root, path),
        "state": state,
        "mode": document.get("mode"),
        "fixed_recipe": document.get("fixed_recipe"),
        "started_at_utc": document.get("started_at_utc"),
        "finished_at_utc": document.get("finished_at_utc"),
        "wall_time_ns": int(document.get("wall_time_ns") or 0),
        "parallel_workers": int(document.get("parallel_workers") or 0),
        "scheduled_executions": int(document.get("scheduled_executions") or 0),
        "completed_executions": int(document.get("completed_executions") or 0),
        "failed_executions": int(document.get("failed_executions") or 0),
        "successful_route_profile_pairs": int(
            coverage.get("successful_route_profile_pairs") or 0
        ),
        "signature_records": int(totals.get("signature_records") or 0),
        "unique_signatures": int(totals.get("unique_signatures") or 0),
        "retained_bytes": int(document.get("retained_bytes") or 0),
        "peak_scratch_bytes": int(document.get("peak_scratch_bytes") or 0),
        "result_bytes": size,
        "modified_at_utc": _modified_at(path),
    }


def _open_inventory_database(path: Path) -> sqlite3.Connection:
    uri = f"file:{quote(str(path.resolve()), safe='/')}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    connection.execute("PRAGMA busy_timeout = 0")
    return connection


def _raw_database(
    root: Path,
    path: Path,
    connection: sqlite3.Connection,
    lane_ids: set[str],
) -> dict[str, object]:
    if (
        connection.execute("PRAGMA user_version").fetchone()[0]
        != LANE_DATABASE_USER_VERSION
    ):
        raise ValueError("unsupported raw lane database version")
    rows = connection.execute("""
        SELECT id, lane_id, lane_label, lane_state, created_at, source_run_id,
               evidence_kind, native_projection_state, signature_records,
               raw_signature_observations, function_relationships
        FROM lane_generation
        """).fetchall()
    if len(rows) != 1:
        raise ValueError("raw lane database must contain one generation")
    generation = dict(rows[0])
    lane_id = str(generation["lane_id"])
    if lane_id not in lane_ids:
        raise ValueError(f"raw database references unknown lane {lane_id}")
    sublanes = [
        str(row[0]) for row in connection.execute("SELECT id FROM sublane ORDER BY id")
    ]
    return {
        "kind": "raw",
        "path": _relative(root, path),
        "bytes": path.stat().st_size,
        "modified_at_utc": _modified_at(path),
        "generation_id": generation["id"],
        "source_generation_id": None,
        "source_run_id": generation["source_run_id"],
        "lane_id": lane_id,
        "sublane_ids": sublanes,
        "state": generation["lane_state"],
        "created_at": generation["created_at"],
        "evidence_kind": generation["evidence_kind"],
        "raw_observations": int(generation["raw_signature_observations"]),
        "unique_signatures": None,
        "repeated_observations": None,
        "repetition_fraction": None,
        "relationships": int(generation["function_relationships"]),
        "native_projections": int(
            connection.execute("SELECT count(*) FROM native_projection").fetchone()[0]
        ),
        "native_projection_state": generation["native_projection_state"],
        "ecological_validation_state": "not-requested",
        "active": False,
    }


def _compact_database(
    root: Path,
    path: Path,
    connection: sqlite3.Connection,
    lane_by_sublane: dict[str, str],
) -> dict[str, object]:
    if connection.execute("PRAGMA user_version").fetchone()[0] != COMPACT_USER_VERSION:
        raise ValueError("unsupported compact lane database version")
    rows = connection.execute("""
        SELECT id, source_generation_id, created_at, state, raw_observations,
               unique_signatures, repeated_observations
        FROM compact_generation
        """).fetchall()
    if len(rows) != 1:
        raise ValueError("compact lane database must contain one generation")
    generation = dict(rows[0])
    sublanes = [
        str(row[0]) for row in connection.execute("SELECT id FROM sublane ORDER BY id")
    ]
    lanes = {lane_by_sublane.get(sublane) for sublane in sublanes}
    if None in lanes or len(lanes) != 1:
        raise ValueError("compact database sublanes do not resolve to one lane")
    raw = int(generation["raw_observations"])
    repeated = int(generation["repeated_observations"])
    admission_states = {
        str(row[0]): int(row[1])
        for row in connection.execute(
            "SELECT state, count(*) FROM admission_decision GROUP BY state"
        )
    }
    ecological_state = (
        "unreviewed" if admission_states.get("unreviewed", 0) else "decisions-recorded"
    )
    return {
        "kind": "compact",
        "path": _relative(root, path),
        "bytes": path.stat().st_size,
        "modified_at_utc": _modified_at(path),
        "generation_id": generation["id"],
        "source_generation_id": generation["source_generation_id"],
        "source_run_id": None,
        "lane_id": next(iter(lanes)),
        "sublane_ids": sublanes,
        "state": generation["state"],
        "created_at": generation["created_at"],
        "evidence_kind": "compacted-occurrences",
        "raw_observations": raw,
        "unique_signatures": int(generation["unique_signatures"]),
        "repeated_observations": repeated,
        "repetition_fraction": repeated / raw if raw else 0.0,
        "relationships": int(
            connection.execute("SELECT count(*) FROM function_relationship").fetchone()[
                0
            ]
        ),
        "native_projections": int(
            connection.execute("SELECT count(*) FROM native_projection").fetchone()[0]
        ),
        "native_projection_state": "not-requested",
        "ecological_validation_state": ecological_state,
        "admission_states": admission_states,
        "active": False,
    }


def _read_lane_database(
    root: Path,
    path: Path,
    lane_ids: set[str],
    lane_by_sublane: dict[str, str],
) -> dict[str, object]:
    with _open_inventory_database(path) as connection:
        application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
        if application_id == LANE_DATABASE_APPLICATION_ID:
            return _raw_database(root, path, connection, lane_ids)
        if application_id == COMPACT_APPLICATION_ID:
            return _compact_database(root, path, connection, lane_by_sublane)
        raise ValueError(f"unrecognised SQLite application id {application_id}")


def detect_lane_inventory(project_root: str | Path) -> dict[str, object]:
    """Discover managed evidence without changing or fully scanning any artifact."""

    root = Path(project_root).expanduser().resolve()
    registry = load_lane_registry(
        root / "lanes/registry.toml", root / "targets/registry.toml"
    )
    lane_ids = {str(lane["id"]) for lane in registry["lanes"]}
    lane_by_sublane = {
        str(sublane["id"]): str(lane["id"])
        for lane in registry["lanes"]
        for sublane in lane["sublanes"]
    }
    issues: list[dict[str, str]] = []

    width_runs: list[dict[str, object]] = []
    width_root = root / "artifacts/width-runs"
    if width_root.is_dir() and not width_root.is_symlink():
        for path in sorted(width_root.glob("*/*/width-run.json")):
            if not _regular_managed_file(root, path):
                issues.append({"path": str(path), "reason": "unsafe width-run path"})
                continue
            try:
                width_runs.append(_read_width_run(root, path))
            except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
                issues.append({"path": _relative(root, path), "reason": str(error)})
    width_runs.sort(
        key=lambda row: str(row.get("finished_at_utc") or row["modified_at_utc"]),
        reverse=True,
    )

    databases: list[dict[str, object]] = []
    database_root = root / "var/fidb-lanes"
    if database_root.is_dir() and not database_root.is_symlink():
        for path in sorted(database_root.rglob("*.sqlite3")):
            if not _regular_managed_file(root, path):
                issues.append({"path": str(path), "reason": "unsafe database path"})
                continue
            try:
                databases.append(
                    _read_lane_database(root, path, lane_ids, lane_by_sublane)
                )
            except (OSError, ValueError, sqlite3.DatabaseError) as error:
                issues.append({"path": _relative(root, path), "reason": str(error)})
    databases.sort(key=lambda row: str(row["created_at"]), reverse=True)

    complete_runs = [row for row in width_runs if row["state"] == "measured-complete"]
    raw_databases = [row for row in databases if row["kind"] == "raw"]
    compact_databases = [row for row in databases if row["kind"] == "compact"]
    return {
        "schema_version": LANE_INVENTORY_SCHEMA,
        "detection_mode": "read-only-metadata",
        "roots": {
            "width_runs": "artifacts/width-runs",
            "lane_databases": "var/fidb-lanes",
        },
        "inspection": {
            "sqlite_open_mode": "read-only-immutable",
            "content_digests": "not-computed",
            "full_integrity_check": "not-run-on-refresh",
        },
        "summary": {
            "width_runs": len(width_runs),
            "complete_width_runs": len(complete_runs),
            "raw_generations": len(raw_databases),
            "compact_generations": len(compact_databases),
            "materialized_generations": len(databases),
            "active_packs": sum(bool(row["active"]) for row in databases),
            "lane_database_bytes": sum(int(row["bytes"]) for row in databases),
            "raw_observations": sum(
                int(row["raw_observations"]) for row in raw_databases
            ),
            "compact_unique_signatures": sum(
                int(row["unique_signatures"]) for row in compact_databases
            ),
            "issues": len(issues),
        },
        "latest_complete_width_run": complete_runs[0] if complete_runs else None,
        "width_runs": width_runs,
        "databases": databases,
        "issues": issues,
    }
