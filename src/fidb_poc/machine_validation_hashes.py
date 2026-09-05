"""Reanalyse sealed machine-validation composites at single-hash granularity.

The expensive build and Ghidra stages deliberately remain separate.  This
module consumes their retained signature exports and the exact-identity
reference index.  It never executes a target binary and never changes the
production queue.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import tomllib
from typing import Iterable, Mapping
from zoneinfo import ZoneInfo


HASH_REPORT_SCHEMA = "fidb-machine-validation-hash-report/v1"
HASH_EVIDENCE_SCHEMA = "fidb-machine-validation-hash-evidence/v1"
DECISION_UNIT = "complete-fid-signature-owner-assertion"
HASH_SCHEDULE_SCHEMA = "fidb-machine-validation-hash-schedule/v1"
DEFAULT_HASH_SCHEDULE = Path("validation/machine-validation-hash-schedule.toml")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_json(path: Path, document: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        prefix=f".{path.name}-", suffix=".tmp", dir=path.parent
    )
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _signature_rows(
    path: Path,
) -> Iterable[tuple[str, str, str, str, str, int, int]]:
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            yield (
                str(row.get("address", "")),
                str(row.get("function_name", row.get("name", ""))),
                str(row.get("ghidra_language_id", row.get("language", ""))),
                str(row["full_hash"]),
                str(row["specific_hash"]),
                int(row["specific_hash_additional_size"]),
                int(row["code_unit_size"]),
            )


def _scope(target_os: str, binary_format: str, language: str) -> str:
    return f"{target_os}|{binary_format}|{language}"


def _create_evidence(path: Path, source_run_id: str, source_digest: str) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.executescript(
        """
        CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE unit_result(
            position INTEGER NOT NULL,
            route_id TEXT NOT NULL,
            treatment_id TEXT NOT NULL,
            fold TEXT NOT NULL,
            query_path TEXT NOT NULL,
            query_sha256 TEXT NOT NULL,
            query_distinct_signatures INTEGER NOT NULL,
            true_positives INTEGER NOT NULL,
            false_positives INTEGER NOT NULL,
            true_negatives INTEGER NOT NULL,
            false_negatives INTEGER NOT NULL,
            unattributed_query_signatures INTEGER NOT NULL,
            PRIMARY KEY(position, fold)
        ) WITHOUT ROWID;
        CREATE TABLE hash_observation(
            scope TEXT NOT NULL,
            language TEXT NOT NULL,
            full_hash TEXT NOT NULL,
            specific_hash TEXT NOT NULL,
            additional_size INTEGER NOT NULL,
            code_size INTEGER NOT NULL,
            outcome TEXT NOT NULL CHECK(outcome IN ('tp','fp','fn')),
            owner TEXT NOT NULL,
            route_id TEXT NOT NULL,
            treatment_id TEXT NOT NULL,
            fold TEXT NOT NULL,
            query_address TEXT NOT NULL,
            query_function TEXT NOT NULL,
            corpus_function TEXT NOT NULL,
            evidence_path TEXT NOT NULL,
            PRIMARY KEY(
                scope, language, full_hash, specific_hash, additional_size,
                code_size, outcome, owner, route_id, treatment_id, fold
            )
        ) WITHOUT ROWID;
        CREATE INDEX hash_observation_outcome
            ON hash_observation(outcome, scope, full_hash, specific_hash);
        CREATE TABLE hash_summary(
            scope TEXT NOT NULL,
            language TEXT NOT NULL,
            full_hash TEXT NOT NULL,
            specific_hash TEXT NOT NULL,
            additional_size INTEGER NOT NULL,
            code_size INTEGER NOT NULL,
            true_positives INTEGER NOT NULL,
            false_positives INTEGER NOT NULL,
            false_negatives INTEGER NOT NULL,
            distinct_correct_owners INTEGER NOT NULL,
            distinct_incorrect_owners INTEGER NOT NULL,
            distinct_reference_owners INTEGER NOT NULL,
            distinct_routes INTEGER NOT NULL,
            distinct_treatments INTEGER NOT NULL,
            PRIMARY KEY(
                scope, language, full_hash, specific_hash, additional_size,
                code_size
            )
        ) WITHOUT ROWID;
        """
    )
    connection.executemany(
        "INSERT INTO metadata VALUES (?,?)",
        (
            ("schema_version", HASH_EVIDENCE_SCHEMA),
            ("source_run_id", source_run_id),
            ("source_digest", source_digest),
            ("decision_unit", DECISION_UNIT),
            ("state", "building"),
        ),
    )
    connection.commit()
    return connection


def _load_query(connection: sqlite3.Connection, query_path: Path) -> int:
    connection.execute("DROP TABLE IF EXISTS temp.query_signature")
    connection.execute(
        """
        CREATE TEMP TABLE query_signature(
            address TEXT NOT NULL,
            function_name TEXT NOT NULL,
            language TEXT NOT NULL,
            full_hash TEXT NOT NULL,
            specific_hash TEXT NOT NULL,
            additional_size INTEGER NOT NULL,
            code_size INTEGER NOT NULL,
            PRIMARY KEY(
                language, full_hash, specific_hash, additional_size, code_size
            )
        ) WITHOUT ROWID
        """
    )
    connection.executemany(
        "INSERT OR IGNORE INTO query_signature VALUES (?,?,?,?,?,?,?)",
        _signature_rows(query_path),
    )
    return int(connection.execute("SELECT COUNT(*) FROM query_signature").fetchone()[0])


def _classify_fold(
    output: sqlite3.Connection,
    reference: sqlite3.Connection,
    *,
    position: int,
    route_id: str,
    treatment_id: str,
    target_os: str,
    binary_format: str,
    fold: str,
    present: list[str],
    cohort: list[str],
    query_path: Path,
    query_relative: str,
) -> dict[str, int]:
    query_count = _load_query(reference, query_path)
    present_set = set(present)
    absent_set = set(cohort) - present_set
    reference.execute("DROP TABLE IF EXISTS temp.fold_owner")
    reference.execute(
        "CREATE TEMP TABLE fold_owner(owner TEXT PRIMARY KEY, present INTEGER NOT NULL) WITHOUT ROWID"
    )
    reference.executemany(
        "INSERT INTO fold_owner VALUES (?,?)",
        ((owner, int(owner in present_set)) for owner in cohort),
    )
    match_sql = """
        SELECT query.address, query.function_name, query.language,
               query.full_hash, query.specific_hash, query.additional_size,
               query.code_size, reference.owner, reference.function_name,
               reference.evidence_path, fold_owner.present
        FROM query_signature AS query
        JOIN reference_identity AS reference
          ON reference.target_os=? AND reference.binary_format=?
         AND reference.route_id=? AND reference.treatment_id=?
         AND reference.language=query.language
         AND reference.full_hash=query.full_hash
         AND reference.specific_hash=query.specific_hash
         AND reference.additional_size=query.additional_size
         AND reference.code_size=query.code_size
        JOIN fold_owner ON fold_owner.owner=reference.owner
    """
    matches = list(
        reference.execute(
            match_sql, (target_os, binary_format, route_id, treatment_id)
        )
    )
    tp = sum(int(row[10]) for row in matches)
    fp = len(matches) - tp
    matched_query = {
        (row[2], row[3], row[4], int(row[5]), int(row[6]))
        for row in matches
        if int(row[10])
    }
    observation_rows = []
    for row in matches:
        address, query_name, language, full_hash, specific_hash, additional, size, owner, corpus_name, evidence_path, is_present = row
        observation_rows.append(
            (
                _scope(target_os, binary_format, str(language)),
                str(language), str(full_hash), str(specific_hash), int(additional),
                int(size), "tp" if is_present else "fp", str(owner), route_id,
                treatment_id, fold, str(address), str(query_name), str(corpus_name),
                str(evidence_path),
            )
        )
    output.executemany(
        "INSERT OR REPLACE INTO hash_observation VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        observation_rows,
    )
    miss_sql = """
        SELECT reference.language, reference.full_hash, reference.specific_hash,
               reference.additional_size, reference.code_size, reference.owner,
               reference.function_name, reference.evidence_path
        FROM reference_identity AS reference
        JOIN fold_owner ON fold_owner.owner=reference.owner AND fold_owner.present=1
        LEFT JOIN query_signature AS query
          ON query.language=reference.language
         AND query.full_hash=reference.full_hash
         AND query.specific_hash=reference.specific_hash
         AND query.additional_size=reference.additional_size
         AND query.code_size=reference.code_size
        WHERE reference.target_os=? AND reference.binary_format=?
          AND reference.route_id=? AND reference.treatment_id=?
          AND query.language IS NULL
    """
    misses = list(
        reference.execute(
            miss_sql, (target_os, binary_format, route_id, treatment_id)
        )
    )
    output.executemany(
        "INSERT OR REPLACE INTO hash_observation VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            (
                _scope(target_os, binary_format, str(language)), str(language),
                str(full_hash), str(specific_hash), int(additional), int(size),
                "fn", str(owner), route_id, treatment_id, fold, "", "",
                str(corpus_name), str(evidence_path),
            )
            for language, full_hash, specific_hash, additional, size, owner, corpus_name, evidence_path in misses
        ),
    )
    tn = query_count * len(absent_set) - fp
    result = {
        "query_distinct_signatures": query_count,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": len(misses),
        "unattributed_query_signatures": query_count - len(matched_query),
    }
    output.execute(
        "INSERT OR REPLACE INTO unit_result VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            position, route_id, treatment_id, fold, query_relative,
            _sha256(query_path), query_count, tp, fp, tn, len(misses),
            result["unattributed_query_signatures"],
        ),
    )
    output.commit()
    return result


def _signature_text(row: sqlite3.Row) -> str:
    return f"{row['full_hash']}:{row['specific_hash']}:{row['additional_size']}:{row['code_size']}"


def _summary_rows(connection: sqlite3.Connection, *, noisy: bool, limit: int) -> list[dict[str, object]]:
    where = "false_positives > 0" if noisy else "distinct_reference_owners > 1"
    order = (
        "false_positives DESC, distinct_reference_owners DESC, true_positives DESC"
        if noisy
        else "distinct_reference_owners DESC, false_positives DESC, true_positives DESC"
    )
    connection.row_factory = sqlite3.Row
    rows = connection.execute(
        f"SELECT * FROM hash_summary WHERE {where} ORDER BY {order} LIMIT ?",
        (limit,),
    ).fetchall()
    return [
        {
            "scope": str(row["scope"]),
            "signature": _signature_text(row),
            "true_positives": int(row["true_positives"]),
            "false_positives": int(row["false_positives"]),
            "false_negatives": int(row["false_negatives"]),
            "distinct_correct_owners": int(row["distinct_correct_owners"]),
            "distinct_incorrect_owners": int(row["distinct_incorrect_owners"]),
            "distinct_reference_owners": int(row["distinct_reference_owners"]),
            "distinct_routes": int(row["distinct_routes"]),
            "distinct_treatments": int(row["distinct_treatments"]),
        }
        for row in rows
    ]


def analyze_hashes(
    project_root: str | Path,
    run_id: str,
    *,
    runtime_path: str | Path = "validation/machine-validation-runtime.toml",
) -> dict[str, object]:
    """Create a reproducible single-hash report from one sealed validation run."""

    from .machine_validation_runner import load_runtime, resolve_evidence

    root = Path(project_root).expanduser().resolve()
    runtime = load_runtime(root, runtime_path)
    evidence = resolve_evidence(root, runtime_path)
    output_root = (root / str(runtime["output_root"])).resolve()
    run_root = (output_root / run_id).resolve()
    if run_root.parent != output_root or not run_root.is_dir():
        raise ValueError("machine-validation source run is unavailable")
    status_path = run_root / "status.json"
    status = json.loads(status_path.read_text(encoding="utf-8"))
    if (
        status.get("state") != "complete"
        or status.get("mode") != "full"
        or int(status.get("complete_work_units", 0))
        != int(status.get("expected_work_units", -1))
        or int(status.get("failed_work_units", 0)) != 0
    ):
        raise ValueError("single-hash analysis requires a sealed complete full run")
    source_report = run_root / "report.json"
    if not source_report.is_file():
        raise ValueError("source validation report is unavailable")
    source_digest = hashlib.sha256()
    source_digest.update(_sha256(source_report).encode("ascii"))
    reference_path = output_root / "reference-index.sqlite3"
    if not reference_path.is_file():
        raise ValueError("machine-validation reference index is unavailable")
    reference_metadata = sqlite3.connect(
        f"file:{reference_path}?mode=ro", uri=True
    )
    try:
        for key, value in reference_metadata.execute(
            "SELECT key, value FROM metadata ORDER BY key"
        ):
            source_digest.update(str(key).encode("utf-8"))
            source_digest.update(b"\0")
            source_digest.update(str(value).encode("utf-8"))
            source_digest.update(b"\n")
    finally:
        reference_metadata.close()
    result_paths = sorted((run_root / "units").glob("*/result.json"))
    if len(result_paths) != int(status["expected_work_units"]):
        raise ValueError("source validation result set is incomplete")
    for path in result_paths:
        source_digest.update(_sha256(path).encode("ascii"))
        result = json.loads(path.read_text(encoding="utf-8"))
        for fold_result in result.get("folds", []):
            fold_root = path.parent / f'fold-{fold_result["fold"]}'
            source_digest.update(_sha256(fold_root / "truth-map.json").encode("ascii"))
            source_digest.update(
                _sha256(fold_root / "query-signatures.jsonl").encode("ascii")
            )
    source_digest_hex = source_digest.hexdigest()
    database_path = run_root / "hash-evidence.sqlite3"
    report_path = run_root / "hash-report.json"
    if database_path.is_file() and report_path.is_file():
        try:
            existing = json.loads(report_path.read_text(encoding="utf-8"))
            if (
                existing.get("schema_version") == HASH_REPORT_SCHEMA
                and existing.get("state") == "measured-complete"
                and existing.get("source_evidence_sha256") == source_digest_hex
            ):
                return existing
        except (OSError, ValueError, json.JSONDecodeError):
            pass
    partial = database_path.with_suffix(".sqlite3.partial")
    partial.unlink(missing_ok=True)
    output = _create_evidence(partial, run_id, source_digest_hex)
    reference = sqlite3.connect(f"file:{reference_path}?mode=ro", uri=True)
    try:
        routes = {route.id: route for route in evidence["configuration"].routes}
        cohort = list(evidence["status"]["randomization"]["canonical_ids"])
        expected_folds = 0
        for result_path in result_paths:
            result = json.loads(result_path.read_text(encoding="utf-8"))
            if result.get("state") != "complete" or result.get("mode") != "full":
                raise ValueError(f"source result is not complete: {result_path}")
            position = int(result["position"])
            route_id = str(result["route_id"])
            treatment_id = str(result["treatment_id"])
            route = routes[route_id]
            for fold_result in result["folds"]:
                fold = str(fold_result["fold"])
                fold_root = result_path.parent / f"fold-{fold}"
                truth = json.loads((fold_root / "truth-map.json").read_text(encoding="utf-8"))
                present = [str(owner) for owner in truth["owners"]]
                query_path = fold_root / "query-signatures.jsonl"
                _classify_fold(
                    output,
                    reference,
                    position=position,
                    route_id=route_id,
                    treatment_id=treatment_id,
                    target_os=str(route.target_os),
                    binary_format=str(route.binary_format),
                    fold=fold,
                    present=present,
                    cohort=cohort,
                    query_path=query_path,
                    query_relative=str(query_path.relative_to(root)),
                )
                expected_folds += 1
        output.execute(
            """
            INSERT INTO hash_summary
            SELECT scope, language, full_hash, specific_hash, additional_size,
                   code_size,
                   SUM(outcome='tp'), SUM(outcome='fp'), SUM(outcome='fn'),
                   COUNT(DISTINCT CASE WHEN outcome='tp' THEN owner END),
                   COUNT(DISTINCT CASE WHEN outcome='fp' THEN owner END),
                   COUNT(DISTINCT owner), COUNT(DISTINCT route_id),
                   COUNT(DISTINCT treatment_id)
            FROM hash_observation
            GROUP BY scope, language, full_hash, specific_hash,
                     additional_size, code_size
            """
        )
        output.execute("UPDATE metadata SET value='complete' WHERE key='state'")
        output.commit()
        output.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        matrix_row = output.execute(
            """
            SELECT SUM(true_positives), SUM(false_positives),
                   SUM(true_negatives), SUM(false_negatives),
                   SUM(query_distinct_signatures),
                   SUM(unattributed_query_signatures), COUNT(*)
            FROM unit_result
            """
        ).fetchone()
        counts = output.execute(
            """
            SELECT COUNT(*),
                   SUM(false_positives > 0),
                   SUM(distinct_reference_owners > 1),
                   SUM(false_negatives > 0)
            FROM hash_summary
            """
        ).fetchone()
        top_noisy = _summary_rows(output, noisy=True, limit=500)
        top_low_information = _summary_rows(output, noisy=False, limit=500)
    finally:
        reference.close()
        output.close()
    partial.replace(database_path)
    matrix = {
        "unit": DECISION_UNIT,
        "true_positives": int(matrix_row[0] or 0),
        "false_positives": int(matrix_row[1] or 0),
        "true_negatives": int(matrix_row[2] or 0),
        "false_negatives": int(matrix_row[3] or 0),
    }
    report = {
        "schema_version": HASH_REPORT_SCHEMA,
        "validation_id": str(runtime["validation_id"]),
        "run_id": run_id,
        "state": "measured-complete",
        "finished_at": _now(),
        "source_evidence_sha256": source_digest_hex,
        "decision_contract": {
            "unit": DECISION_UNIT,
            "positive_population": "exact signatures belonging to libraries present in the composite fold",
            "negative_population": "composite query signatures tested against every library withheld in the opposite fold",
            "true_positive": "expected exact signature observed in its present owner",
            "false_negative": "expected exact signature absent from the composite query",
            "false_positive": "query signature also present in an opposite-fold owner",
            "true_negative": "query signature absent from an opposite-fold owner",
            "same_fold_sharing": "retained as multi-owner ambiguity, not labelled false",
        },
        "confusion_matrix": matrix,
        "failure_summary": {
            "collisions": matrix["false_positives"],
            "misses": matrix["false_negatives"],
        },
        "hash_evidence": {
            "database_path": str(database_path.relative_to(root)),
            "database_sha256": _sha256(database_path),
            "distinct_signatures": int(counts[0] or 0),
            "noisy_signatures": int(counts[1] or 0),
            "multi_owner_signatures": int(counts[2] or 0),
            "missed_signatures": int(counts[3] or 0),
            "query_signature_observations": int(matrix_row[4] or 0),
            "unattributed_query_signatures": int(matrix_row[5] or 0),
            "fold_results": int(matrix_row[6] or 0),
            "top_noisy": top_noisy,
            "top_low_information": top_low_information,
        },
        "failures": [
            {
                "failure_type": "collision",
                "library_id": str(row["scope"]),
                "function_id": "",
                "route_id": "multiple" if int(row["distinct_routes"]) > 1 else "one-route",
                "compiler_id": "multiple" if int(row["distinct_routes"]) > 1 else "one-route",
                "treatment_id": "multiple" if int(row["distinct_treatments"]) > 1 else "one-treatment",
                "signature": str(row["signature"]),
                "candidate_owner": f'{int(row["distinct_incorrect_owners"])} opposite-fold owner(s)',
                "evidence_path": str(database_path.relative_to(root)),
            }
            for row in top_noisy
        ],
        "metrics": {
            "expected_work_units": int(status["expected_work_units"]),
            "complete_work_units": int(status["complete_work_units"]),
            "failed_work_units": 0,
            "expected_fold_results": int(status["expected_work_units"]) * 2,
            "complete_fold_results": expected_folds,
            "threshold": None,
            "all_hash_observations_retained": True,
        },
    }
    _atomic_json(report_path, report)
    updated_status = {
        **status,
        "legacy_report_path": status.get("report_path"),
        "report_path": str(report_path.relative_to(root)),
        "hash_analysis": {
            "state": "complete",
            "decision_unit": DECISION_UNIT,
            "database_path": str(database_path.relative_to(root)),
            "database_sha256": report["hash_evidence"]["database_sha256"],
            "finished_at": report["finished_at"],
        },
    }
    _atomic_json(status_path, updated_status)
    return report


def _clock_minutes(value: str) -> int:
    try:
        hour, minute = (int(part) for part in value.split(":"))
    except (ValueError, TypeError) as error:
        raise ValueError(f"invalid validation schedule time: {value}") from error
    if hour not in range(24) or minute not in range(60):
        raise ValueError(f"invalid validation schedule time: {value}")
    return hour * 60 + minute


def load_hash_schedule(
    project_root: str | Path,
    authority: str | Path = DEFAULT_HASH_SCHEDULE,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    path = (root / authority).resolve()
    if path != root and root not in path.parents:
        raise ValueError("hash-analysis schedule escapes the project root")
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if set(document) != {
        "schema_version", "timezone", "source_run_policy", "runtime",
        "finish_started", "window",
    } or document.get("schema_version") != HASH_SCHEDULE_SCHEMA:
        raise ValueError("hash-analysis schedule has unsupported fields or schema")
    if (
        document["source_run_policy"] != "latest-complete-full-without-current-hash-report"
        or document["finish_started"] is not True
        or not isinstance(document["window"], list)
        or not document["window"]
    ):
        raise ValueError("hash-analysis schedule policy is unsupported")
    ZoneInfo(str(document["timezone"]))
    ids: set[str] = set()
    for window in document["window"]:
        if not isinstance(window, dict) or set(window) not in (
            {"id", "kind", "date", "start", "stop_admitting", "enabled"},
            {"id", "kind", "days", "start", "stop_admitting", "enabled"},
        ):
            raise ValueError("hash-analysis window has unsupported fields")
        if window["id"] in ids or window["kind"] not in {"once", "weekly"}:
            raise ValueError("hash-analysis window identity is invalid")
        ids.add(str(window["id"]))
        start = _clock_minutes(str(window["start"]))
        stop = _clock_minutes(str(window["stop_admitting"]))
        if start == stop:
            raise ValueError("hash-analysis window cannot span a full day")
    return {
        **document,
        "authority_path": str(path.relative_to(root)),
        "authority_sha256": _sha256(path),
    }


def _window_open(schedule: Mapping[str, object], now: datetime) -> tuple[bool, str | None]:
    local = now.astimezone(ZoneInfo(str(schedule["timezone"])))
    minute = local.hour * 60 + local.minute
    weekday = local.strftime("%a").lower()
    for window in schedule["window"]:
        if not window["enabled"]:
            continue
        if window["kind"] == "once" and str(window["date"]) != local.date().isoformat():
            continue
        if window["kind"] == "weekly" and weekday not in window["days"]:
            continue
        start = _clock_minutes(str(window["start"]))
        stop = _clock_minutes(str(window["stop_admitting"]))
        open_now = start <= minute < stop if start < stop else minute >= start or minute < stop
        if open_now:
            return True, str(window["id"])
    return False, None


def scheduled_hash_analysis(
    project_root: str | Path,
    *,
    schedule_path: str | Path = DEFAULT_HASH_SCHEDULE,
    now: datetime | None = None,
) -> dict[str, object]:
    """Run the newest pending hash analysis only inside a reviewed window."""

    from .machine_validation_runner import _post_validation_retention, load_runtime

    root = Path(project_root).expanduser().resolve()
    schedule = load_hash_schedule(root, schedule_path)
    instant = now or datetime.now(timezone.utc)
    open_now, window_id = _window_open(schedule, instant)
    if not open_now:
        return {
            "state": "outside-window",
            "window_id": None,
            "schedule_sha256": schedule["authority_sha256"],
        }
    runtime = load_runtime(root, str(schedule["runtime"]))
    output_root = (root / str(runtime["output_root"])).resolve()
    candidates = []
    for status_path in output_root.glob("*/status.json"):
        try:
            status = json.loads(status_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if (
            status.get("state") == "complete"
            and status.get("mode") == "full"
            and int(status.get("complete_work_units", 0))
            == int(status.get("expected_work_units", -1))
            and int(status.get("failed_work_units", 0)) == 0
        ):
            candidates.append(status_path)
    if not candidates:
        return {
            "state": "no-complete-source-run",
            "window_id": window_id,
            "schedule_sha256": schedule["authority_sha256"],
        }
    status_path = max(candidates, key=lambda path: path.stat().st_mtime_ns)
    report_path = status_path.parent / "hash-report.json"
    if report_path.is_file():
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            if (
                report.get("schema_version") == HASH_REPORT_SCHEMA
                and report.get("state") == "measured-complete"
            ):
                return {
                    "state": "nothing-pending",
                    "window_id": window_id,
                    "run_id": status_path.parent.name,
                    "schedule_sha256": schedule["authority_sha256"],
                }
        except (OSError, ValueError, json.JSONDecodeError):
            pass
    lock = output_root / ".hash-analysis.lock"
    descriptor = None
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.write(descriptor, f"{os.getpid()}\n".encode())
    except FileExistsError as error:
        raise ValueError("another single-hash analysis is already active") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    try:
        report = analyze_hashes(
            root,
            status_path.parent.name,
            runtime_path=str(schedule["runtime"]),
        )
        retention = _post_validation_retention(
            root, runtime, status_path.parent.name
        )
        _atomic_json(status_path.parent / "retention.json", retention)
        final_status = json.loads(status_path.read_text(encoding="utf-8"))
        final_status["retention"] = {
            key: retention.get(key)
            for key in (
                "state", "trigger", "scope", "plan_digest",
                "estimated_apply_seconds", "error",
            )
            if retention.get(key) is not None
        }
        _atomic_json(status_path, final_status)
        return {
            "state": "complete",
            "window_id": window_id,
            "run_id": status_path.parent.name,
            "report_path": str(report_path.relative_to(root)),
            "schedule_sha256": schedule["authority_sha256"],
            "confusion_matrix": report["confusion_matrix"],
            "retention": final_status["retention"],
        }
    finally:
        lock.unlink(missing_ok=True)
