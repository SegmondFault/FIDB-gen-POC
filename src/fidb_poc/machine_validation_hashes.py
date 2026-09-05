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
import time
import tomllib
from typing import Iterable, Mapping
from zoneinfo import ZoneInfo


HASH_REPORT_SCHEMA = "fidb-machine-validation-hash-report/v1"
HASH_EVIDENCE_SCHEMA = "fidb-machine-validation-hash-evidence/v1"
DECISION_UNIT = "complete-fid-signature-owner-assertion"
HASH_SCHEDULE_SCHEMA = "fidb-machine-validation-hash-schedule/v1"
DEFAULT_HASH_SCHEDULE = Path("validation/machine-validation-hash-schedule.toml")
HASH_METHOD_SCHEMA = "fidb-machine-validation-hash-method/v1"
DEFAULT_HASH_METHOD = Path("validation/machine-validation-hash-method.toml")
ANALYSIS_ENGINE = "unit-local-reference-v1"


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


def _create_evidence(
    path: Path,
    source_run_id: str,
    source_digest: str,
    method_id: str = "single-hash-ground-truth-v1",
    method_digest: str = "test-authority",
) -> sqlite3.Connection:
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
            outcome TEXT NOT NULL CHECK(outcome IN ('tp','fp','fn','unattributed')),
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
            unattributed_observations INTEGER NOT NULL,
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
        CREATE TABLE hash_signature_owner(
            scope TEXT NOT NULL,
            language TEXT NOT NULL,
            full_hash TEXT NOT NULL,
            specific_hash TEXT NOT NULL,
            additional_size INTEGER NOT NULL,
            code_size INTEGER NOT NULL,
            owner TEXT NOT NULL,
            reference_observations INTEGER NOT NULL,
            recovered_observations INTEGER NOT NULL,
            missed_observations INTEGER NOT NULL,
            PRIMARY KEY(
                scope, language, full_hash, specific_hash, additional_size,
                code_size, owner
            )
        ) WITHOUT ROWID;
        CREATE TABLE hash_type_summary(
            hash_type TEXT PRIMARY KEY CHECK(
                hash_type IN ('full','specific','complete')
            ),
            distinct_values INTEGER NOT NULL,
            singleton_values INTEGER NOT NULL,
            multi_owner_values INTEGER NOT NULL,
            multi_owner_fraction REAL NOT NULL,
            owner_links INTEGER NOT NULL,
            ambiguous_owner_links INTEGER NOT NULL,
            complete_disambiguated_owner_signatures INTEGER NOT NULL,
            reference_observations INTEGER NOT NULL,
            exact_false_positive_observations INTEGER NOT NULL,
            maximum_distinct_owners INTEGER NOT NULL
        ) WITHOUT ROWID;
        CREATE TABLE hash_component_distribution(
            hash_type TEXT NOT NULL,
            distinct_owners INTEGER NOT NULL,
            distinct_values INTEGER NOT NULL,
            fraction_of_values REAL NOT NULL,
            PRIMARY KEY(hash_type, distinct_owners)
        ) WITHOUT ROWID;
        CREATE TABLE hash_component_noise(
            hash_type TEXT NOT NULL,
            scope TEXT NOT NULL,
            language TEXT NOT NULL,
            component_value TEXT NOT NULL,
            distinct_owners INTEGER NOT NULL,
            reference_observations INTEGER NOT NULL,
            exact_signature_variants INTEGER NOT NULL,
            exact_false_positive_observations INTEGER NOT NULL,
            PRIMARY KEY(hash_type, scope, language, component_value)
        ) WITHOUT ROWID;
        CREATE INDEX hash_component_noise_rank
            ON hash_component_noise(
                hash_type, distinct_owners DESC,
                exact_false_positive_observations DESC,
                reference_observations DESC
            );
        CREATE TABLE hash_component_owner(
            hash_type TEXT NOT NULL,
            scope TEXT NOT NULL,
            language TEXT NOT NULL,
            component_value TEXT NOT NULL,
            owner TEXT NOT NULL,
            reference_observations INTEGER NOT NULL,
            missed_observations INTEGER NOT NULL,
            exact_false_positive_observations INTEGER NOT NULL,
            PRIMARY KEY(
                hash_type, scope, language, component_value, owner
            )
        ) WITHOUT ROWID;
        CREATE TABLE hash_component_library(
            hash_type TEXT NOT NULL,
            owner TEXT NOT NULL,
            distinct_values INTEGER NOT NULL,
            multi_owner_values INTEGER NOT NULL,
            ambiguous_fraction REAL NOT NULL,
            reference_observations INTEGER NOT NULL,
            missed_observations INTEGER NOT NULL,
            exact_false_positive_observations INTEGER NOT NULL,
            PRIMARY KEY(hash_type, owner)
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
            ("method_id", method_id),
            ("method_sha256", method_digest),
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


def _load_unit_reference(
    connection: sqlite3.Connection,
    signatures: Mapping[tuple[str, str, str], Mapping[str, object]],
    cohort: Iterable[str],
    route_id: str,
    treatment_id: str,
) -> int:
    """Load one exact execution identity once for both validation folds."""

    connection.execute("DROP TABLE IF EXISTS temp.unit_reference")
    connection.execute(
        """
        CREATE TEMP TABLE unit_reference(
            language TEXT NOT NULL,
            full_hash TEXT NOT NULL,
            specific_hash TEXT NOT NULL,
            additional_size INTEGER NOT NULL,
            code_size INTEGER NOT NULL,
            owner TEXT NOT NULL,
            function_name TEXT NOT NULL,
            evidence_path TEXT NOT NULL,
            PRIMARY KEY(
                language, full_hash, specific_hash, additional_size,
                code_size, owner
            )
        ) WITHOUT ROWID
        """
    )
    for owner in cohort:
        item = signatures[(owner, route_id, treatment_id)]
        path = Path(item["path"])
        evidence_path = str(item["source"])
        connection.executemany(
            "INSERT OR IGNORE INTO unit_reference VALUES (?,?,?,?,?,?,?,?)",
            (
                (
                    language,
                    full_hash,
                    specific_hash,
                    additional_size,
                    code_size,
                    owner,
                    function_name,
                    evidence_path,
                )
                for (
                    _address,
                    function_name,
                    language,
                    full_hash,
                    specific_hash,
                    additional_size,
                    code_size,
                ) in _signature_rows(path)
            ),
        )
    return int(connection.execute("SELECT COUNT(*) FROM unit_reference").fetchone()[0])


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
    reference_table: str = "reference_identity",
    query_sha256: str | None = None,
) -> dict[str, int]:
    if reference_table not in {"reference_identity", "unit_reference"}:
        raise ValueError("unsupported single-hash reference table")
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
    identity_filter = (
        "" if reference_table == "unit_reference" else
        """reference.target_os=? AND reference.binary_format=?
         AND reference.route_id=? AND reference.treatment_id=? AND"""
    )
    match_sql = f"""
        SELECT query.address, query.function_name, query.language,
               query.full_hash, query.specific_hash, query.additional_size,
               query.code_size, reference.owner, reference.function_name,
               reference.evidence_path, fold_owner.present
        FROM query_signature AS query
        JOIN {reference_table} AS reference
          ON {identity_filter} reference.language=query.language
         AND reference.full_hash=query.full_hash
         AND reference.specific_hash=query.specific_hash
         AND reference.additional_size=query.additional_size
         AND reference.code_size=query.code_size
        JOIN fold_owner ON fold_owner.owner=reference.owner
    """
    parameters = (
        ()
        if reference_table == "unit_reference"
        else (target_os, binary_format, route_id, treatment_id)
    )
    tp = 0
    fp = 0
    matched_query: set[tuple[str, str, str, int, int]] = set()
    observation_rows = []
    for row in reference.execute(match_sql, parameters):
        address, query_name, language, full_hash, specific_hash, additional, size, owner, corpus_name, evidence_path, is_present = row
        if is_present:
            tp += 1
            matched_query.add(
                (
                    str(language),
                    str(full_hash),
                    str(specific_hash),
                    int(additional),
                    int(size),
                )
            )
        else:
            fp += 1
        observation_rows.append(
            (
                _scope(target_os, binary_format, str(language)),
                str(language), str(full_hash), str(specific_hash), int(additional),
                int(size), "tp" if is_present else "fp", str(owner), route_id,
                treatment_id, fold, str(address), str(query_name), str(corpus_name),
                str(evidence_path),
            )
        )
        if len(observation_rows) >= 5000:
            output.executemany(
                "INSERT OR REPLACE INTO hash_observation VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                observation_rows,
            )
            observation_rows.clear()
    if observation_rows:
        output.executemany(
            "INSERT OR REPLACE INTO hash_observation VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            observation_rows,
        )
    unattributed_count = 0
    observation_rows = []
    for row in reference.execute(
        """
        SELECT address, function_name, language, full_hash, specific_hash,
               additional_size, code_size
        FROM query_signature
        """
    ):
        address, function_name, language, full_hash, specific_hash, additional, size = row
        identity = (
            str(language), str(full_hash), str(specific_hash), int(additional), int(size)
        )
        if identity in matched_query:
            continue
        unattributed_count += 1
        observation_rows.append(
            (
                _scope(target_os, binary_format, str(language)), str(language),
                str(full_hash), str(specific_hash), int(additional), int(size),
                "unattributed", "", route_id, treatment_id, fold,
                str(address), str(function_name), "", query_relative,
            )
        )
        if len(observation_rows) >= 5000:
            output.executemany(
                "INSERT OR REPLACE INTO hash_observation VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                observation_rows,
            )
            observation_rows.clear()
    if observation_rows:
        output.executemany(
            "INSERT OR REPLACE INTO hash_observation VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            observation_rows,
        )
    miss_sql = f"""
        SELECT reference.language, reference.full_hash, reference.specific_hash,
               reference.additional_size, reference.code_size, reference.owner,
               reference.function_name, reference.evidence_path
        FROM {reference_table} AS reference
        JOIN fold_owner ON fold_owner.owner=reference.owner AND fold_owner.present=1
        LEFT JOIN query_signature AS query
          ON query.language=reference.language
         AND query.full_hash=reference.full_hash
         AND query.specific_hash=reference.specific_hash
         AND query.additional_size=reference.additional_size
         AND query.code_size=reference.code_size
        WHERE {identity_filter} query.language IS NULL
    """
    miss_count = 0
    observation_rows = []
    for (
        language, full_hash, specific_hash, additional, size, owner,
        corpus_name, evidence_path,
    ) in reference.execute(miss_sql, parameters):
        miss_count += 1
        observation_rows.append(
            (
                _scope(target_os, binary_format, str(language)), str(language),
                str(full_hash), str(specific_hash), int(additional), int(size),
                "fn", str(owner), route_id, treatment_id, fold, "", "",
                str(corpus_name), str(evidence_path),
            )
        )
        if len(observation_rows) >= 5000:
            output.executemany(
                "INSERT OR REPLACE INTO hash_observation VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                observation_rows,
            )
            observation_rows.clear()
    if observation_rows:
        output.executemany(
            "INSERT OR REPLACE INTO hash_observation VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            observation_rows,
        )
    tn = query_count * len(absent_set) - fp
    result = {
        "query_distinct_signatures": query_count,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": miss_count,
        "unattributed_query_signatures": unattributed_count,
    }
    output.execute(
        "INSERT OR REPLACE INTO unit_result VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            position, route_id, treatment_id, fold, query_relative,
            query_sha256 or _sha256(query_path), query_count, tp, fp, tn, miss_count,
            result["unattributed_query_signatures"],
        ),
    )
    return result


def _signature_text(row: sqlite3.Row) -> str:
    return f"{row['full_hash']}:{row['specific_hash']}:{row['additional_size']}:{row['code_size']}"


def _summary_rows(connection: sqlite3.Connection, *, noisy: bool, limit: int) -> list[dict[str, object]]:
    where = (
        "false_positives > 0"
        if noisy
        else "distinct_reference_owners > 1 OR unattributed_observations > 0"
    )
    order = (
        "false_positives DESC, distinct_reference_owners DESC, true_positives DESC"
        if noisy
        else "distinct_reference_owners DESC, unattributed_observations DESC, false_positives DESC"
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
            "unattributed_observations": int(row["unattributed_observations"]),
            "distinct_correct_owners": int(row["distinct_correct_owners"]),
            "distinct_incorrect_owners": int(row["distinct_incorrect_owners"]),
            "distinct_reference_owners": int(row["distinct_reference_owners"]),
            "distinct_routes": int(row["distinct_routes"]),
            "distinct_treatments": int(row["distinct_treatments"]),
        }
        for row in rows
    ]


def _component_expression(hash_type: str, alias: str) -> str:
    if hash_type == "full":
        return f"{alias}.full_hash"
    if hash_type == "specific":
        return f"{alias}.specific_hash"
    if hash_type == "complete":
        return (
            f"{alias}.full_hash || ':' || {alias}.specific_hash || ':' || "
            f"{alias}.additional_size || ':' || {alias}.code_size"
        )
    raise ValueError(f"unsupported hash type: {hash_type}")


def _compile_hash_type_analysis(
    connection: sqlite3.Connection,
    *,
    top_limit: int = 250,
) -> list[dict[str, object]]:
    """Materialise bounded full/specific/complete discrimination evidence."""

    connection.execute(
        """
        INSERT INTO hash_signature_owner
        SELECT scope, language, full_hash, specific_hash, additional_size,
               code_size, owner, COUNT(*), SUM(outcome='tp'), SUM(outcome='fn')
        FROM hash_observation
        WHERE outcome IN ('tp','fn') AND owner != ''
        GROUP BY scope, language, full_hash, specific_hash, additional_size,
                 code_size, owner
        """
    )
    connection.execute(
        """
        CREATE TEMP TABLE exact_population AS
        SELECT scope, language, full_hash, specific_hash, additional_size,
               code_size, COUNT(DISTINCT owner) AS distinct_owners
        FROM hash_signature_owner
        GROUP BY scope, language, full_hash, specific_hash, additional_size,
                 code_size
        """
    )
    connection.execute(
        """
        CREATE INDEX exact_population_identity ON exact_population(
            scope, language, full_hash, specific_hash, additional_size,
            code_size
        )
        """
    )
    analysis = []
    for hash_type in ("full", "specific", "complete"):
        owner_value = _component_expression(hash_type, "source")
        fp_value = _component_expression(hash_type, "observation")
        connection.execute("DROP TABLE IF EXISTS temp.component_owner_population")
        connection.execute("DROP TABLE IF EXISTS temp.component_population")
        connection.execute("DROP TABLE IF EXISTS temp.component_fp")
        connection.execute(
            f"""
            CREATE TEMP TABLE component_owner_population AS
            SELECT source.scope, source.language, {owner_value} AS component_value,
                   source.owner,
                   SUM(source.reference_observations) AS reference_observations,
                   SUM(source.missed_observations) AS missed_observations
            FROM hash_signature_owner AS source
            GROUP BY source.scope, source.language, component_value, source.owner
            """
        )
        connection.execute(
            """
            CREATE INDEX component_owner_population_identity
            ON component_owner_population(
                scope, language, component_value, owner
            )
            """
        )
        connection.execute(
            f"""
            CREATE TEMP TABLE component_population AS
            SELECT source.scope, source.language, {owner_value} AS component_value,
                   COUNT(DISTINCT source.owner) AS distinct_owners,
                   SUM(source.reference_observations) AS reference_observations,
                   COUNT(DISTINCT (
                       source.full_hash || ':' || source.specific_hash || ':' ||
                       source.additional_size || ':' || source.code_size
                   )) AS exact_signature_variants
            FROM hash_signature_owner AS source
            GROUP BY source.scope, source.language, component_value
            """
        )
        connection.execute(
            """
            CREATE UNIQUE INDEX component_population_identity
            ON component_population(scope, language, component_value)
            """
        )
        connection.execute(
            f"""
            CREATE TEMP TABLE component_fp AS
            SELECT observation.scope, observation.language,
                   {fp_value} AS component_value, observation.owner,
                   COUNT(*) AS observations
            FROM hash_observation AS observation
            WHERE observation.outcome='fp'
            GROUP BY observation.scope, observation.language, component_value,
                     observation.owner
            """
        )
        connection.execute(
            """
            CREATE INDEX component_fp_identity ON component_fp(
                scope, language, component_value, owner
            )
            """
        )
        population = connection.execute(
            """
            SELECT COUNT(*), SUM(distinct_owners=1), SUM(distinct_owners>1),
                   SUM(distinct_owners),
                   SUM(CASE WHEN distinct_owners>1 THEN distinct_owners ELSE 0 END),
                   SUM(reference_observations), MAX(distinct_owners)
            FROM component_population
            """
        ).fetchone()
        distinct_values = int(population[0] or 0)
        singleton_values = int(population[1] or 0)
        multi_owner_values = int(population[2] or 0)
        owner_links = int(population[3] or 0)
        ambiguous_owner_links = int(population[4] or 0)
        reference_observations = int(population[5] or 0)
        maximum_owners = int(population[6] or 0)
        exact_false_positives = int(
            connection.execute(
                "SELECT COALESCE(SUM(observations),0) FROM component_fp"
            ).fetchone()[0]
        )
        component_join = _component_expression(hash_type, "signature")
        disambiguated = int(
            connection.execute(
                f"""
                SELECT COUNT(*)
                FROM hash_signature_owner AS signature
                JOIN component_population AS component
                  ON component.scope=signature.scope
                 AND component.language=signature.language
                 AND component.component_value={component_join}
                 AND component.distinct_owners>1
                JOIN exact_population AS exact
                  ON exact.scope=signature.scope
                 AND exact.language=signature.language
                 AND exact.full_hash=signature.full_hash
                 AND exact.specific_hash=signature.specific_hash
                 AND exact.additional_size=signature.additional_size
                 AND exact.code_size=signature.code_size
                 AND exact.distinct_owners=1
                """
            ).fetchone()[0]
        )
        connection.execute(
            "INSERT INTO hash_type_summary VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                hash_type,
                distinct_values,
                singleton_values,
                multi_owner_values,
                multi_owner_values / distinct_values if distinct_values else 0.0,
                owner_links,
                ambiguous_owner_links,
                disambiguated,
                reference_observations,
                exact_false_positives,
                maximum_owners,
            ),
        )
        connection.execute(
            """
            INSERT INTO hash_component_distribution
            SELECT ?, distinct_owners, COUNT(*),
                   CAST(COUNT(*) AS REAL) / ?
            FROM component_population
            GROUP BY distinct_owners
            """,
            (hash_type, distinct_values or 1),
        )
        connection.execute(
            """
            INSERT INTO hash_component_noise
            SELECT ?, population.scope, population.language,
                   population.component_value, population.distinct_owners,
                   population.reference_observations,
                   population.exact_signature_variants,
                   COALESCE(SUM(component_fp.observations),0)
            FROM component_population AS population
            LEFT JOIN component_fp
              ON component_fp.scope=population.scope
             AND component_fp.language=population.language
             AND component_fp.component_value=population.component_value
            WHERE population.distinct_owners>1
            GROUP BY population.scope, population.language,
                     population.component_value
            """,
            (hash_type,),
        )
        connection.execute(
            """
            INSERT INTO hash_component_owner
            SELECT ?, owners.scope, owners.language, owners.component_value,
                   owners.owner, owners.reference_observations,
                   owners.missed_observations,
                   COALESCE(component_fp.observations,0)
            FROM component_owner_population AS owners
            JOIN component_population AS population
              ON population.scope=owners.scope
             AND population.language=owners.language
             AND population.component_value=owners.component_value
             AND population.distinct_owners>1
            LEFT JOIN component_fp
              ON component_fp.scope=owners.scope
             AND component_fp.language=owners.language
             AND component_fp.component_value=owners.component_value
             AND component_fp.owner=owners.owner
            """,
            (hash_type,),
        )
        connection.execute(
            """
            INSERT INTO hash_component_library
            SELECT ?, owners.owner, COUNT(*),
                   SUM(population.distinct_owners>1),
                   CAST(SUM(population.distinct_owners>1) AS REAL) / COUNT(*),
                   SUM(owners.reference_observations),
                   SUM(owners.missed_observations),
                   COALESCE(SUM(component_fp.observations),0)
            FROM component_owner_population AS owners
            JOIN component_population AS population
              ON population.scope=owners.scope
             AND population.language=owners.language
             AND population.component_value=owners.component_value
            LEFT JOIN component_fp
              ON component_fp.scope=owners.scope
             AND component_fp.language=owners.language
             AND component_fp.component_value=owners.component_value
             AND component_fp.owner=owners.owner
            GROUP BY owners.owner
            """,
            (hash_type,),
        )
        distribution = [
            {
                "distinct_owners": int(row[0]),
                "distinct_values": int(row[1]),
                "fraction_of_values": float(row[2]),
            }
            for row in connection.execute(
                """
                SELECT distinct_owners, distinct_values, fraction_of_values
                FROM hash_component_distribution
                WHERE hash_type=? ORDER BY distinct_owners
                """,
                (hash_type,),
            )
        ]
        noisy_rows = []
        for row in connection.execute(
            """
            SELECT scope, language, component_value, distinct_owners,
                   reference_observations, exact_signature_variants,
                   exact_false_positive_observations
            FROM hash_component_noise
            WHERE hash_type=?
            ORDER BY distinct_owners DESC,
                     exact_false_positive_observations DESC,
                     reference_observations DESC, component_value
            LIMIT ?
            """,
            (hash_type, top_limit),
        ):
            scope, language, value = str(row[0]), str(row[1]), str(row[2])
            owners = [
                str(owner[0])
                for owner in connection.execute(
                    """
                    SELECT owner FROM hash_component_owner
                    WHERE hash_type=? AND scope=? AND language=?
                      AND component_value=? ORDER BY owner
                    """,
                    (hash_type, scope, language, value),
                )
            ]
            noisy_rows.append(
                {
                    "scope": scope,
                    "language": language,
                    "value": value,
                    "distinct_owners": int(row[3]),
                    "reference_observations": int(row[4]),
                    "exact_signature_variants": int(row[5]),
                    "exact_false_positive_observations": int(row[6]),
                    "owners": owners,
                }
            )
        libraries = [
            {
                "owner": str(row[0]),
                "distinct_values": int(row[1]),
                "multi_owner_values": int(row[2]),
                "ambiguous_fraction": float(row[3]),
                "reference_observations": int(row[4]),
                "missed_observations": int(row[5]),
                "exact_false_positive_observations": int(row[6]),
            }
            for row in connection.execute(
                """
                SELECT owner, distinct_values, multi_owner_values,
                       ambiguous_fraction, reference_observations,
                       missed_observations,
                       exact_false_positive_observations
                FROM hash_component_library
                WHERE hash_type=?
                ORDER BY ambiguous_fraction DESC, multi_owner_values DESC,
                         owner
                """,
                (hash_type,),
            )
        ]
        analysis.append(
            {
                "hash_type": hash_type,
                "distinct_values": distinct_values,
                "singleton_values": singleton_values,
                "multi_owner_values": multi_owner_values,
                "multi_owner_fraction": (
                    multi_owner_values / distinct_values if distinct_values else 0.0
                ),
                "owner_links": owner_links,
                "ambiguous_owner_links": ambiguous_owner_links,
                "complete_disambiguated_owner_signatures": disambiguated,
                "reference_observations": reference_observations,
                "exact_false_positive_observations": exact_false_positives,
                "maximum_distinct_owners": maximum_owners,
                "distribution": distribution,
                "top_ambiguous": noisy_rows,
                "libraries": libraries,
            }
        )
    connection.execute("DROP TABLE exact_population")
    connection.execute("DROP TABLE component_owner_population")
    connection.execute("DROP TABLE component_population")
    connection.execute("DROP TABLE component_fp")
    return analysis


def load_hash_method(
    project_root: str | Path,
    authority: str | Path = DEFAULT_HASH_METHOD,
) -> dict[str, object]:
    """Load the versioned scientific authority for single-hash analysis."""

    root = Path(project_root).expanduser().resolve()
    path = (root / authority).resolve()
    if path != root and root not in path.parents:
        raise ValueError("hash-analysis method authority escapes the project root")
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    expected_sections = {
        "schema_version",
        "id",
        "label",
        "identity",
        "classification",
        "component",
        "population",
        "reporting",
        "reproducibility",
        "safety",
    }
    if set(document) != expected_sections or document.get("schema_version") != HASH_METHOD_SCHEMA:
        raise ValueError("hash-analysis method has unsupported fields or schema")
    components = document.get("component", {})
    if set(components) != {"full", "specific", "complete"}:
        raise ValueError("hash-analysis method must define all three hash types")
    expected_fields = {
        "full": ["full_hash"],
        "specific": ["specific_hash"],
        "complete": [
            "full_hash",
            "specific_hash",
            "specific_hash_additional_size",
            "code_unit_size",
        ],
    }
    if any(components[name].get("fields") != fields for name, fields in expected_fields.items()):
        raise ValueError("hash-analysis component identity is unsupported")
    if (
        document["classification"].get("decision_unit") != DECISION_UNIT
        or document["classification"].get("library_acceptance_threshold") != "none"
        or document["reproducibility"].get("randomness") != "none"
        or document["safety"] != {
            "execute_target_binaries": False,
            "start_compilers": False,
            "start_jvms": False,
            "mutate_production_queue": False,
        }
    ):
        raise ValueError("hash-analysis method violates the supported safety contract")
    top_limit = int(document["reporting"].get("top_ambiguous_per_hash_type", 0))
    if top_limit < 1 or top_limit > 10_000:
        raise ValueError("hash-analysis reporting bound is invalid")
    return {
        **document,
        "authority_path": str(path.relative_to(root)),
        "authority_sha256": _sha256(path),
    }


def analyze_hashes(
    project_root: str | Path,
    run_id: str,
    *,
    runtime_path: str | Path = "validation/machine-validation-runtime.toml",
    method_path: str | Path = DEFAULT_HASH_METHOD,
) -> dict[str, object]:
    """Create a reproducible single-hash report from one sealed validation run."""

    from .machine_validation_runner import (
        load_runtime,
        resolve_hash_analysis_evidence,
    )

    analysis_started_ns = time.monotonic_ns()
    root = Path(project_root).expanduser().resolve()
    runtime = load_runtime(root, runtime_path)
    method = load_hash_method(root, method_path)
    resolution_started_ns = time.monotonic_ns()
    evidence = resolve_hash_analysis_evidence(root, runtime_path)
    resolution_wall_ns = time.monotonic_ns() - resolution_started_ns
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
    source_digest.update(str(method["authority_sha256"]).encode("ascii"))
    reference_path = output_root / "reference-index.sqlite3"
    if not reference_path.is_file():
        raise ValueError("machine-validation reference index is unavailable")
    reference_metadata = sqlite3.connect(
        f"file:{reference_path}?mode=ro", uri=True
    )
    reference_values: dict[str, str] = {}
    try:
        for key, value in reference_metadata.execute(
            "SELECT key, value FROM metadata ORDER BY key"
        ):
            reference_values[str(key)] = str(value)
            source_digest.update(str(key).encode("utf-8"))
            source_digest.update(b"\0")
            source_digest.update(str(value).encode("utf-8"))
            source_digest.update(b"\n")
    finally:
        reference_metadata.close()
    exact_input_digest = hashlib.sha256(
        json.dumps(
            sorted(
                (list(key), value["sha256"])
                for key, value in evidence["signatures"].items()
            ),
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    if reference_values.get("input_digest") != exact_input_digest:
        raise ValueError(
            "single-hash signature inputs no longer match the sealed reference index"
        )
    result_paths = sorted((run_root / "units").glob("*/result.json"))
    if len(result_paths) != int(status["expected_work_units"]):
        raise ValueError("source validation result set is incomplete")
    query_digests: dict[Path, str] = {}
    for path in result_paths:
        source_digest.update(_sha256(path).encode("ascii"))
        result = json.loads(path.read_text(encoding="utf-8"))
        for fold_result in result.get("folds", []):
            fold_root = path.parent / f'fold-{fold_result["fold"]}'
            source_digest.update(_sha256(fold_root / "truth-map.json").encode("ascii"))
            query_path = fold_root / "query-signatures.jsonl"
            query_digests[query_path] = _sha256(query_path)
            source_digest.update(query_digests[query_path].encode("ascii"))
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
                and existing.get("performance", {}).get("engine") == ANALYSIS_ENGINE
            ):
                return existing
        except (OSError, ValueError, json.JSONDecodeError):
            pass
    partial = database_path.with_suffix(".sqlite3.partial")
    for stale in (
        partial,
        Path(f"{partial}-wal"),
        Path(f"{partial}-shm"),
    ):
        stale.unlink(missing_ok=True)
    output = _create_evidence(
        partial,
        run_id,
        source_digest_hex,
        str(method["id"]),
        str(method["authority_sha256"]),
    )
    reference = sqlite3.connect(f"file:{reference_path}?mode=ro", uri=True)
    try:
        reference.execute("PRAGMA temp_store=MEMORY")
        reference.execute("PRAGMA cache_size=-65536")
        routes = {route.id: route for route in evidence["configuration"].routes}
        cohort = list(evidence["cohort"])
        expected_folds = 0
        reference_rows = 0
        classification_started_ns = time.monotonic_ns()
        for result_path in result_paths:
            result = json.loads(result_path.read_text(encoding="utf-8"))
            if result.get("state") != "complete" or result.get("mode") != "full":
                raise ValueError(f"source result is not complete: {result_path}")
            position = int(result["position"])
            route_id = str(result["route_id"])
            treatment_id = str(result["treatment_id"])
            route = routes[route_id]
            reference_rows += _load_unit_reference(
                reference,
                evidence["signatures"],
                cohort,
                route_id,
                treatment_id,
            )
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
                    reference_table="unit_reference",
                    query_sha256=query_digests[query_path],
                )
                expected_folds += 1
            output.commit()
        classification_wall_ns = time.monotonic_ns() - classification_started_ns
        output.execute(
            """
            INSERT INTO hash_summary
            SELECT scope, language, full_hash, specific_hash, additional_size,
                   code_size,
                   SUM(outcome='tp'), SUM(outcome='fp'), SUM(outcome='fn'),
                   SUM(outcome='unattributed'),
                   COUNT(DISTINCT CASE WHEN outcome='tp' THEN owner END),
                   COUNT(DISTINCT CASE WHEN outcome='fp' THEN owner END),
                   COUNT(DISTINCT owner), COUNT(DISTINCT route_id),
                   COUNT(DISTINCT treatment_id)
            FROM hash_observation
            GROUP BY scope, language, full_hash, specific_hash,
                     additional_size, code_size
            """
        )
        population_started_ns = time.monotonic_ns()
        hash_type_analysis = _compile_hash_type_analysis(
            output,
            top_limit=int(method["reporting"]["top_ambiguous_per_hash_type"]),
        )
        population_wall_ns = time.monotonic_ns() - population_started_ns
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
                   SUM(false_negatives > 0),
                   SUM(unattributed_observations > 0)
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
        "method_authority": {
            "id": method["id"],
            "path": method["authority_path"],
            "sha256": method["authority_sha256"],
            "algorithm_id": method["reproducibility"]["algorithm_id"],
        },
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
            "unattributed_signatures": int(counts[4] or 0),
            "query_signature_observations": int(matrix_row[4] or 0),
            "unattributed_query_signatures": int(matrix_row[5] or 0),
            "fold_results": int(matrix_row[6] or 0),
            "top_noisy": top_noisy,
            "top_low_information": top_low_information,
        },
        "hash_type_analysis": hash_type_analysis,
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
        "performance": {
            "engine": ANALYSIS_ENGINE,
            "jvm_processes_started": 0,
            "compiler_processes_started": 0,
            "exact_reference_rows_loaded": reference_rows,
            "evidence_resolution_wall_time_ns": resolution_wall_ns,
            "classification_wall_time_ns": classification_wall_ns,
            "population_analysis_wall_time_ns": population_wall_ns,
            "total_wall_time_ns": time.monotonic_ns() - analysis_started_ns,
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
