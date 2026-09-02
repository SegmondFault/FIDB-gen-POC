#!/usr/bin/env python3
"""Create a compact experimental lane DB from an immutable raw lane DB.

This tool is intentionally standalone and inspectable. Its default operation is
a read-only preview. It never modifies the source database, refuses to replace
an output, and requires ``--execute --output NEW_PATH`` before writing.

The semantic deduplication key is exactly:

    sublane_id + policy_id + Ghidra LanguageID + Ghidra CompilerSpecID
    + full_hash + specific_hash + specific_hash_additional_size + code_unit_size

Every raw observation becomes one row in ``signature_occurrence``. Compaction
therefore shares the signature key, not the provenance or function identity.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import uuid

RAW_APPLICATION_ID = 0x4649444C  # FIDL
RAW_USER_VERSION = 1
COMPACT_APPLICATION_ID = 0x46494443  # FIDC
COMPACT_USER_VERSION = 1
COMPACT_SCHEMA = "fidb-lane-compact/v1"

SIGNATURE_COLUMNS = (
    "sublane_id",
    "policy_id",
    "ghidra_language_id",
    "ghidra_compiler_spec_id",
    "full_hash",
    "specific_hash",
    "specific_hash_additional_size",
    "code_unit_size",
)
SIGNATURE_COLUMN_SQL = ", ".join(SIGNATURE_COLUMNS)


SCHEMA_SQL = """
CREATE TABLE compact_generation (
    id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    source_generation_id TEXT NOT NULL,
    source_database_sha256 TEXT NOT NULL CHECK (length(source_database_sha256) = 64),
    created_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state = 'experimental-unvalidated'),
    deduplication_key_json TEXT NOT NULL,
    raw_observations INTEGER NOT NULL CHECK (raw_observations >= 0),
    unique_signatures INTEGER NOT NULL CHECK (unique_signatures >= 0),
    repeated_observations INTEGER NOT NULL CHECK (repeated_observations >= 0)
);

CREATE TABLE policy AS SELECT * FROM raw.policy WHERE 0;
CREATE TABLE sublane AS SELECT * FROM raw.sublane WHERE 0;
CREATE TABLE library_family AS SELECT * FROM raw.library_family WHERE 0;
CREATE TABLE library_release AS SELECT * FROM raw.library_release WHERE 0;
CREATE TABLE build_variant AS SELECT * FROM raw.build_variant WHERE 0;
CREATE TABLE native_projection AS SELECT * FROM raw.native_projection WHERE 0;

CREATE TABLE compact_signature (
    id INTEGER PRIMARY KEY,
    sublane_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    ghidra_language_id TEXT NOT NULL,
    ghidra_compiler_spec_id TEXT NOT NULL,
    full_hash TEXT NOT NULL CHECK (length(full_hash) = 16),
    specific_hash TEXT NOT NULL CHECK (length(specific_hash) = 16),
    specific_hash_additional_size INTEGER NOT NULL CHECK (specific_hash_additional_size >= 0),
    code_unit_size INTEGER NOT NULL CHECK (code_unit_size >= 0),
    UNIQUE (
        sublane_id, policy_id, ghidra_language_id, ghidra_compiler_spec_id,
        full_hash, specific_hash, specific_hash_additional_size, code_unit_size
    )
);

CREATE TABLE signature_occurrence (
    id INTEGER PRIMARY KEY,
    signature_id INTEGER NOT NULL REFERENCES compact_signature(id),
    build_variant_id TEXT NOT NULL,
    domain_path TEXT NOT NULL,
    function_name TEXT NOT NULL
);

CREATE TABLE function_relationship (
    id INTEGER PRIMARY KEY,
    source_occurrence_id INTEGER NOT NULL REFERENCES signature_occurrence(id),
    target_occurrence_id INTEGER NOT NULL REFERENCES signature_occurrence(id),
    relationship_kind TEXT NOT NULL,
    UNIQUE (source_occurrence_id, target_occurrence_id, relationship_kind)
);

CREATE TABLE admission_decision (
    signature_id INTEGER PRIMARY KEY REFERENCES compact_signature(id),
    state TEXT NOT NULL CHECK (
        state IN ('unreviewed', 'unique-owner', 'shared-owner', 'collision-suspect', 'excluded')
    ),
    rationale TEXT NOT NULL,
    reviewed_at TEXT,
    reviewed_by TEXT
);

CREATE INDEX compact_signature_hash_lookup ON compact_signature (
    sublane_id, ghidra_language_id, ghidra_compiler_spec_id, full_hash, specific_hash
);
CREATE INDEX compact_occurrence_signature_lookup ON signature_occurrence(signature_id);
CREATE INDEX compact_occurrence_build_lookup ON signature_occurrence(build_variant_id);
"""


# This is the complete compaction algorithm. It is deliberately SQL rather
# than an opaque serializer so reviewers can see exactly what is shared and
# exactly which occurrence evidence survives.
COMPACTION_SQL = f"""
INSERT INTO policy SELECT * FROM raw.policy;
INSERT INTO sublane SELECT * FROM raw.sublane;
INSERT INTO library_family SELECT * FROM raw.library_family;
INSERT INTO library_release SELECT * FROM raw.library_release;
INSERT INTO build_variant SELECT * FROM raw.build_variant;
INSERT INTO native_projection SELECT * FROM raw.native_projection;

INSERT INTO compact_signature ({SIGNATURE_COLUMN_SQL})
SELECT DISTINCT {SIGNATURE_COLUMN_SQL}
FROM raw.raw_signature_observation
ORDER BY {SIGNATURE_COLUMN_SQL};

INSERT INTO signature_occurrence (
    id, signature_id, build_variant_id, domain_path, function_name
)
SELECT
    observation.id,
    signature.id,
    observation.build_variant_id,
    observation.domain_path,
    observation.function_name
FROM raw.raw_signature_observation AS observation
JOIN compact_signature AS signature
  ON signature.sublane_id = observation.sublane_id
 AND signature.policy_id = observation.policy_id
 AND signature.ghidra_language_id = observation.ghidra_language_id
 AND signature.ghidra_compiler_spec_id = observation.ghidra_compiler_spec_id
 AND signature.full_hash = observation.full_hash
 AND signature.specific_hash = observation.specific_hash
 AND signature.specific_hash_additional_size = observation.specific_hash_additional_size
 AND signature.code_unit_size = observation.code_unit_size
ORDER BY observation.id;

INSERT INTO function_relationship (
    id, source_occurrence_id, target_occurrence_id, relationship_kind
)
SELECT id, source_observation_id, target_observation_id, relationship_kind
FROM raw.function_relationship
ORDER BY id;

INSERT INTO admission_decision (
    signature_id, state, rationale, reviewed_at, reviewed_by
)
SELECT id, 'unreviewed', 'awaiting ecological validation', NULL, NULL
FROM compact_signature
ORDER BY id;
"""


IMMUTABLE_TABLES = (
    "compact_generation",
    "policy",
    "sublane",
    "library_family",
    "library_release",
    "build_variant",
    "native_projection",
    "compact_signature",
    "signature_occurrence",
    "function_relationship",
    "admission_decision",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def open_raw(path: Path) -> sqlite3.Connection:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"raw lane database must be a regular file: {path}")
    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    if connection.execute("PRAGMA application_id").fetchone()[0] != RAW_APPLICATION_ID:
        connection.close()
        raise ValueError(f"not a raw FIDB lane database: {path}")
    if connection.execute("PRAGMA user_version").fetchone()[0] != RAW_USER_VERSION:
        connection.close()
        raise ValueError(f"unsupported raw lane database version: {path}")
    if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        connection.close()
        raise ValueError(f"raw lane database failed integrity_check: {path}")
    return connection


def preview_compaction(path: str | Path) -> dict[str, object]:
    source = Path(path)
    connection = open_raw(source)
    try:
        generation_rows = connection.execute(
            "SELECT id, lane_id, evidence_kind FROM lane_generation"
        ).fetchall()
        if len(generation_rows) != 1:
            raise ValueError("raw lane database must contain exactly one generation")
        raw_count = int(
            connection.execute(
                "SELECT count(*) FROM raw_signature_observation"
            ).fetchone()[0]
        )
        unique_count = int(connection.execute(f"""
                SELECT count(*) FROM (
                    SELECT {SIGNATURE_COLUMN_SQL}
                    FROM raw_signature_observation
                    GROUP BY {SIGNATURE_COLUMN_SQL}
                )
                """).fetchone()[0])
    finally:
        connection.close()
    repeated = raw_count - unique_count
    return {
        "schema_version": "fidb-lane-compaction-preview/v1",
        "operation": "read-only-preview",
        "source": {
            "path": str(source.resolve()),
            "sha256": sha256(source),
            "generation_id": generation_rows[0][0],
            "lane_id": generation_rows[0][1],
            "evidence_kind": generation_rows[0][2],
        },
        "deduplication_key": list(SIGNATURE_COLUMNS),
        "raw_observations": raw_count,
        "unique_signatures": unique_count,
        "repeated_observations": repeated,
        "repetition_fraction": repeated / raw_count if raw_count else 0.0,
        "would_modify_source": False,
        "would_preserve_occurrences": raw_count,
    }


def freeze(connection: sqlite3.Connection) -> None:
    for table in IMMUTABLE_TABLES:
        for operation in ("INSERT", "UPDATE", "DELETE"):
            connection.execute(f"""
                CREATE TRIGGER immutable_{table}_{operation.lower()}
                BEFORE {operation} ON {table}
                BEGIN
                    SELECT RAISE(ABORT, 'published compact lane database is immutable');
                END
                """)


def compact_lane_database(
    source_path: str | Path,
    output_path: str | Path,
    *,
    generation_id: str,
    created_at: str | None = None,
) -> dict[str, object]:
    source = Path(source_path).resolve()
    output = Path(output_path).resolve()
    if source == output:
        raise ValueError("compaction output must differ from the raw source")
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"refusing to replace compaction output: {output}")
    if not generation_id or generation_id != generation_id.strip():
        raise ValueError("generation_id must be a non-empty string")
    before_digest = sha256(source)
    preview = preview_compaction(source)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.parent / f".{output.name}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    os.close(descriptor)
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(temporary)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute(f"PRAGMA application_id = {COMPACT_APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version = {COMPACT_USER_VERSION}")
        connection.execute("ATTACH DATABASE ? AS raw", (str(source),))
        connection.executescript(SCHEMA_SQL)
        with connection:
            connection.executescript(COMPACTION_SQL)
            source_generation_id = str(
                connection.execute("SELECT id FROM raw.lane_generation").fetchone()[0]
            )
            connection.execute(
                """
                INSERT INTO compact_generation VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    generation_id,
                    COMPACT_SCHEMA,
                    source_generation_id,
                    before_digest,
                    created_at or datetime.now(timezone.utc).isoformat(),
                    "experimental-unvalidated",
                    json.dumps(SIGNATURE_COLUMNS, separators=(",", ":")),
                    preview["raw_observations"],
                    preview["unique_signatures"],
                    preview["repeated_observations"],
                ),
            )
            output_occurrences = int(
                connection.execute(
                    "SELECT count(*) FROM signature_occurrence"
                ).fetchone()[0]
            )
            if output_occurrences != preview["raw_observations"]:
                raise ValueError("compaction did not preserve every raw occurrence")
            mismatches = int(connection.execute("""
                    SELECT count(*)
                    FROM raw.raw_signature_observation AS observation
                    JOIN signature_occurrence AS occurrence ON occurrence.id = observation.id
                    JOIN compact_signature AS signature ON signature.id = occurrence.signature_id
                    WHERE signature.sublane_id != observation.sublane_id
                       OR signature.policy_id != observation.policy_id
                       OR signature.ghidra_language_id != observation.ghidra_language_id
                       OR signature.ghidra_compiler_spec_id != observation.ghidra_compiler_spec_id
                       OR signature.full_hash != observation.full_hash
                       OR signature.specific_hash != observation.specific_hash
                       OR signature.specific_hash_additional_size != observation.specific_hash_additional_size
                       OR signature.code_unit_size != observation.code_unit_size
                    """).fetchone()[0])
            if mismatches:
                raise ValueError("compaction signature verification found mismatches")
            freeze(connection)
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("compact lane database failed integrity_check")
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise ValueError("compact lane database failed foreign_key_check")
        connection.execute("DETACH DATABASE raw")
        connection.execute("VACUUM")
        connection.close()
        connection = None
        if sha256(source) != before_digest:
            raise ValueError("raw source database changed during compaction")
        try:
            os.link(temporary, output)
        except FileExistsError as error:
            raise FileExistsError(
                f"refusing to replace compaction output: {output}"
            ) from error
    finally:
        if connection is not None:
            connection.close()
        if temporary.exists():
            temporary.unlink()
    return inspect_compact_database(output)


def inspect_compact_database(path: str | Path) -> dict[str, object]:
    database = Path(path)
    if not database.is_file() or database.is_symlink():
        raise ValueError(f"compact lane database must be a regular file: {database}")
    connection = sqlite3.connect(f"file:{database.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        if (
            connection.execute("PRAGMA application_id").fetchone()[0]
            != COMPACT_APPLICATION_ID
        ):
            raise ValueError(f"not a compact FIDB lane database: {database}")
        if (
            connection.execute("PRAGMA user_version").fetchone()[0]
            != COMPACT_USER_VERSION
        ):
            raise ValueError(f"unsupported compact lane database version: {database}")
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError(
                f"compact lane database failed integrity_check: {database}"
            )
        rows = connection.execute("SELECT * FROM compact_generation").fetchall()
        if len(rows) != 1:
            raise ValueError("compact lane database must contain one generation")
        generation = dict(rows[0])
        generation["deduplication_key"] = json.loads(
            generation.pop("deduplication_key_json")
        )
        counts = {
            table: int(
                connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            )
            for table in (
                "compact_signature",
                "signature_occurrence",
                "function_relationship",
                "admission_decision",
            )
        }
    finally:
        connection.close()
    return {
        "schema_version": COMPACT_SCHEMA,
        "path": str(database.resolve()),
        "sha256": sha256(database),
        "bytes": database.stat().st_size,
        "generation": generation,
        "counts": counts,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Preview or explicitly create a compact copy of a raw lane DB."
    )
    result.add_argument("source", type=Path)
    result.add_argument("--output", type=Path)
    result.add_argument("--generation")
    result.add_argument("--execute", action="store_true")
    result.add_argument(
        "--show-sql",
        action="store_true",
        help="print the exact schema and compaction SQL after the JSON result",
    )
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.execute:
            if arguments.output is None or not arguments.generation:
                raise ValueError("--execute requires --output and --generation")
            result = compact_lane_database(
                arguments.source,
                arguments.output,
                generation_id=arguments.generation,
            )
        else:
            if arguments.output is not None or arguments.generation:
                raise ValueError("--output and --generation require --execute")
            result = preview_compaction(arguments.source)
        print(json.dumps(result, indent=2, sort_keys=True))
        if arguments.show_sql:
            print("\n-- compact schema\n")
            print(SCHEMA_SQL.strip())
            print("\n-- compaction algorithm\n")
            print(COMPACTION_SQL.strip())
        return 0
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
