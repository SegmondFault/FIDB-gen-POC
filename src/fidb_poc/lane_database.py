"""Immutable, occurrence-preserving lane database generations."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Iterable, Mapping
import uuid

LANE_DATABASE_SCHEMA = "fidb-lane-database/v1"
LANE_DATABASE_APPLICATION_ID = 0x4649444C  # FIDL
LANE_DATABASE_USER_VERSION = 1
_HASH64 = re.compile(r"^[0-9a-f]{16}$")
_HASH256 = re.compile(r"^[0-9a-f]{64}$")
_MUTABLE_TABLES = (
    "lane_generation",
    "policy",
    "sublane",
    "library_family",
    "library_release",
    "build_variant",
    "signature",
    "function_occurrence",
    "function_relationship",
    "admission_decision",
    "native_projection",
)


SCHEMA_SQL = """
CREATE TABLE lane_generation (
    id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    lane_id TEXT NOT NULL,
    lane_label TEXT NOT NULL,
    lane_state TEXT NOT NULL CHECK (lane_state IN ('experimental', 'active', 'retired')),
    created_at TEXT NOT NULL,
    registry_sha256 TEXT NOT NULL CHECK (length(registry_sha256) = 64),
    source_run_id TEXT NOT NULL,
    source_run_sha256 TEXT NOT NULL CHECK (length(source_run_sha256) = 64),
    evidence_kind TEXT NOT NULL CHECK (evidence_kind IN ('signature-ledger-only', 'complete-fid-graph')),
    native_projection_state TEXT NOT NULL CHECK (
        native_projection_state IN ('blocked-missing-relationships', 'not-requested', 'ready')
    ),
    signature_records INTEGER NOT NULL DEFAULT 0 CHECK (signature_records >= 0),
    unique_signatures INTEGER NOT NULL DEFAULT 0 CHECK (unique_signatures >= 0),
    function_occurrences INTEGER NOT NULL DEFAULT 0 CHECK (function_occurrences >= 0),
    function_relationships INTEGER NOT NULL DEFAULT 0 CHECK (function_relationships >= 0)
);

CREATE TABLE policy (
    id TEXT PRIMARY KEY,
    ghidra_version TEXT NOT NULL,
    ghidra_release TEXT NOT NULL,
    ghidra_build TEXT NOT NULL,
    analysis_profile TEXT NOT NULL,
    fid_algorithm TEXT NOT NULL
);

CREATE TABLE sublane (
    id TEXT PRIMARY KEY,
    generation_id TEXT NOT NULL REFERENCES lane_generation(id),
    target_id TEXT NOT NULL UNIQUE,
    policy_id TEXT NOT NULL REFERENCES policy(id),
    platform TEXT NOT NULL,
    architecture TEXT NOT NULL,
    machine TEXT NOT NULL,
    binary_format TEXT NOT NULL,
    endianness TEXT NOT NULL CHECK (endianness IN ('little', 'big')),
    bits INTEGER NOT NULL CHECK (bits IN (32, 64)),
    definition_state TEXT NOT NULL CHECK (definition_state IN ('mapped', 'unresolved')),
    ghidra_language_ids_json TEXT NOT NULL,
    compiler_spec_ids_json TEXT NOT NULL
);

CREATE TABLE library_family (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    source_language TEXT NOT NULL,
    UNIQUE (name, source_language)
);

CREATE TABLE library_release (
    id INTEGER PRIMARY KEY,
    family_id INTEGER NOT NULL REFERENCES library_family(id),
    version TEXT NOT NULL,
    source_url TEXT NOT NULL,
    source_sha256 TEXT NOT NULL CHECK (length(source_sha256) = 64),
    UNIQUE (family_id, version, source_sha256)
);

CREATE TABLE build_variant (
    id TEXT PRIMARY KEY,
    release_id INTEGER NOT NULL REFERENCES library_release(id),
    sublane_id TEXT NOT NULL REFERENCES sublane(id),
    route_id TEXT NOT NULL,
    compiler_family TEXT NOT NULL,
    compiler_version TEXT NOT NULL,
    compiler_sha256 TEXT,
    treatment_id TEXT NOT NULL,
    build_manifest_sha256 TEXT NOT NULL CHECK (length(build_manifest_sha256) = 64),
    UNIQUE (release_id, sublane_id, route_id, treatment_id, build_manifest_sha256)
);

CREATE TABLE signature (
    id INTEGER PRIMARY KEY,
    sublane_id TEXT NOT NULL REFERENCES sublane(id),
    policy_id TEXT NOT NULL REFERENCES policy(id),
    ghidra_language_id TEXT NOT NULL,
    ghidra_compiler_spec_id TEXT NOT NULL,
    full_hash TEXT NOT NULL CHECK (length(full_hash) = 16),
    specific_hash TEXT NOT NULL CHECK (length(specific_hash) = 16),
    specific_hash_additional_size INTEGER NOT NULL CHECK (specific_hash_additional_size >= 0),
    code_unit_size INTEGER NOT NULL CHECK (code_unit_size >= 0),
    UNIQUE (
        sublane_id,
        policy_id,
        ghidra_language_id,
        ghidra_compiler_spec_id,
        full_hash,
        specific_hash,
        specific_hash_additional_size,
        code_unit_size
    )
);

CREATE TABLE function_occurrence (
    id INTEGER PRIMARY KEY,
    signature_id INTEGER NOT NULL REFERENCES signature(id),
    build_variant_id TEXT NOT NULL REFERENCES build_variant(id),
    domain_path TEXT NOT NULL,
    function_name TEXT NOT NULL,
    UNIQUE (signature_id, build_variant_id, domain_path, function_name)
);

CREATE TABLE function_relationship (
    id INTEGER PRIMARY KEY,
    source_occurrence_id INTEGER NOT NULL REFERENCES function_occurrence(id),
    target_occurrence_id INTEGER NOT NULL REFERENCES function_occurrence(id),
    relationship_kind TEXT NOT NULL,
    UNIQUE (source_occurrence_id, target_occurrence_id, relationship_kind)
);

CREATE TABLE admission_decision (
    signature_id INTEGER PRIMARY KEY REFERENCES signature(id),
    state TEXT NOT NULL CHECK (
        state IN ('unreviewed', 'unique-owner', 'shared-owner', 'collision-suspect', 'excluded')
    ),
    rationale TEXT NOT NULL,
    reviewed_at TEXT,
    reviewed_by TEXT
);

CREATE TABLE native_projection (
    id TEXT PRIMARY KEY,
    sublane_id TEXT NOT NULL REFERENCES sublane(id),
    kind TEXT NOT NULL CHECK (kind IN ('fidb', 'fidbf')),
    relative_path TEXT NOT NULL,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    state TEXT NOT NULL CHECK (state IN ('staged', 'validated')),
    UNIQUE (sublane_id, kind, relative_path)
);

CREATE INDEX signature_hash_lookup ON signature (
    sublane_id,
    ghidra_language_id,
    ghidra_compiler_spec_id,
    full_hash,
    specific_hash
);
CREATE INDEX occurrence_signature_lookup ON function_occurrence(signature_id);
CREATE INDEX occurrence_build_lookup ON function_occurrence(build_variant_id);
CREATE INDEX build_release_lookup ON build_variant(release_id);
"""


REQUIRED_OCCURRENCE_FIELDS = {
    "sublane_id",
    "library",
    "library_version",
    "source_language",
    "source_url",
    "source_sha256",
    "build_id",
    "route_id",
    "compiler_family",
    "compiler_version",
    "compiler_sha256",
    "treatment_id",
    "build_manifest_sha256",
    "ghidra_language_id",
    "ghidra_compiler_spec_id",
    "domain_path",
    "function_name",
    "full_hash",
    "specific_hash",
    "specific_hash_additional_size",
    "code_unit_size",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _nonempty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{label} must be a non-empty string without outer whitespace")
    return value


def _digest(value: object, label: str, *, optional: bool = False) -> str | None:
    if optional and value in {None, ""}:
        return None
    result = _nonempty(value, label)
    if not _HASH256.fullmatch(result):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return result


def _count(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _validate_occurrence(
    raw: Mapping[str, object],
    sublanes: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    unknown = set(raw) - REQUIRED_OCCURRENCE_FIELDS
    missing = REQUIRED_OCCURRENCE_FIELDS - set(raw)
    if unknown or missing:
        raise ValueError(
            "occurrence fields differ from schema: "
            f"missing={sorted(missing)} unknown={sorted(unknown)}"
        )
    row = dict(raw)
    sublane_id = _nonempty(row["sublane_id"], "sublane_id")
    sublane = sublanes.get(sublane_id)
    if sublane is None:
        raise ValueError(
            f"occurrence references a sublane outside this lane: {sublane_id}"
        )
    for field in REQUIRED_OCCURRENCE_FIELDS - {
        "specific_hash_additional_size",
        "code_unit_size",
        "compiler_sha256",
        "source_sha256",
        "build_manifest_sha256",
        "full_hash",
        "specific_hash",
    }:
        row[field] = _nonempty(row[field], field)
    row["source_sha256"] = _digest(row["source_sha256"], "source_sha256")
    row["build_manifest_sha256"] = _digest(
        row["build_manifest_sha256"], "build_manifest_sha256"
    )
    row["compiler_sha256"] = _digest(
        row["compiler_sha256"], "compiler_sha256", optional=True
    )
    for field in ("full_hash", "specific_hash"):
        value = _nonempty(row[field], field)
        if not _HASH64.fullmatch(value):
            raise ValueError(f"{field} must be a lowercase 64-bit hexadecimal hash")
        row[field] = value
    for field in ("specific_hash_additional_size", "code_unit_size"):
        row[field] = _count(row[field], field)
    languages = sublane["ghidra_language_ids"]
    compiler_specs = sublane["compiler_spec_ids"]
    if row["ghidra_language_id"] not in languages:
        raise ValueError(
            f"occurrence language is not admitted by sublane {sublane_id}: "
            f"{row['ghidra_language_id']}"
        )
    if row["ghidra_compiler_spec_id"] not in compiler_specs:
        raise ValueError(
            f"occurrence compiler spec is not admitted by sublane {sublane_id}: "
            f"{row['ghidra_compiler_spec_id']}"
        )
    return row


def _insert_registry(
    connection: sqlite3.Connection,
    registry: Mapping[str, object],
    lane: Mapping[str, object],
    generation_id: str,
    created_at: str,
    registry_sha256: str,
    source_run_id: str,
    source_run_sha256: str,
    evidence_kind: str,
) -> None:
    projection_state = (
        "blocked-missing-relationships"
        if evidence_kind == "signature-ledger-only"
        else "not-requested"
    )
    connection.execute(
        """
        INSERT INTO lane_generation (
            id, schema_version, lane_id, lane_label, lane_state, created_at,
            registry_sha256, source_run_id, source_run_sha256, evidence_kind,
            native_projection_state
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            generation_id,
            LANE_DATABASE_SCHEMA,
            lane["id"],
            lane["label"],
            lane["state"],
            created_at,
            registry_sha256,
            source_run_id,
            source_run_sha256,
            evidence_kind,
            projection_state,
        ),
    )
    policies = {str(row["id"]): row for row in registry["policies"]}
    policy_ids = {str(row["policy_id"]) for row in lane["sublanes"]}
    for policy_id in sorted(policy_ids):
        policy = policies[policy_id]
        connection.execute(
            "INSERT INTO policy VALUES (?, ?, ?, ?, ?, ?)",
            (
                policy["id"],
                policy["ghidra_version"],
                policy["ghidra_release"],
                policy["ghidra_build"],
                policy["analysis_profile"],
                policy["fid_algorithm"],
            ),
        )
    for sublane in lane["sublanes"]:
        target = sublane["target"]
        connection.execute(
            """
            INSERT INTO sublane VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sublane["id"],
                generation_id,
                sublane["target_id"],
                sublane["policy_id"],
                target["platform"],
                target["architecture"],
                target["machine"],
                target["binary_format"],
                target["endianness"],
                target["bits"],
                sublane["definition_state"],
                json.dumps(sublane["ghidra_language_ids"], separators=(",", ":")),
                json.dumps(sublane["compiler_spec_ids"], separators=(",", ":")),
            ),
        )


def _freeze(connection: sqlite3.Connection) -> None:
    for table in _MUTABLE_TABLES:
        for operation in ("INSERT", "UPDATE", "DELETE"):
            name = f"immutable_{table}_{operation.lower()}"
            connection.execute(f"""
                CREATE TRIGGER {name}
                BEFORE {operation} ON {table}
                BEGIN
                    SELECT RAISE(ABORT, 'published lane database is immutable');
                END
                """)


def build_lane_database(
    output: str | Path,
    *,
    registry: Mapping[str, object],
    lane_id: str,
    generation_id: str,
    registry_sha256: str,
    source_run_id: str,
    source_run_sha256: str,
    occurrences: Iterable[Mapping[str, object]],
    evidence_kind: str = "signature-ledger-only",
    created_at: str | None = None,
) -> dict[str, object]:
    """Build and atomically publish one immutable experimental lane database."""

    destination = Path(output)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"refusing to replace lane database: {destination}")
    if evidence_kind not in {"signature-ledger-only", "complete-fid-graph"}:
        raise ValueError(f"unsupported evidence_kind: {evidence_kind}")
    _digest(registry_sha256, "registry_sha256")
    _digest(source_run_sha256, "source_run_sha256")
    generation_id = _nonempty(generation_id, "generation_id")
    source_run_id = _nonempty(source_run_id, "source_run_id")
    lanes = [lane for lane in registry["lanes"] if lane["id"] == lane_id]
    if len(lanes) != 1:
        raise ValueError(f"unknown or duplicate lane: {lane_id}")
    lane = lanes[0]
    sublanes = {str(row["id"]): row for row in lane["sublanes"]}
    timestamp = created_at or datetime.now(timezone.utc).isoformat()
    _nonempty(timestamp, "created_at")

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.parent / f".{destination.name}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    os.close(descriptor)
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(temporary)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute(f"PRAGMA application_id = {LANE_DATABASE_APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version = {LANE_DATABASE_USER_VERSION}")
        connection.executescript(SCHEMA_SQL)
        with connection:
            _insert_registry(
                connection,
                registry,
                lane,
                generation_id,
                timestamp,
                registry_sha256,
                source_run_id,
                source_run_sha256,
                evidence_kind,
            )
            family_ids: dict[tuple[str, str], int] = {}
            release_ids: dict[tuple[int, str, str], int] = {}
            build_fingerprints: dict[str, tuple[object, ...]] = {}
            signature_ids: dict[tuple[object, ...], int] = {}
            signature_records = 0
            for raw in occurrences:
                row = _validate_occurrence(raw, sublanes)
                signature_records += 1
                family_key = (str(row["library"]), str(row["source_language"]))
                family_id = family_ids.get(family_key)
                if family_id is None:
                    cursor = connection.execute(
                        "INSERT INTO library_family (name, source_language) VALUES (?, ?)",
                        family_key,
                    )
                    family_id = int(cursor.lastrowid)
                    family_ids[family_key] = family_id
                release_key = (
                    family_id,
                    str(row["library_version"]),
                    str(row["source_sha256"]),
                )
                release_id = release_ids.get(release_key)
                if release_id is None:
                    cursor = connection.execute(
                        """
                        INSERT INTO library_release (
                            family_id, version, source_url, source_sha256
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (
                            family_id,
                            row["library_version"],
                            row["source_url"],
                            row["source_sha256"],
                        ),
                    )
                    release_id = int(cursor.lastrowid)
                    release_ids[release_key] = release_id
                build_id = str(row["build_id"])
                build_fingerprint = (
                    release_id,
                    row["sublane_id"],
                    row["route_id"],
                    row["compiler_family"],
                    row["compiler_version"],
                    row["compiler_sha256"],
                    row["treatment_id"],
                    row["build_manifest_sha256"],
                )
                if build_id in build_fingerprints:
                    if build_fingerprints[build_id] != build_fingerprint:
                        raise ValueError(
                            f"build_id has inconsistent provenance: {build_id}"
                        )
                else:
                    connection.execute(
                        """
                        INSERT INTO build_variant VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            build_id,
                            release_id,
                            row["sublane_id"],
                            row["route_id"],
                            row["compiler_family"],
                            row["compiler_version"],
                            row["compiler_sha256"],
                            row["treatment_id"],
                            row["build_manifest_sha256"],
                        ),
                    )
                    build_fingerprints[build_id] = build_fingerprint
                signature_key = (
                    row["sublane_id"],
                    sublanes[str(row["sublane_id"])]["policy_id"],
                    row["ghidra_language_id"],
                    row["ghidra_compiler_spec_id"],
                    row["full_hash"],
                    row["specific_hash"],
                    row["specific_hash_additional_size"],
                    row["code_unit_size"],
                )
                signature_id = signature_ids.get(signature_key)
                if signature_id is None:
                    cursor = connection.execute(
                        """
                        INSERT INTO signature (
                            sublane_id, policy_id, ghidra_language_id,
                            ghidra_compiler_spec_id, full_hash, specific_hash,
                            specific_hash_additional_size, code_unit_size
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        signature_key,
                    )
                    signature_id = int(cursor.lastrowid)
                    signature_ids[signature_key] = signature_id
                connection.execute(
                    """
                    INSERT INTO function_occurrence (
                        signature_id, build_variant_id, domain_path, function_name
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        signature_id,
                        build_id,
                        row["domain_path"],
                        row["function_name"],
                    ),
                )
            if signature_records == 0:
                raise ValueError("lane database requires at least one occurrence")
            occurrence_count = int(
                connection.execute(
                    "SELECT count(*) FROM function_occurrence"
                ).fetchone()[0]
            )
            relationship_count = int(
                connection.execute(
                    "SELECT count(*) FROM function_relationship"
                ).fetchone()[0]
            )
            connection.execute(
                """
                UPDATE lane_generation
                SET signature_records = ?, unique_signatures = ?,
                    function_occurrences = ?, function_relationships = ?
                WHERE id = ?
                """,
                (
                    signature_records,
                    len(signature_ids),
                    occurrence_count,
                    relationship_count,
                    generation_id,
                ),
            )
            for signature_id in signature_ids.values():
                connection.execute(
                    """
                    INSERT INTO admission_decision (
                        signature_id, state, rationale, reviewed_at, reviewed_by
                    ) VALUES (?, 'unreviewed', 'awaiting ecological validation', NULL, NULL)
                    """,
                    (signature_id,),
                )
            _freeze(connection)
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("lane database failed SQLite integrity_check")
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise ValueError("lane database failed foreign_key_check")
        connection.execute("VACUUM")
        connection.close()
        connection = None
        try:
            os.link(temporary, destination)
        except FileExistsError as error:
            raise FileExistsError(
                f"refusing to replace lane database: {destination}"
            ) from error
    finally:
        if connection is not None:
            connection.close()
        if temporary.exists():
            temporary.unlink()
    return inspect_lane_database(destination)


def inspect_lane_database(path: str | Path) -> dict[str, object]:
    """Validate and summarize a published lane database without mutating it."""

    database = Path(path)
    if not database.is_file() or database.is_symlink():
        raise ValueError(f"lane database must be a regular file: {database}")
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        if (
            connection.execute("PRAGMA application_id").fetchone()[0]
            != LANE_DATABASE_APPLICATION_ID
        ):
            raise ValueError(f"not an FIDB lane database: {database}")
        if (
            connection.execute("PRAGMA user_version").fetchone()[0]
            != LANE_DATABASE_USER_VERSION
        ):
            raise ValueError(f"unsupported lane database version: {database}")
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError(f"lane database failed integrity_check: {database}")
        generation_rows = connection.execute("SELECT * FROM lane_generation").fetchall()
        if len(generation_rows) != 1:
            raise ValueError("lane database must contain exactly one generation")
        generation = dict(generation_rows[0])
        sublanes = [
            {
                **dict(row),
                "ghidra_language_ids": json.loads(row["ghidra_language_ids_json"]),
                "compiler_spec_ids": json.loads(row["compiler_spec_ids_json"]),
            }
            for row in connection.execute("SELECT * FROM sublane ORDER BY id")
        ]
        for row in sublanes:
            row.pop("ghidra_language_ids_json")
            row.pop("compiler_spec_ids_json")
        counts = {
            table: int(
                connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            )
            for table in (
                "library_family",
                "library_release",
                "build_variant",
                "signature",
                "function_occurrence",
                "function_relationship",
                "admission_decision",
                "native_projection",
            )
        }
    finally:
        connection.close()
    return {
        "schema_version": LANE_DATABASE_SCHEMA,
        "path": str(database.resolve()),
        "sha256": _sha256(database),
        "bytes": database.stat().st_size,
        "generation": generation,
        "sublanes": sublanes,
        "counts": counts,
    }
