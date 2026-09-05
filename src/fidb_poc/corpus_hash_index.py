"""Incremental, rebuildable corpus-wide hash evidence index.

The immutable validation and lane databases remain source evidence.  This
sidecar consumes one sealed machine-validation hash database at a time and
stores append-only batch/owner observations plus a rebuildable current-state
cache.  A failed transaction leaves the previous generation unchanged.
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
from typing import Mapping

AUTHORITY_SCHEMA = "fidb-corpus-hash-index-authority/v1"
DATABASE_SCHEMA = "fidb-corpus-hash-index/v1"
APPLICATION_ID = 0x46494849  # FIHI
USER_VERSION = 1
DEFAULT_AUTHORITY = Path("validation/corpus-hash-index.toml")


SCHEMA_SQL = """
CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE corpus_batch(
    id INTEGER PRIMARY KEY,
    ordinal INTEGER NOT NULL UNIQUE,
    validation_id TEXT NOT NULL,
    run_id TEXT NOT NULL UNIQUE,
    source_evidence_sha256 TEXT NOT NULL UNIQUE,
    source_database_sha256 TEXT NOT NULL,
    method_id TEXT NOT NULL,
    method_sha256 TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    owners INTEGER NOT NULL,
    signatures INTEGER NOT NULL,
    query_observations INTEGER NOT NULL
);
CREATE TABLE corpus_owner(
    owner TEXT PRIMARY KEY,
    first_batch_id INTEGER NOT NULL REFERENCES corpus_batch(id)
) WITHOUT ROWID;
CREATE TABLE signature(
    id INTEGER PRIMARY KEY,
    scope TEXT NOT NULL,
    language TEXT NOT NULL,
    full_hash TEXT NOT NULL,
    specific_hash TEXT NOT NULL,
    additional_size INTEGER NOT NULL,
    code_size INTEGER NOT NULL,
    UNIQUE(scope, language, full_hash, specific_hash, additional_size, code_size)
);
CREATE TABLE signature_batch(
    batch_id INTEGER NOT NULL REFERENCES corpus_batch(id),
    signature_id INTEGER NOT NULL REFERENCES signature(id),
    query_observations INTEGER NOT NULL,
    true_positives INTEGER NOT NULL,
    internal_false_positives INTEGER NOT NULL,
    false_negatives INTEGER NOT NULL,
    unattributed_observations INTEGER NOT NULL,
    PRIMARY KEY(batch_id, signature_id)
) WITHOUT ROWID;
CREATE TABLE signature_owner(
    signature_id INTEGER NOT NULL REFERENCES signature(id),
    owner TEXT NOT NULL REFERENCES corpus_owner(owner),
    first_batch_id INTEGER NOT NULL REFERENCES corpus_batch(id),
    reference_observations INTEGER NOT NULL,
    recovered_observations INTEGER NOT NULL,
    missed_observations INTEGER NOT NULL,
    PRIMARY KEY(signature_id, owner)
) WITHOUT ROWID;
CREATE TABLE signature_state(
    signature_id INTEGER PRIMARY KEY REFERENCES signature(id),
    distinct_owners INTEGER NOT NULL,
    reference_observations INTEGER NOT NULL,
    query_observations INTEGER NOT NULL,
    true_positives INTEGER NOT NULL,
    cumulative_false_positives INTEGER NOT NULL,
    false_negatives INTEGER NOT NULL,
    unattributed_observations INTEGER NOT NULL,
    last_batch_id INTEGER NOT NULL REFERENCES corpus_batch(id)
) WITHOUT ROWID;
CREATE TABLE corpus_generation(
    ordinal INTEGER PRIMARY KEY,
    batch_id INTEGER NOT NULL UNIQUE REFERENCES corpus_batch(id),
    generation_digest TEXT NOT NULL UNIQUE,
    previous_digest TEXT,
    authority_sha256 TEXT NOT NULL,
    source_evidence_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    owners INTEGER NOT NULL,
    signatures INTEGER NOT NULL,
    query_observations INTEGER NOT NULL,
    true_positives INTEGER NOT NULL,
    false_positives INTEGER NOT NULL,
    true_negatives INTEGER NOT NULL,
    false_negatives INTEGER NOT NULL
);
CREATE INDEX signature_lookup ON signature(
    scope, language, full_hash, specific_hash, additional_size, code_size
);
CREATE INDEX signature_owner_owner ON signature_owner(owner, signature_id);
CREATE INDEX signature_state_noise ON signature_state(
    distinct_owners DESC, cumulative_false_positives DESC
);
"""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _inside(root: Path, relative: str | Path, label: str) -> Path:
    path = (root / relative).resolve()
    if path != root and root not in path.parents:
        raise ValueError(f"{label} escapes project root")
    return path


def load_corpus_hash_authority(
    project_root: str | Path,
    authority: str | Path = DEFAULT_AUTHORITY,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    path = _inside(root, authority, "corpus hash authority")
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if (
        set(document)
        != {
            "schema_version",
            "id",
            "label",
            "database",
            "identity",
            "incremental",
            "generation",
            "acceleration",
            "safety",
        }
        or document.get("schema_version") != AUTHORITY_SCHEMA
    ):
        raise ValueError("corpus hash authority has unsupported fields or schema")
    if (
        set(document["identity"])
        != {
            "owner_unit",
            "signature_key",
            "require_disjoint_batch_owners",
        }
        or set(document["incremental"])
        != {
            "ingestion_unit",
            "update",
            "unchanged_signatures",
            "true_negatives",
            "retain_source_observations",
            "idempotency_key",
            "full_rebuild_audit_every_batches",
        }
        or set(document["generation"])
        != {
            "write_policy",
            "snapshot_boundary",
            "digest",
        }
        or set(document["acceleration"])
        != {
            "mode",
            "canonical_backend",
            "candidate_backend",
            "publish_from",
            "candidate_failure",
            "require_exact_equivalence",
            "key_words_u32",
            "workgroup_size",
            "max_records_per_shard",
        }
        or set(document["safety"])
        != {
            "mutate_lane_databases",
            "mutate_source_validation",
            "automatic_filtering",
            "permit_in_place_schema_migration",
            "rebuild_from_retained_evidence",
        }
    ):
        raise ValueError("corpus hash authority sections have unsupported fields")
    expected_key = [
        "compatibility_scope",
        "ghidra_language_id",
        "full_hash",
        "specific_hash",
        "specific_hash_additional_size",
        "code_unit_size",
    ]
    expected_safety = {
        "mutate_lane_databases": False,
        "mutate_source_validation": False,
        "automatic_filtering": False,
        "permit_in_place_schema_migration": False,
        "rebuild_from_retained_evidence": True,
    }
    if document["safety"] != expected_safety:
        raise ValueError("corpus hash authority violates its safety contract")
    if (
        document["identity"]
        != {
            "owner_unit": "library-release",
            "signature_key": expected_key,
            "require_disjoint_batch_owners": True,
        }
        or document["incremental"]["update"] != "delta-only"
        or document["incremental"]["unchanged_signatures"] != "do-not-touch"
        or document["incremental"]["true_negatives"] != "derive-arithmetically"
        or document["incremental"]["idempotency_key"] != "source-evidence-sha256"
        or document["generation"]["snapshot_boundary"] != "each-admitted-batch"
        or document["acceleration"]["canonical_backend"] != "cpu-sqlite"
        or document["acceleration"]["publish_from"] != "canonical-only"
        or document["acceleration"]["require_exact_equivalence"] is not True
        or int(document["acceleration"]["key_words_u32"]) != 7
    ):
        raise ValueError("corpus hash authority violates its incremental contract")
    database = _inside(root, str(document["database"]), "corpus hash database")
    return {
        **document,
        "authority_path": str(path.relative_to(root)),
        "authority_sha256": _sha256(path),
        "database_path": database,
    }


def _create_database(
    connection: sqlite3.Connection, authority: Mapping[str, object]
) -> None:
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
    connection.execute(f"PRAGMA user_version={USER_VERSION}")
    connection.executescript(SCHEMA_SQL)
    connection.executemany(
        "INSERT INTO metadata VALUES (?,?)",
        (
            ("schema_version", DATABASE_SCHEMA),
            ("authority_id", str(authority["id"])),
            ("authority_sha256", str(authority["authority_sha256"])),
        ),
    )
    connection.commit()


def _validate_database(
    connection: sqlite3.Connection, authority: Mapping[str, object]
) -> None:
    if connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID:
        raise ValueError("not an FIDB corpus hash index")
    if connection.execute("PRAGMA user_version").fetchone()[0] != USER_VERSION:
        raise ValueError(
            "unsupported corpus hash index version; rebuild instead of migrating"
        )
    metadata = dict(connection.execute("SELECT key, value FROM metadata"))
    if metadata != {
        "schema_version": DATABASE_SCHEMA,
        "authority_id": str(authority["id"]),
        "authority_sha256": str(authority["authority_sha256"]),
    }:
        raise ValueError(
            "corpus hash index authority changed; publish a new index generation"
        )


def _source_metadata(connection: sqlite3.Connection) -> dict[str, str]:
    metadata = dict(connection.execute("SELECT key, value FROM evidence.metadata"))
    if (
        metadata.get("schema_version") != "fidb-machine-validation-hash-evidence/v1"
        or metadata.get("state") != "complete"
        or not metadata.get("source_digest")
        or not metadata.get("method_id")
        or not metadata.get("method_sha256")
    ):
        raise ValueError("source machine-validation hash evidence is not sealed")
    return metadata


def _generation_document(
    connection: sqlite3.Connection, ordinal: int
) -> dict[str, object]:
    connection.row_factory = sqlite3.Row
    row = connection.execute(
        "SELECT * FROM corpus_generation WHERE ordinal=?", (ordinal,)
    ).fetchone()
    if row is None:
        raise ValueError("corpus generation was not published")
    result = dict(row)
    result["schema_version"] = DATABASE_SCHEMA
    return result


def update_corpus_hash_index(
    project_root: str | Path,
    evidence_path: str | Path,
    *,
    validation_id: str,
    run_id: str,
    authority_path: str | Path = DEFAULT_AUTHORITY,
) -> dict[str, object]:
    """Transactionally apply one previously unseen validation-run delta."""

    root = Path(project_root).expanduser().resolve()
    authority = load_corpus_hash_authority(root, authority_path)
    source = _inside(root, evidence_path, "machine-validation hash evidence")
    if not source.is_file() or source.is_symlink():
        raise ValueError("machine-validation hash evidence is unavailable")
    destination = Path(authority["database_path"])
    destination.parent.mkdir(parents=True, exist_ok=True)
    fresh = not destination.exists()
    if destination.is_symlink() or (destination.exists() and not destination.is_file()):
        raise ValueError("corpus hash index must be a regular file")
    temporary: Path | None = None
    if fresh:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{destination.name}-",
            suffix=".partial",
            dir=destination.parent,
        )
        os.close(descriptor)
        temporary = Path(name)
        temporary.unlink()
    working = temporary or destination
    connection = sqlite3.connect(working, uri=True)
    attached = False
    completed = False
    try:
        if fresh:
            _create_database(connection, authority)
        else:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            _validate_database(connection, authority)
        connection.execute(
            "ATTACH DATABASE ? AS evidence",
            (f"{source.as_uri()}?mode=ro",),
        )
        attached = True
        source_metadata = _source_metadata(connection)
        existing = connection.execute(
            "SELECT ordinal, run_id, source_database_sha256 FROM corpus_batch "
            "WHERE source_evidence_sha256=?",
            (source_metadata["source_digest"],),
        ).fetchone()
        if existing is not None:
            if str(existing[1]) != run_id:
                raise ValueError(
                    "source evidence digest is already assigned to another run"
                )
            return {
                **_generation_document(connection, int(existing[0])),
                "state": "already-ingested",
                "database_path": str(destination.relative_to(root)),
                "database_bytes": destination.stat().st_size,
                "source_database_sha256": str(existing[2]),
                "authority_path": authority["authority_path"],
            }
        source_database_sha256 = _sha256(source)
        owners = [
            str(row[0])
            for row in connection.execute(
                "SELECT DISTINCT owner FROM evidence.hash_signature_owner ORDER BY owner"
            )
        ]
        if not owners:
            raise ValueError("source evidence contains no reference owners")
        placeholders = ",".join("?" for _ in owners)
        repeated = connection.execute(
            f"SELECT owner FROM corpus_owner WHERE owner IN ({placeholders}) ORDER BY owner LIMIT 1",
            owners,
        ).fetchone()
        if repeated is not None:
            raise ValueError(f"corpus batch repeats existing owner: {repeated[0]}")
        ordinal = int(
            connection.execute(
                "SELECT COALESCE(MAX(ordinal),0)+1 FROM corpus_batch"
            ).fetchone()[0]
        )
        previous = connection.execute(
            "SELECT generation_digest, owners, signatures, query_observations, "
            "true_positives, false_positives, true_negatives, false_negatives "
            "FROM corpus_generation ORDER BY ordinal DESC LIMIT 1"
        ).fetchone()
        previous_digest = str(previous[0]) if previous else None
        old_owners = int(previous[1]) if previous else 0
        old_queries = int(previous[3]) if previous else 0
        old_tp = int(previous[4]) if previous else 0
        old_fp = int(previous[5]) if previous else 0
        old_tn = int(previous[6]) if previous else 0
        old_fn = int(previous[7]) if previous else 0

        connection.execute("BEGIN IMMEDIATE")
        cursor = connection.execute(
            """
            INSERT INTO corpus_batch(
                ordinal, validation_id, run_id, source_evidence_sha256,
                source_database_sha256, method_id, method_sha256, ingested_at,
                owners, signatures, query_observations
            ) VALUES (?,?,?,?,?,?,?,?,0,0,0)
            """,
            (
                ordinal,
                validation_id,
                run_id,
                source_metadata["source_digest"],
                source_database_sha256,
                source_metadata["method_id"],
                source_metadata["method_sha256"],
                datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            ),
        )
        batch_id = int(cursor.lastrowid)
        connection.executemany(
            "INSERT INTO corpus_owner VALUES (?,?)",
            ((owner, batch_id) for owner in owners),
        )
        connection.execute("""
            CREATE TEMP TABLE delta_query AS
            SELECT scope, language, full_hash, specific_hash, additional_size,
                   code_size, COUNT(*) AS observations
            FROM (
                SELECT DISTINCT scope, language, full_hash, specific_hash,
                       additional_size, code_size, route_id, treatment_id, fold
                FROM evidence.hash_observation
            )
            GROUP BY scope, language, full_hash, specific_hash,
                     additional_size, code_size
            """)
        connection.execute("""
            CREATE TEMP TABLE delta_owner AS
            SELECT scope, language, full_hash, specific_hash, additional_size,
                   code_size, owner,
                   SUM(reference_observations) AS reference_observations,
                   SUM(recovered_observations) AS recovered_observations,
                   SUM(missed_observations) AS missed_observations
            FROM evidence.hash_signature_owner
            GROUP BY scope, language, full_hash, specific_hash, additional_size,
                     code_size, owner
            """)
        connection.execute("""
            INSERT OR IGNORE INTO signature(
                scope, language, full_hash, specific_hash, additional_size, code_size
            )
            SELECT scope, language, full_hash, specific_hash, additional_size, code_size
            FROM evidence.hash_summary
            """)
        connection.execute(
            """
            INSERT INTO signature_batch
            SELECT ?, signature.id, COALESCE(delta_query.observations,0),
                   summary.true_positives, summary.false_positives,
                   summary.false_negatives, summary.unattributed_observations
            FROM evidence.hash_summary AS summary
            JOIN signature
              ON signature.scope=summary.scope
             AND signature.language=summary.language
             AND signature.full_hash=summary.full_hash
             AND signature.specific_hash=summary.specific_hash
             AND signature.additional_size=summary.additional_size
             AND signature.code_size=summary.code_size
            LEFT JOIN delta_query
              ON delta_query.scope=summary.scope
             AND delta_query.language=summary.language
             AND delta_query.full_hash=summary.full_hash
             AND delta_query.specific_hash=summary.specific_hash
             AND delta_query.additional_size=summary.additional_size
             AND delta_query.code_size=summary.code_size
            """,
            (batch_id,),
        )
        connection.execute(
            """
            CREATE TEMP TABLE delta_rollup AS
            SELECT signature.id AS signature_id,
                   batch.query_observations, batch.true_positives,
                   batch.internal_false_positives, batch.false_negatives,
                   batch.unattributed_observations,
                   COUNT(delta_owner.owner) AS new_owners,
                   COALESCE(SUM(delta_owner.reference_observations),0) AS reference_count
            FROM signature_batch AS batch
            JOIN signature ON signature.id=batch.signature_id
            LEFT JOIN delta_owner
              ON delta_owner.scope=signature.scope
             AND delta_owner.language=signature.language
             AND delta_owner.full_hash=signature.full_hash
             AND delta_owner.specific_hash=signature.specific_hash
             AND delta_owner.additional_size=signature.additional_size
             AND delta_owner.code_size=signature.code_size
            WHERE batch.batch_id=?
            GROUP BY signature.id
            """,
            (batch_id,),
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO signature_state
            SELECT signature_id, 0, 0, 0, 0, 0, 0, 0, ? FROM delta_rollup
            """,
            (batch_id,),
        )
        cross_fp_delta = int(connection.execute("""
                SELECT COALESCE(SUM(
                    delta.query_observations * state.distinct_owners
                    + state.query_observations * delta.new_owners
                ),0)
                FROM delta_rollup AS delta
                JOIN signature_state AS state ON state.signature_id=delta.signature_id
                """).fetchone()[0])
        connection.execute(
            """
            UPDATE signature_state AS state
            SET distinct_owners = state.distinct_owners + delta.new_owners,
                reference_observations = state.reference_observations + delta.reference_count,
                query_observations = state.query_observations + delta.query_observations,
                true_positives = state.true_positives + delta.true_positives,
                cumulative_false_positives = state.cumulative_false_positives
                    + delta.internal_false_positives
                    + delta.query_observations * state.distinct_owners
                    + state.query_observations * delta.new_owners,
                false_negatives = state.false_negatives + delta.false_negatives,
                unattributed_observations = state.unattributed_observations
                    + delta.unattributed_observations,
                last_batch_id = ?
            FROM delta_rollup AS delta
            WHERE state.signature_id=delta.signature_id
            """,
            (batch_id,),
        )
        connection.execute(
            """
            INSERT INTO signature_owner
            SELECT signature.id, delta.owner, ?, delta.reference_observations,
                   delta.recovered_observations, delta.missed_observations
            FROM delta_owner AS delta
            JOIN signature
              ON signature.scope=delta.scope
             AND signature.language=delta.language
             AND signature.full_hash=delta.full_hash
             AND signature.specific_hash=delta.specific_hash
             AND signature.additional_size=delta.additional_size
             AND signature.code_size=delta.code_size
            """,
            (batch_id,),
        )
        signatures = int(
            connection.execute("SELECT COUNT(*) FROM signature").fetchone()[0]
        )
        new_queries = int(
            connection.execute(
                "SELECT COALESCE(SUM(query_observations),0) FROM signature_batch WHERE batch_id=?",
                (batch_id,),
            ).fetchone()[0]
        )
        internal = connection.execute(
            "SELECT COALESCE(SUM(true_positives),0), "
            "COALESCE(SUM(false_positives),0), COALESCE(SUM(true_negatives),0), "
            "COALESCE(SUM(false_negatives),0) FROM evidence.unit_result"
        ).fetchone()
        new_tp, internal_fp, internal_tn, new_fn = (int(value) for value in internal)
        owner_total = old_owners + len(owners)
        query_total = old_queries + new_queries
        cross_negative_pairs = new_queries * old_owners + old_queries * len(owners)
        cumulative = {
            "owners": owner_total,
            "signatures": signatures,
            "query_observations": query_total,
            "true_positives": old_tp + new_tp,
            "false_positives": old_fp + internal_fp + cross_fp_delta,
            "true_negatives": old_tn
            + internal_tn
            + cross_negative_pairs
            - cross_fp_delta,
            "false_negatives": old_fn + new_fn,
        }
        connection.execute(
            "UPDATE corpus_batch SET owners=?, signatures=?, query_observations=? WHERE id=?",
            (
                len(owners),
                int(
                    connection.execute(
                        "SELECT COUNT(*) FROM signature_batch WHERE batch_id=?",
                        (batch_id,),
                    ).fetchone()[0]
                ),
                new_queries,
                batch_id,
            ),
        )
        digest_payload = json.dumps(
            {
                "ordinal": ordinal,
                "previous_digest": previous_digest,
                "authority_sha256": authority["authority_sha256"],
                "source_evidence_sha256": source_metadata["source_digest"],
                **cumulative,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        generation_digest = hashlib.sha256(digest_payload).hexdigest()
        connection.execute(
            """
            INSERT INTO corpus_generation VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                ordinal,
                batch_id,
                generation_digest,
                previous_digest,
                authority["authority_sha256"],
                source_metadata["source_digest"],
                datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                cumulative["owners"],
                cumulative["signatures"],
                cumulative["query_observations"],
                cumulative["true_positives"],
                cumulative["false_positives"],
                cumulative["true_negatives"],
                cumulative["false_negatives"],
            ),
        )
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise ValueError("corpus hash index failed foreign-key verification")
        cached_fp = int(
            connection.execute(
                "SELECT COALESCE(SUM(cumulative_false_positives),0) FROM signature_state"
            ).fetchone()[0]
        )
        if cached_fp != cumulative["false_positives"]:
            raise ValueError("corpus hash index cumulative FP cache is inconsistent")
        if cumulative["true_negatives"] < 0:
            raise ValueError("corpus hash index produced a negative TN population")
        connection.commit()
        result = _generation_document(connection, ordinal)
        completed = True
    except Exception:
        connection.rollback()
        raise
    finally:
        if attached:
            try:
                connection.execute("DETACH DATABASE evidence")
            except sqlite3.Error:
                pass
        connection.close()
        if fresh:
            if completed and temporary is not None:
                temporary.replace(destination)
            elif temporary is not None:
                temporary.unlink(missing_ok=True)
                Path(f"{temporary}-journal").unlink(missing_ok=True)
    return {
        **result,
        "state": "ingested",
        "database_path": str(destination.relative_to(root)),
        "database_bytes": destination.stat().st_size,
        "source_database_sha256": source_database_sha256,
        "authority_path": authority["authority_path"],
    }


def inspect_corpus_hash_index(
    project_root: str | Path,
    authority_path: str | Path = DEFAULT_AUTHORITY,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    authority = load_corpus_hash_authority(root, authority_path)
    path = Path(authority["database_path"])
    if not path.is_file():
        return {
            "schema_version": DATABASE_SCHEMA,
            "state": "not-built",
            "database_path": str(path.relative_to(root)),
            "authority_sha256": authority["authority_sha256"],
        }
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        _validate_database(connection, authority)
        latest = connection.execute(
            "SELECT ordinal FROM corpus_generation ORDER BY ordinal DESC LIMIT 1"
        ).fetchone()
        generation = (
            _generation_document(connection, int(latest[0])) if latest else None
        )
    finally:
        connection.close()
    return {
        "schema_version": DATABASE_SCHEMA,
        "state": "ready" if generation else "empty",
        "database_path": str(path.relative_to(root)),
        "database_bytes": path.stat().st_size,
        "authority_sha256": authority["authority_sha256"],
        "generation": generation,
    }
