"""Build portable, manifest-bound raw FIDBF releases from sealed queue evidence."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import tomllib
from typing import Iterable, Mapping

from .c_width import compile_c_width

EXPORT_STATUS_SCHEMA = "fidb-export-status/v1"
EXPORT_MANIFEST_SCHEMA = "fidb-export-release/v1"
CATALOGUE_APPLICATION_ID = 0x46494458  # FIDX
CATALOGUE_USER_VERSION = 1
DEFAULT_AUTHORITY = Path("export/c10-fidbf-v1.toml")


class ExportError(ValueError):
    """Raised when an export authority or its evidence fails a release gate."""


@dataclass(frozen=True)
class _Artifact:
    identity: str
    library_id: str
    library_version: str
    rank: int
    route_id: str
    treatment_id: str
    job_id: str
    batch_id: str
    cell_id: str
    source_sha256: str
    toolchain_identity: str
    ghidra_language_id: str
    ghidra_compiler_spec_id: str
    artifact_path: Path
    artifact_sha256: str
    artifact_bytes: int
    seal_path: str
    seal_sha256: str
    completed_at: str

    @property
    def package_path(self) -> str:
        safe = self.identity.replace("/", "_").replace(":", "__")
        return f"fidbf/{safe}.fidbf"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _managed_path(root: Path, value: object, *, must_exist: bool = True) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise ExportError("export paths must be non-empty project-relative strings")
    path = (root / value).resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ExportError(f"export path escapes project root: {value}") from error
    if must_exist and (not path.is_file() or path.is_symlink()):
        raise ExportError(f"required export input is missing or unsafe: {value}")
    return path


def _load_authority(
    root: Path, authority_path: Path = DEFAULT_AUTHORITY
) -> dict[str, object]:
    root = root.expanduser().resolve()
    path = _managed_path(root, str(authority_path))
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if document.get("schema_version") != "fidb-export/v1":
        raise ExportError("unsupported export authority schema")
    required = {
        "id",
        "label",
        "release_id",
        "language_id",
        "package_format",
        "compression_level",
        "output_root",
        "population",
        "catalogue",
        "hash_quality",
        "validation",
        "compatibility",
        "verification",
    }
    missing = required - set(document)
    if missing:
        raise ExportError(f"export authority is missing fields: {sorted(missing)}")
    if document["package_format"] != "tar.zst":
        raise ExportError("only tar.zst export packages are supported")
    document["authority_path"] = str(path.relative_to(root))
    document["authority_sha256"] = _sha256(path)
    return document


def _source_rows(
    root: Path, authority: Mapping[str, object]
) -> list[dict[str, object]]:
    population = authority["population"]
    assert isinstance(population, dict)
    source_path = _managed_path(root, population["source_pack"])
    document = tomllib.loads(source_path.read_text(encoding="utf-8"))
    sources = document.get("source")
    if not isinstance(sources, list):
        raise ExportError("source pack has no source rows")
    rows = [dict(row) for row in sources if isinstance(row, dict)]
    expected = int(population["expected_libraries"])
    if len(rows) != expected:
        raise ExportError(
            f"source pack contains {len(rows)} libraries; expected {expected}"
        )
    return rows


def _expected_identities(
    root: Path, authority: Mapping[str, object]
) -> tuple[dict[str, dict[str, object]], set[str], set[str]]:
    population = authority["population"]
    assert isinstance(population, dict)
    width_id = Path(str(population["width_authority"])).stem
    width = compile_c_width(root, width_id)
    pairs = {
        (str(row["route_id"]), str(row["treatment_id"]))
        for row in width["applicability"]
        if row["state"] == "executable"
    }
    per_library = int(population["expected_identities_per_library"])
    if len(pairs) != per_library:
        raise ExportError(
            f"width authority resolves {len(pairs)} identities per library; expected {per_library}"
        )
    sources = _source_rows(root, authority)
    source_by_id = {str(row["id"]): row for row in sources}
    identities = {
        f"{source_id}@{source['version']}:{route}:{treatment}"
        for source_id, source in source_by_id.items()
        for route, treatment in pairs
    }
    expected = int(population["expected_artifacts"])
    if len(identities) != expected:
        raise ExportError(
            f"authority resolves {len(identities)} artifacts; expected {expected}"
        )
    return source_by_id, identities, {route for route, _ in pairs}


def _read_artifacts(
    root: Path,
    ledger: Path,
    source_by_id: Mapping[str, Mapping[str, object]],
) -> tuple[dict[str, _Artifact], list[dict[str, object]]]:
    if not ledger.is_file():
        return {}, []
    connection = sqlite3.connect(f"file:{ledger}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute("""
            SELECT j.job_id, j.batch_id, j.base_cell_id, j.result_json,
                   j.updated_at, r.cell_json
            FROM jobs AS j
            JOIN resolved_cells AS r
              ON r.plan_digest = j.plan_digest AND r.cell_id = j.base_cell_id
            WHERE j.state = 'complete' AND j.result_json IS NOT NULL
            ORDER BY j.updated_at DESC, j.job_id DESC
            """).fetchall()
    finally:
        connection.close()

    artifacts: dict[str, _Artifact] = {}
    duplicates: list[dict[str, object]] = []
    for row in rows:
        try:
            result = json.loads(row["result_json"])
            cell = json.loads(row["cell_json"])
            recipe = cell["recipe"]
            source_id = str(recipe["name"])
            version = str(recipe["version"])
            expected_source = source_by_id.get(source_id)
            if expected_source is None or str(expected_source["version"]) != version:
                continue
            fidbf = result["fidbf"]
            seal = result["seal"]
            route = str(cell["toolchain"]["route"])
            treatment = str(cell["build"]["treatment"])
            identity = f"{source_id}@{version}:{route}:{treatment}"
            artifact_path = _managed_path(root, fidbf["path"])
            artifact = _Artifact(
                identity=identity,
                library_id=source_id,
                library_version=version,
                rank=int(expected_source["rank"]),
                route_id=route,
                treatment_id=treatment,
                job_id=str(row["job_id"]),
                batch_id=str(row["batch_id"]),
                cell_id=str(row["base_cell_id"]),
                source_sha256=str(recipe["sha256"]),
                toolchain_identity=str(cell["toolchain"].get("identity", "")),
                ghidra_language_id=str(cell["analysis"]["ghidra_language"]),
                ghidra_compiler_spec_id=str(cell["analysis"]["ghidra_compiler_spec"]),
                artifact_path=artifact_path,
                artifact_sha256=str(fidbf["sha256"]),
                artifact_bytes=artifact_path.stat().st_size,
                seal_path=str(seal["path"]),
                seal_sha256=str(seal["sha256"]),
                completed_at=str(row["updated_at"]),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError, OSError):
            continue
        previous = artifacts.get(identity)
        if previous is not None:
            duplicates.append(
                {
                    "identity": identity,
                    "selected_job_id": previous.job_id,
                    "duplicate_job_id": artifact.job_id,
                    "same_sha256": previous.artifact_sha256 == artifact.artifact_sha256,
                }
            )
            continue
        artifacts[identity] = artifact
    return artifacts, duplicates


def _sidecar_status(root: Path, authority: Mapping[str, object]) -> dict[str, object]:
    quality = authority["hash_quality"]
    assert isinstance(quality, dict)
    try:
        database = _managed_path(root, quality["database"])
        connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
        try:
            check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            generation = connection.execute(
                """SELECT ordinal, generation_digest, owners, signatures,
                          query_observations, true_positives, false_positives,
                          true_negatives, false_negatives
                   FROM corpus_generation ORDER BY ordinal DESC LIMIT 1"""
            ).fetchone()
        finally:
            connection.close()
        if check != "ok" or generation is None:
            raise ExportError(
                "hash-quality database failed integrity or generation check"
            )
        values = tuple(generation)
        required_owners = int(quality["required_generation_owners"])
        ready = int(values[2]) >= required_owners
        return {
            "state": "ready" if ready else "incomplete",
            "path": str(database.relative_to(root)),
            "bytes": database.stat().st_size,
            "sha256": None,
            "generation": {
                "ordinal": int(values[0]),
                "digest": str(values[1]),
                "owners": int(values[2]),
                "signatures": int(values[3]),
                "query_observations": int(values[4]),
                "true_positives": int(values[5]),
                "false_positives": int(values[6]),
                "true_negatives": int(values[7]),
                "false_negatives": int(values[8]),
            },
        }
    except (ExportError, OSError, sqlite3.Error) as error:
        return {"state": "missing-or-invalid", "error": str(error)}


def inspect_export(
    project_root: str | Path, authority_path: Path = DEFAULT_AUTHORITY
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    authority = _load_authority(root, authority_path)
    population = authority["population"]
    assert isinstance(population, dict)
    source_by_id, expected, routes = _expected_identities(root, authority)
    ledger = _managed_path(root, population["ledger"], must_exist=False)
    artifacts, duplicates = _read_artifacts(root, ledger, source_by_id)
    present = set(artifacts) & expected
    missing = sorted(expected - present)
    unexpected = sorted(set(artifacts) - expected)
    by_library = []
    expected_per_library = int(population["expected_identities_per_library"])
    for source_id, source in sorted(
        source_by_id.items(), key=lambda item: int(item[1]["rank"])
    ):
        count = sum(
            key.startswith(f"{source_id}@{source['version']}:") for key in present
        )
        by_library.append(
            {
                "id": source_id,
                "label": source["label"],
                "version": source["version"],
                "rank": int(source["rank"]),
                "present": count,
                "expected": expected_per_library,
                "missing": expected_per_library - count,
                "complete": count == expected_per_library,
                "bytes": sum(
                    artifact.artifact_bytes
                    for key, artifact in artifacts.items()
                    if key in present and artifact.library_id == source_id
                ),
            }
        )
    quality = _sidecar_status(root, authority)
    validation = authority["validation"]
    compatibility = authority["compatibility"]
    assert isinstance(validation, dict) and isinstance(compatibility, dict)
    report = _managed_path(root, validation["report"], must_exist=False)
    registry = _managed_path(root, compatibility["lane_registry"], must_exist=False)
    blockers = []
    if missing:
        blockers.append(f"{len(missing)} expected FIDBF identities are missing")
    if unexpected:
        blockers.append(f"{len(unexpected)} unexpected C10 identities were found")
    if bool(quality.get("state") != "ready") and bool(authority["hash_quality"].get("required")):  # type: ignore[union-attr]
        blockers.append("hash-quality sidecar is missing, incomplete or invalid")
    if not report.is_file() and bool(validation.get("required")):
        blockers.append("validation report is missing")
    if not registry.is_file():
        blockers.append("lane compatibility registry is missing")
    output_root = _managed_path(root, authority["output_root"], must_exist=False)
    package_path = output_root / f"{authority['release_id']}.tar.zst"
    package_checksum = package_path.with_suffix(package_path.suffix + ".sha256")
    package_sha256 = None
    if package_path.is_file() and package_checksum.is_file():
        fields = package_checksum.read_text(encoding="utf-8").split()
        if len(fields) == 2 and fields[1] == package_path.name:
            package_sha256 = fields[0]
    return {
        "schema_version": EXPORT_STATUS_SCHEMA,
        "authority": {
            "id": authority["id"],
            "label": authority["label"],
            "path": authority["authority_path"],
            "sha256": authority["authority_sha256"],
        },
        "release": {
            "id": authority["release_id"],
            "language_id": authority["language_id"],
            "package_format": authority["package_format"],
            "output_path": str(package_path.relative_to(root)),
            "exists": package_path.is_file(),
            "bytes": package_path.stat().st_size if package_path.is_file() else 0,
            "sha256": package_sha256,
        },
        "population": {
            "expected": len(expected),
            "present": len(present),
            "missing": len(missing),
            "libraries_expected": len(source_by_id),
            "libraries_complete": sum(bool(row["complete"]) for row in by_library),
            "routes": len(routes),
            "treatments": expected_per_library // len(routes),
            "raw_bytes": sum(artifacts[key].artifact_bytes for key in present),
            "duplicate_completed_identities": len(duplicates),
            "unexpected": len(unexpected),
        },
        "libraries": by_library,
        "missing_examples": missing[:20],
        "duplicates": duplicates[:20],
        "hash_quality": quality,
        "validation": {
            "state": "ready" if report.is_file() else "missing",
            "path": str(report.relative_to(root)),
            "bytes": report.stat().st_size if report.is_file() else 0,
        },
        "compatibility": {
            "state": "ready" if registry.is_file() else "missing",
            "path": str(registry.relative_to(root)),
        },
        "blockers": blockers,
        "ready": not blockers,
        "actions": {
            "preview": True,
            "build": not blockers,
        },
    }


def _catalogue(
    path: Path, release_id: str, built_at: str, artifacts: Iterable[_Artifact]
) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript(f"""
            PRAGMA application_id = {CATALOGUE_APPLICATION_ID};
            PRAGMA user_version = {CATALOGUE_USER_VERSION};
            CREATE TABLE release(
                id TEXT PRIMARY KEY,
                schema_version TEXT NOT NULL,
                artifact_kind TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE fidbf_artifact(
                identity TEXT PRIMARY KEY,
                package_path TEXT NOT NULL UNIQUE,
                library_id TEXT NOT NULL,
                library_version TEXT NOT NULL,
                library_rank INTEGER NOT NULL,
                route_id TEXT NOT NULL,
                treatment_id TEXT NOT NULL,
                job_id TEXT NOT NULL,
                batch_id TEXT NOT NULL,
                cell_id TEXT NOT NULL,
                source_sha256 TEXT NOT NULL,
                toolchain_identity TEXT NOT NULL,
                ghidra_language_id TEXT NOT NULL,
                ghidra_compiler_spec_id TEXT NOT NULL,
                artifact_sha256 TEXT NOT NULL,
                artifact_bytes INTEGER NOT NULL,
                seal_path TEXT NOT NULL,
                seal_sha256 TEXT NOT NULL,
                completed_at TEXT NOT NULL
            );
            CREATE INDEX fidbf_artifact_library ON fidbf_artifact(library_id, library_version);
            CREATE INDEX fidbf_artifact_route ON fidbf_artifact(route_id, treatment_id);
            """)
        connection.execute(
            "INSERT INTO release VALUES (?, ?, ?, ?)",
            (release_id, "fidb-export-catalogue/v1", "fidbf", built_at),
        )
        connection.executemany(
            "INSERT INTO fidbf_artifact VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    row.identity,
                    row.package_path,
                    row.library_id,
                    row.library_version,
                    row.rank,
                    row.route_id,
                    row.treatment_id,
                    row.job_id,
                    row.batch_id,
                    row.cell_id,
                    row.source_sha256,
                    row.toolchain_identity,
                    row.ghidra_language_id,
                    row.ghidra_compiler_spec_id,
                    row.artifact_sha256,
                    row.artifact_bytes,
                    row.seal_path,
                    row.seal_sha256,
                    row.completed_at,
                )
                for row in artifacts
            ],
        )
        connection.commit()
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ExportError("generated export catalogue failed SQLite quick_check")
    finally:
        connection.close()


def _snapshot_sqlite(source: Path, destination: Path) -> None:
    opened = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    snapshot = sqlite3.connect(destination)
    try:
        opened.backup(snapshot)
        snapshot.commit()
        if snapshot.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ExportError(f"SQLite snapshot failed quick_check: {source}")
    finally:
        snapshot.close()
        opened.close()


def _toml_string(value: object) -> str:
    return json.dumps(str(value), ensure_ascii=False)


def _release_toml(
    authority: Mapping[str, object], status: Mapping[str, object], built_at: str
) -> str:
    population = status["population"]
    quality = status["hash_quality"]
    assert isinstance(population, dict) and isinstance(quality, dict)
    generation = quality.get("generation") or {}
    assert isinstance(generation, dict)
    return "\n".join(
        [
            f"schema_version = {_toml_string(EXPORT_MANIFEST_SCHEMA)}",
            f"release_id = {_toml_string(authority['release_id'])}",
            f"built_at = {_toml_string(built_at)}",
            f"authority_path = {_toml_string(authority['authority_path'])}",
            f"authority_sha256 = {_toml_string(authority['authority_sha256'])}",
            f"language_id = {_toml_string(authority['language_id'])}",
            f"artifact_kind = {_toml_string('fidbf')}",
            f"artifact_count = {int(population['present'])}",
            f"raw_artifact_bytes = {int(population['raw_bytes'])}",
            "",
            "[catalogue]",
            f"schema_version = {_toml_string('fidb-export-catalogue/v1')}",
            f"path = {_toml_string(authority['catalogue']['path'])}",  # type: ignore[index]
            "",
            "[hash_quality]",
            f"path = {_toml_string(authority['hash_quality']['package_path'])}",  # type: ignore[index]
            f"generation_ordinal = {int(generation.get('ordinal', 0))}",
            f"generation_digest = {_toml_string(generation.get('digest', ''))}",
            f"owners = {int(generation.get('owners', 0))}",
            f"signatures = {int(generation.get('signatures', 0))}",
            "",
            "[validation]",
            f"report = {_toml_string(authority['validation']['package_path'])}",  # type: ignore[index]
            "",
            "[compatibility]",
            f"lane_registry = {_toml_string(authority['compatibility']['package_path'])}",  # type: ignore[index]
            "",
        ]
    )


def _readme(release_id: str) -> str:
    return f"""# {release_id}

This portable research release contains one raw Ghidra `.fidbf` database for
each C10 library, route and treatment identity. `index/catalogue.sqlite3` maps
every file back to its library, build identity, provenance seal and digest.

Start with `manifest.md` for the complete human-readable inventory: covered
libraries and versions, execution variants, database schemas and file counts.

`index/hash-quality.sqlite3` is a separate, versioned evidence sidecar. It
records cross-library signature ownership and validation observations; it does
not silently remove or rewrite signatures in the raw FID databases.

Use `checksums.sha256` to verify every payload before loading it. The package
contains raw archive/object-derived FID populations. The linked-reference
validation report is included as evidence about matching quality, not as an
additional `.fidbf` population.
"""


def _human_bytes(value: int) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    amount = float(value)
    for unit in units:
        if abs(amount) < 1024 or unit == units[-1]:
            return f"{amount:,.0f} {unit}" if unit == "B" else f"{amount:,.2f} {unit}"
        amount /= 1024
    raise AssertionError("unreachable")


def _sqlite_schema(path: Path) -> list[dict[str, object]]:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        table_names = [
            str(row[0]) for row in connection.execute("""SELECT name FROM sqlite_master
                   WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                   ORDER BY name""")
        ]
        tables = []
        for name in table_names:
            quoted = name.replace('"', '""')
            columns = [
                {
                    "name": str(row[1]),
                    "type": str(row[2]) or "ANY",
                    "not_null": bool(row[3]),
                    "primary_key": bool(row[5]),
                }
                for row in connection.execute(f'PRAGMA table_info("{quoted}")')
            ]
            tables.append({"name": name, "columns": columns})
        return tables
    finally:
        connection.close()


def _database_structure(database: Path, package_path: str) -> list[str]:
    lines = [
        f"### `{package_path}`",
        "",
        f"Size: **{_human_bytes(database.stat().st_size)}**",
        "",
    ]
    for table in _sqlite_schema(database):
        lines.extend(
            (
                f"#### `{table['name']}`",
                "",
                "| Column | Type | Constraint |",
                "|---|---|---|",
            )
        )
        for column in table["columns"]:
            constraints = []
            if column["primary_key"]:
                constraints.append("primary key")
            if column["not_null"]:
                constraints.append("not null")
            lines.append(
                f"| `{column['name']}` | `{column['type']}` | "
                f"{', '.join(constraints) or '—'} |"
            )
        lines.append("")
    return lines


def _manifest_markdown(
    authority: Mapping[str, object],
    status: Mapping[str, object],
    artifacts: list[_Artifact],
    catalogue: Path,
    quality: Path,
    built_at: str,
) -> str:
    population = status["population"]
    libraries = status["libraries"]
    assert isinstance(population, dict) and isinstance(libraries, list)
    variants = sorted({(row.route_id, row.treatment_id) for row in artifacts})
    routes = sorted({route for route, _ in variants})
    treatments = sorted({treatment for _, treatment in variants})
    by_route = {
        route: sorted(
            treatment for candidate, treatment in variants if candidate == route
        )
        for route in routes
    }
    lines = [
        f"# {authority['release_id']} manifest",
        "",
        f"Sealed evidence timestamp: `{built_at}`  ",
        f"Export authority: `{authority['authority_path']}`  ",
        f"Authority SHA-256: `{authority['authority_sha256']}`",
        "",
        "## Contents at a glance",
        "",
        "| Item | Count |",
        "|---|---:|",
        f"| Libraries | {len(libraries):,} |",
        f"| Library releases | {len(libraries):,} |",
        f"| Exact execution variants per library | {len(variants):,} |",
        f"| Toolchain/target routes | {len(routes):,} |",
        f"| Treatment profiles | {len(treatments):,} |",
        "| Native Ghidra `.fidb` files | 0 |",
        f"| Raw Ghidra `.fidbf` files | {len(artifacts):,} |",
        f"| Raw `.fidbf` bytes | {_human_bytes(int(population['raw_bytes']))} |",
        "| SQLite database files | 2 |",
        "",
        "This release deliberately exports raw `.fidbf` files. It does not contain a",
        "merged native `.fidb`; consumers can select or project the raw files using the",
        "catalogue and compatibility authority supplied here.",
        "",
        "## Libraries and versions covered",
        "",
        "| Rank | Library | ID | Version | `.fidbf` files | Raw size |",
        "|---:|---|---|---|---:|---:|",
    ]
    for row in libraries:
        assert isinstance(row, dict)
        lines.append(
            f"| {int(row['rank'])} | {row['label']} | `{row['id']}` | "
            f"`{row['version']}` | {int(row['present']):,} | "
            f"{_human_bytes(int(row['bytes']))} |"
        )
    lines.extend(
        [
            "",
            "## Execution variants covered",
            "",
            f"Every library has **{len(variants):,}** exact route/treatment executions.",
            "The table below is the covered applicability set—not a theoretical Cartesian",
            "product. Each row lists the treatment profiles actually present for that route.",
            "",
            "| Route / compiler-target identity | Treatments | Exact variants |",
            "|---|---|---:|",
        ]
    )
    for route, covered in by_route.items():
        lines.append(
            f"| `{route}` | {', '.join(f'`{item}`' for item in covered)} | {len(covered)} |"
        )
    lines.extend(
        [
            "",
            "### Treatment profiles",
            "",
            *[f"- `{treatment}`" for treatment in treatments],
            "",
            "## Database files",
            "",
            "- `index/catalogue.sqlite3` is the package map. Its `fidbf_artifact` rows",
            "  connect each `.fidbf` path to the library release, route, treatment,",
            "  source/toolchain identity, Ghidra language/compiler specification, job,",
            "  provenance seal, byte count and SHA-256.",
            "- `index/hash-quality.sqlite3` is the versioned cross-library evidence",
            "  sidecar. It keeps signatures, many-to-many library ownership, corpus",
            "  generations and accumulated validation outcomes separate from immutable",
            "  raw FID data.",
            "",
            "The exact SQL-facing structure of both packaged databases follows.",
            "",
            *_database_structure(catalogue, str(authority["catalogue"]["path"])),  # type: ignore[index]
            *_database_structure(quality, str(authority["hash_quality"]["package_path"])),  # type: ignore[index]
            "## Other release evidence",
            "",
            f"- `{authority['validation']['package_path']}` — matching/validation report",  # type: ignore[index]
            f"- `{authority['compatibility']['package_path']}` — lane compatibility authority",  # type: ignore[index]
            "- `release.toml` — machine-readable release identity and generation binding",
            "- `checksums.sha256` — SHA-256 for every packaged payload member",
            "",
        ]
    )
    return "\n".join(lines)


def _tar_add_file(archive: tarfile.TarFile, source: Path, arcname: str) -> None:
    info = archive.gettarinfo(str(source), arcname=arcname)
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    with source.open("rb") as stream:
        archive.addfile(info, stream)


def build_export(
    project_root: str | Path, authority_path: Path = DEFAULT_AUTHORITY
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    authority = _load_authority(root, authority_path)
    status = inspect_export(root, authority_path)
    if not status["ready"]:
        raise ExportError("export is blocked: " + "; ".join(status["blockers"]))
    population = authority["population"]
    assert isinstance(population, dict)
    source_by_id, expected, _ = _expected_identities(root, authority)
    ledger = _managed_path(root, population["ledger"])
    artifacts_by_id, _ = _read_artifacts(root, ledger, source_by_id)
    artifacts = [artifacts_by_id[key] for key in sorted(expected)]
    if bool(population["require_ledger_sha256"]):
        mismatches = [
            row.identity
            for row in artifacts
            if _sha256(row.artifact_path) != row.artifact_sha256
        ]
        if mismatches:
            raise ExportError(f"{len(mismatches)} FIDBF files failed ledger SHA-256")

    output_root = _managed_path(root, authority["output_root"], must_exist=False)
    output_root.mkdir(parents=True, exist_ok=True)
    final = output_root / f"{authority['release_id']}.tar.zst"
    temporary_archive = final.with_suffix(final.suffix + ".partial")
    temporary_archive.unlink(missing_ok=True)
    built_at = max(row.completed_at for row in artifacts)
    with tempfile.TemporaryDirectory(
        prefix="fidb-export-", dir=output_root
    ) as raw_temp:
        temp = Path(raw_temp)
        catalogue = temp / "catalogue.sqlite3"
        _catalogue(catalogue, str(authority["release_id"]), built_at, artifacts)
        quality_source = _managed_path(root, authority["hash_quality"]["database"])  # type: ignore[index]
        quality_snapshot = temp / "hash-quality.sqlite3"
        _snapshot_sqlite(quality_source, quality_snapshot)
        release = temp / "release.toml"
        release.write_text(_release_toml(authority, status, built_at), encoding="utf-8")
        readme = temp / "README.md"
        readme.write_text(_readme(str(authority["release_id"])), encoding="utf-8")
        manifest = temp / "manifest.md"
        manifest.write_text(
            _manifest_markdown(
                authority,
                status,
                artifacts,
                catalogue,
                quality_snapshot,
                built_at,
            ),
            encoding="utf-8",
        )
        validation = _managed_path(root, authority["validation"]["report"])  # type: ignore[index]
        registry = _managed_path(root, authority["compatibility"]["lane_registry"])  # type: ignore[index]
        fixed = [
            (release, "release.toml"),
            (readme, "README.md"),
            (manifest, "manifest.md"),
            (catalogue, str(authority["catalogue"]["path"])),  # type: ignore[index]
            (quality_snapshot, str(authority["hash_quality"]["package_path"])),  # type: ignore[index]
            (validation, str(authority["validation"]["package_path"])),  # type: ignore[index]
            (registry, str(authority["compatibility"]["package_path"])),  # type: ignore[index]
        ]
        payload = [
            *fixed,
            *((row.artifact_path, row.package_path) for row in artifacts),
        ]
        checksums = temp / "checksums.sha256"
        checksums.write_text(
            "".join(f"{_sha256(path)}  {arcname}\n" for path, arcname in payload),
            encoding="utf-8",
        )
        payload.append((checksums, "checksums.sha256"))
        zstd = shutil.which("zstd")
        if zstd is None:
            raise ExportError("zstd executable is required to build tar.zst exports")
        process = subprocess.Popen(
            [
                zstd,
                "-q",
                f"-{int(authority['compression_level'])}",
                "-T0",
                "-o",
                str(temporary_archive),
                "-",
            ],
            stdin=subprocess.PIPE,
        )
        assert process.stdin is not None
        try:
            with tarfile.open(fileobj=process.stdin, mode="w|") as archive:
                for path, arcname in payload:
                    _tar_add_file(archive, path, arcname)
        finally:
            process.stdin.close()
        if process.wait() != 0:
            temporary_archive.unlink(missing_ok=True)
            raise ExportError("zstd failed while building export package")

    if bool(authority["verification"]["reopen_archive"]):  # type: ignore[index]
        subprocess.run(["zstd", "-q", "-t", str(temporary_archive)], check=True)
        members = subprocess.run(
            ["tar", "--use-compress-program=zstd", "-tf", str(temporary_archive)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        expected_members = {arcname for _, arcname in payload}
        if set(members) != expected_members or len(members) != len(expected_members):
            temporary_archive.unlink(missing_ok=True)
            raise ExportError(
                "reopened package member set differs from release payload"
            )
    os.replace(temporary_archive, final)
    digest = _sha256(final)
    checksum = final.with_suffix(final.suffix + ".sha256")
    checksum.write_text(f"{digest}  {final.name}\n", encoding="utf-8")
    completed = inspect_export(root, authority_path)
    completed["build"] = {
        "state": "complete",
        "built_at": built_at,
        "path": str(final.relative_to(root)),
        "bytes": final.stat().st_size,
        "sha256": digest,
        "checksum_path": str(checksum.relative_to(root)),
        "members": len(payload),
    }
    return completed


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="fidb-poc export")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "preview", "build"):
        command = commands.add_parser(name)
        command.add_argument("--project-root", type=Path, default=Path.cwd())
        command.add_argument("--authority", type=Path, default=DEFAULT_AUTHORITY)
    arguments = parser.parse_args(argv)
    try:
        result = (
            build_export(arguments.project_root, arguments.authority)
            if arguments.command == "build"
            else inspect_export(arguments.project_root, arguments.authority)
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (ExportError, OSError, sqlite3.Error, subprocess.SubprocessError) as error:
        print(f"error: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
