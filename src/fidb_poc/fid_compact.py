"""Compact, streaming execution path for qualified portable FID matching."""

from __future__ import annotations

import hashlib
import importlib.util
from itertools import groupby
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import tomllib
from typing import Callable, Iterable, Mapping, Sequence

from .fid_matching import _score_inputs, score_rows_cpu, score_rows_gpu

INDEX_SCHEMA = "fidb-compact-candidate-index/v1"
QUERY_EVIDENCE_SCHEMA = "fidb-program-signature-evidence/v1"
FNV_64_PRIME = 1099511628211
MASK_64 = (1 << 64) - 1
PERFORMANCE_SCHEMA = "fidb-fid-matching-performance/v1"
DEFAULT_PERFORMANCE = Path("performance/fid-matching.toml")
ALPHA_ENGINE_1 = "alpha_engine_1"
ALPHA_ENGINE_2 = "alpha_engine_2"
LEGACY_ENGINE_ID = "compact-selected-backend-v1"

CandidateInspector = Callable[[Path], Mapping[str, object]]


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load_fid_matching_performance(
    project_root: str | Path,
    authority: str | Path = DEFAULT_PERFORMANCE,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    path = (root / authority).resolve()
    if path != root and root not in path.parents:
        raise ValueError("FID matching performance authority escapes project root")
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if set(document) != {
        "schema_version",
        "mode",
        "allow_gpu",
        "fallback_to_cpu",
        "candidate_chunk_rows",
        "workgroup_size",
    } or document.get("schema_version") != PERFORMANCE_SCHEMA:
        raise ValueError("FID matching performance authority is unsupported")
    if document["mode"] not in {"auto", "cpu", "gpu"}:
        raise ValueError("FID matching performance mode is invalid")
    if type(document["allow_gpu"]) is not bool:
        raise ValueError("FID matching allow_gpu must be boolean")
    if document["fallback_to_cpu"] is not True:
        raise ValueError("FID matching must retain a CPU fallback")
    if not 1 <= int(document["candidate_chunk_rows"]) <= 4_194_304:
        raise ValueError("FID matching candidate chunk is outside safe bounds")
    if not 1 <= int(document["workgroup_size"]) <= 1024:
        raise ValueError("FID matching WGPU workgroup size is outside safe bounds")
    return {
        **document,
        "authority_path": str(path.relative_to(root)),
        "authority_sha256": _sha256(path),
    }


def selected_backend_id(
    performance: Mapping[str, object], authority: Mapping[str, object]
) -> str:
    mode = str(performance["mode"])
    device = "cpu" if mode == "cpu" or not performance["allow_gpu"] else "gpu"
    return next(
        str(row["id"]) for row in authority["backend"] if row["device"] == device
    )


def _detected_gpu_devices() -> list[dict[str, str]]:
    devices = []
    for card in sorted(Path("/sys/class/drm").glob("card[0-9]*")):
        try:
            vendor = (card / "device" / "vendor").read_text(encoding="utf-8").strip()
            device_id = (card / "device" / "device").read_text(encoding="utf-8").strip()
        except OSError:
            continue
        devices.append(
            {"name": card.name, "vendor_id": vendor, "device_id": device_id}
        )
    return devices


def compile_fid_matching_backend_status(
    project_root: str | Path,
    *,
    performance_authority: str | Path = DEFAULT_PERFORMANCE,
) -> dict[str, object]:
    """Project requested, qualified and effective FID-scoring execution."""

    from .fid_matching import load_matching_authority
    from .fid_matching_campaign import campaign_status

    root = Path(project_root).expanduser().resolve()
    performance = load_fid_matching_performance(root, performance_authority)
    authority = load_matching_authority(root)
    campaign = campaign_status(root)
    canary = campaign["canary"]
    rows = [dict(row) for row in authority["backend"]]
    by_id = {str(row["id"]): row for row in rows}
    cpu = next(row for row in rows if row["device"] == "cpu")
    gpu = next((row for row in rows if row["device"] == "gpu"), None)
    requested = selected_backend_id(performance, authority)
    detected_devices = _detected_gpu_devices()
    wgpu_installed = importlib.util.find_spec("wgpu") is not None
    runtime_available = bool(detected_devices and wgpu_installed)
    backend_evidence = canary.get("backend", {})
    gpu_authoritative = bool(
        gpu
        and canary.get("state") == "qualified"
        and canary.get("oracle", {}).get("decision_mismatches") == 0
        and backend_evidence.get("contract_met") is True
        and backend_evidence.get("requested") == gpu["id"]
        and backend_evidence.get("effective") == [gpu["id"]]
    )
    effective = cpu
    fallback_reason = None
    if requested != cpu["id"]:
        if not runtime_available:
            fallback_reason = "GPU or WGPU runtime unavailable"
        elif not gpu_authoritative:
            fallback_reason = "WGPU FID scorer lacks a current zero-mismatch canary"
        else:
            effective = by_id[requested]
    return {
        "schema_version": "fidb-fid-matching-backend-status/v1",
        "requested_mode": performance["mode"],
        "requested_backend": requested,
        "effective_backend": effective,
        "fallback_reason": fallback_reason,
        "performance": performance,
        "gpu": {
            "allowed": bool(performance["allow_gpu"]),
            "runtime_available": runtime_available,
            "authoritative": gpu_authoritative,
            "wgpu_installed": wgpu_installed,
            "detected_devices": detected_devices,
            "backend": gpu,
            "qualification": {
                "state": canary.get("state"),
                "decision_mismatches": canary.get("oracle", {}).get(
                    "decision_mismatches"
                ),
                "truth_coverage": canary.get("truth", {}).get("coverage"),
                "backend": backend_evidence,
            },
        },
        "backends": rows,
    }


def save_fid_matching_performance_mode(
    project_root: str | Path,
    mode: str,
    *,
    authority: str | Path = DEFAULT_PERFORMANCE,
) -> dict[str, object]:
    """Atomically save the non-executing FID scorer preference in TOML."""

    if mode not in {"auto", "cpu", "gpu"}:
        raise ValueError("FID matching performance mode is invalid")
    root = Path(project_root).expanduser().resolve()
    current = load_fid_matching_performance(root, authority)
    path = (root / authority).resolve()
    rendered = "\n".join(
        (
            f'schema_version = "{PERFORMANCE_SCHEMA}"',
            f'mode = "{mode}"',
            f'allow_gpu = {str(bool(current["allow_gpu"])).lower()}',
            "fallback_to_cpu = true",
            f'candidate_chunk_rows = {int(current["candidate_chunk_rows"])}',
            f'workgroup_size = {int(current["workgroup_size"])}',
            "",
        )
    )
    descriptor, name = tempfile.mkstemp(
        prefix=f".{path.name}-", suffix=".tmp", dir=path.parent
    )
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return compile_fid_matching_backend_status(root)


def _input_digest(entries: Sequence[Mapping[str, object]]) -> str:
    rows = sorted(
        (
            str(row["route_id"]),
            str(row["treatment_id"]),
            str(row["owner"]),
            str(row["fidb_sha256"]),
        )
        for row in entries
    )
    return hashlib.sha256(
        json.dumps(rows, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def validate_compact_candidate_index(
    entries: Sequence[Mapping[str, object]], path: Path
) -> dict[str, object]:
    """Verify that an existing index is the exact projection of ``entries``.

    A validation campaign may reuse an immutable archive index as one arm of a
    larger reference population.  Reuse must never silently rebuild or mutate
    that control artifact, so this check is deliberately read-only and fails
    closed when the input identity differs.
    """

    digest = _input_digest(entries)
    if not _current_index(path, digest):
        raise ValueError("compact FID candidate index does not match its sources")
    return compact_index_status(path)


def _current_index(path: Path, input_digest: str) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        metadata = dict(connection.execute("SELECT key, value FROM metadata"))
        candidates = int(
            connection.execute("SELECT COUNT(*) FROM candidate").fetchone()[0]
        )
    except sqlite3.Error:
        return False
    finally:
        connection.close()
    return (
        metadata.get("schema_version") == INDEX_SCHEMA
        and metadata.get("input_digest") == input_digest
        and candidates > 0
    )


def build_compact_candidate_index(
    entries: Sequence[Mapping[str, object]],
    destination: Path,
    inspector: CandidateInspector,
) -> dict[str, object]:
    """Build one reusable candidate/relation index from immutable FIDBs."""

    if not entries:
        raise ValueError("compact FID index requires candidate sources")
    digest = _input_digest(entries)
    if _current_index(destination, digest):
        return compact_index_status(destination)

    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}-", suffix=".tmp", dir=destination.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    temporary.unlink()
    connection = sqlite3.connect(temporary)
    try:
        connection.executescript("""
            PRAGMA journal_mode=OFF;
            PRAGMA synchronous=OFF;
            CREATE TABLE metadata(
                key TEXT PRIMARY KEY, value TEXT NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE source(
                source_id TEXT PRIMARY KEY,
                fidb_sha256 TEXT NOT NULL,
                fidb_path TEXT NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE candidate(
                route_id TEXT NOT NULL,
                treatment_id TEXT NOT NULL,
                full_hash TEXT NOT NULL,
                candidate_id TEXT NOT NULL,
                source_id TEXT NOT NULL,
                record_key TEXT NOT NULL,
                owner TEXT NOT NULL,
                name TEXT NOT NULL,
                specific_hash TEXT NOT NULL,
                additional_size INTEGER NOT NULL,
                code_unit_size INTEGER NOT NULL,
                auto_pass INTEGER NOT NULL,
                auto_fail INTEGER NOT NULL,
                force_specific INTEGER NOT NULL,
                force_relation INTEGER NOT NULL,
                PRIMARY KEY(route_id, treatment_id, candidate_id)
            ) WITHOUT ROWID;
            CREATE INDEX candidate_lookup
            ON candidate(route_id, treatment_id, full_hash);
            CREATE TABLE relation(
                source_id TEXT NOT NULL,
                kind TEXT NOT NULL CHECK(kind IN ('superior','inferior')),
                smash TEXT NOT NULL,
                PRIMARY KEY(source_id, kind, smash)
            ) WITHOUT ROWID;
        """)
        ordered_entries = sorted(
            entries,
            key=lambda row: (
                str(row["fidb_sha256"]),
                str(row["route_id"]),
                str(row["treatment_id"]),
                str(row["owner"]),
            ),
        )
        for expected_sha256, grouped_entries in groupby(
            ordered_entries, key=lambda row: str(row["fidb_sha256"])
        ):
            source_entries = list(grouped_entries)
            source_paths = {
                str(Path(str(entry["fidb_path"])).resolve())
                for entry in source_entries
            }
            if len(source_paths) != 1:
                raise ValueError("one compact FID source digest maps to multiple paths")
            fidb = Path(source_paths.pop())
            if not fidb.is_file() or _sha256(fidb) != expected_sha256:
                raise ValueError(f"compact FID source digest mismatch: {fidb}")
            source_id = expected_sha256
            source = inspector(fidb)
            if (
                source.get("schema_version")
                != "fidb-compact-candidate-source/v1"
                or source.get("fidb_sha256") != expected_sha256
                or not isinstance(source.get("candidates"), list)
                or not isinstance(source.get("relations"), dict)
            ):
                raise ValueError("compact FID source inspection is invalid")
            connection.execute(
                "INSERT INTO source VALUES (?,?,?)",
                (source_id, expected_sha256, str(fidb)),
            )
            relation_rows = [
                (source_id, kind, str(smash))
                for kind in ("superior", "inferior")
                for smash in source["relations"].get(kind, [])
            ]
            connection.executemany(
                "INSERT OR IGNORE INTO relation VALUES (?,?,?)", relation_rows
            )

            for entry in source_entries:
                expected_owner = str(entry["owner"])
                candidate_rows = []
                for candidate in source["candidates"]:
                    if str(candidate["owner"]) != expected_owner:
                        raise ValueError(
                            "compact FID source owner does not match frozen evidence"
                        )
                    candidate_rows.append(
                        (
                            str(entry["route_id"]),
                            str(entry["treatment_id"]),
                            str(candidate["full_hash"]),
                            str(candidate["candidate_id"]),
                            source_id,
                            str(candidate["record_key"]),
                            expected_owner,
                            str(candidate["name"]),
                            str(candidate["specific_hash"]),
                            int(candidate["specific_hash_additional_size"]),
                            int(candidate["code_unit_size"]),
                            int(candidate.get("auto_pass") is True),
                            int(candidate.get("auto_fail") is True),
                            int(candidate.get("force_specific") is True),
                            int(candidate.get("force_relation") is True),
                        )
                    )
                connection.executemany(
                    "INSERT OR IGNORE INTO candidate VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    candidate_rows,
                )
            connection.commit()

        counts = {
            "sources": int(connection.execute("SELECT COUNT(*) FROM source").fetchone()[0]),
            "candidates": int(
                connection.execute("SELECT COUNT(*) FROM candidate").fetchone()[0]
            ),
            "relations": int(
                connection.execute("SELECT COUNT(*) FROM relation").fetchone()[0]
            ),
        }
        for key, value in {
            "schema_version": INDEX_SCHEMA,
            "input_digest": digest,
            **{name: str(value) for name, value in counts.items()},
        }.items():
            connection.execute("INSERT INTO metadata VALUES (?,?)", (key, value))
        connection.commit()
        connection.execute("PRAGMA optimize")
        connection.close()
        temporary.replace(destination)
    finally:
        try:
            connection.close()
        except sqlite3.Error:
            pass
        temporary.unlink(missing_ok=True)
    return compact_index_status(destination)


def compact_index_status(path: Path) -> dict[str, object]:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        metadata = dict(connection.execute("SELECT key, value FROM metadata"))
    finally:
        connection.close()
    return {
        "schema_version": str(metadata["schema_version"]),
        "input_digest": str(metadata["input_digest"]),
        "sources": int(metadata["sources"]),
        "candidates": int(metadata["candidates"]),
        "relations": int(metadata["relations"]),
        "path": str(path),
        "sha256": _sha256(path),
        "bytes": path.stat().st_size,
    }


def load_query_evidence(path: Path) -> list[dict[str, object]]:
    rows = []
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            row = json.loads(line)
            if (
                not isinstance(row, dict)
                or not isinstance(row.get("children"), list)
                or not isinstance(row.get("parents"), list)
            ):
                raise ValueError("query evidence lacks FID relationship hashes")
            rows.append(row)
    if not rows:
        raise ValueError("query evidence contains no functions")
    return rows


def _relation_smash(record_key: str, related_hash: str) -> str:
    mixed = (int(record_key, 16) * FNV_64_PRIME) & MASK_64
    return format(mixed ^ int(related_hash, 16), "016x")


def match_compact(
    index_path: Path,
    functions: Sequence[Mapping[str, object]],
    route_id: str,
    treatment_id: str,
    authority: Mapping[str, object],
    *,
    backend_id: str,
    chunk_rows: int = 262_144,
    workgroup_size: int = 256,
    fallback_to_cpu: bool = True,
) -> dict[str, object]:
    """Stream candidates through a bounded scorer and retain only winners."""

    if chunk_rows < 1:
        raise ValueError("compact FID candidate chunk must be positive")
    backend = authority["backends"].get(backend_id)
    if backend is None:
        raise ValueError("compact FID backend is not declared")
    started_ns = time.monotonic_ns()
    connection = sqlite3.connect(f"file:{index_path}?mode=ro", uri=True)
    relation_cache: dict[str, tuple[set[str], set[str]]] = {}
    packed: list[tuple[int, int, int, int, int]] = []
    metadata: list[tuple[int, Mapping[str, object]]] = []
    winners: dict[int, tuple[float, list[dict[str, object]]]] = {}
    candidate_count = 0
    effective_backend = backend_id
    fallback_reason = None
    device = None
    gpu_batches = 0

    def relations(source_id: str) -> tuple[set[str], set[str]]:
        cached = relation_cache.get(source_id)
        if cached is not None:
            return cached
        superior = set()
        inferior = set()
        for kind, smash in connection.execute(
            "SELECT kind, smash FROM relation WHERE source_id=?", (source_id,)
        ):
            (superior if kind == "superior" else inferior).add(str(smash))
        relation_cache[source_id] = (superior, inferior)
        return superior, inferior

    def flush() -> None:
        nonlocal packed, metadata, device, effective_backend, fallback_reason, gpu_batches
        if not packed:
            return
        if authority["backends"][effective_backend]["device"] == "gpu":
            try:
                scores, observed_device = score_rows_gpu(
                    packed, authority, workgroup_size=workgroup_size
                )
                device = observed_device or device
                gpu_batches += 1
            except Exception as error:
                if not fallback_to_cpu or gpu_batches:
                    raise
                effective_backend = next(
                    str(row["id"])
                    for row in authority["backend"]
                    if row["device"] == "cpu"
                )
                fallback_reason = f"{type(error).__name__}: {error}"
                scores = score_rows_cpu(packed, authority["semantics"])
        else:
            scores = score_rows_cpu(packed, authority["semantics"])
        for (function_index, candidate), score in zip(metadata, scores, strict=True):
            if score is None:
                continue
            match = {
                "candidate_id": str(candidate["candidate_id"]),
                "owner": str(candidate["owner"]),
                "name": str(candidate["name"]),
                "score": float(score),
            }
            current = winners.get(function_index)
            if current is None or float(score) > current[0]:
                winners[function_index] = (float(score), [match])
            elif float(score) == current[0]:
                current[1].append(match)
        packed = []
        metadata = []

    try:
        for function_index, function in enumerate(functions):
            children = list(function.get("children", []))
            parents = list(function.get("parents", []))
            cursor = connection.execute(
                """
                SELECT candidate_id, source_id, record_key, owner, name,
                       full_hash, specific_hash, additional_size, code_unit_size,
                       auto_pass, auto_fail, force_specific, force_relation
                FROM candidate
                WHERE route_id=? AND treatment_id=? AND full_hash=?
                ORDER BY candidate_id
                """,
                (route_id, treatment_id, str(function["full_hash"])),
            )
            for row in cursor:
                candidate = {
                    "candidate_id": str(row[0]),
                    "owner": str(row[3]),
                    "name": str(row[4]),
                    "full_hash": str(row[5]),
                    "specific_hash": str(row[6]),
                    "specific_hash_additional_size": int(row[7]),
                    "code_unit_size": int(row[8]),
                    "auto_pass": bool(row[9]),
                    "auto_fail": bool(row[10]),
                    "force_specific": bool(row[11]),
                    "force_relation": bool(row[12]),
                }
                superior, inferior = relations(str(row[1]))
                record_key = str(row[2])
                candidate["child_code_units"] = sum(
                    int(relation["code_unit_size"])
                    for relation in children
                    if _relation_smash(record_key, str(relation["full_hash"]))
                    in superior
                )
                candidate["parent_code_units"] = (
                    sum(
                        int(relation["code_unit_size"])
                        for relation in parents
                        if _relation_smash(record_key, str(relation["full_hash"]))
                        in inferior
                    )
                    if len(parents)
                    < int(authority["semantics"]["maximum_parents_for_score"])
                    else 0
                )
                packed.append(
                    _score_inputs(function, candidate, authority["semantics"])
                )
                metadata.append((function_index, candidate))
                candidate_count += 1
                if len(packed) >= chunk_rows:
                    flush()
        flush()
    finally:
        connection.close()

    decisions = []
    for index, function in enumerate(functions):
        matches = winners.get(index, (0.0, []))[1]
        matches.sort(key=lambda row: str(row["candidate_id"]))
        decisions.append(
            {
                "address": str(function["address"]),
                "full_hash": str(function["full_hash"]),
                "specific_hash": str(function["specific_hash"]),
                "matches": matches,
            }
        )
    return {
        "backend": effective_backend,
        "requested_backend": backend_id,
        "fallback_reason": fallback_reason,
        "device": device,
        "functions": decisions,
        "candidate_count": candidate_count,
        "matched_functions": sum(bool(row["matches"]) for row in decisions),
        "candidate_chunk_rows": chunk_rows,
        "wall_time_ns": time.monotonic_ns() - started_ns,
    }


def _match_compact_population_alpha_engine_1(
    index_paths: Sequence[Path],
    functions: Sequence[Mapping[str, object]],
    route_id: str,
    treatment_id: str,
    authority: Mapping[str, object],
    *,
    backend_id: str,
    chunk_rows: int,
    workgroup_size: int,
    fallback_to_cpu: bool,
) -> dict[str, object]:
    """Original independently-scored component implementation."""

    paths = [Path(path).resolve() for path in index_paths]
    started_ns = time.monotonic_ns()
    components = [
        match_compact(
            path,
            functions,
            route_id,
            treatment_id,
            authority,
            backend_id=backend_id,
            chunk_rows=chunk_rows,
            workgroup_size=workgroup_size,
            fallback_to_cpu=fallback_to_cpu,
        )
        for path in paths
    ]
    effective = {str(row["backend"]) for row in components}
    requested = {str(row["requested_backend"]) for row in components}
    if len(effective) != 1 or requested != {backend_id}:
        raise ValueError("compact FID population components used different backends")

    by_component = [
        {str(row["address"]): row for row in execution["functions"]}
        for execution in components
    ]
    if any(len(rows) != len(functions) for rows in by_component):
        raise ValueError("compact FID population component lost query functions")
    decisions = []
    for function in functions:
        address = str(function["address"])
        candidates: dict[str, dict[str, object]] = {}
        for component in by_component:
            row = component.get(address)
            if row is None:
                raise ValueError("compact FID population component addresses differ")
            if (
                str(row["full_hash"]) != str(function["full_hash"])
                or str(row["specific_hash"]) != str(function["specific_hash"])
            ):
                raise ValueError("compact FID population component query identity differs")
            for match in row["matches"]:
                candidate_id = str(match["candidate_id"])
                previous = candidates.get(candidate_id)
                if previous is None or float(match["score"]) > float(
                    previous["score"]
                ):
                    candidates[candidate_id] = dict(match)
        maximum = max(
            (float(row["score"]) for row in candidates.values()), default=None
        )
        winners = (
            sorted(
                (
                    row
                    for row in candidates.values()
                    if float(row["score"]) == maximum
                ),
                key=lambda row: str(row["candidate_id"]),
            )
            if maximum is not None
            else []
        )
        decisions.append(
            {
                "address": address,
                "full_hash": str(function["full_hash"]),
                "specific_hash": str(function["specific_hash"]),
                "matches": winners,
            }
        )
    fallback_reasons = sorted(
        {
            str(row["fallback_reason"])
            for row in components
            if row.get("fallback_reason")
        }
    )
    return {
        "engine": ALPHA_ENGINE_1,
        "backend": next(iter(effective)),
        "requested_backend": backend_id,
        "fallback_reason": "; ".join(fallback_reasons) or None,
        "device": next(
            (row.get("device") for row in components if row.get("device")), None
        ),
        "functions": decisions,
        "candidate_count": sum(int(row["candidate_count"]) for row in components),
        "scored_candidate_count": sum(
            int(row["candidate_count"]) for row in components
        ),
        "deduplicated_candidate_count": 0,
        "matched_functions": sum(bool(row["matches"]) for row in decisions),
        "candidate_chunk_rows": chunk_rows,
        "component_indexes": [
            {
                "path": str(path),
                "sha256": _sha256(path),
                "candidate_count": int(execution["candidate_count"]),
                "wall_time_ns": int(execution["wall_time_ns"]),
            }
            for path, execution in zip(paths, components, strict=True)
        ],
        "wall_time_ns": time.monotonic_ns() - started_ns,
    }


def _match_compact_population_alpha_engine_2(
    index_paths: Sequence[Path],
    functions: Sequence[Mapping[str, object]],
    route_id: str,
    treatment_id: str,
    authority: Mapping[str, object],
    *,
    backend_id: str,
    chunk_rows: int = 262_144,
    workgroup_size: int = 256,
    fallback_to_cpu: bool = True,
) -> dict[str, object]:
    """Stream one logical population across immutable component indexes.

    The component indexes remain independently sealed and auditable, but their
    candidate rows share one bounded scoring stream.  This avoids running the
    GPU/CPU scorer once per reference form.  Exact duplicate score inputs are
    interned inside each chunk while the winning match retains the component
    indexes which supplied it.
    """

    paths = [Path(path).resolve() for path in index_paths]
    if not paths:
        raise ValueError("compact FID population requires at least one index")
    if len(set(paths)) != len(paths):
        raise ValueError("compact FID population contains a duplicate index")
    if chunk_rows < 1:
        raise ValueError("compact FID candidate chunk must be positive")
    backend = authority["backends"].get(backend_id)
    if backend is None:
        raise ValueError("compact FID backend is not declared")

    started_ns = time.monotonic_ns()
    connections = [
        sqlite3.connect(f"file:{path}?mode=ro", uri=True) for path in paths
    ]
    relation_cache: dict[tuple[int, str], tuple[set[str], set[str]]] = {}
    packed: list[tuple[int, int, int, int, int]] = []
    metadata: list[tuple[int, dict[str, object]]] = []
    packed_keys: dict[tuple[object, ...], int] = {}
    winners: dict[int, tuple[float, dict[str, dict[str, object]]]] = {}
    component_counts = [0 for _ in paths]
    raw_candidate_count = 0
    scored_candidate_count = 0
    effective_backend = backend_id
    fallback_reason = None
    device = None
    gpu_batches = 0

    def relations(
        component_index: int, source_id: str
    ) -> tuple[set[str], set[str]]:
        key = (component_index, source_id)
        cached = relation_cache.get(key)
        if cached is not None:
            return cached
        superior = set()
        inferior = set()
        for kind, smash in connections[component_index].execute(
            "SELECT kind, smash FROM relation WHERE source_id=?", (source_id,)
        ):
            (superior if kind == "superior" else inferior).add(str(smash))
        relation_cache[key] = (superior, inferior)
        return superior, inferior

    def flush() -> None:
        nonlocal packed, metadata, packed_keys, device
        nonlocal effective_backend, fallback_reason, gpu_batches
        if not packed:
            return
        if authority["backends"][effective_backend]["device"] == "gpu":
            try:
                scores, observed_device = score_rows_gpu(
                    packed, authority, workgroup_size=workgroup_size
                )
                device = observed_device or device
                gpu_batches += 1
            except Exception as error:
                if not fallback_to_cpu or gpu_batches:
                    raise
                effective_backend = next(
                    str(row["id"])
                    for row in authority["backend"]
                    if row["device"] == "cpu"
                )
                fallback_reason = f"{type(error).__name__}: {error}"
                scores = score_rows_cpu(packed, authority["semantics"])
        else:
            scores = score_rows_cpu(packed, authority["semantics"])
        for (function_index, candidate), score in zip(metadata, scores, strict=True):
            if score is None:
                continue
            candidate_id = str(candidate["candidate_id"])
            match = {
                "candidate_id": candidate_id,
                "owner": str(candidate["owner"]),
                "name": str(candidate["name"]),
                "score": float(score),
                "reference_components": sorted(candidate["reference_components"]),
            }
            current = winners.get(function_index)
            if current is None or float(score) > current[0]:
                winners[function_index] = (float(score), {candidate_id: match})
            elif float(score) == current[0]:
                previous = current[1].get(candidate_id)
                if previous is None:
                    current[1][candidate_id] = match
                else:
                    previous["reference_components"] = sorted(
                        set(previous["reference_components"])
                        | set(match["reference_components"])
                    )
        packed = []
        metadata = []
        packed_keys = {}

    try:
        for function_index, function in enumerate(functions):
            children = list(function.get("children", []))
            parents = list(function.get("parents", []))
            for component_index, connection in enumerate(connections):
                cursor = connection.execute(
                    """
                    SELECT candidate_id, source_id, record_key, owner, name,
                           full_hash, specific_hash, additional_size, code_unit_size,
                           auto_pass, auto_fail, force_specific, force_relation
                    FROM candidate
                    WHERE route_id=? AND treatment_id=? AND full_hash=?
                    ORDER BY candidate_id
                    """,
                    (route_id, treatment_id, str(function["full_hash"])),
                )
                for row in cursor:
                    candidate = {
                        "candidate_id": str(row[0]),
                        "owner": str(row[3]),
                        "name": str(row[4]),
                        "full_hash": str(row[5]),
                        "specific_hash": str(row[6]),
                        "specific_hash_additional_size": int(row[7]),
                        "code_unit_size": int(row[8]),
                        "auto_pass": bool(row[9]),
                        "auto_fail": bool(row[10]),
                        "force_specific": bool(row[11]),
                        "force_relation": bool(row[12]),
                        "reference_components": {component_index},
                    }
                    superior, inferior = relations(component_index, str(row[1]))
                    record_key = str(row[2])
                    candidate["child_code_units"] = sum(
                        int(relation["code_unit_size"])
                        for relation in children
                        if _relation_smash(record_key, str(relation["full_hash"]))
                        in superior
                    )
                    candidate["parent_code_units"] = (
                        sum(
                            int(relation["code_unit_size"])
                            for relation in parents
                            if _relation_smash(record_key, str(relation["full_hash"]))
                            in inferior
                        )
                        if len(parents)
                        < int(authority["semantics"]["maximum_parents_for_score"])
                        else 0
                    )
                    score_input = _score_inputs(
                        function, candidate, authority["semantics"]
                    )
                    raw_candidate_count += 1
                    component_counts[component_index] += 1
                    identity = (
                        function_index,
                        candidate["candidate_id"],
                        candidate["owner"],
                        candidate["name"],
                        score_input,
                    )
                    duplicate = packed_keys.get(identity)
                    if duplicate is not None:
                        metadata[duplicate][1]["reference_components"].add(
                            component_index
                        )
                        continue
                    packed_keys[identity] = len(packed)
                    packed.append(score_input)
                    metadata.append((function_index, candidate))
                    scored_candidate_count += 1
                    if len(packed) >= chunk_rows:
                        flush()
        flush()
    finally:
        for connection in connections:
            connection.close()

    decisions = []
    for index, function in enumerate(functions):
        matches = list(winners.get(index, (0.0, {}))[1].values())
        matches.sort(key=lambda row: str(row["candidate_id"]))
        decisions.append(
            {
                "address": str(function["address"]),
                "full_hash": str(function["full_hash"]),
                "specific_hash": str(function["specific_hash"]),
                "matches": matches,
            }
        )

    return {
        "engine": ALPHA_ENGINE_2,
        "backend": effective_backend,
        "requested_backend": backend_id,
        "fallback_reason": fallback_reason,
        "device": device,
        "functions": decisions,
        "candidate_count": raw_candidate_count,
        "scored_candidate_count": scored_candidate_count,
        "deduplicated_candidate_count": raw_candidate_count - scored_candidate_count,
        "matched_functions": sum(bool(row["matches"]) for row in decisions),
        "candidate_chunk_rows": chunk_rows,
        "component_indexes": [
            {
                "path": str(path),
                "sha256": _sha256(path),
                "candidate_count": component_counts[index],
            }
            for index, path in enumerate(paths)
        ],
        "wall_time_ns": time.monotonic_ns() - started_ns,
    }


def match_compact_population(
    index_paths: Sequence[Path],
    functions: Sequence[Mapping[str, object]],
    route_id: str,
    treatment_id: str,
    authority: Mapping[str, object],
    *,
    backend_id: str,
    engine_id: str = ALPHA_ENGINE_2,
    chunk_rows: int = 262_144,
    workgroup_size: int = 256,
    fallback_to_cpu: bool = True,
) -> dict[str, object]:
    """Run an explicitly identified, reproducible population engine.

    ``compact-selected-backend-v1`` is retained as an alias for the original
    engine because it appears in already-sealed C10 campaign authorities.
    """

    paths = [Path(path).resolve() for path in index_paths]
    if not paths:
        raise ValueError("compact FID population requires at least one index")
    if len(set(paths)) != len(paths):
        raise ValueError("compact FID population contains a duplicate index")
    normalized = (
        ALPHA_ENGINE_1 if engine_id == LEGACY_ENGINE_ID else str(engine_id)
    )
    engines = {
        ALPHA_ENGINE_1: _match_compact_population_alpha_engine_1,
        ALPHA_ENGINE_2: _match_compact_population_alpha_engine_2,
    }
    engine = engines.get(normalized)
    if engine is None:
        raise ValueError(f"compact FID population engine is unsupported: {engine_id}")
    return engine(
        paths,
        functions,
        route_id,
        treatment_id,
        authority,
        backend_id=backend_id,
        chunk_rows=chunk_rows,
        workgroup_size=workgroup_size,
        fallback_to_cpu=fallback_to_cpu,
    )
