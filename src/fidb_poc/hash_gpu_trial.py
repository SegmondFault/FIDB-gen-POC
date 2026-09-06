"""Optional WGPU exact-signature probe compared with a CPU packed baseline."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import tomllib
from typing import Mapping

REPORT_SCHEMA = "fidb-hash-gpu-comparison/v1"
LOOKUP_REPORT_SCHEMA = "fidb-hash-lookup-report/v1"
BACKEND_AUTHORITY_SCHEMA = "fidb-hash-analysis-backends/v1"
DEFAULT_BACKEND_AUTHORITY = Path("validation/hash-analysis-backends.toml")
HASH_PERFORMANCE_SCHEMA = "fidb-hash-analysis-performance/v1"
DEFAULT_HASH_PERFORMANCE = Path("performance/hash-analysis.toml")
SENTINEL = 0xFFFFFFFF


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_hash_backend_authority(
    project_root: str | Path,
    authority: str | Path = DEFAULT_BACKEND_AUTHORITY,
) -> dict[str, object]:
    """Load the selected lookup backend and explicit qualification policy."""

    root = Path(project_root).expanduser().resolve()
    path = (root / authority).resolve()
    if path != root and root not in path.parents:
        raise ValueError("hash backend authority escapes the project root")
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if (
        set(document)
        != {
            "schema_version",
            "selected",
            "comparison_policy",
            "require_zero_mismatches_for_promotion",
            "backend",
        }
        or document.get("schema_version") != BACKEND_AUTHORITY_SCHEMA
    ):
        raise ValueError("hash backend authority has unsupported fields or schema")
    if document["comparison_policy"] != "explicit-qualification-only":
        raise ValueError("hash backend comparison must be explicitly admitted")
    if document["require_zero_mismatches_for_promotion"] is not True:
        raise ValueError("hash backend promotion must require zero mismatches")
    rows = document.get("backend")
    if not isinstance(rows, list) or not rows:
        raise ValueError("hash backend authority has no backends")
    by_id: dict[str, dict[str, object]] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) not in (
            {"id", "state", "implementation", "device", "scope"},
            {
                "id",
                "state",
                "implementation",
                "device",
                "scope",
                "qualification_report",
            },
        ):
            raise ValueError("hash backend entry has unsupported fields")
        backend_id = str(row.get("id") or "")
        if not backend_id or backend_id in by_id:
            raise ValueError("hash backend identity is empty or duplicated")
        if row.get("device") not in {"cpu", "gpu"}:
            raise ValueError("hash backend device is unsupported")
        by_id[backend_id] = dict(row)
    selected = by_id.get(str(document["selected"]))
    if selected is None or selected.get("state") != "qualified-authoritative":
        raise ValueError("selected hash backend is not qualified and authoritative")
    return {
        **document,
        "selected_backend": selected,
        "authority_path": str(path.relative_to(root)),
        "authority_sha256": _sha256(path),
    }


def _inside(root: Path, value: str | Path, label: str) -> Path:
    path = (root / value).resolve()
    if path != root and root not in path.parents:
        raise ValueError(f"{label} escapes the project root")
    return path


def load_hash_performance(
    project_root: str | Path,
    authority: str | Path = DEFAULT_HASH_PERFORMANCE,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    path = _inside(root, authority, "hash performance authority")
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if (
        set(document) != {"schema_version", "mode", "allow_gpu", "fallback_to_cpu"}
        or document.get("schema_version") != HASH_PERFORMANCE_SCHEMA
    ):
        raise ValueError("hash performance authority has unsupported fields or schema")
    if document["mode"] not in {"auto", "cpu", "gpu"}:
        raise ValueError("hash performance mode must be auto, cpu or gpu")
    if (
        type(document["allow_gpu"]) is not bool
        or document["fallback_to_cpu"] is not True
    ):
        raise ValueError("hash performance GPU/fallback policy is unsafe")
    return {
        **document,
        "authority_path": str(path.relative_to(root)),
        "authority_sha256": _sha256(path),
    }


def _detected_gpu_devices() -> list[dict[str, str]]:
    devices = []
    drm_root = Path("/sys/class/drm")
    for card in sorted(drm_root.glob("card[0-9]*")):
        device = card / "device"
        try:
            vendor = (device / "vendor").read_text(encoding="utf-8").strip()
            device_id = (device / "device").read_text(encoding="utf-8").strip()
        except OSError:
            continue
        devices.append({"name": card.name, "vendor_id": vendor, "device_id": device_id})
    return devices


def compile_hash_backend_status(
    project_root: str | Path,
    *,
    backend_authority: str | Path = DEFAULT_BACKEND_AUTHORITY,
    performance_authority: str | Path = DEFAULT_HASH_PERFORMANCE,
) -> dict[str, object]:
    """Project the detected, requested and effective hash lookup backend."""

    root = Path(project_root).expanduser().resolve()
    backends = load_hash_backend_authority(root, backend_authority)
    performance = load_hash_performance(root, performance_authority)
    rows = [dict(row) for row in backends["backend"]]
    by_id = {str(row["id"]): row for row in rows}
    cpu = next((row for row in rows if row["device"] == "cpu"), None)
    gpu = next((row for row in rows if row["device"] == "gpu"), None)
    if cpu is None:
        raise ValueError("hash backend authority has no CPU fallback")
    detected_devices = _detected_gpu_devices()
    wgpu_installed = importlib.util.find_spec("wgpu") is not None
    qualification = None
    if gpu and gpu.get("qualification_report"):
        path = _inside(
            root, str(gpu["qualification_report"]), "GPU qualification report"
        )
        if path.is_file():
            try:
                report = json.loads(path.read_text(encoding="utf-8"))
                qualification = {
                    "state": report.get("state"),
                    "scope": report.get("scope"),
                    "candidate_backend": report.get("candidate_backend"),
                    "report_path": str(path.relative_to(root)),
                    "report_sha256": _sha256(path),
                    "mismatches": report.get("mismatches"),
                    "device": report.get("device"),
                    "performance": report.get("performance"),
                }
            except (OSError, ValueError, json.JSONDecodeError):
                qualification = {
                    "state": "invalid",
                    "report_path": str(path.relative_to(root)),
                }
    gpu_runtime_available = bool(gpu and detected_devices and wgpu_installed)
    gpu_authoritative = bool(
        gpu
        and gpu.get("state") == "qualified-authoritative"
        and gpu.get("scope") == "packed-complete-signature-exact-probe"
        and qualification
        and qualification.get("state") == "equivalent"
        and qualification.get("scope") == gpu.get("scope")
        and qualification.get("candidate_backend") == gpu.get("id")
        and qualification.get("mismatches") == 0
    )
    mode = str(performance["mode"])
    requested_gpu = mode == "gpu" or (mode == "auto" and performance["allow_gpu"])
    effective_id = str(cpu["id"])
    fallback_reason = None
    if requested_gpu:
        if not gpu_runtime_available:
            fallback_reason = "GPU or WGPU runtime unavailable"
        elif not gpu_authoritative:
            fallback_reason = (
                "GPU backend is qualified only for the packed lookup probe"
            )
        else:
            effective_id = str(gpu["id"])
    effective = by_id[effective_id]
    return {
        "schema_version": "fidb-hash-backend-status/v1",
        "authority_path": backends["authority_path"],
        "authority_sha256": backends["authority_sha256"],
        "performance": performance,
        "requested_mode": mode,
        "effective_backend": effective,
        "fallback_reason": fallback_reason,
        "gpu": {
            "allowed": bool(performance["allow_gpu"]),
            "runtime_available": gpu_runtime_available,
            "authoritative": gpu_authoritative,
            "wgpu_installed": wgpu_installed,
            "detected_devices": detected_devices,
            "backend": gpu,
            "qualification": qualification,
        },
        "backends": rows,
    }


def save_hash_performance_mode(
    project_root: str | Path,
    mode: str,
    *,
    authority: str | Path = DEFAULT_HASH_PERFORMANCE,
) -> dict[str, object]:
    """Atomically save a non-executing CPU/GPU preference in TOML."""

    if mode not in {"auto", "cpu", "gpu"}:
        raise ValueError("hash performance mode must be auto, cpu or gpu")
    root = Path(project_root).expanduser().resolve()
    current = load_hash_performance(root, authority)
    path = _inside(root, authority, "hash performance authority")
    rendered = "\n".join(
        (
            f'schema_version = "{HASH_PERFORMANCE_SCHEMA}"',
            f'mode = "{mode}"',
            f'allow_gpu = {str(bool(current["allow_gpu"])).lower()}',
            "fallback_to_cpu = true",
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
    return compile_hash_backend_status(root)


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


def _matrix(
    connection: sqlite3.Connection,
    query: str,
    parameters: tuple[object, ...],
    scopes: Mapping[str, int],
):
    import numpy as np

    count = int(
        connection.execute(f"SELECT COUNT(*) FROM ({query})", parameters).fetchone()[0]
    )
    values = np.empty((count, 7), dtype=np.uint32)
    for index, row in enumerate(connection.execute(query, parameters)):
        scope, full_hash, specific_hash, additional_size, code_size = row
        full = int(str(full_hash), 16)
        specific = int(str(specific_hash), 16)
        values[index] = (
            scopes[str(scope)],
            full >> 32,
            full & SENTINEL,
            specific >> 32,
            specific & SENTINEL,
            int(additional_size),
            int(code_size),
        )
    return values


def _structured(matrix):
    import numpy as np

    dtype = np.dtype([(f"word_{index}", "<u4") for index in range(7)])
    return matrix.view(dtype).reshape(-1)


def _cpu_probe(reference, queries):
    import numpy as np

    reference_keys = _structured(reference)
    query_keys = _structured(queries)
    positions = np.searchsorted(reference_keys, query_keys)
    result = np.full(len(query_keys), SENTINEL, dtype=np.uint32)
    valid = positions < len(reference_keys)
    valid_indices = np.flatnonzero(valid)
    if len(valid_indices):
        equal = reference_keys[positions[valid]] == query_keys[valid]
        matching = valid_indices[equal]
        result[matching] = positions[matching].astype(np.uint32)
    return result


def _shader(reference_count: int, query_count: int, workgroup_size: int) -> str:
    return f"""
const WORDS: u32 = 7u;
const REFERENCE_COUNT: u32 = {reference_count}u;
const QUERY_COUNT: u32 = {query_count}u;
@group(0) @binding(0) var<storage, read> reference_keys: array<u32>;
@group(0) @binding(1) var<storage, read> query_keys: array<u32>;
@group(0) @binding(2) var<storage, read_write> positions: array<u32>;

fn compare(reference_index: u32, query_index: u32) -> i32 {{
    for (var word: u32 = 0u; word < WORDS; word = word + 1u) {{
        let reference_value = reference_keys[reference_index * WORDS + word];
        let query_value = query_keys[query_index * WORDS + word];
        if (reference_value < query_value) {{ return -1; }}
        if (reference_value > query_value) {{ return 1; }}
    }}
    return 0;
}}

@compute @workgroup_size({workgroup_size})
fn main(@builtin(global_invocation_id) invocation: vec3<u32>) {{
    let query_index = invocation.x;
    if (query_index >= QUERY_COUNT) {{ return; }}
    var low: u32 = 0u;
    var high: u32 = REFERENCE_COUNT;
    loop {{
        if (low >= high) {{ break; }}
        let middle = low + (high - low) / 2u;
        if (compare(middle, query_index) < 0) {{
            low = middle + 1u;
        }} else {{
            high = middle;
        }}
    }}
    if (low < REFERENCE_COUNT && compare(low, query_index) == 0) {{
        positions[query_index] = low;
    }} else {{
        positions[query_index] = 0xffffffffu;
    }}
}}
"""


def _gpu_probe(reference, queries, workgroup_size: int):
    import numpy as np
    import wgpu.utils
    from wgpu.utils.compute import compute_with_buffers

    device = wgpu.utils.get_default_device()
    groups = (len(queries) + workgroup_size - 1) // workgroup_size
    output = compute_with_buffers(
        {0: reference, 1: queries},
        {2: (len(queries), "I")},
        _shader(len(reference), len(queries), workgroup_size),
        n=groups,
    )
    result = np.frombuffer(output[2], dtype=np.uint32).copy()
    return result, dict(device.adapter.info)


def _atomic_npy(path: Path, values) -> None:
    import numpy as np

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        prefix=f".{path.name}-", suffix=".tmp", dir=path.parent
    )
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            np.save(stream, values, allow_pickle=False)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _packed_matrices(
    root: Path,
    connection: sqlite3.Connection,
    *,
    batch_id: int,
    generation_digest: str,
):
    """Load or materialise reusable packed keys for one corpus generation."""

    import numpy as np

    if len(generation_digest) != 64 or any(
        character not in "0123456789abcdef" for character in generation_digest
    ):
        raise ValueError("invalid corpus generation digest for packed cache")
    cache = root / "artifacts/hash-discrimination/packed-lookups" / generation_digest
    reference_path = cache / "reference.npy"
    query_path = cache / f"batch-{batch_id}-query.npy"
    metadata_path = cache / f"batch-{batch_id}-metadata.json"
    if reference_path.is_file() and query_path.is_file() and metadata_path.is_file():
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            if (
                metadata.get("schema_version") == "fidb-packed-hash-lookup-cache/v1"
                and metadata.get("generation_digest") == generation_digest
                and metadata.get("batch_id") == batch_id
            ):
                reference = np.load(reference_path, mmap_mode="r", allow_pickle=False)
                queries = np.load(query_path, mmap_mode="r", allow_pickle=False)
                if (
                    reference.ndim == 2
                    and queries.ndim == 2
                    and reference.shape[1] == queries.shape[1] == 7
                    and len(reference) == int(metadata["reference_signatures"])
                    and len(queries) == int(metadata["query_signatures"])
                ):
                    return reference, queries, 0, True, cache
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            pass
    scopes = {
        str(row[0]): index
        for index, row in enumerate(
            connection.execute("SELECT DISTINCT scope FROM signature ORDER BY scope")
        )
    }
    reference_sql = """
        SELECT signature.scope, signature.full_hash, signature.specific_hash,
               signature.additional_size, signature.code_size
        FROM signature_state
        JOIN signature ON signature.id=signature_state.signature_id
        WHERE signature_state.distinct_owners>0
        ORDER BY signature.scope, signature.full_hash,
                 signature.specific_hash, signature.additional_size,
                 signature.code_size
    """
    query_sql = """
        SELECT signature.scope, signature.full_hash, signature.specific_hash,
               signature.additional_size, signature.code_size
        FROM signature_batch
        JOIN signature ON signature.id=signature_batch.signature_id
        WHERE signature_batch.batch_id=?
          AND signature_batch.query_observations>0
        ORDER BY signature.scope, signature.full_hash,
                 signature.specific_hash, signature.additional_size,
                 signature.code_size
    """
    started_ns = time.monotonic_ns()
    reference = _matrix(connection, reference_sql, (), scopes)
    queries = _matrix(connection, query_sql, (batch_id,), scopes)
    packing_wall_ns = time.monotonic_ns() - started_ns
    _atomic_npy(reference_path, reference)
    _atomic_npy(query_path, queries)
    _atomic_json(
        metadata_path,
        {
            "schema_version": "fidb-packed-hash-lookup-cache/v1",
            "generation_digest": generation_digest,
            "batch_id": batch_id,
            "reference_signatures": len(reference),
            "query_signatures": len(queries),
            "key_words_u32": 7,
            "packing_wall_time_ns": packing_wall_ns,
        },
    )
    return reference, queries, packing_wall_ns, False, cache


def compare_packed_probe(
    project_root: str | Path,
    *,
    corpus_database: str | Path,
    batch_id: int,
    generation_digest: str,
    output_path: str | Path,
    authority: Mapping[str, object],
) -> dict[str, object]:
    """Compare CPU and GPU exact-key lookup without granting GPU authority."""

    root = Path(project_root).expanduser().resolve()
    database = (root / corpus_database).resolve()
    output = (root / output_path).resolve()
    if root not in database.parents or root not in output.parents:
        raise ValueError("GPU comparison path escapes project root")
    started_ns = time.monotonic_ns()
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        reference, queries, packing_wall_ns, cache_hit, cache = _packed_matrices(
            root,
            connection,
            batch_id=batch_id,
            generation_digest=generation_digest,
        )
    finally:
        connection.close()
    if not len(reference) or not len(queries):
        raise ValueError("GPU comparison requires reference and query signatures")
    maximum = int(authority["acceleration"]["max_records_per_shard"])
    if len(reference) > maximum:
        raise ValueError(
            "GPU comparison reference exceeds the reviewed C10 shard bound"
        )
    cpu_started_ns = time.monotonic_ns()
    expected = _cpu_probe(reference, queries)
    cpu_wall_ns = time.monotonic_ns() - cpu_started_ns
    candidate_started_ns = time.monotonic_ns()
    observed, device = _gpu_probe(
        reference,
        queries,
        int(authority["acceleration"]["workgroup_size"]),
    )
    gpu_wall_ns = time.monotonic_ns() - candidate_started_ns
    import numpy as np

    mismatch_indices = np.flatnonzero(expected != observed)
    comparison = {
        "schema_version": REPORT_SCHEMA,
        "state": "equivalent" if not len(mismatch_indices) else "mismatch",
        "scope": "packed-complete-signature-exact-probe",
        "generation_digest": generation_digest,
        "canonical_backend": authority["acceleration"]["canonical_backend"],
        "candidate_backend": authority["acceleration"]["candidate_backend"],
        "publish_from": authority["acceleration"]["publish_from"],
        "reference_signatures": len(reference),
        "query_signatures": len(queries),
        "matched_queries": int(np.count_nonzero(expected != SENTINEL)),
        "mismatches": int(len(mismatch_indices)),
        "first_mismatch_indices": [int(value) for value in mismatch_indices[:20]],
        "key_words_u32": 7,
        "packed_input_bytes": int(reference.nbytes + queries.nbytes),
        "packing_cache_hit": cache_hit,
        "packing_cache": str(cache.relative_to(root)),
        "gpu_buffer_bytes": int(reference.nbytes + queries.nbytes + observed.nbytes),
        "performance": {
            "packing_wall_time_ns": packing_wall_ns,
            "cpu_packed_probe_wall_time_ns": cpu_wall_ns,
            "gpu_end_to_end_probe_wall_time_ns": gpu_wall_ns,
            "total_trial_wall_time_ns": time.monotonic_ns() - started_ns,
            "cpu_queries_per_second": (
                len(queries) * 1_000_000_000 / cpu_wall_ns if cpu_wall_ns else None
            ),
            "gpu_queries_per_second": (
                len(queries) * 1_000_000_000 / gpu_wall_ns if gpu_wall_ns else None
            ),
            "probe_speedup": cpu_wall_ns / gpu_wall_ns if gpu_wall_ns else None,
        },
        "device": device,
        "authority_sha256": authority["authority_sha256"],
    }
    _atomic_json(output, comparison)
    return comparison


def run_selected_lookup(
    project_root: str | Path,
    *,
    corpus_result: Mapping[str, object],
    output_path: str | Path,
    authority: Mapping[str, object],
    backend_status: Mapping[str, object],
) -> dict[str, object]:
    """Execute only the selected lookup backend, with fail-safe CPU fallback."""

    import numpy as np

    root = Path(project_root).expanduser().resolve()
    database = _inside(root, str(corpus_result["database_path"]), "corpus database")
    output = _inside(root, output_path, "hash lookup report")
    started_ns = time.monotonic_ns()
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        reference, queries, packing_wall_ns, cache_hit, cache = _packed_matrices(
            root,
            connection,
            batch_id=int(corpus_result["batch_id"]),
            generation_digest=str(corpus_result["generation_digest"]),
        )
    finally:
        connection.close()
    if not len(reference) or not len(queries):
        raise ValueError("hash lookup requires reference and query signatures")
    requested = str(backend_status["effective_backend"]["id"])
    requested_device = str(backend_status["effective_backend"]["device"])
    cpu_backend = next(
        row for row in backend_status["backends"] if row["device"] == "cpu"
    )
    effective = requested
    fallback = None
    lookup_started_ns = time.monotonic_ns()
    device = None
    try:
        if requested_device == "gpu":
            positions, device = _gpu_probe(
                reference,
                queries,
                int(authority["acceleration"]["workgroup_size"]),
            )
        elif requested_device == "cpu":
            positions = _cpu_probe(reference, queries)
        else:
            raise ValueError(f"unsupported hash lookup backend: {requested}")
    except Exception as error:
        if (
            not backend_status["performance"]["fallback_to_cpu"]
            or requested_device == "cpu"
        ):
            raise
        effective = str(cpu_backend["id"])
        fallback = f"{type(error).__name__}: {error}"
        lookup_started_ns = time.monotonic_ns()
        positions = _cpu_probe(reference, queries)
    lookup_wall_ns = time.monotonic_ns() - lookup_started_ns
    report = {
        "schema_version": LOOKUP_REPORT_SCHEMA,
        "state": "complete-with-fallback" if fallback else "complete",
        "generation_digest": corpus_result["generation_digest"],
        "batch_id": corpus_result["batch_id"],
        "requested_backend": requested,
        "effective_backend": effective,
        "fallback": fallback,
        "reference_signatures": len(reference),
        "query_signatures": len(queries),
        "matched_queries": int(np.count_nonzero(positions != SENTINEL)),
        "packing_cache_hit": cache_hit,
        "packing_cache": str(cache.relative_to(root)),
        "device": device,
        "performance": {
            "packing_wall_time_ns": packing_wall_ns,
            "lookup_wall_time_ns": lookup_wall_ns,
            "total_wall_time_ns": time.monotonic_ns() - started_ns,
            "queries_per_second": (
                len(queries) * 1_000_000_000 / lookup_wall_ns
                if lookup_wall_ns
                else None
            ),
        },
        "authority_sha256": authority["authority_sha256"],
        "backend_authority_sha256": backend_status["authority_sha256"],
        "performance_authority_sha256": backend_status["performance"][
            "authority_sha256"
        ],
    }
    _atomic_json(output, report)
    return report


def run_gpu_comparison(
    project_root: str | Path,
    *,
    corpus_result: Mapping[str, object],
    output_path: str | Path,
    authority: Mapping[str, object],
) -> dict[str, object]:
    """Run the optional candidate and retain failures without affecting CPU truth."""

    try:
        return compare_packed_probe(
            project_root,
            corpus_database=str(corpus_result["database_path"]),
            batch_id=int(corpus_result["batch_id"]),
            generation_digest=str(corpus_result["generation_digest"]),
            output_path=output_path,
            authority=authority,
        )
    except Exception as error:
        document = {
            "schema_version": REPORT_SCHEMA,
            "state": "candidate-failed",
            "scope": "packed-complete-signature-exact-probe",
            "generation_digest": corpus_result.get("generation_digest"),
            "canonical_backend": authority["acceleration"]["canonical_backend"],
            "candidate_backend": authority["acceleration"]["candidate_backend"],
            "publish_from": authority["acceleration"]["publish_from"],
            "error": f"{type(error).__name__}: {error}",
            "authority_sha256": authority["authority_sha256"],
        }
        root = Path(project_root).expanduser().resolve()
        _atomic_json((root / output_path).resolve(), document)
        return document
