"""Optional WGPU exact-signature probe compared with a CPU packed baseline."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
from typing import Mapping

REPORT_SCHEMA = "fidb-hash-gpu-comparison/v1"
SENTINEL = 0xFFFFFFFF


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
        scopes = {
            str(row[0]): index
            for index, row in enumerate(
                connection.execute(
                    "SELECT DISTINCT scope FROM signature ORDER BY scope"
                )
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
        packing_started_ns = time.monotonic_ns()
        reference = _matrix(connection, reference_sql, (), scopes)
        queries = _matrix(connection, query_sql, (batch_id,), scopes)
        packing_wall_ns = time.monotonic_ns() - packing_started_ns
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
