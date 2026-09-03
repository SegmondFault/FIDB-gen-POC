"""Disarmed qualification harness for experimental staged schedulers."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Callable, Iterable

from .jvm_policy import java_options
from .staged_backend import (
    BACKEND_PLAN_SCHEMA,
    execute_python_staged,
    write_staged_job,
)
from .timing import utc_now
from .width_benchmark import _manifest_semantics, _selected_groups, _stage_totals
from .width_run import (
    _ResourceSampler,
    _atomic_json,
    _directory_size,
    _read_csv_rows,
    _release_pool_jvm_scratch,
    _seed_group_sources,
    _seed_source_cache,
)

BACKEND_BENCHMARK_SCHEMA = "fidb-backend-benchmark/v1"
BACKEND_COMPARISON_SCHEMA = "fidb-backend-comparison/v1"
BACKENDS = ("python-staged-v1", "rust-staged-v1")
SAFE_LABEL = re.compile(r"[a-z0-9][a-z0-9-]*")


def _python_executable() -> Path:
    """Return an absolute launcher without dereferencing a virtualenv symlink."""

    return Path(sys.executable).absolute()


def backend_benchmark_preview(
    project_root: str | Path,
    *,
    backend: str,
    route_ids: Iterable[str],
    treatment_ids: Iterable[str],
    build_workers: int,
    analysis_workers: int,
    build_jobs_per_cell: int,
    heap_mib: int | None,
    core_limit: int | None,
    authority_id: str = "c-width-v1",
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    if backend not in BACKENDS:
        raise ValueError(f"unsupported experimental backend: {backend}")
    for name, value in (
        ("build workers", build_workers),
        ("analysis workers", analysis_workers),
        ("build jobs per cell", build_jobs_per_cell),
    ):
        if value < 1 or value > 32:
            raise ValueError(f"{name} must be between 1 and 32")
    routes = tuple(route_ids)
    treatments = tuple(treatment_ids)
    compilation, groups = _selected_groups(root, routes, treatments, authority_id)
    return {
        "schema_version": BACKEND_BENCHMARK_SCHEMA,
        "state": "disarmed-preview",
        "backend": backend,
        "width_id": compilation["id"],
        "fixed_recipe": compilation["fixed_recipe"],
        "compilation_digest": compilation["compilation_digest"],
        "routes": list(routes),
        "treatments": list(treatments),
        "scheduled_cells": len(groups),
        "build_workers": build_workers,
        "analysis_workers": analysis_workers,
        "build_jobs_per_cell": build_jobs_per_cell,
        "ghidra_heap_mib": heap_mib,
        "ghidra_core_limit": core_limit,
        "java_tool_options": java_options(heap_mib, core_limit, inherited=""),
        "evidence_class": "isolated-experiment-not-width-evidence",
    }


def _benchmark_root(root: Path, label: str, preview: dict[str, object]) -> Path:
    if SAFE_LABEL.fullmatch(label) is None:
        raise ValueError("backend benchmark label must be a safe lowercase token")
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    payload = json.dumps(preview, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(payload).hexdigest()[:12]
    parent = root / "artifacts/benchmarks/backend-experiments"
    destination = parent / f"{label}-{stamp}-{digest}"
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"backend benchmark destination exists: {destination}")
    parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir()
    if destination.resolve().parent != parent.resolve():
        raise ValueError("backend benchmark destination escaped its managed parent")
    return destination


def _canonical_signature_cells(manifests: Iterable[Path]) -> list[dict[str, object]]:
    cells: list[dict[str, object]] = []
    for manifest in manifests:
        rows = _read_csv_rows(manifest)
        if len(rows) != 1:
            raise ValueError(f"backend manifest must contain one cell: {manifest}")
        row = rows[0]
        group_root = manifest.parents[2]
        signature_path = group_root / row["fid_signatures_path"]
        digest = hashlib.sha256()
        records = 0
        with signature_path.open(encoding="utf-8") as stream:
            canonical = []
            for line in stream:
                if not line.strip():
                    continue
                value = json.loads(line)
                canonical.append(
                    json.dumps(value, sort_keys=True, separators=(",", ":"))
                )
            for encoded in sorted(canonical):
                payload = encoded.encode()
                digest.update(len(payload).to_bytes(8, "big"))
                digest.update(payload)
                records += 1
        cells.append(
            {
                "route_id": row["route"],
                "treatment_id": row["treatment"],
                "status": row["status"],
                "analysis_artifact_sha256": row["analysis_artifact_sha256"],
                "fidb_sha256": row["fidb_sha256"],
                "fid_signatures_sha256": row["fid_signatures_sha256"],
                "canonical_signature_sha256": digest.hexdigest(),
                "canonical_signature_records": records,
                "fid_attempted": int(row["fid_attempted"] or 0),
                "fid_added": int(row["fid_added"] or 0),
                "fid_excluded": int(row["fid_excluded"] or 0),
            }
        )
    return sorted(cells, key=lambda row: (row["route_id"], row["treatment_id"]))


def _canonical_digest(cells: Iterable[dict[str, object]]) -> str:
    fields = (
        "route_id",
        "treatment_id",
        "status",
        "canonical_signature_sha256",
        "canonical_signature_records",
        "fid_attempted",
        "fid_added",
        "fid_excluded",
    )
    semantic_cells = [{field: cell[field] for field in fields} for cell in cells]
    payload = json.dumps(semantic_cells, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _reference_manifests(result_path: Path) -> tuple[Path, list[Path]]:
    root = result_path.resolve().parent
    manifests = sorted(root.glob("group-*/artifacts/libs/fidb_manifest.csv"))
    if not manifests:
        raise ValueError(f"reference contains no retained manifests: {root}")
    return root, manifests


def compare_backend_results(
    reference_path: str | Path, candidate_path: str | Path
) -> dict[str, object]:
    reference_result_path = Path(reference_path).expanduser().resolve()
    candidate_result_path = Path(candidate_path).expanduser().resolve()
    reference = json.loads(reference_result_path.read_text(encoding="utf-8"))
    candidate = json.loads(candidate_result_path.read_text(encoding="utf-8"))
    _reference_root, reference_manifests = _reference_manifests(reference_result_path)
    _candidate_root, candidate_manifests = _reference_manifests(candidate_result_path)
    reference_cells = _canonical_signature_cells(reference_manifests)
    candidate_cells = _canonical_signature_cells(candidate_manifests)
    reference_by_key = {
        (row["route_id"], row["treatment_id"]): row for row in reference_cells
    }
    candidate_by_key = {
        (row["route_id"], row["treatment_id"]): row for row in candidate_cells
    }
    exact_fields = (
        "status",
        "canonical_signature_sha256",
        "canonical_signature_records",
        "fid_attempted",
        "fid_added",
        "fid_excluded",
    )
    diagnostic_fields = ("fid_signatures_sha256", "fidb_sha256")
    mismatches: list[dict[str, object]] = []
    artifact_mismatches: list[dict[str, object]] = []
    diagnostic_differences: list[dict[str, object]] = []
    for key in sorted(set(reference_by_key) | set(candidate_by_key)):
        expected = reference_by_key.get(key)
        observed = candidate_by_key.get(key)
        identity = {"route_id": key[0], "treatment_id": key[1]}
        if expected is None or observed is None:
            mismatches.append(
                {
                    **identity,
                    "field": "cell",
                    "expected": expected,
                    "observed": observed,
                }
            )
            continue
        if expected["analysis_artifact_sha256"] != observed["analysis_artifact_sha256"]:
            artifact_mismatches.append(
                {
                    **identity,
                    "expected": expected["analysis_artifact_sha256"],
                    "observed": observed["analysis_artifact_sha256"],
                }
            )
        for field in exact_fields:
            if expected[field] != observed[field]:
                mismatches.append(
                    {
                        **identity,
                        "field": field,
                        "expected": expected[field],
                        "observed": observed[field],
                    }
                )
        for field in diagnostic_fields:
            if expected[field] != observed[field]:
                diagnostic_differences.append(
                    {
                        **identity,
                        "field": field,
                        "expected": expected[field],
                        "observed": observed[field],
                    }
                )
    authority_fields = (
        "width_id",
        "fixed_recipe",
        "compilation_digest",
        "routes",
        "treatments",
    )
    authority_match = all(
        reference.get(field) == candidate.get(field) for field in authority_fields
    )
    return {
        "schema_version": BACKEND_COMPARISON_SCHEMA,
        "reference": str(reference_result_path),
        "candidate": str(candidate_result_path),
        "authority_match": authority_match,
        "compared_cells": len(set(reference_by_key) | set(candidate_by_key)),
        "semantic_match": authority_match and not mismatches,
        "mismatches": mismatches,
        "artifact_reproducibility_match": not artifact_mismatches,
        "artifact_mismatches": artifact_mismatches,
        "container_or_order_differences": diagnostic_differences,
        "reference_canonical_digest": _canonical_digest(reference_cells),
        "candidate_canonical_digest": _canonical_digest(candidate_cells),
    }


def _execute_rust(
    rust_binary: Path,
    plan_path: Path,
    result_path: Path,
    *,
    timeout_seconds: int,
) -> dict[str, object]:
    if not rust_binary.is_file() or not os.access(rust_binary, os.X_OK):
        raise ValueError(f"Rust staged binary is unavailable: {rust_binary}")
    completed = subprocess.run(
        [str(rust_binary), str(plan_path), str(result_path)],
        cwd=plan_path.parents[2],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_seconds,
        check=False,
    )
    if not result_path.is_file():
        raise PipelineError(
            f"Rust staged backend produced no result (exit {completed.returncode}): "
            f"{completed.stderr.strip()}"
        )
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["launcher_returncode"] = completed.returncode
    result["launcher_stdout"] = completed.stdout
    result["launcher_stderr"] = completed.stderr
    return result


def execute_backend_benchmark(
    project_root: str | Path,
    *,
    label: str,
    backend: str,
    route_ids: Iterable[str],
    treatment_ids: Iterable[str],
    build_workers: int,
    analysis_workers: int,
    build_jobs_per_cell: int,
    heap_mib: int | None,
    core_limit: int | None,
    authority_id: str = "c-width-v1",
    rust_binary: str | Path | None = None,
    reference_path: str | Path | None = None,
    timeout_seconds: int = 14_400,
    progress: Callable[[str], None] | None = None,
    verbose: bool = False,
) -> tuple[dict[str, object], Path]:
    root = Path(project_root).expanduser().resolve()
    routes = tuple(route_ids)
    treatments = tuple(treatment_ids)
    preview = backend_benchmark_preview(
        root,
        backend=backend,
        route_ids=routes,
        treatment_ids=treatments,
        build_workers=build_workers,
        analysis_workers=analysis_workers,
        build_jobs_per_cell=build_jobs_per_cell,
        heap_mib=heap_mib,
        core_limit=core_limit,
        authority_id=authority_id,
    )
    _compilation, groups = _selected_groups(root, routes, treatments, authority_id)
    run_root = _benchmark_root(root, label, preview)
    _atomic_json(run_root / "benchmark-plan.json", preview)
    source_cache = _seed_source_cache(root, run_root, groups[0])
    scheduled = []
    jobs = []
    for index, configuration in enumerate(groups, start=1):
        group_root = run_root / f"group-{index:03d}"
        group_root.mkdir()
        _seed_group_sources(configuration, group_root, source_cache)
        job_path = group_root / "jobs/job.json"
        write_staged_job(configuration, group_root, job_path, index=index)
        scheduled.append((index, configuration, group_root))
        jobs.append(job_path)
    announce = progress or (lambda _message: None)
    announce(
        f"[backend benchmark] {backend}; cells={len(jobs)}; "
        f"build-workers={build_workers}; analysis-workers={analysis_workers}"
    )
    started_at = utc_now()
    started_ns = time.monotonic_ns()
    with _ResourceSampler(run_root, filesystem_scratch=True) as sampler:
        if backend == "python-staged-v1":
            execution = execute_python_staged(
                jobs,
                build_workers=build_workers,
                analysis_workers=analysis_workers,
                build_jobs_per_cell=build_jobs_per_cell,
                java_options=str(preview["java_tool_options"]),
                verbose=verbose,
                progress=announce,
            )
        else:
            if rust_binary is None:
                raise ValueError("rust-staged-v1 requires --rust-binary")
            rust_result = run_root / "rust-execution-result.json"
            rust_plan = {
                "schema_version": BACKEND_PLAN_SCHEMA,
                "project_root": str(root),
                # Preserve the virtual-environment launcher rather than
                # resolving its symlink to the system interpreter.
                "python": str(_python_executable()),
                "worker_module": "fidb_poc.staged_worker",
                "build_workers": build_workers,
                "analysis_workers": analysis_workers,
                "build_jobs_per_cell": build_jobs_per_cell,
                "java_options": preview["java_tool_options"],
                "verbose": verbose,
                "jobs": [
                    {"index": index, "job_path": str(path)}
                    for index, path in enumerate(jobs, start=1)
                ],
            }
            rust_plan_path = run_root / "rust-execution-plan.json"
            _atomic_json(rust_plan_path, rust_plan)
            execution = _execute_rust(
                Path(rust_binary).expanduser().resolve(),
                rust_plan_path,
                rust_result,
                timeout_seconds=timeout_seconds,
            )
    cleanup = _release_pool_jvm_scratch(scheduled)
    manifests = [
        Path(str(row["manifest"]))
        for row in execution.get("analysis_results", [])
        if row.get("manifest")
    ]
    semantic_cells, semantic_digest = _manifest_semantics(manifests)
    canonical_cells = _canonical_signature_cells(manifests)
    errors = list(execution.get("errors", []))
    completed = sum(row["status"] == "complete" for row in semantic_cells)
    measurements = [
        *execution.get("build_results", []),
        *execution.get("analysis_results", []),
    ]
    result = {
        **preview,
        "state": (
            "measured-complete"
            if completed == len(jobs) and not errors
            else "measured-failed"
        ),
        "started_at_utc": started_at,
        "finished_at_utc": utc_now(),
        "wall_time_ns": max(0, time.monotonic_ns() - started_ns),
        "backend_wall_time_ns": execution.get("wall_time_ns"),
        "completed_cells": completed,
        "failed_cells": len(jobs) - completed,
        "peak_process_rss_bytes": sampler.peak_rss_bytes,
        "peak_process_pss_bytes": sampler.peak_pss_bytes,
        "peak_process_uss_bytes": sampler.peak_uss_bytes,
        "peak_scratch_bytes": sampler.peak_scratch_bytes,
        "retained_bytes": _directory_size(run_root),
        "jvm_scratch_cleanup": cleanup,
        "semantic_cells": semantic_cells,
        "semantic_digest": semantic_digest,
        "canonical_signature_cells": canonical_cells,
        "canonical_signature_digest": _canonical_digest(canonical_cells),
        "build_measurements": execution.get("build_results", []),
        "analysis_measurements": execution.get("analysis_results", []),
        "stage_duration_ns": _stage_totals(measurements),
        "errors": errors,
        "launcher": {
            key: execution[key]
            for key in (
                "launcher_returncode",
                "launcher_stdout",
                "launcher_stderr",
            )
            if key in execution
        },
        "diagnostics": execution.get("diagnostics", []),
    }
    result_path = run_root / "benchmark-result.json"
    _atomic_json(result_path, result)
    if reference_path is not None and result["state"] == "measured-complete":
        comparison = compare_backend_results(reference_path, result_path)
        _atomic_json(run_root / "comparison.json", comparison)
        result["reference_comparison"] = comparison
        _atomic_json(result_path, result)
    announce(f"Backend benchmark result: {result_path}")
    return result, result_path
