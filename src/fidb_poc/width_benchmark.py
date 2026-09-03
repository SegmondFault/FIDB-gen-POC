"""Disarmed-by-default benchmarks for the native width execution pipeline.

Benchmarks are deliberately stored outside ``artifacts/width-runs`` so they
cannot be mistaken for coverage evidence or consumed by the lane compiler.
They execute a reviewed subset of the normal width cells and retain the same
manifests, FID databases and signature ledgers for semantic comparison.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import re
import time
from typing import Callable, Iterable

from .config import Configuration
from .jvm_policy import java_options
from .timing import utc_now
from .width_run import (
    _ResourceSampler,
    _atomic_json,
    _directory_size,
    _execute_cell,
    _groups,
    _read_csv_rows,
    _seed_group_sources,
    _seed_source_cache,
    _release_pool_jvm_scratch,
    _terminate_executor,
    compile_width_run_plan,
)

BENCHMARK_SCHEMA = "fidb-width-pipeline-benchmark/v1"
SAFE_LABEL = re.compile(r"[a-z0-9][a-z0-9-]*")


def _selected_groups(
    project_root: Path,
    route_ids: tuple[str, ...],
    treatment_ids: tuple[str, ...],
    authority_id: str = "c-width-v1",
) -> tuple[dict[str, object], tuple[Configuration, ...]]:
    if not route_ids or not treatment_ids:
        raise ValueError("benchmark requires at least one route and treatment")
    if len(set(route_ids)) != len(route_ids):
        raise ValueError("benchmark route ids contain duplicates")
    if len(set(treatment_ids)) != len(treatment_ids):
        raise ValueError("benchmark treatment ids contain duplicates")
    plan = compile_width_run_plan(project_root, canary=False, authority_id=authority_id)
    available_routes = {route for route, _treatments in plan.route_treatments}
    available_treatments = {
        treatment
        for _route, treatments in plan.route_treatments
        for treatment in treatments
    }
    missing_routes = set(route_ids) - available_routes
    missing_treatments = set(treatment_ids) - available_treatments
    if missing_routes:
        raise ValueError(
            f"benchmark routes are not executable: {sorted(missing_routes)}"
        )
    if missing_treatments:
        raise ValueError(
            f"benchmark treatments are not executable: {sorted(missing_treatments)}"
        )
    selected = tuple(
        group
        for group in _groups(plan)
        if group.routes[0].id in route_ids and group.treatments[0].id in treatment_ids
    )
    expected = len(route_ids) * len(treatment_ids)
    if len(selected) != expected:
        raise ValueError(
            "benchmark selection contains inapplicable route/treatment pairs: "
            f"expected {expected}, resolved {len(selected)}"
        )
    return plan.compilation, selected


def _java_options(heap_mib: int | None, core_limit: int | None) -> str:
    """Compatibility wrapper retained for callers and focused unit tests."""

    return java_options(heap_mib, core_limit)


def width_benchmark_preview(
    project_root: str | Path,
    *,
    authority_id: str = "c-width-v1",
    route_ids: Iterable[str],
    treatment_ids: Iterable[str],
    workers: int,
    heap_mib: int | None,
    core_limit: int | None,
    build_jobs_per_cell: int = 4,
    performance_profile_id: str | None = None,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    if workers < 1 or workers > 32:
        raise ValueError("benchmark workers must be between 1 and 32")
    if build_jobs_per_cell < 1 or build_jobs_per_cell > 32:
        raise ValueError("build jobs per cell must be between 1 and 32")
    routes = tuple(route_ids)
    treatments = tuple(treatment_ids)
    compilation, groups = _selected_groups(root, routes, treatments, authority_id)
    java_options = _java_options(heap_mib, core_limit)
    return {
        "schema_version": BENCHMARK_SCHEMA,
        "state": "disarmed-preview",
        "width_id": compilation["id"],
        "fixed_recipe": compilation["fixed_recipe"],
        "compilation_digest": compilation["compilation_digest"],
        "routes": list(routes),
        "treatments": list(treatments),
        "scheduled_cells": len(groups),
        "parallel_workers": workers,
        "build_jobs_per_cell": build_jobs_per_cell,
        "performance_profile": performance_profile_id or "manual",
        "ghidra_heap_mib": heap_mib,
        "ghidra_core_limit": core_limit,
        "java_tool_options": java_options,
    }


def _execute_benchmark_cell(
    configuration: Configuration,
    group_root: str,
    verbose: bool,
    java_options: str,
    build_jobs_per_cell: int,
) -> dict[str, object]:
    if java_options:
        os.environ["JAVA_TOOL_OPTIONS"] = java_options
    else:
        os.environ.pop("JAVA_TOOL_OPTIONS", None)
    measurement = _execute_cell(
        configuration,
        group_root,
        verbose,
        build_jobs_per_cell=build_jobs_per_cell,
    )
    try:
        from java.lang import Runtime as JavaRuntime

        runtime = JavaRuntime.getRuntime()
        measurement["jvm_max_heap_bytes"] = int(runtime.maxMemory())
        measurement["jvm_committed_heap_bytes"] = int(runtime.totalMemory())
        measurement["jvm_used_heap_bytes"] = int(
            runtime.totalMemory() - runtime.freeMemory()
        )
        measurement["jvm_available_processors"] = int(runtime.availableProcessors())
    except (ImportError, RuntimeError):
        measurement["jvm_max_heap_bytes"] = None
        measurement["jvm_committed_heap_bytes"] = None
        measurement["jvm_used_heap_bytes"] = None
        measurement["jvm_available_processors"] = None
    return measurement


def _manifest_semantics(
    manifests: Iterable[Path],
) -> tuple[list[dict[str, object]], str]:
    cells: list[dict[str, object]] = []
    for manifest in manifests:
        rows = _read_csv_rows(manifest)
        if len(rows) != 1:
            raise ValueError(f"benchmark manifest must contain one cell: {manifest}")
        row = rows[0]
        cells.append(
            {
                "route_id": row["route"],
                "treatment_id": row["treatment"],
                "status": row["status"],
                "analysis_artifact_sha256": row["analysis_artifact_sha256"],
                "fid_signatures_sha256": row["fid_signatures_sha256"],
                "fid_signature_records": int(row["fid_signature_records"] or 0),
                "fid_unique_signatures": int(row["fid_unique_signatures"] or 0),
                "fid_programs": int(row["fid_programs"] or 0),
                "fid_attempted": int(row["fid_attempted"] or 0),
                "fid_added": int(row["fid_added"] or 0),
                "fid_excluded": int(row["fid_excluded"] or 0),
            }
        )
    cells.sort(key=lambda row: (str(row["route_id"]), str(row["treatment_id"])))
    payload = json.dumps(cells, sort_keys=True, separators=(",", ":")).encode()
    return cells, hashlib.sha256(payload).hexdigest()


def _stage_totals(measurements: Iterable[dict[str, object]]) -> dict[str, int]:
    result: dict[str, int] = {}
    for measurement in measurements:
        timing = measurement.get("stage_timing")
        if not isinstance(timing, dict):
            continue
        summary = timing.get("summary")
        durations = (
            summary.get("stage_duration_ns") if isinstance(summary, dict) else None
        )
        if not isinstance(durations, dict):
            continue
        for stage, duration in durations.items():
            result[str(stage)] = result.get(str(stage), 0) + int(duration)
    return dict(sorted(result.items()))


def _benchmark_root(root: Path, label: str, preview: dict[str, object]) -> Path:
    if SAFE_LABEL.fullmatch(label) is None:
        raise ValueError(
            "benchmark label must be lowercase letters, digits and hyphens"
        )
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    payload = json.dumps(preview, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(payload).hexdigest()[:12]
    parent = root / "artifacts/benchmarks/width-pipeline"
    destination = parent / f"{label}-{stamp}-{digest}"
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"benchmark destination already exists: {destination}")
    parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir()
    if destination.resolve().parent != parent.resolve():
        raise ValueError("benchmark destination escaped its managed parent")
    return destination


def execute_width_benchmark(
    project_root: str | Path,
    *,
    label: str,
    authority_id: str = "c-width-v1",
    route_ids: Iterable[str],
    treatment_ids: Iterable[str],
    workers: int,
    heap_mib: int | None,
    core_limit: int | None,
    build_jobs_per_cell: int = 4,
    performance_profile_id: str | None = None,
    progress: Callable[[str], None] | None = None,
    verbose: bool = False,
) -> tuple[dict[str, object], Path]:
    root = Path(project_root).expanduser().resolve()
    routes = tuple(route_ids)
    treatments = tuple(treatment_ids)
    preview = width_benchmark_preview(
        root,
        authority_id=authority_id,
        route_ids=routes,
        treatment_ids=treatments,
        workers=workers,
        heap_mib=heap_mib,
        core_limit=core_limit,
        build_jobs_per_cell=build_jobs_per_cell,
        performance_profile_id=performance_profile_id,
    )
    compilation, groups = _selected_groups(root, routes, treatments, authority_id)
    run_root = _benchmark_root(root, label, preview)
    _atomic_json(run_root / "benchmark-plan.json", preview)
    source_cache = _seed_source_cache(root, run_root, groups[0])
    java_options = str(preview["java_tool_options"])
    announce = progress or (lambda _message: None)
    started_at = utc_now()
    started_ns = time.monotonic_ns()
    manifests: list[Path] = []
    measurements: list[dict[str, object]] = []
    errors: list[str] = []
    scheduled: list[tuple[int, Configuration, Path]] = []
    for index, configuration in enumerate(groups, start=1):
        group_root = run_root / f"group-{index:03d}"
        group_root.mkdir()
        _seed_group_sources(configuration, group_root, source_cache)
        scheduled.append((index, configuration, group_root))
    announce(
        f"[benchmark] {len(groups)} cells; workers={workers}; "
        f"heap={heap_mib or 'ergonomic'} MiB; cores={core_limit or 'host'}"
    )
    with _ResourceSampler(run_root, filesystem_scratch=True) as sampler:
        executor = concurrent.futures.ProcessPoolExecutor(
            max_workers=workers,
            mp_context=multiprocessing.get_context("spawn"),
        )
        try:
            futures = {
                executor.submit(
                    _execute_benchmark_cell,
                    configuration,
                    str(group_root),
                    verbose,
                    java_options,
                    build_jobs_per_cell,
                ): (index, configuration, group_root)
                for index, configuration, group_root in scheduled
            }
            for completed, future in enumerate(
                concurrent.futures.as_completed(futures), start=1
            ):
                index, configuration, _group_root = futures[future]
                route = configuration.routes[0].id
                treatment = configuration.treatments[0].id
                try:
                    measurement = future.result()
                except Exception as error:
                    measurement = {
                        "route_id": route,
                        "treatment_id": treatment,
                        "wall_time_ns": 0,
                        "peak_process_rss_bytes": 0,
                        "manifest": "",
                        "pipeline_error": f"worker {type(error).__name__}: {error}",
                        "stage_timing": None,
                    }
                manifest_text = str(measurement.pop("manifest", ""))
                if manifest_text:
                    manifests.append(Path(manifest_text))
                error_text = str(measurement.get("pipeline_error", ""))
                if error_text:
                    errors.append(f"{route}/{treatment}: {error_text}")
                measurement["group"] = index
                measurements.append(measurement)
                announce(
                    f"[benchmark cell {completed}/{len(groups)}] "
                    f"{route}/{treatment} "
                    f"{int(measurement['wall_time_ns']) / 1_000_000_000:.1f}s"
                )
        except BaseException:
            _terminate_executor(executor)
            raise
        else:
            executor.shutdown(wait=True)
        jvm_scratch_cleanup = _release_pool_jvm_scratch(scheduled)
        for measurement in measurements:
            group_root = run_root / f"group-{int(measurement['group']):03d}"
            measurement["final_scratch_bytes"] = _directory_size(group_root / "work")
    semantic_cells, semantic_digest = _manifest_semantics(manifests)
    wall_time_ns = max(0, time.monotonic_ns() - started_ns)
    completed = sum(row["status"] == "complete" for row in semantic_cells)
    signature_records = sum(int(row["fid_signature_records"]) for row in semantic_cells)
    unique_signature_sum = sum(
        int(row["fid_unique_signatures"]) for row in semantic_cells
    )
    wall_hours = wall_time_ns / 3_600_000_000_000
    result: dict[str, object] = {
        **preview,
        "state": (
            "measured-complete" if completed == len(groups) else "measured-incomplete"
        ),
        "started_at_utc": started_at,
        "finished_at_utc": utc_now(),
        "wall_time_ns": wall_time_ns,
        "completed_cells": completed,
        "failed_cells": len(groups) - completed,
        "peak_process_rss_bytes": sampler.peak_rss_bytes,
        "peak_process_pss_bytes": sampler.peak_pss_bytes,
        "peak_process_uss_bytes": sampler.peak_uss_bytes,
        "peak_scratch_bytes": sampler.peak_scratch_bytes,
        "jvm_scratch_cleanup": jvm_scratch_cleanup,
        "retained_bytes": _directory_size(run_root),
        "signature_records": signature_records,
        "unique_signature_sum": unique_signature_sum,
        "signature_records_per_wall_hour": (
            signature_records / wall_hours if wall_hours else 0
        ),
        "unique_signature_sum_per_wall_hour": (
            unique_signature_sum / wall_hours if wall_hours else 0
        ),
        "semantic_digest": semantic_digest,
        "stage_duration_ns": _stage_totals(measurements),
        "measurements": sorted(measurements, key=lambda row: int(row["group"])),
        "semantic_cells": semantic_cells,
        "errors": errors,
    }
    result_path = run_root / "benchmark-result.json"
    _atomic_json(result_path, result)
    announce(f"Benchmark result: {result['state']}")
    announce(f"Benchmark evidence: {result_path}")
    return result, result_path
