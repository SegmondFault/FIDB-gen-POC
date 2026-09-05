"""Experimental split-stage execution backend.

The production width executor deliberately remains in :mod:`width_run`.  This
module exposes the smallest useful experimental boundary: compilation happens
without a JVM, while analysis happens in a bounded process pool whose workers
reuse their embedded Ghidra JVM.  State crossing that boundary is explicit,
JSON encoded and digest sealed so a scheduler written in another language does
not need to reproduce project authority resolution.
"""

from __future__ import annotations

import concurrent.futures
from dataclasses import asdict, fields
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import subprocess
import time
from typing import Callable, Iterable

from .adapters import AdapterError, detect_project
from .config import BuildInput, Configuration, Library, Route, Treatment
from .pipeline import (
    BuildRecord,
    PipelineError,
    _base_record,
    _recreate_directory,
    build_library,
    download_library,
    extract_source,
    populate_fidbs,
    prepare_build_inputs,
    write_manifest,
)
from .timing import TimingRecorder, utc_now
from .width_run import (
    _ResourceSampler,
    _directory_size,
    _release_cell_scratch,
)

STAGED_JOB_SCHEMA = "fidb-staged-job/v1"
STAGED_BUILD_SCHEMA = "fidb-staged-build/v1"
STAGED_RESULT_SCHEMA = "fidb-staged-cell-result/v1"
BACKEND_PLAN_SCHEMA = "fidb-staged-backend-plan/v1"


def _json_digest(document: object) -> str:
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _atomic_json(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _configuration_document(configuration: Configuration) -> dict[str, object]:
    return {
        "libraries": [asdict(item) for item in configuration.libraries],
        "routes": [asdict(item) for item in configuration.routes],
        "treatments": [asdict(item) for item in configuration.treatments],
        "profiles": {
            key: list(value) for key, value in sorted(configuration.profiles.items())
        },
    }


def _tuple_fields(cls: type[object]) -> set[str]:
    # All tuple-valued authority fields have tuple defaults or annotations.  A
    # fixed allowlist is clearer at this trust boundary than generic coercion.
    if cls is Library:
        return {
            "project_markers",
            "allowed_build_systems",
            "static_archives",
        }
    if cls is Route:
        return {
            "compiler",
            "archiver",
            "ranlib",
            "compiler_flags",
            "object_file_markers",
            "linked_file_markers",
            "compiler_version_markers",
        }
    if cls is Treatment:
        return {
            "remove_flags",
            "append_flags",
            "supported_routes",
            "factor_values",
            "factor_variants",
        }
    if cls is BuildInput:
        return set()
    raise TypeError(f"unsupported staged authority class: {cls!r}")


def _authority_item(cls, row: object, context: str):
    if not isinstance(row, dict):
        raise ValueError(f"{context} must be an object")
    expected = {field.name for field in fields(cls)}
    unknown = set(row) - expected
    if unknown:
        raise ValueError(f"{context} contains unknown fields: {sorted(unknown)}")
    # Dataclass constructors provide defaults for optional fields.  Required
    # field errors remain explicit without attempting to invoke default_factory.
    values = dict(row)
    if cls is Library and "build_inputs" in values:
        build_inputs = values["build_inputs"]
        if not isinstance(build_inputs, list):
            raise ValueError(f"{context}.build_inputs must be an array")
        values["build_inputs"] = tuple(
            _authority_item(BuildInput, item, f"{context}.build_inputs[{index}]")
            for index, item in enumerate(build_inputs)
        )
    for name in _tuple_fields(cls):
        if name in values:
            value = values[name]
            if not isinstance(value, list):
                raise ValueError(f"{context}.{name} must be an array")
            if name == "factor_values":
                values[name] = tuple(tuple(pair) for pair in value)
            else:
                values[name] = tuple(value)
    try:
        return cls(**values)
    except TypeError as error:
        raise ValueError(f"{context} is incomplete: {error}") from error


def configuration_from_document(document: object) -> Configuration:
    if not isinstance(document, dict):
        raise ValueError("staged configuration must be an object")
    if set(document) != {"libraries", "routes", "treatments", "profiles"}:
        raise ValueError("staged configuration fields are not canonical")
    libraries = document["libraries"]
    routes = document["routes"]
    treatments = document["treatments"]
    profiles = document["profiles"]
    if not isinstance(libraries, list) or not isinstance(routes, list):
        raise ValueError("staged libraries and routes must be arrays")
    if not isinstance(treatments, list) or not isinstance(profiles, dict):
        raise ValueError("staged treatments/profiles have invalid types")
    if any(not isinstance(value, list) for value in profiles.values()):
        raise ValueError("staged profile values must be arrays")
    return Configuration(
        libraries=tuple(
            _authority_item(Library, row, f"libraries[{index}]")
            for index, row in enumerate(libraries)
        ),
        routes=tuple(
            _authority_item(Route, row, f"routes[{index}]")
            for index, row in enumerate(routes)
        ),
        treatments=tuple(
            _authority_item(Treatment, row, f"treatments[{index}]")
            for index, row in enumerate(treatments)
        ),
        profiles={
            str(key): tuple(value)
            for key, value in profiles.items()
            if isinstance(value, list)
        },
    )


def write_staged_job(
    configuration: Configuration,
    group_root: Path,
    destination: Path,
    *,
    index: int,
) -> dict[str, object]:
    if index < 1:
        raise ValueError("staged job index must be positive")
    if (
        len(configuration.libraries) != 1
        or len(configuration.routes) != 1
        or len(configuration.treatments) != 1
    ):
        raise ValueError("a staged job must contain exactly one width cell")
    authority = _configuration_document(configuration)
    document = {
        "schema_version": STAGED_JOB_SCHEMA,
        "index": index,
        "cell_id": (
            f"{configuration.libraries[0].identifier}/"
            f"{configuration.routes[0].id}/"
            f"{configuration.treatments[0].id}"
        ),
        "group_root": str(group_root.resolve()),
        "configuration": authority,
        "configuration_sha256": _json_digest(authority),
    }
    _atomic_json(destination, document)
    return document


def load_staged_job(path: str | Path) -> tuple[dict[str, object], Configuration, Path]:
    job_path = Path(path).expanduser().resolve()
    document = json.loads(job_path.read_text(encoding="utf-8"))
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != STAGED_JOB_SCHEMA
    ):
        raise ValueError("unsupported staged job schema")
    authority = document.get("configuration")
    if document.get("configuration_sha256") != _json_digest(authority):
        raise ValueError("staged job configuration digest mismatch")
    configuration = configuration_from_document(authority)
    group_root = Path(str(document.get("group_root", ""))).resolve()
    if not group_root.is_dir() or job_path.parent.parent != group_root.resolve():
        raise ValueError("staged job group root is missing or inconsistent")
    expected_cell = (
        f"{configuration.libraries[0].identifier}/"
        f"{configuration.routes[0].id}/"
        f"{configuration.treatments[0].id}"
    )
    if document.get("cell_id") != expected_cell:
        raise ValueError("staged job cell identity mismatch")
    return document, configuration, group_root


def _stage_layout(group_root: Path, *, build: bool) -> None:
    work = group_root / "work"
    artifacts = group_root / "artifacts/libs"
    downloads = work / "downloads"
    if not downloads.is_dir():
        raise PipelineError(f"staged source cache is unavailable: {downloads}")
    work.mkdir(parents=True, exist_ok=True)
    artifacts.mkdir(parents=True, exist_ok=True)
    if build:
        for path in (work / "sources", work / "builds", work / "logs"):
            _recreate_directory(path)
        for path in (
            work / "ghidra",
            artifacts / "fidb",
            artifacts / "fid-signatures",
        ):
            _recreate_directory(path)
        (artifacts / "fidb_manifest.csv").unlink(missing_ok=True)
    else:
        # Analysis may be retried without touching compiler outputs.
        _recreate_directory(work / "ghidra")
        _recreate_directory(artifacts / "fidb")
        _recreate_directory(artifacts / "fid-signatures")
        (artifacts / "fidb_manifest.csv").unlink(missing_ok=True)


def execute_build_stage(
    configuration: Configuration,
    group_root: Path,
    *,
    verbose: bool = False,
    build_jobs_per_cell: int = 4,
    shared_downloads: Path | None = None,
) -> dict[str, object]:
    """Compile one staged cell without importing or starting Ghidra."""

    if build_jobs_per_cell < 1 or build_jobs_per_cell > 32:
        raise ValueError("build jobs per cell must be between 1 and 32")
    if len(configuration.libraries) != 1:
        raise ValueError("staged build requires one library")
    route = configuration.routes[0]
    treatment = configuration.treatments[0]
    library = configuration.libraries[0]
    _stage_layout(group_root, build=True)
    started_at = utc_now()
    started_ns = time.monotonic_ns()
    timing = TimingRecorder()
    state_path = group_root / "work/staged-build.json"
    pipeline_error = ""
    with _ResourceSampler(group_root) as sampler:
        try:
            downloads = shared_downloads or group_root / "work/downloads"
            archive = download_library(
                library,
                downloads,
                content_addressed=shared_downloads is not None,
                timing=timing.span,
            )
            source_root = extract_source(
                library,
                archive,
                group_root / "work/sources",
                timing=timing.span,
                verified=True,
            )
            build_inputs = prepare_build_inputs(
                library,
                downloads,
                group_root / "work/sources/build-inputs",
                content_addressed=shared_downloads is not None,
                timing=timing.span,
            )
            try:
                detection = detect_project(library, source_root)
            except AdapterError as error:
                raise PipelineError(str(error)) from error
            try:
                record, objects = build_library(
                    library,
                    route,
                    treatment,
                    detection,
                    source_root,
                    group_root / "work",
                    group_root / "work/logs",
                    verbose=verbose,
                    build_inputs=build_inputs,
                    build_jobs_per_cell=build_jobs_per_cell,
                    timing=timing.span,
                    skipped=timing.skip,
                )
            except (
                AdapterError,
                OSError,
                PipelineError,
                subprocess.SubprocessError,
            ) as error:
                record = _base_record(library, route, treatment, detection)
                record.status = "build_failed"
                record.error = str(error)
                objects = []
            state = {
                "schema_version": STAGED_BUILD_SCHEMA,
                "configuration_sha256": _json_digest(
                    _configuration_document(configuration)
                ),
                "record": asdict(record),
                "objects": [
                    str(path.resolve().relative_to(group_root.resolve()))
                    for path in objects
                ],
            }
            state["state_sha256"] = _json_digest(state)
            _atomic_json(state_path, state)
        except (OSError, ValueError, PipelineError) as error:
            pipeline_error = str(error)
    return {
        "schema_version": STAGED_RESULT_SCHEMA,
        "stage": "build",
        "route_id": route.id,
        "treatment_id": treatment.id,
        "started_at_utc": started_at,
        "finished_at_utc": utc_now(),
        "wall_time_ns": max(0, time.monotonic_ns() - started_ns),
        "peak_process_rss_bytes": sampler.peak_rss_bytes,
        "peak_process_pss_bytes": sampler.peak_pss_bytes,
        "peak_process_uss_bytes": sampler.peak_uss_bytes,
        "peak_scratch_bytes": sampler.peak_scratch_bytes,
        "resource_samples": sampler.samples,
        "stage_timing": timing.document(),
        "state_path": str(state_path) if state_path.is_file() else "",
        "pipeline_error": pipeline_error,
    }


def _load_build_state(
    configuration: Configuration, group_root: Path
) -> tuple[BuildRecord, list[Path]]:
    path = group_root / "work/staged-build.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema_version") != STAGED_BUILD_SCHEMA:
        raise ValueError("unsupported staged build schema")
    sealed = dict(document)
    observed = sealed.pop("state_sha256", "")
    if observed != _json_digest(sealed):
        raise ValueError("staged build state digest mismatch")
    if sealed.get("configuration_sha256") != _json_digest(
        _configuration_document(configuration)
    ):
        raise ValueError("staged build authority digest mismatch")
    record_row = sealed.get("record")
    if not isinstance(record_row, dict):
        raise ValueError("staged build record is invalid")
    if set(record_row) != {field.name for field in fields(BuildRecord)}:
        raise ValueError("staged build record fields are not canonical")
    record = BuildRecord(**record_row)
    object_rows = sealed.get("objects")
    if not isinstance(object_rows, list):
        raise ValueError("staged build object list is invalid")
    objects = []
    for row in object_rows:
        candidate = (group_root / str(row)).resolve()
        try:
            candidate.relative_to(group_root.resolve())
        except ValueError as error:
            raise ValueError("staged object escaped its group root") from error
        if not candidate.is_file() or candidate.is_symlink():
            raise ValueError(f"staged object is unavailable: {candidate}")
        objects.append(candidate)
    if record.status == "built" and not objects:
        raise ValueError("successful staged build has no objects")
    return record, objects


def execute_analysis_stage(
    configuration: Configuration,
    group_root: Path,
    *,
    verbose: bool = False,
) -> dict[str, object]:
    """Analyze one prepared cell; callers provide a reusable process/JVM."""

    route = configuration.routes[0]
    treatment = configuration.treatments[0]
    library = configuration.libraries[0]
    _stage_layout(group_root, build=False)
    started_at = utc_now()
    started_ns = time.monotonic_ns()
    timing = TimingRecorder()
    manifest = group_root / "artifacts/libs/fidb_manifest.csv"
    pipeline_error = ""
    with _ResourceSampler(group_root) as sampler:
        try:
            record, objects = _load_build_state(configuration, group_root)
            key = (library.identifier, route.id, treatment.id)
            records = {key: record}
            object_sets = {key: objects}
            populate_fidbs(
                configuration,
                group_root,
                records,
                object_sets,
                verbose=verbose,
                timing=timing.span,
            )
            write_manifest((record,), manifest)
            if record.status != "complete":
                raise PipelineError(
                    f"{library.identifier}/{route.id}/{treatment.id}="
                    f"{record.status}: {record.error}"
                )
        except (OSError, ValueError, PipelineError) as error:
            pipeline_error = str(error)
    if manifest.is_file() and not pipeline_error:
        _release_cell_scratch(group_root)
    result = {
        "schema_version": STAGED_RESULT_SCHEMA,
        "stage": "analysis",
        "route_id": route.id,
        "treatment_id": treatment.id,
        "started_at_utc": started_at,
        "finished_at_utc": utc_now(),
        "wall_time_ns": max(0, time.monotonic_ns() - started_ns),
        "peak_process_rss_bytes": sampler.peak_rss_bytes,
        "peak_process_pss_bytes": sampler.peak_pss_bytes,
        "peak_process_uss_bytes": sampler.peak_uss_bytes,
        "peak_scratch_bytes": sampler.peak_scratch_bytes,
        "resource_samples": sampler.samples,
        "stage_timing": timing.document(),
        "manifest": str(manifest) if manifest.is_file() else "",
        "pipeline_error": pipeline_error,
    }
    try:
        from java.lang import Runtime as JavaRuntime

        runtime = JavaRuntime.getRuntime()
        result.update(
            {
                "jvm_max_heap_bytes": int(runtime.maxMemory()),
                "jvm_committed_heap_bytes": int(runtime.totalMemory()),
                "jvm_used_heap_bytes": int(
                    runtime.totalMemory() - runtime.freeMemory()
                ),
                "jvm_available_processors": int(runtime.availableProcessors()),
            }
        )
    except (ImportError, RuntimeError):
        result.update(
            {
                "jvm_max_heap_bytes": None,
                "jvm_committed_heap_bytes": None,
                "jvm_used_heap_bytes": None,
                "jvm_available_processors": None,
            }
        )
    return result


def execute_build_job(
    job_path: str | Path, *, verbose: bool = False, build_jobs_per_cell: int = 4
) -> dict[str, object]:
    document, configuration, group_root = load_staged_job(job_path)
    result = execute_build_stage(
        configuration,
        group_root,
        verbose=verbose,
        build_jobs_per_cell=build_jobs_per_cell,
    )
    result["index"] = int(document["index"])
    result["job_path"] = str(Path(job_path).resolve())
    return result


def execute_analysis_job(
    job_path: str | Path,
    *,
    verbose: bool = False,
    java_options: str | None = None,
) -> dict[str, object]:
    if java_options is not None:
        if java_options:
            os.environ["JAVA_TOOL_OPTIONS"] = java_options
        else:
            os.environ.pop("JAVA_TOOL_OPTIONS", None)
    document, configuration, group_root = load_staged_job(job_path)
    result = execute_analysis_stage(configuration, group_root, verbose=verbose)
    result["index"] = int(document["index"])
    result["job_path"] = str(Path(job_path).resolve())
    return result


def execute_python_staged(
    job_paths: Iterable[Path],
    *,
    build_workers: int,
    analysis_workers: int,
    build_jobs_per_cell: int,
    java_options: str,
    verbose: bool = False,
    progress: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Stream process-scheduled builds into a reusable Ghidra process pool.

    Source extraction is Python-heavy enough that a thread pool serializes on
    the GIL under wide OpenSSL builds.  Separate spawned build processes keep
    that stage independent while still guaranteeing that only analysis-pool
    processes start a JVM.
    """

    if build_workers < 1 or analysis_workers < 1:
        raise ValueError("staged worker counts must be positive")
    announce = progress or (lambda _message: None)
    jobs = tuple(Path(path).resolve() for path in job_paths)
    started_ns = time.monotonic_ns()
    build_results: list[dict[str, object]] = []
    analysis_results: list[dict[str, object]] = []
    errors: list[str] = []
    with (
        concurrent.futures.ProcessPoolExecutor(
            max_workers=build_workers,
            mp_context=multiprocessing.get_context("spawn"),
        ) as build_pool,
        concurrent.futures.ProcessPoolExecutor(
            max_workers=analysis_workers,
            mp_context=multiprocessing.get_context("spawn"),
        ) as analysis_pool,
    ):
        build_futures = {
            build_pool.submit(
                execute_build_job,
                path,
                verbose=verbose,
                build_jobs_per_cell=build_jobs_per_cell,
            ): path
            for path in jobs
        }
        analysis_futures: dict[concurrent.futures.Future, Path] = {}
        build_pool_stopped = False
        while build_futures or analysis_futures:
            candidates = set(build_futures) | set(analysis_futures)
            done, _pending = concurrent.futures.wait(
                candidates, return_when=concurrent.futures.FIRST_COMPLETED
            )
            for future in done:
                if future in build_futures:
                    path = build_futures.pop(future)
                    try:
                        result = future.result()
                    except Exception as error:  # process boundary evidence
                        errors.append(f"build {path}: {type(error).__name__}: {error}")
                        continue
                    build_results.append(result)
                    announce(
                        f"[python staged build {len(build_results)}/{len(jobs)}] "
                        f"{result['route_id']}/{result['treatment_id']}"
                    )
                    if result["state_path"]:
                        analysis_future = analysis_pool.submit(
                            execute_analysis_job,
                            path,
                            verbose=verbose,
                            java_options=java_options,
                        )
                        analysis_futures[analysis_future] = path
                    else:
                        errors.append(
                            f"build {path}: {result['pipeline_error'] or 'no state'}"
                        )
                else:
                    path = analysis_futures.pop(future)
                    try:
                        result = future.result()
                    except Exception as error:  # process boundary evidence
                        errors.append(
                            f"analysis {path}: {type(error).__name__}: {error}"
                        )
                        continue
                    analysis_results.append(result)
                    announce(
                        f"[python staged analysis {len(analysis_results)}/{len(jobs)}] "
                        f"{result['route_id']}/{result['treatment_id']}"
                    )
                    if result["pipeline_error"]:
                        errors.append(f"analysis {path}: {result['pipeline_error']}")
            if not build_futures and not build_pool_stopped:
                # Do not retain idle Python build processes for the much longer
                # Ghidra-analysis tail.
                build_pool.shutdown(wait=True)
                build_pool_stopped = True
    return {
        "backend": "python-staged-v1",
        "wall_time_ns": max(0, time.monotonic_ns() - started_ns),
        "build_results": sorted(build_results, key=lambda row: int(row["index"])),
        "analysis_results": sorted(analysis_results, key=lambda row: int(row["index"])),
        "errors": errors,
    }
