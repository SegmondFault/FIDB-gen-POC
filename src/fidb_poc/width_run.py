"""Execute and measure an applicability-compiled C width campaign."""

from __future__ import annotations

import csv
import concurrent.futures
import gzip
import hashlib
import json
import multiprocessing
import os
import re
import shutil
import threading
import time
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Iterable

from .c_width import compile_c_width, materialize_width_configuration
from .config import Configuration
from .hash_coverage import analyze_signature_coverage
from .jvm_policy import DEFAULT_WIDTH_GHIDRA_HEAP_MIB, java_options
from .toolchain_packs import resolve_toolchain_profile
from .pipeline import PipelineError, download_library, execute
from .timing import TimingRecorder, utc_now

WIDTH_RUN_SCHEMA = "fidb-width-run/v1"
SAFE_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")
MANIFEST_FIELD_LIMIT = 16 * 1024 * 1024


@dataclass(frozen=True)
class WidthRunPlan:
    compilation: dict[str, object]
    configuration: Configuration
    route_treatments: tuple[tuple[str, tuple[str, ...]], ...]
    replays: int
    mode: str

    @property
    def cell_count(self) -> int:
        return sum(len(treatments) for _route, treatments in self.route_treatments)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _directory_size(path: Path, seen: set[tuple[int, int]] | None = None) -> int:
    total = 0
    observed = seen if seen is not None else set()
    if not path.exists():
        return total
    for parent, _directories, files in os.walk(path):
        for name in files:
            candidate = Path(parent) / name
            try:
                metadata = candidate.stat(follow_symlinks=False)
            except FileNotFoundError:
                continue
            identity = (metadata.st_dev, metadata.st_ino)
            if identity in observed:
                continue
            observed.add(identity)
            total += metadata.st_size
    return total


def _pid_rss_bytes(pid: int) -> int:
    try:
        for line in (
            Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines()
        ):
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def _process_tree_pids(root_pid: int) -> set[int]:
    pending = [root_pid]
    observed: set[int] = set()
    while pending:
        pid = pending.pop()
        if pid in observed:
            continue
        observed.add(pid)
        try:
            children = Path(f"/proc/{pid}/task/{pid}/children").read_text(
                encoding="utf-8"
            )
            pending.extend(int(value) for value in children.split())
        except (FileNotFoundError, OSError, ValueError):
            continue
    return observed


def _rss_bytes() -> int:
    return sum(_pid_rss_bytes(pid) for pid in _process_tree_pids(os.getpid()))


def _scratch_size(replay_root: Path) -> int:
    grouped = list(replay_root.glob("group-*/work"))
    direct = replay_root / "work"
    if direct.is_dir():
        grouped.append(direct)
    observed: set[tuple[int, int]] = set()
    return sum(_directory_size(path, observed) for path in grouped)


class _ResourceSampler:
    def __init__(
        self,
        run_root: Path,
        interval_seconds: float = 5.0,
        *,
        filesystem_scratch: bool = False,
    ):
        self.run_root = run_root
        self.interval_seconds = interval_seconds
        self.filesystem_scratch = filesystem_scratch
        self.peak_scratch_bytes = 0
        self.peak_rss_bytes = 0
        self.samples = 0
        self._available_at_start = self._available_bytes()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._sample, daemon=True)

    def _available_bytes(self) -> int:
        try:
            values = os.statvfs(self.run_root)
            return values.f_bavail * values.f_frsize
        except OSError:
            return 0

    def _measure(self) -> None:
        if self.filesystem_scratch:
            available = self._available_bytes()
            scratch = max(0, self._available_at_start - available)
        else:
            scratch = _scratch_size(self.run_root)
        self.peak_scratch_bytes = max(self.peak_scratch_bytes, scratch)
        self.peak_rss_bytes = max(self.peak_rss_bytes, _rss_bytes())
        self.samples += 1

    def _sample(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            self._measure()

    def __enter__(self) -> _ResourceSampler:
        self._measure()
        self._thread.start()
        return self

    def __exit__(self, *_error: object) -> None:
        self._stop.set()
        self._thread.join(timeout=max(2.0, self.interval_seconds * 2))
        self._measure()


def compile_width_run_plan(
    project_root: str | Path,
    *,
    canary: bool,
    authority_id: str = "c-width-v1",
) -> WidthRunPlan:
    root = Path(project_root).expanduser().resolve()
    compilation = compile_c_width(root, authority_id)
    fixed_recipe = str(compilation["fixed_recipe"])
    route_plan = resolve_toolchain_profile(root, str(compilation["toolchain_profile"]))
    configuration = materialize_width_configuration(root, fixed_recipe, route_plan)
    executable = [
        row for row in compilation["applicability"] if row["state"] == "executable"
    ]
    if canary:
        executable = [row for row in executable if row["treatment_id"] == "baseline_o2"]
    route_order = [str(row["id"]) for row in compilation["routes"]]
    treatment_order = [treatment.id for treatment in configuration.treatments]
    by_route: dict[str, set[str]] = {route: set() for route in route_order}
    for row in executable:
        by_route[str(row["route_id"])].add(str(row["treatment_id"]))
    route_treatments = tuple(
        (
            route,
            tuple(
                treatment
                for treatment in treatment_order
                if treatment in by_route[route]
            ),
        )
        for route in route_order
        if by_route[route]
    )
    if not route_treatments:
        raise ValueError("compiled width contains no executable cells")
    selected_routes = {route for route, _treatments in route_treatments}
    selected_treatments = {
        treatment for _route, treatments in route_treatments for treatment in treatments
    }
    configuration = replace(
        configuration,
        routes=tuple(
            route for route in configuration.routes if route.id in selected_routes
        ),
        treatments=tuple(
            treatment
            for treatment in configuration.treatments
            if treatment.id in selected_treatments
        ),
    )
    return WidthRunPlan(
        compilation=compilation,
        configuration=configuration,
        route_treatments=route_treatments,
        replays=1 if canary else int(compilation["summary"]["selected_replay"]),
        mode="canary" if canary else "full",
    )


def _groups(plan: WidthRunPlan) -> tuple[Configuration, ...]:
    """Materialize one isolated configuration per applicable width cell."""
    route_by_id = {route.id: route for route in plan.configuration.routes}
    treatment_by_id = {
        treatment.id: treatment for treatment in plan.configuration.treatments
    }
    return tuple(
        replace(
            plan.configuration,
            routes=(route_by_id[route],),
            treatments=(treatment_by_id[treatment],),
        )
        for route, treatments in plan.route_treatments
        for treatment in treatments
    )


def default_width_workers(
    *,
    heap_mib: int | None = DEFAULT_WIDTH_GHIDRA_HEAP_MIB,
    logical_cpus: int | None = None,
    available_memory_bytes: int | None = None,
) -> int:
    """Choose the measured throughput knee while preserving memory headroom."""

    cpus = max(1, logical_cpus if logical_cpus is not None else (os.cpu_count() or 1))
    cpu_bound = max(1, (cpus * 5 + 7) // 8)
    memory_bytes = available_memory_bytes
    if memory_bytes is None:
        memory_bytes = 0
        try:
            for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
                if line.startswith("MemAvailable:"):
                    memory_bytes = int(line.split()[1]) * 1024
                    break
        except (OSError, ValueError, IndexError):
            pass
    per_worker_bytes = (
        8 * 1024**3 if heap_mib is None else max(3 * 1024**3, int(heap_mib) * 1024**2)
    )
    reserve_bytes = 6 * 1024**3
    memory_bound = (
        max(1, max(0, memory_bytes - reserve_bytes) // per_worker_bytes)
        if memory_bytes
        else 1
    )
    return min(20, cpu_bound, memory_bound)


def width_run_preview(
    plan: WidthRunPlan,
    *,
    workers: int | None = None,
    heap_mib: int | None = DEFAULT_WIDTH_GHIDRA_HEAP_MIB,
    core_limit: int | None = None,
) -> dict[str, object]:
    parallel_workers = (
        default_width_workers(heap_mib=heap_mib) if workers is None else workers
    )
    if parallel_workers < 1 or parallel_workers > 32:
        raise ValueError("width workers must be between 1 and 32")
    configured_java_options = java_options(heap_mib, core_limit, inherited="")
    cells = [
        {
            "route_id": route,
            "treatment_id": treatment,
            "profile_id": _profile_for(plan.compilation, route, treatment),
        }
        for route, treatments in plan.route_treatments
        for treatment in treatments
    ]
    return {
        "schema_version": WIDTH_RUN_SCHEMA,
        "state": "disarmed-preview",
        "mode": plan.mode,
        "width_id": plan.compilation["id"],
        "compilation_digest": plan.compilation["compilation_digest"],
        "fixed_recipe": plan.compilation["fixed_recipe"],
        "replays": plan.replays,
        "build_cells_per_replay": plan.cell_count,
        "scheduled_executions": plan.cell_count * plan.replays,
        "groups_per_replay": len(_groups(plan)),
        "parallel_workers": parallel_workers,
        "ghidra_heap_mib": heap_mib,
        "ghidra_core_limit": core_limit,
        "java_tool_options": configured_java_options,
        "cells": cells,
    }


def _profile_for(
    compilation: dict[str, object], route_id: str, treatment_id: str
) -> str:
    matches = [
        str(row["profile_id"])
        for row in compilation["applicability"]
        if row["state"] == "executable"
        and row["route_id"] == route_id
        and row["treatment_id"] == treatment_id
    ]
    if len(matches) != 1:
        raise ValueError(
            f"expected one executable profile for {route_id}/{treatment_id}, "
            f"found {len(matches)}"
        )
    return matches[0]


def _read_manifest(
    manifest: Path, compilation: dict[str, object]
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    rows = _read_csv_rows(manifest)
    cells = []
    failures = []
    routes = {str(item["id"]): item for item in compilation["routes"]}
    for row in rows:
        route = routes[row["route"]]
        cell = {
            "library": row["library"],
            "version": row["version"],
            "route_id": row["route"],
            "target_id": str(route["target_id"]),
            "compiler_id": str(route["compiler_id"]),
            "compiler_family": str(route["compiler_family"]),
            "treatment_id": row["treatment"],
            "profile_id": _profile_for(compilation, row["route"], row["treatment"]),
            "status": row["status"],
            "analysis_artifact_sha256": row["analysis_artifact_sha256"],
            "fidb_sha256": row["fidb_sha256"],
            "fidb_bytes": row["fidb_bytes"],
            "fid_signatures_path": row["fid_signatures_path"],
            "fid_signatures_sha256": row["fid_signatures_sha256"],
            "fid_signature_records": row["fid_signature_records"],
            "fid_unique_full_hashes": row["fid_unique_full_hashes"],
            "fid_unique_signatures": row["fid_unique_signatures"],
            "fid_programs": row["fid_programs"],
            "fid_attempted": row["fid_attempted"],
            "fid_added": row["fid_added"],
            "fid_excluded": row["fid_excluded"],
        }
        cells.append(cell)
        if row["status"] != "complete":
            failures.append(
                {
                    "route_id": row["route"],
                    "treatment_id": row["treatment"],
                    "status": row["status"],
                    "error": row["error"],
                }
            )
    return cells, failures


def _atomic_json(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _run_id(plan: WidthRunPlan) -> str:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    digest = str(plan.compilation["compilation_digest"])[:12]
    return f"{plan.mode}-{stamp}-{digest}"


def _validated_run_root(project_root: Path, width_id: str, run_id: str) -> Path:
    if SAFE_RUN_ID.fullmatch(run_id) is None:
        raise ValueError("width run id is not a safe path component")
    if SAFE_RUN_ID.fullmatch(width_id) is None:
        raise ValueError("width id is not a safe path component")
    parent = project_root / "artifacts/width-runs" / width_id
    destination = parent / run_id
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"width run destination already exists: {destination}")
    parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir()
    resolved_parent = parent.resolve()
    if destination.resolve().parent != resolved_parent:
        raise ValueError("width run destination escaped its managed parent")
    return destination


def _manifest_rows(paths: Iterable[Path], compilation: dict[str, object]):
    cells: list[dict[str, str]] = []
    failures: list[dict[str, str]] = []
    for path in paths:
        if not path.is_file():
            continue
        group_cells, group_failures = _read_manifest(path, compilation)
        cells.extend(group_cells)
        failures.extend(group_failures)
    return cells, failures


def _read_csv_rows(path: Path) -> list[dict[str, str]]:
    previous_limit = csv.field_size_limit()
    csv.field_size_limit(max(previous_limit, MANIFEST_FIELD_LIMIT))
    try:
        with path.open(newline="", encoding="utf-8") as stream:
            return list(csv.DictReader(stream))
    finally:
        csv.field_size_limit(previous_limit)


def _replay_comparison(replays: list[dict[str, object]]) -> dict[str, object]:
    if len(replays) < 2:
        return {
            "comparable": False,
            "compared_cells": 0,
            "artifact_bytes": {"matching_cells": 0, "mismatches": []},
            "fidb_container_bytes": {"matching_cells": 0, "mismatches": []},
            "fid_semantics": {"matching_cells": 0, "mismatches": []},
        }

    def keyed(replay: dict[str, object]) -> dict[tuple[str, str], dict[str, str]]:
        return {
            (row["route_id"], row["treatment_id"]): row
            for row in replay["cells"]
            if row["status"] == "complete"
        }

    def identity(key: tuple[str, str]) -> dict[str, str]:
        return {"route_id": key[0], "treatment_id": key[1]}

    semantic_fields = (
        "fid_programs",
        "fid_attempted",
        "fid_added",
        "fid_excluded",
    )
    baseline = keyed(replays[0])
    artifact_matches = 0
    fidb_matches = 0
    semantic_matches = 0
    artifact_mismatches: list[dict[str, str]] = []
    fidb_mismatches: list[dict[str, str]] = []
    semantic_mismatches: list[dict[str, object]] = []
    compared = 0
    for replay_index, replay in enumerate(replays[1:], start=2):
        current = keyed(replay)
        for key in sorted(set(baseline) | set(current)):
            compared += 1
            first = baseline.get(key)
            second = current.get(key)
            mismatch_identity = {**identity(key), "replay": replay_index}
            if (
                first is not None
                and second is not None
                and first["analysis_artifact_sha256"]
                == second["analysis_artifact_sha256"]
            ):
                artifact_matches += 1
            else:
                artifact_mismatches.append(mismatch_identity)
            if (
                first is not None
                and second is not None
                and first["fidb_sha256"] == second["fidb_sha256"]
            ):
                fidb_matches += 1
            else:
                fidb_mismatches.append(mismatch_identity)
            first_semantics = (
                {field: first[field] for field in semantic_fields}
                if first is not None
                else None
            )
            second_semantics = (
                {field: second[field] for field in semantic_fields}
                if second is not None
                else None
            )
            if first_semantics == second_semantics and first_semantics is not None:
                semantic_matches += 1
            else:
                semantic_mismatches.append(
                    {
                        **mismatch_identity,
                        "baseline": first_semantics,
                        "observed": second_semantics,
                    }
                )
    return {
        "comparable": True,
        "compared_cells": compared,
        "artifact_bytes": {
            "matching_cells": artifact_matches,
            "mismatches": artifact_mismatches,
        },
        "fidb_container_bytes": {
            "matching_cells": fidb_matches,
            "mismatches": fidb_mismatches,
        },
        "fid_semantics": {
            "matching_cells": semantic_matches,
            "mismatches": semantic_mismatches,
        },
    }


def _seed_source_cache(
    project_root: Path, run_root: Path, configuration: Configuration
) -> dict[str, Path]:
    cache = run_root / "source-cache"
    cache.mkdir()
    result: dict[str, Path] = {}
    for library in configuration.libraries:
        name = f"{library.identifier}.tar.gz"
        existing = project_root / "work/downloads" / name
        destination = cache / name
        if (
            existing.is_file()
            and existing.stat().st_size > 0
            and _sha256(existing) == library.sha256
        ):
            try:
                os.link(existing, destination)
            except OSError:
                shutil.copy2(existing, destination)
        archive = download_library(library, cache)
        result[library.identifier] = archive
    return result


def _seed_group_sources(
    configuration: Configuration,
    group_root: Path,
    source_cache: dict[str, Path],
) -> None:
    downloads = group_root / "work/downloads"
    downloads.mkdir(parents=True)
    for library in configuration.libraries:
        source = source_cache[library.identifier]
        destination = downloads / f"{library.identifier}.tar.gz"
        try:
            os.link(source, destination)
        except OSError:
            shutil.copy2(source, destination)


def _release_cell_scratch(group_root: Path) -> None:
    """Drop per-cell bulk; JVM state is released after the pool shuts down."""
    work = group_root / "work"
    targets = (
        work / "sources",
        work / "builds",
        work / "ghidra/projects",
        work / "ghidra/references",
        work / "ghidra/candidates",
    )
    for target in targets:
        if target.is_symlink():
            raise PipelineError(f"refusing symlinked width scratch target: {target}")
        if target.exists():
            expected_parent = work if target.parent == work else work / "ghidra"
            if target.resolve().parent != expected_parent.resolve():
                raise PipelineError(f"width scratch target escaped its group: {target}")
            shutil.rmtree(target)


def _release_jvm_scratch(group_root: Path) -> dict[str, int]:
    """Archive Ghidra logs and drop its reproducible cache after JVM exit."""

    work = group_root / "work"
    user_root = work / "ghidra/user"
    if not user_root.exists():
        return {"user_bytes": 0, "archived_log_bytes": 0, "reclaimed_bytes": 0}
    if (
        user_root.is_symlink()
        or user_root.resolve().parent != (work / "ghidra").resolve()
    ):
        raise PipelineError(f"refusing unsafe Ghidra user scratch target: {user_root}")
    user_bytes = _directory_size(user_root)
    log_sources = sorted(
        path
        for path in user_root.rglob("application.log*")
        if path.is_file() and not path.is_symlink()
    )
    archive_root = work / "logs/ghidra-jvm"
    archived_log_bytes = 0
    if log_sources:
        archive_root.mkdir(parents=True, exist_ok=True)
    for index, source in enumerate(log_sources, start=1):
        destination = archive_root / f"{index:03d}-{source.name}.gz"
        temporary = destination.with_name(f".{destination.name}.part")
        temporary.unlink(missing_ok=True)
        try:
            with source.open("rb") as input_stream, temporary.open("xb") as raw:
                with gzip.GzipFile(
                    filename=source.name,
                    mode="wb",
                    compresslevel=6,
                    fileobj=raw,
                    mtime=0,
                ) as compressed:
                    shutil.copyfileobj(input_stream, compressed)
            temporary.replace(destination)
            archived_log_bytes += destination.stat().st_size
        finally:
            temporary.unlink(missing_ok=True)
    shutil.rmtree(user_root)
    return {
        "user_bytes": user_bytes,
        "archived_log_bytes": archived_log_bytes,
        "reclaimed_bytes": max(0, user_bytes - archived_log_bytes),
    }


def _release_pool_jvm_scratch(
    scheduled: Iterable[tuple[int, Configuration, Path]],
) -> dict[str, int]:
    result = {"user_bytes": 0, "archived_log_bytes": 0, "reclaimed_bytes": 0}
    for _index, _configuration, group_root in scheduled:
        row = _release_jvm_scratch(group_root)
        for name in result:
            result[name] += row[name]
    return result


def _execute_cell(
    configuration: Configuration,
    group_root_text: str,
    verbose: bool,
    java_options_text: str | None = None,
) -> dict[str, object]:
    """Process-pool entry point for one isolated route/treatment cell."""
    if java_options_text is not None:
        if java_options_text:
            os.environ["JAVA_TOOL_OPTIONS"] = java_options_text
        else:
            os.environ.pop("JAVA_TOOL_OPTIONS", None)
    group_root = Path(group_root_text)
    route_id = configuration.routes[0].id
    treatment_id = configuration.treatments[0].id
    started_at = utc_now()
    started_ns = time.monotonic_ns()
    manifest: Path | None = None
    pipeline_error = ""
    timing = TimingRecorder()
    with _ResourceSampler(group_root) as sampler:
        try:
            manifest = execute(
                configuration,
                group_root,
                verbose=verbose,
                timing=timing.span,
                skipped=timing.skip,
            )
        except (OSError, ValueError, PipelineError) as error:
            pipeline_error = str(error)
            candidate = group_root / "artifacts/libs/fidb_manifest.csv"
            if candidate.is_file():
                manifest = candidate
    generated_scratch_bytes = _directory_size(group_root / "work")
    if manifest is not None and not pipeline_error:
        _release_cell_scratch(group_root)
    return {
        "route_id": route_id,
        "treatment_id": treatment_id,
        "started_at_utc": started_at,
        "finished_at_utc": utc_now(),
        "wall_time_ns": max(0, time.monotonic_ns() - started_ns),
        "peak_scratch_bytes": sampler.peak_scratch_bytes,
        "generated_scratch_bytes": generated_scratch_bytes,
        "final_scratch_bytes": _directory_size(group_root / "work"),
        "retained_bytes": _directory_size(group_root / "artifacts/libs"),
        "peak_process_rss_bytes": sampler.peak_rss_bytes,
        "resource_samples": sampler.samples,
        "stage_timing": timing.document(),
        "manifest": str(manifest) if manifest is not None else "",
        "pipeline_error": pipeline_error,
    }


def _cell_status(manifest: Path | None) -> str:
    if manifest is None or not manifest.is_file():
        return "pipeline_error"
    rows = _read_csv_rows(manifest)
    statuses = {row["status"] for row in rows}
    return next(iter(statuses)) if len(statuses) == 1 else "mixed"


def _terminate_executor(executor: concurrent.futures.ProcessPoolExecutor) -> None:
    terminate_workers = getattr(executor, "terminate_workers", None)
    if terminate_workers is not None:
        terminate_workers()
        return
    processes = tuple(getattr(executor, "_processes", {}).values())
    for process in processes:
        if process.is_alive():
            process.terminate()
    executor.shutdown(wait=True, cancel_futures=True)


def execute_width_run(
    project_root: str | Path,
    *,
    canary: bool,
    authority_id: str = "c-width-v1",
    progress: Callable[[str], None] | None = None,
    verbose: bool = False,
    workers: int | None = None,
    heap_mib: int | None = DEFAULT_WIDTH_GHIDRA_HEAP_MIB,
    core_limit: int | None = None,
) -> tuple[dict[str, object], Path]:
    root = Path(project_root).expanduser().resolve()
    plan = compile_width_run_plan(root, canary=canary, authority_id=authority_id)
    announce = progress or (lambda _message: None)
    parallel_workers = (
        default_width_workers(heap_mib=heap_mib) if workers is None else workers
    )
    if parallel_workers < 1 or parallel_workers > 32:
        raise ValueError("width workers must be between 1 and 32")
    run_root = _validated_run_root(root, str(plan.compilation["id"]), _run_id(plan))
    preview = width_run_preview(
        plan,
        workers=parallel_workers,
        heap_mib=heap_mib,
        core_limit=core_limit,
    )
    effective_java_options = java_options(heap_mib, core_limit)
    _atomic_json(run_root / "width-run-plan.json", preview)
    source_cache = _seed_source_cache(root, run_root, plan.configuration)
    started_at = utc_now()
    started_ns = time.monotonic_ns()
    replay_results: list[dict[str, object]] = []
    groups = _groups(plan)
    for replay_index in range(1, plan.replays + 1):
        replay_root = run_root / f"replay-{replay_index:02d}"
        replay_root.mkdir()
        replay_started_at = utc_now()
        replay_started_ns = time.monotonic_ns()
        manifests: list[Path] = []
        pipeline_errors: list[str] = []
        measurements: list[dict[str, object]] = []
        announce(
            f"[width replay {replay_index}/{plan.replays}] "
            f"{plan.cell_count} build cells; workers={parallel_workers}"
        )
        with _ResourceSampler(replay_root, filesystem_scratch=True) as sampler:
            scheduled = []
            for group_index, configuration in enumerate(groups, start=1):
                group_root = replay_root / f"group-{group_index:03d}"
                group_root.mkdir()
                _seed_group_sources(configuration, group_root, source_cache)
                scheduled.append((group_index, configuration, group_root))
            executor = concurrent.futures.ProcessPoolExecutor(
                max_workers=parallel_workers,
                mp_context=multiprocessing.get_context("spawn"),
            )
            try:
                future_rows = {
                    executor.submit(
                        _execute_cell,
                        configuration,
                        str(group_root),
                        verbose,
                        effective_java_options,
                    ): (group_index, configuration, group_root)
                    for group_index, configuration, group_root in scheduled
                }
                for completed_index, future in enumerate(
                    concurrent.futures.as_completed(future_rows), start=1
                ):
                    group_index, configuration, group_root = future_rows[future]
                    route_id = configuration.routes[0].id
                    treatment_id = configuration.treatments[0].id
                    try:
                        measurement = future.result()
                    except Exception as error:
                        measurement = {
                            "route_id": route_id,
                            "treatment_id": treatment_id,
                            "started_at_utc": "",
                            "finished_at_utc": utc_now(),
                            "wall_time_ns": 0,
                            "peak_scratch_bytes": 0,
                            "generated_scratch_bytes": _directory_size(
                                group_root / "work"
                            ),
                            "final_scratch_bytes": _directory_size(group_root / "work"),
                            "retained_bytes": _directory_size(
                                group_root / "artifacts/libs"
                            ),
                            "peak_process_rss_bytes": 0,
                            "resource_samples": 0,
                            "stage_timing": None,
                            "manifest": "",
                            "pipeline_error": (
                                f"worker {type(error).__name__}: {error}"
                            ),
                        }
                    manifest_text = str(measurement.pop("manifest"))
                    manifest = Path(manifest_text) if manifest_text else None
                    if manifest is not None:
                        manifests.append(manifest)
                    pipeline_error = str(measurement["pipeline_error"])
                    if pipeline_error:
                        pipeline_errors.append(
                            f"{route_id}/{treatment_id}: {pipeline_error}"
                        )
                    measurement["group"] = group_index
                    measurement["status"] = _cell_status(manifest)
                    measurements.append(measurement)
                    wall_seconds = int(measurement["wall_time_ns"]) / 1_000_000_000
                    announce(
                        f"[width cell {completed_index}/{len(groups)}] "
                        f"{route_id}/{treatment_id} "
                        f"{measurement['status']} {wall_seconds:.1f}s"
                    )
                    _atomic_json(
                        replay_root / "replay-progress.json",
                        {
                            "schema_version": WIDTH_RUN_SCHEMA,
                            "state": "running",
                            "completed_cells": completed_index,
                            "scheduled_cells": len(groups),
                            "measurements": sorted(
                                measurements, key=lambda row: int(row["group"])
                            ),
                        },
                    )
            except BaseException:
                _terminate_executor(executor)
                raise
            else:
                executor.shutdown(wait=True)
            jvm_scratch_cleanup = _release_pool_jvm_scratch(scheduled)
            for measurement in measurements:
                group_root = replay_root / f"group-{int(measurement['group']):03d}"
                measurement["final_scratch_bytes"] = _directory_size(
                    group_root / "work"
                )
        cells, failures = _manifest_rows(manifests, plan.compilation)
        measurement_by_cell = {
            (str(row["route_id"]), str(row["treatment_id"])): row
            for row in measurements
        }
        for cell in cells:
            measurement = measurement_by_cell[(cell["route_id"], cell["treatment_id"])]
            for name in (
                "wall_time_ns",
                "peak_scratch_bytes",
                "final_scratch_bytes",
                "retained_bytes",
                "peak_process_rss_bytes",
            ):
                cell[name] = measurement[name]
        hash_coverage = analyze_signature_coverage(
            manifests, plan.compilation, measurements
        )
        outcomes = Counter(row["status"] for row in cells)
        replay_result: dict[str, object] = {
            "replay": replay_index,
            "started_at_utc": replay_started_at,
            "finished_at_utc": utc_now(),
            "wall_time_ns": max(0, time.monotonic_ns() - replay_started_ns),
            "peak_scratch_bytes": sampler.peak_scratch_bytes,
            "final_scratch_bytes": _scratch_size(replay_root),
            "retained_bytes": sum(int(row["retained_bytes"]) for row in measurements),
            "peak_process_rss_bytes": sampler.peak_rss_bytes,
            "resource_samples": sampler.samples,
            "jvm_scratch_cleanup": jvm_scratch_cleanup,
            "parallel_workers": parallel_workers,
            "manifest_sha256": [_sha256(path) for path in manifests],
            "outcomes": dict(sorted(outcomes.items())),
            "cells": cells,
            "measurements": sorted(measurements, key=lambda row: int(row["group"])),
            "failures": failures,
            "pipeline_errors": pipeline_errors,
            "hash_coverage": hash_coverage,
        }
        replay_results.append(replay_result)
        _atomic_json(replay_root / "replay-result.json", replay_result)
    expected = plan.cell_count * plan.replays
    completed = sum(
        row["status"] == "complete"
        for replay in replay_results
        for row in replay["cells"]
    )
    comparison = _replay_comparison(replay_results)
    result: dict[str, object] = {
        "schema_version": WIDTH_RUN_SCHEMA,
        "state": (
            "measured-complete" if completed == expected else "measured-incomplete"
        ),
        "mode": plan.mode,
        "width_id": plan.compilation["id"],
        "compilation_digest": plan.compilation["compilation_digest"],
        "route_profile_digest": plan.compilation["route_profile_digest"],
        "fixed_recipe": plan.compilation["fixed_recipe"],
        "started_at_utc": started_at,
        "finished_at_utc": utc_now(),
        "wall_time_ns": max(0, time.monotonic_ns() - started_ns),
        "replays": plan.replays,
        "build_cells_per_replay": plan.cell_count,
        "scheduled_executions": expected,
        "parallel_workers": parallel_workers,
        "ghidra_heap_mib": heap_mib,
        "ghidra_core_limit": core_limit,
        "java_tool_options": effective_java_options,
        "source_cache_bytes": _directory_size(run_root / "source-cache"),
        "completed_executions": completed,
        "failed_executions": expected - completed,
        "peak_scratch_bytes": max(
            (int(row["peak_scratch_bytes"]) for row in replay_results), default=0
        ),
        "final_scratch_bytes": sum(
            int(row["final_scratch_bytes"]) for row in replay_results
        ),
        "retained_bytes": sum(int(row["retained_bytes"]) for row in replay_results),
        "peak_process_rss_bytes": max(
            (int(row["peak_process_rss_bytes"]) for row in replay_results), default=0
        ),
        "coverage": {
            "successful_route_profile_executions": completed,
            "successful_route_profile_pairs": len(
                {
                    (row["route_id"], row["profile_id"])
                    for replay in replay_results
                    for row in replay["cells"]
                    if row["status"] == "complete"
                }
            ),
            "planned_route_profile_pairs": plan.cell_count,
        },
        "hash_coverage": (
            replay_results[0]["hash_coverage"] if replay_results else None
        ),
        "replay_comparison": comparison,
        "replay_results": replay_results,
    }
    result_path = run_root / "width-run.json"
    _atomic_json(result_path, result)
    announce(f"Width result: {result['state']}")
    announce(f"Width evidence: {result_path}")
    return result, result_path
