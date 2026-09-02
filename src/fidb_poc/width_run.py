"""Execute and measure an applicability-compiled C width campaign."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import threading
import time
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Iterable

from .c_width import compile_c_width, materialize_width_configuration
from .config import Configuration
from .hash_coverage import analyze_signature_coverage
from .toolchain_packs import resolve_toolchain_profile
from .pipeline import PipelineError, execute
from .timing import utc_now

WIDTH_RUN_SCHEMA = "fidb-width-run/v1"
SAFE_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")


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


def _directory_size(path: Path) -> int:
    total = 0
    if not path.exists():
        return total
    for parent, _directories, files in os.walk(path):
        for name in files:
            candidate = Path(parent) / name
            try:
                total += candidate.stat(follow_symlinks=False).st_size
            except FileNotFoundError:
                continue
    return total


def _rss_bytes() -> int:
    try:
        for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def _scratch_size(replay_root: Path) -> int:
    return sum(_directory_size(path) for path in replay_root.glob("group-*/work"))


class _ResourceSampler:
    def __init__(self, run_root: Path, interval_seconds: float = 1.0):
        self.run_root = run_root
        self.interval_seconds = interval_seconds
        self.peak_scratch_bytes = 0
        self.peak_rss_bytes = 0
        self.samples = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._sample, daemon=True)

    def _measure(self) -> None:
        self.peak_scratch_bytes = max(
            self.peak_scratch_bytes, _scratch_size(self.run_root)
        )
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


def compile_width_run_plan(project_root: str | Path, *, canary: bool) -> WidthRunPlan:
    root = Path(project_root).expanduser().resolve()
    compilation = compile_c_width(root)
    fixed_recipe = str(compilation["fixed_recipe"])
    route_plan = resolve_toolchain_profile(
        root, str(compilation["toolchain_profile"])
    )
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
    """Group routes sharing a treatment set without adding Cartesian cells."""
    route_by_id = {route.id: route for route in plan.configuration.routes}
    treatment_by_id = {
        treatment.id: treatment for treatment in plan.configuration.treatments
    }
    grouped: dict[tuple[str, ...], list[str]] = {}
    for route, treatments in plan.route_treatments:
        grouped.setdefault(treatments, []).append(route)
    return tuple(
        replace(
            plan.configuration,
            routes=tuple(route_by_id[route] for route in routes),
            treatments=tuple(treatment_by_id[item] for item in treatments),
        )
        for treatments, routes in grouped.items()
    )


def width_run_preview(plan: WidthRunPlan) -> dict[str, object]:
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
    with manifest.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
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


def execute_width_run(
    project_root: str | Path,
    *,
    canary: bool,
    progress: Callable[[str], None] | None = None,
    verbose: bool = False,
) -> tuple[dict[str, object], Path]:
    root = Path(project_root).expanduser().resolve()
    plan = compile_width_run_plan(root, canary=canary)
    announce = progress or (lambda _message: None)
    run_root = _validated_run_root(
        root, str(plan.compilation["id"]), _run_id(plan)
    )
    preview = width_run_preview(plan)
    _atomic_json(run_root / "width-run-plan.json", preview)
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
        announce(
            f"[width replay {replay_index}/{plan.replays}] "
            f"{plan.cell_count} build cells"
        )
        with _ResourceSampler(replay_root) as sampler:
            for group_index, configuration in enumerate(groups, start=1):
                group_root = replay_root / f"group-{group_index:02d}"
                group_root.mkdir()
                announce(
                    f"[width group {group_index}/{len(groups)}] "
                    f"routes={len(configuration.routes)} "
                    f"treatments={len(configuration.treatments)}"
                )
                try:
                    manifest = execute(
                        configuration,
                        group_root,
                        progress=announce,
                        verbose=verbose,
                    )
                except (OSError, ValueError, PipelineError) as error:
                    pipeline_errors.append(str(error))
                    candidate = group_root / "artifacts/libs/fidb_manifest.csv"
                    if candidate.is_file():
                        manifests.append(candidate)
                else:
                    manifests.append(manifest)
        cells, failures = _manifest_rows(manifests, plan.compilation)
        hash_coverage = analyze_signature_coverage(manifests, plan.compilation)
        outcomes = Counter(row["status"] for row in cells)
        replay_result: dict[str, object] = {
            "replay": replay_index,
            "started_at_utc": replay_started_at,
            "finished_at_utc": utc_now(),
            "wall_time_ns": max(0, time.monotonic_ns() - replay_started_ns),
            "peak_scratch_bytes": sampler.peak_scratch_bytes,
            "final_scratch_bytes": _scratch_size(replay_root),
            "retained_bytes": sum(
                _directory_size(replay_root / f"group-{index:02d}/artifacts/libs")
                for index in range(1, len(groups) + 1)
            ),
            "peak_process_rss_bytes": sampler.peak_rss_bytes,
            "resource_samples": sampler.samples,
            "manifest_sha256": [_sha256(path) for path in manifests],
            "outcomes": dict(sorted(outcomes.items())),
            "cells": cells,
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
