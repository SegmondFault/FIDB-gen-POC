"""Inspectable, evidence-bound planning for bounded overnight width blocks."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import replace
from pathlib import Path
import re
import tomllib

from .c_width import compile_c_width
from .performance_profiles import load_performance_profiles
from .width_batch import load_width_batch, project_width_batch_readiness

BATCH_TIME_MODEL_SCHEMA = "fidb-batch-time-model/v1"
TIME_BLOCK_PLAN_SCHEMA = "fidb-time-block-plan/v1"
DEFAULT_MODEL_PATH = Path("performance/batch-planning.toml")
_ID = re.compile(r"[a-z0-9][a-z0-9-]*")
_TOP_FIELDS = {
    "schema_version",
    "id",
    "label",
    "state",
    "language_id",
    "performance_profile",
    "campaign_batch_paths",
    "target_block_hours",
    "max_block_hours",
    "uncertainty_fraction",
    "reference_source_id",
    "library_complexity_exponent",
    "minimum_complexity_factor",
    "maximum_complexity_factor",
    "reference",
    "libraries",
    "treatments",
}


def _reviewed_recipe_projections(root: Path) -> list[dict[str, object]]:
    """Read the applicability fields needed by planning without loading builds."""

    rows = []
    for path in sorted((root / "recipes").glob("*.toml")):
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        rows.append(
            {
                "id": f'{document["name"]}@{document["version"]}',
                "kind": "native",
                "url": document["url"],
                "sha256": document["sha256"],
                "applicability": {
                    "target_os": list(document.get("supported_target_os", [])),
                    "architectures": list(document.get("supported_architectures", [])),
                    "compiler_families": list(
                        document.get("supported_compiler_families", [])
                    ),
                    "excluded_routes": list(document.get("unsupported_routes", [])),
                },
                "authority_path": str(path.relative_to(root)),
            }
        )
    return rows


def _number(value: object, field: str, *, positive: bool = True) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"batch time model {field} must be numeric")
    result = float(value)
    if not math.isfinite(result) or (positive and result <= 0):
        raise ValueError(f"batch time model {field} must be positive and finite")
    return result


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"batch time model {field} must be a non-empty string")
    return value


def _project_path(root: Path, value: object, field: str) -> tuple[str, Path]:
    if not isinstance(value, (str, Path)) or not str(value).strip():
        raise ValueError(f"batch time model {field} must be a non-empty path")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"batch time model {field} must stay inside project root")
    resolved = (root / relative).resolve()
    if root not in resolved.parents or not resolved.is_file():
        raise ValueError(f"batch time model {field} is not a project file")
    return str(relative), resolved


def _clock_after(start: str, hours: float) -> str:
    hour, minute = (int(value) for value in start.split(":"))
    seconds = hour * 3600 + minute * 60 + round(hours * 3600)
    day_offset, seconds = divmod(seconds, 24 * 3600)
    result = f"{seconds // 3600:02d}:{seconds % 3600 // 60:02d}"
    return f"+{day_offset}d {result}" if day_offset else result


def _pack_blocks(
    items: list[dict[str, object]], target_hours: float, max_hours: float
) -> list[list[dict[str, object]]]:
    """First-fit decreasing, with the least target deviation as tie breaker."""

    blocks: list[list[dict[str, object]]] = []
    totals: list[float] = []
    for item in sorted(
        items, key=lambda row: (-float(row["estimated_hours"]), int(row["rank"]))
    ):
        hours = float(item["estimated_hours"])
        if hours > max_hours + 1e-9:
            raise ValueError(
                f"work item {item['source_id']} estimates {hours:.3f} hours, "
                f"above the {max_hours:.3f}-hour block ceiling; split it before scheduling"
            )
        candidates = [
            (abs(target_hours - (total + hours)), index)
            for index, total in enumerate(totals)
            if total + hours <= max_hours + 1e-9
        ]
        if candidates:
            _, selected = min(candidates)
            blocks[selected].append(item)
            totals[selected] += hours
        else:
            blocks.append([item])
            totals.append(hours)
    return blocks


def compile_time_block_plan(
    project_root: str | Path,
    model_path: str | Path = DEFAULT_MODEL_PATH,
    *,
    performance_profile: str | None = None,
    schedule_start: str | None = None,
) -> dict[str, object]:
    """Compile the current authorities into a dynamic, still-disarmed block plan."""

    root = Path(project_root).expanduser().resolve()
    schedule_path = root / "plans/priority-queue.toml"
    schedule_document = tomllib.loads(schedule_path.read_text(encoding="utf-8"))
    schedule_table = schedule_document.get("schedule", {})
    if not isinstance(schedule_table, dict):
        raise ValueError("queue schedule must be a table")
    if schedule_start is None:
        schedule_start = _text(schedule_table.get("start"), "schedule.start")
    if re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", schedule_start) is None:
        raise ValueError("batch time model schedule start must use HH:MM")
    model_relative, path = _project_path(root, model_path, "authority path")
    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    if set(raw) != _TOP_FIELDS:
        raise ValueError("batch time model has unsupported or missing fields")
    if raw["schema_version"] != BATCH_TIME_MODEL_SCHEMA:
        raise ValueError("unsupported batch time model schema")
    if raw["state"] != "draft-disarmed":
        raise ValueError("batch time model must remain draft-disarmed")
    model_id = _text(raw["id"], "id")
    if _ID.fullmatch(model_id) is None:
        raise ValueError("batch time model id must be a lowercase dash token")
    language_id = _text(raw["language_id"], "language_id")
    target_hours = _number(raw["target_block_hours"], "target_block_hours")
    max_hours = _number(raw["max_block_hours"], "max_block_hours")
    if target_hours > max_hours:
        raise ValueError("batch time model target cannot exceed maximum block hours")
    uncertainty = _number(
        raw["uncertainty_fraction"], "uncertainty_fraction", positive=False
    )
    if uncertainty < 0 or uncertainty >= 1:
        raise ValueError("batch time model uncertainty_fraction must be in [0, 1)")
    exponent = _number(
        raw["library_complexity_exponent"], "library_complexity_exponent"
    )
    minimum = _number(raw["minimum_complexity_factor"], "minimum_complexity_factor")
    maximum = _number(raw["maximum_complexity_factor"], "maximum_complexity_factor")
    if minimum > maximum:
        raise ValueError("minimum complexity factor cannot exceed maximum")

    reference = raw["reference"]
    if not isinstance(reference, dict) or set(reference) != {
        "evidence_path",
        "evidence_sha256",
        "case_id",
        "worker_scaling_exponent",
    }:
        raise ValueError("batch time model reference is incomplete or unsupported")
    evidence_relative, evidence_path = _project_path(
        root, reference["evidence_path"], "reference.evidence_path"
    )
    evidence_sha256 = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    if evidence_sha256 != reference["evidence_sha256"]:
        raise ValueError("batch time model evidence SHA-256 no longer matches")
    evidence = tomllib.loads(evidence_path.read_text(encoding="utf-8"))
    case_id = _text(reference["case_id"], "reference.case_id")
    cases = [row for row in evidence.get("case", []) if row.get("id") == case_id]
    if len(cases) != 1:
        raise ValueError("batch time model reference case is not unique")
    reference_case = cases[0]
    reference_workers = int(reference_case["workers"])
    reference_rate = _number(
        reference_case.get("cells_per_wall_hour"),
        "reference.cells_per_wall_hour",
    )
    scaling_exponent = _number(
        reference["worker_scaling_exponent"], "reference.worker_scaling_exponent"
    )

    profiles = load_performance_profiles(root)
    profile = profiles.select(performance_profile or str(raw["performance_profile"]))
    if profile.settings.worker_mode == "automatic":
        from .host_capacity import detect_host_capacity, resolve_automatic_performance

        automatic = resolve_automatic_performance(
            detect_host_capacity(), profiles.automatic_policy
        )
        profile = replace(
            profile,
            settings=automatic.settings,
            resolution=automatic.document(),
        )
    effective_workers = profile.settings.workers or reference_workers
    estimated_rate = (
        reference_rate * (effective_workers / reference_workers) ** scaling_exponent
    )

    raw_libraries = raw["libraries"]
    if not isinstance(raw_libraries, list) or not raw_libraries:
        raise ValueError("batch time model libraries must be a non-empty array")
    libraries: dict[str, dict[str, int]] = {}
    for row in raw_libraries:
        if not isinstance(row, dict) or set(row) != {"id", "rank", "source_lines"}:
            raise ValueError("batch time model library is incomplete or unsupported")
        source_id = _text(row["id"], "libraries.id")
        rank, source_lines = row["rank"], row["source_lines"]
        if (
            not isinstance(rank, int)
            or isinstance(rank, bool)
            or rank < 1
            or not isinstance(source_lines, int)
            or isinstance(source_lines, bool)
            or source_lines < 1
        ):
            raise ValueError(
                "batch time model library rank/lines must be positive integers"
            )
        if source_id in libraries:
            raise ValueError("batch time model library ids must be unique")
        libraries[source_id] = {"rank": rank, "source_lines": source_lines}
    reference_source_id = _text(raw["reference_source_id"], "reference_source_id")
    if reference_source_id not in libraries:
        raise ValueError("batch time model reference source is not catalogued")
    reference_lines = libraries[reference_source_id]["source_lines"]

    raw_treatments = raw["treatments"]
    if not isinstance(raw_treatments, list) or not raw_treatments:
        raise ValueError("batch time model treatments must be a non-empty array")
    treatment_costs: dict[str, float] = {}
    for row in raw_treatments:
        if not isinstance(row, dict) or set(row) != {"id", "relative_cost"}:
            raise ValueError("batch time model treatment is incomplete or unsupported")
        treatment_id = _text(row["id"], "treatments.id")
        if treatment_id in treatment_costs:
            raise ValueError("batch time model treatment ids must be unique")
        treatment_costs[treatment_id] = _number(
            row["relative_cost"], f"treatments.{treatment_id}.relative_cost"
        )

    raw_batch_paths = raw["campaign_batch_paths"]
    if not isinstance(raw_batch_paths, list) or not raw_batch_paths:
        raise ValueError("batch time model campaign_batch_paths must be non-empty")
    compiled_batches = []
    reviewed_recipes = _reviewed_recipe_projections(root)
    width_cache: dict[str, dict[str, object]] = {}
    for index, value in enumerate(raw_batch_paths):
        relative, batch_path = _project_path(
            root, value, f"campaign_batch_paths[{index}]"
        )
        batch = project_width_batch_readiness(
            load_width_batch(root, batch_path), reviewed_recipes
        )
        if batch["language_id"] != language_id:
            raise ValueError("batch time model campaign mixes languages")
        compiled_batches.append((relative, batch))

    work_items: list[dict[str, object]] = []
    android_executions = 0
    for batch_relative, batch in compiled_batches:
        width_id = Path(str(batch["authorities"]["width"])).stem  # type: ignore[index]
        width = width_cache.setdefault(width_id, compile_c_width(root, width_id))
        selected_pairs = [
            row
            for row in width["applicability"]  # type: ignore[index]
            if row["state"] in {"executable", "unavailable"}
        ]
        missing_costs = sorted(
            {str(row["treatment_id"]) for row in selected_pairs}
            - treatment_costs.keys()
        )
        if missing_costs:
            raise ValueError(
                f"batch time model lacks treatment costs for: {', '.join(missing_costs)}"
            )
        base_pair_count = len(selected_pairs)
        maximum_execution_count = int(
            batch["summary"]["executions_per_library"]  # type: ignore[index]
        )
        if base_pair_count == 0 or maximum_execution_count % base_pair_count:
            raise ValueError(
                "batch execution count cannot be attributed to treatment pairs"
            )
        downstream_multiplier = maximum_execution_count // base_pair_count
        for library in batch["libraries"]:  # type: ignore[index]
            source_id = str(library["id"])
            source = libraries.get(source_id)
            if source is None:
                raise ValueError(
                    f"batch time model lacks source metrics for {source_id}"
                )
            applicable_routes = set(map(str, library["applicable_route_ids"]))
            library_pairs = [
                row
                for row in selected_pairs
                if str(row["route_id"]) in applicable_routes
            ]
            execution_count = len(library_pairs) * downstream_multiplier
            if execution_count != int(library["applicable_executions"]):
                raise ValueError(
                    f"batch applicability drifted for {source_id}: "
                    f"{execution_count} != {library['applicable_executions']}"
                )
            weighted_cells = downstream_multiplier * sum(
                treatment_costs[str(row["treatment_id"])] for row in library_pairs
            )
            android_pairs = (
                sum(
                    str(row["route_id"]).startswith("android-") for row in library_pairs
                )
                * downstream_multiplier
            )
            raw_complexity = (source["source_lines"] / reference_lines) ** exponent
            complexity = min(maximum, max(minimum, raw_complexity))
            hours = weighted_cells / estimated_rate * complexity
            android_executions += android_pairs
            work_items.append(
                {
                    "batch_id": batch["id"],
                    "batch_authority": batch_relative,
                    "source_id": source_id,
                    "label": library["label"],
                    "version": library["version"],
                    "rank": source["rank"],
                    "executions": execution_count,
                    "android_executions": android_pairs,
                    "weighted_cells": round(weighted_cells, 6),
                    "source_lines": source["source_lines"],
                    "complexity_factor": round(complexity, 6),
                    "estimated_hours": round(hours, 6),
                    "planning_lower_hours": round(hours * (1 - uncertainty), 6),
                    "planning_upper_hours": round(hours * (1 + uncertainty), 6),
                }
            )

    packed = _pack_blocks(work_items, target_hours, max_hours)
    blocks = []
    for index, items in enumerate(packed, start=1):
        estimated = sum(float(row["estimated_hours"]) for row in items)
        blocks.append(
            {
                "id": f"{model_id}-block-{index:02d}",
                "position": index,
                "state": "draft-disarmed",
                "estimated_hours": round(estimated, 6),
                "planning_lower_hours": round(estimated * (1 - uncertainty), 6),
                "planning_upper_hours": round(estimated * (1 + uncertainty), 6),
                "expected_start_local": schedule_start,
                "expected_nominal_end_local": _clock_after(schedule_start, estimated),
                "executions": sum(int(row["executions"]) for row in items),
                "android_executions": sum(
                    int(row["android_executions"]) for row in items
                ),
                "items": items,
            }
        )

    source_digests = {
        "model_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "evidence_sha256": evidence_sha256,
        "performance_profiles_sha256": hashlib.sha256(
            (root / profiles.authority_path).read_bytes()
        ).hexdigest(),
        "width_batches_sha256": hashlib.sha256(
            b"".join((root / relative).read_bytes() for relative, _ in compiled_batches)
        ).hexdigest(),
        "schedule_sha256": hashlib.sha256(
            json.dumps(
                schedule_table,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest(),
    }
    body = {
        "schema_version": TIME_BLOCK_PLAN_SCHEMA,
        "id": model_id,
        "label": raw["label"],
        "state": raw["state"],
        "language_id": language_id,
        "authority_path": model_relative,
        "performance_profile": profile.document(),
        "reference": {
            "evidence_path": evidence_relative,
            "case_id": case_id,
            "workers": reference_workers,
            "cells_per_wall_hour": reference_rate,
            "worker_scaling_exponent": scaling_exponent,
            "estimated_cells_per_wall_hour": round(estimated_rate, 6),
        },
        "policy": {
            "target_block_hours": target_hours,
            "max_block_hours": max_hours,
            "uncertainty_fraction": uncertainty,
            "packing": "first-fit-decreasing-best-target",
            "refresh": "recompile-on-authority-read",
            "freeze": "required-before-materialization",
        },
        "summary": {
            "campaign_batches": len(compiled_batches),
            "libraries": len(work_items),
            "blocks": len(blocks),
            "executions": sum(int(row["executions"]) for row in work_items),
            "android_executions": android_executions,
            "estimated_hours": round(
                sum(float(row["estimated_hours"]) for row in work_items), 6
            ),
            "planning_lower_hours": round(
                sum(float(row["planning_lower_hours"]) for row in work_items), 6
            ),
            "planning_upper_hours": round(
                sum(float(row["planning_upper_hours"]) for row in work_items), 6
            ),
        },
        "blocks": blocks,
        "source_digests": source_digests,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return {**body, "plan_digest": hashlib.sha256(canonical).hexdigest()}
