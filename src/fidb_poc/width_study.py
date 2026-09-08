"""Validated coverage-intent authority for bounded matrix-width studies."""

from __future__ import annotations

from pathlib import Path
import tomllib

WIDTH_STUDY_SCHEMA = "fidb-width-study/v1"
WIDTH_AXIS_IDS = (
    "releases",
    "routes",
    "build_profiles",
    "artifact_shapes",
    "analysis_profiles",
    "admission_profiles",
    "replay",
)
WIDTH_LAYERS = {"build-cell", "analysis-reuse", "policy-reuse", "repeat"}
EVIDENCE_CLASSES = {"measured", "proposed", "provisional", "assumption"}


def _non_empty(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"width study {field} must be a non-empty string")
    return value


def _rows(value: object, kind: str, required: set[str]) -> list[dict[str, object]]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"width study must contain at least one {kind}")
    result: list[dict[str, object]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise ValueError(f"width study {kind} row {index} must be a table")
        missing = required - set(raw)
        if missing:
            raise ValueError(
                f"width study {kind} row {index} missing {sorted(missing)}"
            )
        row = dict(raw)
        row_id = _non_empty(row["id"], f"{kind} id")
        if row_id in seen:
            raise ValueError(f"duplicate width study {kind} id: {row_id}")
        seen.add(row_id)
        result.append(row)
    return result


def _metrics(values: dict[str, int], family_count: int) -> dict[str, int]:
    build_width = (
        values["releases"]
        * values["routes"]
        * values["build_profiles"]
        * values["artifact_shapes"]
    )
    build_cells = family_count * build_width
    analysis_runs = build_cells * values["analysis_profiles"]
    return {
        "build_width_per_family": build_width,
        "build_cells": build_cells,
        "analysis_runs": analysis_runs,
        "replayed_executions": analysis_runs * values["replay"],
        "policy_evaluations": analysis_runs * values["admission_profiles"],
    }


def load_width_study(path: str | Path) -> dict[str, object]:
    """Load a defined-but-non-executable matrix-width experiment."""

    study_path = Path(path)
    document = tomllib.loads(study_path.read_text(encoding="utf-8"))
    allowed = {
        "schema_version",
        "id",
        "name",
        "label",
        "language_id",
        "state",
        "selection_status",
        "family_count",
        "default_preset",
        "purpose",
        "ranking_authority",
        "ranking_snapshot",
        "queue_policy",
        "caveat",
        "scaling",
        "calibration",
        "toolchain_requirement",
        "family",
        "axis",
        "preset",
    }
    unknown = set(document) - allowed
    if unknown:
        raise ValueError(f"unknown width study fields: {sorted(unknown)}")
    if document.get("schema_version") != WIDTH_STUDY_SCHEMA:
        raise ValueError(
            f"unsupported width study schema: {document.get('schema_version')}"
        )

    for field in allowed - {
        "family",
        "axis",
        "preset",
        "family_count",
        "scaling",
        "calibration",
        "toolchain_requirement",
    }:
        _non_empty(document.get(field), field)
    family_count = document.get("family_count")
    if not isinstance(family_count, int) or family_count <= 0:
        raise ValueError("width study family_count must be a positive integer")

    scaling = document.get("scaling")
    scaling_fields = {
        "comparison_family_counts",
        "default_target_families",
        "default_workers",
        "maximum_workers",
        "model",
    }
    if not isinstance(scaling, dict) or set(scaling) != scaling_fields:
        raise ValueError("width study scaling has unexpected or missing fields")
    comparison_counts = scaling["comparison_family_counts"]
    if (
        not isinstance(comparison_counts, list)
        or not comparison_counts
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in comparison_counts
        )
        or sorted(set(comparison_counts)) != comparison_counts
    ):
        raise ValueError(
            "width study comparison counts must be sorted positive integers"
        )
    if family_count not in comparison_counts:
        raise ValueError(
            "width study comparison counts must include the study family count"
        )
    if scaling["default_target_families"] not in comparison_counts:
        raise ValueError("width study default target must be a comparison count")
    workers = (scaling["default_workers"], scaling["maximum_workers"])
    if (
        any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in workers
        )
        or workers[0] > workers[1]
    ):
        raise ValueError("width study worker bounds must be positive and monotonic")
    _non_empty(scaling["model"], "scaling model")

    calibration = document.get("calibration")
    calibration_fields = {
        "evidence_class",
        "sample_count",
        "successful_wall_ns_min",
        "successful_wall_ns_p50",
        "successful_wall_ns_max",
        "retained_bundle_bytes_p50",
        "compact_output_bytes_p50",
        "peak_worker_rss_bytes_p50",
        "scratch_peak_state",
        "basis",
        "caveat",
    }
    if not isinstance(calibration, dict) or set(calibration) != calibration_fields:
        raise ValueError("width study calibration has unexpected or missing fields")
    if calibration["evidence_class"] != "measured":
        raise ValueError("width study calibration must be explicitly measured")
    numeric_calibration = calibration_fields - {
        "evidence_class",
        "scratch_peak_state",
        "basis",
        "caveat",
    }
    if any(
        not isinstance(calibration[field], int)
        or isinstance(calibration[field], bool)
        or int(calibration[field]) <= 0
        for field in numeric_calibration
    ):
        raise ValueError(
            "width study calibration measurements must be positive integers"
        )
    if not (
        calibration["successful_wall_ns_min"]
        <= calibration["successful_wall_ns_p50"]
        <= calibration["successful_wall_ns_max"]
    ):
        raise ValueError("width study wall measurements must be monotonic")
    for field in ("scratch_peak_state", "basis", "caveat"):
        _non_empty(calibration[field], f"calibration {field}")

    toolchain_requirements = _rows(
        document.get("toolchain_requirement"),
        "toolchain requirement",
        {
            "id",
            "order",
            "target_id",
            "compiler_family",
            "wave",
            "worker_class",
            "acquisition",
            "version_policy",
            "rationale",
        },
    )
    orders = [row["order"] for row in toolchain_requirements]
    if any(
        not isinstance(order, int) or isinstance(order, bool) or order <= 0
        for order in orders
    ):
        raise ValueError(
            "width study toolchain requirement orders must be positive integers"
        )
    if sorted(orders) != list(range(1, len(toolchain_requirements) + 1)):
        raise ValueError(
            "width study toolchain requirement orders must be contiguous from one"
        )
    toolchain_requirements.sort(key=lambda row: int(row["order"]))
    target_ids: set[str] = set()
    for row in toolchain_requirements:
        for field in (
            "target_id",
            "compiler_family",
            "wave",
            "worker_class",
            "acquisition",
            "version_policy",
            "rationale",
        ):
            _non_empty(row[field], f"toolchain requirement {row['id']} {field}")
        target_id = str(row["target_id"])
        if target_id in target_ids:
            raise ValueError(
                f"duplicate width study toolchain requirement target: {target_id}"
            )
        target_ids.add(target_id)

    families = _rows(
        document.get("family"),
        "family",
        {
            "id",
            "rank",
            "label",
            "source_url",
            "source_state",
            "selection_evidence",
        },
    )
    if len(families) != family_count:
        raise ValueError("width study family_count must match family rows")
    ranks = [row["rank"] for row in families]
    if any(not isinstance(rank, int) or rank <= 0 for rank in ranks):
        raise ValueError("width study family ranks must be positive integers")
    if sorted(ranks) != list(range(1, family_count + 1)):
        raise ValueError("width study family ranks must be contiguous from one")
    families.sort(key=lambda row: int(row["rank"]))
    for row in families:
        for field in (
            "label",
            "source_url",
            "source_state",
            "selection_evidence",
        ):
            _non_empty(row[field], f"family {row['id']} {field}")

    axes = _rows(
        document.get("axis"),
        "axis",
        {
            "id",
            "label",
            "layer",
            "minimum",
            "default",
            "maximum",
            "unit",
            "description",
        },
    )
    axis_by_id = {str(row["id"]): row for row in axes}
    if set(axis_by_id) != set(WIDTH_AXIS_IDS):
        raise ValueError("width study axes must define the complete width model")
    for axis_id in WIDTH_AXIS_IDS:
        row = axis_by_id[axis_id]
        if row["layer"] not in WIDTH_LAYERS:
            raise ValueError(f"invalid width layer for axis {axis_id}")
        for field in ("label", "unit", "description"):
            _non_empty(row[field], f"axis {axis_id} {field}")
        bounds = (row["minimum"], row["default"], row["maximum"])
        if any(not isinstance(value, int) or value <= 0 for value in bounds):
            raise ValueError(f"width axis {axis_id} bounds must be positive integers")
        if not bounds[0] <= bounds[1] <= bounds[2]:
            raise ValueError(f"width axis {axis_id} bounds must be monotonic")
    axes = [axis_by_id[axis_id] for axis_id in WIDTH_AXIS_IDS]
    if len(toolchain_requirements) < int(axis_by_id["routes"]["maximum"]):
        raise ValueError(
            "width study toolchain requirements must cover the maximum route width"
        )

    preset_required = {
        "id",
        "label",
        "evidence_class",
        "description",
        *WIDTH_AXIS_IDS,
    }
    presets = _rows(document.get("preset"), "preset", preset_required)
    for row in presets:
        if row["evidence_class"] not in EVIDENCE_CLASSES:
            raise ValueError(f"invalid evidence class for width preset {row['id']}")
        for field in ("label", "description"):
            _non_empty(row[field], f"preset {row['id']} {field}")
        values: dict[str, int] = {}
        for axis_id in WIDTH_AXIS_IDS:
            value = row[axis_id]
            axis = axis_by_id[axis_id]
            if (
                not isinstance(value, int)
                or value < int(axis["minimum"])
                or value > int(axis["maximum"])
            ):
                raise ValueError(
                    f"width preset {row['id']} {axis_id} is outside declared bounds"
                )
            values[axis_id] = value
        row["metrics"] = _metrics(values, family_count)

    preset_ids = {str(row["id"]) for row in presets}
    if document["default_preset"] not in preset_ids:
        raise ValueError("width study default_preset must name a preset")

    return {
        "schema_version": WIDTH_STUDY_SCHEMA,
        "id": document["id"],
        "name": document["name"],
        "label": document["label"],
        "language_id": document["language_id"],
        "state": document["state"],
        "selection_status": document["selection_status"],
        "family_count": family_count,
        "default_preset": document["default_preset"],
        "purpose": document["purpose"],
        "ranking_authority": document["ranking_authority"],
        "ranking_snapshot": document["ranking_snapshot"],
        "queue_policy": document["queue_policy"],
        "caveat": document["caveat"],
        "scaling": dict(scaling),
        "calibration": dict(calibration),
        "toolchain_requirements": toolchain_requirements,
        "families": families,
        "axes": axes,
        "presets": presets,
        "authority_path": str(study_path),
    }
