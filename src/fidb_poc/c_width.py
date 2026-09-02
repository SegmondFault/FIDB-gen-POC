"""Compile the declared C possibility space into applicable execution width."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tomllib

from .config import load_configuration
from .coverage_universe import load_coverage_universe
from .plan_request import _sensitivity_catalog
from .toolchain_packs import resolve_toolchain_profile
from .width_study import load_width_study

WIDTH_AUTHORITY_SCHEMA = "fidb-c-width/v1"
WIDTH_COMPILATION_SCHEMA = "fidb-width-compilation/v1"
PROFILE_STATES = {"registered", "desired", "guarded"}


def _rows(
    document: dict[str, object], kind: str, required: set[str]
) -> list[dict[str, object]]:
    rows = document.get(kind)
    if not isinstance(rows, list) or not rows:
        raise ValueError(f"C width authority requires at least one {kind}")
    result: list[dict[str, object]] = []
    seen: set[str] = set()
    for index, raw in enumerate(rows):
        if not isinstance(raw, dict) or set(raw) != required:
            raise ValueError(f"C width {kind} row {index} has unexpected fields")
        row = dict(raw)
        row_id = row.get("id")
        if not isinstance(row_id, str) or not row_id or row_id in seen:
            raise ValueError(f"C width {kind} row {index} has duplicate/empty id")
        seen.add(row_id)
        if row.get("state") not in PROFILE_STATES:
            raise ValueError(f"C width {kind} {row_id} has invalid state")
        result.append(row)
    return result


def load_c_width_authority(path: str | Path) -> dict[str, object]:
    authority_path = Path(path)
    document = tomllib.loads(authority_path.read_text(encoding="utf-8"))
    allowed = {
        "schema_version",
        "id",
        "label",
        "language_id",
        "state",
        "fixed_recipe",
        "toolchain_profile",
        "selected_replay",
        "purpose",
        "artifact_profile",
        "analysis_profile",
        "admission_profile",
    }
    if (
        set(document) != allowed
        or document.get("schema_version") != WIDTH_AUTHORITY_SCHEMA
    ):
        raise ValueError("C width authority has an unsupported schema or fields")
    for field in allowed - {
        "artifact_profile",
        "analysis_profile",
        "admission_profile",
        "selected_replay",
    }:
        if not isinstance(document.get(field), str) or not document[field]:
            raise ValueError(f"C width authority {field} must be a non-empty string")
    replay = document.get("selected_replay")
    if (
        not isinstance(replay, int)
        or isinstance(replay, bool)
        or replay < 1
        or replay > 3
    ):
        raise ValueError("C width selected_replay must be between one and three")
    artifacts = _rows(
        document,
        "artifact_profile",
        {"id", "label", "state", "execution", "supported_formats", "description"},
    )
    for row in artifacts:
        formats = row["supported_formats"]
        if (
            not isinstance(formats, list)
            or not formats
            or not all(isinstance(value, str) and value for value in formats)
        ):
            raise ValueError(f"artifact profile {row['id']} has invalid formats")
    analyses = _rows(
        document,
        "analysis_profile",
        {"id", "label", "state", "variant_id", "description"},
    )
    admissions = _rows(
        document,
        "admission_profile",
        {"id", "label", "state", "description"},
    )
    return {
        **{
            key: document[key]
            for key in (
                "schema_version",
                "id",
                "label",
                "language_id",
                "state",
                "fixed_recipe",
                "toolchain_profile",
                "selected_replay",
                "purpose",
            )
        },
        "artifact_profiles": artifacts,
        "analysis_profiles": analyses,
        "admission_profiles": admissions,
        "authority_path": str(authority_path),
    }


def _factor_space(root: Path) -> list[dict[str, object]]:
    factors, _digest = _sensitivity_catalog(root)
    variants_document = tomllib.loads(
        (root / "sensitivity/variants.toml").read_text(encoding="utf-8")
    )
    variants = variants_document.get("variant", [])
    by_factor: dict[str, list[dict[str, object]]] = {}
    for row in variants:
        by_factor.setdefault(str(row["factor"]), []).append(dict(row))
    return [
        {
            **factor,
            "variants": by_factor.get(str(factor["id"]), []),
            "variant_state_counts": {
                state: sum(
                    row["state"] == state
                    for row in by_factor.get(str(factor["id"]), [])
                )
                for state in ("registered", "desired", "guarded", "truth-risk")
            },
        }
        for factor in factors
    ]


def compile_c_width(project_root: str | Path) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    authority = load_c_width_authority(root / "coverage/c-width-v1.toml")
    study = load_width_study(root / "coverage/c-top10-width-study.toml")
    universe = load_coverage_universe(root / "coverage/universe.toml")
    configuration = load_configuration(
        root / "worker.toml", (str(authority["fixed_recipe"]),)
    )
    route_plan = resolve_toolchain_profile(root, str(authority["toolchain_profile"]))
    worker_routes = {route.id: route for route in configuration.routes}
    treatments = {row.id: row for row in configuration.treatments}
    routes = []
    for planned in route_plan["routes"]:
        worker = worker_routes.get(str(planned["id"]))
        if worker is None:
            raise ValueError(f"width route has no worker definition: {planned['id']}")
        routes.append(
            {
                "id": worker.id,
                "label": planned["label"],
                "target_id": planned["target_id"],
                "target_os": worker.target_os,
                "architecture": worker.architecture,
                "binary_format": worker.binary_format,
                "compiler_family": worker.compiler_family,
                "toolchain_state": worker.toolchain_state,
                "toolchain_identity": worker.toolchain_identity,
            }
        )

    profiles = [
        dict(row)
        for row in universe["profiles"]
        if row["language_id"] == authority["language_id"]
    ]
    applicability = []
    for route in routes:
        for profile in profiles:
            reasons = []
            if route["compiler_family"] != profile["compiler_family"]:
                state = "inapplicable"
                reasons.append("compiler family does not match route")
            elif "execution_treatment" not in profile:
                state = "unimplemented"
                reasons.append("no reviewed execution treatment")
            elif profile["execution_treatment"] not in treatments:
                state = "unimplemented"
                reasons.append("execution treatment is not registered")
            elif route["toolchain_state"] != "qualified":
                state = "unavailable"
                reasons.append("route toolchain is not qualified")
            elif not treatments[str(profile["execution_treatment"])].applies_to(
                worker_routes[str(route["id"])]
            ):
                state = "inapplicable"
                reasons.append("treatment excludes route")
            else:
                state = "executable"
            applicability.append(
                {
                    "route_id": route["id"],
                    "profile_id": profile["id"],
                    "treatment_id": profile.get("execution_treatment"),
                    "state": state,
                    "reasons": reasons,
                }
            )

    artifact_profiles = authority["artifact_profiles"]
    analysis_profiles = authority["analysis_profiles"]
    admission_profiles = authority["admission_profiles"]
    executable_pairs = sum(row["state"] == "executable" for row in applicability)
    executable_artifacts = sum(
        row["state"] == "registered" for row in artifact_profiles
    )
    executable_analyses = sum(row["state"] == "registered" for row in analysis_profiles)
    executable_admissions = sum(
        row["state"] == "registered" for row in admission_profiles
    )
    replay = int(authority["selected_replay"])
    build_cells = executable_pairs * executable_artifacts
    analysis_runs = build_cells * executable_analyses
    policy_evaluations = analysis_runs * executable_admissions
    factors = _factor_space(root)
    maximum = {row["id"]: int(row["maximum"]) for row in study["axes"]}
    declared_build_cells = (
        maximum["releases"]
        * maximum["routes"]
        * maximum["build_profiles"]
        * maximum["artifact_shapes"]
    )
    body = {
        "schema_version": WIDTH_COMPILATION_SCHEMA,
        "id": authority["id"],
        "label": authority["label"],
        "state": authority["state"],
        "language_id": authority["language_id"],
        "purpose": authority["purpose"],
        "fixed_recipe": authority["fixed_recipe"],
        "toolchain_profile": authority["toolchain_profile"],
        "route_profile_digest": route_plan["profile_digest"],
        "authorities": {
            "width": "coverage/c-width-v1.toml",
            "study": "coverage/c-top10-width-study.toml",
            "universe": "coverage/universe.toml",
            "worker": "worker.toml",
            "factors": "sensitivity/factors.toml",
            "variants": "sensitivity/variants.toml",
        },
        "routes": routes,
        "build_profiles": profiles,
        "artifact_profiles": artifact_profiles,
        "analysis_profiles": analysis_profiles,
        "admission_profiles": admission_profiles,
        "factors": factors,
        "applicability": applicability,
        "summary": {
            "declared_route_slots": maximum["routes"],
            "implemented_routes": len(routes),
            "qualified_routes": sum(
                row["toolchain_state"] == "qualified" for row in routes
            ),
            "declared_build_profile_slots": maximum["build_profiles"],
            "catalogued_build_profiles": len(profiles),
            "applicable_route_profile_pairs": sum(
                row["state"] != "inapplicable" for row in applicability
            ),
            "executable_route_profile_pairs": executable_pairs,
            "unimplemented_applicable_pairs": sum(
                row["state"] == "unimplemented" for row in applicability
            ),
            "inapplicable_pairs": sum(
                row["state"] == "inapplicable" for row in applicability
            ),
            "feasible_build_cells": build_cells,
            "feasible_analysis_runs": analysis_runs,
            "feasible_policy_evaluations": policy_evaluations,
            "selected_replay": replay,
            "feasible_full_path_executions": analysis_runs * replay,
            "declared_maximum_build_cells_one_family": declared_build_cells,
            "declared_maximum_analysis_runs_one_family": declared_build_cells
            * maximum["analysis_profiles"],
            "declared_maximum_policy_evaluations_one_family": declared_build_cells
            * maximum["analysis_profiles"]
            * maximum["admission_profiles"],
            "sensitivity_factors": len(factors),
            "factors_with_variants": sum(bool(row["variants"]) for row in factors),
        },
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return {**body, "compilation_digest": hashlib.sha256(canonical).hexdigest()}
