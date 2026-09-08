"""Compile the declared C possibility space into applicable execution width."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
import re
import tomllib

from .config import Configuration, Route, load_configuration
from .coverage_universe import load_coverage_universe
from .plan_request import _sensitivity_catalog
from .toolchain_packs import load_toolchain_pack_catalog, resolve_toolchain_profile
from .toolchain_qualification import (
    QualificationError,
    resolve_qualified_route_tools,
)
from .width_study import load_width_study

WIDTH_AUTHORITY_SCHEMA = "fidb-c-width/v1"
WIDTH_COMPILATION_SCHEMA = "fidb-width-compilation/v1"
PROFILE_STATES = {"registered", "desired", "guarded"}
WIDTH_STATES = {"candidate-disarmed", "frozen-measured"}
WIDTH_ID = re.compile(r"[a-z0-9][a-z0-9._-]*")
FREEZE_FIELDS = {
    "evidence_path",
    "evidence_sha256",
    "executed_compilation_digest",
    "completed_executions",
    "wall_time_ns",
    "peak_active_replay_scratch_bytes",
    "final_scratch_bytes",
    "retained_bytes",
    "artifact_byte_identical_cells",
    "fid_semantic_identical_cells",
}


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
        "freeze",
    }
    if (
        set(document) not in (allowed, allowed - {"freeze"})
        or document.get("schema_version") != WIDTH_AUTHORITY_SCHEMA
    ):
        raise ValueError("C width authority has an unsupported schema or fields")
    for field in allowed - {
        "artifact_profile",
        "analysis_profile",
        "admission_profile",
        "selected_replay",
        "freeze",
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
    state = document["state"]
    if state not in WIDTH_STATES:
        raise ValueError(f"C width authority has invalid state: {state}")
    freeze = document.get("freeze")
    if state == "candidate-disarmed" and freeze is not None:
        raise ValueError("candidate C width authority cannot carry freeze evidence")
    if state == "frozen-measured":
        if not isinstance(freeze, dict) or set(freeze) != FREEZE_FIELDS:
            raise ValueError("frozen C width authority requires exact freeze evidence")
        for field in (
            "evidence_path",
            "evidence_sha256",
            "executed_compilation_digest",
        ):
            if not isinstance(freeze[field], str) or not freeze[field]:
                raise ValueError(f"C width freeze {field} must be a non-empty string")
        for field in FREEZE_FIELDS - {
            "evidence_path",
            "evidence_sha256",
            "executed_compilation_digest",
        }:
            if (
                not isinstance(freeze[field], int)
                or isinstance(freeze[field], bool)
                or freeze[field] < 0
            ):
                raise ValueError(f"C width freeze {field} must be non-negative")
        for field in ("evidence_sha256", "executed_compilation_digest"):
            value = str(freeze[field])
            if len(value) != 64 or any(
                character not in "0123456789abcdef" for character in value
            ):
                raise ValueError(f"C width freeze {field} is not a SHA-256 digest")
        root = authority_path.expanduser().resolve().parent.parent
        evidence_path = (root / str(freeze["evidence_path"])).resolve()
        if root not in evidence_path.parents or not evidence_path.is_file():
            raise ValueError(
                "C width freeze evidence path is unavailable or escapes the project"
            )
        evidence_digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        if evidence_digest != freeze["evidence_sha256"]:
            raise ValueError("C width freeze evidence digest does not match")
        evidence = tomllib.loads(evidence_path.read_text(encoding="utf-8"))
        if (
            evidence.get("schema_version") != "fidb-width-freeze/v1"
            or evidence.get("width_id") != document["id"]
            or evidence.get("state") != state
            or evidence.get("executed_compilation_digest")
            != freeze["executed_compilation_digest"]
        ):
            raise ValueError(
                "C width freeze evidence identity does not match authority"
            )
        measurements = evidence.get("measurements")
        reproducibility = evidence.get("reproducibility")
        if not isinstance(measurements, dict) or not isinstance(reproducibility, dict):
            raise ValueError("C width freeze evidence lacks measured sections")
        expected = {
            "completed_executions": measurements.get("completed_executions"),
            "wall_time_ns": measurements.get("wall_time_ns"),
            "peak_active_replay_scratch_bytes": measurements.get(
                "peak_active_replay_scratch_bytes"
            ),
            "final_scratch_bytes": measurements.get("final_scratch_bytes"),
            "retained_bytes": measurements.get("retained_bytes"),
            "artifact_byte_identical_cells": reproducibility.get(
                "artifact_byte_identical_cells"
            ),
            "fid_semantic_identical_cells": reproducibility.get(
                "fid_semantic_identical_cells"
            ),
        }
        if any(freeze[field] != value for field, value in expected.items()):
            raise ValueError("C width freeze summary does not match its evidence")
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
        "freeze": dict(freeze) if isinstance(freeze, dict) else None,
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


def materialize_width_configuration(
    project_root: str | Path,
    fixed_recipe: str,
    route_plan: dict[str, object],
    *,
    _catalog: dict[str, object] | None = None,
) -> Configuration:
    """Project target-independent compiler routes into executable workers.

    `worker.toml` may retain several concrete compiler routes per target.
    Compiler generations come from the toolchain authority and inherit only
    identical target mechanics; tool paths and qualification identities are
    resolved afresh.
    """

    root = Path(project_root).expanduser().resolve()
    catalog = _catalog or load_toolchain_pack_catalog(root)
    configuration = load_configuration(
        root / "worker.toml", (fixed_recipe,), toolchain_catalog=catalog
    )
    catalog_routes = {str(row["id"]): row for row in catalog["routes"]}
    qualifications = {str(row["route_id"]): row for row in catalog["qualifications"]}
    compilers = {str(row["id"]): row for row in catalog["compilers"]}
    worker_routes = {route.id: route for route in configuration.routes}

    template_by_target_family: dict[tuple[str, str], Route] = {}
    for worker in configuration.routes:
        if worker.managed_toolchain_route is None:
            continue
        catalog_route = catalog_routes.get(worker.managed_toolchain_route)
        if catalog_route is None:
            continue
        key = (str(catalog_route["target_id"]), worker.compiler_family)
        existing_template = template_by_target_family.get(key)
        mechanics = (
            worker.target_os,
            worker.architecture,
            worker.binary_format,
            worker.compiler_family,
            worker.compiler_flags,
            worker.object_file_markers,
            worker.linked_suffix,
            worker.linked_file_markers,
            worker.ghidra_language,
            worker.ghidra_compiler_spec,
        )
        if existing_template is not None:
            existing_mechanics = (
                existing_template.target_os,
                existing_template.architecture,
                existing_template.binary_format,
                existing_template.compiler_family,
                existing_template.compiler_flags,
                existing_template.object_file_markers,
                existing_template.linked_suffix,
                existing_template.linked_file_markers,
                existing_template.ghidra_language,
                existing_template.ghidra_compiler_spec,
            )
            if mechanics != existing_mechanics:
                raise ValueError(
                    f"conflicting worker templates for target/compiler {key}"
                )
            continue
        template_by_target_family[key] = worker

    materialized: list[Route] = []
    for planned in route_plan["routes"]:
        route_id = str(planned["id"])
        existing = worker_routes.get(route_id)
        if existing is not None:
            materialized.append(existing)
            continue
        catalog_route = catalog_routes.get(route_id)
        qualification = qualifications.get(route_id)
        if catalog_route is None or qualification is None:
            raise ValueError(f"width route lacks managed authority: {route_id}")
        key = (
            str(catalog_route["target_id"]),
            str(catalog_route["compiler_family"]),
        )
        template = template_by_target_family.get(key)
        if template is None:
            raise ValueError(f"width route has no target worker template: {route_id}")
        compiler = compilers[str(catalog_route["compiler_id"])]
        version = str(compiler["version"])
        markers = (
            (f"clang version {version}",)
            if catalog_route["compiler_family"] == "llvm-clang"
            else (version, "Free Software Foundation")
        )
        worker = replace(
            template,
            id=route_id,
            compiler=(f"@managed/{route_id}/c",),
            archiver=(f"@managed/{route_id}/archiver",),
            ranlib=(f"@managed/{route_id}/ranlib",),
            compiler_version_markers=markers,
            managed_toolchain_route=route_id,
            toolchain_state="unavailable",
            toolchain_identity="unresolved",
            toolchain_blocker="managed route is not qualified",
        )
        try:
            tools = resolve_qualified_route_tools(
                root,
                catalog_route,
                qualification,
                catalog["packs"],
                catalog["inputs"],
            )
        except QualificationError as error:
            worker = replace(worker, toolchain_blocker=str(error))
        else:
            worker = replace(
                worker,
                compiler=(str(tools.compiler),),
                archiver=(str(tools.archiver),),
                ranlib=(str(tools.ranlib),),
                toolchain_state="qualified",
                toolchain_identity=(
                    f"qualified:{tools.route_material_digest}:{tools.record_digest}"
                ),
                toolchain_blocker="",
            )
        materialized.append(worker)
    return replace(configuration, routes=tuple(materialized))


def compile_c_width(
    project_root: str | Path,
    authority_id: str = "c-width-v1",
    *,
    _catalog: dict[str, object] | None = None,
    _inspections: dict[str, object] | None = None,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    if WIDTH_ID.fullmatch(authority_id) is None:
        raise ValueError("C width authority id is not safe")
    authority_relative = f"coverage/{authority_id}.toml"
    authority = load_c_width_authority(root / authority_relative)
    study = load_width_study(root / "coverage/c-top10-width-study.toml")
    universe = load_coverage_universe(root / "coverage/universe.toml")
    catalog = _catalog or load_toolchain_pack_catalog(root)
    route_plan = resolve_toolchain_profile(
        root,
        str(authority["toolchain_profile"]),
        _catalog=catalog,
        _inspections=_inspections,
    )
    configuration = materialize_width_configuration(
        root, str(authority["fixed_recipe"]), route_plan, _catalog=catalog
    )
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
                "compiler_id": planned["compiler_id"],
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
        "freeze": authority["freeze"],
        "authorities": {
            "width": authority_relative,
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
