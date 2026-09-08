"""Validated, disarmed bindings from pinned sources to exact width authority."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import tomllib

from .c_width import compile_c_width
from .source_packs import load_source_pack, select_sources
from .priority_schedule import load_priority_overlay
from .width_study import load_width_study

WIDTH_BATCH_SCHEMA = "fidb-width-batch/v1"
WIDTH_BATCH_COMPILATION_SCHEMA = "fidb-width-batch-compilation/v1"
_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._+-]*$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_FIELDS = {
    "schema_version",
    "id",
    "name",
    "label",
    "state",
    "language_id",
    "purpose",
    "source_pack",
    "source_pack_sha256",
    "source_ids",
    "width_authority",
    "width_authority_sha256",
    "width_route_profile_digest",
    "width_study",
    "width_study_sha256",
    "recipe_policy",
    "queue_policy",
    "expected",
}
_EXPECTED_FIELDS = {
    "libraries",
    "route_profiles",
    "compiler_identities",
    "executable_treatments",
    "executions_per_library",
    "total_executions",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _non_empty(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"width batch {field} must be a non-empty string")
    return value


def _digest(value: object, field: str) -> str:
    text = str(value)
    if _DIGEST.fullmatch(text) is None:
        raise ValueError(f"width batch {field} must be a lowercase SHA-256")
    return text


def _project_file(root: Path, value: object, field: str) -> tuple[str, Path]:
    text = _non_empty(value, field)
    relative = Path(text)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"width batch {field} must stay inside the project")
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ValueError(f"width batch {field} must stay inside the project") from error
    if not path.is_file():
        raise ValueError(f"width batch {field} does not exist: {text}")
    return text, path


def _checked_digest(path: Path, expected: object, field: str) -> str:
    pinned = _digest(expected, field)
    actual = _sha256(path)
    if actual != pinned:
        raise ValueError(
            f"width batch {field} no longer matches {path.name}: "
            f"expected {pinned}, got {actual}"
        )
    return actual


def load_width_batch(
    project_root: str | Path,
    path: str | Path,
    *,
    _toolchain_catalog: dict[str, object] | None = None,
    _inspections: dict[str, object] | None = None,
) -> dict[str, object]:
    """Load and cross-check one immutable, non-executable width batch binding."""

    root = Path(project_root).expanduser().resolve()
    batch_path = Path(path).expanduser().resolve()
    document = tomllib.loads(batch_path.read_text(encoding="utf-8"))
    if set(document) != _FIELDS:
        raise ValueError("width batch has unsupported or missing fields")
    if document["schema_version"] != WIDTH_BATCH_SCHEMA:
        raise ValueError("unsupported width batch schema")
    for field in (
        "id",
        "name",
        "label",
        "language_id",
        "purpose",
        "recipe_policy",
        "queue_policy",
    ):
        _non_empty(document[field], field)
    if _TOKEN.fullmatch(str(document["id"])) is None:
        raise ValueError("width batch id must be a lowercase safe token")
    if document["state"] != "defined-disarmed":
        raise ValueError("width batch must remain explicitly defined-disarmed")
    if document["language_id"] != "c":
        raise ValueError("width batch currently supports only C")

    source_ids = document["source_ids"]
    if (
        not isinstance(source_ids, list)
        or not source_ids
        or any(
            not isinstance(item, str) or _TOKEN.fullmatch(item) is None
            for item in source_ids
        )
        or len(set(source_ids)) != len(source_ids)
    ):
        raise ValueError("width batch source_ids must be unique lowercase safe tokens")

    expected = document["expected"]
    if not isinstance(expected, dict) or set(expected) != _EXPECTED_FIELDS:
        raise ValueError("width batch expected counts are incomplete or unsupported")
    if any(
        not isinstance(expected[field], int)
        or isinstance(expected[field], bool)
        or int(expected[field]) <= 0
        for field in _EXPECTED_FIELDS
    ):
        raise ValueError("width batch expected counts must be positive integers")

    source_relative, source_path = _project_file(
        root, document["source_pack"], "source_pack"
    )
    width_relative, width_path = _project_file(
        root, document["width_authority"], "width_authority"
    )
    study_relative, study_path = _project_file(
        root, document["width_study"], "width_study"
    )
    _checked_digest(source_path, document["source_pack_sha256"], "source_pack_sha256")
    _checked_digest(
        width_path, document["width_authority_sha256"], "width_authority_sha256"
    )
    _checked_digest(study_path, document["width_study_sha256"], "width_study_sha256")

    source_pack = load_source_pack(source_path)
    selected = select_sources(source_pack["source"], tuple(source_ids))  # type: ignore[arg-type]
    if source_pack["language_id"] != document["language_id"]:
        raise ValueError("width batch source pack language does not match")
    if source_pack["study_path"] != study_relative:
        raise ValueError("width batch source pack and width study do not match")
    study_document = tomllib.loads(study_path.read_text(encoding="utf-8"))
    if study_document.get("schema_version") == "fidb-priority-overlay/v1":
        study = load_priority_overlay(root, study_relative)
        study_source_ids = {str(row["id"]) for row in study["subjects"]}
    else:
        study = load_width_study(study_path)
        if study["state"] != "defined-disarmed":
            raise ValueError(
                "width batch study must remain explicitly defined-disarmed"
            )
        study_source_ids = {str(row["id"]) for row in study["families"]}
    if study["language_id"] != document["language_id"]:
        raise ValueError("width batch study language does not match")
    if not set(source_ids) <= study_source_ids:
        raise ValueError("width batch selects sources outside its width study")

    width_id = width_path.stem
    width = compile_c_width(
        root,
        width_id,
        _catalog=_toolchain_catalog,
        _inspections=_inspections,
    )
    if width["language_id"] != document["language_id"]:
        raise ValueError("width batch authority language does not match")
    if width["authorities"]["width"] != width_relative:  # type: ignore[index]
        raise ValueError("width batch compiler resolved a different width authority")
    pinned_route_profile = _digest(
        document["width_route_profile_digest"], "width_route_profile_digest"
    )
    if width["route_profile_digest"] != pinned_route_profile:
        raise ValueError(
            "width batch route profile digest no longer matches reviewed width"
        )

    selected_pairs = [
        row
        for row in width["applicability"]  # type: ignore[index]
        if row["state"] in {"executable", "unavailable"}
    ]
    treatment_ids = {str(row["treatment_id"]) for row in selected_pairs}
    compiler_ids = {str(row["compiler_id"]) for row in width["routes"]}  # type: ignore[index]
    registered_artifacts = sum(
        row["state"] == "registered"
        for row in width["artifact_profiles"]  # type: ignore[index]
    )
    registered_analyses = sum(
        row["state"] == "registered"
        for row in width["analysis_profiles"]  # type: ignore[index]
    )
    executions_per_library = (
        len(selected_pairs)
        * registered_artifacts
        * registered_analyses
        * int(width["summary"]["selected_replay"])  # type: ignore[index]
    )
    actual = {
        "libraries": len(selected),
        "route_profiles": len(width["routes"]),  # type: ignore[arg-type]
        "compiler_identities": len(compiler_ids),
        "executable_treatments": len(treatment_ids),
        "executions_per_library": executions_per_library,
        "total_executions": len(selected) * executions_per_library,
    }
    if actual != expected:
        raise ValueError(
            "width batch expected counts no longer match compiled authority: "
            f"expected {expected}, got {actual}"
        )

    body = {
        "schema_version": WIDTH_BATCH_COMPILATION_SCHEMA,
        "id": document["id"],
        "name": document["name"],
        "label": document["label"],
        "state": document["state"],
        "language_id": document["language_id"],
        "purpose": document["purpose"],
        "recipe_policy": document["recipe_policy"],
        "queue_policy": document["queue_policy"],
        "authority_path": str(batch_path.relative_to(root)),
        "authority_sha256": _sha256(batch_path),
        "authorities": {
            "source_pack": source_relative,
            "source_pack_sha256": document["source_pack_sha256"],
            "width": width_relative,
            "width_sha256": document["width_authority_sha256"],
            "width_route_profile_digest": pinned_route_profile,
            "study": study_relative,
            "study_sha256": document["width_study_sha256"],
        },
        "libraries": [
            {
                "rank": row["rank"],
                "id": row["id"],
                "label": row["label"],
                "version": row["version"],
                "url": row["url"],
                "sha256": row["sha256"],
                "recipe_id": f'{row["id"]}@{row["version"]}',
            }
            for row in selected
        ],
        "execution_pairs": [
            {
                "route_id": row["route_id"],
                "treatment_id": row["treatment_id"],
                "target_os": next(
                    route["target_os"]
                    for route in width["routes"]
                    if route["id"] == row["route_id"]
                ),
                "architecture": next(
                    route["architecture"]
                    for route in width["routes"]
                    if route["id"] == row["route_id"]
                ),
                "compiler_family": next(
                    route["compiler_family"]
                    for route in width["routes"]
                    if route["id"] == row["route_id"]
                ),
            }
            for row in selected_pairs
        ],
        "summary": {
            **actual,
            "applicable_pairs_per_library": width["summary"][  # type: ignore[index]
                "applicable_route_profile_pairs"
            ],
            "unimplemented_pairs_per_library": width["summary"][  # type: ignore[index]
                "unimplemented_applicable_pairs"
            ],
            "declared_maximum_build_cells": len(selected)
            * int(
                width["summary"]["declared_maximum_build_cells_one_family"]  # type: ignore[index]
            ),
            "locally_qualified_routes": width["summary"]["qualified_routes"],  # type: ignore[index]
            "locally_executable_per_library": width["summary"][  # type: ignore[index]
                "feasible_full_path_executions"
            ],
        },
    }
    stable_body = {
        **body,
        "summary": {
            key: value
            for key, value in body["summary"].items()
            if not key.startswith("locally_")
        },
    }
    # This projection is derived entirely from the already-pinned width
    # authority.  Keep it out of the immutable batch identity so adding
    # applicability visibility cannot invalidate historical evidence.
    stable_body.pop("execution_pairs", None)
    canonical = json.dumps(stable_body, sort_keys=True, separators=(",", ":")).encode()
    return {**body, "batch_digest": hashlib.sha256(canonical).hexdigest()}


def project_width_batch_readiness(
    batch: dict[str, object], reviewed_recipes: list[dict[str, object]]
) -> dict[str, object]:
    """Attach recipe readiness without mutating the immutable batch binding."""

    recipes = {
        str(row["id"]): row for row in reviewed_recipes if row["kind"] == "native"
    }
    libraries = []
    blockers = []
    ready = 0
    materializable = 0
    for raw in batch["libraries"]:  # type: ignore[index]
        row = dict(raw)
        recipe = recipes.get(str(row["recipe_id"]))
        if recipe is None:
            recipe_state = "recipe-required"
            reason = f'{row["label"]} {row["version"]} needs a reviewed native recipe'
            blockers.append(reason)
        elif recipe["url"] != row["url"] or recipe["sha256"] != row["sha256"]:
            recipe_state = "recipe-source-mismatch"
            reason = f'{row["label"]} recipe does not match the pinned source authority'
            blockers.append(reason)
        else:
            recipe_state = "recipe-ready"
            reason = ""
            ready += 1
        applicability = recipe.get("applicability", {}) if recipe else {}
        applicable_pairs = [
            pair
            for pair in batch.get("execution_pairs", [])
            if (
                not applicability.get("target_os")
                or pair["target_os"] in applicability["target_os"]
            )
            and (
                not applicability.get("architectures")
                or pair["architecture"] in applicability["architectures"]
            )
            and (
                not applicability.get("compiler_families")
                or pair["compiler_family"] in applicability["compiler_families"]
            )
            and pair["route_id"] not in applicability.get("excluded_routes", [])
        ]
        if recipe_state == "recipe-ready":
            materializable += len(applicable_pairs)
        libraries.append(
            {
                **row,
                "recipe_state": recipe_state,
                "blocker": reason,
                "applicable_route_ids": list(
                    dict.fromkeys(str(pair["route_id"]) for pair in applicable_pairs)
                ),
                "applicable_executions": len(applicable_pairs),
            }
        )

    executions_per_library = int(
        batch["summary"]["executions_per_library"]  # type: ignore[index]
    )
    locally_executable = int(
        batch["summary"]["locally_executable_per_library"]  # type: ignore[index]
    )
    qualified_routes = int(batch["summary"]["locally_qualified_routes"])  # type: ignore[index]
    route_profiles = int(batch["summary"]["route_profiles"])  # type: ignore[index]
    if qualified_routes < route_profiles:
        blockers.append(
            f"{route_profiles - qualified_routes} of {route_profiles} route profiles are not locally qualified"
        )
    projected = {
        **batch,
        "libraries": libraries,
        "readiness": {
            "source_pins": len(libraries),
            "recipe_ready_libraries": ready,
            "recipe_blocked_libraries": len(libraries) - ready,
            "toolchain_ready_routes": qualified_routes,
            "toolchain_blocked_routes": route_profiles - qualified_routes,
            "materializable_executions": materializable,
            "blocked_executions": len(libraries) * executions_per_library
            - materializable,
            "queue_state": "not-materialized-disarmed",
            "blockers": blockers,
        },
    }
    return projected
