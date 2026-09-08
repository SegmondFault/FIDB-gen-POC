"""Compile an operator-priority overlay into a gated campaign schedule."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import tomllib
from typing import Mapping, Sequence

OVERLAY_SCHEMA = "fidb-priority-overlay/v1"
STATUS_SCHEMA = "fidb-priority-schedule-status/v1"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_TOP_LEVEL_FIELDS = {
    "schema_version",
    "id",
    "label",
    "state",
    "language_id",
    "cohort_size",
    "selection_basis",
    "component_policy",
    "scheduling_policy",
    "subject",
}
_SUBJECT_FIELDS = {"order", "id", "source_family", "aliases", "research_key"}


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{label} must be a non-empty trimmed string")
    return value


def _identifier(value: object, label: str) -> str:
    result = _text(value, label)
    if _IDENTIFIER.fullmatch(result) is None:
        raise ValueError(f"{label} must be a stable identifier")
    return result


def _project_path(root: Path, value: str | Path, label: str) -> tuple[Path, str]:
    fragment = Path(value)
    candidate = fragment if fragment.is_absolute() else root / fragment
    if candidate.is_symlink():
        raise ValueError(f"{label} cannot be a symlink")
    path = candidate.resolve()
    try:
        reference = str(path.relative_to(root))
    except ValueError as error:
        raise ValueError(f"{label} escapes the project root") from error
    if not path.is_file():
        raise ValueError(f"{label} is not a regular file: {reference}")
    return path, reference


def load_priority_overlay(
    project_root: str | Path,
    authority: str | Path = "coverage/c-malware-priority-v1.toml",
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    path, reference = _project_path(root, authority, "priority overlay")
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if set(document) != _TOP_LEVEL_FIELDS:
        raise ValueError(
            "priority overlay fields are invalid: "
            f"missing {sorted(_TOP_LEVEL_FIELDS - set(document))}; "
            f"unknown {sorted(set(document) - _TOP_LEVEL_FIELDS)}"
        )
    if document["schema_version"] != OVERLAY_SCHEMA:
        raise ValueError("priority overlay has an unsupported schema_version")
    if document["state"] != "planned-disarmed":
        raise ValueError("priority overlay must remain planned-disarmed")
    cohort_size = document["cohort_size"]
    if (
        not isinstance(cohort_size, int)
        or isinstance(cohort_size, bool)
        or cohort_size < 2
    ):
        raise ValueError(
            "priority overlay cohort_size must be an integer of at least two"
        )
    subjects = document["subject"]
    if not isinstance(subjects, list) or not subjects:
        raise ValueError("priority overlay must contain [[subject]] rows")
    seen_ids: set[str] = set()
    normalized = []
    for position, raw in enumerate(subjects, start=1):
        if not isinstance(raw, dict) or not set(raw).issubset(_SUBJECT_FIELDS):
            raise ValueError(f"priority subject {position} fields are invalid")
        if set(raw) != _SUBJECT_FIELDS:
            missing = sorted(_SUBJECT_FIELDS - set(raw))
            raise ValueError(f"priority subject {position} is missing {missing}")
        if raw["order"] != position:
            raise ValueError(
                "priority subject order must be contiguous and file-ordered"
            )
        subject_id = _identifier(raw["id"], f"priority subject {position} id")
        if subject_id in seen_ids:
            raise ValueError(f"duplicate priority subject: {subject_id}")
        seen_ids.add(subject_id)
        aliases = raw["aliases"]
        if not isinstance(aliases, list) or any(
            not isinstance(alias, str) or not alias or alias != alias.strip()
            for alias in aliases
        ):
            raise ValueError(f"priority subject {subject_id} aliases must be strings")
        if len(set(aliases)) != len(aliases):
            raise ValueError(
                f"priority subject {subject_id} aliases contain duplicates"
            )
        research_key = raw["research_key"]
        if research_key is False:
            research_key = None
        elif research_key is not None:
            research_key = _identifier(
                research_key, f"priority subject {subject_id} research_key"
            )
        normalized.append(
            {
                "order": position,
                "id": subject_id,
                "source_family": _identifier(
                    raw["source_family"],
                    f"priority subject {subject_id} source_family",
                ),
                "aliases": list(aliases),
                "research_key": research_key,
            }
        )
    return {
        "schema_version": OVERLAY_SCHEMA,
        "id": _identifier(document["id"], "priority overlay id"),
        "label": _text(document["label"], "priority overlay label"),
        "state": document["state"],
        "language_id": _identifier(document["language_id"], "priority language_id"),
        "cohort_size": cohort_size,
        "selection_basis": _text(document["selection_basis"], "selection_basis"),
        "component_policy": _text(document["component_policy"], "component_policy"),
        "scheduling_policy": _text(document["scheduling_policy"], "scheduling_policy"),
        "subjects": normalized,
        "authority_path": reference,
        "authority_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _stage(
    *,
    source_available: bool,
    native_recipe: bool,
    width_batch_bound: bool,
    qualification_satisfied: bool,
    runtime_provider: bool = False,
    runtime_provider_ready: bool = False,
) -> str:
    if runtime_provider:
        return "runtime-batch" if runtime_provider_ready else "runtime-acquisition"
    if not source_available:
        return "source-pin-cache"
    if not native_recipe:
        return "recipe-author"
    if not width_batch_bound:
        return "width-batch"
    if not qualification_satisfied:
        return "recipe-qualification"
    return "queue-candidate"


def compile_priority_schedule(
    project_root: str | Path,
    authority: str | Path,
    *,
    programme: Mapping[str, object],
    recipes: Sequence[Mapping[str, object]],
    source_acquisition: Mapping[str, object] | None = None,
    recipe_preparation: Mapping[str, object] | None = None,
    runtime_libraries: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Join priority order to C80 membership and current build readiness."""

    root = Path(project_root).expanduser().resolve()
    overlay = load_priority_overlay(root, authority)
    candidates = {
        str(candidate["canonical_key"]): candidate
        for cohort in programme["cohorts"]  # type: ignore[index]
        for candidate in cohort["candidates"]
    }
    recipe_rows: dict[str, list[Mapping[str, object]]] = {}
    for recipe in recipes:
        recipe_rows.setdefault(str(recipe["name"]), []).append(recipe)
    priority_sources = {
        str(row["candidate_key"]): row
        for row in (source_acquisition or {}).get("candidates", [])  # type: ignore[union-attr]
    }
    prepared_families = {
        str(row["source_family"]): row
        for row in (recipe_preparation or {}).get("families", [])  # type: ignore[union-attr]
    }
    runtime_providers = {
        str(row["subject_id"]): row
        for row in (runtime_libraries or {}).get("providers", [])  # type: ignore[union-attr]
    }

    projected = []
    for raw in overlay["subjects"]:  # type: ignore[assignment]
        subject = dict(raw)
        research_key = subject["research_key"]
        research = candidates.get(str(research_key)) if research_key else None
        priority_source = priority_sources.get(str(subject["source_family"]))
        prepared = prepared_families.get(str(subject["source_family"]))
        runtime_provider = runtime_providers.get(str(subject["id"]))
        matching_recipes = []
        for key in (subject["id"], subject["source_family"]):
            matching_recipes.extend(recipe_rows.get(str(key), []))
        matching_recipes = list(
            {str(row["id"]): row for row in matching_recipes}.values()
        )
        source_sha256 = priority_source.get("sha256") if priority_source else None
        source_version = priority_source.get("version") if priority_source else None
        native_recipe = any(
            row.get("kind") == "native"
            and (
                source_sha256 is None
                or (
                    row.get("sha256") == source_sha256
                    and row.get("version") == source_version
                )
            )
            for row in matching_recipes
        )
        native_source_mismatch = (
            not native_recipe
            and any(row.get("kind") == "native" for row in matching_recipes)
            and source_sha256 is not None
        )
        limited_recipe = bool(matching_recipes) and not native_recipe
        priority_source_pinned = bool(
            priority_source and priority_source["status"] == "pinned"
        )
        priority_source_cached = bool(
            priority_source and priority_source["receipt_cached"]
        )
        source_available = (
            priority_source_cached
            if priority_source
            else bool(
                (
                    research
                    and (
                        research["source_pinned"] or research["research_source_pinned"]
                    )
                )
                or matching_recipes
            )
        )
        width_batch_bound = bool(research and research["width_batch_bound"])
        qualification_satisfied = bool(research and research["qualification_satisfied"])
        runtime_provider_ready = bool(
            runtime_provider
            and int(runtime_provider["cells"]) > 0
            and int(runtime_provider["ready_cells"]) == int(runtime_provider["cells"])
        )
        projected.append(
            {
                **subject,
                "research_overlap": research is not None,
                "research_rank": research["rank"] if research else None,
                "research_display_name": research["display_name"] if research else None,
                "research_source_cached": bool(
                    research and research["research_source_cached"]
                ),
                "priority_source_pinned": priority_source_pinned,
                "priority_source_cached": priority_source_cached,
                "priority_source_version": source_version,
                "priority_source_last_verified_utc": (
                    priority_source.get("last_verified_utc")
                    if priority_source
                    else None
                ),
                "build_source_cached": priority_source_cached
                or bool(research and research["source_cached"]),
                "recipe_state": (
                    "reviewed-runtime"
                    if runtime_provider
                    else "reviewed-native" if native_recipe
                    else (
                        "source-mismatch"
                        if native_source_mismatch
                        else (
                            "reviewed-limited"
                            if limited_recipe
                            else "prepared-not-executable" if prepared else "required"
                        )
                    )
                ),
                "recipe_ids": sorted(str(row["id"]) for row in matching_recipes),
                "recipe_preparation_state": (
                    prepared.get("state") if prepared else None
                ),
                "recipe_preparation_blockers": (
                    list(prepared["blockers"]) if prepared else []
                ),
                "planned_adapter": (
                    prepared.get("planned_adapter") if prepared else None
                ),
                "runtime_provider_kind": (
                    runtime_provider.get("kind") if runtime_provider else None
                ),
                "runtime_provider_cells": (
                    int(runtime_provider["cells"]) if runtime_provider else 0
                ),
                "runtime_provider_ready_cells": (
                    int(runtime_provider["ready_cells"]) if runtime_provider else 0
                ),
                "runtime_provider_blocked_cells": (
                    int(runtime_provider["blocked_cells"]) if runtime_provider else 0
                ),
                "width_batch_bound": width_batch_bound,
                "qualification_satisfied": qualification_satisfied,
                "stage": _stage(
                    source_available=source_available,
                    native_recipe=native_recipe,
                    width_batch_bound=width_batch_bound,
                    qualification_satisfied=qualification_satisfied,
                    runtime_provider=runtime_provider is not None,
                    runtime_provider_ready=runtime_provider_ready,
                ),
            }
        )

    cohort_size = int(overlay["cohort_size"])
    cells_per_subject = int(programme["campaign_executions_per_library"])
    qualification_per_family = int(programme["qualification_routes_per_library"])
    cohorts = []
    for offset in range(0, len(projected), cohort_size):
        rows = projected[offset : offset + cohort_size]
        family_count = len({str(row["source_family"]) for row in rows})
        cohorts.append(
            {
                "id": f'{overlay["id"]}-{offset + 1:03d}-{offset + len(rows):03d}',
                "order": len(cohorts) + 1,
                "state": "planned-disarmed",
                "priority_start": offset + 1,
                "priority_end": offset + len(rows),
                "capacity": len(rows),
                "source_families": family_count,
                "planned_subject_executions": len(rows) * cells_per_subject,
                "planned_source_qualification_cells": family_count
                * qualification_per_family,
                "subjects": rows,
            }
        )

    source_families = {str(row["source_family"]) for row in projected}
    research_keys = {
        str(row["research_key"]) for row in projected if row["research_overlap"]
    }
    summary = {
        "subjects": len(projected),
        "source_families": len(source_families),
        "cohorts": len(cohorts),
        "final_cohort_size": len(cohorts[-1]["subjects"]),
        "research_overlap_subjects": sum(
            bool(row["research_overlap"]) for row in projected
        ),
        "research_overlap_candidates": len(research_keys),
        "priority_additions": sum(not row["research_overlap"] for row in projected),
        "source_families_pinned": len(
            {
                str(row["source_family"])
                for row in projected
                if row["priority_source_pinned"]
            }
        ),
        "source_families_cached": len(
            {
                str(row["source_family"])
                for row in projected
                if row["priority_source_cached"]
            }
        ),
        "recipe_families_prepared": len(
            {
                str(row["source_family"])
                for row in projected
                if row["recipe_preparation_state"]
            }
        ),
        "native_recipe_ready": sum(
            row["recipe_state"] == "reviewed-native" for row in projected
        ),
        "runtime_provider_ready": sum(
            row["recipe_state"] == "reviewed-runtime"
            and row["runtime_provider_blocked_cells"] == 0
            for row in projected
        ),
        "executable_provider_ready": sum(
            row["recipe_state"] == "reviewed-native"
            or (
                row["recipe_state"] == "reviewed-runtime"
                and row["runtime_provider_blocked_cells"] == 0
            )
            for row in projected
        ),
        "limited_recipe_only": sum(
            row["recipe_state"] == "reviewed-limited" for row in projected
        ),
        "qualification_satisfied": sum(
            bool(row["qualification_satisfied"]) for row in projected
        ),
        "maximum_subject_executions": len(projected) * cells_per_subject,
        "maximum_source_qualification_cells": len(source_families)
        * qualification_per_family,
    }
    status_core = {
        "id": overlay["id"],
        "authority_sha256": overlay["authority_sha256"],
        "programme_sha256": programme["authorities"]["programme_sha256"],  # type: ignore[index]
        "subjects": projected,
    }
    return {
        "schema_version": STATUS_SCHEMA,
        "id": overlay["id"],
        "label": overlay["label"],
        "state": overlay["state"],
        "language_id": overlay["language_id"],
        "cohort_size": cohort_size,
        "selection_basis": overlay["selection_basis"],
        "component_policy": overlay["component_policy"],
        "scheduling_policy": overlay["scheduling_policy"],
        "authority_path": overlay["authority_path"],
        "authority_sha256": overlay["authority_sha256"],
        "source_acquisition": (
            {
                "config_path": source_acquisition["config_path"],
                "config_sha256": source_acquisition["config_sha256"],
                "lock_path": source_acquisition["lock_path"],
                "lock_sha256": source_acquisition["lock_sha256"],
                "receipt_path": source_acquisition["receipt_path"],
                "receipt_updated_utc": source_acquisition["receipt_updated_utc"],
                "summary": source_acquisition["summary"],
            }
            if source_acquisition
            else None
        ),
        "recipe_preparation": (
            {
                "authority_path": recipe_preparation["authority_path"],
                "authority_sha256": recipe_preparation["authority_sha256"],
                "summary": recipe_preparation["summary"],
            }
            if recipe_preparation
            else None
        ),
        "runtime_libraries": (
            {
                "authority_path": runtime_libraries["authority_path"],
                "authority_sha256": runtime_libraries["authority_sha256"],
                "provider_digest": runtime_libraries["provider_digest"],
                "summary": runtime_libraries["summary"],
            }
            if runtime_libraries
            else None
        ),
        "programme_id": programme["id"],
        "schedule_digest": hashlib.sha256(
            json.dumps(status_core, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "summary": summary,
        "cohorts": cohorts,
    }
