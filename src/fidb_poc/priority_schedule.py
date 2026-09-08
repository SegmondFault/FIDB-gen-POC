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
) -> str:
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

    projected = []
    for raw in overlay["subjects"]:  # type: ignore[assignment]
        subject = dict(raw)
        research_key = subject["research_key"]
        research = candidates.get(str(research_key)) if research_key else None
        matching_recipes = []
        for key in (subject["id"], subject["source_family"]):
            matching_recipes.extend(recipe_rows.get(str(key), []))
        matching_recipes = list(
            {str(row["id"]): row for row in matching_recipes}.values()
        )
        native_recipe = any(row.get("kind") == "native" for row in matching_recipes)
        limited_recipe = bool(matching_recipes) and not native_recipe
        source_available = bool(
            (
                research
                and (research["source_pinned"] or research["research_source_pinned"])
            )
            or matching_recipes
        )
        width_batch_bound = bool(research and research["width_batch_bound"])
        qualification_satisfied = bool(research and research["qualification_satisfied"])
        projected.append(
            {
                **subject,
                "research_overlap": research is not None,
                "research_rank": research["rank"] if research else None,
                "research_display_name": research["display_name"] if research else None,
                "research_source_cached": bool(
                    research and research["research_source_cached"]
                ),
                "build_source_cached": bool(research and research["source_cached"]),
                "recipe_state": (
                    "reviewed-native"
                    if native_recipe
                    else "reviewed-limited" if limited_recipe else "required"
                ),
                "recipe_ids": sorted(str(row["id"]) for row in matching_recipes),
                "width_batch_bound": width_batch_bound,
                "qualification_satisfied": qualification_satisfied,
                "stage": _stage(
                    source_available=source_available,
                    native_recipe=native_recipe,
                    width_batch_bound=width_batch_bound,
                    qualification_satisfied=qualification_satisfied,
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
        "native_recipe_ready": sum(
            row["recipe_state"] == "reviewed-native" for row in projected
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
        "programme_id": programme["id"],
        "schedule_digest": hashlib.sha256(
            json.dumps(status_core, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "summary": summary,
        "cohorts": cohorts,
    }
