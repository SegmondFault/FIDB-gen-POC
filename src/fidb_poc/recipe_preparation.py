"""Strict, non-executable preparation plans for future native recipes."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import tomllib

from .priority_schedule import load_priority_overlay
from .source_acquisition import load_acquisition_lock

PREPARATION_SCHEMA = "fidb-recipe-preparation/v1"
STATUS_SCHEMA = "fidb-recipe-preparation-status/v1"
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*\Z")
_TOP_LEVEL_FIELDS = {
    "schema_version",
    "id",
    "label",
    "source_acquisition",
    "policy",
    "family",
}
_FAMILY_FIELDS = {
    "order",
    "source_family",
    "detection_subjects",
    "source_directory",
    "project_markers",
    "build_strategy",
    "planned_adapter",
    "expected_archives",
    "state",
    "blockers",
}
_STATES = {
    "recipe-ready",
    "runtime-provider-ready",
    "adapter-required",
    "component-contract-required",
    "dependency-contract-required",
    "specialist-adapter-required",
}


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{label} must be a non-empty trimmed string")
    return value


def _token(value: object, label: str) -> str:
    text = _text(value, label)
    if _TOKEN.fullmatch(text) is None:
        raise ValueError(f"{label} must be a safe token")
    return text


def _strings(value: object, label: str, *, empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not empty):
        raise ValueError(f"{label} must be a {'possibly empty ' if empty else ''}list")
    result = [_text(item, label) for item in value]
    if len(result) != len(set(result)):
        raise ValueError(f"{label} contains duplicates")
    return result


def load_recipe_preparation(
    project_root: str | Path,
    preparation: str | Path = "recipes/preparation/c-malware-priority-v1.toml",
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    relative = Path(preparation)
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or not path.is_file() or path.is_symlink():
        raise ValueError("recipe preparation authority must be a regular project file")
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if set(document) != _TOP_LEVEL_FIELDS:
        raise ValueError("recipe preparation authority fields are invalid")
    if document["schema_version"] != PREPARATION_SCHEMA:
        raise ValueError("recipe preparation authority schema is unsupported")

    preparation_id = _token(document["id"], "recipe preparation id")
    acquisition_id = _token(document["source_acquisition"], "source acquisition")
    overlay = load_priority_overlay(root, f"coverage/{preparation_id}.toml")
    if overlay["id"] != preparation_id:
        raise ValueError("recipe preparation and priority overlay ids differ")
    lock = load_acquisition_lock(root, acquisition_id)
    lock_rows = {
        str(row["candidate_key"]): row
        for row in lock["candidate"]
        if row["status"] == "pinned"
    }
    expected_subjects: dict[str, list[str]] = {}
    for subject in overlay["subjects"]:
        expected_subjects.setdefault(str(subject["source_family"]), []).append(
            str(subject["id"])
        )

    families = document["family"]
    if not isinstance(families, list) or not families:
        raise ValueError("recipe preparation authority requires family rows")
    normalized = []
    for order, row in enumerate(families, start=1):
        if not isinstance(row, dict) or set(row) != _FAMILY_FIELDS:
            raise ValueError(f"recipe preparation family {order} fields are invalid")
        if row["order"] != order:
            raise ValueError("recipe preparation family order must be contiguous")
        family = _token(row["source_family"], f"recipe family {order}")
        if family not in lock_rows:
            raise ValueError(f"recipe family {family} has no pinned source")
        subjects = _strings(row["detection_subjects"], f"{family} subjects")
        if subjects != expected_subjects.get(family):
            raise ValueError(
                f"recipe family {family} subjects differ from priority order"
            )
        state = _text(row["state"], f"{family} state")
        if state not in _STATES:
            raise ValueError(f"recipe family {family} state is unsupported")
        blockers = _strings(row["blockers"], f"{family} blockers", empty=True)
        ready_state = state in {"recipe-ready", "runtime-provider-ready"}
        if ready_state != (not blockers):
            raise ValueError(
                f"recipe family {family} must have blockers exactly when not ready"
            )
        source = lock_rows[family]
        normalized.append(
            {
                "order": order,
                "source_family": family,
                "detection_subjects": subjects,
                "source_directory": _text(
                    row["source_directory"], f"{family} source_directory"
                ),
                "project_markers": _strings(
                    row["project_markers"], f"{family} project_markers"
                ),
                "build_strategy": _text(
                    row["build_strategy"], f"{family} build_strategy"
                ),
                "planned_adapter": _token(
                    row["planned_adapter"], f"{family} planned_adapter"
                ),
                "expected_archives": _strings(
                    row["expected_archives"], f"{family} expected_archives"
                ),
                "state": state,
                "blockers": blockers,
                "source_version": source["version"],
                "source_sha256": source["sha256"],
                "source_url": source["url"],
            }
        )
    if list(expected_subjects) != [row["source_family"] for row in normalized]:
        raise ValueError("recipe preparation does not cover every source family once")
    return {
        "schema_version": STATUS_SCHEMA,
        "id": preparation_id,
        "label": _text(document["label"], "recipe preparation label"),
        "source_acquisition": acquisition_id,
        "policy": _text(document["policy"], "recipe preparation policy"),
        "authority_path": str(path.relative_to(root)),
        "authority_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "source_lock_path": str(Path(str(lock["lock_path"])).relative_to(root)),
        "source_lock_sha256": lock["lock_sha256"],
        "summary": {
            "source_families": len(normalized),
            "detection_subjects": sum(
                len(row["detection_subjects"]) for row in normalized
            ),
            "recipe_ready": sum(row["state"] == "recipe-ready" for row in normalized),
            "runtime_provider_ready": sum(
                row["state"] == "runtime-provider-ready" for row in normalized
            ),
            "prepared_not_executable": sum(
                row["state"]
                not in {"recipe-ready", "runtime-provider-ready"}
                for row in normalized
            ),
        },
        "families": normalized,
    }
