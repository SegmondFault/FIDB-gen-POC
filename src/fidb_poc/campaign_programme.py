"""Read-only projection of the published four-source C80 programme.

The research frontier is deliberately kept separate from reviewed source,
recipe, qualification and queue authorities.  This module joins those layers
for planning without promoting candidates or mutating operational state.
"""

from __future__ import annotations

import csv
import hashlib
from pathlib import Path
import re
import tomllib

from .source_packs import MANAGED_SOURCE_DOWNLOADS, load_source_pack
from .toolchain_cache import inspect_cached

PROGRAMME_SCHEMA = "fidb-campaign-programme/v1"
PROGRAMME_STATUS_SCHEMA = "fidb-campaign-programme-status/v1"

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PROGRAMME_FIELDS = {
    "schema_version",
    "id",
    "label",
    "state",
    "language_id",
    "candidate_authority",
    "candidate_authority_sha256",
    "candidate_population",
    "candidate_cumulative_proxy_pct",
    "cohort_size",
    "cohort_count",
    "final_cohort_size",
    "width_authority",
    "width_authority_sha256",
    "qualification_template",
    "qualification_template_sha256",
    "route_profiles_per_library",
    "treatments_per_route",
    "campaign_executions_per_library",
    "qualification_routes_per_library",
    "qualification_treatment_id",
    "qualification_workers",
    "qualification_build_jobs_per_cell",
    "evidence_class",
    "caveat",
    "pipeline",
    "identity_aliases",
    "cohorts",
}
_COHORT_FIELDS = {
    "id",
    "order",
    "label",
    "candidate_rank_start",
    "candidate_rank_end",
    "capacity",
    "state",
}
_CANDIDATE_HEADER = (
    "popularity_rank",
    "canonical_key",
    "display_name",
    "source_breadth",
    "in_debian_popcon",
    "in_homebrew",
    "in_vcpkg",
    "in_conan",
    "debian_installed_max",
    "debian_regular_use_max",
    "debian_installed_sum",
    "debian_regular_use_sum",
    "homebrew_installs_365d",
    "homebrew_requested_365d",
    "homebrew_reverse_dependencies",
    "vcpkg_reverse_dependencies",
    "conan_literal_reverse_dependencies",
    "popularity_proxy_raw",
    "popularity_proxy_share_pct",
    "cumulative_popularity_proxy_pct",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _project_path(root: Path, value: object, label: str) -> Path:
    relative = Path(str(value))
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"{label} must stay inside the project")
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ValueError(f"{label} must stay inside the project")
    return path


def _verify_digest(path: Path, expected: object, label: str) -> str:
    expected_text = str(expected)
    if _DIGEST.fullmatch(expected_text) is None:
        raise ValueError(f"{label} sha256 is invalid")
    observed = _sha256(path)
    if observed != expected_text:
        raise ValueError(
            f"{label} digest mismatch: expected {expected_text}, observed {observed}"
        )
    return observed


def _candidate_rows(path: Path) -> list[dict[str, object]]:
    with path.open("r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        if tuple(reader.fieldnames or ()) != _CANDIDATE_HEADER:
            raise ValueError("C80 candidate authority has an unexpected header")
        raw_rows = list(reader)

    rows: list[dict[str, object]] = []
    keys: set[str] = set()
    for expected_rank, raw in enumerate(raw_rows, start=1):
        rank = int(raw["popularity_rank"])
        key = raw["canonical_key"]
        if rank != expected_rank:
            raise ValueError("C80 candidate ranks must be contiguous from one")
        if not key or key in keys:
            raise ValueError("C80 candidate keys must be non-empty and unique")
        keys.add(key)
        rows.append(
            {
                "rank": rank,
                "canonical_key": key,
                "display_name": raw["display_name"],
                "source_breadth": int(raw["source_breadth"]),
                "popularity_proxy_share_pct": float(raw["popularity_proxy_share_pct"]),
                "cumulative_popularity_proxy_pct": float(
                    raw["cumulative_popularity_proxy_pct"]
                ),
            }
        )
    return rows


def _reviewed_sources(root: Path) -> dict[str, dict[str, object]]:
    """Return the broadest reviewed C source pack, with verified cache state."""

    packs = [
        load_source_pack(path)
        for path in sorted((root / "sources").glob("c-top*-v1.toml"))
    ]
    if not packs:
        return {}
    pack = max(packs, key=lambda row: len(row["source"]))
    downloads = root / MANAGED_SOURCE_DOWNLOADS
    result = {}
    for source in pack["source"]:
        inspection = inspect_cached(downloads, str(source["sha256"]))
        result[str(source["id"])] = {
            "id": source["id"],
            "label": source["label"],
            "version": source["version"],
            "authority_path": str(Path(str(pack["catalog_path"])).relative_to(root)),
            "authority_sha256": pack["catalog_sha256"],
            "cache_state": inspection.state,
            "cache_bytes": inspection.bytes,
        }
    return result


def _candidate_stage(candidate: dict[str, object]) -> str:
    if not candidate["screened"]:
        return "candidate-screen"
    if not candidate["source_pinned"] or not candidate["source_cached"]:
        return "source-pin-cache"
    if not candidate["recipe_ready"]:
        return "recipe-author"
    if not candidate["width_batch_bound"]:
        return "width-batch"
    if not candidate["qualification_satisfied"]:
        return "recipe-qualification"
    return "queue-candidate"


def _native_recipe_ids(root: Path) -> set[str]:
    result = set()
    for path in sorted((root / "recipes").glob("*.toml")):
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        name = document.get("name")
        if name:
            result.add(str(name))
    return result


def compile_campaign_programme(
    project_root: str | Path,
    programme_path: str | Path = "campaigns/c80-four-source-n80-v1.toml",
    *,
    width_batches: list[dict[str, object]] | None = None,
    recipes: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    """Validate and project the C80 research frontier against current readiness."""

    root = Path(project_root).expanduser().resolve()
    path = _project_path(root, programme_path, "campaign programme")
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    missing = sorted(_PROGRAMME_FIELDS - document.keys())
    extra = sorted(document.keys() - _PROGRAMME_FIELDS)
    if missing or extra:
        raise ValueError(
            "campaign programme fields are invalid: "
            + "; ".join(
                filter(
                    None,
                    (
                        "missing " + ", ".join(missing) if missing else "",
                        "unknown " + ", ".join(extra) if extra else "",
                    ),
                )
            )
        )
    if document["schema_version"] != PROGRAMME_SCHEMA:
        raise ValueError("unsupported campaign programme schema")
    if document["language_id"] != "c" or document["state"] != "planned-disarmed":
        raise ValueError("C80 campaign programme must be C and planned-disarmed")

    candidate_path = _project_path(
        root, document["candidate_authority"], "candidate authority"
    )
    width_path = _project_path(root, document["width_authority"], "width authority")
    template_path = _project_path(
        root, document["qualification_template"], "qualification template"
    )
    candidate_digest = _verify_digest(
        candidate_path,
        document["candidate_authority_sha256"],
        "candidate authority",
    )
    width_digest = _verify_digest(
        width_path, document["width_authority_sha256"], "width authority"
    )
    template_digest = _verify_digest(
        template_path,
        document["qualification_template_sha256"],
        "qualification template",
    )
    candidates = _candidate_rows(candidate_path)
    population = int(document["candidate_population"])
    if len(candidates) != population:
        raise ValueError("C80 candidate population does not match the authority")
    if (
        abs(
            float(candidates[-1]["cumulative_popularity_proxy_pct"])
            - float(document["candidate_cumulative_proxy_pct"])
        )
        > 0.0000005
    ):
        raise ValueError("C80 terminal cumulative proxy does not match the authority")

    raw_aliases = document["identity_aliases"]
    aliases = {str(row["candidate_key"]): str(row["subject_id"]) for row in raw_aliases}
    if len(aliases) != len(raw_aliases):
        raise ValueError("campaign identity aliases must be unique")
    sources = _reviewed_sources(root)
    recipe_ids = (
        {str(row["name"]) for row in recipes if row.get("kind") == "native"}
        if recipes is not None
        else _native_recipe_ids(root)
    )
    batches_by_subject: dict[str, dict[str, object]] = {}
    for batch in width_batches or []:
        for library in batch.get("libraries", []):
            batches_by_subject[str(library["id"])] = batch

    projected_candidates = []
    for raw in candidates:
        subject_id = aliases.get(str(raw["canonical_key"]), str(raw["canonical_key"]))
        source = sources.get(subject_id)
        batch = batches_by_subject.get(subject_id)
        qualification = batch.get("qualification") if batch else None
        candidate = {
            **raw,
            "subject_id": subject_id,
            "screened": source is not None,
            "source_pinned": source is not None,
            "source_cached": bool(
                source and source["cache_state"] == "verified-cached"
            ),
            "source": source,
            "recipe_ready": subject_id in recipe_ids,
            "width_batch_bound": batch is not None,
            "width_batch_id": batch.get("id") if batch else None,
            "qualification_state": (
                qualification.get("state") if qualification else "not-defined"
            ),
            "qualification_satisfied": bool(
                qualification and qualification.get("satisfied")
            ),
        }
        candidate["stage"] = _candidate_stage(candidate)
        projected_candidates.append(candidate)

    raw_cohorts = document["cohorts"]
    if len(raw_cohorts) != int(document["cohort_count"]):
        raise ValueError("campaign cohort count does not match the authority")
    projected_cohorts = []
    next_rank = 1
    for expected_order, raw in enumerate(raw_cohorts, start=1):
        if set(raw) != _COHORT_FIELDS:
            raise ValueError("campaign cohort fields are invalid")
        start = int(raw["candidate_rank_start"])
        end = int(raw["candidate_rank_end"])
        capacity = int(raw["capacity"])
        if (
            int(raw["order"]) != expected_order
            or start != next_rank
            or end - start + 1 != capacity
            or raw["state"] != "planned-disarmed"
        ):
            raise ValueError("campaign cohorts must be contiguous and disarmed")
        rows = projected_candidates[start - 1 : end]
        counts = {
            "screened": sum(bool(row["screened"]) for row in rows),
            "source_pinned": sum(bool(row["source_pinned"]) for row in rows),
            "source_cached": sum(bool(row["source_cached"]) for row in rows),
            "recipe_ready": sum(bool(row["recipe_ready"]) for row in rows),
            "width_batch_bound": sum(bool(row["width_batch_bound"]) for row in rows),
            "qualification_satisfied": sum(
                bool(row["qualification_satisfied"]) for row in rows
            ),
        }
        stage = next(
            (
                stage
                for stage in document["pipeline"]["stages"]
                if any(row["stage"] == stage for row in rows)
            ),
            "queue-candidate",
        )
        projected_cohorts.append(
            {
                **raw,
                "stage": stage,
                "counts": counts,
                "planned_qualification_cells": capacity
                * int(document["qualification_routes_per_library"]),
                "planned_campaign_executions": capacity
                * int(document["campaign_executions_per_library"]),
                "candidates": rows,
            }
        )
        next_rank = end + 1
    if next_rank - 1 != population:
        raise ValueError("campaign cohorts do not cover the candidate population")
    if int(raw_cohorts[-1]["capacity"]) != int(document["final_cohort_size"]):
        raise ValueError("campaign final cohort size does not match the authority")

    stage_counts = {
        stage: sum(row["stage"] == stage for row in projected_candidates)
        for stage in document["pipeline"]["stages"]
    }
    summary = {
        "candidate_population": population,
        "cohorts": len(projected_cohorts),
        "full_cohorts": sum(
            int(row["capacity"]) == int(document["cohort_size"])
            for row in projected_cohorts
        ),
        "final_cohort_size": int(projected_cohorts[-1]["capacity"]),
        "screened_candidates": sum(
            bool(row["screened"]) for row in projected_candidates
        ),
        "source_pinned_candidates": sum(
            bool(row["source_pinned"]) for row in projected_candidates
        ),
        "source_cached_candidates": sum(
            bool(row["source_cached"]) for row in projected_candidates
        ),
        "recipe_ready_candidates": sum(
            bool(row["recipe_ready"]) for row in projected_candidates
        ),
        "qualification_satisfied_candidates": sum(
            bool(row["qualification_satisfied"]) for row in projected_candidates
        ),
        "planned_qualification_cells": population
        * int(document["qualification_routes_per_library"]),
        "planned_campaign_executions": population
        * int(document["campaign_executions_per_library"]),
    }
    return {
        "schema_version": PROGRAMME_STATUS_SCHEMA,
        "id": document["id"],
        "label": document["label"],
        "state": document["state"],
        "language_id": document["language_id"],
        "evidence_class": document["evidence_class"],
        "caveat": document["caveat"],
        "candidate_cumulative_proxy_pct": document["candidate_cumulative_proxy_pct"],
        "cohort_size": document["cohort_size"],
        "route_profiles_per_library": document["route_profiles_per_library"],
        "treatments_per_route": document["treatments_per_route"],
        "campaign_executions_per_library": document["campaign_executions_per_library"],
        "qualification_routes_per_library": document[
            "qualification_routes_per_library"
        ],
        "authorities": {
            "programme": str(path.relative_to(root)),
            "programme_sha256": _sha256(path),
            "candidates": str(candidate_path.relative_to(root)),
            "candidates_sha256": candidate_digest,
            "width": str(width_path.relative_to(root)),
            "width_sha256": width_digest,
            "qualification_template": str(template_path.relative_to(root)),
            "qualification_template_sha256": template_digest,
        },
        "pipeline": document["pipeline"],
        "summary": summary,
        "stage_counts": stage_counts,
        "cohorts": projected_cohorts,
    }
