"""Validated catalogue of the FIDB coverage possibility space.

This authority is intentionally broader than the executable worker inventory.
It records the dimensions and bounded planning profiles that operators want to
reason about without implying that every cross-product is meaningful or ready.
"""

from __future__ import annotations

from pathlib import Path
import tomllib

COVERAGE_UNIVERSE_SCHEMA = "fidb-coverage-universe/v2"
MATRIX_ROLES = {
    "multiplier",
    "applicability",
    "bounded-profile",
    "analysis-reuse",
    "policy-control",
}
CATALOG_STATES = {"catalogued", "desired", "guarded", "study-observed"}
LANGUAGE_STATES = {"active-scope", "designed", "vocabulary-only"}
EVIDENCE_CLASSES = {"measured", "proposed", "provisional", "assumption"}


def _non_empty_strings(value: object, field: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item for item in value)
    ):
        raise ValueError(f"{field} must be a non-empty string list")
    return list(value)


def _unique_rows(
    rows: object, kind: str, required: set[str]
) -> list[dict[str, object]]:
    if not isinstance(rows, list) or not rows:
        raise ValueError(f"coverage universe must contain at least one {kind}")
    result: list[dict[str, object]] = []
    seen: set[str] = set()
    for index, raw in enumerate(rows):
        if not isinstance(raw, dict):
            raise ValueError(f"{kind} row {index} must be a table")
        missing = required - set(raw)
        if missing:
            raise ValueError(f"{kind} row {index} missing {sorted(missing)}")
        row = dict(raw)
        row_id = str(row["id"])
        if not row_id or row_id in seen:
            raise ValueError(f"duplicate or empty {kind} id: {row_id!r}")
        seen.add(row_id)
        result.append(row)
    return result


def load_coverage_universe(path: str | Path) -> dict[str, object]:
    """Load and validate the conceptual coverage authority."""

    universe_path = Path(path)
    document = tomllib.loads(universe_path.read_text(encoding="utf-8"))
    allowed = {
        "schema_version",
        "population",
        "dimension",
        "language",
        "compiler_family",
        "profile",
        "scenario",
    }
    unknown = set(document) - allowed
    if unknown:
        raise ValueError(f"unknown coverage universe fields: {sorted(unknown)}")
    if document.get("schema_version") != COVERAGE_UNIVERSE_SCHEMA:
        raise ValueError(
            f"unsupported coverage universe schema: {document.get('schema_version')}"
        )

    population = document.get("population")
    population_fields = {
        "published_four_source_n80_families",
        "tier_zero_families",
        "published_priority_head_families",
        "nine_source_candidate_spine_keys",
        "nine_source_shared_frontier_keys",
        "nine_source_n80_candidate_rank",
        "global_family_lower_estimate",
        "global_family_central_estimate",
        "global_family_upper_estimate",
        "population_caveat",
    }
    if not isinstance(population, dict) or set(population) != population_fields:
        raise ValueError("coverage population has unexpected or missing fields")
    for field in population_fields - {"population_caveat"}:
        if not isinstance(population[field], int) or int(population[field]) <= 0:
            raise ValueError(f"coverage population {field} must be positive")
    if population["published_priority_head_families"] != (
        population["published_four_source_n80_families"]
        + population["tier_zero_families"]
    ):
        raise ValueError(
            "published priority head must include four-source N80 plus Tier 0"
        )
    if not (
        population["nine_source_n80_candidate_rank"]
        <= population["nine_source_shared_frontier_keys"]
        <= population["nine_source_candidate_spine_keys"]
    ):
        raise ValueError(
            "nine-source N80, frontier and spine must be monotonically nested"
        )
    if not (
        population["global_family_lower_estimate"]
        <= population["global_family_central_estimate"]
        <= population["global_family_upper_estimate"]
    ):
        raise ValueError("global family estimates must be monotonically ordered")

    dimensions = _unique_rows(
        document.get("dimension"),
        "dimension",
        {"id", "label", "layer", "description", "matrix_role", "facets"},
    )
    for row in dimensions:
        if row["matrix_role"] not in MATRIX_ROLES:
            raise ValueError(f"invalid matrix role for dimension {row['id']}")
        row["facets"] = _non_empty_strings(
            row["facets"], f"dimension {row['id']} facets"
        )
        if "factor_ids" in row:
            row["factor_ids"] = _non_empty_strings(
                row["factor_ids"], f"dimension {row['id']} factor_ids"
            )

    languages = _unique_rows(
        document.get("language"),
        "language",
        {
            "id",
            "label",
            "state",
            "scope",
            "denominator",
            "treatment_axes",
            "toolchain_family_ids",
            "caveat",
            "authority",
        },
    )
    for row in languages:
        if row["state"] not in LANGUAGE_STATES:
            raise ValueError(f"invalid state for language {row['id']}")
        row["treatment_axes"] = _non_empty_strings(
            row["treatment_axes"], f"language {row['id']} treatment_axes"
        )
        row["toolchain_family_ids"] = _non_empty_strings(
            row["toolchain_family_ids"], f"language {row['id']} toolchain_family_ids"
        )
    language_ids = {str(row["id"]) for row in languages}

    compiler_families = _unique_rows(
        document.get("compiler_family"),
        "compiler family",
        {
            "id",
            "label",
            "route_scope",
            "state",
            "version_strategy",
            "settings",
            "language_ids",
        },
    )
    for row in compiler_families:
        if row["state"] not in CATALOG_STATES:
            raise ValueError(f"invalid state for compiler family {row['id']}")
        row["settings"] = _non_empty_strings(
            row["settings"], f"compiler family {row['id']} settings"
        )
        row["language_ids"] = _non_empty_strings(
            row["language_ids"], f"compiler family {row['id']} language_ids"
        )
        unknown_languages = set(row["language_ids"]) - language_ids
        if unknown_languages:
            raise ValueError(
                f"unknown languages for compiler family {row['id']}: {sorted(unknown_languages)}"
            )

    compiler_ids = {str(row["id"]) for row in compiler_families}
    for row in languages:
        unknown_compilers = set(row["toolchain_family_ids"]) - compiler_ids
        if unknown_compilers:
            raise ValueError(
                f"unknown compiler families for language {row['id']}: {sorted(unknown_compilers)}"
            )

    profiles = _unique_rows(
        document.get("profile"),
        "profile",
        {
            "id",
            "label",
            "compiler_family",
            "optimization",
            "controls",
            "route_scope",
            "state",
            "language_id",
            "evidence_class",
        },
    )
    for row in profiles:
        if row["compiler_family"] not in compiler_ids:
            raise ValueError(f"unknown compiler family for profile {row['id']}")
        if row["state"] not in CATALOG_STATES:
            raise ValueError(f"invalid state for profile {row['id']}")
        if row["language_id"] not in language_ids:
            raise ValueError(f"unknown language for profile {row['id']}")
        compiler_languages = next(
            compiler["language_ids"]
            for compiler in compiler_families
            if compiler["id"] == row["compiler_family"]
        )
        if row["language_id"] not in compiler_languages:
            raise ValueError(
                f"profile {row['id']} uses a compiler outside its language scope"
            )
        if row["evidence_class"] not in EVIDENCE_CLASSES:
            raise ValueError(f"invalid evidence class for profile {row['id']}")
        row["controls"] = _non_empty_strings(
            row["controls"], f"profile {row['id']} controls"
        )

    scenarios = _unique_rows(
        document.get("scenario"),
        "scenario",
        {
            "id",
            "label",
            "library_families",
            "releases",
            "routes",
            "profiles",
            "unique_executions",
            "replay_multiplier",
            "scope",
            "caveat",
            "language_id",
            "evidence_class",
            "authority",
        },
    )
    for row in scenarios:
        if row["language_id"] not in language_ids:
            raise ValueError(f"unknown language for scenario {row['id']}")
        if row["evidence_class"] not in EVIDENCE_CLASSES:
            raise ValueError(f"invalid evidence class for scenario {row['id']}")
        fields = (
            "library_families",
            "releases",
            "routes",
            "profiles",
            "replay_multiplier",
        )
        if any(
            not isinstance(row[field], int) or int(row[field]) <= 0 for field in fields
        ):
            raise ValueError(
                f"scenario {row['id']} multipliers must be positive integers"
            )
        expected = (
            int(row["library_families"])
            * int(row["releases"])
            * int(row["routes"])
            * int(row["profiles"])
        )
        if row["unique_executions"] != expected:
            raise ValueError(
                f"scenario {row['id']} unique_executions must equal its multipliers"
            )
        row["replayed_executions"] = expected * int(row["replay_multiplier"])

    return {
        "schema_version": COVERAGE_UNIVERSE_SCHEMA,
        "population": dict(population),
        "dimensions": dimensions,
        "languages": languages,
        "compiler_families": compiler_families,
        "profiles": profiles,
        "scenarios": scenarios,
        "authority_path": str(universe_path),
    }
