"""Project the TOML-governed cohort validation lifecycle without executing it."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import tomllib
from typing import Mapping, Sequence

LIFECYCLE_SCHEMA = "fidb-cohort-validation-lifecycle/v1"
LIFECYCLE_STATUS_SCHEMA = "fidb-cohort-validation-lifecycle-status/v1"
DEFAULT_AUTHORITY = Path("validation/cohort-lifecycle.toml")

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TOP_LEVEL_FIELDS = {
    "schema_version",
    "id",
    "label",
    "state",
    "language_id",
    "scientific_cohort_size",
    "minimum_final_partial_size",
    "validation_method_authority",
    "validation_method_authority_sha256",
    "cohort_registry",
    "cohort_registry_sha256",
    "query_evidence_contract",
    "stages",
    "reference_population",
    "execution",
    "fusion",
    "incremental",
    "scheduling",
    "admission",
    "performance",
}
_SECTION_FIELDS = {
    "reference_population": {
        "routine",
        "forms",
        "linked_input",
        "compile_source",
        "link_harness",
        "population_engine",
        "promotion_gate",
        "ablation_populations",
    },
    "execution": {
        "scientific_boundary",
        "scheduler_boundary",
        "folds_per_identity",
        "query_projections_per_composite",
        "automatic_materialization",
        "automatic_scheduling",
        "execute_target_binaries",
    },
    "fusion": {
        "enabled_for_new_runs",
        "single_ghidra_analysis_per_composite",
        "canonical_export",
        "export_roles",
        "routine_backfill",
        "legacy_backfill",
    },
    "incremental": {
        "primary_confusion_scope",
        "corpus_noise_scope",
        "new_cohort_scope",
        "historical_replay",
        "historical_sentinel_authority",
        "historical_sentinel_enabled",
        "full_revalidation_milestones",
        "ecological_validation",
    },
    "scheduling": {
        "trigger",
        "allow_source_recipe_preparation_ahead",
        "allow_recipe_qualification_ahead",
        "maximum_unvalidated_width_cohorts",
        "validation_failure_action",
        "retention_required_before_admission",
        "final_partial_requires_explicit_override",
    },
    "admission": {
        "automatic_corpus_admission",
        "required_evidence",
        "scientific_threshold_authority",
        "unconfigured_threshold_action",
        "infrastructure_failure_action",
    },
    "performance": {
        "estimate_class",
        "legacy_composite_ghidra_analyses_per_cohort",
        "legacy_backfill_ghidra_analyses_per_cohort",
        "fused_ghidra_analyses_per_cohort",
        "observed_composite_build_wall_hours",
        "observed_backfill_wall_hours",
        "observed_gpu_match_wall_hours",
        "projected_fused_cycle_wall_hours_lower",
        "projected_fused_cycle_wall_hours_upper",
    },
}
_STAGES = (
    "source-recipe-preparation",
    "recipe-qualification",
    "width-build",
    "validation-composites",
    "linked-reference-generation",
    "query-evidence-export",
    "incremental-corpus-query",
    "hash-discrimination",
    "retention",
    "corpus-admission",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inside(root: Path, value: object, label: str) -> Path:
    relative = Path(str(value))
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"{label} must stay inside the project")
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ValueError(f"{label} must stay inside the project")
    return path


def load_cohort_validation_lifecycle(
    project_root: str | Path,
    authority_path: str | Path = DEFAULT_AUTHORITY,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    path = _inside(root, authority_path, "cohort lifecycle authority")
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if (
        set(document) != _TOP_LEVEL_FIELDS
        or document.get("schema_version") != LIFECYCLE_SCHEMA
    ):
        raise ValueError("cohort validation lifecycle has unsupported fields or schema")
    for section, fields in _SECTION_FIELDS.items():
        value = document.get(section)
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError(
                f"cohort validation lifecycle {section} fields are invalid"
            )
    if tuple(document["stages"]) != _STAGES:
        raise ValueError("cohort validation lifecycle stages are invalid or reordered")
    if (
        document["state"] != "planned-disarmed"
        or document["language_id"] != "c"
        or document["scientific_cohort_size"] != 10
        or document["minimum_final_partial_size"] != 2
    ):
        raise ValueError("cohort validation lifecycle boundary is unsupported")
    execution = document["execution"]
    if (
        execution["scientific_boundary"] != "completed-library-cohort"
        or execution["scheduler_boundary"] != "time-bounded-resumable-block"
        or execution["folds_per_identity"] != 2
        or execution["query_projections_per_composite"] < 1
        or execution["automatic_materialization"] is not True
        or execution["automatic_scheduling"] is not True
        or execution["execute_target_binaries"] is not False
    ):
        raise ValueError("cohort validation lifecycle execution policy is unsafe")
    fusion = document["fusion"]
    if (
        fusion["enabled_for_new_runs"] is not True
        or fusion["single_ghidra_analysis_per_composite"] is not True
        or fusion["canonical_export"] != "query-signatures.jsonl"
        or set(fusion["export_roles"])
        != {"exact-signatures", "fid-relationship-evidence"}
        or fusion["routine_backfill"] != "forbidden"
    ):
        raise ValueError("cohort validation fused evidence policy is invalid")
    reference = document["reference_population"]
    if reference != {
        "routine": "archive-plus-linked",
        "forms": ["archive", "linked-shared-image"],
        "linked_input": "sealed-static-archive",
        "compile_source": False,
        "link_harness": "whole-archive-shared-image-symbolic-v2",
        "population_engine": "alpha_engine_2",
        "promotion_gate": "zero-mismatch-alpha-engine-1-cross-check",
        "ablation_populations": ["archive-only", "linked-only"],
    }:
        raise ValueError("cohort validation reference population is unsupported")
    scheduling = document["scheduling"]
    admission = document["admission"]
    if (
        scheduling["maximum_unvalidated_width_cohorts"] != 1
        or scheduling["retention_required_before_admission"] is not True
        or scheduling["final_partial_requires_explicit_override"] is not True
        or admission["automatic_corpus_admission"] is not False
        or not admission["required_evidence"]
    ):
        raise ValueError("cohort validation admission policy is not fail-closed")
    method = _inside(
        root, document["validation_method_authority"], "validation method authority"
    )
    expected = str(document["validation_method_authority_sha256"])
    if (
        not method.is_file()
        or _DIGEST.fullmatch(expected) is None
        or _sha256(method) != expected
    ):
        raise ValueError("cohort validation method authority is unavailable or stale")
    registry = _inside(root, document["cohort_registry"], "validation cohort registry")
    registry_digest = str(document["cohort_registry_sha256"])
    if (
        not registry.is_file()
        or _DIGEST.fullmatch(registry_digest) is None
        or _sha256(registry) != registry_digest
    ):
        raise ValueError("validation cohort registry is unavailable or stale")
    return {
        **document,
        "authority_path": str(path.relative_to(root)),
        "authority_sha256": _sha256(path),
    }


def _load_bound_cohorts(
    root: Path,
    lifecycle: Mapping[str, object],
    width_batches: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    path = _inside(root, lifecycle["cohort_registry"], "validation cohort registry")
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if set(document) != {"schema_version", "state", "language_id", "cohort"} or (
        document["schema_version"] != "fidb-validation-cohort-registry/v1"
        or document["state"] != "planned-disarmed"
        or document["language_id"] != lifecycle["language_id"]
    ):
        raise ValueError("validation cohort registry has unsupported fields or schema")
    batches = {str(batch["authority_path"]): batch for batch in width_batches}
    rows = []
    ids: set[str] = set()
    orders: set[int] = set()
    for raw in document["cohort"]:
        expected_fields = {
            "id",
            "order",
            "label",
            "state",
            "source_pack",
            "width_batch",
            "seed",
            "source_ids",
        }
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise ValueError("validation cohort registry row fields are invalid")
        identifier = str(raw["id"])
        order = int(raw["order"])
        source_ids = list(raw["source_ids"])
        if (
            not identifier
            or identifier in ids
            or order in orders
            or raw["state"] != "planned-disarmed"
            or len(source_ids) != int(lifecycle["scientific_cohort_size"])
            or len(set(source_ids)) != len(source_ids)
        ):
            raise ValueError("validation cohort registry identity is invalid")
        ids.add(identifier)
        orders.add(order)
        source_path = _inside(root, raw["source_pack"], "cohort source pack")
        source = tomllib.loads(source_path.read_text(encoding="utf-8"))
        available = {
            f'{item["id"]}@{item["version"]}' for item in source.get("source", [])
        }
        if not set(source_ids).issubset(available):
            raise ValueError(
                f"validation cohort {identifier} is absent from its source pack"
            )
        batch_path = str(raw["width_batch"])
        batch = batches.get(batch_path)
        if batch is None:
            raise ValueError(
                f"validation cohort {identifier} width batch is unavailable"
            )
        requested_names = {identity.rsplit("@", 1)[0] for identity in source_ids}
        batch_names = {str(item["id"]) for item in batch["libraries"]}
        if requested_names != batch_names:
            raise ValueError(
                f"validation cohort {identifier} does not match its width batch"
            )
        ranked = _sha256_ranked(str(raw["seed"]), source_ids)
        split = len(ranked) // 2
        readiness = batch["readiness"]
        rows.append(
            {
                **raw,
                "source_ids": source_ids,
                "fold_a": ranked[:split],
                "fold_b": ranked[split:],
                "width_batch_state": readiness["queue_state"],
                "width_queue_eligible_executions": readiness[
                    "queue_eligible_executions"
                ],
                "validation_state": "awaiting-sealed-width",
                "automatic_materialization": lifecycle["execution"][
                    "automatic_materialization"
                ],
                "automatic_scheduling": lifecycle["execution"]["automatic_scheduling"],
            }
        )
    return sorted(rows, key=lambda row: int(row["order"]))


def _sha256_ranked(seed: str, identities: Sequence[str]) -> list[str]:
    try:
        seed_bytes = bytes.fromhex(seed)
    except ValueError as error:
        raise ValueError("validation cohort seed is not hexadecimal") from error
    if len(seed_bytes) != 32:
        raise ValueError("validation cohort seed must contain 32 bytes")
    return sorted(
        identities,
        key=lambda identity: hashlib.sha256(
            seed_bytes + b"\0" + identity.encode("utf-8")
        ).digest(),
    )


def _stage(identifier: str, state: str, detail: str) -> dict[str, str]:
    return {
        "id": identifier,
        "label": identifier.replace("-", " ").title(),
        "state": state,
        "detail": detail,
    }


def _programme_cohort(
    cohort: Mapping[str, object],
    programme: Mapping[str, object],
    lifecycle: Mapping[str, object],
) -> dict[str, object]:
    capacity = int(cohort["capacity"])
    counts = cohort["counts"]
    identities = int(programme["campaign_executions_per_library"])
    folds = int(lifecycle["execution"]["folds_per_identity"])
    composites = identities * folds
    projections = composites * int(
        lifecycle["execution"]["query_projections_per_composite"]
    )
    recipes_complete = int(counts["recipe_ready"]) == capacity
    qualification_complete = int(counts["qualification_satisfied"]) == capacity
    stages = [
        _stage(
            "source-recipe-preparation",
            "complete" if recipes_complete else "in-progress",
            f'{counts["recipe_ready"]}/{capacity} reviewed recipes',
        ),
        _stage(
            "recipe-qualification",
            "complete" if qualification_complete else "blocked",
            f'{counts["qualification_satisfied"]}/{capacity} qualified subjects',
        ),
        _stage(
            "width-build",
            "ready-disarmed" if qualification_complete else "blocked",
            f"{capacity * identities:,} planned exact build cells",
        ),
        _stage(
            "validation-composites",
            "blocked",
            f"{composites:,} deterministic fold images",
        ),
        _stage(
            "linked-reference-generation",
            "blocked",
            f"{capacity * identities:,} archive-derived linked images; no recompilation",
        ),
    ]
    stages.extend(
        _stage(identifier, "blocked", "depends on sealed cohort width")
        for identifier in _STAGES[5:]
    )
    return {
        "id": cohort["id"],
        "order": cohort["order"],
        "capacity": capacity,
        "candidate_rank_start": cohort["candidate_rank_start"],
        "candidate_rank_end": cohort["candidate_rank_end"],
        "state": "preparation" if recipes_complete else "candidate-work",
        "work": {
            "width_build_cells": capacity * identities,
            "linked_reference_images": capacity * identities,
            "exact_identities": identities,
            "validation_composites": composites,
            "query_projections": projections,
            "fused_ghidra_analyses": composites,
            "legacy_duplicate_analyses_avoided": composites,
        },
        "stages": stages,
    }


def compile_cohort_validation_lifecycle(
    project_root: str | Path,
    *,
    campaign_programmes: Sequence[Mapping[str, object]],
    machine_validations: Sequence[Mapping[str, object]],
    width_batches: Sequence[Mapping[str, object]],
    authority_path: str | Path = DEFAULT_AUTHORITY,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    lifecycle = load_cohort_validation_lifecycle(root, authority_path)
    bound_cohorts = _load_bound_cohorts(root, lifecycle, width_batches)
    programmes = []
    total_cohorts = 0
    total_composites = 0
    total_avoided = 0
    for programme in campaign_programmes:
        cohorts = [
            _programme_cohort(cohort, programme, lifecycle)
            for cohort in programme["cohorts"]
        ]
        total_cohorts += len(cohorts)
        total_composites += sum(
            int(cohort["work"]["validation_composites"]) for cohort in cohorts
        )
        total_avoided += sum(
            int(cohort["work"]["legacy_duplicate_analyses_avoided"])
            for cohort in cohorts
        )
        programmes.append(
            {
                "id": programme["id"],
                "label": programme["label"],
                "cohorts": cohorts,
            }
        )
    active = None
    if machine_validations:
        validation = machine_validations[0]
        matching = validation.get("fid_matching", {})
        full = matching.get("full", {}) if isinstance(matching, dict) else {}
        measured = full.get("state") == "measured-complete"
        active = {
            "id": validation["id"],
            "label": validation["label"],
            "integration": "legacy-run-retrofit",
            "libraries": validation["summary"]["cohort_libraries"],
            "width_state": (
                "complete" if validation["readiness"]["eligible"] else "in-progress"
            ),
            "validation_state": matching.get("state", "not-run"),
            "admission_state": "review-required" if measured else "quarantined",
            "result_state": full.get("state", "not-run"),
        }
    body = {
        "schema_version": LIFECYCLE_STATUS_SCHEMA,
        "id": lifecycle["id"],
        "label": lifecycle["label"],
        "state": lifecycle["state"],
        "language_id": lifecycle["language_id"],
        "authority_path": lifecycle["authority_path"],
        "authority_sha256": lifecycle["authority_sha256"],
        "method_authority": lifecycle["validation_method_authority"],
        "method_authority_sha256": lifecycle["validation_method_authority_sha256"],
        "query_evidence_contract": lifecycle["query_evidence_contract"],
        "execution": lifecycle["execution"],
        "fusion": lifecycle["fusion"],
        "reference_population": lifecycle["reference_population"],
        "incremental": lifecycle["incremental"],
        "scheduling": lifecycle["scheduling"],
        "admission": lifecycle["admission"],
        "performance": lifecycle["performance"],
        "stages": [
            _stage(identifier, "policy", "required for every future cohort")
            for identifier in lifecycle["stages"]
        ],
        "active_cohort": active,
        "programmes": programmes,
        "bound_cohorts": bound_cohorts,
        "summary": {
            "programme_cohorts": total_cohorts,
            "planned_validation_composites": total_composites,
            "legacy_duplicate_analyses_avoided": total_avoided,
            "bound_future_cohorts": len(bound_cohorts),
            "fused_analyses_per_full_cohort": lifecycle["performance"][
                "fused_ghidra_analyses_per_cohort"
            ],
            "legacy_analyses_per_full_cohort": (
                lifecycle["performance"]["legacy_composite_ghidra_analyses_per_cohort"]
                + lifecycle["performance"]["legacy_backfill_ghidra_analyses_per_cohort"]
            ),
        },
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return {**body, "status_digest": hashlib.sha256(canonical).hexdigest()}
