"""Compile the dormant, cohort-based machine-validation authority."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import tomllib
from typing import Iterable, Mapping

from .c_width import compile_c_width

VALIDATION_SCHEMA = "fidb-machine-validation/v1"
VALIDATION_STATUS_SCHEMA = "fidb-machine-validation-status/v1"
VALIDATION_BATCH_SCHEMA = "fidb-machine-validation-batch/v1"
VALIDATION_REPORT_SCHEMA = "fidb-machine-validation-hash-report/v1"
VALIDATION_SCHEDULE_SCHEMA = "fidb-validation-schedule/v1"
DEFAULT_AUTHORITY = Path("validation/machine-validation.toml")

_TOP_LEVEL_FIELDS = {
    "schema_version",
    "id",
    "label",
    "state",
    "language_id",
    "batch_kind",
    "source_pack",
    "width_authority",
    "cohort_size",
    "fold_size",
    "cohort_policy",
    "eligibility",
    "randomization",
    "batch",
    "queries",
    "metrics",
    "planning",
    "ecological_validation",
}
_SECTION_FIELDS = {
    "cohort_policy": {
        "nominal_size",
        "minimum_final_partial_size",
        "final_partial_override",
        "final_partial_justification",
        "split_policy",
    },
    "eligibility": {
        "required_complete_libraries",
        "baseline_exact_identities_per_library",
        "identity_policy",
        "materialize_only_when_eligible",
        "ledger",
        "width_run_glob",
        "report_glob",
    },
    "randomization": {
        "method",
        "algorithm",
        "seed",
        "canonical_ids",
        "fold_a",
        "fold_b",
    },
    "batch": {
        "automatic_materialization",
        "automatic_scheduling",
        "scheduler_registry",
        "production_queue_mutation",
        "first_run_requires_canary",
        "output_root",
        "input_strategy",
        "harness_mode",
        "execute_target_binaries",
        "truth_copy",
        "query_copy",
        "exact_inclusion_sanity",
        "trigger",
    },
    "queries": {"primary_projections"},
    "metrics": {"required"},
    "planning": {
        "estimate_class",
        "central_wall_hours",
        "lower_wall_hours",
        "upper_wall_hours",
        "safe_ram_gib_lower",
        "safe_ram_gib_upper",
        "scratch_headroom_gib_lower",
        "scratch_headroom_gib_upper",
        "raw_retained_gib_lower",
        "raw_retained_gib_upper",
        "compact_output_gib_upper",
    },
    "ecological_validation": {
        "state",
        "included_in_validation_batch",
        "gate",
        "mode",
    },
}


def _inside(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    if path != root and root not in path.parents:
        raise ValueError(f"machine-validation path escapes project root: {relative}")
    return path


def _strings(value: object, field: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item for item in value)
    ):
        raise ValueError(f"machine-validation {field} must be non-empty strings")
    if len(value) != len(set(value)):
        raise ValueError(f"machine-validation {field} contains duplicates")
    return list(value)


def _sha256_ranked(seed: str, identities: Iterable[str]) -> list[str]:
    try:
        seed_bytes = bytes.fromhex(seed)
    except ValueError as error:
        raise ValueError("machine-validation seed is not hexadecimal") from error
    if len(seed_bytes) != 32:
        raise ValueError("machine-validation seed must contain 32 bytes")
    return sorted(
        identities,
        key=lambda identity: hashlib.sha256(
            seed_bytes + b"\0" + identity.encode("utf-8")
        ).digest(),
    )


def load_machine_validation(
    project_root: str | Path,
    authority: str | Path = DEFAULT_AUTHORITY,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    authority_path = _inside(root, str(authority))
    document = tomllib.loads(authority_path.read_text(encoding="utf-8"))
    if (
        set(document) != _TOP_LEVEL_FIELDS
        or document.get("schema_version") != VALIDATION_SCHEMA
    ):
        raise ValueError(
            "machine-validation authority has unsupported schema or fields"
        )
    for section, fields in _SECTION_FIELDS.items():
        value = document.get(section)
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError(f"machine-validation {section} has unexpected fields")
    for field in (
        "id",
        "label",
        "state",
        "language_id",
        "batch_kind",
        "source_pack",
        "width_authority",
    ):
        if not isinstance(document[field], str) or not document[field]:
            raise ValueError(f"machine-validation {field} must be a non-empty string")
    if (
        document["state"] != "designed-dormant"
        or document["batch_kind"] != "validation-run"
    ):
        raise ValueError("machine-validation must remain a dormant validation-run")
    cohort_size = document["cohort_size"]
    fold_size = document["fold_size"]
    cohort_policy = document["cohort_policy"]
    nominal = cohort_policy["nominal_size"]
    minimum_partial = cohort_policy["minimum_final_partial_size"]
    partial = cohort_policy["final_partial_override"]
    justification = cohort_policy["final_partial_justification"]
    if (
        nominal != 10
        or minimum_partial != 2
        or cohort_policy["split_policy"] != "balanced-seeded-random"
        or not isinstance(partial, bool)
        or not isinstance(justification, str)
    ):
        raise ValueError("machine-validation cohort policy is unsupported")
    if partial:
        if not minimum_partial <= cohort_size < nominal or not justification.strip():
            raise ValueError(
                "final partial cohort override requires 2-9 libraries and a justification"
            )
    elif cohort_size != nominal or justification:
        raise ValueError("ordinary machine-validation cohorts must contain exactly ten")
    if fold_size != cohort_size // 2:
        raise ValueError("machine-validation fold size is not maximally balanced")

    randomization = document["randomization"]
    canonical_ids = _strings(randomization["canonical_ids"], "canonical_ids")
    fold_a = _strings(randomization["fold_a"], "fold_a")
    fold_b = _strings(randomization["fold_b"], "fold_b")
    if randomization["algorithm"] != "sha256-ranked-v1":
        raise ValueError("machine-validation randomization algorithm is unsupported")
    ranked = _sha256_ranked(str(randomization["seed"]), canonical_ids)
    if fold_a != ranked[:fold_size] or fold_b != ranked[fold_size:]:
        raise ValueError(
            "machine-validation frozen folds do not match seed and algorithm"
        )
    if set(fold_a).intersection(fold_b) or set(fold_a + fold_b) != set(canonical_ids):
        raise ValueError("machine-validation folds do not exactly partition the cohort")

    source_path = _inside(root, str(document["source_pack"]))
    source = tomllib.loads(source_path.read_text(encoding="utf-8"))
    source_ids = [f'{row["id"]}@{row["version"]}' for row in source.get("source", [])]
    if set(source_ids) != set(canonical_ids) or len(source_ids) != cohort_size:
        raise ValueError("machine-validation cohort does not match its source pack")

    eligibility = document["eligibility"]
    if (
        eligibility["required_complete_libraries"] != cohort_size
        or eligibility["baseline_exact_identities_per_library"] != 222
        or eligibility["identity_policy"] != "all-applicable-execution-identities"
        or eligibility["materialize_only_when_eligible"] is not True
    ):
        raise ValueError("machine-validation eligibility contract is not fail-closed")
    batch = document["batch"]
    if (
        batch["automatic_materialization"] is not True
        or batch["automatic_scheduling"] is not True
        or batch["production_queue_mutation"] is not False
        or batch["first_run_requires_canary"] is not True
        or batch["execute_target_binaries"] is not False
    ):
        raise ValueError(
            "machine-validation cannot auto-queue or execute target programs"
        )
    ecological = document["ecological_validation"]
    if ecological["included_in_validation_batch"] is not False:
        raise ValueError("ecological validation must remain outside machine validation")

    return {
        **document,
        "authority_path": str(authority_path.relative_to(root)),
        "authority_sha256": hashlib.sha256(authority_path.read_bytes()).hexdigest(),
        "source_pack_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
    }


def _empty_evidence(canonical_ids: Iterable[str]) -> dict[str, set[tuple[str, str]]]:
    return {identity: set() for identity in canonical_ids}


def _width_run_evidence(
    root: Path,
    pattern: str,
    evidence: dict[str, set[tuple[str, str]]],
) -> dict[str, object]:
    paths = sorted(root.glob(pattern))
    accepted = 0
    for path in paths:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        identity = document.get("fixed_recipe")
        if identity not in evidence:
            continue
        for replay in document.get("replay_results", []):
            if not isinstance(replay, dict):
                continue
            for cell in replay.get("cells", []):
                if not isinstance(cell, dict) or cell.get("status") != "complete":
                    continue
                route = cell.get("route_id")
                treatment = cell.get("treatment_id")
                if isinstance(route, str) and isinstance(treatment, str):
                    before = len(evidence[str(identity)])
                    evidence[str(identity)].add((route, treatment))
                    accepted += len(evidence[str(identity)]) - before
    return {
        "state": "available",
        "files_scanned": len(paths),
        "accepted_pairs": accepted,
    }


def _ledger_evidence(
    root: Path,
    relative: str,
    evidence: dict[str, set[tuple[str, str]]],
) -> dict[str, object]:
    path = _inside(root, relative)
    if not path.is_file():
        return {"state": "absent", "path": relative, "accepted_pairs": 0}
    accepted = 0
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=0)
        try:
            connection.execute("PRAGMA query_only = ON")
            rows = connection.execute("""
                SELECT cells.cell_json
                FROM jobs
                JOIN resolved_cells AS cells
                  ON cells.plan_digest = jobs.plan_digest
                 AND cells.cell_id = jobs.base_cell_id
                WHERE jobs.state = 'complete'
                """)
            for (cell_json,) in rows:
                cell = json.loads(cell_json)
                recipe = cell.get("recipe", {})
                identity = f'{recipe.get("name")}@{recipe.get("version")}'
                if identity not in evidence:
                    continue
                route = cell.get("toolchain", {}).get("route")
                treatment = cell.get("build", {}).get("treatment")
                if isinstance(route, str) and isinstance(treatment, str):
                    before = len(evidence[identity])
                    evidence[identity].add((route, treatment))
                    accepted += len(evidence[identity]) - before
        finally:
            connection.close()
    except (sqlite3.Error, ValueError, TypeError) as error:
        return {
            "state": "temporarily-unavailable",
            "path": relative,
            "accepted_pairs": 0,
            "detail": str(error),
        }
    return {"state": "available", "path": relative, "accepted_pairs": accepted}


def _cohort_evidence(
    root: Path,
    authority: Mapping[str, object],
    override: Mapping[str, set[tuple[str, str]]] | None,
) -> tuple[dict[str, set[tuple[str, str]]], dict[str, object]]:
    canonical_ids = authority["randomization"]["canonical_ids"]
    evidence = _empty_evidence(canonical_ids)
    if override is not None:
        for identity in canonical_ids:
            evidence[identity].update(override.get(identity, set()))
        return evidence, {"override": {"state": "test-override"}}
    eligibility = authority["eligibility"]
    sources = {
        "width_runs": _width_run_evidence(
            root, str(eligibility["width_run_glob"]), evidence
        )
    }
    sources["coordinator_ledger"] = _ledger_evidence(
        root, str(eligibility["ledger"]), evidence
    )
    return evidence, sources


def _validation_results(
    root: Path, pattern: str, validation_id: str
) -> dict[str, object]:
    paths = sorted(root.glob(pattern), key=lambda path: path.stat().st_mtime_ns)
    if not paths:
        return {
            "state": "not-run",
            "report_path": None,
            "confusion_matrix": {
                "unit": "complete-fid-signature-owner-assertion",
                "true_positives": None,
                "false_positives": None,
                "true_negatives": None,
                "false_negatives": None,
            },
            "failure_summary": {"collisions": 0, "misses": 0},
            "failures": [],
        }
    path = paths[-1]
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return {
            "state": "invalid-report",
            "report_path": str(path.relative_to(root)),
            "detail": str(error),
            "confusion_matrix": {
                "unit": "complete-fid-signature-owner-assertion",
                "true_positives": None,
                "false_positives": None,
                "true_negatives": None,
                "false_negatives": None,
            },
            "failure_summary": {"collisions": 0, "misses": 0},
            "failures": [],
        }
    matrix = document.get("confusion_matrix")
    failures = document.get("failures")
    hash_evidence = document.get("hash_evidence")
    required_matrix = {
        "unit",
        "true_positives",
        "false_positives",
        "true_negatives",
        "false_negatives",
    }
    valid_failures = isinstance(failures, list) and all(
        isinstance(row, dict)
        and row.get("failure_type") in {"collision", "miss"}
        and all(
            isinstance(row.get(field), str)
            for field in (
                "library_id",
                "function_id",
                "route_id",
                "compiler_id",
                "treatment_id",
                "signature",
                "candidate_owner",
                "evidence_path",
            )
        )
        for row in failures
    )
    valid_matrix = (
        isinstance(matrix, dict)
        and set(matrix) == required_matrix
        and matrix.get("unit") == "complete-fid-signature-owner-assertion"
        and all(
            isinstance(matrix.get(field), int) and matrix[field] >= 0
            for field in required_matrix - {"unit"}
        )
    )
    valid_hash_evidence = (
        isinstance(hash_evidence, dict)
        and isinstance(hash_evidence.get("database_path"), str)
        and isinstance(hash_evidence.get("database_sha256"), str)
        and len(hash_evidence["database_sha256"]) == 64
        and all(
            isinstance(hash_evidence.get(field), int)
            and hash_evidence[field] >= 0
            for field in (
                "distinct_signatures",
                "noisy_signatures",
                "multi_owner_signatures",
                "missed_signatures",
                "query_signature_observations",
                "unattributed_query_signatures",
                "fold_results",
            )
        )
        and isinstance(hash_evidence.get("top_noisy"), list)
        and isinstance(hash_evidence.get("top_low_information"), list)
    )
    if (
        document.get("schema_version") != VALIDATION_REPORT_SCHEMA
        or document.get("validation_id") != validation_id
        or document.get("state") != "measured-complete"
        or not valid_matrix
        or not valid_hash_evidence
        or not valid_failures
    ):
        return {
            "state": "invalid-report",
            "report_path": str(path.relative_to(root)),
            "detail": "report does not satisfy fidb-machine-validation-hash-report/v1",
            "confusion_matrix": {
                "unit": "complete-fid-signature-owner-assertion",
                "true_positives": None,
                "false_positives": None,
                "true_negatives": None,
                "false_negatives": None,
            },
            "failure_summary": {"collisions": 0, "misses": 0},
            "failures": [],
        }
    return {
        "state": "measured-complete",
        "report_path": str(path.relative_to(root)),
        "confusion_matrix": matrix,
        "failure_summary": {
            "collisions": int(document.get("failure_summary", {}).get("collisions", 0)),
            "misses": int(document.get("failure_summary", {}).get("misses", 0)),
        },
        "failures": failures,
        "hash_evidence": hash_evidence,
    }


def _validation_schedule_state(root: Path, relative: str, validation_id: str) -> str:
    path = _inside(root, relative)
    if not path.is_file():
        return "scheduler-registry-absent"
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "scheduler-registry-invalid"
    for trigger in document.get("trigger", []):
        if isinstance(trigger, dict) and trigger.get("id") == validation_id:
            state = trigger.get("state")
            return str(state) if isinstance(state, str) else "scheduler-entry-invalid"
    return "scheduler-entry-absent"


def compile_machine_validation(
    project_root: str | Path,
    authority_path: str | Path = DEFAULT_AUTHORITY,
    *,
    evidence_override: Mapping[str, set[tuple[str, str]]] | None = None,
    _width_compilation: Mapping[str, object] | None = None,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    authority = load_machine_validation(root, authority_path)
    width_id = Path(str(authority["width_authority"])).stem
    width = (
        dict(_width_compilation)
        if _width_compilation is not None
        else compile_c_width(root, width_id)
    )
    identities = [
        {
            "route_id": row["route_id"],
            "profile_id": row["profile_id"],
            "treatment_id": row["treatment_id"],
        }
        for row in width["applicability"]
        if row["state"] in {"executable", "unavailable"}
    ]
    expected_pairs = {
        (str(row["route_id"]), str(row["treatment_id"])) for row in identities
    }
    required = len(expected_pairs)
    baseline = int(authority["eligibility"]["baseline_exact_identities_per_library"])
    if len(identities) != required or required < baseline:
        raise ValueError(
            f"machine-validation applicable width regressed below its {baseline}-identity baseline: "
            f"compiled {len(identities)} rows / {len(expected_pairs)} pairs"
        )

    evidence, evidence_sources = _cohort_evidence(root, authority, evidence_override)
    randomization = authority["randomization"]
    fold_by_id = {
        **{identity: "A" for identity in randomization["fold_a"]},
        **{identity: "B" for identity in randomization["fold_b"]},
    }
    libraries = []
    complete_libraries = 0
    completed_inputs = 0
    for identity in randomization["canonical_ids"]:
        completed = len(expected_pairs.intersection(evidence[identity]))
        completed_inputs += completed
        state = (
            "complete"
            if completed == required
            else "building" if completed else "not-started"
        )
        complete_libraries += state == "complete"
        libraries.append(
            {
                "id": identity,
                "fold": fold_by_id[identity],
                "state": state,
                "completed_exact_identities": completed,
                "required_exact_identities": required,
                "missing_exact_identities": required - completed,
            }
        )

    cohort_size = int(authority["cohort_size"])
    eligible = complete_libraries == cohort_size
    blockers = (
        []
        if eligible
        else [
            f"{cohort_size - complete_libraries} of {cohort_size} libraries still lack complete {required}-identity evidence",
            f"{cohort_size * required - completed_inputs} exact library/identity inputs remain",
        ]
    )
    work_units = required
    composite_programs = work_units * 2
    projections_per_program = len(authority["queries"]["primary_projections"])
    query_projections = composite_programs * projections_per_program
    results = _validation_results(
        root, str(authority["eligibility"]["report_glob"]), str(authority["id"])
    )
    schedule_state = _validation_schedule_state(
        root, str(authority["batch"]["scheduler_registry"]), str(authority["id"])
    )
    stages = [
        {
            "id": "cohort-evidence",
            "label": "Complete cohort width",
            "state": "complete" if eligible else "in-progress",
            "detail": f"{completed_inputs}/{cohort_size * required} exact inputs",
        },
        {
            "id": "frozen-random-split",
            "label": "Freeze balanced random split",
            "state": "complete",
            "detail": f'{randomization["algorithm"]} · seed committed',
        },
        {
            "id": "materialize-validation-batch",
            "label": "Materialise validation-run",
            "state": "ready-disarmed" if eligible else "blocked",
            "detail": "automatic scheduler registry · first run claim-blocked",
        },
        {
            "id": "composite-build-analysis",
            "label": "Build + analyse two folds",
            "state": "not-run" if eligible else "blocked",
            "detail": f"{composite_programs} non-executed composites",
        },
        {
            "id": "single-hash-classification",
            "label": "Classify every signature",
            "state": "not-run" if eligible else "blocked",
            "detail": "TP / FP / TN / FN without a match-count threshold",
        },
        {
            "id": "machine-report",
            "label": "Publish machine report",
            "state": "not-run" if eligible else "blocked",
            "detail": "accuracy · ambiguity · marginal coverage · cost",
        },
    ]
    body = {
        "schema_version": VALIDATION_STATUS_SCHEMA,
        "id": authority["id"],
        "label": authority["label"],
        "state": "eligible-disarmed" if eligible else "waiting-for-cohort",
        "language_id": authority["language_id"],
        "batch_kind": authority["batch_kind"],
        "authority_path": authority["authority_path"],
        "authority_sha256": authority["authority_sha256"],
        "authorities": {
            "source_pack": authority["source_pack"],
            "source_pack_sha256": authority["source_pack_sha256"],
            "width": authority["width_authority"],
            "width_compilation_digest": width["compilation_digest"],
        },
        "randomization": randomization,
        "cohort_policy": authority["cohort_policy"],
        "batch": authority["batch"],
        "queries": authority["queries"],
        "metrics": authority["metrics"],
        "planning": authority["planning"],
        "ecological_validation": authority["ecological_validation"],
        "summary": {
            "cohort_libraries": cohort_size,
            "complete_libraries": complete_libraries,
            "exact_identities": required,
            "baseline_exact_identities": baseline,
            "width_delta_from_baseline": required - baseline,
            "completed_exact_inputs": completed_inputs,
            "required_exact_inputs": cohort_size * required,
            "work_units": work_units,
            "composite_programs": composite_programs,
            "query_projections": query_projections,
        },
        "readiness": {
            "eligible": eligible,
            "materializable": eligible,
            "queue_state": schedule_state,
            "execution_state": "not-tested-awaiting-complete-cohort",
            "blockers": blockers,
        },
        "libraries": libraries,
        "stages": stages,
        "width_identities": identities,
        "evidence_sources": evidence_sources,
        "results": results,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return {**body, "status_digest": hashlib.sha256(canonical).hexdigest()}


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _toml_array(values: Iterable[str]) -> str:
    return "[" + ", ".join(_toml_string(value) for value in values) + "]"


def _materialization_digest(status: Mapping[str, object]) -> str:
    """Pin only immutable inputs to a validation batch.

    The live status digest also includes scheduler and result state. Embedding
    that digest in the manifest made writing the generated schedule invalidate
    the manifest immediately.
    """

    pinned = {
        "schema_version": VALIDATION_BATCH_SCHEMA,
        "id": status["id"],
        "authority_path": status["authority_path"],
        "authority_sha256": status["authority_sha256"],
        "authorities": status["authorities"],
        "randomization": status["randomization"],
        "batch": status["batch"],
        "queries": status["queries"],
        "width_identities": status["width_identities"],
    }
    canonical = json.dumps(pinned, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def _render_validation_batch(status: Mapping[str, object]) -> str:
    summary = status["summary"]
    randomization = status["randomization"]
    lines = [
        f"schema_version = {_toml_string(VALIDATION_BATCH_SCHEMA)}",
        f'id = {_toml_string(str(status["id"]))}',
        'kind = "validation-run"',
        'state = "materialized-disarmed"',
        "automatic_scheduling = true",
        "production_queue_mutation = false",
        "execute_target_binaries = false",
        f'authority_path = {_toml_string(str(status["authority_path"]))}',
        f'authority_sha256 = {_toml_string(str(status["authority_sha256"]))}',
        f'materialization_digest = {_toml_string(_materialization_digest(status))}',
        "",
        "[summary]",
        f'work_units = {summary["work_units"]}',
        f'composite_programs = {summary["composite_programs"]}',
        f'query_projections = {summary["query_projections"]}',
        "",
        "[randomization]",
        f'algorithm = {_toml_string(str(randomization["algorithm"]))}',
        f'seed = {_toml_string(str(randomization["seed"]))}',
        f'fold_a = {_toml_array(randomization["fold_a"])}',
        f'fold_b = {_toml_array(randomization["fold_b"])}',
        "",
        "[execution]",
        f'input_strategy = {_toml_string(str(status["batch"]["input_strategy"]))}',
        f'harness_mode = {_toml_string(str(status["batch"]["harness_mode"]))}',
        f'truth_copy = {_toml_string(str(status["batch"]["truth_copy"]))}',
        f'query_copy = {_toml_string(str(status["batch"]["query_copy"]))}',
        f'primary_projections = {_toml_array(status["queries"]["primary_projections"])}',
    ]
    for index, identity in enumerate(status["width_identities"], start=1):
        unit_id = f'{identity["route_id"]}:{identity["profile_id"]}'
        lines.extend(
            (
                "",
                "[[work_unit]]",
                f"position = {index}",
                f"id = {_toml_string(unit_id)}",
                f'route_id = {_toml_string(str(identity["route_id"]))}',
                f'profile_id = {_toml_string(str(identity["profile_id"]))}',
                f'treatment_id = {_toml_string(str(identity["treatment_id"]))}',
                'folds = ["A", "B"]',
                "composite_programs = 2",
                f'query_projections = {2 * len(status["queries"]["primary_projections"])}',
                'state = "planned-disarmed"',
            )
        )
    return "\n".join(lines) + "\n"


def _render_validation_schedule(
    status: Mapping[str, object], manifest_path: str
) -> str:
    claim_gate = (
        "first-run-canary-after-cohort-complete"
        if status["batch"]["first_run_requires_canary"]
        else "eligible"
    )
    return "\n".join(
        (
            f"schema_version = {_toml_string(VALIDATION_SCHEDULE_SCHEMA)}",
            'name = "machine-validation"',
            'state = "scheduled-claim-blocked"',
            "production_queue_mutation = false",
            "",
            "[[trigger]]",
            f'id = {_toml_string(str(status["id"]))}',
            'kind = "validation-run"',
            f'authority = {_toml_string(str(status["authority_path"]))}',
            f'after = {_toml_string(str(status["batch"]["trigger"]))}',
            "automatic_materialization = true",
            "automatic_scheduling = true",
            'state = "scheduled-claim-blocked"',
            f"claim_gate = {_toml_string(claim_gate)}",
            f"manifest = {_toml_string(manifest_path)}",
            "",
        )
    )


def compile_validation_batch(
    project_root: str | Path,
    authority_path: str | Path = DEFAULT_AUTHORITY,
    *,
    evidence_override: Mapping[str, set[tuple[str, str]]] | None = None,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    status = compile_machine_validation(
        root, authority_path, evidence_override=evidence_override
    )
    if not status["readiness"]["eligible"]:
        raise ValueError(
            "machine-validation batch is not eligible: "
            + "; ".join(status["readiness"]["blockers"])
        )
    output_root = _inside(root, str(status["batch"]["output_root"]))
    manifest_path = output_root / str(status["id"]) / "manifest.toml"
    rendered = _render_validation_batch(status)
    schedule_path = _inside(root, str(status["batch"]["scheduler_registry"]))
    rendered_schedule = _render_validation_schedule(
        status, str(manifest_path.relative_to(root))
    )
    return {
        "schema_version": VALIDATION_BATCH_SCHEMA,
        "id": status["id"],
        "kind": "validation-run",
        "state": "materialized-disarmed",
        "manifest_path": str(manifest_path.relative_to(root)),
        "manifest_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
        "schedule_path": str(schedule_path.relative_to(root)),
        "schedule_sha256": hashlib.sha256(
            rendered_schedule.encode("utf-8")
        ).hexdigest(),
        "summary": status["summary"],
        "rendered_manifest": rendered,
        "rendered_schedule": rendered_schedule,
    }


def write_validation_batch(
    document: Mapping[str, object], project_root: str | Path
) -> None:
    root = Path(project_root).expanduser().resolve()
    files = (
        (str(document["manifest_path"]), str(document["rendered_manifest"])),
        (str(document["schedule_path"]), str(document["rendered_schedule"])),
    )
    for relative, rendered in files:
        path = _inside(root, relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.stem}-", suffix=".tmp", dir=path.parent
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(rendered)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, path)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)


def check_validation_batch(
    document: Mapping[str, object], project_root: str | Path
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    mismatches = []
    for path_field, rendered_field in (
        ("manifest_path", "rendered_manifest"),
        ("schedule_path", "rendered_schedule"),
    ):
        path = _inside(root, str(document[path_field]))
        expected = str(document[rendered_field])
        current = path.read_text(encoding="utf-8") if path.is_file() else None
        if current != expected:
            mismatches.append(str(document[path_field]))
    return {
        "state": "current" if not mismatches else "drifted",
        "manifest_path": str(document["manifest_path"]),
        "schedule_path": str(document["schedule_path"]),
        "mismatches": mismatches,
    }


def reconcile_machine_validation(
    project_root: str | Path,
    authority_path: str | Path = DEFAULT_AUTHORITY,
) -> dict[str, object]:
    """Schedule an eligible cohort, or report an unchanged waiting gate.

    The production worker invokes this only after it atomically drains a batch,
    so a cohort is not rescanned after every cell. The generated validation
    schedule remains claim-blocked for its first real canary.
    """

    status = compile_machine_validation(project_root, authority_path)
    if not status["readiness"]["eligible"]:
        return {
            "state": "waiting-for-cohort",
            "changed": False,
            "validation_id": status["id"],
            "complete_libraries": status["summary"]["complete_libraries"],
            "required_libraries": status["summary"]["cohort_libraries"],
        }
    document = compile_validation_batch(project_root, authority_path)
    check = check_validation_batch(document, project_root)
    if check["state"] == "current":
        return {
            "state": "already-scheduled-claim-blocked",
            "changed": False,
            "validation_id": document["id"],
            "manifest_path": document["manifest_path"],
        }
    write_validation_batch(document, project_root)
    return {
        "state": "automatically-scheduled-claim-blocked",
        "changed": True,
        "validation_id": document["id"],
        "manifest_path": document["manifest_path"],
        "schedule_path": document["schedule_path"],
    }


def reconcile_all_machine_validations(
    project_root: str | Path,
) -> list[dict[str, object]]:
    """Reconcile every reviewed cohort after a production batch drain."""

    root = Path(project_root).expanduser().resolve()
    return [
        reconcile_machine_validation(root, path.relative_to(root))
        for path in sorted((root / "validation").glob("*.toml"))
    ]
