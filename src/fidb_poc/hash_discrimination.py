"""Compile the dormant Hash Discrimination Index authority and readiness."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tomllib
from typing import Mapping

from .ecological_validation import compile_ecological_validation
from .lane_inventory import detect_lane_inventory
from .machine_validation import compile_machine_validation
from .noisy_hashes import compile_noisy_hashes

HASH_DISCRIMINATION_SCHEMA = "fidb-hash-discrimination/v1"
HASH_DISCRIMINATION_STATUS_SCHEMA = "fidb-hash-discrimination-status/v1"
DEFAULT_AUTHORITY = Path("validation/hash-discrimination.toml")

_TOP_LEVEL = {
    "schema_version",
    "id",
    "label",
    "state",
    "sources",
    "identity",
    "index",
    "noise_risk",
    "evidence",
    "model",
    "reproducibility",
    "safety",
    "reason_categories",
    "hdi_component",
    "noise_component",
    "signal",
    "treatment",
    "generation",
}
_SECTIONS = {
    "sources": {
        "machine_validation_authority",
        "ecological_validation_authority",
        "noisy_hash_authority",
        "lane_registry",
        "lane_database_root",
        "generation_root",
    },
    "identity": {
        "analyst_term",
        "grouping_key",
        "score_scope",
        "pool_incompatible_sublanes",
    },
    "index": {
        "name",
        "abbreviation",
        "minimum",
        "maximum",
        "higher_means",
        "is_probability",
    },
    "noise_risk": {
        "name",
        "minimum",
        "maximum",
        "higher_means",
        "independent_from_hdi",
    },
    "evidence": {
        "minimum_library_families",
        "count_library_families_before_build_variants",
        "require_all_signature_denominator",
        "require_candidate_contribution_evidence",
        "retain_component_measurements",
        "retain_sample_counts",
        "retain_uncertainty",
    },
    "model": {
        "kind",
        "state",
        "complex_learning_allowed_at_c10",
        "forward_evaluation",
        "hdi_formula",
        "noise_risk_formula",
        "component_value_minimum",
        "component_value_maximum",
        "smoothing_alpha",
        "smoothing_beta",
    },
    "reproducibility": {
        "algorithm_id",
        "deterministic_order",
        "randomness",
        "floating_point",
        "rounding_decimal_places",
        "source_digest_policy",
        "code_revision_required",
        "generation_write_policy",
    },
    "safety": {
        "automatic_filtering",
        "automatic_admission_mutation",
        "missing_measurements",
        "immutable_generations",
        "preserve_unweighted_baseline",
        "require_heldout_ecological_gate",
        "preserve_raw_observations",
    },
}
_SIGNAL_FIELDS = {"id", "label", "requirement", "required"}
_TREATMENT_FIELDS = {"id", "label", "mode", "required"}
_GENERATION_FIELDS = {"id", "cohort_library_families", "role"}
_COMPONENT_FIELDS = {"id", "label", "weight_percent", "calculation"}
_TREATMENTS = ["unweighted-baseline", "exclusion", "down-weighting", "context-required"]


def _inside(root: Path, relative: str, label: str) -> Path:
    candidate = (root / relative).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError(f"{label} escapes project root")
    return candidate


def _unique_rows(rows: object, fields: set[str], label: str) -> list[dict[str, object]]:
    if not isinstance(rows, list) or not rows:
        raise ValueError(f"hash-discrimination {label} must be a non-empty list")
    result: list[dict[str, object]] = []
    identities: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != fields:
            raise ValueError(f"hash-discrimination {label} has unexpected fields")
        identity = row.get("id")
        if not isinstance(identity, str) or not identity or identity in identities:
            raise ValueError(f"hash-discrimination {label} IDs must be unique strings")
        if not isinstance(row.get("label", row.get("role")), str):
            raise ValueError(f"hash-discrimination {label} labels must be strings")
        identities.add(identity)
        result.append(dict(row))
    return result


def load_hash_discrimination_authority(
    project_root: str | Path,
    authority: str | Path = DEFAULT_AUTHORITY,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    path = _inside(root, str(authority), "hash-discrimination authority")
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if (
        set(document) != _TOP_LEVEL
        or document.get("schema_version") != HASH_DISCRIMINATION_SCHEMA
    ):
        raise ValueError(
            "hash-discrimination authority has unsupported fields or schema"
        )
    for section, fields in _SECTIONS.items():
        if (
            not isinstance(document.get(section), dict)
            or set(document[section]) != fields
        ):
            raise ValueError(f"hash-discrimination {section} has unexpected fields")

    sources = document["sources"]
    for name, value in sources.items():
        if not isinstance(value, str) or not value:
            raise ValueError(
                "hash-discrimination source paths must be non-empty strings"
            )
        _inside(root, value, f"hash-discrimination source {name}")

    identity = document["identity"]
    index = document["index"]
    noise = document["noise_risk"]
    evidence = document["evidence"]
    model = document["model"]
    reproducibility = document["reproducibility"]
    safety = document["safety"]
    if (
        document["state"] != "design-awaiting-c10"
        or identity["grouping_key"] != "query-sublane-plus-complete-fid-signature"
        or identity["pool_incompatible_sublanes"] is not False
        or index["name"] != "Hash Discrimination Index"
        or index["abbreviation"] != "HDI"
        or (index["minimum"], index["maximum"]) != (0, 100)
        or index["is_probability"] is not False
        or (noise["minimum"], noise["maximum"]) != (0, 100)
        or noise["independent_from_hdi"] is not True
        or evidence["minimum_library_families"] < 10
        or evidence["count_library_families_before_build_variants"] is not True
        or evidence["require_all_signature_denominator"] is not True
        or evidence["require_candidate_contribution_evidence"] is not True
        or model["state"] != "specified-not-fit"
        or model["complex_learning_allowed_at_c10"] is not False
        or model["forward_evaluation"] is not True
        or model["hdi_formula"] != "sum(component_value * weight_percent)"
        or model["noise_risk_formula"] != "sum(component_value * weight_percent)"
        or (model["component_value_minimum"], model["component_value_maximum"])
        != (0.0, 1.0)
        or model["smoothing_alpha"] <= 0
        or model["smoothing_beta"] <= 0
        or reproducibility["algorithm_id"] != "fidb-hdi-transparent-v0"
        or reproducibility["randomness"] != "none"
        or reproducibility["rounding_decimal_places"] < 0
        or reproducibility["code_revision_required"] is not True
        or reproducibility["generation_write_policy"] != "immutable-create-only"
        or safety["automatic_filtering"] is not False
        or safety["automatic_admission_mutation"] is not False
        or safety["missing_measurements"] != "unavailable-not-zero"
        or safety["immutable_generations"] is not True
        or safety["preserve_unweighted_baseline"] is not True
        or safety["require_heldout_ecological_gate"] is not True
        or safety["preserve_raw_observations"] is not True
    ):
        raise ValueError(
            "hash-discrimination safety or scoring contract is unsupported"
        )

    categories = document["reason_categories"]
    if (
        not isinstance(categories, list)
        or not categories
        or not all(isinstance(value, str) and value for value in categories)
        or len(categories) != len(set(categories))
        or categories[-1] != "unknown"
    ):
        raise ValueError("hash-discrimination reason categories are unsupported")

    signals = _unique_rows(document["signal"], _SIGNAL_FIELDS, "signals")
    hdi_components = _unique_rows(
        document["hdi_component"], _COMPONENT_FIELDS, "HDI components"
    )
    noise_components = _unique_rows(
        document["noise_component"], _COMPONENT_FIELDS, "noise components"
    )
    treatments = _unique_rows(document["treatment"], _TREATMENT_FIELDS, "treatments")
    generations = _unique_rows(
        document["generation"], _GENERATION_FIELDS, "generations"
    )
    if [str(row["id"]) for row in treatments] != _TREATMENTS or not all(
        row["required"] is True for row in treatments
    ):
        raise ValueError("hash-discrimination treatment arms are unsupported")
    for label, components in (
        ("HDI", hdi_components),
        ("noise", noise_components),
    ):
        if (
            any(
                not isinstance(row["weight_percent"], int)
                or row["weight_percent"] <= 0
                or not isinstance(row["calculation"], str)
                or not row["calculation"]
                for row in components
            )
            or sum(int(row["weight_percent"]) for row in components) != 100
        ):
            raise ValueError(
                f"hash-discrimination {label} component weights must total 100"
            )
    cohort_sizes = [row["cohort_library_families"] for row in generations]
    if (
        not all(isinstance(size, int) and size >= 10 for size in cohort_sizes)
        or cohort_sizes != sorted(set(cohort_sizes))
        or cohort_sizes[0] != evidence["minimum_library_families"]
    ):
        raise ValueError("hash-discrimination model generations are unsupported")

    return {
        **document,
        "signal": signals,
        "hdi_component": hdi_components,
        "noise_component": noise_components,
        "treatment": treatments,
        "generation": generations,
        "authority_path": str(path.relative_to(root)),
        "authority_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _signal_state(
    signal_id: str, *, corpus_ready: bool, machine_measured: bool, complete_width: bool
) -> str:
    if signal_id in {
        "library-family-prevalence",
        "owner-concentration",
        "function-triviality",
    }:
        return "available" if corpus_ready else "awaiting-lane-corpus"
    if signal_id == "build-width-stability":
        return "available" if complete_width else "collecting-width"
    if signal_id == "validation-harm":
        return "available" if machine_measured else "awaiting-machine-validation"
    if signal_id == "relational-corroboration":
        return "awaiting-relationship-evidence"
    if signal_id == "generation-drift":
        return "awaiting-multiple-generations"
    return "unavailable"


def compile_hash_discrimination(
    project_root: str | Path,
    authority: str | Path = DEFAULT_AUTHORITY,
    *,
    _machine_validation: Mapping[str, object] | None = None,
    _ecological_validation: Mapping[str, object] | None = None,
    _noisy_hashes: Mapping[str, object] | None = None,
    _lane_inventory: Mapping[str, object] | None = None,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    config = load_hash_discrimination_authority(root, authority)
    machine = (
        dict(_machine_validation)
        if _machine_validation is not None
        else compile_machine_validation(
            root, str(config["sources"]["machine_validation_authority"])
        )
    )
    ecological = (
        dict(_ecological_validation)
        if _ecological_validation is not None
        else compile_ecological_validation(
            root, str(config["sources"]["ecological_validation_authority"])
        )
    )
    noisy = (
        dict(_noisy_hashes)
        if _noisy_hashes is not None
        else compile_noisy_hashes(root, str(config["sources"]["noisy_hash_authority"]))
    )
    inventory = (
        dict(_lane_inventory)
        if _lane_inventory is not None
        else detect_lane_inventory(root)
    )

    complete_libraries = int(machine["summary"]["complete_libraries"])
    minimum_libraries = int(config["evidence"]["minimum_library_families"])
    raw_observations = int(inventory["summary"]["raw_observations"])
    compact_signatures = int(inventory["summary"]["compact_unique_signatures"])
    materialized_generations = int(inventory["summary"]["materialized_generations"])
    corpus_ready = materialized_generations > 0 and (
        raw_observations > 0 or compact_signatures > 0
    )
    machine_measured = machine["results"]["state"] == "measured-complete"
    complete_width = complete_libraries >= minimum_libraries

    blockers = []
    if not complete_width:
        blockers.append(
            f"{minimum_libraries - complete_libraries} of {minimum_libraries} C10 library families still lack complete width"
        )
    if not corpus_ready:
        blockers.append(
            "no occurrence-preserving lane corpus is available for all-signature denominators"
        )
    if not machine_measured:
        blockers.append("the C10 machine-validation report has not been measured")
    blockers.append(
        "candidate-level per-hash attribution contributions are not yet published"
    )

    ready_for_first_fit = (
        complete_width and corpus_ready and machine_measured and not blockers
    )
    generations = []
    for generation in config["generation"]:
        size = int(generation["cohort_library_families"])
        if size == minimum_libraries:
            state = "ready-for-fit" if ready_for_first_fit else "waiting-for-evidence"
        else:
            state = "future-cohort"
        generations.append(
            {
                **generation,
                "state": state,
                "scored_signatures": None,
                "published_at": None,
            }
        )

    signals = [
        {
            **signal,
            "state": _signal_state(
                str(signal["id"]),
                corpus_ready=corpus_ready,
                machine_measured=machine_measured,
                complete_width=complete_width,
            ),
            "measurement": None,
        }
        for signal in config["signal"]
    ]
    treatments = [
        {
            **treatment,
            "state": "planned-unmeasured",
            "precision": None,
            "recall": None,
            "false_positive_rate": None,
            "abstention_rate": None,
            "incorrect_confident_attributions": None,
        }
        for treatment in config["treatment"]
    ]
    summary = {
        "scored_signatures": None,
        "high_discrimination": None,
        "context_only": None,
        "ambiguous_or_shared": None,
        "demonstrated_harmful": None,
        "unclassified": None,
        "observed_collision_signatures": int(noisy["summary"]["observed_hashes"]),
    }
    body = {
        "schema_version": HASH_DISCRIMINATION_STATUS_SCHEMA,
        "id": config["id"],
        "label": config["label"],
        "state": (
            "ready-for-first-fit" if ready_for_first_fit else "awaiting-c10-evidence"
        ),
        "authority_path": config["authority_path"],
        "authority_sha256": config["authority_sha256"],
        "identity": config["identity"],
        "index": config["index"],
        "noise_risk": config["noise_risk"],
        "model": config["model"],
        "reproducibility": config["reproducibility"],
        "safety": config["safety"],
        "reason_categories": config["reason_categories"],
        "readiness": {
            "ready_for_first_fit": ready_for_first_fit,
            "required_library_families": minimum_libraries,
            "complete_library_families": complete_libraries,
            "materialized_lane_generations": materialized_generations,
            "raw_observations": raw_observations,
            "compact_unique_signatures": compact_signatures,
            "machine_validation_state": machine["results"]["state"],
            "ecological_measured_cases": int(ecological["aggregate"]["measured_cases"]),
            "blockers": blockers,
        },
        "signals": signals,
        "hdi_components": config["hdi_component"],
        "noise_components": config["noise_component"],
        "treatments": treatments,
        "generations": generations,
        "summary": summary,
        "noisy_hashes": {
            "state": noisy["state"],
            "status_digest": noisy["status_digest"],
            "summary": noisy["summary"],
        },
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return {**body, "status_digest": hashlib.sha256(canonical).hexdigest()}
