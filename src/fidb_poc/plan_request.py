"""Resolve a declarative build request against the reviewed project catalogs.

The request contains identities and policy only.  URLs, hashes, compiler flags,
commands, adapters and ABI details always come from worker.toml, recipes/ and
toolchains/registry.toml.  Resolution is deliberately separate from execution.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import tomllib
from dataclasses import replace
from pathlib import Path

from .config import Configuration, load_configuration, select_configuration
from .elf import ghidra_language
from .ghidra_fid import compiler_spec_for_language
from .recipe_generator import (
    VM_ISO_SHA256,
    VM_ISO_URL,
    load_recipes as load_source_recipes,
)
from .source_build import EXECUTORS
from .toolchain_registry import load_toolchains

REQUEST_SCHEMA = "fidb-plan/v1"
RESOLVED_SCHEMA = "fidb-resolved-plan/v1"
SENSITIVITY_SCHEMA = "fidb-sensitivity/v1"
VARIANTS_SCHEMA = "fidb-factor-variants/v1"
MATRIX_KINDS = {
    "native",
    "width-native",
    "source-library",
    "archive-library",
    "malware",
}
PRIORITIES = {"background", "normal", "high"}
QUEUE_STRATEGIES = {"recipe-then-variant", "variant-then-recipe"}
QUALIFICATION_GATE_FIELDS = {
    "batch_id",
    "batch_digest",
    "authority_path",
    "authority_sha256",
    "pipeline_authority_path",
    "pipeline_authority_sha256",
    "input_digest",
    "qualification_digest",
    "evidence_path",
    "evidence_sha256",
}


def _keys(row: dict[str, object], allowed: set[str], context: str) -> None:
    unknown = set(row) - allowed
    if unknown:
        raise ValueError(f"{context} contains unsupported fields: {sorted(unknown)}")


def _token(value: object, context: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(
            f"{context} must be a non-empty string without outer whitespace"
        )
    return value


def _tokens(value: object, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{context} must be a non-empty array")
    result = tuple(_token(item, context) for item in value)
    if len(set(result)) != len(result):
        raise ValueError(f"{context} contains duplicates")
    return result


def load_plan_request(path: str | Path) -> dict[str, object]:
    plan_path = Path(path)
    document = tomllib.loads(plan_path.read_text(encoding="utf-8"))
    _keys(
        document,
        {
            "schema_version",
            "name",
            "policy",
            "coverage",
            "queue",
            "qualification_gate",
            "matrix",
        },
        "plan",
    )
    if document.get("schema_version") != REQUEST_SCHEMA:
        raise ValueError(f"unsupported or missing plan schema_version in {plan_path}")
    name = _token(document.get("name"), "plan name")

    policy = document.get("policy", {})
    if not isinstance(policy, dict):
        raise ValueError("plan policy must be a table")
    _keys(policy, {"max_cells", "priority"}, "plan policy")
    max_cells = policy.get("max_cells", 256)
    if not isinstance(max_cells, int) or isinstance(max_cells, bool) or max_cells < 1:
        raise ValueError("plan policy max_cells must be a positive integer")
    priority = policy.get("priority", "normal")
    if priority not in PRIORITIES:
        raise ValueError(f"unsupported plan priority: {priority!r}")

    coverage = document.get("coverage", {})
    if not isinstance(coverage, dict):
        raise ValueError("plan coverage must be a table")
    _keys(coverage, {"factor_variants"}, "plan coverage")
    factor_variants = coverage.get("factor_variants", [])
    if not isinstance(factor_variants, list):
        raise ValueError("plan coverage factor_variants must be an array")
    normalized_variants = tuple(
        _token(item, "plan coverage factor_variants") for item in factor_variants
    )
    if len(set(normalized_variants)) != len(normalized_variants):
        raise ValueError("plan coverage factor_variants contains duplicates")

    queue = document.get("queue", {})
    if not isinstance(queue, dict):
        raise ValueError("plan queue must be a table")
    _keys(queue, {"strategy", "recipe_order"}, "plan queue")
    strategy = queue.get("strategy", "recipe-then-variant")
    if strategy not in QUEUE_STRATEGIES:
        raise ValueError(f"unsupported queue strategy: {strategy!r}")
    recipe_order_value = queue.get("recipe_order", [])
    if not isinstance(recipe_order_value, list):
        raise ValueError("plan queue recipe_order must be an array")
    recipe_order = tuple(
        _token(item, "plan queue recipe_order") for item in recipe_order_value
    )
    if len(set(recipe_order)) != len(recipe_order):
        raise ValueError("plan queue recipe_order contains duplicates")

    raw_qualification_gates = document.get("qualification_gate")
    qualification_gates = []
    if raw_qualification_gates is not None:
        if not isinstance(raw_qualification_gates, list) or not raw_qualification_gates:
            raise ValueError("plan qualification_gate must be a non-empty table array")
        for index, gate in enumerate(raw_qualification_gates, start=1):
            if not isinstance(gate, dict):
                raise ValueError(f"plan qualification gate {index} must be a table")
            _keys(gate, QUALIFICATION_GATE_FIELDS, f"plan qualification gate {index}")
            missing = QUALIFICATION_GATE_FIELDS - set(gate)
            if missing:
                raise ValueError(
                    f"plan qualification gate {index} is missing fields: {sorted(missing)}"
                )
            normalized_gate = {
                field: _token(gate[field], f"plan qualification gate {index} {field}")
                for field in QUALIFICATION_GATE_FIELDS
            }
            for field in (
                "batch_digest",
                "authority_sha256",
                "pipeline_authority_sha256",
                "input_digest",
                "qualification_digest",
                "evidence_sha256",
            ):
                value = normalized_gate[field]
                if len(value) != 64 or any(
                    character not in "0123456789abcdef" for character in value
                ):
                    raise ValueError(
                        f"plan qualification gate {index} {field} must be a lowercase SHA-256"
                    )
            qualification_gates.append(normalized_gate)
        ids = [row["batch_id"] for row in qualification_gates]
        if len(ids) != len(set(ids)):
            raise ValueError("plan qualification gates contain duplicate batch ids")

    matrices = document.get("matrix")
    if not isinstance(matrices, list) or not matrices:
        raise ValueError("plan must contain at least one [[matrix]] table")
    seen: set[str] = set()
    normalized = []
    for index, matrix in enumerate(matrices, start=1):
        if not isinstance(matrix, dict):
            raise ValueError(f"matrix {index} must be a table")
        _keys(
            matrix,
            {
                "id",
                "kind",
                "recipes",
                "routes",
                "treatments",
                "toolchains",
                "executor",
                "factor_variants",
                "width_batch",
            },
            f"matrix {index}",
        )
        matrix_id = _token(matrix.get("id"), f"matrix {index} id")
        if matrix_id in seen:
            raise ValueError(f"duplicate matrix id: {matrix_id}")
        seen.add(matrix_id)
        kind = matrix.get("kind")
        if kind not in MATRIX_KINDS:
            raise ValueError(f"matrix {matrix_id} has unsupported kind: {kind!r}")
        row: dict[str, object] = {
            "id": matrix_id,
            "kind": kind,
            "recipes": _tokens(matrix.get("recipes"), f"matrix {matrix_id} recipes"),
        }
        if "factor_variants" in matrix:
            matrix_factor_variants = matrix["factor_variants"]
            if not isinstance(matrix_factor_variants, list):
                raise ValueError(f"matrix {matrix_id} factor_variants must be an array")
            normalized_matrix_variants = tuple(
                _token(item, f"matrix {matrix_id} factor_variants")
                for item in matrix_factor_variants
            )
            if len(set(normalized_matrix_variants)) != len(normalized_matrix_variants):
                raise ValueError(
                    f"matrix {matrix_id} factor_variants contains duplicates"
                )
            row["factor_variants"] = normalized_matrix_variants
        if kind in {"native", "width-native"}:
            row["routes"] = _tokens(matrix.get("routes"), f"matrix {matrix_id} routes")
            row["treatments"] = _tokens(
                matrix.get("treatments"), f"matrix {matrix_id} treatments"
            )
            forbidden = {"toolchains", "executor"} & set(matrix)
            if forbidden:
                raise ValueError(
                    f"native matrix {matrix_id} cannot set: {sorted(forbidden)}"
                )
            if kind == "width-native":
                row["width_batch"] = _token(
                    matrix.get("width_batch"), f"matrix {matrix_id} width_batch"
                )
            elif "width_batch" in matrix:
                raise ValueError(f"native matrix {matrix_id} cannot set width_batch")
        elif kind == "archive-library":
            row["toolchains"] = _tokens(
                matrix.get("toolchains"), f"matrix {matrix_id} toolchains"
            )
            forbidden = {"routes", "treatments", "executor", "width_batch"} & set(
                matrix
            )
            if forbidden:
                raise ValueError(
                    f"archive-library matrix {matrix_id} cannot set: {sorted(forbidden)}"
                )
        else:
            row["toolchains"] = _tokens(
                matrix.get("toolchains"), f"matrix {matrix_id} toolchains"
            )
            executor = matrix.get("executor", "qemu")
            if executor not in EXECUTORS:
                raise ValueError(
                    f"matrix {matrix_id} has unsupported executor: {executor!r}"
                )
            row["executor"] = executor
            forbidden = {"routes", "treatments", "width_batch"} & set(matrix)
            if forbidden:
                raise ValueError(
                    f"{kind} matrix {matrix_id} cannot set: {sorted(forbidden)}"
                )
        normalized.append(row)
    requested_recipes = {
        recipe for matrix in normalized for recipe in matrix["recipes"]
    }
    if recipe_order and set(recipe_order) != requested_recipes:
        missing = requested_recipes - set(recipe_order)
        extra = set(recipe_order) - requested_recipes
        raise ValueError(
            "plan queue recipe_order must contain each requested recipe exactly once; "
            f"missing={sorted(missing)}, extra={sorted(extra)}"
        )
    if not recipe_order:
        recipe_order = tuple(
            dict.fromkeys(
                recipe for matrix in normalized for recipe in matrix["recipes"]
            )
        )
    result = {
        "schema_version": REQUEST_SCHEMA,
        "name": name,
        "policy": {"max_cells": max_cells, "priority": priority},
        "coverage": {"factor_variants": normalized_variants},
        "queue": {"strategy": strategy, "recipe_order": recipe_order},
        "matrices": normalized,
    }
    if raw_qualification_gates is not None:
        result["qualification_gates"] = tuple(qualification_gates)
    return result


def _sensitivity_catalog(project_root: Path) -> tuple[list[dict[str, object]], str]:
    path = project_root / "sensitivity/factors.toml"
    raw = path.read_bytes()
    document = tomllib.loads(raw.decode("utf-8"))
    if document.get("schema_version") != SENSITIVITY_SCHEMA:
        raise ValueError(f"unsupported or missing sensitivity schema_version in {path}")
    factors = document.get("factor")
    if not isinstance(factors, list) or not factors:
        raise ValueError("sensitivity catalog must contain [[factor]] rows")
    seen = set()
    for row in factors:
        _keys(
            row,
            {
                "id",
                "stage",
                "label",
                "control",
                "evidence",
                "confidence",
                "impact",
                "coverage_action",
            },
            "factor",
        )
        factor_id = _token(row.get("id"), "factor id")
        if factor_id in seen:
            raise ValueError(f"duplicate sensitivity factor: {factor_id}")
        seen.add(factor_id)
        for field in (
            "stage",
            "label",
            "control",
            "evidence",
            "confidence",
            "impact",
            "coverage_action",
        ):
            _token(row.get(field), f"factor {factor_id} {field}")
    return factors, hashlib.sha256(raw).hexdigest()


def _factor_variants(
    project_root: Path, requested: tuple[str, ...], known_factors: set[str]
) -> tuple[list[dict[str, object]], str, dict[str, object]]:
    path = project_root / "sensitivity/variants.toml"
    raw = path.read_bytes()
    document = tomllib.loads(raw.decode("utf-8"))
    if document.get("schema_version") != VARIANTS_SCHEMA:
        raise ValueError(
            f"unsupported or missing factor-variants schema_version in {path}"
        )
    rows = document.get("variant")
    if not isinstance(rows, list) or not rows:
        raise ValueError("factor-variants catalog must contain [[variant]] rows")
    catalog = {}
    for row in rows:
        _keys(
            row,
            {"id", "factor", "group", "label", "state", "authority"},
            "factor variant",
        )
        variant_id = _token(row.get("id"), "factor variant id")
        if variant_id in catalog:
            raise ValueError(f"duplicate factor variant: {variant_id}")
        for field in ("factor", "group", "label", "state", "authority"):
            _token(row.get(field), f"factor variant {variant_id} {field}")
        if row["factor"] not in known_factors:
            raise ValueError(
                f"factor variant {variant_id} references unknown factor: {row['factor']}"
            )
        catalog[variant_id] = row
    missing = set(requested) - set(catalog)
    if missing:
        raise ValueError(f"unknown factor variants: {sorted(missing)}")
    selected = [catalog[variant_id] for variant_id in requested]
    by_factor: dict[str, int] = {}
    for row in selected:
        factor = str(row["factor"])
        by_factor[factor] = by_factor.get(factor, 0) + 1
    combinations = 1
    registered_combinations = 1
    for count in by_factor.values():
        combinations *= count
    for factor in by_factor:
        registered_combinations *= sum(
            row["factor"] == factor and row["state"] == "registered" for row in selected
        )
    summary = {
        "selected": len(selected),
        "combinations": combinations if selected else 1,
        "registered_combinations": registered_combinations if selected else 1,
        "registered": sum(row["state"] == "registered" for row in selected),
        "unmet": sum(row["state"] != "registered" for row in selected),
    }
    return selected, hashlib.sha256(raw).hexdigest(), summary


def _recipe_identity(row: dict[str, object]) -> str:
    return f'{row["name"]}@{row["version"]}'


def _toolchain_identity(row: dict[str, object]) -> str:
    return f'{row["family"]}@{row["version"]}:{row["variant"]}'


def _selected_rows(
    rows: list[dict[str, object]], identities: tuple[str, ...], label: str
) -> list[dict[str, object]]:
    catalog = {_recipe_identity(row): row for row in rows}
    missing = set(identities) - set(catalog)
    if missing:
        raise ValueError(f"unknown {label}: {sorted(missing)}")
    return [catalog[identity] for identity in identities]


def _patches(
    recipe: dict[str, object], variant: str, project_root: Path
) -> list[dict[str, str]]:
    result = []
    for patch in recipe.get("patches", {}).get(variant, []):
        path = Path(str(patch)).resolve()
        try:
            display_path = str(path.relative_to(project_root))
        except ValueError as error:
            raise ValueError(f"patch is outside project root: {path}") from error
        result.append(
            {
                "path": display_path,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    return result


def _analysis(machine: str, endianness: str, bits: int) -> dict[str, object]:
    language = ghidra_language(machine, endianness, bits)
    return {
        "ghidra_language": language,
        "ghidra_compiler_spec": (
            compiler_spec_for_language(language) if language else None
        ),
        "ghidra_version": "execution-probed",
        "analysis_profile": "fid-safe-default",
    }


def _source_cell(
    matrix: dict[str, object],
    recipe: dict[str, object],
    toolchain: dict[str, object],
    project_root: Path,
) -> dict[str, object]:
    variant = str(toolchain["variant"])
    permitted = set(recipe.get("toolchain_variants", []))
    reasons = []
    if toolchain["family"] != recipe["toolchain_family"]:
        reasons.append("toolchain family is incompatible with the recipe")
    if permitted and variant not in permitted:
        reasons.append("recipe does not permit this toolchain variant")
    source_capable = all(
        key in toolchain
        for key in (
            "toolchain_url",
            "toolchain_sha256",
            "cross_bin_prefix",
            "cross_arch",
        )
    )
    if not source_capable:
        reasons.append("registry row is archive-only and has no pinned cross-compiler")
    language = _analysis(
        str(toolchain["machine"]),
        str(toolchain["endianness"]),
        int(toolchain["elf_class"]),
    )
    if language["ghidra_language"] is None:
        reasons.append("target ABI has no Ghidra language mapping")
    status = "blocked" if reasons else "planned"
    toolchain_pin = {
        "family": toolchain["family"],
        "version": str(toolchain["version"]),
        "variant": variant,
        "capability": "source" if source_capable else "archive-only",
    }
    if source_capable:
        toolchain_pin.update(
            {
                "url": toolchain["toolchain_url"],
                "sha256": toolchain["toolchain_sha256"],
                "cross_bin_prefix": toolchain["cross_bin_prefix"],
                "cross_arch": toolchain["cross_arch"],
            }
        )
    build = {
        "adapter": recipe["build_adapter"],
        "output": recipe["library_path"],
        "compiler_flags": "adapter-owned",
        "patches": _patches(recipe, variant, project_root),
    }
    target = {
        "machine": toolchain["machine"],
        "endianness": toolchain["endianness"],
        "elf_class": int(toolchain["elf_class"]),
    }
    return {
        "id": f'{matrix["id"]}:{recipe["name"]}@{recipe["version"]}:{variant}',
        "matrix": matrix["id"],
        "kind": matrix["kind"],
        "status": status,
        "blockers": reasons,
        "readiness": "unprobed" if status == "planned" else "unmet",
        "recipe": {
            "name": recipe["name"],
            "version": str(recipe["version"]),
            "url": recipe["url"],
            "sha256": recipe["sha256"],
        },
        "target": target,
        "toolchain": toolchain_pin,
        "build": build,
        "analysis": language,
        "routing": {"executor": matrix["executor"]},
        "sensitivity": {
            "source-identity": {
                "state": "controlled",
                "value": f'{recipe["name"]}@{recipe["version"]}:{str(recipe["sha256"])[:12]}',
            },
            "target-platform-format": {
                "state": "controlled",
                "value": "linux:ELF",
            },
            "target-abi": {
                "state": "controlled",
                "value": f'{target["machine"]}:{target["endianness"]}:{target["elf_class"]}',
            },
            "compiler-family": {"state": "pinned-with-toolchain", "value": variant},
            "compiler-version": {
                "state": "pinned-with-toolchain",
                "value": str(toolchain["version"]),
            },
            "optimization-level": {"state": "adapter-owned", "value": None},
            "link-time-optimization": {"state": "adapter-owned", "value": None},
            "frame-pointer": {"state": "adapter-owned", "value": None},
            "stack-protection": {"state": "adapter-owned", "value": None},
            "sanitizer-mode": {"state": "adapter-owned", "value": None},
            "cpu-target-tuning": {
                "state": "pinned-with-toolchain",
                "value": variant,
            },
            "position-independent-code": {"state": "adapter-owned", "value": None},
            "debug-information-emission": {
                "state": "adapter-owned",
                "value": None,
            },
            "build-environment": {"state": "execution-probed", "value": None},
            "build-shape": {"state": "controlled", "value": recipe["build_adapter"]},
            "link-shape": {"state": "controlled", "value": recipe["library_path"]},
            "ghidra-language": {
                "state": "controlled",
                "value": language["ghidra_language"],
            },
            "ghidra-compiler-spec": {
                "state": "controlled",
                "value": language["ghidra_compiler_spec"],
            },
            "ghidra-application": {"state": "execution-probed", "value": None},
            "pyghidra-version": {"state": "execution-probed", "value": None},
            "java-runtime": {"state": "execution-probed", "value": None},
            "analysis-configuration": {
                "state": "controlled",
                "value": "fid-safe-default",
            },
        },
    }


def _archive_cell(
    matrix: dict[str, object],
    toolchain: dict[str, object],
    project_root: Path,
) -> dict[str, object]:
    variant = str(toolchain["variant"])
    identity = f'{toolchain["family"]}@{toolchain["version"]}'
    reasons = []
    if identity not in matrix["recipes"]:
        reasons.append("archive identity is incompatible with requested library")
    archive_capable = all(
        key in toolchain for key in ("url", "sha256", "library_member")
    )
    if not archive_capable:
        reasons.append("registry row has no pinned archive candidate")
    analysis = _analysis(
        str(toolchain["machine"]),
        str(toolchain["endianness"]),
        int(toolchain["elf_class"]),
    )
    if analysis["ghidra_language"] is None:
        reasons.append("target ABI has no Ghidra language mapping")
    members = None
    if "members_file" in toolchain:
        members_path = Path(str(toolchain["members_file"])).resolve()
        try:
            relative = str(members_path.relative_to(project_root))
        except ValueError as error:
            raise ValueError(
                f"archive members file is outside project root: {members_path}"
            ) from error
        members = {
            "path": relative,
            "sha256": toolchain["members_sha256"],
        }
    status = "blocked" if reasons else "planned"
    target = {
        "machine": toolchain["machine"],
        "endianness": toolchain["endianness"],
        "elf_class": int(toolchain["elf_class"]),
    }
    return {
        "id": f'{matrix["id"]}:{identity}:{variant}',
        "matrix": matrix["id"],
        "kind": "archive-library",
        "status": status,
        "blockers": reasons,
        "readiness": "unprobed" if status == "planned" else "unmet",
        "recipe": {
            "name": toolchain["family"],
            "version": str(toolchain["version"]),
            "url": toolchain.get("url"),
            "sha256": toolchain.get("sha256"),
        },
        "target": target,
        "toolchain": {
            "family": toolchain["family"],
            "version": str(toolchain["version"]),
            "variant": variant,
            "capability": "archive" if archive_capable else "source-only",
        },
        "build": {
            "adapter": "archive-extract",
            "output": toolchain.get("library_member"),
            "members": members,
            "compiler_flags": None,
        },
        "analysis": analysis,
        "routing": {"executor": "archive-local"},
        "sensitivity": {
            "source-identity": {
                "state": "controlled",
                "value": f'{identity}:{str(toolchain.get("sha256", ""))[:12]}',
            },
            "target-platform-format": {
                "state": "controlled",
                "value": "linux:ELF",
            },
            "target-abi": {
                "state": "controlled",
                "value": f'{target["machine"]}:{target["endianness"]}:{target["elf_class"]}',
            },
            "compiler-family": {
                "state": "archive-provenance-only",
                "value": variant,
            },
            "compiler-version": {
                "state": "archive-provenance-only",
                "value": str(toolchain["version"]),
            },
            "build-shape": {
                "state": "controlled",
                "value": "archive-extract",
            },
            "link-shape": {
                "state": "controlled",
                "value": toolchain.get("library_member"),
            },
            "ghidra-language": {
                "state": "controlled",
                "value": analysis["ghidra_language"],
            },
            "ghidra-compiler-spec": {
                "state": "controlled",
                "value": analysis["ghidra_compiler_spec"],
            },
            "analysis-configuration": {
                "state": "controlled",
                "value": "fid-safe-default",
            },
        },
    }


def _native_cells(
    matrix: dict[str, object], project_root: Path
) -> list[dict[str, object]]:
    configuration = load_configuration(
        project_root / "worker.toml", tuple(matrix["recipes"])
    )
    configuration = select_configuration(
        configuration,
        route_ids=tuple(matrix["routes"]),
        treatment_ids=tuple(matrix["treatments"]),
        profile="smoke",
    )
    return _native_cells_from_configuration(matrix, configuration)


def _native_cells_from_configuration(
    matrix: dict[str, object], configuration: Configuration
) -> list[dict[str, object]]:
    cells = []
    for library in configuration.libraries:
        for route in configuration.routes:
            for treatment in configuration.treatments:
                flags = list(treatment.flags_for(route))
                blockers = []
                if not treatment.applies_to(route):
                    blockers.append("treatment does not support route")
                if route.toolchain_state == "unavailable":
                    blockers.append(route.toolchain_blocker)
                status = "planned" if not blockers else "blocked"
                cell = {
                    "id": f'{matrix["id"]}:{library.identifier}:{route.id}:{treatment.id}',
                    "matrix": matrix["id"],
                    "kind": "native",
                    "status": status,
                    "blockers": blockers,
                    "readiness": "unprobed" if status == "planned" else "unmet",
                    "recipe": {
                        "name": library.name,
                        "version": library.version,
                        "url": library.url,
                        "sha256": library.sha256,
                        **(
                            {
                                "build_inputs": [
                                    build_input.pin()
                                    for build_input in library.build_inputs
                                ]
                            }
                            if library.build_inputs
                            else {}
                        ),
                    },
                    "target": {
                        "os": route.target_os,
                        "architecture": route.architecture,
                        "binary_format": route.binary_format,
                    },
                    "toolchain": {
                        "route": route.id,
                        "compiler": list(route.compiler),
                        "archiver": list(route.archiver),
                        "ranlib": list(route.ranlib),
                        "identity": route.toolchain_identity,
                    },
                    "build": {
                        "adapter": library.preferred_build_system,
                        "treatment": treatment.id,
                        "factor": treatment.factor,
                        "compiler_flags": flags,
                        "artifact_shape": treatment.artifact_shape,
                        "factor_variants": list(treatment.factor_variants),
                        "factor_variant_requirements": dict(
                            zip(
                                (factor for factor, _value in treatment.factor_values),
                                treatment.factor_variants,
                            )
                        ),
                    },
                    "analysis": {
                        "ghidra_language": route.ghidra_language,
                        "ghidra_compiler_spec": route.ghidra_compiler_spec,
                        "ghidra_version": "execution-probed",
                        "analysis_profile": "fid-safe-default",
                    },
                    "routing": {
                        "executor": "native-local",
                        "worker_pool": (
                            "macos-native"
                            if route.target_os == "macos"
                            else "library-local"
                        ),
                    },
                    "sensitivity": {
                        "source-identity": {
                            "state": "controlled",
                            "value": f"{library.identifier}:{library.sha256[:12]}",
                        },
                        "target-platform-format": {
                            "state": "controlled",
                            "value": f"{route.target_os}:{route.binary_format}",
                        },
                        "target-abi": {
                            "state": "controlled",
                            "value": route.architecture,
                        },
                        "compiler-family": {
                            "state": "execution-probed",
                            "value": route.compiler_family,
                        },
                        "compiler-version": {
                            "state": "execution-probed",
                            "value": None,
                        },
                        "optimization-level": {
                            "state": "controlled",
                            "value": "O2",
                        },
                        "link-time-optimization": {
                            "state": "controlled",
                            "value": "off",
                        },
                        "frame-pointer": {
                            "state": "controlled",
                            "value": "retained",
                        },
                        "position-independent-code": {
                            "state": "controlled",
                            "value": "on",
                        },
                        "debug-information-emission": {
                            "state": "controlled",
                            "value": "off",
                        },
                        "sanitizer-mode": {
                            "state": "controlled",
                            "value": "off",
                        },
                        "cpu-target-tuning": {
                            "state": "controlled",
                            "value": route.architecture,
                        },
                        "build-environment": {
                            "state": "execution-probed",
                            "value": None,
                        },
                        "build-shape": {
                            "state": "controlled",
                            "value": library.preferred_build_system,
                        },
                        "link-shape": {
                            "state": "controlled",
                            "value": treatment.phase,
                        },
                        "ghidra-language": {
                            "state": "controlled",
                            "value": route.ghidra_language,
                        },
                        "ghidra-compiler-spec": {
                            "state": "controlled",
                            "value": route.ghidra_compiler_spec,
                        },
                        "ghidra-application": {
                            "state": "execution-probed",
                            "value": None,
                        },
                        "pyghidra-version": {
                            "state": "execution-probed",
                            "value": None,
                        },
                        "java-runtime": {
                            "state": "execution-probed",
                            "value": None,
                        },
                        "analysis-configuration": {
                            "state": "controlled",
                            "value": "fid-safe-default",
                        },
                    },
                }
                for factor, value in treatment.factor_values:
                    cell["sensitivity"][factor] = {
                        "state": "controlled",
                        "value": value,
                    }
                cells.append(cell)
    return cells


def _width_native_cells(
    matrix: dict[str, object],
    project_root: Path,
    *,
    _batch: dict[str, object] | None = None,
    _catalog: dict[str, object] | None = None,
) -> list[dict[str, object]]:
    """Resolve compiler-generation routes through their pinned width batch."""

    from .c_width import compile_c_width, materialize_width_configuration
    from .toolchain_packs import load_toolchain_pack_catalog, resolve_toolchain_profile
    from .width_batch import load_width_batch

    relative = Path(str(matrix["width_batch"]))
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(
            "width-native matrix width_batch must stay inside project root"
        )
    batch_path = (project_root / relative).resolve()
    try:
        batch_path.relative_to(project_root)
    except ValueError as error:
        raise ValueError(
            "width-native matrix width_batch must stay inside project root"
        ) from error

    catalog = _catalog or load_toolchain_pack_catalog(project_root)
    batch = _batch or load_width_batch(
        project_root, batch_path, _toolchain_catalog=catalog
    )
    batch_recipes = {
        str(row["recipe_id"]): row for row in batch["libraries"]  # type: ignore[index]
    }
    requested_recipes = tuple(str(value) for value in matrix["recipes"])
    missing_recipes = set(requested_recipes) - set(batch_recipes)
    if missing_recipes:
        raise ValueError(
            f"width-native matrix selects recipes outside its batch: {sorted(missing_recipes)}"
        )

    width_id = Path(str(batch["authorities"]["width"])).stem  # type: ignore[index]
    compilation = compile_c_width(project_root, width_id, _catalog=catalog)
    route_plan = resolve_toolchain_profile(
        project_root, str(compilation["toolchain_profile"]), _catalog=catalog
    )
    configuration = materialize_width_configuration(
        project_root, requested_recipes[0], route_plan, _catalog=catalog
    )
    recipe_configuration = load_configuration(
        project_root / "worker.toml",
        requested_recipes,
        toolchain_catalog=catalog,
    )
    configuration = replace(configuration, libraries=recipe_configuration.libraries)
    configuration = select_configuration(
        configuration,
        route_ids=tuple(matrix["routes"]),
        treatment_ids=tuple(matrix["treatments"]),
        profile="smoke",
    )

    executable = {
        (str(row["route_id"]), str(row["treatment_id"])): str(row["profile_id"])
        for row in compilation["applicability"]  # type: ignore[index]
        if row["state"] == "executable"
    }
    selected_pairs = {
        (route.id, treatment.id)
        for route in configuration.routes
        for treatment in configuration.treatments
    }
    outside = selected_pairs - executable.keys()
    if outside:
        raise ValueError(
            "width-native matrix selects non-executable route/treatment pairs: "
            f"{sorted(outside)}"
        )
    expected_per_library = int(
        batch["summary"]["executions_per_library"]  # type: ignore[index]
    )
    if expected_per_library != len(executable):
        raise ValueError(
            "width-native plans cannot yet express downstream artifact, analysis, "
            "or replay multipliers"
        )

    route_metadata = {
        str(row["id"]): row for row in compilation["routes"]  # type: ignore[index]
    }
    cells = _native_cells_from_configuration(matrix, configuration)
    for cell in cells:
        route_id = str(cell["toolchain"]["route"])
        treatment_id = str(cell["build"]["treatment"])
        metadata = route_metadata[route_id]
        cell["toolchain"]["compiler_id"] = metadata["compiler_id"]
        cell["sensitivity"]["compiler-family"] = {
            "state": "controlled",
            "value": metadata["compiler_family"],
        }
        cell["sensitivity"]["compiler-version"] = {
            "state": "controlled",
            "value": metadata["compiler_id"],
        }
        cell["width"] = {
            "batch_id": batch["id"],
            "batch_digest": batch["batch_digest"],
            "width_id": compilation["id"],
            "compilation_digest": compilation["compilation_digest"],
            "route_profile_digest": compilation["route_profile_digest"],
            "profile_id": executable[(route_id, treatment_id)],
        }
    return cells


def _complete_sensitivity(
    cells: list[dict[str, object]], factors: list[dict[str, object]]
) -> int:
    unmodeled = 0
    for cell in cells:
        assessment = cell["sensitivity"]
        for factor in factors:
            factor_id = factor["id"]
            if factor_id not in assessment:
                assessment[factor_id] = {"state": "unmodeled", "value": None}
                unmodeled += 1
        cell["usefulness"] = {
            "exact_cell": "intended reference identity",
            "adjacent_variant": "requires factor-specific measured retention",
            "cross_route": "unproven",
            "function_recovery": "route-and-analysis-profile-dependent",
            "unmodeled_factors": sum(
                value["state"] in {"unmodeled", "adapter-owned"}
                for value in assessment.values()
            ),
        }
    return unmodeled


def _variant_combinations(
    variants: list[dict[str, object]],
) -> list[tuple[dict[str, object], ...]]:
    by_factor: dict[str, list[dict[str, object]]] = {}
    for variant in variants:
        by_factor.setdefault(str(variant["factor"]), []).append(variant)
    return list(itertools.product(*by_factor.values())) if by_factor else [()]


def _queue_preview(
    cells: list[dict[str, object]],
    variants_by_matrix: dict[str, list[dict[str, object]]],
    strategy: str,
) -> list[dict[str, object]]:
    pairs: list[tuple[dict[str, object], tuple[dict[str, object], ...]]] = []
    if strategy == "recipe-then-variant":
        for cell in cells:
            variants = variants_by_matrix[str(cell["matrix"])]
            pairs.extend(
                (cell, combination) for combination in _variant_combinations(variants)
            )
    else:
        profiles: dict[
            tuple[str, ...],
            tuple[list[dict[str, object]], list[dict[str, object]]],
        ] = {}
        for cell in cells:
            variants = variants_by_matrix[str(cell["matrix"])]
            profile = tuple(str(variant["id"]) for variant in variants)
            if profile not in profiles:
                profiles[profile] = (variants, [])
            profiles[profile][1].append(cell)
        for variants, profile_cells in profiles.values():
            pairs.extend(
                (cell, combination)
                for combination in _variant_combinations(variants)
                for cell in profile_cells
            )

    result = []
    for position, (cell, combination) in enumerate(pairs, start=1):
        factor_blockers = [
            f'factor variant {variant["id"]} is {variant["state"]}'
            for variant in combination
            if variant["state"] != "registered"
        ]
        requirements = cell.get("build", {}).get("factor_variant_requirements", {})
        factor_blockers.extend(
            f'factor variant {variant["id"]} is incompatible with '
            f'{cell["build"]["treatment"]}'
            for variant in combination
            if requirements.get(str(variant["factor"]))
            not in {
                None,
                variant["id"],
            }
        )
        blockers = [*cell["blockers"], *factor_blockers]
        result.append(
            {
                "position": position,
                "base_cell": cell["id"],
                "factor_variants": [variant["id"] for variant in combination],
                "state": "planned" if not blockers else "blocked",
                "blockers": blockers,
            }
        )
    return result


def queue_identity_digest(rows: list[dict[str, object]]) -> str:
    """Digest the portable, ordered identity and admission state of queue rows."""

    identity = [
        {
            "position": int(row["position"]),
            "base_cell": str(row["base_cell"]),
            "factor_variants": list(row["factor_variants"]),
            "state": str(row["state"]),
        }
        for row in rows
    ]
    canonical = json.dumps(
        identity, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _artifact_inventory(
    project_root: Path, cells: list[dict[str, object]]
) -> dict[str, object]:
    sealed: dict[str, list[str]] = {}
    for path in sorted(
        (project_root / "artifacts/runs").glob(
            "job-*/attempt-*/artifacts/cell-seal.json"
        )
    ):
        try:
            seal = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if (
            not isinstance(seal, dict)
            or seal.get("schema_version") != "fidb-cell-seal/v1"
        ):
            continue
        identity = seal.get("cell")
        artifacts = seal.get("artifacts")
        if not isinstance(identity, dict) or not isinstance(artifacts, dict):
            continue
        cell_id = identity.get("id")
        if not isinstance(cell_id, str) or not cell_id:
            continue
        attempt_root = path.parent.parent
        valid = True
        for key in ("fidb", "fidbf"):
            record = artifacts.get(key)
            if not isinstance(record, dict):
                valid = False
                break
            relative = record.get("path")
            digest = record.get("sha256")
            size = record.get("bytes")
            if (
                not isinstance(relative, str)
                or not relative
                or relative.startswith("/")
                or "\\" in relative
                or any(part in {"", ".", ".."} for part in relative.split("/"))
                or not isinstance(digest, str)
                or not isinstance(size, int)
                or isinstance(size, bool)
                or size < 1
            ):
                valid = False
                break
            artifact = attempt_root / relative
            try:
                payload = artifact.read_bytes()
            except OSError:
                valid = False
                break
            if (
                artifact.is_symlink()
                or len(payload) != size
                or hashlib.sha256(payload).hexdigest() != digest
            ):
                valid = False
                break
        if valid:
            sealed.setdefault(cell_id, []).append(str(path.relative_to(project_root)))

    loose_fidbs = sorted((project_root / "artifacts/fidbs").glob("*.fidb"))
    coverage = {}
    for cell in cells:
        recipe = cell["recipe"]
        evidence = list(sealed.get(str(cell["id"]), []))
        state = "built" if evidence else "not-built"
        if not evidence:
            tokens = (
                str(recipe["name"]).lower(),
                str(recipe["version"]).lower(),
                str(cell["target"].get("machine", "")).lower(),
            )
            loose = [
                path
                for path in loose_fidbs
                if all(not token or token in path.name.lower() for token in tokens)
            ]
            if loose:
                state = "artifact-only"
                evidence = [str(path.relative_to(project_root)) for path in loose]
        coverage[cell["id"]] = {
            "state": state,
            "evidence": evidence,
            "note": (
                "sealed provenance found"
                if state == "built"
                else (
                    "artifact exists without matching provenance manifest"
                    if state == "artifact-only"
                    else "no matching built evidence"
                )
            ),
        }
    states = [row["state"] for row in coverage.values()]
    return {
        "summary": {
            "built": states.count("built"),
            "artifact_only": states.count("artifact-only"),
            "not_built": states.count("not-built"),
        },
        "cells": coverage,
    }


def resolve_plan(
    request_path: str | Path, project_root: str | Path
) -> dict[str, object]:
    root = Path(project_root).resolve()
    request = load_plan_request(request_path)
    width_batches = {}
    width_batches_by_authority = {}
    width_catalog = None
    for matrix in request["matrices"]:
        if matrix["kind"] != "width-native":
            continue
        relative = Path(str(matrix["width_batch"]))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(
                "width-native matrix width_batch must stay inside project root"
            )
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as error:
            raise ValueError(
                "width-native matrix width_batch must stay inside project root"
            ) from error
        from .qualification_pipeline import validate_embedded_gates
        from .toolchain_packs import load_toolchain_pack_catalog
        from .width_batch import load_width_batch

        if width_catalog is None:
            width_catalog = load_toolchain_pack_catalog(root)
        batch = load_width_batch(root, path, _toolchain_catalog=width_catalog)
        width_batches[str(batch["id"])] = batch
        width_batches_by_authority[str(matrix["width_batch"])] = batch
    if width_batches:
        validate_embedded_gates(
            root,
            list(width_batches.values()),
            tuple(request.get("qualification_gates", ())),
        )
    factors, factors_digest = _sensitivity_catalog(root)
    known_factors = {str(factor["id"]) for factor in factors}
    variants, variants_digest, coverage_summary = _factor_variants(
        root,
        tuple(request["coverage"]["factor_variants"]),
        known_factors,
    )
    variants_by_matrix = {}
    matrix_overrides = {}
    matrix_coverage_summaries = {}
    for matrix in request["matrices"]:
        selected = variants
        selected_summary = coverage_summary
        if "factor_variants" in matrix:
            selected, selected_digest, selected_summary = _factor_variants(
                root,
                tuple(matrix["factor_variants"]),
                known_factors,
            )
            if selected_digest != variants_digest:
                raise ValueError("factor-variants catalog changed during resolution")
            matrix_overrides[str(matrix["id"])] = {
                "summary": selected_summary,
                "factor_variants": selected,
            }
        variants_by_matrix[str(matrix["id"])] = selected
        matrix_coverage_summaries[str(matrix["id"])] = selected_summary
    toolchains = load_toolchains(root / "toolchains/registry.toml")
    toolchains_by_identity = {_toolchain_identity(row): row for row in toolchains}
    cells = []
    for matrix in request["matrices"]:
        if matrix["kind"] == "native":
            cells.extend(_native_cells(matrix, root))
            continue
        if matrix["kind"] == "width-native":
            cells.extend(
                _width_native_cells(
                    matrix,
                    root,
                    _batch=width_batches_by_authority[str(matrix["width_batch"])],
                    _catalog=width_catalog,
                )
            )
            continue
        if matrix["kind"] == "archive-library":
            missing = set(matrix["toolchains"]) - set(toolchains_by_identity)
            if missing:
                raise ValueError(f"unknown toolchain variants: {sorted(missing)}")
            requested = set(matrix["recipes"])
            known = {
                f'{toolchains_by_identity[variant]["family"]}@{toolchains_by_identity[variant]["version"]}'
                for variant in matrix["toolchains"]
            }
            if requested != known:
                raise ValueError(
                    "archive-library recipes must exactly match selected registry "
                    f"families/versions: requested={sorted(requested)}, selected={sorted(known)}"
                )
            for variant in matrix["toolchains"]:
                cells.append(
                    _archive_cell(matrix, toolchains_by_identity[variant], root)
                )
            continue
        recipe_directory = (
            "recipes/libs" if matrix["kind"] == "source-library" else "recipes/malware"
        )
        recipes = _selected_rows(
            load_source_recipes(root / recipe_directory),
            tuple(matrix["recipes"]),
            f'{matrix["kind"]} recipes',
        )
        missing = set(matrix["toolchains"]) - set(toolchains_by_identity)
        if missing:
            raise ValueError(f"unknown toolchain variants: {sorted(missing)}")
        for recipe in recipes:
            for variant in matrix["toolchains"]:
                cells.append(
                    _source_cell(matrix, recipe, toolchains_by_identity[variant], root)
                )
    recipe_positions = {
        recipe: position
        for position, recipe in enumerate(request["queue"]["recipe_order"])
    }
    cells.sort(
        key=lambda cell: recipe_positions[
            f'{cell["recipe"]["name"]}@{cell["recipe"]["version"]}'
        ]
    )
    desired_cells = sum(
        int(matrix_coverage_summaries[str(cell["matrix"])]["combinations"])
        for cell in cells
    )
    if desired_cells > request["policy"]["max_cells"]:
        raise ValueError(
            f"resolved plan has {desired_cells} desired cells after factor expansion, "
            f'exceeding max_cells={request["policy"]["max_cells"]}'
        )
    queue_preview = _queue_preview(
        cells, variants_by_matrix, str(request["queue"]["strategy"])
    )
    unmodeled = _complete_sensitivity(cells, factors)
    planned_cells = sum(row["state"] == "planned" for row in queue_preview)
    resolved_coverage = {
        "schema_version": VARIANTS_SCHEMA,
        "catalog_sha256": variants_digest,
        "summary": coverage_summary,
        "factor_variants": variants,
    }
    if matrix_overrides:
        resolved_coverage["matrix_overrides"] = matrix_overrides
    body = {
        "schema_version": RESOLVED_SCHEMA,
        "name": request["name"],
        "policy": request["policy"],
        "coverage": resolved_coverage,
        "queue": request["queue"],
        "matrices": request["matrices"],
        "summary": {
            "base_cells": len(cells),
            "desired_cells": desired_cells,
            "planned_cells": planned_cells,
            "blocked_cells": desired_cells - planned_cells,
            "sensitivity_factors": len(factors),
            "unmodeled_factor_instances": unmodeled,
        },
        "sensitivity_catalog": {
            "schema_version": SENSITIVITY_SCHEMA,
            "sha256": factors_digest,
            "factors": factors,
        },
        "cells": cells,
        "queue_preview": queue_preview,
    }
    if "qualification_gates" in request:
        body["qualification_gates"] = request["qualification_gates"]
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return {
        **body,
        "plan_digest": hashlib.sha256(canonical).hexdigest(),
        "inventory": _artifact_inventory(root, cells),
    }


def write_resolved_plan(document: dict[str, object], destination: str | Path) -> None:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(payload, encoding="utf-8")
    temporary.replace(path)
