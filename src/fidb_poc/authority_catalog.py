"""Read-only projection of the reviewed planning authorities for operators."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tomllib

from .batch_time_model import compile_time_block_plan
from .batch_materializer import load_materialization_manifest
from .campaign_programme import compile_campaign_programme
from .config import load_configuration
from .c_width import compile_c_width
from .coverage_universe import load_coverage_universe
from .lane_registry import load_lane_registry
from .machine_validation import compile_machine_validation
from .machine_validation_runner import (
    canary_gate_status as machine_validation_canary_gate_status,
    runtime_status as machine_validation_runtime_status,
)
from .ecological_validation import compile_ecological_validation
from .hash_discrimination import compile_hash_discrimination
from .noisy_hashes import compile_noisy_hashes
from .plan_request import (
    REQUEST_SCHEMA,
    _factor_variants,
    _sensitivity_catalog,
    load_plan_request,
    resolve_plan,
)
from .performance_profiles import load_performance_profiles
from .qualification_pipeline import compile_qualification_pipeline
from .recipe_generator import load_recipes as load_source_recipes
from .target_registry import load_targets
from .toolchain_registry import load_toolchains
from .toolchain_packs import load_toolchain_pack_catalog
from .width_batch import load_width_batch, project_width_batch_readiness
from .width_study import load_width_study

AUTHORITY_SCHEMA = "fidb-authority-catalog/v18"


def _relative(root: Path, path: Path) -> str:
    return str(path.resolve().relative_to(root))


def _native_authority(
    root: Path, toolchain_pack_catalog: dict[str, object]
) -> tuple[list[dict[str, object]], dict[str, object]]:
    recipe_paths = sorted((root / "recipes").glob("*.toml"))
    requests = []
    for path in recipe_paths:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        requests.append(f'{document["name"]}@{document["version"]}')
    configuration = load_configuration(
        root / "worker.toml",
        tuple(requests),
        toolchain_catalog=toolchain_pack_catalog,
    )
    recipes = [
        {
            "id": f"{row.name}@{row.version}",
            "kind": "native",
            "mode": "native",
            "name": row.name,
            "version": row.version,
            "url": row.url,
            "sha256": row.sha256,
            "build_adapter": row.preferred_build_system,
            "allowed_build_adapters": list(row.allowed_build_systems),
            "static_archives": list(row.static_archives),
            **(
                {
                    "build_inputs": [
                        build_input.pin() for build_input in row.build_inputs
                    ]
                }
                if row.build_inputs
                else {}
            ),
            "authority_path": _relative(root, recipe_paths[index]),
        }
        for index, row in enumerate(configuration.libraries)
    ]
    routes = [
        {
            "id": row.id,
            "target_os": row.target_os,
            "architecture": row.architecture,
            "binary_format": row.binary_format,
            "compiler_family": row.compiler_family,
            "compiler": list(row.compiler),
            "archiver": list(row.archiver),
            "ranlib": list(row.ranlib),
            "compiler_flags": list(row.compiler_flags),
            "ghidra_language": row.ghidra_language,
            "ghidra_compiler_spec": row.ghidra_compiler_spec,
            "managed_toolchain_route": row.managed_toolchain_route,
            "toolchain_state": row.toolchain_state,
            "toolchain_identity": row.toolchain_identity,
            "toolchain_blocker": row.toolchain_blocker,
        }
        for row in configuration.routes
    ]
    treatments = [
        {
            "id": row.id,
            "factor": row.factor,
            "description": row.description,
            "phase": row.phase,
            "remove_flags": list(row.remove_flags),
            "append_flags": list(row.append_flags),
            "supported_routes": list(row.supported_routes),
            "artifact_shape": row.artifact_shape,
            "factor_values": dict(row.factor_values),
            "factor_variants": list(row.factor_variants),
        }
        for row in configuration.treatments
    ]
    return recipes, {
        "routes": routes,
        "treatments": treatments,
        "profiles": {
            name: list(values) for name, values in configuration.profiles.items()
        },
        "authority_path": "worker.toml",
    }


def _source_authority(root: Path) -> list[dict[str, object]]:
    result = []
    for kind, directory in (
        ("source-library", root / "recipes/libs"),
        ("malware", root / "recipes/malware"),
    ):
        paths = {
            (str(document["name"]), str(document["version"])): path
            for path in sorted(directory.glob("*.toml"))
            for document in [tomllib.loads(path.read_text(encoding="utf-8"))]
        }
        for row in load_source_recipes(directory):
            key = (str(row["name"]), str(row["version"]))
            result.append(
                {
                    "id": f'{row["name"]}@{row["version"]}',
                    "kind": kind,
                    "mode": "source",
                    "name": row["name"],
                    "version": str(row["version"]),
                    "url": row["url"],
                    "sha256": row["sha256"],
                    "build_adapter": row["build_adapter"],
                    "library_path": row["library_path"],
                    "toolchain_family": row["toolchain_family"],
                    "toolchain_variants": list(row.get("toolchain_variants", [])),
                    "authority_path": _relative(root, paths[key]),
                }
            )
    return result


def _toolchain_authority(root: Path) -> list[dict[str, object]]:
    result = []
    for row in load_toolchains(root / "toolchains/registry.toml"):
        result.append(
            {
                "id": f'{row["family"]}@{row["version"]}:{row["variant"]}',
                "family": row["family"],
                "version": str(row["version"]),
                "variant": row["variant"],
                "machine": row["machine"],
                "endianness": row["endianness"],
                "elf_class": int(row["elf_class"]),
                "archive_capable": "url" in row,
                "source_capable": "toolchain_url" in row,
                "cross_arch": row.get("cross_arch"),
                "cross_bin_prefix": row.get("cross_bin_prefix"),
                "archive_url": row.get("url"),
                "archive_sha256": row.get("sha256"),
                "toolchain_url": row.get("toolchain_url"),
                "toolchain_sha256": row.get("toolchain_sha256"),
            }
        )
    return result


def _target_authority(
    root: Path,
    native: dict[str, object],
    toolchains: list[dict[str, object]],
    toolchain_pack_catalog: dict[str, object],
) -> list[dict[str, object]]:
    result = []
    routes = native["routes"]
    for target in load_targets(root / "targets/registry.toml"):
        native_route_ids = [
            str(route["id"])
            for route in routes
            if route["target_os"] == target["platform"]
            and route["architecture"] == target["architecture"]
            and route["binary_format"] == target["binary_format"]
        ]
        matching_toolchains = (
            [
                row
                for row in toolchains
                if row["machine"] == target["machine"]
                and row["endianness"] == target["endianness"]
                and row["elf_class"] == target["bits"]
            ]
            if target["platform"] == "linux" and target["binary_format"] == "ELF"
            else []
        )
        managed_routes = [
            row
            for row in toolchain_pack_catalog["routes"]
            if row["target_id"] == target["id"]
        ]
        managed_pack_ids = list(
            dict.fromkeys(
                str(pack_id)
                for route in managed_routes
                for pack_id in route["pack_ids"]
            )
        )
        result.append(
            {
                **target,
                "native_route_ids": native_route_ids,
                "toolchain_ids": [row["id"] for row in matching_toolchains],
                "source_capable_toolchain_ids": [
                    row["id"] for row in matching_toolchains if row["source_capable"]
                ],
                "archive_capable_toolchain_ids": [
                    row["id"] for row in matching_toolchains if row["archive_capable"]
                ],
                "managed_route_ids": [str(row["id"]) for row in managed_routes],
                "managed_pack_ids": managed_pack_ids,
            }
        )
    return result


def _sensitivity_authority(
    root: Path,
) -> tuple[list[dict[str, object]], list[dict[str, object]], dict[str, str]]:
    factors, factors_digest = _sensitivity_catalog(root)
    document = tomllib.loads(
        (root / "sensitivity/variants.toml").read_text(encoding="utf-8")
    )
    requested = tuple(str(row["id"]) for row in document.get("variant", []))
    variants, variants_digest, _summary = _factor_variants(
        root,
        requested,
        {str(row["id"]) for row in factors},
    )
    return (
        factors,
        variants,
        {
            "factors_sha256": factors_digest,
            "variants_sha256": variants_digest,
        },
    )


def _plan_authority(root: Path) -> list[dict[str, object]]:
    plans = []
    for path in sorted((root / "plans").rglob("*.toml")):
        relative_parts = path.relative_to(root / "plans").parts
        if relative_parts and relative_parts[0] in {
            "materialized",
            "auto-materialized",
        }:
            continue
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
        if raw.get("schema_version") != REQUEST_SCHEMA:
            continue
        request = load_plan_request(path)
        resolved = resolve_plan(path, root)
        plans.append(
            {
                "path": _relative(root, path),
                "toml_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "name": request["name"],
                "policy": request["policy"],
                "coverage": request["coverage"],
                "queue": request["queue"],
                "matrices": request["matrices"],
                "plan_digest": resolved["plan_digest"],
                "summary": resolved["summary"],
                "inventory": resolved["inventory"],
            }
        )
    return plans


def _materialized_campaign_authority(root: Path) -> list[dict[str, object]]:
    queue_path = root / "plans/priority-queue.toml"
    queue = tomllib.loads(queue_path.read_text(encoding="utf-8"))
    queue_table = queue.get("queue", {})
    queued = {
        str(row["id"]): row
        for row in queue.get("batch", [])
        if isinstance(row, dict) and "id" in row
    }
    batch_order = list(queue_table.get("batch_order", []))
    armed = queue_table.get("armed") is True
    campaigns = []
    for path in sorted((root / "plans/materialized").glob("*/manifest.toml")):
        manifest = load_materialization_manifest(path)
        blocks = []
        for block in manifest.get("blocks", []):
            row = dict(block)
            plan_path = root / str(row["plan"])
            actual_sha256 = (
                hashlib.sha256(plan_path.read_bytes()).hexdigest()
                if plan_path.is_file()
                else None
            )
            queued_row = queued.get(str(row["id"]))
            queue_registered = (
                queued_row is not None
                and queued_row.get("plan") == row["plan"]
                and queued_row.get("plan_sha256") == row["plan_sha256"]
                and queued_row.get("queue_digest") == row["queue_digest"]
                and queued_row.get("executions") == row["executions"]
            )
            row.update(
                {
                    "plan_integrity": (
                        "verified" if actual_sha256 == row["plan_sha256"] else "drifted"
                    ),
                    "queue_registered": queue_registered,
                    "queue_position": (
                        batch_order.index(row["id"]) + 1
                        if row["id"] in batch_order
                        else None
                    ),
                }
            )
            blocks.append(row)
        plans_verified = all(row["plan_integrity"] == "verified" for row in blocks)
        ready = plans_verified and all(row["queue_registered"] for row in blocks)
        registered_blocks = sum(bool(row["queue_registered"]) for row in blocks)
        campaigns.append(
            {
                **manifest,
                "authority_path": _relative(root, path),
                "authority_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "state": (
                    "queued-armed"
                    if ready and armed
                    else (
                        "queued-disarmed"
                        if ready
                        else (
                            "materialized-unregistered"
                            if plans_verified and registered_blocks == 0
                            else "materialization-drifted"
                        )
                    )
                ),
                "blocks": blocks,
                "readiness": {
                    "verified_plans": sum(
                        row["plan_integrity"] == "verified" for row in blocks
                    ),
                    "registered_blocks": registered_blocks,
                    "queue_armed": armed,
                    "ready": ready,
                },
            }
        )
    return campaigns


def _auto_batch_campaign_authority(root: Path) -> list[dict[str, object]]:
    """Project generated candidate queues without treating them as active."""

    campaigns = []
    base = root / "plans/auto-materialized"
    if not base.is_dir():
        return campaigns
    for path in sorted(base.glob("*/manifest.toml")):
        manifest = tomllib.loads(path.read_text(encoding="utf-8"))
        if manifest.get("schema_version") != "fidb-auto-batch-campaign/v1":
            continue
        queue_path = root / str(manifest["queue"])
        queue = (
            tomllib.loads(queue_path.read_text(encoding="utf-8"))
            if queue_path.is_file()
            else {}
        )
        queue_table = queue.get("queue", {})
        schedule = queue.get("schedule", {})
        registered = {
            str(row["id"]): row
            for row in queue.get("batch", [])
            if isinstance(row, dict) and "id" in row
        }
        order = list(queue_table.get("batch_order", []))
        chunks = []
        for raw in manifest.get("chunks", []):
            chunk = dict(raw)
            plan_path = root / str(chunk["plan"])
            actual_sha256 = (
                hashlib.sha256(plan_path.read_bytes()).hexdigest()
                if plan_path.is_file()
                else None
            )
            queued = registered.get(str(chunk["id"]))
            queue_registered = (
                queued is not None
                and queued.get("plan") == chunk["plan"]
                and queued.get("plan_sha256") == chunk["plan_sha256"]
                and queued.get("queue_digest") == chunk["queue_digest"]
                and queued.get("executions") == chunk["executions"]
            )
            chunk.update(
                {
                    "plan_integrity": (
                        "verified"
                        if actual_sha256 == chunk["plan_sha256"]
                        else "drifted"
                    ),
                    "queue_registered": queue_registered,
                    "queue_position": (
                        order.index(chunk["id"]) + 1 if chunk["id"] in order else None
                    ),
                }
            )
            chunks.append(chunk)
        queue_ready = (
            queue_table.get("armed") is False
            and schedule.get("finish_started_batch") is True
            and schedule.get("chain_batches") is True
            and all(
                row["plan_integrity"] == "verified" and row["queue_registered"]
                for row in chunks
            )
        )
        campaigns.append(
            {
                **manifest,
                "authority_path": _relative(root, path),
                "authority_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "queue_integrity": "verified-disarmed" if queue_ready else "drifted",
                "chunks": chunks,
                "readiness": {
                    "verified_plans": sum(
                        row["plan_integrity"] == "verified" for row in chunks
                    ),
                    "registered_chunks": sum(
                        bool(row["queue_registered"]) for row in chunks
                    ),
                    "queue_disarmed": queue_table.get("armed") is False,
                    "scheduled_chaining": schedule.get("chain_batches") is True,
                    "ready": queue_ready,
                },
            }
        )
    return campaigns


def _width_batch_authority(
    root: Path,
    recipes: list[dict[str, object]],
    toolchain_pack_catalog: dict[str, object],
    inspections: dict[str, object],
) -> list[dict[str, object]]:
    return [
        project_width_batch_readiness(
            load_width_batch(
                root,
                path,
                _toolchain_catalog=toolchain_pack_catalog,
                _inspections=inspections,
            ),
            recipes,
        )
        for path in sorted((root / "batches").glob("*.toml"))
    ]


def _width_study_authority(
    root: Path,
    recipes: list[dict[str, object]],
    native: dict[str, object],
    targets: list[dict[str, object]],
    coverage_universe: dict[str, object],
) -> list[dict[str, object]]:
    studies = []
    language_ids = {str(row["id"]) for row in coverage_universe["languages"]}
    compiler_by_id = {
        str(row["id"]): row for row in coverage_universe["compiler_families"]
    }
    target_by_id = {str(row["id"]): row for row in targets}
    for path in sorted((root / "coverage").glob("*-width-study.toml")):
        study = load_width_study(path)
        if study["language_id"] not in language_ids:
            raise ValueError(
                f"width study {study['id']} uses unknown language {study['language_id']}"
            )
        projected_requirements = []
        for requirement in study["toolchain_requirements"]:
            target_id = str(requirement["target_id"])
            compiler_id = str(requirement["compiler_family"])
            target = target_by_id.get(target_id)
            compiler = compiler_by_id.get(compiler_id)
            if target is None:
                raise ValueError(
                    f"width study {study['id']} uses unknown target {target_id}"
                )
            if compiler is None:
                raise ValueError(
                    f"width study {study['id']} uses unknown compiler family {compiler_id}"
                )
            if study["language_id"] not in compiler["language_ids"]:
                raise ValueError(
                    f"width study {study['id']} compiler {compiler_id} does not support {study['language_id']}"
                )
            native_route_ids = list(target["native_route_ids"])
            source_ids = list(target["source_capable_toolchain_ids"])
            archive_ids = list(target["archive_capable_toolchain_ids"])
            if requirement["acquisition"] == "remote-worker":
                route_state = "remote-required"
            elif native_route_ids:
                route_state = "installed"
            elif source_ids:
                route_state = "pinned-source"
            elif archive_ids:
                route_state = "archive-only"
            else:
                route_state = "definition-required"
            projected_requirements.append(
                {
                    **requirement,
                    "target_label": target["label"],
                    "target_catalog_state": target["catalog_state"],
                    "compiler_label": compiler["label"],
                    "route_state": route_state,
                    "native_route_ids": native_route_ids,
                    "source_capable_toolchain_ids": source_ids,
                    "archive_capable_toolchain_ids": archive_ids,
                }
            )
        reviewed_recipe_releases = 0
        reviewed_recipe_families = 0
        source_evidence_families = 0
        projected_families = []
        for family in study["families"]:
            matches = [
                str(recipe["id"])
                for recipe in recipes
                if recipe["kind"] != "malware" and recipe["name"] == family["id"]
            ]
            reviewed_recipe_releases += len(matches)
            reviewed_recipe_families += bool(matches)
            source_evidence = family["source_state"] == "pinned-study-archive"
            source_evidence_families += source_evidence
            projected_families.append(
                {
                    **family,
                    "recipe_ids": matches,
                    "recipe_state": (
                        "reviewed-recipe"
                        if matches
                        else "source-evidence" if source_evidence else "recipe-required"
                    ),
                }
            )

        registered_routes = sum(
            bool(target["native_route_ids"] or target["source_capable_toolchain_ids"])
            for target in targets
        )
        executable_treatments = len(native["treatments"])
        default = next(
            row for row in study["presets"] if row["id"] == study["default_preset"]
        )
        blockers = []
        default_requirements = projected_requirements[: int(default["routes"])]
        default_route_state_counts = {
            state: sum(
                requirement["route_state"] == state
                for requirement in default_requirements
            )
            for state in (
                "installed",
                "pinned-source",
                "archive-only",
                "remote-required",
                "definition-required",
            )
        }
        missing_recipe_families = int(study["family_count"]) - reviewed_recipe_families
        required_release_pins = int(study["family_count"]) * int(default["releases"])
        if missing_recipe_families:
            blockers.append(
                f"{missing_recipe_families} of {study['family_count']} families need a reviewed recipe"
            )
        if reviewed_recipe_releases < required_release_pins:
            blockers.append(
                f"{required_release_pins - reviewed_recipe_releases} release recipe pins remain"
            )
        if registered_routes < int(default["routes"]):
            blockers.append(
                f"default width needs {default['routes']} registered routes; {registered_routes} are catalogued with source capability"
            )
        if executable_treatments < int(default["build_profiles"]):
            blockers.append(
                f"default width needs {default['build_profiles']} executable build profiles; {executable_treatments} is registered"
            )

        study["families"] = projected_families
        study["toolchain_requirements"] = projected_requirements
        study["authority_path"] = _relative(root, path)
        study["readiness"] = {
            "reviewed_recipe_families": reviewed_recipe_families,
            "reviewed_recipe_releases": reviewed_recipe_releases,
            "source_evidence_families": source_evidence_families,
            "missing_recipe_families": missing_recipe_families,
            "catalogued_target_contexts": len(targets),
            "registered_route_contexts": registered_routes,
            "default_route_state_counts": default_route_state_counts,
            "executable_treatments": executable_treatments,
            "queue_state": "not-materialized",
            "blockers": blockers,
        }
        studies.append(study)
    return studies


def authority_catalog(project_root: str | Path) -> dict[str, object]:
    """Return one validated, JSON-safe view of all planning authorities."""

    root = Path(project_root).expanduser().resolve()
    toolchain_pack_catalog = load_toolchain_pack_catalog(root)
    toolchain_inspections: dict[str, object] = {}
    native_recipes, native = _native_authority(root, toolchain_pack_catalog)
    toolchains = _toolchain_authority(root)
    factors, variants, sensitivity_digests = _sensitivity_authority(root)
    target_path = root / "targets/registry.toml"
    lane_path = root / "lanes/registry.toml"
    performance_path = root / "performance/profiles.toml"
    coverage_path = root / "coverage/universe.toml"
    coverage_universe = load_coverage_universe(coverage_path)
    coverage_universe["authority_path"] = _relative(root, coverage_path)
    recipes = [*native_recipes, *_source_authority(root)]
    targets = _target_authority(root, native, toolchains, toolchain_pack_catalog)
    lane_registry = load_lane_registry(lane_path, target_path)
    lane_registry["authority_path"] = _relative(root, lane_path)
    performance_profiles = load_performance_profiles(root).document()
    width_studies = _width_study_authority(
        root, recipes, native, targets, coverage_universe
    )
    width_batches = _width_batch_authority(
        root, recipes, toolchain_pack_catalog, toolchain_inspections
    )
    qualification_pipeline = compile_qualification_pipeline(
        root, width_batches, validate_routes=False
    )
    qualification_by_batch = {
        str(row["batch_id"]): row for row in qualification_pipeline["gates"]
    }
    qualified_width_batches = []
    for batch in width_batches:
        gate = qualification_by_batch[str(batch["id"])]
        readiness = dict(batch["readiness"])
        blockers = list(readiness["blockers"])
        if not gate["satisfied"]:
            blockers.extend(f"qualification: {blocker}" for blocker in gate["blockers"])
        otherwise_ready = (
            not readiness["recipe_blocked_libraries"]
            and not readiness["toolchain_blocked_routes"]
        )
        readiness.update(
            {
                "qualification_state": gate["state"],
                "qualification_satisfied": gate["satisfied"],
                "queue_eligible_executions": (
                    readiness["materializable_executions"]
                    if otherwise_ready and gate["satisfied"]
                    else 0
                ),
                "queue_state": (
                    gate["promotion_state"]
                    if otherwise_ready and gate["satisfied"]
                    else f'qualification-{gate["state"]}'
                ),
                "blockers": blockers,
            }
        )
        qualified_width_batches.append(
            {**batch, "qualification": gate, "readiness": readiness}
        )
    width_batches = qualified_width_batches
    campaign_programmes = [
        compile_campaign_programme(
            root,
            path.relative_to(root),
            width_batches=width_batches,
            recipes=recipes,
        )
        for path in sorted((root / "campaigns").glob("*.toml"))
    ]
    time_block_plan = compile_time_block_plan(root)
    materialized_campaigns = _materialized_campaign_authority(root)
    auto_batch_campaigns = _auto_batch_campaign_authority(root)
    width_ids = {"c-width-v1"}
    width_ids.update(
        Path(str(row["authorities"]["width"])).stem for row in width_batches
    )
    width_compilations = [
        compile_c_width(
            root,
            width_id,
            _catalog=toolchain_pack_catalog,
            _inspections=toolchain_inspections,
        )
        for width_id in sorted(width_ids)
    ]
    width_compilations_by_id = {
        str(compilation["id"]): compilation for compilation in width_compilations
    }
    machine_validations = []
    for path in sorted((root / "validation").glob("*.toml")):
        authority = tomllib.loads(path.read_text(encoding="utf-8"))
        if authority.get("schema_version") != "fidb-machine-validation/v1":
            continue
        width_id = Path(str(authority["width_authority"])).stem
        machine_validations.append(
            {
                **compile_machine_validation(
                    root,
                    path.relative_to(root),
                    _width_compilation=width_compilations_by_id.get(width_id),
                ),
                "run": machine_validation_runtime_status(root),
                "canary_gate": machine_validation_canary_gate_status(root),
            }
        )
    ecological_validation = compile_ecological_validation(root)
    noisy_hashes = compile_noisy_hashes(root)
    hash_discrimination = compile_hash_discrimination(
        root,
        _machine_validation=machine_validations[0],
        _ecological_validation=ecological_validation,
        _noisy_hashes=noisy_hashes,
    )
    width_paths = [root / str(row["authority_path"]) for row in width_studies]
    width_batch_paths = [root / str(row["authority_path"]) for row in width_batches]
    width_compilation_paths = [
        root / str(row["authorities"]["width"]) for row in width_compilations
    ]
    body = {
        "schema_version": AUTHORITY_SCHEMA,
        "coverage_universe": coverage_universe,
        "width_studies": width_studies,
        "width_batches": width_batches,
        "campaign_programmes": campaign_programmes,
        "qualification_pipeline": qualification_pipeline,
        "time_block_plan": time_block_plan,
        "materialized_campaigns": materialized_campaigns,
        "auto_batch_campaigns": auto_batch_campaigns,
        "machine_validations": machine_validations,
        "ecological_validation": ecological_validation,
        "noisy_hashes": noisy_hashes,
        "hash_discrimination": hash_discrimination,
        "width_compilations": width_compilations,
        "recipes": recipes,
        "native": native,
        "targets": targets,
        "lane_registry": lane_registry,
        "performance_profiles": performance_profiles,
        "toolchains": toolchains,
        "toolchain_pack_catalog": toolchain_pack_catalog,
        "factors": factors,
        "factor_variants": variants,
        "plans": _plan_authority(root),
        "sources": {
            "recipes": "recipes/",
            "routes": "worker.toml",
            "targets": "targets/registry.toml",
            "lanes": "lanes/registry.toml",
            "performance_profiles": "performance/profiles.toml",
            "toolchains": "toolchains/registry.toml",
            "toolchain_packs": "toolchains/packs.toml + compilers.toml + routes.toml + inputs.toml + qualifications.toml + profiles/",
            "factors": "sensitivity/factors.toml",
            "factor_variants": "sensitivity/variants.toml",
            "coverage_universe": "coverage/universe.toml",
            "width_studies": "coverage/*-width-study.toml",
            "width_batches": "batches/*.toml",
            "campaign_programmes": "campaigns/*.toml + coverage/evidence/four-source-n80-v1.csv",
            "qualification_pipeline": "qualification/pipeline.toml + qualification/*.toml",
            "time_block_plan": "performance/batch-planning.toml",
            "materialized_campaigns": "plans/materialized/*/manifest.toml",
            "auto_batch_campaigns": "plans/auto-materialized/*/manifest.toml",
            "machine_validations": "validation/*.toml + plans/validation-schedule.toml",
            "ecological_validation": "validation/ecological-validation.toml + var/fidb-ecological-validation/cases/",
            "noisy_hashes": "validation/noisy-hashes.toml + validation/noisy-hash-decisions/*.toml",
            "hash_discrimination": "validation/hash-discrimination.toml + artifacts/hash-discrimination/",
            "width_compilations": "coverage/c-width-v1.toml plus batch-referenced width authorities",
            "width_evidence": "coverage/evidence/c-route-toolchain-canary-v1-reference-host-2026-09-02.toml",
            "plans": "plans/",
        },
        "source_digests": {
            **sensitivity_digests,
            "targets_sha256": hashlib.sha256(target_path.read_bytes()).hexdigest(),
            "lanes_sha256": hashlib.sha256(lane_path.read_bytes()).hexdigest(),
            "performance_profiles_sha256": hashlib.sha256(
                performance_path.read_bytes()
            ).hexdigest(),
            "coverage_universe_sha256": hashlib.sha256(
                coverage_path.read_bytes()
            ).hexdigest(),
            "width_studies_sha256": hashlib.sha256(
                b"".join(path.read_bytes() for path in width_paths)
            ).hexdigest(),
            "width_batches_sha256": hashlib.sha256(
                b"".join(path.read_bytes() for path in width_batch_paths)
            ).hexdigest(),
            "campaign_programmes_sha256": hashlib.sha256(
                b"".join(
                    (root / str(row["authorities"]["programme"])).read_bytes()
                    + (root / str(row["authorities"]["candidates"])).read_bytes()
                    for row in campaign_programmes
                )
            ).hexdigest(),
            "qualification_pipeline_sha256": hashlib.sha256(
                b"".join(
                    path.read_bytes()
                    for path in sorted((root / "qualification").glob("*.toml"))
                )
            ).hexdigest(),
            "batch_planning_sha256": hashlib.sha256(
                (root / "performance/batch-planning.toml").read_bytes()
            ).hexdigest(),
            "materialized_campaigns_sha256": hashlib.sha256(
                b"".join(
                    (root / str(row["authority_path"])).read_bytes()
                    for row in materialized_campaigns
                )
            ).hexdigest(),
            "auto_batch_campaigns_sha256": hashlib.sha256(
                b"".join(
                    (root / str(row["authority_path"])).read_bytes()
                    for row in auto_batch_campaigns
                )
            ).hexdigest(),
            "machine_validations_sha256": hashlib.sha256(
                b"".join(
                    (root / str(row["authority_path"])).read_bytes()
                    for row in machine_validations
                )
                + (root / "plans/validation-schedule.toml").read_bytes()
            ).hexdigest(),
            "ecological_validation_sha256": hashlib.sha256(
                (root / "validation/ecological-validation.toml").read_bytes()
            ).hexdigest(),
            "noisy_hashes_sha256": hashlib.sha256(
                (root / "validation/noisy-hashes.toml").read_bytes()
                + b"".join(
                    path.read_bytes()
                    for path in sorted(
                        (root / "validation/noisy-hash-decisions").glob("*.toml")
                    )
                )
            ).hexdigest(),
            "hash_discrimination_sha256": hashlib.sha256(
                (root / "validation/hash-discrimination.toml").read_bytes()
            ).hexdigest(),
            "c_width_sha256": hashlib.sha256(
                (root / "coverage/c-width-v1.toml").read_bytes()
            ).hexdigest(),
            "width_compilations_sha256": hashlib.sha256(
                b"".join(path.read_bytes() for path in width_compilation_paths)
            ).hexdigest(),
            "c_width_evidence_sha256": hashlib.sha256(
                (
                    root
                    / "coverage/evidence/c-route-toolchain-canary-v1-reference-host-2026-09-02.toml"
                ).read_bytes()
            ).hexdigest(),
        },
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return {**body, "authority_digest": hashlib.sha256(canonical).hexdigest()}
