"""Declarative, checksum-pinned toolchain packs and profile resolution.

Pack authority describes immutable downloads.  Routes compose those packs for
one reviewed target/compiler pair, while profiles preserve the complete route
denominator (including external workers).  Loading and planning are read-only;
the typed CLI is the only acquisition boundary.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import platform
import re
import tomllib

from .coverage_universe import load_coverage_universe
from .compiler_identities import load_compiler_identities
from .compiler_width_assets import load_compiler_width_assets
from .target_registry import load_targets
from .toolchain_cache import CacheInspection, MANAGED_DOWNLOADS, inspect_cached
from .toolchain_inputs import (
    MANAGED_BINDINGS,
    MANAGED_INPUTS,
    inspect_input_binding,
)
from .toolchain_prepare import MANAGED_PREPARED, inspect_prepared
from .toolchain_qualification import (
    MANAGED_COMPOSED,
    MANAGED_QUALIFIED,
    composition_dependencies,
    inspect_composition,
    inspect_qualification,
    route_material_digest,
)

PACKS_SCHEMA = "fidb-toolchain-packs/v2"
ROUTES_SCHEMA = "fidb-toolchain-routes/v2"
INPUTS_SCHEMA = "fidb-toolchain-inputs/v1"
QUALIFICATIONS_SCHEMA = "fidb-toolchain-qualifications/v1"
PROFILE_SCHEMA = "fidb-toolchain-profile/v1"
CATALOG_SCHEMA = "fidb-toolchain-pack-catalog/v4"
PROFILE_PLAN_SCHEMA = "fidb-toolchain-profile-plan/v3"

_PACK_FIELDS = {
    "id",
    "label",
    "kind",
    "target_ids",
    "compiler_family",
    "compiler_version",
    "compiler_driver",
    "linker_family",
    "linker_version",
    "runtime",
    "runtime_version",
    "url",
    "sha256",
    "download_bytes",
    "installed_bytes_estimate",
    "size_evidence",
    "license_ids",
    "upstream_release",
    "upstream_authority",
    "archive_root",
}
_ROUTE_FIELDS = {
    "id",
    "label",
    "target_id",
    "compiler_id",
    "coverage_requirement_id",
    "compiler_family",
    "target_triple",
    "evidence_role",
    "provisioning",
    "pack_ids",
    "input_ids",
    "worker_class",
    "qualification_state",
    "additional_installed_bytes_estimate",
    "additional_size_evidence",
    "external_requirements",
}
_INPUT_FIELDS = {
    "id",
    "label",
    "kind",
    "target_ids",
    "source_policy",
    "required_metadata",
    "state",
    "authority",
}
_QUALIFICATION_FIELDS = {
    "route_id",
    "tool_source",
    "tool_pack_id",
    "driver_pattern",
    "cxx_driver_pattern",
    "archiver_pattern",
    "version_contains",
    "smoke_languages",
    "composition",
}
_PROFILE_FIELDS = {
    "schema_version",
    "id",
    "label",
    "language_id",
    "host_system",
    "host_architecture",
    "route_ids",
    "external_policy",
    "purpose",
    "authority",
}
_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _read_toml(path: Path) -> dict[str, object]:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _identifier(value: object, field: str) -> str:
    text = _string(value, field)
    if _ID.fullmatch(text) is None:
        raise ValueError(f"{field} must be a stable lowercase identifier")
    return text


def _strings(value: object, field: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        raise ValueError(
            f"{field} must be a {'possibly empty' if allow_empty else 'non-empty'} string list"
        )
    if not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{field} must contain only non-empty strings")
    result = list(value)
    if len(result) != len(set(result)):
        raise ValueError(f"{field} contains duplicates")
    return result


def _rows(
    value: object,
    kind: str,
    fields: set[str],
    *,
    allow_empty: bool = False,
) -> list[dict[str, object]]:
    if not isinstance(value, list) or (not value and not allow_empty):
        raise ValueError(f"toolchain authority requires at least one {kind}")
    result: list[dict[str, object]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise ValueError(f"{kind} row {index} must be a table")
        unknown = set(raw) - fields
        missing = (fields - {"external_requirements"}) - set(raw)
        if unknown or missing:
            raise ValueError(
                f"{kind} row {index} has missing {sorted(missing)} and unknown {sorted(unknown)}"
            )
        row = dict(raw)
        row_id = _identifier(row.get("id"), f"{kind} row {index} id")
        if row_id in seen:
            raise ValueError(f"duplicate {kind} id: {row_id}")
        seen.add(row_id)
        result.append(row)
    return result


def _load_packs(path: Path) -> tuple[dict[str, object], list[dict[str, object]]]:
    document = _read_toml(path)
    allowed = {
        "schema_version",
        "host_system",
        "host_architecture",
        "source_authority",
        "cache_policy",
        "pack",
    }
    if set(document) != allowed or document.get("schema_version") != PACKS_SCHEMA:
        raise ValueError(
            "toolchain packs authority has an unsupported schema or fields"
        )
    header = {
        name: _string(document[name], f"packs {name}") for name in allowed - {"pack"}
    }
    rows = _rows(document.get("pack"), "pack", _PACK_FIELDS)
    for row in rows:
        pack_id = str(row["id"])
        row["target_ids"] = _strings(row["target_ids"], f"pack {pack_id} target_ids")
        row["license_ids"] = _strings(row["license_ids"], f"pack {pack_id} license_ids")
        for field in _PACK_FIELDS - {
            "target_ids",
            "license_ids",
            "download_bytes",
            "installed_bytes_estimate",
        }:
            _string(row[field], f"pack {pack_id} {field}")
        if _DIGEST.fullmatch(str(row["sha256"])) is None:
            raise ValueError(f"pack {pack_id} has invalid sha256")
        if not str(row["url"]).startswith("https://"):
            raise ValueError(f"pack {pack_id} URL must use HTTPS")
        for field in ("download_bytes", "installed_bytes_estimate"):
            if not isinstance(row[field], int) or int(row[field]) <= 0:
                raise ValueError(f"pack {pack_id} {field} must be positive")
        if int(row["installed_bytes_estimate"]) < int(row["download_bytes"]):
            raise ValueError(
                f"pack {pack_id} installed estimate is smaller than its archive"
            )
    return header, rows


def _load_routes(path: Path) -> list[dict[str, object]]:
    document = _read_toml(path)
    if set(document) != {"schema_version", "route"}:
        raise ValueError("toolchain routes authority has unexpected fields")
    if document.get("schema_version") != ROUTES_SCHEMA:
        raise ValueError(
            f"unsupported toolchain routes schema: {document.get('schema_version')}"
        )
    rows = _rows(document.get("route"), "route", _ROUTE_FIELDS)
    for row in rows:
        route_id = str(row["id"])
        for field in _ROUTE_FIELDS - {
            "pack_ids",
            "input_ids",
            "external_requirements",
            "additional_installed_bytes_estimate",
        }:
            _string(row[field], f"route {route_id} {field}")
        row["pack_ids"] = _strings(
            row["pack_ids"], f"route {route_id} pack_ids", allow_empty=True
        )
        row["input_ids"] = _strings(
            row["input_ids"], f"route {route_id} input_ids", allow_empty=True
        )
        row["external_requirements"] = _strings(
            row.get("external_requirements", []),
            f"route {route_id} external_requirements",
            allow_empty=True,
        )
        if (
            not isinstance(row["additional_installed_bytes_estimate"], int)
            or int(row["additional_installed_bytes_estimate"]) < 0
        ):
            raise ValueError(
                f"route {route_id} additional_installed_bytes_estimate must be non-negative"
            )
        if row["provisioning"] not in {
            "downloadable-pack",
            "pack-plus-user-input",
            "external-worker",
        }:
            raise ValueError(f"route {route_id} has invalid provisioning")
        if row["evidence_role"] not in {
            "primary",
            "cross-build",
            "native-reference",
        }:
            raise ValueError(f"route {route_id} has invalid evidence_role")
        if row["provisioning"] == "downloadable-pack" and (
            not row["pack_ids"] or row["input_ids"]
        ):
            raise ValueError(f"downloadable route {route_id} requires a pack")
        if row["provisioning"] == "pack-plus-user-input" and (
            not row["pack_ids"] or not row["input_ids"]
        ):
            raise ValueError(
                f"pack-plus-user-input route {route_id} requires packs and inputs"
            )
        if row["provisioning"] == "external-worker" and (
            row["pack_ids"] or row["input_ids"] or not row["external_requirements"]
        ):
            raise ValueError(
                f"external route {route_id} requires external requirements and no packs"
            )
    return rows


def _load_inputs(path: Path) -> list[dict[str, object]]:
    document = _read_toml(path)
    if set(document) != {"schema_version", "input"}:
        raise ValueError("toolchain inputs authority has unexpected fields")
    if document.get("schema_version") != INPUTS_SCHEMA:
        raise ValueError(
            f"unsupported toolchain inputs schema: {document.get('schema_version')}"
        )
    rows = _rows(document.get("input"), "input", _INPUT_FIELDS, allow_empty=True)
    for row in rows:
        input_id = str(row["id"])
        for field in _INPUT_FIELDS - {"target_ids", "required_metadata"}:
            _string(row[field], f"input {input_id} {field}")
        row["target_ids"] = _strings(row["target_ids"], f"input {input_id} target_ids")
        row["required_metadata"] = _strings(
            row["required_metadata"], f"input {input_id} required_metadata"
        )
        if not str(row["authority"]).startswith("https://"):
            raise ValueError(f"input {input_id} authority must use HTTPS")
    return rows


def _load_qualifications(path: Path) -> list[dict[str, object]]:
    document = _read_toml(path)
    if set(document) != {"schema_version", "qualification"}:
        raise ValueError("toolchain qualifications authority has unexpected fields")
    if document.get("schema_version") != QUALIFICATIONS_SCHEMA:
        raise ValueError(
            "unsupported toolchain qualifications schema: "
            f"{document.get('schema_version')}"
        )
    raw_rows = document.get("qualification")
    if not isinstance(raw_rows, list) or not raw_rows:
        raise ValueError("toolchain authority requires qualifications")
    rows: list[dict[str, object]] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_rows):
        if not isinstance(raw, dict) or set(raw) != _QUALIFICATION_FIELDS:
            raise ValueError(
                f"qualification row {index} has unexpected or missing fields"
            )
        row = dict(raw)
        route_id = _identifier(row["route_id"], f"qualification row {index} route_id")
        if route_id in seen:
            raise ValueError(f"duplicate qualification route: {route_id}")
        seen.add(route_id)
        for field in _QUALIFICATION_FIELDS - {"smoke_languages"}:
            _string(row[field], f"qualification {route_id} {field}")
        row["smoke_languages"] = _strings(
            row["smoke_languages"], f"qualification {route_id} smoke_languages"
        )
        row["id"] = route_id
        rows.append(row)
    return rows


def _load_profiles(directory: Path) -> tuple[list[dict[str, object]], list[Path]]:
    result: list[dict[str, object]] = []
    paths = sorted(directory.glob("*.toml"))
    seen: set[str] = set()
    if not paths:
        raise ValueError("toolchain authority requires at least one profile")
    for path in paths:
        document = _read_toml(path)
        if set(document) != _PROFILE_FIELDS:
            raise ValueError(f"profile {path.name} has unexpected or missing fields")
        if document.get("schema_version") != PROFILE_SCHEMA:
            raise ValueError(f"unsupported toolchain profile schema: {path.name}")
        profile = dict(document)
        profile_id = _identifier(profile["id"], f"profile {path.name} id")
        if profile_id in seen:
            raise ValueError(f"duplicate toolchain profile id: {profile_id}")
        seen.add(profile_id)
        for field in _PROFILE_FIELDS - {"schema_version", "route_ids"}:
            _string(profile[field], f"profile {profile_id} {field}")
        profile["route_ids"] = _strings(
            profile["route_ids"], f"profile {profile_id} route_ids"
        )
        if profile["external_policy"] != "report":
            raise ValueError(f"profile {profile_id} external_policy must be report")
        profile["authority_path"] = str(path.relative_to(directory.parent.parent))
        result.append(profile)
    return result, paths


def load_toolchain_pack_catalog(project_root: str | Path) -> dict[str, object]:
    """Load and cross-validate all pack, route, and profile authority."""

    root = Path(project_root).expanduser().resolve()
    packs_path = root / "toolchains/packs.toml"
    routes_path = root / "toolchains/routes.toml"
    inputs_path = root / "toolchains/inputs.toml"
    qualifications_path = root / "toolchains/qualifications.toml"
    compilers_path = root / "toolchains/compilers.toml"
    compiler_width_path = root / "toolchains/compiler-width.toml"
    profiles_directory = root / "toolchains/profiles"
    header, packs = _load_packs(packs_path)
    routes = _load_routes(routes_path)
    inputs = _load_inputs(inputs_path)
    qualifications = _load_qualifications(qualifications_path)
    profiles, profile_paths = _load_profiles(profiles_directory)
    compilers = load_compiler_identities(compilers_path)
    compiler_width = load_compiler_width_assets(compiler_width_path)
    packs.extend(compiler_width["packs"])
    routes.extend(compiler_width["routes"])
    qualifications.extend(compiler_width["qualifications"])

    targets = load_targets(root / "targets/registry.toml")
    target_ids = {str(row["id"]) for row in targets}
    universe = load_coverage_universe(root / "coverage/universe.toml")
    compiler_ids = {str(row["id"]) for row in universe["compiler_families"]}
    compiler_identity_by_id = {str(row["id"]): row for row in compilers}
    language_ids = {str(row["id"]) for row in universe["languages"]}
    pack_by_id = {str(row["id"]): row for row in packs}
    input_by_id = {str(row["id"]): row for row in inputs}
    route_by_id = {str(row["id"]): row for row in routes}
    qualification_by_id = {str(row["id"]): row for row in qualifications}

    for pack in packs:
        unknown_targets = set(pack["target_ids"]) - target_ids
        if unknown_targets:
            raise ValueError(
                f"pack {pack['id']} has unknown targets: {sorted(unknown_targets)}"
            )
        if pack["compiler_family"] not in compiler_ids:
            raise ValueError(f"pack {pack['id']} has unknown compiler family")

    for toolchain_input in inputs:
        unknown_targets = set(toolchain_input["target_ids"]) - target_ids
        if unknown_targets:
            raise ValueError(
                f"input {toolchain_input['id']} has unknown targets: {sorted(unknown_targets)}"
            )

    for route in routes:
        route_id = str(route["id"])
        if route["target_id"] not in target_ids:
            raise ValueError(
                f"route {route_id} has unknown target {route['target_id']}"
            )
        if route["compiler_family"] not in compiler_ids:
            raise ValueError(f"route {route_id} has unknown compiler family")
        compiler_identity = compiler_identity_by_id.get(str(route["compiler_id"]))
        if compiler_identity is None:
            raise ValueError(f"route {route_id} has unknown compiler identity")
        if compiler_identity["family"] != route["compiler_family"]:
            raise ValueError(
                f"route {route_id} compiler identity differs from its family"
            )
        unknown_packs = set(route["pack_ids"]) - pack_by_id.keys()
        if unknown_packs:
            raise ValueError(
                f"route {route_id} has unknown packs: {sorted(unknown_packs)}"
            )
        unknown_inputs = set(route["input_ids"]) - input_by_id.keys()
        if unknown_inputs:
            raise ValueError(
                f"route {route_id} has unknown inputs: {sorted(unknown_inputs)}"
            )
        for pack_id in route["pack_ids"]:
            pack = pack_by_id[pack_id]
            if route["target_id"] not in pack["target_ids"]:
                raise ValueError(
                    f"route {route_id} target is not provided by pack {pack_id}"
                )
            if route["compiler_family"] != pack["compiler_family"]:
                raise ValueError(
                    f"route {route_id} compiler differs from pack {pack_id}"
                )
        for input_id in route["input_ids"]:
            if route["target_id"] not in input_by_id[input_id]["target_ids"]:
                raise ValueError(
                    f"route {route_id} target is not provided by input {input_id}"
                )

    host_route_ids = {
        str(route["id"])
        for route in routes
        if route["provisioning"] != "external-worker"
    }
    if set(qualification_by_id) != host_route_ids:
        raise ValueError(
            "qualification routes must equal non-external routes: "
            f"missing {sorted(host_route_ids - qualification_by_id.keys())}, "
            f"extra {sorted(qualification_by_id.keys() - host_route_ids)}"
        )
    for qualification in qualifications:
        route_id = str(qualification["route_id"])
        route = route_by_id[route_id]
        if (
            set(qualification["smoke_languages"])
            - {
                "c",
                "cpp",
            }
            or "c" not in qualification["smoke_languages"]
        ):
            raise ValueError(
                f"qualification {route_id} must contain only C-family smoke languages and include c"
            )
        if qualification["tool_source"] == "pack":
            if (
                qualification["tool_pack_id"] not in route["pack_ids"]
                or qualification["composition"] != "none"
            ):
                raise ValueError(
                    f"qualification {route_id} pack source does not match its route"
                )
            tool_pack = pack_by_id[str(qualification["tool_pack_id"])]
            compiler_identity = compiler_identity_by_id[str(route["compiler_id"])]
            if (
                tool_pack["compiler_family"] != compiler_identity["family"]
                or tool_pack["compiler_version"] != compiler_identity["version"]
            ):
                raise ValueError(
                    f"qualification {route_id} tool pack does not match compiler identity"
                )
        elif qualification["tool_source"] == "composed-route":
            if (
                qualification["tool_pack_id"] != "osxcross-composed"
                or qualification["composition"] != "osxcross-llvm"
                or not route["input_ids"]
            ):
                raise ValueError(
                    f"qualification {route_id} composition does not match its route"
                )
        else:
            raise ValueError(f"qualification {route_id} has invalid tool_source")

    for profile in profiles:
        if profile["language_id"] not in language_ids:
            raise ValueError(
                f"profile {profile['id']} has unknown language {profile['language_id']}"
            )
        unknown_routes = set(profile["route_ids"]) - route_by_id.keys()
        if unknown_routes:
            raise ValueError(
                f"profile {profile['id']} has unknown routes: {sorted(unknown_routes)}"
            )
        authority_path = root / str(profile["authority"])
        if not authority_path.is_file():
            raise ValueError(f"profile {profile['id']} authority does not exist")
        authority = _read_toml(authority_path)
        requirement_ids = {
            str(row["id"]) for row in authority.get("toolchain_requirement", [])
        }
        profile_requirement_ids = {
            str(route_by_id[str(route_id)]["coverage_requirement_id"])
            for route_id in profile["route_ids"]
        }
        if not profile_requirement_ids.issubset(requirement_ids):
            raise ValueError(
                f"profile {profile['id']} route requirements are not a subset of its width authority"
            )

    sources = {
        "packs": "toolchains/packs.toml",
        "routes": "toolchains/routes.toml",
        "inputs": "toolchains/inputs.toml",
        "qualifications": "toolchains/qualifications.toml",
        "profiles": "toolchains/profiles/*.toml",
        "compilers": "toolchains/compilers.toml",
        "compiler_width": "toolchains/compiler-width.toml",
    }
    source_digests = {
        "packs_sha256": _sha256(packs_path),
        "routes_sha256": _sha256(routes_path),
        "inputs_sha256": _sha256(inputs_path),
        "qualifications_sha256": _sha256(qualifications_path),
        "profiles_sha256": hashlib.sha256(
            b"".join(path.read_bytes() for path in profile_paths)
        ).hexdigest(),
        "compilers_sha256": _sha256(compilers_path),
        "compiler_width_sha256": _sha256(compiler_width_path),
    }
    body: dict[str, object] = {
        "schema_version": CATALOG_SCHEMA,
        "host": {
            "system": header["host_system"],
            "architecture": header["host_architecture"],
        },
        "source_authority": header["source_authority"],
        "cache_policy": header["cache_policy"],
        "packs": packs,
        "compilers": compilers,
        "compiler_width": {
            key: compiler_width[key]
            for key in (
                "schema_version",
                "host_system",
                "host_architecture",
                "purpose",
                "gcc_generations",
                "gcc_targets",
                "selection",
            )
        },
        "inputs": inputs,
        "routes": routes,
        "qualifications": qualifications,
        "profiles": profiles,
        "sources": sources,
        "source_digests": source_digests,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return {**body, "catalog_digest": hashlib.sha256(canonical).hexdigest()}


def _host_identity() -> tuple[str, str]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if machine in {"amd64", "x64"}:
        machine = "x86_64"
    return system, machine


def resolve_toolchain_profile(
    project_root: str | Path,
    profile_id: str,
    *,
    host_system: str | None = None,
    host_architecture: str | None = None,
    _catalog: dict[str, object] | None = None,
    _inspections: dict[str, CacheInspection] | None = None,
) -> dict[str, object]:
    """Resolve one profile and inspect its cache without mutating the host."""

    root = Path(project_root).expanduser().resolve()
    catalog = _catalog or load_toolchain_pack_catalog(root)
    profiles = {str(row["id"]): row for row in catalog["profiles"]}
    if profile_id not in profiles:
        raise ValueError(f"unknown toolchain profile: {profile_id}")
    profile = profiles[profile_id]
    packs = {str(row["id"]): row for row in catalog["packs"]}
    inputs = {str(row["id"]): row for row in catalog["inputs"]}
    routes = {str(row["id"]): row for row in catalog["routes"]}
    qualifications = {str(row["route_id"]): row for row in catalog["qualifications"]}

    detected_system, detected_architecture = _host_identity()
    actual_system = (host_system or detected_system).lower()
    actual_architecture = (host_architecture or detected_architecture).lower()
    host_compatible = (
        actual_system == profile["host_system"]
        and actual_architecture == profile["host_architecture"]
    )

    route_rows: list[dict[str, object]] = []
    selected_pack_ids: list[str] = []
    selected_input_ids: list[str] = []
    requirements: list[dict[str, object]] = []
    for route_id in profile["route_ids"]:
        route = routes[str(route_id)]
        if route["provisioning"] == "external-worker":
            state = "external-required"
            definition_reviewed = (
                route["qualification_state"] == "external-definition-reviewed"
            )
            requirements.append(
                {
                    "code": "external-worker-required",
                    "severity": "constraint",
                    "route_id": route_id,
                    "message": (
                        f"{route['label']} has a reviewed definition and requires a registered {route['worker_class']} worker"
                        if definition_reviewed
                        else f"{route['label']} requires a separately pinned {route['worker_class']} worker"
                    ),
                    "details": route["external_requirements"],
                }
            )
        else:
            state = "pending-cache-inspection"
            for pack_id in route["pack_ids"]:
                if pack_id not in selected_pack_ids:
                    selected_pack_ids.append(str(pack_id))
            for input_id in route["input_ids"]:
                if input_id not in selected_input_ids:
                    selected_input_ids.append(str(input_id))
        route_rows.append({**route, "state": state})

    input_rows: list[dict[str, object]] = []
    input_state_by_id: dict[str, str] = {}
    for input_id in selected_input_ids:
        toolchain_input = inputs[input_id]
        binding = inspect_input_binding(root, toolchain_input)
        input_state_by_id[input_id] = binding.state
        input_rows.append(
            {
                **toolchain_input,
                "binding": {
                    "state": binding.state,
                    "path": str(binding.binding_path),
                    "material_path": (
                        str(binding.material_path)
                        if binding.material_path is not None
                        else None
                    ),
                    "document": binding.document,
                },
            }
        )
        if binding.state == "missing":
            requirements.append(
                {
                    "code": "user-input-required",
                    "severity": "constraint",
                    "input_id": input_id,
                    "message": f"{toolchain_input['label']} must be privately bound",
                    "details": {
                        "source_policy": toolchain_input["source_policy"],
                        "required_metadata": toolchain_input["required_metadata"],
                    },
                }
            )
        elif binding.state == "broken":
            requirements.append(
                {
                    "code": "input-binding-integrity-failure",
                    "severity": "blocker",
                    "input_id": input_id,
                    "message": f"{toolchain_input['label']} binding failed integrity inspection",
                }
            )

    downloads = root / MANAGED_DOWNLOADS
    prepared = root / MANAGED_PREPARED
    pack_rows: list[dict[str, object]] = []
    cache_state_by_pack: dict[str, str] = {}
    preparation_state_by_pack: dict[str, str] = {}
    inspections = {} if _inspections is None else _inspections
    for pack_id in selected_pack_ids:
        pack = packs[pack_id]
        digest = str(pack["sha256"])
        inspection = inspections.get(digest)
        if inspection is None:
            inspection = inspect_cached(downloads, digest)
            inspections[digest] = inspection
        cache_state_by_pack[pack_id] = inspection.state
        preparation = inspect_prepared(
            prepared,
            digest,
            str(pack["archive_root"]),
        )
        preparation_state_by_pack[pack_id] = preparation.state
        pack_rows.append(
            {
                **pack,
                "state": inspection.state,
                "cache": {
                    "path": str(inspection.path),
                    "bytes": inspection.bytes,
                    "observed_sha256": inspection.observed_sha256,
                },
                "preparation": {
                    "state": preparation.state,
                    "path": str(preparation.path),
                    "root": str(preparation.root),
                    "manifest": preparation.manifest,
                },
            }
        )
        if inspection.state == "missing":
            requirements.append(
                {
                    "code": "pack-download-required",
                    "severity": "action",
                    "pack_id": pack_id,
                    "message": f"{pack['label']} is not in the managed cache",
                }
            )
        elif inspection.state == "broken":
            requirements.append(
                {
                    "code": "pack-integrity-failure",
                    "severity": "blocker",
                    "pack_id": pack_id,
                    "message": f"{pack['label']} failed cache integrity inspection",
                }
            )
        elif preparation.state == "missing":
            requirements.append(
                {
                    "code": "pack-preparation-required",
                    "severity": "action",
                    "pack_id": pack_id,
                    "message": f"{pack['label']} is cached but not safely prepared",
                }
            )
        if preparation.state == "broken":
            requirements.append(
                {
                    "code": "preparation-integrity-failure",
                    "severity": "blocker",
                    "pack_id": pack_id,
                    "message": f"{pack['label']} has a broken preparation record",
                }
            )

    for route in route_rows:
        if route["provisioning"] == "external-worker":
            continue
        states = [cache_state_by_pack[str(pack_id)] for pack_id in route["pack_ids"]]
        preparation_states = [
            preparation_state_by_pack[str(pack_id)] for pack_id in route["pack_ids"]
        ]
        input_states = [
            input_state_by_id[str(input_id)] for input_id in route["input_ids"]
        ]
        if "broken" in states:
            route["state"] = "broken"
        elif not all(state == "verified-cached" for state in states):
            route["state"] = (
                "download-and-input-required"
                if route["input_ids"]
                else "download-required"
            )
        elif "broken" in preparation_states:
            route["state"] = "broken"
        elif not all(state == "prepared" for state in preparation_states):
            route["state"] = (
                "preparation-and-input-required"
                if route["input_ids"]
                else "preparation-required"
            )
        elif "broken" in input_states:
            route["state"] = "broken"
        elif not all(state == "bound-verified" for state in input_states):
            route["state"] = "input-required"
        else:
            route["state"] = "prepared-unqualified"

    for route in route_rows:
        if route["provisioning"] == "external-worker":
            continue
        definition = qualifications[str(route["id"])]
        projection: dict[str, object] = {
            "definition": definition,
            "state": "blocked-by-prerequisites",
            "route_material_digest": None,
            "path": None,
            "record": None,
        }
        route["qualification"] = projection
        if route["state"] != "prepared-unqualified":
            continue
        material_digest = route_material_digest(
            route,
            definition,
            pack_rows,
            input_rows,
        )
        projection["route_material_digest"] = material_digest
        if definition["composition"] == "osxcross-llvm":
            composition = inspect_composition(
                root,
                str(route["id"]),
                material_digest,
            )
            projection["composition"] = {
                "state": composition.state,
                "path": str(composition.path),
                "root": str(composition.root),
                "manifest": composition.manifest,
                "host_dependencies": composition_dependencies(),
            }
            if composition.state == "broken":
                route["state"] = "broken"
                projection["state"] = "broken-composition"
                requirements.append(
                    {
                        "code": "composition-integrity-failure",
                        "severity": "blocker",
                        "route_id": route["id"],
                        "message": f"{route['label']} composition failed integrity inspection",
                    }
                )
                continue
            if composition.state != "composed":
                route["state"] = "composition-required"
                projection["state"] = "composition-required"
                requirements.append(
                    {
                        "code": "route-composition-required",
                        "severity": "action",
                        "route_id": route["id"],
                        "message": f"{route['label']} must be composed from LLVM, osxcross, and the bound SDK",
                    }
                )
                continue
        inspection = inspect_qualification(
            root,
            str(route["id"]),
            material_digest,
        )
        projection.update(
            {
                "state": inspection.state,
                "path": str(inspection.path),
                "record": inspection.record,
            }
        )
        if inspection.state == "qualified":
            route["state"] = "qualified"
        elif inspection.state == "broken":
            route["state"] = "broken"
            requirements.append(
                {
                    "code": "qualification-integrity-failure",
                    "severity": "blocker",
                    "route_id": route["id"],
                    "message": f"{route['label']} qualification failed integrity inspection",
                }
            )
        else:
            route["state"] = "qualification-required"
            requirements.append(
                {
                    "code": "route-qualification-required",
                    "severity": "action",
                    "route_id": route["id"],
                    "message": f"{route['label']} requires fixed C/C++ smoke qualification",
                }
            )

    if not host_compatible:
        requirements.insert(
            0,
            {
                "code": "host-incompatible",
                "severity": "blocker",
                "message": (
                    f"profile requires {profile['host_system']}/{profile['host_architecture']}; "
                    f"detected {actual_system}/{actual_architecture}"
                ),
            },
        )

    state_counts = {
        state: sum(row["state"] == state for row in pack_rows)
        for state in ("missing", "verified-cached", "broken")
    }
    preparation_counts = {
        state: sum(row["preparation"]["state"] == state for row in pack_rows)
        for state in ("missing", "prepared", "broken")
    }
    input_counts = {
        state: sum(row["binding"]["state"] == state for row in input_rows)
        for state in ("missing", "bound-verified", "broken")
    }
    route_counts = {
        state: sum(row["state"] == state for row in route_rows)
        for state in (
            "broken",
            "composition-required",
            "qualification-required",
            "qualified",
            "external-required",
        )
    }
    input_required = bool(input_counts["missing"])
    external_required = bool(route_counts["external-required"])
    if (
        not host_compatible
        or state_counts["broken"]
        or preparation_counts["broken"]
        or input_counts["broken"]
        or route_counts["broken"]
    ):
        state = "blocked"
    elif state_counts["missing"]:
        state = "acquisition-required"
    elif preparation_counts["missing"]:
        state = "preparation-required"
    elif input_required and external_required:
        state = "input-and-external-required"
    elif input_required:
        state = "input-required"
    elif route_counts["composition-required"]:
        state = "composition-required"
    elif route_counts["qualification-required"]:
        state = "qualification-required"
    elif external_required:
        state = "qualified-external-required"
    else:
        state = "qualified"

    total_download = sum(int(row["download_bytes"]) for row in pack_rows)
    pack_installed = sum(int(row["installed_bytes_estimate"]) for row in pack_rows)
    pack_size_evidence = sorted({str(row["size_evidence"]) for row in pack_rows})
    additional_installed = sum(
        int(row["additional_installed_bytes_estimate"]) for row in route_rows
    )
    total_installed = pack_installed + additional_installed
    cached_download = sum(
        int(row["download_bytes"])
        for row in pack_rows
        if row["state"] == "verified-cached"
    )
    cli_examples = [
        {
            "action": action,
            "argv": [
                "fidb-poc",
                "toolchain",
                "profile",
                action,
                profile_id,
                "--project-root",
                str(root),
            ],
            "shell": f"./scripts/toolchains/{action}.sh {profile_id}",
        }
        for action in ("plan", "status", "pull", "prepare", "compose", "qualify")
    ]
    return {
        "schema_version": PROFILE_PLAN_SCHEMA,
        "operation": "status",
        "profile": profile,
        "catalog_digest": catalog["catalog_digest"],
        "profile_digest": hashlib.sha256(
            json.dumps(
                {
                    "profile": profile,
                    "routes": [
                        {
                            **{
                                key: value
                                for key, value in row.items()
                                if key not in {"state", "qualification"}
                            },
                            "qualification": qualifications.get(str(row["id"])),
                        }
                        for row in route_rows
                    ],
                    "packs": [
                        {
                            key: value
                            for key, value in row.items()
                            if key not in {"state", "cache", "preparation"}
                        }
                        for row in pack_rows
                    ],
                    "inputs": [
                        {key: value for key, value in row.items() if key != "binding"}
                        for row in input_rows
                    ],
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest(),
        "state": state,
        "host": {
            "required_system": profile["host_system"],
            "required_architecture": profile["host_architecture"],
            "detected_system": actual_system,
            "detected_architecture": actual_architecture,
            "compatible": host_compatible,
        },
        "managed_downloads": str(downloads),
        "managed_prepared": str(prepared),
        "managed_inputs": str(root / MANAGED_INPUTS),
        "managed_bindings": str(root / MANAGED_BINDINGS),
        "managed_composed": str(root / MANAGED_COMPOSED),
        "managed_qualified": str(root / MANAGED_QUALIFIED),
        "summary": {
            "routes": len(route_rows),
            "coverage_requirements": len(
                {str(row["coverage_requirement_id"]) for row in route_rows}
            ),
            "downloadable_routes": sum(
                row["provisioning"] != "external-worker" for row in route_rows
            ),
            "user_input_routes": sum(bool(row["input_ids"]) for row in route_rows),
            "inputs": len(input_rows),
            "bound_inputs": input_counts["bound-verified"],
            "missing_inputs": input_counts["missing"],
            "broken_inputs": input_counts["broken"],
            "external_routes": sum(
                row["provisioning"] == "external-worker" for row in route_rows
            ),
            "primary_routes": sum(
                row["evidence_role"] == "primary" for row in route_rows
            ),
            "cross_build_routes": sum(
                row["evidence_role"] == "cross-build" for row in route_rows
            ),
            "native_reference_routes": sum(
                row["evidence_role"] == "native-reference" for row in route_rows
            ),
            "packs": len(pack_rows),
            "verified_cached_packs": state_counts["verified-cached"],
            "missing_packs": state_counts["missing"],
            "broken_packs": state_counts["broken"],
            "prepared_packs": preparation_counts["prepared"],
            "missing_preparations": preparation_counts["missing"],
            "broken_preparations": preparation_counts["broken"],
            "composed_routes": sum(
                row.get("qualification", {}).get("composition", {}).get("state")
                == "composed"
                for row in route_rows
            ),
            "missing_compositions": route_counts["composition-required"],
            "qualified_routes": route_counts["qualified"],
            "missing_qualifications": route_counts["qualification-required"],
            "broken_routes": route_counts["broken"],
            "download_bytes": total_download,
            "cached_download_bytes": cached_download,
            "remaining_download_bytes": total_download - cached_download,
            "pack_installed_bytes_estimate": pack_installed,
            "route_additional_installed_bytes_estimate": additional_installed,
            "installed_bytes_estimate": total_installed,
            "installed_size_evidence": "; ".join(pack_size_evidence),
        },
        "routes": route_rows,
        "packs": pack_rows,
        "inputs": input_rows,
        "requirements": requirements,
        "recommended_next_action": (
            "use-compatible-host"
            if not host_compatible
            else (
                "repair-cache"
                if state == "blocked" and state_counts["broken"]
                else (
                    "repair-preparation"
                    if state == "blocked" and preparation_counts["broken"]
                    else (
                        "repair-input-binding"
                        if state == "blocked" and input_counts["broken"]
                        else (
                            "repair-route"
                            if state == "blocked"
                            else (
                                "pull"
                                if state == "acquisition-required"
                                else (
                                    "prepare"
                                    if state == "preparation-required"
                                    else (
                                        "supply-user-input-and-define-external-workers"
                                        if state == "input-and-external-required"
                                        else (
                                            "supply-user-input"
                                            if state == "input-required"
                                            else (
                                                "compose"
                                                if state == "composition-required"
                                                else (
                                                    "qualify"
                                                    if state == "qualification-required"
                                                    else (
                                                        "start-external-workers"
                                                        if state
                                                        == "qualified-external-required"
                                                        else "done"
                                                    )
                                                )
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
        ),
        "cli_examples": cli_examples,
        "trace": {
            "sources": catalog["sources"],
            "source_digests": catalog["source_digests"],
            "profile_authority": profile["authority"],
        },
    }


def resolve_toolchain_profiles(project_root: str | Path) -> list[dict[str, object]]:
    """Resolve every reviewed profile with one catalogue load and cache scan."""

    root = Path(project_root).expanduser().resolve()
    catalog = load_toolchain_pack_catalog(root)
    inspections: dict[str, CacheInspection] = {}
    return [
        resolve_toolchain_profile(
            root,
            str(profile["id"]),
            _catalog=catalog,
            _inspections=inspections,
        )
        for profile in catalog["profiles"]
    ]
