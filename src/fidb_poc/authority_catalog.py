"""Read-only projection of the reviewed planning authorities for operators."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tomllib

from .config import load_configuration
from .plan_request import (
    REQUEST_SCHEMA,
    _factor_variants,
    _sensitivity_catalog,
    load_plan_request,
    resolve_plan,
)
from .recipe_generator import load_recipes as load_source_recipes
from .toolchain_registry import load_toolchains

AUTHORITY_SCHEMA = "fidb-authority-catalog/v1"


def _relative(root: Path, path: Path) -> str:
    return str(path.resolve().relative_to(root))


def _native_authority(root: Path) -> tuple[list[dict[str, object]], dict[str, object]]:
    recipe_paths = sorted((root / "recipes").glob("*.toml"))
    requests = []
    for path in recipe_paths:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        requests.append(f'{document["name"]}@{document["version"]}')
    configuration = load_configuration(root / "worker.json", tuple(requests))
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
            "compiler": list(row.compiler),
            "archiver": list(row.archiver),
            "ranlib": list(row.ranlib),
            "compiler_flags": list(row.compiler_flags),
            "ghidra_language": row.ghidra_language,
            "ghidra_compiler_spec": row.ghidra_compiler_spec,
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
        }
        for row in configuration.treatments
    ]
    return recipes, {
        "routes": routes,
        "treatments": treatments,
        "profiles": {
            name: list(values) for name, values in configuration.profiles.items()
        },
        "authority_path": "worker.json",
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


def authority_catalog(project_root: str | Path) -> dict[str, object]:
    """Return one validated, JSON-safe view of all planning authorities."""

    root = Path(project_root).expanduser().resolve()
    native_recipes, native = _native_authority(root)
    factors, variants, sensitivity_digests = _sensitivity_authority(root)
    body = {
        "schema_version": AUTHORITY_SCHEMA,
        "recipes": [*native_recipes, *_source_authority(root)],
        "native": native,
        "toolchains": _toolchain_authority(root),
        "factors": factors,
        "factor_variants": variants,
        "plans": _plan_authority(root),
        "sources": {
            "recipes": "recipes/",
            "routes": "worker.json",
            "toolchains": "toolchains/registry.toml",
            "factors": "sensitivity/factors.toml",
            "factor_variants": "sensitivity/variants.toml",
            "plans": "plans/",
        },
        "source_digests": sensitivity_digests,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return {**body, "authority_digest": hashlib.sha256(canonical).hexdigest()}
