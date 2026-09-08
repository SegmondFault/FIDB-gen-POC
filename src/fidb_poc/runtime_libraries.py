"""Resolve toolchain-owned runtime archives without inventing source recipes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
import tomllib

from .c_width import compile_c_width, materialize_width_configuration
from .toolchain_cache import MANAGED_DOWNLOADS, inspect_cached
from .toolchain_packs import load_toolchain_pack_catalog, resolve_toolchain_profile
from .toolchain_registry import load_toolchains

CATALOG_SCHEMA = "fidb-runtime-library-catalog/v1"
STATUS_SCHEMA = "fidb-runtime-library-status/v1"
_KINDS = {"qualified-route-query", "archive-registry-family"}
_TOKEN = re.compile(r"[a-z0-9][a-z0-9._+-]*\Z")
_CATALOG_FIELDS = {
    "schema_version",
    "id",
    "label",
    "state",
    "width_authority",
    "registry",
    "policy",
    "provider",
}
_PROVIDER_FIELDS = {
    "order",
    "subject_id",
    "label",
    "kind",
    "library_name",
    "query",
    "target_os",
    "compiler_families",
    "registry_family",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _project_file(root: Path, value: object, field: str) -> tuple[Path, str]:
    relative = Path(str(value))
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"runtime library {field} must stay inside the project")
    path = (root / relative).resolve()
    if root not in path.parents or not path.is_file() or path.is_symlink():
        raise ValueError(f"runtime library {field} is not a regular project file")
    return path, str(relative)


def _tokens(value: object, field: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(
            not isinstance(item, str) or _TOKEN.fullmatch(item) is None
            for item in value
        )
        or len(value) != len(set(value))
    ):
        raise ValueError(f"runtime library {field} must be unique safe tokens")
    return list(value)


def load_runtime_library_catalog(
    project_root: str | Path,
    authority: str | Path = "toolchains/runtime-libraries.toml",
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    path, relative = _project_file(root, authority, "authority")
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if set(document) != _CATALOG_FIELDS:
        raise ValueError("runtime library catalog has unsupported or missing fields")
    if document["schema_version"] != CATALOG_SCHEMA:
        raise ValueError("unsupported runtime library catalog schema")
    if document["state"] != "defined-disarmed":
        raise ValueError("runtime library catalog must remain defined-disarmed")
    for field in ("id", "label", "width_authority", "policy"):
        if not isinstance(document[field], str) or not str(document[field]).strip():
            raise ValueError(f"runtime library {field} must be non-empty")
    if _TOKEN.fullmatch(str(document["id"])) is None:
        raise ValueError("runtime library catalog id must be a safe token")
    registry_path, registry_relative = _project_file(
        root, document["registry"], "registry"
    )
    providers = document["provider"]
    if not isinstance(providers, list) or not providers:
        raise ValueError("runtime library catalog requires provider rows")
    normalized = []
    seen: set[str] = set()
    for position, raw in enumerate(providers, start=1):
        if not isinstance(raw, dict) or set(raw) != _PROVIDER_FIELDS:
            raise ValueError(f"runtime library provider {position} fields are invalid")
        if raw["order"] != position:
            raise ValueError("runtime library provider order must be contiguous")
        subject_id = str(raw["subject_id"])
        if _TOKEN.fullmatch(subject_id) is None or subject_id in seen:
            raise ValueError(f"invalid or duplicate runtime subject: {subject_id}")
        seen.add(subject_id)
        kind = str(raw["kind"])
        if kind not in _KINDS:
            raise ValueError(f"unsupported runtime provider kind: {kind}")
        target_os = _tokens(raw["target_os"], f"provider {subject_id} target_os")
        compiler_families = _tokens(
            raw["compiler_families"], f"provider {subject_id} compiler_families"
        )
        query = raw["query"]
        registry_family = raw["registry_family"]
        if kind == "qualified-route-query":
            if not isinstance(query, str) or not query.startswith("-print-"):
                raise ValueError(f"runtime provider {subject_id} has invalid query")
            if registry_family is not False:
                raise ValueError(
                    f"runtime provider {subject_id} cannot set registry_family"
                )
        elif query is not False or not isinstance(registry_family, str):
            raise ValueError(f"runtime provider {subject_id} needs one registry family")
        normalized.append(
            {
                **raw,
                "subject_id": subject_id,
                "target_os": target_os,
                "compiler_families": compiler_families,
            }
        )
    return {
        **document,
        "provider": normalized,
        "authority_path": relative,
        "authority_sha256": _sha256(path),
        "registry": registry_relative,
        "registry_sha256": _sha256(registry_path),
    }


def _route_version(route: dict[str, object], catalog: dict[str, object]) -> str:
    catalog_routes = {str(row["id"]): row for row in catalog["routes"]}
    packs = {str(row["id"]): row for row in catalog["packs"]}
    source = catalog_routes[str(route["id"])]
    versions = {
        str(packs[str(pack_id)]["runtime_version"])
        for pack_id in source["pack_ids"]
        if str(packs[str(pack_id)]["runtime_version"]).lower() not in {"none", "n/a"}
    }
    return "+".join(sorted(versions)) or str(route["compiler_id"])


def _probe_route_archive(root: Path, route: object, query: str) -> dict[str, object]:
    # Buildroot drivers are deliberate basename-sensitive symlinks through a
    # wrapper. Validate the resolved target, but invoke the reviewed symlink.
    compiler = Path(str(route.compiler[0])).absolute()  # type: ignore[attr-defined]
    managed = (root / "var/fidb-toolchains").resolve()
    if managed not in compiler.resolve().parents:
        return {"state": "compiler-outside-managed-toolchains"}
    result = subprocess.run(
        [str(compiler), query],
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    raw_path = result.stdout.strip()
    if result.returncode != 0 or not raw_path or raw_path == query.split("=", 1)[-1]:
        return {"state": "query-failed", "error": result.stderr.strip()}
    archive = Path(raw_path).resolve()
    if managed not in archive.parents:
        return {"state": "path-outside-managed-toolchains", "path": str(archive)}
    if archive.is_symlink() or not archive.is_file():
        return {"state": "archive-missing", "path": str(archive)}
    listing = subprocess.run(
        [str(route.archiver[0]), "t", str(archive)],  # type: ignore[attr-defined]
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    members = [line for line in listing.stdout.splitlines() if line.strip()]
    if listing.returncode != 0 or not members:
        return {
            "state": "archive-invalid",
            "path": str(archive.relative_to(root)),
            "error": listing.stderr.strip(),
        }
    return {
        "state": "qualified",
        "path": str(archive.relative_to(root)),
        "sha256": _sha256(archive),
        "bytes": archive.stat().st_size,
        "members": len(members),
    }


def runtime_library_status(
    project_root: str | Path,
    *,
    probe: bool = False,
    _catalog: dict[str, object] | None = None,
) -> dict[str, object]:
    """Project every provider; optional probes never compile or launch Ghidra."""

    root = Path(project_root).expanduser().resolve()
    authority = load_runtime_library_catalog(root)
    catalog = _catalog or load_toolchain_pack_catalog(root)
    width = compile_c_width(root, str(authority["width_authority"]), _catalog=catalog)
    route_plan = resolve_toolchain_profile(
        root, str(width["toolchain_profile"]), _catalog=catalog
    )
    configuration = materialize_width_configuration(
        root, "zlib@1.3.2", route_plan, _catalog=catalog
    )
    route_objects = {route.id: route for route in configuration.routes}
    registry = load_toolchains(root / str(authority["registry"]))
    providers = []
    cells = []
    for provider in authority["provider"]:
        provider_cells = []
        if provider["kind"] == "qualified-route-query":
            for route in width["routes"]:
                if (
                    route["target_os"] not in provider["target_os"]
                    or route["compiler_family"] not in provider["compiler_families"]
                ):
                    continue
                runtime_route = route_objects[str(route["id"])]
                status = (
                    _probe_route_archive(root, runtime_route, str(provider["query"]))
                    if probe and route["toolchain_state"] == "qualified"
                    else {
                        "state": (
                            "qualified-unprobed"
                            if route["toolchain_state"] == "qualified"
                            else "route-unavailable"
                        )
                    }
                )
                provider_cells.append(
                    {
                        "id": f'{provider["subject_id"]}:{route["id"]}',
                        "subject_id": provider["subject_id"],
                        "kind": provider["kind"],
                        "route_id": route["id"],
                        "compiler_id": route["compiler_id"],
                        "runtime_version": _route_version(route, catalog),
                        "target_os": route["target_os"],
                        "architecture": route["architecture"],
                        "binary_format": route["binary_format"],
                        "toolchain_identity": route["toolchain_identity"],
                        "ghidra_language": runtime_route.ghidra_language,
                        "ghidra_compiler_spec": runtime_route.ghidra_compiler_spec,
                        "query": provider["query"],
                        **status,
                    }
                )
        else:
            for row in registry:
                if row["family"] != provider["registry_family"] or "url" not in row:
                    continue
                inspection = inspect_cached(
                    root / MANAGED_DOWNLOADS, str(row["sha256"])
                )
                provider_cells.append(
                    {
                        "id": (
                            f'{provider["subject_id"]}:{row["family"]}@'
                            f'{row["version"]}:{row["variant"]}'
                        ),
                        "subject_id": provider["subject_id"],
                        "kind": provider["kind"],
                        "registry_identity": (
                            f'{row["family"]}@{row["version"]}:{row["variant"]}'
                        ),
                        "runtime_version": str(row["version"]),
                        "target_os": "linux",
                        "architecture": row["machine"],
                        "binary_format": "ELF",
                        "sha256": row["sha256"],
                        "bytes": inspection.bytes,
                        "state": (
                            "pinned-cached"
                            if inspection.state == "verified-cached"
                            else "acquisition-required"
                        ),
                    }
                )
        cells.extend(provider_cells)
        providers.append(
            {
                **provider,
                "cells": len(provider_cells),
                "ready_cells": sum(
                    row["state"] in {"qualified", "qualified-unprobed", "pinned-cached"}
                    for row in provider_cells
                ),
                "blocked_cells": sum(
                    row["state"]
                    not in {"qualified", "qualified-unprobed", "pinned-cached"}
                    for row in provider_cells
                ),
            }
        )
    stable = {
        "authority_sha256": authority["authority_sha256"],
        "registry_sha256": authority["registry_sha256"],
        "width_compilation_digest": width["compilation_digest"],
        "cells": [
            {key: value for key, value in row.items() if key not in {"path", "bytes"}}
            for row in cells
        ],
    }
    states = [str(row["state"]) for row in cells]
    return {
        "schema_version": STATUS_SCHEMA,
        "id": authority["id"],
        "label": authority["label"],
        "state": authority["state"],
        "policy": authority["policy"],
        "probe": probe,
        "authority_path": authority["authority_path"],
        "authority_sha256": authority["authority_sha256"],
        "registry_path": authority["registry"],
        "registry_sha256": authority["registry_sha256"],
        "width_authority": authority["width_authority"],
        "width_compilation_digest": width["compilation_digest"],
        "provider_digest": hashlib.sha256(
            json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "summary": {
            "subjects": len(providers),
            "cells": len(cells),
            "ready_cells": sum(
                state in {"qualified", "qualified-unprobed", "pinned-cached"}
                for state in states
            ),
            "blocked_cells": sum(
                state not in {"qualified", "qualified-unprobed", "pinned-cached"}
                for state in states
            ),
            "qualified_route_cells": sum(
                row["kind"] == "qualified-route-query" for row in cells
            ),
            "archive_registry_cells": sum(
                row["kind"] == "archive-registry-family" for row in cells
            ),
            "archive_bytes": sum(int(row.get("bytes") or 0) for row in cells),
            "states": {state: states.count(state) for state in sorted(set(states))},
        },
        "providers": providers,
        "cells": cells,
    }


class RuntimeLibraryResolver:
    """Cache immutable route authorities while probing exact runtime archives."""

    def __init__(self, project_root: str | Path):
        self.root = Path(project_root).expanduser().resolve()
        self.authority = load_runtime_library_catalog(self.root)
        self.providers = {
            str(row["subject_id"]): row for row in self.authority["provider"]
        }
        self.catalog = load_toolchain_pack_catalog(self.root)
        self.width = compile_c_width(
            self.root,
            str(self.authority["width_authority"]),
            _catalog=self.catalog,
        )
        self.route_metadata = {str(row["id"]): row for row in self.width["routes"]}
        route_plan = resolve_toolchain_profile(
            self.root,
            str(self.width["toolchain_profile"]),
            _catalog=self.catalog,
        )
        configuration = materialize_width_configuration(
            self.root, "zlib@1.3.2", route_plan, _catalog=self.catalog
        )
        self.routes = {route.id: route for route in configuration.routes}

    def resolve(
        self, subject_id: str, route_id: str, *, probe: bool = False
    ) -> tuple[dict[str, object], object]:
        provider = self.providers.get(subject_id)
        if provider is None or provider["kind"] != "qualified-route-query":
            raise ValueError(f"runtime subject is not route-owned: {subject_id}")
        metadata = self.route_metadata.get(route_id)
        if metadata is None:
            raise ValueError(f"unknown runtime route: {route_id}")
        if (
            metadata["target_os"] not in provider["target_os"]
            or metadata["compiler_family"] not in provider["compiler_families"]
        ):
            raise ValueError(
                f"runtime provider {subject_id} does not apply to {route_id}"
            )
        route = self.routes[route_id]
        status = (
            _probe_route_archive(self.root, route, str(provider["query"]))
            if probe
            else {"state": "qualified-unprobed"}
        )
        return (
            {
                "id": f"{subject_id}:{route_id}",
                "subject_id": subject_id,
                "label": provider["label"],
                "library_name": provider["library_name"],
                "kind": provider["kind"],
                "route_id": route_id,
                "compiler_id": metadata["compiler_id"],
                "runtime_version": _route_version(metadata, self.catalog),
                "target_os": metadata["target_os"],
                "architecture": metadata["architecture"],
                "binary_format": metadata["binary_format"],
                "toolchain_identity": metadata["toolchain_identity"],
                "ghidra_language": route.ghidra_language,
                "ghidra_compiler_spec": route.ghidra_compiler_spec,
                "query": provider["query"],
                "authority_path": self.authority["authority_path"],
                "authority_sha256": self.authority["authority_sha256"],
                **status,
            },
            route,
        )


def resolve_route_runtime_provider(
    project_root: str | Path,
    subject_id: str,
    route_id: str,
    *,
    probe: bool = False,
) -> tuple[dict[str, object], object]:
    """Resolve one route-owned archive and its exact executable route."""

    return RuntimeLibraryResolver(project_root).resolve(
        subject_id, route_id, probe=probe
    )
