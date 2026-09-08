from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, replace
from pathlib import Path


class RecipesNotFoundError(ValueError):
    def __init__(self, requests: tuple[str, ...], known: tuple[str, ...]):
        self.requests = requests
        self.known = known
        requested = ", ".join(repr(request) for request in requests)
        available = ", ".join(known)
        noun = "recipe" if len(requests) == 1 else "recipes"
        super().__init__(
            f"no approved {noun} for {requested}; known libraries: {available}"
        )


SAFE_PATH_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")
WORKER_FIELDS = {
    "schema_version",
    "recipe_directory",
    "requested_libraries",
    "routes",
    "treatments",
    "profiles",
}
ROUTE_FIELDS = {
    "id",
    "target_os",
    "architecture",
    "binary_format",
    "compiler_family",
    "compiler",
    "archiver",
    "ranlib",
    "compiler_flags",
    "object_file_markers",
    "linked_suffix",
    "linked_file_markers",
    "ghidra_language",
    "ghidra_compiler_spec",
    "compiler_version_markers",
    "managed_toolchain_route",
}
TREATMENT_FIELDS = {
    "id",
    "factor",
    "description",
    "remove_flags",
    "append_flags",
    "supported_routes",
    "phase",
    "artifact_shape",
    "factor_values",
    "factor_variants",
}


def _path_component(value: object, context: str) -> str:
    """Validate configuration text that later becomes one directory component."""
    if not isinstance(value, str) or SAFE_PATH_COMPONENT.fullmatch(value) is None:
        raise ValueError(
            f"{context} must be a safe path component containing only letters, "
            "numbers, dot, underscore, plus and hyphen"
        )
    return value


@dataclass(frozen=True)
class BuildInput:
    kind: str
    name: str
    version: str
    url: str
    sha256: str
    filename: str
    source_directory: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in {"source-tree", "meson-package-cache"}:
            raise ValueError(f"unsupported build input kind: {self.kind}")
        _path_component(self.name, "build input name")
        _path_component(self.version, "build input version")
        _path_component(self.filename, "build input filename")
        if len(self.sha256) != 64 or re.fullmatch(r"[0-9a-f]{64}", self.sha256) is None:
            raise ValueError(f"build input {self.identifier} has an invalid SHA-256")
        if self.kind == "source-tree":
            if self.source_directory is None:
                raise ValueError(
                    f"source-tree build input {self.identifier} needs source_directory"
                )
            _path_component(self.source_directory, "build input source_directory")
        elif self.source_directory is not None:
            raise ValueError(
                f"meson package-cache input {self.identifier} cannot set source_directory"
            )

    @property
    def identifier(self) -> str:
        return f"{self.name}-{self.version}"

    @property
    def cache_key(self) -> str:
        return f"{self.kind}:{self.identifier}:{self.filename}:{self.sha256}"

    def pin(self) -> dict[str, str]:
        row = {
            "kind": self.kind,
            "name": self.name,
            "version": self.version,
            "url": self.url,
            "sha256": self.sha256,
            "filename": self.filename,
        }
        if self.source_directory is not None:
            row["source_directory"] = self.source_directory
        return row


@dataclass(frozen=True)
class Library:
    name: str
    version: str
    url: str
    sha256: str
    source_directory: str
    project_markers: tuple[str, ...]
    allowed_build_systems: tuple[str, ...]
    preferred_build_system: str
    static_archives: tuple[str, ...]
    build_inputs: tuple[BuildInput, ...] = ()
    supported_target_os: tuple[str, ...] = ()
    supported_architectures: tuple[str, ...] = ()
    supported_compiler_families: tuple[str, ...] = ()
    unsupported_routes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _path_component(self.name, "library name")
        _path_component(self.version, "library version")
        _path_component(self.source_directory, "library source_directory")
        for archive in self.static_archives:
            _path_component(archive, "library static archive")
        for route_id in self.unsupported_routes:
            _path_component(route_id, "library unsupported route")
        keys = [row.cache_key for row in self.build_inputs]
        if len(keys) != len(set(keys)):
            raise ValueError(f"{self.identifier} contains duplicate build inputs")
        source_identifiers = [
            row.identifier for row in self.build_inputs if row.kind == "source-tree"
        ]
        if len(source_identifiers) != len(set(source_identifiers)):
            raise ValueError(
                f"{self.identifier} contains colliding source-tree build inputs"
            )

    @property
    def identifier(self) -> str:
        return f"{self.name}-{self.version}"

    def applies_to(self, route: Route) -> bool:
        """Return whether this reviewed recipe supports the resolved route.

        Empty axes are deliberately unbounded so existing recipes retain their
        historical behaviour. New specialist recipes can fail closed on any
        target axis that has not been reviewed yet.
        """

        return (
            (not self.supported_target_os or route.target_os in self.supported_target_os)
            and (
                not self.supported_architectures
                or route.architecture in self.supported_architectures
            )
            and (
                not self.supported_compiler_families
                or route.compiler_family in self.supported_compiler_families
            )
            and route.id not in self.unsupported_routes
        )


@dataclass(frozen=True)
class Route:
    id: str
    target_os: str
    architecture: str
    binary_format: str
    compiler_family: str
    compiler: tuple[str, ...]
    archiver: tuple[str, ...]
    ranlib: tuple[str, ...]
    compiler_flags: tuple[str, ...]
    object_file_markers: tuple[str, ...]
    linked_suffix: str
    linked_file_markers: tuple[str, ...]
    ghidra_language: str
    ghidra_compiler_spec: str = "default"
    compiler_version_markers: tuple[str, ...] = ()
    managed_toolchain_route: str | None = None
    toolchain_state: str = "host-command"
    toolchain_identity: str = "execution-probed"
    toolchain_blocker: str = ""

    def __post_init__(self) -> None:
        _path_component(self.id, "route id")


@dataclass(frozen=True)
class Treatment:
    id: str
    factor: str
    description: str
    remove_flags: tuple[str, ...]
    append_flags: tuple[str, ...]
    supported_routes: tuple[str, ...]
    phase: str = "compile"
    artifact_shape: str = "static-archive-members"
    factor_values: tuple[tuple[str, str], ...] = ()
    factor_variants: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _path_component(self.id, "treatment id")

    def applies_to(self, route: Route) -> bool:
        return not self.supported_routes or route.id in self.supported_routes

    def flags_for(self, route: Route) -> tuple[str, ...]:
        flags = [flag for flag in route.compiler_flags if flag not in self.remove_flags]
        flags.extend(self.append_flags)
        return tuple(flags)


@dataclass(frozen=True)
class Configuration:
    libraries: tuple[Library, ...]
    routes: tuple[Route, ...]
    treatments: tuple[Treatment, ...]
    profiles: dict[str, tuple[str, ...]]


def _required(record: dict, field: str, context: str):
    if field not in record:
        raise ValueError(f"{context} is missing {field!r}")
    return record[field]


def _reject_unknown(record: dict, allowed: set[str], context: str) -> None:
    unknown = set(record) - allowed
    if unknown:
        raise ValueError(f"{context} contains unknown fields: {sorted(unknown)}")


def _load_recipe(path: Path) -> Library:
    row = tomllib.loads(path.read_text(encoding="utf-8"))
    _reject_unknown(
        row,
        {
            "schema_version",
            "mode",
            "name",
            "version",
            "url",
            "sha256",
            "source_directory",
            "project_markers",
            "allowed_build_systems",
            "preferred_build_system",
            "static_archives",
            "build_inputs",
            "supported_target_os",
            "supported_architectures",
            "supported_compiler_families",
            "unsupported_routes",
        },
        f"recipe {path.name}",
    )
    if row.get("schema_version") != "fidb-recipe/v3":
        raise ValueError(f"unsupported or missing schema_version in {path}")
    if row.get("mode") != "native":
        raise ValueError(f'{path}: config.py only handles mode="native" recipes')
    raw_inputs = row.get("build_inputs", [])
    if not isinstance(raw_inputs, list):
        raise ValueError(f"recipe {path.name} build_inputs must be an array of tables")
    build_inputs = []
    for index, raw in enumerate(raw_inputs, start=1):
        context = f"recipe {path.name} build input {index}"
        if not isinstance(raw, dict):
            raise ValueError(f"{context} must be a table")
        allowed = {
            "kind",
            "name",
            "version",
            "url",
            "sha256",
            "filename",
            "source_directory",
        }
        _reject_unknown(raw, allowed, context)
        build_inputs.append(
            BuildInput(
                kind=_required(raw, "kind", context),
                name=_path_component(
                    _required(raw, "name", context), f"{context} name"
                ),
                version=_path_component(
                    _required(raw, "version", context), f"{context} version"
                ),
                url=_required(raw, "url", context),
                sha256=str(_required(raw, "sha256", context)).lower(),
                filename=_path_component(
                    _required(raw, "filename", context), f"{context} filename"
                ),
                source_directory=(
                    _path_component(
                        raw["source_directory"], f"{context} source_directory"
                    )
                    if "source_directory" in raw
                    else None
                ),
            )
        )
    library = Library(
        name=_path_component(
            _required(row, "name", f"recipe {path.name}"),
            f"recipe {path.name} name",
        ),
        version=_path_component(
            _required(row, "version", f"recipe {path.name}"),
            f"recipe {path.name} version",
        ),
        url=_required(row, "url", f"recipe {path.name}"),
        sha256=_required(row, "sha256", f"recipe {path.name}").lower(),
        source_directory=_path_component(
            _required(row, "source_directory", f"recipe {path.name}"),
            f"recipe {path.name} source_directory",
        ),
        project_markers=tuple(_required(row, "project_markers", f"recipe {path.name}")),
        allowed_build_systems=tuple(
            _required(row, "allowed_build_systems", f"recipe {path.name}")
        ),
        preferred_build_system=_required(
            row, "preferred_build_system", f"recipe {path.name}"
        ),
        static_archives=tuple(
            _path_component(value, f"recipe {path.name} static archive")
            for value in _required(row, "static_archives", f"recipe {path.name}")
        ),
        build_inputs=tuple(build_inputs),
        supported_target_os=tuple(row.get("supported_target_os", [])),
        supported_architectures=tuple(row.get("supported_architectures", [])),
        supported_compiler_families=tuple(
            row.get("supported_compiler_families", [])
        ),
        unsupported_routes=tuple(row.get("unsupported_routes", [])),
    )
    if len(library.sha256) != 64:
        raise ValueError(f"{library.identifier} has an invalid SHA-256")
    if not library.project_markers or not library.static_archives:
        raise ValueError(f"{library.identifier} has incomplete detection metadata")
    if library.preferred_build_system not in library.allowed_build_systems:
        raise ValueError(f"{library.identifier} preferred build system is not allowed")
    return library


def _recipe_catalog(recipe_directory: Path) -> dict[str, Library]:
    if not recipe_directory.is_dir():
        raise ValueError(f"recipe directory does not exist: {recipe_directory}")
    recipes: dict[str, Library] = {}
    families: dict[str, list[Library]] = {}
    for path in sorted(recipe_directory.glob("*.toml")):
        recipe = _load_recipe(path)
        keys = (recipe.identifier, f"{recipe.name}@{recipe.version}")
        for key in keys:
            if key in recipes:
                raise ValueError(f"duplicate recipe request key: {key}")
            recipes[key] = recipe
        families.setdefault(recipe.name, []).append(recipe)
    for name, versions in families.items():
        if len(versions) == 1:
            recipes[name] = versions[0]
    return recipes


def _resolve_requests(
    document: dict,
    config_path: Path,
    request_override: tuple[str, ...] | None,
) -> tuple[Library, ...]:
    requests = request_override or tuple(
        _required(document, "requested_libraries", "worker configuration")
    )
    if not requests:
        raise ValueError("at least one library request is required")
    recipe_directory = config_path.parent / document.get("recipe_directory", "recipes")
    catalog = _recipe_catalog(recipe_directory)
    libraries = []
    missing = []
    for request in requests:
        recipe = catalog.get(request)
        if recipe is None:
            missing.append(request)
            continue
        libraries.append(recipe)
    if missing:
        known = tuple(
            sorted({f"{recipe.name}@{recipe.version}" for recipe in catalog.values()})
        )
        raise RecipesNotFoundError(tuple(missing), known)
    if len({library.identifier for library in libraries}) != len(libraries):
        raise ValueError("library requests resolve to duplicate recipes")
    return tuple(libraries)


def _load_route(
    row: dict,
    project_root: Path,
    toolchain_catalog: dict[str, object] | None = None,
) -> Route:
    route_id = _path_component(_required(row, "id", "route"), "route id")
    managed = row.get("managed_toolchain_route")
    if managed is not None:
        managed = _path_component(managed, f"route {route_id} managed_toolchain_route")
        if managed != route_id:
            raise ValueError(
                f"managed route {route_id} must use its canonical toolchain route id"
            )
        forbidden = {"compiler", "archiver", "ranlib"} & set(row)
        if forbidden:
            raise ValueError(
                f"managed route {route_id} cannot persist resolved tool paths: "
                f"{sorted(forbidden)}"
            )
        compiler = (f"@managed/{route_id}/c",)
        archiver = (f"@managed/{route_id}/archiver",)
        ranlib = (f"@managed/{route_id}/ranlib",)
        toolchain_state = "unavailable"
        toolchain_identity = "unresolved"
        toolchain_blocker = "managed toolchain authority is unavailable"
        if toolchain_catalog is not None:
            from .toolchain_qualification import (
                QualificationError,
                resolve_qualified_route_tools,
            )

            catalog = toolchain_catalog
            routes = [item for item in catalog["routes"] if item["id"] == managed]
            qualifications = [
                item
                for item in catalog["qualifications"]
                if item["route_id"] == managed
            ]
            if len(routes) != 1 or len(qualifications) != 1:
                raise ValueError(
                    f"managed route {managed} does not resolve exactly once in authority"
                )
            try:
                tools = resolve_qualified_route_tools(
                    project_root,
                    routes[0],
                    qualifications[0],
                    catalog["packs"],
                    catalog["inputs"],
                )
            except QualificationError as error:
                toolchain_blocker = str(error)
            else:
                compiler = (str(tools.compiler),)
                archiver = (str(tools.archiver),)
                ranlib = (str(tools.ranlib),)
                toolchain_state = "qualified"
                toolchain_identity = (
                    f"qualified:{tools.route_material_digest}:" f"{tools.record_digest}"
                )
                toolchain_blocker = ""
    else:
        compiler = tuple(_required(row, "compiler", "route"))
        archiver = tuple(_required(row, "archiver", "route"))
        ranlib = tuple(row.get("ranlib", row["archiver"]))
        toolchain_state = "host-command"
        toolchain_identity = "execution-probed"
        toolchain_blocker = ""

    return Route(
        id=route_id,
        target_os=_required(row, "target_os", "route"),
        architecture=_required(row, "architecture", "route"),
        binary_format=_required(row, "binary_format", "route"),
        compiler_family=_required(row, "compiler_family", "route"),
        compiler=compiler,
        archiver=archiver,
        ranlib=ranlib,
        compiler_flags=tuple(row.get("compiler_flags", [])),
        object_file_markers=tuple(_required(row, "object_file_markers", "route")),
        linked_suffix=_required(row, "linked_suffix", "route"),
        linked_file_markers=tuple(_required(row, "linked_file_markers", "route")),
        ghidra_language=_required(row, "ghidra_language", "route"),
        ghidra_compiler_spec=row.get("ghidra_compiler_spec", "default"),
        compiler_version_markers=tuple(row.get("compiler_version_markers", [])),
        managed_toolchain_route=managed,
        toolchain_state=toolchain_state,
        toolchain_identity=toolchain_identity,
        toolchain_blocker=toolchain_blocker,
    )


def load_configuration(
    path: Path,
    request_override: tuple[str, ...] | None = None,
    *,
    toolchain_catalog: dict[str, object] | None = None,
) -> Configuration:
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    _reject_unknown(document, WORKER_FIELDS, "worker configuration")
    if document.get("schema_version") != "fidb-worker/v3":
        raise ValueError("unsupported or missing schema_version")

    libraries = _resolve_requests(document, path, request_override)
    route_rows = _required(document, "routes", "worker configuration")
    for row in route_rows:
        _reject_unknown(row, ROUTE_FIELDS, "route")
    project_root = path.parent.resolve()
    authority_files = (
        project_root / "toolchains/routes.toml",
        project_root / "toolchains/packs.toml",
        project_root / "toolchains/inputs.toml",
        project_root / "toolchains/qualifications.toml",
        project_root / "targets/registry.toml",
        project_root / "coverage/universe.toml",
        project_root / "toolchains/profiles",
    )
    if (
        any("managed_toolchain_route" in row for row in route_rows)
        and all(authority.exists() for authority in authority_files)
        and toolchain_catalog is None
    ):
        from .toolchain_packs import load_toolchain_pack_catalog

        # This catalog hashes cached archives. Resolve it once per configuration,
        # not once for every managed route in the same worker.toml.
        toolchain_catalog = load_toolchain_pack_catalog(project_root)
    routes = tuple(
        _load_route(row, project_root, toolchain_catalog) for row in route_rows
    )
    treatment_rows = _required(document, "treatments", "worker configuration")
    for row in treatment_rows:
        _reject_unknown(row, TREATMENT_FIELDS, "treatment")
    treatments = tuple(
        Treatment(
            id=_path_component(_required(row, "id", "treatment"), "treatment id"),
            factor=_required(row, "factor", "treatment"),
            description=_required(row, "description", "treatment"),
            remove_flags=tuple(row.get("remove_flags", [])),
            append_flags=tuple(row.get("append_flags", [])),
            supported_routes=tuple(row.get("supported_routes", [])),
            phase=row.get("phase", "compile"),
            artifact_shape=row.get("artifact_shape", "static-archive-members"),
            factor_values=tuple(
                (str(key), str(value))
                for key, value in row.get("factor_values", {}).items()
            ),
            factor_variants=tuple(row.get("factor_variants", [])),
        )
        for row in treatment_rows
    )
    profiles = {
        name: tuple(treatment_ids)
        for name, treatment_ids in _required(
            document, "profiles", "worker configuration"
        ).items()
    }

    if not routes or not treatments:
        raise ValueError("at least one route and treatment are required")
    if len({route.id for route in routes}) != len(routes):
        raise ValueError("route ids must be unique")
    if len({row.id for row in treatments}) != len(treatments):
        raise ValueError("treatment ids must be unique")
    treatment_ids = {row.id for row in treatments}
    for name, profile_ids in profiles.items():
        unknown = set(profile_ids) - treatment_ids
        if unknown:
            raise ValueError(f"profile {name!r} contains unknown treatments: {unknown}")
    for route in routes:
        if not route.compiler or not route.archiver:
            raise ValueError(f"{route.id} has an empty tool command")
        if not route.linked_suffix.startswith(".") or not route.linked_file_markers:
            raise ValueError(f"{route.id} has incomplete linked-output metadata")
    invalid_phases = {row.phase for row in treatments} - {"compile", "link"}
    if invalid_phases:
        raise ValueError(f"unsupported treatment phases: {sorted(invalid_phases)}")
    for treatment in treatments:
        factors = [factor for factor, _value in treatment.factor_values]
        if len(factors) != len(set(factors)):
            raise ValueError(f"treatment {treatment.id} has duplicate factor values")
        if not treatment.artifact_shape:
            raise ValueError(f"treatment {treatment.id} has no artifact shape")
        if len(treatment.factor_variants) != len(set(treatment.factor_variants)):
            raise ValueError(f"treatment {treatment.id} has duplicate factor variants")
        if len(treatment.factor_variants) != len(treatment.factor_values):
            raise ValueError(
                f"treatment {treatment.id} factor variants must map one-to-one "
                "to factor values"
            )

    return Configuration(
        libraries=libraries,
        routes=routes,
        treatments=treatments,
        profiles=profiles,
    )


def select_configuration(
    configuration: Configuration,
    *,
    route_ids: tuple[str, ...] | None,
    treatment_ids: tuple[str, ...] | None,
    profile: str,
) -> Configuration:
    known_routes = {row.id: row for row in configuration.routes}
    known_treatments = {row.id: row for row in configuration.treatments}
    requested_routes = route_ids or tuple(known_routes)
    if treatment_ids:
        requested_treatments = treatment_ids
    else:
        if profile not in configuration.profiles:
            raise ValueError(f"unknown treatment profile: {profile}")
        requested_treatments = configuration.profiles[profile]

    missing_routes = set(requested_routes) - set(known_routes)
    missing_treatments = set(requested_treatments) - set(known_treatments)
    if missing_routes:
        raise ValueError(f"unknown routes: {sorted(missing_routes)}")
    if missing_treatments:
        raise ValueError(f"unknown treatments: {sorted(missing_treatments)}")
    return replace(
        configuration,
        routes=tuple(known_routes[row] for row in requested_routes),
        treatments=tuple(known_treatments[row] for row in requested_treatments),
    )
