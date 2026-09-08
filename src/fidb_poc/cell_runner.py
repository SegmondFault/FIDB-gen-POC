"""Execute one resolved plan cell through the complete FIDB pipeline.

The resolved cell is deliberately not an execution recipe.  It is an immutable
claim about inputs selected by :mod:`fidb_poc.plan_request`; this module resolves
the same identity from the reviewed project catalogs again immediately before
execution and fails closed if any pin, adapter, target or routing field changed.

All generated state is rooted below ``attempt_root``.  Source-build commands are
still constructed only by the named adapters in ``source_build.py``; no command
or script supplied by a caller is accepted here.
"""

from __future__ import annotations

import csv
from dataclasses import asdict, dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import tomllib
from typing import Mapping, Sequence

from . import ghidra_fid, libc_catalog, malware_build, pipeline
from .config import Configuration, load_configuration, select_configuration
from .elf import ElfFacts, ghidra_language, inspect_elf
from .hunt import _select_objects
from .recipe_generator import generate_cells, load_recipes
from .toolchain_registry import load_toolchains
from .toolchain_cache import MANAGED_DOWNLOADS
from .source_packs import MANAGED_SOURCE_DOWNLOADS
from .runtime_libraries import RuntimeLibraryResolver, resolve_route_runtime_provider
from .timing import (
    CellStage,
    ProgressCallback,
    ProgressEvent,
    ProgressStatus,
    TimingRecorder,
)

SEAL_SCHEMA = "fidb-cell-seal/v1"
VARIANTS_SCHEMA = "fidb-factor-variants/v1"
MANIFEST_FIELD_LIMIT = 16 * 1024 * 1024
SUPPORTED_KINDS = frozenset(
    {"native", "source-library", "archive-library", "runtime-library", "malware"}
)
RAW_COMMAND_FIELDS = frozenset(
    {
        "argv",
        "cmd",
        "command",
        "commands",
        "raw_command",
        "script",
        "shell",
        "shell_command",
    }
)


class CellRunnerError(RuntimeError):
    """Execution failed after the resolved cell passed input validation."""


class CellResolutionError(ValueError):
    """A queued cell no longer resolves exactly from reviewed authorities."""


@dataclass(frozen=True)
class GhidraRuntime:
    install_dir: Path
    identity: dict[str, object]


@dataclass(frozen=True)
class CellRunResult:
    cell_id: str
    kind: str
    executor: str
    manifest_path: Path
    manifest_sha256: str
    fidb_path: Path
    fidbf_path: Path
    timing: dict[str, object]

    @property
    def seal_path(self) -> Path:
        return self.manifest_path

    @property
    def seal_sha256(self) -> str:
        return self.manifest_sha256


@dataclass(frozen=True)
class _WidthContext:
    batch: dict[str, object]
    compilation: dict[str, object]
    configuration: Configuration
    route_metadata: dict[str, dict[str, object]]
    executable_profiles: dict[tuple[str, str], str]


class CellAuthorityResolver:
    """Resolve queued cells through the same authorities as materialization.

    A queue worker keeps one resolver for its lifetime.  Expensive toolchain
    catalog verification and width compilation are therefore shared across
    cells, while every cell is still compared field-for-field with the current
    reviewed authority before any build or JVM work begins.
    """

    def __init__(self, project_root: str | Path):
        self.project_root = Path(project_root).expanduser().resolve()
        self._catalog: dict[str, object] | None = None
        self._width_contexts: dict[str, _WidthContext] = {}
        self._recipe_configurations: dict[str, Configuration] = {}
        self._runtime_resolver: RuntimeLibraryResolver | None = None

    def _toolchain_catalog(self) -> dict[str, object]:
        if self._catalog is None:
            from .toolchain_packs import load_toolchain_pack_catalog

            self._catalog = load_toolchain_pack_catalog(self.project_root)
        return self._catalog

    def runtime_provider(
        self, subject_id: str, route_id: str
    ) -> tuple[dict[str, object], object]:
        if self._runtime_resolver is None:
            self._runtime_resolver = RuntimeLibraryResolver(self.project_root)
        return self._runtime_resolver.resolve(subject_id, route_id, probe=True)

    def _recipe_configuration(self, identity: str) -> Configuration:
        configuration = self._recipe_configurations.get(identity)
        if configuration is None:
            configuration = load_configuration(
                self.project_root / "worker.toml",
                request_override=(identity,),
                toolchain_catalog=self._toolchain_catalog(),
            )
            self._recipe_configurations[identity] = configuration
        return configuration

    def _width_batch_path(self, batch_id: str) -> Path:
        matches = []
        for path in sorted((self.project_root / "batches").glob("*.toml")):
            document = tomllib.loads(path.read_text(encoding="utf-8"))
            if (
                document.get("schema_version") == "fidb-width-batch/v1"
                and document.get("id") == batch_id
            ):
                matches.append(path)
        if len(matches) != 1:
            raise CellResolutionError(
                f"width batch identity {batch_id!r} resolved to "
                f"{len(matches)} reviewed documents"
            )
        return matches[0]

    def _width_context(self, batch_id: str) -> _WidthContext:
        context = self._width_contexts.get(batch_id)
        if context is not None:
            return context

        from .c_width import compile_c_width, materialize_width_configuration
        from .toolchain_packs import resolve_toolchain_profile
        from .width_batch import load_width_batch

        catalog = self._toolchain_catalog()
        batch = load_width_batch(
            self.project_root,
            self._width_batch_path(batch_id),
            _toolchain_catalog=catalog,
        )
        width_id = Path(str(batch["authorities"]["width"])).stem
        compilation = compile_c_width(self.project_root, width_id, _catalog=catalog)
        route_plan = resolve_toolchain_profile(
            self.project_root,
            str(compilation["toolchain_profile"]),
            _catalog=catalog,
        )
        first_recipe = str(batch["libraries"][0]["recipe_id"])
        configuration = materialize_width_configuration(
            self.project_root,
            first_recipe,
            route_plan,
            _catalog=catalog,
        )
        context = _WidthContext(
            batch=batch,
            compilation=compilation,
            configuration=configuration,
            route_metadata={str(row["id"]): dict(row) for row in compilation["routes"]},
            executable_profiles={
                (str(row["route_id"]), str(row["treatment_id"])): str(row["profile_id"])
                for row in compilation["applicability"]
                if row["state"] == "executable"
            },
        )
        self._width_contexts[batch_id] = context
        return context

    def native_configuration(
        self,
        cell: dict[str, object],
        identity: str,
        route_id: str,
        treatment_id: str,
    ) -> tuple[Configuration, str | None, dict[str, object] | None]:
        raw_width = cell.get("width")
        if raw_width is None:
            configuration = self._recipe_configuration(identity)
            return (
                select_configuration(
                    configuration,
                    route_ids=(route_id,),
                    treatment_ids=(treatment_id,),
                    profile="smoke",
                ),
                None,
                None,
            )

        width = _mapping(raw_width, "cell.width")
        batch_id = str(_required(width, "batch_id", "cell.width"))
        context = self._width_context(batch_id)
        route_metadata = context.route_metadata.get(route_id)
        if route_metadata is None:
            raise CellResolutionError(
                f"width route {route_id!r} is absent from batch {batch_id!r}"
            )
        profile_id = context.executable_profiles.get((route_id, treatment_id))
        if profile_id is None:
            raise CellResolutionError(
                f"width route/treatment is not executable: "
                f"{route_id}:{treatment_id}"
            )
        reviewed_width = {
            "batch_id": context.batch["id"],
            "batch_digest": context.batch["batch_digest"],
            "width_id": context.compilation["id"],
            "compilation_digest": context.compilation["compilation_digest"],
            "route_profile_digest": context.compilation["route_profile_digest"],
            "profile_id": profile_id,
        }
        _expect(width, reviewed_width, "native width authority")
        recipe_configuration = self._recipe_configuration(identity)
        configuration = replace(
            context.configuration, libraries=recipe_configuration.libraries
        )
        configuration = select_configuration(
            configuration,
            route_ids=(route_id,),
            treatment_ids=(treatment_id,),
            profile="smoke",
        )
        return configuration, str(route_metadata["compiler_id"]), reviewed_width


def _plain(value: object, context: str = "resolved cell") -> object:
    """Copy JSON-shaped input while rejecting surprising caller objects."""
    if value is None or type(value) in {str, int, float, bool}:
        return value
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CellResolutionError(f"{context} contains a non-string key")
            result[key] = _plain(item, f"{context}.{key}")
        return result
    if isinstance(value, (list, tuple)):
        return [_plain(item, f"{context}[]") for item in value]
    raise CellResolutionError(
        f"{context} contains unsupported value type {type(value).__name__}"
    )


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise CellResolutionError(
            f"resolved cell is not canonical JSON: {error}"
        ) from error


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _reject_raw_commands(value: object, path: str = "cell") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in RAW_COMMAND_FIELDS or normalized.endswith("_command"):
                raise CellResolutionError(
                    f"{path} contains forbidden raw command field {key!r}"
                )
            _reject_raw_commands(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_raw_commands(item, f"{path}[{index}]")


def _mapping(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise CellResolutionError(f"{context} must be a table")
    return value


def _required(row: Mapping[str, object], field: str, context: str) -> object:
    if field not in row:
        raise CellResolutionError(f"{context} is missing {field!r}")
    return row[field]


def _expect(actual: object, expected: object, context: str) -> None:
    if actual != expected:
        raise CellResolutionError(
            f"resolved {context} no longer matches reviewed authority: "
            f"queued={actual!r}, reviewed={expected!r}"
        )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _fsync_directory(path: Path) -> None:
    """Persist an atomic seal rename without following a directory symlink."""

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise CellRunnerError(f"seal parent is not a directory: {path}")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _relative_artifact(path: Path, attempt_root: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise CellRunnerError(f"{label} is not a regular generated file: {path}")
    resolved = path.resolve()
    try:
        resolved.relative_to(attempt_root.resolve())
    except ValueError as error:
        raise CellRunnerError(
            f"{label} escaped the isolated attempt root: {path}"
        ) from error
    if resolved.stat().st_size < 1:
        raise CellRunnerError(f"{label} is empty: {resolved}")
    return resolved


def _artifact(path: Path, attempt_root: Path, label: str) -> dict[str, object]:
    resolved = _relative_artifact(path, attempt_root, label)
    return {
        "path": str(resolved.relative_to(attempt_root.resolve())),
        "sha256": _sha256(resolved),
        "bytes": resolved.stat().st_size,
    }


def _validate_roots(project_root: Path, attempt_root: Path) -> tuple[Path, Path]:
    project = project_root.expanduser().resolve()
    if not project.is_dir():
        raise CellResolutionError(f"project_root is not a directory: {project}")
    for relative in ("worker.toml", "recipes", "toolchains/registry.toml"):
        if not (project / relative).exists():
            raise CellResolutionError(
                f"project_root is missing reviewed authority {relative}: {project}"
            )

    attempt_candidate = attempt_root.expanduser()
    if attempt_candidate.is_symlink():
        raise CellResolutionError(
            f"attempt_root cannot be a symlink: {attempt_candidate}"
        )
    attempt = attempt_candidate.resolve()
    if attempt == project:
        raise CellResolutionError("attempt_root must be isolated from project_root")
    if attempt.exists() and not attempt.is_dir():
        raise CellResolutionError(f"attempt_root is not a directory: {attempt}")
    attempt.mkdir(parents=True, exist_ok=True)
    for name in ("work", "artifacts"):
        generated = attempt / name
        if generated.is_symlink():
            raise CellResolutionError(
                f"isolated generated root cannot be a symlink: {generated}"
            )
        if generated.exists() and not generated.is_dir():
            raise CellResolutionError(
                f"isolated generated root is not a directory: {generated}"
            )
        if generated.is_dir() and any(generated.iterdir()):
            raise CellResolutionError(
                f"isolated generated root must be empty before execution: {generated}"
            )
        generated.mkdir(exist_ok=True)
    return project, attempt


def _resolve_factor_variants(
    project_root: Path, requested: Sequence[str]
) -> tuple[list[dict[str, object]], str]:
    if isinstance(requested, (str, bytes)):
        raise CellResolutionError("factor_variants must be a sequence of variant ids")
    variant_ids = tuple(requested)
    if any(not isinstance(item, str) or not item for item in variant_ids):
        raise CellResolutionError("factor variant ids must be non-empty strings")
    if len(set(variant_ids)) != len(variant_ids):
        raise CellResolutionError("factor variants contain duplicates")

    path = project_root / "sensitivity/variants.toml"
    raw = path.read_bytes()
    document = tomllib.loads(raw.decode("utf-8"))
    if document.get("schema_version") != VARIANTS_SCHEMA:
        raise CellResolutionError(
            f"unsupported or missing factor-variants schema_version in {path}"
        )
    rows = document.get("variant")
    if not isinstance(rows, list) or not rows:
        raise CellResolutionError("factor-variants catalog contains no variants")
    catalog: dict[str, dict[str, object]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise CellResolutionError("factor-variants catalog contains an invalid row")
        variant_id = str(row["id"])
        if variant_id in catalog:
            raise CellResolutionError(f"duplicate factor variant: {variant_id}")
        catalog[variant_id] = row
    missing = set(variant_ids) - set(catalog)
    if missing:
        raise CellResolutionError(f"unknown factor variants: {sorted(missing)}")
    selected = [dict(catalog[variant_id]) for variant_id in variant_ids]
    unsupported = [
        str(row["id"]) for row in selected if row.get("state") != "registered"
    ]
    if unsupported:
        raise CellResolutionError(
            f"unsupported factor variants are not executable: {unsupported}"
        )
    factors = [str(row.get("factor", "")) for row in selected]
    if len(set(factors)) != len(factors):
        raise CellResolutionError(
            "factor variants must select at most one registered value per factor"
        )
    return selected, hashlib.sha256(raw).hexdigest()


def _validate_cell_state(cell: dict[str, object]) -> tuple[str, str]:
    kind = str(_required(cell, "kind", "resolved cell"))
    if kind not in SUPPORTED_KINDS:
        raise CellResolutionError(f"unsupported resolved cell kind: {kind!r}")
    cell_id = str(_required(cell, "id", "resolved cell"))
    if not cell_id:
        raise CellResolutionError("resolved cell id cannot be empty")
    status = cell.get("status", "planned")
    blockers = cell.get("blockers", [])
    if status != "planned" or blockers:
        raise CellResolutionError(
            f"resolved cell is not executable: status={status!r}, blockers={blockers!r}"
        )
    return cell_id, kind


def _validate_native_treatment_variants(
    configuration: Configuration, variants: Sequence[dict[str, object]]
) -> None:
    treatment = configuration.treatments[0]
    selected_by_factor = {str(row["factor"]): str(row["id"]) for row in variants}
    required_by_factor = {
        factor: variant_id
        for (factor, _value), variant_id in zip(
            treatment.factor_values, treatment.factor_variants
        )
    }
    for factor, required_id in required_by_factor.items():
        if factor in selected_by_factor and selected_by_factor[factor] != required_id:
            raise CellResolutionError(
                f"treatment {treatment.id} requires {required_id} for {factor}"
            )


def _resolve_native(
    cell: dict[str, object],
    project_root: Path,
    authority_resolver: CellAuthorityResolver | None = None,
) -> tuple[Configuration, dict[str, object]]:
    recipe = _mapping(_required(cell, "recipe", "native cell"), "cell.recipe")
    target = _mapping(_required(cell, "target", "native cell"), "cell.target")
    toolchain = _mapping(_required(cell, "toolchain", "native cell"), "cell.toolchain")
    build = _mapping(_required(cell, "build", "native cell"), "cell.build")
    analysis = _mapping(_required(cell, "analysis", "native cell"), "cell.analysis")
    routing = _mapping(_required(cell, "routing", "native cell"), "cell.routing")

    identity = f'{_required(recipe, "name", "cell.recipe")}@{_required(recipe, "version", "cell.recipe")}'
    recipe_documents = []
    for path in sorted((project_root / "recipes").glob("*.toml")):
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        if f'{document.get("name")}@{document.get("version")}' == identity:
            recipe_documents.append((path, document))
    if len(recipe_documents) != 1:
        raise CellResolutionError(
            f"native recipe identity {identity} resolved to "
            f"{len(recipe_documents)} reviewed documents"
        )
    _reject_raw_commands(recipe_documents[0][1], f"recipe {recipe_documents[0][0]}")
    resolver = authority_resolver or CellAuthorityResolver(project_root)
    if resolver.project_root != project_root.resolve():
        raise CellResolutionError("cell authority resolver uses a different project")
    route_id = str(_required(toolchain, "route", "cell.toolchain"))
    treatment_id = str(_required(build, "treatment", "cell.build"))
    configuration, compiler_id, reviewed_width = resolver.native_configuration(
        cell,
        identity,
        route_id,
        treatment_id,
    )
    library = configuration.libraries[0]
    route = configuration.routes[0]
    treatment = configuration.treatments[0]

    reviewed_recipe = {
        "name": library.name,
        "version": library.version,
        "url": library.url,
        "sha256": library.sha256,
    }
    if library.build_inputs:
        reviewed_recipe["build_inputs"] = [
            build_input.pin() for build_input in library.build_inputs
        ]
    reviewed_target = {
        "os": route.target_os,
        "architecture": route.architecture,
        "binary_format": route.binary_format,
    }
    reviewed_toolchain = {
        "route": route.id,
        "compiler": list(route.compiler),
        "archiver": list(route.archiver),
        "ranlib": list(route.ranlib),
        "identity": route.toolchain_identity,
    }
    if compiler_id is not None:
        reviewed_toolchain["compiler_id"] = compiler_id
    reviewed_build = {
        "adapter": library.preferred_build_system,
        "treatment": treatment.id,
        "factor": treatment.factor,
        "compiler_flags": list(treatment.flags_for(route)),
        "artifact_shape": treatment.artifact_shape,
        "factor_variants": list(treatment.factor_variants),
        "factor_variant_requirements": dict(
            zip(
                (factor for factor, _value in treatment.factor_values),
                treatment.factor_variants,
            )
        ),
    }
    reviewed_analysis = {
        "ghidra_language": route.ghidra_language,
        "ghidra_compiler_spec": route.ghidra_compiler_spec,
        "ghidra_version": "execution-probed",
        "analysis_profile": "fid-safe-default",
    }
    _expect(recipe, reviewed_recipe, "native recipe pins")
    _expect(target, reviewed_target, "native target")
    _expect(toolchain, reviewed_toolchain, "native toolchain route")
    _expect(build, reviewed_build, "native build adapter and flags")
    _expect(analysis, reviewed_analysis, "native analysis route")
    if reviewed_width is not None:
        _expect(cell.get("width"), reviewed_width, "native width authority")
    worker_pool = "macos-native" if route.target_os == "macos" else "library-local"
    _expect(
        routing,
        {"executor": "native-local", "worker_pool": worker_pool},
        "native executor",
    )
    return configuration, {
        "recipe": reviewed_recipe,
        "toolchain": reviewed_toolchain,
        "build": reviewed_build,
        "target": reviewed_target,
        "analysis": reviewed_analysis,
    }


def preflight_cell_authority(
    resolved_cell: Mapping[str, object],
    factor_variants: Sequence[str],
    project_root: str | Path,
    *,
    authority_resolver: CellAuthorityResolver | None = None,
) -> dict[str, object]:
    """Resolve one exact queued cell without building, starting Java, or writing.

    This is the execution boundary used by queue-wide preflight.  It deliberately
    performs the same strict field comparisons as :func:`run_cell`.
    """

    project = Path(project_root).expanduser().resolve()
    plain = _plain(resolved_cell)
    if not isinstance(plain, dict):
        raise CellResolutionError("resolved cell must be a table")
    _reject_raw_commands(plain)
    cell_id, kind = _validate_cell_state(plain)
    variants, variants_digest = _resolve_factor_variants(project, factor_variants)

    if kind == "native":
        configuration, pins = _resolve_native(
            plain, project, authority_resolver=authority_resolver
        )
        _validate_native_treatment_variants(configuration, variants)
        route = configuration.routes[0]
        treatment = configuration.treatments[0]
        executor = "native-local"
        route_id: str | None = route.id
        treatment_id: str | None = treatment.id
        toolchain_identity: str | None = route.toolchain_identity
    elif kind == "archive-library":
        _generated, pins = _resolve_archive(plain, project)
        executor = "archive-local"
        route_id = None
        treatment_id = None
        toolchain_identity = None
    elif kind == "runtime-library":
        generated, pins = _resolve_runtime(
            plain, project, authority_resolver=authority_resolver
        )
        executor = "runtime-archive-local"
        route = generated["route"]
        route_id = route.id
        treatment_id = None
        toolchain_identity = route.toolchain_identity
    else:
        generated, pins = _resolve_source(plain, project, kind)
        executor = str(generated["executor"])
        route_id = None
        treatment_id = None
        toolchain_identity = None

    return {
        "cell_id": cell_id,
        "kind": kind,
        "executor": executor,
        "route_id": route_id,
        "treatment_id": treatment_id,
        "toolchain_identity": toolchain_identity,
        "factor_variants_catalog_sha256": variants_digest,
        "factor_variant_count": len(variants),
        "pins_sha256": hashlib.sha256(_canonical(pins)).hexdigest(),
    }


def _patch_pins(cell: dict[str, object], project_root: Path) -> list[dict[str, str]]:
    result = []
    for raw_path in cell.get("patches", []):
        path = Path(str(raw_path)).resolve()
        try:
            relative = path.relative_to(project_root.resolve())
        except ValueError as error:
            raise CellResolutionError(
                f"reviewed patch escaped project root: {path}"
            ) from error
        result.append({"path": str(relative), "sha256": _sha256(path)})
    return result


def _find_identity(
    rows: list[dict[str, object]],
    identity: tuple[str, str],
    label: str,
) -> dict[str, object]:
    matches = [
        row
        for row in rows
        if (str(row.get("name")), str(row.get("version"))) == identity
    ]
    if len(matches) != 1:
        raise CellResolutionError(
            f"{label} identity {identity[0]}@{identity[1]} resolved to {len(matches)} rows"
        )
    return matches[0]


def _resolve_source(
    cell: dict[str, object], project_root: Path, kind: str
) -> tuple[dict[str, object], dict[str, object]]:
    recipe_pin = _mapping(_required(cell, "recipe", "source cell"), "cell.recipe")
    target = _mapping(_required(cell, "target", "source cell"), "cell.target")
    toolchain_pin = _mapping(
        _required(cell, "toolchain", "source cell"), "cell.toolchain"
    )
    build = _mapping(_required(cell, "build", "source cell"), "cell.build")
    analysis = _mapping(_required(cell, "analysis", "source cell"), "cell.analysis")
    routing = _mapping(_required(cell, "routing", "source cell"), "cell.routing")
    executor = str(routing.get("executor", "qemu"))
    if executor not in {"qemu", "local"}:
        raise CellResolutionError(f"unsupported source executor: {executor!r}")

    directory = "recipes/libs" if kind == "source-library" else "recipes/malware"
    recipe = _find_identity(
        load_recipes(project_root / directory),
        (str(recipe_pin.get("name")), str(recipe_pin.get("version"))),
        f"{kind} recipe",
    )
    _reject_raw_commands(recipe, f"reviewed {kind} recipe")
    toolchains = load_toolchains(project_root / "toolchains/registry.toml")
    toolchain_matches = [
        row
        for row in toolchains
        if (
            str(row.get("family")),
            str(row.get("version")),
            str(row.get("variant")),
        )
        == (
            str(toolchain_pin.get("family")),
            str(toolchain_pin.get("version")),
            str(toolchain_pin.get("variant")),
        )
    ]
    if len(toolchain_matches) != 1:
        raise CellResolutionError(
            "source toolchain identity resolved to "
            f"{len(toolchain_matches)} reviewed rows"
        )
    _reject_raw_commands(toolchain_matches[0], "reviewed source toolchain")
    generated = generate_cells([recipe], toolchain_matches, executor=executor)
    if len(generated) != 1:
        raise CellResolutionError(
            f"source identity generated {len(generated)} cells instead of one"
        )
    exact = generated[0]

    reviewed_recipe = {
        "name": exact["family"],
        "version": str(exact["version"]),
        "url": exact["source_url"],
        "sha256": exact["source_sha256"],
    }
    reviewed_toolchain = {
        "family": toolchain_matches[0]["family"],
        "version": str(toolchain_matches[0]["version"]),
        "variant": toolchain_matches[0]["variant"],
        "capability": "source",
        "url": exact["toolchain_url"],
        "sha256": exact["toolchain_sha256"],
        "cross_bin_prefix": exact["cross_bin_prefix"],
        "cross_arch": exact["arch"],
    }
    reviewed_build = {
        "adapter": exact["build_adapter"],
        "output": exact["library_path"],
        "compiler_flags": "adapter-owned",
        "patches": _patch_pins(exact, project_root),
    }
    reviewed_target = {
        "machine": exact["machine"],
        "endianness": exact["endianness"],
        "elf_class": int(exact["elf_class"]),
    }
    language = ghidra_language(
        str(exact["machine"]), str(exact["endianness"]), int(exact["elf_class"])
    )
    if language is None:
        raise CellResolutionError("reviewed source target has no Ghidra language")
    reviewed_analysis = {
        "ghidra_language": language,
        "ghidra_compiler_spec": ghidra_fid.compiler_spec_for_language(language),
        "ghidra_version": "execution-probed",
        "analysis_profile": "fid-safe-default",
    }
    _expect(recipe_pin, reviewed_recipe, "source recipe pins")
    _expect(toolchain_pin, reviewed_toolchain, "source toolchain pins")
    _expect(build, reviewed_build, "source build adapter")
    _expect(target, reviewed_target, "source target ABI")
    _expect(analysis, reviewed_analysis, "source analysis route")
    _expect(routing, {"executor": executor}, "source executor")
    return exact, {
        "recipe": reviewed_recipe,
        "toolchain": reviewed_toolchain,
        "build": reviewed_build,
        "target": reviewed_target,
        "analysis": reviewed_analysis,
        "vm": {
            "url": exact["vm_iso_url"],
            "sha256": exact["vm_iso_sha256"],
        },
    }


def _resolve_archive(
    cell: dict[str, object], project_root: Path
) -> tuple[dict[str, object], dict[str, object]]:
    recipe_pin = _mapping(_required(cell, "recipe", "archive cell"), "cell.recipe")
    target = _mapping(_required(cell, "target", "archive cell"), "cell.target")
    toolchain_pin = _mapping(
        _required(cell, "toolchain", "archive cell"), "cell.toolchain"
    )
    build = _mapping(_required(cell, "build", "archive cell"), "cell.build")
    analysis = _mapping(_required(cell, "analysis", "archive cell"), "cell.analysis")
    routing = _mapping(_required(cell, "routing", "archive cell"), "cell.routing")

    matches = [
        row
        for row in load_toolchains(project_root / "toolchains/registry.toml")
        if (
            str(row.get("family")),
            str(row.get("version")),
            str(row.get("variant")),
        )
        == (
            str(toolchain_pin.get("family")),
            str(toolchain_pin.get("version")),
            str(toolchain_pin.get("variant")),
        )
    ]
    if len(matches) != 1:
        raise CellResolutionError(
            f"archive identity resolved to {len(matches)} reviewed registry rows"
        )
    exact = matches[0]
    _reject_raw_commands(exact, "reviewed archive registry row")
    for field in ("url", "sha256", "library_member"):
        if field not in exact:
            raise CellResolutionError(
                f"reviewed archive registry row has no {field}: {exact.get('variant')}"
            )
    members = None
    if "members_file" in exact:
        members_path = Path(str(exact["members_file"])).resolve()
        try:
            relative = str(members_path.relative_to(project_root.resolve()))
        except ValueError as error:
            raise CellResolutionError(
                f"reviewed archive members file escaped project root: {members_path}"
            ) from error
        members = {"path": relative, "sha256": exact["members_sha256"]}
    reviewed_recipe = {
        "name": exact["family"],
        "version": str(exact["version"]),
        "url": exact["url"],
        "sha256": exact["sha256"],
    }
    reviewed_toolchain = {
        "family": exact["family"],
        "version": str(exact["version"]),
        "variant": exact["variant"],
        "capability": "archive",
    }
    reviewed_build = {
        "adapter": "archive-extract",
        "output": exact["library_member"],
        "members": members,
        "compiler_flags": None,
    }
    reviewed_target = {
        "machine": exact["machine"],
        "endianness": exact["endianness"],
        "elf_class": int(exact["elf_class"]),
    }
    language = ghidra_language(
        str(exact["machine"]), str(exact["endianness"]), int(exact["elf_class"])
    )
    if language is None:
        raise CellResolutionError("reviewed archive target has no Ghidra language")
    reviewed_analysis = {
        "ghidra_language": language,
        "ghidra_compiler_spec": ghidra_fid.compiler_spec_for_language(language),
        "ghidra_version": "execution-probed",
        "analysis_profile": "fid-safe-default",
    }
    _expect(recipe_pin, reviewed_recipe, "archive recipe pins")
    _expect(toolchain_pin, reviewed_toolchain, "archive registry identity")
    _expect(build, reviewed_build, "archive extraction adapter")
    _expect(target, reviewed_target, "archive target ABI")
    _expect(analysis, reviewed_analysis, "archive analysis route")
    _expect(routing, {"executor": "archive-local"}, "archive executor")
    return exact, {
        "recipe": reviewed_recipe,
        "toolchain": reviewed_toolchain,
        "build": reviewed_build,
        "target": reviewed_target,
        "analysis": reviewed_analysis,
    }


def _resolve_runtime(
    cell: dict[str, object],
    project_root: Path,
    *,
    authority_resolver: CellAuthorityResolver | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    recipe = _mapping(_required(cell, "recipe", "runtime cell"), "cell.recipe")
    target = _mapping(_required(cell, "target", "runtime cell"), "cell.target")
    toolchain = _mapping(_required(cell, "toolchain", "runtime cell"), "cell.toolchain")
    build = _mapping(_required(cell, "build", "runtime cell"), "cell.build")
    analysis = _mapping(_required(cell, "analysis", "runtime cell"), "cell.analysis")
    routing = _mapping(_required(cell, "routing", "runtime cell"), "cell.routing")
    subject_id = str(recipe.get("name"))
    route_id = str(toolchain.get("route"))
    try:
        if authority_resolver is None:
            provider, route = resolve_route_runtime_provider(
                project_root, subject_id, route_id, probe=True
            )
        else:
            provider, route = authority_resolver.runtime_provider(subject_id, route_id)
    except (OSError, ValueError) as error:
        raise CellResolutionError(str(error)) from error
    if provider["state"] != "qualified":
        raise CellResolutionError(
            f'runtime archive {subject_id}/{route_id} is {provider["state"]}'
        )
    reviewed_recipe = {"name": subject_id, "version": "toolchain-owned"}
    reviewed_target = {
        "os": provider["target_os"],
        "architecture": provider["architecture"],
        "binary_format": provider["binary_format"],
    }
    reviewed_toolchain = {
        "route": route_id,
        "compiler_id": provider["compiler_id"],
        "identity": provider["toolchain_identity"],
    }
    reviewed_build = {
        "adapter": "qualified-runtime-archive",
        "query": provider["query"],
        "runtime_version": provider["runtime_version"],
        "authority_path": provider["authority_path"],
        "authority_sha256": provider["authority_sha256"],
    }
    reviewed_analysis = {
        "ghidra_language": provider["ghidra_language"],
        "ghidra_compiler_spec": provider["ghidra_compiler_spec"],
        "ghidra_version": "execution-probed",
        "analysis_profile": "fid-safe-default",
    }
    reviewed_routing = {
        "executor": "runtime-archive-local",
        "worker_pool": "library-local",
    }
    _expect(recipe, reviewed_recipe, "runtime subject identity")
    _expect(target, reviewed_target, "runtime target")
    _expect(toolchain, reviewed_toolchain, "runtime toolchain route")
    _expect(build, reviewed_build, "runtime archive query")
    _expect(analysis, reviewed_analysis, "runtime analysis route")
    _expect(routing, reviewed_routing, "runtime executor")
    archive = project_root / str(provider["path"])
    return (
        {
            "family": subject_id,
            "version": provider["runtime_version"],
            "variant": route_id,
            "archive": archive,
            "archive_sha256": provider["sha256"],
            "archive_bytes": provider["bytes"],
            "archive_members": provider["members"],
            "route": route,
        },
        {
            "recipe": reviewed_recipe,
            "target": reviewed_target,
            "toolchain": reviewed_toolchain,
            "build": reviewed_build,
            "analysis": reviewed_analysis,
        },
    )


def _initialize_ghidra(attempt_root: Path) -> GhidraRuntime:
    headless, ghidra_home = pipeline.find_ghidra()
    pipeline._require_executable_file(headless, "Ghidra analyzeHeadless")
    identity = pipeline.ghidra_identity(headless, ghidra_home)
    environment = pipeline.ghidra_environment(attempt_root / "work/ghidra/user")
    java, java_version, java_major = pipeline.java_identity(environment)
    pyghidra_version = pipeline.pyghidra_identity()
    started_now = ghidra_fid.ensure_started(ghidra_home, environment)
    return GhidraRuntime(
        install_dir=ghidra_home,
        identity={
            "ghidra": asdict(identity),
            "java": {
                "path": str(java),
                "version": java_version,
                "major": java_major,
            },
            "pyghidra": {"version": pyghidra_version},
            "jvm_started_now": started_now,
        },
    )


def _validated_counts(result: Mapping[str, object]) -> dict[str, int]:
    aliases = {
        "programs": ("programs", "fid_programs"),
        "attempted": ("attempted", "fid_attempted"),
        "added": ("added", "fid_added"),
        "excluded": ("excluded", "fid_excluded"),
    }
    counts: dict[str, int] = {}
    for output_name, names in aliases.items():
        value: object | None = None
        for name in names:
            if name in result:
                value = result[name]
                break
        if isinstance(value, str) and value.isdecimal():
            value = int(value)
        if type(value) is not int or int(value) < 0:
            raise CellRunnerError(f"invalid FID count {output_name}: {value!r}")
        counts[output_name] = int(value)
    if counts["programs"] < 1 or counts["attempted"] < 1 or counts["added"] < 1:
        raise CellRunnerError(f"Ghidra produced empty FID counts: {counts}")
    if counts["attempted"] != counts["added"] + counts["excluded"]:
        raise CellRunnerError(f"Ghidra FID counts do not reconcile: {counts}")
    return counts


def _object_evidence(objects: list[Path], attempt_root: Path) -> dict[str, object]:
    digest = hashlib.sha256()
    total_bytes = 0
    for path in objects:
        resolved = _relative_artifact(path, attempt_root, "selected object")
        size = resolved.stat().st_size
        total_bytes += size
        relative = str(resolved.relative_to(attempt_root.resolve()))
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(_sha256(resolved).encode("ascii"))
        digest.update(b"\n")
    return {
        "object_count": len(objects),
        "object_bytes": total_bytes,
        "object_set_sha256": digest.hexdigest(),
    }


def _build_direct_fidb(
    *,
    objects: list[Path],
    cell: dict[str, object],
    language: str,
    compiler_spec: str,
    attempt_root: Path,
    timing: TimingRecorder,
) -> tuple[Path, dict[str, int]]:
    digest = _digest(cell)
    output = attempt_root / "artifacts/fidbs" / f"{digest[:20]}.fidb"
    result = ghidra_fid.build_library_fidb(
        objects=objects,
        project_dir=attempt_root / "work/ghidra/projects" / digest[:20],
        project_name="cell",
        output=output,
        library=str(cell["family"]),
        version=str(cell["version"]),
        variant=str(cell["variant"]),
        language=language,
        compiler_spec=compiler_spec,
        timing=timing.span,
    )
    with timing.span(
        CellStage.FID_VALIDATION,
        "validating Ghidra FID population counts",
        {"fidb_path": str(output.relative_to(attempt_root))},
    ) as metrics:
        counts = _validated_counts(result)
        metrics.update(counts)
        validated = _relative_artifact(output, attempt_root, "FIDB")
        metrics["fidb_bytes"] = validated.stat().st_size
    return output, counts


def _export_fidbf(fidb: Path, attempt_root: Path) -> Path:
    fidb = _relative_artifact(fidb, attempt_root, "FIDB")
    fidbf = fidb.with_suffix(".fidbf")
    ghidra_fid.export_raw_fidbf(fidb, fidbf)
    _relative_artifact(fidbf, attempt_root, "FIDBF")
    return fidbf


def _native_outputs(
    configuration: Configuration,
    project_root: Path,
    attempt_root: Path,
    timing: TimingRecorder,
    verbose: bool,
    build_jobs_per_cell: int,
) -> tuple[Path, dict[str, int], dict[str, object], dict[str, object]]:
    manifest = pipeline.execute(
        configuration,
        attempt_root,
        progress=None,
        verbose=verbose,
        build_jobs_per_cell=build_jobs_per_cell,
        source_downloads=project_root / MANAGED_SOURCE_DOWNLOADS,
        timing=timing.span,
        skipped=timing.skip,
    )
    with timing.span(
        CellStage.FID_VALIDATION,
        "validating native pipeline FID result",
    ) as metrics:
        manifest = _relative_artifact(Path(manifest), attempt_root, "native manifest")
        previous_limit = csv.field_size_limit()
        csv.field_size_limit(max(previous_limit, MANIFEST_FIELD_LIMIT))
        try:
            with manifest.open(newline="", encoding="utf-8") as stream:
                rows = list(csv.DictReader(stream))
        finally:
            csv.field_size_limit(previous_limit)
        if len(rows) != 1 or rows[0].get("status") != "complete":
            raise CellRunnerError(
                f"native pipeline did not return exactly one complete cell: {rows!r}"
            )
        row = rows[0]
        fidb_value = str(row.get("fidb_path", ""))
        fidb = Path(fidb_value)
        if not fidb.is_absolute():
            fidb = attempt_root / fidb
        fidb = _relative_artifact(fidb, attempt_root, "native FIDB")
        if row.get("fidb_sha256") != _sha256(fidb):
            raise CellRunnerError("native manifest FIDB digest does not match output")
        counts = _validated_counts(row)
        metrics.update(counts)
        metrics["fidb_bytes"] = fidb.stat().st_size
    runtime = {
        "ghidra": {
            "version": row.get("ghidra_version"),
            "release": row.get("ghidra_release"),
            "build": row.get("ghidra_build"),
            "properties_sha256": row.get("ghidra_application_properties_sha256"),
            "headless_path": row.get("ghidra_headless_path"),
        },
        "java": {
            "path": row.get("java_path"),
            "version": row.get("java_version"),
        },
        "pyghidra": {"version": row.get("pyghidra_version")},
    }
    source_evidence = {
        "source_url": row.get("source_url"),
        "source_sha256": row.get("source_sha256"),
        "build_inputs": json.loads(row.get("build_input_pins", "[]")),
        "static_archive_path": row.get("static_archive_path"),
        "static_archive_sha256": row.get("static_archive_sha256"),
        "analysis_artifact_kind": row.get("analysis_artifact_kind"),
        "analysis_artifact_path": row.get("analysis_artifact_path"),
        "analysis_artifact_sha256": row.get("analysis_artifact_sha256"),
        "object_count": int(row.get("object_count", "0")),
        "toolchain": {
            "compiler": {
                "command": row.get("compiler_command"),
                "path": row.get("compiler_path"),
                "sha256": row.get("compiler_sha256"),
                "version": row.get("compiler_version"),
                "flags": row.get("compiler_flags"),
            },
            "archiver": {
                "command": row.get("archiver_command"),
                "path": row.get("archiver_path"),
                "sha256": row.get("archiver_sha256"),
                "version": row.get("archiver_version"),
            },
            "ranlib": {
                "command": row.get("ranlib_command"),
                "path": row.get("ranlib_path"),
                "sha256": row.get("ranlib_sha256"),
                "version": row.get("ranlib_version"),
            },
        },
        "pipeline_manifest": _artifact(manifest, attempt_root, "native manifest"),
    }
    return fidb, counts, runtime, source_evidence


def _source_outputs(
    cell: dict[str, object],
    pins: dict[str, object],
    project_root: Path,
    attempt_root: Path,
    timing: TimingRecorder,
) -> tuple[Path, dict[str, int], dict[str, object], dict[str, object]]:
    guess = libc_catalog.prepare_recipe(
        cell,
        attempt_root / "work/source",
        project_root / MANAGED_DOWNLOADS,
        timing=timing.span,
        skipped=timing.skip,
    )
    expected_guess: dict[str, object] = {
        "family": cell["family"],
        "version": str(cell["version"]),
        "variant": cell["variant"],
        "language": _mapping(pins["analysis"], "pins.analysis")["ghidra_language"],
        "source_url": cell.get("source_url", cell.get("url")),
        "source_sha256": cell.get("source_sha256", cell.get("sha256")),
    }
    if cell.get("mode") == "source":
        expected_guess["executor"] = cell["executor"]
    for field, expected in expected_guess.items():
        _expect(guess.get(field), expected, f"prepared source {field}")
    _expect(
        guess.get("recipe_digest"),
        libc_catalog._digest(cell),
        "prepared source cell digest",
    )
    with timing.span(
        CellStage.ARCHIVE_OBJECT_SELECTION,
        "selecting reviewed analysis objects",
        {"pattern": guess.get("pattern"), "limit": guess.get("limit")},
    ) as selection_metrics:
        objects = _select_objects(guess)
        selection_metrics.update(
            {
                "object_count": len(objects),
                "object_bytes": sum(path.stat().st_size for path in objects),
            }
        )
    with timing.span(
        CellStage.ARTIFACT_VALIDATION,
        "validating selected object target ABI",
        {"object_count": len(objects)},
    ) as validation_metrics:
        expected_target = _mapping(pins["target"], "pins.target")
        for object_path in objects:
            facts = inspect_elf(object_path)
            observed_target = {
                "machine": facts.machine,
                "endianness": facts.endianness,
                "elf_class": facts.elf_class,
            }
            _expect(observed_target, expected_target, "selected object ELF target")
        evidence = {
            "prepared_recipe_digest": guess.get("recipe_digest"),
            **_object_evidence(objects, attempt_root),
        }
        validation_metrics.update(evidence)
    with timing.span(
        CellStage.GHIDRA_STARTUP,
        "initializing isolated Ghidra JVM",
    ) as startup_metrics:
        runtime = _initialize_ghidra(attempt_root)
        startup_metrics.update(runtime.identity)
    fidb, counts = _build_direct_fidb(
        objects=objects,
        cell=cell,
        language=str(_mapping(pins["analysis"], "pins.analysis")["ghidra_language"]),
        compiler_spec=str(
            _mapping(pins["analysis"], "pins.analysis")["ghidra_compiler_spec"]
        ),
        attempt_root=attempt_root,
        timing=timing,
    )
    return fidb, counts, runtime.identity, evidence


def _runtime_outputs(
    cell: dict[str, object],
    pins: dict[str, object],
    project_root: Path,
    attempt_root: Path,
    timing: TimingRecorder,
) -> tuple[Path, dict[str, int], dict[str, object], dict[str, object]]:
    archive = Path(str(cell["archive"]))
    try:
        archive.relative_to((project_root / "var/fidb-toolchains").resolve())
    except ValueError as error:
        raise CellRunnerError("runtime archive escaped managed toolchains") from error
    if archive.is_symlink() or not archive.is_file():
        raise CellRunnerError(f"runtime archive is not a regular file: {archive}")
    _expect(_sha256(archive), cell["archive_sha256"], "runtime archive digest")
    work = attempt_root / "work/runtime-archive"
    logs = attempt_root / "artifacts/logs"
    temporary = work / "tmp"
    temporary.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    environment["TMPDIR"] = str(temporary)
    with timing.span(
        CellStage.ARCHIVE_OBJECT_SELECTION,
        "extracting qualified route-owned runtime archive",
        {
            "archive_bytes": int(cell["archive_bytes"]),
            "archive_members": int(cell["archive_members"]),
        },
    ) as selection_metrics:
        objects = pipeline._extract_archive_objects(
            archive,
            work / "objects",
            cell["route"],
            environment,
            logs / "runtime-archive.log",
        )
        selection_metrics.update(
            {
                "object_count": len(objects),
                "object_bytes": sum(path.stat().st_size for path in objects),
            }
        )
    with timing.span(
        CellStage.ARTIFACT_VALIDATION,
        "validating runtime objects against the reviewed Ghidra language",
        {"object_count": len(objects)},
    ) as validation_metrics:
        expected_language = str(
            _mapping(pins["analysis"], "pins.analysis")["ghidra_language"]
        )
        for object_path in objects:
            facts = inspect_elf(object_path)
            observed_language = ghidra_language(
                facts.machine, facts.endianness, facts.elf_class
            )
            _expect(observed_language, expected_language, "runtime object language")
        evidence = {
            "runtime_archive_path": str(archive.relative_to(project_root)),
            "runtime_archive_sha256": cell["archive_sha256"],
            "runtime_archive_bytes": cell["archive_bytes"],
            "runtime_archive_members": cell["archive_members"],
            **_object_evidence(objects, attempt_root),
        }
        validation_metrics.update(evidence)
    with timing.span(
        CellStage.GHIDRA_STARTUP,
        "initializing isolated Ghidra JVM",
    ) as startup_metrics:
        runtime = _initialize_ghidra(attempt_root)
        startup_metrics.update(runtime.identity)
    fidb, counts = _build_direct_fidb(
        objects=objects,
        cell=cell,
        language=str(_mapping(pins["analysis"], "pins.analysis")["ghidra_language"]),
        compiler_spec=str(
            _mapping(pins["analysis"], "pins.analysis")["ghidra_compiler_spec"]
        ),
        attempt_root=attempt_root,
        timing=timing,
    )
    return fidb, counts, runtime.identity, evidence


def _validate_malware_result(
    result: dict[str, object], cell: dict[str, object], attempt_root: Path
) -> tuple[Path, ElfFacts, dict[str, object]]:
    expected = {
        "family": cell["family"],
        "version": cell["version"],
        "variant": cell["variant"],
        "arch": cell["arch"],
        "source_url": cell["source_url"],
        "source_sha256": cell["source_sha256"],
        "toolchain_url": cell["toolchain_url"],
        "toolchain_sha256": cell["toolchain_sha256"],
        "build_adapter": cell["build_adapter"],
        "executor": cell["executor"],
        "cell_digest": libc_catalog._digest(cell),
    }
    for field, expected_value in expected.items():
        _expect(result.get(field), expected_value, f"malware build {field}")
    binary = _relative_artifact(
        Path(str(result.get("binary_path", ""))), attempt_root, "malware binary"
    )
    binary.chmod(0o644)
    if stat.S_IMODE(binary.stat().st_mode) != 0o644:
        raise CellRunnerError(f"malware binary mode is not 0644: {binary}")
    digest = _sha256(binary)
    if result.get("binary_sha256") != digest:
        raise CellRunnerError("malware build binary digest does not match output")
    facts = inspect_elf(binary)
    expected_target = {
        "machine": cell["machine"],
        "endianness": cell["endianness"],
        "elf_class": int(cell["elf_class"]),
    }
    observed_target = {
        "machine": facts.machine,
        "endianness": facts.endianness,
        "elf_class": facts.elf_class,
    }
    _expect(observed_target, expected_target, "malware ELF target")
    return (
        binary,
        facts,
        {
            "binary": _artifact(binary, attempt_root, "malware binary"),
            "elf": facts.to_dict(),
        },
    )


def _malware_outputs(
    cell: dict[str, object],
    pins: dict[str, object],
    project_root: Path,
    attempt_root: Path,
    timing: TimingRecorder,
) -> tuple[Path, dict[str, int], dict[str, object], dict[str, object]]:
    with timing.span(
        CellStage.COMPILE,
        "cross-building pinned malware source",
        {"executor": cell.get("executor"), "adapter": cell.get("build_adapter")},
    ):
        result = malware_build.build_malware_binary(
            cell, attempt_root / "work/malware", project_root / MANAGED_DOWNLOADS
        )
    with timing.span(
        CellStage.ARTIFACT_VALIDATION,
        "validating static-analysis ELF",
    ) as validation_metrics:
        binary, _facts, evidence = _validate_malware_result(result, cell, attempt_root)
        validation_metrics.update(evidence["binary"])
    with timing.span(
        CellStage.GHIDRA_STARTUP,
        "initializing isolated Ghidra JVM",
    ) as startup_metrics:
        runtime = _initialize_ghidra(attempt_root)
        startup_metrics.update(runtime.identity)
    fidb, counts = _build_direct_fidb(
        objects=[binary],
        cell=cell,
        language=str(_mapping(pins["analysis"], "pins.analysis")["ghidra_language"]),
        compiler_spec=str(
            _mapping(pins["analysis"], "pins.analysis")["ghidra_compiler_spec"]
        ),
        attempt_root=attempt_root,
        timing=timing,
    )
    return fidb, counts, runtime.identity, evidence


def _write_seal(path: Path, document: dict[str, object]) -> tuple[Path, str]:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise CellRunnerError(f"attempt already has a final seal: {path}")
    payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return path, _sha256(path)


def run_cell(
    resolved_cell: Mapping[str, object],
    factor_variants: Sequence[str],
    project_root: Path,
    attempt_root: Path,
    *,
    progress: ProgressCallback | None = None,
    verbose: bool = False,
    build_jobs_per_cell: int = 4,
    authority_resolver: CellAuthorityResolver | None = None,
) -> CellRunResult:
    """Run one already-resolved cell and atomically seal its provenance.

    ``factor_variants`` must contain one executable (``state="registered"``)
    catalog choice per factor.  The choices are evidence about the resolved
    route; they never become caller-provided compiler flags or commands.
    """

    timing = TimingRecorder(progress)
    with timing.span(
        CellStage.REQUEST_VALIDATION,
        "validating queued request and isolated roots",
    ) as validation_metrics:
        project, attempt = _validate_roots(Path(project_root), Path(attempt_root))
        plain = _plain(resolved_cell)
        if not isinstance(plain, dict):
            raise CellResolutionError("resolved cell must be a table")
        _reject_raw_commands(plain)
        cell_id, kind = _validate_cell_state(plain)
        resolved_digest = _digest(plain)
        variants, variants_digest = _resolve_factor_variants(project, factor_variants)
        validation_metrics.update(
            {
                "cell_id": cell_id,
                "kind": kind,
                "factor_variant_count": len(variants),
            }
        )

    with timing.span(
        CellStage.AUTHORITY_RESOLUTION,
        "re-resolving reviewed authorities",
        {"cell_id": cell_id, "kind": kind},
    ) as resolution_metrics:
        if kind == "native":
            configuration, pins = _resolve_native(
                plain, project, authority_resolver=authority_resolver
            )
            _validate_native_treatment_variants(configuration, variants)
            generated = None
            executor = "native-local"
        elif kind == "archive-library":
            generated, pins = _resolve_archive(plain, project)
            configuration = None
            executor = "archive-local"
        elif kind == "runtime-library":
            generated, pins = _resolve_runtime(
                plain, project, authority_resolver=authority_resolver
            )
            configuration = None
            executor = "runtime-archive-local"
        else:
            generated, pins = _resolve_source(plain, project, kind)
            configuration = None
            executor = str(generated["executor"])
        resolution_metrics.update(
            {
                "executor": executor,
                "recipe": _mapping(pins["recipe"], "pins.recipe").get("name"),
            }
        )

    if kind == "native":
        assert configuration is not None
        fidb, counts, runtime, evidence = _native_outputs(
            configuration, project, attempt, timing, verbose, build_jobs_per_cell
        )
    else:
        assert generated is not None
        if kind in {"source-library", "archive-library"}:
            fidb, counts, runtime, evidence = _source_outputs(
                generated, pins, project, attempt, timing
            )
        elif kind == "runtime-library":
            fidb, counts, runtime, evidence = _runtime_outputs(
                generated, pins, project, attempt, timing
            )
        else:
            fidb, counts, runtime, evidence = _malware_outputs(
                generated, pins, project, attempt, timing
            )

    fidb = _relative_artifact(fidb, attempt, "FIDB")
    if kind == "native":
        timing.skip(
            CellStage.FIDB_EXPORT,
            "packed FIDB was exported by the native pipeline",
            {
                "native_pipeline_export": True,
                "bytes": fidb.stat().st_size,
                "sha256": _sha256(fidb),
            },
        )
    else:
        with timing.span(
            CellStage.FIDB_EXPORT,
            "finalizing packed FIDB artifact",
        ) as fidb_metrics:
            fidb_metrics.update(
                {
                    "bytes": fidb.stat().st_size,
                    "sha256": _sha256(fidb),
                    **counts,
                }
            )
    with timing.span(
        CellStage.FIDBF_EXPORT,
        "exporting raw FIDBF artifact",
        {"packed_fidb_bytes": fidb.stat().st_size},
    ) as fidbf_metrics:
        fidbf = _export_fidbf(fidb, attempt)
        fidbf_metrics.update({"bytes": fidbf.stat().st_size, "sha256": _sha256(fidbf)})
    with timing.span(
        CellStage.ARTIFACT_VALIDATION,
        "validating final FIDB and FIDBF artifacts",
    ) as artifact_metrics:
        artifacts = {
            "fidb": _artifact(fidb, attempt, "FIDB"),
            "fidbf": _artifact(fidbf, attempt, "FIDBF"),
        }
        artifact_metrics.update(
            {
                "fidb_bytes": artifacts["fidb"]["bytes"],
                "fidbf_bytes": artifacts["fidbf"]["bytes"],
            }
        )
    pre_seal_timing = timing.document()
    seal = {
        "schema_version": SEAL_SCHEMA,
        "cell": {
            "id": cell_id,
            "kind": kind,
            "resolved_cell_sha256": resolved_digest,
            "factor_variants": variants,
            "factor_variants_catalog_sha256": variants_digest,
            "executor": executor,
        },
        "pins": pins,
        "runtime": runtime,
        "evidence": evidence,
        "counts": counts,
        "artifacts": artifacts,
        "timing": pre_seal_timing,
    }
    with timing.span(
        CellStage.PROVENANCE_SEAL,
        "writing atomic cell provenance seal",
        {
            "included_terminal_spans": len(pre_seal_timing["spans"]),
            "self_timing_included": False,
        },
    ) as seal_metrics:
        seal_path, seal_sha256 = _write_seal(attempt / "artifacts/cell-seal.json", seal)
        seal_metrics.update(
            {"seal_bytes": seal_path.stat().st_size, "seal_sha256": seal_sha256}
        )
    return CellRunResult(
        cell_id=cell_id,
        kind=kind,
        executor=executor,
        manifest_path=seal_path,
        manifest_sha256=seal_sha256,
        fidb_path=fidb,
        fidbf_path=fidbf,
        timing=timing.document(),
    )
