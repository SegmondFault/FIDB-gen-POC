"""Typed operator commands for the reviewed, content-addressed input cache."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

from .toolchain_cache import (
    CacheError,
    MANAGED_DOWNLOADS,
    acquire_pinned,
    inspect_cached,
)
from .toolchain_registry import load_toolchains
from .toolchain_inputs import InputBindingError, bind_input, inspect_input_binding
from .toolchain_packs import load_toolchain_pack_catalog, resolve_toolchain_profile
from .toolchain_prepare import (
    MANAGED_PREPARED,
    PreparationError,
    prepare_pinned_archive,
)
from .toolchain_qualification import (
    QualificationError,
    compose_osxcross,
    qualify_route,
)
from .target_registry import load_targets

CACHE_STATUS_SCHEMA = "fidb-toolchain-cache-status/v1"
INPUT_STATUS_SCHEMA = "fidb-toolchain-input-status/v1"


def _identity(row: dict[str, object]) -> str:
    return f'{row["family"]}@{row["version"]}:{row["variant"]}'


def _rows(project_root: Path) -> list[dict[str, object]]:
    return load_toolchains(project_root / "toolchains/registry.toml")


def _select(
    rows: list[dict[str, object]], requested: tuple[str, ...]
) -> list[dict[str, object]]:
    if not requested:
        return rows
    duplicates = sorted({value for value in requested if requested.count(value) > 1})
    if duplicates:
        raise ValueError("duplicate toolchain identity: " + ", ".join(duplicates))
    by_id = {_identity(row): row for row in rows}
    unknown = sorted(set(requested) - by_id.keys())
    if unknown:
        raise ValueError("unknown reviewed toolchain identity: " + ", ".join(unknown))
    return [by_id[value] for value in requested]


def _inputs(row: dict[str, object], purpose: str) -> list[tuple[str, str, str]]:
    values: list[tuple[str, str, str]] = []
    if purpose in {"all", "archive"} and "url" in row:
        values.append(("archive", str(row["url"]), str(row["sha256"])))
    if purpose in {"all", "toolchain"} and "toolchain_url" in row:
        values.append(
            (
                "toolchain",
                str(row["toolchain_url"]),
                str(row["toolchain_sha256"]),
            )
        )
    if purpose != "all" and not values:
        raise ValueError(
            f"{_identity(row)} does not provide a reviewed {purpose} payload"
        )
    return values


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fidb-poc toolchain",
        description="Inspect or acquire only checksum-pinned registry inputs.",
    )
    parser.add_argument(
        "command", choices=("status", "acquire"), help="typed cache operation"
    )
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--id",
        action="append",
        dest="identities",
        default=[],
        help="reviewed family@version:variant identity; repeat as needed",
    )
    parser.add_argument(
        "--input",
        choices=("all", "archive", "toolchain"),
        default="all",
        help="which reviewed payload to inspect/acquire (default: all)",
    )
    return parser


def _profile_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fidb-poc toolchain profile",
        description=(
            "Run the reviewed pull, preparation, composition, and C-family "
            "qualification lifecycle for a toolchain profile. External worker "
            "requirements are reported, never hidden."
        ),
    )
    parser.add_argument(
        "command",
        choices=("plan", "status", "pull", "prepare", "compose", "qualify"),
        help="typed profile operation",
    )
    parser.add_argument("profile", help="reviewed profile id")
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    return parser


def _input_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fidb-poc toolchain input",
        description="Inspect or privately bind one reviewed non-redistributable input.",
    )
    parser.add_argument("command", choices=("status", "bind"))
    parser.add_argument("input_id", help="reviewed input id")
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--path", type=Path, help="local package to verify and copy")
    parser.add_argument("--sha256", help="declared package SHA-256")
    parser.add_argument("--bytes", type=int, dest="byte_count", help="declared bytes")
    parser.add_argument(
        "--metadata",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="reviewed metadata field; repeat for every required key",
    )
    return parser


def _runtime_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fidb-poc toolchain runtime",
        description="Inspect toolchain-owned runtime-library extraction providers.",
    )
    parser.add_argument("command", choices=("status",))
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--probe",
        action="store_true",
        help="query and validate every exact archive without compilation or Ghidra",
    )
    return parser


def _runtime_main(argv: list[str]) -> int:
    arguments = _runtime_parser().parse_args(argv)
    try:
        from .runtime_libraries import runtime_library_status

        result = runtime_library_status(
            arguments.project_root.resolve(), probe=arguments.probe
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["summary"]["blocked_cells"] == 0 else 1
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def _metadata(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise ValueError("metadata must use KEY=VALUE")
        key, item = value.split("=", 1)
        if not key or not item:
            raise ValueError("metadata keys and values must be non-empty")
        if key in result:
            raise ValueError(f"duplicate metadata key: {key}")
        result[key] = item
    return result


def _input_main(argv: list[str]) -> int:
    arguments = _input_parser().parse_args(argv)
    project_root = arguments.project_root.resolve()
    try:
        catalog = load_toolchain_pack_catalog(project_root)
        inputs = {str(row["id"]): row for row in catalog["inputs"]}
        if arguments.input_id not in inputs:
            raise ValueError(f"unknown reviewed toolchain input: {arguments.input_id}")
        authority = inputs[arguments.input_id]
        if arguments.command == "status":
            inspection = inspect_input_binding(project_root, authority)
            document = asdict(inspection)
            document["binding_path"] = str(inspection.binding_path)
            document["material_path"] = (
                str(inspection.material_path)
                if inspection.material_path is not None
                else None
            )
            result = {
                "schema_version": INPUT_STATUS_SCHEMA,
                "operation": "status",
                "authority": authority,
                "binding": document,
            }
        else:
            if (
                arguments.path is None
                or arguments.sha256 is None
                or arguments.byte_count is None
            ):
                raise ValueError("bind requires --path, --sha256, and --bytes")
            binding = bind_input(
                project_root,
                authority,
                arguments.path.expanduser().resolve(),
                arguments.sha256,
                arguments.byte_count,
                _metadata(arguments.metadata),
            )
            document = asdict(binding)
            document["binding_path"] = str(binding.binding_path)
            document["material_path"] = str(binding.material_path)
            result = {
                "schema_version": INPUT_STATUS_SCHEMA,
                "operation": "bind",
                "authority": authority,
                "binding": document,
            }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (InputBindingError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def _profile_main(argv: list[str]) -> int:
    arguments = _profile_parser().parse_args(argv)
    project_root = arguments.project_root.resolve()
    try:
        before = resolve_toolchain_profile(project_root, arguments.profile)
        before["operation"] = arguments.command
        if arguments.command in {"plan", "status"}:
            print(json.dumps(before, indent=2, sort_keys=True))
            return 0
        if not before["host"]["compatible"]:
            raise ValueError(
                f"refusing profile {arguments.command} on an incompatible host: "
                f"requires {before['host']['required_system']}/"
                f"{before['host']['required_architecture']}"
            )

        if arguments.command == "pull":
            downloads = project_root / MANAGED_DOWNLOADS
            acquisitions = []
            for pack in before["packs"]:
                result = acquire_pinned(
                    str(pack["url"]), str(pack["sha256"]), downloads
                )
                if result.bytes != int(pack["download_bytes"]):
                    raise CacheError(
                        f"reviewed size mismatch for {pack['id']}: expected "
                        f"{pack['download_bytes']}, observed {result.bytes}"
                    )
                values = asdict(result)
                values["path"] = str(result.path)
                values["quarantined"] = (
                    str(result.quarantined) if result.quarantined is not None else None
                )
                acquisitions.append({"pack_id": pack["id"], **values})
            after = resolve_toolchain_profile(project_root, arguments.profile)
            after["operation"] = "pull"
            after["acquisitions"] = acquisitions
        elif arguments.command == "prepare":
            unavailable = [
                str(pack["id"])
                for pack in before["packs"]
                if pack["state"] != "verified-cached"
            ]
            if unavailable:
                raise PreparationError(
                    "refusing preparation until every archive is verified-cached: "
                    + ", ".join(unavailable)
                )
            preparations = []
            prepared = project_root / MANAGED_PREPARED
            for pack in before["packs"]:
                result = prepare_pinned_archive(
                    Path(str(pack["cache"]["path"])),
                    str(pack["sha256"]),
                    int(pack["download_bytes"]),
                    str(pack["archive_root"]),
                    prepared,
                    max_extracted_bytes=max(
                        int(pack["installed_bytes_estimate"]) * 2,
                        int(pack["download_bytes"]) * 8,
                    ),
                )
                values = asdict(result)
                values["path"] = str(result.path)
                values["root"] = str(result.root)
                values["quarantined"] = (
                    str(result.quarantined) if result.quarantined is not None else None
                )
                preparations.append({"pack_id": pack["id"], **values})
            after = resolve_toolchain_profile(project_root, arguments.profile)
            after["operation"] = "prepare"
            after["preparations"] = preparations
        elif arguments.command == "compose":
            composable = [
                route
                for route in before["routes"]
                if route.get("qualification", {})
                .get("definition", {})
                .get("composition")
                != "none"
            ]
            unavailable = [
                str(route["id"])
                for route in composable
                if route["state"]
                not in {"composition-required", "qualification-required", "qualified"}
            ]
            if unavailable:
                raise QualificationError(
                    "refusing composition until route prerequisites are ready: "
                    + ", ".join(unavailable)
                )
            compositions = []
            for route in composable:
                definition = route["qualification"]["definition"]
                result = compose_osxcross(
                    project_root,
                    route,
                    definition,
                    before["packs"],
                    before["inputs"],
                )
                values = asdict(result)
                values["path"] = str(result.path)
                values["root"] = str(result.root)
                compositions.append(values)
            after = resolve_toolchain_profile(project_root, arguments.profile)
            after["operation"] = "compose"
            after["compositions"] = compositions
        else:
            host_routes = [
                route
                for route in before["routes"]
                if route["provisioning"] != "external-worker"
            ]
            unavailable = [
                str(route["id"])
                for route in host_routes
                if route["state"] not in {"qualification-required", "qualified"}
            ]
            if unavailable:
                raise QualificationError(
                    "refusing qualification until every host route is ready: "
                    + ", ".join(unavailable)
                )
            targets = {
                str(row["id"]): row
                for row in load_targets(project_root / "targets/registry.toml")
            }
            qualifications = []
            for route in host_routes:
                definition = route["qualification"]["definition"]
                result = qualify_route(
                    project_root,
                    route,
                    definition,
                    targets[str(route["target_id"])],
                    before["packs"],
                    before["inputs"],
                )
                values = asdict(result)
                values["path"] = str(result.path)
                qualifications.append(values)
            after = resolve_toolchain_profile(project_root, arguments.profile)
            after["operation"] = "qualify"
            after["qualifications"] = qualifications
        print(json.dumps(after, indent=2, sort_keys=True))
        return 0
    except (
        CacheError,
        OSError,
        PreparationError,
        QualificationError,
        ValueError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    tokens = sys.argv[1:] if argv is None else argv
    if tokens and tokens[0] == "input":
        return _input_main(tokens[1:])
    if tokens and tokens[0] == "profile":
        return _profile_main(tokens[1:])
    if tokens and tokens[0] == "runtime":
        return _runtime_main(tokens[1:])
    arguments = _parser().parse_args(tokens)
    project_root = arguments.project_root.resolve()
    downloads = project_root / MANAGED_DOWNLOADS
    try:
        selected = _select(_rows(project_root), tuple(arguments.identities))
        entries = []
        for row in selected:
            inputs = []
            for kind, url, digest in _inputs(row, arguments.input):
                if arguments.command == "acquire":
                    result = acquire_pinned(url, digest, downloads)
                    values = asdict(result)
                    values["path"] = str(result.path)
                    values["quarantined"] = (
                        str(result.quarantined)
                        if result.quarantined is not None
                        else None
                    )
                else:
                    inspection = inspect_cached(downloads, digest)
                    values = asdict(inspection)
                    values["path"] = str(inspection.path)
                inputs.append(
                    {
                        "kind": kind,
                        "source": "reviewed-registry",
                        "url": url,
                        "expected_sha256": digest,
                        **values,
                    }
                )
            entries.append({"id": _identity(row), "inputs": inputs})
        print(
            json.dumps(
                {
                    "schema_version": CACHE_STATUS_SCHEMA,
                    "operation": arguments.command,
                    "managed_downloads": str(downloads),
                    "entries": entries,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    except (CacheError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
