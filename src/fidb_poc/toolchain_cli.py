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
from .toolchain_packs import resolve_toolchain_profile

CACHE_STATUS_SCHEMA = "fidb-toolchain-cache-status/v1"


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
            "Plan, inspect, or pull every checksum-pinned archive in a reviewed "
            "toolchain profile. External worker requirements are reported, never hidden."
        ),
    )
    parser.add_argument(
        "command",
        choices=("plan", "status", "pull"),
        help="typed profile operation",
    )
    parser.add_argument("profile", help="reviewed profile id")
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    return parser


def _profile_main(argv: list[str]) -> int:
    arguments = _profile_parser().parse_args(argv)
    project_root = arguments.project_root.resolve()
    try:
        before = resolve_toolchain_profile(project_root, arguments.profile)
        before["operation"] = arguments.command
        if arguments.command != "pull":
            print(json.dumps(before, indent=2, sort_keys=True))
            return 0
        if not before["host"]["compatible"]:
            raise ValueError(
                "refusing profile pull on an incompatible host: "
                f"requires {before['host']['required_system']}/"
                f"{before['host']['required_architecture']}"
            )

        downloads = project_root / MANAGED_DOWNLOADS
        acquisitions = []
        for pack in before["packs"]:
            result = acquire_pinned(str(pack["url"]), str(pack["sha256"]), downloads)
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
        print(json.dumps(after, indent=2, sort_keys=True))
        return 0
    except (CacheError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    tokens = sys.argv[1:] if argv is None else argv
    if tokens and tokens[0] == "profile":
        return _profile_main(tokens[1:])
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
