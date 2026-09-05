"""Typed source-pack and research-candidate acquisition commands."""

from __future__ import annotations

import argparse
import json
import lzma
from pathlib import Path
import re
import sys

from .source_packs import import_source_archive, pull_source_pack, source_pack_status
from .toolchain_cache import CacheError

_PACK_ID = re.compile(r"^[a-z0-9][a-z0-9._+-]*$")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fidb-poc source",
        description=(
            "Inspect or pull checksum-pinned source archives without extracting "
            "or executing them."
        ),
    )
    parser.add_argument("command", choices=("status", "pull", "import"))
    parser.add_argument("pack", nargs="?", default="c-top10-v1")
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--id",
        action="append",
        dest="source_ids",
        default=[],
        help="reviewed source id; repeat as needed (default: complete pack)",
    )
    parser.add_argument(
        "--file",
        type=Path,
        help="local archive for import; requires exactly one --id",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    tokens = list(argv or [])
    if tokens and tokens[0] == "acquisition":
        return _acquisition_main(tokens[1:])
    arguments = _parser().parse_args(argv)
    if _PACK_ID.fullmatch(arguments.pack) is None:
        print("error: source pack must be a lowercase safe token", file=sys.stderr)
        return 1
    root = arguments.project_root.resolve()
    pack_path = root / "sources" / f"{arguments.pack}.toml"
    try:
        if arguments.command == "import":
            if len(arguments.source_ids) != 1 or arguments.file is None:
                raise ValueError("source import requires exactly one --id and --file")
            result = import_source_archive(
                root,
                pack_path,
                arguments.source_ids[0],
                arguments.file.expanduser(),
            )
        elif arguments.command == "pull":
            result = pull_source_pack(root, pack_path, tuple(arguments.source_ids))
        else:
            result = source_pack_status(root, pack_path, tuple(arguments.source_ids))
            result["operation"] = "status"
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (CacheError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def _acquisition_main(argv: list[str]) -> int:
    from .source_acquisition import (
        acquisition_status,
        pull_acquisition,
        refresh_metadata,
        resolve_acquisition,
    )

    parser = argparse.ArgumentParser(
        prog="fidb-poc source acquisition",
        description=(
            "Freeze registry metadata, resolve every research candidate into a "
            "reviewable TOML lock, and pull only checksum-pinned source bytes."
        ),
    )
    parser.add_argument("command", choices=("refresh", "resolve", "status", "pull"))
    parser.add_argument("acquisition", nargs="?", default="c80-four-source-n80-v1")
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--id", action="append", dest="source_ids", default=[])
    parser.add_argument("--workers", type=int)
    arguments = parser.parse_args(argv)
    root = arguments.project_root.expanduser().resolve()
    try:
        if arguments.command == "refresh":
            if arguments.source_ids or arguments.workers is not None:
                raise ValueError(
                    "source acquisition refresh does not accept --id/--workers"
                )
            result = refresh_metadata(root, arguments.acquisition)
        elif arguments.command == "resolve":
            if arguments.source_ids or arguments.workers is not None:
                raise ValueError(
                    "source acquisition resolve does not accept --id/--workers"
                )
            result = resolve_acquisition(root, arguments.acquisition)
        elif arguments.command == "pull":
            result = pull_acquisition(
                root,
                arguments.acquisition,
                tuple(arguments.source_ids),
                workers=arguments.workers,
                progress=lambda message: print(message, file=sys.stderr, flush=True),
            )
        else:
            if arguments.workers is not None:
                raise ValueError("source acquisition status does not accept --workers")
            result = acquisition_status(
                root, arguments.acquisition, tuple(arguments.source_ids)
            )
        print(json.dumps(result, indent=2, sort_keys=True))
        failures = result.get("failures", [])
        return 1 if failures else 0
    except (
        CacheError,
        OSError,
        ValueError,
        json.JSONDecodeError,
        lzma.LZMAError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
