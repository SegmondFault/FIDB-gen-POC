"""Typed source-pack status and sequential acquisition commands."""

from __future__ import annotations

import argparse
import json
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
