"""Strict compiler identities kept separate from target/toolchain routes."""

from __future__ import annotations

from pathlib import Path
import re
import tomllib

SCHEMA = "fidb-compiler-identities/v1"
FIELDS = {
    "id",
    "family",
    "version",
    "generation",
    "language_ids",
    "release_authority",
}
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def load_compiler_identities(path: str | Path) -> list[dict[str, object]]:
    document = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    if set(document) != {"schema_version", "compiler"}:
        raise ValueError("compiler identity authority has unexpected fields")
    if document.get("schema_version") != SCHEMA:
        raise ValueError("unsupported compiler identity schema")
    raw_rows = document.get("compiler")
    if not isinstance(raw_rows, list) or not raw_rows:
        raise ValueError("compiler identity authority requires compiler rows")
    rows: list[dict[str, object]] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_rows):
        if not isinstance(raw, dict) or set(raw) != FIELDS:
            raise ValueError(f"compiler identity row {index} has unexpected fields")
        row = dict(raw)
        compiler_id = row.get("id")
        if (
            not isinstance(compiler_id, str)
            or IDENTIFIER.fullmatch(compiler_id) is None
            or compiler_id in seen
        ):
            raise ValueError(f"compiler identity row {index} has invalid/duplicate id")
        seen.add(compiler_id)
        for field in FIELDS - {"language_ids"}:
            if not isinstance(row[field], str) or not row[field]:
                raise ValueError(f"compiler {compiler_id} {field} must be non-empty")
        languages = row["language_ids"]
        if (
            not isinstance(languages, list)
            or not languages
            or not all(isinstance(value, str) and value for value in languages)
            or len(languages) != len(set(languages))
        ):
            raise ValueError(f"compiler {compiler_id} has invalid language_ids")
        rows.append(row)
    return rows
