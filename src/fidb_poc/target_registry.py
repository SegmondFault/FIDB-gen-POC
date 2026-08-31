"""Validated target coverage catalogue.

Targets describe desired or observed platform/ABI identities.  They do not
claim that a compiler is installed; live capability detection supplies that
state separately.
"""

from __future__ import annotations

from pathlib import Path
import tomllib

TARGET_SCHEMA = "fidb-targets/v1"
TARGET_FIELDS = {
    "id",
    "label",
    "platform",
    "architecture",
    "machine",
    "binary_format",
    "endianness",
    "bits",
    "catalog_state",
    "evidence",
}
CATALOG_STATES = {"reviewed-route", "reviewed-abi", "study-observed"}
ENDIANNESS = {"little", "big"}


def load_targets(path: str | Path) -> list[dict[str, object]]:
    registry_path = Path(path)
    document = tomllib.loads(registry_path.read_text(encoding="utf-8"))
    if set(document) != {"schema_version", "target"}:
        raise ValueError("target registry must contain only schema_version and target")
    if document["schema_version"] != TARGET_SCHEMA:
        raise ValueError(f"unsupported target registry schema: {document['schema_version']}")
    rows = document["target"]
    if not isinstance(rows, list) or not rows:
        raise ValueError("target registry must contain at least one target")

    result: list[dict[str, object]] = []
    seen: set[str] = set()
    for index, raw in enumerate(rows):
        if not isinstance(raw, dict):
            raise ValueError(f"target row {index} must be a table")
        unknown = set(raw) - TARGET_FIELDS
        missing = TARGET_FIELDS - set(raw)
        if unknown or missing:
            detail = []
            if missing:
                detail.append(f"missing {sorted(missing)}")
            if unknown:
                detail.append(f"unknown {sorted(unknown)}")
            raise ValueError(f"target row {index}: {', '.join(detail)}")
        row = dict(raw)
        target_id = str(row["id"])
        if not target_id or target_id in seen:
            raise ValueError(f"duplicate or empty target id: {target_id!r}")
        seen.add(target_id)
        if row["catalog_state"] not in CATALOG_STATES:
            raise ValueError(f"invalid catalog_state for target {target_id}")
        if row["endianness"] not in ENDIANNESS:
            raise ValueError(f"invalid endianness for target {target_id}")
        if row["bits"] not in {32, 64}:
            raise ValueError(f"invalid word size for target {target_id}")
        evidence = row["evidence"]
        if not isinstance(evidence, list) or not evidence or not all(
            isinstance(value, str) and value for value in evidence
        ):
            raise ValueError(f"target {target_id} requires evidence paths")
        result.append(row)
    return result
