"""Resolve immutable FID reference populations from sealed evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Mapping, Sequence

from .linked_reference_retrofit import (
    GENERATION_SEAL_SCHEMA,
    TASK_SEAL_SCHEMA,
)


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _json_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _inside(root: Path, value: str | Path, label: str) -> Path:
    path = (root / value).resolve()
    if path != root and root not in path.parents:
        raise ValueError(f"{label} escapes the project root")
    return path


def resolve_linked_generation(
    project_root: str | Path,
    generation_seal: str | Path,
    *,
    source_run_id: str,
    expected_identities: Sequence[tuple[str, str, str]],
) -> dict[str, object]:
    """Verify a generation seal and return its exact FIDB candidate sources."""

    root = Path(project_root).expanduser().resolve()
    seal_path = _inside(root, generation_seal, "linked generation seal")
    try:
        generation = json.loads(seal_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("linked generation seal is unavailable or unreadable") from error
    if not (
        generation.get("schema_version") == GENERATION_SEAL_SCHEMA
        and generation.get("state") == "sealed"
        and generation.get("source_run_id") == source_run_id
        and generation.get("reference_form") == "linked-shared-image"
        and isinstance(generation.get("task_seals"), list)
    ):
        raise ValueError("linked generation seal has an incompatible identity")
    generation_identity = {
        "authority_sha256": generation.get("authority_sha256"),
        "plan_sha256": generation.get("plan_sha256"),
        "code_revisions": generation.get("code_revisions"),
        "task_seals": generation.get("task_seals"),
    }
    if generation.get("generation_sha256") != _json_digest(generation_identity):
        raise ValueError("linked generation identity digest does not reconcile")

    expected = {tuple(map(str, row)) for row in expected_identities}
    if len(expected) != len(expected_identities):
        raise ValueError("expected reference identities contain duplicates")
    entries = []
    observed: set[tuple[str, str, str]] = set()
    task_keys = set()
    for receipt in generation["task_seals"]:
        if not isinstance(receipt, dict) or set(receipt) != {
            "task_key",
            "code_revision",
            "path",
            "sha256",
        }:
            raise ValueError("linked generation task receipt is malformed")
        task_path = _inside(root, str(receipt["path"]), "linked task seal")
        if not task_path.is_file() or _sha256(task_path) != receipt["sha256"]:
            raise ValueError(f"linked task seal digest mismatch: {task_path}")
        task = json.loads(task_path.read_text(encoding="utf-8"))
        task_key = str(receipt["task_key"])
        identity = (
            str(task.get("owner")),
            str(task.get("route_id")),
            str(task.get("treatment_id")),
        )
        if not (
            task.get("schema_version") == TASK_SEAL_SCHEMA
            and task.get("state") == "complete"
            and task.get("source_run_id") == source_run_id
            and task.get("reference_form") == "linked-shared-image"
            and task.get("task_key") == task_key
            and task.get("code_revision") == receipt["code_revision"]
            and task_key == f'{task.get("position")}:{task.get("owner")}'
            and identity in expected
            and task_key not in task_keys
            and identity not in observed
        ):
            raise ValueError(f"linked task identity is invalid: {task_key}")
        outputs = [
            row
            for row in task.get("outputs", [])
            if isinstance(row, dict) and row.get("kind") == "fidb"
        ]
        if len(outputs) != 1:
            raise ValueError(f"linked task has no unique FIDB output: {task_key}")
        output = outputs[0]
        fidb = _inside(root, str(output.get("path")), "linked FIDB")
        if (
            not fidb.is_file()
            or fidb.stat().st_size != output.get("bytes")
            or _sha256(fidb) != output.get("sha256")
        ):
            raise ValueError(f"linked FIDB digest mismatch: {task_key}")
        entries.append(
            {
                "owner": identity[0],
                "route_id": identity[1],
                "treatment_id": identity[2],
                "fidb_path": str(fidb),
                "fidb_sha256": str(output["sha256"]),
                "reference_form": "linked-shared-image",
                "task_key": task_key,
                "task_seal_path": str(task_path.relative_to(root)),
                "task_seal_sha256": str(receipt["sha256"]),
            }
        )
        observed.add(identity)
        task_keys.add(task_key)
    if observed != expected:
        missing = sorted(expected - observed)[:20]
        extra = sorted(observed - expected)[:20]
        raise ValueError(
            f"linked generation coverage differs: missing={missing}, extra={extra}"
        )
    entries.sort(
        key=lambda row: (
            str(row["route_id"]),
            str(row["treatment_id"]),
            str(row["owner"]),
        )
    )
    entries_identity = [
        (
            str(row["owner"]),
            str(row["route_id"]),
            str(row["treatment_id"]),
            str(row["fidb_sha256"]),
            str(row["task_seal_sha256"]),
        )
        for row in entries
    ]
    return {
        "id": str(generation["id"]),
        "reference_form": "linked-shared-image",
        "source_run_id": source_run_id,
        "generation_seal_path": str(seal_path.relative_to(root)),
        "generation_seal_sha256": _sha256(seal_path),
        "generation_sha256": str(generation["generation_sha256"]),
        "task_count": len(entries),
        "entries_sha256": _json_digest(entries_identity),
        "entries": entries,
    }
