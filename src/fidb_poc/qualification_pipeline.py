"""Fail-closed recipe-qualification gates for future width campaigns."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tomllib

from .recipe_qualification import (
    compile_recipe_qualification,
    load_recipe_qualification,
    recipe_qualification_status,
)
from .width_batch import load_width_batch

PIPELINE_SCHEMA = "fidb-qualification-pipeline/v1"
PIPELINE_STATUS_SCHEMA = "fidb-qualification-pipeline-status/v1"
DEFAULT_PIPELINE_PATH = Path("qualification/pipeline.toml")
_FIELDS = {
    "schema_version",
    "state",
    "qualification_directory",
    "policy",
    "legacy_exemptions",
}
_POLICY_FIELDS = {
    "require_current_seal_before_materialization",
    "embed_seal_in_generated_plans",
    "require_full_path_canary_after_materialization",
    "automatic_arming",
    "promotion_state",
}
_EXEMPTION_FIELDS = {"batch_id", "batch_digest", "reason"}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _project_path(
    root: Path, value: object, field: str, *, directory: bool = False
) -> Path:
    relative = Path(str(value))
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"qualification pipeline {field} must stay inside the project")
    resolved = (root / relative).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(
            f"qualification pipeline {field} must stay inside the project"
        ) from error
    if directory and not resolved.is_dir():
        raise ValueError(f"qualification pipeline {field} is not a directory")
    return resolved


def load_qualification_pipeline(
    root: Path, path: Path = DEFAULT_PIPELINE_PATH
) -> dict[str, object]:
    root = root.expanduser().resolve()
    resolved = path if path.is_absolute() else root / path
    resolved = resolved.resolve()
    raw = tomllib.loads(resolved.read_text(encoding="utf-8"))
    if set(raw) != _FIELDS:
        raise ValueError("qualification pipeline has unsupported or missing fields")
    if raw["schema_version"] != PIPELINE_SCHEMA:
        raise ValueError("unsupported qualification pipeline schema")
    if raw["state"] != "enforced":
        raise ValueError("qualification pipeline must remain enforced")
    directory = _project_path(
        root, raw["qualification_directory"], "qualification_directory", directory=True
    )
    policy = raw["policy"]
    if not isinstance(policy, dict) or set(policy) != _POLICY_FIELDS:
        raise ValueError("qualification pipeline policy is incomplete or unsupported")
    for field in (
        "require_current_seal_before_materialization",
        "embed_seal_in_generated_plans",
        "require_full_path_canary_after_materialization",
        "automatic_arming",
    ):
        if not isinstance(policy[field], bool):
            raise ValueError(f"qualification pipeline policy.{field} must be boolean")
    if policy["require_current_seal_before_materialization"] is not True:
        raise ValueError(
            "qualification pipeline must fail closed before materialization"
        )
    if policy["embed_seal_in_generated_plans"] is not True:
        raise ValueError(
            "qualification pipeline must embed its seal in generated plans"
        )
    if policy["automatic_arming"] is not False:
        raise ValueError("qualification pipeline cannot arm campaigns automatically")
    if policy["promotion_state"] != "queue-eligible-disarmed":
        raise ValueError("qualification pipeline promotion_state is unsupported")
    exemptions = raw["legacy_exemptions"]
    if not isinstance(exemptions, list):
        raise ValueError("qualification pipeline legacy_exemptions must be an array")
    seen = set()
    for row in exemptions:
        if not isinstance(row, dict) or set(row) != _EXEMPTION_FIELDS:
            raise ValueError("qualification pipeline legacy exemption is invalid")
        batch_id = str(row["batch_id"])
        digest = str(row["batch_digest"])
        if not batch_id or batch_id in seen:
            raise ValueError("qualification pipeline exemptions need unique batch ids")
        if len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise ValueError(
                "qualification pipeline exemption needs a SHA-256 batch digest"
            )
        if not isinstance(row["reason"], str) or not row["reason"].strip():
            raise ValueError(
                "qualification pipeline exemption reason must be non-empty"
            )
        seen.add(batch_id)
    return {
        **raw,
        "authority_path": str(resolved.relative_to(root)),
        "authority_sha256": _sha256(resolved),
        "qualification_directory": str(directory.relative_to(root)),
    }


def _authorities(root: Path, pipeline: dict[str, object]) -> dict[str, Path]:
    directory = root / str(pipeline["qualification_directory"])
    by_batch: dict[str, Path] = {}
    for path in sorted(directory.glob("*.toml")):
        if path.name == Path(str(pipeline["authority_path"])).name:
            continue
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
        if raw.get("schema_version") != "fidb-recipe-qualification/v1":
            continue
        batch_id = str(raw.get("batch_id", ""))
        if not batch_id:
            raise ValueError(f"qualification authority lacks batch_id: {path}")
        if batch_id in by_batch:
            raise ValueError(f"multiple qualification authorities select {batch_id}")
        by_batch[batch_id] = path
    return by_batch


def qualification_gate(
    root: Path,
    batch: dict[str, object],
    *,
    pipeline: dict[str, object] | None = None,
    authorities: dict[str, Path] | None = None,
    validate_routes: bool = True,
) -> dict[str, object]:
    """Project one batch's mandatory promotion gate without executing work."""

    root = root.expanduser().resolve()
    pipeline = pipeline or load_qualification_pipeline(root)
    batch_id = str(batch["id"])
    batch_digest = str(batch["batch_digest"])
    exemption = next(
        (row for row in pipeline["legacy_exemptions"] if row["batch_id"] == batch_id),
        None,
    )
    if exemption is not None:
        if exemption["batch_digest"] != batch_digest:
            return {
                "batch_id": batch_id,
                "batch_digest": batch_digest,
                "state": "legacy-exemption-stale",
                "satisfied": False,
                "promotion_state": "blocked",
                "authority_path": None,
                "qualification_digest": None,
                "evidence_path": None,
                "evidence_sha256": None,
                "summary": {"total": 0, "built": 0, "failed": 0, "remaining": 0},
                "blockers": [
                    "legacy exemption does not match the current batch digest"
                ],
            }
        return {
            "batch_id": batch_id,
            "batch_digest": batch_digest,
            "state": "historical-exempt",
            "satisfied": True,
            "promotion_state": "historical-sealed",
            "authority_path": None,
            "qualification_digest": None,
            "evidence_path": None,
            "evidence_sha256": None,
            "summary": {"total": 0, "built": 0, "failed": 0, "remaining": 0},
            "blockers": [],
            "reason": exemption["reason"],
        }
    authorities = authorities or _authorities(root, pipeline)
    path = authorities.get(batch_id)
    if path is None:
        return {
            "batch_id": batch_id,
            "batch_digest": batch_digest,
            "state": "authority-required",
            "satisfied": False,
            "promotion_state": "blocked",
            "authority_path": None,
            "qualification_digest": None,
            "evidence_path": None,
            "evidence_sha256": None,
            "summary": {"total": 0, "built": 0, "failed": 0, "remaining": 0},
            "blockers": ["future width batch has no recipe-qualification authority"],
        }
    authority: dict[str, object] | None = None
    try:
        authority = load_recipe_qualification(root, path)
        if authority["batch_id"] != batch_id:
            raise ValueError("qualification authority selects a different batch")
        plan = compile_recipe_qualification(
            root,
            path,
            _batch_projection=batch if "readiness" in batch else None,
            validate_routes=validate_routes,
        )
        status = recipe_qualification_status(root, path, _plan=plan)
    except (OSError, ValueError) as error:
        return {
            "batch_id": batch_id,
            "batch_digest": batch_digest,
            "state": "blocked",
            "satisfied": False,
            "promotion_state": "blocked",
            "authority_path": str(path.relative_to(root)),
            "qualification_digest": None,
            "evidence_path": (
                str(authority.get("evidence_path", "")) if authority else None
            ),
            "evidence_sha256": None,
            "summary": {"total": 0, "built": 0, "failed": 0, "remaining": 0},
            "blockers": [str(error)],
        }
    return {
        "batch_id": batch_id,
        "batch_digest": batch_digest,
        "state": status["state"],
        "satisfied": status["satisfied"],
        "promotion_state": (
            pipeline["policy"]["promotion_state"] if status["satisfied"] else "blocked"
        ),
        "authority_path": status["authority_path"],
        "authority_sha256": status["authority_sha256"],
        "pipeline_authority_path": pipeline["authority_path"],
        "pipeline_authority_sha256": pipeline["authority_sha256"],
        "qualification_digest": status["qualification_digest"],
        "input_digest": status["input_digest"],
        "evidence_path": status["evidence_path"],
        "evidence_sha256": status["evidence_sha256"],
        "summary": status["summary"],
        "blockers": status["blockers"],
    }


def compile_qualification_pipeline(
    root: Path,
    batches: list[dict[str, object]],
    *,
    validate_routes: bool = True,
) -> dict[str, object]:
    root = root.expanduser().resolve()
    pipeline = load_qualification_pipeline(root)
    authorities = _authorities(root, pipeline)
    gates = [
        qualification_gate(
            root,
            batch,
            pipeline=pipeline,
            authorities=authorities,
            validate_routes=validate_routes,
        )
        for batch in batches
    ]
    return {
        "schema_version": PIPELINE_STATUS_SCHEMA,
        "state": pipeline["state"],
        "authority_path": pipeline["authority_path"],
        "authority_sha256": pipeline["authority_sha256"],
        "policy": pipeline["policy"],
        "summary": {
            "batches": len(gates),
            "satisfied": sum(bool(row["satisfied"]) for row in gates),
            "blocked": sum(not bool(row["satisfied"]) for row in gates),
            "qualified": sum(row["state"] == "qualified" for row in gates),
            "historical_exempt": sum(
                row["state"] == "historical-exempt" for row in gates
            ),
        },
        "gates": gates,
    }


def require_qualification_gates(
    root: Path,
    batches: list[dict[str, object]],
    *,
    validate_routes: bool = True,
) -> list[dict[str, object]]:
    status = compile_qualification_pipeline(
        root, batches, validate_routes=validate_routes
    )
    blocked = [row for row in status["gates"] if not row["satisfied"]]
    if blocked:
        detail = "; ".join(
            f'{row["batch_id"]}={row["state"]} ({"; ".join(row["blockers"])})'
            for row in blocked
        )
        raise ValueError(f"campaign materialization blocked by qualification: {detail}")
    return [row for row in status["gates"] if row["state"] != "historical-exempt"]


def validate_embedded_gates(
    root: Path,
    batches: list[dict[str, object]],
    embedded: tuple[dict[str, object], ...],
) -> None:
    current = require_qualification_gates(root, batches, validate_routes=False)
    current_by_id = {str(row["batch_id"]): row for row in current}
    embedded_by_id = {str(row["batch_id"]): row for row in embedded}
    if len(embedded_by_id) != len(embedded):
        raise ValueError("plan qualification gates contain duplicate batch ids")
    if set(embedded_by_id) != set(current_by_id):
        raise ValueError(
            "plan qualification gates do not cover its future width batches"
        )
    fields = {
        "batch_id",
        "batch_digest",
        "authority_path",
        "authority_sha256",
        "pipeline_authority_path",
        "pipeline_authority_sha256",
        "input_digest",
        "qualification_digest",
        "evidence_path",
        "evidence_sha256",
    }
    for batch_id, gate in current_by_id.items():
        if any(
            embedded_by_id[batch_id].get(field) != gate.get(field) for field in fields
        ):
            raise ValueError(f"plan qualification gate is stale for {batch_id}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fidb-poc qualification")
    parser.add_argument("command", choices=("status",))
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    arguments = parser.parse_args(argv)
    try:
        root = arguments.project_root.resolve()
        batches = [
            load_width_batch(root, path)
            for path in sorted((root / "batches").glob("*.toml"))
        ]
        document = compile_qualification_pipeline(root, batches)
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0 if document["summary"]["blocked"] == 0 else 1
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
