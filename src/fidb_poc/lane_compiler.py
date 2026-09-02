"""Compile completed width-run signature ledgers into raw lane databases."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Iterable, Iterator

from .lane_database import build_lane_database
from .lane_registry import load_lane_registry, resolve_target_sublane
from .target_registry import load_targets
from .toolchain_packs import load_toolchain_pack_catalog

LANE_PLAN_SCHEMA = "fidb-lane-compilation-plan/v1"
MANIFEST_FIELD_LIMIT = 16 * 1024 * 1024
SIGNATURE_LEDGER_FIELDS = {
    "language",
    "full_hash",
    "specific_hash",
    "specific_hash_additional_size",
    "code_unit_size",
    "domain_path",
    "name",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _inside(path: Path, root: Path, label: str) -> Path:
    if path.is_symlink():
        raise ValueError(f"{label} cannot be a symlink: {path}")
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(f"{label} must remain inside the project root") from error
    return resolved


def _manifest_rows(path: Path) -> list[dict[str, str]]:
    previous_limit = csv.field_size_limit()
    csv.field_size_limit(max(previous_limit, MANIFEST_FIELD_LIMIT))
    try:
        with path.open(newline="", encoding="utf-8") as stream:
            return list(csv.DictReader(stream))
    finally:
        csv.field_size_limit(previous_limit)


def _target_from_manifest(
    row: dict[str, str], targets: list[dict[str, object]]
) -> dict[str, object]:
    matches = [
        target
        for target in targets
        if target["platform"] == row["target_os"]
        and target["architecture"] == row["architecture"]
        and target["binary_format"] == row["binary_format"]
    ]
    if len(matches) != 1:
        raise ValueError(
            "manifest target facts resolve to "
            f"{len(matches)} targets: {row['target_os']}/"
            f"{row['architecture']}/{row['binary_format']}"
        )
    return matches[0]


def compile_lane_plan(
    project_root: str | Path,
    run: str | Path,
    lane_id: str,
    *,
    replay: int = 1,
) -> dict[str, object]:
    """Preview raw lane ingestion without reading every signature record."""

    root = Path(project_root).expanduser().resolve()
    run_path = Path(run)
    run_root = _inside(
        run_path if run_path.is_absolute() else root / run_path, root, "run"
    )
    if not run_root.is_dir():
        raise ValueError(f"width run is not a directory: {run_root}")
    if not isinstance(replay, int) or isinstance(replay, bool) or replay < 1:
        raise ValueError("replay must be a positive integer")
    result_path = run_root / "width-run.json"
    if not result_path.is_file() or result_path.is_symlink():
        raise ValueError(f"width run result is unavailable: {result_path}")
    run_document = json.loads(result_path.read_text(encoding="utf-8"))
    if (
        not isinstance(run_document, dict)
        or run_document.get("schema_version") != "fidb-width-run/v1"
        or run_document.get("state") != "measured-complete"
    ):
        raise ValueError("lane compilation requires a measured-complete width run")
    replay_root = run_root / f"replay-{replay:02d}"
    if not replay_root.is_dir() or replay_root.is_symlink():
        raise ValueError(f"width replay is unavailable: {replay_root}")

    registry_path = root / "lanes/registry.toml"
    target_path = root / "targets/registry.toml"
    registry = load_lane_registry(registry_path, target_path)
    matching_lanes = [lane for lane in registry["lanes"] if lane["id"] == lane_id]
    if len(matching_lanes) != 1:
        raise ValueError(f"unknown or duplicate lane: {lane_id}")
    selected_lane = matching_lanes[0]
    policies = {str(row["id"]): row for row in registry["policies"]}
    targets = load_targets(target_path)
    catalog = load_toolchain_pack_catalog(root)
    routes = {str(row["id"]): row for row in catalog["routes"]}

    cells = []
    for manifest in sorted(
        replay_root.glob("group-*/artifacts/libs/fidb_manifest.csv")
    ):
        group_root = manifest.resolve().parents[2]
        for row in _manifest_rows(manifest):
            if row.get("status") != "complete":
                continue
            route = routes.get(str(row["route"]))
            if route is None:
                raise ValueError(f"manifest references unknown route: {row['route']}")
            target = _target_from_manifest(row, targets)
            if route["target_id"] != target["id"]:
                raise ValueError(
                    f"manifest target differs from route authority: {row['route']}"
                )
            lane, sublane = resolve_target_sublane(registry, str(target["id"]))
            if lane["id"] != lane_id:
                continue
            if sublane["definition_state"] != "mapped":
                raise ValueError(
                    f"selected evidence uses unresolved sublane {sublane['id']}"
                )
            if row["ghidra_language"] not in sublane["ghidra_language_ids"]:
                raise ValueError(
                    f"manifest language is not admitted by sublane {sublane['id']}"
                )
            if row["ghidra_compiler_spec"] not in sublane["compiler_spec_ids"]:
                raise ValueError(
                    f"manifest compiler spec is not admitted by sublane {sublane['id']}"
                )
            policy = policies[str(sublane["policy_id"])]
            policy_facts = (
                ("ghidra_version", "ghidra_version"),
                ("ghidra_release", "ghidra_release"),
                ("ghidra_build", "ghidra_build"),
            )
            if any(
                row[manifest_key] != policy[policy_key]
                for manifest_key, policy_key in policy_facts
            ):
                raise ValueError(
                    f"manifest Ghidra identity differs from sublane policy: {manifest}"
                )
            ledger = _inside(
                group_root / row["fid_signatures_path"], group_root, "signature ledger"
            )
            if not ledger.is_file() or ledger.is_symlink():
                raise ValueError(f"signature ledger is unavailable: {ledger}")
            cells.append(
                {
                    "build_id": (
                        f"{row['library']}@{row['version']}:"
                        f"{row['route']}:{row['treatment']}:replay-{replay:02d}"
                    ),
                    "manifest_path": str(manifest.resolve().relative_to(root)),
                    "manifest_sha256": _sha256(manifest),
                    "signature_ledger_path": str(ledger.relative_to(root)),
                    "signature_ledger_sha256": row["fid_signatures_sha256"],
                    "signature_records": int(row["fid_signature_records"]),
                    "lane_id": lane["id"],
                    "sublane_id": sublane["id"],
                    "target_id": target["id"],
                    "library": row["library"],
                    "library_version": row["version"],
                    "source_language": "c",
                    "source_url": row["source_url"],
                    "source_sha256": row["source_sha256"],
                    "route_id": row["route"],
                    "compiler_family": route["compiler_family"],
                    "compiler_version": row["compiler_version"],
                    "compiler_sha256": row["compiler_sha256"],
                    "treatment_id": row["treatment"],
                    "ghidra_language_id": row["ghidra_language"],
                    "ghidra_compiler_spec_id": row["ghidra_compiler_spec"],
                }
            )
    if not cells:
        raise ValueError(f"width replay contains no complete cells for lane {lane_id}")
    selected_sublanes = sorted({str(row["sublane_id"]) for row in cells})
    return {
        "schema_version": LANE_PLAN_SCHEMA,
        "operation": "raw-lane-compilation-preview",
        "deduplication": "not-performed",
        "lane": {
            "id": selected_lane["id"],
            "label": selected_lane["label"],
            "state": selected_lane["state"],
            "declared_sublanes": len(selected_lane["sublanes"]),
            "selected_sublane_ids": selected_sublanes,
        },
        "source": {
            "run_id": run_root.name,
            "run_path": str(run_root.relative_to(root)),
            "width_result_path": str(result_path.relative_to(root)),
            "width_result_sha256": _sha256(result_path),
            "fixed_recipe": run_document.get("fixed_recipe"),
            "replay": replay,
            "finished_at_utc": run_document.get("finished_at_utc"),
        },
        "registry": {
            "path": str(registry_path.relative_to(root)),
            "sha256": _sha256(registry_path),
        },
        "summary": {
            "cells": len(cells),
            "raw_signature_records": sum(
                int(row["signature_records"]) for row in cells
            ),
            "sublanes_with_evidence": len(selected_sublanes),
            "deduplicated_signatures": None,
            "native_projection_state": "blocked-missing-relationships",
        },
        "cells": cells,
    }


def iter_lane_occurrences(
    project_root: str | Path, plan: dict[str, object]
) -> Iterator[dict[str, object]]:
    """Yield every source ledger row unchanged as one raw lane observation."""

    if plan.get("schema_version") != LANE_PLAN_SCHEMA:
        raise ValueError("unsupported lane compilation plan")
    root = Path(project_root).expanduser().resolve()
    for cell in plan["cells"]:
        ledger = _inside(
            root / str(cell["signature_ledger_path"]), root, "signature ledger"
        )
        if _sha256(ledger) != cell["signature_ledger_sha256"]:
            raise ValueError(f"signature ledger digest differs: {ledger}")
        records = 0
        with ledger.open(encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as error:
                    raise ValueError(
                        f"invalid signature JSON at {ledger}:{line_number}"
                    ) from error
                if not isinstance(row, dict) or set(row) != SIGNATURE_LEDGER_FIELDS:
                    raise ValueError(
                        f"signature fields differ at {ledger}:{line_number}"
                    )
                records += 1
                yield {
                    "sublane_id": cell["sublane_id"],
                    "library": cell["library"],
                    "library_version": cell["library_version"],
                    "source_language": cell["source_language"],
                    "source_url": cell["source_url"],
                    "source_sha256": cell["source_sha256"],
                    "build_id": cell["build_id"],
                    "route_id": cell["route_id"],
                    "compiler_family": cell["compiler_family"],
                    "compiler_version": cell["compiler_version"],
                    "compiler_sha256": cell["compiler_sha256"],
                    "treatment_id": cell["treatment_id"],
                    "build_manifest_sha256": cell["manifest_sha256"],
                    "ghidra_language_id": row["language"],
                    "ghidra_compiler_spec_id": cell["ghidra_compiler_spec_id"],
                    "domain_path": row["domain_path"],
                    "function_name": row["name"],
                    "full_hash": row["full_hash"],
                    "specific_hash": row["specific_hash"],
                    "specific_hash_additional_size": row[
                        "specific_hash_additional_size"
                    ],
                    "code_unit_size": row["code_unit_size"],
                }
        if records != int(cell["signature_records"]):
            raise ValueError(f"signature record count differs: {ledger}")


def build_lane_from_plan(
    project_root: str | Path,
    plan: dict[str, object],
    output: str | Path,
    generation_id: str,
) -> dict[str, object]:
    """Materialize a reviewed preview as a raw immutable lane database."""

    root = Path(project_root).expanduser().resolve()
    registry_path = root / str(plan["registry"]["path"])
    if _sha256(registry_path) != plan["registry"]["sha256"]:
        raise ValueError("lane registry changed after the compilation preview")
    result_path = root / str(plan["source"]["width_result_path"])
    if _sha256(result_path) != plan["source"]["width_result_sha256"]:
        raise ValueError("width result changed after the compilation preview")
    registry = load_lane_registry(registry_path, root / "targets/registry.toml")
    return build_lane_database(
        output,
        registry=registry,
        lane_id=str(plan["lane"]["id"]),
        generation_id=generation_id,
        registry_sha256=str(plan["registry"]["sha256"]),
        source_run_id=str(plan["source"]["run_id"]),
        source_run_sha256=str(plan["source"]["width_result_sha256"]),
        occurrences=iter_lane_occurrences(root, plan),
        evidence_kind="signature-ledger-only",
        created_at=str(plan["source"]["finished_at_utc"]),
    )
