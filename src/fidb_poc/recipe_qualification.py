"""Repeatable, compilation-only qualification for reviewed native recipes."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

from .authority_catalog import authority_catalog
from .c_width import compile_c_width, materialize_width_configuration
from .config import Configuration, select_configuration
from .source_packs import MANAGED_SOURCE_DOWNLOADS
from .staged_backend import execute_build_stage
from .timing import utc_now

AUTHORITY_SCHEMA = "fidb-recipe-qualification/v1"
REPORT_SCHEMA = "fidb-recipe-qualification-report/v1"
_FIELDS = {
    "schema_version",
    "id",
    "state",
    "batch_id",
    "width_authority",
    "treatment_id",
    "workers",
    "build_jobs_per_cell",
    "evidence_path",
    "purpose",
    "route_ids",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_json(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _project_path(root: Path, value: object, field: str) -> Path:
    relative = Path(str(value))
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"recipe qualification {field} must stay inside the project")
    resolved = (root / relative).resolve()
    if root not in resolved.parents:
        raise ValueError(f"recipe qualification {field} must stay inside the project")
    return resolved


def load_recipe_qualification(root: Path, path: Path) -> dict[str, object]:
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if set(document) != _FIELDS:
        raise ValueError("recipe qualification has unsupported or missing fields")
    if document["schema_version"] != AUTHORITY_SCHEMA:
        raise ValueError("unsupported recipe qualification schema")
    if document["state"] != "defined-disarmed":
        raise ValueError("recipe qualification must remain defined-disarmed")
    for field in ("id", "batch_id", "width_authority", "treatment_id", "purpose"):
        if not isinstance(document[field], str) or not str(document[field]).strip():
            raise ValueError(f"recipe qualification {field} must be non-empty")
    for field in ("workers", "build_jobs_per_cell"):
        value = document[field]
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 1 <= value <= 32
        ):
            raise ValueError(f"recipe qualification {field} must be between 1 and 32")
    routes = document["route_ids"]
    if (
        not isinstance(routes, list)
        or not routes
        or any(not isinstance(item, str) or not item for item in routes)
        or len(routes) != len(set(routes))
    ):
        raise ValueError("recipe qualification route_ids must be unique tokens")
    evidence = _project_path(root, document["evidence_path"], "evidence_path")
    authority_path = path.resolve()
    if root not in authority_path.parents:
        raise ValueError("recipe qualification authority must stay inside the project")
    return {
        **document,
        "authority_path": str(authority_path.relative_to(root)),
        "authority_sha256": _sha256(authority_path),
        "evidence_resolved": evidence,
    }


def _batch(root: Path, batch_id: str) -> dict[str, object]:
    matches = [
        row for row in authority_catalog(root)["width_batches"] if row["id"] == batch_id
    ]
    if len(matches) != 1:
        raise ValueError(f"unknown reviewed width batch: {batch_id}")
    return matches[0]


def _cell_id(recipe_id: str, route_id: str, treatment_id: str) -> str:
    return f"{recipe_id}/{route_id}/{treatment_id}"


def compile_recipe_qualification(root: Path, path: Path) -> dict[str, object]:
    root = root.expanduser().resolve()
    authority = load_recipe_qualification(root, path.expanduser().resolve())
    batch = _batch(root, str(authority["batch_id"]))
    width = compile_c_width(root, str(authority["width_authority"]))
    available_routes = {
        str(row["id"]): row
        for row in width["routes"]
        if row["toolchain_state"] == "qualified"
    }
    unknown = sorted(set(authority["route_ids"]) - available_routes.keys())
    if unknown:
        raise ValueError(
            f"qualification routes are not qualified width routes: {unknown}"
        )
    if batch["readiness"]["recipe_blocked_libraries"]:
        raise ValueError("qualification batch contains unresolved recipes")
    if batch["authorities"]["width"] != f"coverage/{authority['width_authority']}.toml":
        raise ValueError("qualification width does not match its batch")

    cells = [
        {
            "id": _cell_id(
                str(library["recipe_id"]), route_id, str(authority["treatment_id"])
            ),
            "recipe_id": library["recipe_id"],
            "library_id": library["id"],
            "rank": library["rank"],
            "route_id": route_id,
            "treatment_id": authority["treatment_id"],
        }
        for library in batch["libraries"]
        for route_id in authority["route_ids"]
    ]
    evidence_path = authority.pop("evidence_resolved")
    return {
        "schema_version": AUTHORITY_SCHEMA,
        **authority,
        "evidence_path": str(evidence_path.relative_to(root)),
        "batch_digest": batch["batch_digest"],
        "width_route_profile_digest": width["route_profile_digest"],
        "summary": {
            "libraries": len(batch["libraries"]),
            "routes": len(authority["route_ids"]),
            "cells": len(cells),
            "workers": authority["workers"],
            "build_jobs_per_cell": authority["build_jobs_per_cell"],
        },
        "cells": cells,
    }


def _configuration(root: Path, cell: dict[str, object]) -> Configuration:
    configuration = materialize_width_configuration(
        root,
        str(cell["recipe_id"]),
        {"routes": [{"id": cell["route_id"]}]},
    )
    return select_configuration(
        configuration,
        route_ids=(str(cell["route_id"]),),
        treatment_ids=(str(cell["treatment_id"]),),
        profile="smoke",
    )


def _result_from_state(
    root: Path,
    cell: dict[str, object],
    group_root: Path,
    result: dict[str, object],
) -> dict[str, object]:
    state_path = Path(str(result.get("state_path", "")))
    record: dict[str, object] = {}
    if state_path.is_file():
        state = json.loads(state_path.read_text(encoding="utf-8"))
        record = dict(state.get("record", {}))
    status = str(record.get("status", "pipeline_error"))
    error = str(record.get("error") or result.get("pipeline_error") or "")
    archive_digests = [
        item for item in str(record.get("static_archive_sha256", "")).split(";") if item
    ]
    object_digests = [
        item
        for item in str(record.get("analysis_artifact_sha256", "")).split(";")
        if item
    ]
    object_digest = (
        hashlib.sha256("\n".join(object_digests).encode()).hexdigest()
        if object_digests
        else ""
    )
    row = {
        **cell,
        "status": status,
        "error": error,
        "started_at_utc": result["started_at_utc"],
        "finished_at_utc": result["finished_at_utc"],
        "wall_time_ns": result["wall_time_ns"],
        "peak_process_rss_bytes": result["peak_process_rss_bytes"],
        "peak_scratch_bytes": result["peak_scratch_bytes"],
        "compiler_sha256": record.get("compiler_sha256", ""),
        "compiler_version": record.get("compiler_version", ""),
        "archive_count": len(archive_digests),
        "archive_sha256": archive_digests,
        "object_count": int(record.get("object_count", 0) or 0),
        "object_set_sha256": object_digest,
        "artifact_validation": "passed" if status == "built" else "failed",
        "failure_evidence_path": (
            "" if status == "built" else str(group_root.relative_to(root))
        ),
    }
    if status == "built":
        shutil.rmtree(group_root)
    return row


def _run_cell(
    root: Path, plan: dict[str, object], cell: dict[str, object], verbose: bool
) -> dict[str, object]:
    safe_cell = hashlib.sha256(str(cell["id"]).encode()).hexdigest()[:20]
    group_root = root / "work/recipe-qualification" / str(plan["id"]) / safe_cell
    if group_root.exists():
        shutil.rmtree(group_root)
    (group_root / "work/downloads").mkdir(parents=True)
    try:
        configuration = _configuration(root, cell)
        result = execute_build_stage(
            configuration,
            group_root,
            verbose=verbose,
            build_jobs_per_cell=int(plan["build_jobs_per_cell"]),
            shared_downloads=root / MANAGED_SOURCE_DOWNLOADS,
        )
        return _result_from_state(root, cell, group_root, result)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        now = utc_now()
        return {
            **cell,
            "status": "qualification_error",
            "error": str(error),
            "started_at_utc": now,
            "finished_at_utc": now,
            "wall_time_ns": 0,
            "peak_process_rss_bytes": 0,
            "peak_scratch_bytes": 0,
            "compiler_sha256": "",
            "compiler_version": "",
            "archive_count": 0,
            "archive_sha256": [],
            "object_count": 0,
            "object_set_sha256": "",
            "artifact_validation": "failed",
            "failure_evidence_path": str(group_root.relative_to(root)),
        }


def _new_report(plan: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": REPORT_SCHEMA,
        "qualification_id": plan["id"],
        "authority_path": plan["authority_path"],
        "authority_sha256": plan["authority_sha256"],
        "batch_id": plan["batch_id"],
        "batch_digest": plan["batch_digest"],
        "width_route_profile_digest": plan["width_route_profile_digest"],
        "started_at_utc": utc_now(),
        "finished_at_utc": None,
        "summary": {
            "total": len(plan["cells"]),
            "built": 0,
            "failed": 0,
            "remaining": len(plan["cells"]),
        },
        "results": [],
    }


def _load_report(path: Path, plan: dict[str, object]) -> dict[str, object]:
    if not path.is_file():
        return _new_report(plan)
    report = json.loads(path.read_text(encoding="utf-8"))
    expected = {
        "schema_version": REPORT_SCHEMA,
        "qualification_id": plan["id"],
        "authority_sha256": plan["authority_sha256"],
        "batch_digest": plan["batch_digest"],
        "width_route_profile_digest": plan["width_route_profile_digest"],
    }
    if any(report.get(field) != value for field, value in expected.items()):
        raise ValueError(
            "existing qualification report does not match current authority"
        )
    return report


def _summarize(report: dict[str, object], total: int) -> None:
    results = report["results"]
    built = sum(row["status"] == "built" for row in results)
    failed = len(results) - built
    report["summary"] = {
        "total": total,
        "built": built,
        "failed": failed,
        "remaining": total - len(results),
    }
    report["finished_at_utc"] = utc_now() if len(results) == total else None


def run_recipe_qualification(
    root: Path, path: Path, *, verbose: bool = False
) -> dict[str, object]:
    plan = compile_recipe_qualification(root, path)
    evidence_path = root.resolve() / str(plan["evidence_path"])
    report = _load_report(evidence_path, plan)
    completed = {row["id"] for row in report["results"]}
    pending = [row for row in plan["cells"] if row["id"] not in completed]
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=int(plan["workers"])
    ) as executor:
        futures = {
            executor.submit(_run_cell, root.resolve(), plan, cell, verbose): cell
            for cell in pending
        }
        for future in concurrent.futures.as_completed(futures):
            row = future.result()
            report["results"].append(row)
            report["results"].sort(key=lambda item: str(item["id"]))
            _summarize(report, len(plan["cells"]))
            _atomic_json(evidence_path, report)
            print(f"{row['status']}: {row['id']}", flush=True)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fidb-poc qualify-recipes")
    parser.add_argument(
        "authority", nargs="?", default="qualification/c11-c20.toml", type=Path
    )
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--execute", action="store_true")
    parser.add_argument(
        "--cells", action="store_true", help="include every exact canary cell"
    )
    parser.add_argument("--verbose", action="store_true")
    arguments = parser.parse_args(argv)
    root = arguments.project_root.resolve()
    authority = arguments.authority
    if not authority.is_absolute():
        authority = root / authority
    try:
        document = (
            run_recipe_qualification(root, authority, verbose=arguments.verbose)
            if arguments.execute
            else compile_recipe_qualification(root, authority)
        )
        if not arguments.cells:
            document = {key: value for key, value in document.items() if key != "cells"}
        print(json.dumps(document, indent=2, sort_keys=True))
        if arguments.execute and document["summary"]["failed"]:
            return 1
        return 0
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
