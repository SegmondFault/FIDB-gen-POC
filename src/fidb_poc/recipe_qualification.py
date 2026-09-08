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

from .c_width import compile_c_width, materialize_width_configuration
from .config import Configuration, select_configuration
from .source_packs import MANAGED_SOURCE_DOWNLOADS
from .staged_backend import execute_build_stage
from .timing import utc_now
from .width_batch import load_width_batch, project_width_batch_readiness

AUTHORITY_SCHEMA = "fidb-recipe-qualification/v1"
REPORT_SCHEMA = "fidb-recipe-qualification-report/v2"
STATUS_SCHEMA = "fidb-recipe-qualification-status/v1"
SEAL_SCHEMA = "fidb-recipe-qualification-seal/v1"
QUALIFICATION_IMPLEMENTATION_PATHS = (
    Path("worker.toml"),
    Path("src/fidb_poc/adapters.py"),
    Path("src/fidb_poc/config.py"),
    Path("src/fidb_poc/source_build.py"),
    Path("src/fidb_poc/staged_backend.py"),
)
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


def _reviewed_recipes(root: Path) -> list[dict[str, object]]:
    rows = []
    for path in sorted((root / "recipes").glob("*.toml")):
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        rows.append(
            {
                "id": f'{document["name"]}@{document["version"]}',
                "kind": "native",
                "url": document["url"],
                "sha256": document["sha256"],
                "applicability": {
                    "target_os": list(document.get("supported_target_os", [])),
                    "architectures": list(
                        document.get("supported_architectures", [])
                    ),
                    "compiler_families": list(
                        document.get("supported_compiler_families", [])
                    ),
                    "excluded_routes": list(document.get("unsupported_routes", [])),
                },
                "authority_path": str(path.relative_to(root)),
            }
        )
    return rows


def _batch(root: Path, batch_id: str) -> dict[str, object]:
    matches = []
    for path in sorted((root / "batches").glob("*.toml")):
        batch = load_width_batch(root, path)
        if batch["id"] == batch_id:
            matches.append(batch)
    if len(matches) != 1:
        raise ValueError(f"unknown reviewed width batch: {batch_id}")
    return project_width_batch_readiness(matches[0], _reviewed_recipes(root))


def _input_authorities(
    root: Path, batch: dict[str, object]
) -> tuple[list[dict[str, str]], str]:
    recipe_paths = {
        str(row["id"]): root / str(row["authority_path"])
        for row in _reviewed_recipes(root)
    }
    paths = list(QUALIFICATION_IMPLEMENTATION_PATHS)
    for library in batch["libraries"]:  # type: ignore[index]
        recipe_id = str(library["recipe_id"])
        if recipe_id not in recipe_paths:
            raise ValueError(f"qualification lacks reviewed recipe {recipe_id}")
        paths.append(recipe_paths[recipe_id].relative_to(root))
    rows = []
    for relative in sorted(set(paths), key=str):
        path = root / relative
        if not path.is_file():
            raise ValueError(f"qualification input authority is missing: {relative}")
        rows.append({"path": str(relative), "sha256": _sha256(path)})
    return rows, _canonical_digest(rows)


def _canonical_digest(value: object) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _cell_id(recipe_id: str, route_id: str, treatment_id: str) -> str:
    return f"{recipe_id}/{route_id}/{treatment_id}"


def compile_recipe_qualification(
    root: Path,
    path: Path,
    *,
    _batch_projection: dict[str, object] | None = None,
    validate_routes: bool = True,
) -> dict[str, object]:
    root = root.expanduser().resolve()
    authority = load_recipe_qualification(root, path.expanduser().resolve())
    batch = _batch_projection or _batch(root, str(authority["batch_id"]))
    if batch["id"] != authority["batch_id"]:
        raise ValueError("qualification batch projection selects a different batch")
    width = None
    if validate_routes:
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
    input_authorities, input_digest = _input_authorities(root, batch)

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
        if route_id in library.get("applicable_route_ids", authority["route_ids"])
    ]
    evidence_path = authority.pop("evidence_resolved")
    return {
        "schema_version": AUTHORITY_SCHEMA,
        **authority,
        "evidence_path": str(evidence_path.relative_to(root)),
        "batch_digest": batch["batch_digest"],
        "width_route_profile_digest": (
            width["route_profile_digest"]
            if width is not None
            else batch["authorities"]["width_route_profile_digest"]
        ),
        "input_authorities": input_authorities,
        "input_digest": input_digest,
        "summary": {
            "libraries": len(batch["libraries"]),
            "routes": len({str(row["route_id"]) for row in cells}),
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
        "input_digest": plan["input_digest"],
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


def _archive_stale_report(path: Path, plan: dict[str, object]) -> Path:
    digest = _sha256(path)
    directory = path.parent / "history" / str(plan["id"])
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"{digest}.json"
    suffix = 1
    while destination.exists():
        destination = directory / f"{digest}-{suffix}.json"
        suffix += 1
    path.replace(destination)
    return destination


def _load_report(
    path: Path,
    plan: dict[str, object],
    *,
    restart_stale: bool = False,
) -> dict[str, object]:
    if not path.is_file():
        return _new_report(plan)
    report = json.loads(path.read_text(encoding="utf-8"))
    expected = {
        "schema_version": REPORT_SCHEMA,
        "qualification_id": plan["id"],
        "authority_sha256": plan["authority_sha256"],
        "batch_digest": plan["batch_digest"],
        "width_route_profile_digest": plan["width_route_profile_digest"],
        "input_digest": plan["input_digest"],
    }
    if any(report.get(field) != value for field, value in expected.items()):
        if restart_stale:
            archived = _archive_stale_report(path, plan)
            print(f"archived stale qualification evidence: {archived}", flush=True)
            return _new_report(plan)
        raise ValueError(
            "existing qualification report does not match current authority; "
            "rerun with --restart-stale to archive it and begin a new generation"
        )
    return report


def _seal_body(plan: dict[str, object], report: dict[str, object]) -> dict[str, object]:
    latest = {str(row["id"]): row for row in report["results"]}
    results = []
    for cell in sorted(plan["cells"], key=lambda row: str(row["id"])):
        row = latest[str(cell["id"])]
        results.append(
            {
                "id": row["id"],
                "compiler_sha256": row.get("compiler_sha256", ""),
                "compiler_version": row.get("compiler_version", ""),
                "archive_count": row.get("archive_count", 0),
                "archive_sha256": row.get("archive_sha256", []),
                "object_count": row.get("object_count", 0),
                "object_set_sha256": row.get("object_set_sha256", ""),
                "artifact_validation": row.get("artifact_validation", ""),
            }
        )
    return {
        "schema_version": SEAL_SCHEMA,
        "qualification_id": plan["id"],
        "authority_sha256": plan["authority_sha256"],
        "batch_id": plan["batch_id"],
        "batch_digest": plan["batch_digest"],
        "width_route_profile_digest": plan["width_route_profile_digest"],
        "input_digest": plan["input_digest"],
        "results": results,
    }


def _summarize(
    report: dict[str, object], total: int, plan: dict[str, object] | None = None
) -> None:
    results = report["results"]
    latest = {row["id"]: row for row in results}
    built = sum(row["status"] == "built" for row in latest.values())
    failed = len(latest) - built
    report["summary"] = {
        "total": total,
        "built": built,
        "failed": failed,
        "remaining": total - len(latest),
    }
    report["finished_at_utc"] = utc_now() if built == total else None
    report.pop("seal", None)
    if built == total and plan is not None:
        body = _seal_body(plan, report)
        report["seal"] = {
            "schema_version": SEAL_SCHEMA,
            "qualified_at_utc": report["finished_at_utc"],
            "qualification_digest": _canonical_digest(body),
        }


def recipe_qualification_status(
    root: Path,
    path: Path,
    *,
    _plan: dict[str, object] | None = None,
) -> dict[str, object]:
    """Return a fail-closed, read-only qualification lifecycle projection."""

    root = root.expanduser().resolve()
    plan = _plan or compile_recipe_qualification(root, path)
    evidence_path = root / str(plan["evidence_path"])
    base = {
        "schema_version": STATUS_SCHEMA,
        "qualification_id": plan["id"],
        "batch_id": plan["batch_id"],
        "authority_path": plan["authority_path"],
        "authority_sha256": plan["authority_sha256"],
        "batch_digest": plan["batch_digest"],
        "width_route_profile_digest": plan["width_route_profile_digest"],
        "input_digest": plan["input_digest"],
        "evidence_path": plan["evidence_path"],
        "summary": {
            "total": len(plan["cells"]),
            "built": 0,
            "failed": 0,
            "remaining": len(plan["cells"]),
        },
        "satisfied": False,
        "qualification_digest": None,
        "evidence_sha256": None,
        "blockers": [],
    }
    if not evidence_path.is_file():
        return {
            **base,
            "state": "required",
            "blockers": ["qualification has not been executed"],
        }
    try:
        report = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return {
            **base,
            "state": "invalid",
            "blockers": [f"qualification evidence is unreadable: {error}"],
        }
    expected = {
        "schema_version": REPORT_SCHEMA,
        "qualification_id": plan["id"],
        "authority_sha256": plan["authority_sha256"],
        "batch_id": plan["batch_id"],
        "batch_digest": plan["batch_digest"],
        "width_route_profile_digest": plan["width_route_profile_digest"],
        "input_digest": plan["input_digest"],
    }
    drift = [field for field, value in expected.items() if report.get(field) != value]
    evidence_sha256 = _sha256(evidence_path)
    if drift:
        return {
            **base,
            "state": "stale",
            "evidence_sha256": evidence_sha256,
            "blockers": [
                "qualification evidence does not match current " + ", ".join(drift)
            ],
        }
    results = report.get("results", [])
    if not isinstance(results, list):
        return {
            **base,
            "state": "invalid",
            "evidence_sha256": evidence_sha256,
            "blockers": ["qualification results must be an array"],
        }
    latest = {str(row.get("id")): row for row in results if isinstance(row, dict)}
    expected_ids = {str(row["id"]) for row in plan["cells"]}
    built = sum(
        latest.get(cell_id, {}).get("status") == "built"
        and latest.get(cell_id, {}).get("artifact_validation") == "passed"
        for cell_id in expected_ids
    )
    attempted = sum(cell_id in latest for cell_id in expected_ids)
    failed = attempted - built
    summary = {
        "total": len(expected_ids),
        "built": built,
        "failed": failed,
        "remaining": len(expected_ids) - attempted,
    }
    if set(latest) - expected_ids:
        return {
            **base,
            "state": "invalid",
            "summary": summary,
            "evidence_sha256": evidence_sha256,
            "blockers": ["qualification evidence contains unexpected cell identities"],
        }
    seal = report.get("seal")
    expected_seal = (
        _canonical_digest(_seal_body(plan, report))
        if built == len(expected_ids)
        else None
    )
    sealed = (
        isinstance(seal, dict)
        and seal.get("schema_version") == SEAL_SCHEMA
        and seal.get("qualification_digest") == expected_seal
        and report.get("finished_at_utc") is not None
    )
    if built == len(expected_ids) and failed == 0 and sealed:
        return {
            **base,
            "state": "qualified",
            "summary": summary,
            "satisfied": True,
            "qualification_digest": expected_seal,
            "evidence_sha256": evidence_sha256,
            "blockers": [],
        }
    blockers = []
    if failed:
        blockers.append(f"{failed} qualification cells failed")
    if summary["remaining"]:
        blockers.append(f'{summary["remaining"]} qualification cells remain')
    if built == len(expected_ids) and not sealed:
        blockers.append("complete results lack a valid qualification seal")
    return {
        **base,
        "state": "failed" if failed else "incomplete",
        "summary": summary,
        "evidence_sha256": evidence_sha256,
        "blockers": blockers,
    }


def run_recipe_qualification(
    root: Path,
    path: Path,
    *,
    verbose: bool = False,
    restart_stale: bool = False,
) -> dict[str, object]:
    plan = compile_recipe_qualification(root, path)
    evidence_path = root.resolve() / str(plan["evidence_path"])
    report = _load_report(evidence_path, plan, restart_stale=restart_stale)
    completed = {row["id"] for row in report["results"] if row["status"] == "built"}
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
            _summarize(report, len(plan["cells"]), plan)
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
        "--status", action="store_true", help="show the current sealed gate state"
    )
    parser.add_argument(
        "--cells", action="store_true", help="include every exact canary cell"
    )
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--restart-stale",
        action="store_true",
        help="archive mismatched evidence before starting a new generation",
    )
    arguments = parser.parse_args(argv)
    root = arguments.project_root.resolve()
    authority = arguments.authority
    if not authority.is_absolute():
        authority = root / authority
    try:
        if arguments.execute and arguments.status:
            raise ValueError("--execute and --status are mutually exclusive")
        if arguments.restart_stale and not arguments.execute:
            raise ValueError("--restart-stale requires --execute")
        document = (
            run_recipe_qualification(
                root,
                authority,
                verbose=arguments.verbose,
                restart_stale=arguments.restart_stale,
            )
            if arguments.execute
            else (
                recipe_qualification_status(root, authority)
                if arguments.status
                else compile_recipe_qualification(root, authority)
            )
        )
        if not arguments.cells:
            document = {key: value for key, value in document.items() if key != "cells"}
        print(json.dumps(document, indent=2, sort_keys=True))
        if arguments.execute and document["summary"]["failed"]:
            return 1
        if arguments.status and not document["satisfied"]:
            return 1
        return 0
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
