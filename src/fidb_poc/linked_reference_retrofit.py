"""Build a sealed executable-shaped reference generation from retained C10 archives.

The archive-only C10 reference corpus is immutable control evidence.  This module
links each already-built library independently, never executes the resulting
image, and builds a second FIDB whose provenance is explicitly
``linked-shared-image``.  Tasks are digest-idempotent and independently sealed so
an interrupted run resumes without rebuilding completed work.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import tomllib
from typing import Iterable, Mapping, Sequence

from .machine_validation import LINK_HARNESS_POLICY

AUTHORITY_SCHEMA = "fidb-linked-reference-retrofit/v1"
PLAN_SCHEMA = "fidb-linked-reference-plan/v1"
TASK_SEAL_SCHEMA = "fidb-linked-reference-task-seal/v1"
GENERATION_SEAL_SCHEMA = "fidb-linked-reference-generation-seal/v1"
DEFAULT_AUTHORITY = Path("validation/linked-reference-retrofit.toml")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def _atomic_json(path: Path, document: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        prefix=f".{path.name}-", suffix=".tmp", dir=path.parent
    )
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _code_revision(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    revision = result.stdout.strip()
    return revision if result.returncode == 0 and len(revision) == 40 else "unavailable"


def load_authority(
    project_root: str | Path, authority: str | Path = DEFAULT_AUTHORITY
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    path = _inside(root, authority, "linked-reference authority")
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    expected = {
        "schema_version",
        "id",
        "state",
        "source_run_id",
        "runtime",
        "output_root",
        "source_archive_recovery",
        "reference",
        "execution",
        "canary",
        "retention",
        "safety",
    }
    if set(document) != expected or document.get("schema_version") != AUTHORITY_SCHEMA:
        raise ValueError("linked-reference authority has unsupported fields or schema")
    if document["state"] != "experimental-enabled":
        raise ValueError("linked-reference authority is not enabled")
    recovery = document["source_archive_recovery"]
    if set(recovery) != {
        "allow_digest_refresh_owners",
        "require_path_prefix",
        "reason",
    }:
        raise ValueError("linked-reference source recovery policy is invalid")
    allowed = recovery["allow_digest_refresh_owners"]
    if allowed != ["openssl@3.5.8"] or not str(recovery["reason"]).strip():
        raise ValueError("linked-reference source recovery exception is unsupported")
    recovery_root = _inside(
        root, str(recovery["require_path_prefix"]), "source recovery prefix"
    )
    if recovery_root.name != "preparation":
        raise ValueError("linked-reference source recovery prefix is too broad")
    if document["reference"] != {
        "form": "linked-shared-image",
        "link_harness": LINK_HARNESS_POLICY,
        "variant_suffix": "linked-reference-v1",
        "retain_fidb": True,
        "retain_fidbf": True,
        "retain_signature_ledger": True,
    }:
        raise ValueError("linked-reference construction policy is unsupported")
    execution = document["execution"]
    if set(execution) != {
        "workers",
        "jvm_initial_heap_mib",
        "jvm_max_heap_mib",
        "jvm_active_processors",
        "identical_failure_limit",
    }:
        raise ValueError("linked-reference execution policy has unsupported fields")
    for name in execution:
        if type(execution[name]) is not int or int(execution[name]) < 1:
            raise ValueError(f"linked-reference execution.{name} must be positive")
    if int(execution["workers"]) > 16:
        raise ValueError("linked-reference worker count exceeds the reviewed bound")
    canary = document["canary"]
    if set(canary) != {"tasks"} or not isinstance(canary["tasks"], list):
        raise ValueError("linked-reference canary policy is invalid")
    for value in canary["tasks"]:
        _parse_task_key(str(value))
    if document["retention"] != {
        "remove_success_work": True,
        "retain_failed_work": True,
    }:
        raise ValueError("linked-reference retention policy is unsupported")
    safety = document["safety"]
    expected_safety = {
        "execute_target_binaries": False,
        "compile_source": False,
        "invoke_linker": True,
        "mutate_archive_baseline": False,
        "mutate_production_queue": False,
        "require_production_queue_drained": True,
        "minimum_free_disk_gib": safety.get("minimum_free_disk_gib"),
        "minimum_available_memory_gib": safety.get("minimum_available_memory_gib"),
    }
    if safety != expected_safety:
        raise ValueError("linked-reference authority violates its safety contract")
    for name in ("minimum_free_disk_gib", "minimum_available_memory_gib"):
        if type(safety[name]) is not int or int(safety[name]) < 1:
            raise ValueError(f"linked-reference safety.{name} must be positive")
    for field in ("runtime", "output_root"):
        _inside(root, str(document[field]), field)
    return {
        **document,
        "authority_path": str(path.relative_to(root)),
        "authority_sha256": _sha256(path),
    }


def _parse_task_key(value: str) -> tuple[int, str]:
    position, separator, owner = value.partition(":")
    if not separator or not position.isdigit() or int(position) < 1 or not owner:
        raise ValueError(f"invalid linked-reference task key: {value}")
    return int(position), owner


def _slug(value: str) -> str:
    result = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")
    if not result:
        raise ValueError("linked-reference path identity is empty")
    return result


def _available_memory_bytes() -> int:
    fields = {}
    for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        name, value = line.split(":", 1)
        fields[name] = int(value.strip().split()[0]) * 1024
    return fields.get("MemAvailable", 0)


def _production_active(root: Path, runtime: Mapping[str, object]) -> int:
    ledger = _inside(root, str(runtime["ledger"]), "coordinator ledger")
    connection = sqlite3.connect(f"file:{ledger}?mode=ro", uri=True)
    try:
        row = connection.execute(
            "SELECT COUNT(*) FROM jobs "
            "WHERE active=1 AND state IN ('leased','running')"
        ).fetchone()
        return int(row[0])
    finally:
        connection.close()


def _task_root(
    root: Path, authority: Mapping[str, object], task: Mapping[str, object]
) -> Path:
    return _inside(
        root,
        Path(str(authority["output_root"]))
        / str(authority["id"])
        / "tasks"
        / f"{int(task['position']):03d}-{_slug(str(task['route_id']))}-{_slug(str(task['treatment_id']))}"
        / _slug(str(task["owner"])),
        "linked-reference task output",
    )


def _valid_task_seal(
    root: Path,
    authority: Mapping[str, object],
    task: Mapping[str, object],
) -> dict[str, object] | None:
    path = _task_root(root, authority, task) / "seal.json"
    try:
        seal = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not (
        seal.get("schema_version") == TASK_SEAL_SCHEMA
        and seal.get("state") == "complete"
        and seal.get("task_key") == task["task_key"]
        and seal.get("input_sha256") == task["input_sha256"]
        and seal.get("authority_sha256") == authority["authority_sha256"]
    ):
        return None
    outputs = seal.get("outputs")
    if not isinstance(outputs, list) or not outputs:
        return None
    for output in outputs:
        try:
            candidate = _inside(root, str(output["path"]), "linked-reference output")
        except (KeyError, TypeError, ValueError):
            return None
        if (
            not candidate.is_file()
            or candidate.stat().st_size != output.get("bytes")
            or _sha256(candidate) != output.get("sha256")
        ):
            return None
    return seal


def compile_plan(
    project_root: str | Path,
    authority_path: str | Path = DEFAULT_AUTHORITY,
    *,
    verify_archives: bool = False,
) -> dict[str, object]:
    from .machine_validation_runner import load_runtime, resolve_hash_analysis_evidence

    root = Path(project_root).expanduser().resolve()
    authority = load_authority(root, authority_path)
    runtime = load_runtime(root, str(authority["runtime"]))
    evidence = resolve_hash_analysis_evidence(root, str(authority["runtime"]))
    run_root = _inside(
        root,
        Path(str(runtime["output_root"])) / str(authority["source_run_id"]),
        "linked-reference source run",
    )
    routes = {route.id: route for route in evidence["configuration"].routes}
    revision = _code_revision(root)
    tasks = []
    seen: set[tuple[int, str]] = set()
    for position in range(1, len(evidence["manifest"]["work_unit"]) + 1):
        matches = list((run_root / "units").glob(f"{position:03d}-*/result.json"))
        if len(matches) != 1:
            raise ValueError(
                f"source validation unit {position} is missing or ambiguous"
            )
        result_path = matches[0]
        result = json.loads(result_path.read_text(encoding="utf-8"))
        if result.get("state") != "complete":
            raise ValueError(f"source validation unit {position} is not complete")
        route_id = str(result["route_id"])
        treatment_id = str(result["treatment_id"])
        route = routes.get(route_id)
        if route is None:
            raise ValueError(f"source validation route is unavailable: {route_id}")
        owners_in_unit = set()
        for fold in ("A", "B"):
            truth_path = result_path.parent / f"fold-{fold}" / "truth-map.json"
            truth = json.loads(truth_path.read_text(encoding="utf-8"))
            if (
                truth.get("schema_version") != "fidb-machine-validation-truth-map/v1"
                or truth.get("route_id") != route_id
                or truth.get("treatment_id") != treatment_id
                or truth.get("fold") != fold
            ):
                raise ValueError(f"source truth map is invalid for {position}:{fold}")
            for item in truth.get("archives", []):
                owner = str(item["owner"])
                identity = (position, owner)
                if identity in seen:
                    raise ValueError(
                        f"source owner is duplicated in unit {position}: {owner}"
                    )
                seen.add(identity)
                owners_in_unit.add(owner)
                paths = [
                    _inside(root, value, "source archive") for value in item["paths"]
                ]
                digests = [str(value) for value in item["sha256"]]
                if len(paths) != len(digests) or not paths:
                    raise ValueError(
                        f"source archive evidence is invalid for {position}:{owner}"
                    )
                archives = []
                for path, digest in zip(paths, digests, strict=True):
                    if not path.is_file():
                        raise ValueError(f"source archive is absent: {path}")
                    actual_digest = _sha256(path)
                    digest_state = "recorded"
                    if actual_digest != digest:
                        recovery = authority["source_archive_recovery"]
                        recovery_root = _inside(
                            root,
                            str(recovery["require_path_prefix"]),
                            "source recovery prefix",
                        )
                        if (
                            owner not in recovery["allow_digest_refresh_owners"]
                            or recovery_root not in path.parents
                        ):
                            raise ValueError(f"source archive digest mismatch: {path}")
                        digest_state = "recovered-current-bytes"
                    archives.append(
                        {
                            "path": str(path.relative_to(root)),
                            "sha256": actual_digest,
                            "source_recorded_sha256": digest,
                            "source_digest_state": digest_state,
                            "bytes": path.stat().st_size,
                        }
                    )
                task_key = f"{position}:{owner}"
                identity_document = {
                    "authority_sha256": authority["authority_sha256"],
                    "runtime_sha256": runtime["authority_sha256"],
                    "source_run_id": authority["source_run_id"],
                    "source_result_sha256": _sha256(result_path),
                    "source_truth_sha256": _sha256(truth_path),
                    "task_key": task_key,
                    "position": position,
                    "route_id": route_id,
                    "treatment_id": treatment_id,
                    "owner": owner,
                    "fold": fold,
                    "binary_format": route.binary_format,
                    "ghidra_language_id": route.ghidra_language,
                    "ghidra_compiler_spec_id": route.ghidra_compiler_spec,
                    "compiler_command": list(route.compiler),
                    "link_harness": LINK_HARNESS_POLICY,
                    "reference_form": authority["reference"]["form"],
                    "archives": archives,
                }
                tasks.append(
                    {
                        **identity_document,
                        # A task seal records the implementation that produced it,
                        # but a compatible bug-fix commit must not invalidate sound
                        # completed evidence when this resumable stage continues.
                        "code_revision": revision,
                        "input_sha256": _json_digest(identity_document),
                        "weight_bytes": sum(int(row["bytes"]) for row in archives),
                    }
                )
        if owners_in_unit != set(evidence["cohort"]):
            raise ValueError(f"source validation unit {position} does not cover C10")
    tasks.sort(key=lambda row: (int(row["position"]), str(row["owner"])))
    plan_identity = {
        "authority_sha256": authority["authority_sha256"],
        "runtime_sha256": runtime["authority_sha256"],
        "source_run_id": authority["source_run_id"],
        "task_inputs": [row["input_sha256"] for row in tasks],
    }
    completed = sum(
        _valid_task_seal(root, authority, task) is not None for task in tasks
    )
    return {
        "schema_version": PLAN_SCHEMA,
        "id": authority["id"],
        "state": "complete" if completed == len(tasks) else "ready",
        "authority_path": authority["authority_path"],
        "authority_sha256": authority["authority_sha256"],
        "runtime_path": authority["runtime"],
        "runtime_sha256": runtime["authority_sha256"],
        "source_run_id": authority["source_run_id"],
        "code_revision": revision,
        "plan_sha256": _json_digest(plan_identity),
        "task_count": len(tasks),
        "complete_tasks": completed,
        "pending_tasks": len(tasks) - completed,
        "archive_bytes": sum(int(row["weight_bytes"]) for row in tasks),
        "source_digest_refreshes": sum(
            1
            for task in tasks
            for archive in task["archives"]
            if archive["source_digest_state"] == "recovered-current-bytes"
        ),
        "tasks": tasks,
        "_authority": authority,
        "_runtime": runtime,
        "_evidence": evidence,
    }


def preflight(
    project_root: str | Path, authority: str | Path = DEFAULT_AUTHORITY
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    plan = compile_plan(root, authority, verify_archives=True)
    runtime = plan["_runtime"]
    policy = plan["_authority"]["safety"]
    memory = _available_memory_bytes()
    disk = shutil.disk_usage(root).free
    blockers = []
    if _production_active(root, runtime):
        blockers.append("production queue has active jobs")
    if memory < int(policy["minimum_available_memory_gib"]) * 1024**3:
        blockers.append("available memory is below the reviewed floor")
    if disk < int(policy["minimum_free_disk_gib"]) * 1024**3:
        blockers.append("free disk is below the reviewed floor")
    headless = Path(str(runtime["ghidra_headless"]))
    if not headless.is_file() or not os.access(headless, os.X_OK):
        blockers.append("reviewed Ghidra launcher is unavailable")
    tracked = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=root,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if tracked.returncode or tracked.stdout.strip():
        blockers.append("tracked worktree changes must be committed before execution")
    return {
        "schema_version": "fidb-linked-reference-preflight/v1",
        "state": "ready" if not blockers else "blocked",
        "authority_path": plan["authority_path"],
        "authority_sha256": plan["authority_sha256"],
        "plan_sha256": plan["plan_sha256"],
        "code_revision": plan["code_revision"],
        "task_count": plan["task_count"],
        "complete_tasks": plan["complete_tasks"],
        "pending_tasks": plan["pending_tasks"],
        "source_digest_refreshes": plan["source_digest_refreshes"],
        "available_memory_bytes": memory,
        "free_disk_bytes": disk,
        "blockers": blockers,
    }


def _archive_failure(
    root: Path, task_root: Path, document: Mapping[str, object]
) -> None:
    attempts = task_root / "failures"
    attempts.mkdir(parents=True, exist_ok=True)
    ordinal = 1
    while (attempts / f"failure-{ordinal:03d}.json").exists():
        ordinal += 1
    _atomic_json(attempts / f"failure-{ordinal:03d}.json", document)


def _failure_fingerprint(error: Exception) -> str:
    message = f"{type(error).__name__}: {error}"
    message = re.sub(r"/[^\s:]+", "<path>", message)
    message = re.sub(r"\b[0-9a-f]{16,}\b", "<hex>", message, flags=re.IGNORECASE)
    message = re.sub(r"\b\d+\b", "<n>", message)
    return hashlib.sha256(message.encode("utf-8")).hexdigest()


def _next_attempt(task_root: Path) -> Path:
    attempts = task_root / "attempts"
    attempts.mkdir(parents=True, exist_ok=True)
    ordinal = 1
    while (attempts / f"attempt-{ordinal:03d}").exists():
        ordinal += 1
    path = attempts / f"attempt-{ordinal:03d}"
    path.mkdir()
    return path


def _run_task(
    root: Path,
    authority: Mapping[str, object],
    evidence: Mapping[str, object],
    task: Mapping[str, object],
) -> dict[str, object]:
    from . import ghidra_fid
    from .machine_validation_runner import _link_composite, _strip_tool

    reusable = _valid_task_seal(root, authority, task)
    if reusable is not None:
        return reusable
    routes = {route.id: route for route in evidence["configuration"].routes}
    route = routes[str(task["route_id"])]
    task_root = _task_root(root, authority, task)
    task_root.mkdir(parents=True, exist_ok=True)
    attempt = _next_attempt(task_root)
    work = attempt / "work"
    artifacts = attempt / "artifacts"
    work.mkdir()
    artifacts.mkdir()
    started = time.monotonic_ns()
    started_at = _now()
    archives = []
    for item in task["archives"]:
        path = _inside(root, str(item["path"]), "linked-reference archive")
        if not path.is_file() or _sha256(path) != item["sha256"]:
            raise ValueError(f"linked-reference archive digest mismatch: {path}")
        archives.append(path)
    suffix = ".dll" if route.binary_format == "PE/COFF" else ".elf"
    truth_binary = work / f"truth{suffix}"
    query_binary = work / f"query{suffix}"
    link_map = work / "link.map"
    _link_composite(
        route,
        archives,
        truth_binary,
        link_map,
        harness_mode=LINK_HARNESS_POLICY,
    )
    strip = subprocess.run(
        [
            str(_strip_tool(route)),
            "--strip-debug",
            str(truth_binary),
            "-o",
            str(query_binary),
        ],
        text=True,
        capture_output=True,
        timeout=300,
        check=False,
    )
    (artifacts / "strip.log").write_text(strip.stdout + strip.stderr, encoding="utf-8")
    if (
        strip.returncode
        or not query_binary.is_file()
        or not query_binary.stat().st_size
    ):
        raise RuntimeError(f"linked-reference strip failed: {strip.stderr[-2000:]}")
    owner = str(task["owner"])
    library, separator, version = owner.rpartition("@")
    if not separator or not library or not version:
        raise ValueError(f"linked-reference owner is invalid: {owner}")
    stem = _slug(owner)
    fidb = artifacts / f"{stem}.fidb"
    result = ghidra_fid.build_library_fidb(
        objects=[query_binary],
        project_dir=work / "project",
        project_name="linked_reference",
        output=fidb,
        library=library,
        version=version,
        variant=(
            f"{task['route_id']}-{task['treatment_id']}-"
            f"{authority['reference']['variant_suffix']}"
        ),
        language=route.ghidra_language,
        compiler_spec=route.ghidra_compiler_spec,
    )
    signatures = artifacts / f"{stem}.fid-signatures.jsonl"
    signature_counts = ghidra_fid.export_fid_signatures(
        fidb, signatures, route.ghidra_language
    )
    fidbf = artifacts / f"{stem}.fidbf"
    ghidra_fid.export_raw_fidbf(fidb, fidbf)
    for evidence_name in ("link.log", "link-audit.json", "link.map"):
        source = work / evidence_name
        if source.is_file():
            shutil.copy2(source, artifacts / evidence_name)
    outputs = []
    for kind, path in (
        ("fidb", fidb),
        ("fidbf", fidbf),
        ("signature-ledger", signatures),
        ("link-audit", artifacts / "link-audit.json"),
        ("link-map", artifacts / "link.map"),
        ("link-log", artifacts / "link.log"),
        ("strip-log", artifacts / "strip.log"),
    ):
        if path.is_file():
            outputs.append(
                {
                    "kind": kind,
                    "path": str(path.relative_to(root)),
                    "sha256": _sha256(path),
                    "bytes": path.stat().st_size,
                }
            )
    seal = {
        "schema_version": TASK_SEAL_SCHEMA,
        "state": "complete",
        "task_key": task["task_key"],
        "input_sha256": task["input_sha256"],
        "authority_path": authority["authority_path"],
        "authority_sha256": authority["authority_sha256"],
        "source_run_id": authority["source_run_id"],
        "code_revision": task["code_revision"],
        "reference_form": authority["reference"]["form"],
        "position": task["position"],
        "route_id": task["route_id"],
        "treatment_id": task["treatment_id"],
        "owner": owner,
        "fold": task["fold"],
        "archives": task["archives"],
        "query_image": {
            "sha256": _sha256(query_binary),
            "bytes": query_binary.stat().st_size,
        },
        "fid_population": {key: int(value) for key, value in result.items()},
        "signature_counts": {
            key: int(value) for key, value in signature_counts.items()
        },
        "outputs": outputs,
        "started_at": started_at,
        "finished_at": _now(),
        "wall_time_ns": time.monotonic_ns() - started,
    }
    _atomic_json(attempt / "seal.json", seal)
    _atomic_json(task_root / "seal.json", seal)
    if authority["retention"]["remove_success_work"]:
        shutil.rmtree(work)
    return seal


def _balanced_chunks(
    tasks: Sequence[Mapping[str, object]], workers: int
) -> tuple[list[list[str]], list[int]]:
    if not tasks:
        return [], []
    count = min(workers, len(tasks))
    chunks: list[list[str]] = [[] for _ in range(count)]
    loads = [0 for _ in range(count)]
    for task in sorted(
        tasks, key=lambda row: (-int(row["weight_bytes"]), str(row["task_key"]))
    ):
        worker = min(range(count), key=lambda index: (loads[index], index))
        chunks[worker].append(str(task["task_key"]))
        loads[worker] += int(task["weight_bytes"])
    return chunks, loads


def worker(
    project_root: str | Path,
    task_keys: Iterable[str],
    authority_path: str | Path = DEFAULT_AUTHORITY,
) -> int:
    from . import ghidra_fid
    from .machine_validation_runner import resolve_hash_analysis_evidence
    from .pipeline import find_ghidra, ghidra_environment

    root = Path(project_root).expanduser().resolve()
    plan = compile_plan(root, authority_path)
    authority = plan["_authority"]
    evidence = resolve_hash_analysis_evidence(root, str(authority["runtime"]))
    by_key = {str(task["task_key"]): task for task in plan["tasks"]}
    selected = []
    for key in task_keys:
        task = by_key.get(str(key))
        if task is None:
            raise ValueError(f"linked-reference worker task is unknown: {key}")
        selected.append(task)
    execution = authority["execution"]
    os.environ["_JAVA_OPTIONS"] = (
        f'-Xms{execution["jvm_initial_heap_mib"]}m '
        f'-Xmx{execution["jvm_max_heap_mib"]}m '
        f'-XX:ActiveProcessorCount={execution["jvm_active_processors"]}'
    )
    runtime = plan["_runtime"]
    os.environ["GHIDRA_HEADLESS"] = str(runtime["ghidra_headless"])
    worker_root = _inside(
        root,
        Path(str(authority["output_root"]))
        / str(authority["id"])
        / "workers"
        / str(os.getpid()),
        "linked-reference worker root",
    )
    worker_root.mkdir(parents=True, exist_ok=True)
    _headless, ghidra_home = find_ghidra()
    ghidra_fid.ensure_started(
        ghidra_home, ghidra_environment(worker_root / "ghidra-user")
    )
    fingerprints: Counter[str] = Counter()
    completed = failed = 0
    for task in selected:
        try:
            _run_task(root, authority, evidence, task)
            completed += 1
        except Exception as error:
            failed += 1
            fingerprint = _failure_fingerprint(error)
            fingerprints[fingerprint] += 1
            task_root = _task_root(root, authority, task)
            failure = {
                "schema_version": "fidb-linked-reference-task-failure/v1",
                "task_key": task["task_key"],
                "input_sha256": task["input_sha256"],
                "error": f"{type(error).__name__}: {error}",
                "failure_fingerprint": fingerprint,
                "failed_at": _now(),
            }
            _archive_failure(root, task_root, failure)
            if fingerprints[fingerprint] >= int(execution["identical_failure_limit"]):
                _atomic_json(
                    worker_root / "circuit-breaker.json",
                    {
                        "schema_version": "fidb-linked-reference-circuit-breaker/v1",
                        "state": "open",
                        "failure_fingerprint": fingerprint,
                        "failures": fingerprints[fingerprint],
                        "last_task": task["task_key"],
                        "opened_at": _now(),
                    },
                )
                break
        _atomic_json(
            worker_root / "status.json",
            {
                "schema_version": "fidb-linked-reference-worker-status/v1",
                "pid": os.getpid(),
                "state": "running",
                "completed": completed,
                "failed": failed,
                "remaining": len(selected) - completed - failed,
                "updated_at": _now(),
            },
        )
    _atomic_json(
        worker_root / "status.json",
        {
            "schema_version": "fidb-linked-reference-worker-status/v1",
            "pid": os.getpid(),
            "state": "complete" if failed == 0 else "failed-or-partial",
            "completed": completed,
            "failed": failed,
            "remaining": len(selected) - completed - failed,
            "updated_at": _now(),
        },
    )
    return 0 if failed == 0 else 1


def _status_from_plan(
    root: Path, plan: Mapping[str, object], mode: str | None = None
) -> dict[str, object]:
    authority = plan["_authority"]
    completed = []
    failed = 0
    retained_bytes = 0
    wall_time_ns = 0
    for task in plan["tasks"]:
        seal = _valid_task_seal(root, authority, task)
        if seal is not None:
            completed.append(seal)
            retained_bytes += sum(int(row["bytes"]) for row in seal["outputs"])
            wall_time_ns += int(seal["wall_time_ns"])
        failed += len(list(_task_root(root, authority, task).glob("failures/*.json")))
    expected = (
        len(authority["canary"]["tasks"])
        if mode == "canary"
        else int(plan["task_count"])
    )
    complete_keys = {str(row["task_key"]) for row in completed}
    target_keys = (
        set(map(str, authority["canary"]["tasks"]))
        if mode == "canary"
        else {str(row["task_key"]) for row in plan["tasks"]}
    )
    complete_target = len(complete_keys & target_keys)
    return {
        "schema_version": "fidb-linked-reference-status/v1",
        "id": authority["id"],
        "state": "complete" if complete_target == expected else "partial",
        "mode": mode,
        "authority_path": authority["authority_path"],
        "authority_sha256": authority["authority_sha256"],
        "plan_sha256": plan["plan_sha256"],
        "code_revision": plan["code_revision"],
        "source_run_id": authority["source_run_id"],
        "expected_tasks": expected,
        "complete_tasks": complete_target,
        "pending_tasks": expected - complete_target,
        "failure_records": failed,
        "retained_bytes": retained_bytes,
        "aggregate_task_wall_time_ns": wall_time_ns,
    }


def status(
    project_root: str | Path, authority: str | Path = DEFAULT_AUTHORITY
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    return _status_from_plan(root, compile_plan(root, authority))


def _generation_seal(root: Path, plan: Mapping[str, object]) -> dict[str, object]:
    authority = plan["_authority"]
    seals = []
    for task in plan["tasks"]:
        seal = _valid_task_seal(root, authority, task)
        if seal is None:
            raise ValueError("cannot seal an incomplete linked-reference generation")
        path = _task_root(root, authority, task) / "seal.json"
        seals.append(
            {
                "task_key": task["task_key"],
                "code_revision": seal["code_revision"],
                "path": str(path.relative_to(root)),
                "sha256": _sha256(path),
            }
        )
    identity = {
        "authority_sha256": authority["authority_sha256"],
        "plan_sha256": plan["plan_sha256"],
        "code_revisions": sorted({str(seal["code_revision"]) for seal in seals}),
        "task_seals": seals,
    }
    document = {
        "schema_version": GENERATION_SEAL_SCHEMA,
        "state": "sealed",
        "id": authority["id"],
        "source_run_id": authority["source_run_id"],
        "reference_form": authority["reference"]["form"],
        **identity,
        "generation_sha256": _json_digest(identity),
        "sealed_at": _now(),
    }
    destination = _inside(
        root,
        Path(str(authority["output_root"]))
        / str(authority["id"])
        / "generation-seal.json",
        "linked-reference generation seal",
    )
    if destination.is_file():
        current = json.loads(destination.read_text(encoding="utf-8"))
        if current.get("generation_sha256") != document["generation_sha256"]:
            raise ValueError(
                "linked-reference generation seal already exists with another identity"
            )
        return current
    _atomic_json(destination, document)
    return document


def run(
    project_root: str | Path,
    mode: str,
    authority_path: str | Path = DEFAULT_AUTHORITY,
) -> dict[str, object]:
    if mode not in {"canary", "full"}:
        raise ValueError("linked-reference run mode must be canary or full")
    root = Path(project_root).expanduser().resolve()
    readiness = preflight(root, authority_path)
    if readiness["blockers"]:
        raise ValueError("; ".join(readiness["blockers"]))
    plan = compile_plan(root, authority_path)
    authority = plan["_authority"]
    by_key = {str(task["task_key"]): task for task in plan["tasks"]}
    requested = (
        [by_key[str(key)] for key in authority["canary"]["tasks"]]
        if mode == "canary"
        else list(plan["tasks"])
    )
    pending = [
        task for task in requested if _valid_task_seal(root, authority, task) is None
    ]
    run_root = _inside(
        root,
        Path(str(authority["output_root"])) / str(authority["id"]),
        "linked-reference run root",
    )
    run_root.mkdir(parents=True, exist_ok=True)
    lock_path = run_root / ".run.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        os.close(descriptor)
        raise ValueError("another linked-reference run is active") from error
    started_at = _now()
    try:
        if not pending:
            result = _status_from_plan(root, plan, mode)
            if mode == "full" and result["state"] == "complete":
                result["generation"] = _generation_seal(root, plan)
            return result
        chunks, loads = _balanced_chunks(
            pending, int(authority["execution"]["workers"])
        )
        _atomic_json(
            run_root / "status.json",
            {
                "schema_version": "fidb-linked-reference-run-status/v1",
                "state": "running",
                "mode": mode,
                "started_at": started_at,
                "code_revision": plan["code_revision"],
                "plan_sha256": plan["plan_sha256"],
                "pending_tasks": len(pending),
                "estimated_archive_byte_loads": loads,
                "worker_pids": [],
            },
        )
        processes = []
        streams = []
        try:
            for index, chunk in enumerate(chunks, start=1):
                log = (run_root / f"{mode}-worker-{index:02d}.log").open(
                    "a", encoding="utf-8"
                )
                streams.append(log)
                process = subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "fidb_poc.linked_reference_retrofit",
                        "_worker",
                        "--project-root",
                        str(root),
                        "--authority",
                        str(authority["authority_path"]),
                        "--tasks",
                        ",".join(chunk),
                    ],
                    cwd=root,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                processes.append(process)
            _atomic_json(
                run_root / "status.json",
                {
                    "schema_version": "fidb-linked-reference-run-status/v1",
                    "state": "running",
                    "mode": mode,
                    "started_at": started_at,
                    "code_revision": plan["code_revision"],
                    "plan_sha256": plan["plan_sha256"],
                    "pending_tasks": len(pending),
                    "estimated_archive_byte_loads": loads,
                    "worker_pids": [process.pid for process in processes],
                },
            )
            return_codes = [process.wait() for process in processes]
        finally:
            for stream in streams:
                stream.close()
        refreshed = compile_plan(root, authority_path)
        result = _status_from_plan(root, refreshed, mode)
        result["started_at"] = started_at
        result["finished_at"] = _now()
        result["worker_return_codes"] = return_codes
        if mode == "full" and result["state"] == "complete":
            result["generation"] = _generation_seal(root, refreshed)
        _atomic_json(run_root / "status.json", result)
        return result
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("status", "preflight", "run", "_worker"):
        child = commands.add_parser(command)
        child.add_argument("--project-root", type=Path, default=Path.cwd())
        child.add_argument("--authority", type=Path, default=DEFAULT_AUTHORITY)
        if command == "run":
            child.add_argument("--mode", choices=("canary", "full"), required=True)
        if command == "_worker":
            child.add_argument("--tasks", required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "status":
            document = status(arguments.project_root, arguments.authority)
        elif arguments.command == "preflight":
            document = preflight(arguments.project_root, arguments.authority)
        elif arguments.command == "run":
            document = run(arguments.project_root, arguments.mode, arguments.authority)
        else:
            return worker(
                arguments.project_root,
                [value for value in arguments.tasks.split(",") if value],
                arguments.authority,
            )
        print(json.dumps(document, indent=2, sort_keys=True))
        if document.get("state") in {"blocked", "failed", "failed-or-partial"}:
            return 1
        return 0
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
