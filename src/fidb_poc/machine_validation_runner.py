"""Execute the reviewed C10 machine-validation campaign.

The production queue remains immutable.  This runner consumes sealed build
evidence, reconstructs the compacted OpenSSL archives when required, builds
never-executed fold composites, exports their FID hashes and performs a
leave-one-exact-identity-out owner comparison from a bounded SQLite index.
"""

from __future__ import annotations

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import tomllib
from typing import Iterable, Mapping

from .c_width import compile_c_width, materialize_width_configuration
from .machine_validation import (
    LINK_HARNESS_POLICY,
    QUERY_COPY_POLICY,
    compile_machine_validation,
)
from .toolchain_packs import load_toolchain_pack_catalog, resolve_toolchain_profile
from .validation_analysis import (
    QUERY_ANALYSIS_POLICY,
    QUERY_ANALYSIS_RECOVERY_POLICY,
)

RUNTIME_SCHEMA = "fidb-machine-validation-runtime/v1"
RUN_STATUS_SCHEMA = "fidb-machine-validation-run-status/v1"
UNIT_RESULT_SCHEMA = "fidb-machine-validation-unit/v1"
FOLD_RESULT_SCHEMA = "fidb-machine-validation-fold-result/v1"
WORK_CLAIM_SCHEMA = "fidb-machine-validation-work-claim/v1"
PREPARED_FOLD_SCHEMA = "fidb-machine-validation-prepared-fold/v1"
REFERENCE_INDEX_SCHEMA = "fidb-machine-validation-reference-index/v3"
DEFAULT_RUNTIME = Path("validation/machine-validation-runtime.toml")
PAUSE_REQUEST_NAME = "pause-request.json"


class TransientEvidenceError(ValueError):
    """The evidence authority could not be read consistently yet."""


_OBJDUMP_INSTRUCTION = re.compile(
    r"^\s*[0-9a-f]+:\s+(?:(?:[0-9a-f]{2,16})\s+)+"
    r"(?P<mnemonic>[a-z][a-z0-9.]*)\s*(?P<operands>.*)$",
    re.IGNORECASE,
)
_ZERO_DIRECT_TARGET = re.compile(
    r"(?:^|,\s*)(?:#)?(?:0x)?0+(?:\s*<[^>]+>)?\s*$",
    re.IGNORECASE,
)

_DIRECT_BRANCH_MNEMONICS = {
    "b",
    "ba",
    "bal",
    "bc",
    "bca",
    "bcl",
    "bcla",
    "bf",
    "bl",
    "bla",
    "blx",
    "bra",
    "bsr",
    "bt",
    "bx",
    "cbnz",
    "cbz",
    "tbnz",
    "tbz",
}
_BRANCH_CONDITIONS = {
    "cc",
    "cs",
    "eq",
    "ge",
    "gt",
    "hi",
    "hs",
    "le",
    "lo",
    "ls",
    "lt",
    "mi",
    "ne",
    "nv",
    "pl",
    "vc",
    "vs",
}


def _is_control_flow_mnemonic(mnemonic: str) -> bool:
    value = mnemonic.lower().split(".", 1)[0]
    if value in _DIRECT_BRANCH_MNEMONICS or value in {"call", "callq", "jsr"}:
        return True
    if value.startswith("j"):
        return True
    if value.startswith("b") and value[1:] in _BRANCH_CONDITIONS:
        return True
    if value.startswith("bl") and value[2:] in _BRANCH_CONDITIONS:
        return True
    return value in {
        "beqz",
        "bgez",
        "bgezal",
        "bgtz",
        "blez",
        "bltz",
        "bltzal",
        "bnez",
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _inside(root: Path, value: str, label: str) -> Path:
    path = (
        (root / value).expanduser().resolve()
        if not Path(value).is_absolute()
        else Path(value).resolve()
    )
    if path != root and root not in path.parents:
        raise ValueError(f"{label} escapes the project root: {value}")
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


def _result_documents(run_root: Path, mode: str) -> list[dict[str, object]]:
    documents = []
    for path in (run_root / "units").glob("*/result.json"):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if document.get("mode") == mode:
            documents.append(document)
    return documents


def _result_counts(run_root: Path, mode: str) -> tuple[int, int]:
    documents = _result_documents(run_root, mode)
    return (
        sum(row.get("state") == "complete" for row in documents),
        sum(row.get("state") == "failed" for row in documents),
    )


def _failed_work_unit_count(
    run_root: Path,
    mode: str,
    *,
    postprocess_started: bool,
) -> int:
    """Keep downstream failures separate from source-cell failures."""

    failed = _result_counts(run_root, mode)[1]
    return failed if postprocess_started else max(1, failed)


def _fold_checkpoint_path(unit_root: Path, fold: str) -> Path:
    return unit_root / f"fold-{fold}" / "fold-result.json"


def _load_fold_checkpoint(
    path: Path,
    *,
    mode: str,
    position: int,
    route_id: str,
    treatment_id: str,
    fold: str,
    runtime_authority_sha256: str,
) -> dict[str, object] | None:
    """Return a completed fold only when its full scientific identity matches."""

    if not path.is_file():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    expected = {
        "schema_version": FOLD_RESULT_SCHEMA,
        "state": "complete",
        "mode": mode,
        "position": position,
        "route_id": route_id,
        "treatment_id": treatment_id,
        "fold": fold,
        "runtime_authority_sha256": runtime_authority_sha256,
    }
    if any(document.get(key) != value for key, value in expected.items()):
        return None
    result = document.get("result")
    if not isinstance(result, dict) or result.get("fold") != fold:
        return None
    return result


def _write_fold_checkpoint(
    path: Path,
    result: Mapping[str, object],
    *,
    mode: str,
    position: int,
    route_id: str,
    treatment_id: str,
    fold: str,
    runtime_authority_sha256: str,
) -> None:
    _atomic_json(
        path,
        {
            "schema_version": FOLD_RESULT_SCHEMA,
            "state": "complete",
            "mode": mode,
            "position": position,
            "route_id": route_id,
            "treatment_id": treatment_id,
            "fold": fold,
            "runtime_authority_sha256": runtime_authority_sha256,
            "completed_at": _now(),
            "result": dict(result),
        },
    )


def _validation_process_active(pid: object, run_id: str) -> bool:
    """Reject stale PIDs and zombies without signalling an unrelated process."""
    if type(pid) is not int or pid < 1:
        return False
    process = Path("/proc") / str(pid)
    try:
        fields = (process / "stat").read_text(encoding="utf-8").split()
        command = (
            (process / "cmdline")
            .read_bytes()
            .replace(b"\0", b" ")
            .decode("utf-8", errors="replace")
        )
    except OSError:
        return False
    return (
        len(fields) > 2
        and fields[2] != "Z"
        and "machine-validation" in command
        and run_id in command
    )


def _terminate_worker_groups(processes: list[subprocess.Popen[bytes]]) -> None:
    """Stop validation sessions, including their Ghidra descendants."""
    live = [process for process in processes if process.poll() is None]
    for process in live:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 15
    for process in live:
        try:
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def _unit_result_path(
    run_root: Path, unit: Mapping[str, object], position: int
) -> Path:
    return (
        run_root
        / "units"
        / f"{position:03d}-{unit['route_id']}-{unit['treatment_id']}"
        / "result.json"
    )


def _claim_path(run_root: Path, position: int) -> Path:
    return run_root / "claims" / f"{position:03d}.json"


def _claim_position(run_root: Path, position: int, *, pid: int | None = None) -> bool:
    """Claim one unit without a coordinator or cross-process race."""

    path = _claim_path(run_root, position)
    path.parent.mkdir(parents=True, exist_ok=True)
    owner = os.getpid() if pid is None else pid
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(
            {
                "schema_version": WORK_CLAIM_SCHEMA,
                "position": position,
                "pid": owner,
                "claimed_at": _now(),
            },
            stream,
            sort_keys=True,
        )
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    return True


def _release_position_claim(
    run_root: Path, position: int, *, pid: int | None = None
) -> bool:
    path = _claim_path(run_root, position)
    try:
        claim = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    owner = os.getpid() if pid is None else pid
    if claim.get("pid") != owner or claim.get("position") != position:
        return False
    path.unlink(missing_ok=True)
    return True


def _release_worker_claims(run_root: Path, pid: int) -> list[int]:
    released = []
    for path in (run_root / "claims").glob("*.json"):
        try:
            claim = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if claim.get("pid") != pid:
            continue
        position = claim.get("position")
        if type(position) is int and _release_position_claim(
            run_root, position, pid=pid
        ):
            released.append(position)
    return sorted(released)


def _worker_finished_cleanly(run_root: Path, pid: int) -> bool:
    try:
        progress = json.loads(
            _worker_progress_path(run_root, pid).read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        return False
    return progress.get("state") == "finished"


def _cost_aware_positions(
    run_root: Path,
    units: Mapping[int, Mapping[str, object]],
    positions: Iterable[int],
    mode: str,
) -> list[int]:
    """Put historically expensive cells first while preserving deterministic ties."""

    route_seconds: dict[str, list[float]] = defaultdict(list)
    for document in _result_documents(run_root, mode):
        if document.get("state") != "complete":
            continue
        elapsed = document.get("wall_time_ns")
        route_id = document.get("route_id")
        if type(elapsed) is int and elapsed > 0 and isinstance(route_id, str):
            route_seconds[route_id].append(elapsed / 1_000_000_000)
    route_cost = {
        route_id: sum(values) / len(values)
        for route_id, values in route_seconds.items()
    }
    observed_default = sum(route_cost.values()) / len(route_cost) if route_cost else 0.0

    def key(position: int) -> tuple[float, int]:
        route_id = str(units[position]["route_id"])
        return (-route_cost.get(route_id, observed_default), position)

    return sorted(positions, key=key)


def _terminal_positions(
    run_root: Path,
    mode: str,
    units: Mapping[int, Mapping[str, object]],
    positions: Iterable[int],
) -> set[int]:
    terminal = set()
    for position in positions:
        path = _unit_result_path(run_root, units[position], position)
        try:
            result = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if result.get("mode") == mode and result.get("state") in {
            "complete",
            "failed",
        }:
            terminal.add(position)
    return terminal


def _worker_progress_path(run_root: Path, pid: int) -> Path:
    return run_root / "workers" / f"{pid}.json"


def _write_worker_progress(
    run_root: Path,
    state: str,
    *,
    position: int | None = None,
    started_unix_ns: int | None = None,
) -> None:
    document = {
        "schema_version": "fidb-machine-validation-worker-progress/v1",
        "pid": os.getpid(),
        "state": state,
        "position": position,
        "updated_at": _now(),
    }
    if started_unix_ns is not None:
        document["started_unix_ns"] = started_unix_ns
    _atomic_json(_worker_progress_path(run_root, os.getpid()), document)


def _timed_out_position(
    run_root: Path, pid: int, timeout_seconds: int, now_unix_ns: int
) -> int | None:
    try:
        progress = json.loads(
            _worker_progress_path(run_root, pid).read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        return None
    position = progress.get("position")
    started = progress.get("started_unix_ns")
    if (
        progress.get("state") != "running"
        or type(position) is not int
        or type(started) is not int
    ):
        return None
    if now_unix_ns - started < timeout_seconds * 1_000_000_000:
        return None
    return position


def _supervisor_failure(
    run_root: Path,
    unit: Mapping[str, object],
    position: int,
    mode: str,
    reason_code: str,
    detail: str,
) -> Path:
    result_path = _unit_result_path(run_root, unit, position)
    if result_path.is_file():
        return result_path
    _atomic_json(
        result_path,
        {
            "schema_version": UNIT_RESULT_SCHEMA,
            "state": "failed",
            "mode": mode,
            "position": position,
            "route_id": str(unit["route_id"]),
            "profile_id": str(unit["profile_id"]),
            "treatment_id": str(unit["treatment_id"]),
            "started_at": _now(),
            "wall_time_ns": 0,
            "reason_code": reason_code,
            "error": detail,
            "folds": [],
        },
    )
    return result_path


def _prior_supervisor_attempts(result_path: Path, reason_code: str) -> int:
    baseline = _latest_explicit_requeue_attempt(result_path)
    attempts = result_path.parent / "attempts"
    count = 0
    for path in attempts.glob("result-*.json"):
        match = re.fullmatch(r"result-(\d+)\.json", path.name)
        if match is None or int(match.group(1)) <= baseline:
            continue
        try:
            result = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if result.get("reason_code") == reason_code:
            count += 1
    return count


def _latest_explicit_requeue_attempt(result_path: Path) -> int:
    """Return the archived-attempt boundary of the latest explicit requeue.

    Operator requeue is a reviewed recovery decision.  It preserves all old
    attempts, but automatic retry allowance must begin again after that
    boundary rather than being consumed by failures from an earlier run.
    """

    try:
        position = int(result_path.parent.name.split("-", 1)[0])
        run_root = result_path.parents[2]
    except (IndexError, ValueError):
        return 0
    receipts = run_root / "requeues"
    for receipt_path in sorted(receipts.glob("requeue-*.json"), reverse=True):
        try:
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if position not in receipt.get("positions", []):
            continue
        for row in receipt.get("archived_results", []):
            if row.get("position") != position:
                continue
            match = re.search(
                r"/result-(\d+)\.json$", str(row.get("archived_path", ""))
            )
            if match is not None:
                return int(match.group(1))
        return 0
    return 0


def _has_archived_supervisor_failure(result_path: Path, reason_code: str) -> bool:
    attempts = result_path.parent / "attempts"
    for path in attempts.glob("result-*.json"):
        try:
            result = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if result.get("reason_code") == reason_code:
            return True
    return False


def _query_analysis_policy(result_path: Path, route: object) -> str:
    language = str(getattr(route, "ghidra_language", ""))
    if language.startswith("SuperH4:") and _has_archived_supervisor_failure(
        result_path, "cell-timeout"
    ):
        return QUERY_ANALYSIS_RECOVERY_POLICY
    return QUERY_ANALYSIS_POLICY


def _archive_failed_result(result_path: Path) -> Path | None:
    """Retain concise failure evidence before an explicit resume retries a unit."""
    if not result_path.is_file():
        return None
    try:
        document = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if document.get("state") == "complete":
        return None
    attempts = result_path.parent / "attempts"
    attempts.mkdir(parents=True, exist_ok=True)
    attempt = 1
    while (attempts / f"result-{attempt:03d}.json").exists():
        attempt += 1
    archived = attempts / f"result-{attempt:03d}.json"
    result_path.replace(archived)
    return archived


def load_runtime(
    project_root: str | Path, authority: str | Path = DEFAULT_RUNTIME
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    path = _inside(root, str(authority), "machine-validation runtime")
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    expected = {
        "schema_version",
        "validation_id",
        "manifest",
        "schedule",
        "output_root",
        "ledger",
        "source_archive",
        "openssl_width_report",
        "ghidra_headless",
        "execution",
        "canary",
        "safety",
    }
    if set(document) != expected or document.get("schema_version") != RUNTIME_SCHEMA:
        raise ValueError("machine-validation runtime has unsupported fields or schema")
    execution = document["execution"]
    canary = document["canary"]
    safety = document["safety"]
    if set(execution) != {
        "workers",
        "build_jobs_per_cell",
        "jvm_initial_heap_mib",
        "jvm_max_heap_mib",
        "jvm_active_processors",
        "minimum_distinct_hashes",
        "max_failure_rows",
        "checkpoint_every_units",
        "retain_ghidra_projects_on_failure",
        "retain_ghidra_projects_on_success",
        "worker_startup_attempts",
        "worker_startup_retry_seconds",
        "continue_after_cell_failure",
        "cell_timeout_seconds",
        "cell_timeout_attempts",
        "maximum_worker_restarts",
        "worker_poll_seconds",
        "scheduling_policy",
        "preparation_workers",
        "preparation_batch_size",
    }:
        raise ValueError("machine-validation execution policy has unexpected fields")
    if set(canary) != {
        "positions",
        "folds_by_position",
        "minimum_distinct_hashes",
        "require_formats",
    }:
        raise ValueError("machine-validation canary policy has unexpected fields")
    if set(safety) != {
        "execute_target_binaries",
        "require_production_queue_drained",
        "minimum_free_disk_gib",
        "minimum_available_memory_gib",
    }:
        raise ValueError("machine-validation safety policy has unexpected fields")
    for field in (
        "workers",
        "build_jobs_per_cell",
        "jvm_initial_heap_mib",
        "jvm_max_heap_mib",
        "jvm_active_processors",
        "minimum_distinct_hashes",
        "max_failure_rows",
        "checkpoint_every_units",
        "worker_startup_attempts",
        "worker_startup_retry_seconds",
        "cell_timeout_seconds",
        "cell_timeout_attempts",
        "maximum_worker_restarts",
        "worker_poll_seconds",
        "preparation_workers",
        "preparation_batch_size",
    ):
        if type(execution[field]) is not int or execution[field] < 1:
            raise ValueError(f"machine-validation execution.{field} must be positive")
    if type(execution["continue_after_cell_failure"]) is not bool:
        raise ValueError(
            "machine-validation execution.continue_after_cell_failure must be boolean"
        )
    if execution["scheduling_policy"] != "dynamic-longest-observed-first":
        raise ValueError("machine-validation scheduling policy is unsupported")
    if safety["execute_target_binaries"] is not False:
        raise ValueError("machine-validation must never execute target binaries")
    for field in (
        "manifest",
        "schedule",
        "output_root",
        "ledger",
        "source_archive",
        "openssl_width_report",
    ):
        _inside(root, str(document[field]), field)
    headless = Path(str(document["ghidra_headless"])).resolve()
    if not headless.is_file() or not os.access(headless, os.X_OK):
        raise ValueError(
            f"configured Ghidra headless launcher is unavailable: {headless}"
        )
    return {
        **document,
        "authority_path": str(path.relative_to(root)),
        "authority_sha256": _sha256(path),
    }


def _configuration(root: Path, recipe: str = "openssl@3.5.8"):
    catalog = load_toolchain_pack_catalog(root)
    width = compile_c_width(root, "c-width-v2", _catalog=catalog)
    route_plan = resolve_toolchain_profile(
        root, str(width["toolchain_profile"]), _catalog=catalog
    )
    return materialize_width_configuration(root, recipe, route_plan, _catalog=catalog)


def _manifest(root: Path, runtime: Mapping[str, object]) -> dict[str, object]:
    path = _inside(root, str(runtime["manifest"]), "validation manifest")
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if (
        document.get("schema_version") != "fidb-machine-validation-batch/v1"
        or document.get("id") != runtime["validation_id"]
    ):
        raise ValueError("machine-validation manifest identity does not match runtime")
    if (
        document.get("state") != "materialized-disarmed"
        or document.get("execute_target_binaries") is not False
    ):
        raise ValueError(
            "machine-validation manifest is not safely materialized and disarmed"
        )
    units = document.get("work_unit")
    if not isinstance(units, list) or len(units) != 222:
        raise ValueError(
            "machine-validation manifest must contain exactly 222 work units"
        )
    hash_job = document.get("hash_discrimination_job")
    if (
        not isinstance(hash_job, dict)
        or hash_job.get("id") != "hash-discrimination"
        or hash_job.get("kind") != "validation-postprocess"
        or hash_job.get("state") != "planned-disarmed"
        or hash_job.get("automatic") is not True
        or hash_job.get("required_for_run_completion") is not True
        or hash_job.get("after") != "composite-build-analysis"
    ):
        raise ValueError(
            "machine-validation manifest lacks the required hash-discrimination job"
        )
    for field in ("method_authority", "corpus_authority", "backend_authority"):
        authority_path = _inside(root, str(hash_job.get(field, "")), field)
        if not authority_path.is_file() or _sha256(authority_path) != hash_job.get(
            f"{field}_sha256"
        ):
            raise ValueError(f"machine-validation {field} is unavailable or stale")
    return document


def _queue_drained(root: Path, runtime: Mapping[str, object]) -> bool:
    path = _inside(root, str(runtime["ledger"]), "production ledger")
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
    try:
        count = connection.execute(
            "SELECT COUNT(*) FROM jobs WHERE active = 1 AND state IN ('queued','leased','running','failed')"
        ).fetchone()[0]
        return int(count) == 0
    finally:
        connection.close()


def _production_evidence(
    root: Path,
    runtime: Mapping[str, object],
    cohort: set[str],
    *,
    verify_archives: bool = True,
) -> tuple[dict, dict]:
    archives: dict[tuple[str, str, str], dict[str, object]] = {}
    signatures: dict[tuple[str, str, str], dict[str, object]] = {}
    ledger = _inside(root, str(runtime["ledger"]), "production ledger")
    connection = sqlite3.connect(f"file:{ledger}?mode=ro", uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute("""
            SELECT jobs.job_id, jobs.result_json, cells.cell_json
            FROM jobs
            JOIN resolved_cells AS cells
              ON cells.plan_digest = jobs.plan_digest AND cells.cell_id = jobs.base_cell_id
            WHERE jobs.active = 1 AND jobs.state = 'complete'
            """)
        for row in rows:
            cell = json.loads(row["cell_json"])
            recipe = cell.get("recipe", {})
            owner = f'{recipe.get("name")}@{recipe.get("version")}'
            if owner not in cohort:
                continue
            route = str(cell.get("toolchain", {}).get("route", ""))
            treatment = str(cell.get("build", {}).get("treatment", ""))
            key = (owner, route, treatment)
            if key in signatures:
                raise ValueError(f"duplicate active production evidence for {key}")
            result = json.loads(row["result_json"])
            attempt = _inside(root, str(result["attempt_root"]), "attempt root")
            if verify_archives:
                seal_path = _inside(root, str(result["seal"]["path"]), "cell seal")
                if _sha256(seal_path) != result["seal"]["sha256"]:
                    raise ValueError(f"cell seal digest mismatch for {row['job_id']}")
                seal = json.loads(seal_path.read_text(encoding="utf-8"))
                archive_paths = [
                    attempt / value
                    for value in str(seal["evidence"]["static_archive_path"]).split(";")
                ]
                archive_digests = str(seal["evidence"]["static_archive_sha256"]).split(
                    ";"
                )
                if len(archive_paths) != len(archive_digests) or any(
                    not path.is_file() for path in archive_paths
                ):
                    raise ValueError(
                        f"retained static archives are incomplete for {key}"
                    )
                if any(
                    _sha256(path) != digest
                    for path, digest in zip(archive_paths, archive_digests, strict=True)
                ):
                    raise ValueError(
                        f"retained static archive digest mismatch for {key}"
                    )
                archives[key] = {
                    "paths": archive_paths,
                    "sha256": archive_digests,
                    "source": str(attempt.relative_to(root)),
                }
            signature_files = list(
                (attempt / "artifacts/libs/fid-signatures").glob("*.jsonl")
            )
            if len(signature_files) != 1 or not signature_files[0].is_file():
                raise ValueError(f"retained signature evidence is incomplete for {key}")
            signatures[key] = {
                "path": signature_files[0],
                "sha256": _sha256(signature_files[0]),
                "source": str(signature_files[0].relative_to(root)),
            }
    finally:
        connection.close()
    return archives, signatures


def _width_openssl_signatures(
    root: Path, runtime: Mapping[str, object], expected: set[tuple[str, str, str]]
) -> dict:
    report_path = _inside(
        root, str(runtime["openssl_width_report"]), "OpenSSL width report"
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    expected_digests: dict[tuple[str, str], str] = {}
    for replay in report.get("replay_results", []):
        for cell in replay.get("cells", []):
            if cell.get("status") == "complete":
                expected_digests[(str(cell["route_id"]), str(cell["treatment_id"]))] = (
                    str(cell["fid_signatures_sha256"])
                )
    base = report_path.parent / "replay-01"
    result = {}
    for key in expected:
        owner, route, treatment = key
        if owner != "openssl@3.5.8":
            continue
        digest = expected_digests.get((route, treatment))
        if digest is None:
            continue
        name = f"openssl-3.5.8-{route}-{treatment}.fid-signatures.jsonl"
        matches = list(base.glob(f"group-*/artifacts/libs/fid-signatures/{name}"))
        if len(matches) != 1 or _sha256(matches[0]) != digest:
            raise ValueError(
                f"OpenSSL width signature evidence is unavailable or changed for {route}:{treatment}"
            )
        result[key] = {
            "path": matches[0],
            "sha256": digest,
            "source": str(matches[0].relative_to(root)),
        }
    return result


def resolve_evidence(
    project_root: str | Path, runtime_path: str | Path = DEFAULT_RUNTIME
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    runtime = load_runtime(root, runtime_path)
    manifest = _manifest(root, runtime)
    status = compile_machine_validation(root)
    if not status["readiness"]["eligible"]:
        unavailable = {
            name: source.get("detail", source.get("state"))
            for name, source in status.get("evidence_sources", {}).items()
            if isinstance(source, dict)
            and source.get("state") == "temporarily-unavailable"
        }
        detail = "; ".join(
            str(value) for value in status["readiness"].get("blockers", [])
        )
        message = "machine-validation cohort is no longer eligible"
        if detail:
            message += f": {detail}"
        if unavailable:
            message += "; temporarily unavailable evidence: " + ", ".join(
                f"{name}={value}" for name, value in sorted(unavailable.items())
            )
            raise TransientEvidenceError(message)
        raise ValueError(message)
    cohort = set(status["randomization"]["canonical_ids"])
    expected = {
        (owner, str(unit["route_id"]), str(unit["treatment_id"]))
        for owner in cohort
        for unit in manifest["work_unit"]
    }
    archives, signatures = _production_evidence(root, runtime, cohort)
    signatures.update(
        _width_openssl_signatures(root, runtime, expected - set(signatures))
    )
    missing_signatures = expected - set(signatures)
    missing_archives = expected - set(archives)
    reconstructable = {key for key in missing_archives if key[0] == "openssl@3.5.8"}
    unrecoverable = missing_archives - reconstructable
    configuration = _configuration(root)
    routes = {route.id: route for route in configuration.routes}
    treatments = {treatment.id: treatment for treatment in configuration.treatments}
    missing_tools = []
    for unit in manifest["work_unit"]:
        route = routes.get(str(unit["route_id"]))
        treatment = treatments.get(str(unit["treatment_id"]))
        if route is None or treatment is None or not treatment.applies_to(route):
            missing_tools.append(str(unit["id"]))
            continue
        for command in (route.compiler, route.archiver, route.ranlib):
            if not Path(command[0]).is_file() or not os.access(command[0], os.X_OK):
                missing_tools.append(str(unit["id"]))
                break
    free_disk = shutil.disk_usage(root).free
    available_memory = _available_memory_bytes()
    blockers = []
    if missing_signatures:
        blockers.append(f"{len(missing_signatures)} signature inputs are missing")
    if unrecoverable:
        blockers.append(
            f"{len(unrecoverable)} static archive inputs are missing and unrecoverable"
        )
    if missing_tools:
        blockers.append(
            f"{len(set(missing_tools))} work units lack executable reviewed tools"
        )
    if runtime["safety"]["require_production_queue_drained"] and not _queue_drained(
        root, runtime
    ):
        blockers.append("production queue is not drained")
    if free_disk < int(runtime["safety"]["minimum_free_disk_gib"]) * 1024**3:
        blockers.append("free disk is below the reviewed safety floor")
    if (
        available_memory
        < int(runtime["safety"]["minimum_available_memory_gib"]) * 1024**3
    ):
        blockers.append("available memory is below the reviewed safety floor")
    return {
        "runtime": runtime,
        "manifest": manifest,
        "status": status,
        "configuration": configuration,
        "archives": archives,
        "signatures": signatures,
        "summary": {
            "expected_inputs": len(expected),
            "sealed_archive_inputs": len(archives),
            "reconstructable_archive_inputs": len(reconstructable),
            "signature_inputs": len(signatures),
            "work_units": len(manifest["work_unit"]),
            "free_disk_bytes": free_disk,
            "available_memory_bytes": available_memory,
        },
        "blockers": blockers,
    }


def _resolve_worker_evidence(root: Path, runtime_path: str | Path) -> dict[str, object]:
    """Resolve worker authority with bounded retries for transient ledger reads."""

    runtime = load_runtime(root, runtime_path)
    attempts = int(runtime["execution"]["worker_startup_attempts"])
    delay = int(runtime["execution"]["worker_startup_retry_seconds"])
    for attempt in range(1, attempts + 1):
        try:
            return resolve_evidence(root, runtime_path)
        except TransientEvidenceError:
            if attempt == attempts:
                raise
            time.sleep(delay)
    raise AssertionError("bounded worker evidence resolution did not terminate")


def resolve_hash_analysis_evidence(
    project_root: str | Path,
    runtime_path: str | Path = DEFAULT_RUNTIME,
) -> dict[str, object]:
    """Resolve only the immutable inputs needed by single-hash analysis.

    Full validation preflight deliberately verifies retained archives, compiler
    executables, queue state, RAM and disk because it may rebuild and analyse
    composites.  A post-run hash pass consumes already sealed JSONL exports and
    must not pay that multi-gigabyte archive-verification cost or inherit those
    execution-only gates.
    """

    root = Path(project_root).expanduser().resolve()
    runtime = load_runtime(root, runtime_path)
    manifest = _manifest(root, runtime)
    randomization = manifest.get("randomization", {})
    fold_a = [str(owner) for owner in randomization.get("fold_a", [])]
    fold_b = [str(owner) for owner in randomization.get("fold_b", [])]
    if (
        not fold_a
        or not fold_b
        or len(set(fold_a)) != len(fold_a)
        or len(set(fold_b)) != len(fold_b)
        or set(fold_a) & set(fold_b)
    ):
        raise ValueError(
            "machine-validation manifest must freeze two non-empty disjoint folds"
        )
    cohort = set(fold_a) | set(fold_b)
    expected = {
        (owner, str(unit["route_id"]), str(unit["treatment_id"]))
        for owner in cohort
        for unit in manifest["work_unit"]
    }
    _archives, signatures = _production_evidence(
        root, runtime, cohort, verify_archives=False
    )
    signatures.update(
        _width_openssl_signatures(root, runtime, expected - set(signatures))
    )
    missing = expected - set(signatures)
    if missing:
        raise ValueError(
            f"single-hash analysis is missing {len(missing)} exact signature inputs"
        )
    configuration = _configuration(root)
    routes = {route.id: route for route in configuration.routes}
    treatments = {treatment.id: treatment for treatment in configuration.treatments}
    invalid = [
        str(unit["id"])
        for unit in manifest["work_unit"]
        if (
            (route := routes.get(str(unit["route_id"]))) is None
            or (treatment := treatments.get(str(unit["treatment_id"]))) is None
            or not treatment.applies_to(route)
        )
    ]
    if invalid:
        raise ValueError(
            f"single-hash analysis has {len(invalid)} invalid width identities"
        )
    return {
        "runtime": runtime,
        "manifest": manifest,
        "configuration": configuration,
        "cohort": sorted(cohort),
        "signatures": signatures,
        "expected_inputs": len(expected),
    }


def _available_memory_bytes() -> int:
    fields = {}
    for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        name, value = line.split(":", 1)
        fields[name] = int(value.strip().split()[0]) * 1024
    return fields.get("MemAvailable", 0)


def preflight(
    project_root: str | Path, runtime_path: str | Path = DEFAULT_RUNTIME
) -> dict[str, object]:
    evidence = resolve_evidence(project_root, runtime_path)
    runtime = evidence["runtime"]
    return {
        "schema_version": "fidb-machine-validation-preflight/v1",
        "validation_id": runtime["validation_id"],
        "state": "ready" if not evidence["blockers"] else "blocked",
        "authority_path": runtime["authority_path"],
        "authority_sha256": runtime["authority_sha256"],
        "summary": evidence["summary"],
        "blockers": evidence["blockers"],
    }


def _resolve_link_qualification(
    root: Path,
    run_id: str,
    evidence: Mapping[str, object] | None = None,
) -> tuple[dict[str, object], dict[str, object] | None, dict[str, object] | None]:
    """Resolve the mandatory pre-Ghidra link gate without duplicating its audit."""

    from .machine_validation_links import (
        compile_link_qualification,
        link_qualification_admission,
        link_qualification_status,
        load_link_qualification,
    )

    authority = load_link_qualification(root)
    if run_id in authority["admission"]["grandfather_run_ids"]:
        admission = link_qualification_admission(root, run_id, _evidence=evidence)
        return admission, None, None
    plan = compile_link_qualification(root, _evidence=evidence)
    status = link_qualification_status(root, _plan=plan)
    admission = link_qualification_admission(
        root,
        run_id,
        _evidence=evidence,
        _plan=plan,
        _status=status,
    )
    return admission, plan, status


def _run_root(root: Path, runtime: Mapping[str, object], run_id: str) -> Path:
    if not run_id or any(
        character
        not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
        for character in run_id
    ):
        raise ValueError("machine-validation run id is not a safe path component")
    return _inside(root, f'{runtime["output_root"]}/{run_id}', "validation run")


def _strip_tool(route) -> Path:
    directory = Path(route.compiler[0]).parent
    compiler_name = Path(route.compiler[0]).name
    candidates = []
    if compiler_name.endswith("-gcc"):
        candidates.append(directory / f"{compiler_name[:-4]}-strip")
    if compiler_name.endswith("-clang"):
        candidates.append(directory / f"{compiler_name[:-6]}-strip")
    candidates.extend((directory / "llvm-strip", directory / "strip"))
    for path in candidates:
        if path.is_file() and os.access(path, os.X_OK):
            return path
    raise ValueError(f"no strip tool found beside compiler for {route.id}")


def _companion_tool(route, name: str) -> Path:
    compiler = Path(route.compiler[0])
    compiler_name = compiler.name
    candidates = []
    if compiler_name.endswith("-gcc"):
        candidates.append(compiler.with_name(f"{compiler_name[:-4]}-{name}"))
    candidates.extend(
        (
            compiler.parent / f"llvm-{name}",
            compiler.parent / name,
        )
    )
    for command in (f"llvm-{name}", name):
        if resolved := shutil.which(command):
            candidates.append(Path(resolved))
    for path in candidates:
        if path.is_file() and os.access(path, os.X_OK):
            return path
    raise ValueError(f"no {name} tool found for validation route {route.id}")


def _zero_control_flow_lines(lines: Iterable[str]) -> list[str]:
    hits = []
    for line in lines:
        instruction = _OBJDUMP_INSTRUCTION.match(line)
        if instruction is None:
            continue
        if not _is_control_flow_mnemonic(instruction["mnemonic"]):
            continue
        if _ZERO_DIRECT_TARGET.search(instruction["operands"]):
            hits.append(line.strip())
    return hits


def _audit_linked_image(
    route,
    output: Path,
    audit_path: Path,
    harness_mode: str,
    *,
    linker_compatibility: str = "strict",
) -> dict[str, object]:
    objdump = _companion_tool(route, "objdump")
    result = subprocess.run(
        [str(objdump), "-d", str(output)],
        text=True,
        capture_output=True,
        timeout=300,
        check=False,
    )
    hits = _zero_control_flow_lines(result.stdout.splitlines())
    audit = {
        "schema_version": "fidb-validation-link-audit/v1",
        "harness_mode": harness_mode,
        "linker_compatibility": linker_compatibility,
        "text_relocations_permitted": linker_compatibility
        == "android-32-text-relocations",
        "route_id": route.id,
        "binary_format": route.binary_format,
        "image_kind": "shared-object" if route.binary_format == "ELF" else "dll",
        "artifact": str(output),
        "artifact_sha256": _sha256(output),
        "objdump": str(objdump),
        "objdump_returncode": result.returncode,
        "direct_zero_control_flow_count": len(hits),
        "direct_zero_control_flow": hits[:20],
    }
    _atomic_json(audit_path, audit)
    if result.returncode != 0:
        raise RuntimeError(
            f"linked-image audit failed for {route.id}: {result.stderr[-2000:]}"
        )
    if hits:
        raise RuntimeError(
            f"linked-image audit rejected {route.id}: "
            f"{len(hits)} direct control-flow transfers target address zero"
        )
    return audit


def _needs_android_32_text_relocations(route, stderr: str) -> bool:
    """Recognise the bounded Android 32-bit non-PIC archive failure.

    Android API 21 can represent these relocations in a shared image.  The
    validation image is never executed; allowing them preserves the original
    archive instructions while the link audit still rejects unresolved direct
    control flow to address zero.
    """

    return (
        route.binary_format == "ELF"
        and getattr(route, "target_os", None) == "android"
        and getattr(route, "architecture", None) in {"arm", "i686"}
        and "recompile with -fPIC" in stderr
        and ("R_ARM_ABS32" in stderr or "R_386_32" in stderr)
    )


def _link_composite(
    route,
    archives: list[Path],
    output: Path,
    truth_map: Path,
    *,
    harness_mode: str,
) -> Path:
    if harness_mode != LINK_HARNESS_POLICY:
        raise ValueError(
            f"unsupported validation harness {harness_mode!r}; "
            f"expected {LINK_HARNESS_POLICY!r}"
        )
    output.parent.mkdir(parents=True, exist_ok=True)

    def command(
        support: list[Path], *, allow_android_32_text_relocations: bool = False
    ) -> list[str]:
        if route.binary_format == "PE/COFF":
            return [
                *route.compiler,
                "-shared",
                "-nostdlib",
                "-Wl,/force:unresolved",
                "-Wl,/force:multiple",
                "-Wl,--whole-archive",
                *map(str, archives),
                "-Wl,--no-whole-archive",
                "-o",
                str(output),
            ]
        compatibility_flags = (
            ["-Wl,-z,notext"] if allow_android_32_text_relocations else []
        )
        return [
            *route.compiler,
            "-shared",
            "-nostdlib",
            "-Wl,-Bsymbolic",
            "-Wl,--allow-multiple-definition",
            *compatibility_flags,
            f"-Wl,-Map,{truth_map}",
            *map(str, support),
            "-Wl,--whole-archive",
            *map(str, archives),
            "-Wl,--no-whole-archive",
            "-o",
            str(output),
        ]

    support: list[Path] = []
    allow_android_32_text_relocations = False
    result = subprocess.run(
        command(support), text=True, capture_output=True, timeout=900, check=False
    )
    log = result.stdout + result.stderr
    stack_support_attempted = False
    for _attempt in range(2):
        if result.returncode == 0:
            break
        if (
            not allow_android_32_text_relocations
            and _needs_android_32_text_relocations(route, result.stderr)
        ):
            allow_android_32_text_relocations = True
            retry_label = "android 32-bit text-relocation compatibility"
        elif (
            not stack_support_attempted
            and route.binary_format == "ELF"
            and "__stack_chk_fail_local" in result.stderr
        ):
            stack_support_attempted = True
            source = output.parent / "stack-chk-fail-local.S"
            support_object = output.parent / "stack-chk-fail-local.o"
            source.write_text(
                ".text\n.globl __stack_chk_fail_local\n.hidden __stack_chk_fail_local\n"
                ".type __stack_chk_fail_local, %function\n__stack_chk_fail_local:\n"
                ".size __stack_chk_fail_local, .-__stack_chk_fail_local\n",
                encoding="utf-8",
            )
            compiled = subprocess.run(
                [
                    *route.compiler,
                    "-c",
                    "-x",
                    "assembler",
                    str(source),
                    "-o",
                    str(support_object),
                ],
                text=True,
                capture_output=True,
                timeout=120,
                check=False,
            )
            log += (
                "\n--- validation stack-check support ---\n"
                + compiled.stdout
                + compiled.stderr
            )
            if compiled.returncode != 0 or not support_object.is_file():
                break
            support = [support_object]
            retry_label = "stack-check support"
        else:
            break
        output.unlink(missing_ok=True)
        result = subprocess.run(
            command(
                support,
                allow_android_32_text_relocations=(allow_android_32_text_relocations),
            ),
            text=True,
            capture_output=True,
            timeout=900,
            check=False,
        )
        log += (
            f"\n--- validation composite retry: {retry_label} ---\n"
            + result.stdout
            + result.stderr
        )
    (output.parent / "link.log").write_text(log, encoding="utf-8")
    if result.returncode != 0 or not output.is_file() or output.stat().st_size == 0:
        raise RuntimeError(
            f"composite link failed for {route.id}: {result.stderr[-2000:]}"
        )
    _audit_linked_image(
        route,
        output,
        truth_map.with_name("link-audit.json"),
        harness_mode,
        linker_compatibility=(
            "android-32-text-relocations"
            if allow_android_32_text_relocations
            else "strict"
        ),
    )
    return output


def _prepared_fold_path(unit_root: Path, fold: str) -> Path:
    return unit_root / f"fold-{fold}" / "prepared.json"


def _load_prepared_fold(
    root: Path,
    path: Path,
    *,
    position: int,
    route_id: str,
    treatment_id: str,
    fold: str,
    runtime_authority_sha256: str,
) -> dict[str, object] | None:
    if not path.is_file():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    expected = {
        "schema_version": PREPARED_FOLD_SCHEMA,
        "state": "prepared",
        "position": position,
        "route_id": route_id,
        "treatment_id": treatment_id,
        "fold": fold,
        "runtime_authority_sha256": runtime_authority_sha256,
        "link_harness_policy": LINK_HARNESS_POLICY,
        "query_copy_policy": QUERY_COPY_POLICY,
    }
    if any(document.get(key) != value for key, value in expected.items()):
        return None
    try:
        truth_binary = _inside(root, str(document["truth_binary"]), "prepared truth")
        query_binary = _inside(root, str(document["query_binary"]), "prepared query")
    except (KeyError, TypeError, ValueError):
        return None
    if not truth_binary.is_file() or not query_binary.is_file():
        return None
    return document


def _prepare_fold(
    root: Path,
    evidence: Mapping[str, object],
    route,
    treatment,
    unit_root: Path,
    position: int,
    fold: str,
    owners: list[str],
    archive_items: list[tuple[str, Mapping[str, object]]],
) -> dict[str, object]:
    marker_path = _prepared_fold_path(unit_root, fold)
    identity = {
        "position": position,
        "route_id": route.id,
        "treatment_id": treatment.id,
        "fold": fold,
        "runtime_authority_sha256": str(evidence["runtime"]["authority_sha256"]),
    }
    prepared = _load_prepared_fold(root, marker_path, **identity)
    if prepared is not None:
        return prepared
    fold_root = marker_path.parent
    truth = {
        "schema_version": "fidb-machine-validation-truth-map/v1",
        "fold": fold,
        "owners": owners,
        "route_id": route.id,
        "treatment_id": treatment.id,
        "archives": [
            {
                "owner": owner,
                "paths": [str(path.relative_to(root)) for path in item["paths"]],
                "sha256": item["sha256"],
            }
            for owner, item in archive_items
        ],
    }
    _atomic_json(fold_root / "truth-map.json", truth)
    suffix = ".dll" if route.binary_format == "PE/COFF" else ".elf"
    truth_binary = fold_root / f"truth{suffix}"
    archives = [path for _owner, item in archive_items for path in item["paths"]]
    _link_composite(
        route,
        archives,
        truth_binary,
        fold_root / "link.map",
        harness_mode=str(evidence["manifest"]["execution"]["harness_mode"]),
    )
    link_audit = json.loads((fold_root / "link-audit.json").read_text(encoding="utf-8"))
    query_binary = fold_root / f"query{suffix}"
    result = subprocess.run(
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
    if result.returncode != 0 or not query_binary.is_file():
        raise RuntimeError(
            f"query-copy creation failed for {route.id}: {result.stderr[-2000:]}"
        )
    prepared = {
        "schema_version": PREPARED_FOLD_SCHEMA,
        "state": "prepared",
        **identity,
        "prepared_at": _now(),
        "link_harness_policy": LINK_HARNESS_POLICY,
        "query_copy_policy": QUERY_COPY_POLICY,
        "truth_binary": str(truth_binary.relative_to(root)),
        "truth_sha256": _sha256(truth_binary),
        "query_binary": str(query_binary.relative_to(root)),
        "query_sha256": _sha256(query_binary),
        "link_audit": link_audit,
    }
    _atomic_json(marker_path, prepared)
    return prepared


def _prepare_position(
    root: Path,
    evidence: Mapping[str, object],
    run_root: Path,
    position: int,
    mode: str,
    requested_folds: Iterable[str] | None = None,
) -> int:
    units = {int(unit["position"]): unit for unit in evidence["manifest"]["work_unit"]}
    routes = {route.id: route for route in evidence["configuration"].routes}
    treatments = {
        treatment.id: treatment for treatment in evidence["configuration"].treatments
    }
    fold_map = {
        "A": evidence["status"]["randomization"]["fold_a"],
        "B": evidence["status"]["randomization"]["fold_b"],
    }
    canary_folds = defaultdict(set)
    for item in evidence["runtime"]["canary"]["folds_by_position"]:
        canary_position, fold = str(item).split(":", 1)
        canary_folds[int(canary_position)].add(fold)
    unit = units[position]
    route = routes[str(unit["route_id"])]
    treatment = treatments[str(unit["treatment_id"])]
    unit_root = _unit_result_path(run_root, unit, position).parent
    if requested_folds is None:
        folds = sorted(canary_folds[position]) if mode == "canary" else ["A", "B"]
    else:
        folds = sorted(set(requested_folds))
        if not folds or any(fold not in {"A", "B"} for fold in folds):
            raise ValueError("validation preparation folds must be A and/or B")
    for fold in folds:
        checkpoint = _load_fold_checkpoint(
            _fold_checkpoint_path(unit_root, fold),
            mode=mode,
            position=position,
            route_id=route.id,
            treatment_id=treatment.id,
            fold=fold,
            runtime_authority_sha256=str(evidence["runtime"]["authority_sha256"]),
        )
        if checkpoint is not None:
            continue
        owners = list(fold_map[fold])
        archive_items = []
        for owner in owners:
            key = (owner, route.id, treatment.id)
            item = evidence["archives"].get(key)
            if item is None:
                item = _rebuild_openssl_archives(
                    root,
                    evidence,
                    route,
                    treatment,
                    run_root / "preparation" / f"{position:03d}" / "openssl",
                )
                evidence["archives"][key] = item
            archive_items.append((owner, item))
        _prepare_fold(
            root,
            evidence,
            route,
            treatment,
            unit_root,
            position,
            fold,
            owners,
            archive_items,
        )
    return position


def _read_signature_rows(path: Path) -> Iterable[dict[str, object]]:
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"signature row is not an object: {path}")
            yield row


def build_reference_index(
    project_root: str | Path, evidence: Mapping[str, object], run_root: Path
) -> Path:
    root = Path(project_root).resolve()
    path = run_root / "reference-index.sqlite3"
    input_digest = hashlib.sha256(
        json.dumps(
            sorted(
                (list(key), value["sha256"])
                for key, value in evidence["signatures"].items()
            ),
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    if path.is_file():
        connection = sqlite3.connect(path)
        try:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key='input_digest'"
            ).fetchone()
            schema = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()
            count = connection.execute(
                "SELECT COUNT(*) FROM reference_owner_signature"
            ).fetchone()[0]
            if (
                row
                and row[0] == input_digest
                and schema
                and schema[0] == REFERENCE_INDEX_SCHEMA
                and count > 0
            ):
                return path
        except sqlite3.Error:
            pass
        finally:
            connection.close()
        path.unlink()
    connection = sqlite3.connect(path)
    try:
        connection.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE reference_identity(
                language TEXT NOT NULL, target_os TEXT NOT NULL, binary_format TEXT NOT NULL,
                full_hash TEXT NOT NULL, specific_hash TEXT NOT NULL,
                additional_size INTEGER NOT NULL, code_size INTEGER NOT NULL,
                owner TEXT NOT NULL, route_id TEXT NOT NULL, treatment_id TEXT NOT NULL,
                function_name TEXT NOT NULL, evidence_path TEXT NOT NULL,
                PRIMARY KEY(
                    target_os, binary_format, language, full_hash, specific_hash,
                    additional_size, code_size, owner, route_id, treatment_id
                )
            ) WITHOUT ROWID;
            CREATE TABLE reference_owner_signature(
                language TEXT NOT NULL, target_os TEXT NOT NULL, binary_format TEXT NOT NULL,
                full_hash TEXT NOT NULL, specific_hash TEXT NOT NULL,
                additional_size INTEGER NOT NULL, code_size INTEGER NOT NULL,
                owner TEXT NOT NULL, function_name TEXT NOT NULL,
                evidence_path TEXT NOT NULL, identity_count INTEGER NOT NULL,
                PRIMARY KEY(
                    target_os, binary_format, language, full_hash, specific_hash,
                    additional_size, code_size, owner
                )
            ) WITHOUT ROWID;
        """)
        routes = {route.id: route for route in evidence["configuration"].routes}
        inserted = 0
        for (owner, route, treatment), item in sorted(evidence["signatures"].items()):
            route_authority = routes[route]
            batch = []
            for row in _read_signature_rows(item["path"]):
                batch.append(
                    (
                        str(row.get("language", row.get("ghidra_language_id", ""))),
                        route_authority.target_os,
                        route_authority.binary_format,
                        str(row["full_hash"]),
                        str(row["specific_hash"]),
                        int(row["specific_hash_additional_size"]),
                        int(row["code_unit_size"]),
                        owner,
                        route,
                        treatment,
                        str(row.get("name", row.get("function_name", ""))),
                        str(item["source"]),
                    )
                )
                if len(batch) >= 5000:
                    before = connection.total_changes
                    connection.executemany(
                        "INSERT OR IGNORE INTO reference_identity VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        batch,
                    )
                    inserted += connection.total_changes - before
                    batch.clear()
            if batch:
                before = connection.total_changes
                connection.executemany(
                    "INSERT OR IGNORE INTO reference_identity VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    batch,
                )
                inserted += connection.total_changes - before
            connection.commit()
        connection.execute("""
            INSERT INTO reference_owner_signature
            SELECT language, target_os, binary_format, full_hash, specific_hash,
                   additional_size, code_size, owner, MIN(function_name),
                   MIN(evidence_path), COUNT(*)
            FROM reference_identity
            GROUP BY target_os, binary_format, language, full_hash, specific_hash,
                     additional_size, code_size, owner
            """)
        connection.execute(
            "INSERT INTO metadata VALUES ('schema_version',?)",
            (REFERENCE_INDEX_SCHEMA,),
        )
        connection.execute(
            "INSERT INTO metadata VALUES ('input_digest',?)", (input_digest,)
        )
        connection.execute("INSERT INTO metadata VALUES ('rows',?)", (str(inserted),))
        connection.commit()
    finally:
        connection.close()
    return path


def _query_index(
    index_path: Path,
    query_path: Path,
    route_id: str,
    treatment_id: str,
    target_os: str,
    binary_format: str,
    include_exact: bool,
) -> tuple[dict[str, set[str]], dict[str, dict[str, str]]]:
    connection = sqlite3.connect(index_path)
    try:
        connection.executescript("""
            CREATE TEMP TABLE query_signature(
                address TEXT, function_name TEXT, language TEXT, full_hash TEXT,
                specific_hash TEXT, additional_size INTEGER, code_size INTEGER
            );
        """)
        rows = [
            (
                str(row.get("address", "")),
                str(row.get("function_name", "")),
                str(row.get("ghidra_language_id", row.get("language", ""))),
                str(row["full_hash"]),
                str(row["specific_hash"]),
                int(row["specific_hash_additional_size"]),
                int(row["code_unit_size"]),
            )
            for row in _read_signature_rows(query_path)
        ]
        connection.executemany(
            "INSERT INTO query_signature VALUES (?,?,?,?,?,?,?)", rows
        )
        exact_clause = (
            ""
            if include_exact
            else """
            AND (
                reference.identity_count > 1
                OR NOT EXISTS (
                    SELECT 1
                    FROM reference_identity AS exact
                    WHERE exact.target_os=reference.target_os
                      AND exact.binary_format=reference.binary_format
                      AND exact.language=reference.language
                      AND exact.full_hash=reference.full_hash
                      AND exact.specific_hash=reference.specific_hash
                      AND exact.additional_size=reference.additional_size
                      AND exact.code_size=reference.code_size
                      AND exact.owner=reference.owner
                      AND exact.route_id=? AND exact.treatment_id=?
                )
            )
        """
        )
        parameters = () if include_exact else (route_id, treatment_id)
        matches: dict[str, set[str]] = defaultdict(set)
        examples: dict[str, dict[str, str]] = {}
        sql = f"""
            SELECT query.address, query.function_name, reference.owner,
                   reference.function_name, reference.evidence_path,
                   query.full_hash, query.specific_hash, query.additional_size, query.code_size
            FROM query_signature AS query
            CROSS JOIN reference_owner_signature AS reference
              ON reference.target_os=? AND reference.binary_format=?
             AND reference.language=query.language AND reference.full_hash=query.full_hash
             AND reference.specific_hash=query.specific_hash
             AND reference.additional_size=query.additional_size AND reference.code_size=query.code_size
            WHERE 1=1 {exact_clause}
        """
        for row in connection.execute(sql, (target_os, binary_format, *parameters)):
            (
                address,
                query_name,
                owner,
                corpus_name,
                evidence_path,
                full_hash,
                specific_hash,
                additional,
                size,
            ) = row
            signature = f"{full_hash}:{specific_hash}:{additional}:{size}"
            matches[str(owner)].add(f"{address}:{signature}")
            examples.setdefault(
                str(owner),
                {
                    "function_id": str(query_name or address),
                    "signature": signature,
                    "candidate_owner": str(owner),
                    "evidence_path": str(evidence_path),
                    "corpus_function": str(corpus_name),
                },
            )
        return matches, examples
    finally:
        connection.close()


def _rebuild_openssl_archives(
    root: Path, evidence: Mapping[str, object], route, treatment, worker_root: Path
) -> dict[str, object]:
    from .pipeline import build_library, detect_project, extract_source

    source_archive = _inside(
        root, str(evidence["runtime"]["source_archive"]), "OpenSSL source archive"
    )
    configuration = evidence["configuration"]
    library = configuration.libraries[0]
    marker = worker_root / "source-root.txt"
    if not marker.is_file():
        extracted = worker_root / "extracted"
        source_root = extract_source(library, source_archive, extracted, verified=True)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(str(source_root), encoding="utf-8")
    else:
        source_root = Path(marker.read_text(encoding="utf-8"))
        if not source_root.is_dir():
            raise ValueError("cached OpenSSL validation source root is missing")
    detection = detect_project(library, source_root)
    work = worker_root / "work"
    record, _objects = build_library(
        library,
        route,
        treatment,
        detection,
        source_root,
        work,
        worker_root / "logs",
        build_jobs_per_cell=int(
            evidence["runtime"]["execution"]["build_jobs_per_cell"]
        ),
    )
    if record.status != "built":
        raise RuntimeError(record.error or "OpenSSL archive reconstruction failed")
    paths = [
        (work.parent / value).resolve()
        for value in record.static_archive_path.split(";")
    ]
    return {
        "paths": paths,
        "sha256": record.static_archive_sha256.split(";"),
        "source": "validation-rebuild",
    }


def _worker(
    project_root: str | Path,
    runtime_path: str | Path,
    run_id: str,
    positions: list[int],
    mode: str,
) -> int:
    root = Path(project_root).resolve()
    evidence = _resolve_worker_evidence(root, runtime_path)
    run_root = _run_root(root, evidence["runtime"], run_id)
    index = (
        _inside(root, str(evidence["runtime"]["output_root"]), "validation output")
        / "reference-index.sqlite3"
    )
    if not index.is_file():
        raise ValueError("machine-validation reference index is absent")
    configuration = evidence["configuration"]
    routes = {route.id: route for route in configuration.routes}
    treatments = {treatment.id: treatment for treatment in configuration.treatments}
    units = {int(unit["position"]): unit for unit in evidence["manifest"]["work_unit"]}
    fold_map = {
        "A": evidence["status"]["randomization"]["fold_a"],
        "B": evidence["status"]["randomization"]["fold_b"],
    }
    canary_folds = defaultdict(set)
    for item in evidence["runtime"]["canary"]["folds_by_position"]:
        position, fold = str(item).split(":", 1)
        canary_folds[int(position)].add(fold)
    os.environ["GHIDRA_HEADLESS"] = str(evidence["runtime"]["ghidra_headless"])
    execution = evidence["runtime"]["execution"]
    os.environ["_JAVA_OPTIONS"] = (
        f'-Xms{execution["jvm_initial_heap_mib"]}m -Xmx{execution["jvm_max_heap_mib"]}m '
        f'-XX:ActiveProcessorCount={execution["jvm_active_processors"]}'
    )
    from . import ghidra_fid
    from .pipeline import find_ghidra, ghidra_environment

    _headless, ghidra_home = find_ghidra()
    ghidra_fid.ensure_started(
        ghidra_home,
        ghidra_environment(run_root / f"worker-{os.getpid()}" / "ghidra-user"),
    )
    _write_worker_progress(run_root, "idle")
    failed_positions = 0
    for position in positions:
        unit = units[position]
        result_path = _unit_result_path(run_root, unit, position)
        unit_root = result_path.parent
        if result_path.is_file():
            previous = json.loads(result_path.read_text(encoding="utf-8"))
            if previous.get("state") in {"complete", "failed"}:
                continue
        if not _claim_position(run_root, position):
            continue
        if result_path.is_file():
            previous = json.loads(result_path.read_text(encoding="utf-8"))
            if previous.get("state") in {"complete", "failed"}:
                _release_position_claim(run_root, position)
                continue
            _archive_failed_result(result_path)
        route = routes[str(unit["route_id"])]
        treatment = treatments[str(unit["treatment_id"])]
        query_analysis_policy = _query_analysis_policy(result_path, route)
        folds = sorted(canary_folds[position]) if mode == "canary" else ["A", "B"]
        fold_results = []
        started_ns = time.monotonic_ns()
        _write_worker_progress(
            run_root,
            "running",
            position=position,
            started_unix_ns=time.time_ns(),
        )
        try:
            for fold in folds:
                fold_root = unit_root / f"fold-{fold}"
                checkpoint_path = _fold_checkpoint_path(unit_root, fold)
                checkpoint = _load_fold_checkpoint(
                    checkpoint_path,
                    mode=mode,
                    position=position,
                    route_id=route.id,
                    treatment_id=treatment.id,
                    fold=fold,
                    runtime_authority_sha256=str(
                        evidence["runtime"]["authority_sha256"]
                    ),
                )
                if checkpoint is not None:
                    fold_results.append(checkpoint)
                    continue
                owners = list(fold_map[fold])
                prepared = _load_prepared_fold(
                    root,
                    _prepared_fold_path(unit_root, fold),
                    position=position,
                    route_id=route.id,
                    treatment_id=treatment.id,
                    fold=fold,
                    runtime_authority_sha256=str(
                        evidence["runtime"]["authority_sha256"]
                    ),
                )
                if prepared is None:
                    _prepare_position(root, evidence, run_root, position, mode)
                    prepared = _load_prepared_fold(
                        root,
                        _prepared_fold_path(unit_root, fold),
                        position=position,
                        route_id=route.id,
                        treatment_id=treatment.id,
                        fold=fold,
                        runtime_authority_sha256=str(
                            evidence["runtime"]["authority_sha256"]
                        ),
                    )
                if prepared is None:
                    raise RuntimeError(
                        f"prepared validation fold is unavailable: {position}:{fold}"
                    )
                truth_binary = _inside(
                    root, str(prepared["truth_binary"]), "prepared truth"
                )
                query_binary = _inside(
                    root, str(prepared["query_binary"]), "prepared query"
                )
                link_audit = prepared["link_audit"]
                project_parent = (
                    run_root
                    / f"worker-{os.getpid()}"
                    / "projects"
                    / f"{position:03d}-{fold}"
                )
                project_dir, program_path = ghidra_fid.analyze_target(
                    query_binary,
                    project_parent,
                    "composite",
                    route.ghidra_language,
                    route.ghidra_compiler_spec,
                    analysis_policy=query_analysis_policy,
                )
                query_signatures = fold_root / "query-signatures.jsonl"
                signature_summary = ghidra_fid.export_program_signatures(
                    project_dir, "composite", program_path, query_signatures
                )
                matches, examples = _query_index(
                    index,
                    query_signatures,
                    route.id,
                    treatment.id,
                    route.target_os,
                    route.binary_format,
                    mode == "canary",
                )
                threshold = int(
                    evidence["runtime"]["canary" if mode == "canary" else "execution"][
                        "minimum_distinct_hashes"
                    ]
                )
                positive = {
                    owner
                    for owner, values in matches.items()
                    if len(values) >= threshold
                }
                cohort = set(evidence["status"]["randomization"]["canonical_ids"])
                present = set(owners)
                absent = cohort - present
                failures = []
                for owner in sorted(absent & positive):
                    failures.append(
                        {
                            "failure_type": "collision",
                            "library_id": owner,
                            **examples[owner],
                        }
                    )
                for owner in sorted(present - positive):
                    failures.append(
                        {
                            "failure_type": "miss",
                            "library_id": owner,
                            "function_id": "",
                            "signature": "",
                            "candidate_owner": "",
                            "evidence_path": str(query_signatures.relative_to(root)),
                        }
                    )
                fold_result = {
                    "fold": fold,
                    "binary_format": route.binary_format,
                    "link_harness_policy": LINK_HARNESS_POLICY,
                    "query_analysis_policy": query_analysis_policy,
                    "link_audit": link_audit,
                    "query_sha256": prepared["query_sha256"],
                    "truth_sha256": prepared["truth_sha256"],
                    "signature_summary": signature_summary,
                    "owner_match_counts": {
                        owner: len(matches.get(owner, set()))
                        for owner in sorted(cohort)
                    },
                    "positive_owners": sorted(positive),
                    "confusion_matrix": {
                        "true_positives": len(present & positive),
                        "false_positives": len(absent & positive),
                        "true_negatives": len(absent - positive),
                        "false_negatives": len(present - positive),
                    },
                    "failures": failures,
                }
                fold_results.append(fold_result)
                _write_fold_checkpoint(
                    checkpoint_path,
                    fold_result,
                    mode=mode,
                    position=position,
                    route_id=route.id,
                    treatment_id=treatment.id,
                    fold=fold,
                    runtime_authority_sha256=str(
                        evidence["runtime"]["authority_sha256"]
                    ),
                )
                if not execution["retain_ghidra_projects_on_success"]:
                    shutil.rmtree(project_parent, ignore_errors=True)
            document = {
                "schema_version": UNIT_RESULT_SCHEMA,
                "state": "complete",
                "mode": mode,
                "position": position,
                "route_id": route.id,
                "profile_id": unit["profile_id"],
                "treatment_id": treatment.id,
                "query_analysis_policy": query_analysis_policy,
                "started_at": _now(),
                "wall_time_ns": time.monotonic_ns() - started_ns,
                "folds": fold_results,
            }
            _atomic_json(result_path, document)
            _write_worker_progress(run_root, "idle", position=position)
        except Exception as error:
            _atomic_json(
                result_path,
                {
                    "schema_version": UNIT_RESULT_SCHEMA,
                    "state": "failed",
                    "mode": mode,
                    "position": position,
                    "route_id": route.id,
                    "treatment_id": treatment.id,
                    "query_analysis_policy": query_analysis_policy,
                    "wall_time_ns": time.monotonic_ns() - started_ns,
                    "error": f"{type(error).__name__}: {error}",
                    "folds": fold_results,
                },
            )
            _write_worker_progress(run_root, "idle", position=position)
            failed_positions += 1
            if not execution["continue_after_cell_failure"]:
                _release_position_claim(run_root, position)
                _write_worker_progress(run_root, "finished", position=position)
                return 1
        _release_position_claim(run_root, position)
    _write_worker_progress(run_root, "finished")
    return int(failed_positions > 0)


def _aggregate(
    run_root: Path,
    validation_id: str,
    mode: str,
    expected_positions: set[int],
    minimum_hashes: int,
    max_failure_rows: int,
    runtime: Mapping[str, object],
) -> dict[str, object]:
    results = []
    for path in sorted((run_root / "units").glob("*/result.json")):
        row = json.loads(path.read_text(encoding="utf-8"))
        if (
            row.get("mode") == mode
            and int(row.get("position", -1)) in expected_positions
        ):
            results.append(row)
    failed = [row for row in results if row.get("state") == "failed"]
    matrix = {
        "true_positives": 0,
        "false_positives": 0,
        "true_negatives": 0,
        "false_negatives": 0,
    }
    failures = []
    wall_time_ns = 0
    query_analysis_policies: dict[str, int] = defaultdict(int)
    for row in results:
        wall_time_ns += int(row.get("wall_time_ns", 0))
        for fold in row.get("folds", []):
            query_analysis_policies[
                str(fold.get("query_analysis_policy") or QUERY_ANALYSIS_POLICY)
            ] += 1
            for key in matrix:
                matrix[key] += int(fold["confusion_matrix"][key])
            for failure in fold.get("failures", []):
                failures.append(
                    {
                        **failure,
                        "route_id": str(row["route_id"]),
                        "compiler_id": str(row["route_id"]),
                        "treatment_id": str(row["treatment_id"]),
                    }
                )
    complete_positions = {
        int(row["position"]) for row in results if row.get("state") == "complete"
    }
    complete = not failed and complete_positions == expected_positions
    report = {
        "schema_version": (
            "fidb-machine-validation-canary/v1"
            if mode == "canary"
            else "fidb-machine-validation-report/v1"
        ),
        "validation_id": validation_id,
        "state": "measured-complete" if complete else "failed",
        "mode": mode,
        "finished_at": _now(),
        "runtime_authority": runtime["authority_path"],
        "runtime_authority_sha256": runtime["authority_sha256"],
        "canary_contract_sha256": _canary_contract_sha256(runtime),
        "reference_index_schema": REFERENCE_INDEX_SCHEMA,
        "link_harness_policy": LINK_HARNESS_POLICY,
        "query_copy_policy": QUERY_COPY_POLICY,
        "query_analysis_policy": QUERY_ANALYSIS_POLICY,
        "query_analysis_recovery_policy": QUERY_ANALYSIS_RECOVERY_POLICY,
        "query_analysis_policy_folds": dict(sorted(query_analysis_policies.items())),
        "confusion_matrix": {"unit": "owner-labelled-candidate-decision", **matrix},
        "failure_summary": {
            "collisions": sum(row["failure_type"] == "collision" for row in failures),
            "misses": sum(row["failure_type"] == "miss" for row in failures),
        },
        "failures": failures[:max_failure_rows],
        "metrics": {
            "expected_work_units": len(expected_positions),
            "complete_work_units": len(complete_positions),
            "failed_work_units": len(failed),
            "worker_sum_wall_time_ns": wall_time_ns,
            "minimum_distinct_hashes": minimum_hashes,
            "failure_rows_truncated": max(0, len(failures) - max_failure_rows),
        },
    }
    return report


def _canary_contract_sha256(runtime: Mapping[str, object]) -> str:
    """Hash inputs which can change canary meaning, excluding operations tuning."""

    contract = {
        "validation_id": runtime.get("validation_id"),
        "manifest": runtime.get("manifest"),
        "source_archive": runtime.get("source_archive"),
        "openssl_width_report": runtime.get("openssl_width_report"),
        "ghidra_headless": runtime.get("ghidra_headless"),
        "canary": runtime.get("canary"),
        "reference_index_schema": REFERENCE_INDEX_SCHEMA,
        "link_harness_policy": LINK_HARNESS_POLICY,
        "query_copy_policy": QUERY_COPY_POLICY,
    }
    canonical = json.dumps(contract, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def _legacy_canary_contract_matches(
    document: Mapping[str, object], runtime: Mapping[str, object]
) -> bool:
    """Recognise pre-contract-digest canaries by every retained semantic field."""

    metrics = document.get("metrics")
    canary = runtime.get("canary")
    if not isinstance(metrics, dict) or not isinstance(canary, dict):
        return False
    expected = len(canary.get("positions", []))
    return (
        document.get("canary_contract_sha256") is None
        and document.get("schema_version") == "fidb-machine-validation-canary/v1"
        and document.get("validation_id") == runtime.get("validation_id")
        and document.get("mode") == "canary"
        and metrics.get("expected_work_units") == expected
        and metrics.get("complete_work_units") == expected
        and metrics.get("failed_work_units") == 0
        and metrics.get("minimum_distinct_hashes")
        == canary.get("minimum_distinct_hashes")
    )


def canary_gate_status(
    project_root: str | Path,
    runtime_path: str | Path = DEFAULT_RUNTIME,
) -> dict[str, object]:
    """Return the latest canary compatible with the current runtime contract."""

    root = Path(project_root).resolve()
    runtime = load_runtime(root, runtime_path)
    contract_sha256 = _canary_contract_sha256(runtime)
    output_root = _inside(root, str(runtime["output_root"]), "validation output")
    reports = sorted(
        output_root.glob("*-canary/canary-report.json"),
        key=lambda path: path.stat().st_mtime_ns,
        reverse=True,
    )
    latest = None
    for path in reports:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if latest is None:
            latest = {
                "run_id": path.parent.name,
                "report_path": str(path.relative_to(root)),
                "state": document.get("state", "invalid"),
            }
        semantic_contract_matches = document.get(
            "canary_contract_sha256"
        ) == contract_sha256 or _legacy_canary_contract_matches(document, runtime)
        if (
            document.get("state") == "measured-complete"
            and semantic_contract_matches
            and document.get("reference_index_schema") == REFERENCE_INDEX_SCHEMA
            and document.get("link_harness_policy") == LINK_HARNESS_POLICY
            and document.get("query_copy_policy") == QUERY_COPY_POLICY
        ):
            return {
                "ready": True,
                "state": "passed",
                "run_id": path.parent.name,
                "report_path": str(path.relative_to(root)),
                "runtime_authority_sha256": runtime["authority_sha256"],
                "canary_contract_sha256": contract_sha256,
                "legacy_contract": document.get("canary_contract_sha256") is None,
            }
    return {
        "ready": False,
        "state": "not-run" if latest is None else "stale-or-failed",
        "run_id": None if latest is None else latest["run_id"],
        "report_path": None if latest is None else latest["report_path"],
        "runtime_authority_sha256": runtime["authority_sha256"],
        "canary_contract_sha256": contract_sha256,
    }


def _post_validation_retention(
    root: Path, runtime: Mapping[str, object], run_id: str
) -> dict[str, object]:
    """Run the shared, dry-run-first collector without invalidating the report."""

    try:
        from .retention import automatic_retention, load_retention_policy

        policy = load_retention_policy(root)
        if (
            not policy.validation_enabled
            or not policy.validation_automatic_after_terminal_run
        ):
            return {
                "state": "disabled",
                "trigger": "machine-validation-complete",
                "scope": "machine-validation",
            }
        return automatic_retention(
            root,
            str(runtime["ledger"]),
            trigger="machine-validation-complete",
            session_id=f"machine-validation-{run_id}",
        )
    except (OSError, RuntimeError, ValueError) as error:
        return {
            "state": "failed-safely",
            "trigger": "machine-validation-complete",
            "scope": "machine-validation",
            "error": f"{type(error).__name__}: {error}",
        }


def _spawn_validation_worker(
    root: Path,
    runtime_path: str | Path,
    run_root: Path,
    run_id: str,
    mode: str,
    worker_id: int,
    positions: list[int],
    restarts: int = 0,
) -> dict[str, object]:
    log_path = run_root / f"worker-{worker_id:02d}.log"
    with log_path.open("ab", buffering=0) as log:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "fidb_poc.cli",
                "machine-validation",
                "_worker",
                "--project-root",
                str(root),
                "--runtime",
                str(runtime_path),
                "--run-id",
                run_id,
                "--mode",
                mode,
                "--positions",
                ",".join(map(str, positions)),
            ],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
        )
    return {
        "worker_id": worker_id,
        "process": process,
        "positions": positions,
        "restarts": restarts,
        "handled": False,
    }


def _live_worker_processes(
    workers: Iterable[Mapping[str, object]],
) -> list[subprocess.Popen[bytes]]:
    return [
        process
        for worker in workers
        if isinstance((process := worker.get("process")), subprocess.Popen)
        and process.poll() is None
    ]


def run_validation(
    project_root: str | Path,
    mode: str,
    runtime_path: str | Path = DEFAULT_RUNTIME,
    run_id: str | None = None,
) -> dict[str, object]:
    if mode not in {"canary", "full"}:
        raise ValueError("machine-validation mode must be canary or full")
    root = Path(project_root).resolve()
    evidence = resolve_evidence(root, runtime_path)
    if evidence["blockers"]:
        raise ValueError("; ".join(evidence["blockers"]))
    runtime = evidence["runtime"]
    if run_id is None:
        run_id = f'{datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")}-{mode}'
    run_root = _run_root(root, runtime, run_id)
    admission, qualification_plan, qualification_status = _resolve_link_qualification(
        root, run_id, evidence
    )
    if not admission["ready"]:
        raise ValueError(
            "machine-validation link qualification is not satisfied: "
            + "; ".join(str(value) for value in admission.get("blockers", []))
        )
    output_root = _inside(root, str(runtime["output_root"]), "validation output")
    output_root.mkdir(parents=True, exist_ok=True)
    run_root.mkdir(parents=True, exist_ok=True)
    if qualification_plan is None:
        _atomic_json(
            run_root / "link-qualification.json",
            {
                "schema_version": "fidb-machine-validation-link-reuse/v1",
                **admission,
                "recorded_at": _now(),
            },
        )
    current_path = output_root / "current.json"
    lock = output_root / ".runner.lock"
    descriptor = None
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.write(descriptor, f"{os.getpid()}\n".encode())
    except FileExistsError as error:
        raise ValueError("another machine-validation run is already active") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    positions = (
        {int(value) for value in runtime["canary"]["positions"]}
        if mode == "canary"
        else {int(unit["position"]) for unit in evidence["manifest"]["work_unit"]}
    )
    status_path = run_root / "status.json"
    prior_status = {}
    if status_path.is_file():
        try:
            prior_status = json.loads(status_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            prior_status = {}
    started = str(prior_status.get("started_at") or _now())
    attempt_started = _now()
    resume_count = int(prior_status.get("resume_count", 0))
    complete_count, failed_count = _result_counts(run_root, mode)
    pause_request = run_root / PAUSE_REQUEST_NAME
    hash_job = evidence["manifest"]["hash_discrimination_job"]
    postprocess_job = (
        {
            "id": str(hash_job["id"]),
            "kind": str(hash_job["kind"]),
            "state": "planned",
            "materialized_with_batch": True,
            "required_for_run_completion": True,
            "stages": [
                {"id": str(stage), "state": "pending"} for stage in hash_job["stages"]
            ],
        }
        if mode == "full"
        else None
    )
    postprocess_started = False
    workers: list[dict[str, object]] = []
    _atomic_json(
        current_path, {"run_id": run_id, "path": str(status_path.relative_to(root))}
    )
    _atomic_json(
        status_path,
        {
            "schema_version": RUN_STATUS_SCHEMA,
            "validation_id": runtime["validation_id"],
            "run_id": run_id,
            "mode": mode,
            "state": "preparing-index",
            "pid": os.getpid(),
            "started_at": started,
            "attempt_started_at": attempt_started,
            "resume_count": resume_count,
            "finished_at": None,
            "expected_work_units": len(positions),
            "complete_work_units": complete_count,
            "failed_work_units": failed_count,
            "postprocess_job": postprocess_job,
        },
    )
    try:
        index = build_reference_index(root, evidence, output_root)
        if mode == "full":
            gate = canary_gate_status(root, runtime_path)
            if not gate["ready"]:
                raise ValueError(
                    "full machine validation requires a completed canary for the "
                    "current runtime and reference-index contract"
                )
        units = {
            int(unit["position"]): unit for unit in evidence["manifest"]["work_unit"]
        }
        pending = sorted(
            positions - _terminal_positions(run_root, mode, units, positions)
        )
        pending = _cost_aware_positions(run_root, units, pending, mode)
        if qualification_plan is not None:
            from .machine_validation_links import reuse_qualified_links

            reuse_qualified_links(
                root,
                evidence,
                run_root,
                set(pending),
                _plan=qualification_plan,
                _status=qualification_status,
            )
        shutil.rmtree(run_root / "claims", ignore_errors=True)
        _atomic_json(
            run_root / "scheduling-order.json",
            {
                "schema_version": "fidb-machine-validation-scheduling-order/v1",
                "policy": runtime["execution"]["scheduling_policy"],
                "created_at": _now(),
                "positions": pending,
            },
        )
        prepared_count = 0
        preparation_failed_count = 0
        preparation_workers = int(runtime["execution"]["preparation_workers"])
        preparation_batch_size = int(runtime["execution"]["preparation_batch_size"])
        for offset in range(0, len(pending), preparation_batch_size):
            if pause_request.is_file():
                break
            batch = pending[offset : offset + preparation_batch_size]
            _atomic_json(
                status_path,
                {
                    "schema_version": RUN_STATUS_SCHEMA,
                    "validation_id": runtime["validation_id"],
                    "run_id": run_id,
                    "mode": mode,
                    "state": "preparing-units",
                    "pid": os.getpid(),
                    "worker_pids": [],
                    "started_at": started,
                    "attempt_started_at": attempt_started,
                    "resume_count": resume_count,
                    "finished_at": None,
                    "expected_work_units": len(positions),
                    "complete_work_units": _result_counts(run_root, mode)[0],
                    "failed_work_units": _result_counts(run_root, mode)[1],
                    "prepared_work_units": prepared_count,
                    "preparation_failed_work_units": preparation_failed_count,
                    "expected_preparation_work_units": len(pending),
                    "postprocess_job": postprocess_job,
                },
            )
            with ThreadPoolExecutor(
                max_workers=min(preparation_workers, len(batch))
            ) as executor:
                futures = {
                    executor.submit(
                        _prepare_position,
                        root,
                        evidence,
                        run_root,
                        position,
                        mode,
                    ): position
                    for position in batch
                }
                for future in as_completed(futures):
                    position = futures[future]
                    try:
                        future.result()
                        prepared_count += 1
                    except Exception as error:
                        preparation_failed_count += 1
                        _supervisor_failure(
                            run_root,
                            units[position],
                            position,
                            mode,
                            "preparation-failed",
                            f"{type(error).__name__}: {error}",
                        )
        worker_count = min(int(runtime["execution"]["workers"]), len(pending))
        if not pause_request.is_file():
            for index in range(1, worker_count + 1):
                workers.append(
                    _spawn_validation_worker(
                        root,
                        runtime_path,
                        run_root,
                        run_id,
                        mode,
                        index,
                        pending,
                    )
                )
        pause_requested = False
        while True:
            documents = _result_documents(run_root, mode)
            if pause_request.is_file():
                pause_requested = True
                live_processes = _live_worker_processes(workers)
                _atomic_json(
                    status_path,
                    {
                        "schema_version": RUN_STATUS_SCHEMA,
                        "validation_id": runtime["validation_id"],
                        "run_id": run_id,
                        "mode": mode,
                        "state": "pausing",
                        "pid": os.getpid(),
                        "worker_pids": [process.pid for process in live_processes],
                        "started_at": started,
                        "attempt_started_at": attempt_started,
                        "resume_count": resume_count,
                        "finished_at": None,
                        "expected_work_units": len(positions),
                        "complete_work_units": sum(
                            row.get("state") == "complete" for row in documents
                        ),
                        "failed_work_units": sum(
                            row.get("state") == "failed" for row in documents
                        ),
                        "postprocess_job": postprocess_job,
                    },
                )
                _terminate_worker_groups(live_processes)
                break
            for worker in workers:
                process = worker["process"]
                if not isinstance(process, subprocess.Popen):
                    raise TypeError("validation worker process record is invalid")
                if process.poll() is None:
                    timed_out = _timed_out_position(
                        run_root,
                        process.pid,
                        int(runtime["execution"]["cell_timeout_seconds"]),
                        time.time_ns(),
                    )
                    if timed_out is not None:
                        _terminate_worker_groups([process])
                        _release_worker_claims(run_root, process.pid)
                        result_path = _supervisor_failure(
                            run_root,
                            units[timed_out],
                            timed_out,
                            mode,
                            "cell-timeout",
                            "validation cell exceeded the configured supervisor timeout",
                        )
                        attempt = (
                            _prior_supervisor_attempts(result_path, "cell-timeout") + 1
                        )
                        if (
                            attempt < int(runtime["execution"]["cell_timeout_attempts"])
                            and json.loads(result_path.read_text(encoding="utf-8")).get(
                                "reason_code"
                            )
                            == "cell-timeout"
                        ):
                            _archive_failed_result(result_path)
                if process.poll() is not None and not worker["handled"]:
                    released = _release_worker_claims(run_root, process.pid)
                    terminal = _terminal_positions(run_root, mode, units, positions)
                    remaining = [
                        position for position in pending if position not in terminal
                    ]
                    if _worker_finished_cleanly(run_root, process.pid):
                        worker["handled"] = True
                    elif remaining and int(worker["restarts"]) < int(
                        runtime["execution"]["maximum_worker_restarts"]
                    ):
                        replacement = _spawn_validation_worker(
                            root,
                            runtime_path,
                            run_root,
                            run_id,
                            mode,
                            int(worker["worker_id"]),
                            pending,
                            int(worker["restarts"]) + 1,
                        )
                        worker.update(replacement)
                    else:
                        if released:
                            for position in released:
                                _supervisor_failure(
                                    run_root,
                                    units[position],
                                    position,
                                    mode,
                                    "worker-restarts-exhausted",
                                    "validation worker exited before completing its claimed unit",
                                )
                        worker["handled"] = True
            if all(bool(worker["handled"]) for worker in workers):
                break
            live_processes = _live_worker_processes(workers)
            _atomic_json(
                status_path,
                {
                    "schema_version": RUN_STATUS_SCHEMA,
                    "validation_id": runtime["validation_id"],
                    "run_id": run_id,
                    "mode": mode,
                    "state": "running",
                    "pid": os.getpid(),
                    "worker_pids": [process.pid for process in live_processes],
                    "worker_restarts": sum(
                        int(worker["restarts"]) for worker in workers
                    ),
                    "started_at": started,
                    "attempt_started_at": attempt_started,
                    "resume_count": resume_count,
                    "finished_at": None,
                    "expected_work_units": len(positions),
                    "complete_work_units": sum(
                        row.get("state") == "complete" for row in documents
                    ),
                    "failed_work_units": sum(
                        row.get("state") == "failed" for row in documents
                    ),
                    "postprocess_job": postprocess_job,
                },
            )
            time.sleep(int(runtime["execution"]["worker_poll_seconds"]))
        if pause_requested:
            complete_count, failed_count = _result_counts(run_root, mode)
            paused = {
                "schema_version": RUN_STATUS_SCHEMA,
                "validation_id": runtime["validation_id"],
                "run_id": run_id,
                "mode": mode,
                "state": "paused",
                "pid": os.getpid(),
                "worker_pids": [],
                "started_at": started,
                "attempt_started_at": attempt_started,
                "resume_count": resume_count,
                "finished_at": None,
                "paused_at": _now(),
                "expected_work_units": len(positions),
                "complete_work_units": complete_count,
                "failed_work_units": failed_count,
                "postprocess_job": postprocess_job,
            }
            _atomic_json(status_path, paused)
            return paused
        minimum = int(
            runtime["canary" if mode == "canary" else "execution"][
                "minimum_distinct_hashes"
            ]
        )
        report = _aggregate(
            run_root,
            str(runtime["validation_id"]),
            mode,
            positions,
            minimum,
            int(runtime["execution"]["max_failure_rows"]),
            runtime,
        )
        report_path = run_root / (
            "canary-report.json" if mode == "canary" else "report.json"
        )
        _atomic_json(report_path, report)
        full_postprocess = report["state"] == "measured-complete" and mode == "full"
        completed_status = {
            "schema_version": RUN_STATUS_SCHEMA,
            "validation_id": runtime["validation_id"],
            "run_id": run_id,
            "mode": mode,
            "state": (
                "postprocessing"
                if full_postprocess
                else "complete" if report["state"] == "measured-complete" else "failed"
            ),
            "pid": os.getpid(),
            "worker_pids": [],
            "worker_restarts": sum(int(worker["restarts"]) for worker in workers),
            "started_at": started,
            "finished_at": _now(),
            "expected_work_units": len(positions),
            "attempt_started_at": attempt_started,
            "resume_count": resume_count,
            "complete_work_units": report["metrics"]["complete_work_units"],
            "failed_work_units": report["metrics"]["failed_work_units"],
            "report_path": str(report_path.relative_to(root)),
            "postprocess_job": (
                {
                    **postprocess_job,
                    "state": "running",
                    "stages": [
                        {
                            **stage,
                            "state": (
                                "running"
                                if stage["id"] == "classify-signatures"
                                else "pending"
                            ),
                        }
                        for stage in postprocess_job["stages"]
                    ],
                }
                if full_postprocess and postprocess_job
                else postprocess_job
            ),
        }
        _atomic_json(status_path, completed_status)
        if full_postprocess:
            # Keep report.json as evidence of the superseded thresholded
            # implementation.  The status-bound scientific report is rebuilt
            # from every retained signature with no acceptance threshold.
            from .machine_validation_hashes import analyze_hashes

            postprocess_started = True
            report = analyze_hashes(root, run_id, runtime_path=runtime_path)
            completed_status = json.loads(status_path.read_text(encoding="utf-8"))
        if report["state"] == "measured-complete":
            # The retention collector refuses to touch validation scratch while
            # this lock exists. Release it only after the terminal report and
            # status are durable, then record the independent cleanup outcome.
            lock.unlink(missing_ok=True)
            retaining_status = {
                **completed_status,
                "state": "retaining",
            }
            if retaining_status.get("postprocess_job"):
                retaining_status["postprocess_job"] = {
                    **retaining_status["postprocess_job"],
                    "state": "running",
                    "stages": [
                        {
                            **stage,
                            "state": (
                                "running" if stage["id"] == "retention" else "complete"
                            ),
                        }
                        for stage in retaining_status["postprocess_job"]["stages"]
                    ],
                }
            _atomic_json(status_path, retaining_status)
            retention = _post_validation_retention(root, runtime, run_id)
            _atomic_json(run_root / "retention.json", retention)
            final_status = {
                **retaining_status,
                "state": "complete",
                "finished_at": _now(),
            }
            if final_status.get("postprocess_job"):
                final_status["postprocess_job"] = {
                    **final_status["postprocess_job"],
                    "state": "complete",
                    "stages": [
                        {**stage, "state": "complete"}
                        for stage in final_status["postprocess_job"]["stages"]
                    ],
                }
            _atomic_json(
                status_path,
                {
                    **final_status,
                    "retention": {
                        key: retention.get(key)
                        for key in (
                            "state",
                            "trigger",
                            "scope",
                            "plan_digest",
                            "estimated_apply_seconds",
                            "error",
                        )
                        if retention.get(key) is not None
                    },
                },
            )
        return report
    except Exception as error:
        _terminate_worker_groups(_live_worker_processes(workers))
        failed_state = "postprocess-failed" if postprocess_started else "failed"
        _atomic_json(
            status_path,
            {
                "schema_version": RUN_STATUS_SCHEMA,
                "validation_id": runtime["validation_id"],
                "run_id": run_id,
                "mode": mode,
                "state": failed_state,
                "pid": os.getpid(),
                "started_at": started,
                "finished_at": _now(),
                "expected_work_units": len(positions),
                "attempt_started_at": attempt_started,
                "resume_count": resume_count,
                "complete_work_units": _result_counts(run_root, mode)[0],
                "failed_work_units": _failed_work_unit_count(
                    run_root,
                    mode,
                    postprocess_started=postprocess_started,
                ),
                "error": f"{type(error).__name__}: {error}",
                "postprocess_job": (
                    {
                        **postprocess_job,
                        "state": "failed",
                        "error": f"{type(error).__name__}: {error}",
                    }
                    if postprocess_started and postprocess_job
                    else postprocess_job
                ),
            },
        )
        raise
    finally:
        lock.unlink(missing_ok=True)


def runtime_status(
    project_root: str | Path, runtime_path: str | Path = DEFAULT_RUNTIME
) -> dict[str, object]:
    root = Path(project_root).resolve()
    runtime = load_runtime(root, runtime_path)
    current = (
        _inside(root, str(runtime["output_root"]), "validation output") / "current.json"
    )
    if not current.is_file():
        return {
            "state": "not-started",
            "run_id": None,
            "mode": None,
            "complete_work_units": 0,
            "failed_work_units": 0,
        }
    pointer = json.loads(current.read_text(encoding="utf-8"))
    status_path = _inside(root, str(pointer["path"]), "validation run status")
    if not status_path.is_file():
        return {
            "state": "invalid",
            "run_id": pointer.get("run_id"),
            "mode": None,
            "complete_work_units": 0,
            "failed_work_units": 0,
        }
    status = json.loads(status_path.read_text(encoding="utf-8"))
    if status.get("state") in {
        "queued",
        "preparing-index",
        "preparing-units",
        "running",
        "pausing",
        "postprocessing",
        "retaining",
    }:
        run_id = str(status.get("run_id") or "")
        if not _validation_process_active(status.get("pid"), run_id):
            status = {**status, "state": "interrupted", "worker_pids": []}
    return status


def _current_status_path(root: Path, runtime: Mapping[str, object]) -> Path:
    current = (
        _inside(root, str(runtime["output_root"]), "validation output") / "current.json"
    )
    if not current.is_file():
        raise ValueError("machine validation has no current run")
    pointer = json.loads(current.read_text(encoding="utf-8"))
    status_path = _inside(root, str(pointer["path"]), "validation run status")
    if not status_path.is_file():
        raise ValueError("machine validation current status is missing")
    return status_path


def _clear_stale_lock(output_root: Path, run_id: str) -> None:
    lock = output_root / ".runner.lock"
    if not lock.is_file():
        return
    try:
        pid = int(lock.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        pid = 0
    if _validation_process_active(pid, run_id):
        raise ValueError("machine-validation run process is still active")
    lock.unlink(missing_ok=True)


def _spawn_validation(
    root: Path,
    runtime_path: str | Path,
    mode: str,
    run_id: str,
    log_path: Path,
) -> subprocess.Popen[bytes]:
    with log_path.open("ab", buffering=0) as log:
        return subprocess.Popen(
            [
                sys.executable,
                "-m",
                "fidb_poc.cli",
                "machine-validation",
                "run",
                "--project-root",
                str(root),
                "--runtime",
                str(runtime_path),
                "--mode",
                mode,
                "--run-id",
                run_id,
            ],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
        )


def pause_validation(
    project_root: str | Path,
    runtime_path: str | Path = DEFAULT_RUNTIME,
    *,
    actor: str = "operator",
) -> dict[str, object]:
    root = Path(project_root).resolve()
    runtime = load_runtime(root, runtime_path)
    status_path = _current_status_path(root, runtime)
    status = runtime_status(root, runtime_path)
    if status.get("state") == "paused":
        return status
    if status.get("state") == "interrupted" or (
        status.get("state") == "failed"
        and int(status.get("complete_work_units", 0))
        < int(status.get("expected_work_units", 0))
        and not _validation_process_active(
            status.get("pid"), str(status.get("run_id") or "")
        )
    ):
        paused = {
            **status,
            "state": "paused",
            "paused_at": _now(),
            "pause_actor": actor,
            "worker_pids": [],
        }
        _atomic_json(status_path, paused)
        return paused
    if status.get("state") not in {
        "queued",
        "preparing-index",
        "preparing-units",
        "running",
        "pausing",
    }:
        raise ValueError("machine validation is not active")
    run_id = str(status["run_id"])
    requested_at = _now()
    _atomic_json(
        status_path.parent / PAUSE_REQUEST_NAME,
        {
            "schema_version": "fidb-machine-validation-pause-request/v1",
            "run_id": run_id,
            "requested_at": requested_at,
            "actor": actor,
        },
    )
    pausing = {
        **status,
        "state": "pausing",
        "pause_requested_at": requested_at,
        "pause_actor": actor,
    }
    _atomic_json(status_path, pausing)
    return pausing


def requeue_failed_validation(
    project_root: str | Path,
    positions: Iterable[int],
    runtime_path: str | Path = DEFAULT_RUNTIME,
    *,
    actor: str = "operator",
) -> dict[str, object]:
    """Preserve failed evidence and make only the named cells resumable."""

    root = Path(project_root).resolve()
    runtime = load_runtime(root, runtime_path)
    status_path = _current_status_path(root, runtime)
    status = runtime_status(root, runtime_path)
    if status.get("state") not in {"paused", "interrupted", "failed"}:
        raise ValueError(
            "machine validation must be stopped before failed cells requeue"
        )
    run_id = str(status.get("run_id") or "")
    if not run_id or _validation_process_active(status.get("pid"), run_id):
        raise ValueError("machine-validation run process is still active")
    requested = sorted(set(positions))
    if not requested or any(
        type(position) is not int or position < 1 for position in requested
    ):
        raise ValueError("failed-cell requeue requires positive positions")
    run_root = status_path.parent
    evidence = resolve_evidence(root, runtime_path)
    units = {int(unit["position"]): unit for unit in evidence["manifest"]["work_unit"]}
    unknown = sorted(set(requested) - set(units))
    if unknown:
        raise ValueError(f"unknown validation positions: {unknown}")
    candidates = []
    for position in requested:
        path = _unit_result_path(run_root, units[position], position)
        try:
            result = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(
                f"validation position {position} has no failed result"
            ) from error
        if result.get("state") != "failed" or result.get("mode") != status.get("mode"):
            raise ValueError(f"validation position {position} is not failed")
        candidates.append((position, path, _sha256(path)))
    archived_rows = []
    for position, path, digest in candidates:
        archived = _archive_failed_result(path)
        if archived is None:
            raise RuntimeError(f"failed result could not be archived: {position}")
        archived_rows.append(
            {
                "position": position,
                "result_sha256": digest,
                "archived_path": str(archived.relative_to(root)),
            }
        )
    receipts = run_root / "requeues"
    receipt_number = 1
    while (receipts / f"requeue-{receipt_number:03d}.json").exists():
        receipt_number += 1
    receipt_path = receipts / f"requeue-{receipt_number:03d}.json"
    receipt = {
        "schema_version": "fidb-machine-validation-requeue/v1",
        "run_id": run_id,
        "mode": status["mode"],
        "actor": actor,
        "requeued_at": _now(),
        "positions": requested,
        "archived_results": archived_rows,
    }
    _atomic_json(receipt_path, receipt)
    complete_count, failed_count = _result_counts(run_root, str(status["mode"]))
    _atomic_json(
        status_path,
        {
            **status,
            "state": "paused",
            "worker_pids": [],
            "complete_work_units": complete_count,
            "failed_work_units": failed_count,
            "last_requeue_receipt": str(receipt_path.relative_to(root)),
        },
    )
    return {
        **receipt,
        "receipt_path": str(receipt_path.relative_to(root)),
        "remaining_failed_work_units": failed_count,
    }


def resume_validation(
    project_root: str | Path,
    runtime_path: str | Path = DEFAULT_RUNTIME,
    *,
    foreground: bool = False,
) -> dict[str, object]:
    root = Path(project_root).resolve()
    runtime = load_runtime(root, runtime_path)
    status_path = _current_status_path(root, runtime)
    status = runtime_status(root, runtime_path)
    if status.get("state") == "complete":
        run_id = str(status.get("run_id") or "")
        mode = str(status.get("mode") or "")
        expected = int(status.get("expected_work_units", 0))
        if (
            mode not in {"canary", "full"}
            or not run_id
            or expected < 1
            or int(status.get("complete_work_units", 0)) != expected
            or int(status.get("failed_work_units", 0)) != 0
        ):
            raise ValueError(
                "completed machine validation has inconsistent cell evidence"
            )
        if mode == "full":
            postprocess = status.get("postprocess_job", {})
            stages = (
                postprocess.get("stages", []) if isinstance(postprocess, dict) else []
            )
            if (
                postprocess.get("state") != "complete"
                or not stages
                or any(stage.get("state") != "complete" for stage in stages)
            ):
                raise ValueError(
                    "completed machine validation has incomplete postprocessing"
                )
            hash_report_path = status_path.parent / "hash-report.json"
            retention_path = status_path.parent / "retention.json"
            try:
                hash_report = json.loads(hash_report_path.read_text(encoding="utf-8"))
                retention = json.loads(retention_path.read_text(encoding="utf-8"))
            except (OSError, ValueError, json.JSONDecodeError) as error:
                raise ValueError(
                    "completed machine validation lacks terminal postprocess evidence"
                ) from error
            if (
                hash_report.get("state") != "measured-complete"
                or hash_report.get("run_id") != run_id
                or retention.get("state") != "complete"
            ):
                raise ValueError(
                    "completed machine validation terminal evidence is inconsistent"
                )
        return status
    postprocess_retry = status.get("state") == "postprocess-failed"
    if status.get("state") not in {
        "paused",
        "interrupted",
        "failed",
        "postprocess-failed",
    }:
        raise ValueError("machine validation is not resumable")
    run_id = str(status.get("run_id") or "")
    mode = str(status.get("mode") or "")
    if mode not in {"canary", "full"} or not run_id:
        raise ValueError("machine validation resume identity is invalid")
    expected = int(status.get("expected_work_units", 0))
    if postprocess_retry:
        actual_complete, actual_failed = _result_counts(status_path.parent, mode)
        if mode != "full" or actual_complete != expected or actual_failed != 0:
            raise ValueError(
                "postprocess retry requires a sealed full run with no failed cells"
            )
    else:
        actual_complete = int(status.get("complete_work_units", 0))
        actual_failed = int(status.get("failed_work_units", 0))
    if not postprocess_retry and actual_complete >= expected:
        raise ValueError("machine validation has no incomplete work to resume")
    if _validation_process_active(status.get("pid"), run_id):
        raise ValueError("machine-validation run process is still active")
    pre = preflight(root, runtime_path)
    if pre["state"] != "ready":
        raise ValueError("; ".join(pre["blockers"]))
    admission, _plan, _status = _resolve_link_qualification(root, run_id)
    if not admission["ready"]:
        raise ValueError(
            "machine-validation link qualification is not satisfied: "
            + "; ".join(str(value) for value in admission.get("blockers", []))
        )
    if mode == "full" and not canary_gate_status(root, runtime_path)["ready"]:
        raise ValueError(
            "full machine validation requires a completed canary for the current "
            "runtime and reference-index contract"
        )
    output_root = _inside(root, str(runtime["output_root"]), "validation output")
    _clear_stale_lock(output_root, run_id)
    (status_path.parent / PAUSE_REQUEST_NAME).unlink(missing_ok=True)
    resume_count = int(status.get("resume_count", 0)) + 1
    queued = {
        **status,
        "state": "queued",
        "pid": None,
        "worker_pids": [],
        "finished_at": None,
        "resumed_at": _now(),
        "resume_count": resume_count,
        "complete_work_units": actual_complete,
        "failed_work_units": actual_failed,
    }
    queued.pop("error", None)
    queued.pop("report_path", None)
    _atomic_json(status_path, queued)
    if foreground:
        return run_validation(root, mode, runtime_path, run_id)
    log_path = status_path.parent / "run.log"
    process = _spawn_validation(root, runtime_path, mode, run_id, log_path)
    queued["pid"] = process.pid
    _atomic_json(status_path, queued)
    return {
        "state": "queued",
        "run_id": run_id,
        "mode": mode,
        "pid": process.pid,
        "resume_count": resume_count,
        "complete_work_units": actual_complete,
        "failed_work_units": actual_failed,
        "log_path": str(log_path.relative_to(root)),
    }


def start_validation(
    project_root: str | Path,
    mode: str,
    runtime_path: str | Path = DEFAULT_RUNTIME,
    run_id: str | None = None,
) -> dict[str, object]:
    if mode not in {"canary", "full"}:
        raise ValueError("machine-validation mode must be canary or full")
    root = Path(project_root).resolve()
    pre = preflight(root, runtime_path)
    if pre["state"] != "ready":
        raise ValueError("; ".join(pre["blockers"]))
    current = runtime_status(root, runtime_path)
    if current.get("state") in {
        "preparing-index",
        "preparing-units",
        "running",
        "queued",
        "pausing",
        "postprocessing",
        "retaining",
    }:
        raise ValueError("machine validation is already running")
    if current.get("state") == "postprocess-failed":
        raise ValueError(
            "recover the completed run's required hash-discrimination job before starting another run"
        )
    if current.get("state") in {"paused", "interrupted"}:
        raise ValueError(
            "resume or explicitly retire the checkpointed machine-validation run"
        )
    if mode == "full" and not canary_gate_status(root, runtime_path)["ready"]:
        raise ValueError(
            "full machine validation requires a completed canary for the current "
            "runtime and reference-index contract"
        )
    if run_id is None:
        run_id = f'{datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")}-{mode}'
    runtime = load_runtime(root, runtime_path)
    run_root = _run_root(root, runtime, run_id)
    if run_root.exists():
        raise ValueError(
            f"machine-validation run id already exists: {run_id}; "
            "resume its checkpoint or choose a new immutable run id"
        )
    admission, _plan, _status = _resolve_link_qualification(root, run_id)
    if not admission["ready"]:
        raise ValueError(
            "machine-validation link qualification is not satisfied: "
            + "; ".join(str(value) for value in admission.get("blockers", []))
        )
    run_root.mkdir(parents=True, exist_ok=True)
    log_path = run_root / "run.log"
    status_path = run_root / "status.json"
    output_root = _inside(root, str(runtime["output_root"]), "validation output")
    output_root.mkdir(parents=True, exist_ok=True)
    _atomic_json(
        status_path,
        {
            "schema_version": RUN_STATUS_SCHEMA,
            "validation_id": runtime["validation_id"],
            "run_id": run_id,
            "mode": mode,
            "state": "queued",
            "pid": None,
            "started_at": _now(),
            "finished_at": None,
            "expected_work_units": 0,
            "complete_work_units": 0,
            "failed_work_units": 0,
            "resume_count": 0,
        },
    )
    _atomic_json(
        output_root / "current.json",
        {"run_id": run_id, "path": str(status_path.relative_to(root))},
    )
    process = _spawn_validation(root, runtime_path, mode, run_id, log_path)
    queued = json.loads(status_path.read_text(encoding="utf-8"))
    queued["pid"] = process.pid
    _atomic_json(status_path, queued)
    return {
        "state": "queued",
        "run_id": run_id,
        "mode": mode,
        "pid": process.pid,
        "log_path": str(log_path.relative_to(root)),
    }
