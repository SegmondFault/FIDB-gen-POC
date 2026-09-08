"""Durable files, checkpoints, claims, and process state for machine validation."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time
from typing import Iterable, Mapping

from .validation_analysis import QUERY_ANALYSIS_POLICY, QUERY_ANALYSIS_RECOVERY_POLICY

FOLD_RESULT_SCHEMA = "fidb-machine-validation-fold-result/v1"
UNIT_RESULT_SCHEMA = "fidb-machine-validation-unit/v1"
WORK_CLAIM_SCHEMA = "fidb-machine-validation-work-claim/v1"
QUERY_EVIDENCE_CONTRACT = "fidb-integrated-query-evidence/v1"


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
            "evidence_contract": QUERY_EVIDENCE_CONTRACT,
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
