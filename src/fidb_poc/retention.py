"""Dry-run-first retention and garbage collection for queue attempts.

The collector treats the SQLite ledger as runtime truth and TOML as retention
authority.  It never makes a completed queue result disappear: successful
attempts remain complete until a relationship-complete lane import receipt is
present. Failed attempts are reduced only after a self-verifying evidence
bundle has been written, and earlier retries are collapsed only when their
normalised failure fingerprints match the retained representative.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
import time
import tomllib
from typing import Iterator, Mapping, Sequence

POLICY_SCHEMA = "fidb-retention-policy/v1"
HOLDS_SCHEMA = "fidb-retention-holds/v1"
PLAN_SCHEMA = "fidb-retention-plan/v1"
STATE_SCHEMA = "fidb-retention-state/v1"
BUNDLE_SCHEMA = "fidb-failure-evidence/v1"
RECEIPT_SCHEMA = "fidb-lane-import-receipt/v1"
MEMORY_AUDIT_SCHEMA = "fidb-memory-cleanup-audit/v1"
DEFAULT_POLICY = Path("retention/policy.toml")
DEFAULT_LEDGER = Path("var/fidb-coordinator/ledger.sqlite3")
_JOB_ID = re.compile(r"job-[0-9a-f]{64}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_STAGING = re.compile(r"(job-[0-9a-f]{64})-g([1-9][0-9]*)-[A-Za-z0-9_-]+\Z")


class RetentionError(RuntimeError):
    """Retention authority, evidence, or lifecycle state is unsafe."""


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _only_keys(value: Mapping[str, object], allowed: set[str], label: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise ValueError(f"{label} has unsupported fields: {sorted(unknown)}")


def _table(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a TOML table")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{label} must be a non-empty string without outer whitespace")
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be true or false")
    return value


def _positive(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{label} must be a non-empty array")
    result = tuple(_text(item, label) for item in value)
    if len(set(result)) != len(result):
        raise ValueError(f"{label} contains duplicates")
    return result


def _inside(
    root: Path, value: str | Path, label: str, *, create_parent: bool = False
) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        resolved = candidate.expanduser().resolve()
    else:
        resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(f"{label} must remain inside the project root") from error
    current = root
    for part in resolved.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"{label} cannot traverse a symlink: {current}")
    if create_parent:
        resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


@dataclass(frozen=True)
class RetentionPolicy:
    root: Path
    source_path: Path
    name: str
    runs: Path
    failure_bundles: Path
    plans: Path
    state: Path
    memory_audits: Path
    lane_import_receipts: Path
    holds_path: Path
    preserve_until_lane_imported: bool
    prune_after_receipt: tuple[str, ...]
    required_result_artifacts: tuple[str, ...]
    retain_latest_evidence_bundle: bool
    collapse_identical_retries: bool
    evidence_globs: tuple[str, ...]
    max_evidence_file_bytes: int
    automation_enabled: bool
    automation_trigger: str
    automation_mode: str
    dry_run_first: bool
    maximum_estimated_seconds: int
    worker_action: str
    memory_cleanup_enabled: bool
    audit_after_recycle: bool
    post_recycle_rss_warning_mib: int
    park_terminal_workers: bool
    park_poll_seconds: int
    maximum_actions: int
    maximum_scan_files: int
    authority_sha256: str

    def document(self) -> dict[str, object]:
        return {
            "schema_version": POLICY_SCHEMA,
            "name": self.name,
            "authority_path": str(self.source_path.relative_to(self.root)),
            "authority_sha256": self.authority_sha256,
            "paths": {
                "runs": str(self.runs.relative_to(self.root)),
                "failure_bundles": str(self.failure_bundles.relative_to(self.root)),
                "plans": str(self.plans.relative_to(self.root)),
                "state": str(self.state.relative_to(self.root)),
                "memory_audits": str(self.memory_audits.relative_to(self.root)),
                "lane_import_receipts": str(
                    self.lane_import_receipts.relative_to(self.root)
                ),
                "holds": str(self.holds_path.relative_to(self.root)),
            },
            "success": {
                "preserve_until_lane_imported": self.preserve_until_lane_imported,
                "prune_after_receipt": list(self.prune_after_receipt),
                "required_result_artifacts": list(self.required_result_artifacts),
            },
            "failure": {
                "retain_latest_evidence_bundle": self.retain_latest_evidence_bundle,
                "collapse_identical_retries": self.collapse_identical_retries,
                "evidence_globs": list(self.evidence_globs),
                "max_evidence_file_bytes": self.max_evidence_file_bytes,
            },
            "automation": {
                "enabled": self.automation_enabled,
                "trigger": self.automation_trigger,
                "mode": self.automation_mode,
                "dry_run_first": self.dry_run_first,
                "maximum_estimated_seconds": self.maximum_estimated_seconds,
                "worker_action": self.worker_action,
            },
            "memory_cleanup": {
                "enabled": self.memory_cleanup_enabled,
                "audit_after_recycle": self.audit_after_recycle,
                "post_recycle_rss_warning_mib": self.post_recycle_rss_warning_mib,
                "park_terminal_workers": self.park_terminal_workers,
                "park_poll_seconds": self.park_poll_seconds,
            },
            "limits": {
                "maximum_actions": self.maximum_actions,
                "maximum_scan_files": self.maximum_scan_files,
            },
        }


def load_retention_policy(
    project_root: str | Path, authority: str | Path = DEFAULT_POLICY
) -> RetentionPolicy:
    root = Path(project_root).expanduser().resolve()
    source = _inside(root, authority, "retention policy")
    payload = source.read_bytes()
    document = tomllib.loads(payload.decode("utf-8"))
    _only_keys(
        document,
        {
            "schema_version",
            "name",
            "paths",
            "success",
            "failure",
            "automation",
            "memory_cleanup",
            "limits",
        },
        "retention policy",
    )
    if document.get("schema_version") != POLICY_SCHEMA:
        raise ValueError("retention policy has unsupported schema_version")
    paths = _table(document.get("paths"), "retention paths")
    success = _table(document.get("success"), "retention success")
    failure = _table(document.get("failure"), "retention failure")
    automation = _table(document.get("automation"), "retention automation")
    memory_cleanup = _table(
        document.get("memory_cleanup"), "retention memory_cleanup"
    )
    limits = _table(document.get("limits"), "retention limits")
    _only_keys(
        paths,
        {
            "runs",
            "failure_bundles",
            "plans",
            "state",
            "memory_audits",
            "lane_import_receipts",
            "holds",
        },
        "retention paths",
    )
    _only_keys(
        success,
        {
            "preserve_until_lane_imported",
            "prune_after_receipt",
            "required_result_artifacts",
        },
        "retention success",
    )
    _only_keys(
        failure,
        {
            "retain_latest_evidence_bundle",
            "collapse_identical_retries",
            "evidence_globs",
            "max_evidence_file_bytes",
        },
        "retention failure",
    )
    _only_keys(
        automation,
        {
            "enabled",
            "trigger",
            "mode",
            "dry_run_first",
            "maximum_estimated_seconds",
            "worker_action",
        },
        "retention automation",
    )
    _only_keys(
        memory_cleanup,
        {
            "enabled",
            "audit_after_recycle",
            "post_recycle_rss_warning_mib",
            "park_terminal_workers",
            "park_poll_seconds",
        },
        "retention memory_cleanup",
    )
    _only_keys(limits, {"maximum_actions", "maximum_scan_files"}, "retention limits")
    trigger = _text(automation.get("trigger"), "retention automation trigger")
    mode = _text(automation.get("mode"), "retention automation mode")
    worker_action = _text(automation.get("worker_action"), "retention worker action")
    if trigger != "queue-drained":
        raise ValueError("retention automation trigger must be queue-drained")
    if mode not in {"plan", "apply"}:
        raise ValueError("retention automation mode must be plan or apply")
    if worker_action not in {"none", "recycle"}:
        raise ValueError("retention worker_action must be none or recycle")
    if not _boolean(automation.get("dry_run_first"), "automation dry_run_first"):
        raise ValueError("retention automation must remain dry-run-first")
    prune = _strings(success.get("prune_after_receipt"), "success prune_after_receipt")
    if any(Path(item).is_absolute() or ".." in Path(item).parts for item in prune):
        raise ValueError("success prune paths must be safe attempt-relative paths")
    globs = _strings(failure.get("evidence_globs"), "failure evidence_globs")
    return RetentionPolicy(
        root=root,
        source_path=source,
        name=_text(document.get("name"), "retention policy name"),
        runs=_inside(root, _text(paths.get("runs"), "runs path"), "runs path"),
        failure_bundles=_inside(
            root,
            _text(paths.get("failure_bundles"), "failure bundles path"),
            "failure bundles path",
        ),
        plans=_inside(root, _text(paths.get("plans"), "plans path"), "plans path"),
        state=_inside(root, _text(paths.get("state"), "state path"), "state path"),
        memory_audits=_inside(
            root,
            _text(paths.get("memory_audits"), "memory audits path"),
            "memory audits path",
        ),
        lane_import_receipts=_inside(
            root,
            _text(paths.get("lane_import_receipts"), "lane receipts path"),
            "lane receipts path",
        ),
        holds_path=_inside(root, _text(paths.get("holds"), "holds path"), "holds path"),
        preserve_until_lane_imported=_boolean(
            success.get("preserve_until_lane_imported"),
            "success preserve_until_lane_imported",
        ),
        prune_after_receipt=prune,
        required_result_artifacts=_strings(
            success.get("required_result_artifacts"),
            "success required_result_artifacts",
        ),
        retain_latest_evidence_bundle=_boolean(
            failure.get("retain_latest_evidence_bundle"),
            "failure retain_latest_evidence_bundle",
        ),
        collapse_identical_retries=_boolean(
            failure.get("collapse_identical_retries"),
            "failure collapse_identical_retries",
        ),
        evidence_globs=globs,
        max_evidence_file_bytes=_positive(
            failure.get("max_evidence_file_bytes"), "failure max_evidence_file_bytes"
        ),
        automation_enabled=_boolean(automation.get("enabled"), "automation enabled"),
        automation_trigger=trigger,
        automation_mode=mode,
        dry_run_first=True,
        maximum_estimated_seconds=_positive(
            automation.get("maximum_estimated_seconds"),
            "automation maximum_estimated_seconds",
        ),
        worker_action=worker_action,
        memory_cleanup_enabled=_boolean(
            memory_cleanup.get("enabled"), "memory_cleanup enabled"
        ),
        audit_after_recycle=_boolean(
            memory_cleanup.get("audit_after_recycle"),
            "memory_cleanup audit_after_recycle",
        ),
        post_recycle_rss_warning_mib=_positive(
            memory_cleanup.get("post_recycle_rss_warning_mib"),
            "memory_cleanup post_recycle_rss_warning_mib",
        ),
        park_terminal_workers=_boolean(
            memory_cleanup.get("park_terminal_workers"),
            "memory_cleanup park_terminal_workers",
        ),
        park_poll_seconds=_positive(
            memory_cleanup.get("park_poll_seconds"),
            "memory_cleanup park_poll_seconds",
        ),
        maximum_actions=_positive(
            limits.get("maximum_actions"), "limits maximum_actions"
        ),
        maximum_scan_files=_positive(
            limits.get("maximum_scan_files"), "limits maximum_scan_files"
        ),
        authority_sha256=hashlib.sha256(payload).hexdigest(),
    )


@dataclass(frozen=True)
class RetentionHold:
    id: str
    job_id: str
    attempt_numbers: tuple[int, ...]
    reason: str

    def matches(self, job_id: str, attempt_number: int | None = None) -> bool:
        return self.job_id == job_id and (
            not self.attempt_numbers
            or attempt_number is None
            or attempt_number in self.attempt_numbers
        )


def load_retention_holds(policy: RetentionPolicy) -> tuple[RetentionHold, ...]:
    document = tomllib.loads(policy.holds_path.read_text(encoding="utf-8"))
    _only_keys(document, {"schema_version", "hold"}, "retention holds")
    if document.get("schema_version") != HOLDS_SCHEMA:
        raise ValueError("retention holds has unsupported schema_version")
    rows = document.get("hold", [])
    if not isinstance(rows, list):
        raise ValueError("retention hold must be an array of tables")
    result = []
    seen = set()
    for index, raw in enumerate(rows, start=1):
        row = _table(raw, f"hold {index}")
        _only_keys(row, {"id", "job_id", "attempt_numbers", "reason"}, f"hold {index}")
        hold_id = _text(row.get("id"), f"hold {index} id")
        job_id = _text(row.get("job_id"), f"hold {index} job_id")
        reason = _text(row.get("reason"), f"hold {index} reason")
        if hold_id in seen or not _JOB_ID.fullmatch(job_id):
            raise ValueError(f"hold {index} has duplicate id or invalid job_id")
        raw_numbers = row.get("attempt_numbers", [])
        if not isinstance(raw_numbers, list) or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 1
            for value in raw_numbers
        ):
            raise ValueError(
                f"hold {index} attempt_numbers must contain positive integers"
            )
        numbers = tuple(raw_numbers)
        if len(set(numbers)) != len(numbers):
            raise ValueError(f"hold {index} attempt_numbers contains duplicates")
        seen.add(hold_id)
        result.append(RetentionHold(hold_id, job_id, numbers, reason))
    return tuple(result)


def _open_ledger(root: Path, ledger: str | Path) -> sqlite3.Connection:
    path = _inside(root, ledger, "retention ledger")
    if not path.is_file() or path.is_symlink():
        raise RetentionError(f"retention ledger is unavailable: {path}")
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    required = {"jobs", "attempts", "stage_attempts", "coordinator_state", "events"}
    tables = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    if not required.issubset(tables):
        connection.close()
        raise RetentionError("retention ledger is missing required coordinator tables")
    return connection


def _relative(root: Path, path: Path) -> str:
    return str(path.resolve().relative_to(root))


def _safe_regular(root: Path, path: Path, label: str) -> Path:
    resolved = _inside(root, path, label)
    if not resolved.is_file() or resolved.is_symlink():
        raise RetentionError(f"{label} is not a regular file: {resolved}")
    return resolved


def _load_json(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RetentionError(f"{label} is not valid JSON: {path}") from error
    if not isinstance(value, dict):
        raise RetentionError(f"{label} must be a JSON object: {path}")
    return value


def _verify_digest(path: Path, expected: object, label: str) -> None:
    if not isinstance(expected, str) or not _SHA256.fullmatch(expected):
        raise RetentionError(f"{label} has no valid SHA-256")
    actual = _sha256(path)
    if actual != expected:
        raise RetentionError(f"{label} SHA-256 mismatch: {path}")


def _verify_success(
    policy: RetentionPolicy, row: sqlite3.Row
) -> tuple[dict[str, object], Path, dict[str, object]]:
    try:
        result = json.loads(str(row["result_json"]))
    except (TypeError, json.JSONDecodeError) as error:
        raise RetentionError("completed job has invalid result JSON") from error
    if not isinstance(result, dict):
        raise RetentionError("completed job result must be an object")
    attempt_value = result.get("attempt_root")
    if not isinstance(attempt_value, str):
        raise RetentionError("completed job has no attempt_root")
    attempt_root = _inside(policy.root, attempt_value, "completed attempt root")
    if not attempt_root.is_dir() or attempt_root.is_symlink():
        raise RetentionError(f"completed attempt root is unavailable: {attempt_root}")
    if attempt_root.parent.name != str(row["job_id"]):
        raise RetentionError("completed attempt root does not match its ledger job")
    artifacts: dict[str, object] = {}
    for name in policy.required_result_artifacts:
        record = result.get(name)
        if not isinstance(record, dict):
            raise RetentionError(f"completed result has no {name} artifact")
        raw_path = record.get("path")
        if not isinstance(raw_path, str):
            raise RetentionError(f"completed {name} artifact has no path")
        path = _safe_regular(policy.root, Path(raw_path), f"completed {name}")
        try:
            path.relative_to(attempt_root)
        except ValueError as error:
            raise RetentionError(
                f"completed {name} escapes its attempt root"
            ) from error
        _verify_digest(path, record.get("sha256"), f"completed {name}")
        artifacts[name] = {
            "path": _relative(policy.root, path),
            "sha256": record["sha256"],
            "bytes": path.stat().st_size,
        }
    seal_record = artifacts.get("seal")
    assert isinstance(seal_record, dict)
    seal = _load_json(policy.root / str(seal_record["path"]), "cell seal")
    if seal.get("schema_version") != "fidb-cell-seal/v1":
        raise RetentionError("completed cell seal has unsupported schema")
    if seal.get("cell", {}).get("id") != result.get("cell_id"):
        raise RetentionError("completed cell seal does not bind the ledger result")
    sealed_artifacts = seal.get("artifacts")
    if not isinstance(sealed_artifacts, dict):
        raise RetentionError("completed cell seal has no artifacts table")
    for name in ("fidb", "fidbf"):
        sealed = sealed_artifacts.get(name)
        retained = artifacts.get(name)
        if not isinstance(sealed, dict) or not isinstance(retained, dict):
            raise RetentionError(f"cell seal does not describe {name}")
        if sealed.get("sha256") != retained.get("sha256") or sealed.get(
            "bytes"
        ) != retained.get("bytes"):
            raise RetentionError(f"cell seal {name} does not match retained result")
    return (
        result,
        attempt_root,
        {"artifacts": artifacts, "seal_sha256": seal_record["sha256"]},
    )


def _valid_lane_receipt(
    policy: RetentionPolicy,
    job_id: str,
    attempt_root: Path,
    seal_sha256: str,
) -> tuple[bool, str | None]:
    path = policy.lane_import_receipts / f"{job_id}.json"
    if not path.exists():
        return False, None
    try:
        receipt = _load_json(
            _safe_regular(policy.root, path, "lane import receipt"),
            "lane import receipt",
        )
    except RetentionError as error:
        return False, str(error)
    valid = (
        receipt.get("schema_version") == RECEIPT_SCHEMA
        and receipt.get("job_id") == job_id
        and receipt.get("attempt_root") == _relative(policy.root, attempt_root)
        and receipt.get("seal_sha256") == seal_sha256
        and receipt.get("relationship_complete") is True
        and isinstance(receipt.get("lane_generation"), str)
        and bool(receipt.get("lane_generation"))
    )
    return valid, (
        None
        if valid
        else "lane import receipt does not bind relationship-complete evidence"
    )


def _attempt_stats(path: Path, maximum_files: int) -> dict[str, int]:
    apparent = 0
    allocated = 0
    files = 0
    directories = 0
    if path.is_symlink():
        raise RetentionError(f"refusing symlinked retention target: {path}")
    for current, names, filenames in os.walk(path, followlinks=False):
        directories += 1
        current_path = Path(current)
        for name in names:
            if (current_path / name).is_symlink():
                raise RetentionError(
                    f"refusing tree containing symlinked directory: {current_path / name}"
                )
        for name in filenames:
            candidate = current_path / name
            if candidate.is_symlink() or not candidate.is_file():
                raise RetentionError(
                    f"refusing non-regular retention member: {candidate}"
                )
            stat_result = candidate.stat()
            files += 1
            if files > maximum_files:
                raise RetentionError("retention scan exceeded maximum_scan_files")
            apparent += stat_result.st_size
            allocated += stat_result.st_blocks * 512
    return {
        "files": files,
        "directories": directories,
        "apparent_bytes": apparent,
        "allocated_bytes": allocated,
    }


def _normalise_failure(value: str, attempt_root: Path) -> str:
    result = value.replace(str(attempt_root), "<attempt-root>")
    result = re.sub(
        r"job-[0-9a-f]{64}-g[1-9][0-9]*-[A-Za-z0-9_-]+", "<attempt>", result
    )
    return result


def _failure_fingerprint(
    attempt: sqlite3.Row, stages: Sequence[sqlite3.Row], attempt_root: Path
) -> tuple[str, dict[str, object]]:
    failed = [
        stage for stage in stages if str(stage["state"]) in {"failed", "interrupted"}
    ]
    evidence = {
        "attempt_state": str(attempt["state"]),
        "attempt_error": _normalise_failure(str(attempt["error"] or ""), attempt_root),
        "failed_stages": [
            {
                "stage": str(stage["stage"]),
                "state": str(stage["state"]),
                "error": _normalise_failure(str(stage["error"] or ""), attempt_root),
            }
            for stage in failed
        ],
    }
    return _digest(evidence), evidence


def _evidence_files(
    policy: RetentionPolicy, attempt_root: Path
) -> tuple[list[dict[str, object]], str | None]:
    selected: list[dict[str, object]] = []
    seen: set[str] = set()
    for current, directories, files in os.walk(attempt_root, followlinks=False):
        current_path = Path(current)
        directories[:] = [
            name for name in directories if not (current_path / name).is_symlink()
        ]
        for name in files:
            path = current_path / name
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(attempt_root).as_posix()
            if relative in seen or not any(
                fnmatch.fnmatch(relative, pattern) for pattern in policy.evidence_globs
            ):
                continue
            size = path.stat().st_size
            if size > policy.max_evidence_file_bytes:
                return (
                    [],
                    f"evidence file exceeds {policy.max_evidence_file_bytes} bytes: {relative}",
                )
            seen.add(relative)
            selected.append(
                {"relative_path": relative, "bytes": size, "sha256": _sha256(path)}
            )
    selected.sort(key=lambda row: str(row["relative_path"]))
    return selected, None


def _hold_for(
    holds: Sequence[RetentionHold], job_id: str, attempt_number: int | None = None
) -> RetentionHold | None:
    return next((hold for hold in holds if hold.matches(job_id, attempt_number)), None)


def _ledger_fingerprint(connection: sqlite3.Connection) -> dict[str, object]:
    state = connection.execute(
        "SELECT sync_generation, synced_at FROM coordinator_state WHERE singleton=1"
    ).fetchone()
    counts = {
        str(row["state"]): int(row["n"])
        for row in connection.execute(
            "SELECT state, COUNT(*) n FROM jobs GROUP BY state"
        )
    }
    attempts = connection.execute(
        "SELECT COUNT(*) n, MAX(attempt_id) maximum FROM attempts"
    ).fetchone()
    return {
        "sync_generation": int(state["sync_generation"]),
        "synced_at": state["synced_at"],
        "job_counts": counts,
        "attempt_count": int(attempts["n"]),
        "maximum_attempt_id": int(attempts["maximum"] or 0),
    }


def _latest_session(connection: sqlite3.Connection) -> str:
    row = connection.execute(
        "SELECT event_id, occurred_at FROM events WHERE event_type='batch.drained' ORDER BY event_id DESC LIMIT 1"
    ).fetchone()
    if row is not None:
        return f"batch-drained-{int(row['event_id'])}"
    attempt = connection.execute(
        "SELECT MAX(attempt_id) maximum FROM attempts"
    ).fetchone()
    return f"attempt-{int(attempt['maximum'] or 0)}"


def current_retention_session(
    project_root: str | Path,
    ledger: str | Path = DEFAULT_LEDGER,
) -> str:
    root = Path(project_root).expanduser().resolve()
    connection = _open_ledger(root, ledger)
    try:
        return _latest_session(connection)
    finally:
        connection.close()


def compile_retention_plan(
    project_root: str | Path,
    ledger: str | Path = DEFAULT_LEDGER,
    authority: str | Path = DEFAULT_POLICY,
) -> dict[str, object]:
    started = time.monotonic_ns()
    generated_at = datetime.now(timezone.utc).isoformat()
    policy = load_retention_policy(project_root, authority)
    holds = load_retention_holds(policy)
    actions: list[dict[str, object]] = []
    preserved: list[dict[str, object]] = []
    quarantined: list[dict[str, object]] = []
    verified_successes = 0
    connection = _open_ledger(policy.root, ledger)
    try:
        ledger_fingerprint = _ledger_fingerprint(connection)
        session_id = _latest_session(connection)
        jobs = {
            str(row["job_id"]): row
            for row in connection.execute("SELECT * FROM jobs ORDER BY job_id")
        }
        attempts_by_job: dict[str, list[sqlite3.Row]] = {}
        for row in connection.execute(
            "SELECT * FROM attempts ORDER BY job_id, attempt_number, attempt_id"
        ):
            attempts_by_job.setdefault(str(row["job_id"]), []).append(row)

        for job_id, job in jobs.items():
            if str(job["state"]) != "complete":
                continue
            hold = _hold_for(holds, job_id)
            try:
                _result, attempt_root, verification = _verify_success(policy, job)
            except RetentionError as error:
                quarantined.append(
                    {
                        "kind": "completed-attempt",
                        "job_id": job_id,
                        "reason": str(error),
                    }
                )
                continue
            verified_successes += 1
            if hold is not None:
                preserved.append(
                    {
                        "kind": "completed-attempt",
                        "job_id": job_id,
                        "path": _relative(policy.root, attempt_root),
                        "reason": f"hold:{hold.id}",
                        "detail": hold.reason,
                    }
                )
                continue
            receipt_valid, receipt_error = _valid_lane_receipt(
                policy, job_id, attempt_root, str(verification["seal_sha256"])
            )
            if receipt_error:
                quarantined.append(
                    {
                        "kind": "lane-import-receipt",
                        "job_id": job_id,
                        "reason": receipt_error,
                    }
                )
            if policy.preserve_until_lane_imported and not receipt_valid:
                preserved.append(
                    {
                        "kind": "completed-attempt",
                        "job_id": job_id,
                        "path": _relative(policy.root, attempt_root),
                        "reason": "awaiting-relationship-complete-lane-import",
                    }
                )
                continue
            for relative in policy.prune_after_receipt:
                target = _inside(
                    policy.root, attempt_root / relative, "successful scratch target"
                )
                if not target.exists():
                    continue
                try:
                    stats = _attempt_stats(target, policy.maximum_scan_files)
                except RetentionError as error:
                    quarantined.append(
                        {
                            "kind": "completed-scratch",
                            "job_id": job_id,
                            "path": _relative(policy.root, target),
                            "reason": str(error),
                        }
                    )
                    continue
                actions.append(
                    {
                        "kind": "prune-success-scratch",
                        "job_id": job_id,
                        "paths": [_relative(policy.root, target)],
                        "receipt_verified": receipt_valid,
                        **stats,
                    }
                )

        known_staging: set[Path] = set()
        for job_id, attempts in attempts_by_job.items():
            failed_attempts = [
                attempt
                for attempt in attempts
                if str(attempt["state"]) in {"failed", "expired"}
            ]
            if not failed_attempts:
                continue
            candidates = []
            for attempt in failed_attempts:
                generation = int(attempt["lease_generation"])
                matches = sorted(policy.runs.glob(f"staging/{job_id}-g{generation}-*"))
                if len(matches) != 1:
                    quarantined.append(
                        {
                            "kind": "failed-attempt",
                            "job_id": job_id,
                            "attempt_number": int(attempt["attempt_number"]),
                            "reason": f"expected one staging directory, found {len(matches)}",
                        }
                    )
                    continue
                root = matches[0]
                known_staging.add(root.resolve())
                hold = _hold_for(holds, job_id, int(attempt["attempt_number"]))
                if hold is not None:
                    preserved.append(
                        {
                            "kind": "failed-attempt",
                            "job_id": job_id,
                            "attempt_number": int(attempt["attempt_number"]),
                            "path": _relative(policy.root, root),
                            "reason": f"hold:{hold.id}",
                            "detail": hold.reason,
                        }
                    )
                    continue
                stages = connection.execute(
                    "SELECT * FROM stage_attempts WHERE attempt_id=? ORDER BY sequence, stage_attempt_id",
                    (int(attempt["attempt_id"]),),
                ).fetchall()
                fingerprint, fingerprint_evidence = _failure_fingerprint(
                    attempt, stages, root
                )
                candidates.append(
                    (attempt, root, stages, fingerprint, fingerprint_evidence)
                )
            if not candidates:
                continue
            representative = max(
                candidates,
                key=lambda item: (
                    int(item[0]["attempt_number"]),
                    int(item[0]["attempt_id"]),
                ),
            )
            rep_attempt, rep_root, rep_stages, fingerprint, fingerprint_evidence = (
                representative
            )
            collapsible = [representative]
            for candidate in candidates:
                if candidate is representative:
                    continue
                if policy.collapse_identical_retries and candidate[3] == fingerprint:
                    collapsible.append(candidate)
                else:
                    quarantined.append(
                        {
                            "kind": "failed-attempt",
                            "job_id": job_id,
                            "attempt_number": int(candidate[0]["attempt_number"]),
                            "path": _relative(policy.root, candidate[1]),
                            "reason": "failure fingerprint differs from retained representative",
                            "failure_fingerprint": candidate[3],
                        }
                    )
            if not policy.retain_latest_evidence_bundle:
                preserved.extend(
                    {
                        "kind": "failed-attempt",
                        "job_id": job_id,
                        "attempt_number": int(item[0]["attempt_number"]),
                        "path": _relative(policy.root, item[1]),
                        "reason": "failure bundling disabled",
                    }
                    for item in collapsible
                )
                continue
            files, evidence_error = _evidence_files(policy, rep_root)
            if evidence_error:
                quarantined.append(
                    {
                        "kind": "failed-attempt",
                        "job_id": job_id,
                        "attempt_number": int(rep_attempt["attempt_number"]),
                        "path": _relative(policy.root, rep_root),
                        "reason": evidence_error,
                    }
                )
                continue
            stats = {
                "files": 0,
                "directories": 0,
                "apparent_bytes": 0,
                "allocated_bytes": 0,
            }
            safe = True
            for item in collapsible:
                try:
                    item_stats = _attempt_stats(item[1], policy.maximum_scan_files)
                except RetentionError as error:
                    quarantined.append(
                        {
                            "kind": "failed-attempt",
                            "job_id": job_id,
                            "attempt_number": int(item[0]["attempt_number"]),
                            "path": _relative(policy.root, item[1]),
                            "reason": str(error),
                        }
                    )
                    safe = False
                    break
                for field in stats:
                    stats[field] += item_stats[field]
            if not safe:
                continue
            bundle = (
                policy.failure_bundles
                / job_id
                / fingerprint[:16]
                / f"attempt-{int(rep_attempt['attempt_id'])}"
            )
            actions.append(
                {
                    "kind": "bundle-failed-attempts",
                    "job_id": job_id,
                    "job_state": str(jobs.get(job_id, {"state": "inactive"})["state"]),
                    "batch_id": str(
                        jobs.get(job_id, {"batch_id": "unknown"})["batch_id"]
                    ),
                    "base_cell_id": str(
                        jobs.get(job_id, {"base_cell_id": "unknown"})["base_cell_id"]
                    ),
                    "representative_attempt_id": int(rep_attempt["attempt_id"]),
                    "representative_attempt_number": int(rep_attempt["attempt_number"]),
                    "failure_fingerprint": fingerprint,
                    "failure_evidence": fingerprint_evidence,
                    "source_paths": [
                        _relative(policy.root, item[1]) for item in collapsible
                    ],
                    "collapsed_attempts": [
                        int(item[0]["attempt_number"]) for item in collapsible
                    ],
                    "bundle_path": _relative(policy.root, bundle),
                    "evidence_files": files,
                    "stage_evidence": [
                        {
                            "attempt_number": int(item[0]["attempt_number"]),
                            "attempt_id": int(item[0]["attempt_id"]),
                            "state": str(item[0]["state"]),
                            "started_at": str(item[0]["started_at"]),
                            "ended_at": item[0]["ended_at"],
                            "error": _normalise_failure(
                                str(item[0]["error"] or ""), item[1]
                            ),
                            "failed_stages": [
                                {
                                    "stage": str(stage["stage"]),
                                    "state": str(stage["state"]),
                                    "error": _normalise_failure(
                                        str(stage["error"] or ""), item[1]
                                    ),
                                    "details": json.loads(str(stage["details_json"])),
                                    "metrics": json.loads(str(stage["metrics_json"])),
                                }
                                for stage in item[2]
                                if str(stage["state"]) in {"failed", "interrupted"}
                            ],
                        }
                        for item in collapsible
                    ],
                    **stats,
                }
            )

        staging_root = policy.runs / "staging"
        if staging_root.is_dir():
            for path in staging_root.iterdir():
                if not path.is_dir() or path.is_symlink():
                    quarantined.append(
                        {
                            "kind": "unknown-staging",
                            "path": _relative(policy.root, path),
                            "reason": "non-directory or symlink in staging root",
                        }
                    )
                elif path.resolve() not in known_staging:
                    match = _STAGING.fullmatch(path.name)
                    quarantined.append(
                        {
                            "kind": "unknown-staging",
                            "path": _relative(policy.root, path),
                            "reason": (
                                "no unique failed ledger attempt owns staging directory"
                                if match
                                else "unrecognised staging directory name"
                            ),
                        }
                    )
    finally:
        connection.close()

    if len(actions) > policy.maximum_actions:
        raise RetentionError(
            f"retention plan exceeds maximum_actions={policy.maximum_actions}"
        )
    summary = {
        "verified_successes": verified_successes,
        "actions": len(actions),
        "failure_bundles": sum(
            row["kind"] == "bundle-failed-attempts" for row in actions
        ),
        "success_scratch_prunes": sum(
            row["kind"] == "prune-success-scratch" for row in actions
        ),
        "source_directories": sum(
            len(row["paths"] if "paths" in row else row["source_paths"])
            for row in actions
        ),
        "recoverable_apparent_bytes": sum(
            int(row["apparent_bytes"]) for row in actions
        ),
        "recoverable_allocated_bytes": sum(
            int(row["allocated_bytes"]) for row in actions
        ),
        "preserved": len(preserved),
        "quarantined": len(quarantined),
    }
    plan_basis = {
        "schema_version": PLAN_SCHEMA,
        "policy": policy.document(),
        "ledger": ledger_fingerprint,
        "session_id": session_id,
        "actions": actions,
        "preserved": preserved,
        "quarantined": quarantined,
        "summary": summary,
    }
    elapsed = time.monotonic_ns() - started
    estimate = max(
        elapsed / 1_000_000_000,
        summary["source_directories"] * 0.02
        + summary["recoverable_allocated_bytes"] / (256 * 1024 * 1024),
    )
    return {
        **plan_basis,
        "plan_digest": _digest(plan_basis),
        "generated_at": generated_at,
        "scan_duration_ns": elapsed,
        "estimated_apply_seconds": round(estimate, 3),
        # Quarantined paths are absent from actions, so independent verified
        # actions can still be collected safely.
        "automatic_apply_eligible": estimate <= policy.maximum_estimated_seconds,
    }


def _atomic_json(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n"
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_memory_cleanup_audit(
    project_root: str | Path,
    *,
    worker_id: str,
    session_id: str,
    before_rss_bytes: int,
    after_rss_bytes: int,
    before_jvm_started: bool | None,
    after_jvm_started: bool | None,
    authority: str | Path = DEFAULT_POLICY,
) -> dict[str, object]:
    """Record the fresh-process check which follows a worker recycle."""

    policy = load_retention_policy(project_root, authority)
    worker = _text(worker_id, "memory audit worker_id")
    session = _text(session_id, "memory audit session_id")
    if before_rss_bytes < 0 or after_rss_bytes < 0:
        raise ValueError("memory audit RSS values must be non-negative")
    threshold = policy.post_recycle_rss_warning_mib * 1024 * 1024
    reasons = []
    if after_jvm_started is not False:
        reasons.append("fresh worker JVM state could not be proven absent")
    if after_rss_bytes > threshold:
        reasons.append("fresh worker RSS exceeds the TOML warning threshold")
    report = {
        "schema_version": MEMORY_AUDIT_SCHEMA,
        "state": "passed" if not reasons else "warning",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "session_id": session,
        "worker_id": worker,
        "pid": os.getpid(),
        "before": {
            "rss_bytes": before_rss_bytes,
            "embedded_jvm_started": before_jvm_started,
        },
        "after": {
            "rss_bytes": after_rss_bytes,
            "embedded_jvm_started": after_jvm_started,
        },
        "reclaimed_rss_bytes": max(0, before_rss_bytes - after_rss_bytes),
        "post_recycle_rss_warning_bytes": threshold,
        "reasons": reasons,
    }
    if not policy.memory_cleanup_enabled or not policy.audit_after_recycle:
        return {**report, "state": "disabled"}
    session_key = hashlib.sha256(session.encode("utf-8")).hexdigest()[:16]
    worker_key = hashlib.sha256(worker.encode("utf-8")).hexdigest()[:16]
    _atomic_json(policy.memory_audits / session_key / f"{worker_key}.json", report)
    return report


def _memory_cleanup_status(policy: RetentionPolicy) -> dict[str, object]:
    result: dict[str, object] = {
        "enabled": policy.memory_cleanup_enabled,
        "audit_after_recycle": policy.audit_after_recycle,
        "post_recycle_rss_warning_bytes": (
            policy.post_recycle_rss_warning_mib * 1024 * 1024
        ),
        "latest_session": None,
    }
    if not policy.memory_audits.is_dir() or policy.memory_audits.is_symlink():
        return result
    session_dirs = [
        path
        for path in policy.memory_audits.iterdir()
        if path.is_dir() and not path.is_symlink()
    ]
    if not session_dirs:
        return result
    latest = max(session_dirs, key=lambda path: path.stat().st_mtime_ns)
    reports = []
    unreadable = 0
    for path in sorted(latest.glob("*.json"))[:64]:
        if path.is_symlink() or not path.is_file():
            unreadable += 1
            continue
        try:
            report = _load_json(path, "memory cleanup audit")
        except (OSError, ValueError):
            unreadable += 1
            continue
        if report.get("schema_version") != MEMORY_AUDIT_SCHEMA:
            unreadable += 1
            continue
        reports.append(report)
    if not reports:
        result["latest_session"] = {"unreadable_reports": unreadable}
        return result
    reports.sort(key=lambda item: str(item.get("worker_id", "")))

    def audit_rss(item: Mapping[str, object], phase: str) -> int:
        value = item.get(phase)
        if not isinstance(value, dict):
            return 0
        rss = value.get("rss_bytes")
        return rss if isinstance(rss, int) and not isinstance(rss, bool) else 0

    result["latest_session"] = {
        "session_id": reports[0].get("session_id"),
        "recorded_at": max(str(item.get("recorded_at", "")) for item in reports),
        "workers": len(reports),
        "passed": sum(item.get("state") == "passed" for item in reports),
        "warnings": sum(item.get("state") == "warning" for item in reports),
        "unreadable_reports": unreadable,
        "before_rss_bytes": sum(audit_rss(item, "before") for item in reports),
        "after_rss_bytes": sum(audit_rss(item, "after") for item in reports),
        "reclaimed_rss_bytes": sum(
            int(item.get("reclaimed_rss_bytes", 0)) for item in reports
        ),
        "reports": reports[:10],
    }
    return result


def write_retention_plan(plan: Mapping[str, object], project_root: str | Path) -> Path:
    root = Path(project_root).resolve()
    policy = load_retention_policy(root, str(plan["policy"]["authority_path"]))
    digest = str(plan.get("plan_digest", ""))
    if not _SHA256.fullmatch(digest):
        raise RetentionError("retention plan has no valid digest")
    path = policy.plans / f"{digest}.json"
    _atomic_json(path, plan)
    _atomic_json(
        policy.plans / "latest.json",
        {
            "schema_version": PLAN_SCHEMA,
            "plan_digest": digest,
            "path": _relative(root, path),
            "generated_at": plan["generated_at"],
        },
    )
    return path


def _saved_plan_digest(plan: Mapping[str, object]) -> str:
    basis = {
        key: plan[key]
        for key in (
            "schema_version",
            "policy",
            "ledger",
            "session_id",
            "actions",
            "preserved",
            "quarantined",
            "summary",
        )
    }
    return _digest(basis)


@contextmanager
def collector_lock(policy: RetentionPolicy, *, blocking: bool = True) -> Iterator[bool]:
    lock = policy.state.with_name("collector.lock")
    lock.parent.mkdir(parents=True, exist_ok=True)
    with lock.open("a+b") as stream:
        flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
        try:
            fcntl.flock(stream.fileno(), flags)
        except BlockingIOError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _assert_apply_idle(connection: sqlite3.Connection) -> None:
    active = connection.execute(
        "SELECT COUNT(*) n FROM jobs WHERE state IN ('leased','running')"
    ).fetchone()
    attempts = connection.execute(
        "SELECT COUNT(*) n FROM attempts WHERE state IN ('leased','running')"
    ).fetchone()
    if int(active["n"]) or int(attempts["n"]):
        raise RetentionError("retention apply requires zero leased or running work")
    state = connection.execute(
        "SELECT armed, paused FROM coordinator_state WHERE singleton=1"
    ).fetchone()
    queued = connection.execute(
        "SELECT COUNT(*) n FROM jobs WHERE active=1 AND state='queued'"
    ).fetchone()
    if int(queued["n"]) and int(state["armed"]) and not int(state["paused"]):
        raise RetentionError(
            "retention apply requires a terminal queue, or an explicitly paused/disarmed queue"
        )


def _copy_bundle(
    policy: RetentionPolicy, action: Mapping[str, object], plan_digest: str
) -> int:
    destination = _inside(policy.root, str(action["bundle_path"]), "failure bundle")
    if destination.exists():
        evidence = _load_json(destination / "evidence.json", "failure evidence bundle")
        if (
            evidence.get("plan_digest") != plan_digest
            or evidence.get("failure_fingerprint") != action["failure_fingerprint"]
        ):
            raise RetentionError(
                f"existing failure bundle does not match plan: {destination}"
            )
        return sum(
            path.stat().st_size for path in destination.rglob("*") if path.is_file()
        )
    source_paths = action.get("source_paths")
    if not isinstance(source_paths, list) or not source_paths:
        raise RetentionError("failure bundle action has no source paths")
    representative = _inside(policy.root, str(source_paths[0]), "failed representative")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent)
    )
    try:
        copied = []
        for record in action.get("evidence_files", []):
            if not isinstance(record, dict):
                raise RetentionError("failure evidence record is invalid")
            relative = Path(str(record["relative_path"]))
            source = _safe_regular(
                policy.root, representative / relative, "failed evidence file"
            )
            _verify_digest(source, record.get("sha256"), "failed evidence file")
            target = _inside(
                temporary,
                temporary / "files" / relative,
                "failure bundle member",
                create_parent=True,
            )
            shutil.copy2(source, target)
            _verify_digest(target, record.get("sha256"), "copied failure evidence")
            copied.append(record)
        evidence = {
            "schema_version": BUNDLE_SCHEMA,
            "plan_digest": plan_digest,
            "job_id": action["job_id"],
            "job_state": action["job_state"],
            "batch_id": action["batch_id"],
            "base_cell_id": action["base_cell_id"],
            "representative_attempt_id": action["representative_attempt_id"],
            "representative_attempt_number": action["representative_attempt_number"],
            "failure_fingerprint": action["failure_fingerprint"],
            "failure_evidence": action["failure_evidence"],
            "collapsed_attempts": action["collapsed_attempts"],
            "source_paths": source_paths,
            "files": copied,
            "stage_evidence": action["stage_evidence"],
        }
        _atomic_json(temporary / "evidence.json", evidence)
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return sum(path.stat().st_size for path in destination.rglob("*") if path.is_file())


def _remove_tree(policy: RetentionPolicy, value: str) -> dict[str, int]:
    path = _inside(policy.root, value, "retention deletion target")
    if not path.exists():
        return {"files": 0, "directories": 0, "apparent_bytes": 0, "allocated_bytes": 0}
    stats = _attempt_stats(path, policy.maximum_scan_files)
    shutil.rmtree(path)
    return stats


def apply_retention_plan(
    project_root: str | Path,
    plan_digest: str,
    ledger: str | Path = DEFAULT_LEDGER,
    authority: str | Path = DEFAULT_POLICY,
) -> dict[str, object]:
    if not _SHA256.fullmatch(plan_digest):
        raise RetentionError("apply requires an exact retention plan digest")
    policy = load_retention_policy(project_root, authority)
    plan_path = policy.plans / f"{plan_digest}.json"
    if not plan_path.is_file() or plan_path.is_symlink():
        raise RetentionError(f"retention plan is unavailable: {plan_path}")
    saved = _load_json(plan_path, "retention plan")
    if (
        saved.get("schema_version") != PLAN_SCHEMA
        or saved.get("plan_digest") != plan_digest
    ):
        raise RetentionError("saved retention plan identity is invalid")
    if _saved_plan_digest(saved) != plan_digest:
        raise RetentionError("saved retention plan content does not match its digest")
    with collector_lock(policy) as acquired:
        if not acquired:  # pragma: no cover - blocking lock always acquires
            raise RetentionError("retention collector is busy")
        connection = _open_ledger(policy.root, ledger)
        try:
            _assert_apply_idle(connection)
        finally:
            connection.close()
        current = compile_retention_plan(policy.root, ledger, authority)
        if current["plan_digest"] != plan_digest:
            raise RetentionError(
                f"retention plan is stale; current digest is {current['plan_digest']}"
            )
        before = shutil.disk_usage(policy.root).free
        started = time.monotonic_ns()
        started_at = datetime.now(timezone.utc).isoformat()
        removed = {
            "files": 0,
            "directories": 0,
            "apparent_bytes": 0,
            "allocated_bytes": 0,
        }
        bundle_bytes = 0
        completed_actions = []
        for action in saved.get("actions", []):
            if not isinstance(action, dict):
                raise RetentionError("retention plan action is invalid")
            kind = action.get("kind")
            if kind == "bundle-failed-attempts":
                bundle_bytes += _copy_bundle(policy, action, plan_digest)
                paths = action["source_paths"]
            elif kind == "prune-success-scratch":
                if action.get("receipt_verified") is not True:
                    raise RetentionError(
                        "success scratch action lacks a verified lane receipt"
                    )
                paths = action["paths"]
            else:
                raise RetentionError(f"unsupported retention action: {kind}")
            for path in paths:
                stats = _remove_tree(policy, str(path))
                for field in removed:
                    removed[field] += stats[field]
            completed_actions.append(
                {"kind": kind, "job_id": action["job_id"], "paths": list(paths)}
            )
        duration = time.monotonic_ns() - started
        after = shutil.disk_usage(policy.root).free
        result = {
            "schema_version": STATE_SCHEMA,
            "state": "complete",
            "mode": "apply",
            "plan_digest": plan_digest,
            "session_id": saved["session_id"],
            "started_at": started_at,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "duration_ns": duration,
            "actions_completed": len(completed_actions),
            "removed": removed,
            "bundle_bytes": bundle_bytes,
            "filesystem_free_bytes_delta": after - before,
            "completed_actions": completed_actions,
        }
        _atomic_json(policy.state, result)
        return result


def retention_status(
    project_root: str | Path,
    authority: str | Path = DEFAULT_POLICY,
) -> dict[str, object]:
    policy = load_retention_policy(project_root, authority)
    latest = None
    pointer = policy.plans / "latest.json"
    if pointer.is_file() and not pointer.is_symlink():
        latest = _load_json(pointer, "latest retention plan")
        plan_path = _inside(
            policy.root, str(latest.get("path", "")), "latest retention plan path"
        )
        if plan_path.is_file():
            plan = _load_json(plan_path, "latest retention plan")
            action_examples = []
            for action in list(plan.get("actions", []))[:10]:
                if not isinstance(action, dict):
                    continue
                action_examples.append(
                    {
                        key: action[key]
                        for key in (
                            "kind",
                            "job_id",
                            "bundle_path",
                            "source_paths",
                            "paths",
                            "failure_fingerprint",
                            "apparent_bytes",
                            "allocated_bytes",
                        )
                        if key in action
                    }
                )
            latest = {
                **latest,
                "summary": plan.get("summary"),
                "scan_duration_ns": plan.get("scan_duration_ns"),
                "estimated_apply_seconds": plan.get("estimated_apply_seconds"),
                "automatic_apply_eligible": plan.get("automatic_apply_eligible"),
                "preserved_examples": list(plan.get("preserved", []))[:10],
                "quarantine_examples": list(plan.get("quarantined", []))[:20],
                "action_examples": action_examples,
            }
    last_run = None
    if policy.state.is_file():
        stored = _load_json(policy.state, "retention state")
        last_run = {
            key: value
            for key, value in stored.items()
            if key != "completed_actions"
        }
        last_run["completed_action_examples"] = list(
            stored.get("completed_actions", [])
        )[:10]
    return {
        "schema_version": "fidb-retention-status/v1",
        "policy": policy.document(),
        "latest_plan": latest,
        "last_run": last_run,
        "memory_cleanup": _memory_cleanup_status(policy),
    }


def automatic_retention(
    project_root: str | Path,
    ledger: str | Path = DEFAULT_LEDGER,
    authority: str | Path = DEFAULT_POLICY,
) -> dict[str, object]:
    policy = load_retention_policy(project_root, authority)
    if not policy.automation_enabled:
        return {
            "state": "disabled",
            "session_id": current_retention_session(project_root, ledger),
            "worker_action": "none",
        }
    with collector_lock(policy, blocking=False) as acquired:
        if not acquired:
            return {
                "state": "collector-busy",
                "session_id": current_retention_session(project_root, ledger),
                "worker_action": policy.worker_action,
            }
        plan = compile_retention_plan(policy.root, ledger, authority)
        path = write_retention_plan(plan, policy.root)
    result: dict[str, object] = {
        "state": "planned",
        "session_id": plan["session_id"],
        "plan_digest": plan["plan_digest"],
        "plan_path": _relative(policy.root, path),
        "summary": plan["summary"],
        "estimated_apply_seconds": plan["estimated_apply_seconds"],
        "worker_action": policy.worker_action,
    }
    if policy.automation_mode != "apply":
        return result
    if not plan["automatic_apply_eligible"]:
        result["state"] = "manual-review-required"
        return result
    applied = apply_retention_plan(
        policy.root, str(plan["plan_digest"]), ledger, authority
    )
    return {**result, "state": "complete", "apply": applied}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="fidb-poc retention",
        description="Plan, inspect and apply evidence-safe queue retention.",
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--project-root", type=Path, default=Path.cwd())
    common.add_argument("--state", type=Path, default=DEFAULT_LEDGER)
    common.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser(
        "status", parents=[common], help="show policy, latest plan and last apply"
    )
    commands.add_parser(
        "plan",
        parents=[common],
        help="write a non-destructive content-addressed plan",
    )
    apply = commands.add_parser(
        "apply", parents=[common], help="apply one exact current plan"
    )
    apply.add_argument("--plan-digest", required=True)
    commands.add_parser(
        "auto", parents=[common], help="run the configured queue-drained collector"
    )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.command == "status":
            document = retention_status(arguments.project_root, arguments.policy)
        elif arguments.command == "plan":
            document = compile_retention_plan(
                arguments.project_root, arguments.state, arguments.policy
            )
            path = write_retention_plan(document, arguments.project_root)
            document = {
                **document,
                "plan_path": _relative(Path(arguments.project_root).resolve(), path),
            }
        elif arguments.command == "apply":
            document = apply_retention_plan(
                arguments.project_root,
                arguments.plan_digest,
                arguments.state,
                arguments.policy,
            )
        else:
            document = automatic_retention(
                arguments.project_root, arguments.state, arguments.policy
            )
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    except (OSError, RetentionError, ValueError) as error:
        print(f"error: {error}", file=os.sys.stderr)
        return 1
