"""Pre-Ghidra qualification and reuse of machine-validation link images."""

from __future__ import annotations

from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import time
import tomllib
from typing import Mapping

AUTHORITY_SCHEMA = "fidb-machine-validation-link-qualification/v1"
REPORT_SCHEMA = "fidb-machine-validation-link-qualification-report/v1"
SEAL_SCHEMA = "fidb-machine-validation-link-qualification-seal/v1"
REUSE_SCHEMA = "fidb-machine-validation-link-reuse/v1"
DEFAULT_AUTHORITY = Path("validation/machine-validation-link-qualification.toml")

_TOP_LEVEL = {
    "schema_version",
    "id",
    "state",
    "runtime",
    "output_root",
    "execution",
    "admission",
    "reuse",
    "safety",
}
_SECTIONS = {
    "execution": {"workers", "batch_size", "identical_failure_limit"},
    "admission": {"require_for_new_runs", "grandfather_run_ids"},
    "reuse": {"mode", "verify_sha256"},
    "safety": {"execute_target_binaries", "retain_failure_evidence"},
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    ).hexdigest()


def _inside(root: Path, value: object, label: str) -> Path:
    path = Path(str(value))
    resolved = path.resolve() if path.is_absolute() else (root / path).resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError(f"{label} escapes the project root")
    return resolved


def _atomic_json(path: Path, document: object) -> None:
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


def load_link_qualification(
    project_root: str | Path,
    authority_path: str | Path = DEFAULT_AUTHORITY,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    path = _inside(root, authority_path, "link-qualification authority")
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if (
        set(document) != _TOP_LEVEL
        or document.get("schema_version") != AUTHORITY_SCHEMA
    ):
        raise ValueError(
            "link-qualification authority has unsupported fields or schema"
        )
    for section, fields in _SECTIONS.items():
        if (
            not isinstance(document.get(section), dict)
            or set(document[section]) != fields
        ):
            raise ValueError(f"link-qualification {section} has unexpected fields")
    if document["state"] != "defined-disarmed":
        raise ValueError("link qualification must remain defined-disarmed")
    execution = document["execution"]
    for field in ("workers", "batch_size", "identical_failure_limit"):
        if type(execution[field]) is not int or not 1 <= int(execution[field]) <= 64:
            raise ValueError(f"link-qualification execution.{field} must be 1-64")
    admission = document["admission"]
    if admission["require_for_new_runs"] is not True:
        raise ValueError("link qualification must be required for new runs")
    grandfather = admission["grandfather_run_ids"]
    if (
        not isinstance(grandfather, list)
        or any(not isinstance(value, str) or not value for value in grandfather)
        or len(grandfather) != len(set(grandfather))
    ):
        raise ValueError("link-qualification grandfather run ids must be unique")
    if document["reuse"] != {"mode": "hardlink-or-copy", "verify_sha256": True}:
        raise ValueError("link-qualification reuse policy is unsupported")
    if document["safety"] != {
        "execute_target_binaries": False,
        "retain_failure_evidence": True,
    }:
        raise ValueError("link-qualification safety policy is unsupported")
    runtime = _inside(root, document["runtime"], "link-qualification runtime")
    output_root = _inside(root, document["output_root"], "link output root")
    return {
        **document,
        "authority_path": str(path.relative_to(root)),
        "authority_sha256": _sha256(path),
        "runtime": str(runtime.relative_to(root)),
        "output_root": str(output_root.relative_to(root)),
    }


def _input_authorities(
    root: Path, authority: Mapping[str, object]
) -> list[dict[str, str]]:
    paths = {
        Path(str(authority["authority_path"])),
        Path(str(authority["runtime"])),
        Path("worker.toml"),
        Path("src/fidb_poc/machine_validation.py"),
        Path("src/fidb_poc/machine_validation_runner.py"),
        Path("src/fidb_poc/machine_validation_links.py"),
    }
    for directory in ("toolchains", "coverage", "recipes"):
        paths.update(
            path.relative_to(root) for path in (root / directory).rglob("*.toml")
        )
    rows = []
    for relative in sorted(paths, key=str):
        path = root / relative
        if not path.is_file():
            raise ValueError(
                f"link-qualification input authority is missing: {relative}"
            )
        rows.append({"path": str(relative), "sha256": _sha256(path)})
    return rows


def compile_link_qualification(
    project_root: str | Path,
    authority_path: str | Path = DEFAULT_AUTHORITY,
    *,
    _evidence: Mapping[str, object] | None = None,
) -> dict[str, object]:
    from .machine_validation import LINK_HARNESS_POLICY, QUERY_COPY_POLICY
    from .machine_validation_runner import resolve_evidence

    root = Path(project_root).expanduser().resolve()
    authority = load_link_qualification(root, authority_path)
    evidence = dict(_evidence or resolve_evidence(root, str(authority["runtime"])))
    if evidence["blockers"]:
        raise ValueError("; ".join(str(value) for value in evidence["blockers"]))
    units = sorted(
        evidence["manifest"]["work_unit"], key=lambda row: int(row["position"])
    )
    cells = [
        {
            "id": f'{int(unit["position"]):03d}:{fold}',
            "position": int(unit["position"]),
            "fold": fold,
            "route_id": str(unit["route_id"]),
            "treatment_id": str(unit["treatment_id"]),
        }
        for unit in units
        for fold in ("A", "B")
    ]
    cohort = list(evidence["status"]["randomization"]["canonical_ids"])
    archive_rows = []
    source_archive = _inside(
        root, evidence["runtime"]["source_archive"], "source archive"
    )
    source_archive_sha256 = _sha256(source_archive)
    for owner in sorted(cohort):
        for unit in units:
            key = (owner, str(unit["route_id"]), str(unit["treatment_id"]))
            archive = evidence["archives"].get(key)
            if archive is None and owner != "openssl@3.5.8":
                raise ValueError(f"static archive input is unavailable for {key}")
            archive_rows.append(
                {
                    "owner": owner,
                    "route_id": key[1],
                    "treatment_id": key[2],
                    "archive_sha256": (
                        list(archive["sha256"])
                        if archive is not None
                        else [f"openssl-source:{source_archive_sha256}"]
                    ),
                }
            )
    input_authorities = _input_authorities(root, authority)
    contract = {
        "authority_sha256": authority["authority_sha256"],
        "runtime_authority_sha256": evidence["runtime"]["authority_sha256"],
        "validation_id": evidence["runtime"]["validation_id"],
        "link_harness_policy": LINK_HARNESS_POLICY,
        "query_copy_policy": QUERY_COPY_POLICY,
        "fold_a": evidence["status"]["randomization"]["fold_a"],
        "fold_b": evidence["status"]["randomization"]["fold_b"],
        "cells": cells,
        "input_authorities": input_authorities,
        "archive_set_sha256": _canonical_digest(archive_rows),
    }
    input_digest = _canonical_digest(contract)
    generation_root = root / str(authority["output_root"]) / input_digest
    return {
        "schema_version": AUTHORITY_SCHEMA,
        **authority,
        "runtime_authority_sha256": evidence["runtime"]["authority_sha256"],
        "validation_id": evidence["runtime"]["validation_id"],
        "link_harness_policy": LINK_HARNESS_POLICY,
        "query_copy_policy": QUERY_COPY_POLICY,
        "input_authorities": input_authorities,
        "archive_set_sha256": contract["archive_set_sha256"],
        "input_digest": input_digest,
        "generation_root": str(generation_root.relative_to(root)),
        "report_path": str((generation_root / "report.json").relative_to(root)),
        "summary": {
            "exact_identities": len(units),
            "fold_link_cells": len(cells),
            "workers": authority["execution"]["workers"],
            "batch_size": authority["execution"]["batch_size"],
            "identical_failure_limit": authority["execution"][
                "identical_failure_limit"
            ],
        },
        "cells": cells,
        "_evidence": evidence,
    }


def _failure_reason(error: Exception) -> str:
    detail = str(error).lower()
    if "runtime loader" in detail or ("unknown" in detail and "route" in detail):
        return "authority-resolution"
    if "identity" in detail and ("differ" in detail or "mismatch" in detail):
        return "authority-identity-mismatch"
    if "composite link failed" in detail:
        return "composite-link"
    if "query-copy creation failed" in detail:
        return "query-copy"
    if "direct control-flow" in detail or "link audit" in detail:
        return "link-audit"
    if "strip tool" in detail:
        return "strip-tool"
    return "preparation-error"


def failure_fingerprint(root: Path, error: Exception) -> dict[str, str]:
    reason = _failure_reason(error)
    normalized = f"{type(error).__name__}: {error}"
    normalized = normalized.replace(str(root), "<PROJECT>")
    normalized = re.sub(r"/tmp/[^\s:]+", "<TMP>", normalized)
    normalized = re.sub(r"for\s+[A-Za-z0-9_.-]+:", "for <ROUTE>:", normalized)
    normalized = re.sub(r"0x[0-9a-fA-F]+", "0x#", normalized)
    normalized = re.sub(r"\b\d{3,}\b", "#", normalized)
    normalized = " ".join(normalized.split())[-2000:]
    return {
        "reason_code": reason,
        "normalized_error": normalized,
        "failure_fingerprint": _canonical_digest(
            {"reason_code": reason, "normalized_error": normalized}
        ),
    }


def _qualification_root(root: Path, plan: Mapping[str, object]) -> Path:
    return _inside(root, plan["generation_root"], "link-qualification generation")


def _new_report(plan: Mapping[str, object]) -> dict[str, object]:
    return {
        "schema_version": REPORT_SCHEMA,
        "qualification_id": plan["id"],
        "validation_id": plan["validation_id"],
        "authority_path": plan["authority_path"],
        "authority_sha256": plan["authority_sha256"],
        "runtime_authority_sha256": plan["runtime_authority_sha256"],
        "input_digest": plan["input_digest"],
        "started_at": _now(),
        "finished_at": None,
        "state": "incomplete",
        "summary": {
            "total": len(plan["cells"]),
            "qualified": 0,
            "failed": 0,
            "remaining": len(plan["cells"]),
        },
        "circuit_breaker": {
            "threshold": plan["execution"]["identical_failure_limit"],
            "state": "closed",
            "failure_fingerprint": None,
            "observed": 0,
        },
        "attempts": [],
    }


def _latest_attempts(report: Mapping[str, object]) -> dict[str, dict[str, object]]:
    return {
        str(row["id"]): row
        for row in report.get("attempts", [])
        if isinstance(row, dict) and row.get("id")
    }


def _seal_body(
    plan: Mapping[str, object], latest: Mapping[str, Mapping[str, object]]
) -> dict[str, object]:
    return {
        "schema_version": SEAL_SCHEMA,
        "qualification_id": plan["id"],
        "validation_id": plan["validation_id"],
        "authority_sha256": plan["authority_sha256"],
        "runtime_authority_sha256": plan["runtime_authority_sha256"],
        "input_digest": plan["input_digest"],
        "outputs": [
            {
                key: latest[str(cell["id"])][key]
                for key in (
                    "id",
                    "position",
                    "fold",
                    "route_id",
                    "treatment_id",
                    "prepared_path",
                    "truth_sha256",
                    "query_sha256",
                    "link_audit_sha256",
                )
            }
            for cell in plan["cells"]
        ],
    }


def _summarize(report: dict[str, object], plan: Mapping[str, object]) -> None:
    expected = {str(cell["id"]) for cell in plan["cells"]}
    latest = _latest_attempts(report)
    qualified = sum(
        latest.get(cell_id, {}).get("status") == "qualified" for cell_id in expected
    )
    failed = sum(
        cell_id in latest and latest[cell_id].get("status") != "qualified"
        for cell_id in expected
    )
    remaining = len(expected) - qualified - failed
    report["summary"] = {
        "total": len(expected),
        "qualified": qualified,
        "failed": failed,
        "remaining": remaining,
    }
    report.pop("seal", None)
    if qualified == len(expected):
        report["state"] = "qualified"
        report["finished_at"] = _now()
        body = _seal_body(plan, latest)
        report["seal"] = {
            "schema_version": SEAL_SCHEMA,
            "qualification_digest": _canonical_digest(body),
            "sealed_at": report["finished_at"],
        }
    elif report["circuit_breaker"]["state"] == "open":
        report["state"] = "circuit-open"
        report["finished_at"] = _now()
    else:
        report["state"] = "failed" if remaining == 0 and failed else "incomplete"
        report["finished_at"] = _now() if remaining == 0 else None


def _qualify_position(
    root: Path,
    plan: Mapping[str, object],
    position: int,
    folds: list[str],
) -> list[dict[str, object]]:
    from .machine_validation_runner import (
        _load_prepared_fold,
        _prepare_position,
        _prepared_fold_path,
        _unit_result_path,
    )

    evidence = plan["_evidence"]
    units = {int(unit["position"]): unit for unit in evidence["manifest"]["work_unit"]}
    unit = units[position]
    generation_root = _qualification_root(root, plan)
    unit_root = _unit_result_path(generation_root, unit, position).parent
    rows = []
    for fold in folds:
        started_ns = time.monotonic_ns()
        try:
            _prepare_position(
                root,
                evidence,
                generation_root,
                position,
                "full",
                requested_folds=(fold,),
            )
            marker_path = _prepared_fold_path(unit_root, fold)
            prepared = _load_prepared_fold(
                root,
                marker_path,
                position=position,
                route_id=str(unit["route_id"]),
                treatment_id=str(unit["treatment_id"]),
                fold=fold,
                runtime_authority_sha256=str(plan["runtime_authority_sha256"]),
            )
            if prepared is None:
                raise RuntimeError(
                    "prepared link marker is unavailable after qualification"
                )
            rows.append(
                {
                    "id": f"{position:03d}:{fold}",
                    "status": "qualified",
                    "position": position,
                    "fold": fold,
                    "route_id": str(unit["route_id"]),
                    "treatment_id": str(unit["treatment_id"]),
                    "prepared_path": str(marker_path.relative_to(root)),
                    "truth_sha256": prepared["truth_sha256"],
                    "query_sha256": prepared["query_sha256"],
                    "link_audit_sha256": _canonical_digest(prepared["link_audit"]),
                    "wall_time_ns": time.monotonic_ns() - started_ns,
                    "attempted_at": _now(),
                }
            )
        except Exception as error:
            fingerprint = failure_fingerprint(root, error)
            rows.append(
                {
                    "id": f"{position:03d}:{fold}",
                    "status": "failed",
                    "position": position,
                    "fold": fold,
                    "route_id": str(unit["route_id"]),
                    "treatment_id": str(unit["treatment_id"]),
                    "error": f"{type(error).__name__}: {error}",
                    **fingerprint,
                    "failure_evidence_path": str(
                        (unit_root / f"fold-{fold}").relative_to(root)
                    ),
                    "wall_time_ns": time.monotonic_ns() - started_ns,
                    "attempted_at": _now(),
                }
            )
    return rows


def run_link_qualification(
    project_root: str | Path,
    authority_path: str | Path = DEFAULT_AUTHORITY,
    *,
    _plan: dict[str, object] | None = None,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    plan = _plan or compile_link_qualification(root, authority_path)
    generation_root = _qualification_root(root, plan)
    report_path = generation_root / "report.json"
    if report_path.is_file():
        report = json.loads(report_path.read_text(encoding="utf-8"))
        expected = {
            "schema_version": REPORT_SCHEMA,
            "qualification_id": plan["id"],
            "authority_sha256": plan["authority_sha256"],
            "runtime_authority_sha256": plan["runtime_authority_sha256"],
            "input_digest": plan["input_digest"],
        }
        if any(report.get(key) != value for key, value in expected.items()):
            raise ValueError("link-qualification report identity is invalid")
        if report.get("state") == "qualified":
            return report
    else:
        report = _new_report(plan)
    latest = _latest_attempts(report)
    pending: list[tuple[int, str]] = []
    for cell in plan["cells"]:
        if latest.get(str(cell["id"]), {}).get("status") != "qualified":
            pending.append((int(cell["position"]), str(cell["fold"])))
    failures: Counter[str] = Counter()
    threshold = int(plan["execution"]["identical_failure_limit"])
    batch_size = int(plan["execution"]["batch_size"])
    pending.sort()
    report["circuit_breaker"] = {
        "threshold": threshold,
        "state": "closed",
        "failure_fingerprint": None,
        "observed": 0,
    }
    for offset in range(0, len(pending), batch_size):
        batch = pending[offset : offset + batch_size]
        with ThreadPoolExecutor(
            max_workers=min(int(plan["execution"]["workers"]), len(batch))
        ) as executor:
            futures = {
                executor.submit(_qualify_position, root, plan, position, [fold]): (
                    position,
                    fold,
                )
                for position, fold in batch
            }
            for future in as_completed(futures):
                rows = future.result()
                report["attempts"].extend(rows)
                for row in rows:
                    if row["status"] == "failed":
                        fingerprint = str(row["failure_fingerprint"])
                        failures[fingerprint] += 1
                        if failures[fingerprint] >= threshold:
                            report["circuit_breaker"] = {
                                "threshold": threshold,
                                "state": "open",
                                "failure_fingerprint": fingerprint,
                                "reason_code": row["reason_code"],
                                "observed": failures[fingerprint],
                            }
                _summarize(report, plan)
                _atomic_json(report_path, report)
        if report["circuit_breaker"]["state"] == "open":
            break
    _summarize(report, plan)
    _atomic_json(report_path, report)
    return report


def link_qualification_status(
    project_root: str | Path,
    authority_path: str | Path = DEFAULT_AUTHORITY,
    *,
    _plan: dict[str, object] | None = None,
    _evidence: Mapping[str, object] | None = None,
) -> dict[str, object]:
    from .machine_validation_runner import _load_prepared_fold

    root = Path(project_root).expanduser().resolve()
    plan = _plan or compile_link_qualification(
        root, authority_path, _evidence=_evidence
    )
    report_path = _inside(root, plan["report_path"], "link-qualification report")
    base = {
        "schema_version": AUTHORITY_SCHEMA,
        "qualification_id": plan["id"],
        "validation_id": plan["validation_id"],
        "authority_path": plan["authority_path"],
        "authority_sha256": plan["authority_sha256"],
        "runtime_authority_sha256": plan["runtime_authority_sha256"],
        "input_digest": plan["input_digest"],
        "report_path": plan["report_path"],
        "summary": {
            "total": len(plan["cells"]),
            "qualified": 0,
            "failed": 0,
            "remaining": len(plan["cells"]),
        },
        "satisfied": False,
        "qualification_digest": None,
        "blockers": [],
    }
    if not report_path.is_file():
        return {
            **base,
            "state": "required",
            "blockers": ["link qualification has not run"],
        }
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return {
            **base,
            "state": "invalid",
            "blockers": [f"qualification report is unreadable: {error}"],
        }
    expected_report = {
        "schema_version": REPORT_SCHEMA,
        "qualification_id": plan["id"],
        "authority_sha256": plan["authority_sha256"],
        "runtime_authority_sha256": plan["runtime_authority_sha256"],
        "input_digest": plan["input_digest"],
    }
    if any(report.get(key) != value for key, value in expected_report.items()):
        return {
            **base,
            "state": "invalid",
            "blockers": ["qualification report identity is stale or invalid"],
        }
    latest = _latest_attempts(report)
    expected_ids = {str(cell["id"]) for cell in plan["cells"]}
    if set(latest) - expected_ids:
        return {
            **base,
            "state": "invalid",
            "blockers": ["qualification report contains unexpected cells"],
        }
    invalid_outputs = []
    for cell in plan["cells"]:
        row = latest.get(str(cell["id"]))
        if row is None or row.get("status") != "qualified":
            continue
        prepared_value = row.get("prepared_path")
        if not isinstance(prepared_value, str) or not prepared_value:
            invalid_outputs.append(str(cell["id"]))
            continue
        prepared_path = _inside(root, prepared_value, "prepared link")
        prepared = _load_prepared_fold(
            root,
            prepared_path,
            position=int(cell["position"]),
            route_id=str(cell["route_id"]),
            treatment_id=str(cell["treatment_id"]),
            fold=str(cell["fold"]),
            runtime_authority_sha256=str(plan["runtime_authority_sha256"]),
        )
        if prepared is None:
            invalid_outputs.append(str(cell["id"]))
            continue
        truth = _inside(root, prepared["truth_binary"], "qualified truth binary")
        query = _inside(root, prepared["query_binary"], "qualified query binary")
        if (
            _sha256(truth) != row.get("truth_sha256")
            or _sha256(query) != row.get("query_sha256")
            or _canonical_digest(prepared["link_audit"]) != row.get("link_audit_sha256")
        ):
            invalid_outputs.append(str(cell["id"]))
    summary = dict(report.get("summary", base["summary"]))
    blockers = []
    if invalid_outputs:
        blockers.append(
            f"{len(invalid_outputs)} qualified link outputs failed verification"
        )
    if summary.get("failed"):
        blockers.append(f'{summary["failed"]} link cells failed')
    if summary.get("remaining"):
        blockers.append(f'{summary["remaining"]} link cells remain')
    seal = report.get("seal")
    expected_seal = (
        _canonical_digest(_seal_body(plan, latest))
        if summary.get("qualified") == len(expected_ids)
        else None
    )
    sealed = (
        isinstance(seal, dict)
        and seal.get("schema_version") == SEAL_SCHEMA
        and seal.get("qualification_digest") == expected_seal
    )
    if not sealed and summary.get("qualified") == len(expected_ids):
        blockers.append("complete link outputs lack a valid seal")
    satisfied = not blockers and sealed
    return {
        **base,
        "state": "qualified" if satisfied else str(report.get("state", "invalid")),
        "summary": summary,
        "satisfied": satisfied,
        "qualification_digest": expected_seal if satisfied else None,
        "report_sha256": _sha256(report_path),
        "circuit_breaker": report.get("circuit_breaker"),
        "blockers": blockers,
    }


def link_qualification_admission(
    project_root: str | Path,
    run_id: str,
    authority_path: str | Path = DEFAULT_AUTHORITY,
    *,
    _evidence: Mapping[str, object] | None = None,
    _plan: dict[str, object] | None = None,
    _status: Mapping[str, object] | None = None,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    authority = load_link_qualification(root, authority_path)
    if run_id in authority["admission"]["grandfather_run_ids"]:
        return {
            "ready": True,
            "state": "grandfathered-checkpoint",
            "run_id": run_id,
            "qualification_id": authority["id"],
            "reason": "existing checkpoint predates the mandatory link-qualification gate",
        }
    status = dict(
        _status
        or link_qualification_status(
            root, authority_path, _plan=_plan, _evidence=_evidence
        )
    )
    return {
        "ready": bool(status["satisfied"]),
        "state": status["state"],
        "run_id": run_id,
        "qualification_id": authority["id"],
        "qualification_digest": status.get("qualification_digest"),
        "blockers": status["blockers"],
    }


def _link_or_copy(source: Path, destination: Path) -> None:
    try:
        os.link(source, destination)
    except OSError:
        shutil.copy2(source, destination)


def reuse_qualified_links(
    project_root: str | Path,
    evidence: Mapping[str, object],
    run_root: Path,
    positions: set[int],
    authority_path: str | Path = DEFAULT_AUTHORITY,
    *,
    _plan: dict[str, object] | None = None,
    _status: Mapping[str, object] | None = None,
) -> dict[str, object]:
    from .machine_validation_runner import (
        _load_prepared_fold,
        _prepared_fold_path,
        _unit_result_path,
    )

    root = Path(project_root).expanduser().resolve()
    plan = _plan or compile_link_qualification(root, authority_path, _evidence=evidence)
    status = dict(
        _status or link_qualification_status(root, authority_path, _plan=plan)
    )
    receipt_path = run_root / "link-qualification.json"
    if not status["satisfied"]:
        receipt = {
            "schema_version": REUSE_SCHEMA,
            "state": "unavailable-fallback",
            "qualification_id": plan["id"],
            "input_digest": plan["input_digest"],
            "reused_folds": 0,
            "blockers": status["blockers"],
            "recorded_at": _now(),
        }
        _atomic_json(receipt_path, receipt)
        return receipt
    report_path = _inside(root, plan["report_path"], "qualification report")
    latest = _latest_attempts(json.loads(report_path.read_text(encoding="utf-8")))
    units = {int(unit["position"]): unit for unit in evidence["manifest"]["work_unit"]}
    reused = 0
    already_present = 0
    preserved_partial = 0
    for cell in plan["cells"]:
        position = int(cell["position"])
        if position not in positions:
            continue
        unit = units[position]
        destination_unit = _unit_result_path(run_root, unit, position).parent
        destination_marker = _prepared_fold_path(destination_unit, str(cell["fold"]))
        prepared = _load_prepared_fold(
            root,
            destination_marker,
            position=position,
            route_id=str(cell["route_id"]),
            treatment_id=str(cell["treatment_id"]),
            fold=str(cell["fold"]),
            runtime_authority_sha256=str(plan["runtime_authority_sha256"]),
        )
        if prepared is not None:
            already_present += 1
            continue
        destination = destination_marker.parent
        if destination.exists() and any(destination.iterdir()):
            preserved_partial += 1
            continue
        source_marker = _inside(
            root,
            latest[str(cell["id"])]["prepared_path"],
            "qualified prepared marker",
        )
        source = source_marker.parent
        destination.mkdir(parents=True, exist_ok=True)
        created = []
        try:
            for source_path in source.iterdir():
                if not source_path.is_file() or source_path.name == "prepared.json":
                    continue
                destination_path = destination / source_path.name
                _link_or_copy(source_path, destination_path)
                created.append(destination_path)
            document = json.loads(source_marker.read_text(encoding="utf-8"))
            truth = _inside(root, document["truth_binary"], "qualified truth")
            query = _inside(root, document["query_binary"], "qualified query")
            document["truth_binary"] = str((destination / truth.name).relative_to(root))
            document["query_binary"] = str((destination / query.name).relative_to(root))
            document["link_qualification"] = {
                "qualification_id": plan["id"],
                "qualification_digest": status["qualification_digest"],
                "source_prepared_path": str(source_marker.relative_to(root)),
            }
            _atomic_json(destination_marker, document)
            reused += 1
        except Exception:
            for path in created:
                path.unlink(missing_ok=True)
            destination_marker.unlink(missing_ok=True)
            raise
    receipt = {
        "schema_version": REUSE_SCHEMA,
        "state": "reused",
        "qualification_id": plan["id"],
        "qualification_digest": status["qualification_digest"],
        "input_digest": plan["input_digest"],
        "reused_folds": reused,
        "already_present_folds": already_present,
        "preserved_partial_folds": preserved_partial,
        "recorded_at": _now(),
    }
    _atomic_json(receipt_path, receipt)
    return receipt
