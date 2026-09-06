"""Aggregate recurring validation collisions into a managed trust ledger."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import tomllib
from typing import Mapping

from .lane_registry import load_lane_registry

NOISY_HASH_SCHEMA = "fidb-noisy-hashes/v1"
NOISY_HASH_STATUS_SCHEMA = "fidb-noisy-hash-status/v1"
NOISY_HASH_DECISION_SCHEMA = "fidb-noisy-hash-decision/v1"
DEFAULT_AUTHORITY = Path("validation/noisy-hashes.toml")
_SIGNATURE_ID = re.compile(r"^noise-[0-9a-f]{24}$")
_TOP_LEVEL = {
    "schema_version",
    "id",
    "label",
    "state",
    "sources",
    "classification",
    "management",
    "display",
}
_SECTIONS = {
    "sources": {
        "machine_evidence_glob",
        "ecological_report_glob",
        "route_registry",
        "lane_registry",
        "decision_glob",
    },
    "classification": {
        "candidate_min_collisions",
        "confirmed_min_collisions",
        "confirmed_min_distinct_runs",
        "high_risk_min_distinct_owners",
        "grouping_key",
    },
    "management": {
        "default_state",
        "allowed_states",
        "quarantine_effect",
        "automatic_deletion",
        "require_reason",
    },
    "display": {
        "max_evidence_rows_per_hash",
        "max_hash_rows",
        "show_single_observation_candidates",
    },
}


def _inside(root: Path, relative: str, label: str) -> Path:
    candidate = (root / relative).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError(f"{label} escapes project root")
    return candidate


def load_noisy_hash_authority(
    project_root: str | Path,
    authority: str | Path = DEFAULT_AUTHORITY,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    path = _inside(root, str(authority), "noisy-hash authority")
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if (
        set(document) != _TOP_LEVEL
        or document.get("schema_version") != NOISY_HASH_SCHEMA
    ):
        raise ValueError("noisy-hash authority has unsupported fields or schema")
    for section, fields in _SECTIONS.items():
        if (
            not isinstance(document.get(section), dict)
            or set(document[section]) != fields
        ):
            raise ValueError(f"noisy-hash {section} has unexpected fields")
    classification = document["classification"]
    management = document["management"]
    display = document["display"]
    if (
        document["state"] != "active-observation"
        or classification["grouping_key"] != "query-sublane-plus-complete-fid-signature"
        or classification["candidate_min_collisions"] != 1
        or classification["confirmed_min_collisions"]
        < classification["candidate_min_collisions"]
        or classification["confirmed_min_distinct_runs"] < 2
        or management["default_state"] != "observe"
        or management["automatic_deletion"] is not False
        or management["require_reason"] is not True
        or display["max_evidence_rows_per_hash"] < 1
        or display["max_hash_rows"] < 1
    ):
        raise ValueError("noisy-hash trust policy is unsupported")
    expected_states = ["observe", "quarantine", "reviewed-shared", "cleared"]
    if management["allowed_states"] != expected_states:
        raise ValueError("noisy-hash allowed states are unsupported")
    for value in document["sources"].values():
        if not isinstance(value, str) or not value:
            raise ValueError("noisy-hash sources must be non-empty strings")
    return {
        **document,
        "authority_path": str(path.relative_to(root)),
        "authority_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _route_scopes(
    root: Path, lane_registry_path: str, route_registry_path: str
) -> dict[str, str]:
    registry = load_lane_registry(
        _inside(root, lane_registry_path, "lane registry"),
        root / "targets/registry.toml",
    )
    target_scope = {
        str(sublane["target_id"]): str(sublane["id"])
        for lane in registry["lanes"]
        for sublane in lane["sublanes"]
    }
    routes = tomllib.loads(
        _inside(root, route_registry_path, "route registry").read_text(encoding="utf-8")
    ).get("route", [])
    exact = {
        str(row["id"]): target_scope.get(
            str(row["target_id"]), f'target:{row["target_id"]}'
        )
        for row in routes
    }
    return exact


def _scope_for_failure(
    failure: Mapping[str, object],
    report: Mapping[str, object],
    routes: Mapping[str, str],
) -> str:
    probe = report.get("probe")
    if isinstance(probe, dict) and isinstance(probe.get("sublane_id"), str):
        return str(probe["sublane_id"])
    route = str(failure.get("route_id") or "unknown")
    if route in routes:
        return routes[route]
    candidates = [key for key in routes if route.startswith(f"{key}-")]
    if candidates:
        return routes[max(candidates, key=len)]
    return f"route:{route}"


def _decision_files(
    root: Path, pattern: str, allowed_states: set[str]
) -> dict[str, dict[str, object]]:
    decisions: dict[str, dict[str, object]] = {}
    for path in sorted(root.glob(pattern)):
        if not path.is_file() or path.is_symlink():
            continue
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        if (
            document.get("schema_version") != NOISY_HASH_DECISION_SCHEMA
            or not _SIGNATURE_ID.fullmatch(str(document.get("signature_id", "")))
            or document.get("state") not in allowed_states
            or not isinstance(document.get("reason"), str)
            or not document["reason"].strip()
        ):
            raise ValueError(f"invalid noisy-hash decision: {path}")
        decisions[str(document["signature_id"])] = {
            **document,
            "path": str(path.relative_to(root)),
        }
    return decisions


def compile_noisy_hashes(
    project_root: str | Path,
    authority: str | Path = DEFAULT_AUTHORITY,
    *,
    max_hash_rows: int | None = None,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    config = load_noisy_hash_authority(root, authority)
    routes = _route_scopes(
        root,
        str(config["sources"]["lane_registry"]),
        str(config["sources"]["route_registry"]),
    )
    decisions = _decision_files(
        root,
        str(config["sources"]["decision_glob"]),
        set(config["management"]["allowed_states"]),
    )
    groups: dict[tuple[str, str], dict[str, object]] = {}
    evidence_limit = int(config["display"]["max_evidence_rows_per_hash"])
    source_specs = (("ecological", str(config["sources"]["ecological_report_glob"])),)
    reports_scanned = 0
    evidence_databases_scanned = 0
    for path in sorted(root.glob(str(config["sources"]["machine_evidence_glob"]))):
        if not path.is_file() or path.is_symlink():
            continue
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            metadata = dict(connection.execute("SELECT key, value FROM metadata"))
            if (
                metadata.get("schema_version")
                != "fidb-machine-validation-hash-evidence/v1"
                or metadata.get("state") != "complete"
            ):
                continue
            evidence_databases_scanned += 1
            run_id = metadata.get("source_run_id", path.parent.name)
            for row in connection.execute("""
                SELECT scope, language, full_hash, specific_hash,
                       additional_size, code_size, owner, route_id,
                       treatment_id, query_function, evidence_path
                FROM hash_observation
                WHERE outcome='fp'
                ORDER BY scope, full_hash, specific_hash, additional_size,
                         code_size, owner, route_id, treatment_id
                """):
                signature = (
                    f'{row["full_hash"]}:{row["specific_hash"]}:'
                    f'{row["additional_size"]}:{row["code_size"]}'
                )
                scope = str(row["scope"])
                group = groups.setdefault(
                    (scope, signature),
                    {
                        "scope": scope,
                        "signature": signature,
                        "runs": set(),
                        "owners": set(),
                        "sources": set(),
                        "evidence": [],
                        "collisions": 0,
                    },
                )
                group["runs"].add(run_id)
                group["owners"].add(str(row["owner"]))
                group["sources"].add("machine")
                group["collisions"] += 1
                if len(group["evidence"]) < evidence_limit:
                    group["evidence"].append(
                        {
                            "source": "machine",
                            "run_id": run_id,
                            "owner": str(row["owner"]),
                            "library_id": str(row["owner"]),
                            "function_id": str(row["query_function"]),
                            "route_id": str(row["route_id"]),
                            "compiler_id": str(row["route_id"]),
                            "treatment_id": str(row["treatment_id"]),
                            "evidence_path": str(
                                row["evidence_path"] or path.relative_to(root)
                            ),
                        }
                    )
        except sqlite3.Error:
            continue
        finally:
            connection.close()
    for source_kind, pattern in source_specs:
        for path in sorted(root.glob(pattern)):
            if not path.is_file() or path.is_symlink():
                continue
            try:
                report = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(report, dict):
                continue
            reports_scanned += 1
            run_id = str(report.get("case_id") or report.get("id") or path.parent.name)
            for failure in report.get("failures", []):
                if (
                    not isinstance(failure, dict)
                    or failure.get("failure_type") != "collision"
                ):
                    continue
                signature = str(failure.get("signature") or "")
                if not signature:
                    continue
                scope = _scope_for_failure(failure, report, routes)
                group = groups.setdefault(
                    (scope, signature),
                    {
                        "scope": scope,
                        "signature": signature,
                        "runs": set(),
                        "owners": set(),
                        "sources": set(),
                        "evidence": [],
                        "collisions": 0,
                    },
                )
                group["runs"].add(run_id)
                owner = str(
                    failure.get("owner") or failure.get("candidate_owner") or "unknown"
                )
                group["owners"].add(owner)
                group["sources"].add(source_kind)
                group["collisions"] += 1
                if len(group["evidence"]) < evidence_limit:
                    group["evidence"].append(
                        {
                            "source": source_kind,
                            "run_id": run_id,
                            "owner": owner,
                            "library_id": failure.get("library_id") or owner,
                            "function_id": failure.get("function_id")
                            or failure.get("target_function")
                            or "",
                            "route_id": failure.get("route_id") or "",
                            "compiler_id": failure.get("compiler_id") or "",
                            "treatment_id": failure.get("treatment_id") or "",
                            "evidence_path": failure.get("evidence_path")
                            or str(path.relative_to(root)),
                        }
                    )
    rows: list[dict[str, object]] = []
    thresholds = config["classification"]
    for (scope, signature), group in groups.items():
        identity = hashlib.sha256(f"{scope}\0{signature}".encode()).hexdigest()
        signature_id = f"noise-{identity[:24]}"
        collisions = int(group["collisions"])
        distinct_runs = len(group["runs"])
        distinct_owners = len(group["owners"])
        classification = (
            "confirmed-noisy"
            if collisions >= int(thresholds["confirmed_min_collisions"])
            and distinct_runs >= int(thresholds["confirmed_min_distinct_runs"])
            else "candidate-noisy"
        )
        risk = (
            "high"
            if distinct_owners >= int(thresholds["high_risk_min_distinct_owners"])
            else "review"
        )
        decision = decisions.get(signature_id)
        disposition = (
            str(decision["state"])
            if decision
            else str(config["management"]["default_state"])
        )
        rows.append(
            {
                "signature_id": signature_id,
                "scope": scope,
                "signature": signature,
                "classification": classification,
                "risk": risk,
                "disposition": disposition,
                "collisions": collisions,
                "distinct_runs": distinct_runs,
                "distinct_owners": distinct_owners,
                "owners": sorted(group["owners"]),
                "sources": sorted(group["sources"]),
                "decision": decision,
                "evidence": group["evidence"][:evidence_limit],
                "evidence_rows_truncated": max(0, collisions - evidence_limit),
            }
        )
    rows.sort(
        key=lambda row: (
            row["disposition"] != "quarantine",
            row["classification"] != "confirmed-noisy",
            -int(row["collisions"]),
            str(row["signature_id"]),
        )
    )
    total_hashes = len(rows)
    row_limit = (
        int(config["display"]["max_hash_rows"])
        if max_hash_rows is None
        else max_hash_rows
    )
    if type(row_limit) is not int or row_limit < 0:
        raise ValueError("noisy-hash max_hash_rows must be a non-negative integer")
    returned_rows = rows[:row_limit]
    full_summary = {
        "observed_hashes": total_hashes,
        "returned_hashes": total_hashes,
        "hash_rows_truncated": 0,
        "candidate_noisy": sum(
            row["classification"] == "candidate-noisy" for row in rows
        ),
        "confirmed_noisy": sum(
            row["classification"] == "confirmed-noisy" for row in rows
        ),
        "quarantined": sum(row["disposition"] == "quarantine" for row in rows),
        "reviewed_shared": sum(row["disposition"] == "reviewed-shared" for row in rows),
        "cleared": sum(row["disposition"] == "cleared" for row in rows),
        "reports_scanned": reports_scanned,
        "evidence_databases_scanned": evidence_databases_scanned,
    }
    body = {
        "schema_version": NOISY_HASH_STATUS_SCHEMA,
        "id": config["id"],
        "label": config["label"],
        "state": config["state"],
        "authority_path": config["authority_path"],
        "authority_sha256": config["authority_sha256"],
        "classification": config["classification"],
        "management": config["management"],
        "summary": full_summary,
        "hashes": rows,
    }
    digest = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"), default=list).encode()
    ).hexdigest()
    response_summary = {
        **full_summary,
        "returned_hashes": len(returned_rows),
        "hash_rows_truncated": total_hashes - len(returned_rows),
    }
    return {
        **body,
        "summary": response_summary,
        "hashes": returned_rows,
        "status_digest": digest,
    }


def save_noisy_hash_decision(
    project_root: str | Path,
    signature_id: str,
    state: str,
    reason: str,
    *,
    reviewed_by: str = "local-operator",
    authority: str | Path = DEFAULT_AUTHORITY,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    status = compile_noisy_hashes(root, authority, max_hash_rows=2**31 - 1)
    matches = [row for row in status["hashes"] if row["signature_id"] == signature_id]
    if len(matches) != 1:
        raise ValueError("signature_id is not present in the current noisy-hash ledger")
    if state not in status["management"]["allowed_states"]:
        raise ValueError("unsupported noisy-hash disposition")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
        raise ValueError("decision reason must contain 1-500 characters")
    if (
        not isinstance(reviewed_by, str)
        or not reviewed_by.strip()
        or len(reviewed_by) > 100
    ):
        raise ValueError("reviewed_by must contain 1-100 characters")
    row = matches[0]
    document = {
        "schema_version": NOISY_HASH_DECISION_SCHEMA,
        "signature_id": signature_id,
        "scope": row["scope"],
        "signature": row["signature"],
        "state": state,
        "reason": reason.strip(),
        "reviewed_by": reviewed_by.strip(),
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
        "source_status_digest": status["status_digest"],
    }
    decision_root = _inside(root, "validation/noisy-hash-decisions", "decision root")
    decision_root.mkdir(parents=True, exist_ok=True)
    destination = decision_root / f"{signature_id}.toml"
    rendered = "\n".join(
        [
            f'schema_version = {json.dumps(document["schema_version"])}',
            f'signature_id = {json.dumps(document["signature_id"])}',
            f'scope = {json.dumps(document["scope"])}',
            f'signature = {json.dumps(document["signature"])}',
            f'state = {json.dumps(document["state"])}',
            f'reason = {json.dumps(document["reason"])}',
            f'reviewed_by = {json.dumps(document["reviewed_by"])}',
            f'reviewed_at = {json.dumps(document["reviewed_at"])}',
            f'source_status_digest = {json.dumps(document["source_status_digest"])}',
            "",
        ]
    )
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{signature_id}.", suffix=".tmp", dir=decision_root
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return compile_noisy_hashes(root, authority)
