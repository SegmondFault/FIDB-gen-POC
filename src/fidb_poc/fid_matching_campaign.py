"""Schedule and execute the native-FID C10 validation methodology."""

from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import tomllib
from typing import Iterable, Mapping
from zoneinfo import ZoneInfo

from .fid_match_qualification import (
    _fidb_from_signatures,
    qualify_retained_validation,
    run_compact_retained_validation,
)
from .fid_compact import (
    build_compact_candidate_index,
    load_fid_matching_performance,
    selected_backend_id,
    validate_compact_candidate_index,
)
from .fid_matching import load_matching_authority
from .fid_reference_population import resolve_linked_generation
from .machine_validation import LINK_HARNESS_POLICY

CAMPAIGN_SCHEMA = "fidb-fid-matching-campaign/v1"
STATUS_SCHEMA = "fidb-fid-matching-campaign-status/v1"
REPORT_SCHEMA = "fidb-fid-matching-campaign-report/v1"
DEFAULT_CAMPAIGN = Path("validation/fid-matching-run.toml")


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


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


def _acquire_campaign_lock(path: Path) -> int:
    """Acquire a crash-safe process lock and leave an inspectable owner record."""

    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        os.close(descriptor)
        raise ValueError("another FID matching campaign process is active") from error
    payload = json.dumps(
        {
            "pid": os.getpid(),
            "acquired_at": datetime.now(timezone.utc).isoformat(),
        },
        sort_keys=True,
    ).encode("utf-8")
    os.ftruncate(descriptor, 0)
    os.write(descriptor, payload)
    os.fsync(descriptor)
    return descriptor


def _release_campaign_lock(descriptor: int) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _clock_minutes(value: str) -> int:
    try:
        hour, minute = (int(part) for part in value.split(":"))
    except (TypeError, ValueError) as error:
        raise ValueError(f"invalid FID matching schedule time: {value}") from error
    if not 0 <= hour <= 23 or not 0 <= minute <= 59:
        raise ValueError(f"invalid FID matching schedule time: {value}")
    return hour * 60 + minute


def _reference_policy(document: Mapping[str, object]) -> dict[str, object]:
    raw = document.get("reference")
    if raw is None:
        return {
            "population": "archive-only",
            "component": [
                {
                    "id": "archive",
                    "kind": "archive-evidence",
                    "candidate_index": None,
                }
            ],
            "legacy_default": True,
        }
    if not isinstance(raw, dict) or set(raw) != {"population", "component"}:
        raise ValueError("FID matching reference population is invalid")
    population = str(raw["population"])
    expected_kinds = {
        "archive-only": ["archive-evidence"],
        "linked-only": ["linked-generation"],
        "archive-plus-linked": ["archive-evidence", "linked-generation"],
    }
    if population not in expected_kinds or not isinstance(raw["component"], list):
        raise ValueError("FID matching reference population is unsupported")
    components = []
    ids = set()
    for item in raw["component"]:
        if not isinstance(item, dict):
            raise ValueError("FID matching reference component is invalid")
        kind = str(item.get("kind"))
        component_id = str(item.get("id"))
        if not component_id or component_id in ids:
            raise ValueError("FID matching reference component identity is invalid")
        ids.add(component_id)
        if kind == "archive-evidence" and set(item) == {
            "id",
            "kind",
            "candidate_index",
        }:
            candidate_index = str(item["candidate_index"])
            if not candidate_index:
                raise ValueError("archive reference index path is empty")
            components.append(
                {
                    "id": component_id,
                    "kind": kind,
                    "candidate_index": candidate_index,
                }
            )
        elif kind == "linked-generation" and set(item) == {
            "id",
            "kind",
            "generation_seal",
        }:
            generation_seal = str(item["generation_seal"])
            if not generation_seal:
                raise ValueError("linked reference generation seal path is empty")
            components.append(
                {
                    "id": component_id,
                    "kind": kind,
                    "generation_seal": generation_seal,
                }
            )
        else:
            raise ValueError("FID matching reference component is unsupported")
    if [str(row["kind"]) for row in components] != expected_kinds[population]:
        raise ValueError("FID matching reference components do not match population")
    return {
        "population": population,
        "component": components,
        "legacy_default": False,
    }


def load_campaign(
    project_root: str | Path, authority: str | Path = DEFAULT_CAMPAIGN
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    path = _inside(root, authority, "FID matching campaign")
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    expected = {
        "schema_version",
        "id",
        "state",
        "enabled",
        "source_run_id",
        "runtime",
        "matching_authority",
        "qualification_evidence",
        "output_root",
        "methodology",
        "execution",
        "canary",
        "safety",
        "schedule",
    }
    if (
        frozenset(document)
        not in {frozenset(expected), frozenset(expected | {"reference"})}
        or document.get("schema_version") != CAMPAIGN_SCHEMA
    ):
        raise ValueError("FID matching campaign has unsupported fields or schema")
    if document["state"] != "scheduled" or document["enabled"] is not True:
        raise ValueError("FID matching campaign is not scheduled")
    methodology = document["methodology"]
    if methodology != {
        "decision_unit": "query-function-library-owner",
        "candidate_semantics": "compact-portable-ghidra-fid-v1",
        "truth_precedence": ["linker-map", "unique-reference-name"],
        "unresolved_truth": "retain-exclude-from-confusion-matrix",
        "retain_hash_types": ["full", "specific", "complete"],
        "retain_oracle_inputs": "canary-only",
        "retain_backend_outputs": "canary-only",
        "retain_hash_observations": True,
        "backend_contract": "selected-backend-no-fallback-canary",
        "required_link_harness": LINK_HARNESS_POLICY,
    }:
        raise ValueError("FID matching campaign methodology is unsupported")
    execution = document["execution"]
    if (
        set(execution)
        != {
            "workers",
            "scheduling",
            "engine",
            "performance",
            "compare_cpu_and_gpu",
            "finish_started",
            "resume_completed_cases",
        }
        or not 1 <= int(execution["workers"]) <= 16
        or execution["scheduling"] != "largest-query-first-greedy-v1"
        or execution["engine"] != "compact-selected-backend-v1"
    ):
        raise ValueError("FID matching execution policy is invalid")
    if (
        not isinstance(execution["compare_cpu_and_gpu"], bool)
        or execution["finish_started"] is not True
        or execution["resume_completed_cases"] is not True
    ):
        raise ValueError("FID matching execution policy is invalid")
    canary = document["canary"]
    if (
        set(canary)
        != {
            "cases",
            "workers",
            "oracle_replay_campaign_id",
            "minimum_truth_coverage",
            "require_zero_decision_mismatches",
            "auto_chain_full",
        }
        or not canary["cases"]
        or not 1 <= int(canary["workers"]) <= int(execution["workers"])
        or not str(canary["oracle_replay_campaign_id"])
    ):
        raise ValueError("FID matching canary policy is invalid")
    for case in canary["cases"]:
        _parse_case(str(case))
    if not 0 < float(canary["minimum_truth_coverage"]) <= 1:
        raise ValueError("FID matching canary truth coverage is invalid")
    if canary["require_zero_decision_mismatches"] is not True:
        raise ValueError("FID matching canary must fail closed on oracle mismatch")
    if document["safety"] != {
        "execute_target_binaries": False,
        "start_compilers": False,
        "mutate_production_queue": False,
        "require_no_active_production_jobs": True,
    }:
        raise ValueError("FID matching campaign violates the safety contract")
    schedule = document["schedule"]
    if set(schedule) != {"timezone", "window"} or not schedule["window"]:
        raise ValueError("FID matching schedule is invalid")
    ZoneInfo(str(schedule["timezone"]))
    for window in schedule["window"]:
        if (
            set(window)
            != {
                "id",
                "kind",
                "days",
                "start",
                "stop_admitting",
                "enabled",
            }
            or window["kind"] != "weekly"
        ):
            raise ValueError("FID matching schedule window is unsupported")
        if _clock_minutes(str(window["start"])) == _clock_minutes(
            str(window["stop_admitting"])
        ):
            raise ValueError("FID matching schedule window cannot span a full day")
    return {
        **document,
        "reference": _reference_policy(document),
        "authority_path": str(path.relative_to(root)),
        "authority_sha256": _sha256(path),
    }


def _parse_case(value: str) -> tuple[int, str]:
    try:
        raw_position, fold = value.split(":", 1)
        position = int(raw_position)
    except (ValueError, TypeError) as error:
        raise ValueError(f"invalid FID matching case: {value}") from error
    if position < 1 or fold not in {"A", "B"}:
        raise ValueError(f"invalid FID matching case: {value}")
    return position, fold


def _expected_cases(campaign: Mapping[str, object], mode: str) -> list[tuple[int, str]]:
    if mode == "canary":
        return [_parse_case(str(value)) for value in campaign["canary"]["cases"]]
    if mode != "full":
        raise ValueError("FID matching campaign mode must be canary or full")
    return [(position, fold) for position in range(1, 223) for fold in ("A", "B")]


def _balanced_case_chunks(
    weighted_cases: Iterable[tuple[str, int]], workers: int
) -> tuple[list[list[str]], list[int]]:
    """Deterministically schedule the largest retained queries first.

    Greedy least-loaded bin packing prevents regularly ordered treatments or
    folds from concentrating expensive cases on one long-lived JVM worker.
    """

    pending = sorted(weighted_cases, key=lambda row: (-row[1], row[0]))
    if not pending:
        return [], []
    count = min(workers, len(pending))
    chunks: list[list[str]] = [[] for _ in range(count)]
    loads = [0 for _ in range(count)]
    for case, weight in pending:
        worker = min(range(count), key=lambda index: (loads[index], index))
        chunks[worker].append(case)
        loads[worker] += weight
    return chunks, loads


def _campaign_root(root: Path, campaign: Mapping[str, object]) -> Path:
    return _inside(
        root,
        Path(str(campaign["output_root"])) / str(campaign["id"]),
        "FID matching campaign output",
    )


def _tree_bytes(path: Path) -> int:
    return sum(
        item.stat().st_size
        for item in path.rglob("*")
        if item.is_file() and not item.is_symlink()
    )


def _cleanup_campaign_scratch(
    root: Path, campaign: Mapping[str, object]
) -> dict[str, object]:
    """Remove only known disposable matcher scratch after workers have exited."""

    campaign_root = _campaign_root(root, campaign)
    candidates = [
        campaign_root / "compact-index-ghidra-user",
        campaign_root / "worker-scratch",
    ]
    cases = campaign_root / "cases"
    if cases.is_dir():
        candidates.extend(cases.glob("*/work"))
    removed = []
    recoverable_bytes = 0
    for path in candidates:
        if not path.exists():
            continue
        resolved = path.resolve()
        if path.is_symlink() or campaign_root not in resolved.parents:
            raise ValueError(f"matcher scratch cleanup target is unsafe: {path}")
        recoverable_bytes += _tree_bytes(path)
        shutil.rmtree(path)
        removed.append(str(path.relative_to(root)))
    return {
        "state": "complete",
        "removed_paths": removed,
        "recoverable_bytes": recoverable_bytes,
    }


def _compact_index_entries(
    root: Path, evidence: Mapping[str, object]
) -> list[dict[str, object]]:
    entries = []
    for (owner, route_id, treatment_id), item in sorted(
        evidence["signatures"].items()
    ):
        fidb = _fidb_from_signatures(root, Path(item["path"]))
        entries.append(
            {
                "owner": str(owner),
                "route_id": str(route_id),
                "treatment_id": str(treatment_id),
                "fidb_path": str(fidb),
                "fidb_sha256": _sha256(fidb),
            }
        )
    return entries


def _entries_identity(entries: Iterable[Mapping[str, object]]) -> str:
    rows = sorted(
        (
            str(row["owner"]),
            str(row["route_id"]),
            str(row["treatment_id"]),
            str(row["fidb_sha256"]),
        )
        for row in entries
    )
    return hashlib.sha256(
        json.dumps(rows, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _reference_components(
    root: Path,
    campaign: Mapping[str, object],
    evidence: Mapping[str, object],
) -> dict[str, object]:
    archive_entries = _compact_index_entries(root, evidence)
    expected = [tuple(map(str, key)) for key in evidence["signatures"]]
    components = []
    for specification in campaign["reference"]["component"]:
        kind = str(specification["kind"])
        if kind == "archive-evidence":
            entries = [dict(row) for row in archive_entries]
            identity = {
                "id": str(specification["id"]),
                "kind": kind,
                "entries_sha256": _entries_identity(entries),
                "entry_count": len(entries),
                "candidate_index": specification.get("candidate_index"),
            }
        else:
            generation = resolve_linked_generation(
                root,
                str(specification["generation_seal"]),
                source_run_id=str(campaign["source_run_id"]),
                expected_identities=expected,
            )
            entries = [dict(row) for row in generation.pop("entries")]
            generation_id = str(generation.pop("id"))
            identity = {
                "id": str(specification["id"]),
                "kind": kind,
                "generation_id": generation_id,
                **generation,
            }
        components.append({**identity, "entries": entries})
    population_identity = {
        "population": campaign["reference"]["population"],
        "components": [
            {key: value for key, value in row.items() if key != "entries"}
            for row in components
        ],
    }
    return {
        **population_identity,
        "population_sha256": hashlib.sha256(
            json.dumps(
                population_identity, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest(),
        "components": components,
    }


def _ensure_compact_candidate_indexes(
    root: Path,
    campaign: Mapping[str, object],
    evidence: Mapping[str, object],
    runtime: Mapping[str, object],
    ghidra_user_home: Path,
) -> dict[str, object]:
    """Resolve every population component while peer workers wait."""

    from . import ghidra_fid
    from .pipeline import find_ghidra, ghidra_environment

    campaign_root = _campaign_root(root, campaign)
    campaign_root.mkdir(parents=True, exist_ok=True)
    lock_path = campaign_root / ".compact-index.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        population = _reference_components(root, campaign, evidence)
        ghidra_started = False

        def inspect(path: Path) -> Mapping[str, object]:
            nonlocal ghidra_started
            if not ghidra_started:
                os.environ["GHIDRA_HEADLESS"] = str(runtime["ghidra_headless"])
                _headless, ghidra_home = find_ghidra()
                ghidra_fid.ensure_started(
                    ghidra_home,
                    ghidra_environment(ghidra_user_home),
                )
                ghidra_started = True
            return ghidra_fid.inspect_fid_candidate_source(path)

        indexes = []
        for component in population["components"]:
            external = component.get("candidate_index")
            if external:
                destination = _inside(root, str(external), "archive candidate index")
                status = validate_compact_candidate_index(
                    component["entries"], destination
                )
                index_mode = "immutable-reuse"
            else:
                suffix = "" if campaign["reference"]["legacy_default"] else (
                    f'-{component["id"]}'
                )
                destination = campaign_root / f"compact-candidate-index{suffix}.sqlite3"
                status = build_compact_candidate_index(
                    component["entries"], destination, inspect
                )
                index_mode = "campaign-local"
            indexes.append(
                {
                    **status,
                    "component_id": component["id"],
                    "component_kind": component["kind"],
                    "index_mode": index_mode,
                }
            )
        return {
            "population": population["population"],
            "population_sha256": population["population_sha256"],
            "components": [
                {key: value for key, value in row.items() if key != "entries"}
                for row in population["components"]
            ],
            "indexes": indexes,
            "_entries": [
                dict(entry)
                for component in population["components"]
                for entry in component["entries"]
            ],
        }
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _case_summary_path(
    root: Path, campaign: Mapping[str, object], position: int, fold: str
) -> Path:
    return (
        _campaign_root(root, campaign)
        / "cases"
        / f"{campaign['source_run_id']}-{position:03d}-{fold}"
        / "summary.json"
    )


def _reusable_case(
    root: Path,
    campaign: Mapping[str, object],
    position: int,
    fold: str,
    method_sha256: str,
    selected_backend: str,
) -> bool:
    path = _case_summary_path(root, campaign, position, fold)
    if not path.is_file():
        return False
    try:
        previous = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    case = previous.get("case", {})
    return (
        previous.get("state") == "qualified"
        and previous.get("authority_sha256") == method_sha256
        and previous.get("selected_backend") == selected_backend
        and case.get("run_id") == campaign["source_run_id"]
        and int(case.get("position", -1)) == position
        and case.get("fold") == fold
        and case.get("link_harness_policy")
        == campaign["methodology"]["required_link_harness"]
        and (
            campaign["reference"]["legacy_default"]
            or case.get("campaign_authority_sha256")
            == campaign["authority_sha256"]
        )
    )


def _archive_prior_case_failure(summary_path: Path) -> str | None:
    failure = summary_path.with_name("failure.json")
    if not failure.is_file():
        return None
    attempts = summary_path.parent / "attempts"
    attempts.mkdir(parents=True, exist_ok=True)
    ordinals = []
    for path in attempts.glob("attempt-*-failure.json"):
        try:
            ordinals.append(int(path.name.split("-", 2)[1]))
        except (IndexError, ValueError):
            continue
    destination = attempts / f"attempt-{max(ordinals, default=0) + 1:03d}-failure.json"
    failure.replace(destination)
    return str(destination)


def _scheduled_case_chunks(
    root: Path,
    campaign: Mapping[str, object],
    mode: str,
) -> tuple[list[list[str]], dict[str, object]]:
    from .machine_validation_runner import load_runtime

    runtime = load_runtime(root, str(campaign["runtime"]))
    run_root = _inside(
        root,
        Path(str(runtime["output_root"])) / str(campaign["source_run_id"]),
        "FID matching source run",
    )
    method = load_matching_authority(root, str(campaign["matching_authority"]))
    weighted = []
    reused = 0
    for position, fold in _expected_cases(campaign, mode):
        if _reusable_case(
            root,
            campaign,
            position,
            fold,
            str(method["authority_sha256"]),
            str(method["selected"]),
        ):
            reused += 1
            continue
        matches = list((run_root / "units").glob(f"{position:03d}-*/result.json"))
        if len(matches) != 1:
            raise ValueError(f"{position}:{fold} source unit is missing or ambiguous")
        result = json.loads(matches[0].read_text(encoding="utf-8"))
        fold_results = [
            row for row in result.get("folds", []) if row.get("fold") == fold
        ]
        if len(fold_results) != 1:
            raise ValueError(f"{position}:{fold} source fold evidence is absent")
        weight = int(
            fold_results[0].get("signature_summary", {}).get("functions_hashed", 0)
        )
        if weight < 1:
            raise ValueError(f"{position}:{fold} source query cost is unavailable")
        weighted.append((f"{position}:{fold}", weight))
    workers = int(
        campaign["canary"]["workers"]
        if mode == "canary"
        else campaign["execution"]["workers"]
    )
    chunks, loads = _balanced_case_chunks(weighted, workers)
    return chunks, {
        "policy": campaign["execution"]["scheduling"],
        "estimated_function_loads": loads,
        "pending_cases": len(weighted),
        "reused_cases": reused,
    }


def _terminal_campaign_report(
    root: Path,
    campaign: Mapping[str, object],
    mode: str,
) -> dict[str, object] | None:
    path = _campaign_root(root, campaign) / f"{mode}-report.json"
    if not path.is_file():
        return None
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    method = load_matching_authority(root, str(campaign["matching_authority"]))
    expected_state = "qualified" if mode == "canary" else "measured-complete"
    progress = report.get("progress", {})
    expected_cases = len(_expected_cases(campaign, mode))
    if (
        report.get("schema_version") != REPORT_SCHEMA
        or report.get("campaign_id") != campaign["id"]
        or report.get("mode") != mode
        or report.get("state") != expected_state
        or report.get("authority_sha256") != campaign["authority_sha256"]
        or report.get("source_run_id") != campaign["source_run_id"]
        or report.get("method_authority", {}).get("sha256")
        != method["authority_sha256"]
        or int(progress.get("expected_cases", -1)) != expected_cases
        or int(progress.get("complete_cases", -1)) != expected_cases
        or int(progress.get("failed_or_pending_cases", -1)) != 0
    ):
        return None
    return report


def _aggregate(
    root: Path, campaign: Mapping[str, object], mode: str
) -> dict[str, object]:
    expected = _expected_cases(campaign, mode)
    summaries = []
    failures = []
    pending = 0
    matrix = {
        "true_positives": 0,
        "false_positives": 0,
        "true_negatives": 0,
        "false_negatives": 0,
    }
    truth_labelled = 0
    truth_unlabelled = 0
    mismatch_count = 0
    selected_backends = set()
    requested_backends = set()
    fallback_cases = []
    reference_receipts: dict[str, dict[str, object]] = {}
    for position, fold in expected:
        path = _case_summary_path(root, campaign, position, fold)
        if not path.is_file():
            failure_path = path.with_name("failure.json")
            if failure_path.is_file():
                failures.append(
                    {
                        "case": f"{position}:{fold}",
                        "error": json.loads(
                            failure_path.read_text(encoding="utf-8")
                        ).get("error", "failed without an error message"),
                    }
                )
            else:
                pending += 1
            continue
        summary = json.loads(path.read_text(encoding="utf-8"))
        if summary.get("state") != "qualified":
            failures.append({"case": f"{position}:{fold}", "error": summary["state"]})
            continue
        summaries.append(summary)
        receipt = summary.get("case", {}).get("reference_population", {})
        if isinstance(receipt, dict) and receipt:
            identity = str(receipt.get("population_sha256", ""))
            reference_receipts[identity] = receipt
        selected_backends.add(str(summary["selected_backend"]))
        requested_backends.add(str(summary["requested_backend"]))
        if summary.get("performance", {}).get("fallback_reason"):
            fallback_cases.append(f"{position}:{fold}")
        classification = summary["classification"]
        for key in matrix:
            matrix[key] += int(classification["confusion_matrix"][key])
        truth_labelled += int(classification["truth"]["labelled_functions"])
        truth_unlabelled += int(classification["truth"]["unlabelled_functions"])
        mismatch_count += sum(
            int(row["decision_mismatches"]) for row in summary["comparisons"]
        )
    total_truth = truth_labelled + truth_unlabelled
    truth_coverage = truth_labelled / total_truth if total_truth else 0.0
    complete = len(summaries) == len(expected) and not failures
    if len(reference_receipts) > 1:
        failures.append(
            {
                "case": "reference-population",
                "error": "case evidence used multiple reference populations",
            }
        )
        complete = False
    performance = load_fid_matching_performance(
        root, str(campaign["execution"]["performance"])
    )
    requested_backend = selected_backend_id(
        performance, load_matching_authority(root, str(campaign["matching_authority"]))
    )
    backend_contract_met = (
        selected_backends in (set(), {requested_backend})
        and requested_backends in (set(), {requested_backend})
        and not fallback_cases
    )
    canary_passed = (
        complete
        and mismatch_count == 0
        and backend_contract_met
        and truth_coverage >= float(campaign["canary"]["minimum_truth_coverage"])
    )
    if mode == "canary" and canary_passed:
        state = "qualified"
    elif mode == "full" and complete and mismatch_count == 0:
        state = "measured-complete"
    elif failures or mismatch_count:
        state = "incomplete-or-failed"
    elif summaries:
        state = "partial"
    else:
        state = "pending"
    stage_state = (
        "complete"
        if complete
        else (
            "failed"
            if failures or mismatch_count
            else "partial" if summaries else "pending"
        )
    )
    matching = load_matching_authority(root, str(campaign["matching_authority"]))
    portable_stages = (
        [
            {"id": f"portable-{row['device']}", "state": stage_state}
            for row in matching["backend"]
        ]
        if campaign["execution"]["compare_cpu_and_gpu"]
        else [
            {
                "id": f"portable-{matching['backends'][matching['selected']]['device']}",
                "state": stage_state,
            }
        ]
    )
    return {
        "schema_version": REPORT_SCHEMA,
        "campaign_id": campaign["id"],
        "mode": mode,
        "state": state,
        "authority_path": campaign["authority_path"],
        "authority_sha256": campaign["authority_sha256"],
        "source_run_id": campaign["source_run_id"],
        "reference_population": (
            next(iter(reference_receipts.values()))
            if reference_receipts
            else campaign["reference"]
        ),
        "workers": (
            campaign["canary"]["workers"]
            if mode == "canary"
            else campaign["execution"]["workers"]
        ),
        "backend": {
            "requested": requested_backend,
            "effective": sorted(selected_backends),
            "fallback_cases": fallback_cases,
            "contract_met": backend_contract_met,
            "performance_authority_path": performance["authority_path"],
            "performance_authority_sha256": performance["authority_sha256"],
        },
        "method_authority": {
            "id": "compact-portable-fid-owner-validation-v1",
            "path": matching["authority_path"],
            "sha256": matching["authority_sha256"],
            "algorithm_id": "compact-index-portable-fid-v1",
        },
        "decision_contract": {
            "true_positive": "qualified portable FID accepts the link-attributed library owner",
            "false_positive": "qualified portable FID accepts an owner other than the link-attributed owner",
            "true_negative": "qualified portable FID rejects an incorrect library owner",
            "false_negative": "qualified portable FID does not accept the link-attributed library owner",
            "unresolved_truth": "retained but excluded from the confusion matrix",
        },
        "construct_validity": {
            "state": "native-oracle-qualified-portable-fid-owner-ground-truth",
            "recall_claim": "synthetic-linked-executable-native-fid-recall",
            "reference_unit": "per-library-fid-function-record",
            "query_unit": "link-attributed-composite-function",
            "truth_precedence": campaign["methodology"]["truth_precedence"],
        },
        "pipeline_job": {
            "id": "native-fid-hash-discrimination",
            "kind": "validation-postprocess",
            "state": stage_state,
            "materialized_with_batch": True,
            "required_for_run_completion": True,
            "stages": [
                {
                    "id": "compact-candidate-index",
                    "state": stage_state,
                    "components": [
                        str(row["id"])
                        for row in campaign["reference"]["component"]
                    ],
                },
                {"id": "query-relationship-evidence", "state": stage_state},
                *(
                    [{"id": "native-oracle-replay", "state": stage_state}]
                    if mode == "canary"
                    else []
                ),
                *portable_stages,
                {"id": "owner-classification", "state": stage_state},
                {"id": "hash-population", "state": stage_state},
            ],
        },
        "progress": {
            "expected_cases": len(expected),
            "complete_cases": len(summaries),
            "failed_cases": len(failures),
            "pending_cases": pending,
            "failed_or_pending_cases": len(failures) + pending,
        },
        "oracle": {
            "decision_mismatches": mismatch_count,
            "canary_passed": (canary_passed if mode == "canary" and complete else None),
        },
        "truth": {
            "labelled_functions": truth_labelled,
            "unlabelled_functions": truth_unlabelled,
            "coverage": truth_coverage,
        },
        "confusion_matrix": matrix,
        "failures": failures[:1000],
    }


def _publish_hash_evidence(
    root: Path,
    campaign: Mapping[str, object],
    mode: str,
    report: dict[str, object],
) -> None:
    """Roll retained per-case observations into a compact, queryable sidecar."""

    destination = _campaign_root(root, campaign) / f"{mode}-hash-evidence.sqlite3"
    temporary = destination.with_suffix(".sqlite3.part")
    temporary.unlink(missing_ok=True)
    connection = sqlite3.connect(temporary)
    observed = 0
    try:
        connection.executescript("""
            PRAGMA journal_mode=OFF;
            PRAGMA synchronous=OFF;
            CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
            CREATE TABLE hash_owner(
                scope TEXT NOT NULL,
                hash_type TEXT NOT NULL,
                value TEXT NOT NULL,
                owner TEXT NOT NULL,
                observations INTEGER NOT NULL,
                true_positives INTEGER NOT NULL,
                false_positives INTEGER NOT NULL,
                false_negatives INTEGER NOT NULL,
                shared_code INTEGER NOT NULL,
                ambiguous_attribution INTEGER NOT NULL,
                incorrect_confident_attribution INTEGER NOT NULL,
                PRIMARY KEY(scope, hash_type, value, owner)
            ) WITHOUT ROWID;
            """)
        insert = """
            INSERT INTO hash_owner VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(scope, hash_type, value, owner) DO UPDATE SET
              observations=observations+excluded.observations,
              true_positives=true_positives+excluded.true_positives,
              false_positives=false_positives+excluded.false_positives,
              false_negatives=false_negatives+excluded.false_negatives,
              shared_code=shared_code+excluded.shared_code,
              ambiguous_attribution=ambiguous_attribution+excluded.ambiguous_attribution,
              incorrect_confident_attribution=incorrect_confident_attribution+excluded.incorrect_confident_attribution
        """
        for position, fold in _expected_cases(campaign, mode):
            summary_path = _case_summary_path(root, campaign, position, fold)
            if not summary_path.is_file():
                continue
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            classification_path = _inside(
                root,
                str(summary["classification_path"]),
                "FID classification evidence",
            )
            classification = json.loads(classification_path.read_text(encoding="utf-8"))
            case = summary["case"]
            scope = "|".join(
                (
                    str(case.get("target_os", "unknown")),
                    str(case.get("binary_format", "unknown")),
                    str(case.get("ghidra_language_id", "unknown")),
                    str(case.get("ghidra_compiler_spec_id", "unknown")),
                )
            )
            rows = []
            for observation in classification["observations"]:
                outcome = str(observation["outcome"])
                category = str(observation["category"])
                rows.append(
                    (
                        scope,
                        str(observation["hash_type"]),
                        str(observation["value"]),
                        str(observation["candidate_owner"]),
                        1,
                        int(outcome == "tp"),
                        int(outcome == "fp"),
                        int(outcome == "fn"),
                        int(category == "shared-code-evidence"),
                        int(category == "ambiguous-attribution"),
                        int(category == "incorrect-confident-attribution"),
                    )
                )
            connection.executemany(insert, rows)
            observed += len(rows)
            connection.commit()
        connection.executescript("""
            CREATE TABLE hash_population AS
            SELECT scope, hash_type, value,
                   COUNT(*) AS distinct_owners,
                   SUM(observations) AS observations,
                   SUM(true_positives) AS true_positives,
                   SUM(false_positives) AS false_positives,
                   SUM(false_negatives) AS false_negatives,
                   SUM(shared_code) AS shared_code,
                   SUM(ambiguous_attribution) AS ambiguous_attribution,
                   SUM(incorrect_confident_attribution) AS incorrect_confident_attribution
            FROM hash_owner GROUP BY scope, hash_type, value;
            CREATE UNIQUE INDEX hash_population_identity
            ON hash_population(scope, hash_type, value);
            CREATE INDEX hash_population_noise
            ON hash_population(hash_type, false_positives DESC, distinct_owners DESC);
            """)
        metadata = {
            "schema_version": "fidb-portable-fid-hash-evidence/v1",
            "campaign_id": str(campaign["id"]),
            "source_run_id": str(campaign["source_run_id"]),
            "authority_sha256": str(campaign["authority_sha256"]),
            "observations": str(observed),
        }
        connection.executemany(
            "INSERT INTO metadata VALUES (?,?)", sorted(metadata.items())
        )
        connection.commit()

        hash_types = []
        for hash_type in ("full", "specific", "complete"):
            population = connection.execute(
                """
                SELECT COUNT(*), SUM(distinct_owners=1), SUM(distinct_owners>1),
                       SUM(distinct_owners),
                       SUM(CASE WHEN distinct_owners>1 THEN distinct_owners ELSE 0 END),
                       SUM(observations), SUM(false_positives), MAX(distinct_owners)
                FROM hash_population WHERE hash_type=?
                """,
                (hash_type,),
            ).fetchone()
            distinct_values = int(population[0] or 0)
            noisy_values = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM hash_population
                    WHERE hash_type=? AND false_positives>0
                    """,
                    (hash_type,),
                ).fetchone()[0]
            )
            distribution = [
                {
                    "distinct_owners": int(row[0]),
                    "distinct_values": int(row[1]),
                    "fraction_of_values": (
                        int(row[1]) / distinct_values if distinct_values else 0.0
                    ),
                }
                for row in connection.execute(
                    """
                    SELECT distinct_owners, COUNT(*) FROM hash_population
                    WHERE hash_type=? GROUP BY distinct_owners ORDER BY distinct_owners
                    """,
                    (hash_type,),
                )
            ]
            top_ambiguous = []
            for row in connection.execute(
                """
                SELECT scope, value, distinct_owners, observations,
                       false_positives FROM hash_population
                WHERE hash_type=? AND (distinct_owners>1 OR false_positives>0)
                ORDER BY false_positives DESC, distinct_owners DESC, observations DESC
                LIMIT 250
                """,
                (hash_type,),
            ):
                owners = [
                    str(value[0])
                    for value in connection.execute(
                        """
                        SELECT owner FROM hash_owner
                        WHERE scope=? AND hash_type=? AND value=? ORDER BY owner
                        """,
                        (row[0], hash_type, row[1]),
                    )
                ]
                top_ambiguous.append(
                    {
                        "scope": str(row[0]),
                        "language": str(row[0]).split("|", 3)[2],
                        "value": str(row[1]),
                        "distinct_owners": int(row[2]),
                        "reference_observations": int(row[3]),
                        "exact_signature_variants": 1,
                        "exact_false_positive_observations": int(row[4]),
                        "owners": owners,
                    }
                )
            libraries = [
                {
                    "owner": str(row[0]),
                    "distinct_values": int(row[1]),
                    "multi_owner_values": int(row[2]),
                    "ambiguous_fraction": (
                        int(row[2]) / int(row[1]) if int(row[1]) else 0.0
                    ),
                    "reference_observations": int(row[3]),
                    "missed_observations": int(row[4]),
                    "exact_false_positive_observations": int(row[5]),
                }
                for row in connection.execute(
                    """
                    SELECT owner, COUNT(*),
                           SUM(population.distinct_owners>1),
                           SUM(owner.observations), SUM(owner.false_negatives),
                           SUM(owner.false_positives)
                    FROM hash_owner AS owner JOIN hash_population AS population
                      ON population.scope=owner.scope
                     AND population.hash_type=owner.hash_type
                     AND population.value=owner.value
                    WHERE owner.hash_type=? GROUP BY owner ORDER BY owner
                    """,
                    (hash_type,),
                )
            ]
            hash_types.append(
                {
                    "hash_type": hash_type,
                    "distinct_values": distinct_values,
                    "singleton_values": int(population[1] or 0),
                    "multi_owner_values": int(population[2] or 0),
                    "multi_owner_fraction": (
                        int(population[2] or 0) / distinct_values
                        if distinct_values
                        else 0.0
                    ),
                    "owner_links": int(population[3] or 0),
                    "ambiguous_owner_links": int(population[4] or 0),
                    "complete_disambiguated_owner_signatures": 0,
                    "reference_observations": int(population[5] or 0),
                    "exact_false_positive_observations": int(population[6] or 0),
                    "maximum_distinct_owners": int(population[7] or 0),
                    "false_positive_values": noisy_values,
                    "distribution": distribution,
                    "top_ambiguous": top_ambiguous,
                    "libraries": libraries,
                }
            )
    finally:
        connection.close()
    temporary.replace(destination)
    report["hash_type_analysis"] = hash_types
    report["hash_evidence"] = {
        "database_path": str(destination.relative_to(root)),
        "database_sha256": _sha256(destination),
        "query_function_owner_observations": observed,
        "distinct_signatures": next(
            row["distinct_values"]
            for row in hash_types
            if row["hash_type"] == "complete"
        ),
        "noisy_signatures": next(
            row["false_positive_values"]
            for row in hash_types
            if row["hash_type"] == "complete"
        ),
    }


def campaign_status(
    project_root: str | Path, authority: str | Path = DEFAULT_CAMPAIGN
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    campaign = load_campaign(root, authority)
    campaign_root = _campaign_root(root, campaign)
    status_path = campaign_root / "status.json"
    status = (
        json.loads(status_path.read_text(encoding="utf-8"))
        if status_path.is_file()
        else {"state": "scheduled", "mode": None, "started_at": None}
    )
    canary_path = campaign_root / "canary-report.json"
    full_path = campaign_root / "full-report.json"
    matching = load_matching_authority(root, str(campaign["matching_authority"]))

    def current_report(path: Path, mode: str) -> dict[str, object]:
        report = (
            json.loads(path.read_text(encoding="utf-8"))
            if path.is_file()
            else _aggregate(root, campaign, mode)
        )
        method = report.get("method_authority", {})
        current = (
            report.get("authority_sha256") == campaign["authority_sha256"]
            and isinstance(method, dict)
            and method.get("sha256") == matching["authority_sha256"]
        )
        if path.is_file() and not current:
            return {
                **report,
                "state": "stale-authority",
                "stale_reason": "campaign or matching authority digest changed",
            }
        return report

    canary = current_report(canary_path, "canary")
    full = current_report(full_path, "full")
    qualification_path = _inside(
        root, str(campaign["qualification_evidence"]), "FID matching qualification"
    )
    qualification = (
        json.loads(qualification_path.read_text(encoding="utf-8"))
        if qualification_path.is_file()
        else {"state": "absent"}
    )
    if (
        qualification.get("state") == "qualified"
        and qualification.get("authority_sha256") != matching["authority_sha256"]
    ):
        qualification = {**qualification, "state": "stale"}
    return {
        "schema_version": STATUS_SCHEMA,
        "id": campaign["id"],
        "state": status.get("state", "scheduled"),
        "mode": status.get("mode"),
        "started_at": status.get("started_at"),
        "finished_at": status.get("finished_at"),
        "authority_path": campaign["authority_path"],
        "authority_sha256": campaign["authority_sha256"],
        "matching_authority": campaign["matching_authority"],
        "qualification": qualification,
        "source_run_id": campaign["source_run_id"],
        "workers": campaign["execution"]["workers"],
        "schedule": campaign["schedule"],
        "methodology": campaign["methodology"],
        "source_harness": _source_harness_preflight(root, campaign, "canary"),
        "canary": canary,
        "full": full,
    }


def _production_active(root: Path, campaign: Mapping[str, object]) -> int:
    from .machine_validation_runner import load_runtime

    runtime = load_runtime(root, str(campaign["runtime"]))
    ledger = _inside(root, str(runtime["ledger"]), "coordinator ledger")
    connection = sqlite3.connect(f"file:{ledger}?mode=ro", uri=True)
    try:
        row = connection.execute(
            "SELECT COUNT(*) FROM jobs WHERE active=1 AND state IN ('leased','running')"
        ).fetchone()
        return int(row[0])
    finally:
        connection.close()


def _resource_preflight(
    root: Path, campaign: Mapping[str, object]
) -> dict[str, object]:
    from .machine_validation_runner import _available_memory_bytes, load_runtime

    runtime = load_runtime(root, str(campaign["runtime"]))
    available_memory = _available_memory_bytes()
    free_disk = shutil.disk_usage(root).free
    safety = runtime["safety"]
    memory_floor = int(safety["minimum_available_memory_gib"]) * 1024**3
    disk_floor = int(safety["minimum_free_disk_gib"]) * 1024**3
    blockers = []
    if available_memory < memory_floor:
        blockers.append("available memory is below the reviewed safety floor")
    if free_disk < disk_floor:
        blockers.append("free disk is below the reviewed safety floor")
    headless = Path(str(runtime["ghidra_headless"]))
    if not headless.is_file() or not os.access(headless, os.X_OK):
        blockers.append("reviewed Ghidra headless executable is unavailable")
    return {
        "state": "ready" if not blockers else "blocked",
        "available_memory_bytes": available_memory,
        "minimum_available_memory_bytes": memory_floor,
        "free_disk_bytes": free_disk,
        "minimum_free_disk_bytes": disk_floor,
        "blockers": blockers,
    }


def _source_harness_preflight(
    root: Path,
    campaign: Mapping[str, object],
    mode: str,
) -> dict[str, object]:
    from .machine_validation_runner import load_runtime

    required = str(campaign["methodology"]["required_link_harness"])
    expected = len(_expected_cases(campaign, mode))
    try:
        runtime = load_runtime(root, str(campaign["runtime"]))
    except (OSError, ValueError) as error:
        return {
            "state": "blocked",
            "required_link_harness": required,
            "checked_cases": 0,
            "expected_cases": expected,
            "blockers": [f"validation runtime is unavailable: {error}"],
        }
    run_root = _inside(
        root,
        Path(str(runtime["output_root"])) / str(campaign["source_run_id"]),
        "FID matching source run",
    )
    blockers = []
    checked = 0
    for position, fold in _expected_cases(campaign, mode):
        matches = list((run_root / "units").glob(f"{position:03d}-*/result.json"))
        if len(matches) != 1:
            blockers.append(f"{position}:{fold} source unit is missing or ambiguous")
            continue
        try:
            result = json.loads(matches[0].read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            blockers.append(f"{position}:{fold} source result is unreadable")
            continue
        fold_results = [
            row for row in result.get("folds", []) if row.get("fold") == fold
        ]
        if len(fold_results) != 1:
            blockers.append(f"{position}:{fold} source fold evidence is absent")
            continue
        evidence = fold_results[0]
        if evidence.get("link_harness_policy") != required:
            blockers.append(f"{position}:{fold} uses a stale link harness")
            continue
        if evidence.get("link_audit", {}).get("direct_zero_control_flow_count") != 0:
            blockers.append(f"{position}:{fold} failed its zero-control-flow audit")
            continue
        checked += 1
    return {
        "state": "ready" if not blockers else "blocked",
        "required_link_harness": required,
        "checked_cases": checked,
        "expected_cases": expected,
        "blockers": blockers,
    }


def worker_cases(
    project_root: str | Path,
    cases: Iterable[str],
    mode: str,
    authority: str | Path = DEFAULT_CAMPAIGN,
) -> int:
    if mode not in {"canary", "full"}:
        raise ValueError("FID matching worker mode is invalid")
    root = Path(project_root).expanduser().resolve()
    campaign = load_campaign(root, authority)
    method = load_matching_authority(root, str(campaign["matching_authority"]))
    from .machine_validation_runner import (
        load_runtime,
        resolve_hash_analysis_evidence,
    )

    runtime = load_runtime(root, str(campaign["runtime"]))
    evidence = resolve_hash_analysis_evidence(
        root, str(campaign["runtime"])
    )
    execution = runtime["execution"]
    os.environ["_JAVA_OPTIONS"] = (
        f'-Xms{execution["jvm_initial_heap_mib"]}m '
        f'-Xmx{execution["jvm_max_heap_mib"]}m '
        f'-XX:ActiveProcessorCount={execution["jvm_active_processors"]}'
    )
    relative_output = Path(str(campaign["output_root"])) / str(campaign["id"]) / "cases"
    worker_scratch = (
        _campaign_root(root, campaign) / "worker-scratch" / f"worker-{os.getpid()}"
    )
    reference = _ensure_compact_candidate_indexes(
        root, campaign, evidence, runtime, worker_scratch / "ghidra-user"
    )
    index_paths = [str(row["path"]) for row in reference["indexes"]]
    reference_receipt = {
        "population": reference["population"],
        "population_sha256": reference["population_sha256"],
        "components": reference["components"],
        "indexes": [
            {
                "component_id": row["component_id"],
                "component_kind": row["component_kind"],
                "index_mode": row["index_mode"],
                "path": str(Path(str(row["path"])).resolve().relative_to(root)),
                "sha256": row["sha256"],
                "input_digest": row["input_digest"],
                "sources": row["sources"],
                "candidates": row["candidates"],
                "relations": row["relations"],
            }
            for row in reference["indexes"]
        ],
    }
    failed = 0
    for value in cases:
        position, fold = _parse_case(value)
        summary_path = _case_summary_path(root, campaign, position, fold)
        if _reusable_case(
            root,
            campaign,
            position,
            fold,
            str(method["authority_sha256"]),
            str(method["selected"]),
        ):
            continue
        _archive_prior_case_failure(summary_path)
        try:
            replay_root = (
                root
                / str(campaign["output_root"])
                / str(campaign["canary"]["oracle_replay_campaign_id"])
                / "cases"
                / f"{campaign['source_run_id']}-{position:03d}-{fold}"
                if mode == "canary"
                else None
            )
            if mode == "canary" and not campaign["reference"]["legacy_default"]:
                source_matches = list(
                    (
                        _inside(
                            root,
                            Path(str(runtime["output_root"]))
                            / str(campaign["source_run_id"]),
                            "FID matching source run",
                        )
                        / "units"
                    ).glob(f"{position:03d}-*/result.json")
                )
                if len(source_matches) != 1:
                    raise ValueError("native canary source unit is missing")
                source_result = json.loads(
                    source_matches[0].read_text(encoding="utf-8")
                )
                route_id = str(source_result["route_id"])
                treatment_id = str(source_result["treatment_id"])
                candidate_fidbs = [
                    str(row["fidb_path"])
                    for row in reference["_entries"]
                    if row["route_id"] == route_id
                    and row["treatment_id"] == treatment_id
                ]
                qualify_retained_validation(
                    root,
                    str(campaign["source_run_id"]),
                    position=position,
                    fold=fold,
                    runtime_path=str(campaign["runtime"]),
                    authority_path=str(campaign["matching_authority"]),
                    output_root=relative_output,
                    compare_backends=False,
                    candidate_fidbs=candidate_fidbs,
                    candidate_indexes=index_paths,
                    performance_path=str(campaign["execution"]["performance"]),
                    reference_population=reference_receipt,
                    campaign_authority_sha256=str(campaign["authority_sha256"]),
                )
            else:
                run_compact_retained_validation(
                    root,
                    str(campaign["source_run_id"]),
                    position=position,
                    fold=fold,
                    candidate_indexes=index_paths,
                    runtime_path=str(campaign["runtime"]),
                    authority_path=str(campaign["matching_authority"]),
                    performance_path=str(campaign["execution"]["performance"]),
                    output_root=relative_output,
                    oracle_replay_source=replay_root,
                    ghidra_user_home=worker_scratch / "ghidra-user",
                    reference_population=reference_receipt,
                    campaign_authority_sha256=str(campaign["authority_sha256"]),
                )
        except Exception as error:
            failed += 1
            _atomic_json(
                summary_path.with_name("failure.json"),
                {
                    "case": value,
                    "error": f"{type(error).__name__}: {error}",
                    "failed_at": datetime.now(timezone.utc).isoformat(),
                },
            )
    return 1 if failed else 0


def run_campaign(
    project_root: str | Path,
    mode: str,
    authority: str | Path = DEFAULT_CAMPAIGN,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    campaign = load_campaign(root, authority)
    source = _source_harness_preflight(root, campaign, mode)
    if source["blockers"]:
        raise ValueError("; ".join(source["blockers"][:20]))
    if _production_active(root, campaign):
        raise ValueError("production jobs are active; FID matching remains unclaimed")
    resources = _resource_preflight(root, campaign)
    if resources["blockers"]:
        raise ValueError("; ".join(resources["blockers"]))
    campaign_root = _campaign_root(root, campaign)
    campaign_root.mkdir(parents=True, exist_ok=True)
    lock = campaign_root / ".campaign.lock"
    lock_descriptor = _acquire_campaign_lock(lock)
    try:
        stale_scratch = _cleanup_campaign_scratch(root, campaign)
        chunks, scheduling = _scheduled_case_chunks(root, campaign, mode)
        if not chunks:
            terminal = _terminal_campaign_report(root, campaign, mode)
            if terminal is not None:
                _release_campaign_lock(lock_descriptor)
                return terminal
    except Exception:
        _release_campaign_lock(lock_descriptor)
        raise
    started_at = datetime.now(timezone.utc).isoformat()
    _atomic_json(
        campaign_root / "status.json",
        {
            "state": "running",
            "mode": mode,
            "started_at": started_at,
            "worker_pids": [],
            "resource_preflight": resources,
            "source_harness_preflight": source,
            "scheduling": scheduling,
        },
    )
    processes = []
    streams = []
    try:
        for index, chunk in enumerate(chunks, start=1):
            log = (campaign_root / f"{mode}-worker-{index:02d}.log").open(
                "a", encoding="utf-8"
            )
            streams.append(log)
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "fidb_poc.cli",
                    "machine-validation",
                    "_matcher-worker",
                    "--project-root",
                    str(root),
                    "--matcher-campaign",
                    str(campaign["authority_path"]),
                    "--cases",
                    ",".join(chunk),
                    "--mode",
                    mode,
                ],
                cwd=root,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            processes.append(process)
        _atomic_json(
            campaign_root / "status.json",
            {
                "state": "running",
                "mode": mode,
                "started_at": started_at,
                "worker_pids": [process.pid for process in processes],
                "resource_preflight": resources,
                "scheduling": scheduling,
            },
        )
        return_codes = [process.wait() for process in processes]
        retention = _cleanup_campaign_scratch(root, campaign)
        retention["recoverable_bytes"] += stale_scratch["recoverable_bytes"]
        retention["removed_paths"] = sorted(
            set(stale_scratch["removed_paths"] + retention["removed_paths"])
        )
        report = _aggregate(root, campaign, mode)
        _publish_hash_evidence(root, campaign, mode, report)
        report["worker_return_codes"] = return_codes
        report["scheduling"] = scheduling
        report["retention"] = retention
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        report["wall_time_seconds"] = (
            time.time() - datetime.fromisoformat(started_at).timestamp()
        )
        report_path = campaign_root / f"{mode}-report.json"
        _atomic_json(report_path, report)
        final_state = (
            "complete"
            if report["state"] in {"qualified", "measured-complete"}
            else "failed"
        )
        _atomic_json(
            campaign_root / "status.json",
            {
                "state": final_state,
                "mode": mode,
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "worker_pids": [],
                "report_path": str(report_path.relative_to(root)),
                "resource_preflight": resources,
                "scheduling": scheduling,
            },
        )
        return report
    finally:
        for stream in streams:
            stream.close()
        _release_campaign_lock(lock_descriptor)


def _window_open(
    campaign: Mapping[str, object], instant: datetime
) -> tuple[bool, str | None]:
    schedule = campaign["schedule"]
    local = instant.astimezone(ZoneInfo(str(schedule["timezone"])))
    minute = local.hour * 60 + local.minute
    weekday = local.strftime("%a").lower()
    for window in schedule["window"]:
        if not window["enabled"] or weekday not in window["days"]:
            continue
        start = _clock_minutes(str(window["start"]))
        stop = _clock_minutes(str(window["stop_admitting"]))
        open_now = (
            start <= minute < stop if start < stop else minute >= start or minute < stop
        )
        if open_now:
            return True, str(window["id"])
    return False, None


def scheduled_campaign(
    project_root: str | Path,
    authority: str | Path = DEFAULT_CAMPAIGN,
    *,
    now: datetime | None = None,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    campaign = load_campaign(root, authority)
    open_now, window_id = _window_open(campaign, now or datetime.now(timezone.utc))
    if not open_now:
        return {"state": "outside-window", "window_id": None}
    status = campaign_status(root, authority)
    if status["full"]["state"] == "measured-complete":
        return {"state": "nothing-pending", "window_id": window_id}
    if status["canary"]["state"] != "qualified":
        canary = run_campaign(root, "canary", authority)
        if canary["state"] != "qualified":
            return {"state": "canary-failed", "window_id": window_id, "report": canary}
    if campaign["canary"]["auto_chain_full"] is True:
        full = run_campaign(root, "full", authority)
        return {"state": full["state"], "window_id": window_id, "report": full}
    return {"state": "canary-qualified", "window_id": window_id}
