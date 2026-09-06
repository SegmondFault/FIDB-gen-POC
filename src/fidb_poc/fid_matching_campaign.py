"""Schedule and execute the native-FID C10 validation methodology."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import tomllib
from typing import Iterable, Mapping
from zoneinfo import ZoneInfo

from .fid_match_qualification import qualify_retained_validation
from .fid_matching import load_matching_authority

CAMPAIGN_SCHEMA = "fidb-fid-matching-campaign/v1"
STATUS_SCHEMA = "fidb-fid-matching-campaign-status/v1"
REPORT_SCHEMA = "fidb-fid-matching-campaign-report/v1"
DEFAULT_CAMPAIGN = Path("validation/fid-matching-run.toml")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def _clock_minutes(value: str) -> int:
    try:
        hour, minute = (int(part) for part in value.split(":"))
    except (TypeError, ValueError) as error:
        raise ValueError(f"invalid FID matching schedule time: {value}") from error
    if not 0 <= hour <= 23 or not 0 <= minute <= 59:
        raise ValueError(f"invalid FID matching schedule time: {value}")
    return hour * 60 + minute


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
    if set(document) != expected or document.get("schema_version") != CAMPAIGN_SCHEMA:
        raise ValueError("FID matching campaign has unsupported fields or schema")
    if document["state"] != "scheduled" or document["enabled"] is not True:
        raise ValueError("FID matching campaign is not scheduled")
    methodology = document["methodology"]
    if methodology != {
        "decision_unit": "query-function-library-owner",
        "candidate_semantics": "native-ghidra-fid",
        "truth_precedence": ["linker-map", "unique-reference-name"],
        "unresolved_truth": "retain-exclude-from-confusion-matrix",
        "retain_hash_types": ["full", "specific", "complete"],
        "retain_oracle_inputs": True,
        "retain_backend_outputs": True,
        "retain_hash_observations": True,
    }:
        raise ValueError("FID matching campaign methodology is unsupported")
    execution = document["execution"]
    if set(execution) != {
        "workers",
        "compare_cpu_and_gpu",
        "finish_started",
        "resume_completed_cases",
    } or not 1 <= int(execution["workers"]) <= 16:
        raise ValueError("FID matching execution policy is invalid")
    if any(execution[name] is not True for name in execution if name != "workers"):
        raise ValueError("FID matching execution policy must preserve comparison and resume")
    canary = document["canary"]
    if set(canary) != {
        "cases",
        "minimum_truth_coverage",
        "require_zero_decision_mismatches",
        "auto_chain_full",
    } or not canary["cases"]:
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
        if set(window) != {
            "id",
            "kind",
            "days",
            "start",
            "stop_admitting",
            "enabled",
        } or window["kind"] != "weekly":
            raise ValueError("FID matching schedule window is unsupported")
        if _clock_minutes(str(window["start"])) == _clock_minutes(
            str(window["stop_admitting"])
        ):
            raise ValueError("FID matching schedule window cannot span a full day")
    return {
        **document,
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


def _campaign_root(root: Path, campaign: Mapping[str, object]) -> Path:
    return _inside(
        root,
        Path(str(campaign["output_root"])) / str(campaign["id"]),
        "FID matching campaign output",
    )


def _case_summary_path(
    root: Path, campaign: Mapping[str, object], position: int, fold: str
) -> Path:
    return (
        _campaign_root(root, campaign)
        / "cases"
        / f"{campaign['source_run_id']}-{position:03d}-{fold}"
        / "summary.json"
    )


def _aggregate(
    root: Path, campaign: Mapping[str, object], mode: str
) -> dict[str, object]:
    expected = _expected_cases(campaign, mode)
    summaries = []
    failures = []
    matrix = {
        "true_positives": 0,
        "false_positives": 0,
        "true_negatives": 0,
        "false_negatives": 0,
    }
    truth_labelled = 0
    truth_unlabelled = 0
    mismatch_count = 0
    for position, fold in expected:
        path = _case_summary_path(root, campaign, position, fold)
        if not path.is_file():
            failure_path = path.with_name("failure.json")
            failures.append(
                {
                    "case": f"{position}:{fold}",
                    "error": (
                        json.loads(failure_path.read_text(encoding="utf-8")).get(
                            "error", "not attempted"
                        )
                        if failure_path.is_file()
                        else "not attempted"
                    ),
                }
            )
            continue
        summary = json.loads(path.read_text(encoding="utf-8"))
        if summary.get("state") != "qualified":
            failures.append({"case": f"{position}:{fold}", "error": summary["state"]})
            continue
        summaries.append(summary)
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
    canary_passed = (
        complete
        and mismatch_count == 0
        and truth_coverage >= float(campaign["canary"]["minimum_truth_coverage"])
    )
    state = (
        "qualified"
        if mode == "canary" and canary_passed
        else "measured-complete"
        if mode == "full" and complete and mismatch_count == 0
        else "incomplete-or-failed"
    )
    return {
        "schema_version": REPORT_SCHEMA,
        "campaign_id": campaign["id"],
        "mode": mode,
        "state": state,
        "authority_path": campaign["authority_path"],
        "authority_sha256": campaign["authority_sha256"],
        "source_run_id": campaign["source_run_id"],
        "progress": {
            "expected_cases": len(expected),
            "complete_cases": len(summaries),
            "failed_or_pending_cases": len(expected) - len(summaries),
        },
        "oracle": {
            "decision_mismatches": mismatch_count,
            "canary_passed": canary_passed if mode == "canary" else None,
        },
        "truth": {
            "labelled_functions": truth_labelled,
            "unlabelled_functions": truth_unlabelled,
            "coverage": truth_coverage,
        },
        "confusion_matrix": matrix,
        "failures": failures[:1000],
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
    canary = _aggregate(root, campaign, "canary")
    full = _aggregate(root, campaign, "full")
    qualification_path = _inside(
        root, str(campaign["qualification_evidence"]), "FID matching qualification"
    )
    qualification = (
        json.loads(qualification_path.read_text(encoding="utf-8"))
        if qualification_path.is_file()
        else {"state": "absent"}
    )
    matching = load_matching_authority(root, str(campaign["matching_authority"]))
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


def worker_cases(
    project_root: str | Path,
    cases: Iterable[str],
    authority: str | Path = DEFAULT_CAMPAIGN,
) -> int:
    root = Path(project_root).expanduser().resolve()
    campaign = load_campaign(root, authority)
    relative_output = (
        Path(str(campaign["output_root"])) / str(campaign["id"]) / "cases"
    )
    failed = 0
    for value in cases:
        position, fold = _parse_case(value)
        summary_path = _case_summary_path(root, campaign, position, fold)
        if summary_path.is_file():
            try:
                if json.loads(summary_path.read_text(encoding="utf-8")).get(
                    "state"
                ) == "qualified":
                    continue
            except (OSError, ValueError, json.JSONDecodeError):
                pass
        try:
            qualify_retained_validation(
                root,
                str(campaign["source_run_id"]),
                position=position,
                fold=fold,
                runtime_path=str(campaign["runtime"]),
                authority_path=str(campaign["matching_authority"]),
                output_root=relative_output,
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
    if _production_active(root, campaign):
        raise ValueError("production jobs are active; FID matching remains unclaimed")
    campaign_root = _campaign_root(root, campaign)
    campaign_root.mkdir(parents=True, exist_ok=True)
    lock = campaign_root / ".campaign.lock"
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise ValueError("another FID matching campaign process is active") from error
    os.close(descriptor)
    cases = [f"{position}:{fold}" for position, fold in _expected_cases(campaign, mode)]
    workers = min(int(campaign["execution"]["workers"]), len(cases))
    chunks = [cases[index::workers] for index in range(workers)]
    started_at = datetime.now(timezone.utc).isoformat()
    _atomic_json(
        campaign_root / "status.json",
        {
            "state": "running",
            "mode": mode,
            "started_at": started_at,
            "worker_pids": [],
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
            },
        )
        return_codes = [process.wait() for process in processes]
        report = _aggregate(root, campaign, mode)
        report["worker_return_codes"] = return_codes
        report["wall_time_seconds"] = time.time() - datetime.fromisoformat(
            started_at
        ).timestamp()
        report_path = campaign_root / f"{mode}-report.json"
        _atomic_json(report_path, report)
        final_state = "complete" if report["state"] in {"qualified", "measured-complete"} else "failed"
        _atomic_json(
            campaign_root / "status.json",
            {
                "state": final_state,
                "mode": mode,
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "worker_pids": [],
                "report_path": str(report_path.relative_to(root)),
            },
        )
        return report
    finally:
        for stream in streams:
            stream.close()
        lock.unlink(missing_ok=True)


def _window_open(campaign: Mapping[str, object], instant: datetime) -> tuple[bool, str | None]:
    schedule = campaign["schedule"]
    local = instant.astimezone(ZoneInfo(str(schedule["timezone"])))
    minute = local.hour * 60 + local.minute
    weekday = local.strftime("%a").lower()
    for window in schedule["window"]:
        if not window["enabled"] or weekday not in window["days"]:
            continue
        start = _clock_minutes(str(window["start"]))
        stop = _clock_minutes(str(window["stop_admitting"]))
        open_now = start <= minute < stop if start < stop else minute >= start or minute < stop
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
