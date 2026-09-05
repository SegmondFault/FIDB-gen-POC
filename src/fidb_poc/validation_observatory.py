"""Read-only, bounded index of immutable machine-validation hash reports."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Mapping

from .machine_validation_hashes import HASH_REPORT_SCHEMA

VALIDATION_OBSERVATORY_SCHEMA = "fidb-validation-observatory/v1"
DEFAULT_REPORT_GLOB = "artifacts/validation-runs/*/*/hash-report.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _rates(matrix: Mapping[str, object]) -> dict[str, float | None]:
    tp = int(matrix.get("true_positives", 0))
    fp = int(matrix.get("false_positives", 0))
    tn = int(matrix.get("true_negatives", 0))
    fn = int(matrix.get("false_negatives", 0))
    return {
        "true_positive_rate": _ratio(tp, tp + fn),
        "false_positive_rate": _ratio(fp, fp + tn),
        "true_negative_rate": _ratio(tn, tn + fp),
        "false_negative_rate": _ratio(fn, fn + tp),
        "precision": _ratio(tp, tp + fp),
    }


def _hash_type_summary(row: Mapping[str, object]) -> dict[str, object]:
    fields = (
        "hash_type",
        "distinct_values",
        "singleton_values",
        "multi_owner_values",
        "multi_owner_fraction",
        "owner_links",
        "ambiguous_owner_links",
        "complete_disambiguated_owner_signatures",
        "reference_observations",
        "exact_false_positive_observations",
        "maximum_distinct_owners",
    )
    return {field: row.get(field) for field in fields}


def _hash_evidence_summary(row: object) -> dict[str, object]:
    if not isinstance(row, dict):
        return {}
    fields = (
        "database_path",
        "database_sha256",
        "distinct_signatures",
        "noisy_signatures",
        "multi_owner_signatures",
        "missed_signatures",
        "unattributed_signatures",
        "query_signature_observations",
        "unattributed_query_signatures",
        "fold_results",
    )
    return {field: row.get(field) for field in fields}


def _read_reports(root: Path, report_glob: str) -> list[dict[str, object]]:
    reports: list[dict[str, object]] = []
    for path in sorted(root.glob(report_glob)):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if (
            not isinstance(document, dict)
            or document.get("schema_version") != HASH_REPORT_SCHEMA
            or document.get("state") != "measured-complete"
        ):
            continue
        validation_id = str(document.get("validation_id") or path.parent.parent.name)
        run_id = str(document.get("run_id") or path.parent.name)
        matrix = document.get("confusion_matrix", {})
        if not isinstance(matrix, dict):
            matrix = {}
        hash_types = document.get("hash_type_analysis", [])
        if not isinstance(hash_types, list):
            hash_types = []
        key = f"{validation_id}:{run_id}"
        reports.append(
            {
                "key": key,
                "validation_id": validation_id,
                "run_id": run_id,
                "finished_at": str(document.get("finished_at") or ""),
                "report_path": str(path.relative_to(root)),
                "report_sha256": _sha256(path),
                "source_evidence_sha256": str(
                    document.get("source_evidence_sha256") or ""
                ),
                "method_authority": document.get("method_authority"),
                "corpus_index": document.get("corpus_index"),
                "gpu_comparison": document.get("gpu_comparison"),
                "decision_contract": document.get("decision_contract"),
                "confusion_matrix": matrix,
                "rates": _rates(matrix),
                "hash_evidence": document.get("hash_evidence", {}),
                "hash_evidence_summary": _hash_evidence_summary(
                    document.get("hash_evidence", {})
                ),
                "hash_types": [
                    _hash_type_summary(row)
                    for row in hash_types
                    if isinstance(row, dict)
                ],
                "hash_type_detail": [
                    row for row in hash_types if isinstance(row, dict)
                ],
                "failures": document.get("failures", []),
                "performance": document.get("performance", {}),
            }
        )
    reports.sort(key=lambda row: (str(row["finished_at"]), str(row["key"])))
    return reports


def compile_validation_observatory(
    project_root: str | Path,
    *,
    selected_run: str | None = None,
    report_glob: str = DEFAULT_REPORT_GLOB,
) -> dict[str, object]:
    """Compile all-run summaries plus one bounded per-run drill-down."""

    root = Path(project_root).expanduser().resolve()
    reports = _read_reports(root, report_glob)
    latest_key = str(reports[-1]["key"]) if reports else None
    requested_key = selected_run or latest_key
    selected = next(
        (row for row in reports if row["key"] == requested_key),
        None,
    )
    run_summaries = [
        {
            key: value
            for key, value in row.items()
            if key not in {"hash_evidence", "hash_type_detail", "failures"}
        }
        for row in reports
    ]
    for summary in run_summaries:
        summary["hash_evidence"] = summary.pop("hash_evidence_summary")
    detail = None
    if selected is not None:
        detail = {
            **selected,
            "hash_evidence": selected["hash_evidence"],
            "hash_type_analysis": selected["hash_type_detail"],
        }
        detail.pop("hash_type_detail", None)
        detail.pop("hash_evidence_summary", None)
    trends = []
    for hash_type in ("full", "specific", "complete"):
        points = []
        for report in reports:
            summary = next(
                (
                    row
                    for row in report["hash_types"]
                    if row.get("hash_type") == hash_type
                ),
                None,
            )
            if summary is not None:
                points.append(
                    {
                        "run_key": report["key"],
                        "run_id": report["run_id"],
                        "finished_at": report["finished_at"],
                        **summary,
                    }
                )
        trends.append({"hash_type": hash_type, "points": points})
    validations = sorted({str(row["validation_id"]) for row in reports})
    methods = sorted(
        {
            str(authority.get("id"))
            for row in reports
            if isinstance((authority := row.get("method_authority")), dict)
            and authority.get("id")
        }
    )
    return {
        "schema_version": VALIDATION_OBSERVATORY_SCHEMA,
        "generated_at": _now(),
        "state": "ready" if reports else "awaiting-evidence",
        "summary": {
            "measured_runs": len(reports),
            "validation_cohorts": len(validations),
            "method_versions": methods,
        },
        "latest_run_key": latest_key,
        "selected_run_key": selected["key"] if selected is not None else None,
        "selection_found": selected is not None or selected_run is None,
        "runs": run_summaries,
        "trends": trends,
        "selected": detail,
    }
