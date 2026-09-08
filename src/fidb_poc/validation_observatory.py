"""Read-only, bounded index of immutable machine-validation hash reports."""

from __future__ import annotations

from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Mapping

from .machine_validation_hashes import HASH_REPORT_SCHEMA
from .fid_matching_campaign import REPORT_SCHEMA as FID_MATCH_REPORT_SCHEMA

VALIDATION_OBSERVATORY_SCHEMA = "fidb-validation-observatory/v1"
DEFAULT_REPORT_GLOB = "artifacts/validation-runs/*/*/hash-report.json"
FID_MATCH_REPORT_GLOB = "artifacts/fid-matching-runs/*/full-report.json"


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
        "false_positive_values",
        "maximum_distinct_owners",
    )
    return {field: row.get(field) for field in fields}


def _evidence_path(root: Path, value: object) -> Path | None:
    relative = Path(str(value))
    if relative.is_absolute() or ".." in relative.parts:
        return None
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or not path.is_file() or path.is_symlink():
        return None
    return path


def _noise_concentration(
    root: Path, report: Mapping[str, object]
) -> dict[str, dict[str, object]]:
    """Return a bounded FP-concentration curve from immutable hash evidence."""

    evidence = report.get("hash_evidence")
    if not isinstance(evidence, dict):
        return {}
    database = _evidence_path(root, evidence.get("database_path", ""))
    if database is None:
        return {}
    stat = database.stat()
    return _noise_concentration_database(str(database), stat.st_size, stat.st_mtime_ns)


@lru_cache(maxsize=32)
def _noise_concentration_database(
    database_path: str, _size: int, _mtime_ns: int
) -> dict[str, dict[str, object]]:
    """Read one immutable evidence generation once per API process."""

    connection = sqlite3.connect(f"file:{database_path}?mode=ro", uri=True)
    try:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if "hash_population" in tables:
            table = "hash_population"
            value_column = "value"
            false_positive_column = "false_positives"
        elif "hash_component_noise" in tables:
            table = "hash_component_noise"
            value_column = "component_value"
            false_positive_column = "exact_false_positive_observations"
        else:
            return {}
        result = {}
        for hash_type in ("full", "specific", "complete"):
            population = connection.execute(
                f"""
                SELECT COUNT(*), COALESCE(SUM({false_positive_column}), 0)
                FROM {table}
                WHERE hash_type=? AND {false_positive_column}>0
                """,
                (hash_type,),
            ).fetchone()
            noisy_values = int(population[0])
            false_positives = int(population[1])
            points = [
                {
                    "rank": 0,
                    "noisy_hash_fraction": 0.0,
                    "false_positive_fraction": 0.0,
                    "false_positive_observations": 0,
                }
            ]
            if noisy_values and false_positives:
                rows = connection.execute(
                    f"""
                    WITH ranked AS (
                      SELECT
                        ROW_NUMBER() OVER (
                          ORDER BY {false_positive_column} DESC, {value_column}
                        ) AS rank,
                        COUNT(*) OVER () AS noisy_values,
                        SUM({false_positive_column}) OVER () AS total_false_positives,
                        SUM({false_positive_column}) OVER (
                          ORDER BY {false_positive_column} DESC, {value_column}
                          ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
                        ) AS cumulative_false_positives
                      FROM {table}
                      WHERE hash_type=? AND {false_positive_column}>0
                    ), sampled AS (
                      SELECT rank, noisy_values, total_false_positives,
                             cumulative_false_positives
                      FROM ranked WHERE rank=1
                      UNION
                      SELECT MAX(rank), MAX(noisy_values),
                             MAX(total_false_positives),
                             MAX(cumulative_false_positives)
                      FROM ranked
                      GROUP BY CAST(((rank - 1) * 100) / noisy_values AS INTEGER)
                    )
                    SELECT rank, noisy_values, total_false_positives,
                           cumulative_false_positives
                    FROM sampled ORDER BY rank
                    """,
                    (hash_type,),
                )
                points.extend(
                    {
                        "rank": int(row[0]),
                        "noisy_hash_fraction": int(row[0]) / int(row[1]),
                        "false_positive_fraction": int(row[3]) / int(row[2]),
                        "false_positive_observations": int(row[3]),
                    }
                    for row in rows
                )
            result[hash_type] = {
                "noisy_values": noisy_values,
                "false_positive_observations": false_positives,
                "concentration": points,
            }
        return result
    except sqlite3.DatabaseError:
        return {}
    finally:
        connection.close()


def _with_noise_population(
    root: Path, report: Mapping[str, object]
) -> list[dict[str, object]]:
    """Add population partitions and a bounded curve to selected-run detail."""

    observed = _noise_concentration(root, report)
    enriched = []
    for source in report.get("hash_type_detail", []):
        if not isinstance(source, dict):
            continue
        row = dict(source)
        detail = observed.get(str(row.get("hash_type")), {})
        distinct = int(row.get("distinct_values", 0))
        multi_owner = int(row.get("multi_owner_values", 0))
        noisy = int(detail.get("noisy_values", row.get("false_positive_values", 0)))
        false_positives = int(
            detail.get(
                "false_positive_observations",
                row.get("exact_false_positive_observations", 0),
            )
        )
        noisy = min(max(noisy, 0), distinct)
        other_multi_owner = min(max(multi_owner - noisy, 0), distinct - noisy)
        single_owner = max(distinct - noisy - other_multi_owner, 0)
        row["false_positive_values"] = noisy
        row["noise_population"] = {
            "noisy_values": noisy,
            "noisy_fraction": _ratio(noisy, distinct),
            "other_multi_owner_values": other_multi_owner,
            "other_multi_owner_fraction": _ratio(other_multi_owner, distinct),
            "single_owner_values": single_owner,
            "single_owner_fraction": _ratio(single_owner, distinct),
            "false_positive_observations": false_positives,
            "false_positive_fraction": 1.0 if false_positives else None,
        }
        row["false_positive_concentration"] = detail.get("concentration", [])
        enriched.append(row)
    return enriched


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


def _construct_validity(
    document: Mapping[str, object], hash_types: list[object]
) -> dict[str, object]:
    recorded = document.get("construct_validity")
    if isinstance(recorded, dict):
        return recorded
    complete = next(
        (
            row
            for row in hash_types
            if isinstance(row, dict) and row.get("hash_type") == "complete"
        ),
        {},
    )
    libraries = complete.get("libraries", []) if isinstance(complete, dict) else []
    by_owner = []
    for row in libraries if isinstance(libraries, list) else []:
        if not isinstance(row, dict):
            continue
        recovered = int(row.get("reference_observations", 0)) - int(
            row.get("missed_observations", 0)
        )
        missed = int(row.get("missed_observations", 0))
        denominator = recovered + missed
        by_owner.append(
            {
                "id": str(row.get("owner") or ""),
                "true_positives": recovered,
                "false_negatives": missed,
                "false_negative_rate": missed / denominator if denominator else None,
            }
        )
    return {
        "state": "construct-validity-unresolved",
        "recall_claim": "harness-conditional-not-intrinsic-fid-recall",
        "reference_unit": "per-library-archive-function",
        "query_unit": "five-library-linked-composite-function",
        "route_false_negative_rate_spread": None,
        "by_route": [],
        "by_treatment": [],
        "by_owner": by_owner,
        "legacy_projection": True,
    }


def _read_reports(root: Path, report_glob: str) -> list[dict[str, object]]:
    reports: list[dict[str, object]] = []
    patterns = [report_glob]
    if report_glob == DEFAULT_REPORT_GLOB:
        patterns.append(FID_MATCH_REPORT_GLOB)
    paths = sorted({path for pattern in patterns for path in root.glob(pattern)})
    for path in paths:
        if not path.is_file() or path.is_symlink():
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if (
            not isinstance(document, dict)
            or document.get("state") != "measured-complete"
        ):
            continue
        schema = document.get("schema_version")
        if schema not in {HASH_REPORT_SCHEMA, FID_MATCH_REPORT_SCHEMA}:
            continue
        native_fid = schema == FID_MATCH_REPORT_SCHEMA
        validation_id = str(
            document.get("validation_id")
            or document.get("campaign_id")
            or path.parent.parent.name
        )
        run_id = str(
            document.get("run_id") or document.get("source_run_id") or path.parent.name
        )
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
                "lookup_backend": document.get("lookup_backend"),
                "pipeline_job": document.get("pipeline_job")
                or {
                    "id": "hash-discrimination",
                    "kind": "validation-postprocess",
                    "state": "legacy-evidence-published",
                    "materialized_with_batch": False,
                    "required_for_run_completion": False,
                    "stages": [],
                },
                "construct_validity": (
                    document.get("construct_validity")
                    if native_fid
                    else _construct_validity(document, hash_types)
                ),
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
                "performance": document.get("performance", {})
                or {
                    "wall_time_seconds": document.get("wall_time_seconds"),
                    "workers": document.get("workers"),
                },
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
            if key
            not in {
                "hash_evidence",
                "hash_type_detail",
                "failures",
                "construct_validity",
            }
        }
        for row in reports
    ]
    for summary, report in zip(run_summaries, reports, strict=True):
        summary["hash_evidence"] = summary.pop("hash_evidence_summary")
        construct = report["construct_validity"]
        summary["construct_validity"] = {
            key: construct.get(key)
            for key in (
                "state",
                "recall_claim",
                "route_false_negative_rate_spread",
                "legacy_projection",
            )
            if construct.get(key) is not None
        }
    detail = None
    if selected is not None:
        detail = {
            **selected,
            "hash_evidence": selected["hash_evidence"],
            "hash_type_analysis": _with_noise_population(root, selected),
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
