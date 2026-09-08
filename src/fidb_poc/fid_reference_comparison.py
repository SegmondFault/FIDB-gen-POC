from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import tomllib
from pathlib import Path
from typing import Mapping


AUTHORITY_SCHEMA = "fidb-reference-comparison/v1"
REPORT_SCHEMA = "fidb-reference-comparison-report/v1"
SEAL_SCHEMA = "fidb-reference-comparison-seal/v1"
CAMPAIGN_REPORT_SCHEMA = "fidb-fid-matching-campaign-report/v1"
DEFAULT_AUTHORITY = "validation/fid-reference-comparison.toml"
_REVISION = re.compile(r"[0-9a-f]{40}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _inside(root: Path, value: str | Path, label: str) -> Path:
    path = (root / value).expanduser().resolve()
    if root != path and root not in path.parents:
        raise ValueError(f"{label} escapes the project root")
    return path


def _atomic_json(path: Path, document: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}-", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_comparison_authority(
    project_root: str | Path,
    authority: str | Path = DEFAULT_AUTHORITY,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    path = _inside(root, authority, "FID reference comparison authority")
    raw = path.read_bytes()
    document = tomllib.loads(raw.decode("utf-8"))
    if set(document) != {
        "schema_version",
        "id",
        "source_run_id",
        "baseline_arm",
        "output_report",
        "output_seal",
        "arm",
    } or document.get("schema_version") != AUTHORITY_SCHEMA:
        raise ValueError("FID reference comparison authority is invalid")
    arms = document.get("arm")
    if not isinstance(arms, list) or len(arms) != 3:
        raise ValueError("FID reference comparison requires exactly three arms")
    parsed = []
    seen = set()
    for arm in arms:
        if not isinstance(arm, dict) or set(arm) not in (
            {
                "id",
                "population",
                "campaign_id",
                "report",
                "producer_revision",
                "candidate_index",
            },
            {
                "id",
                "population",
                "campaign_id",
                "report",
                "producer_revision",
                "candidate_index",
                "generation_seal",
            },
        ):
            raise ValueError("FID reference comparison arm is invalid")
        arm_id = str(arm["id"])
        population = str(arm["population"])
        indexes = arm["candidate_index"]
        if (
            not arm_id
            or arm_id in seen
            or population
            not in {"archive-only", "linked-only", "archive-plus-linked"}
            or not isinstance(indexes, list)
            or not indexes
            or len(set(map(str, indexes))) != len(indexes)
            or not _REVISION.fullmatch(str(arm["producer_revision"]))
        ):
            raise ValueError("FID reference comparison arm identity is invalid")
        seen.add(arm_id)
        parsed.append({**arm, "candidate_index": list(map(str, indexes))})
    if {str(row["population"]) for row in parsed} != {
        "archive-only",
        "linked-only",
        "archive-plus-linked",
    } or str(document["baseline_arm"]) not in seen:
        raise ValueError("FID reference comparison populations are incomplete")
    return {
        **document,
        "arm": parsed,
        "authority_path": str(path.relative_to(root)),
        "authority_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _rates(matrix: Mapping[str, object]) -> dict[str, float]:
    tp = int(matrix["true_positives"])
    fp = int(matrix["false_positives"])
    tn = int(matrix["true_negatives"])
    fn = int(matrix["false_negatives"])
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    return {
        "precision": precision,
        "recall": recall,
        "specificity": _ratio(tn, tn + fp),
        "false_positive_rate": _ratio(fp, fp + tn),
        "false_negative_rate": _ratio(fn, fn + tp),
        "f1": _ratio(2 * precision * recall, precision + recall),
    }


def _comparison(source: Mapping[str, object], target: Mapping[str, object]) -> dict[str, object]:
    source_matrix = source["confusion_matrix"]
    target_matrix = target["confusion_matrix"]
    return {
        "from": source["id"],
        "to": target["id"],
        "confusion_delta": {
            key: int(target_matrix[key]) - int(source_matrix[key])
            for key in (
                "true_positives",
                "false_positives",
                "true_negatives",
                "false_negatives",
            )
        },
        "rate_delta": {
            key: float(target["rates"][key]) - float(source["rates"][key])
            for key in source["rates"]
        },
    }


def freeze_reference_comparison(
    project_root: str | Path,
    authority: str | Path = DEFAULT_AUTHORITY,
) -> dict[str, object]:
    """Verify and freeze the deterministic archive/linked/union comparison."""

    root = Path(project_root).expanduser().resolve()
    policy = load_comparison_authority(root, authority)
    file_receipts: dict[Path, dict[str, object]] = {}

    def receipt(path: Path) -> dict[str, object]:
        cached = file_receipts.get(path)
        if cached is None:
            if not path.is_file():
                raise ValueError(f"comparison input is unavailable: {path}")
            cached = {
                "path": str(path.relative_to(root)),
                "sha256": _sha256(path),
                "bytes": path.stat().st_size,
            }
            file_receipts[path] = cached
        return dict(cached)

    resolved = []
    positive_count = None
    negative_count = None
    linked_seal_sha256 = None
    for arm in policy["arm"]:
        report_path = _inside(root, str(arm["report"]), "comparison arm report")
        report_receipt = receipt(report_path)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        backend = report.get("backend", {})
        if not (
            report.get("schema_version") == CAMPAIGN_REPORT_SCHEMA
            and report.get("campaign_id") == arm["campaign_id"]
            and report.get("source_run_id") == policy["source_run_id"]
            and report.get("mode") == "full"
            and report.get("state") == "measured-complete"
            and backend.get("contract_met") is True
            and backend.get("requested") == "gpu-portable-fid-v1"
            and backend.get("effective") == ["gpu-portable-fid-v1"]
            and backend.get("fallback_cases") == []
            and report.get("progress", {}).get("failed_or_pending_cases") == 0
        ):
            raise ValueError(f"comparison arm is not frozen complete: {arm['id']}")
        reference = report.get("reference_population")
        if arm["population"] == "archive-only":
            if reference not in (None, {}, {"population": "archive-only"}):
                raise ValueError("legacy archive reference population is inconsistent")
        elif not isinstance(reference, dict) or reference.get("population") != arm["population"]:
            raise ValueError(f"comparison reference population differs: {arm['id']}")
        matrix = report.get("confusion_matrix", {})
        if set(matrix) != {
            "true_positives",
            "false_positives",
            "true_negatives",
            "false_negatives",
        } or any(int(value) < 0 for value in matrix.values()):
            raise ValueError(f"comparison confusion matrix is invalid: {arm['id']}")
        positives = int(matrix["true_positives"]) + int(matrix["false_negatives"])
        negatives = int(matrix["true_negatives"]) + int(matrix["false_positives"])
        positive_count = positives if positive_count is None else positive_count
        negative_count = negatives if negative_count is None else negative_count
        if positives != positive_count or negatives != negative_count:
            raise ValueError("comparison arms use different decision populations")

        index_receipts = [
            receipt(_inside(root, value, "comparison candidate index"))
            for value in arm["candidate_index"]
        ]
        if isinstance(reference, dict) and reference.get("indexes"):
            reported = {
                (str(row["path"]), str(row["sha256"]))
                for row in reference["indexes"]
            }
            observed = {(row["path"], row["sha256"]) for row in index_receipts}
            if reported != observed:
                raise ValueError(f"comparison index receipts differ: {arm['id']}")

        generation_receipt = None
        if arm.get("generation_seal"):
            generation_receipt = receipt(
                _inside(root, str(arm["generation_seal"]), "linked generation seal")
            )
            if linked_seal_sha256 not in (None, generation_receipt["sha256"]):
                raise ValueError("comparison arms use different linked generations")
            linked_seal_sha256 = str(generation_receipt["sha256"])
            components = reference.get("components", []) if isinstance(reference, dict) else []
            linked_components = [
                row for row in components if row.get("kind") == "linked-generation"
            ]
            if len(linked_components) != 1 or linked_components[0].get(
                "generation_seal_sha256"
            ) != generation_receipt["sha256"]:
                raise ValueError(f"linked generation receipt differs: {arm['id']}")

        hash_evidence = report.get("hash_evidence", {})
        evidence_path = _inside(
            root, str(hash_evidence.get("database_path", "")), "hash evidence database"
        )
        evidence_receipt = receipt(evidence_path)
        if evidence_receipt["sha256"] != hash_evidence.get("database_sha256"):
            raise ValueError(f"hash evidence digest differs: {arm['id']}")
        resolved.append(
            {
                "id": str(arm["id"]),
                "population": str(arm["population"]),
                "campaign_id": str(arm["campaign_id"]),
                "producer_revision": str(arm["producer_revision"]),
                "report": report_receipt,
                "campaign_authority": {
                    "path": report["authority_path"],
                    "sha256": report["authority_sha256"],
                },
                "method_authority": report["method_authority"],
                "performance_authority": {
                    "path": backend["performance_authority_path"],
                    "sha256": backend["performance_authority_sha256"],
                },
                "reference_population": reference or {"population": "archive-only"},
                "candidate_indexes": index_receipts,
                "linked_generation_seal": generation_receipt,
                "hash_evidence": {
                    **evidence_receipt,
                    "distinct_signatures": hash_evidence["distinct_signatures"],
                    "noisy_signatures": hash_evidence["noisy_signatures"],
                    "query_function_owner_observations": hash_evidence[
                        "query_function_owner_observations"
                    ],
                },
                "truth": report["truth"],
                "confusion_matrix": {key: int(value) for key, value in matrix.items()},
                "rates": _rates(matrix),
                "campaign_wall_time_seconds": report["wall_time_seconds"],
                "finished_at": report["finished_at"],
            }
        )

    by_id = {row["id"]: row for row in resolved}
    baseline = by_id[str(policy["baseline_arm"])]
    linked = next(row for row in resolved if row["population"] == "linked-only")
    union = next(row for row in resolved if row["population"] == "archive-plus-linked")
    report = {
        "schema_version": REPORT_SCHEMA,
        "id": policy["id"],
        "source_run_id": policy["source_run_id"],
        "authority_path": policy["authority_path"],
        "authority_sha256": policy["authority_sha256"],
        "decision_population": {
            "positive_owner_decisions": positive_count,
            "negative_owner_decisions": negative_count,
        },
        "baseline_arm": baseline["id"],
        "arms": resolved,
        "comparisons": [
            _comparison(baseline, row)
            for row in resolved
            if row["id"] != baseline["id"]
        ]
        + [_comparison(linked, union)],
    }
    report_path = _inside(root, str(policy["output_report"]), "comparison report")
    seal_path = _inside(root, str(policy["output_seal"]), "comparison seal")
    _atomic_json(report_path, report)
    seal = {
        "schema_version": SEAL_SCHEMA,
        "id": policy["id"],
        "authority_path": policy["authority_path"],
        "authority_sha256": policy["authority_sha256"],
        "report_path": str(report_path.relative_to(root)),
        "report_sha256": _sha256(report_path),
        "input_report_sha256": {
            row["id"]: row["report"]["sha256"] for row in resolved
        },
    }
    _atomic_json(seal_path, seal)
    return {**report, "report_path": str(report_path.relative_to(root)), "seal": seal}
