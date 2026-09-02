"""Function-level FID signature overlap and marginal-coverage analysis."""

from __future__ import annotations

import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Callable, Iterable

SCHEMA = "fidb-hash-coverage/v1"
SIGNATURE_FIELDS = (
    "language",
    "full_hash",
    "specific_hash",
    "specific_hash_additional_size",
    "code_unit_size",
)
Signature = tuple[str, str, str, int, int]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_signatures(path: Path) -> set[Signature]:
    signatures: set[Signature] = set()
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            try:
                row = json.loads(line)
                signature = (
                    str(row["language"]),
                    str(row["full_hash"]),
                    str(row["specific_hash"]),
                    int(row["specific_hash_additional_size"]),
                    int(row["code_unit_size"]),
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                raise ValueError(
                    f"invalid FID signature at {path}:{line_number}"
                ) from error
            if len(signature[1]) != 16 or len(signature[2]) != 16:
                raise ValueError(f"invalid FID hash width at {path}:{line_number}")
            signatures.add(signature)
    if not signatures:
        raise ValueError(f"FID signature ledger is empty: {path}")
    return signatures


def _union(sets: Iterable[set[Signature]]) -> set[Signature]:
    result: set[Signature] = set()
    for signatures in sets:
        result.update(signatures)
    return result


def _dimension_summary(
    cells: list[dict[str, object]], key: Callable[[dict[str, object]], str]
) -> list[dict[str, object]]:
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for cell in cells:
        grouped[key(cell)].append(cell)
    unions = {
        name: _union(item["signatures"] for item in members)
        for name, members in grouped.items()
    }
    rows = []
    for name in sorted(grouped):
        others = _union(value for other, value in unions.items() if other != name)
        wall_time_ns = sum(int(item.get("wall_time_ns", 0)) for item in grouped[name])
        exclusive = len(unions[name] - others)
        rows.append(
            {
                "id": name,
                "cells": len(grouped[name]),
                "unique_signatures": len(unions[name]),
                "exclusive_signatures": exclusive,
                "overlap_signatures": len(unions[name] & others),
                "cell_wall_time_ns": wall_time_ns,
                "retained_bytes": sum(
                    int(item.get("retained_bytes", 0)) for item in grouped[name]
                ),
                "exclusive_signatures_per_wall_hour": (
                    exclusive / (wall_time_ns / 3_600_000_000_000)
                    if wall_time_ns
                    else None
                ),
            }
        )
    return rows


def _member_marginals(
    cells: list[dict[str, object]],
    group_key: Callable[[dict[str, object]], tuple[str, ...]],
    member_key: Callable[[dict[str, object]], str],
) -> list[dict[str, object]]:
    grouped: dict[tuple[str, ...], list[dict[str, object]]] = defaultdict(list)
    for cell in cells:
        grouped[group_key(cell)].append(cell)
    result = []
    for group, members in sorted(grouped.items()):
        for member in members:
            others = _union(
                item["signatures"] for item in members if item is not member
            )
            signatures = member["signatures"]
            marginal = len(signatures - others)
            wall_time_ns = int(member.get("wall_time_ns", 0))
            result.append(
                {
                    "group": list(group),
                    "member": member_key(member),
                    "unique_signatures": len(signatures),
                    "marginal_signatures_if_added_last": marginal,
                    "overlap_signatures": len(signatures & others),
                    "marginal_fraction": (
                        marginal / len(signatures) if signatures else 0.0
                    ),
                    "wall_time_ns": wall_time_ns,
                    "retained_bytes": int(member.get("retained_bytes", 0)),
                    "marginal_signatures_per_wall_hour": (
                        marginal / (wall_time_ns / 3_600_000_000_000)
                        if wall_time_ns
                        else None
                    ),
                }
            )
    return result


def _pairwise_within_groups(
    cells: list[dict[str, object]],
    group_key: Callable[[dict[str, object]], tuple[str, ...]],
) -> list[dict[str, object]]:
    grouped: dict[tuple[str, ...], list[dict[str, object]]] = defaultdict(list)
    for cell in cells:
        grouped[group_key(cell)].append(cell)
    rows = []
    for group, members in sorted(grouped.items()):
        ordered = sorted(members, key=lambda item: str(item["cell_id"]))
        for left_index, left in enumerate(ordered):
            for right in ordered[left_index + 1 :]:
                intersection = len(left["signatures"] & right["signatures"])
                union = len(left["signatures"] | right["signatures"])
                rows.append(
                    {
                        "group": list(group),
                        "left": left["cell_id"],
                        "right": right["cell_id"],
                        "intersection_signatures": intersection,
                        "union_signatures": union,
                        "jaccard": intersection / union if union else 1.0,
                    }
                )
    return rows


def _pairwise_same_target(cells: list[dict[str, object]]) -> list[dict[str, object]]:
    by_target: dict[str, list[dict[str, object]]] = defaultdict(list)
    for cell in cells:
        by_target[str(cell["target_id"])].append(cell)
    rows = []
    for target_id, members in sorted(by_target.items()):
        ordered = sorted(members, key=lambda item: str(item["cell_id"]))
        for left_index, left in enumerate(ordered):
            for right in ordered[left_index + 1 :]:
                intersection = len(left["signatures"] & right["signatures"])
                union = len(left["signatures"] | right["signatures"])
                rows.append(
                    {
                        "target_id": target_id,
                        "left": left["cell_id"],
                        "right": right["cell_id"],
                        "intersection_signatures": intersection,
                        "union_signatures": union,
                        "jaccard": intersection / union if union else 1.0,
                    }
                )
    return rows


def analyze_signature_coverage(
    manifests: Iterable[Path],
    compilation: dict[str, object],
    measurements: Iterable[dict[str, object]] = (),
) -> dict[str, object]:
    routes = {str(row["id"]): row for row in compilation["routes"]}
    costs = {
        (str(row["route_id"]), str(row["treatment_id"])): row for row in measurements
    }
    cells: list[dict[str, object]] = []
    for manifest in manifests:
        group_root = manifest.resolve().parents[2]
        with manifest.open(newline="", encoding="utf-8") as stream:
            for row in csv.DictReader(stream):
                if row["status"] != "complete":
                    continue
                signature_path = (group_root / row["fid_signatures_path"]).resolve()
                if group_root not in signature_path.parents:
                    raise ValueError("FID signature ledger escapes its run group")
                if _sha256(signature_path) != row["fid_signatures_sha256"]:
                    raise ValueError(f"FID signature digest differs: {signature_path}")
                signatures = load_signatures(signature_path)
                if len(signatures) != int(row["fid_unique_signatures"]):
                    raise ValueError(
                        f"FID unique signature count differs: {signature_path}"
                    )
                route = routes[row["route"]]
                cost = costs.get((row["route"], row["treatment"]), {})
                cells.append(
                    {
                        "cell_id": f"{row['route']}/{row['treatment']}",
                        "route_id": row["route"],
                        "target_id": str(route["target_id"]),
                        "compiler_id": str(route["compiler_id"]),
                        "compiler_family": str(route["compiler_family"]),
                        "treatment_id": row["treatment"],
                        "signature_records": int(row["fid_signature_records"]),
                        "unique_full_hashes": int(row["fid_unique_full_hashes"]),
                        "wall_time_ns": int(cost.get("wall_time_ns", 0)),
                        "peak_scratch_bytes": int(cost.get("peak_scratch_bytes", 0)),
                        "retained_bytes": int(cost.get("retained_bytes", 0)),
                        "signatures": signatures,
                    }
                )
    all_signatures = _union(cell["signatures"] for cell in cells)
    full_hashes = {(signature[0], signature[1]) for signature in all_signatures}
    pairwise = _pairwise_same_target(cells)
    compiler_marginals = _member_marginals(
        cells,
        lambda cell: (str(cell["target_id"]), str(cell["treatment_id"])),
        lambda cell: str(cell["compiler_id"]),
    )
    treatment_marginals = _member_marginals(
        cells,
        lambda cell: (str(cell["route_id"]),),
        lambda cell: str(cell["treatment_id"]),
    )
    compiler_pairs = _pairwise_within_groups(
        cells,
        lambda cell: (str(cell["target_id"]), str(cell["treatment_id"])),
    )
    treatment_pairs = _pairwise_within_groups(
        cells,
        lambda cell: (str(cell["route_id"]),),
    )
    result = {
        "schema_version": SCHEMA,
        "comparison_identity": list(SIGNATURE_FIELDS),
        "cells": [
            {key: value for key, value in cell.items() if key != "signatures"}
            | {"unique_signatures": len(cell["signatures"])}
            for cell in sorted(cells, key=lambda item: str(item["cell_id"]))
        ],
        "totals": {
            "cells": len(cells),
            "signature_records": sum(int(cell["signature_records"]) for cell in cells),
            "unique_full_hashes": len(full_hashes),
            "unique_signatures": len(all_signatures),
        },
        "by_compiler": _dimension_summary(cells, lambda cell: str(cell["compiler_id"])),
        "by_treatment": _dimension_summary(
            cells, lambda cell: str(cell["treatment_id"])
        ),
        "compiler_marginal_within_target_treatment": compiler_marginals,
        "treatment_marginal_within_route": treatment_marginals,
        "compiler_pairwise_within_target_treatment": compiler_pairs,
        "treatment_pairwise_within_route": treatment_pairs,
        "pairwise_same_target": pairwise,
        "near_duplicate_pairs": [
            row for row in pairwise if float(row["jaccard"]) >= 0.98
        ],
        "overstressed_candidates": {
            "compiler_members_at_or_below_one_percent_marginal": [
                row
                for row in compiler_marginals
                if float(row["marginal_fraction"]) <= 0.01
            ],
            "treatment_members_at_or_below_one_percent_marginal": [
                row
                for row in treatment_marginals
                if float(row["marginal_fraction"]) <= 0.01
            ],
            "compiler_pairs_at_or_above_0_98_jaccard": [
                row for row in compiler_pairs if float(row["jaccard"]) >= 0.98
            ],
            "treatment_pairs_at_or_above_0_98_jaccard": [
                row for row in treatment_pairs if float(row["jaccard"]) >= 0.98
            ],
        },
    }
    return result
