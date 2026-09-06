"""Portable implementation of Ghidra's FID candidate scoring decision.

Ghidra remains the source of FID hashes and the qualification oracle.  This
module reproduces the bounded, data-parallel part of ``FidProgramSeeker`` so
that candidate scoring can run on a CPU or WGPU after the required score inputs
have been exported.  It deliberately does not compile or execute target code.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import time
import tomllib
from typing import Mapping, Sequence

MATCHING_AUTHORITY_SCHEMA = "fidb-portable-fid-matching/v1"
MATCH_INPUT_SCHEMA = "fidb-portable-fid-input/v1"
MATCH_REPORT_SCHEMA = "fidb-portable-fid-report/v1"
DEFAULT_MATCHING_AUTHORITY = Path("validation/fid-matching.toml")

AUTO_PASS = 1
AUTO_FAIL = 2
FORCE_SPECIFIC = 4
FORCE_RELATION = 8


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inside(root: Path, value: str | Path, label: str) -> Path:
    path = (root / value).resolve()
    if path != root and root not in path.parents:
        raise ValueError(f"{label} escapes the project root")
    return path


def load_matching_authority(
    project_root: str | Path,
    authority: str | Path = DEFAULT_MATCHING_AUTHORITY,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    path = _inside(root, authority, "FID matching authority")
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if (
        set(document)
        != {
            "schema_version",
            "selected",
            "semantics",
            "oracle",
            "evidence",
            "backend",
        }
        or document.get("schema_version") != MATCHING_AUTHORITY_SCHEMA
    ):
        raise ValueError("FID matching authority has unsupported fields or schema")
    semantics = document["semantics"]
    if semantics != {
        "candidate_key": "full_hash",
        "score_threshold": 14.6,
        "medium_code_unit_limit": 24,
        "specific_constant_weight": 0.67,
        "maximum_parents_for_score": 500,
        "force_relation_uses": "child",
        "winner_policy": "all-equal-highest-score",
    }:
        raise ValueError(
            "FID matching semantics do not match reviewed Ghidra semantics"
        )
    oracle = document["oracle"]
    if (
        oracle.get("implementation") != "ghidra-fid-program-seeker"
        or oracle.get("require_zero_decision_mismatches") is not True
        or int(oracle.get("score_max_float32_ulps", -1)) not in {0, 1}
    ):
        raise ValueError("FID matching oracle policy is unsafe")
    evidence = document["evidence"]
    if set(evidence) != {
        "retain_candidate_scores",
        "retain_native_decisions",
        "retain_portable_decisions",
        "retain_mismatches",
        "maximum_mismatch_rows",
    } or any(
        evidence[name] is not True
        for name in (
            "retain_candidate_scores",
            "retain_native_decisions",
            "retain_portable_decisions",
            "retain_mismatches",
        )
    ):
        raise ValueError("FID matching evidence policy is incomplete")
    if not 1 <= int(evidence["maximum_mismatch_rows"]) <= 100_000:
        raise ValueError("FID matching mismatch bound is invalid")
    rows = document["backend"]
    if not isinstance(rows, list) or len(rows) != 2:
        raise ValueError("FID matching authority requires one CPU and one GPU backend")
    by_id: dict[str, dict[str, object]] = {}
    devices = set()
    for row in rows:
        required = {"id", "device", "implementation", "state"}
        allowed = required | {"allowed_adapter_types"}
        if not required.issubset(row) or set(row) - allowed:
            raise ValueError("FID matching backend has unsupported fields")
        backend_id = str(row["id"])
        device = str(row["device"])
        if not backend_id or backend_id in by_id or device not in {"cpu", "gpu"}:
            raise ValueError("FID matching backend identity is invalid")
        by_id[backend_id] = dict(row)
        devices.add(device)
        adapter_types = row.get("allowed_adapter_types")
        if device == "gpu":
            if (
                not isinstance(adapter_types, list)
                or not adapter_types
                or any(
                    value not in {"IntegratedGPU", "DiscreteGPU"}
                    for value in adapter_types
                )
            ):
                raise ValueError("FID matching GPU backend must require hardware")
        elif adapter_types is not None:
            raise ValueError("FID matching CPU backend cannot declare GPU adapters")
    if devices != {"cpu", "gpu"} or str(document["selected"]) not in by_id:
        raise ValueError("FID matching CPU/GPU backend set is incomplete")
    return {
        **document,
        "backends": by_id,
        "authority_path": str(path.relative_to(root)),
        "authority_sha256": _sha256(path),
    }


def _f32(value: float) -> float:
    return struct.unpack("<f", struct.pack("<f", float(value)))[0]


def _f32_ulps(left: float, right: float) -> int:
    """Return the ULP distance for non-negative FID scores."""

    if left < 0 or right < 0:
        raise ValueError("FID scores cannot be negative")
    left_bits = struct.unpack("<I", struct.pack("<f", float(left)))[0]
    right_bits = struct.unpack("<I", struct.pack("<f", float(right)))[0]
    return abs(left_bits - right_bits)


def _candidate_flags(candidate: Mapping[str, object]) -> int:
    flags = 0
    if candidate.get("auto_pass") is True:
        flags |= AUTO_PASS
    if candidate.get("auto_fail") is True:
        flags |= AUTO_FAIL
    if candidate.get("force_specific") is True:
        flags |= FORCE_SPECIFIC
    if candidate.get("force_relation") is True:
        flags |= FORCE_RELATION
    return flags


def _score_inputs(
    function: Mapping[str, object],
    candidate: Mapping[str, object],
    semantics: Mapping[str, object],
) -> tuple[int, int, int, int, int]:
    if str(candidate["full_hash"]) != str(function["full_hash"]):
        raise ValueError("portable FID candidate does not share the query full hash")
    flags = _candidate_flags(candidate)
    function_units = int(candidate["code_unit_size"])
    if flags & AUTO_PASS:
        function_units = max(function_units, int(semantics["medium_code_unit_limit"]))
    specific_units = (
        int(candidate["specific_hash_additional_size"])
        if str(candidate["specific_hash"]) == str(function["specific_hash"])
        else 0
    )
    return (
        function_units,
        specific_units,
        int(candidate.get("child_code_units", 0)),
        int(candidate.get("parent_code_units", 0)),
        flags,
    )


def _score_cpu_row(
    values: tuple[int, int, int, int, int], semantics: Mapping[str, object]
) -> float | None:
    function_units, specific_units, child_units, parent_units, flags = values
    if flags & AUTO_FAIL:
        return None
    if flags & FORCE_SPECIFIC and specific_units == 0:
        return None
    if flags & FORCE_RELATION and child_units == 0:
        return None
    primary = _f32(function_units)
    primary = _f32(
        primary + float(semantics["specific_constant_weight"]) * specific_units
    )
    overall = _f32(_f32(primary + _f32(child_units)) + _f32(parent_units))
    if overall < _f32(float(semantics["score_threshold"])):
        return None
    return overall


def _cull(
    functions: Sequence[Mapping[str, object]], scores: Sequence[float | None]
) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    cursor = 0
    for function in functions:
        candidates = list(function.get("candidates", []))
        values = scores[cursor : cursor + len(candidates)]
        cursor += len(candidates)
        accepted = [
            (candidate, score)
            for candidate, score in zip(candidates, values)
            if score is not None
        ]
        if accepted:
            maximum = max(float(score) for _candidate, score in accepted)
            winners = [
                {
                    "candidate_id": str(candidate["candidate_id"]),
                    "owner": str(candidate["owner"]),
                    "name": str(candidate["name"]),
                    "score": float(score),
                }
                for candidate, score in accepted
                if float(score) == maximum
            ]
        else:
            winners = []
        output.append(
            {
                "address": str(function["address"]),
                "full_hash": str(function["full_hash"]),
                "specific_hash": str(function["specific_hash"]),
                "matches": winners,
            }
        )
    if cursor != len(scores):
        raise ValueError("portable FID score vector does not reconcile")
    return output


def match_cpu(
    document: Mapping[str, object], authority: Mapping[str, object]
) -> dict[str, object]:
    """Score and cull candidates with Java-float-compatible CPU arithmetic."""

    _validate_input(document)
    semantics = authority["semantics"]
    started_ns = time.monotonic_ns()
    functions = list(document["functions"])
    scores: list[float | None] = []
    for function in functions:
        for candidate in function.get("candidates", []):
            scores.append(
                _score_cpu_row(_score_inputs(function, candidate, semantics), semantics)
            )
    decisions = _cull(functions, scores)
    return {
        "backend": "cpu-portable-fid-v1",
        "device": None,
        "functions": decisions,
        "candidate_count": len(scores),
        "matched_functions": sum(bool(row["matches"]) for row in decisions),
        "wall_time_ns": time.monotonic_ns() - started_ns,
    }


def _gpu_shader(candidate_count: int, workgroup_size: int, semantics) -> str:
    threshold = float(semantics["score_threshold"])
    weight = float(semantics["specific_constant_weight"])
    return f"""
const CANDIDATE_COUNT: u32 = {candidate_count}u;
const WORDS: u32 = 5u;
const AUTO_FAIL: u32 = {AUTO_FAIL}u;
const FORCE_SPECIFIC: u32 = {FORCE_SPECIFIC}u;
const FORCE_RELATION: u32 = {FORCE_RELATION}u;
@group(0) @binding(0) var<storage, read> inputs: array<u32>;
@group(0) @binding(1) var<storage, read_write> scores: array<f32>;
@group(0) @binding(2) var<storage, read_write> accepted: array<u32>;

@compute @workgroup_size({workgroup_size})
fn main(@builtin(global_invocation_id) invocation: vec3<u32>) {{
    let index = invocation.x;
    if (index >= CANDIDATE_COUNT) {{ return; }}
    let base = index * WORDS;
    let function_units = inputs[base];
    let specific_units = inputs[base + 1u];
    let child_units = inputs[base + 2u];
    let parent_units = inputs[base + 3u];
    let flags = inputs[base + 4u];
    if ((flags & AUTO_FAIL) != 0u ||
        ((flags & FORCE_SPECIFIC) != 0u && specific_units == 0u) ||
        ((flags & FORCE_RELATION) != 0u && child_units == 0u)) {{
        scores[index] = 0.0;
        accepted[index] = 0u;
        return;
    }}
    let score = f32(function_units) + {weight} * f32(specific_units) +
        f32(child_units) + f32(parent_units);
    scores[index] = score;
    accepted[index] = select(0u, 1u, score >= {threshold});
}}
"""


def match_gpu(
    document: Mapping[str, object],
    authority: Mapping[str, object],
    *,
    workgroup_size: int = 256,
) -> dict[str, object]:
    """Score the same candidate rows with WGPU, retaining CPU-side culling."""

    _validate_input(document)
    if workgroup_size < 1 or workgroup_size > 1024:
        raise ValueError("portable FID WGPU workgroup size is invalid")
    import numpy as np
    import wgpu.utils
    from wgpu.utils.compute import compute_with_buffers

    semantics = authority["semantics"]
    functions = list(document["functions"])
    rows = [
        _score_inputs(function, candidate, semantics)
        for function in functions
        for candidate in function.get("candidates", [])
    ]
    started_ns = time.monotonic_ns()
    if rows:
        inputs = np.asarray(rows, dtype=np.uint32)
        groups = (len(rows) + workgroup_size - 1) // workgroup_size
        device = wgpu.utils.get_default_device()
        device_info = dict(device.adapter.info)
        gpu_backend = next(
            row for row in authority["backend"] if row["device"] == "gpu"
        )
        if device_info.get("adapter_type") not in gpu_backend[
            "allowed_adapter_types"
        ]:
            raise ValueError(
                "portable FID WGPU requires a hardware adapter; "
                f"resolved {device_info.get('adapter_type') or 'unknown'}"
            )
        buffers = compute_with_buffers(
            {0: inputs},
            {1: (len(rows), "f"), 2: (len(rows), "I")},
            _gpu_shader(len(rows), workgroup_size, semantics),
            n=groups,
        )
        raw_scores = np.frombuffer(buffers[1], dtype=np.float32)
        accepted = np.frombuffer(buffers[2], dtype=np.uint32)
        scores = [
            float(score) if int(keep) else None
            for score, keep in zip(raw_scores, accepted)
        ]
    else:
        scores = []
        device_info = None
    decisions = _cull(functions, scores)
    return {
        "backend": "gpu-portable-fid-v1",
        "device": device_info,
        "functions": decisions,
        "candidate_count": len(rows),
        "matched_functions": sum(bool(row["matches"]) for row in decisions),
        "wall_time_ns": time.monotonic_ns() - started_ns,
    }


def _validate_input(document: Mapping[str, object]) -> None:
    if document.get("schema_version") != MATCH_INPUT_SCHEMA:
        raise ValueError("portable FID input has unsupported schema")
    functions = document.get("functions")
    if not isinstance(functions, list):
        raise ValueError("portable FID input functions must be an array")
    seen = set()
    for function in functions:
        if not isinstance(function, dict) or not {
            "address",
            "full_hash",
            "specific_hash",
            "candidates",
            "native_matches",
        }.issubset(function):
            raise ValueError("portable FID function input is incomplete")
        address = str(function["address"])
        if address in seen or not isinstance(function["candidates"], list):
            raise ValueError("portable FID function identity is duplicated or invalid")
        seen.add(address)
        candidate_ids = set()
        for candidate in function["candidates"]:
            required = {
                "candidate_id",
                "owner",
                "name",
                "full_hash",
                "specific_hash",
                "specific_hash_additional_size",
                "code_unit_size",
                "child_code_units",
                "parent_code_units",
                "auto_pass",
                "auto_fail",
                "force_specific",
                "force_relation",
            }
            if not isinstance(candidate, dict) or not required.issubset(candidate):
                raise ValueError("portable FID candidate input is incomplete")
            candidate_id = str(candidate["candidate_id"])
            if candidate_id in candidate_ids:
                raise ValueError("portable FID candidate identity is duplicated")
            candidate_ids.add(candidate_id)


def compare_with_oracle(
    document: Mapping[str, object],
    portable: Mapping[str, object],
    authority: Mapping[str, object],
) -> dict[str, object]:
    """Compare one portable backend with native FidProgramSeeker decisions."""

    _validate_input(document)
    native = {
        str(row["address"]): {
            str(match["candidate_id"]): float(match["score"])
            for match in row["native_matches"]
        }
        for row in document["functions"]
    }
    observed = {
        str(row["address"]): {
            str(match["candidate_id"]): float(match["score"])
            for match in row["matches"]
        }
        for row in portable["functions"]
    }
    maximum_ulps = int(authority["oracle"]["score_max_float32_ulps"])
    mismatches = []
    compared_scores = 0
    maximum_score_delta = 0.0
    maximum_score_ulps = 0
    for address in sorted(set(native) | set(observed)):
        expected = native.get(address, {})
        actual = observed.get(address, {})
        missing = sorted(set(expected) - set(actual))
        unexpected = sorted(set(actual) - set(expected))
        score_differences = []
        for candidate_id in sorted(set(expected) & set(actual)):
            compared_scores += 1
            delta = abs(expected[candidate_id] - actual[candidate_id])
            ulps = _f32_ulps(expected[candidate_id], actual[candidate_id])
            maximum_score_delta = max(maximum_score_delta, delta)
            maximum_score_ulps = max(maximum_score_ulps, ulps)
            if ulps > maximum_ulps:
                score_differences.append(
                    {
                        "candidate_id": candidate_id,
                        "native": expected[candidate_id],
                        "portable": actual[candidate_id],
                        "absolute_delta": delta,
                        "float32_ulps": ulps,
                    }
                )
        if missing or unexpected or score_differences:
            mismatches.append(
                {
                    "address": address,
                    "missing_candidates": missing,
                    "unexpected_candidates": unexpected,
                    "score_differences": score_differences,
                }
            )
    limit = int(authority["evidence"]["maximum_mismatch_rows"])
    decision_mismatches = len(mismatches)
    return {
        "state": "equivalent" if decision_mismatches == 0 else "mismatch",
        "oracle": authority["oracle"]["implementation"],
        "backend": portable["backend"],
        "functions": len(native),
        "candidate_scores_compared": compared_scores,
        "decision_mismatches": decision_mismatches,
        "maximum_score_delta": maximum_score_delta,
        "maximum_score_float32_ulps": maximum_score_ulps,
        "mismatches": mismatches[:limit],
        "mismatch_rows_truncated": max(0, decision_mismatches - limit),
    }


def qualification_report(
    document: Mapping[str, object],
    authority: Mapping[str, object],
    *,
    include_gpu: bool = True,
) -> dict[str, object]:
    """Run CPU and optionally WGPU, comparing each independently to Ghidra."""

    started_ns = time.monotonic_ns()
    input_bytes = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    cpu = match_cpu(document, authority)
    comparisons = [compare_with_oracle(document, cpu, authority)]
    executions = [cpu]
    if include_gpu:
        gpu = match_gpu(document, authority)
        executions.append(gpu)
        comparisons.append(compare_with_oracle(document, gpu, authority))
    state = (
        "qualified"
        if len(comparisons) == 2
        and all(row["state"] == "equivalent" for row in comparisons)
        else "incomplete-or-mismatch"
    )
    return {
        "schema_version": MATCH_REPORT_SCHEMA,
        "state": state,
        "scope": "ghidra-fid-candidate-scoring-and-winner-selection",
        "input_sha256": hashlib.sha256(input_bytes).hexdigest(),
        "authority_path": authority["authority_path"],
        "authority_sha256": authority["authority_sha256"],
        "oracle": authority["oracle"]["implementation"],
        "executions": executions,
        "comparisons": comparisons,
        "wall_time_ns": time.monotonic_ns() - started_ns,
    }


def classify_matches(
    document: Mapping[str, object], owners: Sequence[str]
) -> dict[str, object]:
    """Classify native FID owner decisions for functions with frozen truth.

    One labelled query function contributes one positive owner decision and
    ``len(owners) - 1`` negative owner decisions.  Functions whose provenance
    cannot be resolved from the linker map or an unambiguous reference name
    are retained but excluded from the confusion matrix.
    """

    _validate_input(document)
    owner_universe = tuple(sorted(set(str(owner) for owner in owners)))
    if len(owner_universe) < 2:
        raise ValueError("portable FID classification requires multiple owners")
    matrix = {
        "true_positives": 0,
        "false_positives": 0,
        "true_negatives": 0,
        "false_negatives": 0,
    }
    basis_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    observations: list[dict[str, object]] = []
    labelled = 0
    unlabelled = 0
    ambiguous_truth = 0
    for function in document["functions"]:
        truth_owner = function.get("truth_owner")
        truth_basis = str(function.get("truth_basis", "unresolved"))
        if not truth_owner or truth_owner not in owner_universe:
            unlabelled += 1
            ambiguous_truth += len(function.get("truth_candidates", [])) > 1
            continue
        labelled += 1
        basis_counts[truth_basis] = basis_counts.get(truth_basis, 0) + 1
        matches = list(function.get("native_matches", []))
        by_owner: dict[str, list[Mapping[str, object]]] = {}
        for match in matches:
            by_owner.setdefault(str(match["owner"]), []).append(match)
        accepted_owners = set(by_owner)
        recovered = str(truth_owner) in accepted_owners
        matrix["true_positives" if recovered else "false_negatives"] += 1
        incorrect = accepted_owners - {str(truth_owner)}
        matrix["false_positives"] += len(incorrect)
        matrix["true_negatives"] += len(owner_universe) - 1 - len(incorrect)

        owner_outcomes = [
            (str(truth_owner), "tp" if recovered else "fn", None)
        ] + [
            (owner, "fp", by_owner[owner][0]) for owner in sorted(incorrect)
        ]
        for candidate_owner, outcome, match in owner_outcomes:
            if outcome == "tp":
                category = "correct-attribution"
            elif outcome == "fn":
                category = "miss"
            elif match and str(match.get("name", "")) == str(
                function.get("function_name", "")
            ):
                category = "shared-code-evidence"
            elif len(accepted_owners) > 1:
                category = "ambiguous-attribution"
            else:
                category = "incorrect-confident-attribution"
            category_counts[category] = category_counts.get(category, 0) + 1
            values = {
                "full": str(function["full_hash"]),
                "specific": str(function["specific_hash"]),
                "complete": ":".join(
                    (
                        str(function["full_hash"]),
                        str(function["specific_hash"]),
                        str(function.get("specific_hash_additional_size", 0)),
                        str(function.get("code_unit_size", 0)),
                    )
                ),
            }
            for hash_type, value in values.items():
                observations.append(
                    {
                        "address": str(function["address"]),
                        "function_name": str(function.get("function_name", "")),
                        "hash_type": hash_type,
                        "value": value,
                        "outcome": outcome,
                        "truth_owner": str(truth_owner),
                        "candidate_owner": candidate_owner,
                        "truth_basis": truth_basis,
                        "accepted_owner_count": len(accepted_owners),
                        "category": category,
                    }
                )

    tp = matrix["true_positives"]
    fp = matrix["false_positives"]
    tn = matrix["true_negatives"]
    fn = matrix["false_negatives"]

    def rate(numerator: int, denominator: int) -> float | None:
        return numerator / denominator if denominator else None

    return {
        "schema_version": "fidb-portable-fid-classification/v1",
        "decision_unit": "query-function-library-owner",
        "owners": list(owner_universe),
        "truth": {
            "labelled_functions": labelled,
            "unlabelled_functions": unlabelled,
            "ambiguous_truth_functions": ambiguous_truth,
            "basis_counts": dict(sorted(basis_counts.items())),
        },
        "confusion_matrix": matrix,
        "rates": {
            "precision": rate(tp, tp + fp),
            "recall": rate(tp, tp + fn),
            "false_positive_rate": rate(fp, fp + tn),
            "specificity": rate(tn, tn + fp),
        },
        "categories": dict(sorted(category_counts.items())),
        "observations": observations,
    }
