"""Bounded native-Ghidra qualification for portable FID matching backends."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import time
from typing import Mapping

from .fid_matching import (
    classify_matches,
    compare_with_oracle,
    load_matching_authority,
    match_cpu,
    match_gpu,
)

QUALIFICATION_SCHEMA = "fidb-portable-fid-qualification/v1"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def _fidb_from_signatures(root: Path, source: Path) -> Path:
    text = str(source)
    marker = "/fid-signatures/"
    suffix = ".fid-signatures.jsonl"
    if marker not in text or not text.endswith(suffix):
        raise ValueError(f"cannot resolve FIDB from signature evidence: {source}")
    candidate = Path(text.replace(marker, "/fidb/")[: -len(suffix)] + ".fidb")
    candidate = candidate.resolve()
    if root not in candidate.parents or not candidate.is_file():
        raise ValueError(f"resolved native oracle FIDB is unavailable: {candidate}")
    return candidate


def _signature_names(path: Path) -> set[str]:
    names = set()
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                row = json.loads(line)
                name = str(row.get("function_name", row.get("name", "")))
                if name:
                    names.add(name)
    return names


def _linker_truth_intervals(
    root: Path, truth: Mapping[str, object], link_map: Path
) -> list[tuple[int, int, str]]:
    if not link_map.is_file():
        return []
    archive_owners: dict[str, str] = {}
    for item in truth["archives"]:
        for relative in item["paths"]:
            archive_owners[str((root / str(relative)).resolve())] = str(item["owner"])
    row_pattern = re.compile(
        r"^\s*(?:\.\S+\s+)?0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+(.+?\.a)(?:\([^)]*\))?\s*$"
    )
    intervals = []
    for line in link_map.read_text(encoding="utf-8", errors="replace").splitlines():
        match = row_pattern.match(line)
        if not match:
            continue
        start = int(match.group(1), 16)
        size = int(match.group(2), 16)
        owner = archive_owners.get(str(Path(match.group(3)).resolve()))
        if owner and size:
            intervals.append((start, start + size, owner))
    return sorted(set(intervals))


def _annotate_truth(
    root: Path,
    oracle: dict[str, object],
    fold_root: Path,
    signature_paths: Mapping[str, Path],
) -> None:
    truth = json.loads((fold_root / "truth-map.json").read_text(encoding="utf-8"))
    owners = [str(owner) for owner in truth["owners"]]
    owner_by_name: dict[str, set[str]] = {}
    for owner in owners:
        for name in _signature_names(signature_paths[owner]):
            owner_by_name.setdefault(name, set()).add(owner)
    intervals = _linker_truth_intervals(root, truth, fold_root / "link.map")
    for function in oracle["functions"]:
        try:
            address = int(str(function["address"]), 16)
        except ValueError:
            address = -1
        interval_owners = {
            owner for start, end, owner in intervals if start <= address < end
        }
        name_owners = owner_by_name.get(str(function.get("function_name", "")), set())
        if len(interval_owners) == 1:
            candidates = interval_owners
            basis = "linker-map"
        elif len(name_owners) == 1:
            candidates = name_owners
            basis = "unique-reference-name"
        else:
            candidates = interval_owners or name_owners
            basis = "ambiguous" if candidates else "unresolved"
        function["truth_candidates"] = sorted(candidates)
        function["truth_owner"] = (
            next(iter(candidates)) if len(candidates) == 1 else None
        )
        function["truth_basis"] = basis
    oracle["truth"] = {
        "owners": owners,
        "truth_map_path": str((fold_root / "truth-map.json").relative_to(root)),
        "link_map_path": (
            str((fold_root / "link.map").relative_to(root))
            if (fold_root / "link.map").is_file()
            else None
        ),
        "linker_intervals": len(intervals),
    }


def qualify_retained_validation(
    project_root: str | Path,
    run_id: str,
    *,
    position: int,
    fold: str,
    runtime_path: str | Path = "validation/machine-validation-runtime.toml",
    authority_path: str | Path = "validation/fid-matching.toml",
    output_root: str | Path = "qualification/evidence",
    reuse_oracle: bool = False,
) -> dict[str, object]:
    """Qualify CPU and WGPU against one retained, reviewed validation unit."""

    if position < 1 or fold not in {"A", "B"}:
        raise ValueError("FID matcher qualification position/fold is invalid")
    from . import ghidra_fid
    from .machine_validation_runner import load_runtime, resolve_hash_analysis_evidence
    from .pipeline import find_ghidra, ghidra_environment

    started_ns = time.monotonic_ns()
    root = Path(project_root).expanduser().resolve()
    authority = load_matching_authority(root, authority_path)
    runtime = load_runtime(root, runtime_path)
    evidence = resolve_hash_analysis_evidence(root, runtime_path)
    validation_root = (root / str(runtime["output_root"])).resolve()
    run_root = (validation_root / run_id).resolve()
    if run_root.parent != validation_root or not run_root.is_dir():
        raise ValueError("retained validation run is unavailable")
    matches = list((run_root / "units").glob(f"{position:03d}-*/result.json"))
    if len(matches) != 1:
        raise ValueError("retained validation unit is missing or ambiguous")
    result = json.loads(matches[0].read_text(encoding="utf-8"))
    if result.get("state") != "complete":
        raise ValueError("retained validation unit is not complete")
    route_id = str(result["route_id"])
    treatment_id = str(result["treatment_id"])
    routes = {route.id: route for route in evidence["configuration"].routes}
    route = routes[route_id]
    fold_root = matches[0].parent / f"fold-{fold}"
    query_binary = next(
        (
            path
            for path in (fold_root / "query.elf", fold_root / "query.dll")
            if path.is_file()
        ),
        None,
    )
    if query_binary is None:
        raise ValueError("retained validation query binary is unavailable")
    fidbs = []
    signature_paths = {}
    for owner in evidence["cohort"]:
        item = evidence["signatures"].get((owner, route_id, treatment_id))
        if item is None:
            raise ValueError(f"signature evidence is absent for {owner}")
        signature_path = Path(item["path"])
        signature_paths[owner] = signature_path
        fidbs.append(_fidb_from_signatures(root, signature_path))

    case_id = f"{run_id}-{position:03d}-{fold}"
    destination = (root / output_root / case_id).resolve()
    if root not in destination.parents:
        raise ValueError("FID matcher qualification output escapes project root")
    destination.mkdir(parents=True, exist_ok=True)
    oracle_path = destination / "oracle-input.json"
    if reuse_oracle:
        if not oracle_path.is_file():
            raise ValueError(
                "replay requested but retained native oracle is unavailable"
            )
        oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
    else:
        project_parent = destination / "work" / "project"
        if project_parent.exists():
            shutil.rmtree(project_parent)
        os.environ["GHIDRA_HEADLESS"] = str(runtime["ghidra_headless"])
        _headless, ghidra_home = find_ghidra()
        ghidra_fid.ensure_started(
            ghidra_home, ghidra_environment(destination / "work" / "ghidra-user")
        )
        project_dir, program_path = ghidra_fid.analyze_target(
            query_binary,
            project_parent,
            "oracle",
            route.ghidra_language,
            route.ghidra_compiler_spec,
        )
        oracle = ghidra_fid.export_fid_oracle_input(
            project_dir, "oracle", program_path, fidbs, oracle_path
        )
    _annotate_truth(root, oracle, fold_root, signature_paths)
    _atomic_json(oracle_path, oracle)
    cpu = match_cpu(oracle, authority)
    gpu = match_gpu(oracle, authority)
    classification = classify_matches(oracle, evidence["cohort"])
    cpu_path = destination / "cpu-output.json"
    gpu_path = destination / "gpu-output.json"
    _atomic_json(cpu_path, cpu)
    _atomic_json(gpu_path, gpu)
    classification_path = destination / "classification.json"
    _atomic_json(classification_path, classification)
    comparisons = [
        compare_with_oracle(oracle, cpu, authority),
        compare_with_oracle(oracle, gpu, authority),
    ]
    state = (
        "qualified"
        if all(row["state"] == "equivalent" for row in comparisons)
        else "mismatch"
    )
    summary = {
        "schema_version": QUALIFICATION_SCHEMA,
        "state": state,
        "scope": "ghidra-fid-candidate-scoring-and-winner-selection",
        "case": {
            "validation_id": runtime["validation_id"],
            "run_id": run_id,
            "position": position,
            "fold": fold,
            "route_id": route_id,
            "treatment_id": treatment_id,
            "target_os": route.target_os,
            "binary_format": route.binary_format,
            "ghidra_language_id": route.ghidra_language,
            "ghidra_compiler_spec_id": route.ghidra_compiler_spec,
            "query_path": str(query_binary.relative_to(root)),
            "query_sha256": _sha256(query_binary),
            "fidb_count": len(fidbs),
            "fidb_sha256": [_sha256(path) for path in fidbs],
        },
        "authority_path": authority["authority_path"],
        "authority_sha256": authority["authority_sha256"],
        "oracle": {
            "implementation": authority["oracle"]["implementation"],
            "source": "retained-replay" if reuse_oracle else "native-execution",
            "functions": len(oracle["functions"]),
            "functions_with_candidates": sum(
                bool(row["candidates"]) for row in oracle["functions"]
            ),
            "accepted_functions": sum(
                bool(row["native_matches"]) for row in oracle["functions"]
            ),
            "input_path": str(oracle_path.relative_to(root)),
            "input_sha256": _sha256(oracle_path),
        },
        "executions": [
            {
                "backend": execution["backend"],
                "candidate_count": execution["candidate_count"],
                "matched_functions": execution["matched_functions"],
                "wall_time_ns": execution["wall_time_ns"],
                "device": execution["device"],
                "output_path": str(path.relative_to(root)),
                "output_sha256": _sha256(path),
            }
            for execution, path in ((cpu, cpu_path), (gpu, gpu_path))
        ],
        "comparisons": comparisons,
        "classification": {
            key: classification[key]
            for key in (
                "decision_unit",
                "truth",
                "confusion_matrix",
                "rates",
                "categories",
            )
        },
        "classification_path": str(classification_path.relative_to(root)),
        "classification_sha256": _sha256(classification_path),
        "wall_time_ns": time.monotonic_ns() - started_ns,
    }
    summary_path = destination / "summary.json"
    _atomic_json(summary_path, summary)
    shutil.rmtree(destination / "work", ignore_errors=True)
    return {**summary, "report_path": str(summary_path.relative_to(root))}
