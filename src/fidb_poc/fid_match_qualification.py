"""Bounded native-Ghidra qualification for portable FID matching backends."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
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
from .validation_analysis import (
    QUERY_ANALYSIS_POLICY,
    QUERY_ANALYSIS_RECOVERY_POLICY,
)

QUALIFICATION_SCHEMA = "fidb-portable-fid-qualification/v1"
RELATIONSHIP_RECEIPT_SCHEMA = "fidb-query-relationship-evidence/v1"


def _retained_query_analysis_policy(
    fold_result: Mapping[str, object], route: object
) -> str:
    """Reuse the exact policy that sealed the retained query evidence."""

    policy = str(fold_result.get("query_analysis_policy") or QUERY_ANALYSIS_POLICY)
    if policy not in {QUERY_ANALYSIS_POLICY, QUERY_ANALYSIS_RECOVERY_POLICY}:
        raise ValueError(f"retained query analysis policy is unsupported: {policy}")
    language = str(getattr(route, "ghidra_language", ""))
    if policy == QUERY_ANALYSIS_RECOVERY_POLICY and not language.startswith("SuperH4:"):
        raise ValueError("SuperH query recovery policy cannot be applied to another ISA")
    return policy


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


def _load_retained_oracle_replay(
    root: Path,
    destination: Path,
    *,
    run_id: str,
    position: int,
    fold: str,
    route_id: str,
    treatment_id: str,
    query_binary: Path,
    fidbs: list[Path],
    language_id: str,
    compiler_spec_id: str,
    authority: Mapping[str, object],
    link_harness_policy: str,
) -> dict[str, object]:
    """Load an immutable native oracle only when all source identities agree."""

    summary_path = destination / "summary.json"
    oracle_path = destination / "oracle-input.json"
    if not summary_path.is_file() or not oracle_path.is_file():
        raise ValueError("replay requested but retained native oracle is unavailable")
    try:
        previous = json.loads(summary_path.read_text(encoding="utf-8"))
        oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("retained native oracle evidence is unreadable") from error
    case = previous.get("case", {})
    oracle_receipt = previous.get("oracle", {})
    expected_fidb_sha256 = [_sha256(path) for path in fidbs]
    if not (
        previous.get("state") == "qualified"
        and case.get("run_id") == run_id
        and int(case.get("position", -1)) == position
        and case.get("fold") == fold
        and case.get("route_id") == route_id
        and case.get("treatment_id") == treatment_id
        and case.get("query_sha256") == _sha256(query_binary)
        and case.get("fidb_sha256") == expected_fidb_sha256
        and case.get("link_harness_policy") == link_harness_policy
        and oracle_receipt.get("implementation")
        == authority["oracle"]["implementation"]
        and oracle_receipt.get("input_path") == str(oracle_path.relative_to(root))
        and oracle_receipt.get("input_sha256") == _sha256(oracle_path)
    ):
        raise ValueError("retained native oracle does not match current source evidence")
    if not (
        oracle.get("schema_version") == "fidb-portable-fid-input/v1"
        and oracle.get("oracle") == authority["oracle"]["implementation"]
        and oracle.get("language_id") == language_id
        and oracle.get("compiler_spec_id") == compiler_spec_id
        and float(oracle.get("score_threshold", -1))
        == float(authority["semantics"]["score_threshold"])
        and int(oracle.get("medium_code_unit_limit", -1))
        == int(authority["semantics"]["medium_code_unit_limit"])
        and isinstance(oracle.get("functions"), list)
    ):
        raise ValueError("retained native oracle uses incompatible matching semantics")
    return oracle


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


def _symbol_address_bias(
    query_binary: Path, functions: list[dict[str, object]]
) -> dict[str, int]:
    """Measure Ghidra's import bias against retained symbols in the query image."""

    nm = shutil.which("llvm-nm") or shutil.which("nm")
    if nm is None:
        raise ValueError("truth attribution requires llvm-nm or nm")
    result = subprocess.run(
        [nm, "-S", "--defined-only", str(query_binary)],
        text=True,
        capture_output=True,
        timeout=300,
        check=False,
    )
    if result.returncode:
        raise ValueError(f"could not inspect query symbols: {result.stderr[-1000:]}")
    symbols: dict[str, set[int]] = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 4:
            try:
                address = int(fields[0], 16)
            except ValueError:
                continue
            symbols.setdefault(fields[-1], set()).add(address)
    differences = Counter()
    for function in functions:
        addresses = symbols.get(str(function.get("function_name", "")), set())
        if len(addresses) != 1:
            continue
        try:
            ghidra_address = int(str(function["address"]), 16)
        except (KeyError, ValueError):
            continue
        differences[ghidra_address - next(iter(addresses))] += 1
    if not differences:
        raise ValueError("could not establish Ghidra-to-linker address bias")
    bias, supporting_symbols = differences.most_common(1)[0]
    return {
        "bytes": bias,
        "supporting_symbols": supporting_symbols,
        "observed_biases": len(differences),
    }


def _annotate_truth(
    root: Path,
    oracle: dict[str, object],
    fold_root: Path,
    signature_paths: Mapping[str, Path],
    query_binary: Path,
) -> None:
    truth = json.loads((fold_root / "truth-map.json").read_text(encoding="utf-8"))
    owners = [str(owner) for owner in truth["owners"]]
    owner_by_name: dict[str, set[str]] = {}
    for owner in owners:
        for name in _signature_names(signature_paths[owner]):
            owner_by_name.setdefault(name, set()).add(owner)
    intervals = _linker_truth_intervals(root, truth, fold_root / "link.map")
    address_bias = _symbol_address_bias(query_binary, oracle["functions"])
    for function in oracle["functions"]:
        try:
            address = int(str(function["address"]), 16) - address_bias["bytes"]
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
        "ghidra_to_linker_address_bias": address_bias,
    }


def ensure_query_relationship_evidence(
    root: Path,
    fold_root: Path,
    fold_result: Mapping[str, object],
    query_binary: Path,
    route: object,
    treatment_id: str,
    runtime: Mapping[str, object],
    work_root: Path,
) -> tuple[Path, dict[str, object], str]:
    """Return digest-bound query hashes/relations, backfilling a legacy fold once."""

    direct = fold_root / "query-signatures.jsonl"
    summary = fold_result.get("signature_summary")
    if (
        isinstance(summary, dict)
        and direct.is_file()
        and summary.get("evidence_schema") == "fidb-program-signature-evidence/v1"
        and summary.get("artifact_sha256") == _sha256(direct)
        and summary.get("artifact_bytes") == direct.stat().st_size
    ):
        return direct, dict(summary), "original-fold-export"

    output = fold_root / "query-fid-evidence.jsonl"
    receipt_path = fold_root / "relationship-evidence.json"
    query_sha256 = _sha256(query_binary)
    query_policy = _retained_query_analysis_policy(fold_result, route)
    if receipt_path.is_file():
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        evidence = receipt.get("evidence", {})
        if not (
            receipt.get("schema_version") == RELATIONSHIP_RECEIPT_SCHEMA
            and receipt.get("query_sha256") == query_sha256
            and receipt.get("route_id") == getattr(route, "id")
            and receipt.get("treatment_id") == treatment_id
            and receipt.get("query_analysis_policy") == query_policy
            and evidence.get("schema_version")
            == "fidb-program-signature-evidence/v1"
            and evidence.get("path") == str(output.relative_to(root))
            and output.is_file()
            and evidence.get("sha256") == _sha256(output)
            and evidence.get("bytes") == output.stat().st_size
        ):
            raise ValueError("query relationship-evidence receipt is invalid")
        return output, dict(receipt["signature_summary"]), "sealed-backfill"

    from . import ghidra_fid
    from .pipeline import find_ghidra, ghidra_environment

    os.environ["GHIDRA_HEADLESS"] = str(runtime["ghidra_headless"])
    _headless, ghidra_home = find_ghidra()
    ghidra_fid.ensure_started(
        ghidra_home, ghidra_environment(work_root / "ghidra-user")
    )
    project_parent = work_root / "query-project"
    if project_parent.exists():
        shutil.rmtree(project_parent)
    project_dir, program_path = ghidra_fid.analyze_target(
        query_binary,
        project_parent,
        "compact-query",
        getattr(route, "ghidra_language"),
        getattr(route, "ghidra_compiler_spec"),
        analysis_policy=query_policy,
    )
    signature_summary = ghidra_fid.export_program_signatures(
        project_dir, "compact-query", program_path, output
    )
    if signature_summary.get("evidence_schema") != (
        "fidb-program-signature-evidence/v1"
    ):
        raise ValueError("query relationship backfill emitted unsupported evidence")
    receipt = {
        "schema_version": RELATIONSHIP_RECEIPT_SCHEMA,
        "query_sha256": query_sha256,
        "route_id": getattr(route, "id"),
        "treatment_id": treatment_id,
        "query_analysis_policy": query_policy,
        "signature_summary": signature_summary,
        "evidence": {
            "schema_version": signature_summary["evidence_schema"],
            "path": str(output.relative_to(root)),
            "sha256": _sha256(output),
            "bytes": output.stat().st_size,
        },
    }
    _atomic_json(receipt_path, receipt)
    shutil.rmtree(project_parent, ignore_errors=True)
    return output, signature_summary, "new-backfill"


def _portable_executions(
    oracle: Mapping[str, object],
    authority: Mapping[str, object],
    *,
    compare_backends: bool,
) -> list[dict[str, object]]:
    """Run both backends for qualification or one reviewed backend routinely."""

    backend_ids = (
        [str(row["id"]) for row in authority["backend"]]
        if compare_backends
        else [str(authority["selected"])]
    )
    executions = []
    for backend_id in backend_ids:
        backend = authority["backends"][backend_id]
        execution = (
            match_gpu(oracle, authority)
            if backend["device"] == "gpu"
            else match_cpu(oracle, authority)
        )
        if execution.get("backend") != backend_id:
            raise ValueError("portable FID backend returned the wrong identity")
        executions.append(execution)
    return executions


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
    oracle_replay_source: str | Path | None = None,
    compare_backends: bool = True,
) -> dict[str, object]:
    """Run native FID and either qualify all or verify the selected backend."""

    if position < 1 or fold not in {"A", "B"}:
        raise ValueError("FID matcher qualification position/fold is invalid")
    from . import ghidra_fid
    from .machine_validation import LINK_HARNESS_POLICY
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
    fold_results = [row for row in result.get("folds", []) if row.get("fold") == fold]
    if len(fold_results) != 1:
        raise ValueError("retained validation fold result is unavailable")
    fold_result = fold_results[0]
    if fold_result.get("link_harness_policy") != LINK_HARNESS_POLICY:
        raise ValueError("retained validation fold uses a stale link harness")
    if fold_result.get("link_audit", {}).get("direct_zero_control_flow_count") != 0:
        raise ValueError("retained validation fold failed its link audit")
    routes = {route.id: route for route in evidence["configuration"].routes}
    route = routes[route_id]
    query_analysis_policy = _retained_query_analysis_policy(fold_result, route)
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
        replay_source = (
            Path(oracle_replay_source).resolve()
            if oracle_replay_source is not None
            else destination
        )
        if replay_source != root and root not in replay_source.parents:
            raise ValueError("native oracle replay source escapes project root")
        oracle = _load_retained_oracle_replay(
            root,
            replay_source,
            run_id=run_id,
            position=position,
            fold=fold,
            route_id=route_id,
            treatment_id=treatment_id,
            query_binary=query_binary,
            fidbs=fidbs,
            language_id=route.ghidra_language,
            compiler_spec_id=route.ghidra_compiler_spec,
            authority=authority,
            link_harness_policy=LINK_HARNESS_POLICY,
        )
        oracle_evidence_path = replay_source / "oracle-input.json"
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
            analysis_policy=query_analysis_policy,
        )
        oracle = ghidra_fid.export_fid_oracle_input(
            project_dir, "oracle", program_path, fidbs, oracle_path
        )
        oracle_evidence_path = oracle_path
    _annotate_truth(root, oracle, fold_root, signature_paths, query_binary)
    if oracle_evidence_path == oracle_path:
        _atomic_json(oracle_path, oracle)
    executions = _portable_executions(
        oracle,
        authority,
        compare_backends=compare_backends,
    )
    classification = classify_matches(oracle, evidence["cohort"])
    execution_paths = []
    for execution in executions:
        device = str(authority["backends"][execution["backend"]]["device"])
        path = destination / f"{device}-output.json"
        _atomic_json(path, execution)
        execution_paths.append(path)
    classification_path = destination / "classification.json"
    _atomic_json(classification_path, classification)
    comparisons = [
        compare_with_oracle(oracle, execution, authority) for execution in executions
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
        "execution_policy": (
            "qualification-all-backends"
            if compare_backends
            else "selected-backend-only"
        ),
        "selected_backend": authority["selected"],
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
            "query_analysis_policy": query_analysis_policy,
            "query_path": str(query_binary.relative_to(root)),
            "query_sha256": _sha256(query_binary),
            "link_harness_policy": LINK_HARNESS_POLICY,
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
            "input_path": str(oracle_evidence_path.relative_to(root)),
            "input_sha256": _sha256(oracle_evidence_path),
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
            for execution, path in zip(executions, execution_paths, strict=True)
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


def run_compact_retained_validation(
    project_root: str | Path,
    run_id: str,
    *,
    position: int,
    fold: str,
    candidate_index: str | Path,
    runtime_path: str | Path = "validation/machine-validation-runtime.toml",
    authority_path: str | Path = "validation/fid-matching.toml",
    performance_path: str | Path = "performance/fid-matching.toml",
    output_root: str | Path = "qualification/evidence",
    oracle_replay_source: str | Path | None = None,
) -> dict[str, object]:
    """Run the selected compact backend without constructing a native oracle."""

    if position < 1 or fold not in {"A", "B"}:
        raise ValueError("compact FID matcher position/fold is invalid")
    from .fid_compact import (
        load_fid_matching_performance,
        load_query_evidence,
        match_compact,
        selected_backend_id,
    )
    from .fid_matching import MATCH_INPUT_SCHEMA
    from .machine_validation import LINK_HARNESS_POLICY
    from .machine_validation_runner import load_runtime, resolve_hash_analysis_evidence

    started_ns = time.monotonic_ns()
    root = Path(project_root).expanduser().resolve()
    authority = load_matching_authority(root, authority_path)
    performance = load_fid_matching_performance(root, performance_path)
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
    route_id = str(result["route_id"])
    treatment_id = str(result["treatment_id"])
    fold_results = [row for row in result.get("folds", []) if row.get("fold") == fold]
    if len(fold_results) != 1:
        raise ValueError("retained validation fold result is unavailable")
    fold_result = fold_results[0]
    if fold_result.get("link_harness_policy") != LINK_HARNESS_POLICY:
        raise ValueError("retained validation fold uses a stale link harness")
    if fold_result.get("link_audit", {}).get("direct_zero_control_flow_count") != 0:
        raise ValueError("retained validation fold failed its link audit")
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
    case_id = f"{run_id}-{position:03d}-{fold}"
    destination = (root / output_root / case_id).resolve()
    if root not in destination.parents:
        raise ValueError("compact FID matcher output escapes project root")
    destination.mkdir(parents=True, exist_ok=True)
    query_path, query_summary, query_source = ensure_query_relationship_evidence(
        root,
        fold_root,
        fold_result,
        query_binary,
        route,
        treatment_id,
        runtime,
        destination / "work",
    )
    functions = load_query_evidence(query_path)
    document = {
        "schema_version": MATCH_INPUT_SCHEMA,
        "functions": [
            {**row, "candidates": [], "native_matches": []} for row in functions
        ],
    }
    signature_paths = {}
    fidbs = []
    for owner in evidence["cohort"]:
        item = evidence["signatures"].get((owner, route_id, treatment_id))
        if item is None:
            raise ValueError(f"signature evidence is absent for {owner}")
        signature_paths[owner] = Path(item["path"])
        fidbs.append(_fidb_from_signatures(root, Path(item["path"])))
    _annotate_truth(root, document, fold_root, signature_paths, query_binary)

    index_path = Path(candidate_index).resolve()
    if root not in index_path.parents or not index_path.is_file():
        raise ValueError("compact FID candidate index is unavailable")
    requested_backend = selected_backend_id(performance, authority)
    execution = match_compact(
        index_path,
        document["functions"],
        route_id,
        treatment_id,
        authority,
        backend_id=requested_backend,
        chunk_rows=int(performance["candidate_chunk_rows"]),
        workgroup_size=int(performance["workgroup_size"]),
        fallback_to_cpu=bool(performance["fallback_to_cpu"]),
    )
    classification = classify_matches(document, evidence["cohort"], execution)
    comparisons = []
    oracle_receipt = {
        "implementation": authority["oracle"]["implementation"],
        "source": "bounded-canary-only",
        "functions": len(document["functions"]),
        "functions_with_candidates": None,
        "accepted_functions": None,
        "input_path": None,
        "input_sha256": None,
    }
    if oracle_replay_source is not None:
        replay_source = Path(oracle_replay_source).resolve()
        oracle = _load_retained_oracle_replay(
            root,
            replay_source,
            run_id=run_id,
            position=position,
            fold=fold,
            route_id=route_id,
            treatment_id=treatment_id,
            query_binary=query_binary,
            fidbs=fidbs,
            language_id=route.ghidra_language,
            compiler_spec_id=route.ghidra_compiler_spec,
            authority=authority,
            link_harness_policy=LINK_HARNESS_POLICY,
        )
        comparisons = [compare_with_oracle(oracle, execution, authority)]
        oracle_path = replay_source / "oracle-input.json"
        oracle_receipt = {
            "implementation": authority["oracle"]["implementation"],
            "source": "retained-replay",
            "functions": len(oracle["functions"]),
            "functions_with_candidates": sum(
                bool(row["candidates"]) for row in oracle["functions"]
            ),
            "accepted_functions": sum(
                bool(row["native_matches"]) for row in oracle["functions"]
            ),
            "input_path": str(oracle_path.relative_to(root)),
            "input_sha256": _sha256(oracle_path),
        }
    equivalent = all(row["state"] == "equivalent" for row in comparisons)
    execution_path = destination / "selected-output.json"
    classification_path = destination / "classification.json"
    _atomic_json(execution_path, execution)
    _atomic_json(classification_path, classification)
    summary = {
        "schema_version": QUALIFICATION_SCHEMA,
        "state": "qualified" if equivalent else "mismatch",
        "scope": "compact-portable-fid-routine-execution",
        "execution_policy": "selected-backend-only",
        "selected_backend": execution["backend"],
        "requested_backend": requested_backend,
        "performance": {
            "authority_path": performance["authority_path"],
            "authority_sha256": performance["authority_sha256"],
            "fallback_reason": execution["fallback_reason"],
        },
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
            "query_analysis_policy": _retained_query_analysis_policy(
                fold_result, route
            ),
            "query_path": str(query_binary.relative_to(root)),
            "query_sha256": _sha256(query_binary),
            "query_evidence_path": str(query_path.relative_to(root)),
            "query_evidence_sha256": _sha256(query_path),
            "query_evidence_source": query_source,
            "link_harness_policy": LINK_HARNESS_POLICY,
            "candidate_index_path": str(index_path.relative_to(root)),
            "candidate_index_sha256": _sha256(index_path),
        },
        "authority_path": authority["authority_path"],
        "authority_sha256": authority["authority_sha256"],
        "oracle": oracle_receipt,
        "executions": [
            {
                "backend": execution["backend"],
                "requested_backend": requested_backend,
                "candidate_count": execution["candidate_count"],
                "matched_functions": execution["matched_functions"],
                "wall_time_ns": execution["wall_time_ns"],
                "device": execution["device"],
                "output_path": str(execution_path.relative_to(root)),
                "output_sha256": _sha256(execution_path),
            }
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
        "query_signature_summary": query_summary,
        "wall_time_ns": time.monotonic_ns() - started_ns,
    }
    summary_path = destination / "summary.json"
    _atomic_json(summary_path, summary)
    shutil.rmtree(destination / "work", ignore_errors=True)
    return {**summary, "report_path": str(summary_path.relative_to(root))}
