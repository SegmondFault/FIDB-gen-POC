#!/usr/bin/env python3
"""Trace selected FID misses across archive, one-library and composite forms.

The tool is deliberately bounded: it uses already-retained reference and
composite signatures, builds one synthetic executable for each selected owner,
and starts one Ghidra JVM for those one-library binaries.  Target binaries are
never executed and production queue state is never modified.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

from fidb_poc import ghidra_fid
from fidb_poc.fid_match_qualification import (
    _annotate_truth,
    _fidb_from_signatures,
    _linker_truth_intervals,
    _symbol_address_bias,
)
from fidb_poc.fid_matching import classify_matches
from fidb_poc.machine_validation_runner import (
    LINK_HARNESS_POLICY,
    _link_composite,
    _strip_tool,
    load_runtime,
    resolve_hash_analysis_evidence,
)
from fidb_poc.pipeline import find_ghidra, ghidra_environment


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    with path.open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def _atomic_json(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.part")
    temporary.unlink(missing_ok=True)
    try:
        temporary.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _parse_function(value: str) -> tuple[str, str]:
    owner, separator, function = value.partition(":")
    if not separator or not owner or not function:
        raise ValueError(f"invalid --function value: {value!r}")
    return owner, function


def _archive_member(archive: Path, function: str) -> str:
    result = subprocess.run(
        ["nm", "-A", "--defined-only", str(archive)],
        text=True,
        capture_output=True,
        timeout=120,
        check=True,
    )
    pattern = re.compile(
        rf"^.+:(?P<member>[^:]+):[0-9a-fA-F]+\s+\S\s+{re.escape(function)}$"
    )
    members = {
        match.group("member")
        for line in result.stdout.splitlines()
        if (match := pattern.match(line))
    }
    if len(members) != 1:
        raise ValueError(
            f"expected one archive member for {function}, found {sorted(members)}"
        )
    return members.pop()


def _extract_member(
    archiver: tuple[str, ...], archive: Path, member: str, output: Path
) -> None:
    result = subprocess.run(
        [*archiver, "p", str(archive), member],
        capture_output=True,
        timeout=120,
        check=True,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(result.stdout)


def _symbol(binary: Path, function: str) -> dict[str, object]:
    result = subprocess.run(
        ["nm", "-S", "--defined-only", str(binary)],
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
    )
    matches = [
        fields
        for line in result.stdout.splitlines()
        if len(fields := line.split()) >= 4 and fields[-1] == function
    ]
    return {
        "present": bool(matches),
        "entries": [
            {
                "address": fields[0],
                "size_bytes": int(fields[1], 16),
                "type": fields[-2],
            }
            for fields in matches
        ],
    }


def _disassembly(binary: Path, function: str) -> dict[str, object]:
    result = subprocess.run(
        ["objdump", "-d", f"--disassemble={function}", str(binary)],
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
    )
    instruction = re.compile(r"^\s*[0-9a-fA-F]+:\s+(?:[0-9a-fA-F]{2}\s+)+")
    zero_transfer = re.compile(r"\b(?:callq?|jmpq?)\s+0(?:\s|\s*<)")
    instructions = [
        line for line in result.stdout.splitlines() if instruction.match(line)
    ]
    return {
        "instruction_count": len(instructions),
        "direct_zero_transfers": sum(
            bool(zero_transfer.search(line)) for line in instructions
        ),
    }


def _stage(
    rows: list[dict[str, object]],
    function: str,
    reference_full_hashes: set[str],
    binary: Path | None = None,
) -> dict[str, object]:
    named = [row for row in rows if row.get("function_name") == function]
    full_hash = [
        row for row in rows if str(row.get("full_hash")) in reference_full_hashes
    ]
    return {
        "binary_path": str(binary) if binary else None,
        "binary_sha256": _sha256(binary) if binary else None,
        "symbol": _symbol(binary, function) if binary else None,
        "disassembly": _disassembly(binary, function) if binary else None,
        "named_functions": named,
        "reference_full_hash_matches": full_hash[:20],
        "reference_full_hash_survived": bool(full_hash),
    }


def _population_survival(
    root: Path,
    rows: list[dict[str, object]],
    truth: dict[str, object],
    link_map: Path,
    evidence: dict[str, object],
    route_id: str,
    treatment_id: str,
    query_binary: Path,
) -> dict[str, object]:
    reference_hashes: dict[str, set[str]] = {}
    reference_names: dict[str, set[str]] = {}
    for owner in evidence["cohort"]:
        path = Path(evidence["signatures"][(owner, route_id, treatment_id)]["path"])
        reference = _read_jsonl(path)
        reference_hashes[str(owner)] = {str(row["full_hash"]) for row in reference}
        reference_names[str(owner)] = {
            str(row.get("function_name", row.get("name", ""))) for row in reference
        }
    all_hashes = set().union(*reference_hashes.values())
    present = {str(owner) for owner in truth["owners"]}
    intervals = _linker_truth_intervals(root, truth, link_map)
    address_bias = _symbol_address_bias(query_binary, rows)
    labelled = correct = any_candidate = unresolved = 0
    for row in rows:
        try:
            address = int(str(row["address"]), 16) - address_bias["bytes"]
        except (KeyError, ValueError):
            unresolved += 1
            continue
        owners = {owner for start, end, owner in intervals if start <= address < end}
        if len(owners) != 1:
            name = str(row.get("function_name", ""))
            owners = {
                owner for owner in present if name and name in reference_names[owner]
            }
        if len(owners) != 1:
            unresolved += 1
            continue
        owner = next(iter(owners))
        full_hash = str(row["full_hash"])
        labelled += 1
        correct += full_hash in reference_hashes[owner]
        any_candidate += full_hash in all_hashes
    return {
        "query_functions": len(rows),
        "labelled_functions": labelled,
        "unresolved_functions": unresolved,
        "correct_owner_full_hash_candidates": correct,
        "any_owner_full_hash_candidates": any_candidate,
        "correct_owner_candidate_rate": correct / labelled if labelled else None,
        "any_owner_candidate_rate": any_candidate / labelled if labelled else None,
        "linker_intervals": len(intervals),
        "ghidra_to_linker_address_bias": address_bias,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--position", type=int, required=True)
    parser.add_argument("--fold", choices=("A", "B"), required=True)
    parser.add_argument("--function", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--rebuild-composite",
        action="store_true",
        help="also rebuild and analyse the selected fold with the current harness",
    )
    parser.add_argument(
        "--native-oracle",
        action="store_true",
        help="run native Ghidra FID over the rebuilt composite and report recall",
    )
    parser.add_argument(
        "--runtime",
        type=Path,
        default=Path("validation/machine-validation-runtime.toml"),
    )
    arguments = parser.parse_args()
    started = time.monotonic()
    root = arguments.project_root.expanduser().resolve()
    output = (root / arguments.output).resolve()
    if root not in output.parents:
        raise ValueError("diagnostic output must remain inside the project")
    output.mkdir(parents=True, exist_ok=True)

    runtime = load_runtime(root, arguments.runtime)
    evidence = resolve_hash_analysis_evidence(root, arguments.runtime)
    run_root = root / str(runtime["output_root"]) / arguments.run_id
    units = list((run_root / "units").glob(f"{arguments.position:03d}-*"))
    if len(units) != 1:
        raise ValueError("selected validation unit is missing or ambiguous")
    unit = units[0]
    result = json.loads((unit / "result.json").read_text(encoding="utf-8"))
    route_id = str(result["route_id"])
    treatment_id = str(result["treatment_id"])
    routes = {route.id: route for route in evidence["configuration"].routes}
    route = routes[route_id]
    fold_root = unit / f"fold-{arguments.fold}"
    truth = json.loads((fold_root / "truth-map.json").read_text(encoding="utf-8"))
    archive_sets = {
        str(item["owner"]): [root / str(path) for path in item["paths"]]
        for item in truth["archives"]
    }
    archives = {owner: paths[0] for owner, paths in archive_sets.items()}
    selected = [_parse_function(value) for value in arguments.function]
    if any(owner not in archives for owner, _function in selected):
        raise ValueError("selected owner is not present in the chosen fold")

    execution = runtime["execution"]
    os.environ["GHIDRA_HEADLESS"] = str(runtime["ghidra_headless"])
    os.environ["_JAVA_OPTIONS"] = (
        f'-Xms{execution["jvm_initial_heap_mib"]}m '
        f'-Xmx{execution["jvm_max_heap_mib"]}m '
        f'-XX:ActiveProcessorCount={execution["jvm_active_processors"]}'
    )
    one_library: dict[str, dict[str, object]] = {}
    new_analyses = 0
    ghidra_home: Path | None = None
    for owner in sorted({owner for owner, _function in selected}):
        safe_owner = re.sub(r"[^A-Za-z0-9_.-]+", "-", owner)
        owner_root = output / "one-library" / safe_owner
        truth_binary = owner_root / "truth.elf"
        query_binary = owner_root / "query.elf"
        signature_path = owner_root / "query-signatures.jsonl"
        if (
            truth_binary.is_file()
            and query_binary.is_file()
            and signature_path.is_file()
        ):
            summary = {
                "functions_hashed": len(_read_jsonl(signature_path)),
                "reused": True,
            }
        else:
            if ghidra_home is None:
                _headless, ghidra_home = find_ghidra()
                ghidra_fid.ensure_started(
                    ghidra_home,
                    ghidra_environment(output / "work" / "ghidra-user"),
                )
            _link_composite(
                route,
                [archives[owner]],
                truth_binary,
                owner_root / "link.map",
                harness_mode=LINK_HARNESS_POLICY,
            )
            strip = subprocess.run(
                [
                    str(_strip_tool(route)),
                    "--strip-debug",
                    str(truth_binary),
                    "-o",
                    str(query_binary),
                ],
                text=True,
                capture_output=True,
                timeout=300,
                check=False,
            )
            if strip.returncode or not query_binary.is_file():
                raise RuntimeError(
                    f"one-library strip failed for {owner}: {strip.stderr}"
                )
            project_parent = output / "work" / "projects" / safe_owner
            project_dir, program_path = ghidra_fid.analyze_target(
                query_binary,
                project_parent,
                "one-library",
                route.ghidra_language,
                route.ghidra_compiler_spec,
            )
            summary = ghidra_fid.export_program_signatures(
                project_dir, "one-library", program_path, signature_path
            )
            new_analyses += 1
        one_library[owner] = {
            "truth_binary": truth_binary,
            "query_binary": query_binary,
            "signature_path": signature_path,
            "summary": summary,
        }

    retained_composite_binary = next(
        path
        for path in (fold_root / "query.elf", fold_root / "query.dll")
        if path.is_file()
    )
    retained_composite_rows = _read_jsonl(fold_root / "query-signatures.jsonl")
    composite_binary = retained_composite_binary
    composite_rows = retained_composite_rows
    if arguments.rebuild_composite:
        composite_root = output / "five-library"
        suffix = ".dll" if route.binary_format == "PE/COFF" else ".elf"
        truth_binary = composite_root / f"truth{suffix}"
        query_binary = composite_root / f"query{suffix}"
        signature_path = composite_root / "query-signatures.jsonl"
        if not (
            truth_binary.is_file()
            and query_binary.is_file()
            and signature_path.is_file()
        ):
            _link_composite(
                route,
                [
                    archive
                    for owner in truth["owners"]
                    for archive in archive_sets[str(owner)]
                ],
                truth_binary,
                composite_root / "link.map",
                harness_mode=LINK_HARNESS_POLICY,
            )
            strip = subprocess.run(
                [
                    str(_strip_tool(route)),
                    "--strip-debug",
                    str(truth_binary),
                    "-o",
                    str(query_binary),
                ],
                text=True,
                capture_output=True,
                timeout=300,
                check=False,
            )
            if strip.returncode or not query_binary.is_file():
                raise RuntimeError(
                    f"five-library strip failed for {route.id}: {strip.stderr}"
                )
            if ghidra_home is None:
                _headless, ghidra_home = find_ghidra()
                ghidra_fid.ensure_started(
                    ghidra_home,
                    ghidra_environment(output / "work" / "ghidra-user"),
                )
            project_parent = output / "work" / "projects" / "five-library"
            project_dir, program_path = ghidra_fid.analyze_target(
                query_binary,
                project_parent,
                "five-library",
                route.ghidra_language,
                route.ghidra_compiler_spec,
            )
            ghidra_fid.export_program_signatures(
                project_dir, "five-library", program_path, signature_path
            )
            new_analyses += 1
        composite_binary = query_binary
        composite_rows = _read_jsonl(signature_path)

    native_classification = None
    if arguments.native_oracle:
        if not arguments.rebuild_composite:
            raise ValueError("--native-oracle requires --rebuild-composite")
        composite_root = output / "five-library"
        _atomic_json(composite_root / "truth-map.json", truth)
        signature_paths = {
            str(owner): Path(
                evidence["signatures"][(owner, route_id, treatment_id)]["path"]
            )
            for owner in evidence["cohort"]
        }
        fidbs = [
            _fidb_from_signatures(root, signature_paths[str(owner)])
            for owner in evidence["cohort"]
        ]
        if ghidra_home is None:
            _headless, ghidra_home = find_ghidra()
            ghidra_fid.ensure_started(
                ghidra_home,
                ghidra_environment(output / "work" / "ghidra-user"),
            )
        project_parent = output / "work" / "projects" / "native-oracle"
        project_dir, program_path = ghidra_fid.analyze_target(
            composite_binary,
            project_parent,
            "native-oracle",
            route.ghidra_language,
            route.ghidra_compiler_spec,
        )
        oracle_path = output / "native-oracle-input.json"
        oracle = ghidra_fid.export_fid_oracle_input(
            project_dir,
            "native-oracle",
            program_path,
            fidbs,
            oracle_path,
        )
        _annotate_truth(
            root,
            oracle,
            composite_root,
            signature_paths,
            composite_binary,
        )
        _atomic_json(oracle_path, oracle)
        native_classification = classify_matches(oracle, evidence["cohort"])
        _atomic_json(output / "native-classification.json", native_classification)
        new_analyses += 1
    traces = []
    for owner, function in selected:
        reference_path = Path(
            evidence["signatures"][(owner, route_id, treatment_id)]["path"]
        )
        reference_rows = [
            row
            for row in _read_jsonl(reference_path)
            if str(row.get("function_name", row.get("name", ""))) == function
        ]
        if not reference_rows:
            raise ValueError(f"reference signature is absent for {owner}:{function}")
        reference_hashes = {str(row["full_hash"]) for row in reference_rows}
        archive = archives[owner]
        member = _archive_member(archive, function)
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", f"{owner}-{function}")
        extracted = output / "archive-members" / f"{safe_name}-{member}"
        _extract_member(route.archiver, archive, member, extracted)
        one = one_library[owner]
        traces.append(
            {
                "owner": owner,
                "function": function,
                "archive": {
                    "path": str(archive.relative_to(root)),
                    "sha256": _sha256(archive),
                    "member": member,
                    "member_path": str(extracted.relative_to(root)),
                    "member_sha256": _sha256(extracted),
                    "symbol": _symbol(extracted, function),
                    "disassembly": _disassembly(extracted, function),
                    "reference_signature_path": str(reference_path.relative_to(root)),
                    "reference_signatures": reference_rows,
                },
                "one_library": _stage(
                    _read_jsonl(one["signature_path"]),
                    function,
                    reference_hashes,
                    one["query_binary"],
                ),
                "five_library_composite": _stage(
                    composite_rows,
                    function,
                    reference_hashes,
                    composite_binary,
                ),
                "retained_five_library_composite": _stage(
                    retained_composite_rows,
                    function,
                    reference_hashes,
                    retained_composite_binary,
                ),
            }
        )

    report = {
        "schema_version": "fidb-fn-trace/v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "run_id": arguments.run_id,
        "position": arguments.position,
        "fold": arguments.fold,
        "route_id": route_id,
        "treatment_id": treatment_id,
        "language_id": route.ghidra_language,
        "compiler_spec_id": route.ghidra_compiler_spec,
        "safety": {
            "target_binaries_executed": False,
            "production_queue_mutated": False,
            "new_ghidra_analyses": new_analyses,
        },
        "population_survival": {
            "retained_composite": _population_survival(
                root,
                retained_composite_rows,
                truth,
                fold_root / "link.map",
                evidence,
                route_id,
                treatment_id,
                retained_composite_binary,
            ),
            "current_harness_composite": (
                _population_survival(
                    root,
                    composite_rows,
                    truth,
                    output / "five-library" / "link.map",
                    evidence,
                    route_id,
                    treatment_id,
                    composite_binary,
                )
                if arguments.rebuild_composite
                else None
            ),
        },
        "native_fid": (
            {
                key: native_classification[key]
                for key in (
                    "decision_unit",
                    "truth",
                    "confusion_matrix",
                    "rates",
                    "categories",
                )
            }
            if native_classification is not None
            else None
        ),
        "traces": traces,
        "wall_time_seconds": time.monotonic() - started,
    }
    report_path = output / "report.json"
    _atomic_json(report_path, report)
    shutil.rmtree(output / "work" / "projects", ignore_errors=True)
    print(
        json.dumps(
            {**report, "report_path": str(report_path.relative_to(root))}, indent=2
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
