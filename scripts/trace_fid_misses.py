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
from fidb_poc.machine_validation_runner import (
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--position", type=int, required=True)
    parser.add_argument("--fold", choices=("A", "B"), required=True)
    parser.add_argument("--function", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
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
    archives = {
        str(item["owner"]): root / str(item["paths"][0]) for item in truth["archives"]
    }
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
                route, [archives[owner]], truth_binary, owner_root / "link.map"
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

    composite_binary = next(
        path
        for path in (fold_root / "query.elf", fold_root / "query.dll")
        if path.is_file()
    )
    composite_rows = _read_jsonl(fold_root / "query-signatures.jsonl")
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
