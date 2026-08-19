# Export Function ID hashes from the current Ghidra program.
# @category FunctionID
# @runtime PyGhidra

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from ghidra.feature.fid.service import FidService

if TYPE_CHECKING:
    from ghidra.ghidra_builtins import *


def unsigned_hex(value: int) -> str:
    return f"{int(value) & 0xFFFFFFFFFFFFFFFF:016x}"


def main() -> None:
    args = list(getScriptArgs())
    if len(args) != 4:
        raise ValueError(
            "usage: export_fid_hashes "
            "<case-label> <expected-language-id> <source-sha256> <output.jsonl>"
        )

    case_label, expected_language, source_sha256, output_path_text = args
    actual_language = str(currentProgram.getLanguageID())
    if actual_language != expected_language:
        raise ValueError(
            f"Ghidra language mismatch: expected {expected_language}, "
            f"got {actual_language}"
        )

    compiler_spec = str(currentProgram.getCompilerSpec().getCompilerSpecID())
    functions = currentProgram.getFunctionManager().getFunctionsNoStubs(True)
    service = FidService()
    output_path = Path(output_path_text)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as output:
        for function in functions:
            monitor.checkCancelled()
            hashes = service.hashFunction(function)
            if hashes is None:
                continue
            row = {
                "case": case_label,
                "source_sha256": source_sha256,
                "program": currentProgram.getName(),
                "language_id": actual_language,
                "compiler_spec": compiler_spec,
                "entry_point": str(function.getEntryPoint()),
                "function_name": function.getName(),
                "code_unit_size": hashes.getCodeUnitSize(),
                "specific_hash_additional_size": (
                    hashes.getSpecificHashAdditionalSize()
                ),
                "full_hash": unsigned_hex(hashes.getFullHash()),
                "specific_hash": unsigned_hex(hashes.getSpecificHash()),
            }
            output.write(json.dumps(row, sort_keys=True) + "\n")


main()
