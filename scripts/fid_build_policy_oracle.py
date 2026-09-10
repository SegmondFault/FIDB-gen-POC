#!/usr/bin/env python3
"""Compare one retained object under an explicit FID-build analysis policy."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import time

from fidb_poc import ghidra_fid
from fidb_poc.pipeline import find_ghidra, ghidra_environment, ghidra_identity
from fidb_poc.validation_analysis import (
    FID_BUILD_ANALYSIS_POLICY,
    FID_BUILD_RELOCATABLE_GCC_EXCEPTION_DISABLED_POLICY,
    GHIDRA_DEFAULT_DIAGNOSTIC_POLICY,
    GHIDRA_LSDA_BURST_DIAGNOSTIC_POLICY,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _semantic_digest(path: Path) -> tuple[str, int]:
    rows = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    rows.sort(
        key=lambda row: (
            str(row.get("full_hash")),
            str(row.get("specific_hash")),
            str(row.get("name")),
            str(row.get("domain_path")),
        )
    )
    payload = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest(), len(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("object", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--analysis-policy",
        choices=(
            FID_BUILD_ANALYSIS_POLICY,
            FID_BUILD_RELOCATABLE_GCC_EXCEPTION_DISABLED_POLICY,
        ),
        required=True,
    )
    parser.add_argument("--language", default="MIPS:BE:32:default")
    parser.add_argument("--compiler-spec", default="default")
    parser.add_argument(
        "--diagnostic-policy",
        choices=(
            GHIDRA_DEFAULT_DIAGNOSTIC_POLICY,
            GHIDRA_LSDA_BURST_DIAGNOSTIC_POLICY,
        ),
        default=GHIDRA_LSDA_BURST_DIAGNOSTIC_POLICY,
    )
    arguments = parser.parse_args()

    source = arguments.object.expanduser().resolve()
    if not source.is_file() or source.is_symlink():
        raise ValueError(f"oracle object is unavailable: {source}")
    output = arguments.output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=False)
    headless, install_dir = find_ghidra()
    environment = ghidra_environment(output / "user")
    started = ghidra_fid.ensure_started(install_dir, environment)
    diagnostics = ghidra_fid.configure_ghidra_diagnostics(arguments.diagnostic_policy)
    fidb = output / "oracle.fidb"
    started_ns = time.monotonic_ns()
    counts = ghidra_fid.build_library_fidb(
        objects=[source],
        project_dir=output / "project",
        project_name="fid_build_policy_oracle",
        output=fidb,
        library="protobuf-oracle",
        version="36.1",
        variant=arguments.analysis_policy,
        language=arguments.language,
        compiler_spec=arguments.compiler_spec,
        analysis_policy=arguments.analysis_policy,
        diagnostic_policy=arguments.diagnostic_policy,
    )
    signatures = output / "signatures.jsonl"
    signature_counts = ghidra_fid.export_fid_signatures(
        fidb, signatures, arguments.language
    )
    wall_ns = time.monotonic_ns() - started_ns
    semantic_sha256, semantic_records = _semantic_digest(signatures)
    log_paths = list((output / "user").rglob("application.log*"))
    result = {
        "schema_version": "fidb-fid-build-policy-oracle/v1",
        "object": str(source),
        "object_sha256": _sha256(source),
        "object_bytes": source.stat().st_size,
        "analysis_policy": arguments.analysis_policy,
        "diagnostic_policy": diagnostics,
        "ghidra": ghidra_identity(headless, install_dir).__dict__,
        "jvm_started": started,
        "wall_time_ns": wall_ns,
        "counts": counts,
        "signature_counts": signature_counts,
        "semantic_records": semantic_records,
        "semantic_sha256": semantic_sha256,
        "fidb_sha256": _sha256(fidb),
        "signatures_sha256": _sha256(signatures),
        "application_log_files": len(log_paths),
        "application_log_bytes": sum(path.stat().st_size for path in log_paths),
    }
    (output / "result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
