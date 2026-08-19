from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .pipeline import (
    PipelineError,
    find_ghidra,
    find_pyghidra,
    ghidra_environment,
    run_command,
    sha256,
)

SCHEMA_VERSION = "fidb-language-probe/v2"


@dataclass(frozen=True)
class ProbeCase:
    label: str
    language_id: str


def ghidra_version(ghidra_home: Path) -> tuple[str, Path]:
    properties_path = ghidra_home / "Ghidra/application.properties"
    if not properties_path.is_file():
        raise PipelineError(f"missing Ghidra application properties: {properties_path}")
    properties = {}
    for raw_line in properties_path.read_text(encoding="utf-8").splitlines():
        key, separator, value = raw_line.partition("=")
        if separator:
            properties[key.strip()] = value.strip()
    version = properties.get("application.version")
    if not version:
        raise PipelineError(f"missing application.version in {properties_path}")
    return version, properties_path


def parse_case(value: str) -> ProbeCase:
    label, separator, language_id = value.partition("=")
    if not separator or not label.strip() or not language_id.strip():
        raise argparse.ArgumentTypeError("case must be LABEL=GHIDRA_LANGUAGE_ID")
    label = label.strip()
    if re.fullmatch(r"[A-Za-z0-9_-]+", label) is None:
        raise argparse.ArgumentTypeError(
            "case label may contain only letters, numbers, underscore and hyphen"
        )
    return ProbeCase(label, language_id.strip())


def validate_cases(cases: Iterable[ProbeCase]) -> tuple[ProbeCase, ...]:
    result = tuple(cases)
    if len(result) < 2:
        raise ValueError("at least two --case values are required")
    labels = [case.label for case in result]
    if len(labels) != len(set(labels)):
        raise ValueError("case labels must be unique")
    return result


def load_rows(path: Path) -> list[dict[str, object]]:
    rows = []
    with path.open(encoding="utf-8") as stream:
        for line_number, raw_line in enumerate(stream, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise ValueError(f"invalid JSON at {path}:{line_number}") from error
    if not rows:
        raise ValueError(f"Ghidra exported no hashable functions: {path}")
    return rows


def compare_rows(
    reference_case: str,
    comparison_case: str,
    reference_rows: list[dict[str, object]],
    comparison_rows: list[dict[str, object]],
) -> dict[str, object]:
    reference = {str(row["entry_point"]): row for row in reference_rows}
    comparison = {str(row["entry_point"]): row for row in comparison_rows}
    shared = sorted(reference.keys() & comparison.keys())
    full_equal = sum(
        reference[key]["full_hash"] == comparison[key]["full_hash"] for key in shared
    )
    specific_equal = sum(
        reference[key]["specific_hash"] == comparison[key]["specific_hash"]
        for key in shared
    )
    dual_equal = sum(
        reference[key]["full_hash"] == comparison[key]["full_hash"]
        and reference[key]["specific_hash"] == comparison[key]["specific_hash"]
        for key in shared
    )

    def percentage(numerator: int, denominator: int) -> str:
        if denominator == 0:
            return "0.000000"
        return f"{100.0 * numerator / denominator:.6f}"

    return {
        "reference_case": reference_case,
        "comparison_case": comparison_case,
        "reference_hashable": len(reference),
        "comparison_hashable": len(comparison),
        "shared_entrypoints": len(shared),
        "full_hash_equal": full_equal,
        "specific_hash_equal": specific_equal,
        "dual_hash_equal": dual_equal,
        "reference_retained_pct": percentage(dual_equal, len(reference)),
        "comparison_retained_pct": percentage(dual_equal, len(comparison)),
    }


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        raise ValueError(f"refusing to write an empty CSV: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Import one fixed binary under several Ghidra LanguageIDs and compare "
            "the resulting Function ID hashes."
        )
    )
    result.add_argument("--binary", type=Path, required=True)
    result.add_argument(
        "--case",
        action="append",
        type=parse_case,
        required=True,
        help="probe case as LABEL=GHIDRA_LANGUAGE_ID; repeat at least twice",
    )
    result.add_argument(
        "--cspec",
        default="default",
        help="Ghidra compiler specification used for every case (default: default)",
    )
    result.add_argument(
        "--project-root",
        type=Path,
        default=Path.cwd(),
        help="FIDB-POC project directory (default: current directory)",
    )
    result.add_argument(
        "--output-directory",
        type=Path,
        help="output directory (default: PROJECT/output/language_probe/ID)",
    )
    result.add_argument(
        "--fresh",
        action="store_true",
        help="replace only this probe's exact work and output directories",
    )
    return result


def _is_strict_descendant(path: Path, parent: Path) -> bool:
    try:
        relative = path.relative_to(parent)
    except ValueError:
        return False
    return bool(relative.parts)


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def resolve_probe_directories(
    project_root: Path,
    output_directory: Path | None,
    probe_id: str,
) -> tuple[Path, Path]:
    """Resolve and validate the only directories a fresh probe may remove."""
    project_root = project_root.resolve()
    output_root = project_root / "output/language_probe"
    work_root = project_root / "work/language_probe"
    requested_output = (
        output_directory.absolute()
        if output_directory is not None
        else output_root / probe_id
    )
    requested_work = work_root / probe_id

    # Resolving to a different lexical path means this root or one of its
    # existing parents is a symlink.  Never accept an in-project alias as the
    # boundary for a recursive deletion.
    for label, path in (
        ("output root", output_root),
        ("work root", work_root),
        ("output directory", requested_output),
        ("work directory", requested_work),
    ):
        if path.resolve() != path:
            raise ValueError(f"probe {label} must not contain symlink aliases: {path}")

    resolved_output = requested_output.resolve()
    resolved_work = requested_work.resolve()

    for label, root in (("output", output_root), ("work", work_root)):
        if not _is_strict_descendant(root, project_root):
            raise ValueError(f"probe {label} root must stay below project root: {root}")
    if _paths_overlap(output_root, work_root):
        raise ValueError(
            f"probe output and work roots must not overlap: {output_root}; {work_root}"
        )

    for label, path, root in (
        ("output", resolved_output, output_root),
        ("work", resolved_work, work_root),
    ):
        if not _is_strict_descendant(path, root):
            raise ValueError(f"probe {label} directory must stay below {root}: {path}")
    if _paths_overlap(resolved_output, resolved_work):
        raise ValueError(
            "probe output and work directories must not overlap: "
            f"{resolved_output}; {resolved_work}"
        )
    return resolved_output, resolved_work


def execute_probe(arguments: argparse.Namespace) -> Path:
    project_root = arguments.project_root.resolve()
    binary = arguments.binary.resolve()
    cases = validate_cases(arguments.case)
    if not binary.is_file():
        raise ValueError(f"binary does not exist: {binary}")

    binary_sha256 = sha256(binary)
    probe_id = f"{binary.stem}-{binary_sha256[:12]}"
    output_directory, work_directory = resolve_probe_directories(
        project_root,
        arguments.output_directory,
        probe_id,
    )

    # Both paths are fully validated before either one can be removed.
    for path in (output_directory, work_directory):
        if path.exists():
            if not arguments.fresh:
                raise ValueError(f"probe output already exists; use --fresh: {path}")
            shutil.rmtree(path)

    output_directory.mkdir(parents=True)
    projects = work_directory / "projects"
    logs = work_directory / "logs"
    raw = work_directory / "raw"
    projects.mkdir(parents=True)
    raw.mkdir(parents=True)

    headless, ghidra_home = find_ghidra()
    version, application_properties = ghidra_version(ghidra_home)
    pyghidra = find_pyghidra(headless)
    builtin_scripts = ghidra_home / "Ghidra/Features/FunctionID/ghidra_scripts"
    local_scripts = project_root / "ghidra_scripts"
    fid_prescript = builtin_scripts / "FunctionIDHeadlessPrescript.java"
    exporter_script = local_scripts / "export_fid_hashes.py"
    script_path = f"{builtin_scripts};{local_scripts}"
    rows_by_case: dict[str, list[dict[str, object]]] = {}

    for case in cases:
        case_output = raw / f"{case.label}.jsonl"
        environment = ghidra_environment(work_directory / "user" / case.label)
        project_name = f"FID_LANGUAGE_PROBE_{case.label}"
        run_command(
            [
                str(headless),
                str(projects),
                project_name,
                "-import",
                str(binary),
                "-processor",
                case.language_id,
                "-cspec",
                arguments.cspec,
                "-overwrite",
                "-analysisTimeoutPerFile",
                "300",
                "-max-cpu",
                "2",
                "-scriptPath",
                script_path,
                "-preScript",
                "FunctionIDHeadlessPrescript.java",
            ],
            cwd=project_root,
            environment=environment,
            log_path=logs / f"{case.label}.log",
            timeout=1800,
        )
        run_command(
            [
                str(pyghidra),
                "--headless",
                str(projects),
                project_name,
                "-process",
                binary.name,
                "-noanalysis",
                "-scriptPath",
                str(local_scripts),
                "-postScript",
                "export_fid_hashes.py",
                case.label,
                case.language_id,
                binary_sha256,
                str(case_output),
                "-max-cpu",
                "1",
            ],
            cwd=project_root,
            environment=environment,
            log_path=logs / f"{case.label}-export.log",
            timeout=1800,
        )
        rows_by_case[case.label] = load_rows(case_output)

    if sha256(binary) != binary_sha256:
        raise PipelineError("input binary changed during the probe")

    function_rows = [row for case in cases for row in rows_by_case[case.label]]
    matrix_rows = [
        compare_rows(
            reference.label,
            comparison.label,
            rows_by_case[reference.label],
            rows_by_case[comparison.label],
        )
        for reference in cases
        for comparison in cases
    ]
    functions_path = output_directory / "functions.csv"
    matrix_path = output_directory / "compatibility_matrix.csv"
    write_csv(functions_path, function_rows)
    write_csv(matrix_path, matrix_rows)

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "binary": str(binary),
        "binary_sha256": binary_sha256,
        "binary_bytes": binary.stat().st_size,
        "ghidra_headless": str(headless),
        "ghidra_version": version,
        "ghidra_application_properties": {
            "path": str(application_properties),
            "sha256": sha256(application_properties),
        },
        "compiler_spec": arguments.cspec,
        "scripts": {
            "fid_prescript": {
                "path": str(fid_prescript),
                "sha256": sha256(fid_prescript),
            },
            "hash_exporter": {
                "path": str(exporter_script),
                "sha256": sha256(exporter_script),
            },
            "probe_implementation": {
                "path": str(Path(__file__).resolve()),
                "sha256": sha256(Path(__file__).resolve()),
            },
        },
        "cases": [
            {
                "label": case.label,
                "language_id": case.language_id,
                "hashable_functions": len(rows_by_case[case.label]),
            }
            for case in cases
        ],
        "outputs": {
            "functions_csv": {
                "path": functions_path.name,
                "sha256": sha256(functions_path),
            },
            "compatibility_matrix_csv": {
                "path": matrix_path.name,
                "sha256": sha256(matrix_path),
            },
        },
    }
    manifest_path = output_directory / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return output_directory


def run_probe(
    *,
    project_root: Path,
    binary: Path,
    cases: Iterable[ProbeCase],
    compiler_spec: str = "default",
    output_directory: Path | None = None,
    fresh: bool = False,
) -> Path:
    """Run the probe without requiring callers to construct CLI arguments."""
    return execute_probe(
        argparse.Namespace(
            project_root=project_root,
            binary=binary,
            case=list(cases),
            cspec=compiler_spec,
            output_directory=output_directory,
            fresh=fresh,
        )
    )


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = parser().parse_args(argv)
        output_directory = execute_probe(arguments)
        print(f"Probe complete: {output_directory}")
        print(f"Matrix: {output_directory / 'compatibility_matrix.csv'}")
        return 0
    except (OSError, ValueError, PipelineError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
