"""Held-out binary imports and exact-signature ecological corpus checks.

Imported files are treated as hostile data: they are copied into a bounded,
project-local case directory, inspected as bytes, analysed by Ghidra, and
never executed.  The validator queries every library owner in the latest
compatible lane generation and publishes explicit binary/library decisions.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import struct
import subprocess
import sys
import tempfile
import tomllib
from typing import BinaryIO, Iterable, Mapping
from urllib.parse import quote
import uuid

from .elf import ElfInspectionError, inspect_elf
from .lane_database import LANE_DATABASE_APPLICATION_ID
from .lane_inventory import COMPACT_APPLICATION_ID, detect_lane_inventory
from .lane_registry import load_lane_registry

ECOLOGICAL_SCHEMA = "fidb-ecological-validation/v1"
ECOLOGICAL_STATUS_SCHEMA = "fidb-ecological-validation-status/v1"
ECOLOGICAL_CASE_SCHEMA = "fidb-ecological-validation-case/v1"
ECOLOGICAL_REPORT_SCHEMA = "fidb-ecological-validation-report/v1"
DEFAULT_AUTHORITY = Path("validation/ecological-validation.toml")
_CASE_ID = re.compile(r"^eco-[0-9a-f]{16}-[0-9a-f]{8}$")
_OWNER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+:-]*@[A-Za-z0-9][A-Za-z0-9_.+:-]*$")
_PLATFORM_HINTS = {"auto", "linux", "android", "windows", "macos", "ios"}
_TOP_LEVEL = {
    "schema_version",
    "id",
    "label",
    "state",
    "lane_registry",
    "imports",
    "corpus",
    "analysis",
    "truth",
    "report",
}
_SECTIONS = {
    "imports": {
        "case_root",
        "max_file_bytes",
        "allowed_formats",
        "never_execute",
        "preserve_original",
    },
    "corpus": {
        "database_root",
        "scope",
        "generation_policy",
        "include_states",
        "database_kinds",
        "prefer_kind",
    },
    "analysis": {
        "engine",
        "run_mode",
        "max_concurrent_runs",
        "project_root",
        "max_failure_rows",
        "execute_target_binaries",
    },
    "truth": {
        "decision_unit",
        "unlisted_library_policy",
        "allow_observational_without_truth",
    },
    "report": {"retain_all_owner_summaries", "retain_function_evidence"},
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _inside(root: Path, relative: str, label: str) -> Path:
    candidate = (root / relative).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError(f"{label} escapes project root: {relative}")
    return candidate


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_json(path: Path, document: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def load_ecological_validation(
    project_root: str | Path,
    authority: str | Path = DEFAULT_AUTHORITY,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    path = _inside(root, str(authority), "ecological-validation authority")
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if (
        set(document) != _TOP_LEVEL
        or document.get("schema_version") != ECOLOGICAL_SCHEMA
    ):
        raise ValueError(
            "ecological-validation authority has unsupported fields or schema"
        )
    for section, fields in _SECTIONS.items():
        value = document.get(section)
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError(f"ecological-validation {section} has unexpected fields")
    for field in ("id", "label", "state", "lane_registry"):
        if not isinstance(document[field], str) or not document[field]:
            raise ValueError(f"ecological-validation {field} must be non-empty")
    imports = document["imports"]
    corpus = document["corpus"]
    analysis = document["analysis"]
    truth = document["truth"]
    if (
        document["state"] != "experimental-held-out"
        or imports["never_execute"] is not True
        or imports["preserve_original"] is not True
        or analysis["execute_target_binaries"] is not False
    ):
        raise ValueError(
            "ecological-validation must preserve and never execute imports"
        )
    if (
        not isinstance(imports["max_file_bytes"], int)
        or isinstance(imports["max_file_bytes"], bool)
        or imports["max_file_bytes"] < 1
        or imports["max_file_bytes"] > 1024 * 1024 * 1024
    ):
        raise ValueError("ecological-validation max_file_bytes must be 1-1073741824")
    if imports["allowed_formats"] != ["ELF", "PE/COFF", "Mach-O"]:
        raise ValueError("ecological-validation allowed_formats are unsupported")
    if (
        corpus["scope"] != "entire-compatible-lane-corpus"
        or corpus["generation_policy"] != "latest-compatible-generation"
        or corpus["prefer_kind"] != "compact"
        or corpus["database_kinds"] != ["compact", "raw"]
    ):
        raise ValueError("ecological-validation corpus policy is unsupported")
    if not isinstance(corpus["include_states"], list) or not corpus["include_states"]:
        raise ValueError("ecological-validation include_states must be non-empty")
    if (
        analysis["engine"] != "ghidra-fid-exact-signature-v1"
        or analysis["run_mode"] != "isolated-subprocess"
        or analysis["max_concurrent_runs"] != 1
        or not isinstance(analysis["max_failure_rows"], int)
        or analysis["max_failure_rows"] < 1
    ):
        raise ValueError("ecological-validation analysis policy is unsupported")
    if (
        truth["decision_unit"] != "imported-binary-corpus-library-presence"
        or truth["unlisted_library_policy"] != "absent-only-when-truth-complete"
        or truth["allow_observational_without_truth"] is not True
    ):
        raise ValueError("ecological-validation truth policy is unsupported")
    for field in (
        imports["case_root"],
        corpus["database_root"],
        analysis["project_root"],
    ):
        if not isinstance(field, str) or not field:
            raise ValueError("ecological-validation managed paths must be non-empty")
        _inside(root, field, "ecological-validation managed path")
    lane_path = _inside(root, str(document["lane_registry"]), "lane registry")
    load_lane_registry(lane_path, root / "targets/registry.toml")
    return {
        **document,
        "authority_path": str(path.relative_to(root)),
        "authority_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "lane_registry_sha256": hashlib.sha256(lane_path.read_bytes()).hexdigest(),
    }


def _target_id(
    binary_format: str,
    machine: str,
    bits: int,
    endianness: str,
    platform_hint: str,
    sample: bytes,
) -> tuple[str | None, str, str | None]:
    if binary_format == "ELF":
        platform = platform_hint
        if platform == "auto":
            platform = (
                "android"
                if b"Android" in sample
                or b"/system/bin/linker" in sample
                or b"/apex/com.android" in sample
                else "linux"
            )
        if platform not in {"linux", "android"}:
            return (
                None,
                platform,
                "ELF imports require a Linux or Android platform hint",
            )
        if platform == "android":
            mapping = {
                ("x86", 32, "little"): "android-x86-32-elf",
                ("x86-64", 64, "little"): "android-x86-64-elf",
                ("ARM", 32, "little"): "android-armeabi-v7a-elf",
                ("AArch64", 64, "little"): "android-arm64-v8a-elf",
            }
        else:
            mapping = {
                ("x86", 32, "little"): "linux-x86-32-elf",
                ("x86-64", 64, "little"): "linux-x86-64-elf",
                ("ARM", 32, "little"): "linux-arm32-elf",
                ("AArch64", 64, "little"): "linux-aarch64-elf",
                ("MIPS", 32, "big"): "linux-mips32-be-elf",
                ("MIPS", 32, "little"): "linux-mips32-le-elf",
                ("MIPS", 64, "little"): "linux-mips64-le-elf",
                ("PowerPC", 32, "big"): "linux-powerpc32-be-elf",
                ("SH", 32, "little"): "linux-sh32-le-elf",
                ("M68K", 32, "big"): "linux-m68k-elf",
                ("RISC-V", 32, "little"): "linux-riscv32-elf",
                ("RISC-V", 64, "little"): "linux-riscv64-elf",
                ("SPARC", 32, "big"): "linux-sparc32-be-elf",
                ("LoongArch", 64, "little"): "linux-loongarch64-elf",
            }
        target = mapping.get((machine, bits, endianness))
        return (
            target,
            platform,
            None if target else "ELF target is not in the lane registry",
        )
    if binary_format == "PE/COFF":
        target = {
            ("x86", 32): "windows-x86-32-pecoff",
            ("x86-64", 64): "windows-x86-64-pecoff",
        }.get((machine, bits))
        return target, "windows", None if target else "PE/COFF target is unsupported"
    platform = "macos" if platform_hint == "auto" else platform_hint
    if platform not in {"macos", "ios"}:
        return None, platform, "Mach-O imports require a macOS or iOS platform hint"
    mapping = {
        ("macos", "x86-64", 64): "macos-x86-64-macho",
        ("macos", "AArch64", 64): "macos-arm64-macho",
        ("ios", "ARM", 32): "ios-armv7-macho",
        ("ios", "AArch64", 64): "ios-arm64-macho",
    }
    target = mapping.get((platform, machine, bits))
    return target, platform, None if target else "Mach-O target is unsupported"


def _probe_binary(path: Path, platform_hint: str) -> dict[str, object]:
    with path.open("rb") as stream:
        sample = stream.read(4 * 1024 * 1024)
    if sample.startswith(b"\x7fELF"):
        facts = inspect_elf(path)
        binary_format = "ELF"
        machine = facts.machine
        bits = facts.elf_class
        endianness = facts.endianness
    elif sample.startswith(b"MZ"):
        if len(sample) < 64:
            raise ValueError("truncated PE/COFF DOS header")
        pe_offset = int.from_bytes(sample[60:64], "little")
        with path.open("rb") as stream:
            stream.seek(pe_offset)
            header = stream.read(24)
        if len(header) < 24 or header[:4] != b"PE\0\0":
            raise ValueError("invalid PE/COFF signature")
        machine_code = int.from_bytes(header[4:6], "little")
        machine, bits = {
            0x14C: ("x86", 32),
            0x8664: ("x86-64", 64),
            0x1C4: ("ARM", 32),
            0xAA64: ("AArch64", 64),
        }.get(machine_code, (f"unknown ({machine_code})", 0))
        binary_format = "PE/COFF"
        endianness = "little"
    else:
        magics = {
            b"\xfe\xed\xfa\xce": (">", 32),
            b"\xce\xfa\xed\xfe": ("<", 32),
            b"\xfe\xed\xfa\xcf": (">", 64),
            b"\xcf\xfa\xed\xfe": ("<", 64),
        }
        if sample[:4] in {
            b"\xca\xfe\xba\xbe",
            b"\xbe\xba\xfe\xca",
            b"\xca\xfe\xba\xbf",
            b"\xbf\xba\xfe\xca",
        }:
            return {
                "state": "blocked-multi-slice",
                "binary_format": "Mach-O",
                "blocker": "universal Mach-O must be split into thin architecture slices",
                "target_id": None,
                "lane_id": None,
                "sublane_id": None,
            }
        if sample[:4] not in magics or len(sample) < 12:
            raise ValueError("file is not a supported ELF, PE/COFF, or Mach-O binary")
        prefix, bits = magics[sample[:4]]
        cpu_type = struct.unpack(f"{prefix}I", sample[4:8])[0]
        machine = {
            7: "x86",
            0x01000007: "x86-64",
            12: "ARM",
            0x0100000C: "AArch64",
        }.get(cpu_type, f"unknown ({cpu_type})")
        binary_format = "Mach-O"
        endianness = "little" if prefix == "<" else "big"
    target, platform, blocker = _target_id(
        binary_format, machine, bits, endianness, platform_hint, sample
    )
    return {
        "state": "identified" if target else "blocked-unsupported-target",
        "binary_format": binary_format,
        "platform": platform,
        "architecture": machine,
        "bits": bits,
        "endianness": endianness,
        "target_id": target,
        "lane_id": None,
        "sublane_id": None,
        "ghidra_language_id": None,
        "ghidra_compiler_spec_id": None,
        "blocker": blocker,
    }


def _resolve_lane(root: Path, probe: dict[str, object]) -> dict[str, object]:
    if probe.get("target_id") is None:
        return probe
    registry = load_lane_registry(
        root / "lanes/registry.toml", root / "targets/registry.toml"
    )
    matches = [
        (lane, sublane)
        for lane in registry["lanes"]
        for sublane in lane["sublanes"]
        if sublane["target_id"] == probe["target_id"]
    ]
    if len(matches) != 1:
        return {
            **probe,
            "state": "blocked-lane-routing",
            "blocker": "target does not resolve to exactly one sublane",
        }
    lane, sublane = matches[0]
    languages = list(sublane["ghidra_language_ids"])
    compiler_specs = list(sublane["compiler_spec_ids"])
    if (
        sublane["definition_state"] != "mapped"
        or len(languages) != 1
        or len(compiler_specs) != 1
    ):
        return {
            **probe,
            "state": "blocked-lane-routing",
            "lane_id": lane["id"],
            "sublane_id": sublane["id"],
            "blocker": "sublane lacks one reviewed Ghidra language/compiler specification",
        }
    return {
        **probe,
        "state": "routed",
        "lane_id": lane["id"],
        "sublane_id": sublane["id"],
        "policy_id": sublane["policy_id"],
        "ghidra_language_id": languages[0],
        "ghidra_compiler_spec_id": compiler_specs[0],
        "blocker": None,
    }


def _validate_metadata(metadata: Mapping[str, object]) -> dict[str, object]:
    allowed = {
        "filename",
        "label",
        "platform_hint",
        "expected_present",
        "expected_absent",
        "truth_complete",
    }
    if set(metadata) != allowed:
        raise ValueError("ecological import metadata has unsupported fields")
    filename = metadata["filename"]
    label = metadata["label"]
    platform_hint = metadata["platform_hint"]
    truth_complete = metadata["truth_complete"]
    if (
        not isinstance(filename, str)
        or not filename
        or len(filename) > 255
        or Path(filename).name != filename
        or any(ord(character) < 32 for character in filename)
    ):
        raise ValueError("filename must be a safe 1-255 character basename")
    if (
        not isinstance(label, str)
        or not label
        or label != label.strip()
        or len(label) > 128
        or any(ord(character) < 32 for character in label)
    ):
        raise ValueError("label must be 1-128 printable characters")
    if platform_hint not in _PLATFORM_HINTS:
        raise ValueError("platform_hint is unsupported")
    if not isinstance(truth_complete, bool):
        raise ValueError("truth_complete must be boolean")
    lists: dict[str, list[str]] = {}
    for field in ("expected_present", "expected_absent"):
        value = metadata[field]
        if not isinstance(value, list) or not all(
            isinstance(item, str) and _OWNER.fullmatch(item) for item in value
        ):
            raise ValueError(
                f"{field} must contain canonical family@version identifiers"
            )
        if len(value) != len(set(value)):
            raise ValueError(f"{field} contains duplicates")
        lists[field] = sorted(value)
    if set(lists["expected_present"]).intersection(lists["expected_absent"]):
        raise ValueError("one library cannot be both expected present and absent")
    return {
        "filename": filename,
        "label": label,
        "platform_hint": platform_hint,
        "expected_present": lists["expected_present"],
        "expected_absent": lists["expected_absent"],
        "truth_complete": truth_complete,
    }


def import_ecological_binary(
    project_root: str | Path,
    stream: BinaryIO,
    length: int,
    metadata: Mapping[str, object],
    authority: str | Path = DEFAULT_AUTHORITY,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    config = load_ecological_validation(root, authority)
    normalized = _validate_metadata(metadata)
    maximum = int(config["imports"]["max_file_bytes"])
    if (
        not isinstance(length, int)
        or isinstance(length, bool)
        or length < 1
        or length > maximum
    ):
        raise ValueError(f"import size must be 1-{maximum} bytes")
    case_root = _inside(root, str(config["imports"]["case_root"]), "case root")
    case_root.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".ecological-import-", dir=case_root
    )
    temporary = Path(temporary_name)
    digest = hashlib.sha256()
    received = 0
    try:
        with os.fdopen(descriptor, "wb") as output:
            while received < length:
                block = stream.read(min(1024 * 1024, length - received))
                if not block:
                    break
                received += len(block)
                digest.update(block)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
        if received != length:
            raise ValueError("import body length differs from Content-Length")
        binary_sha256 = digest.hexdigest()
        metadata_digest = hashlib.sha256(
            json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        case_id = f"eco-{binary_sha256[:16]}-{metadata_digest[:8]}"
        case_dir = case_root / case_id
        if case_dir.exists():
            manifest = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
            if manifest.get("binary", {}).get("sha256") != binary_sha256:
                raise ValueError(
                    "existing ecological case identity conflicts with import"
                )
            return _compile_case(root, config, manifest)
        case_dir.mkdir(mode=0o700)
        binary_path = case_dir / "input.bin"
        temporary.replace(binary_path)
        os.chmod(binary_path, 0o600)
        try:
            probe = _resolve_lane(
                root, _probe_binary(binary_path, str(normalized["platform_hint"]))
            )
        except (ElfInspectionError, OSError, ValueError) as error:
            probe = {
                "state": "blocked-invalid-binary",
                "binary_format": "unknown",
                "target_id": None,
                "lane_id": None,
                "sublane_id": None,
                "blocker": str(error),
            }
        manifest = {
            "schema_version": ECOLOGICAL_CASE_SCHEMA,
            "case_id": case_id,
            "label": normalized["label"],
            "state": "imported",
            "created_at": _now(),
            "updated_at": _now(),
            "authority_sha256": config["authority_sha256"],
            "binary": {
                "original_filename": normalized["filename"],
                "stored_path": str(binary_path.relative_to(root)),
                "bytes": length,
                "sha256": binary_sha256,
                "never_execute": True,
            },
            "platform_hint": normalized["platform_hint"],
            "truth": {
                "expected_present": normalized["expected_present"],
                "expected_absent": normalized["expected_absent"],
                "complete": normalized["truth_complete"],
            },
            "probe": probe,
            "run": {
                "started_at": None,
                "finished_at": None,
                "error": None,
                "pid": None,
            },
        }
        _atomic_json(case_dir / "case.json", manifest)
        return _compile_case(root, config, manifest)
    finally:
        temporary.unlink(missing_ok=True)


def _read_case(
    root: Path, config: Mapping[str, object], case_id: str
) -> dict[str, object]:
    if not _CASE_ID.fullmatch(case_id):
        raise ValueError("invalid ecological case id")
    case_root = _inside(root, str(config["imports"]["case_root"]), "case root")
    path = case_root / case_id / "case.json"
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"ecological case does not exist: {case_id}")
    document = json.loads(path.read_text(encoding="utf-8"))
    if (
        document.get("schema_version") != ECOLOGICAL_CASE_SCHEMA
        or document.get("case_id") != case_id
    ):
        raise ValueError("ecological case manifest is invalid")
    return document


def _select_corpus(
    root: Path, config: Mapping[str, object], probe: Mapping[str, object]
) -> list[dict[str, object]]:
    lane_id = probe.get("lane_id")
    sublane_id = probe.get("sublane_id")
    if not lane_id or not sublane_id:
        return []
    inventory = detect_lane_inventory(root)
    accepted_states = set(config["corpus"]["include_states"])
    candidates = [
        row
        for row in inventory["databases"]
        if row["lane_id"] == lane_id
        and sublane_id in row["sublane_ids"]
        and row["state"] in accepted_states
        and row["kind"] in config["corpus"]["database_kinds"]
    ]
    candidates.sort(
        key=lambda row: (
            str(row["created_at"]),
            row["kind"] == config["corpus"]["prefer_kind"],
        ),
        reverse=True,
    )
    return candidates[:1]


def _empty_results() -> dict[str, object]:
    return {
        "state": "not-run",
        "confusion_matrix": {
            "unit": "imported-binary-corpus-library-presence",
            "true_positives": None,
            "false_positives": None,
            "true_negatives": None,
            "false_negatives": None,
        },
        "failure_summary": {"collisions": 0, "misses": 0},
        "failures": [],
        "owner_matches": [],
        "report_path": None,
    }


def _compile_case(
    root: Path, config: Mapping[str, object], manifest: Mapping[str, object]
) -> dict[str, object]:
    case_id = str(manifest["case_id"])
    corpus = _select_corpus(root, config, manifest["probe"])
    report_path = _inside(
        root,
        f'{config["imports"]["case_root"]}/{case_id}/report.json',
        "ecological report",
    )
    results = _empty_results()
    if report_path.is_file() and not report_path.is_symlink():
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            if (
                report.get("schema_version") == ECOLOGICAL_REPORT_SCHEMA
                and report.get("case_id") == case_id
            ):
                failures = list(report["failures"])
                owners = []
                for owner in report["owner_matches"][:250]:
                    owners.append(
                        {**owner, "evidence": list(owner.get("evidence", []))[:10]}
                    )
                results = {
                    "state": report["state"],
                    "confusion_matrix": report["confusion_matrix"],
                    "failure_summary": report["failure_summary"],
                    "failures": failures[:250],
                    "failure_rows_truncated": max(0, len(failures) - 250),
                    "owner_matches": owners,
                    "owner_rows_truncated": max(0, len(report["owner_matches"]) - 250),
                    "report_path": str(report_path.relative_to(root)),
                    "metrics": report["metrics"],
                }
        except (OSError, ValueError, KeyError, TypeError):
            results = {**_empty_results(), "state": "invalid-report"}
    blockers: list[str] = []
    probe = manifest["probe"]
    if probe.get("state") != "routed":
        blockers.append(
            str(probe.get("blocker") or "binary is not routed to a query sublane")
        )
    if not corpus:
        blockers.append("no compatible materialized lane database is available")
    state = str(manifest["state"])
    ready = not blockers and state not in {"queued", "running"}
    return {
        **manifest,
        "readiness": {
            "ready_to_run": ready,
            "blockers": blockers,
            "corpus_generations": len(corpus),
        },
        "corpus": [
            {
                "path": row["path"],
                "generation_id": row["generation_id"],
                "lane_id": row["lane_id"],
                "kind": row["kind"],
                "state": row["state"],
                "bytes": row["bytes"],
                "raw_observations": row["raw_observations"],
                "unique_signatures": row["unique_signatures"],
            }
            for row in corpus
        ],
        "results": results,
    }


def compile_ecological_validation(
    project_root: str | Path,
    authority: str | Path = DEFAULT_AUTHORITY,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    config = load_ecological_validation(root, authority)
    case_root = _inside(root, str(config["imports"]["case_root"]), "case root")
    cases: list[dict[str, object]] = []
    if case_root.is_dir() and not case_root.is_symlink():
        for path in sorted(case_root.glob("eco-*/case.json")):
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
                cases.append(_compile_case(root, config, document))
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                continue
    cases.sort(key=lambda row: str(row["created_at"]), reverse=True)
    inventory = detect_lane_inventory(root)
    matrix = {
        "true_positives": 0,
        "false_positives": 0,
        "true_negatives": 0,
        "false_negatives": 0,
    }
    measured = 0
    failures: list[dict[str, object]] = []
    for case in cases:
        confusion = case["results"]["confusion_matrix"]
        if confusion["true_positives"] is None:
            continue
        measured += 1
        for key in matrix:
            matrix[key] += int(confusion[key])
        failures.extend(case["results"]["failures"])
    aggregate = (
        {"unit": "imported-binary-corpus-library-presence", **matrix}
        if measured
        else {
            "unit": "imported-binary-corpus-library-presence",
            **{key: None for key in matrix},
        }
    )
    body = {
        "schema_version": ECOLOGICAL_STATUS_SCHEMA,
        "id": config["id"],
        "label": config["label"],
        "state": config["state"],
        "authority_path": config["authority_path"],
        "authority_sha256": config["authority_sha256"],
        "policy": {
            "corpus_scope": config["corpus"]["scope"],
            "generation_policy": config["corpus"]["generation_policy"],
            "analysis_engine": config["analysis"]["engine"],
            "decision_unit": config["truth"]["decision_unit"],
            "never_execute": True,
            "max_file_bytes": config["imports"]["max_file_bytes"],
        },
        "corpus": {
            "materialized_generations": inventory["summary"][
                "materialized_generations"
            ],
            "active_packs": inventory["summary"]["active_packs"],
            "bytes": inventory["summary"]["lane_database_bytes"],
            "raw_observations": inventory["summary"]["raw_observations"],
            "compact_unique_signatures": inventory["summary"][
                "compact_unique_signatures"
            ],
            "issues": inventory["summary"]["issues"],
        },
        "summary": {
            "imported_cases": len(cases),
            "ready_cases": sum(
                bool(case["readiness"]["ready_to_run"]) for case in cases
            ),
            "running_cases": sum(
                case["state"] in {"queued", "running"} for case in cases
            ),
            "completed_cases": sum(
                case["results"]["state"] == "measured-complete" for case in cases
            ),
            "labelled_cases": sum(
                bool(
                    case["truth"]["complete"]
                    or case["truth"]["expected_present"]
                    or case["truth"]["expected_absent"]
                )
                for case in cases
            ),
        },
        "aggregate": {
            "measured_cases": measured,
            "confusion_matrix": aggregate,
            "failure_summary": {
                "collisions": sum(
                    row.get("failure_type") == "collision" for row in failures
                ),
                "misses": sum(row.get("failure_type") == "miss" for row in failures),
            },
            "failures": failures[: int(config["analysis"]["max_failure_rows"])],
        },
        "cases": cases,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return {**body, "status_digest": hashlib.sha256(canonical).hexdigest()}


def _open_database(path: Path) -> sqlite3.Connection:
    uri = f"file:{quote(str(path.resolve()), safe='/')}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    connection.execute("PRAGMA busy_timeout = 0")
    return connection


def _owner_rows(connection: sqlite3.Connection) -> set[str]:
    return {
        f"{row[0]}@{row[1]}"
        for row in connection.execute(
            "SELECT family.name, release.version FROM library_release AS release JOIN library_family AS family ON family.id = release.family_id"
        )
    }


def _corpus_matches(
    root: Path,
    corpus: Iterable[Mapping[str, object]],
    probe: Mapping[str, object],
    signatures: list[dict[str, object]],
) -> tuple[set[str], list[dict[str, object]], set[str]]:
    by_full_hash: dict[str, list[dict[str, object]]] = {}
    for row in signatures:
        by_full_hash.setdefault(str(row["full_hash"]), []).append(row)
    positive_owners: set[str] = set()
    all_owners: set[str] = set()
    matches: list[dict[str, object]] = []
    full_hashes = sorted(by_full_hash)
    for database in corpus:
        path = _inside(root, str(database["path"]), "lane database")
        with _open_database(path) as connection:
            application_id = int(
                connection.execute("PRAGMA application_id").fetchone()[0]
            )
            all_owners.update(_owner_rows(connection))
            if application_id == LANE_DATABASE_APPLICATION_ID:
                query = """
                    SELECT observation.full_hash, observation.specific_hash,
                           observation.specific_hash_additional_size, observation.code_unit_size,
                           observation.function_name AS corpus_function,
                           observation.domain_path, family.name AS family, release.version,
                           variant.route_id, variant.compiler_family, variant.compiler_version,
                           variant.treatment_id
                    FROM raw_signature_observation AS observation
                    JOIN build_variant AS variant ON variant.id = observation.build_variant_id
                    JOIN library_release AS release ON release.id = variant.release_id
                    JOIN library_family AS family ON family.id = release.family_id
                    WHERE observation.sublane_id = ? AND observation.policy_id = ?
                      AND observation.ghidra_language_id = ?
                      AND observation.ghidra_compiler_spec_id = ?
                      AND observation.full_hash IN ({placeholders})
                """
            elif application_id == COMPACT_APPLICATION_ID:
                query = """
                    SELECT signature.full_hash, signature.specific_hash,
                           signature.specific_hash_additional_size, signature.code_unit_size,
                           occurrence.function_name AS corpus_function,
                           occurrence.domain_path, family.name AS family, release.version,
                           variant.route_id, variant.compiler_family, variant.compiler_version,
                           variant.treatment_id
                    FROM compact_signature AS signature
                    JOIN signature_occurrence AS occurrence ON occurrence.signature_id = signature.id
                    JOIN build_variant AS variant ON variant.id = occurrence.build_variant_id
                    JOIN library_release AS release ON release.id = variant.release_id
                    JOIN library_family AS family ON family.id = release.family_id
                    WHERE signature.sublane_id = ? AND signature.policy_id = ?
                      AND signature.ghidra_language_id = ?
                      AND signature.ghidra_compiler_spec_id = ?
                      AND signature.full_hash IN ({placeholders})
                """
            else:
                raise ValueError(
                    f"unsupported lane database application id: {application_id}"
                )
            for offset in range(0, len(full_hashes), 400):
                chunk = full_hashes[offset : offset + 400]
                if not chunk:
                    continue
                rendered = query.format(placeholders=",".join("?" for _ in chunk))
                parameters = [
                    probe["sublane_id"],
                    probe["policy_id"],
                    probe["ghidra_language_id"],
                    probe["ghidra_compiler_spec_id"],
                    *chunk,
                ]
                for corpus_row in connection.execute(rendered, parameters):
                    key = (
                        str(corpus_row["full_hash"]),
                        str(corpus_row["specific_hash"]),
                        int(corpus_row["specific_hash_additional_size"]),
                        int(corpus_row["code_unit_size"]),
                    )
                    owner = f'{corpus_row["family"]}@{corpus_row["version"]}'
                    for target_row in by_full_hash.get(key[0], []):
                        target_key = (
                            str(target_row["full_hash"]),
                            str(target_row["specific_hash"]),
                            int(target_row["specific_hash_additional_size"]),
                            int(target_row["code_unit_size"]),
                        )
                        if target_key != key:
                            continue
                        positive_owners.add(owner)
                        matches.append(
                            {
                                "owner": owner,
                                "address": target_row["address"],
                                "target_function": target_row["function_name"],
                                "corpus_function": corpus_row["corpus_function"],
                                "signature": ":".join(
                                    (key[0], key[1], str(key[2]), str(key[3]))
                                ),
                                "route_id": corpus_row["route_id"],
                                "compiler_id": f'{corpus_row["compiler_family"]}-{corpus_row["compiler_version"]}',
                                "treatment_id": corpus_row["treatment_id"],
                                "evidence_path": f'{database["path"]}:{corpus_row["domain_path"]}',
                            }
                        )
    unique = {
        (
            row["owner"],
            row["address"],
            row["signature"],
            row["route_id"],
            row["treatment_id"],
            row["evidence_path"],
        ): row
        for row in matches
    }
    return positive_owners, list(unique.values()), all_owners


def _read_signatures(path: Path) -> list[dict[str, object]]:
    rows = []
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError("target signature row is not an object")
            rows.append(row)
    return rows


def run_ecological_case(
    project_root: str | Path,
    case_id: str,
    authority: str | Path = DEFAULT_AUTHORITY,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    config = load_ecological_validation(root, authority)
    manifest = _read_case(root, config, case_id)
    compiled = _compile_case(root, config, manifest)
    if compiled["readiness"]["blockers"]:
        raise ValueError("; ".join(compiled["readiness"]["blockers"]))
    case_root = _inside(root, f'{config["imports"]["case_root"]}/{case_id}', "case")
    global_lock = _inside(
        root, f'{config["imports"]["case_root"]}/.runner.lock', "ecological lock"
    )
    descriptor = None
    try:
        descriptor = os.open(global_lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.write(descriptor, f"{os.getpid()}\n".encode())
    except FileExistsError as error:
        raise ValueError("another ecological validation is already running") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    started = _now()
    manifest = {
        **manifest,
        "state": "running",
        "updated_at": started,
        "run": {
            "started_at": started,
            "finished_at": None,
            "error": None,
            "pid": os.getpid(),
        },
    }
    _atomic_json(case_root / "case.json", manifest)
    try:
        from . import ghidra_fid
        from .pipeline import find_ghidra, ghidra_environment

        probe = manifest["probe"]
        binary = _inside(
            root, str(manifest["binary"]["stored_path"]), "imported binary"
        )
        if _sha256(binary) != manifest["binary"]["sha256"]:
            raise ValueError("imported binary digest changed")
        _headless, ghidra_home = find_ghidra()
        environment = ghidra_environment(case_root / "ghidra-user")
        ghidra_fid.ensure_started(ghidra_home, environment)
        project_parent = (
            _inside(
                root, str(config["analysis"]["project_root"]), "Ghidra project root"
            )
            / case_id
        )
        signatures_path = case_root / "target-signatures.jsonl"
        _project_dir, _program_path, signature_summary, _journal_retries = (
            ghidra_fid.analyze_and_export_program_signatures(
                binary,
                project_parent,
                "target",
                str(probe["ghidra_language_id"]),
                signatures_path,
                str(probe["ghidra_compiler_spec_id"]),
            )
        )
        signatures = _read_signatures(signatures_path)
        positive, matches, corpus_owners = _corpus_matches(
            root, compiled["corpus"], probe, signatures
        )
        truth = manifest["truth"]
        present = set(truth["expected_present"])
        absent = (
            (corpus_owners | set(truth["expected_absent"])) - present
            if truth["complete"]
            else set(truth["expected_absent"])
        )
        labelled = bool(present or absent or truth["complete"])
        confusion = {
            "unit": "imported-binary-corpus-library-presence",
            "true_positives": len(present & positive) if labelled else None,
            "false_positives": len(absent & positive) if labelled else None,
            "true_negatives": len(absent - positive) if labelled else None,
            "false_negatives": len(present - positive) if labelled else None,
        }
        max_failures = int(config["analysis"]["max_failure_rows"])
        failures = [
            {"failure_type": "collision", **row}
            for row in matches
            if row["owner"] in absent
        ]
        failures.extend(
            {
                "failure_type": "miss",
                "owner": owner,
                "address": "",
                "target_function": "",
                "corpus_function": "",
                "signature": "",
                "route_id": str(probe["target_id"]),
                "compiler_id": str(probe["ghidra_compiler_spec_id"]),
                "treatment_id": "ecological-import",
                "evidence_path": str(manifest["binary"]["stored_path"]),
            }
            for owner in sorted(present - positive)
        )
        owner_matches = []
        for owner in sorted(positive):
            owner_rows = [row for row in matches if row["owner"] == owner]
            owner_matches.append(
                {
                    "owner": owner,
                    "matched_functions": len(
                        {str(row["address"]) for row in owner_rows}
                    ),
                    "matched_occurrences": len(owner_rows),
                    "truth": (
                        "present"
                        if owner in present
                        else "absent" if owner in absent else "unlabelled"
                    ),
                    "evidence": owner_rows[:25],
                }
            )
        finished = _now()
        report = {
            "schema_version": ECOLOGICAL_REPORT_SCHEMA,
            "case_id": case_id,
            "state": "measured-complete",
            "started_at": started,
            "finished_at": finished,
            "authority_sha256": config["authority_sha256"],
            "binary_sha256": manifest["binary"]["sha256"],
            "probe": probe,
            "truth": truth,
            "corpus": [
                {
                    **row,
                    "sha256": _sha256(_inside(root, str(row["path"]), "lane database")),
                }
                for row in compiled["corpus"]
            ],
            "confusion_matrix": confusion,
            "failure_summary": {
                "collisions": sum(
                    row["failure_type"] == "collision" for row in failures
                ),
                "misses": sum(row["failure_type"] == "miss" for row in failures),
            },
            "failures": failures[:max_failures],
            "owner_matches": owner_matches,
            "metrics": {
                **signature_summary,
                "corpus_libraries": len(corpus_owners),
                "matched_libraries": len(positive),
                "exact_occurrence_matches": len(matches),
                "failure_rows_truncated": max(0, len(failures) - max_failures),
            },
        }
        _atomic_json(case_root / "report.json", report)
        _atomic_json(
            case_root / "case.json",
            {
                **manifest,
                "state": "complete",
                "updated_at": finished,
                "run": {
                    "started_at": started,
                    "finished_at": finished,
                    "error": None,
                    "pid": os.getpid(),
                },
            },
        )
        return report
    except Exception as error:
        finished = _now()
        _atomic_json(
            case_root / "case.json",
            {
                **manifest,
                "state": "failed",
                "updated_at": finished,
                "run": {
                    "started_at": started,
                    "finished_at": finished,
                    "error": f"{type(error).__name__}: {error}",
                    "pid": os.getpid(),
                },
            },
        )
        raise
    finally:
        global_lock.unlink(missing_ok=True)


def start_ecological_case(
    project_root: str | Path,
    case_id: str,
    authority: str | Path = DEFAULT_AUTHORITY,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    config = load_ecological_validation(root, authority)
    manifest = _read_case(root, config, case_id)
    compiled = _compile_case(root, config, manifest)
    if compiled["readiness"]["blockers"]:
        raise ValueError("; ".join(compiled["readiness"]["blockers"]))
    if manifest["state"] in {"queued", "running"}:
        raise ValueError("ecological validation case is already queued or running")
    case_root = _inside(root, f'{config["imports"]["case_root"]}/{case_id}', "case")
    log_path = case_root / "run.log"
    queued = {
        **manifest,
        "state": "queued",
        "updated_at": _now(),
        "run": {"started_at": None, "finished_at": None, "error": None, "pid": None},
    }
    _atomic_json(case_root / "case.json", queued)
    try:
        with log_path.open("ab", buffering=0) as log:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "fidb_poc.cli",
                    "ecological-validation",
                    "run",
                    "--project-root",
                    str(root),
                    "--authority",
                    str(authority),
                    "--case",
                    case_id,
                ],
                cwd=root,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                close_fds=True,
            )
        _atomic_json(
            case_root / "case.json",
            {**queued, "run": {**queued["run"], "pid": process.pid}},
        )
    except Exception as error:
        _atomic_json(
            case_root / "case.json",
            {
                **queued,
                "state": "failed",
                "run": {**queued["run"], "error": str(error)},
            },
        )
        raise
    return _compile_case(root, config, _read_case(root, config, case_id))
