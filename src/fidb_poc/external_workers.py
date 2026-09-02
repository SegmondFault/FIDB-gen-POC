"""Reviewed, command-free definitions and preflight for external workers."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import tomllib
from typing import Mapping, Sequence

from .config import load_configuration
from .operations_policy import ResourcePolicy, evaluate_resources
from .pipeline import PipelineError, find_ghidra, ghidra_identity, java_identity, sha256
from .toolchain_packs import load_toolchain_pack_catalog

EXTERNAL_TOOLCHAIN_SCHEMA = "fidb-external-toolchain/v1"
EXTERNAL_PREFLIGHT_SCHEMA = "fidb-external-worker-preflight/v1"
_ID = re.compile(r"[a-z0-9][a-z0-9._-]*\Z")
_FIELDS = {
    "schema_version",
    "id",
    "label",
    "route_id",
    "worker_pool",
    "worker_class",
    "host_system",
    "host_architecture",
    "target_id",
    "compiler_family",
    "probe_kind",
    "languages",
    "deployment_target",
    "worker_configuration",
    "license_authority",
    "source_policy",
    "required_tools",
    "required_metadata",
    "resources",
}
_RESOURCE_FIELDS = {
    "min_available_memory_gib",
    "min_free_disk_gib",
    "max_load_per_cpu",
    "max_temperature_c",
}


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{context} must be a non-empty string")
    return value


def _identifier(value: object, context: str) -> str:
    result = _text(value, context)
    if _ID.fullmatch(result) is None:
        raise ValueError(f"{context} must be a stable lowercase identifier")
    return result


def _strings(value: object, context: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
        or len(set(value)) != len(value)
    ):
        raise ValueError(f"{context} must be a non-empty unique string list")
    return tuple(value)


@dataclass(frozen=True)
class ExternalToolchainDefinition:
    id: str
    label: str
    route_id: str
    worker_pool: str
    worker_class: str
    host_system: str
    host_architecture: str
    target_id: str
    compiler_family: str
    probe_kind: str
    languages: tuple[str, ...]
    deployment_target: str
    worker_configuration: str
    license_authority: str
    source_policy: str
    required_tools: tuple[str, ...]
    required_metadata: tuple[str, ...]
    resources: ResourcePolicy
    source_path: Path
    sha256: str

    def registration_identity(self) -> dict[str, object]:
        return {
            "id": self.id,
            "sha256": self.sha256,
            "route_id": self.route_id,
            "worker_pool": self.worker_pool,
            "worker_class": self.worker_class,
            "probe_kind": self.probe_kind,
            "languages": list(self.languages),
        }


def _definition_path(reference: str | Path, project_root: Path) -> Path:
    external_root = (project_root / "toolchains/external").resolve()
    value = Path(reference)
    candidate = value if value.suffix == ".toml" else Path(f"{value}.toml")
    if not candidate.is_absolute():
        candidate = external_root / candidate.name
    resolved = candidate.resolve()
    try:
        resolved.relative_to(external_root)
    except ValueError as error:
        raise ValueError(
            "external toolchain definition escaped toolchains/external"
        ) from error
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError(
            f"external toolchain definition is not a regular file: {resolved}"
        )
    return resolved


def load_external_toolchain(
    reference: str | Path, project_root: str | Path
) -> ExternalToolchainDefinition:
    root = Path(project_root).expanduser().resolve()
    source = _definition_path(reference, root)
    document = tomllib.loads(source.read_text(encoding="utf-8"))
    if (
        set(document) != _FIELDS
        or document.get("schema_version") != EXTERNAL_TOOLCHAIN_SCHEMA
    ):
        raise ValueError(
            "external toolchain definition has unsupported fields or schema"
        )
    resources = document["resources"]
    if not isinstance(resources, dict) or set(resources) != _RESOURCE_FIELDS:
        raise ValueError("external toolchain resources have unsupported fields")
    numeric: dict[str, float] = {}
    for field in _RESOURCE_FIELDS:
        value = resources[field]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            raise ValueError(
                f"external toolchain resources {field} must be non-negative"
            )
        numeric[field] = float(value)
    definition = ExternalToolchainDefinition(
        id=_identifier(document["id"], "external toolchain id"),
        label=_text(document["label"], "external toolchain label"),
        route_id=_identifier(document["route_id"], "external route id"),
        worker_pool=_identifier(document["worker_pool"], "external worker pool"),
        worker_class=_identifier(document["worker_class"], "external worker class"),
        host_system=_identifier(document["host_system"], "external host system"),
        host_architecture=_identifier(
            document["host_architecture"], "external host architecture"
        ),
        target_id=_identifier(document["target_id"], "external target id"),
        compiler_family=_identifier(
            document["compiler_family"], "external compiler family"
        ),
        probe_kind=_identifier(document["probe_kind"], "external probe kind"),
        languages=tuple(
            _identifier(item, "external language")
            for item in _strings(document["languages"], "external languages")
        ),
        deployment_target=_text(
            document["deployment_target"], "external deployment target"
        ),
        worker_configuration=_text(
            document["worker_configuration"], "external worker configuration"
        ),
        license_authority=_text(
            document["license_authority"], "external license authority"
        ),
        source_policy=_text(document["source_policy"], "external source policy"),
        required_tools=_strings(document["required_tools"], "external required tools"),
        required_metadata=_strings(
            document["required_metadata"], "external required metadata"
        ),
        resources=ResourcePolicy(**numeric),
        source_path=source,
        sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
    )
    if definition.id != source.stem or definition.id != definition.route_id:
        raise ValueError("external definition id, filename and route_id must match")
    if definition.probe_kind not in {"apple-xcode"}:
        raise ValueError(f"unsupported external probe kind: {definition.probe_kind}")

    catalog = load_toolchain_pack_catalog(root)
    route = next(
        (row for row in catalog["routes"] if row["id"] == definition.route_id), None
    )
    if route is None or route["provisioning"] != "external-worker":
        raise ValueError("external definition does not name an external-worker route")
    expected = {
        "target_id": definition.target_id,
        "compiler_family": definition.compiler_family,
        "worker_class": definition.worker_class,
    }
    for field, value in expected.items():
        if route[field] != value:
            raise ValueError(f"external definition disagrees with route {field}")

    configuration_path = (root / definition.worker_configuration).resolve()
    try:
        configuration_path.relative_to(root)
    except ValueError as error:
        raise ValueError(
            "external worker configuration escaped project root"
        ) from error
    configuration = load_configuration(configuration_path)
    configured = next(
        (item for item in configuration.routes if item.id == definition.route_id), None
    )
    if configured is None:
        raise ValueError("external route is absent from worker configuration")
    if (
        configured.target_os != "macos"
        or configured.architecture != definition.host_architecture
        or configured.binary_format != "Mach-O"
    ):
        raise ValueError("external definition disagrees with worker route target")
    return definition


def _run(
    command: Sequence[str], *, timeout: int = 30
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        env=dict(os.environ),
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _checked(command: Sequence[str], context: str) -> str:
    result = _run(command)
    output = "\n".join(
        part.strip() for part in (result.stdout, result.stderr) if part.strip()
    )
    if result.returncode != 0 or not output:
        raise RuntimeError(f"{context} failed: {output or 'no output'}")
    return output


def _sysctl(name: str) -> str:
    return _checked(("/usr/sbin/sysctl", "-n", name), f"sysctl {name}").strip()


def _apple_preflight(
    definition: ExternalToolchainDefinition, project_root: Path
) -> dict[str, object]:
    blockers: list[str] = []
    system = platform.system().lower()
    architecture = platform.machine().lower()
    host: dict[str, object] = {
        "system": system,
        "architecture": architecture,
        "macos_version": platform.mac_ver()[0] or None,
        "hardware": None,
    }
    toolchain: dict[str, object] = {"deployment_target": definition.deployment_target}
    analysis: dict[str, object] = {}
    smoke: dict[str, object] = {"languages": {}, "archive": None}
    if system != definition.host_system:
        blockers.append(f"host-system-mismatch:{system or 'unknown'}")
    if architecture not in {definition.host_architecture, "aarch64"}:
        blockers.append(f"host-architecture-mismatch:{architecture or 'unknown'}")
    if blockers:
        return {
            "blockers": blockers,
            "host": host,
            "toolchain": toolchain,
            "analysis": analysis,
            "smoke": smoke,
        }

    try:
        host["hardware"] = _sysctl("hw.model")
        if not str(host["hardware"]).startswith("Mac"):
            blockers.append("apple-branded-hardware-not-confirmed")
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        blockers.append(f"hardware-probe-failed:{error}")

    paths = {name: shutil.which(name) for name in definition.required_tools}
    missing = sorted(name for name, path in paths.items() if path is None)
    blockers.extend(f"required-tool-missing:{name}" for name in missing)
    toolchain["required_tools"] = paths
    if missing:
        return {
            "blockers": blockers,
            "host": host,
            "toolchain": toolchain,
            "analysis": analysis,
            "smoke": smoke,
        }

    try:
        xcode = _checked(("xcodebuild", "-version"), "Xcode version")
        lines = xcode.splitlines()
        toolchain["xcode_version"] = lines[0] if lines else None
        toolchain["xcode_build"] = lines[1] if len(lines) > 1 else None
        toolchain["sdk_path"] = _checked(
            ("xcrun", "--sdk", "macosx", "--show-sdk-path"), "macOS SDK path"
        ).strip()
        toolchain["sdk_version"] = _checked(
            ("xcrun", "--sdk", "macosx", "--show-sdk-version"),
            "macOS SDK version",
        ).strip()
        clang_path = Path(
            _checked(
                ("xcrun", "--sdk", "macosx", "--find", "clang"), "Apple Clang path"
            ).strip()
        )
        toolchain["apple_clang_path"] = str(clang_path.resolve())
        toolchain["apple_clang_sha256"] = sha256(clang_path)
        toolchain["apple_clang_version"] = _checked(
            ("xcrun", "--sdk", "macosx", "clang", "--version"),
            "Apple Clang version",
        ).splitlines()[0]
        if "Apple clang version" not in str(toolchain["apple_clang_version"]):
            blockers.append("compiler-is-not-apple-clang")
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        blockers.append(f"apple-toolchain-probe-failed:{error}")

    try:
        headless, ghidra_home = find_ghidra()
        identity = ghidra_identity(headless, ghidra_home)
        java_path, java_version, java_major = java_identity(dict(os.environ))
        pyghidra_version = importlib.metadata.version("pyghidra")
        analysis.update(
            {
                "ghidra_version": identity.version,
                "ghidra_release": identity.release,
                "ghidra_build": identity.build,
                "ghidra_properties_sha256": identity.properties_sha256,
                "ghidra_headless_path": identity.headless_path,
                "java_path": str(java_path),
                "java_version": java_version,
                "java_major": java_major,
                "pyghidra_version": pyghidra_version,
            }
        )
    except (OSError, PipelineError, importlib.metadata.PackageNotFoundError) as error:
        blockers.append(f"analysis-toolchain-probe-failed:{error}")

    if not any(item.startswith("apple-toolchain-probe-failed:") for item in blockers):
        unsupported = sorted(set(definition.languages) - {"c", "cpp"})
        blockers.extend(f"smoke-language-unsupported:{item}" for item in unsupported)
        try:
            with tempfile.TemporaryDirectory(
                prefix="fidb-apple-preflight-"
            ) as temporary:
                root = Path(temporary)
                objects: list[Path] = []
                sources = {
                    "c": ("clang", "smoke.c", "int fidb_smoke(void) { return 0; }\n"),
                    "cpp": (
                        "clang++",
                        "smoke.cpp",
                        'extern "C" int fidb_cpp_smoke() { return 0; }\n',
                    ),
                }
                for language in definition.languages:
                    if language not in sources:
                        continue
                    driver, filename, content = sources[language]
                    source = root / filename
                    output = root / f"{language}.o"
                    source.write_text(content, encoding="utf-8")
                    command = (
                        "xcrun",
                        "--sdk",
                        "macosx",
                        driver,
                        "-arch",
                        "arm64",
                        f"-mmacosx-version-min={definition.deployment_target}",
                        "-c",
                        str(source),
                        "-o",
                        str(output),
                    )
                    completed = _run(command)
                    description = (
                        _checked(("file", "-b", str(output)), f"{language} object")
                        if completed.returncode == 0
                        else ""
                    )
                    passed = completed.returncode == 0 and all(
                        marker in description
                        for marker in ("Mach-O", "arm64", "object")
                    )
                    smoke["languages"][language] = {
                        "passed": passed,
                        "file": description,
                    }
                    if not passed:
                        blockers.append(f"smoke-compile-failed:{language}")
                    else:
                        objects.append(output)
                if objects:
                    archive = root / "libfidb-smoke.a"
                    archived = _run(
                        (
                            "xcrun",
                            "--sdk",
                            "macosx",
                            "ar",
                            "rcs",
                            str(archive),
                            *map(str, objects),
                        )
                    )
                    smoke["archive"] = {
                        "passed": archived.returncode == 0 and archive.is_file(),
                        "sha256": sha256(archive) if archive.is_file() else None,
                    }
                    if not smoke["archive"]["passed"]:
                        blockers.append("smoke-archive-failed")
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            blockers.append(f"smoke-probe-failed:{error}")

    return {
        "blockers": blockers,
        "host": host,
        "toolchain": toolchain,
        "analysis": analysis,
        "smoke": smoke,
    }


def preflight_external_toolchain(
    definition: ExternalToolchainDefinition, project_root: str | Path
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    if definition.probe_kind != "apple-xcode":  # load validation also fences this
        raise ValueError(f"unsupported external probe kind: {definition.probe_kind}")
    probe = _apple_preflight(definition, root)
    resources = evaluate_resources(definition.resources, root).document()
    blockers = list(probe.pop("blockers"))
    blockers.extend(f"resource:{reason}" for reason in resources["reasons"])
    metadata = {
        "hardware": probe["host"].get("hardware"),
        "macos_version": probe["host"].get("macos_version"),
        "xcode_version": probe["toolchain"].get("xcode_version"),
        "xcode_build": probe["toolchain"].get("xcode_build"),
        "sdk_version": probe["toolchain"].get("sdk_version"),
        "sdk_path": probe["toolchain"].get("sdk_path"),
        "deployment_target": probe["toolchain"].get("deployment_target"),
        "apple_clang_version": probe["toolchain"].get("apple_clang_version"),
        "apple_clang_path": probe["toolchain"].get("apple_clang_path"),
        "apple_clang_sha256": probe["toolchain"].get("apple_clang_sha256"),
        "ghidra_version": probe["analysis"].get("ghidra_version"),
        "java_version": probe["analysis"].get("java_version"),
    }
    blockers.extend(
        f"required-metadata-missing:{name}"
        for name in definition.required_metadata
        if not metadata.get(name)
    )
    unique_blockers = list(dict.fromkeys(blockers))
    return {
        "schema_version": EXTERNAL_PREFLIGHT_SCHEMA,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "ready": not unique_blockers,
        "definition": definition.registration_identity(),
        "host": probe["host"],
        "toolchain": probe["toolchain"],
        "analysis": probe["analysis"],
        "smoke": probe["smoke"],
        "resources": resources,
        "metadata": metadata,
        "blockers": unique_blockers,
    }


def validate_registration(
    document: object,
    definition: ExternalToolchainDefinition,
) -> dict[str, object]:
    if not isinstance(document, dict):
        raise ValueError("external worker preflight must be an object")
    required = {
        "schema_version",
        "checked_at",
        "ready",
        "definition",
        "host",
        "toolchain",
        "analysis",
        "smoke",
        "resources",
        "metadata",
        "blockers",
    }
    if (
        set(document) != required
        or document.get("schema_version") != EXTERNAL_PREFLIGHT_SCHEMA
    ):
        raise ValueError("external worker preflight has unsupported fields or schema")
    if document.get("ready") is not True or document.get("blockers") != []:
        raise ValueError("external worker preflight is not ready")
    if document.get("definition") != definition.registration_identity():
        raise ValueError("external worker preflight definition identity changed")
    if len(json.dumps(document, separators=(",", ":"), allow_nan=False)) > 256 * 1024:
        raise ValueError("external worker preflight exceeds 256 KiB")
    metadata = document.get("metadata")
    if not isinstance(metadata, dict) or any(
        not metadata.get(name) for name in definition.required_metadata
    ):
        raise ValueError("external worker preflight lacks required metadata")
    return dict(document)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="fidb-poc external-worker")
    result.add_argument("preflight", choices=("preflight",))
    result.add_argument("--project-root", type=Path, default=Path.cwd())
    result.add_argument("--definition", default="macos-arm64-apple-clang")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        definition = load_external_toolchain(
            arguments.definition, arguments.project_root
        )
        document = preflight_external_toolchain(definition, arguments.project_root)
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0 if document["ready"] else 1
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=os.sys.stderr)
        return 1
