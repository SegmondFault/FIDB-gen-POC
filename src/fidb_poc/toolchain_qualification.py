"""Composition and C-family smoke qualification for reviewed toolchain routes."""

from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import struct
import subprocess
import tempfile
from typing import Callable, Sequence

from .toolchain_cache import MANAGED_CACHE_ROOT

COMPOSITION_SCHEMA = "fidb-toolchain-composition/v1"
QUALIFICATION_RECORD_SCHEMA = "fidb-toolchain-qualification-record/v1"
MANAGED_COMPOSED = MANAGED_CACHE_ROOT / "composed"
MANAGED_QUALIFIED = MANAGED_CACHE_ROOT / "qualified"
COMPOSITION_DEPENDENCIES = (
    "bash",
    "cmake",
    "make",
    "patch",
    "xz",
    "bzip2",
    "cpio",
    "git",
    "sed",
    "awk",
    "tar",
)
_COMPOSITION_MANIFEST = ".fidb-composed.json"
_QUALIFICATION_RECORD = "qualification.json"


class QualificationError(RuntimeError):
    """A reviewed route could not be composed or qualified."""


@dataclass(frozen=True)
class CompositionInspection:
    path: Path
    root: Path
    state: str
    manifest: dict[str, object] | None = None


@dataclass(frozen=True)
class CompositionResult:
    path: Path
    root: Path
    route_id: str
    route_material_digest: str
    log_sha256: str
    log_bytes: int
    cache_hit: bool


@dataclass(frozen=True)
class QualificationInspection:
    path: Path
    state: str
    record: dict[str, object] | None = None


@dataclass(frozen=True)
class QualificationResult:
    path: Path
    route_id: str
    route_material_digest: str
    record_digest: str
    cache_hit: bool


@dataclass(frozen=True)
class QualifiedRouteTools:
    """Executable tools recovered from one intact qualification authority."""

    compiler: Path
    cxx_compiler: Path
    archiver: Path
    ranlib: Path
    route_material_digest: str
    record_digest: str
    compiler_version_output: str


Runner = Callable[..., subprocess.CompletedProcess[str]]


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def route_material_digest(
    route: dict[str, object],
    qualification: dict[str, object],
    packs: Sequence[dict[str, object]],
    inputs: Sequence[dict[str, object]],
) -> str:
    """Digest the exact authority and locally bound materials for one route."""

    pack_by_id = {str(pack["id"]): pack for pack in packs}
    input_by_id = {str(item["id"]): item for item in inputs}
    selected_packs = []
    for pack_id in route["pack_ids"]:
        pack = pack_by_id[str(pack_id)]
        selected_packs.append(
            {
                "id": pack["id"],
                "sha256": pack["sha256"],
                "archive_root": pack["archive_root"],
                "compiler_version": pack["compiler_version"],
                "linker_version": pack["linker_version"],
                "runtime_version": pack["runtime_version"],
            }
        )
    selected_inputs = []
    for input_id in route["input_ids"]:
        item = input_by_id[str(input_id)]
        binding = item.get("binding")
        if not isinstance(binding, dict) or binding.get("state") != "bound-verified":
            raise QualificationError(f"route input is not bound: {input_id}")
        document = binding.get("document")
        if not isinstance(document, dict):
            raise QualificationError(f"route input binding is incomplete: {input_id}")
        selected_inputs.append(
            {
                "id": input_id,
                "sha256": document["sha256"],
                "bytes": document["bytes"],
                "metadata": document["metadata"],
            }
        )
    return _canonical_digest(
        {
            "route": {
                key: value
                for key, value in route.items()
                if key not in {"state", "qualification", "compiler_id"}
            },
            "qualification": qualification,
            "packs": selected_packs,
            "inputs": selected_inputs,
        }
    )


def composition_dependencies() -> list[dict[str, object]]:
    return [
        {
            "name": name,
            "path": shutil.which(name),
            "available": shutil.which(name) is not None,
        }
        for name in COMPOSITION_DEPENDENCIES
    ]


def inspect_composition(
    project_root: Path,
    route_id: str,
    material_digest: str,
) -> CompositionInspection:
    destination = project_root / MANAGED_COMPOSED / route_id / material_digest
    root = destination / "toolchain"
    manifest_path = destination / _COMPOSITION_MANIFEST
    if not destination.exists():
        return CompositionInspection(destination, root, "missing")
    if destination.is_symlink() or not destination.is_dir():
        return CompositionInspection(destination, root, "broken")
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return CompositionInspection(destination, root, "broken")
    required = {
        "schema_version",
        "route_id",
        "route_material_digest",
        "command",
        "environment",
        "pack_sha256s",
        "input_sha256s",
        "log_sha256",
        "log_bytes",
    }
    if (
        not isinstance(document, dict)
        or set(document) != required
        or document.get("schema_version") != COMPOSITION_SCHEMA
        or document.get("route_id") != route_id
        or document.get("route_material_digest") != material_digest
        or root.is_symlink()
        or not root.is_dir()
    ):
        return CompositionInspection(destination, root, "broken")
    log = destination / "build.log"
    if (
        log.is_symlink()
        or not log.is_file()
        or log.stat().st_size != document.get("log_bytes")
        or _sha256(log) != document.get("log_sha256")
    ):
        return CompositionInspection(destination, root, "broken")
    return CompositionInspection(destination, root, "composed", document)


def _run_composition(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    log: Path,
    timeout_seconds: int,
) -> None:
    with log.open("xb") as output:
        try:
            completed = subprocess.run(
                command,
                cwd=cwd,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise QualificationError("osxcross composition timed out") from error
        output.flush()
        os.fsync(output.fileno())
    if completed.returncode != 0:
        tail = log.read_bytes()[-4096:].decode("utf-8", errors="replace")
        raise QualificationError(
            f"osxcross composition failed with status {completed.returncode}: {tail}"
        )


def compose_osxcross(
    project_root: Path,
    route: dict[str, object],
    qualification: dict[str, object],
    packs: Sequence[dict[str, object]],
    inputs: Sequence[dict[str, object]],
    *,
    timeout_seconds: int = 3600,
) -> CompositionResult:
    """Compose the reviewed LLVM-flavor osxcross route in an atomic store."""

    if qualification["composition"] != "osxcross-llvm":
        raise QualificationError("route does not declare osxcross composition")
    missing_dependencies = [
        row["name"] for row in composition_dependencies() if not row["available"]
    ]
    if missing_dependencies:
        raise QualificationError(
            "osxcross host dependencies are missing: "
            + ", ".join(str(value) for value in missing_dependencies)
        )
    pack_by_id = {str(pack["id"]): pack for pack in packs}
    input_by_id = {str(item["id"]): item for item in inputs}
    source_pack = next(
        pack for pack in packs if str(pack["id"]).startswith("osxcross-source-")
    )
    llvm_pack = next(pack for pack in packs if pack["kind"] == "compiler-tooling")
    for pack_id in route["pack_ids"]:
        preparation = pack_by_id[str(pack_id)].get("preparation")
        if not isinstance(preparation, dict) or preparation.get("state") != "prepared":
            raise QualificationError(f"route pack is not prepared: {pack_id}")
    sdk = input_by_id[str(route["input_ids"][0])]
    binding = sdk.get("binding")
    if not isinstance(binding, dict) or binding.get("state") != "bound-verified":
        raise QualificationError("Apple SDK input is not bound")
    binding_document = binding.get("document")
    if not isinstance(binding_document, dict):
        raise QualificationError("Apple SDK binding document is missing")
    metadata = binding_document.get("metadata")
    if not isinstance(metadata, dict) or metadata.get("package_format") != "tar-xz":
        raise QualificationError("Apple SDK package_format must be tar-xz")
    material_digest = route_material_digest(route, qualification, packs, inputs)
    existing = inspect_composition(project_root, str(route["id"]), material_digest)
    if existing.state == "composed":
        manifest = existing.manifest or {}
        return CompositionResult(
            existing.path,
            existing.root,
            str(route["id"]),
            material_digest,
            str(manifest["log_sha256"]),
            int(manifest["log_bytes"]),
            True,
        )
    if existing.state == "broken":
        raise QualificationError("existing route composition is broken")

    route_directory = project_root / MANAGED_COMPOSED / str(route["id"])
    route_directory.mkdir(parents=True, exist_ok=True)
    locks = project_root / MANAGED_CACHE_ROOT / "locks"
    locks.mkdir(parents=True, exist_ok=True)
    lock_path = locks / f"compose-{material_digest}.lock"
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        existing = inspect_composition(project_root, str(route["id"]), material_digest)
        if existing.state == "composed":
            manifest = existing.manifest or {}
            return CompositionResult(
                existing.path,
                existing.root,
                str(route["id"]),
                material_digest,
                str(manifest["log_sha256"]),
                int(manifest["log_bytes"]),
                True,
            )
        staging = Path(
            tempfile.mkdtemp(prefix=f".{material_digest}.", dir=route_directory)
        )
        try:
            source_root = Path(str(source_pack["preparation"]["root"]))
            llvm_root = Path(str(llvm_pack["preparation"]["root"]))
            if source_root.is_symlink() or not source_root.is_dir():
                raise QualificationError("prepared osxcross source root is invalid")
            if llvm_root.is_symlink() or not llvm_root.is_dir():
                raise QualificationError("prepared LLVM root is invalid")
            work_source = staging / "source"
            shutil.copytree(source_root, work_source, symlinks=True)
            tarballs = work_source / "tarballs"
            tarballs.mkdir(exist_ok=True)
            sdk_name = f"MacOSX{metadata['sdk_version']}.sdk.tar.xz"
            sdk_material = Path(str(binding["material_path"]))
            if sdk_material.is_symlink() or not sdk_material.is_file():
                raise QualificationError("bound Apple SDK material is invalid")
            shutil.copyfile(sdk_material, tarballs / sdk_name)
            target = staging / "toolchain"
            command = [str(work_source / "build.sh")]
            environment = {
                "PATH": f"{llvm_root / 'bin'}:/usr/bin:/bin",
                "UNATTENDED": "1",
                "BUILD_FLAVOR": "llvm",
                "TARGET_DIR": str(target),
                "OSX_VERSION_MIN": str(metadata["deployment_target"]),
                "ENABLE_ARCHS": "arm64",
                "JOBS": str(max(1, min(os.cpu_count() or 1, 8))),
            }
            log = staging / "build.log"
            _run_composition(
                command,
                cwd=work_source,
                environment=environment,
                log=log,
                timeout_seconds=timeout_seconds,
            )
            if target.is_symlink() or not target.is_dir():
                raise QualificationError(
                    "osxcross did not produce its target directory"
                )
            manifest = {
                "schema_version": COMPOSITION_SCHEMA,
                "route_id": route["id"],
                "route_material_digest": material_digest,
                "command": ["./build.sh"],
                "environment": {
                    key: environment[key]
                    for key in (
                        "UNATTENDED",
                        "BUILD_FLAVOR",
                        "OSX_VERSION_MIN",
                        "ENABLE_ARCHS",
                        "JOBS",
                    )
                },
                "pack_sha256s": [
                    pack_by_id[str(pack_id)]["sha256"] for pack_id in route["pack_ids"]
                ],
                "input_sha256s": [binding_document["sha256"]],
                "log_sha256": _sha256(log),
                "log_bytes": log.stat().st_size,
            }
            manifest_path = staging / _COMPOSITION_MANIFEST
            with manifest_path.open("x", encoding="utf-8") as output:
                json.dump(manifest, output, indent=2, sort_keys=True)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            destination = route_directory / material_digest
            os.replace(staging, destination)
            _fsync_directory(route_directory)
            return CompositionResult(
                destination,
                destination / "toolchain",
                str(route["id"]),
                material_digest,
                str(manifest["log_sha256"]),
                int(manifest["log_bytes"]),
                False,
            )
        finally:
            if staging.exists():
                shutil.rmtree(staging)


def _safe_tool(root: Path, pattern: str) -> Path:
    pure = PurePosixPath(pattern)
    if pure.is_absolute() or ".." in pure.parts:
        raise QualificationError(f"unsafe qualification tool pattern: {pattern}")
    matches = list(root.glob(pattern))
    if len(matches) != 1:
        raise QualificationError(
            f"qualification tool pattern must match exactly once: {pattern}"
        )
    path = matches[0]
    resolved_root = root.resolve()
    try:
        path.resolve().relative_to(resolved_root)
    except (OSError, ValueError) as error:
        raise QualificationError(
            f"qualification tool escapes root: {pattern}"
        ) from error
    if not path.is_file() or not os.access(path, os.X_OK):
        raise QualificationError(f"qualification tool is not executable: {path}")
    return path


def _run_checked(
    runner: Runner,
    arguments: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: int,
) -> subprocess.CompletedProcess[str]:
    try:
        result = runner(
            arguments,
            cwd=cwd,
            env=environment,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise QualificationError(
            f"qualification command timed out: {arguments[0]}"
        ) from error
    if result.returncode != 0:
        raise QualificationError(
            f"qualification command failed ({result.returncode}): "
            f"{' '.join(arguments)}\n{result.stderr[-2048:]}"
        )
    return result


_ELF_MACHINES = {
    "aarch64": 183,
    "arm": 40,
    "i686": 3,
    "m68k": 4,
    "mips": 8,
    "mipsel": 8,
    "powerpc": 20,
    "sh4": 42,
    "x86_64": 62,
}


def _inspect_object(path: Path, target: dict[str, object]) -> dict[str, object]:
    data = path.read_bytes()
    binary_format = str(target["binary_format"])
    architecture = str(target["architecture"])
    if binary_format == "ELF":
        if len(data) < 20 or data[:4] != b"\x7fELF":
            raise QualificationError(f"smoke object is not ELF: {path}")
        expected_class = 2 if target["bits"] == 64 else 1
        expected_data = 1 if target["endianness"] == "little" else 2
        byteorder = "little" if data[5] == 1 else "big"
        machine = int.from_bytes(data[18:20], byteorder)
        if (
            data[4] != expected_class
            or data[5] != expected_data
            or machine != _ELF_MACHINES[architecture]
        ):
            raise QualificationError(f"ELF smoke object does not match target: {path}")
        details = {"elf_class": data[4], "elf_data": data[5], "machine": machine}
    elif binary_format == "PE/COFF":
        machine = int.from_bytes(data[:2], "little") if len(data) >= 2 else -1
        if machine != 0x8664:
            raise QualificationError(f"COFF smoke object does not match x86-64: {path}")
        details = {"machine": machine}
    elif binary_format == "Mach-O":
        if len(data) < 8 or data[:4] != b"\xcf\xfa\xed\xfe":
            raise QualificationError(
                f"smoke object is not 64-bit little-endian Mach-O: {path}"
            )
        cpu_type = struct.unpack("<I", data[4:8])[0]
        if cpu_type != 0x0100000C:
            raise QualificationError(f"Mach-O smoke object is not ARM64: {path}")
        details = {"cpu_type": cpu_type}
    else:
        raise QualificationError(f"unsupported smoke object format: {binary_format}")
    return {
        "path": path.name,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "binary_format": binary_format,
        **details,
    }


def inspect_qualification(
    project_root: Path,
    route_id: str,
    material_digest: str,
) -> QualificationInspection:
    destination = project_root / MANAGED_QUALIFIED / route_id / material_digest
    record_path = destination / _QUALIFICATION_RECORD
    if not destination.exists():
        return QualificationInspection(destination, "missing")
    if destination.is_symlink() or not destination.is_dir():
        return QualificationInspection(destination, "broken")
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return QualificationInspection(destination, "broken")
    required = {
        "schema_version",
        "route_id",
        "route_material_digest",
        "target_id",
        "compiler_version_output",
        "tools",
        "commands",
        "sources",
        "objects",
        "archive",
        "record_digest",
    }
    if (
        not isinstance(record, dict)
        or set(record) != required
        or record.get("schema_version") != QUALIFICATION_RECORD_SCHEMA
        or record.get("route_id") != route_id
        or record.get("route_material_digest") != material_digest
    ):
        return QualificationInspection(destination, "broken")
    unsigned = {key: value for key, value in record.items() if key != "record_digest"}
    if _canonical_digest(unsigned) != record["record_digest"]:
        return QualificationInspection(destination, "broken")
    materials = [*record.get("objects", []), record.get("archive")]
    for material in materials:
        if not isinstance(material, dict) or not isinstance(material.get("path"), str):
            return QualificationInspection(destination, "broken")
        path = destination / str(material["path"])
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_size != material.get("bytes")
            or _sha256(path) != material.get("sha256")
        ):
            return QualificationInspection(destination, "broken")
    return QualificationInspection(destination, "qualified", record)


def resolve_qualified_route_tools(
    project_root: Path,
    route: dict[str, object],
    qualification: dict[str, object],
    packs: Sequence[dict[str, object]],
    inputs: Sequence[dict[str, object]],
) -> QualifiedRouteTools:
    """Resolve a qualified route to tools without trusting cached path text.

    The qualification record contributes the exact material identity, but each
    executable is resolved again beneath the checksum-addressed prepared (or
    composed) root.  Callers therefore keep stable route IDs in TOML rather
    than persisting workstation-specific cache paths.
    """

    material_digest = route_material_digest(route, qualification, packs, inputs)
    inspection = inspect_qualification(project_root, str(route["id"]), material_digest)
    if inspection.state != "qualified" or inspection.record is None:
        raise QualificationError(
            f"route {route['id']} is not qualified: {inspection.state}"
        )

    if qualification["tool_source"] == "pack":
        from .toolchain_prepare import MANAGED_PREPARED, inspect_prepared

        pack = next(
            (row for row in packs if row["id"] == qualification["tool_pack_id"]),
            None,
        )
        if pack is None:
            raise QualificationError(
                f"route {route['id']} references an unknown qualification pack"
            )
        preparation = inspect_prepared(
            project_root / MANAGED_PREPARED,
            str(pack["sha256"]),
            str(pack["archive_root"]),
        )
        if preparation.state != "prepared":
            raise QualificationError(
                f"route {route['id']} preparation is not ready: {preparation.state}"
            )
        tool_root = preparation.root
    else:
        composition = inspect_composition(
            project_root, str(route["id"]), material_digest
        )
        if composition.state != "composed":
            raise QualificationError(
                f"route {route['id']} composition is not ready: {composition.state}"
            )
        tool_root = composition.root

    compiler = _safe_tool(tool_root, str(qualification["driver_pattern"]))
    cxx_compiler = _safe_tool(tool_root, str(qualification["cxx_driver_pattern"]))
    archiver = _safe_tool(tool_root, str(qualification["archiver_pattern"]))
    if archiver.name == "llvm-ar":
        ranlib_name = "llvm-ranlib"
    elif archiver.name.endswith("-ar"):
        ranlib_name = f"{archiver.name[:-3]}-ranlib"
    elif archiver.name == "ar":
        ranlib_name = "ranlib"
    else:
        raise QualificationError(
            f"route {route['id']} has no reviewed ranlib derivation for {archiver.name}"
        )
    ranlib = _safe_tool(
        tool_root,
        str(
            PurePosixPath(str(qualification["archiver_pattern"])).with_name(ranlib_name)
        ),
    )

    record_tools = inspection.record.get("tools")
    expected_tools = {
        "c": str(compiler.relative_to(tool_root)),
        "cpp": str(cxx_compiler.relative_to(tool_root)),
        "archiver": str(archiver.relative_to(tool_root)),
    }
    if record_tools != expected_tools:
        raise QualificationError(
            f"route {route['id']} qualification tool paths no longer match authority"
        )
    return QualifiedRouteTools(
        compiler=compiler,
        cxx_compiler=cxx_compiler,
        archiver=archiver,
        ranlib=ranlib,
        route_material_digest=material_digest,
        record_digest=str(inspection.record["record_digest"]),
        compiler_version_output=str(inspection.record["compiler_version_output"]),
    )


def qualify_route(
    project_root: Path,
    route: dict[str, object],
    qualification: dict[str, object],
    target: dict[str, object],
    packs: Sequence[dict[str, object]],
    inputs: Sequence[dict[str, object]],
    *,
    runner: Runner = subprocess.run,
    timeout_seconds: int = 60,
) -> QualificationResult:
    """Compile fixed C/C++ objects and archive them with one reviewed route."""

    material_digest = route_material_digest(route, qualification, packs, inputs)
    existing = inspect_qualification(project_root, str(route["id"]), material_digest)
    if existing.state == "qualified":
        return QualificationResult(
            existing.path,
            str(route["id"]),
            material_digest,
            str((existing.record or {})["record_digest"]),
            True,
        )
    if existing.state == "broken":
        raise QualificationError("existing route qualification is broken")
    if qualification["tool_source"] == "pack":
        pack = next(row for row in packs if row["id"] == qualification["tool_pack_id"])
        preparation = pack.get("preparation")
        if not isinstance(preparation, dict) or preparation.get("state") != "prepared":
            raise QualificationError("qualification pack is not prepared")
        tool_root = Path(str(preparation["root"]))
    else:
        composition = inspect_composition(
            project_root, str(route["id"]), material_digest
        )
        if composition.state != "composed":
            raise QualificationError("route composition is not ready")
        tool_root = composition.root
    compiler = _safe_tool(tool_root, str(qualification["driver_pattern"]))
    cxx_compiler = _safe_tool(tool_root, str(qualification["cxx_driver_pattern"]))
    archiver = _safe_tool(tool_root, str(qualification["archiver_pattern"]))

    route_directory = project_root / MANAGED_QUALIFIED / str(route["id"])
    route_directory.mkdir(parents=True, exist_ok=True)
    locks = project_root / MANAGED_CACHE_ROOT / "locks"
    locks.mkdir(parents=True, exist_ok=True)
    lock_path = locks / f"qualify-{material_digest}.lock"
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        existing = inspect_qualification(
            project_root, str(route["id"]), material_digest
        )
        if existing.state == "qualified":
            return QualificationResult(
                existing.path,
                str(route["id"]),
                material_digest,
                str((existing.record or {})["record_digest"]),
                True,
            )
        staging = Path(
            tempfile.mkdtemp(prefix=f".{material_digest}.", dir=route_directory)
        )
        try:
            c_source = staging / "smoke.c"
            cpp_source = staging / "smoke.cpp"
            c_source.write_text(
                "int fidb_toolchain_smoke_c(int value) { return value + 7; }\n",
                encoding="utf-8",
            )
            cpp_source.write_text(
                'extern "C" int fidb_toolchain_smoke_cpp(int value) noexcept '
                "{ return value * 3; }\n",
                encoding="utf-8",
            )
            c_object = staging / "smoke-c.o"
            cpp_object = staging / "smoke-cpp.o"
            archive = staging / "libfidb-toolchain-smoke.a"
            environment = {
                "PATH": f"{compiler.parent}:/usr/bin:/bin",
                "LC_ALL": "C",
                "LANG": "C",
            }
            version_command = [str(compiler), "--version"]
            c_command = [
                str(compiler),
                "-O2",
                "-fPIC",
                "-c",
                str(c_source),
                "-o",
                str(c_object),
            ]
            cpp_command = [
                str(cxx_compiler),
                "-std=c++17",
                "-O2",
                "-fPIC",
                "-c",
                str(cpp_source),
                "-o",
                str(cpp_object),
            ]
            archive_command = [
                str(archiver),
                "rcs",
                str(archive),
                str(c_object),
                str(cpp_object),
            ]
            version = _run_checked(
                runner,
                version_command,
                cwd=staging,
                environment=environment,
                timeout_seconds=timeout_seconds,
            )
            version_output = (version.stdout + version.stderr).strip()
            if str(qualification["version_contains"]) not in version_output:
                raise QualificationError(
                    "compiler version output does not contain reviewed marker"
                )
            for command in (c_command, cpp_command, archive_command):
                _run_checked(
                    runner,
                    command,
                    cwd=staging,
                    environment=environment,
                    timeout_seconds=timeout_seconds,
                )
            objects = [
                _inspect_object(c_object, target),
                _inspect_object(cpp_object, target),
            ]
            if archive.read_bytes()[:8] != b"!<arch>\n":
                raise QualificationError("smoke library is not a static archive")
            archive_record = {
                "path": archive.name,
                "bytes": archive.stat().st_size,
                "sha256": _sha256(archive),
                "format": "ar",
            }
            unsigned = {
                "schema_version": QUALIFICATION_RECORD_SCHEMA,
                "route_id": route["id"],
                "route_material_digest": material_digest,
                "target_id": route["target_id"],
                "compiler_version_output": version_output,
                "tools": {
                    "c": str(compiler.relative_to(tool_root)),
                    "cpp": str(cxx_compiler.relative_to(tool_root)),
                    "archiver": str(archiver.relative_to(tool_root)),
                },
                "commands": {
                    "version": ["<compiler>", "--version"],
                    "c": ["<compiler>", "-O2", "-fPIC", "-c", "smoke.c"],
                    "cpp": [
                        "<cxx-compiler>",
                        "-std=c++17",
                        "-O2",
                        "-fPIC",
                        "-c",
                        "smoke.cpp",
                    ],
                    "archive": [
                        "<archiver>",
                        "rcs",
                        archive.name,
                        "smoke-c.o",
                        "smoke-cpp.o",
                    ],
                },
                "sources": {
                    "c_sha256": _sha256(c_source),
                    "cpp_sha256": _sha256(cpp_source),
                },
                "objects": objects,
                "archive": archive_record,
            }
            record = {**unsigned, "record_digest": _canonical_digest(unsigned)}
            record_path = staging / _QUALIFICATION_RECORD
            with record_path.open("x", encoding="utf-8") as output:
                json.dump(record, output, indent=2, sort_keys=True)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            c_source.unlink()
            cpp_source.unlink()
            destination = route_directory / material_digest
            os.replace(staging, destination)
            _fsync_directory(route_directory)
            return QualificationResult(
                destination,
                str(route["id"]),
                material_digest,
                str(record["record_digest"]),
                False,
            )
        finally:
            if staging.exists():
                shutil.rmtree(staging)
