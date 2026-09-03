"""Read-only worker capability and reviewed-toolchain inventory.

This module deliberately detects rather than prepares.  It never downloads,
extracts, installs, compiles, or substitutes a host compiler for a reviewed
registry entry.  The result keeps host tools, pinned archive cache state, and
queue-route eligibility separate so a local library worker is not blocked by
QEMU or malware requirements which do not belong to that pool.
"""

from __future__ import annotations

import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sqlite3
import subprocess
from typing import Mapping

from .config import load_configuration
from .coordinator import worker_pool_accepts_cell
from .host_capacity import detect_host_capacity, resolve_automatic_performance
from .toolchain_registry import load_toolchains
from .toolchain_cache import MANAGED_DOWNLOADS, inspect_cached
from .toolchain_packs import resolve_toolchain_profiles

CAPABILITIES_SCHEMA = "fidb-worker-capabilities/v1"
TOOLCHAIN_CACHE = MANAGED_DOWNLOADS

_HOST_TOOLS = (
    "file",
    "ar",
    "ranlib",
    "make",
    "patch",
    "qemu-img",
    "qemu-system-x86_64",
)


def _executable(path: Path) -> bool:
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return False
    return resolved.is_file() and os.access(resolved, os.X_OK)


def _resolve_executable(name: str, environment: Mapping[str, str]) -> str | None:
    candidate = Path(name)
    if candidate.is_absolute():
        return str(candidate.resolve()) if _executable(candidate) else None
    found = shutil.which(name, path=environment.get("PATH"))
    if found is None:
        return None
    resolved = Path(found).resolve()
    return str(resolved) if _executable(resolved) else None


def _host_memory_bytes() -> int | None:
    path = Path("/proc/meminfo")
    if not path.is_file():
        return None
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                fields = line.split()
                if len(fields) >= 2:
                    return int(fields[1]) * 1024
    except (OSError, ValueError):
        return None
    return None


def _ghidra(environment: Mapping[str, str]) -> dict[str, object]:
    configured = environment.get("GHIDRA_HEADLESS")
    configured_path = Path(configured) if configured else None
    configured_ready = configured_path is not None and _executable(configured_path)
    candidates: list[Path] = []
    if configured:
        candidates.append(Path(configured))
    standard = Path("/opt/ghidra/support/analyzeHeadless")
    if standard not in candidates:
        candidates.append(standard)

    installed = next((path.resolve() for path in candidates if _executable(path)), None)
    result: dict[str, object] = {
        "configured": bool(configured),
        "configured_path": configured,
        "installed": installed is not None,
        "path": str(installed) if installed is not None else None,
        "ready": configured_ready,
        "state": "ready" if configured_ready else "missing",
    }
    if configured and not configured_ready:
        result["state"] = "configured-missing"
    elif installed is not None and not configured:
        result["state"] = "installed-unconfigured"

    if installed is not None:
        properties = installed.parent.parent / "Ghidra/application.properties"
        if properties.is_file():
            try:
                values = {}
                for raw_line in properties.read_text(encoding="utf-8").splitlines():
                    line = raw_line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, value = line.split("=", 1)
                        values[key.strip()] = value.strip()
                result["version"] = values.get("application.version")
                result["release"] = values.get("application.release.name")
            except OSError:
                result["version"] = None
    return result


def _java(environment: Mapping[str, str]) -> dict[str, object]:
    java_home = environment.get("JAVA_HOME")
    configured = Path(java_home) / "bin/java" if java_home else None
    if configured is not None:
        path = str(configured.resolve()) if _executable(configured) else None
        state = "available" if path is not None else "configured-missing"
    else:
        path = _resolve_executable("java", environment)
        state = "available" if path is not None else "missing"
    version = None
    major = None
    error = None
    if path is not None:
        try:
            completed = subprocess.run(
                [path, "-version"],
                env=dict(environment),
                text=True,
                capture_output=True,
                check=False,
                timeout=5,
            )
            output = "\n".join(
                value for value in (completed.stdout, completed.stderr) if value
            )
            match = re.search(r'version\s+"(?P<version>\d+(?:\.\d+)*)', output)
            if completed.returncode == 0 and match is not None:
                version = match.group("version")
                components = version.split(".")
                major = int(components[1] if components[0] == "1" else components[0])
                if major < 21:
                    state = "incompatible"
                    error = "Ghidra requires Java 21 or later"
            else:
                state = "broken"
                error = "Java version probe failed"
        except (OSError, subprocess.SubprocessError, ValueError):
            state = "broken"
            error = "Java version probe failed"
    return {
        "configured_home": java_home,
        "available": path is not None,
        "ready": state == "available",
        "state": state,
        "path": path,
        "version": version,
        "major": major,
        "error": error,
    }


def _pyghidra() -> dict[str, object]:
    try:
        version = importlib.metadata.version("pyghidra")
    except importlib.metadata.PackageNotFoundError:
        version = None
    return {"available": version is not None, "version": version}


def _cache_entry(cache_root: Path, digest: object) -> dict[str, object]:
    expected = str(digest)
    inspected = inspect_cached(cache_root, expected)
    result: dict[str, object] = {
        "expected_sha256": expected,
        "path": str(inspected.path),
        "bytes": inspected.bytes,
        "state": inspected.state,
    }
    if inspected.observed_sha256 is not None:
        result["observed_sha256"] = inspected.observed_sha256
    return result


def _registry_inventory(project_root: Path) -> list[dict[str, object]]:
    registry = load_toolchains(project_root / "toolchains/registry.toml")
    cache_root = project_root / TOOLCHAIN_CACHE
    rows = []
    for row in registry:
        capabilities = []
        archives: dict[str, object] = {}
        if "url" in row:
            capabilities.append("archive")
            archives["archive_candidate"] = _cache_entry(cache_root, row["sha256"])
        if "toolchain_url" in row:
            capabilities.append("source")
            archives["cross_toolchain"] = _cache_entry(
                cache_root, row["toolchain_sha256"]
            )
        cache_states = [str(item["state"]) for item in archives.values()]
        if "broken" in cache_states:
            state = "broken"
        elif cache_states and all(value == "verified-cached" for value in cache_states):
            state = "verified-cached"
        else:
            state = "missing"
        rows.append(
            {
                "id": f'{row["family"]}@{row["version"]}:{row["variant"]}',
                "family": row["family"],
                "version": str(row["version"]),
                "variant": row["variant"],
                "target": {
                    "machine": row["machine"],
                    "endianness": row["endianness"],
                    "elf_class": int(row["elf_class"]),
                    "cross_arch": row.get("cross_arch"),
                },
                "capabilities": capabilities,
                "state": state,
                "archives": archives,
                "cross_bin_prefix": row.get("cross_bin_prefix"),
                "prepared_state": "per-attempt-extraction",
            }
        )
    return rows


def _native_routes(
    project_root: Path, environment: Mapping[str, str]
) -> list[dict[str, object]]:
    configuration = load_configuration(project_root / "worker.toml")
    rows = []
    for route in configuration.routes:
        tools = {}
        for label, command in (
            ("compiler", route.compiler),
            ("archiver", route.archiver),
            ("ranlib", route.ranlib),
        ):
            path = _resolve_executable(command[0], environment)
            tools[label] = {
                "configured": list(command),
                "available": path is not None,
                "path": path,
            }
        rows.append(
            {
                "id": route.id,
                "target": {
                    "os": route.target_os,
                    "architecture": route.architecture,
                    "binary_format": route.binary_format,
                },
                "tools": tools,
                "ready": all(bool(tool["available"]) for tool in tools.values()),
            }
        )
    return rows


def _active_cells(connection: sqlite3.Connection | None) -> list[dict[str, object]]:
    if connection is None:
        return []
    try:
        rows = connection.execute("""
            SELECT jobs.job_id, jobs.batch_id, jobs.state, cells.cell_json
            FROM jobs
            JOIN batches ON batches.batch_id = jobs.batch_id
            JOIN resolved_cells AS cells
              ON cells.plan_digest = jobs.plan_digest
             AND cells.cell_id = jobs.base_cell_id
            WHERE jobs.active = 1 AND batches.active = 1
            ORDER BY batches.position, jobs.position, jobs.job_id
            """).fetchall()
    except sqlite3.OperationalError:
        return []
    result = []
    for row in rows:
        result.append(
            {
                "job_id": str(row["job_id"]),
                "batch_id": str(row["batch_id"]),
                "job_state": str(row["state"]),
                "cell": json.loads(row["cell_json"]),
            }
        )
    return result


def _job_readiness(
    rows: list[dict[str, object]],
    *,
    native_routes: list[dict[str, object]],
    tools: dict[str, dict[str, object]],
    analysis_ready: bool,
    registry: list[dict[str, object]],
) -> list[dict[str, object]]:
    route_ready = {str(route["id"]): bool(route["ready"]) for route in native_routes}
    registry_by_variant = {
        str(row["variant"]): row for row in registry if "source" in row["capabilities"]
    }
    result = []
    for item in rows:
        cell = item["cell"]
        kind = str(cell.get("kind"))
        routing = cell.get("routing") if isinstance(cell.get("routing"), dict) else {}
        executor = str(routing.get("executor", "unknown"))
        reasons: list[str] = []

        eligible = worker_pool_accepts_cell("library-local", cell)
        if kind == "malware":
            reasons.append("malware is outside the library-local worker pool")
        elif kind == "native" and executor != "native-local":
            reasons.append(f"native cell is routed to {executor}, not native-local")
        elif kind == "source-library" and executor != "local":
            reasons.append(f"source-library cell is routed to {executor}, not local")
        elif kind == "archive-library" and executor != "archive-local":
            reasons.append(
                f"archive-library cell is routed to {executor}, not archive-local"
            )
        elif kind not in {"native", "source-library", "archive-library", "malware"}:
            reasons.append(f"unsupported cell kind: {kind}")

        readiness = "not-applicable"
        if eligible:
            hard_blocker = False
            missing_dependency = False
            acquisition_state: str | None = None
            if item["job_state"] == "blocked" or cell.get("status") == "blocked":
                hard_blocker = True
                reasons.extend(str(value) for value in cell.get("blockers", []))
            if not analysis_ready:
                missing_dependency = True
                reasons.append(
                    "Ghidra, Java, or PyGhidra analysis dependency is unavailable"
                )
            if kind == "native":
                toolchain = cell.get("toolchain")
                route = (
                    str(toolchain.get("route")) if isinstance(toolchain, dict) else ""
                )
                if not route_ready.get(route, False):
                    missing_dependency = True
                    reasons.append(f"configured native route is not ready: {route}")
            elif kind == "source-library":
                toolchain = cell.get("toolchain")
                variant = (
                    str(toolchain.get("variant")) if isinstance(toolchain, dict) else ""
                )
                inventory = registry_by_variant.get(variant)
                host_ready = bool(tools["make"]["available"]) and bool(
                    tools["patch"]["available"]
                )
                if inventory is None:
                    hard_blocker = True
                    reasons.append(f"no reviewed source toolchain row: {variant}")
                if not host_ready:
                    missing_dependency = True
                    reasons.append("local source adapter requires make and patch")
                if inventory is not None:
                    toolchain_cache = inventory["archives"].get("cross_toolchain", {})
                    toolchain_state = toolchain_cache.get("state")
                    if toolchain_state == "broken":
                        hard_blocker = True
                        reasons.append(
                            "managed toolchain cache failed digest verification"
                        )
                    elif toolchain_state == "verified-cached":
                        reasons.append(
                            "pinned toolchain is checksum-verified in the managed cache"
                        )
                        acquisition_state = None
                    else:
                        acquisition_state = "download-required"
                        reasons.append(
                            "pinned toolchain archive is not in the managed cache"
                        )
            else:
                toolchain = cell.get("toolchain")
                variant = (
                    str(toolchain.get("variant")) if isinstance(toolchain, dict) else ""
                )
                inventory = registry_by_variant.get(variant)
                if inventory is None:
                    hard_blocker = True
                    reasons.append(f"no reviewed archive registry row: {variant}")
                else:
                    archive_cache = inventory["archives"].get("archive_candidate", {})
                    archive_state = archive_cache.get("state")
                    if archive_state == "broken":
                        hard_blocker = True
                        reasons.append(
                            "managed archive cache failed digest verification"
                        )
                    elif archive_state != "verified-cached":
                        acquisition_state = "download-required"
                        reasons.append(
                            "pinned archive candidate is not in the managed cache"
                        )

            if hard_blocker:
                readiness = "blocked"
            elif missing_dependency:
                readiness = "missing-dependency"
            elif acquisition_state is not None:
                readiness = acquisition_state
            else:
                readiness = "ready"

        result.append(
            {
                "job_id": item["job_id"],
                "batch_id": item["batch_id"],
                "job_state": item["job_state"],
                "kind": kind,
                "executor": executor,
                "library_local_eligible": eligible,
                "readiness": readiness,
                "reasons": reasons,
            }
        )
    return result


def detect_capabilities(
    project_root: str | Path,
    *,
    connection: sqlite3.Connection | None = None,
    environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Return a read-only local worker and reviewed-toolchain inventory."""

    root = Path(project_root).resolve()
    effective_environment = dict(os.environ if environment is None else environment)
    tools = {
        name: {
            "available": (path := _resolve_executable(name, effective_environment))
            is not None,
            "path": path,
        }
        for name in _HOST_TOOLS
    }
    ghidra = _ghidra(effective_environment)
    java = _java(effective_environment)
    pyghidra = _pyghidra()
    analysis_ready = bool(ghidra["ready"] and java["ready"] and pyghidra["available"])
    native_routes = _native_routes(root, effective_environment)
    registry = _registry_inventory(root)
    toolchain_profiles = resolve_toolchain_profiles(root)
    active_cells = _active_cells(connection)
    active = _job_readiness(
        active_cells,
        native_routes=native_routes,
        tools=tools,
        analysis_ready=analysis_ready,
        registry=registry,
    )
    eligible = [row for row in active if row["library_local_eligible"]]
    immediately_ready = [row for row in eligible if row["readiness"] == "ready"]
    acquisition_ready = [
        row
        for row in eligible
        if row["readiness"] in {"ready", "download-required", "prepare-required"}
    ]
    macos_jobs = [
        row
        for row in active_cells
        if worker_pool_accepts_cell("macos-native", row["cell"])
    ]
    qemu_ready = bool(
        tools["qemu-img"]["available"] and tools["qemu-system-x86_64"]["available"]
    )
    host_capacity = detect_host_capacity()
    automatic_performance = resolve_automatic_performance(host_capacity)
    return {
        "schema_version": CAPABILITIES_SCHEMA,
        "detection_mode": "read-only",
        "host": {
            "system": platform.system(),
            "machine": platform.machine(),
            "physical_cores": host_capacity.physical_cores,
            "logical_cpus": host_capacity.logical_cpus,
            "smt_siblings": host_capacity.smt_siblings,
            "threads_per_core": host_capacity.threads_per_core,
            "memory_bytes": host_capacity.total_memory_bytes,
            "available_memory_bytes": host_capacity.available_memory_bytes,
            "memory_model": host_capacity.memory_model,
            "capacity": host_capacity.document(),
        },
        "automatic_performance": automatic_performance.document(),
        "tools": tools,
        "analysis": {
            "ready": analysis_ready,
            "ghidra": ghidra,
            "java": java,
            "pyghidra": pyghidra,
        },
        "native_routes": native_routes,
        "executors": {
            "native-local": {
                "ready": any(bool(row["ready"]) for row in native_routes),
                "isolation_boundary": "invoking-linux-environment",
            },
            "local": {
                "ready": bool(
                    tools["make"]["available"] and tools["patch"]["available"]
                ),
                "isolation_boundary": "invoking-linux-environment",
                "opt_in": True,
            },
            "qemu": {
                "ready": qemu_ready,
                "isolation_boundary": "qemu-vm",
                "required_for_library_local_pool": False,
                "diagnostic_only_for_library_local_pool": True,
                "kvm": {
                    "available": Path("/dev/kvm").exists()
                    and os.access("/dev/kvm", os.R_OK | os.W_OK)
                },
            },
        },
        "worker_pools": {
            "library-local": {
                "cell_kinds": ["native", "source-library", "archive-library"],
                "source_executor": "local",
                "excluded_cell_kinds": ["malware"],
                "qemu_required": False,
                "eligible_jobs": len(eligible),
                "ready_now": len(immediately_ready),
                "runnable_with_pinned_acquisition": len(acquisition_ready),
                "blocked": len(eligible) - len(acquisition_ready),
            },
            "macos-native": {
                "cell_kinds": ["native"],
                "source_executor": "native-local",
                "excluded_cell_kinds": [
                    "source-library",
                    "archive-library",
                    "malware",
                ],
                "qemu_required": False,
                "eligible_jobs": len(macos_jobs),
                "ready_now": 0,
                "runnable_with_pinned_acquisition": 0,
                "blocked": 0,
                "external_registration_required": True,
            },
        },
        "active_job_readiness": active,
        "toolchains": {
            "registry_path": str(root / "toolchains/registry.toml"),
            "managed_cache": str(root / TOOLCHAIN_CACHE),
            "managed_preparation": "per-attempt-extraction",
            "entries": registry,
        },
        "toolchain_profiles": {
            "managed_downloads": str(root / TOOLCHAIN_CACHE),
            "plans": toolchain_profiles,
        },
    }
