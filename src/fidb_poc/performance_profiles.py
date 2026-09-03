"""Validated, inspectable host performance policies for width execution."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import tomllib

from .jvm_policy import java_options

PERFORMANCE_PROFILES_SCHEMA = "fidb-performance-profiles/v1"
DEFAULT_PERFORMANCE_PROFILES_PATH = Path("performance/profiles.toml")
MAX_WIDTH_WORKERS = 32
MAX_BUILD_JOBS_PER_CELL = 32
_ID = re.compile(r"[a-z0-9][a-z0-9-]*")
_QUALIFICATIONS = {
    "current-default",
    "portable-starting-point",
    "measured-openssl",
    "derived-from-measured-openssl",
}
_WORKER_MODES = {"automatic", "fixed"}
_MEMORY_MODELS = {"dedicated-system-memory", "unified"}


@dataclass(frozen=True)
class PerformanceSettings:
    worker_mode: str
    workers: int | None
    build_jobs_per_cell: int
    ghidra_heap_mib: int | None
    ghidra_core_limit: int | None

    def document(self) -> dict[str, object]:
        return {
            "worker_mode": self.worker_mode,
            "workers": self.workers,
            "build_jobs_per_cell": self.build_jobs_per_cell,
            "ghidra_heap_mib": self.ghidra_heap_mib,
            "ghidra_core_limit": self.ghidra_core_limit,
        }


@dataclass(frozen=True)
class PerformanceProfile:
    id: str
    label: str
    description: str
    qualification: str
    guidance: str
    evidence_path: str | None
    host: dict[str, object]
    settings: PerformanceSettings
    resolution: dict[str, object] | None = None

    def document(self) -> dict[str, object]:
        document = {
            "id": self.id,
            "label": self.label,
            "description": self.description,
            "qualification": self.qualification,
            "guidance": self.guidance,
            "evidence_path": self.evidence_path,
            "host": self.host,
            "settings": self.settings.document(),
        }
        if self.resolution is not None:
            document["resolution"] = self.resolution
        return document


@dataclass(frozen=True)
class PerformanceProfiles:
    default_profile: str
    authority_path: str
    profiles: tuple[PerformanceProfile, ...]

    def select(self, profile_id: str | None = None) -> PerformanceProfile:
        selected_id = profile_id or self.default_profile
        matches = [profile for profile in self.profiles if profile.id == selected_id]
        if len(matches) != 1:
            raise ValueError(f"unknown performance profile: {selected_id}")
        return matches[0]

    def document(self) -> dict[str, object]:
        return {
            "schema_version": PERFORMANCE_PROFILES_SCHEMA,
            "default_profile": self.default_profile,
            "authority_path": self.authority_path,
            "profiles": [profile.document() for profile in self.profiles],
        }


def _required_string(table: dict[str, object], name: str, context: str) -> str:
    value = table.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context}.{name} must be a non-empty string")
    return value


def _optional_positive_integer(
    table: dict[str, object], name: str, context: str
) -> int | None:
    value = table.get(name)
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{context}.{name} must be a positive integer")
    return value


def _load_host(table: object, context: str) -> dict[str, object]:
    if not isinstance(table, dict):
        raise ValueError(f"{context}.host must be a table")
    expected = {
        "system",
        "architecture",
        "physical_cores",
        "logical_cpus",
        "memory_mib",
        "memory_model",
    }
    unknown = set(table) - expected
    if unknown:
        raise ValueError(f"{context}.host has unknown fields: {sorted(unknown)}")
    memory_model = _required_string(table, "memory_model", f"{context}.host")
    if memory_model not in _MEMORY_MODELS:
        raise ValueError(f"{context}.host.memory_model is not supported")
    return {
        "system": _required_string(table, "system", f"{context}.host"),
        "architecture": _required_string(
            table, "architecture", f"{context}.host"
        ),
        "physical_cores": _optional_positive_integer(
            table, "physical_cores", f"{context}.host"
        ),
        "logical_cpus": _optional_positive_integer(
            table, "logical_cpus", f"{context}.host"
        ),
        "memory_mib": _optional_positive_integer(
            table, "memory_mib", f"{context}.host"
        ),
        "memory_model": memory_model,
    }


def _load_settings(table: object, context: str) -> PerformanceSettings:
    if not isinstance(table, dict):
        raise ValueError(f"{context}.settings must be a table")
    expected = {
        "worker_mode",
        "workers",
        "build_jobs_per_cell",
        "ghidra_heap_mib",
        "ghidra_core_limit",
    }
    unknown = set(table) - expected
    if unknown:
        raise ValueError(f"{context}.settings has unknown fields: {sorted(unknown)}")
    mode = _required_string(table, "worker_mode", f"{context}.settings")
    if mode not in _WORKER_MODES:
        raise ValueError(f"{context}.settings.worker_mode is not supported")
    workers = _optional_positive_integer(table, "workers", f"{context}.settings")
    if mode == "automatic" and workers is not None:
        raise ValueError(f"{context}.settings automatic mode must omit workers")
    if mode == "fixed" and workers is None:
        raise ValueError(f"{context}.settings fixed mode requires workers")
    if workers is not None and workers > MAX_WIDTH_WORKERS:
        raise ValueError(
            f"{context}.settings.workers must not exceed {MAX_WIDTH_WORKERS}"
        )
    build_jobs = _optional_positive_integer(
        table, "build_jobs_per_cell", f"{context}.settings"
    )
    if build_jobs is None:
        raise ValueError(f"{context}.settings.build_jobs_per_cell is required")
    if build_jobs > MAX_BUILD_JOBS_PER_CELL:
        raise ValueError(
            f"{context}.settings.build_jobs_per_cell must not exceed "
            f"{MAX_BUILD_JOBS_PER_CELL}"
        )
    heap = _optional_positive_integer(
        table, "ghidra_heap_mib", f"{context}.settings"
    )
    core_limit = _optional_positive_integer(
        table, "ghidra_core_limit", f"{context}.settings"
    )
    java_options(heap, core_limit, inherited="")
    return PerformanceSettings(mode, workers, build_jobs, heap, core_limit)


def load_performance_profiles(
    project_root: str | Path,
    path: str | Path = DEFAULT_PERFORMANCE_PROFILES_PATH,
) -> PerformanceProfiles:
    root = Path(project_root).expanduser().resolve()
    authority = Path(path)
    if not authority.is_absolute():
        authority = root / authority
    authority = authority.resolve()
    if authority == root or root not in authority.parents:
        raise ValueError("performance profile authority must be inside project root")
    document = tomllib.loads(authority.read_text(encoding="utf-8"))
    expected = {"schema_version", "default_profile", "profiles"}
    unknown = set(document) - expected
    if unknown:
        raise ValueError(f"performance authority has unknown fields: {sorted(unknown)}")
    if document.get("schema_version") != PERFORMANCE_PROFILES_SCHEMA:
        raise ValueError("unsupported performance profile schema")
    default_profile = _required_string(document, "default_profile", "performance")
    raw_profiles = document.get("profiles")
    if not isinstance(raw_profiles, list) or not raw_profiles:
        raise ValueError("performance.profiles must be a non-empty array")
    profiles: list[PerformanceProfile] = []
    expected_profile = {
        "id",
        "label",
        "description",
        "qualification",
        "guidance",
        "evidence_path",
        "host",
        "settings",
    }
    for index, raw in enumerate(raw_profiles):
        context = f"performance.profiles[{index}]"
        if not isinstance(raw, dict):
            raise ValueError(f"{context} must be a table")
        unknown_profile = set(raw) - expected_profile
        if unknown_profile:
            raise ValueError(f"{context} has unknown fields: {sorted(unknown_profile)}")
        profile_id = _required_string(raw, "id", context)
        if not _ID.fullmatch(profile_id):
            raise ValueError(f"{context}.id must be a lowercase dash token")
        qualification = _required_string(raw, "qualification", context)
        if qualification not in _QUALIFICATIONS:
            raise ValueError(f"{context}.qualification is not supported")
        evidence_path = raw.get("evidence_path")
        if evidence_path is not None:
            if not isinstance(evidence_path, str) or not evidence_path:
                raise ValueError(f"{context}.evidence_path must be a string")
            evidence = (root / evidence_path).resolve()
            if evidence == root or root not in evidence.parents or not evidence.is_file():
                raise ValueError(f"{context}.evidence_path is not a project file")
        profiles.append(
            PerformanceProfile(
                id=profile_id,
                label=_required_string(raw, "label", context),
                description=_required_string(raw, "description", context),
                qualification=qualification,
                guidance=_required_string(raw, "guidance", context),
                evidence_path=evidence_path,
                host=_load_host(raw.get("host"), context),
                settings=_load_settings(raw.get("settings"), context),
            )
        )
    ids = [profile.id for profile in profiles]
    if len(ids) != len(set(ids)):
        raise ValueError("performance profile ids must be unique")
    if default_profile not in ids:
        raise ValueError("performance.default_profile does not name a profile")
    return PerformanceProfiles(
        default_profile=default_profile,
        authority_path=str(authority.relative_to(root)),
        profiles=tuple(profiles),
    )
