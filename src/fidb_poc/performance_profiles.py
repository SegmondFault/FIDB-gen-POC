"""Validated, inspectable host performance policies for width execution."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import tomllib

from .jvm_policy import java_options

PERFORMANCE_PROFILES_SCHEMA = "fidb-performance-profiles/v2"
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
class AutomaticMemoryTier:
    minimum_memory_mib: int
    ghidra_heap_mib: int

    def document(self) -> dict[str, int]:
        return {
            "minimum_memory_mib": self.minimum_memory_mib,
            "ghidra_heap_mib": self.ghidra_heap_mib,
        }


@dataclass(frozen=True)
class AutomaticCpuTier:
    minimum_physical_cores: int
    build_jobs_per_cell: int
    ghidra_core_limit: int

    def document(self) -> dict[str, int]:
        return {
            "minimum_physical_cores": self.minimum_physical_cores,
            "build_jobs_per_cell": self.build_jobs_per_cell,
            "ghidra_core_limit": self.ghidra_core_limit,
        }


@dataclass(frozen=True)
class AutomaticPolicy:
    selector_version: str
    maximum_workers: int
    physical_core_weight: float
    smt_sibling_weight: float
    memory_reserve_fraction: float
    memory_reserve_min_mib: int
    per_worker_min_mib: int
    memory_basis: str
    live_pressure: str
    memory_tiers: tuple[AutomaticMemoryTier, ...]
    cpu_tiers: tuple[AutomaticCpuTier, ...]

    def document(self) -> dict[str, object]:
        return {
            "selector_version": self.selector_version,
            "maximum_workers": self.maximum_workers,
            "physical_core_weight": self.physical_core_weight,
            "smt_sibling_weight": self.smt_sibling_weight,
            "memory_reserve_fraction": self.memory_reserve_fraction,
            "memory_reserve_min_mib": self.memory_reserve_min_mib,
            "per_worker_min_mib": self.per_worker_min_mib,
            "memory_basis": self.memory_basis,
            "live_pressure": self.live_pressure,
            "memory_tiers": [tier.document() for tier in self.memory_tiers],
            "cpu_tiers": [tier.document() for tier in self.cpu_tiers],
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
    automatic_policy: AutomaticPolicy
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
            "automatic_policy": self.automatic_policy.document(),
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


def _required_positive_integer(
    table: dict[str, object], name: str, context: str
) -> int:
    value = _optional_positive_integer(table, name, context)
    if value is None:
        raise ValueError(f"{context}.{name} is required")
    return value


def _required_number(table: dict[str, object], name: str, context: str) -> float:
    value = table.get(name)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"{context}.{name} must be numeric")
    return float(value)


def _load_automatic_policy(table: object) -> AutomaticPolicy:
    context = "performance.automatic_policy"
    if not isinstance(table, dict):
        raise ValueError(f"{context} must be a table")
    expected = {
        "selector_version",
        "maximum_workers",
        "physical_core_weight",
        "smt_sibling_weight",
        "memory_reserve_fraction",
        "memory_reserve_min_mib",
        "per_worker_min_mib",
        "memory_basis",
        "live_pressure",
        "memory_tiers",
        "cpu_tiers",
    }
    unknown = set(table) - expected
    if unknown:
        raise ValueError(f"{context} has unknown fields: {sorted(unknown)}")
    maximum_workers = _required_positive_integer(table, "maximum_workers", context)
    if maximum_workers > MAX_WIDTH_WORKERS:
        raise ValueError(
            f"{context}.maximum_workers must not exceed {MAX_WIDTH_WORKERS}"
        )
    physical_weight = _required_number(table, "physical_core_weight", context)
    smt_weight = _required_number(table, "smt_sibling_weight", context)
    if not 0 < physical_weight <= 1:
        raise ValueError(f"{context}.physical_core_weight must be in (0, 1]")
    if not 0 <= smt_weight <= 1:
        raise ValueError(f"{context}.smt_sibling_weight must be in [0, 1]")
    reserve_fraction = _required_number(table, "memory_reserve_fraction", context)
    if not 0 <= reserve_fraction < 1:
        raise ValueError(f"{context}.memory_reserve_fraction must be in [0, 1)")

    raw_memory_tiers = table.get("memory_tiers")
    if not isinstance(raw_memory_tiers, list) or not raw_memory_tiers:
        raise ValueError(f"{context}.memory_tiers must be a non-empty array")
    memory_tiers = []
    for index, raw in enumerate(raw_memory_tiers):
        tier_context = f"{context}.memory_tiers[{index}]"
        if not isinstance(raw, dict) or set(raw) != {
            "minimum_memory_mib",
            "ghidra_heap_mib",
        }:
            raise ValueError(f"{tier_context} is incomplete or unsupported")
        minimum = raw["minimum_memory_mib"]
        if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 0:
            raise ValueError(f"{tier_context}.minimum_memory_mib must be non-negative")
        heap = _required_positive_integer(raw, "ghidra_heap_mib", tier_context)
        java_options(heap, None, inherited="")
        memory_tiers.append(AutomaticMemoryTier(minimum, heap))
    if memory_tiers[0].minimum_memory_mib != 0 or any(
        left.minimum_memory_mib >= right.minimum_memory_mib
        for left, right in zip(memory_tiers, memory_tiers[1:])
    ):
        raise ValueError(f"{context}.memory_tiers must start at zero and increase")

    raw_cpu_tiers = table.get("cpu_tiers")
    if not isinstance(raw_cpu_tiers, list) or not raw_cpu_tiers:
        raise ValueError(f"{context}.cpu_tiers must be a non-empty array")
    cpu_tiers = []
    for index, raw in enumerate(raw_cpu_tiers):
        tier_context = f"{context}.cpu_tiers[{index}]"
        if not isinstance(raw, dict) or set(raw) != {
            "minimum_physical_cores",
            "build_jobs_per_cell",
            "ghidra_core_limit",
        }:
            raise ValueError(f"{tier_context} is incomplete or unsupported")
        minimum = _required_positive_integer(
            raw, "minimum_physical_cores", tier_context
        )
        build_jobs = _required_positive_integer(
            raw, "build_jobs_per_cell", tier_context
        )
        if build_jobs > MAX_BUILD_JOBS_PER_CELL:
            raise ValueError(
                f"{tier_context}.build_jobs_per_cell must not exceed "
                f"{MAX_BUILD_JOBS_PER_CELL}"
            )
        core_limit = _required_positive_integer(raw, "ghidra_core_limit", tier_context)
        java_options(None, core_limit, inherited="")
        cpu_tiers.append(AutomaticCpuTier(minimum, build_jobs, core_limit))
    if cpu_tiers[0].minimum_physical_cores != 1 or any(
        left.minimum_physical_cores >= right.minimum_physical_cores
        for left, right in zip(cpu_tiers, cpu_tiers[1:])
    ):
        raise ValueError(f"{context}.cpu_tiers must start at one and increase")

    return AutomaticPolicy(
        selector_version=_required_string(table, "selector_version", context),
        maximum_workers=maximum_workers,
        physical_core_weight=physical_weight,
        smt_sibling_weight=smt_weight,
        memory_reserve_fraction=reserve_fraction,
        memory_reserve_min_mib=_required_positive_integer(
            table, "memory_reserve_min_mib", context
        ),
        per_worker_min_mib=_required_positive_integer(
            table, "per_worker_min_mib", context
        ),
        memory_basis=_required_string(table, "memory_basis", context),
        live_pressure=_required_string(table, "live_pressure", context),
        memory_tiers=tuple(memory_tiers),
        cpu_tiers=tuple(cpu_tiers),
    )


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
        "architecture": _required_string(table, "architecture", f"{context}.host"),
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
    heap = _optional_positive_integer(table, "ghidra_heap_mib", f"{context}.settings")
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
    expected = {"schema_version", "default_profile", "automatic_policy", "profiles"}
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
            if (
                evidence == root
                or root not in evidence.parents
                or not evidence.is_file()
            ):
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
        automatic_policy=_load_automatic_policy(document.get("automatic_policy")),
        profiles=tuple(profiles),
    )
