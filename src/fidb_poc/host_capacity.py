"""Host topology detection and reproducible automatic performance resolution.

Detection is deliberately separate from execution.  Callers receive both the
raw, inspectable host facts and the exact settings derived from them, so an
``auto`` run can retain the effective policy rather than relying on a label.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import os
from pathlib import Path
import platform
import subprocess
from typing import Iterable

from .performance_profiles import PerformanceSettings

HOST_CAPACITY_SCHEMA = "fidb-host-capacity/v1"
AUTO_PERFORMANCE_SCHEMA = "fidb-auto-performance/v1"
AUTO_SELECTOR_VERSION = "physical-smt-memory-v1"
GIB = 1024**3


@dataclass(frozen=True)
class HostCapacity:
    system: str
    architecture: str
    physical_cores: int
    logical_cpus: int
    smt_siblings: int
    threads_per_core: float
    total_memory_bytes: int
    available_memory_bytes: int
    memory_model: str
    cpu_affinity_limited: bool
    cgroup_cpu_quota: float | None
    cgroup_memory_limit_bytes: int | None
    sources: dict[str, str]

    def document(self) -> dict[str, object]:
        return {
            "schema_version": HOST_CAPACITY_SCHEMA,
            "system": self.system,
            "architecture": self.architecture,
            "physical_cores": self.physical_cores,
            "logical_cpus": self.logical_cpus,
            "smt_siblings": self.smt_siblings,
            "threads_per_core": round(self.threads_per_core, 3),
            "total_memory_mib": self.total_memory_bytes // 1024**2,
            "available_memory_mib": self.available_memory_bytes // 1024**2,
            "memory_model": self.memory_model,
            "cpu_affinity_limited": self.cpu_affinity_limited,
            "cgroup_cpu_quota": self.cgroup_cpu_quota,
            "cgroup_memory_limit_mib": (
                self.cgroup_memory_limit_bytes // 1024**2
                if self.cgroup_memory_limit_bytes is not None
                else None
            ),
            "sources": dict(self.sources),
        }


@dataclass(frozen=True)
class AutomaticPerformance:
    host: HostCapacity
    settings: PerformanceSettings
    cpu_worker_bound: int
    memory_worker_bound: int
    memory_reserve_bytes: int
    per_worker_budget_bytes: int

    def document(self) -> dict[str, object]:
        return {
            "schema_version": AUTO_PERFORMANCE_SCHEMA,
            "selector_version": AUTO_SELECTOR_VERSION,
            "profile_id": "auto",
            "host": self.host.document(),
            "effective_settings": self.settings.document(),
            "bounds": {
                "cpu_workers": self.cpu_worker_bound,
                "memory_workers": self.memory_worker_bound,
                "memory_reserve_mib": self.memory_reserve_bytes // 1024**2,
                "per_worker_budget_mib": self.per_worker_budget_bytes // 1024**2,
                "maximum_workers": 32,
            },
            "policy": {
                "physical_core_weight": 1.0,
                "smt_sibling_weight": 0.25,
                "memory_basis": "effective-total",
                "live_pressure": "enforced-separately-by-resource-gates",
            },
        }


def _read_integer(path: Path) -> int | None:
    try:
        value = int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    return value if value >= 0 else None


def _linux_meminfo(path: Path) -> tuple[int, int] | None:
    try:
        rows = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    values: dict[str, int] = {}
    for row in rows:
        fields = row.split()
        if len(fields) >= 2 and fields[0] in {"MemTotal:", "MemAvailable:"}:
            try:
                values[fields[0]] = int(fields[1]) * 1024
            except ValueError:
                return None
    if "MemTotal:" not in values:
        return None
    total = values["MemTotal:"]
    return total, values.get("MemAvailable:", total)


def _linux_physical_cores(sys_cpu_root: Path, cpus: Iterable[int]) -> int | None:
    cores: set[tuple[int, int]] = set()
    for cpu in cpus:
        topology = sys_cpu_root / f"cpu{cpu}" / "topology"
        package = _read_integer(topology / "physical_package_id")
        core = _read_integer(topology / "core_id")
        if package is None or core is None:
            return None
        cores.add((package, core))
    return len(cores) or None


def _linux_cpu_quota(cgroup_root: Path) -> float | None:
    try:
        fields = (cgroup_root / "cpu.max").read_text(encoding="utf-8").split()
    except OSError:
        return None
    if len(fields) != 2 or fields[0] == "max":
        return None
    try:
        quota, period = int(fields[0]), int(fields[1])
    except ValueError:
        return None
    if quota < 1 or period < 1:
        return None
    return round(quota / period, 3)


def _linux_cgroup_memory(cgroup_root: Path) -> tuple[int | None, int | None]:
    try:
        raw_limit = (cgroup_root / "memory.max").read_text(encoding="utf-8").strip()
    except OSError:
        return None, None
    if raw_limit == "max":
        return None, None
    try:
        limit = int(raw_limit)
    except ValueError:
        return None, None
    current = _read_integer(cgroup_root / "memory.current")
    return (limit if limit > 0 else None), current


def _sysctl_integer(name: str) -> int | None:
    try:
        result = subprocess.run(
            ["/usr/sbin/sysctl", "-n", name],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        )
        return int(result.stdout.strip())
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def detect_host_capacity(
    *,
    proc_meminfo: Path = Path("/proc/meminfo"),
    sys_cpu_root: Path = Path("/sys/devices/system/cpu"),
    cgroup_root: Path = Path("/sys/fs/cgroup"),
) -> HostCapacity:
    """Detect scheduler-visible CPUs and usable main memory.

    Linux CPU affinity and cgroup ceilings are honoured.  On integrated-GPU
    systems this intentionally uses memory visible to the OS; it does not
    guess at firmware-reserved VRAM from nominal DIMM capacity.
    """

    system = platform.system().lower() or "unknown"
    architecture = platform.machine().lower() or "unknown"
    installed_logical = max(1, os.cpu_count() or 1)
    try:
        visible_cpus = sorted(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        visible_cpus = list(range(installed_logical))
    if not visible_cpus:
        visible_cpus = [0]
    logical = len(visible_cpus)
    affinity_limited = logical < installed_logical
    sources = {
        "logical_cpus": (
            "sched_getaffinity" if hasattr(os, "sched_getaffinity") else "os.cpu_count"
        ),
    }

    physical = None
    total = available = None
    quota = None
    cgroup_limit = cgroup_current = None
    if system == "linux":
        physical = _linux_physical_cores(sys_cpu_root, visible_cpus)
        sources["physical_cores"] = (
            "linux-sysfs-topology" if physical else "logical-fallback"
        )
        memory = _linux_meminfo(proc_meminfo)
        if memory is not None:
            total, available = memory
            sources["memory"] = "proc-meminfo"
        quota = _linux_cpu_quota(cgroup_root)
        cgroup_limit, cgroup_current = _linux_cgroup_memory(cgroup_root)
    elif system == "darwin":
        physical = _sysctl_integer("hw.physicalcpu")
        sysctl_logical = _sysctl_integer("hw.logicalcpu")
        if sysctl_logical:
            logical = min(logical, sysctl_logical)
        total = _sysctl_integer("hw.memsize")
        available = total
        sources["physical_cores"] = (
            "sysctl-hw.physicalcpu" if physical else "logical-fallback"
        )
        sources["memory"] = "sysctl-hw.memsize" if total else "sysconf-fallback"

    physical = max(1, min(logical, physical or logical))
    if total is None:
        try:
            total = int(os.sysconf("SC_PHYS_PAGES")) * int(os.sysconf("SC_PAGE_SIZE"))
        except (OSError, ValueError):
            total = 8 * GIB
        available = total
        sources.setdefault("memory", "sysconf-or-conservative-fallback")
    assert available is not None
    if cgroup_limit is not None and cgroup_limit < total:
        total = cgroup_limit
        if cgroup_current is not None:
            available = min(available, max(0, cgroup_limit - cgroup_current))
        sources["memory_limit"] = "cgroup-v2"

    if quota is not None and quota < logical:
        quota_logical = max(1, math.ceil(quota))
        logical = min(logical, quota_logical)
        physical = min(physical, logical)
        sources["cpu_limit"] = "cgroup-v2"

    smt = max(0, logical - physical)
    memory_model = (
        "unified"
        if system == "darwin" and architecture in {"arm64", "aarch64"}
        else "dedicated-system-memory"
    )
    return HostCapacity(
        system=system,
        architecture=architecture,
        physical_cores=physical,
        logical_cpus=logical,
        smt_siblings=smt,
        threads_per_core=logical / physical,
        total_memory_bytes=total,
        available_memory_bytes=min(total, available),
        memory_model=memory_model,
        cpu_affinity_limited=affinity_limited,
        cgroup_cpu_quota=quota,
        cgroup_memory_limit_bytes=cgroup_limit,
        sources=sources,
    )


def resolve_automatic_performance(host: HostCapacity) -> AutomaticPerformance:
    """Derive a conservative cross-library policy from one host snapshot."""

    total_gib = host.total_memory_bytes / GIB
    if total_gib < 12:
        heap_mib = 2048
    elif total_gib < 24:
        heap_mib = 3072
    else:
        heap_mib = 4096

    build_jobs = (
        4 if host.physical_cores >= 12 else 2 if host.physical_cores >= 4 else 1
    )
    core_limit = 4 if host.physical_cores >= 8 else 2 if host.physical_cores >= 4 else 1
    cpu_bound = min(
        host.logical_cpus,
        host.physical_cores + math.ceil(host.smt_siblings * 0.25),
    )
    reserve = max(4 * GIB, math.ceil(host.total_memory_bytes * 0.10))
    per_worker = max(4 * GIB, heap_mib * 1024**2)
    memory_bound = max(1, (max(0, host.total_memory_bytes - reserve)) // per_worker)
    workers = max(1, min(32, cpu_bound, memory_bound))
    settings = PerformanceSettings(
        worker_mode="fixed",
        workers=workers,
        build_jobs_per_cell=build_jobs,
        ghidra_heap_mib=heap_mib,
        ghidra_core_limit=core_limit,
    )
    return AutomaticPerformance(
        host=host,
        settings=settings,
        cpu_worker_bound=cpu_bound,
        memory_worker_bound=memory_bound,
        memory_reserve_bytes=reserve,
        per_worker_budget_bytes=per_worker,
    )
