"""Reviewed host-capacity selection for linked-reference Ghidra workers."""

from __future__ import annotations

import hashlib
from pathlib import Path
import tomllib
from typing import Mapping

from .host_capacity import HostCapacity, detect_host_capacity

SCHEMA = "fidb-linked-reference-performance/v1"
DEFAULT_AUTHORITY = Path("performance/linked-reference.toml")
QUALIFICATIONS = {"measured-c10", "capacity-qualified", "experimental"}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inside(root: Path, value: str | Path) -> Path:
    path = (root / value).resolve()
    if path != root and root not in path.parents:
        raise ValueError("linked-reference performance authority escapes project root")
    return path


def load_linked_reference_performance(
    project_root: str | Path,
    authority: str | Path = DEFAULT_AUTHORITY,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    path = _inside(root, authority)
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if set(document) != {
        "schema_version",
        "mode",
        "fixed_profile",
        "automatic",
        "profiles",
    } or document.get("schema_version") != SCHEMA:
        raise ValueError("linked-reference performance authority is unsupported")
    if document["mode"] not in {"auto", "fixed"}:
        raise ValueError("linked-reference performance mode is invalid")
    automatic = document["automatic"]
    if not isinstance(automatic, dict) or set(automatic) != {
        "memory_reserve_mib",
        "native_overhead_per_worker_mib",
        "allowed_qualifications",
    }:
        raise ValueError("linked-reference automatic policy is invalid")
    for name in ("memory_reserve_mib", "native_overhead_per_worker_mib"):
        if type(automatic[name]) is not int or int(automatic[name]) < 1:
            raise ValueError(f"linked-reference automatic.{name} is invalid")
    allowed = automatic["allowed_qualifications"]
    if (
        not isinstance(allowed, list)
        or not allowed
        or any(value not in QUALIFICATIONS for value in allowed)
    ):
        raise ValueError("linked-reference automatic qualifications are invalid")
    profiles = document["profiles"]
    if not isinstance(profiles, list) or not profiles:
        raise ValueError("linked-reference performance profiles are absent")
    ids = set()
    normalized = []
    expected = {
        "id",
        "workers",
        "jvm_initial_heap_mib",
        "jvm_max_heap_mib",
        "jvm_active_processors",
        "minimum_physical_cores",
        "minimum_logical_cpus",
        "minimum_total_memory_mib",
        "maximum_cpu_oversubscription",
        "qualification",
        "evidence_path",
        "guidance",
    }
    for raw in profiles:
        if not isinstance(raw, dict) or set(raw) != expected:
            raise ValueError("linked-reference performance profile is unsupported")
        profile_id = str(raw["id"])
        if not profile_id or profile_id in ids:
            raise ValueError("linked-reference performance profile id is invalid")
        ids.add(profile_id)
        for name in (
            "workers",
            "jvm_initial_heap_mib",
            "jvm_max_heap_mib",
            "jvm_active_processors",
            "minimum_physical_cores",
            "minimum_logical_cpus",
            "minimum_total_memory_mib",
        ):
            if type(raw[name]) is not int or int(raw[name]) < 1:
                raise ValueError(f"linked-reference profile {profile_id}.{name} is invalid")
        if int(raw["workers"]) > 16:
            raise ValueError("linked-reference worker count exceeds the reviewed bound")
        if int(raw["jvm_initial_heap_mib"]) > int(raw["jvm_max_heap_mib"]):
            raise ValueError("linked-reference initial heap exceeds maximum heap")
        oversubscription = raw["maximum_cpu_oversubscription"]
        if (
            not isinstance(oversubscription, (int, float))
            or isinstance(oversubscription, bool)
            or not 1 <= float(oversubscription) <= 2
        ):
            raise ValueError("linked-reference CPU oversubscription is invalid")
        if raw["qualification"] not in QUALIFICATIONS:
            raise ValueError("linked-reference profile qualification is invalid")
        if not str(raw["guidance"]).strip():
            raise ValueError("linked-reference profile guidance is empty")
        evidence_path = raw["evidence_path"]
        if not isinstance(evidence_path, str):
            raise ValueError("linked-reference profile evidence path is invalid")
        if evidence_path:
            _inside(root, evidence_path)
        normalized.append({**raw, "evidence_path": evidence_path or None})
    fixed_profile = str(document["fixed_profile"])
    if fixed_profile not in ids:
        raise ValueError("linked-reference fixed profile is unknown")
    return {
        **document,
        "profiles": normalized,
        "authority_path": str(path.relative_to(root)),
        "authority_sha256": _sha256(path),
    }


def _profile_blockers(
    profile: Mapping[str, object],
    host: HostCapacity,
    *,
    reserve_mib: int,
    native_overhead_mib: int,
) -> list[str]:
    blockers = []
    if host.physical_cores < int(profile["minimum_physical_cores"]):
        blockers.append("physical-core floor not met")
    if host.logical_cpus < int(profile["minimum_logical_cpus"]):
        blockers.append("logical-CPU floor not met")
    if host.total_memory_bytes // 1024**2 < int(profile["minimum_total_memory_mib"]):
        blockers.append("OS-visible memory floor not met")
    processor_demand = int(profile["workers"]) * int(profile["jvm_active_processors"])
    allowed_demand = host.logical_cpus * float(profile["maximum_cpu_oversubscription"])
    if processor_demand > allowed_demand:
        blockers.append("JVM processor demand exceeds reviewed oversubscription")
    working_set = int(profile["workers"]) * (
        int(profile["jvm_max_heap_mib"]) + native_overhead_mib
    )
    if working_set + reserve_mib > host.available_memory_bytes // 1024**2:
        blockers.append("current available memory cannot cover workers plus reserve")
    return blockers


def resolve_linked_reference_performance(
    project_root: str | Path,
    authority: str | Path = DEFAULT_AUTHORITY,
    *,
    host: HostCapacity | None = None,
) -> dict[str, object]:
    root = Path(project_root).expanduser().resolve()
    config = load_linked_reference_performance(root, authority)
    detected = host or detect_host_capacity()
    automatic = config["automatic"]
    candidates = []
    for profile in config["profiles"]:
        blockers = _profile_blockers(
            profile,
            detected,
            reserve_mib=int(automatic["memory_reserve_mib"]),
            native_overhead_mib=int(automatic["native_overhead_per_worker_mib"]),
        )
        candidates.append({**profile, "eligible": not blockers, "blockers": blockers})
    if config["mode"] == "fixed":
        selected = next(
            row for row in candidates if row["id"] == config["fixed_profile"]
        )
    else:
        allowed = set(automatic["allowed_qualifications"])
        eligible = [
            row
            for row in candidates
            if row["eligible"] and row["qualification"] in allowed
        ]
        selected = max(eligible, key=lambda row: int(row["workers"])) if eligible else None
    blockers = [] if selected is not None and selected["eligible"] else (
        list(selected["blockers"]) if selected is not None else ["no automatic profile fits this host"]
    )
    return {
        "schema_version": "fidb-linked-reference-performance-resolution/v1",
        "state": "ready" if not blockers else "blocked",
        "mode": config["mode"],
        "authority_path": config["authority_path"],
        "authority_sha256": config["authority_sha256"],
        "host": detected.document(),
        "selected_profile": selected,
        "profiles": candidates,
        "blockers": blockers,
    }
