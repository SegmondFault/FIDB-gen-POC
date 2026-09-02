"""Validated JVM resource policy shared by width runs and benchmarks."""

from __future__ import annotations

import os
import re
import shlex

DEFAULT_WIDTH_GHIDRA_HEAP_MIB = 4096
MIN_GHIDRA_HEAP_MIB = 1024
MAX_GHIDRA_HEAP_MIB = 32768
MAX_GHIDRA_CORE_LIMIT = 32

_HEAP_OPTION = re.compile(r"^-Xmx(?P<amount>[1-9][0-9]*)(?P<unit>[kKmMgG]?)$")


def _heap_mib(option: str) -> int | None:
    match = _HEAP_OPTION.fullmatch(option)
    if match is None:
        return None
    amount = int(match.group("amount"))
    unit = match.group("unit").lower()
    if unit == "g":
        return amount * 1024
    if unit in {"", "k"}:
        divisor = 1024**2 if unit == "" else 1024
        if amount % divisor:
            raise ValueError(f"JVM maximum heap is not a whole MiB: {option}")
        return amount // divisor
    return amount


def java_options(
    heap_mib: int | None,
    core_limit: int | None,
    *,
    inherited: str | None = None,
) -> str:
    """Add explicit bounds without duplicating or overriding caller policy.

    ``heap_mib=None`` deliberately preserves an inherited maximum heap or
    Java's ergonomic default.  An equivalent inherited bound is accepted;
    conflicting bounds fail closed so the evidence records one unambiguous
    policy.
    """

    source = os.environ.get("JAVA_TOOL_OPTIONS", "") if inherited is None else inherited
    source = source.strip()
    parsed = shlex.split(source)
    existing_heaps = [item for item in parsed if item.startswith("-Xmx")]
    if len(existing_heaps) > 1:
        raise ValueError("JAVA_TOOL_OPTIONS contains multiple -Xmx settings")
    if heap_mib is not None:
        if heap_mib < MIN_GHIDRA_HEAP_MIB or heap_mib > MAX_GHIDRA_HEAP_MIB:
            raise ValueError(
                f"Ghidra heap must be between {MIN_GHIDRA_HEAP_MIB} and "
                f"{MAX_GHIDRA_HEAP_MIB} MiB"
            )
        if existing_heaps:
            inherited_heap = _heap_mib(existing_heaps[0])
            if inherited_heap is None:
                raise ValueError(
                    f"unsupported inherited JVM maximum heap: {existing_heaps[0]}"
                )
            if inherited_heap != heap_mib:
                raise ValueError(
                    "inherited JVM maximum heap conflicts with requested bound: "
                    f"{inherited_heap} MiB != {heap_mib} MiB"
                )
        else:
            parsed.append(f"-Xmx{heap_mib}m")

    existing_core_limits = [
        item
        for item in parsed
        if item.startswith("-Dcpu.core.limit=")
        or item.startswith("-Dcpu.core.override=")
    ]
    if len(existing_core_limits) > 1:
        raise ValueError("JAVA_TOOL_OPTIONS contains multiple Ghidra CPU limits")
    if core_limit is not None:
        if core_limit < 1 or core_limit > MAX_GHIDRA_CORE_LIMIT:
            raise ValueError(
                f"Ghidra core limit must be between 1 and {MAX_GHIDRA_CORE_LIMIT}"
            )
        if existing_core_limits:
            try:
                inherited_limit = int(existing_core_limits[0].split("=", 1)[1])
            except (IndexError, ValueError) as error:
                raise ValueError(
                    f"invalid inherited Ghidra CPU limit: {existing_core_limits[0]}"
                ) from error
            if inherited_limit != core_limit:
                raise ValueError(
                    "inherited Ghidra CPU limit conflicts with requested bound: "
                    f"{inherited_limit} != {core_limit}"
                )
        else:
            parsed.append(f"-Dcpu.core.limit={core_limit}")
    return " ".join(parsed)
