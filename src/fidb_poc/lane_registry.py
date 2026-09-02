"""Validated analyst-facing lane and query-sublane authority."""

from __future__ import annotations

from pathlib import Path
import re
import tomllib

from .target_registry import load_targets


LANE_SCHEMA = "fidb-lanes/v1"
LANE_STATES = {"experimental", "active", "retired"}
SUBLANE_STATES = {"mapped", "unresolved"}
_TOKEN = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_POLICY_FIELDS = {
    "id",
    "ghidra_version",
    "ghidra_release",
    "ghidra_build",
    "analysis_profile",
    "fid_algorithm",
}
_LANE_FIELDS = {
    "id",
    "label",
    "platform",
    "architecture_family",
    "state",
    "description",
    "sublane",
}
_SUBLANE_FIELDS = {
    "id",
    "target_id",
    "policy_id",
    "definition_state",
    "ghidra_language_ids",
    "compiler_spec_ids",
}


def _table_fields(
    row: dict[str, object], expected: set[str], label: str
) -> None:
    unknown = set(row) - expected
    missing = expected - set(row)
    if unknown or missing:
        details = []
        if missing:
            details.append(f"missing {sorted(missing)}")
        if unknown:
            details.append(f"unknown {sorted(unknown)}")
        raise ValueError(f"{label}: {', '.join(details)}")


def _token(value: object, label: str) -> str:
    result = str(value)
    if not _TOKEN.fullmatch(result):
        raise ValueError(f"{label} must be a lowercase hyphenated token")
    return result


def _strings(value: object, label: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        raise ValueError(f"{label} must be a{' possibly empty' if allow_empty else ' non-empty'} list")
    if not all(isinstance(item, str) and item == item.strip() and item for item in value):
        raise ValueError(f"{label} must contain non-empty strings without outer whitespace")
    if len(set(value)) != len(value):
        raise ValueError(f"{label} contains duplicates")
    return list(value)


def load_lane_registry(
    path: str | Path, target_path: str | Path
) -> dict[str, object]:
    """Load a closed-schema lane registry and join its referenced targets."""

    registry_path = Path(path)
    document = tomllib.loads(registry_path.read_text(encoding="utf-8"))
    if set(document) != {"schema_version", "policy", "lane"}:
        raise ValueError(
            "lane registry must contain only schema_version, policy and lane"
        )
    if document["schema_version"] != LANE_SCHEMA:
        raise ValueError(f"unsupported lane registry schema: {document['schema_version']}")

    raw_policies = document["policy"]
    if not isinstance(raw_policies, list) or not raw_policies:
        raise ValueError("lane registry must contain at least one FID policy")
    policies: list[dict[str, object]] = []
    policy_ids: set[str] = set()
    for index, raw in enumerate(raw_policies):
        if not isinstance(raw, dict):
            raise ValueError(f"policy row {index} must be a table")
        _table_fields(raw, _POLICY_FIELDS, f"policy row {index}")
        row = dict(raw)
        policy_id = _token(row["id"], f"policy row {index} id")
        if policy_id in policy_ids:
            raise ValueError(f"duplicate policy id: {policy_id}")
        policy_ids.add(policy_id)
        for field in _POLICY_FIELDS - {"id"}:
            value = row[field]
            if not isinstance(value, str) or not value or value != value.strip():
                raise ValueError(f"policy {policy_id} {field} must be a non-empty string")
        row["id"] = policy_id
        policies.append(row)

    targets = load_targets(target_path)
    targets_by_id = {str(row["id"]): row for row in targets}
    raw_lanes = document["lane"]
    if not isinstance(raw_lanes, list) or not raw_lanes:
        raise ValueError("lane registry must contain at least one lane")
    lanes: list[dict[str, object]] = []
    lane_ids: set[str] = set()
    sublane_ids: set[str] = set()
    mapped_targets: set[str] = set()
    for lane_index, raw_lane in enumerate(raw_lanes):
        if not isinstance(raw_lane, dict):
            raise ValueError(f"lane row {lane_index} must be a table")
        _table_fields(raw_lane, _LANE_FIELDS, f"lane row {lane_index}")
        lane = dict(raw_lane)
        lane_id = _token(lane["id"], f"lane row {lane_index} id")
        if lane_id in lane_ids:
            raise ValueError(f"duplicate lane id: {lane_id}")
        lane_ids.add(lane_id)
        if lane["state"] not in LANE_STATES:
            raise ValueError(f"invalid state for lane {lane_id}")
        for field in ("label", "platform", "architecture_family", "description"):
            value = lane[field]
            if not isinstance(value, str) or not value or value != value.strip():
                raise ValueError(f"lane {lane_id} {field} must be a non-empty string")

        raw_sublanes = lane["sublane"]
        if not isinstance(raw_sublanes, list) or not raw_sublanes:
            raise ValueError(f"lane {lane_id} must contain at least one sublane")
        sublanes: list[dict[str, object]] = []
        for sublane_index, raw_sublane in enumerate(raw_sublanes):
            if not isinstance(raw_sublane, dict):
                raise ValueError(
                    f"lane {lane_id} sublane row {sublane_index} must be a table"
                )
            label = f"lane {lane_id} sublane row {sublane_index}"
            _table_fields(raw_sublane, _SUBLANE_FIELDS, label)
            sublane = dict(raw_sublane)
            sublane_id = _token(sublane["id"], f"{label} id")
            if sublane_id in sublane_ids:
                raise ValueError(f"duplicate sublane id: {sublane_id}")
            sublane_ids.add(sublane_id)
            target_id = str(sublane["target_id"])
            target = targets_by_id.get(target_id)
            if target is None:
                raise ValueError(
                    f"sublane {sublane_id} references unknown target {target_id}"
                )
            if target["platform"] != lane["platform"]:
                raise ValueError(
                    f"sublane {sublane_id} target platform differs from lane {lane_id}"
                )
            if target_id in mapped_targets:
                raise ValueError(f"target appears in multiple sublanes: {target_id}")
            mapped_targets.add(target_id)
            policy_id = str(sublane["policy_id"])
            if policy_id not in policy_ids:
                raise ValueError(
                    f"sublane {sublane_id} references unknown policy {policy_id}"
                )
            definition_state = str(sublane["definition_state"])
            if definition_state not in SUBLANE_STATES:
                raise ValueError(f"invalid definition_state for sublane {sublane_id}")
            languages = _strings(
                sublane["ghidra_language_ids"],
                f"sublane {sublane_id} ghidra_language_ids",
                allow_empty=definition_state == "unresolved",
            )
            compiler_specs = _strings(
                sublane["compiler_spec_ids"],
                f"sublane {sublane_id} compiler_spec_ids",
                allow_empty=definition_state == "unresolved",
            )
            if definition_state == "mapped" and (not languages or not compiler_specs):
                raise ValueError(
                    f"mapped sublane {sublane_id} requires Ghidra language and compiler specs"
                )
            sublanes.append(
                {
                    **sublane,
                    "id": sublane_id,
                    "ghidra_language_ids": languages,
                    "compiler_spec_ids": compiler_specs,
                    "target": dict(target),
                }
            )
        lanes.append({**lane, "id": lane_id, "sublanes": sublanes})

    missing_targets = set(targets_by_id) - mapped_targets
    if missing_targets:
        raise ValueError(
            "lane registry omits target definitions: " + ", ".join(sorted(missing_targets))
        )
    return {
        "schema_version": LANE_SCHEMA,
        "policies": policies,
        "lanes": lanes,
    }


def resolve_target_sublane(
    registry: dict[str, object],
    target_id: str,
) -> tuple[dict[str, object], dict[str, object]]:
    """Resolve one reviewed target to its broad lane and exact sublane."""

    matches = [
        (lane, sublane)
        for lane in registry["lanes"]
        for sublane in lane["sublanes"]
        if sublane["target_id"] == target_id
    ]
    if len(matches) != 1:
        raise ValueError(
            f"target {target_id} resolves to {len(matches)} lane sublanes, expected one"
        )
    return matches[0]


def resolve_program_sublanes(
    registry: dict[str, object],
    *,
    platform: str | None = None,
    binary_format: str | None = None,
    architecture: str | None = None,
    machine: str | None = None,
    bits: int | None = None,
    endianness: str | None = None,
    ghidra_language_id: str | None = None,
    compiler_spec_id: str | None = None,
    include_unresolved: bool = True,
) -> dict[str, object]:
    """Resolve inspected program facts without requiring a user to pick a sublane.

    The caller supplies whichever facts its binary loader and Ghidra program have
    established.  Partial facts intentionally return every compatible candidate;
    ambiguity is data for the integration to resolve, never permission to guess.
    """

    selectors = {
        "platform": platform,
        "binary_format": binary_format,
        "architecture": architecture,
        "machine": machine,
        "bits": bits,
        "endianness": endianness,
        "ghidra_language_id": ghidra_language_id,
        "compiler_spec_id": compiler_spec_id,
    }
    if not any(value is not None for value in selectors.values()):
        raise ValueError("at least one inspected program fact is required")
    if bits is not None and bits not in {32, 64}:
        raise ValueError("bits must be 32 or 64")

    candidates: list[dict[str, object]] = []
    for lane in registry["lanes"]:
        if platform is not None and lane["platform"] != platform:
            continue
        for sublane in lane["sublanes"]:
            if not include_unresolved and sublane["definition_state"] != "mapped":
                continue
            target = sublane["target"]
            target_selectors = {
                "binary_format": binary_format,
                "architecture": architecture,
                "machine": machine,
                "bits": bits,
                "endianness": endianness,
            }
            if any(
                value is not None and target[field] != value
                for field, value in target_selectors.items()
            ):
                continue
            if (
                ghidra_language_id is not None
                and ghidra_language_id not in sublane["ghidra_language_ids"]
            ):
                continue
            if (
                compiler_spec_id is not None
                and compiler_spec_id not in sublane["compiler_spec_ids"]
            ):
                continue
            candidates.append(
                {
                    "lane_id": lane["id"],
                    "lane_label": lane["label"],
                    "lane_state": lane["state"],
                    "sublane_id": sublane["id"],
                    "definition_state": sublane["definition_state"],
                    "policy_id": sublane["policy_id"],
                    "target_id": sublane["target_id"],
                    "target": dict(target),
                    "ghidra_language_ids": list(sublane["ghidra_language_ids"]),
                    "compiler_spec_ids": list(sublane["compiler_spec_ids"]),
                }
            )

    return {
        "schema_version": "fidb-lane-resolution/v1",
        "state": (
            "unsupported"
            if not candidates
            else "exact" if len(candidates) == 1 else "ambiguous"
        ),
        "selectors": selectors,
        "candidates": candidates,
    }
