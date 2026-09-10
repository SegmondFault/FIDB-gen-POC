"""Reviewed, provenance-bound policies for native FID construction."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import tomllib

from .config import Library, Route, Treatment
from .validation_analysis import (
    FID_BUILD_ANALYSIS_POLICY,
    FID_BUILD_RELOCATABLE_GCC_EXCEPTION_DISABLED_POLICY,
    GHIDRA_DEFAULT_DIAGNOSTIC_POLICY,
    GHIDRA_LSDA_BURST_DIAGNOSTIC_POLICY,
)

SCHEMA = "fidb-fid-build-policy/v1"
DEFAULT_PATH = Path("performance/fid-build-analysis.toml")
_TOP_LEVEL_FIELDS = {
    "schema_version",
    "default_analysis_policy",
    "default_diagnostic_policy",
    "rule",
}
_RULE_FIELDS = {
    "id",
    "enabled",
    "libraries",
    "route_prefixes",
    "artifact_shapes",
    "analysis_policy",
    "diagnostic_policy",
}
_ANALYSIS_POLICIES = {
    FID_BUILD_ANALYSIS_POLICY,
    FID_BUILD_RELOCATABLE_GCC_EXCEPTION_DISABLED_POLICY,
}
_DIAGNOSTIC_POLICIES = {
    GHIDRA_DEFAULT_DIAGNOSTIC_POLICY,
    GHIDRA_LSDA_BURST_DIAGNOSTIC_POLICY,
}


@dataclass(frozen=True)
class FidBuildPolicyRule:
    id: str
    enabled: bool
    libraries: tuple[str, ...]
    route_prefixes: tuple[str, ...]
    artifact_shapes: tuple[str, ...]
    analysis_policy: str
    diagnostic_policy: str

    def matches(self, library: Library, route: Route, treatment: Treatment) -> bool:
        return (
            self.enabled
            and (library.name in self.libraries or library.identifier in self.libraries)
            and any(route.id.startswith(prefix) for prefix in self.route_prefixes)
            and treatment.artifact_shape in self.artifact_shapes
        )


@dataclass(frozen=True)
class FidBuildPolicySelection:
    rule_id: str
    analysis_policy: str
    diagnostic_policy: str
    authority_path: str
    authority_sha256: str


@dataclass(frozen=True)
class FidBuildPolicyAuthority:
    default_analysis_policy: str
    default_diagnostic_policy: str
    rules: tuple[FidBuildPolicyRule, ...]
    authority_path: str
    authority_sha256: str

    def select(
        self, library: Library, route: Route, treatment: Treatment
    ) -> FidBuildPolicySelection:
        matches = [
            rule for rule in self.rules if rule.matches(library, route, treatment)
        ]
        if len(matches) > 1:
            raise ValueError(
                "multiple FID-build policy rules match "
                f"{library.identifier}/{route.id}/{treatment.id}: "
                + ", ".join(rule.id for rule in matches)
            )
        rule = matches[0] if matches else None
        return FidBuildPolicySelection(
            rule_id=rule.id if rule else "default",
            analysis_policy=(
                rule.analysis_policy if rule else self.default_analysis_policy
            ),
            diagnostic_policy=(
                rule.diagnostic_policy if rule else self.default_diagnostic_policy
            ),
            authority_path=self.authority_path,
            authority_sha256=self.authority_sha256,
        )


def _strings(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"FID-build policy {field} must be a non-empty array")
    result = tuple(str(item) for item in value)
    if any(not item for item in result) or len(set(result)) != len(result):
        raise ValueError(f"FID-build policy {field} must contain unique text values")
    return result


def _validate_policy(value: object, allowed: set[str], field: str) -> str:
    policy = str(value)
    if policy not in allowed:
        raise ValueError(f"unsupported FID-build {field}: {policy}")
    return policy


def load_fid_build_policy(
    project_root: Path, path: Path = DEFAULT_PATH
) -> FidBuildPolicyAuthority:
    """Load one strict TOML authority without allowing it to escape the project."""

    root = project_root.expanduser().resolve()
    source = path if path.is_absolute() else root / path
    source = source.resolve()
    try:
        relative = source.relative_to(root)
    except ValueError as error:
        raise ValueError("FID-build policy authority escaped the project") from error
    raw = tomllib.loads(source.read_text(encoding="utf-8"))
    if set(raw) != _TOP_LEVEL_FIELDS:
        raise ValueError("FID-build policy authority has unsupported or missing fields")
    if raw["schema_version"] != SCHEMA:
        raise ValueError("unsupported FID-build policy schema")
    default_analysis = _validate_policy(
        raw["default_analysis_policy"], _ANALYSIS_POLICIES, "analysis policy"
    )
    default_diagnostics = _validate_policy(
        raw["default_diagnostic_policy"],
        _DIAGNOSTIC_POLICIES,
        "diagnostic policy",
    )
    rows = raw["rule"]
    if not isinstance(rows, list):
        raise ValueError("FID-build policy rule must be an array of tables")
    rules = []
    identifiers = set()
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, dict) or set(row) != _RULE_FIELDS:
            raise ValueError(
                f"FID-build policy rule {index} is incomplete or unsupported"
            )
        identifier = str(row["id"])
        if not identifier or identifier in identifiers:
            raise ValueError("FID-build policy rules need unique non-empty ids")
        if not isinstance(row["enabled"], bool):
            raise ValueError(
                f"FID-build policy rule {identifier} enabled must be boolean"
            )
        identifiers.add(identifier)
        rules.append(
            FidBuildPolicyRule(
                id=identifier,
                enabled=row["enabled"],
                libraries=_strings(row["libraries"], f"rule {identifier} libraries"),
                route_prefixes=_strings(
                    row["route_prefixes"], f"rule {identifier} route_prefixes"
                ),
                artifact_shapes=_strings(
                    row["artifact_shapes"], f"rule {identifier} artifact_shapes"
                ),
                analysis_policy=_validate_policy(
                    row["analysis_policy"], _ANALYSIS_POLICIES, "analysis policy"
                ),
                diagnostic_policy=_validate_policy(
                    row["diagnostic_policy"],
                    _DIAGNOSTIC_POLICIES,
                    "diagnostic policy",
                ),
            )
        )
    return FidBuildPolicyAuthority(
        default_analysis_policy=default_analysis,
        default_diagnostic_policy=default_diagnostics,
        rules=tuple(rules),
        authority_path=str(relative),
        authority_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
    )
