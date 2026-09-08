"""TOML-authoritative operational campaign selection.

Campaign programmes describe scientific intent.  This module binds one
operational slice to one queue and one durable ledger without rewriting either
authority.  Selection is deliberately separate, local state under ``var/``.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import tomllib
from typing import Mapping, Sequence

from .coordinator import Coordinator
from .coordinator_config import QueueConfig

REGISTRY_SCHEMA = "fidb-campaign-registry/v1"
SELECTION_SCHEMA = "fidb-campaign-selection/v1"
STATUS_SCHEMA = "fidb-campaign-registry-status/v1"
DEFAULT_REGISTRY = Path("operations/campaigns.toml")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_STATES = {"configured", "planned", "retired"}


@dataclass(frozen=True)
class CampaignBinding:
    id: str
    label: str
    family_id: str
    slice_id: str
    host: str
    state: str
    phase: str
    queue_path: Path | None
    queue_ref: str | None
    ledger_path: Path
    ledger_ref: str
    programme_ref: str | None
    priority_ref: str | None
    authority_digests: Mapping[str, str]
    priority_subjects: int
    digest: str

    @property
    def selectable(self) -> bool:
        return self.state == "configured" and self.queue_path is not None


@dataclass(frozen=True)
class CampaignRegistry:
    root: Path
    source_path: Path
    source_ref: str
    default_campaign: str
    selection_path: Path
    selection_ref: str
    campaigns: tuple[CampaignBinding, ...]

    def by_id(self, campaign_id: str) -> CampaignBinding:
        matches = [row for row in self.campaigns if row.id == campaign_id]
        if len(matches) != 1:
            raise ValueError(f"unknown campaign: {campaign_id}")
        return matches[0]


def _only_keys(row: Mapping[str, object], allowed: set[str], context: str) -> None:
    unknown = set(row) - allowed
    if unknown:
        raise ValueError(f"{context} contains unsupported fields: {sorted(unknown)}")


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(
            f"{context} must be a non-empty string without outer whitespace"
        )
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{context} contains control characters")
    return value


def _identifier(value: object, context: str) -> str:
    result = _text(value, context)
    if not _IDENTIFIER.fullmatch(result):
        raise ValueError(f"{context} must be a stable identifier")
    return result


def _inside(
    root: Path,
    value: object,
    context: str,
    *,
    allow_absolute: bool = False,
) -> tuple[Path, str]:
    reference = str(value) if isinstance(value, Path) else _text(value, context)
    fragment = Path(reference)
    if fragment.is_absolute() and not allow_absolute:
        raise ValueError(f"{context} must be relative to the project root")
    candidate = fragment if fragment.is_absolute() else root / fragment
    if candidate.is_symlink():
        raise ValueError(f"{context} cannot be a symlink")
    resolved = candidate.resolve()
    try:
        normalized = str(resolved.relative_to(root))
    except ValueError as error:
        raise ValueError(f"{context} escapes the project root") from error
    return resolved, normalized


def _file_authority(
    root: Path,
    value: object,
    context: str,
    *,
    allow_absolute: bool = False,
) -> tuple[Path, str]:
    path, reference = _inside(root, value, context, allow_absolute=allow_absolute)
    if not path.is_file():
        raise ValueError(f"{context} is not a file: {reference}")
    return path, reference


def _binding_digest(values: Mapping[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(values, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validate_priority_authority(path: Path) -> int:
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    _only_keys(
        document,
        {
            "schema_version",
            "id",
            "label",
            "language_id",
            "selection_basis",
            "component_policy",
            "subject",
        },
        "priority authority",
    )
    if document.get("schema_version") != "fidb-priority-overlay/v1":
        raise ValueError("priority authority has an unsupported schema_version")
    _identifier(document.get("id"), "priority authority id")
    _text(document.get("label"), "priority authority label")
    _identifier(document.get("language_id"), "priority authority language_id")
    _text(document.get("selection_basis"), "priority authority selection_basis")
    _text(document.get("component_policy"), "priority authority component_policy")
    subjects = document.get("subject")
    if not isinstance(subjects, list) or not subjects:
        raise ValueError("priority authority must contain [[subject]] rows")
    seen: set[str] = set()
    for position, raw in enumerate(subjects, start=1):
        if not isinstance(raw, dict):
            raise ValueError(f"priority subject {position} must be a table")
        _only_keys(
            raw,
            {"order", "id", "source_family", "aliases"},
            f"priority subject {position}",
        )
        if raw.get("order") != position:
            raise ValueError(
                "priority subject order must be contiguous and file-ordered"
            )
        subject_id = _identifier(raw.get("id"), f"priority subject {position} id")
        if subject_id in seen:
            raise ValueError(f"duplicate priority subject: {subject_id}")
        seen.add(subject_id)
        _identifier(
            raw.get("source_family"), f"priority subject {subject_id} source_family"
        )
        aliases = raw.get("aliases")
        if not isinstance(aliases, list) or any(
            not isinstance(alias, str) or not alias or alias != alias.strip()
            for alias in aliases
        ):
            raise ValueError(f"priority subject {subject_id} aliases must be strings")
        if len(set(aliases)) != len(aliases):
            raise ValueError(
                f"priority subject {subject_id} aliases contain duplicates"
            )
    return len(subjects)


def load_campaign_registry(
    project_root: str | Path,
    authority: str | Path = DEFAULT_REGISTRY,
) -> CampaignRegistry:
    root = Path(project_root).expanduser().resolve()
    source_path, source_ref = _file_authority(
        root, authority, "campaign registry", allow_absolute=True
    )
    document = tomllib.loads(source_path.read_text(encoding="utf-8"))
    _only_keys(
        document,
        {"schema_version", "default_campaign", "selection_state", "campaign"},
        "campaign registry",
    )
    if document.get("schema_version") != REGISTRY_SCHEMA:
        raise ValueError("campaign registry has an unsupported schema_version")
    default_campaign = _identifier(document.get("default_campaign"), "default campaign")
    selection_path, selection_ref = _inside(
        root, document.get("selection_state"), "campaign selection state"
    )
    if not Path(selection_ref).parts or Path(selection_ref).parts[0] != "var":
        raise ValueError("campaign selection state must live below var/")

    raw_campaigns = document.get("campaign")
    if not isinstance(raw_campaigns, list) or not raw_campaigns:
        raise ValueError("campaign registry must contain [[campaign]] rows")
    campaigns: list[CampaignBinding] = []
    seen: set[str] = set()
    for position, raw in enumerate(raw_campaigns, start=1):
        if not isinstance(raw, dict):
            raise ValueError(f"campaign {position} must be a table")
        _only_keys(
            raw,
            {
                "id",
                "label",
                "family_id",
                "slice_id",
                "host",
                "state",
                "phase",
                "queue",
                "ledger",
                "programme",
                "priority_authority",
            },
            f"campaign {position}",
        )
        campaign_id = _identifier(raw.get("id"), f"campaign {position} id")
        if campaign_id in seen:
            raise ValueError(f"duplicate campaign id: {campaign_id}")
        seen.add(campaign_id)
        state = _text(raw.get("state"), f"campaign {campaign_id} state")
        if state not in _STATES:
            raise ValueError(
                f"campaign {campaign_id} state must be one of {sorted(_STATES)}"
            )
        ledger_path, ledger_ref = _inside(
            root, raw.get("ledger"), f"campaign {campaign_id} ledger"
        )
        if not Path(ledger_ref).parts or Path(ledger_ref).parts[0] != "var":
            raise ValueError(f"campaign {campaign_id} ledger must live below var/")

        queue_path = None
        queue_ref = None
        authority_digests: dict[str, str] = {}
        if raw.get("queue") is not None:
            queue_path, queue_ref = _file_authority(
                root, raw["queue"], f"campaign {campaign_id} queue"
            )
            QueueConfig.load(queue_path, root)
            authority_digests["queue_sha256"] = _sha256(queue_path)
        if state == "configured" and queue_path is None:
            raise ValueError(f"configured campaign {campaign_id} requires a queue")

        programme_ref = None
        if raw.get("programme") is not None:
            programme_path, programme_ref = _file_authority(
                root, raw["programme"], f"campaign {campaign_id} programme"
            )
            authority_digests["programme_sha256"] = _sha256(programme_path)
        priority_ref = None
        priority_subjects = 0
        if raw.get("priority_authority") is not None:
            priority_path, priority_ref = _file_authority(
                root,
                raw["priority_authority"],
                f"campaign {campaign_id} priority authority",
            )
            priority_subjects = _validate_priority_authority(priority_path)
            authority_digests["priority_sha256"] = _sha256(priority_path)
        identity = {
            "id": campaign_id,
            "label": _text(raw.get("label"), f"campaign {campaign_id} label"),
            "family_id": _identifier(
                raw.get("family_id"), f"campaign {campaign_id} family_id"
            ),
            "slice_id": _identifier(
                raw.get("slice_id"), f"campaign {campaign_id} slice_id"
            ),
            "host": _identifier(raw.get("host"), f"campaign {campaign_id} host"),
            "state": state,
            "phase": _text(raw.get("phase"), f"campaign {campaign_id} phase"),
            "queue": queue_ref,
            "ledger": ledger_ref,
            "programme": programme_ref,
            "priority_authority": priority_ref,
            "authority_digests": authority_digests,
        }
        campaigns.append(
            CampaignBinding(
                id=campaign_id,
                label=str(identity["label"]),
                family_id=str(identity["family_id"]),
                slice_id=str(identity["slice_id"]),
                host=str(identity["host"]),
                state=state,
                phase=str(identity["phase"]),
                queue_path=queue_path,
                queue_ref=queue_ref,
                ledger_path=ledger_path,
                ledger_ref=ledger_ref,
                programme_ref=programme_ref,
                priority_ref=priority_ref,
                authority_digests=authority_digests,
                priority_subjects=priority_subjects,
                digest=_binding_digest(identity),
            )
        )
    registry = CampaignRegistry(
        root=root,
        source_path=source_path,
        source_ref=source_ref,
        default_campaign=default_campaign,
        selection_path=selection_path,
        selection_ref=selection_ref,
        campaigns=tuple(campaigns),
    )
    default = registry.by_id(default_campaign)
    if not default.selectable:
        raise ValueError("default campaign must be configured and selectable")
    return registry


def active_campaign(registry: CampaignRegistry) -> tuple[CampaignBinding, str]:
    if not registry.selection_path.exists():
        return registry.by_id(registry.default_campaign), "registry-default"
    if registry.selection_path.is_symlink() or not registry.selection_path.is_file():
        raise ValueError("campaign selection state must be a regular file")
    document = tomllib.loads(registry.selection_path.read_text(encoding="utf-8"))
    _only_keys(
        document,
        {
            "schema_version",
            "campaign_id",
            "campaign_digest",
            "selected_at",
            "selected_by",
        },
        "campaign selection",
    )
    if document.get("schema_version") != SELECTION_SCHEMA:
        raise ValueError("campaign selection has an unsupported schema_version")
    selected = registry.by_id(
        _identifier(document.get("campaign_id"), "selected campaign id")
    )
    if not selected.selectable:
        raise ValueError(f"selected campaign is no longer selectable: {selected.id}")
    if document.get("campaign_digest") != selected.digest:
        raise ValueError(
            "selected campaign binding changed; remove the local selection only after review"
        )
    _text(document.get("selected_at"), "campaign selected_at")
    _text(document.get("selected_by"), "campaign selected_by")
    return selected, "local-selection"


def resolve_campaign_paths(
    project_root: str | Path,
    authority: str | Path = DEFAULT_REGISTRY,
) -> tuple[Path, Path, CampaignBinding]:
    registry = load_campaign_registry(project_root, authority)
    binding, _source = active_campaign(registry)
    if binding.queue_path is None:  # protected by selectable validation
        raise ValueError(f"active campaign has no queue: {binding.id}")
    return binding.ledger_path, binding.queue_path, binding


def _read_ledger_status(
    registry: CampaignRegistry, binding: CampaignBinding
) -> dict[str, object] | None:
    if not binding.ledger_path.is_file():
        return None
    with Coordinator(binding.ledger_path, registry.root) as coordinator:
        return coordinator.status()


def campaign_registry_status(
    project_root: str | Path,
    authority: str | Path = DEFAULT_REGISTRY,
) -> dict[str, object]:
    registry = load_campaign_registry(project_root, authority)
    active, selection_source = active_campaign(registry)
    rows = []
    for binding in registry.campaigns:
        queue = (
            QueueConfig.load(binding.queue_path, registry.root)
            if binding.queue_path is not None
            else None
        )
        ledger = _read_ledger_status(registry, binding)
        counts = ledger.get("counts") if ledger else None
        live_work = bool(
            isinstance(counts, dict)
            and (int(counts.get("leased", 0)) or int(counts.get("running", 0)))
        )
        queue_armed = bool(queue and queue.armed)
        ledger_armed = bool(ledger and ledger.get("armed"))
        safe_to_leave = not queue_armed and not ledger_armed and not live_work
        blockers = []
        if binding.state == "planned":
            blockers.append("queue not materialized")
        elif binding.state == "retired":
            blockers.append("campaign retired")
        if queue_armed:
            blockers.append("queue authority armed")
        if ledger_armed:
            blockers.append("ledger armed")
        if live_work:
            blockers.append("live leases or running jobs")
        rows.append(
            {
                "id": binding.id,
                "label": binding.label,
                "family_id": binding.family_id,
                "slice_id": binding.slice_id,
                "host": binding.host,
                "state": binding.state,
                "phase": binding.phase,
                "active": binding.id == active.id,
                "selectable": binding.selectable,
                "safe_to_leave": safe_to_leave,
                "queue": binding.queue_ref,
                "ledger": binding.ledger_ref,
                "programme": binding.programme_ref,
                "priority_authority": binding.priority_ref,
                "campaign_digest": binding.digest,
                "authority_digests": dict(binding.authority_digests),
                "priority_subjects": binding.priority_subjects,
                "queue_armed": queue_armed,
                "ledger_initialized": ledger is not None,
                "ledger_status": ledger.get("status") if ledger else "not-initialized",
                "counts": counts,
                "blockers": blockers,
            }
        )
    return {
        "schema_version": STATUS_SCHEMA,
        "authority_path": registry.source_ref,
        "selection_path": registry.selection_ref,
        "selection_source": selection_source,
        "active_campaign_id": active.id,
        "active_queue": active.queue_ref,
        "active_ledger": active.ledger_ref,
        "worker_restart_required_after_switch": True,
        "campaigns": rows,
    }


def _selection_toml(binding: CampaignBinding, actor: str) -> str:
    selected_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return (
        f'schema_version = "{SELECTION_SCHEMA}"\n'
        f'campaign_id = "{binding.id}"\n'
        f'campaign_digest = "{binding.digest}"\n'
        f'selected_at = "{selected_at}"\n'
        f'selected_by = "{actor}"\n'
    )


def _durable_replace(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink() or path.is_symlink():
        raise ValueError("campaign selection path cannot traverse a symlink")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def select_campaign(
    project_root: str | Path,
    campaign_id: str,
    *,
    authority: str | Path = DEFAULT_REGISTRY,
    actor: str = "operator",
) -> dict[str, object]:
    actor = _identifier(actor, "selection actor")
    requested = _identifier(campaign_id, "campaign id")
    registry = load_campaign_registry(project_root, authority)
    registry.selection_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = registry.selection_path.parent / ".selection.lock"
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        registry = load_campaign_registry(project_root, authority)
        current, _source = active_campaign(registry)
        target = registry.by_id(requested)
        if target.id == current.id:
            return campaign_registry_status(project_root, authority)
        if not target.selectable or target.queue_path is None:
            raise ValueError(
                f"campaign is not selectable: {target.id} ({target.state})"
            )
        target_queue = QueueConfig.load(target.queue_path, registry.root)
        if target_queue.armed:
            raise ValueError(
                f"target campaign queue must be disarmed before selection: {target.id}"
            )
        current_status = _read_ledger_status(registry, current)
        if current_status is not None:
            counts = current_status["counts"]
            assert isinstance(counts, dict)
            if bool(current_status["armed"]):
                raise ValueError(
                    "current campaign ledger must be disarmed before switching"
                )
            if int(counts["leased"]) or int(counts["running"]):
                raise ValueError(
                    "current campaign has live leases or running jobs; switch refused"
                )
        _durable_replace(registry.selection_path, _selection_toml(target, actor))
    return campaign_registry_status(project_root, authority)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="fidb-poc campaigns",
        description="Inspect or safely select an operational campaign binding.",
    )
    result.add_argument("command", choices=("status", "select"))
    result.add_argument("campaign_id", nargs="?")
    result.add_argument("--project-root", type=Path, default=Path.cwd())
    result.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.command == "status":
            if arguments.campaign_id is not None:
                raise ValueError("campaigns status does not accept a campaign id")
            document = campaign_registry_status(
                arguments.project_root, arguments.registry
            )
        else:
            if arguments.campaign_id is None:
                raise ValueError("campaigns select requires a campaign id")
            document = select_campaign(
                arguments.project_root,
                arguments.campaign_id,
                authority=arguments.registry,
                actor="cli",
            )
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=os.sys.stderr)
        return 1
