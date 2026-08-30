"""Validated TOML draft resolution and bounded project-local persistence."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import tempfile

from .plan_request import load_plan_request, resolve_plan

DRAFT_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
MAX_DRAFT_BYTES = 64 * 1024


class DraftConflictError(ValueError):
    """The caller attempted to overwrite a different saved draft."""


def _validated_text(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("plan TOML must be a non-empty string")
    payload = value.encode("utf-8")
    if len(payload) > MAX_DRAFT_BYTES:
        raise ValueError(f"plan TOML exceeds {MAX_DRAFT_BYTES} bytes")
    if "\x00" in value:
        raise ValueError("plan TOML must not contain NUL bytes")
    return value.rstrip() + "\n"


def _resolve_text(text: str, project_root: Path) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="fidb-plan-draft-") as temporary:
        path = Path(temporary) / "draft.toml"
        path.write_text(text, encoding="utf-8")
        load_plan_request(path)
        return resolve_plan(path, project_root)


def resolve_plan_draft(
    toml_text: object, project_root: str | Path
) -> dict[str, object]:
    """Resolve a draft without retaining it anywhere in the project."""

    root = Path(project_root).expanduser().resolve()
    text = _validated_text(toml_text)
    resolved = _resolve_text(text, root)
    return {
        "schema_version": "fidb-plan-draft-resolution/v1",
        "toml_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "resolved": resolved,
    }


def save_plan_draft(
    name: object,
    toml_text: object,
    project_root: str | Path,
    *,
    expected_sha256: object = None,
) -> dict[str, object]:
    """Validate, resolve and atomically save one named draft under plans/drafts."""

    if not isinstance(name, str) or DRAFT_NAME.fullmatch(name) is None:
        raise ValueError("draft name must be a lowercase letter/digit/hyphen token")
    if expected_sha256 is not None and (
        not isinstance(expected_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
    ):
        raise ValueError("expected_sha256 must be a lowercase SHA-256 digest")

    root = Path(project_root).expanduser().resolve()
    text = _validated_text(toml_text)
    resolved = _resolve_text(text, root)
    if resolved["name"] != name:
        raise ValueError("draft name must match the TOML plan name")

    directory = root / "plans/drafts"
    if directory.is_symlink():
        raise ValueError("plans/drafts cannot be a symlink")
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"{name}.toml"
    if destination.is_symlink():
        raise ValueError("draft destination cannot be a symlink")

    previous_sha256 = None
    if destination.exists():
        if not destination.is_file():
            raise ValueError("draft destination is not a regular file")
        previous_sha256 = hashlib.sha256(destination.read_bytes()).hexdigest()
        if expected_sha256 is None:
            raise DraftConflictError(
                "draft already exists; expected_sha256 is required to update it"
            )
        if expected_sha256 != previous_sha256:
            raise DraftConflictError("saved draft changed since it was loaded")
    elif expected_sha256 is not None:
        raise DraftConflictError("saved draft does not exist")

    payload = text.encode("utf-8")
    temporary = directory / f".{name}.toml.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o644,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        directory_descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise

    digest = hashlib.sha256(payload).hexdigest()
    return {
        "schema_version": "fidb-plan-draft/v1",
        "path": str(destination.relative_to(root)),
        "toml_sha256": digest,
        "previous_sha256": previous_sha256,
        "resolved": resolved,
    }
