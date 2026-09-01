"""Typed binding of non-redistributable toolchain inputs."""

from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import BinaryIO

from .toolchain_cache import MANAGED_CACHE_ROOT

INPUT_BINDING_SCHEMA = "fidb-toolchain-input-binding/v1"
MANAGED_INPUTS = MANAGED_CACHE_ROOT / "inputs"
MANAGED_BINDINGS = MANAGED_CACHE_ROOT / "bindings"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class InputBindingError(RuntimeError):
    """A required private toolchain input could not be safely bound."""


@dataclass(frozen=True)
class InputBindingInspection:
    input_id: str
    state: str
    binding_path: Path
    material_path: Path | None = None
    document: dict[str, object] | None = None


@dataclass(frozen=True)
class InputBindingResult:
    input_id: str
    binding_path: Path
    material_path: Path
    sha256: str
    bytes: int
    metadata: dict[str, str]
    material_cache_hit: bool


def _validate_digest(digest: str) -> None:
    if _DIGEST.fullmatch(digest) is None:
        raise ValueError("sha256 must be 64 lowercase hexadecimal characters")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _hash_stream(source: BinaryIO, output: BinaryIO | None = None) -> tuple[str, int]:
    digest = hashlib.sha256()
    byte_count = 0
    while block := source.read(1024 * 1024):
        byte_count += len(block)
        digest.update(block)
        if output is not None:
            output.write(block)
    return digest.hexdigest(), byte_count


def _required_metadata(authority: dict[str, object]) -> set[str]:
    values = authority.get("required_metadata")
    if not isinstance(values, list) or not all(
        isinstance(value, str) and value for value in values
    ):
        raise ValueError("input authority required_metadata is invalid")
    return set(values)


def inspect_input_binding(
    project_root: Path,
    authority: dict[str, object],
) -> InputBindingInspection:
    """Validate a local binding and its private content-addressed material."""

    input_id = str(authority["id"])
    binding_path = project_root / MANAGED_BINDINGS / f"{input_id}.json"
    if not binding_path.exists():
        return InputBindingInspection(
            input_id=input_id,
            state="missing",
            binding_path=binding_path,
        )
    if binding_path.is_symlink() or not binding_path.is_file():
        return InputBindingInspection(
            input_id=input_id,
            state="broken",
            binding_path=binding_path,
        )
    try:
        document = json.loads(binding_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return InputBindingInspection(
            input_id=input_id,
            state="broken",
            binding_path=binding_path,
        )
    required_fields = {
        "schema_version",
        "input_id",
        "kind",
        "target_ids",
        "authority",
        "sha256",
        "bytes",
        "metadata",
    }
    if (
        not isinstance(document, dict)
        or set(document) != required_fields
        or document.get("schema_version") != INPUT_BINDING_SCHEMA
        or document.get("input_id") != input_id
        or document.get("kind") != authority.get("kind")
        or document.get("target_ids") != authority.get("target_ids")
        or document.get("authority") != authority.get("authority")
        or not isinstance(document.get("metadata"), dict)
        or set(document["metadata"]) != _required_metadata(authority)
        or not all(
            isinstance(value, str) and value for value in document["metadata"].values()
        )
        or not isinstance(document.get("bytes"), int)
        or int(document["bytes"]) < 1
        or not isinstance(document.get("sha256"), str)
        or _DIGEST.fullmatch(str(document["sha256"])) is None
    ):
        return InputBindingInspection(
            input_id=input_id,
            state="broken",
            binding_path=binding_path,
        )
    material_path = project_root / MANAGED_INPUTS / str(document["sha256"])
    if (
        material_path.is_symlink()
        or not material_path.is_file()
        or material_path.stat().st_size != int(document["bytes"])
    ):
        return InputBindingInspection(
            input_id=input_id,
            state="broken",
            binding_path=binding_path,
            material_path=material_path,
            document=document,
        )
    try:
        with material_path.open("rb") as stream:
            observed, observed_bytes = _hash_stream(stream)
    except OSError:
        observed, observed_bytes = "", -1
    if observed != str(document["sha256"]) or observed_bytes != int(document["bytes"]):
        return InputBindingInspection(
            input_id=input_id,
            state="broken",
            binding_path=binding_path,
            material_path=material_path,
            document=document,
        )
    return InputBindingInspection(
        input_id=input_id,
        state="bound-verified",
        binding_path=binding_path,
        material_path=material_path,
        document=document,
    )


def bind_input(
    project_root: Path,
    authority: dict[str, object],
    source_path: Path,
    expected_sha256: str,
    expected_bytes: int,
    metadata: dict[str, str],
) -> InputBindingResult:
    """Verify, privately cache, and atomically bind one reviewed input type."""

    _validate_digest(expected_sha256)
    if expected_bytes < 1:
        raise ValueError("bytes must be positive")
    if set(metadata) != _required_metadata(authority) or not all(
        isinstance(value, str) and value for value in metadata.values()
    ):
        raise InputBindingError(
            "metadata must contain exactly: "
            + ", ".join(sorted(_required_metadata(authority)))
        )
    if source_path.is_symlink() or not source_path.is_file():
        raise InputBindingError("input source must be a regular, non-symlink file")
    if source_path.stat().st_size != expected_bytes:
        raise InputBindingError(
            f"input byte count mismatch: expected {expected_bytes}, "
            f"observed {source_path.stat().st_size}"
        )

    materials = project_root / MANAGED_INPUTS
    bindings = project_root / MANAGED_BINDINGS
    locks = project_root / MANAGED_CACHE_ROOT / "locks"
    for directory in (materials, bindings, locks):
        directory.mkdir(parents=True, exist_ok=True)
    material_path = materials / expected_sha256
    lock_path = locks / f"input-{expected_sha256}.lock"
    material_cache_hit = False
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if material_path.exists():
            if material_path.is_symlink() or not material_path.is_file():
                raise InputBindingError("existing input material is not a regular file")
            with material_path.open("rb") as existing:
                observed, observed_bytes = _hash_stream(existing)
            if observed != expected_sha256 or observed_bytes != expected_bytes:
                raise InputBindingError(
                    "existing input material failed integrity check"
                )
            material_cache_hit = True
        else:
            descriptor, name = tempfile.mkstemp(
                prefix=f".{expected_sha256}.", suffix=".part", dir=materials
            )
            temporary = Path(name)
            try:
                with (
                    source_path.open("rb") as source,
                    os.fdopen(descriptor, "wb") as output,
                ):
                    observed, observed_bytes = _hash_stream(source, output)
                    output.flush()
                    os.fsync(output.fileno())
                if observed != expected_sha256 or observed_bytes != expected_bytes:
                    raise InputBindingError(
                        "input digest or byte count does not match declared values"
                    )
                os.chmod(temporary, 0o600)
                os.replace(temporary, material_path)
                _fsync_directory(materials)
            finally:
                temporary.unlink(missing_ok=True)

    input_id = str(authority["id"])
    document = {
        "schema_version": INPUT_BINDING_SCHEMA,
        "input_id": input_id,
        "kind": authority["kind"],
        "target_ids": authority["target_ids"],
        "authority": authority["authority"],
        "sha256": expected_sha256,
        "bytes": expected_bytes,
        "metadata": metadata,
    }
    binding_path = bindings / f"{input_id}.json"
    descriptor, name = tempfile.mkstemp(
        prefix=f".{input_id}.", suffix=".json", dir=bindings
    )
    temporary_binding = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(document, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary_binding, 0o600)
        os.replace(temporary_binding, binding_path)
        _fsync_directory(bindings)
    finally:
        temporary_binding.unlink(missing_ok=True)
    return InputBindingResult(
        input_id=input_id,
        binding_path=binding_path,
        material_path=material_path,
        sha256=expected_sha256,
        bytes=expected_bytes,
        metadata=dict(metadata),
        material_cache_hit=material_cache_hit,
    )
