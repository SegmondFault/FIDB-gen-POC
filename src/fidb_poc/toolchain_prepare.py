"""Safe, content-addressed preparation of reviewed toolchain archives."""

from __future__ import annotations

import copy
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
import tempfile
import time
import zipfile

from .toolchain_cache import MANAGED_CACHE_ROOT

PREPARATION_SCHEMA = "fidb-toolchain-preparation/v1"
MANAGED_PREPARED = MANAGED_CACHE_ROOT / "prepared"
DEFAULT_MAX_MEMBERS = 1_000_000
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MANIFEST = ".fidb-prepared.json"


class PreparationError(RuntimeError):
    """A reviewed toolchain archive could not be safely prepared."""


@dataclass(frozen=True)
class PreparationInspection:
    path: Path
    root: Path
    state: str
    manifest: dict[str, object] | None = None


@dataclass(frozen=True)
class PreparationResult:
    path: Path
    root: Path
    archive_sha256: str
    archive_bytes: int
    extracted_bytes: int
    members: int
    files: int
    directories: int
    symlinks: int
    cache_hit: bool
    quarantined: Path | None = None


def _validate_digest(digest: str) -> None:
    if _DIGEST.fullmatch(digest) is None:
        raise ValueError("archive_sha256 must be 64 lowercase hexadecimal characters")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _safe_parts(
    value: str,
    *,
    field: str,
    base: tuple[str, ...] = (),
) -> tuple[str, ...]:
    if not value or "\x00" in value:
        raise PreparationError(f"archive {field} is empty or contains NUL")
    path = PurePosixPath(value)
    if path.is_absolute():
        raise PreparationError(f"archive {field} is absolute: {value}")
    parts: list[str] = list(base)
    for part in path.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                raise PreparationError(
                    f"archive {field} escapes extraction root: {value}"
                )
            parts.pop()
        else:
            parts.append(part)
    if not parts:
        raise PreparationError(f"archive {field} does not name a material path")
    return tuple(parts)


def _validate_member(member: tarfile.TarInfo) -> None:
    member_parts = _safe_parts(member.name, field="member path")
    if member.ischr() or member.isblk() or member.isfifo():
        raise PreparationError(
            f"archive contains unsupported special member: {member.name}"
        )
    if member.issym() or member.islnk():
        base = member_parts[:-1] if member.issym() else ()
        _safe_parts(member.linkname, field="link target", base=base)


def _sanitized(member: tarfile.TarInfo) -> tarfile.TarInfo:
    _validate_member(member)
    clean = copy.copy(member)
    if clean.isdir():
        clean.mode = 0o755
    elif clean.isfile():
        clean.mode = 0o755 if clean.mode & 0o111 else 0o644
    clean.uid = os.getuid()
    clean.gid = os.getgid()
    clean.uname = ""
    clean.gname = ""
    return clean


def _zip_kind(member: zipfile.ZipInfo) -> str:
    mode = member.external_attr >> 16
    file_type = stat.S_IFMT(mode)
    if member.is_dir() or file_type == stat.S_IFDIR:
        return "directory"
    if file_type == stat.S_IFLNK:
        return "symlink"
    if file_type in {0, stat.S_IFREG}:
        return "file"
    raise PreparationError(
        f"archive contains unsupported special member: {member.filename}"
    )


def _zip_members(
    source: zipfile.ZipFile,
    *,
    max_extracted_bytes: int,
    max_members: int,
) -> tuple[list[tuple[zipfile.ZipInfo, tuple[str, ...], str]], int]:
    members = source.infolist()
    if len(members) > max_members:
        raise PreparationError(
            f"archive has {len(members)} members; limit is {max_members}"
        )
    extracted_bytes = sum(int(member.file_size) for member in members)
    if extracted_bytes > max_extracted_bytes:
        raise PreparationError(
            f"archive expands to {extracted_bytes} bytes; limit is "
            f"{max_extracted_bytes}"
        )

    result: list[tuple[zipfile.ZipInfo, tuple[str, ...], str]] = []
    kinds: dict[tuple[str, ...], str] = {}
    for member in members:
        if member.flag_bits & 0x1:
            raise PreparationError(
                f"archive contains encrypted member: {member.filename}"
            )
        parts = _safe_parts(member.filename, field="member path")
        if parts in kinds:
            raise PreparationError(
                f"archive contains duplicate material path: {member.filename}"
            )
        kind = _zip_kind(member)
        kinds[parts] = kind
        result.append((member, parts, kind))

    for _member, parts, _kind in result:
        for length in range(1, len(parts)):
            ancestor = parts[:length]
            ancestor_kind = kinds.get(ancestor)
            if ancestor_kind is not None and ancestor_kind != "directory":
                raise PreparationError(
                    "archive member is nested beneath a non-directory: "
                    + "/".join(parts)
                )
    return result, extracted_bytes


def _extract_zip(
    archive: Path,
    staging: Path,
    *,
    max_extracted_bytes: int,
    max_members: int,
) -> dict[str, int]:
    with zipfile.ZipFile(archive, mode="r") as source:
        members, extracted_bytes = _zip_members(
            source,
            max_extracted_bytes=max_extracted_bytes,
            max_members=max_members,
        )
        directories = [row for row in members if row[2] == "directory"]
        files = [row for row in members if row[2] == "file"]
        symlinks = [row for row in members if row[2] == "symlink"]
        for _member, parts, _kind in sorted(directories, key=lambda row: len(row[1])):
            destination = staging.joinpath(*parts)
            destination.mkdir(parents=True, exist_ok=True)
            destination.chmod(0o755)
        for member, parts, _kind in files:
            destination = staging.joinpath(*parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with (
                source.open(member, mode="r") as input_stream,
                destination.open("xb") as output_stream,
            ):
                shutil.copyfileobj(input_stream, output_stream)
            if destination.stat().st_size != member.file_size:
                raise PreparationError(
                    f"archive member size changed during extraction: {member.filename}"
                )
            mode = member.external_attr >> 16
            destination.chmod(0o755 if mode & 0o111 else 0o644)
        for member, parts, _kind in symlinks:
            if member.file_size > 4096:
                raise PreparationError(
                    f"archive symlink target is too large: {member.filename}"
                )
            try:
                linkname = source.read(member).decode("utf-8")
            except UnicodeDecodeError as error:
                raise PreparationError(
                    f"archive symlink target is not UTF-8: {member.filename}"
                ) from error
            _safe_parts(linkname, field="link target", base=parts[:-1])
            destination = staging.joinpath(*parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.symlink_to(linkname)
    return {
        "members": len(members),
        "extracted_bytes": extracted_bytes,
        "files": len(files),
        "directories": len(directories),
        "symlinks": len(symlinks),
    }


def _extract_tar(
    archive: Path,
    staging: Path,
    *,
    max_extracted_bytes: int,
    max_members: int,
) -> dict[str, int]:
    with tarfile.open(archive, mode="r:*") as source:
        members = source.getmembers()
        if len(members) > max_members:
            raise PreparationError(
                f"archive has {len(members)} members; limit is {max_members}"
            )
        extracted_bytes = sum(int(member.size) for member in members if member.isfile())
        if extracted_bytes > max_extracted_bytes:
            raise PreparationError(
                f"archive expands to {extracted_bytes} bytes; limit is "
                f"{max_extracted_bytes}"
            )
        sanitized = [_sanitized(member) for member in members]
        source.extractall(staging, members=sanitized, numeric_owner=False)
    return {
        "members": len(members),
        "extracted_bytes": extracted_bytes,
        "files": sum(member.isfile() for member in members),
        "directories": sum(member.isdir() for member in members),
        "symlinks": sum(member.issym() or member.islnk() for member in members),
    }


def inspect_prepared(
    prepared: Path,
    archive_sha256: str,
    archive_root: str,
) -> PreparationInspection:
    """Inspect one published preparation record without mutating it."""

    _validate_digest(archive_sha256)
    destination = prepared / archive_sha256
    root = destination / archive_root
    manifest_path = destination / _MANIFEST
    if not destination.exists():
        return PreparationInspection(path=destination, root=root, state="missing")
    if destination.is_symlink() or not destination.is_dir():
        return PreparationInspection(path=destination, root=root, state="broken")
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return PreparationInspection(path=destination, root=root, state="broken")
    required = {
        "schema_version",
        "archive_sha256",
        "archive_bytes",
        "archive_root",
        "extracted_bytes",
        "members",
        "files",
        "directories",
        "symlinks",
    }
    if (
        not isinstance(document, dict)
        or set(document) != required
        or document.get("schema_version") != PREPARATION_SCHEMA
        or document.get("archive_sha256") != archive_sha256
        or document.get("archive_root") != archive_root
        or root.is_symlink()
        or not root.is_dir()
    ):
        return PreparationInspection(path=destination, root=root, state="broken")
    return PreparationInspection(
        path=destination,
        root=root,
        state="prepared",
        manifest=document,
    )


def _quarantine(prepared: Path, destination: Path, digest: str) -> Path:
    quarantine = prepared.parent / "quarantine-prepared"
    quarantine.mkdir(parents=True, exist_ok=True)
    target = quarantine / f"{digest}.{time.time_ns()}.{os.getpid()}.invalid"
    os.replace(destination, target)
    _fsync_directory(prepared)
    _fsync_directory(quarantine)
    return target


def prepare_pinned_archive(
    archive: Path,
    archive_sha256: str,
    expected_archive_bytes: int,
    archive_root: str,
    prepared: Path,
    *,
    max_extracted_bytes: int,
    max_members: int = DEFAULT_MAX_MEMBERS,
) -> PreparationResult:
    """Safely extract a verified archive and publish it by atomic rename."""

    _validate_digest(archive_sha256)
    _safe_parts(archive_root, field="reviewed archive root")
    if expected_archive_bytes < 1 or max_extracted_bytes < 1 or max_members < 1:
        raise ValueError("archive, extraction, and member limits must be positive")
    if archive.is_symlink() or not archive.is_file():
        raise PreparationError("reviewed archive is missing or not a regular file")
    observed_bytes = archive.stat().st_size
    if observed_bytes != expected_archive_bytes:
        raise PreparationError(
            f"reviewed archive size mismatch: expected {expected_archive_bytes}, "
            f"observed {observed_bytes}"
        )
    observed_sha256 = _sha256(archive)
    if observed_sha256 != archive_sha256:
        raise PreparationError(
            "reviewed archive digest mismatch before extraction: "
            f"expected {archive_sha256}, observed {observed_sha256}"
        )

    prepared.mkdir(parents=True, exist_ok=True)
    locks = prepared.parent / "locks"
    locks.mkdir(parents=True, exist_ok=True)
    destination = prepared / archive_sha256
    quarantined: Path | None = None
    lock_path = locks / f"prepare-{archive_sha256}.lock"
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        existing = inspect_prepared(prepared, archive_sha256, archive_root)
        if existing.state == "prepared":
            manifest = existing.manifest or {}
            return PreparationResult(
                path=existing.path,
                root=existing.root,
                archive_sha256=archive_sha256,
                archive_bytes=expected_archive_bytes,
                extracted_bytes=int(manifest["extracted_bytes"]),
                members=int(manifest["members"]),
                files=int(manifest["files"]),
                directories=int(manifest["directories"]),
                symlinks=int(manifest["symlinks"]),
                cache_hit=True,
            )
        if destination.exists():
            quarantined = _quarantine(prepared, destination, archive_sha256)

        staging = Path(tempfile.mkdtemp(prefix=f".{archive_sha256}.", dir=prepared))
        try:
            if zipfile.is_zipfile(archive):
                extraction = _extract_zip(
                    archive,
                    staging,
                    max_extracted_bytes=max_extracted_bytes,
                    max_members=max_members,
                )
            else:
                extraction = _extract_tar(
                    archive,
                    staging,
                    max_extracted_bytes=max_extracted_bytes,
                    max_members=max_members,
                )
            root = staging / archive_root
            if root.is_symlink() or not root.is_dir():
                raise PreparationError(
                    f"reviewed archive root is missing after extraction: {archive_root}"
                )
            document = {
                "schema_version": PREPARATION_SCHEMA,
                "archive_sha256": archive_sha256,
                "archive_bytes": expected_archive_bytes,
                "archive_root": archive_root,
                "extracted_bytes": extraction["extracted_bytes"],
                "members": extraction["members"],
                "files": extraction["files"],
                "directories": extraction["directories"],
                "symlinks": extraction["symlinks"],
            }
            manifest_path = staging / _MANIFEST
            with manifest_path.open("x", encoding="utf-8") as output:
                json.dump(document, output, indent=2, sort_keys=True)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(staging, destination)
            _fsync_directory(prepared)
            return PreparationResult(
                path=destination,
                root=destination / archive_root,
                archive_sha256=archive_sha256,
                archive_bytes=expected_archive_bytes,
                extracted_bytes=extraction["extracted_bytes"],
                members=extraction["members"],
                files=int(document["files"]),
                directories=int(document["directories"]),
                symlinks=int(document["symlinks"]),
                cache_hit=False,
                quarantined=quarantined,
            )
        except (OSError, tarfile.TarError, zipfile.BadZipFile, ValueError) as error:
            raise PreparationError(
                f"failed to prepare reviewed archive: {archive}"
            ) from error
        finally:
            if staging.exists():
                shutil.rmtree(staging)
