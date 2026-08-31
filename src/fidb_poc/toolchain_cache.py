"""Locked, checksum-verified acquisition of reviewed build inputs.

The caller supplies a URL and digest only after resolving them from reviewed
project authority.  This module never chooses or substitutes an input.  It
stores immutable payloads by SHA-256 and makes a completed payload visible
only after verification and an atomic, durable rename.
"""

from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import os
from pathlib import Path
import re
import tempfile
import time
from typing import BinaryIO, Callable
from urllib.error import URLError
from urllib.request import Request, urlopen

DEFAULT_TIMEOUT_SECONDS = 60.0
DEFAULT_ATTEMPTS = 3
DEFAULT_BACKOFF_SECONDS = 1.0
DEFAULT_MAX_BYTES = 8 * 1024 * 1024 * 1024
MANAGED_CACHE_ROOT = Path("var/fidb-toolchains")
MANAGED_DOWNLOADS = MANAGED_CACHE_ROOT / "downloads"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class CacheError(RuntimeError):
    """A reviewed payload could not be safely acquired or cached."""


class CacheIntegrityError(CacheError):
    """Downloaded or cached bytes do not match their reviewed digest."""


@dataclass(frozen=True)
class CacheInspection:
    path: Path
    state: str
    bytes: int | None = None
    observed_sha256: str | None = None


@dataclass(frozen=True)
class AcquisitionResult:
    path: Path
    sha256: str
    bytes: int
    cache_hit: bool
    attempts: int
    quarantined: Path | None = None


def _validate_digest(digest: str) -> None:
    if _DIGEST.fullmatch(digest) is None:
        raise ValueError("expected_sha256 must be 64 lowercase hexadecimal characters")


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


def inspect_cached(downloads: Path, expected_sha256: str) -> CacheInspection:
    """Inspect one content-addressed payload without mutating the store."""

    _validate_digest(expected_sha256)
    path = downloads / expected_sha256
    if not path.exists():
        return CacheInspection(path=path, state="missing")
    if path.is_symlink() or not path.is_file():
        return CacheInspection(path=path, state="broken")
    try:
        size = path.stat().st_size
        observed = _sha256(path)
    except OSError:
        return CacheInspection(path=path, state="broken")
    return CacheInspection(
        path=path,
        state="verified-cached" if observed == expected_sha256 else "broken",
        bytes=size,
        observed_sha256=observed,
    )


def _quarantine(downloads: Path, path: Path, expected_sha256: str) -> Path:
    quarantine = downloads.parent / "quarantine"
    quarantine.mkdir(parents=True, exist_ok=True)
    destination = quarantine / (
        f"{expected_sha256}.{time.time_ns()}.{os.getpid()}.invalid"
    )
    os.replace(path, destination)
    _fsync_directory(downloads)
    _fsync_directory(quarantine)
    return destination


def _copy_response(
    response: BinaryIO,
    output: BinaryIO,
    *,
    max_bytes: int,
) -> tuple[str, int]:
    digest = hashlib.sha256()
    byte_count = 0
    while chunk := response.read(1024 * 1024):
        byte_count += len(chunk)
        if byte_count > max_bytes:
            raise CacheError(
                f"reviewed payload exceeds acquisition limit of {max_bytes} bytes"
            )
        output.write(chunk)
        digest.update(chunk)
    return digest.hexdigest(), byte_count


def acquire_pinned(
    url: str,
    expected_sha256: str,
    downloads: Path,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    attempts: int = DEFAULT_ATTEMPTS,
    backoff_seconds: float = DEFAULT_BACKOFF_SECONDS,
    max_bytes: int = DEFAULT_MAX_BYTES,
    opener: Callable[..., BinaryIO] = urlopen,
) -> AcquisitionResult:
    """Acquire exactly one reviewed payload into a shared immutable store.

    A per-digest advisory lock serializes workers.  Invalid existing bytes are
    quarantined for diagnosis, partial downloads are never installed, and the
    returned file has already been verified against ``expected_sha256``.
    """

    _validate_digest(expected_sha256)
    if attempts < 1:
        raise ValueError("attempts must be at least 1")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if backoff_seconds < 0:
        raise ValueError("backoff_seconds must not be negative")
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")

    downloads.mkdir(parents=True, exist_ok=True)
    locks = downloads.parent / "locks"
    locks.mkdir(parents=True, exist_ok=True)
    _fsync_directory(downloads.parent)
    destination = downloads / expected_sha256
    quarantined: Path | None = None

    lock_path = locks / f"{expected_sha256}.lock"
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        cached = inspect_cached(downloads, expected_sha256)
        if cached.state == "verified-cached":
            return AcquisitionResult(
                path=destination,
                sha256=expected_sha256,
                bytes=int(cached.bytes or 0),
                cache_hit=True,
                attempts=0,
            )
        if destination.exists():
            quarantined = _quarantine(downloads, destination, expected_sha256)

        request = Request(url, headers={"User-Agent": "fidb-poc/0.1"})
        last_error: BaseException | None = None
        for attempt in range(1, attempts + 1):
            temporary: Path | None = None
            try:
                descriptor, name = tempfile.mkstemp(
                    prefix=f".{expected_sha256}.", suffix=".part", dir=downloads
                )
                temporary = Path(name)
                with os.fdopen(descriptor, "wb") as output:
                    with opener(request, timeout=timeout_seconds) as response:
                        content_length = response.headers.get("Content-Length")
                        if (
                            content_length is not None
                            and int(content_length) > max_bytes
                        ):
                            raise CacheError(
                                "reviewed payload Content-Length exceeds acquisition "
                                f"limit of {max_bytes} bytes"
                            )
                        observed, byte_count = _copy_response(
                            response, output, max_bytes=max_bytes
                        )
                    output.flush()
                    os.fsync(output.fileno())
                if observed != expected_sha256:
                    raise CacheIntegrityError(
                        "downloaded payload digest does not match reviewed SHA-256: "
                        f"expected {expected_sha256}, observed {observed}"
                    )
                os.chmod(temporary, 0o644)
                os.replace(temporary, destination)
                temporary = None
                _fsync_directory(downloads)
                return AcquisitionResult(
                    path=destination,
                    sha256=expected_sha256,
                    bytes=byte_count,
                    cache_hit=False,
                    attempts=attempt,
                    quarantined=quarantined,
                )
            except CacheIntegrityError:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
                raise
            except (OSError, URLError, CacheError, ValueError) as error:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
                last_error = error
                if attempt < attempts:
                    time.sleep(backoff_seconds * (2 ** (attempt - 1)))
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)

        raise CacheError(
            f"failed to acquire reviewed payload after {attempts} attempts: {url}"
        ) from last_error
