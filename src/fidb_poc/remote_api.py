"""Authenticated worker-only HTTP boundary for the host-local coordinator."""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import fcntl
import hashlib
import hmac
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import socket
import tempfile
from typing import Mapping, Sequence
from urllib.parse import urlsplit

from .cell_runner import CellRunResult
from .coordinator import Coordinator, CoordinatorError, QueueConfig, WORKER_POOLS
from .external_workers import load_external_toolchain, validate_registration
from .queue_cli import (
    JOB_TIMING_SCHEMA,
    _durably_publish,
    _result_document,
    _validate_cell_timing,
)
from .operations_policy import emit_notification
from .timing import CellStage, ProgressEvent, TimingRecorder

REMOTE_API_SCHEMA = "fidb-remote-worker-api/v1"
CREDENTIALS_SCHEMA = "fidb-remote-worker-credentials/v1"
DEFAULT_BIND = "127.0.0.1"
DEFAULT_PORT = 8766
DEFAULT_STATE = Path("var/fidb-coordinator/ledger.sqlite3")
DEFAULT_QUEUE = Path("plans/priority-queue.toml")
MAX_JSON_BYTES = 96 * 1024 * 1024
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024
MAX_CHUNK_BYTES = 8 * 1024 * 1024
_TOKEN_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_JOB_ID = re.compile(r"job-[0-9a-f]{64}\Z")
_WORKER_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_ROUTES = {
    "/api/v1/worker/register",
    "/api/v1/worker/claim",
    "/api/v1/worker/renew",
    "/api/v1/worker/stage",
    "/api/v1/worker/fail",
    "/api/v1/worker/upload",
    "/api/v1/worker/complete",
}


class RemoteApiError(RuntimeError):
    def __init__(self, status: HTTPStatus, code: str, message: str):
        self.status = status
        self.code = code
        self.message = message
        super().__init__(message)


@dataclass(frozen=True)
class WorkerCredential:
    worker_id: str
    token_sha256: str
    pools: tuple[str, ...]


def load_credentials(path: str | Path) -> dict[str, WorkerCredential]:
    source = Path(path).expanduser().resolve()
    if not source.is_file() or source.is_symlink():
        raise ValueError(f"worker credentials must be a regular file: {source}")
    if source.stat().st_mode & 0o077:
        raise ValueError("worker credentials must not be accessible by group or other")
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("worker credentials are not valid JSON") from error
    if not isinstance(document, dict) or set(document) != {"schema_version", "workers"}:
        raise ValueError("worker credentials have unsupported fields")
    if document["schema_version"] != CREDENTIALS_SCHEMA:
        raise ValueError("worker credentials have an unsupported schema")
    rows = document["workers"]
    if not isinstance(rows, list) or not rows:
        raise ValueError("worker credentials must contain at least one worker")
    result: dict[str, WorkerCredential] = {}
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, dict) or set(row) != {
            "worker_id",
            "token_sha256",
            "pools",
        }:
            raise ValueError(f"worker credential {index} has unsupported fields")
        worker_id = row["worker_id"]
        digest = row["token_sha256"]
        pools = row["pools"]
        if not isinstance(worker_id, str) or not _WORKER_ID.fullmatch(worker_id):
            raise ValueError(f"worker credential {index} has an invalid worker_id")
        if worker_id in result:
            raise ValueError(f"duplicate worker credential: {worker_id}")
        if not isinstance(digest, str) or not _TOKEN_DIGEST.fullmatch(digest):
            raise ValueError(
                f"worker credential {worker_id} has an invalid token digest"
            )
        if (
            not isinstance(pools, list)
            or not pools
            or any(pool not in WORKER_POOLS for pool in pools)
            or len(set(pools)) != len(pools)
        ):
            raise ValueError(
                f"worker credential {worker_id} pools must be unique values from "
                f"{list(WORKER_POOLS)}"
            )
        result[worker_id] = WorkerCredential(worker_id, digest, tuple(pools))
    return result


@dataclass(frozen=True)
class RemoteApiConfig:
    project_root: Path
    state_path: Path
    queue_path: Path
    credentials_path: Path
    credentials: Mapping[str, WorkerCredential]
    max_json_bytes: int = MAX_JSON_BYTES
    max_artifact_bytes: int = MAX_ARTIFACT_BYTES

    @classmethod
    def from_paths(
        cls,
        project_root: str | Path,
        state_path: str | Path,
        queue_path: str | Path,
        credentials_path: str | Path,
    ) -> "RemoteApiConfig":
        root = Path(project_root).expanduser().resolve()
        state = Path(state_path)
        if not state.is_absolute():
            state = root / state
        state = state.resolve()
        try:
            state.relative_to(root)
        except ValueError as error:
            raise ValueError(
                "remote coordinator state must remain inside project"
            ) from error
        if not state.is_file() or state.is_symlink():
            raise ValueError(f"coordinator state does not exist: {state}")
        queue = Path(queue_path)
        if not queue.is_absolute():
            queue = root / queue
        queue = queue.resolve()
        try:
            queue.relative_to(root)
        except ValueError as error:
            raise ValueError("remote queue must remain inside project") from error
        if not queue.is_file() or queue.is_symlink():
            raise ValueError(f"remote queue does not exist: {queue}")
        credentials_path = Path(credentials_path).expanduser().resolve()
        return cls(
            root,
            state,
            queue,
            credentials_path,
            load_credentials(credentials_path),
        )


class _RemoteServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        config: RemoteApiConfig,
        handler: type[BaseHTTPRequestHandler],
    ) -> None:
        self.config = config
        super().__init__(address, handler)


class _Ipv6RemoteServer(_RemoteServer):
    address_family = socket.AF_INET6


def _only_fields(document: Mapping[str, object], allowed: set[str]) -> None:
    unknown = set(document) - allowed
    if unknown:
        raise RemoteApiError(
            HTTPStatus.BAD_REQUEST,
            "unsupported-fields",
            f"unsupported request fields: {sorted(unknown)}",
        )


def _text(document: Mapping[str, object], field: str, maximum: int = 4096) -> str:
    value = document.get(field)
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise RemoteApiError(
            HTTPStatus.BAD_REQUEST, "invalid-field", f"{field} is invalid"
        )
    return value


def _lease_fields(document: Mapping[str, object]) -> tuple[str, str, int]:
    job_id = _text(document, "job_id", 68)
    token = _text(document, "lease_token", 256)
    generation = document.get("lease_generation")
    if not _JOB_ID.fullmatch(job_id):
        raise RemoteApiError(HTTPStatus.BAD_REQUEST, "invalid-job", "job_id is invalid")
    if (
        isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation < 1
    ):
        raise RemoteApiError(
            HTTPStatus.BAD_REQUEST, "invalid-generation", "lease_generation is invalid"
        )
    return job_id, token, generation


def _relative(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise RemoteApiError(
            HTTPStatus.BAD_REQUEST, "invalid-path", f"{label} is invalid"
        )
    path = Path(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise RemoteApiError(
            HTTPStatus.BAD_REQUEST, "invalid-path", f"{label} is invalid"
        )
    return path


def _staging(config: RemoteApiConfig, job_id: str, generation: int) -> Path:
    root = config.project_root / "artifacts/runs/remote-staging"
    if root.is_symlink():
        raise RemoteApiError(
            HTTPStatus.CONFLICT, "unsafe-staging", "remote staging root is a symlink"
        )
    root.mkdir(parents=True, exist_ok=True)
    staging = root / f"{job_id}-g{generation}"
    if staging.is_symlink():
        raise RemoteApiError(
            HTTPStatus.CONFLICT, "unsafe-staging", "remote attempt root is a symlink"
        )
    staging.mkdir(parents=True, exist_ok=True)
    return staging


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _upload_lock_path(config: RemoteApiConfig, staging: Path, relative: Path) -> Path:
    lock_root = config.project_root / "var/fidb-remote-upload-locks"
    if lock_root.is_symlink():
        raise RemoteApiError(
            HTTPStatus.CONFLICT,
            "unsafe-staging",
            "remote upload lock root is a symlink",
        )
    lock_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(lock_root, 0o700)
    identity = hashlib.sha256(
        f"{staging.name}\0{relative.as_posix()}".encode()
    ).hexdigest()
    lock_path = lock_root / f"{identity}.lock"
    if lock_path.is_symlink():
        raise RemoteApiError(
            HTTPStatus.CONFLICT,
            "unsafe-staging",
            "remote upload lock path is a symlink",
        )
    return lock_path


def _store_upload(
    config: RemoteApiConfig,
    staging: Path,
    relative: Path,
    content: bytes,
    expected_sha256: str,
) -> dict[str, object]:
    if len(content) > config.max_artifact_bytes:
        raise RemoteApiError(
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            "artifact-too-large",
            "remote artifact exceeds the configured limit",
        )
    digest = hashlib.sha256(content).hexdigest()
    if not _TOKEN_DIGEST.fullmatch(expected_sha256) or not hmac.compare_digest(
        digest, expected_sha256
    ):
        raise RemoteApiError(
            HTTPStatus.BAD_REQUEST, "digest-mismatch", "remote artifact digest mismatch"
        )
    destination = staging / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    current = staging
    for part in relative.parts[:-1]:
        current /= part
        if current.is_symlink():
            raise RemoteApiError(
                HTTPStatus.CONFLICT, "unsafe-staging", "artifact parent is a symlink"
            )
    if destination.exists() or destination.is_symlink():
        if destination.is_file() and not destination.is_symlink():
            observed = hashlib.sha256(destination.read_bytes()).hexdigest()
            if hmac.compare_digest(observed, digest):
                return {"path": str(relative), "sha256": digest, "bytes": len(content)}
        raise RemoteApiError(
            HTTPStatus.CONFLICT, "artifact-conflict", "artifact upload already exists"
        )
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
        directory_fd = os.open(
            destination.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)
    return {"path": str(relative), "sha256": digest, "bytes": len(content)}


def _store_upload_chunk(
    config: RemoteApiConfig,
    staging: Path,
    relative: Path,
    content: bytes,
    *,
    artifact_sha256: str,
    artifact_bytes: object,
    offset: object,
    chunk_sha256: str,
    final: object,
) -> dict[str, object]:
    if (
        isinstance(artifact_bytes, bool)
        or not isinstance(artifact_bytes, int)
        or not 0 < artifact_bytes <= config.max_artifact_bytes
    ):
        raise RemoteApiError(
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            "artifact-too-large",
            "remote artifact size is invalid or exceeds the configured limit",
        )
    if (
        isinstance(offset, bool)
        or not isinstance(offset, int)
        or offset < 0
        or offset >= artifact_bytes
    ):
        raise RemoteApiError(
            HTTPStatus.BAD_REQUEST, "invalid-offset", "artifact chunk offset is invalid"
        )
    if (
        not content
        or len(content) > MAX_CHUNK_BYTES
        or offset + len(content) > artifact_bytes
    ):
        raise RemoteApiError(
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            "chunk-too-large",
            "artifact chunk is empty, oversized, or exceeds the declared artifact",
        )
    if not isinstance(final, bool) or final != (
        offset + len(content) == artifact_bytes
    ):
        raise RemoteApiError(
            HTTPStatus.BAD_REQUEST,
            "invalid-final-chunk",
            "final must identify exactly the last artifact chunk",
        )
    observed_chunk = hashlib.sha256(content).hexdigest()
    if (
        not _TOKEN_DIGEST.fullmatch(chunk_sha256)
        or not hmac.compare_digest(observed_chunk, chunk_sha256)
        or not _TOKEN_DIGEST.fullmatch(artifact_sha256)
    ):
        raise RemoteApiError(
            HTTPStatus.BAD_REQUEST, "digest-mismatch", "artifact chunk digest mismatch"
        )

    destination = staging / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    current = staging
    for part in relative.parts[:-1]:
        current /= part
        if current.is_symlink():
            raise RemoteApiError(
                HTTPStatus.CONFLICT, "unsafe-staging", "artifact parent is a symlink"
            )
    partial = destination.with_name(f".{destination.name}.upload")
    metadata_path = destination.with_name(f".{destination.name}.upload.json")
    lock_path = _upload_lock_path(config, staging, relative)
    for candidate in (destination, partial, metadata_path):
        if candidate.is_symlink():
            raise RemoteApiError(
                HTTPStatus.CONFLICT,
                "unsafe-staging",
                "artifact upload path is a symlink",
            )
    lock_fd = os.open(
        lock_path,
        os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if destination.is_file():
            complete_size = destination.stat().st_size
            complete_digest = _sha256_file(destination)
            if complete_size == artifact_bytes and hmac.compare_digest(
                complete_digest, artifact_sha256
            ):
                return {
                    "path": str(relative),
                    "sha256": complete_digest,
                    "bytes": complete_size,
                    "next_offset": complete_size,
                    "complete": True,
                }
            raise RemoteApiError(
                HTTPStatus.CONFLICT,
                "artifact-conflict",
                "completed artifact upload already exists with another identity",
            )
        if destination.exists():
            raise RemoteApiError(
                HTTPStatus.CONFLICT,
                "artifact-conflict",
                "artifact destination is invalid",
            )

        expected_metadata = {
            "schema_version": "fidb-remote-artifact-upload/v1",
            "path": str(relative),
            "sha256": artifact_sha256,
            "bytes": artifact_bytes,
        }
        if partial.exists() or metadata_path.exists():
            if not partial.is_file() or not metadata_path.is_file():
                raise RemoteApiError(
                    HTTPStatus.CONFLICT,
                    "artifact-conflict",
                    "partial artifact upload is inconsistent",
                )
            try:
                existing_metadata = json.loads(
                    metadata_path.read_text(encoding="utf-8")
                )
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise RemoteApiError(
                    HTTPStatus.CONFLICT,
                    "artifact-conflict",
                    "partial artifact metadata is invalid",
                ) from error
            if existing_metadata != expected_metadata:
                raise RemoteApiError(
                    HTTPStatus.CONFLICT,
                    "artifact-conflict",
                    "partial artifact identity changed",
                )
        elif offset == 0:
            with metadata_path.open("x", encoding="utf-8") as metadata_stream:
                metadata_stream.write(
                    json.dumps(expected_metadata, sort_keys=True, separators=(",", ":"))
                )
                metadata_stream.flush()
                os.fsync(metadata_stream.fileno())
            os.chmod(metadata_path, 0o600)
            partial.touch(mode=0o600)
        else:
            raise RemoteApiError(
                HTTPStatus.CONFLICT,
                "artifact-offset-conflict",
                "artifact upload must begin at offset zero",
            )

        current_size = partial.stat().st_size
        if current_size < offset:
            raise RemoteApiError(
                HTTPStatus.CONFLICT,
                "artifact-offset-conflict",
                "artifact chunk begins after the durable upload offset",
            )
        if current_size > offset:
            with partial.open("rb") as stream:
                stream.seek(offset)
                existing = stream.read(len(content))
            if existing != content:
                raise RemoteApiError(
                    HTTPStatus.CONFLICT,
                    "artifact-offset-conflict",
                    "replayed artifact chunk differs from durable bytes",
                )
        else:
            with partial.open("ab") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        next_offset = max(current_size, offset + len(content))
        complete = False
        if final:
            if partial.stat().st_size != artifact_bytes:
                raise RemoteApiError(
                    HTTPStatus.CONFLICT,
                    "artifact-offset-conflict",
                    "final artifact is not durably complete",
                )
            observed = _sha256_file(partial)
            if not hmac.compare_digest(observed, artifact_sha256):
                partial.unlink(missing_ok=True)
                metadata_path.unlink(missing_ok=True)
                raise RemoteApiError(
                    HTTPStatus.BAD_REQUEST,
                    "digest-mismatch",
                    "completed remote artifact digest mismatch",
                )
            os.chmod(partial, 0o644)
            os.replace(partial, destination)
            metadata_path.unlink()
            directory_fd = os.open(
                destination.parent,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            complete = True
        return {
            "path": str(relative),
            "sha256": artifact_sha256,
            "bytes": artifact_bytes,
            "next_offset": next_offset,
            "complete": complete,
        }
    finally:
        os.close(lock_fd)


class RemoteWorkerHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "FIDBRemoteWorkerAPI/1"
    sys_version = ""

    @property
    def remote_server(self) -> _RemoteServer:
        assert isinstance(self.server, _RemoteServer)
        return self.server

    def log_message(self, format: str, *args: object) -> None:
        return None

    def _response(self, status: HTTPStatus, document: object) -> None:
        payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def _error(self, error: RemoteApiError) -> None:
        self.close_connection = True
        self._response(
            error.status,
            {
                "schema_version": REMOTE_API_SCHEMA,
                "error": {"code": error.code, "message": error.message},
            },
        )

    def _body(self) -> dict[str, object]:
        if self.headers.get("Transfer-Encoding") is not None:
            raise RemoteApiError(
                HTTPStatus.BAD_REQUEST,
                "unsupported-transfer-encoding",
                "chunked request bodies are not accepted",
            )
        values = self.headers.get_all("Content-Length", failobj=[])
        if len(values) != 1:
            raise RemoteApiError(
                HTTPStatus.LENGTH_REQUIRED,
                "content-length-required",
                "exactly one Content-Length is required",
            )
        try:
            length = int(values[0])
        except ValueError as error:
            raise RemoteApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid-content-length",
                "invalid Content-Length",
            ) from error
        if length < 2 or length > self.remote_server.config.max_json_bytes:
            raise RemoteApiError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "request-too-large",
                "worker request exceeds the configured limit",
            )
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip()
        if content_type != "application/json":
            raise RemoteApiError(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "content-type-required",
                "worker requests require application/json",
            )
        try:
            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError("short body")
            document = json.loads(body)
        except (UnicodeError, ValueError, json.JSONDecodeError) as error:
            raise RemoteApiError(
                HTTPStatus.BAD_REQUEST, "invalid-json", "request is not valid JSON"
            ) from error
        if not isinstance(document, dict):
            raise RemoteApiError(
                HTTPStatus.BAD_REQUEST, "invalid-json", "request must be a JSON object"
            )
        return document

    def _authenticate(self, document: Mapping[str, object]) -> WorkerCredential:
        worker_id = _text(document, "worker_id", 128)
        credential = self.remote_server.config.credentials.get(worker_id)
        authorization = self.headers.get("Authorization", "")
        if not authorization.startswith("Bearer ") or len(authorization) > 1024:
            credential = None
            token = ""
        else:
            token = authorization[7:]
        observed = hashlib.sha256(token.encode()).hexdigest()
        expected = credential.token_sha256 if credential else "0" * 64
        if not credential or not hmac.compare_digest(observed, expected):
            raise RemoteApiError(
                HTTPStatus.UNAUTHORIZED,
                "authentication-failed",
                "worker authentication failed",
            )
        return credential

    def do_POST(self) -> None:  # noqa: N802
        try:
            target = urlsplit(self.path)
            if target.query or target.fragment or target.path not in _ROUTES:
                raise RemoteApiError(
                    HTTPStatus.NOT_FOUND, "not-found", "worker endpoint not found"
                )
            document = self._body()
            credential = self._authenticate(document)
            if target.path != "/api/v1/worker/register":
                with Coordinator(
                    self.remote_server.config.state_path,
                    self.remote_server.config.project_root,
                ) as coordinator:
                    coordinator.touch_worker(
                        credential.worker_id,
                        transport="remote-http",
                        pools=credential.pools,
                        metadata={"last_operation": target.path.rsplit("/", 1)[-1]},
                    )
            result = self._operation(target.path, document, credential)
            self._response(HTTPStatus.OK, result)
        except RemoteApiError as error:
            self._error(error)
        except CoordinatorError as error:
            self._error(
                RemoteApiError(HTTPStatus.CONFLICT, "lease-conflict", str(error))
            )
        except (OSError, ValueError) as error:
            self._error(
                RemoteApiError(HTTPStatus.CONFLICT, "operation-failed", str(error))
            )
        except Exception:
            self._error(
                RemoteApiError(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    "internal-error",
                    "worker operation could not be completed",
                )
            )

    def _operation(
        self,
        path: str,
        document: dict[str, object],
        credential: WorkerCredential,
    ) -> dict[str, object]:
        config = self.remote_server.config
        if path == "/api/v1/worker/register":
            _only_fields(document, {"worker_id", "preflight"})
            raw_preflight = document.get("preflight")
            if not isinstance(raw_preflight, dict):
                raise RemoteApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid-preflight",
                    "worker registration requires a structured preflight",
                )
            identity = raw_preflight.get("definition")
            definition_id = identity.get("id") if isinstance(identity, dict) else None
            if not isinstance(definition_id, str):
                raise RemoteApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid-preflight",
                    "worker preflight has no definition identity",
                )
            definition = load_external_toolchain(definition_id, config.project_root)
            if definition.worker_pool not in credential.pools:
                raise RemoteApiError(
                    HTTPStatus.FORBIDDEN,
                    "pool-denied",
                    "worker is not authorized for the external toolchain pool",
                )
            preflight = validate_registration(raw_preflight, definition)
            with Coordinator(config.state_path, config.project_root) as coordinator:
                worker = coordinator.touch_worker(
                    credential.worker_id,
                    transport="remote-http",
                    pools=credential.pools,
                    metadata={
                        "last_operation": "register",
                        "external_toolchain": preflight,
                    },
                )
            return {"schema_version": REMOTE_API_SCHEMA, "worker": worker}

        if path == "/api/v1/worker/claim":
            _only_fields(document, {"worker_id", "pool"})
            pool = _text(document, "pool", 64)
            if pool not in credential.pools:
                raise RemoteApiError(
                    HTTPStatus.FORBIDDEN,
                    "pool-denied",
                    "worker is not authorized for this pool",
                )
            queue = QueueConfig.load(config.queue_path, config.project_root)
            schedule = queue.operations.schedule.evaluate()
            if not queue.armed:
                with Coordinator(config.state_path, config.project_root) as coordinator:
                    pool_status = coordinator.pool_status(pool)
                return {
                    "schema_version": REMOTE_API_SCHEMA,
                    "lease": None,
                    "gate": {
                        "queue_armed": queue.armed,
                        "schedule": schedule.document(),
                    },
                    "pool": pool_status,
                }
            with Coordinator(config.state_path, config.project_root) as coordinator:
                block = (
                    coordinator.execution_block()
                    if queue.operations.schedule.finish_started_batch
                    else None
                )
                if (
                    block is not None
                    and not bool(block["active"])
                    and schedule.claims_allowed
                ):
                    if schedule.window_started_at is None:
                        raise ValueError(
                            "open schedule did not provide a durable window identity"
                        )
                    block = coordinator.start_next_block(
                        schedule.window_started_at,
                        scheduled=True,
                        allow_scheduled_reentry=(
                            queue.operations.schedule.chain_batches
                        ),
                        actor=credential.worker_id,
                    )
                claims_allowed = (
                    bool(block and block["active"])
                    if queue.operations.schedule.finish_started_batch
                    else schedule.claims_allowed
                )
                if not claims_allowed:
                    pool_status = coordinator.pool_status(pool)
                    return {
                        "schema_version": REMOTE_API_SCHEMA,
                        "lease": None,
                        "gate": {
                            "queue_armed": queue.armed,
                            "schedule": schedule.document(),
                            "execution_block": block,
                        },
                        "pool": pool_status,
                    }
                lease = coordinator.claim(
                    credential.worker_id,
                    pool=pool,
                    batch_id=(
                        str(block["batch_id"])
                        if block is not None and bool(block["active"])
                        else None
                    ),
                )
                if block is not None and lease is None:
                    coordinator.finish_active_block_if_drained(
                        actor=credential.worker_id
                    )
                pool_status = coordinator.pool_status(pool)
            if lease is None:
                return {
                    "schema_version": REMOTE_API_SCHEMA,
                    "lease": None,
                    "pool": pool_status,
                }
            try:
                _staging(config, str(lease["job_id"]), int(lease["lease_generation"]))
            except Exception as error:
                with Coordinator(config.state_path, config.project_root) as coordinator:
                    coordinator.fail(
                        str(lease["job_id"]),
                        str(lease["lease_token"]),
                        int(lease["lease_generation"]),
                        f"remote staging failed: {type(error).__name__}: {error}",
                        retryable=True,
                    )
                raise
            return {
                "schema_version": REMOTE_API_SCHEMA,
                "lease": lease,
                "pool": pool_status,
            }

        common = {"worker_id", "job_id", "lease_token", "lease_generation"}
        job_id, token, generation = _lease_fields(document)
        with Coordinator(config.state_path, config.project_root) as coordinator:
            durable_job = coordinator.get_job(job_id)
            if durable_job["leased_by"] != credential.worker_id:
                raise RemoteApiError(
                    HTTPStatus.FORBIDDEN,
                    "lease-owner-mismatch",
                    "lease is not owned by the authenticated worker",
                )
            if path == "/api/v1/worker/renew":
                _only_fields(document, common)
                job = coordinator.renew(job_id, token, generation)
                return {"schema_version": REMOTE_API_SCHEMA, "job": job}
            if path == "/api/v1/worker/stage":
                _only_fields(
                    document,
                    common | {"stage", "status", "duration_ns", "details"},
                )
                event_id = coordinator.record_stage(
                    job_id,
                    token,
                    generation,
                    _text(document, "stage", 128),
                    status=_text(document, "status", 32),
                    duration_ns=document.get("duration_ns"),
                    details=document.get("details"),
                )
                return {"schema_version": REMOTE_API_SCHEMA, "event_id": event_id}
            if path == "/api/v1/worker/fail":
                _only_fields(document, common | {"error", "retryable"})
                retryable = document.get("retryable")
                if not isinstance(retryable, bool):
                    raise RemoteApiError(
                        HTTPStatus.BAD_REQUEST,
                        "invalid-field",
                        "retryable must be a boolean",
                    )
                job = coordinator.fail(
                    job_id,
                    token,
                    generation,
                    _text(document, "error"),
                    retryable=retryable,
                )
                try:
                    notification_policy = QueueConfig.load(
                        config.queue_path, config.project_root
                    ).operations.notifications
                    error_text = str(document["error"])
                    emit_notification(
                        notification_policy,
                        "job-requeued" if job["state"] == "queued" else "job-failed",
                        {
                            "worker_id": credential.worker_id,
                            "job_id": job_id,
                            "reason": error_text,
                            "state": job["state"],
                        },
                    )
                    if error_text == "remote schedule hard cutoff":
                        emit_notification(
                            notification_policy,
                            "schedule-cutoff",
                            {"worker_id": credential.worker_id, "job_id": job_id},
                        )
                except (OSError, ValueError):
                    pass
                return {"schema_version": REMOTE_API_SCHEMA, "job": job}
            if path == "/api/v1/worker/upload":
                chunked = "offset" in document
                fields = (
                    {
                        "relative_path",
                        "artifact_sha256",
                        "artifact_bytes",
                        "offset",
                        "chunk_sha256",
                        "content_base64",
                        "final",
                    }
                    if chunked
                    else {"relative_path", "sha256", "content_base64"}
                )
                _only_fields(document, common | fields)
                coordinator.renew(job_id, token, generation)
                relative = _relative(document.get("relative_path"), "relative_path")
                encoded = _text(document, "content_base64", config.max_json_bytes)
                try:
                    content = base64.b64decode(encoded, validate=True)
                except ValueError as error:
                    raise RemoteApiError(
                        HTTPStatus.BAD_REQUEST,
                        "invalid-base64",
                        "artifact content is not valid base64",
                    ) from error
                if chunked:
                    artifact = _store_upload_chunk(
                        config,
                        _staging(config, job_id, generation),
                        relative,
                        content,
                        artifact_sha256=_text(document, "artifact_sha256", 64),
                        artifact_bytes=document.get("artifact_bytes"),
                        offset=document.get("offset"),
                        chunk_sha256=_text(document, "chunk_sha256", 64),
                        final=document.get("final"),
                    )
                else:
                    artifact = _store_upload(
                        config,
                        _staging(config, job_id, generation),
                        relative,
                        content,
                        _text(document, "sha256", 64),
                    )
                return {"schema_version": REMOTE_API_SCHEMA, "artifact": artifact}
            if path == "/api/v1/worker/complete":
                _only_fields(
                    document,
                    common
                    | {
                        "cell_id",
                        "kind",
                        "executor",
                        "seal_path",
                        "seal_sha256",
                        "fidb_path",
                        "fidbf_path",
                        "timing",
                    },
                )
                coordinator.renew(job_id, token, generation)
                staging = _staging(config, job_id, generation)
                final = (
                    config.project_root
                    / "artifacts/runs"
                    / job_id
                    / f"attempt-{generation}"
                )
                resolved_row = coordinator.connection.execute(
                    """
                    SELECT resolved_cells.cell_json
                    FROM jobs JOIN resolved_cells
                      ON resolved_cells.plan_digest = jobs.plan_digest
                     AND resolved_cells.cell_id = jobs.base_cell_id
                    WHERE jobs.job_id = ?
                    """,
                    (job_id,),
                ).fetchone()
                if resolved_row is None:
                    raise RemoteApiError(
                        HTTPStatus.CONFLICT,
                        "missing-authority",
                        "leased cell authority is unavailable",
                    )
                resolved_cell = json.loads(resolved_row["cell_json"])
                expected_identity = {
                    "cell_id": resolved_cell.get("id"),
                    "kind": resolved_cell.get("kind"),
                    "executor": resolved_cell.get("routing", {}).get("executor"),
                }
                observed_identity = {
                    field: document.get(field) for field in expected_identity
                }
                if observed_identity != expected_identity:
                    raise RemoteApiError(
                        HTTPStatus.CONFLICT,
                        "cell-identity-mismatch",
                        "completed result does not match the leased resolved cell",
                    )
                result = CellRunResult(
                    cell_id=_text(document, "cell_id", 512),
                    kind=_text(document, "kind", 64),
                    executor=_text(document, "executor", 64),
                    manifest_path=staging
                    / _relative(document.get("seal_path"), "seal_path"),
                    manifest_sha256=_text(document, "seal_sha256", 64),
                    fidb_path=staging
                    / _relative(document.get("fidb_path"), "fidb_path"),
                    fidbf_path=staging
                    / _relative(document.get("fidbf_path"), "fidbf_path"),
                    timing=document.get("timing"),
                )
                _validate_cell_timing(result.timing)

                def progress(event: ProgressEvent) -> None:
                    coordinator.record_stage(
                        job_id,
                        token,
                        generation,
                        event.stage.value,
                        status=event.status.value,
                        duration_ns=event.duration_ns,
                        details={
                            "message": event.message,
                            "metrics": event.metrics,
                            "started_at": event.started_at,
                            "finished_at": event.finished_at,
                        },
                    )

                publication = TimingRecorder(progress)
                with publication.span(
                    CellStage.PUBLICATION,
                    "publishing authenticated remote worker artifacts",
                    {"worker_id": credential.worker_id},
                ):
                    final.parent.mkdir(parents=True, exist_ok=True)
                    published = _durably_publish(
                        result, staging, final, config.project_root
                    )
                    result_document = _result_document(
                        result, published, final, config.project_root
                    )
                result_document["timing"] = {
                    "schema_version": JOB_TIMING_SCHEMA,
                    "cell": result.timing,
                    "publication": publication.document(),
                }
                job = coordinator.complete(
                    job_id, token, generation, result=result_document
                )
                return {"schema_version": REMOTE_API_SCHEMA, "job": job}
        raise RemoteApiError(
            HTTPStatus.NOT_FOUND, "not-found", "worker endpoint not found"
        )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="fidb-poc worker-api")
    result.add_argument("serve", choices=("serve",))
    result.add_argument("--project-root", type=Path, default=Path.cwd())
    result.add_argument("--state", type=Path, default=DEFAULT_STATE)
    result.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    result.add_argument(
        "--campaign-registry",
        type=Path,
        help="resolve queue and ledger from the active operational campaign",
    )
    result.add_argument("--credentials", type=Path, required=True)
    result.add_argument("--bind", default=DEFAULT_BIND)
    result.add_argument("--port", type=int, default=DEFAULT_PORT)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        state = arguments.state
        queue = arguments.queue
        if arguments.campaign_registry is not None:
            from .campaign_registry import resolve_campaign_paths

            state, queue, _binding = resolve_campaign_paths(
                arguments.project_root, arguments.campaign_registry
            )
        config = RemoteApiConfig.from_paths(
            arguments.project_root,
            state,
            queue,
            arguments.credentials,
        )
        parsed = urlsplit(f"//{arguments.bind}")
        bind = parsed.hostname or arguments.bind
        if bind not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError(
                "worker API binds only to loopback; publish it through reviewed TLS"
            )
        if not 1 <= arguments.port <= 65535:
            raise ValueError("worker API port must be 1-65535")
        server_class = _Ipv6RemoteServer if ":" in bind else _RemoteServer
        with server_class(
            (bind, arguments.port), config, RemoteWorkerHandler
        ) as server:
            server.serve_forever()
        return 0
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=os.sys.stderr)
        return 1
