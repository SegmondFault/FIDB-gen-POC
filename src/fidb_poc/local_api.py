"""Bounded local HTTP adapter for the FIDB coordinator.

The API is intentionally narrower than the worker CLI.  It exposes durable
state and reviewed authorities, plus typed coordinator controls and validated
plan-draft resolution/persistence. It cannot arm a queue, claim a job, run a
build, or accept a command string.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import ipaddress
import json
import logging
from pathlib import Path
import socket
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Mapping, Sequence
from urllib.parse import parse_qs, urlsplit

from .authority_catalog import authority_catalog
from .capabilities import detect_capabilities
from .coordinator import (
    DEFAULT_TIMING_LIMIT,
    MAX_TIMING_LIMIT,
    Coordinator,
    CoordinatorError,
    QueueConfig,
)
from .operations_policy import evaluate_operations
from .plan_drafts import DraftConflictError, resolve_plan_draft, save_plan_draft

API_SCHEMA = "fidb-local-api/v1"
DEFAULT_BIND = "127.0.0.1"
DEFAULT_PORT = 8765
DEFAULT_QUEUE = Path("plans/priority-queue.toml")
DEFAULT_STATE = Path("var/fidb-coordinator/ledger.sqlite3")
MAX_REQUEST_TARGET_BYTES = 4_096
MAX_REQUEST_BODY_BYTES = 16 * 1024
MAX_RESPONSE_BODY_BYTES = 8 * 1024 * 1024
DEFAULT_EVENT_LIMIT = 100
MAX_EVENT_LIMIT = 500

_GET_PATHS = {
    "/api/v1/health",
    "/api/v1/status",
    "/api/v1/snapshot",
    "/api/v1/events",
    "/api/v1/capabilities",
    "/api/v1/authority",
    "/api/v1/timings",
    "/api/v1/preflight",
}
_POST_PATHS = {
    "/api/v1/sync",
    "/api/v1/pause",
    "/api/v1/resume",
    "/api/v1/plan-drafts/resolve",
    "/api/v1/plan-drafts/save",
}

log = logging.getLogger(__name__)


class ApiError(RuntimeError):
    """A safe client-facing API error."""

    def __init__(self, status: HTTPStatus, code: str, message: str):
        self.status = status
        self.code = code
        self.message = message
        super().__init__(message)


def _inside_project(path: Path, root: Path, label: str) -> Path:
    candidate = path if path.is_absolute() else root / path
    if candidate.is_symlink():
        raise ValueError(f"{label} cannot be a symlink: {candidate}")
    resolved = candidate.expanduser().resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(f"{label} must remain inside the project root") from error
    return resolved


def _origin(value: str) -> str:
    if value != value.strip() or not value:
        raise ValueError("allowed origin must be a non-empty origin")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"invalid allowed origin: {value}")
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


@dataclass(frozen=True)
class LocalApiConfig:
    """Validated fixed paths and protocol bounds used by an API server."""

    project_root: Path
    state_path: Path
    queue_path: Path
    allowed_origins: tuple[str, ...] = ()
    max_request_body_bytes: int = MAX_REQUEST_BODY_BYTES
    max_response_body_bytes: int = MAX_RESPONSE_BODY_BYTES
    max_event_limit: int = MAX_EVENT_LIMIT
    max_timing_limit: int = MAX_TIMING_LIMIT

    @classmethod
    def from_paths(
        cls,
        project_root: str | Path,
        state_path: str | Path = DEFAULT_STATE,
        queue_path: str | Path = DEFAULT_QUEUE,
        *,
        allowed_origins: Sequence[str] = (),
    ) -> "LocalApiConfig":
        root = Path(project_root).expanduser().resolve()
        required = (
            root / "pyproject.toml",
            root / "worker.toml",
            root / "recipes",
            root / "targets/registry.toml",
            root / "lanes/registry.toml",
            root / "toolchains/registry.toml",
        )
        if not root.is_dir() or any(not path.exists() for path in required):
            raise ValueError(f"not an FIDB project root: {root}")
        state = _inside_project(Path(state_path), root, "coordinator state")
        queue = _inside_project(Path(queue_path), root, "queue configuration")
        if not queue.is_file():
            raise ValueError(f"queue configuration is not a file: {queue}")
        origins = tuple(_origin(value) for value in allowed_origins)
        if len(set(origins)) != len(origins):
            raise ValueError("allowed origins contain duplicates")
        return cls(
            project_root=root,
            state_path=state,
            queue_path=queue,
            allowed_origins=origins,
        )

    def __post_init__(self) -> None:
        if self.max_request_body_bytes < 2:
            raise ValueError("max_request_body_bytes must be at least 2")
        if self.max_response_body_bytes < 256:
            raise ValueError("max_response_body_bytes must be at least 256")
        if self.max_event_limit < 1:
            raise ValueError("max_event_limit must be positive")
        if self.max_timing_limit < 1 or self.max_timing_limit > MAX_TIMING_LIMIT:
            raise ValueError(f"max_timing_limit must be 1-{MAX_TIMING_LIMIT}")


def _bind_address(value: str) -> str:
    if value == "localhost":
        return "127.0.0.1"
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError(
            "bind must be localhost or a literal local interface address"
        ) from error
    if address.is_unspecified or address.is_multicast:
        raise ValueError("wildcard and multicast bind addresses are not permitted")
    return str(address)


def _event_page(coordinator: Coordinator, after: int, limit: int) -> dict[str, object]:
    rows = coordinator.connection.execute(
        """
        SELECT * FROM events
        WHERE event_id > ?
        ORDER BY event_id
        LIMIT ?
        """,
        (after, limit + 1),
    ).fetchall()
    has_more = len(rows) > limit
    selected = rows[:limit]
    events = [
        {
            "event_id": int(row["event_id"]),
            "occurred_at": str(row["occurred_at"]),
            "event_type": str(row["event_type"]),
            "actor": str(row["actor"]),
            "batch_id": row["batch_id"],
            "job_id": row["job_id"],
            "plan_digest": row["plan_digest"],
            "payload": json.loads(row["payload_json"]),
        }
        for row in selected
    ]
    return {
        "schema_version": "fidb-coordinator-events/v1",
        "after": after,
        "limit": limit,
        "events": events,
        "next_cursor": events[-1]["event_id"] if events else after,
        "has_more": has_more,
    }


def _public_snapshot(
    coordinator: Coordinator,
    include_inactive: bool,
    stage_attempt_limit: int = MAX_TIMING_LIMIT,
) -> dict[str, object]:
    result = coordinator.snapshot(
        include_inactive=include_inactive,
        include_events=False,
        stage_attempt_limit=stage_attempt_limit,
    )
    # Lease tokens are worker fencing credentials and never belong in the
    # analyst/control-plane response, even on a loopback API.
    for job in result.get("jobs", []):
        if isinstance(job, dict):
            job.pop("lease_token", None)
    return result


def _duplicate_safe_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


class _ApiServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        config: LocalApiConfig,
        handler: type[BaseHTTPRequestHandler],
    ) -> None:
        self.config = config
        super().__init__(server_address, handler)


class _Ipv6ApiServer(_ApiServer):
    address_family = socket.AF_INET6


class LocalApiHandler(BaseHTTPRequestHandler):
    """Strict JSON handler for the fixed local coordinator API."""

    protocol_version = "HTTP/1.1"
    server_version = "FIDBLocalAPI/1"
    sys_version = ""

    @property
    def api_server(self) -> _ApiServer:
        assert isinstance(self.server, _ApiServer)
        return self.server

    def log_message(self, format: str, *args: object) -> None:
        log.info("local-api %s - %s", self.address_string(), format % args)

    def _request_origin(self, *, mutation: bool) -> str | None:
        origin = self.headers.get("Origin")
        if origin is None:
            return None
        try:
            normalized = _origin(origin)
        except ValueError as error:
            raise ApiError(HTTPStatus.FORBIDDEN, "origin-denied", str(error)) from error
        host = self.headers.get("Host", "").lower()
        same_origin = normalized in {f"http://{host}", f"https://{host}"}
        allowed = normalized in self.api_server.config.allowed_origins or same_origin
        if not allowed:
            raise ApiError(
                HTTPStatus.FORBIDDEN,
                "origin-denied",
                "request origin is not allowed",
            )
        return normalized

    def _headers(self, length: int, origin: str | None) -> None:
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        if origin is not None:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

    def _json_response(
        self,
        status: HTTPStatus,
        document: object,
        *,
        origin: str | None = None,
    ) -> None:
        payload = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        if len(payload) > self.api_server.config.max_response_body_bytes:
            raise ApiError(
                HTTPStatus.INSUFFICIENT_STORAGE,
                "response-too-large",
                "response exceeds the configured API limit",
            )
        self.send_response(status)
        self._headers(len(payload), origin)
        self.end_headers()
        self.wfile.write(payload)

    def _error(self, error: ApiError, origin: str | None = None) -> None:
        # Some failures (origin rejection, an unknown endpoint, oversized
        # content) occur before the request body is consumed.  Closing the
        # connection prevents those bytes from being parsed as a second HTTP
        # request on the persistent connection.
        self.close_connection = True
        document = {
            "schema_version": API_SCHEMA,
            "error": {"code": error.code, "message": error.message},
        }
        payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        self.send_response(error.status)
        self._headers(len(payload), origin)
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def _dispatch(self, operation: Callable[[], None], *, mutation: bool) -> None:
        origin = None
        try:
            if len(self.path.encode("utf-8")) > MAX_REQUEST_TARGET_BYTES:
                raise ApiError(
                    HTTPStatus.REQUEST_URI_TOO_LONG,
                    "request-target-too-long",
                    "request target exceeds the API limit",
                )
            origin = self._request_origin(mutation=mutation)
            operation()
        except ApiError as error:
            self._error(error, origin)
        except (CoordinatorError, ValueError, OSError) as error:
            self._error(
                ApiError(HTTPStatus.CONFLICT, "operation-failed", str(error)),
                origin,
            )
        except Exception:
            log.exception("unhandled local API error")
            self._error(
                ApiError(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    "internal-error",
                    "the local API could not complete the request",
                ),
                origin,
            )

    def _target(self) -> tuple[str, dict[str, list[str]]]:
        target = urlsplit(self.path)
        try:
            query = (
                parse_qs(
                    target.query,
                    keep_blank_values=True,
                    strict_parsing=True,
                    max_num_fields=8,
                )
                if target.query
                else {}
            )
        except ValueError as error:
            raise ApiError(
                HTTPStatus.BAD_REQUEST, "invalid-query", "query string is invalid"
            ) from error
        return target.path, query

    def _coordinator(self) -> Coordinator:
        if not self.api_server.config.state_path.is_file():
            raise ApiError(
                HTTPStatus.CONFLICT,
                "coordinator-not-initialized",
                "coordinator state does not exist; synchronize the configured queue",
            )
        return Coordinator(
            self.api_server.config.state_path,
            self.api_server.config.project_root,
        )

    def _read_body(self) -> dict[str, object]:
        if self.headers.get("Transfer-Encoding") is not None:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "unsupported-transfer-encoding",
                "chunked request bodies are not accepted",
            )
        lengths = self.headers.get_all("Content-Length", failobj=[])
        if len(lengths) != 1:
            raise ApiError(
                HTTPStatus.LENGTH_REQUIRED,
                "content-length-required",
                "exactly one Content-Length header is required",
            )
        try:
            length = int(lengths[0])
        except (TypeError, ValueError) as error:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid-content-length",
                "Content-Length must be a non-negative integer",
            ) from error
        if length < 0:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid-content-length",
                "Content-Length must be a non-negative integer",
            )
        if length > self.api_server.config.max_request_body_bytes:
            raise ApiError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "request-body-too-large",
                "request body exceeds the configured API limit",
            )
        if self.headers.get_content_type() != "application/json":
            raise ApiError(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "json-required",
                "Content-Type must be application/json",
            )
        payload = self.rfile.read(length)
        try:
            document = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=_duplicate_safe_object,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError(f"invalid JSON constant: {value}")
                ),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid-json",
                "request body must be one valid JSON object",
            ) from error
        if not isinstance(document, dict):
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid-json-shape",
                "request body must be a JSON object",
            )
        return document

    @staticmethod
    def _only_fields(document: Mapping[str, object], allowed: set[str]) -> None:
        unknown = set(document) - allowed
        if unknown:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "unsupported-fields",
                f"unsupported request fields: {sorted(unknown)}",
            )

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._dispatch(self._get, mutation=False)

    def _get(self) -> None:
        origin = self._request_origin(mutation=False)
        path, query = self._target()
        if path not in _GET_PATHS:
            if path in _POST_PATHS:
                raise ApiError(
                    HTTPStatus.METHOD_NOT_ALLOWED,
                    "method-not-allowed",
                    "this endpoint requires POST",
                )
            raise ApiError(HTTPStatus.NOT_FOUND, "not-found", "endpoint not found")

        if path == "/api/v1/health":
            if query:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST, "invalid-query", "health takes no query"
                )
            coordinator = {"state": "not-initialized"}
            if self.api_server.config.state_path.is_file():
                with self._coordinator() as opened:
                    status = opened.status()
                coordinator = {
                    "state": "ready",
                    "queue_status": status["status"],
                    "max_workers": status["max_workers"],
                    "active_workers": status["active_workers"],
                    "available_worker_slots": status["available_worker_slots"],
                }
            self._json_response(
                HTTPStatus.OK,
                {
                    "schema_version": API_SCHEMA,
                    "status": "ok",
                    "service": "fidb-local-api",
                    "coordinator": coordinator,
                },
                origin=origin,
            )
            return

        if path == "/api/v1/capabilities":
            if query:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid-query",
                    "capabilities takes no query",
                )
            if self.api_server.config.state_path.is_file():
                with self._coordinator() as coordinator:
                    result = detect_capabilities(
                        self.api_server.config.project_root,
                        connection=coordinator.connection,
                    )
                    status = coordinator.status()
                for pool in result["worker_pools"].values():
                    pool.update(
                        {
                            "max_workers": status["max_workers"],
                            "active_workers": status["active_workers"],
                            "available_worker_slots": status["available_worker_slots"],
                        }
                    )
            else:
                result = detect_capabilities(self.api_server.config.project_root)
            self._json_response(HTTPStatus.OK, result, origin=origin)
            return

        if path == "/api/v1/authority":
            if query:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid-query",
                    "authority takes no query",
                )
            self._json_response(
                HTTPStatus.OK,
                authority_catalog(self.api_server.config.project_root),
                origin=origin,
            )
            return

        if path == "/api/v1/preflight":
            if query:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST, "invalid-query", "preflight takes no query"
                )
            queue = QueueConfig.load(
                self.api_server.config.queue_path,
                self.api_server.config.project_root,
            )
            result = evaluate_operations(
                queue.operations, self.api_server.config.project_root
            )
            result["queue_armed"] = queue.armed
            result["ready"] = bool(result["ready"]) and queue.armed
            self._json_response(HTTPStatus.OK, result, origin=origin)
            return

        with self._coordinator() as coordinator:
            if path == "/api/v1/status":
                if query:
                    raise ApiError(
                        HTTPStatus.BAD_REQUEST, "invalid-query", "status takes no query"
                    )
                result = coordinator.status()
            elif path == "/api/v1/snapshot":
                unknown = set(query) - {"include_inactive"}
                if unknown or any(len(values) != 1 for values in query.values()):
                    raise ApiError(
                        HTTPStatus.BAD_REQUEST,
                        "invalid-query",
                        "snapshot query is invalid",
                    )
                raw = query.get("include_inactive", ["false"])[0]
                if raw not in {"false", "true"}:
                    raise ApiError(
                        HTTPStatus.BAD_REQUEST,
                        "invalid-query",
                        "include_inactive must be true or false",
                    )
                result = _public_snapshot(
                    coordinator,
                    raw == "true",
                    self.api_server.config.max_timing_limit,
                )
            elif path == "/api/v1/timings":
                unknown = set(query) - {"limit"}
                if unknown or any(len(values) != 1 for values in query.values()):
                    raise ApiError(
                        HTTPStatus.BAD_REQUEST,
                        "invalid-query",
                        "timings query is invalid",
                    )
                try:
                    limit = int(query.get("limit", [str(DEFAULT_TIMING_LIMIT)])[0])
                except ValueError as error:
                    raise ApiError(
                        HTTPStatus.BAD_REQUEST,
                        "invalid-query",
                        "timing limit must be an integer",
                    ) from error
                if limit < 1 or limit > self.api_server.config.max_timing_limit:
                    raise ApiError(
                        HTTPStatus.BAD_REQUEST,
                        "invalid-query",
                        "timing limit must be "
                        f"1-{self.api_server.config.max_timing_limit}",
                    )
                result = coordinator.timings(limit=limit)
            else:
                unknown = set(query) - {"after", "limit"}
                if unknown or any(len(values) != 1 for values in query.values()):
                    raise ApiError(
                        HTTPStatus.BAD_REQUEST,
                        "invalid-query",
                        "events query is invalid",
                    )
                try:
                    after = int(query.get("after", ["0"])[0])
                    limit = int(query.get("limit", [str(DEFAULT_EVENT_LIMIT)])[0])
                except ValueError as error:
                    raise ApiError(
                        HTTPStatus.BAD_REQUEST,
                        "invalid-query",
                        "after and limit must be integers",
                    ) from error
                if (
                    after < 0
                    or limit < 1
                    or limit > self.api_server.config.max_event_limit
                ):
                    raise ApiError(
                        HTTPStatus.BAD_REQUEST,
                        "invalid-query",
                        f"after must be non-negative and limit must be 1-{self.api_server.config.max_event_limit}",
                    )
                result = _event_page(coordinator, after, limit)
        self._json_response(HTTPStatus.OK, result, origin=origin)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._dispatch(self._post, mutation=True)

    def _post(self) -> None:
        origin = self._request_origin(mutation=True)
        path, query = self._target()
        if query:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid-query",
                "control endpoints take no query",
            )
        if path not in _POST_PATHS:
            if path in _GET_PATHS:
                raise ApiError(
                    HTTPStatus.METHOD_NOT_ALLOWED,
                    "method-not-allowed",
                    "this endpoint is read-only",
                )
            raise ApiError(HTTPStatus.NOT_FOUND, "not-found", "endpoint not found")
        document = self._read_body()
        if path == "/api/v1/plan-drafts/resolve":
            self._only_fields(document, {"toml"})
            try:
                result = resolve_plan_draft(
                    document.get("toml"),
                    self.api_server.config.project_root,
                )
            except ValueError as error:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid-plan-draft",
                    str(error),
                ) from error
        elif path == "/api/v1/plan-drafts/save":
            self._only_fields(document, {"name", "toml", "expected_sha256"})
            try:
                result = save_plan_draft(
                    document.get("name"),
                    document.get("toml"),
                    self.api_server.config.project_root,
                    expected_sha256=document.get("expected_sha256"),
                )
            except DraftConflictError as error:
                raise ApiError(
                    HTTPStatus.CONFLICT,
                    "draft-conflict",
                    str(error),
                ) from error
            except ValueError as error:
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid-plan-draft",
                    str(error),
                ) from error
        elif path == "/api/v1/sync":
            self._only_fields(document, set())
            with Coordinator(
                self.api_server.config.state_path,
                self.api_server.config.project_root,
            ) as coordinator:
                coordinator.sync_queue(
                    self.api_server.config.queue_path,
                    actor="local-api",
                )
                result = coordinator.status()
        elif path == "/api/v1/pause":
            self._only_fields(document, {"reason"})
            reason = document.get("reason")
            if (
                not isinstance(reason, str)
                or not reason
                or reason != reason.strip()
                or len(reason) > 256
                or any(
                    ord(character) < 32 or ord(character) == 127 for character in reason
                )
            ):
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid-pause-reason",
                    "reason must be 1-256 printable characters without outer whitespace",
                )
            with self._coordinator() as coordinator:
                result = coordinator.pause(reason, actor="local-api")
        else:
            self._only_fields(document, set())
            with self._coordinator() as coordinator:
                result = coordinator.resume(actor="local-api")
        self._json_response(HTTPStatus.OK, result, origin=origin)

    def do_OPTIONS(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._dispatch(self._options, mutation=False)

    def _options(self) -> None:
        origin = self._request_origin(mutation=False)
        if origin is None:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "origin-required",
                "CORS preflight requires an allowed Origin",
            )
        path, query = self._target()
        if query or path not in _GET_PATHS | _POST_PATHS:
            raise ApiError(HTTPStatus.NOT_FOUND, "not-found", "endpoint not found")
        requested_method = self.headers.get("Access-Control-Request-Method", "")
        expected = "POST" if path in _POST_PATHS else "GET"
        if requested_method != expected:
            raise ApiError(
                HTTPStatus.METHOD_NOT_ALLOWED,
                "method-not-allowed",
                f"preflight method must be {expected}",
            )
        requested_headers = {
            value.strip().lower()
            for value in self.headers.get("Access-Control-Request-Headers", "").split(
                ","
            )
            if value.strip()
        }
        if requested_headers - {"content-type"}:
            raise ApiError(
                HTTPStatus.FORBIDDEN,
                "headers-denied",
                "preflight requested unsupported headers",
            )
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Content-Length", "0")
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", expected)
        if expected == "POST":
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "300")
        self.send_header("Vary", "Origin")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()


def create_server(
    config: LocalApiConfig,
    *,
    bind: str = DEFAULT_BIND,
    port: int = DEFAULT_PORT,
) -> ThreadingHTTPServer:
    """Create, but do not start, a configured local API server."""

    address = _bind_address(bind)
    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
        raise ValueError("port must be between 0 and 65535")
    server_class = _Ipv6ApiServer if ":" in address else _ApiServer
    return server_class((address, port), config, LocalApiHandler)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fidb-poc api",
        description=(
            "Serve a bounded coordinator API. The default bind is loopback; "
            "use a specific interface address explicitly when a proxy requires it."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="serve the local coordinator API")
    serve.add_argument("--project-root", type=Path, default=Path.cwd())
    serve.add_argument("--state", type=Path, default=DEFAULT_STATE)
    serve.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    serve.add_argument("--bind", default=DEFAULT_BIND)
    serve.add_argument("--port", type=int, default=DEFAULT_PORT)
    serve.add_argument(
        "--allow-origin",
        action="append",
        default=[],
        help="exact browser origin allowed for cross-origin access; repeat as needed",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        config = LocalApiConfig.from_paths(
            arguments.project_root,
            arguments.state,
            arguments.queue,
            allowed_origins=arguments.allow_origin,
        )
        server = create_server(config, bind=arguments.bind, port=arguments.port)
    except (OSError, ValueError) as error:
        print(f"fidb-poc api: {error}", file=__import__("sys").stderr)
        return 2

    address, port = server.server_address[:2]
    display_address = f"[{address}]" if ":" in str(address) else address
    print(f"FIDB local API listening on http://{display_address}:{port}", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover - module execution convenience
    raise SystemExit(main())
