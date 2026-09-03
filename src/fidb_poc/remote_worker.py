"""Authenticated HTTP client for a remote typed FIDB worker."""

from __future__ import annotations

import argparse
import base64
from dataclasses import replace
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import threading
import time
from typing import Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .cell_runner import CellResolutionError, ProgressEvent, run_cell
from .coordinator import QueueConfig, WORKER_POOLS
from .external_workers import (
    load_external_toolchain,
    preflight_external_toolchain,
)
from .operations_policy import evaluate_operations
from .remote_api import MAX_CHUNK_BYTES


class RemoteWorkerError(RuntimeError):
    """A remote worker request or local execution failed safely."""


class RemoteCoordinatorClient:
    def __init__(
        self,
        origin: str,
        worker_id: str,
        token: str,
        *,
        timeout_seconds: int = 30,
        allow_http_loopback: bool = False,
    ) -> None:
        parsed = urlsplit(origin)
        loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
        if (
            (parsed.scheme != "https" and not (allow_http_loopback and loopback))
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "remote coordinator must be an HTTPS origin "
                "(plain HTTP is test-only on loopback)"
            )
        if not worker_id or worker_id != worker_id.strip():
            raise ValueError("worker id must be a non-empty token")
        if not token or len(token) > 512:
            raise ValueError("remote worker token is missing or too long")
        self.origin = origin.rstrip("/")
        self.worker_id = worker_id
        self.token = token
        self.timeout_seconds = timeout_seconds

    def request(
        self, operation: str, document: Mapping[str, object]
    ) -> dict[str, object]:
        body = json.dumps(
            {"worker_id": self.worker_id, **document},
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        request = Request(
            f"{self.origin}/api/v1/worker/{operation}",
            data=body,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                payload = response.read(4 * 1024 * 1024)
        except HTTPError as error:
            payload = error.read(64 * 1024)
            try:
                message = json.loads(payload).get("error", {}).get("message")
            except (UnicodeError, json.JSONDecodeError):
                message = None
            raise RemoteWorkerError(
                message or f"remote coordinator returned HTTP {error.code}"
            ) from error
        except (OSError, URLError) as error:
            raise RemoteWorkerError(
                f"remote coordinator unavailable: {error}"
            ) from error
        try:
            result = json.loads(payload)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise RemoteWorkerError(
                "remote coordinator returned invalid JSON"
            ) from error
        if not isinstance(result, dict):
            raise RemoteWorkerError("remote coordinator returned a non-object response")
        return result

    @staticmethod
    def lease_fields(lease: Mapping[str, object]) -> dict[str, object]:
        return {
            "job_id": lease["job_id"],
            "lease_token": lease["lease_token"],
            "lease_generation": lease["lease_generation"],
        }


class _RemoteHeartbeat:
    def __init__(
        self,
        client: RemoteCoordinatorClient,
        lease: Mapping[str, object],
        interval_seconds: float,
    ) -> None:
        self.client = client
        self.lease = lease
        self.interval = interval_seconds
        self.stopped = threading.Event()
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stopped.set()
        self.thread.join(timeout=self.interval + 2)

    def check(self) -> None:
        if self.error:
            raise RemoteWorkerError(f"remote lease heartbeat failed: {self.error}")

    def _run(self) -> None:
        try:
            while not self.stopped.wait(self.interval):
                self.client.request(
                    "renew", RemoteCoordinatorClient.lease_fields(self.lease)
                )
        except BaseException as error:
            self.error = error
            self.stopped.set()


def _attempt_root(
    project_root: Path, worker_id: str, lease: Mapping[str, object]
) -> Path:
    safe_worker = worker_id.replace(".", "-").replace("_", "-")
    root = (
        project_root
        / "var/fidb-remote-worker"
        / safe_worker
        / f"{lease['job_id']}-g{lease['lease_generation']}"
    )
    if root.exists() or root.is_symlink():
        raise RemoteWorkerError(f"remote attempt root already exists: {root}")
    root.mkdir(parents=True)
    return root


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.resolve(strict=True).relative_to(root.resolve()))
    except (FileNotFoundError, ValueError) as error:
        raise RemoteWorkerError(
            f"generated artifact escaped attempt root: {path}"
        ) from error


def _upload(
    client: RemoteCoordinatorClient,
    lease: Mapping[str, object],
    path: Path,
    attempt_root: Path,
) -> None:
    artifact_sha256 = hashlib.sha256()
    artifact_bytes = 0
    with path.open("rb") as stream:
        for content in iter(lambda: stream.read(1024 * 1024), b""):
            artifact_sha256.update(content)
            artifact_bytes += len(content)
    if artifact_bytes < 1:
        raise RemoteWorkerError(f"generated artifact is empty: {path}")
    digest = artifact_sha256.hexdigest()
    offset = 0
    with path.open("rb") as stream:
        while offset < artifact_bytes:
            content = stream.read(MAX_CHUNK_BYTES)
            response = client.request(
                "upload",
                {
                    **client.lease_fields(lease),
                    "relative_path": _relative(path, attempt_root),
                    "artifact_sha256": digest,
                    "artifact_bytes": artifact_bytes,
                    "offset": offset,
                    "chunk_sha256": hashlib.sha256(content).hexdigest(),
                    "content_base64": base64.b64encode(content).decode("ascii"),
                    "final": offset + len(content) == artifact_bytes,
                },
            )
            artifact = response.get("artifact")
            expected_offset = offset + len(content)
            if (
                isinstance(artifact, dict)
                and artifact.get("complete") is True
                and artifact.get("next_offset") == artifact_bytes
                and artifact.get("sha256") == digest
                and artifact.get("bytes") == artifact_bytes
            ):
                return
            if (
                not isinstance(artifact, dict)
                or isinstance(artifact.get("next_offset"), bool)
                or not isinstance(artifact.get("next_offset"), int)
                or not expected_offset <= artifact["next_offset"] <= artifact_bytes
                or artifact.get("complete") is not False
            ):
                raise RemoteWorkerError(
                    "remote coordinator returned an invalid upload acknowledgement"
                )
            if artifact["next_offset"] == artifact_bytes and not artifact["complete"]:
                offset = max(0, artifact_bytes - MAX_CHUNK_BYTES)
            else:
                offset = artifact["next_offset"]
            stream.seek(offset)


def execute_remote_lease(
    client: RemoteCoordinatorClient,
    lease: Mapping[str, object],
    project_root: Path,
    *,
    lease_seconds: int,
    verbose: bool = False,
    cutoff_event: threading.Event | None = None,
) -> bool:
    attempt = _attempt_root(project_root, client.worker_id, lease)
    fields = client.lease_fields(lease)
    heartbeat = _RemoteHeartbeat(client, lease, max(1.0, min(60.0, lease_seconds / 3)))

    def progress(event: ProgressEvent) -> None:
        heartbeat.check()
        client.request(
            "stage",
            {
                **fields,
                "stage": event.stage.value,
                "status": event.status.value,
                "duration_ns": event.duration_ns,
                "details": {
                    "message": event.message,
                    "metrics": event.metrics,
                    "started_at": event.started_at,
                    "finished_at": event.finished_at,
                },
            },
        )

    heartbeat.start()
    try:
        result = run_cell(
            lease["cell"],
            lease["factor_variants"],
            project_root,
            attempt,
            progress=progress,
            verbose=verbose,
        )
        heartbeat.check()
        for path in (result.seal_path, result.fidb_path, result.fidbf_path):
            _upload(client, lease, Path(path), attempt)
        response = client.request(
            "complete",
            {
                **fields,
                "cell_id": result.cell_id,
                "kind": result.kind,
                "executor": result.executor,
                "seal_path": _relative(Path(result.seal_path), attempt),
                "seal_sha256": result.seal_sha256,
                "fidb_path": _relative(Path(result.fidb_path), attempt),
                "fidbf_path": _relative(Path(result.fidbf_path), attempt),
                "timing": result.timing,
            },
        )
        job = response.get("job")
        if not isinstance(job, dict) or job.get("state") != "complete":
            raise RemoteWorkerError(
                "remote coordinator did not complete the leased job"
            )
        return True
    except KeyboardInterrupt:
        reason = (
            "remote schedule hard cutoff"
            if cutoff_event is not None and cutoff_event.is_set()
            else "remote worker interrupted"
        )
        try:
            client.request(
                "fail",
                {**fields, "error": reason, "retryable": True},
            )
        except RemoteWorkerError:
            pass
        raise
    except Exception as error:
        retryable = not isinstance(error, (CellResolutionError, ValueError))
        try:
            client.request(
                "fail",
                {
                    **fields,
                    "error": f"{type(error).__name__}: {error}",
                    "retryable": retryable,
                },
            )
        except RemoteWorkerError:
            pass
        print(f"error: {lease['job_id']}: {error}", file=sys.stderr, flush=True)
        return False
    finally:
        heartbeat.stop()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="fidb-poc remote-worker")
    result.add_argument("run", choices=("run",))
    result.add_argument("--project-root", type=Path, default=Path.cwd())
    result.add_argument("--queue", type=Path, default=Path("plans/priority-queue.toml"))
    result.add_argument("--coordinator", required=True)
    result.add_argument("--worker-id", required=True)
    result.add_argument("--token-env", default="FIDB_REMOTE_WORKER_TOKEN")
    result.add_argument("--pool", choices=WORKER_POOLS, required=True)
    result.add_argument(
        "--external-toolchain",
        help="reviewed toolchains/external definition id for this worker",
    )
    result.add_argument("--poll-seconds", type=int, default=5)
    result.add_argument("--once", action="store_true")
    result.add_argument("--until-drained", action="store_true")
    result.add_argument("--verbose", "-v", action="store_true")
    result.add_argument(
        "--allow-http-loopback", action="store_true", help=argparse.SUPPRESS
    )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    if arguments.once and arguments.until_drained:
        print(
            "error: --once and --until-drained are mutually exclusive", file=sys.stderr
        )
        return 1
    root = arguments.project_root.expanduser().resolve()
    queue_path = (
        arguments.queue if arguments.queue.is_absolute() else root / arguments.queue
    )
    try:
        queue = QueueConfig.load(queue_path, root)
        token = os.environ.get(arguments.token_env, "")
        client = RemoteCoordinatorClient(
            arguments.coordinator,
            arguments.worker_id,
            token,
            allow_http_loopback=arguments.allow_http_loopback,
        )
        if arguments.external_toolchain:
            definition = load_external_toolchain(arguments.external_toolchain, root)
            if definition.worker_pool != arguments.pool:
                raise ValueError("external toolchain worker_pool does not match --pool")
            preflight = preflight_external_toolchain(definition, root)
            if not preflight["ready"]:
                print(json.dumps(preflight, indent=2, sort_keys=True))
                raise RemoteWorkerError("external toolchain preflight did not pass")
            queue = replace(
                queue,
                operations=replace(
                    queue.operations,
                    resources=definition.resources,
                ),
            )
            client.request("register", {"preflight": preflight})
        previous_sigterm = signal.getsignal(signal.SIGTERM)

        def interrupt(_signum: int, _frame: object) -> None:
            raise KeyboardInterrupt

        signal.signal(signal.SIGTERM, interrupt)
        try:
            while True:
                operations = evaluate_operations(queue.operations, root)
                resources = operations["resources"]
                schedule = operations["schedule"]
                if not isinstance(resources, dict) or not isinstance(schedule, dict):
                    raise RemoteWorkerError("operations preflight is malformed")
                schedule_blocks_request = (
                    not bool(schedule["claims_allowed"])
                    and not queue.operations.schedule.finish_started_batch
                )
                if not bool(resources["passed"]) or schedule_blocks_request:
                    if arguments.once:
                        print(json.dumps(operations, indent=2, sort_keys=True))
                        return 0
                    time.sleep(arguments.poll_seconds)
                    continue
                response = client.request("claim", {"pool": arguments.pool})
                lease = response.get("lease")
                if lease is None:
                    pool_status = response.get("pool")
                    if (
                        arguments.until_drained
                        and isinstance(pool_status, dict)
                        and pool_status.get("drained") is True
                    ):
                        return 0
                    if arguments.until_drained and isinstance(
                        response.get("gate"), dict
                    ):
                        print(json.dumps(response["gate"], indent=2, sort_keys=True))
                        return 1
                    if arguments.once:
                        return 0
                    time.sleep(arguments.poll_seconds)
                    continue
                if not isinstance(lease, dict):
                    raise RemoteWorkerError(
                        "remote coordinator returned an invalid lease"
                    )
                cutoff_event = threading.Event()
                timer = None
                cutoff_value = (
                    None
                    if queue.operations.schedule.finish_started_batch
                    else schedule.get("hard_cutoff_at")
                )
                if isinstance(cutoff_value, str):
                    cutoff_at = datetime.fromisoformat(cutoff_value)
                    delay = max(0.0, cutoff_at.timestamp() - time.time())

                    def interrupt_at_cutoff() -> None:
                        cutoff_event.set()
                        os.kill(os.getpid(), signal.SIGTERM)

                    timer = threading.Timer(delay, interrupt_at_cutoff)
                    timer.daemon = True
                    timer.start()
                try:
                    succeeded = execute_remote_lease(
                        client,
                        lease,
                        root,
                        lease_seconds=queue.lease_seconds,
                        verbose=arguments.verbose,
                        cutoff_event=cutoff_event,
                    )
                except KeyboardInterrupt:
                    if cutoff_event.is_set():
                        if arguments.once:
                            return 1
                        continue
                    raise
                finally:
                    if timer is not None:
                        timer.cancel()
                if arguments.once:
                    return 0 if succeeded else 1
        finally:
            signal.signal(signal.SIGTERM, previous_sigterm)
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, RemoteWorkerError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
