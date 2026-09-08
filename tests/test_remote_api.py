import base64
from email.parser import BytesParser
from email.policy import default
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from fidb_poc.coordinator import Coordinator, QueueConfig
from fidb_poc.external_workers import load_external_toolchain
from fidb_poc.remote_api import (
    CREDENTIALS_SCHEMA,
    RemoteApiConfig,
    RemoteWorkerHandler,
    _RemoteServer,
    load_credentials,
)
from fidb_poc.timing import CellStage, TimingRecorder


class _OpenBytesIO(io.BytesIO):
    def close(self):
        self.flush()


class _RequestSocket:
    def __init__(self, request: bytes):
        self.input = io.BytesIO(request)
        self.output = _OpenBytesIO()

    def makefile(self, mode: str, *_args, **_kwargs):
        return self.input if "r" in mode else self.output

    def sendall(self, payload: bytes):
        self.output.write(payload)


def _handle(config: RemoteApiConfig, request: bytes):
    transport = _RequestSocket(request)
    server = object.__new__(_RemoteServer)
    server.config = config
    RemoteWorkerHandler(transport, ("127.0.0.1", 42000), server)
    header, body = transport.output.getvalue().split(b"\r\n\r\n", 1)
    lines = header.split(b"\r\n")
    status = int(lines[0].split()[1])
    headers = BytesParser(policy=default).parsebytes(b"\r\n".join(lines[1:]) + b"\r\n")
    document = json.loads(body) if body else {}
    return status, document, headers


class RemoteApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_root = Path(__file__).resolve().parents[1]

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="remote-api-test-", dir=self.source_root
        )
        self.directory = Path(self.temporary.name)
        self.root = self.directory / "project"
        self.root.mkdir()
        for name in ("pyproject.toml", "worker.toml"):
            shutil.copy2(self.source_root / name, self.root / name)
        for name in (
            "coverage",
            "plans",
            "recipes",
            "sensitivity",
            "targets",
            "toolchains",
        ):
            shutil.copytree(self.source_root / name, self.root / name)
        self.state = self.root / "var/ledger.sqlite3"
        self.queue = self.root / "queue.toml"
        self.queue.write_text(
            """schema_version = "fidb-queue/v1"
name = "remote-test"
[queue]
armed = true
max_workers = 1
batch_order = ["remote"]
poll_seconds = 1
lease_seconds = 60
max_attempts = 2
[[batch]]
id = "remote"
name = "remote test"
plan = "plans/bzip2-native.toml"
""",
            encoding="utf-8",
        )
        self.token = "test-remote-token-with-entropy"
        self.second_token = "second-test-remote-token-with-entropy"
        self.credentials = self.directory / "workers.json"
        self.credentials.write_text(
            json.dumps(
                {
                    "schema_version": CREDENTIALS_SCHEMA,
                    "workers": [
                        {
                            "worker_id": "remote-test-1",
                            "token_sha256": hashlib.sha256(
                                self.token.encode()
                            ).hexdigest(),
                            "pools": ["library-local"],
                        },
                        {
                            "worker_id": "remote-test-2",
                            "token_sha256": hashlib.sha256(
                                self.second_token.encode()
                            ).hexdigest(),
                            "pools": ["library-local", "macos-native"],
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        os.chmod(self.credentials, 0o600)
        with Coordinator(self.state, self.root) as coordinator:
            coordinator.sync(QueueConfig.load(self.queue, self.root), now=10)
        self.config = RemoteApiConfig.from_paths(
            self.root, self.state, self.queue, self.credentials
        )

    def tearDown(self):
        self.temporary.cleanup()

    def request(
        self,
        operation: str,
        body: dict[str, object],
        *,
        token: str | None = None,
        worker_id: str = "remote-test-1",
    ):
        encoded = json.dumps({"worker_id": worker_id, **body}).encode()
        request = (
            f"POST /api/v1/worker/{operation} HTTP/1.1\r\n"
            "Host: worker.local\r\n"
            f"Authorization: Bearer {token if token is not None else self.token}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(encoded)}\r\n\r\n"
        ).encode("ascii") + encoded
        return _handle(self.config, request)

    def test_credentials_require_private_mode_and_hashed_tokens(self):
        self.assertIn("remote-test-1", load_credentials(self.credentials))
        os.chmod(self.credentials, 0o644)
        with self.assertRaisesRegex(ValueError, "group or other"):
            load_credentials(self.credentials)

    def test_authentication_and_pool_authorization_fail_closed(self):
        status, document, _ = self.request(
            "claim", {"pool": "library-local"}, token="wrong"
        )
        self.assertEqual(status, 401)
        self.assertEqual(document["error"]["code"], "authentication-failed")

        status, document, _ = self.request("claim", {"pool": "invented"})
        self.assertEqual(status, 403)
        self.assertEqual(document["error"]["code"], "pool-denied")
        with Coordinator(self.state, self.root) as coordinator:
            self.assertEqual(coordinator.status()["counts"]["leased"], 0)

    def test_disabled_schedule_waits_for_manual_block_without_window_identity(self):
        self.queue.write_text(
            self.queue.read_text(encoding="utf-8") + """
[schedule]
enabled = false
timezone = "Europe/Luxembourg"
days = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
start = "00:00"
stop_claiming = "05:30"
finish_started_batch = true
""",
            encoding="utf-8",
        )

        status, document, _ = self.request("claim", {"pool": "library-local"})

        self.assertEqual(status, 200)
        self.assertIsNone(document["lease"])
        self.assertFalse(document["gate"]["execution_block"]["active"])

    def test_external_worker_registers_reviewed_capabilities_and_keeps_them(self):
        definition = load_external_toolchain("macos-arm64-apple-clang", self.root)
        metadata = {name: f"test-{name}" for name in definition.required_metadata}
        preflight = {
            "schema_version": "fidb-external-worker-preflight/v1",
            "checked_at": "2026-09-02T08:00:00+00:00",
            "ready": True,
            "definition": definition.registration_identity(),
            "host": {"system": "darwin", "architecture": "arm64"},
            "toolchain": {},
            "analysis": {},
            "smoke": {"languages": {"c": {"passed": True}}},
            "resources": {"passed": True, "reasons": [], "metrics": {}},
            "metadata": metadata,
            "blockers": [],
        }

        status, registered, _ = self.request(
            "register",
            {"preflight": preflight},
            token=self.second_token,
            worker_id="remote-test-2",
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            registered["worker"]["metadata"]["external_toolchain"]["definition"],
            definition.registration_identity(),
        )

        status, response, _ = self.request(
            "claim",
            {"pool": "macos-native"},
            token=self.second_token,
            worker_id="remote-test-2",
        )
        self.assertEqual(status, 200)
        self.assertIsNone(response["lease"])
        self.assertTrue(response["pool"]["drained"])
        with Coordinator(self.state, self.root) as coordinator:
            worker = next(
                row
                for row in coordinator.snapshot()["workers"]
                if row["worker_id"] == "remote-test-2"
            )
        self.assertEqual(worker["metadata"]["last_operation"], "claim")
        self.assertEqual(worker["metadata"]["external_toolchain"]["metadata"], metadata)

        changed = json.loads(json.dumps(preflight))
        changed["definition"]["sha256"] = "0" * 64
        status, document, _ = self.request(
            "register",
            {"preflight": changed},
            token=self.second_token,
            worker_id="remote-test-2",
        )
        self.assertEqual(status, 409)
        self.assertEqual(document["error"]["code"], "operation-failed")

    def test_remote_claim_upload_and_server_validated_publication(self):
        status, claimed, _ = self.request("claim", {"pool": "library-local"})
        self.assertEqual(status, 200)
        lease = claimed["lease"]
        fields = {
            "job_id": lease["job_id"],
            "lease_token": lease["lease_token"],
            "lease_generation": lease["lease_generation"],
        }
        fidb = b"packed-fidb"
        fidbf = b"raw-fidbf"
        recorder = TimingRecorder()
        with recorder.span(CellStage.COMPILE, "reviewed remote compile"):
            pass
        sealed_timing = recorder.document()
        seal_document = {
            "schema_version": "fidb-cell-seal/v1",
            "cell": {
                "id": lease["cell"]["id"],
                "kind": lease["cell"]["kind"],
                "executor": lease["cell"]["routing"]["executor"],
            },
            "artifacts": {
                "fidb": {
                    "path": "artifacts/result.fidb",
                    "sha256": hashlib.sha256(fidb).hexdigest(),
                    "bytes": len(fidb),
                },
                "fidbf": {
                    "path": "artifacts/result.fidbf",
                    "sha256": hashlib.sha256(fidbf).hexdigest(),
                    "bytes": len(fidbf),
                },
            },
            "timing": sealed_timing,
        }
        seal = (json.dumps(seal_document, sort_keys=True) + "\n").encode()
        with recorder.span(CellStage.PROVENANCE_SEAL, "sealed remote result"):
            pass
        timing = recorder.document()

        for relative, content in (
            ("artifacts/result.fidb", fidb),
            ("artifacts/result.fidbf", fidbf),
            ("artifacts/cell-seal.json", seal),
        ):
            status, uploaded, _ = self.request(
                "upload",
                {
                    **fields,
                    "relative_path": relative,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "content_base64": base64.b64encode(content).decode(),
                },
            )
            self.assertEqual(status, 200)
            self.assertEqual(uploaded["artifact"]["path"], relative)

        status, completed, _ = self.request(
            "complete",
            {
                **fields,
                "cell_id": lease["cell"]["id"],
                "kind": lease["cell"]["kind"],
                "executor": lease["cell"]["routing"]["executor"],
                "seal_path": "artifacts/cell-seal.json",
                "seal_sha256": hashlib.sha256(seal).hexdigest(),
                "fidb_path": "artifacts/result.fidb",
                "fidbf_path": "artifacts/result.fidbf",
                "timing": timing,
            },
        )

        self.assertEqual(status, 200)
        self.assertEqual(completed["job"]["state"], "complete")
        final = (
            self.root
            / "artifacts/runs"
            / lease["job_id"]
            / f"attempt-{lease['lease_generation']}"
        )
        self.assertEqual((final / "artifacts/result.fidb").read_bytes(), fidb)
        with Coordinator(self.state, self.root) as coordinator:
            snapshot = coordinator.snapshot()
        self.assertEqual(len(snapshot["workers"]), 1)
        self.assertEqual(snapshot["workers"][0]["worker_id"], "remote-test-1")
        self.assertEqual(snapshot["workers"][0]["transport"], "remote-http")
        self.assertEqual(
            len(
                [
                    event
                    for event in snapshot["events"]
                    if event["event_type"] == "worker.registered"
                ]
            ),
            1,
        )

    def test_chunked_upload_is_idempotent_and_final_digest_gated(self):
        status, claimed, _ = self.request("claim", {"pool": "library-local"})
        self.assertEqual(status, 200)
        lease = claimed["lease"]
        fields = {
            "job_id": lease["job_id"],
            "lease_token": lease["lease_token"],
            "lease_generation": lease["lease_generation"],
        }
        content = b"chunked remote artifact"
        digest = hashlib.sha256(content).hexdigest()
        relative = "artifacts/result.fidb"

        def upload(offset: int, chunk: bytes, final: bool):
            return self.request(
                "upload",
                {
                    **fields,
                    "relative_path": relative,
                    "artifact_sha256": digest,
                    "artifact_bytes": len(content),
                    "offset": offset,
                    "chunk_sha256": hashlib.sha256(chunk).hexdigest(),
                    "content_base64": base64.b64encode(chunk).decode(),
                    "final": final,
                },
            )

        first = content[:8]
        status, uploaded, _ = upload(0, first, False)
        self.assertEqual(status, 200)
        self.assertEqual(uploaded["artifact"]["next_offset"], 8)
        self.assertFalse(uploaded["artifact"]["complete"])

        status, replayed, _ = upload(0, first, False)
        self.assertEqual(status, 200)
        self.assertEqual(replayed["artifact"]["next_offset"], 8)

        status, completed, _ = upload(8, content[8:], True)
        self.assertEqual(status, 200)
        self.assertTrue(completed["artifact"]["complete"])
        staging = (
            self.root
            / "artifacts/runs/remote-staging"
            / f"{lease['job_id']}-g{lease['lease_generation']}"
            / relative
        )
        self.assertEqual(staging.read_bytes(), content)
        self.assertFalse(staging.with_name(".result.fidb.upload").exists())
        self.assertFalse(staging.with_name(".result.fidb.upload.json").exists())
        self.assertFalse(staging.with_name(".result.fidb.upload.lock").exists())

    def test_lease_owner_paths_and_completed_identity_fail_closed(self):
        status, claimed, _ = self.request("claim", {"pool": "library-local"})
        self.assertEqual(status, 200)
        lease = claimed["lease"]
        fields = {
            "job_id": lease["job_id"],
            "lease_token": lease["lease_token"],
            "lease_generation": lease["lease_generation"],
        }

        status, document, _ = self.request(
            "renew",
            fields,
            token=self.second_token,
            worker_id="remote-test-2",
        )
        self.assertEqual(status, 403)
        self.assertEqual(document["error"]["code"], "lease-owner-mismatch")

        content = b"escape"
        status, document, _ = self.request(
            "upload",
            {
                **fields,
                "relative_path": "../escape",
                "sha256": hashlib.sha256(content).hexdigest(),
                "content_base64": base64.b64encode(content).decode(),
            },
        )
        self.assertEqual(status, 400)
        self.assertEqual(document["error"]["code"], "invalid-path")
        self.assertFalse((self.root / "artifacts/runs/escape").exists())

        status, document, _ = self.request(
            "complete",
            {
                **fields,
                "cell_id": "different-cell",
                "kind": lease["cell"]["kind"],
                "executor": lease["cell"]["routing"]["executor"],
                "seal_path": "artifacts/cell-seal.json",
                "seal_sha256": "0" * 64,
                "fidb_path": "artifacts/result.fidb",
                "fidbf_path": "artifacts/result.fidbf",
                "timing": {},
            },
        )
        self.assertEqual(status, 409)
        self.assertEqual(document["error"]["code"], "cell-identity-mismatch")


if __name__ == "__main__":
    unittest.main()
