import base64
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from fidb_poc.cell_runner import CellRunResult
from fidb_poc.remote_worker import (
    RemoteCoordinatorClient,
    execute_remote_lease,
)


class RemoteWorkerTests(unittest.TestCase):
    def test_client_requires_https_except_explicit_loopback_test_mode(self):
        with self.assertRaisesRegex(ValueError, "HTTPS origin"):
            RemoteCoordinatorClient("http://worker.example", "worker-1", "token")
        with self.assertRaisesRegex(ValueError, "HTTPS origin"):
            RemoteCoordinatorClient("http://127.0.0.1:8766", "worker-1", "token")

        client = RemoteCoordinatorClient(
            "http://127.0.0.1:8766",
            "worker-1",
            "token",
            allow_http_loopback=True,
        )
        self.assertEqual(client.origin, "http://127.0.0.1:8766")

    def test_remote_execution_uploads_only_typed_sealed_materials(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        requests: list[tuple[str, dict[str, object]]] = []

        class FakeClient:
            worker_id = "remote-worker-1"

            @staticmethod
            def lease_fields(lease):
                return RemoteCoordinatorClient.lease_fields(lease)

            def request(self, operation, document):
                requests.append((operation, document))
                if operation == "complete":
                    return {"job": {"state": "complete"}}
                if operation == "upload":
                    content = base64.b64decode(document["content_base64"])
                    return {
                        "artifact": {
                            "path": document["relative_path"],
                            "sha256": document["artifact_sha256"],
                            "bytes": document["artifact_bytes"],
                            "next_offset": document["offset"] + len(content),
                            "complete": document["final"],
                        }
                    }
                return {"ok": True}

        lease = {
            "job_id": f"job-{'a' * 64}",
            "lease_token": "fenced-token",
            "lease_generation": 1,
            "cell": {"id": "cell", "kind": "native"},
            "factor_variants": [],
        }

        def fake_run_cell(_cell, _variants, _root, attempt, **_kwargs):
            artifacts = attempt / "artifacts"
            artifacts.mkdir()
            seal = artifacts / "cell-seal.json"
            fidb = artifacts / "result.fidb"
            fidbf = artifacts / "result.fidbf"
            seal.write_bytes(b"seal")
            fidb.write_bytes(b"fidb")
            fidbf.write_bytes(b"fidbf")
            return CellRunResult(
                cell_id="cell",
                kind="native",
                executor="native-local",
                manifest_path=seal,
                manifest_sha256=hashlib.sha256(seal.read_bytes()).hexdigest(),
                fidb_path=fidb,
                fidbf_path=fidbf,
                timing={"schema_version": "fidb-execution-timing/v1"},
            )

        with mock.patch("fidb_poc.remote_worker.run_cell", side_effect=fake_run_cell):
            completed = execute_remote_lease(
                FakeClient(), lease, root, lease_seconds=60
            )

        self.assertTrue(completed)
        self.assertEqual(
            [operation for operation, _ in requests],
            [
                "upload",
                "upload",
                "upload",
                "complete",
            ],
        )
        uploads = [
            document for operation, document in requests if operation == "upload"
        ]
        self.assertEqual(
            {document["relative_path"] for document in uploads},
            {
                "artifacts/cell-seal.json",
                "artifacts/result.fidb",
                "artifacts/result.fidbf",
            },
        )
        self.assertTrue(all("command" not in document for _, document in requests))


if __name__ == "__main__":
    unittest.main()
