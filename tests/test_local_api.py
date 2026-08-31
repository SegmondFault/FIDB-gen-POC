import hashlib
from email.parser import BytesParser
from email.policy import default
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fidb_poc import capabilities
from fidb_poc.cli import main as cli_main
from fidb_poc.coordinator import MAX_TIMING_LIMIT, Coordinator, QueueConfig
from fidb_poc.local_api import (
    LocalApiConfig,
    LocalApiHandler,
    _ApiServer,
    _bind_address,
)


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


def _handle(config: LocalApiConfig, request: bytes):
    transport = _RequestSocket(request)
    server = object.__new__(_ApiServer)
    server.config = config
    LocalApiHandler(transport, ("127.0.0.1", 42000), server)
    header, body = transport.output.getvalue().split(b"\r\n\r\n", 1)
    lines = header.split(b"\r\n")
    status = int(lines[0].split()[1])
    headers = BytesParser(policy=default).parsebytes(b"\r\n".join(lines[1:]) + b"\r\n")
    document = json.loads(body) if body else {}
    return status, document, headers


class LocalApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_root = Path(__file__).resolve().parents[1]

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for name in ("pyproject.toml", "worker.toml"):
            shutil.copy2(self.source_root / name, self.root / name)
        for name in ("plans", "recipes", "sensitivity", "targets", "toolchains"):
            shutil.copytree(self.source_root / name, self.root / name)
        self.state = self.root / "var/fidb-coordinator/ledger.sqlite3"
        self.queue = self.root / "plans/priority-queue.toml"
        self.queue_config = QueueConfig.load(self.queue, self.root)
        self.max_workers = self.queue_config.max_workers
        self.config = LocalApiConfig.from_paths(
            self.root,
            self.state,
            self.queue,
            allowed_origins=("http://analyst.test:3000",),
        )

    def tearDown(self):
        self.temporary.cleanup()

    def request(
        self,
        method: str,
        path: str,
        body: object | None = None,
        *,
        origin: str | None = None,
        raw_body: bytes | None = None,
    ) -> tuple[int, dict[str, object], object]:
        data = raw_body or b""
        headers = ["Host: api.local"]
        if body is not None:
            data = json.dumps(body).encode("utf-8")
        if body is not None or raw_body is not None:
            headers.extend(
                (
                    "Content-Type: application/json",
                    f"Content-Length: {len(data)}",
                )
            )
        if origin is not None:
            headers.append(f"Origin: {origin}")
        request = (
            f"{method} {path} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n\r\n"
        ).encode("ascii") + data
        return _handle(self.config, request)

    def sync(self) -> dict[str, object]:
        status, document, _ = self.request("POST", "/api/v1/sync", {})
        self.assertEqual(status, 200)
        return document

    def claim_synced_job(self, *, now: float = 20) -> dict[str, object]:
        self.sync()
        with Coordinator(self.state, self.root) as coordinator:
            coordinator.connection.execute(
                "UPDATE coordinator_state SET armed = 1 WHERE singleton = 1"
            )
            lease = coordinator.claim("timing-test-worker", now=now)
        self.assertIsNotNone(lease)
        return lease

    def test_health_is_available_before_sync_without_creating_state(self):
        status, document, headers = self.request("GET", "/api/v1/health")

        self.assertEqual(status, 200)
        self.assertEqual(document["status"], "ok")
        self.assertEqual(document["coordinator"]["state"], "not-initialized")
        self.assertFalse(self.state.exists())
        self.assertIsNone(headers.get("Access-Control-Allow-Origin"))

    def test_sync_status_and_snapshot_expose_worker_slots_but_not_lease_tokens(self):
        synced = self.sync()
        self.assertEqual(synced["max_workers"], self.max_workers)
        self.assertEqual(synced["active_workers"], 0)
        self.assertEqual(synced["available_worker_slots"], self.max_workers)
        self.assertEqual(synced["armed"], self.queue_config.armed)

        status, snapshot, _ = self.request("GET", "/api/v1/snapshot")
        self.assertEqual(status, 200)
        self.assertEqual(len(snapshot["jobs"]), 2)
        self.assertEqual(
            {row["base_cell"] for row in snapshot["jobs"]},
            {
                "tier0-zlib-native:zlib-1.3.1:linux-x86_64-gnu-gcc:baseline_o2",
                "bzip2-native:bzip2-1.0.7:linux-x86_64-gnu-gcc:baseline_o2",
            },
        )
        self.assertNotIn("events", snapshot)
        self.assertTrue(all("lease_token" not in row for row in snapshot["jobs"]))

    def test_preflight_exposes_enforced_schedule_and_live_resource_gates(self):
        status, document, _ = self.request("GET", "/api/v1/preflight")

        self.assertEqual(status, 200)
        self.assertEqual(document["schema_version"], "fidb-operations-preflight/v1")
        self.assertFalse(document["queue_armed"])
        self.assertFalse(document["ready"])
        self.assertEqual(
            document["policy"]["schedule"]["timezone"], "Europe/Luxembourg"
        )
        self.assertEqual(document["policy"]["schedule"]["hard_cutoff"], "06:15")
        self.assertIn("available_memory_gib", document["resources"]["metrics"])
        self.assertIn("temperature_c", document["resources"]["metrics"])

        status, error, _ = self.request("GET", "/api/v1/preflight?extra=true")
        self.assertEqual(status, 400)
        self.assertEqual(error["error"]["code"], "invalid-query")

    def test_events_are_cursor_paginated_and_bounded(self):
        self.sync()
        status, first, _ = self.request("GET", "/api/v1/events?after=0&limit=1")
        self.assertEqual(status, 200)
        self.assertEqual(len(first["events"]), 1)
        self.assertTrue(first["has_more"])
        cursor = first["next_cursor"]

        status, second, _ = self.request(
            "GET", f"/api/v1/events?after={cursor}&limit=500"
        )
        self.assertEqual(status, 200)
        self.assertTrue(all(row["event_id"] > cursor for row in second["events"]))

        status, document, _ = self.request("GET", "/api/v1/events?limit=501")
        self.assertEqual(status, 400)
        self.assertEqual(document["error"]["code"], "invalid-query")

    def test_timings_endpoint_has_no_eta_or_throughput_without_samples(self):
        self.sync()

        status, document, _ = self.request("GET", "/api/v1/timings")

        self.assertEqual(status, 200)
        self.assertEqual(document["schema_version"], "fidb-timings/v1")
        self.assertEqual(document["sample_counts"]["stage_spans"], 0)
        self.assertIsNone(document["throughput"])
        self.assertIsNone(document["eta"])

    def test_timings_endpoint_returns_measured_spans_and_bounded_history(self):
        lease = self.claim_synced_job()
        with Coordinator(self.state, self.root) as coordinator:
            arguments = (
                lease["job_id"],
                lease["lease_token"],
                lease["lease_generation"],
            )
            coordinator.record_stage(
                *arguments,
                "compile",
                details={"metrics": {"object_count": 3}},
                now=21,
            )
            coordinator.record_stage(
                *arguments,
                "compile",
                status="completed",
                duration_ns=1_500,
                details={"metrics": {"object_count": 4}},
                now=22,
            )
            coordinator.complete(*arguments, now=23)

        status, document, _ = self.request("GET", "/api/v1/timings?limit=1")

        self.assertEqual(status, 200)
        self.assertEqual(document["limit"], 1)
        self.assertEqual(len(document["recent"]), 1)
        self.assertEqual(document["recent"][0]["duration_ns"], 1_500)
        self.assertEqual(document["recent"][0]["duration_source"], "worker-monotonic")
        self.assertNotIn("lease_token", document["recent"][0])
        self.assertEqual(document["stages"][0]["duration_ns"]["p50"], 1_500)
        self.assertIsNotNone(document["throughput"])
        self.assertIsNone(document["eta"])

        status, error, _ = self.request(
            "GET", f"/api/v1/timings?limit={MAX_TIMING_LIMIT + 1}"
        )
        self.assertEqual(status, 400)
        self.assertEqual(error["error"]["code"], "invalid-query")

    def test_public_snapshot_bounds_stage_history_and_exposes_no_fence(self):
        lease = self.claim_synced_job()
        with Coordinator(self.state, self.root) as coordinator:
            for _index in range(MAX_TIMING_LIMIT + 1):
                coordinator.record_stage(
                    lease["job_id"],
                    lease["lease_token"],
                    lease["lease_generation"],
                    "optional-stage",
                    status="skipped",
                    duration_ns=0,
                    now=21,
                )

        status, snapshot, _ = self.request("GET", "/api/v1/snapshot")

        self.assertEqual(status, 200)
        self.assertEqual(len(snapshot["stage_attempts"]), MAX_TIMING_LIMIT)
        self.assertEqual(snapshot["stage_attempts_total"], MAX_TIMING_LIMIT + 1)
        self.assertTrue(snapshot["stage_attempts_truncated"])
        self.assertTrue(
            all("lease_token" not in row for row in snapshot["stage_attempts"])
        )
        self.assertTrue(all("lease_token" not in row for row in snapshot["attempts"]))

    def test_only_typed_sync_pause_and_resume_controls_exist(self):
        self.sync()
        status, paused, _ = self.request(
            "POST", "/api/v1/pause", {"reason": "maintenance"}
        )
        self.assertEqual(status, 200)
        self.assertTrue(paused["paused"])

        status, resumed, _ = self.request("POST", "/api/v1/resume", {})
        self.assertEqual(status, 200)
        self.assertFalse(resumed["paused"])

        status, document, _ = self.request(
            "POST", "/api/v1/sync", {"command": "make all"}
        )
        self.assertEqual(status, 400)
        self.assertEqual(document["error"]["code"], "unsupported-fields")

        status, document, _ = self.request("POST", "/api/v1/run", {})
        self.assertEqual(status, 404)
        self.assertEqual(document["error"]["code"], "not-found")

    def test_plan_drafts_resolve_and_save_only_after_validation(self):
        toml = (self.root / "plans/bzip2-native.toml").read_text(encoding="utf-8")

        status, resolved, _ = self.request(
            "POST",
            "/api/v1/plan-drafts/resolve",
            {"toml": toml},
        )
        self.assertEqual(status, 200)
        self.assertEqual(resolved["resolved"]["summary"]["planned_cells"], 1)
        self.assertFalse((self.root / "plans/drafts").exists())

        status, saved, _ = self.request(
            "POST",
            "/api/v1/plan-drafts/save",
            {"name": "bzip2-native-baseline", "toml": toml},
        )
        self.assertEqual(status, 200)
        self.assertEqual(saved["path"], "plans/drafts/bzip2-native-baseline.toml")

        status, conflict, _ = self.request(
            "POST",
            "/api/v1/plan-drafts/save",
            {"name": "bzip2-native-baseline", "toml": toml},
        )
        self.assertEqual(status, 409)
        self.assertEqual(conflict["error"]["code"], "draft-conflict")

        status, invalid, _ = self.request(
            "POST",
            "/api/v1/plan-drafts/resolve",
            {"toml": toml + '\ncommand = "make anything"\n'},
        )
        self.assertEqual(status, 400)
        self.assertEqual(invalid["error"]["code"], "invalid-plan-draft")

    def test_cors_is_exact_and_never_wildcard(self):
        status, _, headers = self.request(
            "GET", "/api/v1/health", origin="http://analyst.test:3000"
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            headers.get("Access-Control-Allow-Origin"),
            "http://analyst.test:3000",
        )
        self.assertNotEqual(headers.get("Access-Control-Allow-Origin"), "*")

        status, document, headers = self.request(
            "POST",
            "/api/v1/sync",
            {},
            origin="http://untrusted.test:3000",
        )
        self.assertEqual(status, 403)
        self.assertEqual(document["error"]["code"], "origin-denied")
        self.assertIsNone(headers.get("Access-Control-Allow-Origin"))
        self.assertFalse(self.state.exists())

    def test_large_and_malformed_json_are_rejected_without_syncing(self):
        limited = LocalApiConfig(
            project_root=self.config.project_root,
            state_path=self.config.state_path,
            queue_path=self.config.queue_path,
            allowed_origins=(),
            max_request_body_bytes=8,
        )
        self.config = limited

        status, document, _ = self.request(
            "POST", "/api/v1/sync", raw_body=b'{"value":12345}'
        )
        self.assertEqual(status, 413)
        self.assertEqual(document["error"]["code"], "request-body-too-large")
        self.assertFalse(self.state.exists())

        status, document, _ = self.request("POST", "/api/v1/sync", raw_body=b"{")
        self.assertEqual(status, 400)
        self.assertEqual(document["error"]["code"], "invalid-json")

    def test_capabilities_are_library_local_and_qemu_does_not_gate_pool(self):
        self.sync()
        status, document, _ = self.request("GET", "/api/v1/capabilities")

        self.assertEqual(status, 200)
        pool = document["worker_pools"]["library-local"]
        self.assertEqual(pool["eligible_jobs"], 2)
        self.assertEqual(pool["max_workers"], self.max_workers)
        self.assertFalse(pool["qemu_required"])
        self.assertFalse(
            document["executors"]["qemu"]["required_for_library_local_pool"]
        )
        self.assertTrue(
            all(
                row["library_local_eligible"]
                for row in document["active_job_readiness"]
            )
        )
        self.assertEqual(
            {
                (row["kind"], row["executor"])
                for row in document["active_job_readiness"]
            },
            {("native", "native-local")},
        )

    def test_authority_endpoint_projects_reviewed_catalogs_and_plans(self):
        status, document, _ = self.request("GET", "/api/v1/authority")

        self.assertEqual(status, 200)
        self.assertEqual(document["schema_version"], "fidb-authority-catalog/v2")
        self.assertEqual(len(document["recipes"]), 4)
        self.assertEqual(len(document["targets"]), 15)
        self.assertEqual(len(document["toolchains"]), 41)
        self.assertEqual(len(document["factors"]), 41)
        self.assertTrue(document["plans"])

    def test_capabilities_detection_never_mutates_cache(self):
        managed_cache = self.root / capabilities.TOOLCHAIN_CACHE
        result = capabilities.detect_capabilities(self.root, environment={"PATH": ""})

        self.assertFalse(managed_cache.exists())
        self.assertEqual(result["detection_mode"], "read-only")
        self.assertTrue(result["toolchains"]["entries"])
        self.assertTrue(
            all(row["state"] == "missing" for row in result["toolchains"]["entries"])
        )

    def test_verified_cache_is_distinct_from_prepared_toolchain(self):
        payload = b"reviewed pinned archive"
        digest = hashlib.sha256(payload).hexdigest()
        cache = self.root / capabilities.TOOLCHAIN_CACHE
        cache.mkdir(parents=True)
        (cache / digest).write_bytes(payload)

        entry = capabilities._cache_entry(cache, digest)

        self.assertEqual(entry["state"], "verified-cached")
        self.assertEqual(entry["observed_sha256"], digest)

    def test_invalid_bind_and_origins_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "wildcard"):
            _bind_address("0.0.0.0")
        with self.assertRaisesRegex(ValueError, "invalid allowed origin"):
            LocalApiConfig.from_paths(
                self.root,
                self.state,
                self.queue,
                allowed_origins=("*",),
            )

    def test_cli_dispatches_api_subcommand(self):
        with patch("fidb_poc.local_api.main", return_value=19) as api_main:
            status = cli_main(["api", "serve", "--port", "9000"])

        self.assertEqual(status, 19)
        api_main.assert_called_once_with(["serve", "--port", "9000"])

    def test_exact_origin_preflight(self):
        request = (
            "OPTIONS /api/v1/sync HTTP/1.1\r\n"
            "Host: api.local\r\n"
            "Origin: http://analyst.test:3000\r\n"
            "Access-Control-Request-Method: POST\r\n"
            "Access-Control-Request-Headers: Content-Type\r\n\r\n"
        ).encode("ascii")

        status, _, headers = _handle(self.config, request)

        self.assertEqual(status, 204)
        self.assertEqual(
            headers.get("Access-Control-Allow-Origin"),
            "http://analyst.test:3000",
        )
        self.assertNotEqual(headers.get("Access-Control-Allow-Origin"), "*")


if __name__ == "__main__":
    unittest.main()
