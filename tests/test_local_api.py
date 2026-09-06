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
        for name in (
            "batches",
            "benchmarks",
            "campaigns",
            "coverage",
            "lanes",
            "performance",
            "plans",
            "qualification",
            "recipes",
            "retention",
            "sensitivity",
            "sources",
            "targets",
            "toolchains",
            "validation",
        ):
            shutil.copytree(self.source_root / name, self.root / name)
        shutil.copy2(
            self.source_root / "tests/fixtures/local-api-priority-queue.toml",
            self.root / "plans/priority-queue.toml",
        )
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
        self.assertEqual(len(snapshot["jobs"]), 3)
        self.assertEqual(
            {row["base_cell"] for row in snapshot["jobs"]},
            {
                "tier0-zlib-native:zlib-1.3.1:linux-x86_64-gnu-gcc:baseline_o2",
                "bzip2-native:bzip2-1.0.7:linux-x86_64-gnu-gcc:baseline_o2",
                "macos-zlib-native:zlib-1.3.1:macos-arm64-apple-clang:baseline_o2",
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
        self.assertEqual(document["policy"]["schedule"]["start"], "01:00")
        self.assertEqual(document["policy"]["schedule"]["stop_claiming"], "05:30")
        self.assertIsNone(document["policy"]["schedule"]["hard_cutoff"])
        self.assertTrue(document["policy"]["schedule"]["finish_started_batch"])
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

    def test_control_panel_snapshot_bounds_history_and_compacts_job_results(self):
        lease = self.claim_synced_job()
        with Coordinator(self.state, self.root) as coordinator:
            coordinator.complete(
                lease["job_id"],
                lease["lease_token"],
                lease["lease_generation"],
                result={
                    "executor": "test-executor",
                    "fidb": {"path": "artifact.fidb", "sha256": "a" * 64},
                    "timing": {"large": ["internal"] * 100},
                },
                now=23,
            )

        status, snapshot, _ = self.request(
            "GET", "/api/v1/snapshot?detail=control-panel"
        )

        self.assertEqual(status, 200)
        self.assertEqual(snapshot["snapshot_detail"], "control-panel")
        self.assertEqual(snapshot["attempts_total"], 1)
        self.assertFalse(snapshot["attempts_truncated"])
        self.assertEqual(snapshot["result_jobs_total"], 1)
        self.assertEqual(snapshot["result_jobs_included"], 1)
        self.assertFalse(snapshot["result_jobs_truncated"])
        job = next(row for row in snapshot["jobs"] if row["job_id"] == lease["job_id"])
        self.assertEqual(job["result"]["executor"], "test-executor")
        self.assertEqual(job["result"]["fidb"]["path"], "artifact.fidb")
        self.assertNotIn("timing", job["result"])
        self.assertNotIn("queue_row", job)
        self.assertNotIn("factor_variants", job)

        status, error, _ = self.request("GET", "/api/v1/snapshot?detail=large")
        self.assertEqual(status, 400)
        self.assertEqual(error["error"]["code"], "invalid-query")

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
        self.assertEqual(
            sum(
                row["library_local_eligible"]
                for row in document["active_job_readiness"]
            ),
            2,
        )
        self.assertEqual(document["worker_pools"]["macos-native"]["eligible_jobs"], 1)
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
        self.assertEqual(document["schema_version"], "fidb-authority-catalog/v18")
        self.assertEqual(
            document["campaign_programmes"][0]["summary"]["candidate_population"], 276
        )
        self.assertEqual(document["auto_batch_campaigns"][0]["summary"]["chunks"], 23)
        self.assertEqual(document["performance_profiles"]["default_profile"], "auto")
        self.assertEqual(len(document["recipes"]), 30)
        self.assertEqual(len(document["targets"]), 24)
        self.assertEqual(len(document["lane_registry"]["lanes"]), 15)
        self.assertEqual(len(document["coverage_universe"]["dimensions"]), 7)
        self.assertEqual(len(document["toolchains"]), 41)
        self.assertEqual(len(document["toolchain_pack_catalog"]["packs"]), 31)
        self.assertEqual(len(document["toolchain_pack_catalog"]["inputs"]), 0)
        self.assertEqual(len(document["factors"]), 41)
        width_study = next(
            row for row in document["width_studies"] if row["id"] == "batch-010"
        )
        self.assertEqual(
            width_study["presets"][1]["metrics"]["build_cells"],
            180,
        )
        width_batch = next(
            row for row in document["width_batches"] if row["id"] == "batch-020"
        )
        self.assertEqual(
            width_batch["summary"]["total_executions"],
            1_998,
        )
        self.assertEqual(
            width_batch["readiness"]["queue_state"],
            "qualification-historical-exempt",
        )
        next_cohort = next(
            row for row in document["width_batches"] if row["id"] == "batch-c11-20"
        )
        self.assertEqual(next_cohort["summary"]["total_executions"], 2_220)
        self.assertEqual(next_cohort["readiness"]["recipe_ready_libraries"], 10)
        self.assertEqual(next_cohort["readiness"]["blocked_executions"], 2_220)
        self.assertEqual(
            next_cohort["readiness"]["queue_state"],
            "qualification-blocked",
        )
        self.assertTrue(document["plans"])

    def test_ecological_status_and_binary_import_are_bounded(self):
        status, document, _ = self.request("GET", "/api/v1/ecological-validation")
        self.assertEqual(status, 200)
        self.assertEqual(
            document["schema_version"], "fidb-ecological-validation-status/v1"
        )
        self.assertEqual(document["summary"]["imported_cases"], 0)

        identity = b"\x7fELF" + bytes((2, 1, 1, 0)) + bytes(8)
        header = __import__("struct").pack(
            "<HHIQQQIHHHHHH", 2, 62, 1, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0
        )
        payload = identity + header
        request = (
            "POST /api/v1/ecological-validation/import HTTP/1.1\r\n"
            "Host: api.local\r\n"
            "Content-Type: application/octet-stream\r\n"
            f"Content-Length: {len(payload)}\r\n"
            "X-FIDB-Filename: held-out.bin\r\n"
            "X-FIDB-Label: Held%20out%20binary\r\n"
            "X-FIDB-Platform-Hint: linux\r\n"
            "X-FIDB-Expected-Present: openssl%403.5.8\r\n"
            "X-FIDB-Expected-Absent: \r\n"
            "X-FIDB-Truth-Complete: true\r\n\r\n"
        ).encode("ascii") + payload
        imported_status, imported, _ = _handle(self.config, request)
        self.assertEqual(imported_status, 201)
        self.assertEqual(imported["probe"]["sublane_id"], "linux-x86-elf64")
        self.assertEqual(imported["truth"]["expected_present"], ["openssl@3.5.8"])
        self.assertFalse(imported["binary"]["never_execute"] is False)

        status, document, _ = self.request("GET", "/api/v1/ecological-validation")
        self.assertEqual(status, 200)
        self.assertEqual(document["summary"]["imported_cases"], 1)

    def test_machine_validation_status_and_start_are_bounded(self):
        status, document, _ = self.request("GET", "/api/v1/machine-validation")
        self.assertEqual(status, 200)
        self.assertEqual(
            document["schema_version"], "fidb-machine-validation-status/v1"
        )
        self.assertEqual(document["run"]["state"], "not-started")
        self.assertFalse(document["canary_gate"]["ready"])

        status, live, _ = self.request("GET", "/api/v1/machine-validation/run")
        self.assertEqual(status, 200)
        self.assertEqual(live["run"]["state"], "not-started")
        self.assertFalse(live["canary_gate"]["ready"])

        status, document, _ = self.request(
            "GET", "/api/v1/machine-validation?mode=full"
        )
        self.assertEqual(status, 400)
        self.assertEqual(document["error"]["code"], "invalid-query")

        accepted = {
            "state": "queued",
            "run_id": "fixed-canary",
            "mode": "canary",
            "pid": 42,
            "log_path": "artifacts/validation-runs/fixed/run.log",
        }
        with patch(
            "fidb_poc.local_api.start_machine_validation",
            return_value=accepted,
        ) as start:
            status, document, _ = self.request(
                "POST", "/api/v1/machine-validation/start", {"mode": "canary"}
            )
        self.assertEqual(status, 202)
        self.assertEqual(document, accepted)
        start.assert_called_once_with(self.root, "canary", run_id=None)

        with patch(
            "fidb_poc.local_api.start_machine_validation",
            return_value={**accepted, "run_id": "planned-full", "mode": "full"},
        ) as start:
            status, _document, _ = self.request(
                "POST",
                "/api/v1/machine-validation/start",
                {"mode": "full", "run_id": "planned-full"},
            )
        self.assertEqual(status, 202)
        start.assert_called_once_with(self.root, "full", run_id="planned-full")

        status, document, _ = self.request(
            "POST",
            "/api/v1/machine-validation/start",
            {"mode": "full", "run_id": ""},
        )
        self.assertEqual(status, 400)
        self.assertEqual(document["error"]["code"], "invalid-machine-validation-run-id")

        status, document, _ = self.request(
            "POST", "/api/v1/machine-validation/start", {"mode": "unsafe"}
        )
        self.assertEqual(status, 400)
        self.assertEqual(document["error"]["code"], "invalid-machine-validation-mode")

        paused = {"state": "pausing", "run_id": "fixed-full", "mode": "full"}
        with patch(
            "fidb_poc.local_api.pause_machine_validation", return_value=paused
        ) as pause:
            status, document, _ = self.request(
                "POST", "/api/v1/machine-validation/pause", {}
            )
        self.assertEqual(status, 202)
        self.assertEqual(document, paused)
        pause.assert_called_once_with(self.root, actor="local-api")

        resumed = {"state": "queued", "run_id": "fixed-full", "mode": "full"}
        with patch(
            "fidb_poc.local_api.resume_machine_validation", return_value=resumed
        ) as resume:
            status, document, _ = self.request(
                "POST", "/api/v1/machine-validation/resume", {}
            )
        self.assertEqual(status, 202)
        self.assertEqual(document, resumed)
        resume.assert_called_once_with(self.root)

    def test_noisy_hash_status_endpoint_is_read_only(self):
        status, document, _ = self.request("GET", "/api/v1/noisy-hashes")
        self.assertEqual(status, 200)
        self.assertEqual(document["schema_version"], "fidb-noisy-hash-status/v1")
        self.assertEqual(document["summary"]["observed_hashes"], 0)

    def test_validation_observatory_selects_one_read_only_run(self):
        compiled = {
            "schema_version": "fidb-validation-observatory/v1",
            "selected_run_key": "c10:run-1",
        }
        with patch(
            "fidb_poc.local_api.compile_validation_observatory",
            return_value=compiled,
        ) as compile_observatory:
            status, document, _ = self.request(
                "GET", "/api/v1/validation-observatory?run_id=c10:run-1"
            )

        self.assertEqual(status, 200)
        self.assertEqual(document, compiled)
        compile_observatory.assert_called_once_with(self.root, selected_run="c10:run-1")

        status, document, _ = self.request(
            "GET", "/api/v1/validation-observatory?run_id=a&run_id=b"
        )
        self.assertEqual(status, 400)
        self.assertEqual(document["error"]["code"], "invalid-query")

    def test_hash_discrimination_status_endpoint_is_read_only(self):
        status, document, _ = self.request("GET", "/api/v1/hash-discrimination")
        self.assertEqual(status, 200)
        self.assertEqual(
            document["schema_version"], "fidb-hash-discrimination-status/v1"
        )
        self.assertEqual(document["index"]["name"], "Hash Discrimination Index")
        self.assertIsNone(document["summary"]["scored_signatures"])

        status, document, _ = self.request(
            "GET", "/api/v1/hash-discrimination?generation=latest"
        )
        self.assertEqual(status, 400)
        self.assertEqual(document["error"]["code"], "invalid-query")

    def test_hash_backend_status_and_toml_mode_control(self):
        status, document, _ = self.request("GET", "/api/v1/hash-analysis-backend")
        self.assertEqual(status, 200)
        self.assertEqual(document["schema_version"], "fidb-hash-backend-status/v1")

        status, document, _ = self.request(
            "POST", "/api/v1/hash-analysis-backend/mode", {"mode": "cpu"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(document["requested_mode"], "cpu")
        self.assertEqual(document["effective_backend"]["id"], "cpu-packed-probe-v1")
        self.assertIn(
            'mode = "cpu"',
            (self.root / "performance/hash-analysis.toml").read_text(encoding="utf-8"),
        )

        status, document, _ = self.request(
            "POST", "/api/v1/hash-analysis-backend/mode", {"mode": "cuda"}
        )
        self.assertEqual(status, 400)
        self.assertEqual(document["error"]["code"], "invalid-hash-analysis-mode")

    def test_retention_endpoints_preserve_dry_run_and_exact_apply_contract(self):
        self.sync()

        status, initial, _ = self.request("GET", "/api/v1/retention")
        self.assertEqual(status, 200)
        self.assertEqual(initial["schema_version"], "fidb-retention-status/v1")
        self.assertIsNone(initial["latest_plan"])

        status, planned, _ = self.request("POST", "/api/v1/retention/plan", {})
        self.assertEqual(status, 200)
        digest = planned["latest_plan"]["plan_digest"]
        self.assertEqual(len(digest), 64)
        self.assertEqual(planned["latest_plan"]["summary"]["actions"], 0)
        self.assertIsNone(planned["last_run"])

        status, applied, _ = self.request(
            "POST", "/api/v1/retention/apply", {"plan_digest": digest}
        )
        self.assertEqual(status, 200)
        self.assertEqual(applied["last_run"]["state"], "complete")
        self.assertEqual(applied["last_run"]["plan_digest"], digest)

        status, rejected, _ = self.request(
            "POST", "/api/v1/retention/apply", {"plan_digest": "wrong"}
        )
        self.assertEqual(status, 409)
        self.assertEqual(rejected["error"]["code"], "operation-failed")

    def test_lane_inventory_endpoint_is_read_only_and_rejects_query(self):
        status, document, _ = self.request("GET", "/api/v1/lane-inventory")

        self.assertEqual(status, 200)
        self.assertEqual(document["schema_version"], "fidb-lane-inventory/v1")
        self.assertEqual(document["detection_mode"], "read-only-metadata")
        self.assertEqual(document["summary"]["materialized_generations"], 0)
        self.assertFalse((self.root / "var/fidb-lanes").exists())

        status, document, _ = self.request("GET", "/api/v1/lane-inventory?path=outside")
        self.assertEqual(status, 400)
        self.assertEqual(document["error"]["code"], "invalid-query")

    def test_capabilities_detection_never_mutates_cache(self):
        managed_cache = self.root / capabilities.TOOLCHAIN_CACHE
        result = capabilities.detect_capabilities(self.root, environment={"PATH": ""})

        self.assertFalse(managed_cache.exists())
        self.assertEqual(result["detection_mode"], "read-only")
        self.assertTrue(result["toolchains"]["entries"])
        self.assertEqual(len(result["toolchain_profiles"]["plans"]), 7)
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
