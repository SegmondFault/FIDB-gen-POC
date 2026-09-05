import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fidb_poc.machine_validation_runner import (
    QUERY_COPY_POLICY,
    REFERENCE_INDEX_SCHEMA,
    _archive_failed_result,
    _link_composite,
    _post_validation_retention,
    _query_index,
    canary_gate_status,
    load_runtime,
    pause_validation,
    resume_validation,
    runtime_status,
)


class MachineValidationRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]

    def test_runtime_is_toml_controlled_and_never_executes_targets(self):
        runtime = load_runtime(self.root)

        self.assertEqual(runtime["validation_id"], "c-top10-cohort-001")
        self.assertEqual(runtime["execution"]["workers"], 4)
        self.assertFalse(runtime["safety"]["execute_target_binaries"])
        self.assertEqual(runtime["canary"]["positions"], [1, 145, 175])

    def test_reference_query_can_include_or_withhold_exact_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            index = root / "reference.sqlite3"
            connection = sqlite3.connect(index)
            connection.executescript(
                """
                CREATE TABLE reference_identity(
                    language TEXT, target_os TEXT, binary_format TEXT,
                    full_hash TEXT, specific_hash TEXT,
                    additional_size INTEGER, code_size INTEGER, owner TEXT,
                    route_id TEXT, treatment_id TEXT, function_name TEXT,
                    evidence_path TEXT
                );
                CREATE TABLE reference_owner_signature(
                    language TEXT, target_os TEXT, binary_format TEXT,
                    full_hash TEXT, specific_hash TEXT,
                    additional_size INTEGER, code_size INTEGER, owner TEXT,
                    function_name TEXT, evidence_path TEXT, identity_count INTEGER
                );
                """
            )
            connection.executemany(
                "INSERT INTO reference_identity VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                [
                    ("x86:LE:64:default", "linux", "ELF", "01", "02", 3, 4, "one@1", "r1", "t1", "one", "one.jsonl"),
                    ("x86:LE:64:default", "linux", "ELF", "01", "02", 3, 4, "one@1", "r2", "t2", "one", "two.jsonl"),
                ],
            )
            connection.execute(
                "INSERT INTO reference_owner_signature VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "x86:LE:64:default", "linux", "ELF", "01", "02", 3, 4,
                    "one@1", "one", "one.jsonl", 2,
                ),
            )
            connection.commit()
            connection.close()
            query = root / "query.jsonl"
            query.write_text(
                json.dumps(
                    {
                        "address": "1000",
                        "function_name": "anonymous",
                        "ghidra_language_id": "x86:LE:64:default",
                        "full_hash": "01",
                        "specific_hash": "02",
                        "specific_hash_additional_size": 3,
                        "code_unit_size": 4,
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            included, _ = _query_index(index, query, "r1", "t1", "linux", "ELF", True)
            withheld, _ = _query_index(index, query, "r1", "t1", "linux", "ELF", False)

            self.assertEqual(len(included["one@1"]), 1)
            self.assertEqual(len(withheld["one@1"]), 1)
            connection = sqlite3.connect(index)
            connection.execute("DELETE FROM reference_identity WHERE route_id='r2'")
            connection.execute(
                "UPDATE reference_owner_signature SET identity_count=1"
            )
            connection.commit()
            connection.close()
            withheld, _ = _query_index(index, query, "r1", "t1", "linux", "ELF", False)
            self.assertNotIn("one@1", withheld)

            wrong_platform, _ = _query_index(
                index, query, "r1", "t1", "android", "ELF", True
            )
            self.assertEqual(wrong_platform, {})

    def test_canary_gate_rejects_stale_runtime_and_accepts_exact_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "runs"
            stale = output / "20260904T100000Z-canary" / "canary-report.json"
            stale.parent.mkdir(parents=True)
            stale.write_text(
                json.dumps(
                    {
                        "state": "measured-complete",
                        "runtime_authority_sha256": "old",
                        "reference_index_schema": REFERENCE_INDEX_SCHEMA,
                        "query_copy_policy": QUERY_COPY_POLICY,
                    }
                ),
                encoding="utf-8",
            )
            runtime = {
                "output_root": "runs",
                "authority_sha256": "current",
            }
            with patch(
                "fidb_poc.machine_validation_runner.load_runtime",
                return_value=runtime,
            ):
                rejected = canary_gate_status(root)
                self.assertFalse(rejected["ready"])
                self.assertEqual(rejected["state"], "stale-or-failed")

                current = output / "20260904T110000Z-canary" / "canary-report.json"
                current.parent.mkdir(parents=True)
                current.write_text(
                    json.dumps(
                        {
                            "state": "measured-complete",
                            "runtime_authority_sha256": "current",
                            "reference_index_schema": REFERENCE_INDEX_SCHEMA,
                            "query_copy_policy": QUERY_COPY_POLICY,
                        }
                    ),
                    encoding="utf-8",
                )
                accepted = canary_gate_status(root)

            self.assertTrue(accepted["ready"])
            self.assertEqual(accepted["run_id"], current.parent.name)

    def test_pause_and_resume_preserve_the_current_run_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_root = root / "runs/fixed-full"
            run_root.mkdir(parents=True)
            status_path = run_root / "status.json"
            current = root / "runs/current.json"
            current.write_text(
                json.dumps({"run_id": "fixed-full", "path": "runs/fixed-full/status.json"}),
                encoding="utf-8",
            )
            status_path.write_text(
                json.dumps(
                    {
                        "schema_version": "fidb-machine-validation-run-status/v1",
                        "validation_id": "validation",
                        "run_id": "fixed-full",
                        "mode": "full",
                        "state": "running",
                        "pid": 42,
                        "expected_work_units": 222,
                        "complete_work_units": 119,
                        "failed_work_units": 2,
                        "resume_count": 0,
                    }
                ),
                encoding="utf-8",
            )
            runtime = {"output_root": "runs"}
            with (
                patch("fidb_poc.machine_validation_runner.load_runtime", return_value=runtime),
                patch("fidb_poc.machine_validation_runner._validation_process_active", return_value=True),
            ):
                pausing = pause_validation(root, actor="test")
            self.assertEqual(pausing["state"], "pausing")
            self.assertEqual(pausing["run_id"], "fixed-full")
            self.assertTrue((run_root / "pause-request.json").is_file())

            paused = {**pausing, "state": "paused", "pid": 42, "worker_pids": []}
            status_path.write_text(json.dumps(paused), encoding="utf-8")
            process = Mock(pid=84)
            with (
                patch("fidb_poc.machine_validation_runner.load_runtime", return_value=runtime),
                patch("fidb_poc.machine_validation_runner._validation_process_active", return_value=False),
                patch("fidb_poc.machine_validation_runner.preflight", return_value={"state": "ready", "blockers": []}),
                patch("fidb_poc.machine_validation_runner.canary_gate_status", return_value={"ready": True}),
                patch("fidb_poc.machine_validation_runner._spawn_validation", return_value=process),
            ):
                resumed = resume_validation(root)
            self.assertEqual(resumed["state"], "queued")
            self.assertEqual(resumed["run_id"], "fixed-full")
            self.assertEqual(resumed["complete_work_units"], 119)
            self.assertEqual(resumed["resume_count"], 1)
            self.assertFalse((run_root / "pause-request.json").exists())
            stored = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertEqual(stored["pid"], 84)

    def test_runtime_status_marks_a_missing_process_interrupted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_root = root / "runs/fixed"
            run_root.mkdir(parents=True)
            (root / "runs/current.json").write_text(
                json.dumps({"run_id": "fixed", "path": "runs/fixed/status.json"}),
                encoding="utf-8",
            )
            (run_root / "status.json").write_text(
                json.dumps(
                    {
                        "run_id": "fixed", "mode": "full", "state": "running",
                        "pid": 42, "worker_pids": [43], "complete_work_units": 3,
                        "failed_work_units": 0,
                    }
                ),
                encoding="utf-8",
            )
            with (
                patch("fidb_poc.machine_validation_runner.load_runtime", return_value={"output_root": "runs"}),
                patch("fidb_poc.machine_validation_runner._validation_process_active", return_value=False),
            ):
                status = runtime_status(root)
            self.assertEqual(status["state"], "interrupted")
            self.assertEqual(status["worker_pids"], [])

    def test_incomplete_stopped_failure_can_be_marked_paused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_root = root / "runs/fixed"
            run_root.mkdir(parents=True)
            (root / "runs/current.json").write_text(
                json.dumps({"run_id": "fixed", "path": "runs/fixed/status.json"}),
                encoding="utf-8",
            )
            status_path = run_root / "status.json"
            status_path.write_text(
                json.dumps(
                    {
                        "run_id": "fixed", "mode": "full", "state": "failed",
                        "pid": 42, "expected_work_units": 10, "complete_work_units": 4,
                        "failed_work_units": 1,
                    }
                ),
                encoding="utf-8",
            )
            with (
                patch("fidb_poc.machine_validation_runner.load_runtime", return_value={"output_root": "runs"}),
                patch("fidb_poc.machine_validation_runner._validation_process_active", return_value=False),
            ):
                status = pause_validation(root, actor="test")
            self.assertEqual(status["state"], "paused")
            self.assertEqual(status["failed_work_units"], 1)
            self.assertEqual(status["pause_actor"], "test")

    def test_failed_result_is_archived_before_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = Path(temporary) / "unit/result.json"
            result.parent.mkdir()
            result.write_text(json.dumps({"state": "failed", "error": "link"}), encoding="utf-8")
            _archive_failed_result(result)
            self.assertFalse(result.exists())
            archived = result.parent / "attempts/result-001.json"
            self.assertEqual(json.loads(archived.read_text(encoding="utf-8"))["error"], "link")

    def test_elf_composite_retries_hidden_stack_check_with_target_stub(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "library.a"
            archive.write_bytes(b"archive")
            output = root / "truth.elf"
            calls = []

            def run(command, **_kwargs):
                calls.append(command)
                if "-c" in command:
                    Path(command[-1]).write_bytes(b"object")
                    return Mock(returncode=0, stdout="", stderr="")
                if len(calls) == 1:
                    return Mock(
                        returncode=1,
                        stdout="",
                        stderr="hidden symbol `__stack_chk_fail_local' isn't defined",
                    )
                output.write_bytes(b"\x7fELF")
                return Mock(returncode=0, stdout="", stderr="")

            route = SimpleNamespace(
                id="linux-powerpc32-be-gcc-12",
                binary_format="ELF",
                compiler=("/toolchain/bin/powerpc-gcc",),
            )
            with patch("fidb_poc.machine_validation_runner.subprocess.run", side_effect=run):
                linked = _link_composite(route, [archive], output, root / "link.map")

            self.assertEqual(linked, output)
            self.assertEqual(len(calls), 3)
            self.assertIn(str(root / "stack-chk-fail-local.o"), calls[2])
            self.assertIn("validation composite retry", (root / "link.log").read_text())



    def test_terminal_validation_uses_shared_scoped_retention(self):
        policy = SimpleNamespace(
            validation_enabled=True,
            validation_automatic_after_terminal_run=True,
        )
        expected = {"state": "complete", "plan_digest": "abc"}
        with (
            patch("fidb_poc.retention.load_retention_policy", return_value=policy),
            patch(
                "fidb_poc.retention.automatic_retention", return_value=expected
            ) as collect,
        ):
            result = _post_validation_retention(
                Path("/project"), {"ledger": "ledger.sqlite3"}, "run-full"
            )

        self.assertEqual(result, expected)
        collect.assert_called_once_with(
            Path("/project"),
            "ledger.sqlite3",
            trigger="machine-validation-complete",
            session_id="machine-validation-run-full",
        )

    def test_terminal_validation_retention_failure_does_not_invalidate_report(self):
        with patch(
            "fidb_poc.retention.load_retention_policy",
            side_effect=ValueError("invalid policy"),
        ):
            result = _post_validation_retention(
                Path("/project"), {"ledger": "ledger.sqlite3"}, "run-full"
            )

        self.assertEqual(result["state"], "failed-safely")
        self.assertIn("invalid policy", result["error"])


if __name__ == "__main__":
    unittest.main()
