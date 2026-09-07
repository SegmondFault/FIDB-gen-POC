import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fidb_poc.machine_validation_runner import (
    DEFAULT_RUNTIME,
    LINK_HARNESS_POLICY,
    QUERY_COPY_POLICY,
    REFERENCE_INDEX_SCHEMA,
    _archive_failed_result,
    _claim_position,
    _cost_aware_positions,
    _fold_checkpoint_path,
    _link_composite,
    _load_fold_checkpoint,
    _load_prepared_fold,
    _post_validation_retention,
    _prepared_fold_path,
    _prior_supervisor_attempts,
    _query_index,
    _query_analysis_policy,
    _resolve_worker_evidence,
    _release_position_claim,
    _release_worker_claims,
    _supervisor_failure,
    _terminal_positions,
    _timed_out_position,
    _worker,
    _write_fold_checkpoint,
    _width_openssl_signatures,
    _zero_control_flow_lines,
    canary_gate_status,
    load_runtime,
    pause_validation,
    requeue_failed_validation,
    resume_validation,
    runtime_status,
    start_validation,
    TransientEvidenceError,
)
from fidb_poc.validation_analysis import (
    QUERY_ANALYSIS_POLICY,
    QUERY_ANALYSIS_RECOVERY_POLICY,
)
from fidb_poc.machine_validation_hashes import (
    ANALYSIS_ENGINE,
    DECISION_UNIT,
    _classify_fold,
    _compile_hash_type_analysis,
    _create_evidence,
    _load_unit_reference,
    _window_open,
    load_hash_method,
    load_hash_schedule,
)


class MachineValidationRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]

    def test_runtime_is_toml_controlled_and_never_executes_targets(self):
        runtime = load_runtime(self.root)

        self.assertEqual(runtime["validation_id"], "c-top10-cohort-001")
        self.assertEqual(runtime["execution"]["workers"], 4)
        self.assertEqual(runtime["execution"]["worker_startup_attempts"], 5)
        self.assertTrue(runtime["execution"]["continue_after_cell_failure"])
        self.assertEqual(runtime["execution"]["cell_timeout_seconds"], 1800)
        self.assertEqual(runtime["execution"]["cell_timeout_attempts"], 2)
        self.assertEqual(
            runtime["execution"]["scheduling_policy"],
            "dynamic-longest-observed-first",
        )
        self.assertEqual(runtime["execution"]["preparation_workers"], 8)
        self.assertEqual(runtime["execution"]["preparation_batch_size"], 16)
        self.assertFalse(runtime["safety"]["execute_target_binaries"])
        self.assertEqual(runtime["canary"]["positions"], [1, 145, 175])

    def test_reference_query_can_include_or_withhold_exact_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            index = root / "reference.sqlite3"
            connection = sqlite3.connect(index)
            connection.executescript("""
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
                """)
            connection.executemany(
                "INSERT INTO reference_identity VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        "x86:LE:64:default",
                        "linux",
                        "ELF",
                        "01",
                        "02",
                        3,
                        4,
                        "one@1",
                        "r1",
                        "t1",
                        "one",
                        "one.jsonl",
                    ),
                    (
                        "x86:LE:64:default",
                        "linux",
                        "ELF",
                        "01",
                        "02",
                        3,
                        4,
                        "one@1",
                        "r2",
                        "t2",
                        "one",
                        "two.jsonl",
                    ),
                ],
            )
            connection.execute(
                "INSERT INTO reference_owner_signature VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "x86:LE:64:default",
                    "linux",
                    "ELF",
                    "01",
                    "02",
                    3,
                    4,
                    "one@1",
                    "one",
                    "one.jsonl",
                    2,
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
            connection.execute("UPDATE reference_owner_signature SET identity_count=1")
            connection.commit()
            connection.close()
            withheld, _ = _query_index(index, query, "r1", "t1", "linux", "ELF", False)
            self.assertNotIn("one@1", withheld)

            wrong_platform, _ = _query_index(
                index, query, "r1", "t1", "android", "ELF", True
            )
            self.assertEqual(wrong_platform, {})

    def test_openssl_fallback_cannot_fill_another_library_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "width-run.json"
            report.write_text(json.dumps({"replay_results": []}), encoding="utf-8")

            resolved = _width_openssl_signatures(
                root,
                {"openssl_width_report": report.name},
                {("sqlite@3.53.4", "route", "treatment")},
            )

            self.assertEqual(resolved, {})

    def test_single_hash_analysis_has_no_library_acceptance_threshold(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            index = root / "reference.sqlite3"
            reference = sqlite3.connect(index)
            reference.execute("""
                CREATE TABLE reference_identity(
                    language TEXT, target_os TEXT, binary_format TEXT,
                    full_hash TEXT, specific_hash TEXT,
                    additional_size INTEGER, code_size INTEGER, owner TEXT,
                    route_id TEXT, treatment_id TEXT, function_name TEXT,
                    evidence_path TEXT
                )
                """)
            reference.executemany(
                "INSERT INTO reference_identity VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        "lang",
                        "linux",
                        "ELF",
                        "01",
                        "a",
                        0,
                        10,
                        "one",
                        "r",
                        "t",
                        "one-hit",
                        "one.jsonl",
                    ),
                    (
                        "lang",
                        "linux",
                        "ELF",
                        "04",
                        "d",
                        0,
                        40,
                        "one",
                        "r",
                        "t",
                        "one-miss",
                        "one.jsonl",
                    ),
                    (
                        "lang",
                        "linux",
                        "ELF",
                        "05",
                        "e",
                        0,
                        50,
                        "two",
                        "r",
                        "t",
                        "two-miss",
                        "two.jsonl",
                    ),
                    (
                        "lang",
                        "linux",
                        "ELF",
                        "02",
                        "b",
                        0,
                        20,
                        "three",
                        "r",
                        "t",
                        "wrong-owner",
                        "three.jsonl",
                    ),
                    (
                        "lang",
                        "linux",
                        "ELF",
                        "01",
                        "z",
                        0,
                        99,
                        "three",
                        "r",
                        "t",
                        "full-only-peer",
                        "three.jsonl",
                    ),
                ],
            )
            reference.commit()
            query = root / "query.jsonl"
            query.write_text(
                "\n".join(
                    json.dumps(
                        {
                            "address": str(index),
                            "function_name": f"query-{index}",
                            "ghidra_language_id": "lang",
                            "full_hash": full,
                            "specific_hash": specific,
                            "specific_hash_additional_size": 0,
                            "code_unit_size": size,
                        }
                    )
                    for index, (full, specific, size) in enumerate(
                        (("01", "a", 10), ("02", "b", 20), ("03", "c", 30))
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            signatures = {}
            for owner in ("one", "two", "three"):
                source = root / f"{owner}.jsonl"
                rows = reference.execute(
                    """
                    SELECT function_name, language, full_hash, specific_hash,
                           additional_size, code_size
                    FROM reference_identity WHERE owner=?
                    """,
                    (owner,),
                ).fetchall()
                source.write_text(
                    "".join(
                        json.dumps(
                            {
                                "address": "",
                                "function_name": name,
                                "ghidra_language_id": language,
                                "full_hash": full,
                                "specific_hash": specific,
                                "specific_hash_additional_size": additional,
                                "code_unit_size": size,
                            }
                        )
                        + "\n"
                        for name, language, full, specific, additional, size in rows
                    ),
                    encoding="utf-8",
                )
                signatures[(owner, "r", "t")] = {
                    "path": source,
                    "source": source.name,
                }
            loaded = _load_unit_reference(
                reference, signatures, ("one", "two", "three"), "r", "t"
            )
            output = _create_evidence(root / "evidence.sqlite3", "run", "digest")
            result = _classify_fold(
                output,
                reference,
                position=1,
                route_id="r",
                treatment_id="t",
                target_os="linux",
                binary_format="ELF",
                fold="A",
                present=["one", "two"],
                cohort=["one", "two", "three"],
                query_path=query,
                query_relative="query.jsonl",
                reference_table="unit_reference",
            )
            outcomes = dict(
                output.execute(
                    "SELECT outcome, COUNT(*) FROM hash_observation GROUP BY outcome"
                ).fetchall()
            )
            _classify_fold(
                output,
                reference,
                position=1,
                route_id="r",
                treatment_id="t",
                target_os="linux",
                binary_format="ELF",
                fold="B",
                present=["three"],
                cohort=["one", "two", "three"],
                query_path=query,
                query_relative="query.jsonl",
                reference_table="unit_reference",
            )
            hash_types = {
                row["hash_type"]: row
                for row in _compile_hash_type_analysis(output, top_limit=10)
            }
            output.close()
            reference.close()

            self.assertEqual(DECISION_UNIT, "complete-fid-signature-owner-assertion")
            self.assertEqual(ANALYSIS_ENGINE, "unit-local-reference-v1")
            self.assertEqual(loaded, 5)
            self.assertEqual(result["true_positives"], 1)
            self.assertEqual(result["false_positives"], 1)
            self.assertEqual(result["true_negatives"], 2)
            self.assertEqual(result["false_negatives"], 2)
            self.assertEqual(result["unattributed_query_signatures"], 2)
            self.assertEqual(outcomes, {"fn": 2, "fp": 1, "tp": 1, "unattributed": 2})
            self.assertEqual(hash_types["full"]["multi_owner_values"], 1)
            self.assertEqual(hash_types["specific"]["multi_owner_values"], 0)
            self.assertEqual(hash_types["complete"]["multi_owner_values"], 0)
            self.assertEqual(
                hash_types["full"]["complete_disambiguated_owner_signatures"], 2
            )
            self.assertEqual(
                hash_types["full"]["top_ambiguous"][0]["owners"],
                ["one", "three"],
            )

    def test_hash_analysis_windows_are_toml_controlled(self):
        schedule = load_hash_schedule(self.root)

        afternoon = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)
        overnight = datetime(2026, 9, 5, 1, 0, tzinfo=timezone.utc)
        closed = datetime(2026, 9, 5, 6, 0, tzinfo=timezone.utc)

        self.assertEqual(
            _window_open(schedule, afternoon),
            (True, "c10-reanalysis-2026-09-05-afternoon"),
        )
        self.assertEqual(_window_open(schedule, overnight), (True, "normal-overnight"))
        self.assertEqual(_window_open(schedule, closed), (False, None))

    def test_single_hash_method_is_versioned_and_safe(self):
        method = load_hash_method(self.root)

        self.assertEqual(method["id"], "single-hash-ground-truth-v1")
        self.assertEqual(set(method["component"]), {"full", "specific", "complete"})
        self.assertEqual(
            method["classification"]["library_acceptance_threshold"], "none"
        )
        self.assertFalse(method["safety"]["start_jvms"])
        self.assertEqual(
            method["construct"]["recall_claim"],
            "harness-conditional-not-intrinsic-fid-recall",
        )
        self.assertEqual(len(method["authority_sha256"]), 64)

    def test_canary_gate_rejects_stale_contract_and_accepts_operational_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "runs"
            stale = output / "20260904T100000Z-canary" / "canary-report.json"
            stale.parent.mkdir(parents=True)
            stale.write_text(
                json.dumps(
                    {
                        "state": "measured-complete",
                        "schema_version": "fidb-machine-validation-canary/v1",
                        "validation_id": "validation",
                        "mode": "canary",
                        "runtime_authority_sha256": "old",
                        "reference_index_schema": REFERENCE_INDEX_SCHEMA,
                        "link_harness_policy": "old-harness",
                        "query_copy_policy": QUERY_COPY_POLICY,
                    }
                ),
                encoding="utf-8",
            )
            runtime = {
                "output_root": "runs",
                "authority_sha256": "current",
                "validation_id": "validation",
                "manifest": "manifest.toml",
                "source_archive": "source.tar.gz",
                "openssl_width_report": "width.json",
                "ghidra_headless": "/opt/ghidra/analyzeHeadless",
                "canary": {
                    "positions": [1, 2, 3],
                    "folds_by_position": ["1:A"],
                    "minimum_distinct_hashes": 1,
                    "require_formats": ["ELF"],
                },
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
                            "schema_version": "fidb-machine-validation-canary/v1",
                            "validation_id": "validation",
                            "mode": "canary",
                            "runtime_authority_sha256": "older-operational-policy",
                            "reference_index_schema": REFERENCE_INDEX_SCHEMA,
                            "link_harness_policy": LINK_HARNESS_POLICY,
                            "query_copy_policy": QUERY_COPY_POLICY,
                            "metrics": {
                                "expected_work_units": 3,
                                "complete_work_units": 3,
                                "failed_work_units": 0,
                                "minimum_distinct_hashes": 1,
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                accepted = canary_gate_status(root)

            self.assertTrue(accepted["ready"])
            self.assertEqual(accepted["run_id"], current.parent.name)
            self.assertTrue(accepted["legacy_contract"])

    def test_pause_and_resume_preserve_the_current_run_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_root = root / "runs/fixed-full"
            run_root.mkdir(parents=True)
            status_path = run_root / "status.json"
            current = root / "runs/current.json"
            current.write_text(
                json.dumps(
                    {"run_id": "fixed-full", "path": "runs/fixed-full/status.json"}
                ),
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
                patch(
                    "fidb_poc.machine_validation_runner.load_runtime",
                    return_value=runtime,
                ),
                patch(
                    "fidb_poc.machine_validation_runner._validation_process_active",
                    return_value=True,
                ),
            ):
                pausing = pause_validation(root, actor="test")
            self.assertEqual(pausing["state"], "pausing")
            self.assertEqual(pausing["run_id"], "fixed-full")
            self.assertTrue((run_root / "pause-request.json").is_file())

            paused = {**pausing, "state": "paused", "pid": 42, "worker_pids": []}
            status_path.write_text(json.dumps(paused), encoding="utf-8")
            process = Mock(pid=84)
            with (
                patch(
                    "fidb_poc.machine_validation_runner.load_runtime",
                    return_value=runtime,
                ),
                patch(
                    "fidb_poc.machine_validation_runner._validation_process_active",
                    return_value=False,
                ),
                patch(
                    "fidb_poc.machine_validation_runner.preflight",
                    return_value={"state": "ready", "blockers": []},
                ),
                patch(
                    "fidb_poc.machine_validation_runner.canary_gate_status",
                    return_value={"ready": True},
                ),
                patch(
                    "fidb_poc.machine_validation_runner._resolve_link_qualification",
                    return_value=({"ready": True}, None, None),
                ),
                patch(
                    "fidb_poc.machine_validation_runner._spawn_validation",
                    return_value=process,
                ),
            ):
                resumed = resume_validation(root)
            self.assertEqual(resumed["state"], "queued")
            self.assertEqual(resumed["run_id"], "fixed-full")
            self.assertEqual(resumed["complete_work_units"], 119)
            self.assertEqual(resumed["resume_count"], 1)
            self.assertFalse((run_root / "pause-request.json").exists())
            stored = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertEqual(stored["pid"], 84)

    def test_foreground_resume_keeps_service_chain_attached(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_root = root / "runs/fixed-full"
            run_root.mkdir(parents=True)
            status_path = run_root / "status.json"
            (root / "runs/current.json").write_text(
                json.dumps(
                    {"run_id": "fixed-full", "path": "runs/fixed-full/status.json"}
                ),
                encoding="utf-8",
            )
            status_path.write_text(
                json.dumps(
                    {
                        "run_id": "fixed-full",
                        "mode": "full",
                        "state": "paused",
                        "pid": 42,
                        "expected_work_units": 222,
                        "complete_work_units": 82,
                        "failed_work_units": 0,
                        "resume_count": 2,
                    }
                ),
                encoding="utf-8",
            )
            (run_root / "pause-request.json").write_text("{}", encoding="utf-8")
            terminal = {"state": "measured-complete", "run_id": "fixed-full"}
            runtime = {"output_root": "runs"}
            with (
                patch(
                    "fidb_poc.machine_validation_runner.load_runtime",
                    return_value=runtime,
                ),
                patch(
                    "fidb_poc.machine_validation_runner._validation_process_active",
                    return_value=False,
                ),
                patch(
                    "fidb_poc.machine_validation_runner.preflight",
                    return_value={"state": "ready", "blockers": []},
                ),
                patch(
                    "fidb_poc.machine_validation_runner.canary_gate_status",
                    return_value={"ready": True},
                ),
                patch(
                    "fidb_poc.machine_validation_runner._resolve_link_qualification",
                    return_value=({"ready": True}, None, None),
                ),
                patch(
                    "fidb_poc.machine_validation_runner.run_validation",
                    return_value=terminal,
                ) as run,
                patch(
                    "fidb_poc.machine_validation_runner._spawn_validation"
                ) as spawn,
            ):
                resumed = resume_validation(root, foreground=True)

            self.assertEqual(resumed, terminal)
            run.assert_called_once_with(root, "full", DEFAULT_RUNTIME, "fixed-full")
            spawn.assert_not_called()
            self.assertFalse((run_root / "pause-request.json").exists())
            queued = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertEqual(queued["state"], "queued")
            self.assertEqual(queued["resume_count"], 3)

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
                        "run_id": "fixed",
                        "mode": "full",
                        "state": "running",
                        "pid": 42,
                        "worker_pids": [43],
                        "complete_work_units": 3,
                        "failed_work_units": 0,
                    }
                ),
                encoding="utf-8",
            )
            with (
                patch(
                    "fidb_poc.machine_validation_runner.load_runtime",
                    return_value={
                        "validation_id": "validation",
                        "output_root": "runs",
                    },
                ),
                patch(
                    "fidb_poc.machine_validation_runner._validation_process_active",
                    return_value=False,
                ),
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
                        "run_id": "fixed",
                        "mode": "full",
                        "state": "failed",
                        "pid": 42,
                        "expected_work_units": 10,
                        "complete_work_units": 4,
                        "failed_work_units": 1,
                    }
                ),
                encoding="utf-8",
            )
            with (
                patch(
                    "fidb_poc.machine_validation_runner.load_runtime",
                    return_value={
                        "validation_id": "validation",
                        "output_root": "runs",
                    },
                ),
                patch(
                    "fidb_poc.machine_validation_runner._validation_process_active",
                    return_value=False,
                ),
            ):
                status = pause_validation(root, actor="test")
            self.assertEqual(status["state"], "paused")
            self.assertEqual(status["failed_work_units"], 1)
            self.assertEqual(status["pause_actor"], "test")

    def test_failed_cells_are_requeued_with_an_evidence_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_root = root / "runs/fixed"
            run_root.mkdir(parents=True)
            status_path = run_root / "status.json"
            (root / "runs/current.json").write_text(
                json.dumps({"run_id": "fixed", "path": "runs/fixed/status.json"}),
                encoding="utf-8",
            )
            status = {
                "run_id": "fixed",
                "mode": "full",
                "state": "paused",
                "pid": 42,
                "expected_work_units": 2,
                "complete_work_units": 1,
                "failed_work_units": 1,
            }
            status_path.write_text(json.dumps(status), encoding="utf-8")
            unit = {
                "position": 2,
                "route_id": "route",
                "profile_id": "profile",
                "treatment_id": "treatment",
            }
            result = run_root / "units/002-route-treatment/result.json"
            result.parent.mkdir(parents=True)
            result.write_text(
                json.dumps({"state": "failed", "mode": "full", "error": "old"}),
                encoding="utf-8",
            )
            with (
                patch(
                    "fidb_poc.machine_validation_runner.load_runtime",
                    return_value={"output_root": "runs"},
                ),
                patch(
                    "fidb_poc.machine_validation_runner.runtime_status",
                    return_value=status,
                ),
                patch(
                    "fidb_poc.machine_validation_runner._validation_process_active",
                    return_value=False,
                ),
                patch(
                    "fidb_poc.machine_validation_runner.resolve_evidence",
                    return_value={"manifest": {"work_unit": [unit]}},
                ),
            ):
                receipt = requeue_failed_validation(root, [2], actor="test")

            self.assertEqual(receipt["positions"], [2])
            self.assertEqual(receipt["remaining_failed_work_units"], 0)
            self.assertFalse(result.exists())
            self.assertTrue((result.parent / "attempts/result-001.json").is_file())
            self.assertTrue((run_root / "requeues/requeue-001.json").is_file())

    def test_failed_result_is_archived_before_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = Path(temporary) / "unit/result.json"
            result.parent.mkdir()
            result.write_text(
                json.dumps({"state": "failed", "error": "link"}), encoding="utf-8"
            )
            _archive_failed_result(result)
            self.assertFalse(result.exists())
            archived = result.parent / "attempts/result-001.json"
            self.assertEqual(
                json.loads(archived.read_text(encoding="utf-8"))["error"], "link"
            )

    def test_explicit_requeue_starts_a_fresh_automatic_timeout_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary) / "run"
            result = run_root / "units/007-route-treatment/result.json"
            attempts = result.parent / "attempts"
            attempts.mkdir(parents=True)
            for number in (1, 2, 3):
                (attempts / f"result-{number:03d}.json").write_text(
                    json.dumps(
                        {
                            "state": "failed",
                            "reason_code": "cell-timeout",
                        }
                    ),
                    encoding="utf-8",
                )
            receipts = run_root / "requeues"
            receipts.mkdir()
            (receipts / "requeue-001.json").write_text(
                json.dumps(
                    {
                        "positions": [7],
                        "archived_results": [
                            {
                                "position": 7,
                                "archived_path": (
                                    "runs/fixed/units/007-route-treatment/"
                                    "attempts/result-002.json"
                                ),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(_prior_supervisor_attempts(result, "cell-timeout"), 1)

    def test_superh_timeout_selects_evidence_recorded_analysis_recovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = Path(temporary) / "units/007-route-treatment/result.json"
            attempts = result.parent / "attempts"
            attempts.mkdir(parents=True)
            (attempts / "result-001.json").write_text(
                json.dumps({"state": "failed", "reason_code": "cell-timeout"}),
                encoding="utf-8",
            )

            superh = SimpleNamespace(ghidra_language="SuperH4:LE:32:default")
            x86 = SimpleNamespace(ghidra_language="x86:LE:64:default")
            self.assertEqual(
                _query_analysis_policy(result, superh),
                QUERY_ANALYSIS_RECOVERY_POLICY,
            )
            self.assertEqual(_query_analysis_policy(result, x86), QUERY_ANALYSIS_POLICY)

    def test_workers_claim_units_exclusively_and_release_only_their_own(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary)

            self.assertTrue(_claim_position(run_root, 7, pid=101))
            self.assertFalse(_claim_position(run_root, 7, pid=202))
            self.assertFalse(_release_position_claim(run_root, 7, pid=202))
            self.assertEqual(_release_worker_claims(run_root, 101), [7])
            self.assertTrue(_claim_position(run_root, 7, pid=202))

    def test_cost_aware_queue_runs_slowest_observed_route_first(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary)
            units = {
                1: {"route_id": "fast", "treatment_id": "o2"},
                2: {"route_id": "slow", "treatment_id": "o2"},
                3: {"route_id": "unknown", "treatment_id": "o2"},
            }
            for position, route, seconds in ((10, "fast", 2), (11, "slow", 9)):
                path = run_root / "units" / str(position) / "result.json"
                path.parent.mkdir(parents=True)
                path.write_text(
                    json.dumps(
                        {
                            "state": "complete",
                            "mode": "full",
                            "route_id": route,
                            "wall_time_ns": seconds * 1_000_000_000,
                        }
                    ),
                    encoding="utf-8",
                )

            self.assertEqual(
                _cost_aware_positions(run_root, units, units, "full"), [2, 3, 1]
            )

    def test_prepared_fold_requires_exact_identity_and_live_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unit = root / "unit"
            marker = _prepared_fold_path(unit, "B")
            marker.parent.mkdir(parents=True)
            truth = marker.parent / "truth.elf"
            query = marker.parent / "query.elf"
            truth.write_bytes(b"truth")
            query.write_bytes(b"query")
            document = {
                "schema_version": "fidb-machine-validation-prepared-fold/v1",
                "state": "prepared",
                "position": 9,
                "route_id": "route",
                "treatment_id": "o2",
                "fold": "B",
                "runtime_authority_sha256": "authority",
                "link_harness_policy": LINK_HARNESS_POLICY,
                "query_copy_policy": QUERY_COPY_POLICY,
                "truth_binary": str(truth.relative_to(root)),
                "query_binary": str(query.relative_to(root)),
            }
            marker.write_text(json.dumps(document), encoding="utf-8")
            identity = {
                "position": 9,
                "route_id": "route",
                "treatment_id": "o2",
                "fold": "B",
                "runtime_authority_sha256": "authority",
            }

            self.assertEqual(_load_prepared_fold(root, marker, **identity), document)
            query.unlink()
            self.assertIsNone(_load_prepared_fold(root, marker, **identity))

    def test_fold_checkpoint_reuses_only_the_exact_scientific_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            unit = Path(temporary) / "unit"
            path = _fold_checkpoint_path(unit, "A")
            result = {"fold": "A", "query_sha256": "query", "failures": []}
            identity = {
                "mode": "full",
                "position": 17,
                "route_id": "linux-x86-64-gcc-13",
                "treatment_id": "optimization_o2",
                "fold": "A",
                "runtime_authority_sha256": "authority",
            }

            _write_fold_checkpoint(path, result, **identity)

            self.assertEqual(_load_fold_checkpoint(path, **identity), result)
            self.assertIsNone(
                _load_fold_checkpoint(
                    path, **{**identity, "runtime_authority_sha256": "changed"}
                )
            )

    def test_worker_retries_transient_evidence_resolution(self):
        runtime = {
            "execution": {
                "worker_startup_attempts": 3,
                "worker_startup_retry_seconds": 2,
            }
        }
        evidence = {"runtime": runtime}
        with (
            patch(
                "fidb_poc.machine_validation_runner.load_runtime",
                return_value=runtime,
            ),
            patch(
                "fidb_poc.machine_validation_runner.resolve_evidence",
                side_effect=[TransientEvidenceError("locked"), evidence],
            ) as resolve,
            patch("fidb_poc.machine_validation_runner.time.sleep") as sleep,
        ):
            resolved = _resolve_worker_evidence(Path("/project"), "runtime.toml")

        self.assertIs(resolved, evidence)
        self.assertEqual(resolve.call_count, 2)
        sleep.assert_called_once_with(2)

    def test_worker_records_a_failed_cell_then_continues_its_shard(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "runs").mkdir()
            (root / "runs/reference-index.sqlite3").touch()
            route = SimpleNamespace(id="route")
            treatment = SimpleNamespace(id="treatment")
            execution = {
                "jvm_initial_heap_mib": 256,
                "jvm_max_heap_mib": 1024,
                "jvm_active_processors": 1,
                "continue_after_cell_failure": True,
            }
            evidence = {
                "runtime": {
                    "output_root": "runs",
                    "authority_sha256": "authority",
                    "ghidra_headless": "/bin/true",
                    "execution": execution,
                    "canary": {"folds_by_position": []},
                },
                "configuration": SimpleNamespace(
                    routes=[route], treatments=[treatment]
                ),
                "manifest": {
                    "work_unit": [
                        {
                            "position": position,
                            "route_id": "route",
                            "profile_id": "profile",
                            "treatment_id": "treatment",
                        }
                        for position in (1, 2)
                    ],
                    "execution": {"harness_mode": LINK_HARNESS_POLICY},
                },
                "status": {
                    "randomization": {
                        "fold_a": ["openssl@3.5.8"],
                        "fold_b": ["other@1"],
                        "canonical_ids": ["openssl@3.5.8", "other@1"],
                    }
                },
                "archives": {},
            }
            with (
                patch(
                    "fidb_poc.machine_validation_runner._resolve_worker_evidence",
                    return_value=evidence,
                ),
                patch("fidb_poc.pipeline.find_ghidra", return_value=(None, root)),
                patch("fidb_poc.pipeline.ghidra_environment", return_value={}),
                patch("fidb_poc.ghidra_fid.ensure_started"),
                patch(
                    "fidb_poc.machine_validation_runner._rebuild_openssl_archives",
                    side_effect=RuntimeError("fixture failure"),
                ) as rebuild,
            ):
                result = _worker(root, "runtime.toml", "run", [1, 2], "full")

            self.assertEqual(result, 1)
            self.assertEqual(rebuild.call_count, 2)
            results = sorted((root / "runs/run/units").glob("*/result.json"))
            self.assertEqual(len(results), 2)
            self.assertTrue(
                all(
                    json.loads(path.read_text())["state"] == "failed"
                    for path in results
                )
            )

    def test_worker_progress_only_times_out_an_active_cell(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary)
            progress = run_root / "workers/42.json"
            progress.parent.mkdir()
            progress.write_text(
                json.dumps(
                    {
                        "state": "running",
                        "position": 17,
                        "started_unix_ns": 1_000_000_000,
                    }
                ),
                encoding="utf-8",
            )

            self.assertIsNone(_timed_out_position(run_root, 42, 30, 30_000_000_000))
            self.assertEqual(_timed_out_position(run_root, 42, 30, 31_000_000_000), 17)
            progress.write_text(
                json.dumps({"state": "idle", "position": 17}), encoding="utf-8"
            )
            self.assertIsNone(_timed_out_position(run_root, 42, 30, 99_000_000_000))

    def test_supervisor_failure_is_terminal_and_preserves_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary)
            unit = {
                "position": 7,
                "route_id": "route",
                "profile_id": "profile",
                "treatment_id": "treatment",
            }
            result_path = _supervisor_failure(
                run_root,
                unit,
                7,
                "full",
                "cell-timeout",
                "timed out",
            )

            result = json.loads(result_path.read_text(encoding="utf-8"))
            self.assertEqual(result["reason_code"], "cell-timeout")
            self.assertEqual(result["route_id"], "route")
            self.assertEqual(_terminal_positions(run_root, "full", {7: unit}, [7]), {7})

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
            with (
                patch(
                    "fidb_poc.machine_validation_runner.subprocess.run",
                    side_effect=run,
                ),
                patch("fidb_poc.machine_validation_runner._audit_linked_image"),
            ):
                linked = _link_composite(
                    route,
                    [archive],
                    output,
                    root / "link.map",
                    harness_mode=LINK_HARNESS_POLICY,
                )

            self.assertEqual(linked, output)
            self.assertEqual(len(calls), 3)
            self.assertIn(str(root / "stack-chk-fail-local.o"), calls[2])
            self.assertIn("-shared", calls[2])
            self.assertIn("-Wl,-Bsymbolic", calls[2])
            self.assertNotIn("-Wl,-e,0", calls[2])
            self.assertNotIn("-Wl,--unresolved-symbols=ignore-all", calls[2])
            self.assertIn("validation composite retry", (root / "link.log").read_text())

    def test_android_32_composite_records_bounded_text_relocation_retry(self):
        for architecture, relocation in (
            ("arm", "R_ARM_ABS32"),
            ("i686", "R_386_32"),
        ):
            with self.subTest(architecture=architecture), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "library.a"
                archive.write_bytes(b"archive")
                output = root / "truth.elf"
                calls = []

                def run(command, **_kwargs):
                    calls.append(command)
                    if len(calls) == 1:
                        return Mock(
                            returncode=1,
                            stdout="",
                            stderr=(
                                f"relocation {relocation} cannot be used; "
                                "recompile with -fPIC"
                            ),
                        )
                    output.write_bytes(b"\x7fELF")
                    return Mock(returncode=0, stdout="", stderr="")

                route = SimpleNamespace(
                    id=f"android-{architecture}",
                    target_os="android",
                    architecture=architecture,
                    binary_format="ELF",
                    compiler=("/toolchain/bin/clang",),
                )
                with (
                    patch(
                        "fidb_poc.machine_validation_runner.subprocess.run",
                        side_effect=run,
                    ),
                    patch(
                        "fidb_poc.machine_validation_runner._audit_linked_image"
                    ) as audit,
                ):
                    linked = _link_composite(
                        route,
                        [archive],
                        output,
                        root / "link.map",
                        harness_mode=LINK_HARNESS_POLICY,
                    )

                self.assertEqual(linked, output)
                self.assertEqual(len(calls), 2)
                self.assertNotIn("-Wl,-z,notext", calls[0])
                self.assertIn("-Wl,-z,notext", calls[1])
                self.assertEqual(
                    audit.call_args.kwargs["linker_compatibility"],
                    "android-32-text-relocations",
                )
                self.assertIn(
                    "android 32-bit text-relocation compatibility",
                    (root / "link.log").read_text(),
                )

    def test_non_android_composite_does_not_relax_non_pic_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "library.a"
            archive.write_bytes(b"archive")
            route = SimpleNamespace(
                id="linux-i686",
                target_os="linux",
                architecture="i686",
                binary_format="ELF",
                compiler=("/toolchain/bin/clang",),
            )
            failure = Mock(
                returncode=1,
                stdout="",
                stderr="relocation R_386_32 cannot be used; recompile with -fPIC",
            )
            with patch(
                "fidb_poc.machine_validation_runner.subprocess.run",
                return_value=failure,
            ) as run:
                with self.assertRaisesRegex(RuntimeError, "composite link failed"):
                    _link_composite(
                        route,
                        [archive],
                        root / "truth.elf",
                        root / "link.map",
                        harness_mode=LINK_HARNESS_POLICY,
                    )
            run.assert_called_once()

    def test_zero_address_control_flow_is_detected_across_instruction_sets(self):
        lines = [
            "  4010: e8 eb bf ff ff call 0 <missing>",
            "  1004: 97ffff00 bl 0 <missing>",
            "  2008: 0c000000 jal 0 <missing>",
            "  300c: e8 6f 00 00 call 3080 <present>",
            "  4010: ff 10 call *(%rax)",
            "  25bc10: e3cb7000 bic r7, fp, #0",
            "  25bc14: e3c77000 bic r7, r7, #0",
            "  3d369b: 00 .byte 0",
            "  5000: 00 00 add 0,%eax",
        ]

        self.assertEqual(len(_zero_control_flow_lines(lines)), 3)

    def test_composite_rejects_stale_harness_authority_before_linking(self):
        route = SimpleNamespace(id="route", binary_format="ELF", compiler=("cc",))
        with self.assertRaisesRegex(ValueError, "unsupported validation harness"):
            _link_composite(
                route,
                [],
                Path("output"),
                Path("link.map"),
                harness_mode="whole-archive-link-map",
            )

    def test_full_start_accepts_one_immutable_planned_run_id(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                patch(
                    "fidb_poc.machine_validation_runner.preflight",
                    return_value={"state": "ready", "blockers": []},
                ),
                patch(
                    "fidb_poc.machine_validation_runner.runtime_status",
                    return_value={"state": "not-started"},
                ),
                patch(
                    "fidb_poc.machine_validation_runner.canary_gate_status",
                    return_value={"ready": True},
                ),
                patch(
                    "fidb_poc.machine_validation_runner.load_runtime",
                    return_value={
                        "validation_id": "validation",
                        "output_root": "runs",
                    },
                ),
                patch(
                    "fidb_poc.machine_validation_runner._resolve_link_qualification",
                    return_value=({"ready": True}, None, None),
                ),
                patch(
                    "fidb_poc.machine_validation_runner._spawn_validation",
                    return_value=SimpleNamespace(pid=42),
                ),
            ):
                started = start_validation(root, "full", run_id="planned-full")
                with self.assertRaisesRegex(ValueError, "run id already exists"):
                    start_validation(root, "full", run_id="planned-full")
                with self.assertRaisesRegex(ValueError, "safe path component"):
                    start_validation(root, "full", run_id="../escape")

            self.assertEqual(started["run_id"], "planned-full")
            self.assertEqual(
                json.loads((root / "runs/planned-full/status.json").read_text())[
                    "mode"
                ],
                "full",
            )

    def test_new_run_is_not_created_when_link_qualification_is_unsatisfied(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = {"validation_id": "validation", "output_root": "runs"}
            with (
                patch(
                    "fidb_poc.machine_validation_runner.preflight",
                    return_value={"state": "ready", "blockers": []},
                ),
                patch(
                    "fidb_poc.machine_validation_runner.runtime_status",
                    return_value={"state": "not-started"},
                ),
                patch(
                    "fidb_poc.machine_validation_runner.canary_gate_status",
                    return_value={"ready": True},
                ),
                patch(
                    "fidb_poc.machine_validation_runner.load_runtime",
                    return_value=runtime,
                ),
                patch(
                    "fidb_poc.machine_validation_runner._resolve_link_qualification",
                    return_value=(
                        {
                            "ready": False,
                            "blockers": ["four link cells failed"],
                        },
                        None,
                        None,
                    ),
                ),
                patch("fidb_poc.machine_validation_runner._spawn_validation") as spawn,
            ):
                with self.assertRaisesRegex(ValueError, "four link cells failed"):
                    start_validation(root, "full", run_id="future-full")

            self.assertFalse((root / "runs/future-full").exists())
            spawn.assert_not_called()

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
