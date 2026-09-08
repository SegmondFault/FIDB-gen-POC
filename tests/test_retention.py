from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from fidb_poc.retention import (
    RetentionError,
    apply_retention_plan,
    automatic_retention,
    compile_retention_plan,
    load_retention_policy,
    main,
    retention_status,
    write_memory_cleanup_audit,
    write_retention_plan,
)


class RetentionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source_root = Path(__file__).resolve().parents[1]

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        shutil.copytree(self.source_root / "retention", self.root / "retention")
        self.database = self.root / "var/fidb-coordinator/ledger.sqlite3"
        self.database.parent.mkdir(parents=True)
        with sqlite3.connect(self.database) as connection:
            connection.executescript("""
                CREATE TABLE coordinator_state (
                    singleton INTEGER PRIMARY KEY, sync_generation INTEGER,
                    synced_at TEXT, armed INTEGER, paused INTEGER
                );
                CREATE TABLE jobs (
                    job_id TEXT PRIMARY KEY, state TEXT, result_json TEXT,
                    batch_id TEXT, base_cell_id TEXT, active INTEGER
                );
                CREATE TABLE attempts (
                    attempt_id INTEGER PRIMARY KEY, job_id TEXT,
                    attempt_number INTEGER, lease_generation INTEGER,
                    state TEXT, started_at TEXT, ended_at TEXT, error TEXT
                );
                CREATE TABLE stage_attempts (
                    stage_attempt_id INTEGER PRIMARY KEY, attempt_id INTEGER,
                    sequence INTEGER, stage TEXT, state TEXT, error TEXT,
                    details_json TEXT, metrics_json TEXT
                );
                CREATE TABLE events (
                    event_id INTEGER PRIMARY KEY, occurred_at TEXT, event_type TEXT
                );
                INSERT INTO coordinator_state VALUES (1, 7, '2026-09-04T00:00:00+00:00', 0, 1);
                INSERT INTO events VALUES (42, '2026-09-04T03:00:00+00:00', 'batch.drained');
                """)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def job_id(number: int) -> str:
        return f"job-{number:064x}"

    def add_job(
        self,
        number: int,
        state: str,
        *,
        result: dict[str, object] | None = None,
    ) -> str:
        job_id = self.job_id(number)
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT INTO jobs VALUES (?, ?, ?, 'batch-test', 'cell-test', 1)",
                (job_id, state, json.dumps(result) if result is not None else None),
            )
        return job_id

    def add_failed_attempt(
        self,
        job_id: str,
        attempt_id: int,
        attempt_number: int,
        error: str,
    ) -> Path:
        generation = attempt_number
        attempt = (
            self.root / "artifacts/runs/staging" / f"{job_id}-g{generation}-fixture"
        )
        logs = attempt / "work/logs"
        logs.mkdir(parents=True)
        (logs / "build.log").write_text(f"failure: {error}\n", encoding="utf-8")
        (attempt / "work/disposable.bin").write_bytes(b"x" * 1024)
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT INTO attempts VALUES (?, ?, ?, ?, 'failed', ?, ?, ?)",
                (
                    attempt_id,
                    job_id,
                    attempt_number,
                    generation,
                    "2026-09-04T00:00:00+00:00",
                    "2026-09-04T00:01:00+00:00",
                    error.replace("<attempt>", str(attempt)),
                ),
            )
            connection.execute(
                "INSERT INTO stage_attempts VALUES (?, ?, 1, 'compile', 'failed', ?, '{}', '{}')",
                (
                    attempt_id,
                    attempt_id,
                    error.replace("<attempt>", str(attempt)),
                ),
            )
        return attempt

    def add_success(self, number: int) -> tuple[str, Path, dict[str, object]]:
        job_id = self.job_id(number)
        attempt = self.root / "artifacts/runs" / job_id / "attempt-1"
        artifacts = attempt / "artifacts"
        artifacts.mkdir(parents=True)
        work = attempt / "work"
        work.mkdir()
        (work / "scratch.bin").write_bytes(b"scratch")
        fidb = artifacts / "result.fidb"
        fidbf = artifacts / "result.fidbf"
        fidb.write_bytes(b"packed")
        fidbf.write_bytes(b"raw")
        cell_id = "cell-test"
        seal = artifacts / "cell-seal.json"
        seal.write_text(
            json.dumps(
                {
                    "schema_version": "fidb-cell-seal/v1",
                    "cell": {"id": cell_id},
                    "artifacts": {
                        "fidb": {
                            "sha256": hashlib.sha256(fidb.read_bytes()).hexdigest(),
                            "bytes": fidb.stat().st_size,
                        },
                        "fidbf": {
                            "sha256": hashlib.sha256(fidbf.read_bytes()).hexdigest(),
                            "bytes": fidbf.stat().st_size,
                        },
                    },
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        result = {
            "cell_id": cell_id,
            "attempt_root": str(attempt.relative_to(self.root)),
            "seal": self.artifact_record(seal),
            "fidb": self.artifact_record(fidb),
            "fidbf": self.artifact_record(fidbf),
        }
        self.add_job(number, "complete", result=result)
        return job_id, attempt, result

    def artifact_record(self, path: Path) -> dict[str, object]:
        return {
            "path": str(path.relative_to(self.root)),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "bytes": path.stat().st_size,
        }

    def add_complete_validation_run(
        self,
        run_id: str = "validation-full",
        *,
        relationship_evidence: bool = True,
    ) -> Path:
        run = self.root / "artifacts/validation-runs/cohort-001" / run_id
        unit = run / "units/001-route-baseline"
        folds = []
        for name in ("A", "B"):
            fold = unit / f"fold-{name}"
            fold.mkdir(parents=True)
            (fold / "truth-map.json").write_text(
                json.dumps({"fold": name, "owners": [f"library-{name}"]}),
                encoding="utf-8",
            )
            signatures = fold / "query-signatures.jsonl"
            signatures.write_text(
                json.dumps(
                    {
                        "full_hash": name,
                        "specific_hash": name,
                        "children": [],
                        "parents": [],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (fold / "truth.elf").write_bytes(b"truth" + name.encode())
            (fold / "query.elf").write_bytes(b"query" + name.encode())
            fold_result = {
                "fold": name,
                "query_sha256": hashlib.sha256(
                    (fold / "query.elf").read_bytes()
                ).hexdigest(),
            }
            if relationship_evidence:
                fold_result["signature_summary"] = {
                    "evidence_schema": "fidb-program-signature-evidence/v1",
                    "functions_hashed": 1,
                    "relation_hashes": 0,
                    "artifact_sha256": hashlib.sha256(
                        signatures.read_bytes()
                    ).hexdigest(),
                    "artifact_bytes": signatures.stat().st_size,
                }
            folds.append(fold_result)
        (unit / "result.json").write_text(
            json.dumps(
                {
                    "schema_version": "fidb-machine-validation-unit/v1",
                    "state": "complete",
                    "mode": "full",
                    "position": 1,
                    "folds": folds,
                }
            ),
            encoding="utf-8",
        )
        database = run / "hash-evidence.sqlite3"
        database.write_bytes(b"retained hash observations")
        report = run / "hash-report.json"
        report.write_text(
            json.dumps(
                {
                    "schema_version": "fidb-machine-validation-hash-report/v1",
                    "validation_id": "cohort-001",
                    "state": "measured-complete",
                    "hash_evidence": {
                        "database_path": str(database.relative_to(self.root)),
                        "database_sha256": hashlib.sha256(
                            database.read_bytes()
                        ).hexdigest(),
                    },
                    "metrics": {
                        "expected_work_units": 1,
                        "complete_work_units": 1,
                        "failed_work_units": 0,
                    },
                }
            ),
            encoding="utf-8",
        )
        (run / "status.json").write_text(
            json.dumps(
                {
                    "schema_version": "fidb-machine-validation-run-status/v1",
                    "validation_id": "cohort-001",
                    "run_id": run_id,
                    "mode": "full",
                    "state": "complete",
                    "expected_work_units": 1,
                    "complete_work_units": 1,
                    "failed_work_units": 0,
                    "report_path": str(report.relative_to(self.root)),
                }
            ),
            encoding="utf-8",
        )
        worker = run / "worker-1234"
        worker.mkdir()
        (worker / "disposable.bin").write_bytes(b"scratch" * 100)
        (run / "worker-01.log").write_text("retained worker log\n", encoding="utf-8")
        return run

    def test_success_is_verified_but_preserved_until_lane_receipt(self) -> None:
        job_id, attempt, _result = self.add_success(1)

        plan = compile_retention_plan(self.root)

        self.assertEqual(plan["summary"]["verified_successes"], 1)
        self.assertEqual(plan["summary"]["success_scratch_prunes"], 0)
        self.assertEqual(plan["preserved"][0]["job_id"], job_id)
        self.assertEqual(
            plan["preserved"][0]["reason"],
            "awaiting-relationship-complete-lane-import",
        )
        self.assertTrue((attempt / "work/scratch.bin").is_file())

    def test_verified_lane_receipt_allows_only_success_scratch_prune(self) -> None:
        job_id, attempt, result = self.add_success(2)
        policy = load_retention_policy(self.root)
        policy.lane_import_receipts.mkdir(parents=True)
        (policy.lane_import_receipts / f"{job_id}.json").write_text(
            json.dumps(
                {
                    "schema_version": "fidb-lane-import-receipt/v1",
                    "job_id": job_id,
                    "attempt_root": str(attempt.relative_to(self.root)),
                    "seal_sha256": result["seal"]["sha256"],
                    "relationship_complete": True,
                    "lane_generation": "linux-x86-generation-1",
                }
            ),
            encoding="utf-8",
        )
        plan = compile_retention_plan(self.root)
        write_retention_plan(plan, self.root)

        applied = apply_retention_plan(self.root, plan["plan_digest"])

        self.assertEqual(applied["actions_completed"], 1)
        self.assertFalse((attempt / "work").exists())
        self.assertTrue((attempt / "artifacts/result.fidb").is_file())
        self.assertTrue((attempt / "artifacts/result.fidbf").is_file())
        self.assertTrue((attempt / "artifacts/cell-seal.json").is_file())

    def test_identical_failed_retries_collapse_into_one_verified_bundle(self) -> None:
        job_id = self.add_job(3, "failed")
        first = self.add_failed_attempt(job_id, 31, 1, "compiler failed in <attempt>")
        second = self.add_failed_attempt(job_id, 32, 2, "compiler failed in <attempt>")
        plan = compile_retention_plan(self.root)
        action = plan["actions"][0]
        self.assertEqual(action["collapsed_attempts"], [2, 1])
        self.assertEqual(len(action["evidence_files"]), 1)
        self.assertEqual(
            action["evidence_files"][0]["relative_path"], "work/logs/build.log"
        )
        write_retention_plan(plan, self.root)

        applied = apply_retention_plan(self.root, plan["plan_digest"])

        self.assertEqual(applied["actions_completed"], 1)
        self.assertFalse(first.exists())
        self.assertFalse(second.exists())
        bundle = self.root / action["bundle_path"]
        evidence = json.loads((bundle / "evidence.json").read_text(encoding="utf-8"))
        self.assertEqual(evidence["failure_fingerprint"], action["failure_fingerprint"])
        self.assertTrue((bundle / "files/work/logs/build.log").is_file())

    def test_different_failed_retry_is_quarantined_and_not_removed(self) -> None:
        job_id = self.add_job(4, "failed")
        first = self.add_failed_attempt(job_id, 41, 1, "configure failed")
        second = self.add_failed_attempt(job_id, 42, 2, "link failed")

        plan = compile_retention_plan(self.root)
        action = plan["actions"][0]

        self.assertEqual(action["collapsed_attempts"], [2])
        self.assertEqual(plan["summary"]["quarantined"], 1)
        self.assertTrue(plan["automatic_apply_eligible"])
        write_retention_plan(plan, self.root)
        apply_retention_plan(self.root, plan["plan_digest"])
        self.assertTrue(first.exists())
        self.assertFalse(second.exists())

    def test_apply_rejects_tampered_or_stale_plan(self) -> None:
        job_id = self.add_job(5, "failed")
        self.add_failed_attempt(job_id, 51, 1, "failed")
        plan = compile_retention_plan(self.root)
        path = write_retention_plan(plan, self.root)
        document = json.loads(path.read_text(encoding="utf-8"))
        document["summary"]["recoverable_apparent_bytes"] += 1
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(RetentionError, "does not match its digest"):
            apply_retention_plan(self.root, plan["plan_digest"])

        path.write_text(json.dumps(plan), encoding="utf-8")
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE coordinator_state SET sync_generation=8 WHERE singleton=1"
            )
        with self.assertRaisesRegex(RetentionError, "plan is stale"):
            apply_retention_plan(self.root, plan["plan_digest"])

    def test_cli_accepts_project_options_after_subcommand(self) -> None:
        with patch("fidb_poc.retention.retention_status", return_value={"state": "ok"}):
            status = main(["status", "--project-root", str(self.root)])

        self.assertEqual(status, 0)

    def test_status_exposes_compact_action_examples(self) -> None:
        job_id = self.add_job(6, "failed")
        self.add_failed_attempt(job_id, 61, 1, "compiler failed")
        plan = compile_retention_plan(self.root)
        self.assertIn("stage_evidence", plan["actions"][0])
        write_retention_plan(plan, self.root)

        status = retention_status(self.root)

        example = status["latest_plan"]["action_examples"][0]
        self.assertEqual(example["job_id"], job_id)
        self.assertNotIn("stage_evidence", example)
        self.assertNotIn("evidence_files", example)

    def test_memory_cleanup_audits_are_aggregated_by_recycle_session(self) -> None:
        first = write_memory_cleanup_audit(
            self.root,
            worker_id="worker-1",
            session_id="batch-drained-42",
            before_rss_bytes=2 * 1024**3,
            after_rss_bytes=64 * 1024**2,
            before_jvm_started=True,
            after_jvm_started=False,
        )
        second = write_memory_cleanup_audit(
            self.root,
            worker_id="worker-2",
            session_id="batch-drained-42",
            before_rss_bytes=3 * 1024**3,
            after_rss_bytes=96 * 1024**2,
            before_jvm_started=True,
            after_jvm_started=False,
        )

        status = retention_status(self.root)
        memory = status["memory_cleanup"]["latest_session"]

        self.assertEqual(first["state"], "passed")
        self.assertEqual(second["state"], "passed")
        self.assertEqual(memory["workers"], 2)
        self.assertEqual(memory["passed"], 2)
        self.assertEqual(memory["warnings"], 0)
        self.assertEqual(memory["before_rss_bytes"], 5 * 1024**3)
        self.assertEqual(memory["after_rss_bytes"], 160 * 1024**2)

    def test_memory_cleanup_audit_warns_on_fresh_jvm_or_high_rss(self) -> None:
        report = write_memory_cleanup_audit(
            self.root,
            worker_id="worker-1",
            session_id="batch-drained-43",
            before_rss_bytes=128 * 1024**2,
            after_rss_bytes=700 * 1024**2,
            before_jvm_started=False,
            after_jvm_started=True,
        )

        self.assertEqual(report["state"], "warning")
        self.assertEqual(len(report["reasons"]), 2)

    def test_validation_plan_preserves_hash_evidence_and_prunes_transient_binaries(
        self,
    ) -> None:
        run = self.add_complete_validation_run()

        plan = compile_retention_plan(
            self.root,
            scope="machine-validation",
            trigger="machine-validation-complete",
            session_id="machine-validation-validation-full",
        )

        self.assertEqual(plan["scope"], "machine-validation")
        self.assertEqual(plan["summary"]["verified_validation_runs"], 1)
        self.assertEqual(plan["summary"]["validation_scratch_prunes"], 1)
        self.assertEqual(plan["summary"]["validation_composite_prunes"], 1)
        self.assertEqual(plan["summary"]["validation_composite_files"], 4)
        self.assertEqual(plan["summary"]["validation_source_directories"], 1)
        self.assertEqual(len(plan["actions"]), 2)
        scratch = next(
            action
            for action in plan["actions"]
            if action["kind"] == "prune-validation-scratch"
        )
        composites = next(
            action
            for action in plan["actions"]
            if action["kind"] == "prune-validation-composites"
        )
        self.assertEqual(scratch["run_id"], "validation-full")
        self.assertEqual(
            scratch["paths"], [str((run / "worker-1234").relative_to(self.root))]
        )
        self.assertEqual(len(composites["paths"]), 4)
        self.assertGreater(scratch["retained_evidence_files"], 0)

        write_retention_plan(plan, self.root)
        apply_retention_plan(self.root, plan["plan_digest"])

        self.assertFalse((run / "worker-1234").exists())
        self.assertTrue((run / "worker-01.log").is_file())
        self.assertTrue((run / "hash-report.json").is_file())
        self.assertTrue((run / "hash-evidence.sqlite3").is_file())
        self.assertTrue(
            (run / "units/001-route-baseline/fold-A/query-signatures.jsonl").is_file()
        )
        self.assertFalse((run / "units/001-route-baseline/fold-A/query.elf").exists())
        self.assertFalse((run / "units/001-route-baseline/fold-B/truth.elf").exists())

    def test_legacy_validation_composites_wait_for_relationship_backfill(self) -> None:
        run = self.add_complete_validation_run(
            "validation-legacy", relationship_evidence=False
        )

        plan = compile_retention_plan(self.root, scope="machine-validation")

        self.assertEqual(plan["summary"]["verified_validation_runs"], 1)
        self.assertEqual(plan["summary"]["validation_composite_prunes"], 0)
        self.assertIn(
            "backfill",
            next(
                row["reason"]
                for row in plan["preserved"]
                if row["kind"] == "validation-evidence"
            ),
        )
        write_retention_plan(plan, self.root)
        apply_retention_plan(self.root, plan["plan_digest"])
        self.assertTrue((run / "units/001-route-baseline/fold-A/query.elf").is_file())

    def test_sealed_relationship_backfill_releases_legacy_composites(self) -> None:
        run = self.add_complete_validation_run(
            "validation-backfilled", relationship_evidence=False
        )
        result_path = run / "units/001-route-baseline/result.json"
        result = json.loads(result_path.read_text(encoding="utf-8"))
        result["route_id"] = "route"
        result["treatment_id"] = "baseline"
        result_path.write_text(json.dumps(result), encoding="utf-8")
        for fold_result in result["folds"]:
            fold = run / "units/001-route-baseline" / f"fold-{fold_result['fold']}"
            evidence = fold / "query-fid-evidence.jsonl"
            evidence.write_text(
                json.dumps(
                    {
                        "full_hash": "aa",
                        "specific_hash": "bb",
                        "children": [],
                        "parents": [],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (fold / "relationship-evidence.json").write_text(
                json.dumps(
                    {
                        "schema_version": "fidb-query-relationship-evidence/v1",
                        "query_sha256": fold_result["query_sha256"],
                        "route_id": "route",
                        "treatment_id": "baseline",
                        "evidence": {
                            "schema_version": "fidb-program-signature-evidence/v1",
                            "path": str(evidence.relative_to(self.root)),
                            "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
                            "bytes": evidence.stat().st_size,
                        },
                    }
                ),
                encoding="utf-8",
            )

        plan = compile_retention_plan(self.root, scope="machine-validation")

        self.assertEqual(plan["summary"]["validation_composite_files"], 4)
        write_retention_plan(plan, self.root)
        apply_retention_plan(self.root, plan["plan_digest"])
        self.assertFalse((run / "units/001-route-baseline/fold-A/query.elf").exists())
        self.assertTrue(
            (run / "units/001-route-baseline/fold-A/query-fid-evidence.jsonl").is_file()
        )

    def test_incomplete_validation_run_is_quarantined_without_action(self) -> None:
        run = self.add_complete_validation_run("validation-failed")
        status = json.loads((run / "status.json").read_text(encoding="utf-8"))
        status["state"] = "failed"
        (run / "status.json").write_text(json.dumps(status), encoding="utf-8")

        plan = compile_retention_plan(self.root, scope="machine-validation")

        self.assertEqual(plan["summary"]["verified_validation_runs"], 0)
        self.assertEqual(plan["summary"]["validation_scratch_prunes"], 0)
        self.assertEqual(plan["quarantined"][0]["kind"], "validation-run")
        self.assertTrue((run / "worker-1234/disposable.bin").is_file())

    def test_machine_validation_automatic_retention_is_scoped(self) -> None:
        run = self.add_complete_validation_run("validation-auto")
        result = automatic_retention(
            self.root,
            trigger="machine-validation-complete",
            session_id="machine-validation-validation-auto",
        )

        self.assertEqual(result["state"], "complete")
        self.assertEqual(result["scope"], "machine-validation")
        self.assertEqual(result["trigger"], "machine-validation-complete")
        self.assertFalse((run / "worker-1234").exists())


if __name__ == "__main__":
    unittest.main()
