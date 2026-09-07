import tempfile
import unittest
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch
from zoneinfo import ZoneInfo

from fidb_poc.fid_matching_campaign import (
    _acquire_campaign_lock,
    _archive_prior_case_failure,
    _balanced_case_chunks,
    _cleanup_campaign_scratch,
    _expected_cases,
    _publish_hash_evidence,
    _reusable_case,
    _resource_preflight,
    _release_campaign_lock,
    _source_harness_preflight,
    _terminal_campaign_report,
    _window_open,
    campaign_status,
    load_campaign,
    run_campaign,
)
from fidb_poc.fid_match_qualification import (
    _linker_truth_intervals,
    _load_retained_oracle_replay,
    _portable_executions,
    _retained_query_analysis_policy,
    _symbol_address_bias,
)
from fidb_poc.validation_analysis import (
    QUERY_ANALYSIS_POLICY,
    QUERY_ANALYSIS_RECOVERY_POLICY,
)


class FidMatchingCampaignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.campaign = load_campaign(cls.root)

    def test_campaign_freezes_all_c10_function_owner_cases(self):
        self.assertEqual(len(_expected_cases(self.campaign, "canary")), 4)
        self.assertEqual(len(_expected_cases(self.campaign, "full")), 444)
        self.assertFalse(self.campaign["execution"]["compare_cpu_and_gpu"])
        self.assertEqual(self.campaign["canary"]["workers"], 1)
        self.assertEqual(
            self.campaign["methodology"]["retain_backend_outputs"], "canary-only"
        )
        self.assertEqual(
            self.campaign["execution"]["scheduling"],
            "largest-query-first-greedy-v1",
        )
        self.assertTrue(self.campaign["safety"]["require_no_active_production_jobs"])
        self.assertFalse(self.campaign["safety"]["execute_target_binaries"])

    def test_largest_first_scheduler_balances_periodic_expensive_cases(self):
        weighted = [
            (f"{position}:A", 100 if position % 2 == 0 else 10)
            for position in range(1, 13)
        ]
        chunks, loads = _balanced_case_chunks(weighted, 4)

        self.assertEqual(sum(len(chunk) for chunk in chunks), len(weighted))
        self.assertEqual(max(loads), 200)
        self.assertEqual(min(loads), 130)
        for chunk in chunks:
            weights = [dict(weighted)[case] for case in chunk]
            self.assertEqual(weights, sorted(weights, reverse=True))

    def test_campaign_cleanup_removes_only_known_scratch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = {**self.campaign, "output_root": "runs"}
            campaign_root = root / "runs" / str(campaign["id"])
            scratch = [
                campaign_root / "compact-index-ghidra-user" / "cache.bin",
                campaign_root / "worker-scratch" / "worker-1" / "cache.bin",
                campaign_root / "cases" / "case-1" / "work" / "project.bin",
            ]
            for path in scratch:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"scratch")
            evidence = campaign_root / "cases" / "case-1" / "summary.json"
            evidence.write_text("{}", encoding="utf-8")

            report = _cleanup_campaign_scratch(root, campaign)

            self.assertEqual(report["recoverable_bytes"], 21)
            self.assertTrue(evidence.is_file())
            self.assertTrue(all(not path.exists() for path in scratch))

    def test_completed_case_reuse_is_bound_to_matching_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = {**self.campaign, "output_root": "out"}
            path = (
                root
                / "out"
                / campaign["id"]
                / "cases"
                / f"{campaign['source_run_id']}-001-A"
                / "summary.json"
            )
            path.parent.mkdir(parents=True)
            path.write_text(
                json.dumps(
                    {
                        "state": "qualified",
                        "authority_sha256": "old-method",
                        "selected_backend": "gpu-portable-fid-v1",
                        "case": {
                            "run_id": campaign["source_run_id"],
                            "position": 1,
                            "fold": "A",
                            "link_harness_policy": campaign["methodology"][
                                "required_link_harness"
                            ],
                        },
                    }
                ),
                encoding="utf-8",
            )

            self.assertFalse(
                _reusable_case(
                    root, campaign, 1, "A", "new-method", "gpu-portable-fid-v1"
                )
            )
            self.assertTrue(
                _reusable_case(
                    root, campaign, 1, "A", "old-method", "gpu-portable-fid-v1"
                )
            )
            self.assertFalse(
                _reusable_case(
                    root, campaign, 1, "A", "old-method", "cpu-portable-fid-v1"
                )
            )

    def test_oracle_replay_is_bound_to_exact_query_and_fidb_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "case"
            destination.mkdir()
            query = root / "query.elf"
            fidb = root / "library.fidb"
            query.write_bytes(b"query")
            fidb.write_bytes(b"fidb")
            oracle_path = destination / "oracle-input.json"
            oracle = {
                "schema_version": "fidb-portable-fid-input/v1",
                "oracle": "ghidra-fid-program-seeker",
                "language_id": "x86:LE:64:default",
                "compiler_spec_id": "gcc",
                # Ghidra serializes the Java float while TOML retains the
                # shorter decimal spelling of the same policy value.
                "score_threshold": 14.600000381469727,
                "medium_code_unit_limit": 24,
                "functions": [],
            }
            oracle_path.write_text(json.dumps(oracle), encoding="utf-8")

            def digest(path):
                return hashlib.sha256(path.read_bytes()).hexdigest()

            (destination / "summary.json").write_text(
                json.dumps(
                    {
                        "state": "qualified",
                        "case": {
                            "run_id": "source-run",
                            "position": 7,
                            "fold": "B",
                            "route_id": "linux-x86-64-gcc",
                            "treatment_id": "baseline_o2",
                            "query_sha256": digest(query),
                            "fidb_sha256": [digest(fidb)],
                            "link_harness_policy": "harness-v2",
                        },
                        "oracle": {
                            "implementation": "ghidra-fid-program-seeker",
                            "input_path": "case/oracle-input.json",
                            "input_sha256": digest(oracle_path),
                        },
                    }
                ),
                encoding="utf-8",
            )
            authority = {
                "oracle": {"implementation": "ghidra-fid-program-seeker"},
                "semantics": {
                    "score_threshold": 14.6,
                    "medium_code_unit_limit": 24,
                },
            }
            loaded = _load_retained_oracle_replay(
                root,
                destination,
                run_id="source-run",
                position=7,
                fold="B",
                route_id="linux-x86-64-gcc",
                treatment_id="baseline_o2",
                query_binary=query,
                fidbs=[fidb],
                language_id="x86:LE:64:default",
                compiler_spec_id="gcc",
                authority=authority,
                link_harness_policy="harness-v2",
            )
            self.assertEqual(loaded, oracle)

            query.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "does not match"):
                _load_retained_oracle_replay(
                    root,
                    destination,
                    run_id="source-run",
                    position=7,
                    fold="B",
                    route_id="linux-x86-64-gcc",
                    treatment_id="baseline_o2",
                    query_binary=query,
                    fidbs=[fidb],
                    language_id="x86:LE:64:default",
                    compiler_spec_id="gcc",
                    authority=authority,
                    link_harness_policy="harness-v2",
                )

    def test_campaign_lock_recovers_automatically_after_owner_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / ".campaign.lock"
            first = _acquire_campaign_lock(path)
            try:
                with self.assertRaisesRegex(ValueError, "another FID matching"):
                    _acquire_campaign_lock(path)
            finally:
                _release_campaign_lock(first)

            second = _acquire_campaign_lock(path)
            _release_campaign_lock(second)
            owner = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(owner["pid"], os.getpid())

    def test_terminal_campaign_report_is_reused_only_under_exact_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = {
                **self.campaign,
                "output_root": "out",
                "authority_sha256": "campaign-digest",
            }
            destination = root / "out" / campaign["id"]
            destination.mkdir(parents=True)
            report_path = destination / "canary-report.json"
            report = {
                "schema_version": "fidb-fid-matching-campaign-report/v1",
                "campaign_id": campaign["id"],
                "mode": "canary",
                "state": "qualified",
                "authority_sha256": "campaign-digest",
                "source_run_id": campaign["source_run_id"],
                "method_authority": {"sha256": "method-digest"},
                "progress": {
                    "expected_cases": 4,
                    "complete_cases": 4,
                    "failed_or_pending_cases": 0,
                },
                "wall_time_seconds": 129.0,
            }
            report_path.write_text(json.dumps(report), encoding="utf-8")
            with patch(
                "fidb_poc.fid_matching_campaign.load_matching_authority",
                return_value={"authority_sha256": "method-digest"},
            ):
                self.assertEqual(
                    _terminal_campaign_report(root, campaign, "canary"), report
                )
                report["authority_sha256"] = "stale-campaign"
                report_path.write_text(json.dumps(report), encoding="utf-8")
                self.assertIsNone(_terminal_campaign_report(root, campaign, "canary"))

    def test_all_reused_campaign_does_not_republish_terminal_report(self):
        terminal = {"state": "qualified", "wall_time_seconds": 129.0}
        scheduling = {
            "policy": "largest-query-first-greedy-v1",
            "pending_cases": 0,
            "reused_cases": 4,
            "estimated_function_loads": [],
        }
        with (
            patch(
                "fidb_poc.fid_matching_campaign.load_campaign",
                return_value=self.campaign,
            ),
            patch(
                "fidb_poc.fid_matching_campaign._source_harness_preflight",
                return_value={"blockers": []},
            ),
            patch(
                "fidb_poc.fid_matching_campaign._production_active",
                return_value=False,
            ),
            patch(
                "fidb_poc.fid_matching_campaign._resource_preflight",
                return_value={"blockers": []},
            ),
            patch(
                "fidb_poc.fid_matching_campaign._acquire_campaign_lock",
                return_value=42,
            ),
            patch(
                "fidb_poc.fid_matching_campaign._scheduled_case_chunks",
                return_value=([], scheduling),
            ),
            patch(
                "fidb_poc.fid_matching_campaign._terminal_campaign_report",
                return_value=terminal,
            ),
            patch("fidb_poc.fid_matching_campaign._release_campaign_lock") as release,
            patch("fidb_poc.fid_matching_campaign._atomic_json") as write,
        ):
            result = run_campaign(self.root, "canary")

        self.assertEqual(result, terminal)
        release.assert_called_once_with(42)
        write.assert_not_called()

    def test_retry_archives_prior_case_failure_as_ordered_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            summary = Path(temporary) / "case" / "summary.json"
            summary.parent.mkdir()
            failure = summary.with_name("failure.json")
            failure.write_text(json.dumps({"error": "first"}), encoding="utf-8")

            first = _archive_prior_case_failure(summary)
            self.assertFalse(failure.exists())
            self.assertEqual(
                json.loads(Path(first).read_text(encoding="utf-8"))["error"], "first"
            )
            failure.write_text(json.dumps({"error": "second"}), encoding="utf-8")
            second = _archive_prior_case_failure(summary)

            self.assertTrue(first.endswith("attempt-001-failure.json"))
            self.assertTrue(second.endswith("attempt-002-failure.json"))
            self.assertEqual(
                json.loads(Path(second).read_text(encoding="utf-8"))["error"], "second"
            )

        with tempfile.TemporaryDirectory() as temporary, patch(
            "fidb_poc.fid_matching_campaign._campaign_root",
            return_value=Path(temporary),
        ):
            status = campaign_status(self.root)
        self.assertEqual(status["canary"]["state"], "pending")
        self.assertEqual(
            [stage["id"] for stage in status["canary"]["pipeline_job"]["stages"]],
            [
                "compact-candidate-index",
                "query-relationship-evidence",
                "native-oracle-replay",
                "portable-gpu",
                "owner-classification",
                "hash-population",
            ],
        )

    def test_routine_campaign_executes_only_the_selected_backend(self):
        authority = {
            "selected": "cpu-portable-fid-v1",
            "backend": [
                {"id": "cpu-portable-fid-v1"},
                {"id": "gpu-portable-fid-v1"},
            ],
            "backends": {
                "cpu-portable-fid-v1": {"device": "cpu"},
                "gpu-portable-fid-v1": {"device": "gpu"},
            },
        }
        selected = {"backend": "cpu-portable-fid-v1"}
        with (
            patch(
                "fidb_poc.fid_match_qualification.match_cpu",
                return_value=selected,
            ) as cpu,
            patch("fidb_poc.fid_match_qualification.match_gpu") as gpu,
        ):
            executions = _portable_executions({}, authority, compare_backends=False)

        self.assertEqual(executions, [selected])
        cpu.assert_called_once()
        gpu.assert_not_called()

    def test_matcher_reuses_the_retained_query_analysis_policy(self):
        superh = Mock(ghidra_language="SuperH4:BE:32:default")
        x86 = Mock(ghidra_language="x86:LE:64:default")

        self.assertEqual(
            _retained_query_analysis_policy({}, superh), QUERY_ANALYSIS_POLICY
        )
        self.assertEqual(
            _retained_query_analysis_policy(
                {"query_analysis_policy": QUERY_ANALYSIS_RECOVERY_POLICY}, superh
            ),
            QUERY_ANALYSIS_RECOVERY_POLICY,
        )
        with self.assertRaisesRegex(ValueError, "cannot be applied"):
            _retained_query_analysis_policy(
                {"query_analysis_policy": QUERY_ANALYSIS_RECOVERY_POLICY}, x86
            )
        with self.assertRaisesRegex(ValueError, "unsupported"):
            _retained_query_analysis_policy(
                {"query_analysis_policy": "unreviewed"}, superh
            )

    def test_schedule_opens_only_in_the_reviewed_window(self):
        timezone = ZoneInfo("Europe/Luxembourg")
        self.assertEqual(
            _window_open(self.campaign, datetime(2026, 9, 7, 1, 0, tzinfo=timezone)),
            (True, "normal-overnight"),
        )
        self.assertEqual(
            _window_open(self.campaign, datetime(2026, 9, 7, 8, 0, tzinfo=timezone)),
            (False, None),
        )

    def test_resource_preflight_enforces_runtime_toml_floors(self):
        with (
            patch(
                "fidb_poc.machine_validation_runner.load_runtime",
                return_value={
                    "ghidra_headless": "/missing-ghidra",
                    "safety": {
                        "minimum_available_memory_gib": 24,
                        "minimum_free_disk_gib": 100,
                    },
                },
            ),
            patch(
                "fidb_poc.machine_validation_runner._available_memory_bytes",
                return_value=20 * 1024**3,
            ),
            patch("fidb_poc.fid_matching_campaign.shutil.disk_usage") as disk_usage,
        ):
            disk_usage.return_value.free = 90 * 1024**3

            result = _resource_preflight(self.root, self.campaign)

        self.assertEqual(result["state"], "blocked")
        self.assertEqual(len(result["blockers"]), 3)

    def test_source_preflight_rejects_stale_and_accepts_audited_harness(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result_path = root / "runs/source/units/001-route/result.json"
            result_path.parent.mkdir(parents=True)
            campaign = {
                **self.campaign,
                "source_run_id": "source",
                "runtime": "runtime.toml",
                "canary": {**self.campaign["canary"], "cases": ["1:B"]},
            }
            with patch(
                "fidb_poc.machine_validation_runner.load_runtime",
                return_value={"output_root": "runs"},
            ):
                result_path.write_text(
                    json.dumps({"folds": [{"fold": "B"}]}), encoding="utf-8"
                )
                stale = _source_harness_preflight(root, campaign, "canary")
                result_path.write_text(
                    json.dumps(
                        {
                            "folds": [
                                {
                                    "fold": "B",
                                    "link_harness_policy": campaign["methodology"][
                                        "required_link_harness"
                                    ],
                                    "link_audit": {"direct_zero_control_flow_count": 0},
                                }
                            ]
                        }
                    ),
                    encoding="utf-8",
                )
                ready = _source_harness_preflight(root, campaign, "canary")

            self.assertEqual(stale["state"], "blocked")
            self.assertEqual(ready["state"], "ready")

    def test_status_exposes_qualification_and_pending_cases(self):
        with tempfile.TemporaryDirectory() as temporary, patch(
            "fidb_poc.fid_matching_campaign._campaign_root",
            return_value=Path(temporary),
        ):
            status = campaign_status(self.root)
        self.assertEqual(status["qualification"]["state"], "stale")
        self.assertEqual(status["canary"]["state"], "pending")
        self.assertEqual(status["canary"]["failures"], [])
        self.assertIsNone(status["canary"]["oracle"]["canary_passed"])
        self.assertEqual(status["canary"]["progress"]["expected_cases"], 4)
        self.assertEqual(status["canary"]["progress"]["pending_cases"], 4)
        self.assertEqual(status["full"]["progress"]["expected_cases"], 444)

    def test_status_rejects_a_stale_saved_canary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = {
                **self.campaign,
                "output_root": "out",
                "qualification_evidence": "qualification.json",
                "authority_path": "campaign.toml",
                "authority_sha256": "new-campaign",
            }
            (root / "qualification.json").write_text(
                json.dumps({"state": "absent"}), encoding="utf-8"
            )
            campaign_root = root / "out" / campaign["id"]
            campaign_root.mkdir(parents=True)
            (campaign_root / "canary-report.json").write_text(
                json.dumps(
                    {
                        "state": "qualified",
                        "authority_sha256": "old-campaign",
                        "method_authority": {"sha256": "old-method"},
                    }
                ),
                encoding="utf-8",
            )

            with (
                patch(
                    "fidb_poc.fid_matching_campaign.load_campaign",
                    return_value=campaign,
                ),
                patch(
                    "fidb_poc.fid_matching_campaign.load_matching_authority",
                    return_value={
                        "authority_path": "matching.toml",
                        "authority_sha256": "new-method",
                        "selected": "cpu-portable-fid-v1",
                        "backend": [
                            {"id": "cpu-portable-fid-v1", "device": "cpu"},
                            {"id": "gpu-portable-fid-v1", "device": "gpu"},
                        ],
                        "backends": {
                            "cpu-portable-fid-v1": {"device": "cpu"},
                            "gpu-portable-fid-v1": {"device": "gpu"},
                        },
                    },
                ),
                patch(
                    "fidb_poc.fid_matching_campaign.load_fid_matching_performance",
                    return_value={
                        "mode": "cpu",
                        "allow_gpu": True,
                        "authority_path": "performance.toml",
                        "authority_sha256": "performance-digest",
                    },
                ),
            ):
                status = campaign_status(root, "campaign.toml")

            self.assertEqual(status["canary"]["state"], "stale-authority")

    def test_linker_map_resolves_archive_sections_to_owners(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "libsample.a"
            archive.touch()
            link_map = root / "link.map"
            link_map.write_text(
                f" .text 0x00001000 0x20 {archive}(one.o)\n",
                encoding="utf-8",
            )
            truth = {"archives": [{"owner": "sample@1", "paths": ["libsample.a"]}]}
            self.assertEqual(
                _linker_truth_intervals(root, truth, link_map),
                [(0x1000, 0x1020, "sample@1")],
            )

    def test_symbol_address_bias_normalizes_shared_image_imports(self):
        functions = [
            {"address": "00101200", "function_name": "one"},
            {"address": "00101300", "function_name": "two"},
        ]
        symbols = "00001200 20 T one\n00001300 30 T two\n"
        with (
            patch("fidb_poc.fid_match_qualification.shutil.which", return_value="nm"),
            patch(
                "fidb_poc.fid_match_qualification.subprocess.run",
                return_value=Mock(returncode=0, stdout=symbols, stderr=""),
            ),
        ):
            bias = _symbol_address_bias(Path("query.so"), functions)

        self.assertEqual(bias["bytes"], 0x100000)
        self.assertEqual(bias["supporting_symbols"], 2)

    def test_postprocess_compacts_hash_observations_by_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = {
                **self.campaign,
                "source_run_id": "source",
                "output_root": "out",
            }
            for position, fold in _expected_cases(campaign, "canary"):
                case = f"source-{position:03d}-{fold}"
                destination = root / "out" / campaign["id"] / "cases" / case
                destination.mkdir(parents=True)
                classification_path = destination / "classification.json"
                classification_path.write_text(
                    json.dumps(
                        {
                            "observations": [
                                {
                                    "hash_type": hash_type,
                                    "value": "aa",
                                    "candidate_owner": "sample@1",
                                    "outcome": "fp" if fold == "A" else "tp",
                                    "category": (
                                        "ambiguous-attribution"
                                        if fold == "A"
                                        else "correct-attribution"
                                    ),
                                }
                                for hash_type in ("full", "specific", "complete")
                            ]
                        }
                    ),
                    encoding="utf-8",
                )
                (destination / "summary.json").write_text(
                    json.dumps(
                        {
                            "classification_path": str(
                                classification_path.relative_to(root)
                            ),
                            "case": {
                                "target_os": "linux",
                                "binary_format": "ELF",
                                "ghidra_language_id": "x86:LE:64:default",
                                "ghidra_compiler_spec_id": "gcc",
                            },
                        }
                    ),
                    encoding="utf-8",
                )
            report = {}

            _publish_hash_evidence(root, campaign, "canary", report)

            self.assertEqual(report["hash_evidence"]["noisy_signatures"], 1)
            self.assertEqual(len(report["hash_type_analysis"]), 3)
            self.assertTrue((root / report["hash_evidence"]["database_path"]).is_file())


if __name__ == "__main__":
    unittest.main()
