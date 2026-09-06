import tempfile
import unittest
import json
from datetime import datetime
from pathlib import Path
from unittest.mock import patch
from zoneinfo import ZoneInfo

from fidb_poc.fid_matching_campaign import (
    _expected_cases,
    _publish_hash_evidence,
    _resource_preflight,
    _window_open,
    campaign_status,
    load_campaign,
)
from fidb_poc.fid_match_qualification import _linker_truth_intervals


class FidMatchingCampaignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.campaign = load_campaign(cls.root)

    def test_campaign_freezes_all_c10_function_owner_cases(self):
        self.assertEqual(len(_expected_cases(self.campaign, "canary")), 4)
        self.assertEqual(len(_expected_cases(self.campaign, "full")), 444)
        self.assertTrue(self.campaign["safety"]["require_no_active_production_jobs"])
        self.assertFalse(self.campaign["safety"]["execute_target_binaries"])

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

    def test_status_exposes_qualification_and_pending_cases(self):
        status = campaign_status(self.root)
        self.assertEqual(status["qualification"]["state"], "qualified")
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
