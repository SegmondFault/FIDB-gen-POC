import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from fidb_poc.fid_matching_campaign import (
    _expected_cases,
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
            _window_open(
                self.campaign, datetime(2026, 9, 7, 1, 0, tzinfo=timezone)
            ),
            (True, "normal-overnight"),
        )
        self.assertEqual(
            _window_open(
                self.campaign, datetime(2026, 9, 7, 8, 0, tzinfo=timezone)
            ),
            (False, None),
        )

    def test_status_exposes_qualification_and_pending_cases(self):
        status = campaign_status(self.root)
        self.assertEqual(status["qualification"]["state"], "qualified")
        self.assertEqual(status["canary"]["progress"]["expected_cases"], 4)
        self.assertEqual(status["full"]["progress"]["expected_cases"], 444)

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
            truth = {
                "archives": [{"owner": "sample@1", "paths": ["libsample.a"]}]
            }
            self.assertEqual(
                _linker_truth_intervals(root, truth, link_map),
                [(0x1000, 0x1020, "sample@1")],
            )


if __name__ == "__main__":
    unittest.main()
