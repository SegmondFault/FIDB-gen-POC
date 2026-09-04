import json
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock
from zoneinfo import ZoneInfo

from fidb_poc.operations_policy import (
    NotificationPolicy,
    ResourcePolicy,
    SchedulePolicy,
    emit_notification,
    evaluate_resources,
    load_operations_policy,
)


class OperationsPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_overnight_window_stops_claims_then_reaches_hard_cutoff(self):
        policy = SchedulePolicy(
            enabled=True,
            timezone_name="Europe/Luxembourg",
            days=("mon",),
            start=datetime.strptime("22:00", "%H:%M").time(),
            stop_claiming=datetime.strptime("05:45", "%H:%M").time(),
            hard_cutoff=datetime.strptime("06:15", "%H:%M").time(),
        )
        zone = ZoneInfo("Europe/Luxembourg")

        open_state = policy.evaluate(datetime(2026, 8, 31, 23, 0, tzinfo=zone))
        draining = policy.evaluate(datetime(2026, 9, 1, 6, 0, tzinfo=zone))
        closed = policy.evaluate(datetime(2026, 9, 1, 6, 15, tzinfo=zone))

        self.assertTrue(open_state.claims_allowed)
        self.assertEqual(open_state.reason, "inside-claim-window")
        self.assertFalse(draining.claims_allowed)
        self.assertEqual(draining.reason, "claim-window-closed")
        self.assertEqual(draining.hard_cutoff_at, "2026-09-01T06:15:00+02:00")
        self.assertFalse(closed.claims_allowed)
        self.assertEqual(closed.reason, "outside-schedule-window")
        self.assertEqual(closed.next_window_at, "2026-09-07T22:00:00+02:00")

    def test_finish_started_batch_uses_admission_window_without_a_cutoff(self):
        policy = load_operations_policy(
            {
                "schedule": {
                    "enabled": True,
                    "timezone": "Europe/Luxembourg",
                    "days": ["wed"],
                    "start": "01:00",
                    "stop_claiming": "05:30",
                    "finish_started_batch": True,
                    "chain_batches": True,
                }
            },
            self.root,
        ).schedule
        zone = ZoneInfo("Europe/Luxembourg")

        open_state = policy.evaluate(datetime(2026, 9, 2, 4, 0, tzinfo=zone))
        closed = policy.evaluate(datetime(2026, 9, 2, 5, 30, tzinfo=zone))

        self.assertTrue(open_state.claims_allowed)
        self.assertIsNone(open_state.hard_cutoff_at)
        self.assertFalse(closed.claims_allowed)
        self.assertTrue(policy.finish_started_batch)
        self.assertTrue(policy.chain_batches)
        self.assertEqual(policy.document()["start"], "01:00")
        self.assertEqual(policy.document()["stop_claiming"], "05:30")
        self.assertIsNone(policy.document()["hard_cutoff"])

    def test_date_override_extends_only_the_named_claim_window(self):
        policy = load_operations_policy(
            {
                "schedule": {
                    "enabled": True,
                    "timezone": "Europe/Luxembourg",
                    "days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
                    "start": "00:00",
                    "stop_claiming": "05:30",
                    "finish_started_batch": True,
                    "chain_batches": True,
                    "date_overrides": [
                        {
                            "date": "2026-09-04",
                            "stop_claiming": "18:00",
                        }
                    ],
                }
            },
            self.root,
        ).schedule
        zone = ZoneInfo("Europe/Luxembourg")

        extended = policy.evaluate(datetime(2026, 9, 4, 12, 0, tzinfo=zone))
        expired = policy.evaluate(datetime(2026, 9, 5, 12, 0, tzinfo=zone))

        self.assertTrue(extended.claims_allowed)
        self.assertEqual(extended.stop_claiming_at, "2026-09-04T18:00:00+02:00")
        self.assertFalse(expired.claims_allowed)
        self.assertEqual(expired.next_window_at, "2026-09-06T00:00:00+02:00")
        self.assertEqual(
            policy.document()["date_overrides"][0]["date"], "2026-09-04"
        )

    def test_schedule_and_policy_validation_fail_closed(self):
        cases = (
            (
                {"schedule": {"enabled": True, "timezone": "not/a-zone"}},
                "unknown schedule timezone",
            ),
            (
                {"schedule": {"days": ["mon", "mon"]}},
                "schedule days",
            ),
            (
                {
                    "schedule": {
                        "enabled": True,
                        "start": "22:00",
                        "stop_claiming": "06:15",
                        "hard_cutoff": "05:45",
                    }
                },
                "must not be after",
            ),
            (
                {"schedule": {"chain_batches": True}},
                "requires finish_started_batch",
            ),
            (
                {"notifications": {"webhook_url_env": "lowercase"}},
                "uppercase environment variable",
            ),
        )
        for document, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    load_operations_policy(document, self.root)

    def test_resource_gates_report_each_unmet_threshold(self):
        policy = ResourcePolicy(
            min_available_memory_gib=12,
            min_free_disk_gib=200,
            max_load_per_cpu=1,
            max_temperature_c=90,
        )
        state = evaluate_resources(
            policy,
            self.root,
            memory_bytes=8 * 1024**3,
            free_disk_bytes=100 * 1024**3,
            load_1m=40,
            logical_cpus=32,
            temperature_c=95,
        )

        self.assertFalse(state.passed)
        self.assertEqual(
            state.reasons,
            (
                "available-memory-below-minimum",
                "free-disk-below-minimum",
                "load-per-cpu-above-maximum",
                "temperature-above-maximum",
            ),
        )
        self.assertEqual(state.metrics["load_per_cpu"], 1.25)

    def test_temperature_gate_fails_closed_when_sensor_is_unavailable(self):
        with mock.patch("fidb_poc.operations_policy._temperature_c", return_value=None):
            state = evaluate_resources(
                ResourcePolicy(max_temperature_c=90),
                self.root,
                memory_bytes=1,
                free_disk_bytes=1,
                load_1m=0,
                logical_cpus=1,
            )
        self.assertFalse(state.passed)
        self.assertIn("temperature-unavailable", state.reasons)

    def test_notification_outbox_is_durable_and_webhook_failure_is_nonfatal(self):
        outbox = self.root / "var/notifications.jsonl"
        policy = NotificationPolicy(
            events=("job-failed",),
            outbox=outbox,
            webhook_url_env="TEST_WEBHOOK_URL",
        )
        with mock.patch.dict(os.environ, {"TEST_WEBHOOK_URL": "http://unsafe"}):
            delivery = emit_notification(
                policy,
                "job-failed",
                {"job_id": "job-1", "reason": "test"},
                now=datetime.fromisoformat("2026-08-31T22:00:00+00:00"),
            )

        self.assertIn("webhook_error", delivery)
        document = json.loads(outbox.read_text(encoding="utf-8"))
        self.assertEqual(document["schema_version"], "fidb-notification/v1")
        self.assertEqual(document["event"], "job-failed")
        self.assertEqual(document["payload"]["job_id"], "job-1")
        self.assertEqual(outbox.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
