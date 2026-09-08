import tempfile
import unittest
from pathlib import Path

from fidb_poc.campaign_registry import (
    active_campaign,
    campaign_registry_status,
    load_campaign_registry,
    resolve_campaign_paths,
    select_campaign,
)
from fidb_poc.coordinator import Coordinator

QUEUE = """\
schema_version = "fidb-queue/v1"
name = "{name}"

[queue]
armed = {armed}
max_workers = 1
batch_order = ["batch-001"]
poll_seconds = 5
lease_seconds = 3600
max_attempts = 1

[schedule]
enabled = false
timezone = "Europe/Luxembourg"
days = ["mon"]
start = "00:00"
stop_claiming = "05:30"
finish_started_batch = true

[resources]
min_available_memory_gib = 1
min_free_disk_gib = 1
max_load_per_cpu = 1.0
max_temperature_c = 90

[notifications]
events = ["job-failed"]
outbox = "var/notifications.jsonl"
timeout_seconds = 1

[[batch]]
id = "batch-001"
name = "test batch"
plan = "plans/plan.toml"
"""


REGISTRY = """\
schema_version = "fidb-campaign-registry/v1"
default_campaign = "alpha"
selection_state = "var/campaigns/active.toml"

[[campaign]]
id = "alpha"
label = "Alpha campaign"
family_id = "family"
slice_id = "nonapple"
host = "linux-x86_64"
state = "configured"
phase = "ready"
queue = "plans/alpha.toml"
ledger = "var/campaigns/alpha.sqlite3"
programme = "campaigns/programme.toml"
priority_authority = "coverage/priority.toml"

[[campaign]]
id = "beta"
label = "Beta campaign"
family_id = "family"
slice_id = "apple"
host = "macos-arm64"
state = "configured"
phase = "ready"
queue = "plans/beta.toml"
ledger = "var/campaigns/beta.sqlite3"

[[campaign]]
id = "future"
label = "Future campaign"
family_id = "future"
slice_id = "apple"
host = "macos-arm64"
state = "planned"
phase = "not materialized"
ledger = "var/campaigns/future.sqlite3"
"""


class CampaignRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for directory in ("campaigns", "coverage", "operations", "plans", "var"):
            (self.root / directory).mkdir()
        (self.root / "plans/plan.toml").write_text("placeholder = true\n")
        (self.root / "plans/alpha.toml").write_text(
            QUEUE.format(name="alpha", armed="false")
        )
        (self.root / "plans/beta.toml").write_text(
            QUEUE.format(name="beta", armed="false")
        )
        (self.root / "campaigns/programme.toml").write_text('schema_version = "test"\n')
        (self.root / "coverage/priority.toml").write_text("""\
schema_version = "fidb-priority-overlay/v1"
id = "priority"
label = "Priority"
language_id = "c"
selection_basis = "test"
component_policy = "test"

[[subject]]
order = 1
id = "zlib"
source_family = "zlib"
aliases = ["libz"]
""")
        (self.root / "operations/campaigns.toml").write_text(REGISTRY)

    def tearDown(self):
        self.temporary.cleanup()

    def test_registry_uses_default_without_mutable_selection(self):
        registry = load_campaign_registry(self.root)
        active, source = active_campaign(registry)
        state, queue, binding = resolve_campaign_paths(self.root)

        self.assertEqual(active.id, "alpha")
        self.assertEqual(source, "registry-default")
        self.assertEqual(binding.id, "alpha")
        self.assertEqual(state, self.root / "var/campaigns/alpha.sqlite3")
        self.assertEqual(queue, self.root / "plans/alpha.toml")
        self.assertFalse(registry.selection_path.exists())

    def test_switch_is_durable_and_planned_campaign_is_visible_but_unselectable(self):
        result = select_campaign(self.root, "beta", actor="test")

        self.assertEqual(result["active_campaign_id"], "beta")
        self.assertEqual(result["selection_source"], "local-selection")
        self.assertTrue((self.root / "var/campaigns/active.toml").is_file())
        future = next(row for row in result["campaigns"] if row["id"] == "future")
        self.assertFalse(future["selectable"])
        self.assertIn("queue not materialized", future["blockers"])
        with self.assertRaisesRegex(ValueError, "not selectable"):
            select_campaign(self.root, "future", actor="test")

    def test_switch_refuses_armed_current_ledger(self):
        state = self.root / "var/campaigns/alpha.sqlite3"
        with Coordinator(state, self.root) as coordinator:
            coordinator.connection.execute(
                "UPDATE coordinator_state SET armed = 1 WHERE singleton = 1"
            )

        with self.assertRaisesRegex(ValueError, "ledger must be disarmed"):
            select_campaign(self.root, "beta", actor="test")

    def test_switch_refuses_armed_target_authority(self):
        (self.root / "plans/beta.toml").write_text(
            QUEUE.format(name="beta", armed="true")
        )

        with self.assertRaisesRegex(
            ValueError, "target campaign queue must be disarmed"
        ):
            select_campaign(self.root, "beta", actor="test")

    def test_project_registry_exposes_current_and_apple_slices(self):
        project = Path(__file__).resolve().parents[1]
        status = campaign_registry_status(project)

        self.assertEqual(status["active_campaign_id"], "c80-malware-priority-nonapple")
        by_id = {row["id"]: row for row in status["campaigns"]}
        self.assertTrue(by_id["c80-malware-priority-nonapple"]["selectable"])
        self.assertEqual(
            by_id["c80-malware-priority-nonapple"]["priority_subjects"], 25
        )
        self.assertFalse(by_id["c80-malware-priority-apple"]["selectable"])
        self.assertEqual(by_id["c80-malware-priority-apple"]["slice_id"], "apple")


if __name__ == "__main__":
    unittest.main()
