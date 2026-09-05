import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from fidb_poc.machine_validation import (
    compile_machine_validation,
    compile_validation_batch,
    load_machine_validation,
)


class MachineValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]

    def test_frozen_split_is_reproducible_and_width_is_live(self):
        authority = load_machine_validation(self.root)
        status = compile_machine_validation(self.root, evidence_override={})

        self.assertEqual(status["state"], "waiting-for-cohort")
        self.assertEqual(status["summary"]["complete_libraries"], 0)
        self.assertEqual(status["summary"]["exact_identities"], 222)
        self.assertEqual(status["summary"]["width_delta_from_baseline"], 0)
        self.assertEqual(status["summary"]["required_exact_inputs"], 2_220)
        self.assertEqual(status["summary"]["composite_programs"], 444)
        self.assertEqual(status["summary"]["query_projections"], 1_332)
        self.assertEqual(
            set(authority["randomization"]["fold_a"]).intersection(
                authority["randomization"]["fold_b"]
            ),
            set(),
        )
        self.assertFalse(status["readiness"]["eligible"])
        self.assertIn(
            status["results"]["state"],
            {"not-run", "invalid-report", "measured-complete"},
        )
        self.assertEqual(
            status["results"]["confusion_matrix"]["unit"],
            "complete-fid-signature-owner-assertion",
        )
        self.assertIsNone(status["results"]["confusion_matrix"]["true_positives"])

    def test_incomplete_cohort_cannot_materialize(self):
        with self.assertRaisesRegex(ValueError, "not eligible"):
            compile_validation_batch(self.root, evidence_override={})

    def test_complete_cohort_materializes_a_separate_scheduled_batch(self):
        empty = compile_machine_validation(self.root, evidence_override={})
        pairs = {
            (row["route_id"], row["treatment_id"]) for row in empty["width_identities"]
        }
        evidence = {row["id"]: set(pairs) for row in empty["libraries"]}
        status = compile_machine_validation(self.root, evidence_override=evidence)
        document = compile_validation_batch(self.root, evidence_override=evidence)

        self.assertTrue(status["readiness"]["eligible"])
        self.assertEqual(status["state"], "eligible-disarmed")
        self.assertEqual(document["kind"], "validation-run")
        manifest = tomllib.loads(document["rendered_manifest"])
        self.assertEqual(manifest["state"], "materialized-disarmed")
        self.assertEqual(len(manifest["work_unit"]), 222)
        self.assertEqual(manifest["summary"]["composite_programs"], 444)
        self.assertEqual(len(manifest["materialization_digest"]), 64)
        self.assertEqual(
            manifest["execution"]["query_copy"],
            "debug-stripped-symbol-indexed",
        )
        schedule = tomllib.loads(document["rendered_schedule"])
        self.assertEqual(schedule["state"], "scheduled-claim-blocked")
        self.assertTrue(schedule["trigger"][0]["automatic_scheduling"])
        self.assertEqual(
            schedule["trigger"][0]["claim_gate"],
            "first-run-canary-after-cohort-complete",
        )

    def test_live_schedule_state_does_not_invalidate_materialized_manifest(self):
        empty = compile_machine_validation(self.root, evidence_override={})
        pairs = {
            (row["route_id"], row["treatment_id"])
            for row in empty["width_identities"]
        }
        evidence = {row["id"]: set(pairs) for row in empty["libraries"]}
        with patch(
            "fidb_poc.machine_validation._validation_schedule_state",
            return_value="waiting-for-cohort",
        ):
            waiting = compile_validation_batch(self.root, evidence_override=evidence)
        with patch(
            "fidb_poc.machine_validation._validation_schedule_state",
            return_value="scheduled-claim-blocked",
        ):
            scheduled = compile_validation_batch(self.root, evidence_override=evidence)

        self.assertEqual(waiting["rendered_manifest"], scheduled["rendered_manifest"])


if __name__ == "__main__":
    unittest.main()
