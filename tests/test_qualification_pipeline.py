from __future__ import annotations

from pathlib import Path
import unittest
from unittest.mock import patch

from fidb_poc.qualification_pipeline import (
    compile_qualification_pipeline,
    load_qualification_pipeline,
    qualification_gate,
    require_qualification_gates,
)
from fidb_poc.width_batch import load_width_batch


class QualificationPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[1]
        cls.legacy = load_width_batch(
            cls.root, cls.root / "batches/c-next-nine-mega-width.toml"
        )
        cls.future = load_width_batch(
            cls.root, cls.root / "batches/c-11-20-mega-width.toml"
        )

    def test_policy_is_enforced_and_cannot_arm(self) -> None:
        policy = load_qualification_pipeline(self.root)

        self.assertEqual(policy["state"], "enforced")
        self.assertTrue(policy["policy"]["require_current_seal_before_materialization"])
        self.assertTrue(policy["policy"]["embed_seal_in_generated_plans"])
        self.assertFalse(policy["policy"]["automatic_arming"])

    def test_legacy_exemption_is_bound_to_exact_batch_digest(self) -> None:
        gate = qualification_gate(self.root, self.legacy)

        self.assertEqual(gate["state"], "historical-exempt")
        self.assertTrue(gate["satisfied"])

        changed = {**self.legacy, "batch_digest": "f" * 64}
        stale = qualification_gate(self.root, changed)
        self.assertEqual(stale["state"], "legacy-exemption-stale")
        self.assertFalse(stale["satisfied"])

    def test_future_batch_requires_a_current_seal(self) -> None:
        fake_status = {
            "state": "required",
            "satisfied": False,
            "authority_path": "qualification/c11-c20.toml",
            "authority_sha256": "a" * 64,
            "input_digest": "b" * 64,
            "qualification_digest": None,
            "evidence_path": "qualification/evidence/c11.json",
            "evidence_sha256": None,
            "summary": {"total": 160, "built": 0, "failed": 0, "remaining": 160},
            "blockers": ["qualification has not been executed"],
        }
        with (
            patch(
                "fidb_poc.qualification_pipeline.compile_recipe_qualification",
                return_value={"placeholder": True},
            ),
            patch(
                "fidb_poc.qualification_pipeline.recipe_qualification_status",
                return_value=fake_status,
            ),
        ):
            status = compile_qualification_pipeline(self.root, [self.future])
            with self.assertRaisesRegex(ValueError, "blocked by qualification"):
                require_qualification_gates(self.root, [self.future])

        self.assertEqual(status["summary"]["blocked"], 1)
        self.assertEqual(status["gates"][0]["state"], "required")
        self.assertEqual(status["gates"][0]["promotion_state"], "blocked")


if __name__ == "__main__":
    unittest.main()
