from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "validation/evidence/c10-reference-form-comparison-v1.json"


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class ReferenceFormEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
        authority_path = ROOT / cls.receipt["comparison_authority"]["path"]
        cls.authority = tomllib.loads(authority_path.read_text(encoding="utf-8"))

    def test_receipt_binds_the_reviewed_comparison_authority(self) -> None:
        receipt = self.receipt
        authority = self.authority
        authority_path = ROOT / receipt["comparison_authority"]["path"]

        self.assertEqual(receipt["state"], "measured-complete")
        self.assertEqual(receipt["id"], authority["id"])
        self.assertEqual(receipt["source_run_id"], authority["source_run_id"])
        self.assertEqual(
            receipt["comparison_authority"]["sha256"], _sha256(authority_path)
        )

        expected_arms = {
            arm["id"]: (
                arm["campaign_id"],
                arm["producer_revision"],
                arm["report"],
            )
            for arm in authority["arm"]
        }
        observed_arms = {
            arm["id"]: (
                arm["campaign_id"],
                arm["producer_revision"],
                arm["report_path"],
            )
            for arm in receipt["arms"]
        }
        self.assertEqual(observed_arms, expected_arms)

    def test_confusion_counts_rates_and_deltas_are_self_consistent(self) -> None:
        receipt = self.receipt
        positive = receipt["decision_population"]["positive_owner_decisions"]
        negative = receipt["decision_population"]["negative_owner_decisions"]
        arms = {arm["id"]: arm for arm in receipt["arms"]}

        for arm in arms.values():
            confusion = arm["confusion_matrix"]
            tp = confusion["true_positives"]
            fp = confusion["false_positives"]
            tn = confusion["true_negatives"]
            fn = confusion["false_negatives"]
            self.assertEqual(tp + fn, positive)
            self.assertEqual(tn + fp, negative)
            precision = tp / (tp + fp)
            recall = tp / (tp + fn)
            fpr = fp / (fp + tn)
            f1 = 2 * precision * recall / (precision + recall)
            self.assertTrue(math.isclose(arm["rates"]["precision"], precision))
            self.assertTrue(math.isclose(arm["rates"]["recall"], recall))
            self.assertTrue(math.isclose(arm["rates"]["false_positive_rate"], fpr))
            self.assertTrue(math.isclose(arm["rates"]["f1"], f1))

        pairs = {
            "archive_to_linked": ("archive-only", "linked-only"),
            "linked_to_union": ("linked-only", "archive-plus-linked"),
        }
        rate_names = ("precision", "recall", "false_positive_rate", "f1")
        count_names = (
            "true_positives",
            "false_positives",
            "true_negatives",
            "false_negatives",
        )
        for delta_id, (before_id, after_id) in pairs.items():
            before = arms[before_id]
            after = arms[after_id]
            delta = receipt["measured_deltas"][delta_id]
            for name in count_names:
                self.assertEqual(
                    delta[name],
                    after["confusion_matrix"][name]
                    - before["confusion_matrix"][name],
                )
            for name in rate_names:
                self.assertTrue(
                    math.isclose(
                        delta[name], after["rates"][name] - before["rates"][name]
                    )
                )

    def test_local_runtime_seals_match_the_tracked_receipt_when_present(self) -> None:
        checks = (
            self.receipt["comparison_report"],
            self.receipt["comparison_seal"],
            {
                "path": self.receipt["linked_generation"]["seal_path"],
                "sha256": self.receipt["linked_generation"]["seal_sha256"],
            },
        )
        for check in checks:
            path = ROOT / check["path"]
            if path.exists():
                self.assertEqual(check["sha256"], _sha256(path), path)


if __name__ == "__main__":
    unittest.main()
