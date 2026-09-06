import importlib.util
import unittest
from pathlib import Path

from fidb_poc.fid_matching import (
    MATCH_INPUT_SCHEMA,
    classify_matches,
    compare_with_oracle,
    load_matching_authority,
    match_cpu,
    match_gpu,
)


def candidate(identifier, *, code, specific="bb", additional=0, child=0, **flags):
    return {
        "candidate_id": identifier,
        "owner": f"{identifier}@1",
        "name": identifier,
        "full_hash": "aa",
        "specific_hash": specific,
        "specific_hash_additional_size": additional,
        "code_unit_size": code,
        "child_code_units": child,
        "parent_code_units": 0,
        "auto_pass": flags.get("auto_pass", False),
        "auto_fail": flags.get("auto_fail", False),
        "force_specific": flags.get("force_specific", False),
        "force_relation": flags.get("force_relation", False),
    }


class FidMatchingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.authority = load_matching_authority(cls.root)

    def document(self):
        return {
            "schema_version": MATCH_INPUT_SCHEMA,
            "functions": [
                {
                    "address": "1000",
                    "full_hash": "aa",
                    "specific_hash": "bb",
                    "candidates": [
                        candidate("specific", code=10, additional=8),
                        candidate("relation", code=14, specific="cc", child=2),
                    ],
                    "native_matches": [
                        {
                            "candidate_id": "relation",
                            "owner": "relation@1",
                            "name": "relation",
                            "score": 16.0,
                        }
                    ],
                },
                {
                    "address": "2000",
                    "full_hash": "aa",
                    "specific_hash": "bb",
                    "candidates": [candidate("failed", code=100, auto_fail=True)],
                    "native_matches": [],
                },
                {
                    "address": "3000",
                    "full_hash": "aa",
                    "specific_hash": "bb",
                    "candidates": [
                        candidate(
                            "forced-relation",
                            code=10,
                            child=5,
                            force_relation=True,
                        )
                    ],
                    "native_matches": [
                        {
                            "candidate_id": "forced-relation",
                            "owner": "forced-relation@1",
                            "name": "forced-relation",
                            "score": 15.0,
                        }
                    ],
                },
                {
                    "address": "4000",
                    "full_hash": "aa",
                    "specific_hash": "bb",
                    "candidates": [
                        candidate(
                            "forced-specific",
                            code=100,
                            specific="cc",
                            force_specific=True,
                        )
                    ],
                    "native_matches": [],
                },
            ],
        }

    def test_cpu_reproduces_candidate_flags_scoring_and_winner_culling(self):
        document = self.document()
        result = match_cpu(document, self.authority)

        self.assertEqual(result["candidate_count"], 5)
        self.assertEqual(result["matched_functions"], 2)
        self.assertEqual(
            [row["matches"] for row in result["functions"]],
            [
                [
                    {
                        "candidate_id": "relation",
                        "owner": "relation@1",
                        "name": "relation",
                        "score": 16.0,
                    }
                ],
                [],
                [
                    {
                        "candidate_id": "forced-relation",
                        "owner": "forced-relation@1",
                        "name": "forced-relation",
                        "score": 15.0,
                    }
                ],
                [],
            ],
        )
        comparison = compare_with_oracle(document, result, self.authority)
        self.assertEqual(comparison["state"], "equivalent")
        self.assertEqual(comparison["decision_mismatches"], 0)

    @unittest.skipUnless(importlib.util.find_spec("wgpu"), "wgpu is not installed")
    def test_wgpu_reproduces_the_same_oracle_decisions(self):
        document = self.document()
        try:
            result = match_gpu(document, self.authority, workgroup_size=32)
        except ValueError as error:
            if "requires a hardware adapter" in str(error):
                self.skipTest(str(error))
            raise
        comparison = compare_with_oracle(document, result, self.authority)

        self.assertEqual(comparison["state"], "equivalent")
        self.assertEqual(comparison["decision_mismatches"], 0)

    def test_candidate_full_hash_must_equal_query(self):
        document = self.document()
        document["functions"][0]["candidates"][0]["full_hash"] = "different"
        with self.assertRaisesRegex(ValueError, "does not share"):
            match_cpu(document, self.authority)

    def test_classification_counts_one_owner_decision_per_function(self):
        document = self.document()
        document["functions"][0]["truth_owner"] = "relation@1"
        document["functions"][0]["truth_basis"] = "linker-map"
        document["functions"][2]["truth_owner"] = "other@1"
        document["functions"][2]["truth_basis"] = "unique-reference-name"
        classification = classify_matches(
            document, ["relation@1", "forced-relation@1", "other@1"]
        )

        self.assertEqual(
            classification["confusion_matrix"],
            {
                "true_positives": 1,
                "false_positives": 1,
                "true_negatives": 3,
                "false_negatives": 1,
            },
        )
        self.assertEqual(classification["truth"]["labelled_functions"], 2)
        self.assertEqual(classification["truth"]["unlabelled_functions"], 2)


if __name__ == "__main__":
    unittest.main()
    classify_matches,
