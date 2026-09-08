import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from fidb_poc.fid_reference_comparison import (
    freeze_reference_comparison,
    load_comparison_authority,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FidReferenceComparisonTests(unittest.TestCase):
    def test_project_authority_pins_three_reference_populations(self):
        root = Path(__file__).resolve().parents[1]
        policy = load_comparison_authority(root)

        self.assertEqual(policy["baseline_arm"], "archive-only")
        self.assertEqual(
            [row["population"] for row in policy["arm"]],
            ["archive-only", "linked-only", "archive-plus-linked"],
        )

    def test_freeze_verifies_inputs_and_emits_deterministic_deltas(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            validation = root / "validation"
            artifacts = root / "artifacts"
            validation.mkdir()
            artifacts.mkdir()
            archive_index = artifacts / "archive.sqlite3"
            linked_index = artifacts / "linked.sqlite3"
            generation_seal = artifacts / "generation-seal.json"
            archive_index.write_bytes(b"archive-index")
            linked_index.write_bytes(b"linked-index")
            generation_seal.write_text('{"sealed":true}\n', encoding="utf-8")
            generation_sha256 = _sha256(generation_seal)
            index_receipts = {
                "archive": {
                    "path": "artifacts/archive.sqlite3",
                    "sha256": _sha256(archive_index),
                },
                "linked": {
                    "path": "artifacts/linked.sqlite3",
                    "sha256": _sha256(linked_index),
                },
            }
            arms = [
                ("archive", "archive-only", (70, 10, 90, 30), ["archive"]),
                ("linked", "linked-only", (85, 5, 95, 15), ["linked"]),
                (
                    "union",
                    "archive-plus-linked",
                    (90, 6, 94, 10),
                    ["archive", "linked"],
                ),
            ]
            for arm_id, population, values, indexes in arms:
                evidence = artifacts / f"{arm_id}-evidence.sqlite3"
                evidence.write_bytes(f"{arm_id}-evidence".encode())
                tp, fp, tn, fn = values
                reference = None
                if population != "archive-only":
                    reference = {
                        "population": population,
                        "components": [
                            {
                                "kind": "linked-generation",
                                "generation_seal_sha256": generation_sha256,
                            }
                        ],
                        "indexes": [index_receipts[index] for index in indexes],
                    }
                report = {
                    "schema_version": "fidb-fid-matching-campaign-report/v1",
                    "campaign_id": f"campaign-{arm_id}",
                    "source_run_id": "source-v1",
                    "mode": "full",
                    "state": "measured-complete",
                    "authority_path": f"validation/{arm_id}.toml",
                    "authority_sha256": arm_id * 8,
                    "backend": {
                        "contract_met": True,
                        "requested": "gpu-portable-fid-v1",
                        "effective": ["gpu-portable-fid-v1"],
                        "fallback_cases": [],
                        "performance_authority_path": "performance/fid.toml",
                        "performance_authority_sha256": "performance",
                    },
                    "progress": {"failed_or_pending_cases": 0},
                    "reference_population": reference,
                    "confusion_matrix": {
                        "true_positives": tp,
                        "false_positives": fp,
                        "true_negatives": tn,
                        "false_negatives": fn,
                    },
                    "hash_evidence": {
                        "database_path": str(evidence.relative_to(root)),
                        "database_sha256": _sha256(evidence),
                        "distinct_signatures": 12,
                        "noisy_signatures": 2,
                        "query_function_owner_observations": 200,
                    },
                    "method_authority": {"sha256": "method"},
                    "truth": {
                        "coverage": 1.0,
                        "labelled_functions": 100,
                        "unlabelled_functions": 0,
                    },
                    "wall_time_seconds": 1.0,
                    "finished_at": "2026-09-08T00:00:00+00:00",
                }
                (artifacts / f"{arm_id}-report.json").write_text(
                    json.dumps(report), encoding="utf-8"
                )
            (validation / "fid-reference-comparison.toml").write_text(
                """
schema_version = "fidb-reference-comparison/v1"
id = "comparison-v1"
source_run_id = "source-v1"
baseline_arm = "archive"
output_report = "artifacts/comparison.json"
output_seal = "artifacts/comparison-seal.json"

[[arm]]
id = "archive"
population = "archive-only"
campaign_id = "campaign-archive"
report = "artifacts/archive-report.json"
producer_revision = "0000000000000000000000000000000000000000"
candidate_index = ["artifacts/archive.sqlite3"]

[[arm]]
id = "linked"
population = "linked-only"
campaign_id = "campaign-linked"
report = "artifacts/linked-report.json"
producer_revision = "1111111111111111111111111111111111111111"
candidate_index = ["artifacts/linked.sqlite3"]
generation_seal = "artifacts/generation-seal.json"

[[arm]]
id = "union"
population = "archive-plus-linked"
campaign_id = "campaign-union"
report = "artifacts/union-report.json"
producer_revision = "2222222222222222222222222222222222222222"
candidate_index = ["artifacts/archive.sqlite3", "artifacts/linked.sqlite3"]
generation_seal = "artifacts/generation-seal.json"
""".strip()
                + "\n",
                encoding="utf-8",
            )

            first = freeze_reference_comparison(root)
            first_digest = _sha256(artifacts / "comparison.json")
            second = freeze_reference_comparison(root)

            self.assertEqual(first_digest, _sha256(artifacts / "comparison.json"))
            self.assertEqual(first["arms"], second["arms"])
            self.assertEqual(first["arms"][0]["rates"]["recall"], 0.7)
            self.assertEqual(
                first["comparisons"][0]["confusion_delta"]["true_positives"],
                15,
            )
            self.assertEqual(
                first["comparisons"][-1]["confusion_delta"]["false_negatives"],
                -5,
            )


if __name__ == "__main__":
    unittest.main()
