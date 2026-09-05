import json
import tempfile
import unittest
from pathlib import Path

from fidb_poc.validation_observatory import compile_validation_observatory


class ValidationObservatoryTests(unittest.TestCase):
    def _report(self, root: Path, cohort: str, run: str, finished: str, shared: int):
        path = root / "artifacts/validation-runs" / cohort / run / "hash-report.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "schema_version": "fidb-machine-validation-hash-report/v1",
                    "state": "measured-complete",
                    "validation_id": cohort,
                    "run_id": run,
                    "finished_at": finished,
                    "source_evidence_sha256": "source",
                    "method_authority": {
                        "id": "single-hash-ground-truth-v1",
                        "sha256": "method",
                    },
                    "corpus_index": {
                        "state": "ingested",
                        "ordinal": 1 if cohort == "c10" else 2,
                        "generation_digest": f"generation-{cohort}",
                        "owners": 10 if cohort == "c10" else 20,
                        "signatures": 12,
                        "database_path": "artifacts/hash-discrimination/corpus-index-v1.sqlite3",
                        "authority_sha256": "corpus-method",
                    },
                    "gpu_comparison": {
                        "state": "equivalent",
                        "scope": "packed-complete-signature-exact-probe",
                        "report_path": "gpu-comparison.json",
                        "candidate_backend": "gpu-wgpu-packed-probe-v1",
                        "publish_from": "canonical-only",
                        "mismatches": 0,
                    },
                    "confusion_matrix": {
                        "true_positives": 8,
                        "false_positives": 2,
                        "true_negatives": 18,
                        "false_negatives": 2,
                    },
                    "hash_evidence": {
                        "database_path": "evidence.sqlite3",
                        "distinct_signatures": 12,
                        "top_noisy": [{"signature": "large-detail"}],
                    },
                    "hash_type_analysis": [
                        {
                            "hash_type": "full",
                            "distinct_values": 10,
                            "singleton_values": 10 - shared,
                            "multi_owner_values": shared,
                            "multi_owner_fraction": shared / 10,
                            "owner_links": 12,
                            "ambiguous_owner_links": shared * 2,
                            "complete_disambiguated_owner_signatures": shared,
                            "reference_observations": 20,
                            "exact_false_positive_observations": 2,
                            "maximum_distinct_owners": 2,
                            "distribution": [
                                {
                                    "distinct_owners": 1,
                                    "distinct_values": 10 - shared,
                                    "fraction_of_values": (10 - shared) / 10,
                                }
                            ],
                            "top_ambiguous": [{"value": "01", "owners": ["a", "b"]}],
                            "libraries": [{"owner": "a", "ambiguous_fraction": 0.1}],
                        }
                    ],
                    "failures": [{"failure_type": "collision"}],
                }
            ),
            encoding="utf-8",
        )

    def test_indexes_all_runs_and_bounds_unselected_detail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._report(root, "c10", "run-1", "2026-09-01T00:00:00Z", 1)
            self._report(root, "c20", "run-2", "2026-09-02T00:00:00Z", 3)

            result = compile_validation_observatory(root)

            self.assertEqual(result["state"], "ready")
            self.assertEqual(result["summary"]["measured_runs"], 2)
            self.assertEqual(result["summary"]["validation_cohorts"], 2)
            self.assertEqual(result["latest_run_key"], "c20:run-2")
            self.assertEqual(result["selected"]["run_id"], "run-2")
            self.assertEqual(result["selected"]["rates"]["false_positive_rate"], 0.1)
            self.assertEqual(result["selected"]["corpus_index"]["ordinal"], 2)
            self.assertEqual(result["selected"]["gpu_comparison"]["mismatches"], 0)
            self.assertEqual(
                result["selected"]["hash_type_analysis"][0]["top_ambiguous"][0]["value"],
                "01",
            )
            self.assertNotIn("top_noisy", result["runs"][0]["hash_evidence"])
            self.assertEqual(len(result["trends"][0]["points"]), 2)

    def test_selects_a_specific_immutable_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._report(root, "c10", "run-1", "2026-09-01T00:00:00Z", 1)
            self._report(root, "c20", "run-2", "2026-09-02T00:00:00Z", 3)

            result = compile_validation_observatory(
                root, selected_run="c10:run-1"
            )

            self.assertTrue(result["selection_found"])
            self.assertEqual(result["selected_run_key"], "c10:run-1")
            self.assertEqual(result["selected"]["report_sha256"], result["runs"][0]["report_sha256"])

    def test_unknown_run_does_not_fall_back_silently(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._report(root, "c10", "run-1", "2026-09-01T00:00:00Z", 1)

            result = compile_validation_observatory(root, selected_run="missing")

            self.assertFalse(result["selection_found"])
            self.assertIsNone(result["selected_run_key"])
            self.assertIsNone(result["selected"])


if __name__ == "__main__":
    unittest.main()
