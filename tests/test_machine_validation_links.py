import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fidb_poc.machine_validation_links import (
    _canonical_digest,
    _new_report,
    _summarize,
    failure_fingerprint,
    link_qualification_admission,
    link_qualification_status,
    load_link_qualification,
    run_link_qualification,
)
from fidb_poc.machine_validation_runner import (
    LINK_HARNESS_POLICY,
    PREPARED_FOLD_SCHEMA,
    QUERY_COPY_POLICY,
)


class MachineValidationLinkQualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.project_root = Path(__file__).resolve().parents[1]

    def test_authority_is_disarmed_and_grandfathers_only_the_live_checkpoint(self):
        authority = load_link_qualification(self.project_root)

        self.assertEqual(authority["state"], "defined-disarmed")
        self.assertEqual(authority["execution"]["identical_failure_limit"], 4)
        self.assertEqual(
            authority["admission"]["grandfather_run_ids"],
            ["c10-shared-image-symbolic-v2-full"],
        )
        admission = link_qualification_admission(
            self.project_root, "c10-shared-image-symbolic-v2-full"
        )
        self.assertTrue(admission["ready"])
        self.assertEqual(admission["state"], "grandfathered-checkpoint")

    def test_failure_fingerprint_removes_attempt_specific_paths_and_addresses(self):
        root = Path("/project")
        first = RuntimeError(
            "composite link failed for linux-x86-gcc12: "
            "/project/qualification/run-001 at 0x7ff01234 after 123456 bytes"
        )
        second = RuntimeError(
            "composite link failed for linux-x86-gcc13: "
            "/project/qualification/run-999 at 0x7abc9999 after 987654 bytes"
        )

        one = failure_fingerprint(root, first)
        two = failure_fingerprint(root, second)

        self.assertEqual(one["reason_code"], "composite-link")
        self.assertEqual(one["failure_fingerprint"], two["failure_fingerprint"])

    def test_runtime_authority_failure_classes_remain_distinct(self):
        unknown = failure_fingerprint(
            Path("/project"),
            ValueError("versioned route is unknown to the runtime loader"),
        )
        mismatch = failure_fingerprint(
            Path("/project"),
            ValueError("queued toolchain identity mismatch for base route"),
        )

        self.assertEqual(unknown["reason_code"], "authority-resolution")
        self.assertEqual(mismatch["reason_code"], "authority-identity-mismatch")
        self.assertNotEqual(
            unknown["failure_fingerprint"], mismatch["failure_fingerprint"]
        )

    def test_identical_failure_circuit_opens_before_more_width_is_claimed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cells = [
                {
                    "id": f"{position:03d}:A",
                    "position": position,
                    "fold": "A",
                    "route_id": f"route-{position}",
                    "treatment_id": "o2",
                }
                for position in range(1, 11)
            ]
            plan = {
                "id": "fixture",
                "validation_id": "validation",
                "authority_path": "authority.toml",
                "authority_sha256": "a" * 64,
                "runtime_authority_sha256": "b" * 64,
                "input_digest": "c" * 64,
                "generation_root": "evidence/generation",
                "execution": {
                    "workers": 4,
                    "batch_size": 4,
                    "identical_failure_limit": 4,
                },
                "cells": cells,
            }

            def fail(_root, _plan, position, folds):
                fold = folds[0]
                return [
                    {
                        "id": f"{position:03d}:{fold}",
                        "status": "failed",
                        "position": position,
                        "fold": fold,
                        "route_id": f"route-{position}",
                        "treatment_id": "o2",
                        "reason_code": "authority-resolution",
                        "failure_fingerprint": "same-failure",
                        "error": "unknown route",
                    }
                ]

            with patch(
                "fidb_poc.machine_validation_links._qualify_position",
                side_effect=fail,
            ):
                report = run_link_qualification(root, _plan=plan)

            self.assertEqual(report["state"], "circuit-open")
            self.assertEqual(report["circuit_breaker"]["observed"], 4)
            self.assertEqual(report["summary"]["failed"], 4)
            self.assertEqual(report["summary"]["remaining"], 6)
            self.assertEqual(len(report["attempts"]), 4)

    def test_status_verifies_every_sealed_link_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fold_root = root / "evidence/generation/units/001-route-o2/fold-A"
            fold_root.mkdir(parents=True)
            truth = fold_root / "truth.elf"
            query = fold_root / "query.elf"
            truth.write_bytes(b"truth")
            query.write_bytes(b"query")
            audit = {"state": "passed", "direct_zero_transfers": 0}
            marker = fold_root / "prepared.json"
            marker.write_text(
                json.dumps(
                    {
                        "schema_version": PREPARED_FOLD_SCHEMA,
                        "state": "prepared",
                        "position": 1,
                        "route_id": "route",
                        "treatment_id": "o2",
                        "fold": "A",
                        "runtime_authority_sha256": "b" * 64,
                        "link_harness_policy": LINK_HARNESS_POLICY,
                        "query_copy_policy": QUERY_COPY_POLICY,
                        "truth_binary": str(truth.relative_to(root)),
                        "query_binary": str(query.relative_to(root)),
                        "link_audit": audit,
                    }
                ),
                encoding="utf-8",
            )
            plan = {
                "id": "fixture",
                "validation_id": "validation",
                "authority_path": "authority.toml",
                "authority_sha256": "a" * 64,
                "runtime_authority_sha256": "b" * 64,
                "input_digest": "c" * 64,
                "generation_root": "evidence/generation",
                "report_path": "evidence/generation/report.json",
                "execution": {"identical_failure_limit": 4},
                "cells": [
                    {
                        "id": "001:A",
                        "position": 1,
                        "fold": "A",
                        "route_id": "route",
                        "treatment_id": "o2",
                    }
                ],
            }
            report = _new_report(plan)
            report["attempts"].append(
                {
                    "id": "001:A",
                    "status": "qualified",
                    "position": 1,
                    "fold": "A",
                    "route_id": "route",
                    "treatment_id": "o2",
                    "prepared_path": str(marker.relative_to(root)),
                    "truth_sha256": __import__("hashlib").sha256(b"truth").hexdigest(),
                    "query_sha256": __import__("hashlib").sha256(b"query").hexdigest(),
                    "link_audit_sha256": _canonical_digest(audit),
                }
            )
            _summarize(report, plan)
            (root / plan["report_path"]).write_text(
                json.dumps(report), encoding="utf-8"
            )

            status = link_qualification_status(root, _plan=plan)
            self.assertTrue(status["satisfied"])
            query.write_bytes(b"tampered")
            status = link_qualification_status(root, _plan=plan)
            self.assertFalse(status["satisfied"])
            self.assertIn("failed verification", status["blockers"][0])


if __name__ == "__main__":
    unittest.main()
