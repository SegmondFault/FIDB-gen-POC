from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from fidb_poc.fid_reference_population import resolve_linked_generation
from fidb_poc.linked_reference_retrofit import (
    GENERATION_SEAL_SCHEMA,
    TASK_SEAL_SCHEMA,
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def json_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class FidReferencePopulationTests(unittest.TestCase):
    def fixture(self, root: Path) -> Path:
        fidb = root / "artifacts" / "sample.fidb"
        fidb.parent.mkdir(parents=True)
        fidb.write_bytes(b"fidb")
        task = {
            "schema_version": TASK_SEAL_SCHEMA,
            "state": "complete",
            "source_run_id": "source-run",
            "reference_form": "linked-shared-image",
            "task_key": "1:sample@1",
            "position": 1,
            "owner": "sample@1",
            "route_id": "route",
            "treatment_id": "treatment",
            "code_revision": "revision",
            "outputs": [
                {
                    "kind": "fidb",
                    "path": "artifacts/sample.fidb",
                    "sha256": digest(fidb),
                    "bytes": fidb.stat().st_size,
                }
            ],
        }
        task_path = root / "artifacts" / "task-seal.json"
        task_path.write_text(json.dumps(task), encoding="utf-8")
        receipts = [
            {
                "task_key": "1:sample@1",
                "code_revision": "revision",
                "path": "artifacts/task-seal.json",
                "sha256": digest(task_path),
            }
        ]
        identity = {
            "authority_sha256": "a" * 64,
            "plan_sha256": "b" * 64,
            "code_revisions": ["revision"],
            "task_seals": receipts,
        }
        generation = {
            "schema_version": GENERATION_SEAL_SCHEMA,
            "state": "sealed",
            "id": "generation",
            "source_run_id": "source-run",
            "reference_form": "linked-shared-image",
            **identity,
            "generation_sha256": json_digest(identity),
        }
        path = root / "artifacts" / "generation-seal.json"
        path.write_text(json.dumps(generation), encoding="utf-8")
        return path

    def test_resolves_only_a_complete_digest_bound_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.fixture(root)

            result = resolve_linked_generation(
                root,
                path,
                source_run_id="source-run",
                expected_identities=[("sample@1", "route", "treatment")],
            )

            self.assertEqual(result["task_count"], 1)
            self.assertEqual(result["entries"][0]["owner"], "sample@1")
            self.assertEqual(result["generation_seal_sha256"], digest(path))

    def test_rejects_changed_task_outputs_and_incomplete_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.fixture(root)
            (root / "artifacts" / "sample.fidb").write_bytes(b"changed")

            with self.assertRaisesRegex(ValueError, "FIDB digest mismatch"):
                resolve_linked_generation(
                    root,
                    path,
                    source_run_id="source-run",
                    expected_identities=[("sample@1", "route", "treatment")],
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.fixture(root)
            with self.assertRaisesRegex(ValueError, "coverage differs"):
                resolve_linked_generation(
                    root,
                    path,
                    source_run_id="source-run",
                    expected_identities=[
                        ("sample@1", "route", "treatment"),
                        ("missing@1", "route", "treatment"),
                    ],
                )


if __name__ == "__main__":
    unittest.main()
