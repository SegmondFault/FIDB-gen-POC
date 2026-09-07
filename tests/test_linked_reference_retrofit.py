from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

from fidb_poc.linked_reference_retrofit import (
    _balanced_chunks,
    _failure_fingerprint,
    _parse_task_key,
    _reference_analysis_policy,
    load_authority,
)
from fidb_poc.validation_analysis import (
    FID_BUILD_ANALYSIS_POLICY,
    FID_BUILD_RECOVERY_ANALYSIS_POLICY,
    QUERY_ANALYSIS_RECOVERY_POLICY,
)


class LinkedReferenceRetrofitTests(unittest.TestCase):
    def test_source_query_recovery_propagates_to_superh_reference_build(self) -> None:
        self.assertEqual(
            _reference_analysis_policy(
                "SuperH4:LE:32:default", QUERY_ANALYSIS_RECOVERY_POLICY
            ),
            FID_BUILD_RECOVERY_ANALYSIS_POLICY,
        )
        self.assertEqual(
            _reference_analysis_policy("x86:LE:64:default", None),
            FID_BUILD_ANALYSIS_POLICY,
        )
        with self.assertRaisesRegex(ValueError, "non-SuperH"):
            _reference_analysis_policy(
                "x86:LE:64:default", QUERY_ANALYSIS_RECOVERY_POLICY
            )

    def test_checked_in_authority_is_fail_closed(self) -> None:
        root = Path(__file__).resolve().parents[1]
        authority = load_authority(root)
        self.assertEqual(authority["id"], "c10-linked-reference-v1")
        self.assertEqual(authority["reference"]["form"], "linked-shared-image")
        self.assertFalse(authority["safety"]["execute_target_binaries"])
        self.assertFalse(authority["safety"]["compile_source"])
        self.assertTrue(authority["safety"]["invoke_linker"])
        self.assertFalse(authority["safety"]["mutate_archive_baseline"])
        self.assertEqual(
            authority["source_archive_recovery"]["allow_digest_refresh_owners"],
            ["openssl@3.5.8"],
        )

    def test_task_keys_retain_owner_version(self) -> None:
        self.assertEqual(_parse_task_key("67:gmp@6.3.0"), (67, "gmp@6.3.0"))
        for invalid in ("", "0:gmp@6.3.0", "67", "x:gmp@6.3.0"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                _parse_task_key(invalid)

    def test_balancer_places_largest_tasks_first(self) -> None:
        tasks = [
            {"task_key": "1:a", "weight_bytes": 100},
            {"task_key": "1:b", "weight_bytes": 80},
            {"task_key": "1:c", "weight_bytes": 20},
            {"task_key": "1:d", "weight_bytes": 10},
        ]
        chunks, loads = _balanced_chunks(tasks, 2)
        self.assertEqual(len(chunks), 2)
        self.assertEqual(
            sorted(sum(chunks, [])), sorted(row["task_key"] for row in tasks)
        )
        self.assertEqual(sum(loads), 210)
        self.assertLessEqual(max(loads) - min(loads), 10)

    def test_failure_fingerprint_ignores_paths_and_numbers(self) -> None:
        first = ValueError("failed /tmp/a/job-12 after 41 records")
        second = ValueError("failed /tmp/b/job-99 after 77 records")
        self.assertEqual(_failure_fingerprint(first), _failure_fingerprint(second))

    def test_unknown_authority_fields_are_rejected(self) -> None:
        root = Path(__file__).resolve().parents[1]
        text = (root / "validation/linked-reference-retrofit.toml").read_text()
        with tempfile.TemporaryDirectory(dir=root) as temporary:
            path = Path(temporary) / "authority.toml"
            path.write_text(text + "\nunknown = true\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_authority(root, path.relative_to(root))


if __name__ == "__main__":
    unittest.main()
