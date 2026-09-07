from __future__ import annotations

import tempfile
from pathlib import Path
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

from fidb_poc.linked_reference_retrofit import (
    _balanced_chunks,
    _active_task_timed_out,
    _failure_fingerprint,
    _parse_task_key,
    _reference_analysis_policy,
    _supervise_workers,
    load_authority,
    load_supervisor_authority,
)
from fidb_poc.validation_analysis import (
    FID_BUILD_ANALYSIS_POLICY,
    FID_BUILD_RECOVERY_ANALYSIS_POLICY,
    QUERY_ANALYSIS_RECOVERY_POLICY,
)


class LinkedReferenceRetrofitTests(unittest.TestCase):
    def test_supervisor_recycles_only_the_timed_out_shard(self) -> None:
        root = Path(__file__).resolve().parents[1]
        authority = {
            "id": "test",
            "output_root": "artifacts/linked-reference-runs",
        }
        task = {
            "task_key": "1:gmp@6.3.0",
            "input_sha256": "a" * 64,
            "position": 1,
            "route_id": "linux-x86-64-gcc-12",
            "treatment_id": "baseline_o2",
            "owner": "gmp@6.3.0",
        }
        first = Mock(pid=101)
        first.poll.return_value = None
        second = Mock(pid=102)
        second.poll.return_value = 0
        old = (datetime.now(timezone.utc) - timedelta(seconds=61)).isoformat()
        supervisor = {
            "task_timeout_seconds": 60,
            "task_timeout_retries": 1,
            "termination_grace_seconds": 5,
            "poll_seconds": 1,
            "authority_path": "validation/test-supervisor.toml",
            "authority_sha256": "b" * 64,
        }
        with (
            patch(
                "fidb_poc.linked_reference_retrofit._spawn_worker_process",
                side_effect=[first, second],
            ) as spawn,
            patch(
                "fidb_poc.linked_reference_retrofit._read_worker_status",
                return_value={
                    "schema_version": "fidb-linked-reference-worker-status/v1",
                    "active_task": task["task_key"],
                    "active_started_at": old,
                },
            ),
            patch(
                "fidb_poc.linked_reference_retrofit._valid_task_seal",
                return_value=None,
            ),
            patch(
                "fidb_poc.linked_reference_retrofit._stop_timed_out_process",
                return_value="terminated",
            ) as stop,
            patch(
                "fidb_poc.linked_reference_retrofit._archive_failure"
            ) as archive,
            patch("fidb_poc.linked_reference_retrofit.time.sleep"),
        ):
            return_codes, events = _supervise_workers(
                root=root,
                plan={"_authority": authority, "tasks": [task]},
                chunks=[[task["task_key"]]],
                logs=[object()],
                supervisor=supervisor,
            )

        self.assertEqual(return_codes, [0])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["reason_code"], "task-timeout")
        self.assertEqual(spawn.call_count, 2)
        stop.assert_called_once_with(first, 5)
        archive.assert_called_once()

    def test_checked_in_supervisor_bounds_individual_tasks(self) -> None:
        root = Path(__file__).resolve().parents[1]
        supervisor = load_supervisor_authority(root)
        self.assertEqual(supervisor["workers"], 6)
        self.assertEqual(supervisor["task_timeout_seconds"], 900)
        self.assertEqual(supervisor["task_timeout_retries"], 1)

    def test_task_timeout_requires_an_active_aware_timestamp(self) -> None:
        now = datetime.now(timezone.utc)
        self.assertFalse(
            _active_task_timed_out({}, now=now, timeout_seconds=60)
        )
        self.assertFalse(
            _active_task_timed_out(
                {
                    "active_task": "1:gmp@6.3.0",
                    "active_started_at": (now - timedelta(seconds=30)).isoformat(),
                },
                now=now,
                timeout_seconds=60,
            )
        )
        self.assertTrue(
            _active_task_timed_out(
                {
                    "active_task": "1:gmp@6.3.0",
                    "active_started_at": (now - timedelta(seconds=61)).isoformat(),
                },
                now=now,
                timeout_seconds=60,
            )
        )

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
