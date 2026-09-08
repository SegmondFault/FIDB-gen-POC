from __future__ import annotations

from pathlib import Path
import unittest

from fidb_poc.host_capacity import GIB, HostCapacity
from fidb_poc.linked_reference_performance import (
    load_linked_reference_performance,
    resolve_linked_reference_performance,
)


def host(memory_gib: int, available_gib: int) -> HostCapacity:
    return HostCapacity(
        system="linux",
        architecture="x86_64",
        physical_cores=16,
        logical_cpus=32,
        smt_siblings=16,
        threads_per_core=2.0,
        total_memory_bytes=memory_gib * GIB,
        available_memory_bytes=available_gib * GIB,
        memory_model="dedicated-system-memory",
        cpu_affinity_limited=False,
        cgroup_cpu_quota=None,
        cgroup_memory_limit_bytes=None,
        sources={"test": "fixture"},
    )


class LinkedReferencePerformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[1]

    def test_checked_in_profiles_are_toml_and_bounded(self) -> None:
        config = load_linked_reference_performance(self.root)
        self.assertEqual([row["workers"] for row in config["profiles"]], [6, 8, 10, 12])
        self.assertEqual(config["mode"], "auto")

    def test_94_gib_host_selects_eight_workers(self) -> None:
        result = resolve_linked_reference_performance(self.root, host=host(94, 78))
        self.assertEqual(result["state"], "ready")
        self.assertEqual(result["selected_profile"]["workers"], 8)

    def test_112_gib_host_selects_ten_workers(self) -> None:
        result = resolve_linked_reference_performance(self.root, host=host(112, 104))
        self.assertEqual(result["selected_profile"]["workers"], 10)

    def test_experimental_twelve_is_never_selected_automatically(self) -> None:
        result = resolve_linked_reference_performance(self.root, host=host(128, 120))
        self.assertEqual(result["selected_profile"]["workers"], 10)
        twelve = next(row for row in result["profiles"] if row["workers"] == 12)
        self.assertTrue(twelve["eligible"])
        self.assertEqual(twelve["qualification"], "experimental")


if __name__ == "__main__":
    unittest.main()
