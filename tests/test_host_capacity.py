import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fidb_poc.host_capacity import (
    GIB,
    HostCapacity,
    detect_host_capacity,
    resolve_automatic_performance,
)


class HostCapacityTests(unittest.TestCase):
    def test_linux_detection_distinguishes_physical_cores_and_smt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cpu_root = root / "cpu"
            cgroup = root / "cgroup"
            cgroup.mkdir()
            (cgroup / "cpu.max").write_text("max 100000\n", encoding="utf-8")
            (cgroup / "memory.max").write_text("max\n", encoding="utf-8")
            meminfo = root / "meminfo"
            meminfo.write_text(
                "MemTotal:       98304000 kB\nMemAvailable:   90112000 kB\n",
                encoding="utf-8",
            )
            for cpu in range(8):
                topology = cpu_root / f"cpu{cpu}" / "topology"
                topology.mkdir(parents=True)
                (topology / "physical_package_id").write_text("0\n", encoding="utf-8")
                (topology / "core_id").write_text(str(cpu % 4), encoding="utf-8")

            with (
                mock.patch("platform.system", return_value="Linux"),
                mock.patch("platform.machine", return_value="x86_64"),
                mock.patch("os.cpu_count", return_value=8),
                mock.patch("os.sched_getaffinity", return_value=set(range(8))),
            ):
                host = detect_host_capacity(
                    proc_meminfo=meminfo,
                    sys_cpu_root=cpu_root,
                    cgroup_root=cgroup,
                )

        self.assertEqual(host.physical_cores, 4)
        self.assertEqual(host.logical_cpus, 8)
        self.assertEqual(host.smt_siblings, 4)
        self.assertEqual(host.threads_per_core, 2)
        self.assertEqual(host.total_memory_bytes, 98_304_000 * 1024)

    def test_cgroup_cpu_and_memory_limits_bound_detected_capacity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cgroup = root / "cgroup"
            cgroup.mkdir()
            (cgroup / "cpu.max").write_text("250000 100000\n", encoding="utf-8")
            (cgroup / "memory.max").write_text(str(12 * GIB), encoding="utf-8")
            (cgroup / "memory.current").write_text(str(2 * GIB), encoding="utf-8")
            meminfo = root / "meminfo"
            meminfo.write_text(
                f"MemTotal: {64 * GIB // 1024} kB\n"
                f"MemAvailable: {48 * GIB // 1024} kB\n",
                encoding="utf-8",
            )
            with (
                mock.patch("platform.system", return_value="Linux"),
                mock.patch("platform.machine", return_value="x86_64"),
                mock.patch("os.cpu_count", return_value=8),
                mock.patch("os.sched_getaffinity", return_value=set(range(8))),
                mock.patch(
                    "fidb_poc.host_capacity._linux_physical_cores", return_value=4
                ),
            ):
                host = detect_host_capacity(
                    proc_meminfo=meminfo,
                    sys_cpu_root=root / "missing",
                    cgroup_root=cgroup,
                )

        self.assertEqual(host.logical_cpus, 3)
        self.assertEqual(host.physical_cores, 3)
        self.assertEqual(host.total_memory_bytes, 12 * GIB)
        self.assertEqual(host.available_memory_bytes, 10 * GIB)
        self.assertEqual(host.cgroup_cpu_quota, 2.5)

    def test_auto_policy_weights_smt_and_memory_separately(self):
        host = HostCapacity(
            system="linux",
            architecture="x86_64",
            physical_cores=16,
            logical_cpus=32,
            smt_siblings=16,
            threads_per_core=2,
            total_memory_bytes=94 * GIB,
            available_memory_bytes=85 * GIB,
            memory_model="dedicated-system-memory",
            cpu_affinity_limited=False,
            cgroup_cpu_quota=None,
            cgroup_memory_limit_bytes=None,
            sources={},
        )

        resolution = resolve_automatic_performance(host)

        self.assertEqual(resolution.cpu_worker_bound, 20)
        self.assertGreaterEqual(resolution.memory_worker_bound, 20)
        self.assertEqual(resolution.settings.workers, 20)
        self.assertEqual(resolution.settings.build_jobs_per_cell, 4)
        self.assertEqual(resolution.settings.ghidra_heap_mib, 4096)
        self.assertEqual(resolution.settings.ghidra_core_limit, 4)

    def test_small_memory_host_is_memory_bounded(self):
        host = HostCapacity(
            system="linux",
            architecture="x86_64",
            physical_cores=4,
            logical_cpus=8,
            smt_siblings=4,
            threads_per_core=2,
            total_memory_bytes=8 * GIB,
            available_memory_bytes=7 * GIB,
            memory_model="dedicated-system-memory",
            cpu_affinity_limited=False,
            cgroup_cpu_quota=None,
            cgroup_memory_limit_bytes=None,
            sources={},
        )

        resolution = resolve_automatic_performance(host)

        self.assertEqual(resolution.settings.workers, 1)
        self.assertEqual(resolution.settings.ghidra_heap_mib, 2048)
        self.assertEqual(resolution.settings.build_jobs_per_cell, 2)


if __name__ == "__main__":
    unittest.main()
