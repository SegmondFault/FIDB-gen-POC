import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fidb_poc.hash_gpu_trial import (
    SENTINEL,
    _cpu_probe,
    _shader,
    compile_hash_backend_status,
    save_hash_performance_mode,
)


@unittest.skipUnless(importlib.util.find_spec("numpy"), "GPU extra is not installed")
class HashGpuTrialTests(unittest.TestCase):
    def backend_root(self, root: Path) -> None:
        (root / "validation/evidence").mkdir(parents=True)
        (root / "performance").mkdir()
        (root / "validation/hash-analysis-backends.toml").write_text(
            """schema_version = "fidb-hash-analysis-backends/v1"
selected = "gpu-wgpu-packed-probe-v1"
comparison_policy = "explicit-qualification-only"
require_zero_mismatches_for_promotion = true

[[backend]]
id = "cpu-packed-probe-v1"
state = "qualified-fallback"
implementation = "numpy-sorted-packed-probe"
device = "cpu"
scope = "packed-complete-signature-exact-probe"

[[backend]]
id = "gpu-wgpu-packed-probe-v1"
state = "qualified-authoritative"
implementation = "wgpu-packed-exact-probe"
device = "gpu"
scope = "packed-complete-signature-exact-probe"
qualification_report = "validation/evidence/gpu.json"
""",
            encoding="utf-8",
        )
        (root / "performance/hash-analysis.toml").write_text(
            """schema_version = "fidb-hash-analysis-performance/v1"
mode = "auto"
allow_gpu = true
fallback_to_cpu = true
""",
            encoding="utf-8",
        )
        (root / "validation/evidence/gpu.json").write_text(
            json.dumps(
                {
                    "candidate_backend": "gpu-wgpu-packed-probe-v1",
                    "state": "equivalent",
                    "scope": "packed-complete-signature-exact-probe",
                    "mismatches": 0,
                    "device": {"device": "test"},
                    "performance": {"probe_speedup": 3.3},
                }
            ),
            encoding="utf-8",
        )

    def test_cpu_packed_probe_preserves_exact_key_identity(self):
        import numpy as np

        reference = np.array(
            [
                [0, 0, 1, 0, 2, 3, 4],
                [0, 0, 5, 0, 6, 7, 8],
                [1, 0, 1, 0, 2, 3, 4],
            ],
            dtype=np.uint32,
        )
        queries = np.array(
            [
                [0, 0, 1, 0, 2, 3, 4],
                [0, 0, 2, 0, 2, 3, 4],
                [1, 0, 1, 0, 2, 3, 4],
            ],
            dtype=np.uint32,
        )

        self.assertEqual(
            _cpu_probe(reference, queries).tolist(),
            [0, SENTINEL, 2],
        )

    def test_shader_pins_bounds_and_workgroup_size(self):
        shader = _shader(17, 9, 256)

        self.assertIn("REFERENCE_COUNT: u32 = 17u", shader)
        self.assertIn("QUERY_COUNT: u32 = 9u", shader)
        self.assertIn("@compute @workgroup_size(256)", shader)

    def test_auto_selects_only_qualified_available_gpu_and_cpu_override_is_toml(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.backend_root(root)
            with (
                patch(
                    "fidb_poc.hash_gpu_trial._detected_gpu_devices",
                    return_value=[
                        {"name": "card0", "vendor_id": "v", "device_id": "d"}
                    ],
                ),
                patch(
                    "fidb_poc.hash_gpu_trial.importlib.util.find_spec",
                    return_value=object(),
                ),
            ):
                automatic = compile_hash_backend_status(root)
                cpu = save_hash_performance_mode(root, "cpu")

            self.assertEqual(automatic["effective_backend"]["device"], "gpu")
            self.assertTrue(automatic["gpu"]["authoritative"])
            self.assertEqual(cpu["effective_backend"]["id"], "cpu-packed-probe-v1")
            self.assertEqual(cpu["requested_mode"], "cpu")
            self.assertIn(
                'mode = "cpu"', (root / "performance/hash-analysis.toml").read_text()
            )


if __name__ == "__main__":
    unittest.main()
